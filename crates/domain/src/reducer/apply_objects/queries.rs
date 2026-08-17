//! Read-only `ProjectionState` query helpers: message / reaction / poll /
//! relation / membership lookups plus the cell-keyed Realm policy readers.
//! Inherent-impl block on `ProjectionState`; methods resolve by type, so
//! cross-family `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

fn is_policy_frontier_component(component: &str) -> bool {
    (component.starts_with("ak.component.realm.")
        && (component.contains("policy")
            || matches!(
                component,
                arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1
                    | arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1
                    | arkret_wire::CellFamilyId::REALM_MEDIA_SERVICE_V1
                    | arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1
                    | arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1
            )))
        || (component.starts_with("ak.component.circle.")
            && ["policy", "history", "encryption", "lifecycle"]
                .iter()
                .any(|marker| component.contains(marker)))
}

impl ProjectionState {
    pub(crate) fn message_by_target_ref(&self, target_ref: &str) -> Option<&MessageState> {
        // Classify by canonical typed id, not by kind prefix: `ak:event:x` is
        // not an Event id, so it must not take the Event-keyed branch.
        if arkret_identifiers::MessageId::new(target_ref).is_ok() {
            return self
                .messages
                .values()
                .find(|message| message.message_id == target_ref)
                .or_else(|| self.messages.get(target_ref))
                .or_else(|| {
                    let event_id = message_event_id_from_ref(target_ref);
                    self.messages.get(&event_id)
                });
        }
        if arkret_identifiers::EventId::new(target_ref).is_ok() {
            return self.messages.get(target_ref);
        }
        self.messages.get(target_ref).or_else(|| {
            let event_id = message_event_id_from_ref(target_ref);
            self.messages.get(&event_id).or_else(|| {
                self.messages
                    .values()
                    .find(|message| message.message_id == target_ref)
            })
        })
    }

    pub fn redaction_key_for_message_target(&self, target_ref: &str) -> String {
        if target_ref.trim().is_empty() {
            return String::new();
        }
        self.message_by_target_ref(target_ref)
            .map(|message| message.event_id.clone())
            .unwrap_or_else(|| target_ref.to_owned())
    }

    pub fn redaction_cell_for_message(
        &self,
        message: &MessageState,
    ) -> Option<&RedactionCellValue> {
        self.redaction_cells
            .get(&message.event_id)
            .or_else(|| self.redaction_cells.get(&message.message_id))
            .or_else(|| {
                message
                    .revision_of
                    .as_deref()
                    .and_then(|original_id| self.redaction_cells.get(original_id))
            })
            .and_then(|cell| cell.as_ref())
    }
}

impl ProjectionState {
    // ── Query helpers ──

    /// Get all non-redacted messages for a Realm, sorted by creation time.
    pub fn messages_for_realm(&self, realm_id: &str) -> Vec<&MessageState> {
        let superseded = self.superseded_message_ids();
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.realm_id == realm_id
                    && !superseded.contains(m.event_id.as_str())
                    && self.redaction_cell_for_message(m).is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a Realm including redacted rows, sorted by creation
    /// time. Superseded revisions are still dropped (only the latest revision
    /// of a message survives). The message stream (sync timeline) uses this so
    /// a redacted message keeps its slot and can be surfaced as a per-message
    /// tombstone (strand-and-message.md §9) instead of vanishing — the read
    /// path replaces its body with the redaction tombstone before emitting.
    pub fn messages_for_realm_including_redacted(&self, realm_id: &str) -> Vec<&MessageState> {
        let superseded = self.superseded_message_ids();
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| m.realm_id == realm_id && !superseded.contains(m.event_id.as_str()))
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a thread, sorted by creation time.
    pub fn messages_for_thread(&self, thread_id: &str) -> Vec<&MessageState> {
        let superseded = self.superseded_message_ids();
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.thread_id == thread_id
                    && !superseded.contains(m.event_id.as_str())
                    && self.redaction_cell_for_message(m).is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    fn superseded_message_ids(&self) -> std::collections::BTreeSet<&str> {
        self.messages
            .values()
            .filter_map(|message| message.revision_of.as_deref())
            .collect()
    }

    /// Resolve a Message's `(created_at, sender, thread_id)` by target ref,
    /// accepting either the `ak:event:` storage id or the `ak:message:`
    /// object-ref form. Used by the constraint-schema.md §14.2 edit/redact
    /// window evaluator, which needs the original Message `created_at` to
    /// measure the elapsed window. Returns `None` for unknown targets.
    pub fn message_origin(
        &self,
        target_ref: &str,
    ) -> Option<(chrono::DateTime<chrono::Utc>, String, String)> {
        let msg = self.message_by_target_ref(target_ref)?;
        Some((msg.created_at, msg.sender.clone(), msg.thread_id.clone()))
    }

    /// Resolve the `realm_id` (effective scope) of a Message by target ref,
    /// accepting the `ak:message:` object-ref or `ak:event:` storage id.
    /// Used by the strand-and-message.md §9.8.2 reaction scope check. Returns
    /// `None` for unknown targets (the reducer's dependency handling then
    /// keeps the reaction pending).
    pub fn message_realm(&self, target_ref: &str) -> Option<String> {
        self.message_by_target_ref(target_ref)
            .map(|msg| msg.realm_id.clone())
    }

    /// Resolve the Circle scope inherited by an event targeting a Message.
    pub fn message_circle_scope(&self, target_ref: &str) -> Option<String> {
        self.message_by_target_ref(target_ref)
            .and_then(|message| message.content.get("scope_circle_id"))
            .and_then(Value::as_str)
            .filter(|circle_id| circle_id.starts_with("ak:circle:"))
            .map(ToOwned::to_owned)
    }

    /// Projection-layer view of a single message that
    /// consults the parallel `redaction` cell. Returns:
    ///   - `Some(view)` with `content = Some(_)` for live messages (no redaction cell set, or set
    ///     back to null);
    ///   - `Some(view)` with `content = None` + `redaction = Some(_)` when the parallel cell is in
    ///     effect — caller renders the tombstone;
    ///   - `None` if no underlying [`MessageState`] is known.
    ///
    /// The ordered-log historical entry id is preserved unchanged so
    /// federation / sync replay still emits the same `event_id`.
    pub fn projected_message(
        &self,
        event_id: &str,
        viewer_is_author: bool,
    ) -> Option<ProjectedMessageView> {
        let msg = self.messages.get(event_id)?;
        let redaction = self.redaction_cell_for_message(msg).cloned();
        let content = match (&redaction, viewer_is_author) {
            // No redaction in effect — full payload visible.
            (None, _) => Some(msg.content.clone()),
            // Author keeps the audit-view of the original payload.
            (Some(_), true) => Some(msg.content.clone()),
            // Other members see the tombstone.
            (Some(_), false) => None,
        };
        Some(ProjectedMessageView {
            event_id: msg.event_id.clone(),
            realm_id: msg.realm_id.clone(),
            sender: msg.sender.clone(),
            thread_id: msg.thread_id.clone(),
            created_at: msg.created_at,
            content,
            redaction,
        })
    }

    /// Get active reactions for an event.
    pub fn reactions_for_event(&self, event_id: &str) -> Vec<&ReactionState> {
        self.reactions
            .get(event_id)
            .map(|by_actor| {
                by_actor
                    .values()
                    .flat_map(|by_key| by_key.values().filter(|r| r.active))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn poll(&self, poll_id: &str) -> Option<&PollState> {
        self.polls.get(poll_id)
    }

    /// Get members of a Realm currently in `state="join"`.
    /// For state-specific queries use [`members_in_state`].
    pub fn members_of_realm(&self, realm_id: &str) -> Vec<&SolandMembershipState> {
        self.members_in_state(realm_id, "join")
    }

    /// All `SolandMembershipState` entries for a Realm whose FSM state matches
    /// `state` (`invite` / `join` / `leave` / `ban` / `knock`).
    pub fn members_in_state(&self, realm_id: &str, state: &str) -> Vec<&SolandMembershipState> {
        self.members
            .iter()
            .filter(|((sid, _), m)| sid == realm_id && m.state == state)
            .map(|(_, m)| m)
            .collect()
    }

    /// Look up a single `(realm_id, actor_id)` member entry.
    pub fn member(&self, realm_id: &str, actor_id: &str) -> Option<&SolandMembershipState> {
        self.members
            .get(&(realm_id.to_owned(), actor_id.to_owned()))
    }

    pub fn membership_authority(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<&arkret_wire::PrincipalAuthorityKey> {
        self.membership_authorities
            .get(&(realm_id.to_owned(), actor_id.to_owned()))
    }

    pub fn agent_membership_binding(
        &self,
        realm_id: &str,
        agent_id: &str,
    ) -> Option<
        &arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding,
    >{
        self.agent_membership_bindings
            .get(&(realm_id.to_owned(), agent_id.to_owned()))
    }

    /// Deterministic membership/lifecycle half of Native Personal Agent
    /// effective membership. Callers that authorize Agent activity must also
    /// verify the durable provision/accountability binding owned by the
    /// identity service.
    pub fn effective_agent_membership_base(&self, realm_id: &str, agent_id: &str) -> bool {
        let Some(agent) = self.member(realm_id, agent_id) else {
            return false;
        };
        if agent.state != "join"
            || self.agent_lifecycles.get(agent_id)
                != Some(&arkret_models_collaboration::agent_operations::AgentLifecycleState::Active)
        {
            return false;
        }
        let Some(binding) = self.agent_membership_binding(realm_id, agent_id) else {
            return false;
        };
        let controller_id = binding.controller_authority.principal_id.as_str();
        let Some(controller) = self.member(realm_id, controller_id) else {
            return false;
        };
        controller.state == "join"
            && controller.membership_event_ref.as_deref()
                == Some(binding.controller_membership_generation_ref.as_str())
            && self.membership_authority(realm_id, controller_id)
                == Some(&binding.controller_authority)
    }

    /// Read the FSM state of a member directly from the cells map.
    /// Returns `None` if the cell hasn't been written or is in `Bottom`
    /// state. The cell_subject is the actor_id per spec
    /// `ak.component.member.state.v1` cell_family declaration.
    pub fn member_fsm_state(&self, actor_id: &str) -> Option<String> {
        let cell_id = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.member.state.v1:{actor_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    // ── Cell-keyed query helpers ──

    pub fn realm_null_subject_cell_value(
        &self,
        realm_id: &str,
        cell_family: &str,
    ) -> Option<&Value> {
        let cell_id = format!("ak:cell:{cell_family}:null");
        match self
            .realm_null_subject_cells
            .get(&(realm_id.to_owned(), cell_id))
        {
            Some(CellState::Value(value)) => Some(value),
            Some(CellState::Bottom(_)) | None => None,
        }
    }

    /// Read the effective `ak.realm.read_receipt_policy` value out of the
    /// Realm-scoped null-subject cell cache. Returns `None` when:
    ///   - the cell has never been written, OR
    ///   - the cell is in `Bottom` state (concurrent conflict needs recovery)
    pub fn read_receipt_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_null_subject_cell_value(
            realm_id,
            arkret_wire::CellFamilyId::REALM_READ_RECEIPT_POLICY_V1,
        )
    }

    /// Effective Realm reducer profile. This singleton is the only profile
    /// authority used by reducers and federation admission.
    pub fn realm_reducer_profile(&self, realm_id: &str) -> Option<&str> {
        self.realm_null_subject_cell_value(
            realm_id,
            arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1,
        )
        .and_then(Value::as_str)
    }

    // ── Realm lifecycle cell helpers ──

    /// Read the effective display profile singleton. Returns `None` for an
    /// absent or conflicting profile cell.
    pub fn realm_profile_cell_value(&self, realm_id: &str) -> Option<&Value> {
        match self.realm_profile_cells.get(realm_id)? {
            CellState::Value(value) => Some(value),
            CellState::Bottom(_) => None,
        }
    }

    /// Read the `ak.component.realm.create.v1` ordered-log entries for the
    /// realm's genesis history. Returns `None` for realms with no create
    /// events (e.g. before first projection) or `Bottom` state.
    pub fn realm_create_log(&self, realm_id: &str) -> Option<&[Value]> {
        match self.realm_create_cells.get(realm_id)? {
            CellState::Value(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// Immutable identity/security genesis value projected by
    /// `ak.realm.create` into its dedicated singleton cell.
    pub fn realm_genesis_cell_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_null_subject_cell_value(realm_id, arkret_wire::CellFamilyId::REALM_GENESIS_V1)
    }

    /// Identifies the registered Direct Conversation Realm role from the
    /// immutable genesis singleton.
    /// Unknown, incomplete, or malformed role declarations fail closed and
    /// never fall back to member-count, title, category, or tag heuristics.
    pub fn realm_is_direct_conversation(&self, realm_id: &str) -> bool {
        self.realm_genesis_cell_value(realm_id)
            .and_then(|object| object.get("purpose"))
            .and_then(Value::as_str)
            == Some("direct_conversation")
    }

    /// True when the `ak.component.realm.destroy.v1` cell has a Value.
    pub fn realm_is_destroyed(&self, realm_id: &str) -> bool {
        self.realm_null_subject_cell_value(realm_id, arkret_wire::CellFamilyId::REALM_DESTROY_V1)
            .is_some()
    }

    /// True when the `ak.component.realm.tombstone.v1` cell has a Value.
    pub fn realm_is_tombstoned(&self, realm_id: &str) -> bool {
        self.realm_null_subject_cell_value(realm_id, arkret_wire::CellFamilyId::REALM_TOMBSTONE_V1)
            .is_some()
    }

    /// Stream-F (Wave 1B) — true if the Realm is in ANY terminal state
    /// (tombstoned OR destroyed). The wire-layer
    /// `terminal_realm_check` consults this to reject non-audit
    /// writes against terminal Realms. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub fn realm_is_in_terminal_state(&self, realm_id: &str) -> bool {
        if let Some(s) = self.realm_states.get(realm_id)
            && s.terminal_state.is_some()
        {
            return true;
        }
        // Fall back to cell-presence checks so peers that hydrate from
        // cells without rebuilding `realm_states` still see terminal state.
        self.realm_is_tombstoned(realm_id) || self.realm_is_destroyed(realm_id)
    }

    /// True when the Realm's reversible freeze facet is active at `now`.
    pub fn realm_is_frozen_at(&self, realm_id: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
        let Some(state) = self.realm_states.get(realm_id) else {
            return false;
        };
        if !state.frozen {
            return false;
        }
        match state.freeze_expires_at {
            Some(expires_at) => expires_at > now,
            None => true,
        }
    }

    /// Read the projected `ak.component.realm.delivery_binding_policy.v1`
    /// cas-register value, if any. The wire cell id has a literal `null`
    /// subject, so the enclosing Realm id is part of the cache namespace.
    pub fn realm_delivery_binding_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_null_subject_cell_value(
            realm_id,
            arkret_wire::CellFamilyId::REALM_DELIVERY_BINDING_POLICY_V1,
        )
    }

    pub fn realm_policy_bundle_cell_value(&self, realm_id: &str) -> Option<&Value> {
        match self.realm_policy_bundle_cells.get(realm_id)? {
            // The registry projects `field=payload`, so authoritative Seal
            // replay stores the generic state payload `{"value": ...}`.
            // Live dispatch already normalizes that envelope before caching.
            // Return the one canonical policy value from both paths.
            CellState::Value(value) => Some(value.get("value").unwrap_or(value)),
            CellState::Bottom(_) => None,
        }
    }

    pub fn realm_join_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_policy_bundle_cell_value(realm_id)?
            .get("join_policy")
    }

    /// Submit-time and reducer-time hard gate for Join Policy.
    /// `principal_admission` and `cooldown` are non-bypassable
    /// preconditions; remaining gates are evaluated with `combinator`.
    pub fn check_membership_join_admission(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = crate::kinds::canonical_kind_for_operation(operation);
        let (member, hard_gates_only) = match &kind {
            Some(arkret_wire::EventKind::MemberState) => {
                let payload = operation
                    .typed_payload::<arkret_wire::event_spec::MemberState>()
                    .map_err(|_| "gate_check_failed")?;
                if payload.membership
                    != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
                {
                    return Ok(());
                }
                (payload.actor_id.map(|actor_id| actor_id.to_string()), false)
            }
            Some(arkret_wire::EventKind::InviteCreate) => {
                let payload = operation
                    .typed_payload::<arkret_wire::event_spec::InviteCreate>()
                    .map_err(|_| "gate_check_failed")?;
                (Some(payload.invitee.to_string()), true)
            }
            Some(arkret_wire::EventKind::InviteAccept) => {
                (Some(operation.context.sender.to_string()), true)
            }
            _ => return Ok(()),
        };
        let member = member.as_deref();
        let Some(member) = member else {
            return Err("gate_check_failed");
        };
        if kind == Some(arkret_wire::EventKind::MemberState)
            && self
                .member(operation.realm_id.as_str(), member)
                .is_some_and(|membership| membership.state == "join")
        {
            // `join -> join` refreshes an existing member's delivery binding;
            // it is not a new Realm entry and therefore does not re-run entry
            // gates or the Realm join rule.
            return Ok(());
        }
        let join_rule =
            (!hard_gates_only).then(|| self.realm_default_join_rule(operation.realm_id.as_str()));
        let is_self_authored = operation.context.sender.as_str() == member;
        if join_rule.is_some_and(|rule| matches!(rule, "invite" | "closed")) && is_self_authored {
            return Err("gate_check_failed");
        }
        let Some(join_policy) = self.realm_join_policy_cell_value(operation.realm_id.as_str())
        else {
            return Ok(());
        };
        if let Err(reason) = validate_join_policy_payload(join_policy) {
            return if reason == "join_policy_duplicate_gate_id" {
                Err("join_policy_duplicate_gate_id")
            } else {
                Err("gate_check_failed")
            };
        }
        let Some(gates) = join_policy.get("gates").and_then(Value::as_array) else {
            return Err("gate_check_failed");
        };
        let proofs = operation
            .payload
            .get("gate_proofs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if proofs.len() > 16 || gate_proofs_have_duplicate_gate_ids(proofs) {
            return Err("gate_check_failed");
        }
        for gate in gates {
            let Some(gate) = gate.as_object() else {
                return Err("gate_check_failed");
            };
            match gate.get("kind").and_then(Value::as_str) {
                Some("principal_admission") => {
                    // DID-method admission must be evaluated from the frozen
                    // registration and origin-service admission evidence
                    // selected by the exact principal authority pair. A
                    // projection's current full_id is not a substitute for
                    // that accepted pair binding.
                    if !principal_admission_gate_allows(gate, member, None) {
                        return Err("gate_check_failed");
                    }
                }
                Some("cooldown")
                    if self.cooldown_gate_blocks_join(
                        gate,
                        operation.realm_id.as_str(),
                        member,
                        operation.created_at,
                    ) =>
                {
                    return Err("gate_check_failed");
                }
                _ => {}
            }
        }
        if hard_gates_only {
            return Ok(());
        }
        if !join_rule
            .is_some_and(|rule| matches!(rule, "knock" | "restricted" | "knock_restricted"))
        {
            return Ok(());
        }
        let normal_gates = gates.iter().filter_map(Value::as_object).filter(|gate| {
            !matches!(
                gate.get("kind").and_then(Value::as_str),
                Some("principal_admission" | "cooldown")
            )
        });
        match join_policy.get("combinator").and_then(Value::as_str) {
            Some("all") => {
                for gate in normal_gates {
                    if !self.join_gate_allows(gate, proofs, member, operation.created_at) {
                        return Err("gate_check_failed");
                    }
                }
                Ok(())
            }
            Some("any") => {
                let mut saw_normal_gate = false;
                for gate in normal_gates {
                    saw_normal_gate = true;
                    if self.join_gate_allows(gate, proofs, member, operation.created_at) {
                        return Ok(());
                    }
                }
                if saw_normal_gate {
                    Err("gate_check_failed")
                } else {
                    Ok(())
                }
            }
            _ => Err("gate_check_failed"),
        }
    }

    pub fn realm_default_join_rule(&self, realm_id: &str) -> &str {
        self.realm_join_rules
            .get(realm_id)
            .map(String::as_str)
            .unwrap_or("invite")
    }

    fn cooldown_gate_blocks_join(
        &self,
        gate: &serde_json::Map<String, Value>,
        realm_id: &str,
        member: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(min_interval) = gate
            .get("min_interval_since_leave")
            .and_then(Value::as_str)
            .and_then(parse_iso8601_duration)
        else {
            return true;
        };
        let Some(previous) = self.member(realm_id, member) else {
            return false;
        };
        previous.state == "leave" && now.signed_duration_since(previous.updated_at) < min_interval
    }

    fn join_gate_allows(
        &self,
        gate: &serde_json::Map<String, Value>,
        proofs: &[Value],
        member: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        match gate.get("kind").and_then(Value::as_str) {
            Some("parent_membership") => self.parent_membership_gate_allows(gate, member),
            Some("challenge_response") => gate
                .get("gate_id")
                .and_then(Value::as_str)
                .and_then(|gate_id| gate_proof_for_gate(proofs, gate_id))
                .is_some_and(|proof| challenge_response_gate_allows(gate, proof, now)),
            Some("claim_required") => gate
                .get("gate_id")
                .and_then(Value::as_str)
                .and_then(|gate_id| gate_proof_for_gate(proofs, gate_id))
                .is_some_and(|proof| claim_required_gate_has_proof(gate, proof)),
            Some("application_form" | "manual_review") => false,
            _ => false,
        }
    }

    fn parent_membership_gate_allows(
        &self,
        gate: &serde_json::Map<String, Value>,
        member: &str,
    ) -> bool {
        let required = gate
            .get("require_min_membership")
            .and_then(Value::as_str)
            .unwrap_or("join");
        gate.get("membership_source_realm_ids")
            .and_then(Value::as_array)
            .is_some_and(|source_realms| {
                source_realms
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|realm_id| {
                        self.member(realm_id, member).is_some_and(|membership| {
                            membership_state_satisfies_minimum(&membership.state, required)
                        })
                    })
            })
    }

    pub fn realm_search_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_null_subject_cell_value(
            realm_id,
            arkret_wire::CellFamilyId::REALM_SEARCH_POLICY_V1,
        )
    }

    /// R3.1 — query realm links by direction and optional link_kind
    /// allow-list. Returns a Vec sorted by `(target_realm_id, link_kind)`
    /// so the response is stable across calls.
    ///
    /// `direction` controls which side(s) of the edge to return:
    /// `outbound` → edges where `realm_id == realm_id`, `inbound` →
    /// edges where `target_realm_id == realm_id`, `both` → both
    /// (outbound first, inbound second).
    pub fn realm_links_query(
        &self,
        realm_id: &str,
        direction: arkret_models_collaboration::governance::realm_governance::RealmLinkDirection,
        link_kind_allow: Option<&[String]>,
    ) -> Vec<RealmLinkState> {
        use arkret_models_collaboration::governance::realm_governance::RealmLinkDirection;
        let filter = |row: &&RealmLinkState| {
            link_kind_allow
                .map(|allow| allow.iter().any(|k| k == &row.link_kind))
                .unwrap_or(true)
        };
        let mut out: Vec<RealmLinkState> = Vec::new();
        if matches!(
            direction,
            RealmLinkDirection::Outbound | RealmLinkDirection::Both
        ) && let Some(rows) = self.realm_links.get(realm_id)
        {
            out.extend(rows.iter().filter(filter).cloned());
        }
        if matches!(
            direction,
            RealmLinkDirection::Inbound | RealmLinkDirection::Both
        ) && let Some(rows) = self.realm_links_inbound.get(realm_id)
        {
            out.extend(rows.iter().filter(filter).cloned());
        }
        out.sort_by(|a, b| {
            a.target_realm_id
                .cmp(&b.target_realm_id)
                .then(a.link_kind.cmp(&b.link_kind))
                .then(a.realm_id.cmp(&b.realm_id))
        });
        out
    }

    /// R3.2 — read the most-recent `ak.realm.inheritance_policy`
    /// projection for a child Realm, if any.
    pub fn realm_inheritance_policy(&self, realm_id: &str) -> Option<&RealmInheritancePolicyState> {
        self.realm_inheritance_policies.get(realm_id)
    }

    /// realm-links.md §6.2 — every per-`(child, source)` inheritance
    /// declaration the child Realm has on file, in deterministic source
    /// order. Unlike [`Self::realm_inheritance_policy`] this surfaces ALL
    /// opted-in sources (multi-`governed_by`), so the effective-policy read
    /// can compute the narrow-only intersection across them.
    pub fn realm_inheritance_policies_for_child(
        &self,
        realm_id: &str,
    ) -> Vec<&RealmInheritancePolicyState> {
        self.realm_inheritance_policies_by_source
            .iter()
            .filter(|((child, _source), _state)| child == realm_id)
            .map(|(_key, state)| state)
            .collect()
    }

    /// R3.2 — read the most-recent `ak.capability.derived` projection
    /// for a capability id, if any.
    pub fn capability_derived_state(&self, capability_id: &str) -> Option<&CapabilityDerivedState> {
        self.capability_derived.get(capability_id)
    }

    /// G3.S2 — read the most-recent `ak.realm.policy_server` projection
    /// for a Realm, walking up the `governed_by` link chain when the
    /// realm itself has no row of its own (org-level fallback). Returns
    /// `None` if neither the realm nor any ancestor declared a policy
    /// server. The walk caps at depth 8 and uses a visited set because
    /// general Realm Link graphs may contain cycles.
    pub fn try_realm_policy_server_config(
        &self,
        realm_id: &str,
    ) -> Result<Option<&RealmPolicyServerConfig>, &'static str> {
        let mut cursor = realm_id.to_owned();
        let mut visited = std::collections::BTreeSet::new();
        for _ in 0..8 {
            if !visited.insert(cursor.clone()) {
                return Err("realm_policy_server_governance_cycle");
            }
            let cell_id = "ak:cell:ak.component.realm.policy_server.v1:null".to_owned();
            match self
                .realm_null_subject_cells
                .get(&(cursor.clone(), cell_id))
            {
                Some(CellState::Bottom(_)) => return Err("cell_bottom_state"),
                Some(CellState::Value(value)) => {
                    let is_tombstone = value.as_object().is_some_and(|object| {
                        object.len() == 1
                            && object.get("tombstone").and_then(Value::as_bool) == Some(true)
                    });
                    if !is_tombstone && !self.realm_policy_servers.contains_key(&cursor) {
                        return Err("realm_policy_server_projection_missing");
                    }
                }
                _ => {}
            }
            if let Some(config) = self.realm_policy_servers.get(&cursor) {
                return Ok(Some(config));
            }
            let targets = self
                .realm_links
                .get(&cursor)
                .into_iter()
                .flatten()
                .filter(|row| row.link_kind == "governed_by" && row.status == "active")
                .map(|row| row.target_realm_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            match targets.len() {
                0 => return Ok(None),
                1 => cursor = (*targets.first().expect("one governed_by target")).to_owned(),
                _ => return Err("realm_policy_server_governance_ambiguous"),
            }
        }
        Err("realm_policy_server_governance_depth_exceeded")
    }

    /// Read the create-locked Realm encryption profile from genesis.
    pub fn realm_encryption_profile(&self, realm_id: &str) -> Option<String> {
        self.realm_genesis_cell_value(realm_id)
            .and_then(|genesis| genesis.get("encryption_profile"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    /// Profiles the Realm object declares in `schema_refs[]`.
    ///
    /// This is where a Realm declares `ak.profile.e2ee_relaxed.v1`
    /// (`encryption-and-audit.md` §2.4.1). The Realm has no
    /// `supported_profiles` field — that name belongs to the *service*
    /// description — and the policy bundle deliberately does not carry the
    /// profile either, so this create-log read is the only source.
    pub fn realm_schema_refs(&self, realm_id: &str) -> Vec<String> {
        self.realm_genesis_cell_value(realm_id)
            .and_then(|genesis| genesis.get("schema_refs"))
            .and_then(Value::as_array)
            .map(|refs| {
                refs.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Realm ceiling on encrypted-envelope `aad_visibility_event_id_kind`, resolved
    /// from the accepted policy bundle. An absent component is the `hidden`
    /// ceiling, never an unchecked one.
    pub fn realm_aad_visibility_ceiling(
        &self,
        realm_id: &str,
    ) -> arkret_models_crypto::AadVisibilityCeiling {
        crate::reducer::policy_validation::aad_visibility_ceiling_from_bundle(
            self.realm_policy_bundle_cell_value(realm_id),
        )
    }

    /// The Realm's non-`⊥` policy control cells.
    ///
    /// `authz/policy-server.md` §5 defines `policy_frontier_digest` as a
    /// *filtered state root* over exactly these cells, reusing the governance
    /// `state_root` Merkle rules of `event-auth-state-resolution.md` §6.2.1 —
    /// JCS leaves, cell-id order, `leaf=H(0x00||bytes)`, `node=H(0x01||l||r)`.
    /// It is explicitly not an issuer-local opaque value, which is why this
    /// enumerates cells rather than hashing a hand-built object: a cross-issuer
    /// verifier has to be able to recompute the same number from the same Seal
    /// view.
    ///
    /// `⊥` cells are excluded: §5 says "全部 non-`⊥` policy control cell".
    pub fn realm_policy_control_cells(
        &self,
        realm_id: &str,
    ) -> BTreeMap<CellRef, arkret_state::lattice::CellState> {
        let mut cells = BTreeMap::new();
        let mut insert = |wire: String, state: &arkret_state::lattice::CellState| {
            if matches!(state, arkret_state::lattice::CellState::Bottom(_)) {
                return;
            }
            if let Ok(cell_ref) = CellRef::new(wire) {
                cells.insert(cell_ref, state.clone());
            }
        };
        if let Some(bundle) = self.realm_policy_bundle_cells.get(realm_id) {
            insert(
                "ak:cell:ak.component.realm.policy_bundle.v1:null".to_owned(),
                bundle,
            );
        }
        for ((cell_realm_id, wire), state) in &self.realm_null_subject_cells {
            if cell_realm_id == realm_id {
                insert(wire.clone(), state);
            }
        }
        // Realm-subject cells (families keyed by the Realm id rather than the
        // null subject) live in the generic cell store.
        for (cell_ref, state) in &self.cells {
            if cell_ref.as_str().ends_with(&format!(":{realm_id}")) {
                insert(cell_ref.as_str().to_owned(), state);
            }
        }
        cells
    }

    /// `authz/policy-server.md` §5 `policy_frontier_digest` for this Realm.
    ///
    /// Delegates the leaf/sort/combine rules to the SDK so an issuer and a
    /// verifier cannot drift; a hash assembled from policy field names would be
    /// issuer-local and would fail the cross-issuer structured comparison the
    /// section requires.
    pub fn realm_policy_frontier_digest(&self, realm_id: &str) -> Option<arkret_wire::Hash> {
        let cells = self
            .realm_policy_control_cells(realm_id)
            .into_iter()
            .filter(|(cell, _)| {
                arkret_wire::cell::CellId::from_ref(cell)
                    .map(|cell| is_policy_frontier_component(cell.component()))
                    .unwrap_or(false)
            })
            .collect::<BTreeMap<_, _>>();
        arkret_state::compute_state_root(&cells).ok()
    }

    pub fn realm_digest_algorithm(&self, realm_id: &str) -> Option<String> {
        self.realm_null_subject_cell_value(
            realm_id,
            arkret_wire::CellFamilyId::REALM_DIGEST_SUITE_V1,
        )
        .and_then(|value| value.get("to_digest_algorithm"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            self.realm_genesis_cell_value(realm_id)
                .and_then(|genesis| genesis.get("digest_algorithm"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
    }

    pub fn realm_requires_content_encryption(&self, realm_id: &str) -> bool {
        encryption_profile_requires_content_encryption(
            self.realm_encryption_profile(realm_id).as_deref(),
        )
    }

    /// Effective Realm `content_encryption_floor` projected from the
    /// `ak.component.realm.policy_bundle.v1` cell. `None` means the spec
    /// default `allow_plaintext`. Independent of `encryption_profile`, which
    /// only declares the encryption mechanism (realm-and-space.md §2.3).
    pub fn realm_content_encryption_floor(&self, realm_id: &str) -> Option<String> {
        let components = self.realm_policy_bundle_cell_value(realm_id)?;
        policy_floor_field(components, "content_encryption_floor").map(ToOwned::to_owned)
    }

    /// Effective Realm `metadata_encryption_floor` projected from the
    /// `ak.component.realm.policy_bundle.v1` cell. `None` means the
    /// reducer default is inferred elsewhere (`e2ee_required` for MLS /
    /// e2ee_required Realms, else `allow_plaintext`).
    pub fn realm_metadata_encryption_floor(&self, realm_id: &str) -> Option<String> {
        let components = self.realm_policy_bundle_cell_value(realm_id)?;
        policy_floor_field(components, "metadata_encryption_floor").map(ToOwned::to_owned)
    }

    /// Effective Realm `content_scheme` projected from the
    /// `ak.component.realm.policy_bundle.v1` cell. `None` means no scheme has been negotiated
    /// yet — callers treat that as the application-message default
    /// (`mls_rfc9420`). Drives the one-way `content_scheme` ratchet in
    /// `apply_realm_policy_bundle`.
    pub fn realm_content_scheme(&self, realm_id: &str) -> Option<String> {
        self.realm_policy_bundle_cell_value(realm_id)
            .and_then(content_scheme_field)
            .map(ToOwned::to_owned)
    }

    /// Effective Realm `history_visibility` projected from its dedicated cell.
    pub fn realm_history_visibility(&self, realm_id: &str) -> Option<String> {
        self.realm_null_subject_cell_value(
            realm_id,
            arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1,
        )
        .and_then(|value| {
            value
                .get("value")
                .and_then(Value::as_str)
                .or_else(|| value.as_str())
        })
        .map(ToOwned::to_owned)
    }

    /// Effective Realm `durability_policy` (Realm Recovery Key, realm-and-space.md
    /// §2.3.1) projected from the `ak.component.realm.policy_bundle.v1` cell.
    /// `None` means no policy has been declared yet — callers treat that as the
    /// spec default `mode=none` (no organizational recovery path). Deserialized
    /// into the authoritative SDK [`arkret_models_collaboration::objects::realm::DurabilityPolicy`]
    /// strong type (soland does not redefine the spec shape). The RRK share-acceptance
    /// gate reads this to confirm a recipient is a declared recovery recipient.
    pub fn realm_durability_policy(
        &self,
        realm_id: &str,
    ) -> Option<arkret_models_collaboration::objects::realm::DurabilityPolicy> {
        let components = self.realm_policy_bundle_cell_value(realm_id)?;
        let durability = crate::reducer::durability_policy_field(components)?;
        serde_json::from_value(durability.clone()).ok()
    }

    /// Read the create-locked Realm `security_class` from genesis.
    pub fn realm_security_class(&self, realm_id: &str) -> Option<String> {
        // Security class is create-locked and has no mutable fallback.
        if let Some(genesis) = self.realm_genesis_cell_value(realm_id)
            && let Some(s) = genesis.get("security_class").and_then(Value::as_str)
        {
            return Some(s.to_owned());
        }
        None
    }

    /// Read the effective Realm federation policy from the policy bundle.
    pub fn realm_federation_policy(&self, realm_id: &str) -> Option<String> {
        self.realm_policy_bundle_cell_value(realm_id)
            .and_then(|value| value.get("federation_policy"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
}

fn gate_proofs_have_duplicate_gate_ids(proofs: &[Value]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    for proof in proofs {
        let Some(gate_id) = proof.get("gate_id").and_then(Value::as_str) else {
            return true;
        };
        if gate_id.trim().is_empty() || !seen.insert(gate_id.to_owned()) {
            return true;
        }
    }
    false
}

fn gate_proof_for_gate<'a>(
    proofs: &'a [Value],
    gate_id: &str,
) -> Option<&'a serde_json::Map<String, Value>> {
    proofs.iter().find_map(|proof| {
        let object = proof.as_object()?;
        (object.get("gate_id").and_then(Value::as_str) == Some(gate_id)).then_some(object)
    })
}
