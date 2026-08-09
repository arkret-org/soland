use super::*;

/// Cell family of the registered Realm authority-root singleton.
///
/// `realm_null_subject_cells` keys the Realm-scoped `null`-subject families by
/// their family id, so the wire cell ref constant is split here rather than
/// re-spelled.
const REALM_AUTHORITY_ROOT_FAMILY: &str = arkret_wire::CellFamilyId::REALM_AUTHORITY_ROOT_V1;

/// Re-derive the registered `ak.component.realm.authority_root.v1` genesis
/// value from an `ak.realm.create` payload.
///
/// `realm-and-space.md` §2.5 makes this the sixth genesis write and the only
/// authority a Realm has at genesis: there is no founding grant. The value is
/// recomputed through the SDK's own projection type instead of being read off a
/// producer field, so a receiver can never be talked into a different
/// controller, epoch, generation, or registry basis than the signed create
/// payload derives.
fn genesis_authority_root_value(
    payload_object: Option<&serde_json::Map<String, Value>>,
    created_by: &str,
) -> Result<Value, &'static str> {
    let object = payload_object.ok_or("realm_authority_root_missing")?;
    let digest = object
        .get("capability_action_registry_digest")
        .and_then(Value::as_str)
        .ok_or("realm_authority_root_missing")?;
    let digest = arkret_identifiers::Hash::new(digest.to_owned())
        .map_err(|_| "realm_authority_root_conflict")?;
    let controller =
        arkret_identifiers::Did::new(created_by).map_err(|_| "realm_authority_root_conflict")?;
    serde_json::to_value(
        arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(controller, digest),
    )
    .map_err(|_| "realm_authority_root_conflict")
}

/// The registry-projected authority-root write of this create Event, when the
/// caller supplied the contract projection.
fn registered_authority_root_write(writes: &[ProjectedCellWrite]) -> Option<Value> {
    writes
        .iter()
        .find(|write| write.cell.as_str() == arkret_wire::REALM_AUTHORITY_ROOT_CELL)
        .and_then(|write| write.as_direct())
        .and_then(|effect| effect.op.value)
}

impl ProjectionState {
    /// Apply `ak.realm.upgrade` to the canonical reducer-profile singleton.
    /// The current profile interprets the Event and must register the target
    /// as a direct upgrade edge before the cell can change.
    pub(crate) fn apply_realm_upgrade(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(current) = self.realm_reducer_profile(&realm_id).map(ToOwned::to_owned) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::DEPENDENCY_MISSING.to_owned(),
            };
        };
        let Some(target) = operation
            .payload
            .get("target_reducer_profile")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if target != arkret_wire::CORE_REDUCER_PROFILE
            || !arkret_policy::generated::profiles::is_reducer_profile_id(target)
            || !arkret_policy::generated::profiles::can_upgrade_reducer_profile(&current, target)
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::PROFILE_UNSUPPORTED.to_owned(),
            };
        }
        self.realm_null_subject_cells.insert(
            (
                realm_id.clone(),
                format!(
                    "ak:cell:{}:null",
                    arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1
                ),
            ),
            CellState::Value(Value::String(target.to_owned())),
        );
        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: arkret_wire::EventKind::RealmUpgrade.as_str().to_owned(),
        }
    }

    /// Current value of this Realm's registered authority-root cell.
    ///
    /// The controller named here holds effective `ak.realm.owner`
    /// (`authz/capabilities.md` §3.2). `realm_states[..].owner` is a
    /// discardable presentation mirror and MUST NOT be consulted for
    /// authorization.
    pub fn realm_authority_root(
        &self,
        realm_id: &str,
    ) -> Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue> {
        serde_json::from_value(
            self.realm_null_subject_cell_value(realm_id, REALM_AUTHORITY_ROOT_FAMILY)?
                .clone(),
        )
        .ok()
    }

    /// Registry snapshot the Realm's authority root was established against.
    pub fn realm_authority_registry_basis(&self, realm_id: &str) -> Option<arkret_wire::Hash> {
        self.realm_authority_root(realm_id)
            .map(|root| root.capability_action_registry_digest)
    }

    /// Apply one of the three root-cell CAS transitions. The registry-derived
    /// CBA write remains the canonical state transition; this method enforces
    /// the semantic guards and keeps the structured projection mirror in sync.
    pub(crate) fn apply_realm_authority_transition(
        &mut self,
        operation: &Operation,
        kind: arkret_wire::EventKind,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(mut root) = self.realm_authority_root(&realm_id) else {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_root_missing".to_owned(),
            };
        };
        if operation.context.sender != root.controller_id {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_controller_mismatch".to_owned(),
            };
        }
        if operation.payload.get("realm_id").and_then(Value::as_str) != Some(realm_id.as_str()) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let expected_digest = match arkret_canonical::canonical_sha256(&root) {
            Ok(digest) => digest,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: "realm_authority_root_conflict".to_owned(),
                };
            }
        };
        if operation
            .payload
            .get("expected_state_digest")
            .and_then(Value::as_str)
            != Some(expected_digest.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_root_conflict".to_owned(),
            };
        }

        match &kind {
            arkret_wire::EventKind::RealmOwnerTransfer => {
                let typed =
                    operation.typed_payload::<arkret_wire::event_spec::RealmOwnerTransfer>();
                let Ok(payload) = typed else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                if payload.patch.controller_epoch != root.controller_epoch.saturating_add(1)
                    || self
                        .member(&realm_id, payload.patch.controller_id.as_str())
                        .is_none_or(|member| member.state != "join")
                    || serde_json::to_value(&payload.successor_acceptance)
                        .ok()
                        .is_none_or(|proof| match proof {
                            Value::String(value) => value.is_empty(),
                            Value::Object(value) => value.is_empty(),
                            _ => true,
                        })
                {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_controller_mismatch".to_owned(),
                    };
                }
                root.controller_id = payload.patch.controller_id;
                root.controller_epoch = payload.patch.controller_epoch;
            }
            arkret_wire::EventKind::RealmAuthorityReset => {
                let typed =
                    operation.typed_payload::<arkret_wire::event_spec::RealmAuthorityReset>();
                let Ok(payload) = typed else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                if payload.destructive_confirmation != kind.as_str()
                    || payload.patch.authority_generation
                        != root.authority_generation.saturating_add(1)
                {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_root_conflict".to_owned(),
                    };
                }
                root.authority_generation = payload.patch.authority_generation;
            }
            arkret_wire::EventKind::RealmAuthorityBasisUpdate => {
                let typed =
                    operation.typed_payload::<arkret_wire::event_spec::RealmAuthorityBasisUpdate>();
                let Ok(payload) = typed else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                if arkret_policy::require_registry_basis(Some(
                    &payload.patch.capability_action_registry_digest,
                ))
                .is_err()
                {
                    return ProjectionEffect::Rejected {
                        reason: "capability_registry_basis_unavailable".to_owned(),
                    };
                }
                root.capability_action_registry_digest =
                    payload.patch.capability_action_registry_digest;
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        }

        let Ok(value) = serde_json::to_value(root) else {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_root_conflict".to_owned(),
            };
        };
        self.realm_null_subject_cells.insert(
            (
                realm_id.clone(),
                arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            ),
            CellState::Value(value),
        );
        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind
                .as_str()
                .strip_prefix("ak.realm.")
                .unwrap_or(kind.as_str())
                .to_owned(),
        }
    }

    pub(crate) fn apply_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(new_state) = operation.payload.get("membership").and_then(Value::as_str) else {
            return ProjectionEffect::Ignored;
        };
        if !matches!(new_state, "invite" | "join" | "leave" | "ban" | "knock") {
            return ProjectionEffect::Ignored;
        }
        let member = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let realm_id = operation.realm_id.to_string();

        if member.is_empty() {
            return ProjectionEffect::Ignored;
        }
        let current_state = self
            .member(&realm_id, &member)
            .map(|membership| membership.state.as_str())
            .unwrap_or("leave");
        let transition_allowed = matches!(
            (current_state, new_state),
            ("leave", "knock" | "join" | "ban")
                | ("knock", "join" | "leave" | "ban")
                | ("join", "join" | "leave" | "ban")
                | ("ban", "leave")
        );
        if !transition_allowed {
            return ProjectionEffect::Rejected {
                reason: "invalid_membership_transition".to_owned(),
            };
        }

        // Spec 0a5ab85 (`membership_payload` conditional required) — when
        // `membership=join`, the payload MUST carry `actor_id` (above) +
        // `delivery_status`; when `delivery_status=routable`, it MUST carry
        // `delivery_binding`. Validate here and reject malformed joins.
        if new_state == "join" {
            if let Err(reason) = self.check_membership_join_admission(operation) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            let delivery_status = operation
                .payload
                .get("delivery_status")
                .and_then(Value::as_str);
            match delivery_status {
                None => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        member = %member,
                        "rejected join without delivery_status (spec 0a5ab85)"
                    );
                    return ProjectionEffect::Ignored;
                }
                Some("routable") => {
                    let Some(binding) = operation
                        .payload
                        .get("delivery_binding")
                        .and_then(Value::as_object)
                    else {
                        tracing::warn!(
                            realm_id = %realm_id,
                            member = %member,
                            "rejected routable join without delivery_binding (spec 0a5ab85)"
                        );
                        return ProjectionEffect::Ignored;
                    };
                    // R1.2 — `ak.realm.delivery_binding_policy` enforcement.
                    // Without a projected policy cell, fail-closed for
                    // routable joins per spec join-policy.md §5.1.3 —
                    // there is no DID Document fallback path. The registered
                    // Direct Conversation founding unit is the sole exception:
                    // contact-and-direct-conversation.md §6 fixes that atomic
                    // sequence as Realm create then peer join, so no policy
                    // event can precede the peer join.
                    let policy_value = self
                        .realm_delivery_binding_policy_cell_value(&realm_id)
                        .cloned()
                        .or_else(|| {
                            self.direct_conversation_bootstrap_delivery_policy(
                                &realm_id, operation, binding,
                            )
                        });
                    let Some(policy) = policy_value else {
                        return ProjectionEffect::Rejected {
                            reason: "delivery_binding_policy_unset".to_owned(),
                        };
                    };
                    if let Err(reason) = enforce_delivery_binding_policy(&policy, binding) {
                        return ProjectionEffect::Rejected {
                            reason: reason.to_owned(),
                        };
                    }
                }
                Some("unroutable") => {
                    // Member is recorded but Realm-scoped delivery is
                    // suppressed until a rebind upgrades to routable.
                }
                Some(other) => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        member = %member,
                        delivery_status = %other,
                        "rejected join with unknown delivery_status"
                    );
                    return ProjectionEffect::Ignored;
                }
            }
        }

        self.project_accepted_membership(
            operation,
            &operation.payload,
            now,
            new_state.to_owned(),
            member,
            realm_id,
        )
    }

    /// Project the final creator-membership slot of an already-validated
    /// ordinary Realm bootstrap unit.
    ///
    /// The closed unit validator has established that this is the genesis
    /// actor's own `leave -> join` transition. Re-running the ordinary join
    /// gate here would reject every invite-only Realm before it can acquire
    /// its first member. Keep the bypass narrow by independently checking the
    /// accepted envelope actor and the receiver-derived FSM write before
    /// materializing the membership projection.
    pub fn apply_validated_realm_bootstrap_membership(
        &mut self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> ProjectionEffect {
        if operation.event_kind != arkret_wire::EventKind::MemberState {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let Some(member) = operation
            .payload
            .get("actor_id")
            .and_then(Value::as_str)
            .filter(|member| !member.is_empty())
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if operation.context.sender.as_str() != member
            || operation.payload.get("membership").and_then(Value::as_str) != Some("join")
            || self.member(operation.realm_id.as_str(), member).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let [write] = cell_writes else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let Ok(cell_id) = arkret_wire::CellId::from_ref(&write.cell) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
            || cell_id.subject() != member
            || !matches!(
                &write.op,
                arkret_wire::cba::ProjectedOp::TransitionTo { to }
                    if to == &Value::String("join".to_owned())
            )
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }

        self.restore_accepted_membership(operation, operation.created_at)
    }

    /// Project the peer-membership slot of an already-validated Direct
    /// Conversation founding unit.
    ///
    /// Unlike an ordinary Realm bootstrap's creator self-join, this Event is
    /// authored by the founder while `payload.actor_id` names the other
    /// participant. The closed three-Event validator has already established
    /// that actor relationship and the exact pair. Keep this reducer-side
    /// bypass scoped to that caller context, and independently require the
    /// Direct Conversation Realm role, the registered bootstrap reason, an
    /// absent prior membership, and the receiver-derived FSM write.
    pub fn apply_validated_direct_conversation_founding_membership(
        &mut self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> ProjectionEffect {
        if operation.event_kind != arkret_wire::EventKind::MemberState
            || !self.realm_is_direct_conversation(operation.realm_id.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let Some(member) = operation
            .payload
            .get("actor_id")
            .and_then(Value::as_str)
            .filter(|member| !member.is_empty())
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if operation.payload.get("membership").and_then(Value::as_str) != Some("join")
            || operation.payload.get("reason").and_then(Value::as_str)
                != Some("direct_conversation_bootstrap")
            || self.member(operation.realm_id.as_str(), member).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let [write] = cell_writes else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let Ok(cell_id) = arkret_wire::CellId::from_ref(&write.cell) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
            || cell_id.subject() != member
            || !matches!(
                &write.op,
                arkret_wire::cba::ProjectedOp::TransitionTo { to }
                    if to == &Value::String("join".to_owned())
            )
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }

        self.restore_accepted_membership(operation, operation.created_at)
    }

    fn direct_conversation_bootstrap_delivery_policy(
        &self,
        realm_id: &str,
        operation: &Operation,
        binding: &serde_json::Map<String, Value>,
    ) -> Option<Value> {
        if !self.realm_is_direct_conversation(realm_id)
            || operation.payload.get("reason").and_then(Value::as_str)
                != Some("direct_conversation_bootstrap")
        {
            return None;
        }

        // A Direct Conversation create projects its creator as the first
        // joined member. Permit this policy-free path only while that creator
        // is still the Realm's sole joined member, never for later additions
        // or rebinds.
        let joined_members = self
            .members
            .values()
            .filter(|member| member.realm_id == realm_id && member.state == "join")
            .count();
        if joined_members != 1 {
            return None;
        }

        let recipient_service_id = binding
            .get("recipient_service_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())?;
        Some(serde_json::json!({
            "allowed_binding_sources": ["explicit"],
            "did_document_default_allowed": false,
            "allowed_recipient_services": [recipient_service_id],
            "required_endorsers": [],
        }))
    }

    /// Restore an already-accepted canonical membership Event into the
    /// reducer's structured cache.
    ///
    /// Admission policy, delivery binding and gate checks ran before the Event
    /// became canonical. Hydration must materialize that accepted truth rather
    /// than re-evaluate it against a partially rebuilt policy projection.
    pub fn restore_accepted_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(new_state) = operation
            .payload
            .get("membership")
            .and_then(Value::as_str)
            .filter(|state| matches!(*state, "invite" | "join" | "leave" | "ban" | "knock"))
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Ignored;
        };
        let Some(member) = operation
            .payload
            .get("actor_id")
            .and_then(Value::as_str)
            .filter(|member| !member.is_empty())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Ignored;
        };
        self.project_accepted_membership(
            operation,
            &operation.payload,
            now,
            new_state,
            member,
            operation.realm_id.to_string(),
        )
    }

    fn project_accepted_membership(
        &mut self,
        operation: &Operation,
        payload: &Value,
        now: chrono::DateTime<chrono::Utc>,
        new_state: String,
        member: String,
        realm_id: String,
    ) -> ProjectionEffect {
        // Side-band data: `role` lives outside the FSM cell and is captured
        // here for the structured cache. `joined_at` is set on the first
        // `join` transition; subsequent transitions preserve the original.
        let role = payload
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_owned();
        let key = (realm_id.clone(), member.clone());
        let previous = self.members.get(&key);
        let invited_at = match new_state.as_str() {
            "invite" => previous.and_then(|m| m.invited_at).or(Some(now)),
            "join" => previous.and_then(|m| {
                m.invited_at
                    .or_else(|| (m.state == "invite").then_some(m.updated_at))
            }),
            _ => previous.and_then(|m| m.invited_at),
        };
        let joined_at = match (new_state.as_str(), previous) {
            ("join", Some(previous)) if previous.state == "join" => previous.joined_at,
            ("join", _) => now,
            (_, Some(previous)) => previous.joined_at,
            _ => now,
        };
        let event_ref = Some(operation.context.event_id.to_string());
        let delivery_status = if new_state == "join" {
            payload
                .get("delivery_status")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        } else {
            None
        };
        let recipient_service_id =
            if new_state == "join" && delivery_status.as_deref() == Some("routable") {
                payload
                    .get("delivery_binding")
                    .and_then(Value::as_object)
                    .and_then(|binding| binding.get("recipient_service_id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
            } else {
                None
            };
        let delivery_binding_frontier =
            if new_state == "join" && delivery_status.as_deref() == Some("routable") {
                payload
                    .get("delivery_binding")
                    .and_then(Value::as_object)
                    .and_then(|binding| binding.get("delivery_binding_frontier"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
                    .or_else(|| event_ref.clone())
            } else {
                None
            };
        let remove_membership_frontier = matches!(new_state.as_str(), "leave" | "ban").then(|| {
            vec![
                event_ref
                    .clone()
                    .unwrap_or_else(|| operation.operation_id.as_str().to_owned()),
            ]
        });

        // Update the structured cache with side-band + FSM state mirror.
        self.members.insert(
            key.clone(),
            SolandMembershipState {
                member: member.clone(),
                realm_id: realm_id.clone(),
                state: new_state.to_owned(),
                role,
                delivery_status,
                recipient_service_id,
                membership_event_ref: event_ref,
                delivery_binding_frontier,
                invited_at,
                joined_at,
                updated_at: now,
                reason: payload
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned),
            },
        );
        if matches!(new_state.as_str(), "leave" | "ban") {
            let updated_by = operation.context.sender.as_str();
            self.enqueue_realm_mls_member_removal(
                &realm_id,
                &member,
                new_state.as_str(),
                remove_membership_frontier.clone().unwrap_or_default(),
                now,
            );
            self.cascade_realm_member_removal_to_circles(
                &realm_id,
                &member,
                new_state.as_str(),
                updated_by,
                remove_membership_frontier.unwrap_or_default(),
                now,
            );
        }

        // Synthesize the FSM cell state. Cell ref shape per spec
        // `ak:cell:ak.component.member.state.v1:<actor_id>` — note the
        // cell_subject is `actor_id` (per-actor), not (realm_id, actor)
        // composite. The Realm scoping is implicit in the CellStore key.
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.member.state.v1:{member}"
        )) {
            self.cells.insert(
                cell_id,
                CellState::Value(Value::String(new_state.to_owned())),
            );
        }

        // join-policy.md §7 — project the candidate profile-private
        // application / review / cancel sub-payloads carried on this
        // `ak.member.state` event into the application-review workflow cache.

        ProjectionEffect::MembershipChanged {
            realm_id,
            member,
            action: new_state.to_owned(),
        }
    }

    /// Queue the cryptographic removal for every Realm-default MLS group.
    ///
    /// Realm membership and MLS membership are separate state machines.  The
    /// accepted `ak.member.state` transition advances the governance frontier;
    /// it must not silently leave the removed principal in the Realm-default
    /// MLS group.  Circle obligations are queued separately by
    /// `cascade_realm_member_removal_to_circles`.
    fn enqueue_realm_mls_member_removal(
        &mut self,
        realm_id: &str,
        member: &str,
        trigger_membership: &str,
        membership_frontier: Vec<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let group_refs = self
            .mls_commit_epochs
            .values()
            .filter(|row| {
                row.effective_scope.get("kind").and_then(Value::as_str) == Some("realm")
                    && row.effective_scope.get("realm_id").and_then(Value::as_str) == Some(realm_id)
            })
            .map(|row| row.group_id.clone())
            .collect::<Vec<_>>();
        for group_ref in group_refs {
            let duplicate = self.pending_mls_removals.iter().any(|obligation| {
                obligation.realm_id == realm_id
                    && obligation.circle_id.is_none()
                    && obligation.mls_group_ref.as_deref() == Some(group_ref.as_str())
                    && obligation.actor_id == member
                    && obligation.membership_frontier == membership_frontier
            });
            if duplicate {
                continue;
            }
            self.pending_mls_removals.push(MlsRemoveObligation {
                realm_id: realm_id.to_owned(),
                circle_id: None,
                mls_group_ref: Some(group_ref),
                actor_id: member.to_owned(),
                device_id: None,
                membership_frontier: membership_frontier.clone(),
                trigger_membership: trigger_membership.to_owned(),
                triggered_at: now,
            });
        }
    }

    fn cascade_realm_member_removal_to_circles(
        &mut self,
        realm_id: &str,
        member: &str,
        trigger_membership: &str,
        updated_by: &str,
        membership_frontier: Vec<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let mut removed_circle_ids = Vec::new();
        for circle in self
            .circles
            .values_mut()
            .filter(|circle| circle.realm_id == realm_id)
        {
            if !circle.members.remove(member) {
                continue;
            }
            removed_circle_ids.push(circle.circle_id.clone());
            circle.updated_by = Some(updated_by.to_owned());
            circle.updated_at = Some(now);
            if circle.encryption_profile == "mls_rfc9420" {
                self.pending_mls_removals.push(MlsRemoveObligation {
                    realm_id: realm_id.to_owned(),
                    circle_id: Some(circle.circle_id.clone()),
                    mls_group_ref: circle.mls_group_ref.clone(),
                    actor_id: member.to_owned(),
                    device_id: None,
                    membership_frontier: membership_frontier.clone(),
                    trigger_membership: trigger_membership.to_owned(),
                    triggered_at: now,
                });
            }
        }
        for circle_id in removed_circle_ids {
            let previous = self
                .circle_memberships
                .get(&(circle_id.clone(), member.to_owned()))
                .cloned();
            self.circle_memberships.insert(
                (circle_id.clone(), member.to_owned()),
                CircleMembershipState {
                    circle_id,
                    member: member.to_owned(),
                    state: trigger_membership.to_owned(),
                    invited_at: previous
                        .as_ref()
                        .and_then(|membership| membership.invited_at),
                    joined_at: previous
                        .as_ref()
                        .map(|membership| membership.joined_at)
                        .unwrap_or(now),
                    updated_at: now,
                },
            );
        }
    }

    pub fn cascade_controller_agent_memberships(
        &mut self,
        realm_id: &str,
        controller_id: &str,
        agent_ids: &[String],
        updated_by: &str,
        membership_frontier: Vec<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<String> {
        let mut removed = Vec::new();
        for agent_id in agent_ids {
            let key = (realm_id.to_owned(), agent_id.clone());
            let Some(previous) = self.members.get(&key).cloned() else {
                continue;
            };
            if previous.state != "join" {
                continue;
            }
            self.members.insert(
                key,
                SolandMembershipState {
                    state: "leave".to_owned(),
                    delivery_status: None,
                    recipient_service_id: None,
                    delivery_binding_frontier: None,
                    membership_event_ref: membership_frontier.first().cloned(),
                    updated_at: now,
                    reason: Some(
                        arkret_wire::error_codes::ReasonCode::CONTROLLER_MEMBERSHIP_ENDED
                            .to_owned(),
                    ),
                    ..previous
                },
            );
            if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
                "ak:cell:ak.component.member.state.v1:{agent_id}"
            )) {
                self.cells
                    .insert(cell_id, CellState::Value(Value::String("leave".to_owned())));
            }
            self.enqueue_realm_mls_member_removal(
                realm_id,
                agent_id,
                "leave",
                membership_frontier.clone(),
                now,
            );
            self.cascade_realm_member_removal_to_circles(
                realm_id,
                agent_id,
                "leave",
                updated_by,
                membership_frontier.clone(),
                now,
            );
            removed.push(agent_id.clone());
        }
        if !removed.is_empty() {
            tracing::info!(
                realm_id,
                controller_id,
                removed_agents = removed.len(),
                "cascaded controller membership removal to native personal agents"
            );
        }
        removed
    }

    /// COT-06-004 — apply `ak.realm.set_default_strand`. Points the Realm's
    /// `default_strand_id` at `payload.strand_id`. The named Strand MUST already be
    /// projected in this Realm (else `failed_precondition` — no dangling
    /// pointer). Optional `expected_default_strand_id` is an optimistic-
    /// concurrency CAS guard: when present it MUST equal the current
    /// `default_strand_id` (or both null), else `cas_mismatch`.
    ///
    /// Authorization (actor holds `ak.realm.set_default_strand` / `ak.realm.admin`
    /// on the Realm, or owns it) is enforced at ingest in
    /// `routing::events::operations::policy::validate_set_default_strand_policy`,
    /// mirroring the ban / moderation capability gates. The reducer does the
    /// structural acceptance check only.
    pub(crate) fn apply_realm_set_default_strand(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "set_default_strand_strand_id_missing".to_owned(),
            };
        };

        // failed_precondition: the target Strand MUST already be projected in
        // this Realm. Prevents a dangling default pointer.
        match self.strands.get(&strand_id) {
            Some(strand) if strand.realm_id == realm_id => {}
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "set_default_strand_strand_realm_mismatch".to_owned(),
                };
            }
            None => {
                return ProjectionEffect::Rejected {
                    reason: "failed_precondition".to_owned(),
                };
            }
        }

        // Optimistic-concurrency CAS guard. `expected_default_strand_id` is
        // `oneOf[strand_id, null]`: when the field is present (including an
        // explicit JSON null), it MUST match the current pointer.
        if let Some(expected) = operation.payload.get("expected_default_strand_id") {
            let current = self
                .realm_states
                .get(&realm_id)
                .and_then(|realm| realm.default_strand_id.as_deref());
            let expected = expected.as_str();
            if expected != current {
                return ProjectionEffect::Rejected {
                    reason: "cas_mismatch".to_owned(),
                };
            }
        }

        // Structured cache: set the Realm default-Strand pointer. Create a
        // minimal Realm row if we somehow haven't projected a create yet
        // (federation backfill ordering tolerance).
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| SolandRealmState {
                realm_id: realm_id.clone(),
                owner: None,
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            });
        realm.default_strand_id = Some(strand_id.clone());
        realm.updated_at = now;

        ProjectionEffect::RealmDefaultStrandSet {
            realm_id,
            strand_id,
        }
    }

    /// The registered cell family that backs `ak.realm.profile` display state
    /// and its CAS-register / bottom mechanics. Its
    /// wire subject is the literal `null`; `realm_id` is the enclosing
    /// CellStore namespace and remains a side-band map key.
    ///
    /// This is deliberately NOT `ak.component.realm.organization.v1`: that
    /// cell family is the organization-authorized relationship statement
    /// surface (`ak.realm.organization`, cell subject
    /// `(organization_id, relationship)`) and must not be overwritten by
    /// Realm profile writes. The accepted SDK CellStore projection is the
    /// source of truth for conflict state; this service-local mirror must not
    /// infer concurrency from incomparable operation and Seal identifiers.
    #[cfg(test)]
    pub(crate) fn realm_profile_cell_id() -> Option<CellRef> {
        CellRef::new(arkret_wire::REALM_PROFILE_CELL.to_owned()).ok()
    }

    pub fn check_bottom_cell_transition(&self, operation: &Operation) -> Result<(), &'static str> {
        match crate::kinds::canonical_kind_for_operation(operation) {
            Some(arkret_wire::EventKind::RealmProfile) => {
                let realm_id = operation.realm_id.to_string();
                if matches!(
                    self.realm_profile_cells.get(&realm_id),
                    Some(CellState::Bottom(_))
                ) {
                    return Err("cell_bottom_state");
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Apply a `ak.realm.*` lifecycle event. Stream-F (Wave 1B) rewrite
    /// of the former Realm lifecycle reducer: the function is now
    /// restricted to the canonical Realm lifecycle kinds
    /// (`ak.realm.create`, `ak.realm.profile`, `ak.realm.archive`,
    /// `ak.realm.tombstone`, `ak.realm.destroy`). Space-container lifecycle
    /// (`ak.space.create` / `update` / `parent` / `archive` / `restore`
    /// / `tombstone`) is handled by `apply_space_container_*`
    /// in this same impl block — they were already separate methods
    /// before this rename, so no extraction was needed.
    ///
    /// Spec seals:
    ///   - `realm-and-space.md` §2.5 (terminal state distinction: tombstone vs destroy)
    ///   - `realm-and-space.md` §2.5.1 (destroy cascade rules)
    ///   - `realm-and-space.md` §2.5.2 (erasure receipt fanout — reducer leg only; the actual
    ///     federation push lives outside)
    pub(crate) fn apply_realm_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        kind: arkret_wire::EventKind,
    ) -> ProjectionEffect {
        // Defensive: only canonical Realm-lifecycle kinds may
        // reach this function. The dispatch table enforces this; the
        // assertion keeps internal callers honest.
        debug_assert!(
            matches!(
                &kind,
                arkret_wire::EventKind::RealmCreate
                    | arkret_wire::EventKind::RealmProfile
                    | arkret_wire::EventKind::RealmArchive
                    | arkret_wire::EventKind::RealmFreeze
                    | arkret_wire::EventKind::RealmTombstone
                    | arkret_wire::EventKind::RealmDestroy
            ),
            "apply_realm_lifecycle dispatched with non-realm kind: {kind}",
        );

        // Keep the structured cache and the canonical cells map in sync.
        //
        // Per spec event-kind-registry, each ak.realm.* lifecycle event
        // writes a distinct cell family with its own lattice:
        //   ak.realm.create     → ak.component.realm.create.v1  (genesis singleton)
        //   ak.realm.profile    → ak.component.realm.profile.v1 (cas-register, singleton)
        //   ak.realm.archive    → ak.component.realm.archive.v1 (cas-register, singleton)
        //   ak.realm.freeze     → ak.component.realm.freeze.v1 (cas-register, singleton)
        //   ak.realm.tombstone  → ak.component.realm.tombstone.v1 (cas-register, singleton)
        //   ak.realm.destroy    → ak.component.realm.destroy.v1 (cas-register, singleton)
        //
        // Stream-F (Wave 1B): tombstone and destroy are both terminal but
        // write distinct cell families. Bottom = reject; a second
        // terminal-state write rejects with `realm_already_terminal`.
        let payload_object = operation.payload.get("object").and_then(Value::as_object);
        let realm_id = operation.realm_id.to_string();
        let create_reducer_profile = if kind == arkret_wire::EventKind::RealmCreate {
            let Some(profile) = payload_object
                .and_then(|object| object.get("reducer_profile"))
                .and_then(Value::as_str)
            else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            if profile != arkret_wire::CORE_REDUCER_PROFILE
                || !arkret_policy::generated::profiles::is_reducer_profile_id(profile)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::PROFILE_UNSUPPORTED.to_owned(),
                };
            }
            Some(profile.to_owned())
        } else {
            None
        };
        let creator = if kind == arkret_wire::EventKind::RealmCreate {
            registered_authority_root_write(self.projected_cell_writes()).and_then(|value| {
                value
                    .get("controller_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        } else {
            None
        };
        let owner = operation
            .payload
            .get("owner")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| creator.clone());
        // Display state is carried only by `ak.realm.profile`.
        let title = operation
            .payload
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        // Security class is create-locked genesis state. Federation policy is
        // independently validated by the policy-bundle reducer.
        // Round 4 (B1.2) — capture (and validate against any existing
        // locked value) the Realm trust_domain.
        let payload_trust_domain = operation
            .payload
            .get("trust_domain")
            .or_else(|| payload_object.and_then(|object| object.get("trust_domain")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_digest_algorithm = operation
            .payload
            .get("digest_algorithm")
            .or_else(|| payload_object.and_then(|object| object.get("digest_algorithm")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "sha256".to_owned());
        if arkret_canonical::digest_suite(&payload_digest_algorithm).is_err() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::UNSUPPORTED_DIGEST_ALGORITHM.to_owned(),
            };
        }
        if let Some(ref new_td) = payload_trust_domain {
            // Shape MUST be `ak:trust_domain:<scope>` — delegate to SDK
            // typed id validator.
            if arkret_identifiers::TypedTrustDomainId::new(new_td.clone()).is_err() {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
            // Compare against any prior locked value. Any mismatch is a
            // cross-domain replay attempt: a peer is trying to relabel a
            // Realm into a different trust domain.
            if let Some(existing) = self.realm_states.get(&realm_id)
                && let Some(locked_td) = existing.trust_domain.as_deref()
                && locked_td != new_td.as_str()
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED.to_owned(),
                };
            }
        }

        // Stream-F (Wave 1B): terminal-state preflight. A Realm already
        // in `tombstoned` or `destroyed` state MUST NOT accept another
        // terminal-state write (cell family is cas-register with
        // bottom=reject; the structured cache mirrors that).
        if let Some(existing) = self.realm_states.get(&realm_id)
            && existing.terminal_state.is_some()
            && matches!(
                &kind,
                arkret_wire::EventKind::RealmTombstone | arkret_wire::EventKind::RealmDestroy
            )
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_terminal".to_owned(),
            };
        }

        // Stream-F (Wave 1B): ak.realm.tombstone preconditions. The
        // event MUST carry a syntactically valid `successor_realm_id`
        // pointing at a `ak:realm:<44-char-token>` distinct from the
        // terminating Realm. Absent → `missing_successor`; malformed →
        // `schema_violation`; self-reference → `successor_self_reference`.
        let payload_successor_realm_id = operation
            .payload
            .get("successor_realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if kind == arkret_wire::EventKind::RealmTombstone {
            match payload_successor_realm_id.as_deref() {
                None => {
                    return ProjectionEffect::Rejected {
                        reason: "missing_successor".to_owned(),
                    };
                }
                Some(id) => {
                    if arkret_identifiers::RealmId::new(id).is_err() {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                        };
                    }
                    if id == realm_id {
                        return ProjectionEffect::Rejected {
                            reason: "successor_self_reference".to_owned(),
                        };
                    }
                }
            }
        }
        // ak.realm.destroy MUST NOT carry successor_realm_id (spec §2.5).
        if kind == arkret_wire::EventKind::RealmDestroy && payload_successor_realm_id.is_some() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }

        if kind == arkret_wire::EventKind::RealmCreate && self.realm_create_log(&realm_id).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_exists".to_owned(),
            };
        }

        // `realm-and-space.md` §2.5 — genesis registers five cell writes and
        // the authority root is one of them. Derive it before any structured
        // cache mutation so a create that cannot establish an authority root
        // rejects the whole atomic bootstrap unit instead of materializing a
        // Realm nobody can govern.
        let authority_root = if kind == arkret_wire::EventKind::RealmCreate {
            let projected = registered_authority_root_write(self.projected_cell_writes());
            let derived = match creator.as_deref() {
                Some(creator) => match genesis_authority_root_value(payload_object, creator) {
                    Ok(value) => value,
                    Err(reason) => {
                        return ProjectionEffect::Rejected {
                            reason: reason.to_owned(),
                        };
                    }
                },
                None => match projected.clone() {
                    Some(value) => value,
                    None => {
                        return ProjectionEffect::Rejected {
                            reason: "realm_authority_root_conflict".to_owned(),
                        };
                    }
                },
            };
            // When the caller supplied the registry projection of the signed
            // Event, the two derivations must agree byte-for-byte: the value is
            // a `state_root` leaf preimage, so a divergence is a forked genesis.
            if let Some(projected) = projected
                && projected != derived
            {
                return ProjectionEffect::Rejected {
                    reason: "realm_authority_root_conflict".to_owned(),
                };
            }
            Some(derived)
        } else {
            None
        };

        // Structured cache mirror.
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| SolandRealmState {
                realm_id: realm_id.clone(),
                owner: owner.clone(),
                title: title.clone(),
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: payload_trust_domain.clone(),
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            });
        // `morph.md` §4.1 S3 — merge any declared opt-in conformance profile
        // ids from canonical genesis `schema_refs[]` into the Realm's growing
        // profile set. Later declarations have the dedicated `ak.realm.schema`
        // carrier; this lifecycle path never infers them from the removed
        // monolithic Realm update payload.
        for profile in realm_declared_profiles(operation) {
            if !realm.active_profiles.contains(&profile) {
                realm.active_profiles.push(profile);
            }
        }
        // Lock trust_domain on first observation (ak.realm.create). The
        // mismatch case is already rejected above; here we only set the
        // value when it has not yet been captured.
        if realm.trust_domain.is_none()
            && let Some(td) = payload_trust_domain.clone()
        {
            realm.trust_domain = Some(td);
        }
        // Stream-F (Wave 1B): both terminal-state events flip the
        // summary `deleted` flag. The richer `terminal_state` /
        // `successor_realm_id` fields are the source of truth.
        if kind == arkret_wire::EventKind::RealmDestroy
            || kind == arkret_wire::EventKind::RealmTombstone
        {
            realm.deleted = true;
        }
        if kind == arkret_wire::EventKind::RealmTombstone {
            realm.terminal_state = Some("tombstoned".to_owned());
            realm.successor_realm_id = payload_successor_realm_id.clone();
        } else if kind == arkret_wire::EventKind::RealmDestroy {
            realm.terminal_state = Some("destroyed".to_owned());
            realm.successor_realm_id = None;
        } else if kind == arkret_wire::EventKind::RealmArchive {
            realm.archived = operation
                .payload
                .get("archived")
                .and_then(Value::as_bool)
                .unwrap_or(true);
        } else if kind == arkret_wire::EventKind::RealmFreeze {
            realm.frozen = operation
                .payload
                .get("frozen")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            realm.freeze_expires_at = operation
                .payload
                .get("freeze_expires_at")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&chrono::Utc));
        }
        if owner.is_some() {
            realm.owner.clone_from(&owner);
        }
        if title.is_some() {
            realm.title.clone_from(&title);
        }
        realm.updated_at = now;

        // Cells map: synth a CellState::Value per the spec cell family
        // for this canonical kind.
        match kind {
            k if k == arkret_wire::EventKind::RealmCreate => {
                self.realm_create_cells.insert(
                    realm_id.clone(),
                    CellState::Value(Value::Array(vec![Value::String(realm_id.clone())])),
                );
                if let Some(genesis) = payload_object {
                    self.realm_null_subject_cells.insert(
                        (realm_id.clone(), arkret_wire::REALM_GENESIS_CELL.to_owned()),
                        CellState::Value(Value::Object(genesis.clone())),
                    );
                }
                if let Some(notary) = payload_object.and_then(|object| object.get("notary")) {
                    self.realm_notary_cells
                        .insert(realm_id.clone(), CellState::Value(notary.clone()));
                }
                if let Some(authority_root) = authority_root {
                    self.realm_null_subject_cells.insert(
                        (
                            realm_id.clone(),
                            arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
                        ),
                        CellState::Value(authority_root),
                    );
                }
                if let Some(reducer_profile) = create_reducer_profile {
                    self.realm_null_subject_cells.insert(
                        (
                            realm_id.clone(),
                            format!(
                                "ak:cell:{}:null",
                                arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1
                            ),
                        ),
                        CellState::Value(Value::String(reducer_profile)),
                    );
                }
            }
            k if k == arkret_wire::EventKind::RealmProfile => {
                self.realm_profile_cells.insert(
                    realm_id.clone(),
                    CellState::Value(operation.payload.clone()),
                );
            }
            k if k == arkret_wire::EventKind::RealmArchive => {
                let mut value = serde_json::Map::new();
                value.insert(
                    "archived".to_owned(),
                    operation
                        .payload
                        .get("archived")
                        .cloned()
                        .unwrap_or(Value::Bool(true)),
                );
                if let Some(reason) = operation.payload.get("reason").cloned() {
                    value.insert("reason".to_owned(), reason);
                }
                value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                value.insert(
                    "operation_id".to_owned(),
                    Value::String(operation.operation_id.as_str().to_owned()),
                );
                self.realm_null_subject_cells.insert(
                    (
                        realm_id.clone(),
                        "ak:cell:ak.component.realm.archive.v1:null".to_owned(),
                    ),
                    CellState::Value(Value::Object(value)),
                );
            }
            k if k == arkret_wire::EventKind::RealmFreeze => {
                let mut value = serde_json::Map::new();
                value.insert(
                    "frozen".to_owned(),
                    operation
                        .payload
                        .get("frozen")
                        .cloned()
                        .unwrap_or(Value::Bool(true)),
                );
                if let Some(reason) = operation.payload.get("reason").cloned() {
                    value.insert("reason".to_owned(), reason);
                }
                if let Some(freeze_expires_at) = operation.payload.get("freeze_expires_at").cloned()
                {
                    value.insert("freeze_expires_at".to_owned(), freeze_expires_at);
                }
                value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                value.insert(
                    "operation_id".to_owned(),
                    Value::String(operation.operation_id.as_str().to_owned()),
                );
                self.realm_null_subject_cells.insert(
                    (
                        realm_id.clone(),
                        "ak:cell:ak.component.realm.freeze.v1:null".to_owned(),
                    ),
                    CellState::Value(Value::Object(value)),
                );
            }
            k if k == arkret_wire::EventKind::RealmTombstone => {
                // Stream-F (Wave 1B): tombstone writes its own terminal
                // cell with `successor_realm_id` so peers hydrating from
                // cells alone can distinguish migration from destroy.
                let value = serde_json::json!({
                    "terminal_kind": "tombstoned",
                    "tombstoned": true,
                    "successor_realm_id": payload_successor_realm_id,
                    "at": arkret_canonical::format_timestamp_canonical(now),
                    "operation_id": operation.operation_id.as_str(),
                });
                self.realm_null_subject_cells.insert(
                    (
                        realm_id.clone(),
                        "ak:cell:ak.component.realm.tombstone.v1:null".to_owned(),
                    ),
                    CellState::Value(value),
                );
                // Tombstone keeps child Space/Strand placement live:
                // succession transfers the navigation surface to the
                // successor Realm. Spec §2.5 row "tombstone" — no
                // realm_destroyed_orphan cascade fires here.
            }
            k if k == arkret_wire::EventKind::RealmDestroy => {
                // cas-register: terminal {destroyed: true, at: ts}.
                let value = serde_json::json!({
                    "terminal_kind": "destroyed",
                    "destroyed": true,
                    "at": arkret_canonical::format_timestamp_canonical(now),
                    "operation_id": operation.operation_id.as_str(),
                });
                self.realm_null_subject_cells.insert(
                    (
                        realm_id.clone(),
                        "ak:cell:ak.component.realm.destroy.v1:null".to_owned(),
                    ),
                    CellState::Value(value),
                );
                // Stream-F (Wave 1B): destroy cascade per spec
                // §2.5.1 ¶6 + ¶7.
                self.cascade_realm_destroy(&realm_id);
            }
            _ => {}
        }

        // `contact-and-direct-conversation.md` section 6.1 fixes the founder
        // membership as a reducer projection of the Direct Conversation
        // genesis Event. The peer remains the unit's sole explicit membership
        // Event. Ordinary Realm creates intentionally do not take this branch:
        // their creator membership is an explicit final bootstrap slot.
        if kind == arkret_wire::EventKind::RealmCreate
            && payload_object
                .and_then(|object| object.get("purpose"))
                .and_then(Value::as_str)
                == Some("direct_conversation")
            && let Some(founder) = creator
        {
            let founder_payload = serde_json::json!({
                "actor_id": founder,
                "membership": "join",
                "role": "member",
                "reason": "direct_conversation_bootstrap"
            });
            let _ = self.project_accepted_membership(
                operation,
                &founder_payload,
                now,
                "join".to_owned(),
                founder.to_string(),
                realm_id.clone(),
            );
        }

        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind.strip_prefix("ak.realm.").unwrap_or(kind).to_owned(),
        }
    }

    /// Stream-F (Wave 1B + Wave 2C) — `ak.realm.destroy` child-cascade.
    /// Spec `realm-and-space.md` §2.5.1:
    ///   ¶6 child Space-container placement (same Realm) → mark
    ///      `realm_destroyed_orphan` (locked read-only projection).
    ///   ¶6 cross-Realm `parent_ref` edge pointing at a Space inside
    ///      the destroyed Realm → mark the *referencing* container's
    ///      `parent_ref_locked = true` (Stream-F Wave 2C). The
    ///      referencing Space stays alive in its OWN Realm; only the
    ///      parent edge is downgraded so membership / capability /
    ///      history / E2EE / retention stops propagating across the
    ///      destroy frontier.
    /// AKP-0007: `Strand.discussion_realm_ref` is a removed wire field.
    /// Intra-Realm discussion boundaries now live on a Circle
    /// (`scope_circle_id`) and never cross the Realm frontier, so no
    /// cross-Realm discussion cascade is required here.
    ///
    /// The terminal-state admission check (event_log.rs) prevents
    /// further writes against the destroyed Realm itself, which is the
    /// load-bearing safety property; this cascade applies the
    /// projection-side downgrade so UI / navigation surfaces honour
    /// the destroy frontier without a fresh query against the
    /// terminated Realm.
    pub(crate) fn cascade_realm_destroy(&mut self, destroyed_realm_id: &str) {
        // ¶6 same-Realm child Space-container cascade.
        let mut orphaned_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.realm_id == destroyed_realm_id && !container.orphaned {
                container.orphaned = true;
                orphaned_count += 1;
            }
        }

        // ¶6 cross-Realm parent_ref lazy-link downgrade (Stream-F
        // Wave 2C). Spec realm-and-space.md §2.5.1 ¶6.
        //
        // For every Space across ALL Realms, check whether its
        // `parent_ref` resolves to a Space whose home Realm is the
        // destroyed one. The destroyed Realm's own children are
        // already covered by the `orphaned` pass above; this loop
        // catches the *cross-Realm* edges that target a Space
        // hosted inside the destroyed Realm. Containers stay alive
        // in their own Realms — only the navigation edge is locked.
        //
        // We first snapshot the parent_id lookup so we can mutate
        // the same map without re-borrowing it.
        let parent_home_realms: std::collections::BTreeMap<String, String> = self
            .space_containers
            .iter()
            .map(|(id, c)| (id.clone(), c.realm_id.clone()))
            .collect();
        let mut parent_lock_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.parent_ref_locked {
                continue; // already locked by an earlier destroy frontier
            }
            // Only consider cross-Realm parent edges (same-Realm
            // children of the destroyed Realm are already marked
            // orphaned above; their parent_ref_locked status is
            // implied by the orphaned flag).
            if container.realm_id == destroyed_realm_id {
                continue;
            }
            let Some(parent_id) = container.parent_ref.as_ref() else {
                continue;
            };
            // Resolve the parent's home Realm. If the parent isn't
            // in the projection (federated / not yet replicated),
            // we can't downgrade — leave it for the federation
            // backfill path to catch on next replay.
            let Some(parent_home) = parent_home_realms.get(parent_id) else {
                continue;
            };
            if parent_home == destroyed_realm_id {
                container.parent_ref_locked = true;
                parent_lock_count += 1;
            }
        }

        // AKP-0007: no cross-Realm discussion edges to sever — Circles
        // are intra-Realm and `ak.realm.destroy` already tombstones their
        // parent Realm; further Circle writes fall under the terminal
        // admission check in `event_log::validate_event_envelope`.

        tracing::info!(
            destroyed_realm_id = %destroyed_realm_id,
            orphaned_space_containers = orphaned_count,
            cross_realm_parent_refs_locked = parent_lock_count,
            "stream-F realm.destroy cascade applied"
        );
    }

    /// Stream-F (Wave 1B + Wave 2C) — apply a
    /// `ak.audit.erasure_receipt` event. Stores the receipt in
    /// [`ProjectionState::erasure_receipts`] with validated `outcome` +
    /// `scope.storage_boundary` + `fanout_status` fields. The receipt
    /// is durable; this projection cache backs the
    /// `erasure_receipts_endpoint` server-describe surface.
    ///
    /// `scope.realm_id` is retained so standard Event fanout consumers can
    /// correlate the receipt with its affected Realm.
    pub(crate) fn apply_audit_erasure_receipt(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        // Accept either the inner payload shape (canonical) or a
        // flat object whose top-level fields are receipt fields.
        // Spec `realm-and-space.md` §2.5.2 + erasure-receipt.schema.json.
        let outcome = payload
            .get("outcome")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let outcome = match outcome {
            Some(s) => s,
            None => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        // The canonical schema enumerates 3 outcomes; the spec brief
        // adds `scheduled` / `failed` for the receiving-peer feedback
        // path. We accept all five and let the wire validator enforce
        // the strict canonical set when the schema version requires.
        let valid_outcomes = [
            "completed",
            "partially_completed",
            "blocked_by_legal_hold",
            "scheduled",
            "failed",
        ];
        if !valid_outcomes.contains(&outcome.as_str()) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        // `scope` MUST be present per schema; we only require it to
        // be an object — the wire validator enforces the inner shape.
        let Some(scope) = payload.get("scope").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let storage_boundary = scope
            .get("storage_boundary")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // Stream-F (Wave 2C) — extract the optional scope.realm_id.
        // Drives the federation peer-set selection downstream. Per
        // erasure-receipt.schema.json the field is optional; receipts
        // for account-private erasures (no Realm scope) skip the
        // federation fanout entirely.
        let scope_realm_id = scope
            .get("realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let receipt_id = payload
            .get("receipt_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let issuer = payload
            .get("issuer")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (subject_kind, subject_ref) = payload
            .get("subject")
            .and_then(Value::as_object)
            .map(|s| {
                (
                    s.get("kind").and_then(Value::as_str).map(ToOwned::to_owned),
                    s.get("subject_ref")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                )
            })
            .unwrap_or((None, None));
        let fanout_status = payload
            .get("fanout_status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "pending".to_owned());

        self.erasure_receipts.push(ErasureReceiptRecord {
            receipt_id: receipt_id.clone(),
            issuer,
            subject_kind,
            subject_ref,
            outcome: outcome.clone(),
            storage_boundary,
            scope_realm_id,
            fanout_status,
            recorded_at: now,
            payload: payload.clone(),
        });

        tracing::info!(
            receipt_id = ?receipt_id,
            outcome = %outcome,
            operation_id = %operation.operation_id.as_str(),
            "stream-F erasure_receipt recorded"
        );

        // No dedicated ProjectionEffect variant yet — surface as
        // RealmLifecycle with a synthetic action so existing
        // dispatchers (e.g. the broadcast layer) treat the event as
        // a Realm-level audit signal. TODO(stream-F-followup): add
        // a dedicated `ProjectionEffect::ErasureReceiptRecorded` once
        // the federation layer wants a typed handle.
        ProjectionEffect::RealmLifecycle {
            realm_id: operation.realm_id.to_string(),
            action: "audit.erasure_receipt".to_owned(),
        }
    }
}
