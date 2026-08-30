use arkret_models_collaboration::governance::erasure::{
    ErasureFanoutStatus, ErasureOutcome, ErasureReceipt, ErasureStorageBoundary, ErasureSubjectKind,
};

use super::*;

/// Cell family of the registered Realm authority-root singleton.
///
/// `realm_null_subject_cells` keys the Realm-scoped `null`-subject families by
/// their family id, so the wire cell ref constant is split here rather than
/// re-spelled.
const REALM_AUTHORITY_ROOT_FAMILY: &str = arkret_wire::CellFamilyId::REALM_AUTHORITY_ROOT_V1;
pub const PRINCIPAL_RESOLUTION_CELL: &str = "ak:cell:ak.component.identity.resolution.v1:null";

fn erasure_subject_kind_name(kind: ErasureSubjectKind) -> &'static str {
    match kind {
        ErasureSubjectKind::Principal => "principal",
        ErasureSubjectKind::Space => "space",
        ErasureSubjectKind::Event => "event",
        ErasureSubjectKind::Blob => "blob",
        ErasureSubjectKind::Device => "device",
        ErasureSubjectKind::AccountPrivateState => "account_private_state",
    }
}

fn erasure_storage_boundary_name(boundary: ErasureStorageBoundary) -> &'static str {
    match boundary {
        ErasureStorageBoundary::CanonicalLogMinimization => "canonical_log_minimization",
        ErasureStorageBoundary::BlobStore => "blob_store",
        ErasureStorageBoundary::ProjectionStore => "projection_store",
        ErasureStorageBoundary::AccountPrivateStore => "account_private_store",
        ErasureStorageBoundary::SearchIndex => "search_index",
        ErasureStorageBoundary::PushRoutes => "push_routes",
        ErasureStorageBoundary::DeviceSecretStore => "device_secret_store",
        ErasureStorageBoundary::MediaDerivatives => "media_derivatives",
        ErasureStorageBoundary::ServiceDefined => "service_defined",
    }
}

fn erasure_outcome_name(outcome: ErasureOutcome) -> &'static str {
    match outcome {
        ErasureOutcome::Completed => "completed",
        ErasureOutcome::PartiallyCompleted => "partially_completed",
        ErasureOutcome::BlockedByLegalHold => "blocked_by_legal_hold",
    }
}

fn erasure_fanout_status_name(status: ErasureFanoutStatus) -> &'static str {
    match status {
        ErasureFanoutStatus::Pending => "pending",
        ErasureFanoutStatus::Complete => "complete",
        ErasureFanoutStatus::Incomplete => "incomplete",
    }
}

fn principal_genesis_resolution_value(
    operation: &Operation,
    payload_object: Option<&serde_json::Map<String, Value>>,
) -> Result<Option<Value>, &'static str> {
    let Some(object) = payload_object else {
        return Ok(None);
    };
    if !matches!(
        object.get("purpose").and_then(Value::as_str),
        Some("principal_control" | "managed_agent_control" | "applet_managed_control")
    ) {
        return Ok(None);
    }
    let commitment = object
        .get("initial_resolution")
        .cloned()
        .ok_or("identity_resolution_missing")?;
    let did = commitment
        .get("did")
        .and_then(Value::as_str)
        .ok_or("identity_resolution_invalid")?;
    let did = arkret_wire::Did::new(did.to_owned()).map_err(|_| "identity_resolution_invalid")?;
    let projected =
        arkret_wire::project_did_to_core_id(&did).map_err(|_| "identity_resolution_invalid")?;
    if &projected != operation.context.sender.signing_principal_id()
        || commitment
            .get("method_history_head")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || commitment
            .get("version_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("identity_resolution_invalid");
    }
    let mut projection = commitment
        .as_object()
        .cloned()
        .ok_or("identity_resolution_invalid")?;
    projection.insert(
        "resolution_event_ref".to_owned(),
        Value::String(operation.context.accepted_event_id.to_string()),
    );
    projection.insert(
        "updated_at".to_owned(),
        Value::String(utc_timestamp_z(operation.created_at)),
    );
    Ok(Some(Value::Object(projection)))
}

/// Re-derive the registered `ak.component.realm.authority_root.v1` genesis
/// value from an `ak.realm.create` payload.
///
/// `realm-and-space.md` §2.5 makes this the sixth genesis write and the only
/// authority a Realm has at genesis: there is no founding grant. The value is
/// recomputed through the SDK's own projection type instead of being read off a
/// producer field, so a receiver can never be talked into a different
/// controller, epoch, or generation than the signed create payload derives.
fn genesis_authority_root_value(
    payload_object: Option<&serde_json::Map<String, Value>>,
    created_by: &arkret_wire::ActorId,
) -> Result<Value, &'static str> {
    let _object = payload_object.ok_or("realm_authority_root_missing")?;
    serde_json::to_value(
        arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(created_by.clone()),
    )
    .map_err(|_| "realm_authority_root_conflict")
}

/// The registry-projected authority-root write of this create Event, when the
/// caller supplied the contract projection.
fn registered_authority_root_write(writes: &[ProjectedCellWrite]) -> Option<Value> {
    writes
        .iter()
        .find(|write| write.cell_id.as_str() == arkret_wire::REALM_AUTHORITY_ROOT_CELL)
        .and_then(|write| write.as_direct())
        .and_then(|effect| effect.op.value)
}

fn registered_principal_resolution_write(writes: &[ProjectedCellWrite]) -> Option<Value> {
    writes
        .iter()
        .find(|write| write.cell_id.as_str() == PRINCIPAL_RESOLUTION_CELL)
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
            || !arkret_wire::can_upgrade_reducer_profile(&current, target)
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::UNSUPPORTED_PROFILE.to_owned(),
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

    /// Apply one of the two root-cell CAS transitions. The registry-derived
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
                let Ok(successor_epoch) =
                    arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload::successor_controller_epoch(
                        root.controller_epoch,
                    )
                else {
                    return ProjectionEffect::Rejected {
                        reason: "reducer_projection_failed".to_owned(),
                    };
                };
                if self
                    .member(&realm_id, &payload.patch.controller_id.to_string())
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
                root.controller_epoch = successor_epoch;
            }
            arkret_wire::EventKind::RealmAuthorityReset => {
                let typed =
                    operation.typed_payload::<arkret_wire::event_spec::RealmAuthorityReset>();
                let Ok(payload) = typed else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                if payload.destructive_confirmation != kind.as_str() {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_root_conflict".to_owned(),
                    };
                }
                let Ok(successor_generation) =
                    arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload::successor_authority_generation(
                        root.authority_generation,
                    )
                else {
                    return ProjectionEffect::Rejected {
                        reason: "reducer_projection_failed".to_owned(),
                    };
                };
                root.authority_generation = successor_generation;
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
        let payload = match serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone())
        {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let new_state = match payload.membership {
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join => "join",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Knock => "knock",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave => "leave",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Ban => "ban",
        };
        let member = payload.member_id.to_string();
        let realm_id = operation.realm_id.to_string();
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

        // Delivery is derived from the exact ActorId. Membership carries no
        // parallel routing binding or server sidecar.
        if new_state == "join" {
            if let Err(reason) = self.check_membership_join_admission(operation) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
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
    /// actor's own initial `null -> join` write. Re-running the ordinary join
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
        let Ok(payload) = serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone()) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let member = payload.member_id.to_string();
        let Ok(member_subject) = payload
            .member_id
            .canonical_key()
            .and_then(|key| arkret_wire::composite_subject(&[key]))
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if operation.context.sender != payload.member_id
            || payload.membership
                != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
            || self.member(operation.realm_id.as_str(), &member).is_some()
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
        let Ok(cell_id) = arkret_wire::CellId::from_ref(&write.cell_id) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
            || cell_id.subject() != member_subject
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

    /// Project either explicit membership slot of an already-validated Direct
    /// Conversation founding unit.
    ///
    /// Both Events are authored by the founder: one names the peer and the
    /// final genesis `head_eq null` slot names the founder. The closed
    /// four-Event validator has already established those relationships and
    /// the exact pair. Keep this reducer-side bootstrap bypass scoped to that
    /// caller context and independently require the Direct Conversation Realm
    /// role, registered reason, absent prior membership and derived FSM write.
    pub fn apply_validated_direct_conversation_bootstrap_membership(
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
        let Ok(payload) = serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone()) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let member = payload.member_id.to_string();
        let Ok(member_subject) = payload
            .member_id
            .canonical_key()
            .and_then(|key| arkret_wire::composite_subject(&[key]))
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if payload.membership
                != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
            || payload.reason.as_deref() != Some("direct_conversation_bootstrap")
            || self.member(operation.realm_id.as_str(), &member).is_some()
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
        let Ok(cell_id) = arkret_wire::CellId::from_ref(&write.cell_id) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
            || cell_id.subject() != member_subject
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

    /// Restore an already-accepted canonical membership Event into the
    /// reducer's structured cache.
    ///
    /// Admission policy, exact member identity and gate checks ran before the Event
    /// became canonical. Hydration must materialize that accepted truth rather
    /// than re-evaluate it against a partially rebuilt policy projection.
    pub fn restore_accepted_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Ok(typed) = serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone()) else {
            return ProjectionEffect::Ignored;
        };
        let new_state = match typed.membership {
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join => "join",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Knock => "knock",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave => "leave",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Ban => "ban",
        };
        let member = typed.member_id.to_string();
        self.project_accepted_membership(
            operation,
            &operation.payload,
            now,
            new_state.to_owned(),
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
        let remove_membership_frontier = matches!(new_state.as_str(), "leave" | "ban").then(|| {
            vec![
                event_ref
                    .clone()
                    .unwrap_or_else(|| operation.operation_id.as_str().to_owned()),
            ]
        });

        if new_state == "join" {
            let binding = payload
                .get("agent_controller_binding")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok());
            match binding {
                Some(binding) => {
                    self.agent_membership_bindings.insert(key.clone(), binding);
                }
                None => {
                    self.agent_membership_bindings.remove(&key);
                }
            }
        } else if let Some(binding) = payload
            .get("agent_controller_binding")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
        {
            self.agent_membership_bindings.insert(key.clone(), binding);
        }

        // Update the structured cache with side-band + FSM state mirror.
        self.members.insert(
            key.clone(),
            SolandMembershipState {
                member: member.clone(),
                realm_id: realm_id.clone(),
                state: new_state.to_owned(),
                role,
                membership_event_ref: event_ref,
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
            let updated_by = operation.context.sender.to_string();
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
                &updated_by,
                remove_membership_frontier.unwrap_or_default(),
                now,
            );
        }

        // Mirror the registry's composite ActorId subject. Realm scoping is
        // implicit in the CellStore key, while the subject preserves the
        // complete tagged actor (including its Station binding).
        if let Ok(actor) = serde_json::from_value::<arkret_wire::ActorId>(
            payload.get("member_id").cloned().unwrap_or(Value::Null),
        ) && let Ok(actor_key) = actor.canonical_key()
            && let Ok(subject) = arkret_wire::composite_subject(&[actor_key])
            && let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
                "ak:cell:ak.component.member.state.v1:{subject}"
            ))
        {
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
        let managed_agent_status = if kind == arkret_wire::EventKind::RealmCreate
            && payload_object
                .and_then(|object| object.get("purpose"))
                .and_then(Value::as_str)
                == Some("managed_agent_control")
        {
            let agent_id = operation.context.sender.signing_principal_id().to_string();
            let actor_key = match operation.context.sender.canonical_key() {
                Ok(actor_key) => actor_key,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
            let actor_subject = match arkret_wire::composite_subject(&[actor_key]) {
                Ok(subject) => subject,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
            let cell = match arkret_identifiers::CellRef::new(format!(
                "ak:cell:{}:{actor_subject}",
                arkret_wire::CellFamilyId::AGENT_STATUS_V1
            )) {
                Ok(cell) => cell,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
            let projected_transition = self
                .projected_cell_writes()
                .iter()
                .find(|write| write.cell_id == cell)
                .and_then(ProjectedCellWrite::as_direct)
                .map(|effect| effect.op);
            let Some(projected_transition) = projected_transition else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            };
            if projected_transition.op_type != arkret_wire::cba::LatticeOpType::Transition
                || projected_transition.from.as_ref().and_then(Value::as_str)
                    != Some("uninitialized")
                || projected_transition.to.as_ref().and_then(Value::as_str) != Some("active")
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            }
            if self.cells.contains_key(&cell) || self.agent_lifecycles.contains_key(&agent_id) {
                return ProjectionEffect::Rejected {
                    reason: "invalid_agent_lifecycle_transition".to_owned(),
                };
            }
            Some((agent_id, cell))
        } else {
            None
        };
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
                || !arkret_wire::is_reducer_profile_id(profile)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::UNSUPPORTED_PROFILE.to_owned(),
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
                    .cloned()
                    .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
            })
        } else {
            None
        };
        // `realm_create_payload` is `{object}` with `additionalProperties:false`,
        // so `ak.realm.create` cannot carry a top-level `owner`: the owning
        // principal is the genesis authority-root controller.
        let owner = creator.as_ref().map(ToString::to_string);
        // `ak.realm.profile` is the one Realm facet payload that carries the
        // human-readable title (`zh/models/realm-and-space.md`); no other kind
        // handled here declares it.
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
            if arkret_identifiers::TrustDomainId::new(new_td.clone()).is_err() {
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
            let derived = match creator.as_ref() {
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
        let principal_genesis_resolution = if kind == arkret_wire::EventKind::RealmCreate {
            match principal_genesis_resolution_value(operation, payload_object) {
                Ok(value) => {
                    if value != registered_principal_resolution_write(self.projected_cell_writes())
                    {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                        };
                    }
                    value
                }
                Err(reason) => {
                    return ProjectionEffect::Rejected {
                        reason: reason.to_owned(),
                    };
                }
            }
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
            });
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
        match &kind {
            arkret_wire::EventKind::RealmCreate => {
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
                if let Some(history_access) = payload_object.and_then(|object| {
                    object
                        .get("history_access")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            matches!(
                                object.get("purpose").and_then(Value::as_str),
                                Some(
                                    "direct_conversation"
                                        | "principal_control"
                                        | "managed_agent_control"
                                        | "applet_managed_control"
                                )
                            )
                            .then_some("since_join")
                        })
                }) {
                    self.realm_null_subject_cells.insert(
                        (
                            realm_id.clone(),
                            "ak:cell:ak.component.realm.history_access.v1:null".to_owned(),
                        ),
                        CellState::Value(Value::String(history_access.to_owned())),
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
                if let Some(resolution) = principal_genesis_resolution {
                    self.realm_null_subject_cells.insert(
                        (realm_id.clone(), PRINCIPAL_RESOLUTION_CELL.to_owned()),
                        CellState::Value(resolution),
                    );
                }
                // The managed-Agent PCR genesis is the sole transition from
                // the internal FSM state `uninitialized` to the first public
                // state `active`. Provision admission only reserves/declares
                // the future PCR and must never activate this cell early.
                if let Some((agent_id, cell)) = managed_agent_status {
                    self.cells
                        .insert(cell, CellState::Value(Value::String("active".to_owned())));
                    self.agent_lifecycles
                        .insert(agent_id, AgentLifecycleState::Active);
                }
            }
            arkret_wire::EventKind::RealmProfile => {
                self.realm_profile_cells.insert(
                    realm_id.clone(),
                    CellState::Value(operation.payload.clone()),
                );
            }
            arkret_wire::EventKind::RealmArchive => {
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
            arkret_wire::EventKind::RealmFreeze => {
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
            arkret_wire::EventKind::RealmTombstone => {
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
            arkret_wire::EventKind::RealmDestroy => {
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

        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind
                .as_str()
                .strip_prefix("ak.realm.")
                .unwrap_or(kind.as_str())
                .to_owned(),
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
        // The generic projected-operation envelope intentionally erases its
        // heterogeneous payload. Restore the event-kind-specific type exactly
        // once at this reducer boundary so required fields, identifiers, and
        // enums cannot degrade into optional strings.
        let receipt = match serde_json::from_value::<ErasureReceipt>(payload.clone()) {
            Ok(receipt) if receipt.validate_minimal().is_ok() => receipt,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };

        let receipt_id = receipt.receipt_id.clone();
        let issuer_id = receipt.issuer_id.clone();
        let subject_kind = erasure_subject_kind_name(receipt.subject.kind).to_owned();
        let subject_ref = receipt.subject.subject_ref.clone();
        let outcome = erasure_outcome_name(receipt.outcome).to_owned();
        let storage_boundary =
            erasure_storage_boundary_name(receipt.scope.storage_boundary).to_owned();
        let scope_realm_id = receipt.scope.realm_id.as_ref().map(ToString::to_string);
        let fanout_status = erasure_fanout_status_name(
            receipt
                .fanout_status
                .unwrap_or(ErasureFanoutStatus::Pending),
        )
        .to_owned();

        self.erasure_receipts.push(ErasureReceiptRecord {
            receipt_id: Some(receipt_id.clone()),
            issuer_id: Some(issuer_id),
            subject_kind: Some(subject_kind),
            subject_ref: Some(subject_ref),
            outcome: outcome.clone(),
            storage_boundary: Some(storage_boundary),
            scope_realm_id,
            fanout_status,
            recorded_at: now,
            payload: payload.clone(),
        });

        tracing::info!(
            receipt_id = %receipt_id,
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
