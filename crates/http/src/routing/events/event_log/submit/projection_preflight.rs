use super::*;

pub(super) struct ProjectionPreflightContext<'a> {
    pub(super) session: &'a SessionRecord,
    pub(super) parsed: &'a ValidatedEventEnvelope,
    pub(super) submitted_event: &'a Event,
    pub(super) envelope: &'a Value,
    pub(super) projection_operation: Option<&'a arkret_event_draft::ProjectedEventOperation>,
    pub(super) projected_cell_writes: &'a [arkret_wire::cbs::ProjectedCellWrite],
    pub(super) frozen_pre_state: &'a arkret_schema::FrozenPreState,
    pub(super) internal_admission: Option<&'a InternalEventAdmission>,
    pub(super) batch_operations: &'a [arkret_event_draft::ProjectedEventOperation],
    pub(super) preparing_agent_membership: bool,
    pub(super) has_internal_plaintext_service_binding: bool,
}

pub(super) struct ProjectionPreflightOutcome {
    pub(super) consent_admission: Option<crate::routing::identity::consent::ConsentAdmission>,
    pub(super) actor_private_account_data: Option<soland_services::events::CommitAccountDataCas>,
}

/// Run all reducer- and policy-facing projection checks before constructing
/// the canonical commit command. No persistence write is permitted in this
/// stage; rejected invite claims are the sole recorded rejection effect.
pub(super) async fn apply_projection_preflight(
    state: &AppState,
    context: ProjectionPreflightContext<'_>,
) -> Result<ProjectionPreflightOutcome, SubmitOneError> {
    let ProjectionPreflightContext {
        session,
        parsed,
        submitted_event,
        envelope,
        projection_operation,
        projected_cell_writes,
        frozen_pre_state,
        internal_admission,
        batch_operations,
        preparing_agent_membership,
        has_internal_plaintext_service_binding,
    } = context;
    let mut consent_admission = None;
    let mut actor_private_account_data = None;
    if let Some(operation) = projection_operation.as_ref() {
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(operation)) {
            return Err(SubmitOneError::semantic_schema_violation(message));
        }
        if let Some(basis) = &submitted_event.seal_basis {
            let frozen = state
                .projections()
                .effective_state_at(&basis.leaves, &operation.realm_id)
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "failed_precondition",
                        format!("Control Move frozen Seal basis unavailable: {error}"),
                    )
                })?;
            validate_cas_write_guards(state, operation, projected_cell_writes, &frozen)?;
        }
        preflight_moderation_dismiss(state, operation).await?;
        actor_private_account_data = preflight_account_data_cas(state, operation).await?;
        preflight_member_identity_state_guard(state, operation)?;
        // Holder-private consent is admission state, not a post-acceptance
        // cache: resolve the whole or_set mutation and its eager invalidation
        // here so a Move that cannot be projected is refused with zero writes
        // (`consent-model.md` sections 3.1, 3.3 and 4.1.2).
        consent_admission = crate::routing::identity::consent::preflight_consent_admission(
            state,
            operation,
            submitted_event,
        )
        .await
        .map_err(|rejection| {
            SubmitOneError::new(rejection.status, rejection.code, rejection.message)
        })?;
        if let Err(reason) =
            crate::routing::identity::agents::sidecar::validate_sidecar_mls_event_binding(
                state,
                parsed.device_id_str(),
                operation,
            )
            .await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        if let Err(reason) =
            crate::routing::identity::agents::sidecar::validate_sidecar_exchange_control_event(
                state, operation,
            )
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        validate_active_series_authority_before_commit(state, parsed, operation).await?;
        if !has_internal_plaintext_service_binding
            && let Err(reason) =
                validate_content_encryption_floor(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // AKP-0016 — reject agent_participation ceiling writes that widen
        // the parent scope's ceiling (tighten-only invariant).
        if let Err(reason) =
            validate_agent_participation_ceiling(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // AKP-0016 §5.2 / architecture §7 — Agent writes
        // require an auditable agent_context plus the effective participation
        // bit for the write mode. Per 0016-agent-participation-policy.md §6,
        // missing materialised grants are preconditions, not auth-context
        // denials.
        // The MIMI reporter lane already verifies the closed, short-lived
        // holder transcript and the current Agent proxy/key authorization.
        // Its closed moderation payload cannot carry the ordinary
        // agent_context/approval fields, so do not require that second,
        // incompatible authorization profile for the same producer.
        if !internal_admission.is_some_and(InternalEventAdmission::is_mimi_agent_reporter) {
            let agent_policy_operation = operation_with_unsigned_agent_context(operation, envelope);
            match validate_agent_reply_participation(
                state,
                std::slice::from_ref(&agent_policy_operation),
            )
            .await
            {
                Ok(()) => {}
                Err(reason) => {
                    return Err(SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        reason,
                        reason,
                    ));
                }
            }
        }
        // Policy validation always sees the whole submit batch, so facet
        // writes can cross-check sibling scheme/profile values instead of
        // only the projection (`operations::policy_extra`). Outside a batch
        // surface the lane sees the Event's own Operation alone.
        let policy_operations: &[arkret_event_draft::ProjectedEventOperation] =
            if batch_operations.is_empty() {
                std::slice::from_ref(operation)
            } else {
                batch_operations
            };
        let policy_result = if preparing_agent_membership {
            crate::routing::events::operations::validate_single_operation_policy_for_agent_membership_cascade(
                state,
                operation,
                policy_operations,
                has_internal_plaintext_service_binding,
            )
            .await
        } else {
            crate::routing::events::operations::validate_single_operation_policy_in_batch(
                state,
                operation,
                policy_operations,
                has_internal_plaintext_service_binding,
            )
            .await
        };
        if let Err(message) = policy_result {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            let mut rejection = SubmitOneError::new(status, code, message);
            if is_direct_conversation_admission_reason(message) {
                rejection = rejection.with_details(serde_json::json!({
                    "reason_code": message,
                }));
            }
            return Err(rejection);
        }
        // Recipient trust is checked by the claim ledger only after the exact
        // destination receipt has been authenticated, never by a local DID lookup.
        if internal_admission.is_none()
            && let Some(reason) =
                preflight_mls_welcome_claim_ledger_reject(state, &parsed.actor, operation).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        // The typed decode above proves the validated envelope is a JSON
        // object, so this deref cannot fail.
        let envelope_object = envelope
            .as_object()
            .expect("validated Event envelope decoded as a JSON object");
        if let Some(reason) = preflight_mls_welcome_claim_signature_reject(
            state,
            session,
            envelope_object,
            &parsed.actor,
            operation,
            internal_admission,
        )
        .await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        if let Err(reason) =
            crate::routing::events::projection::validate_invite_cancel_pre_admission(
                parsed.actor_id.as_str(),
                operation,
                frozen_pre_state,
            )
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        let (invite_preflight_reject, invite_proof_context) = {
            // Admission checks below are mandatory and MUST NOT be skipped
            // (fail-closed). The projection lock is a `parking_lot::Mutex`
            // (no poisoning), so acquiring it cannot fail and this block
            // always runs.
            let proj = state.projections().snapshot();
            if let Err(reason) = proj.check_space_container_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // governance-objects.md §5.3 — a directed invite whose invitee
            // already holds the Realm live-target slot is an invalid duplicate,
            // not a stale head. It is refused before the generic head_eq check
            // so the rejection carries its registered sub-reason and echoes the
            // occupying invite instead of a bare `failed_precondition` the
            // client cannot act on.
            if let Err(rejection) =
                crate::routing::events::projection::validate_invite_live_target_admission(
                    operation, &proj,
                )
            {
                return Err(match rejection {
                    crate::routing::events::projection::InviteLiveTargetRejection::ProjectionFailed(
                        reason,
                    ) => SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason),
                    crate::routing::events::projection::InviteLiveTargetRejection::Occupied(
                        problem,
                    ) => SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "failed_precondition",
                        "the invitee already holds a live directed invite in this Realm",
                    )
                    .with_details(problem),
                });
            }
            // event-and-patch.md §4.4 — a Control Move's generic
            // `preconditions[].head_eq` compare-and-swap MUST be evaluated
            // against the materialized head before any effect lands; a stale
            // head fails closed with `failed_precondition` and no partial
            // apply.
            if let Err(reason) = proj.check_move_preconditions(operation) {
                let (code, message) = cbs_bottom_reject(reason);
                let mut error = SubmitOneError::new(StatusCode::PRECONDITION_FAILED, code, message);
                if reason == "cell_bottom_state" {
                    error = error
                        .with_details(serde_json::json!({ "reason_code": "cell_in_bottom_state" }));
                }
                return Err(error);
            }
            if let Err(reason) = proj.check_morph_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_redaction_target_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_tracks_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_bottom_cell_transition(operation) {
                let (code, message) = cbs_bottom_reject(reason);
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    code,
                    message,
                ));
            }
            if let Err(reason) = proj.check_membership_join_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_pin_scope_safety(operation) {
                let status = if reason == "not_found" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::PRECONDITION_FAILED
                };
                return Err(SubmitOneError::new(status, reason, reason));
            }
            // relation.md §2/§4 — relation effective scope is reducer-managed,
            // and structural contains/belongs_to MUST stay within one Realm.
            if let Err(reason) = proj.check_relation_invariants(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // realm-and-space.md §3.6 — Strand creation carries no position;
            // any placement metadata is a wire-shape violation. A separate
            // Move establishes the first board/list position.
            if let Err(reason) = proj.check_strand_position_typing(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    reason,
                ));
            }
            // forbidden-wire-fields.json — create payloads carrying a
            // registered forbidden field fail admission with the same
            // registered reason the reducer would reject with.
            if let Err(reason) = proj.check_strand_create_forbidden_wire_fields(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    reason,
                )
                .with_details(serde_json::json!({"reason_code": reason})));
            }
            if let Err(reason) = proj.check_morph_create_forbidden_wire_fields(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    reason,
                )
                .with_details(serde_json::json!({"reason_code": reason})));
            }
            if let Err(reason) = proj.check_child_scope_policy_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // capabilities.md §10.2 — a capability grant whose typed
            // authority refs close a cycle MUST be rejected before it projects.
            if let Err(reason) = proj.check_authority_cycle(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if parsed.kind == arkret_wire::EventKind::RealmLink.as_str() {
                let target_realm_id = operation
                    .payload
                    .get("target_realm_id")
                    .and_then(Value::as_str)
                    .expect("validated Realm Link target_realm_id");
                let link_kind = operation
                    .payload
                    .get("link_kind")
                    .and_then(Value::as_str)
                    .expect("validated Realm Link link_kind");
                let status = operation
                    .payload
                    .get("status")
                    .and_then(Value::as_str)
                    .expect("validated Realm Link status");
                if let Err(reason) =
                    soland_domain::reducer::realm_links::check_realm_link_admissible(
                        &proj,
                        operation.realm_id.as_str(),
                        target_realm_id,
                        link_kind,
                        status,
                    )
                {
                    let code = if reason == arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION {
                        "failed_precondition"
                    } else {
                        "schema_violation"
                    };
                    return Err(SubmitOneError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        code,
                        reason,
                    )
                    .with_details(serde_json::json!({"reason_code": reason})));
                }
            }
            if let Some(reason) = state
                .projections()
                .preflight_capability_rejection(operation, projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projections()
                .preflight_realm_policy_rejection(operation, projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projections()
                .preflight_calendar_rejection(operation, projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state.projections().preflight_mls_rejection(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            // Poll response validity is admission state, not a best-effort
            // post-commit projection. This path is shared by local and peer
            // federation submission, so an unresolved/cross-scope Poll or an
            // invalid selection can never enter the canonical Event log.
            if let Some(reason) = state
                .projections()
                .preflight_poll_rejection(operation, projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projections()
                .preflight_moderation_rejection(operation, projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            let invite_preflight_reject = state
                .projections()
                .preflight_invite_rejection(operation, projected_cell_writes);
            let invite_proof_context = if invite_preflight_reject.is_none() {
                invite_claim_proof_context_from_projection(state.projections(), operation).map_err(
                    |reason| SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason),
                )?
            } else {
                None
            };
            (invite_preflight_reject, invite_proof_context)
        };
        if let Some(reason) = invite_preflight_reject {
            record_rejected_invite_claim_effect(state, operation)
                .await
                .map_err(|message| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invite_claim_reject_effect_failed",
                        message,
                    )
                })?;
            if operation.event_kind == arkret_wire::EventKind::InviteClaim {
                tracing::info!(
                    internal_reason = %reason,
                    "invite claim rejected with non-enumerating wire response"
                );
                return Err(SubmitOneError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "invite claim not found",
                ));
            }
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        if let Some(context) = invite_proof_context
            && let Err(reason) =
                verify_invite_claim_proofs_for_operation(state, operation, &context).await
        {
            record_rejected_invite_claim_effect(state, operation)
                .await
                .map_err(|message| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invite_claim_reject_effect_failed",
                        message,
                    )
                })?;
            tracing::info!(
                internal_reason = %reason,
                "invite claim proof rejected with non-enumerating wire response"
            );
            return Err(SubmitOneError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "invite claim not found",
            ));
        }
    }
    Ok(ProjectionPreflightOutcome {
        consent_admission,
        actor_private_account_data,
    })
}
