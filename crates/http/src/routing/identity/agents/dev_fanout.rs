//! Personal-Agent aggregate Event fan-out.
//!
//! Provisioning accepts only the closed controller-signed Event pair carried
//! by the SDK request type. Older aggregate operations that do not yet carry a
//! signed Event fail closed instead of asking Soland to impersonate a
//! controller or writing a development-only proof shape into durable history.

use arkret_wire::Event;
use chrono::Utc;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};

use super::SessionRecord;
use crate::routing::events::event_log::submit_initial_event_submission;
use crate::state::AppState;

/// Build a server-authored envelope for `session.actor` and submit it via the
/// shared internal event API. `actor_seq` is taken as
/// `max_actor_seq(actor) + 1` so concurrent fan-out events stay strictly
/// increasing.
pub(super) async fn submit_agent_fanout_event(
    _state: &AppState,
    _session: &SessionRecord,
    _realm_id: &str,
    _kind: &str,
    _payload: Value,
) -> Result<String, AppError> {
    Err(
        AppError::unsupported_feature("operation requires a controller-signed SDK Event")
            .with_wire_code("controller_signed_event_required"),
    )
}

fn agent_fanout_submit_error(
    kind: &str,
    status: salvo::http::StatusCode,
    wire_code: String,
    detail: String,
) -> AppError {
    let message = format!("agent fan-out submit failed for {kind}: {detail}");
    if let Some(code) = ErrorCode::from_wire(&wire_code) {
        return AppError::new(code, message).with_status(status);
    }

    // Reducer rejection reasons (for example
    // `grant_exceeds_issuer_authority`) are stable reason codes, not
    // top-level error codes. Preserve the semantic HTTP class and expose the
    // reducer discriminator in details instead of turning an expected
    // failed-precondition into a misleading 500 internal_error.
    let code = match status {
        salvo::http::StatusCode::PRECONDITION_FAILED => ErrorCode::FailedPrecondition,
        salvo::http::StatusCode::CONFLICT => ErrorCode::Conflict,
        salvo::http::StatusCode::FORBIDDEN => ErrorCode::CapabilityDenied,
        salvo::http::StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
        salvo::http::StatusCode::BAD_REQUEST => ErrorCode::InvalidParam,
        _ => ErrorCode::InternalError,
    };
    AppError::new(code, message)
        .with_status(status)
        .with_reason_code(wire_code)
}

/// Resolve the authenticated controller's own Principal Control Realm. Agent
/// provisioning may write controller-owned facts there, but it must never
/// create an ordinary Realm and reuse it as an Agent PCR.
pub(super) async fn require_controller_principal_control_realm(
    state: &AppState,
    session: &SessionRecord,
) -> Result<String, AppError> {
    let realm_id = soland_services::identity::principal_control_realm_for_did(&session.actor);
    if !crate::routing::events::event_log::realm_is_indexed(state, &realm_id) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "controller Principal Control Realm must be initialized before provisioning an Agent",
        )
        .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
        .with_reason_code("principal_control_realm_missing"));
    }

    // The Realm directory index and reducer projection are separate caches.
    // Repair the reducer-side owner from the durable Realm metadata before
    // issuing the accountability event so this aggregate stays correct even when a
    // running process has an indexed self Realm but a stale projection cache.
    // Startup hydration normally provides the same state, but correctness of
    // provisioning must not depend on a restart having rebuilt every cache.
    let meta = state
        .realms()
        .realm_metadata(&realm_id)
        .await
        .map_err(|err| AppError::internal(format!("self Realm metadata lookup failed: {err}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "self Realm is indexed without durable metadata",
            )
            .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
            .with_reason_code("self_realm_metadata_missing")
        })?;
    reconcile_self_realm_owner_projection(state, &realm_id, &session.actor, &meta)?;
    Ok(realm_id)
}

fn reconcile_self_realm_owner_projection(
    state: &AppState,
    realm_id: &str,
    controller_id: &str,
    meta: &soland_services::events::RealmMetadata,
) -> Result<(), AppError> {
    if meta.owner != controller_id {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "self Realm owner does not match the authenticated controller",
        )
        .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
        .with_reason_code("self_realm_owner_mismatch"));
    }

    if !state.projections().reconcile_realm_owner(
        realm_id,
        controller_id,
        meta.deleted,
        meta.created_at,
        meta.updated_at,
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "self Realm projection owner does not match durable metadata",
        )
        .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
        .with_reason_code("self_realm_owner_mismatch"));
    }
    Ok(())
}

/// `did-usage-and-verification.md` §2.2: a proof `verification_method` MUST be
/// a DID URL with a `#fragment` rooted in `root`. A bare `root` DID names no
/// concrete verification method and is rejected.
fn verification_method_rooted_in(verification_method: &str, root: &str) -> bool {
    verification_method.starts_with(&format!("{root}#"))
}

/// Validate and admit the single controller-authored provisioning fact.
///
/// The containing Event proof is the only signature. The registered reducer
/// atomically projects the provision, accountability, and selector cells.
#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_provision_event(
    state: &AppState,
    session: &SessionRecord,
    controller_realm_id: &str,
    agent_id: &arkret_wire::Did,
    principal_control_realm_id: &arkret_wire::RealmId,
    controller_authorization_ref: &arkret_wire::DidUrl,
    agent_slug: &str,
    requested_scope_digest: &arkret_wire::Hash,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<String, AppError> {
    let event = &submission.event;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(event)
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
    if event.actor_id.as_str() != session.actor
        || event.realm_id.as_str() != controller_realm_id
        || payload.agent_id != *agent_id
        || payload.controller_id.as_str() != session.actor
        || payload.principal_control_realm_id != *principal_control_realm_id
        || payload.controller_authorization_ref != *controller_authorization_ref
        || payload.agent_slug != agent_slug
        || payload.requested_scope_digest != *requested_scope_digest
    {
        return Err(AppError::invalid_param(
            "provision_event does not match the authenticated allocation",
        ));
    }
    let event_id = event.event_id.to_string();
    submit_initial_event_submission(state, session, submission)
        .await
        .map_err(|error| {
            agent_fanout_submit_error(
                arkret_wire::EventKind::AGENT_PROVISION,
                error.status,
                error.code,
                error.message,
            )
        })?;
    Ok(event_id)
}

/// Revoke an ordinary capability grant during Agent lifecycle teardown.
/// Revoke an ordinary capability grant during Agent lifecycle teardown.
/// `ak.capability.revoke` is idempotent when the grant was never accepted.
pub(super) async fn revoke_capability_grant(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    grant_id: &str,
) -> Result<String, AppError> {
    let payload = json!({ "grant_id": grant_id });
    let event_id =
        submit_agent_fanout_event(state, session, realm_id, "ak.capability.revoke", payload)
            .await?;
    // The durable reducer event is the source of truth; this mirrors the
    // same revoke into the in-memory authz read index before the HTTP command
    // returns so subsequent resource checks fail closed immediately.
    state.authorization().mark_projected_grant_revoked(grant_id);
    Ok(event_id)
}

/// AKP-0008 §4.11 — submit a durable lifecycle transition event
/// (`ak.self.agent.{pause,resume,deactivate}`) driving the FSM reducer.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_durable_agent_lifecycle(
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    event_kind: &str,
    previous_status: &str,
    reason: Option<&str>,
    sidecar_exposure_ack: Option<&Value>,
    event: &Event,
) -> Result<(), AppError> {
    let (transition, next_status) = match event_kind {
        "ak.self.agent.pause" => ("pause", "paused"),
        "ak.self.agent.resume" => ("resume", "active"),
        "ak.self.agent.deactivate" => ("deactivate", "deactivated"),
        _ => {
            return Err(AppError::invalid_param(
                "unsupported Agent lifecycle Event kind",
            ));
        }
    };
    if event.kind.as_str() != event_kind
        || event.realm_id.as_str() != realm_id
        || event.actor_id.as_str() != agent_id
        || event
            .executed_by
            .as_ref()
            .map(arkret_identifiers::Did::as_str)
            != Some(session.actor.as_str())
        || event.authorization_ref.as_deref() != Some(authorization_ref)
    {
        return Err(AppError::capability_denied(
            "lifecycle_event does not match the managed Agent controller binding",
        ));
    }
    if event.proofs.is_empty() {
        return Err(
            AppError::invalid_param("lifecycle_event must carry a controller proof")
                .with_wire_code("controller_signed_event_required"),
        );
    }
    let payload_reason = event.payload.get("reason").and_then(Value::as_str);
    let payload_ack = event.payload.get("sidecar_exposure_ack");
    if event.payload.get("agent_id").and_then(Value::as_str) != Some(agent_id)
        || event.payload.get("controller_id").and_then(Value::as_str)
            != Some(session.actor.as_str())
        || event.payload.get("transition").and_then(Value::as_str) != Some(transition)
        || event.payload.get("previous_status").and_then(Value::as_str) != Some(previous_status)
        || payload_reason != reason
        || payload_ack != sidecar_exposure_ack
    {
        return Err(AppError::invalid_param(
            "lifecycle_event payload does not match the requested transition",
        ));
    }
    // v1 carries no producer `effects[]`: the Agent status transition is
    // derived from `kind + payload` by the registered contract, and `from`
    // comes from the frozen pre-state (`ProjectedOp::TransitionTo`), not from
    // the producer. The payload fields that feed the projection were pinned
    // above, so the remaining check is that the contract derives exactly one
    // write, on this Agent's status cell, transitioning to `next_status`.
    let expected_cell = format!("ak:cell:ak.component.agent.status.v1:{agent_id}");
    let derived =
        arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| {
                AppError::invalid_param(format!(
                    "lifecycle_event Agent status projection failed: {error}"
                ))
            })?;
    let matches_transition = derived.len() == 1
        && derived[0].cell.as_str() == expected_cell
        && matches!(
            &derived[0].op,
            arkret_wire::cba::ProjectedOp::Direct(op)
                if op.op_type == arkret_wire::cba::LatticeOpType::Transition
                    && op.to.as_ref().and_then(Value::as_str) == Some(next_status)
        );
    if !matches_transition {
        return Err(AppError::invalid_param(
            "lifecycle_event must derive the exact Agent status transition",
        ));
    }
    let _ = (previous_status, reason);
    Ok(())
}

/// Submit an already validated, controller-signed Event through ordinary Event
/// admission while preserving the reducer's wire error.
pub(super) async fn submit_signed_agent_event(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<String, AppError> {
    let event = &submission.event;
    let event_kind = event.kind.as_str().to_owned();
    let event_id = event.event_id.to_string();
    crate::routing::events::event_log::submit_initial_event_submission(state, session, submission)
        .await
        .map_err(|error| {
            agent_fanout_submit_error(&event_kind, error.status, error.code, error.message)
        })?;
    Ok(event_id)
}

/// AKP-0008 §4.11 — submit a durable lifecycle transition event
/// (`ak.self.agent.{pause,resume,deactivate}`) driving the FSM reducer.
#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_durable_agent_lifecycle(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    event_kind: &str,
    previous_status: &str,
    reason: Option<&str>,
    sidecar_exposure_ack: Option<&Value>,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<String, AppError> {
    validate_durable_agent_lifecycle(
        session,
        realm_id,
        agent_id,
        authorization_ref,
        event_kind,
        previous_status,
        reason,
        sidecar_exposure_ack,
        &submission.event,
    )?;
    submit_signed_agent_event(state, session, submission).await
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CapabilityActionId, ServiceOperationId};
    use soland_storage_postgres::Db;

    use super::*;

    fn realm_meta(owner: &str) -> soland_services::events::RealmMetadata {
        let now = chrono::Utc::now();
        soland_services::events::RealmMetadata {
            owner: owner.to_owned(),
            deleted: false,
            discoverability: "invite_only".to_owned(),
            history_visibility: "shared".to_owned(),
            history_sharing_policy: None,
            history_sharing_policy_digest: None,
            preview_policy: None,
            preview_policy_digest: None,
            asset_privacy_policy: None,
            asset_privacy_policy_digest: None,
            encryption_profile: None,
            plaintext_visible_services: Default::default(),
            plaintext_visible_service_classes: Default::default(),
            minimal_metadata_realm: false,
            aad_visibility_ceiling: Default::default(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn reducer_rejection_keeps_failed_precondition_reason() {
        let error = agent_fanout_submit_error(
            "ak.capability.grant",
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "grant_exceeds_issuer_authority".to_owned(),
            "grant_exceeds_issuer_authority".to_owned(),
        );

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.reason_code.as_deref(),
            Some("grant_exceeds_issuer_authority")
        );
        assert_eq!(
            error.http_status(),
            salvo::http::StatusCode::PRECONDITION_FAILED
        );
    }

    #[test]
    fn self_realm_owner_reconciles_without_implying_capability() {
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        let realm_id = "ak:realm:019f5548-2d3c-751b-90d6-f262c6feacea";
        let controller = "did:webvh:z6mkfixture:example.test:users:alice";

        reconcile_self_realm_owner_projection(
            &state,
            realm_id,
            controller,
            &realm_meta(controller),
        )
        .expect("durable owner should repair the missing projection");

        let projection = state.projections().snapshot();
        assert_eq!(
            projection
                .realm_states
                .get(realm_id)
                .and_then(|realm| realm.owner.as_deref()),
            Some(controller)
        );
        assert!(!projection.issuer_has_projected_capability(
            controller,
            realm_id,
            CapabilityActionId::MESSAGE_CREATE,
            realm_id,
            chrono::Utc::now(),
        ));
    }

    #[test]
    fn self_realm_owner_reconciliation_fails_closed_on_mismatch() {
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        let error = reconcile_self_realm_owner_projection(
            &state,
            "ak:realm:019f5548-2d3c-751b-90d6-f262c6feacea",
            "did:webvh:z6mkfixture:example.test:users:alice",
            &realm_meta("did:webvh:z6mkfixture:example.test:users:bob"),
        )
        .expect_err("mismatched durable ownership must not be overwritten");

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.reason_code.as_deref(),
            Some("self_realm_owner_mismatch")
        );
    }

    #[test]
    fn runtime_agent_key_scope_service_actions_are_registered() {
        let registry = soland_services::protocol_artifacts::operation_ids();
        for action in [
            ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
            ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
        ] {
            assert!(
                registry.contains(action),
                "dev fanout agent_key_scope action `{action}` must exist in operation registry"
            );
        }
    }

    #[test]
    fn deprecated_self_events_scope_tokens_are_not_registered() {
        let registry = soland_services::protocol_artifacts::operation_ids();
        for action in [
            "events.subscribe",
            "ak.self.events.subscribe",
            "ak.self-events.subscribe",
            "ak.self-events.stream.subscribe",
        ] {
            assert!(
                !registry.contains(action),
                "deprecated self-events shortcut `{action}` must not be used as an agent runtime scope"
            );
        }
    }

    // did-usage-and-verification.md §2.2 — the accountability-grant and
    // selector-claim proofs MUST name a `#fragment` DID URL rooted in the
    // authenticated controller. The bare controller DID names no concrete
    // verification method, and a sibling DID that merely shares the prefix
    // must not slip through the `starts_with` check.
    #[test]
    fn provision_proof_verification_method_rejects_bare_controller_did() {
        let controller = "did:webvh:z6mkfixture:example.test:users:alice";

        assert!(verification_method_rooted_in(
            &format!("{controller}#device-1"),
            controller
        ));
        assert!(!verification_method_rooted_in(controller, controller));
        assert!(!verification_method_rooted_in(
            &format!("{controller}:bob#device-1"),
            controller
        ));
        assert!(!verification_method_rooted_in(
            "did:webvh:z6mkfixture:example.test:users:bob#device-1",
            controller
        ));
    }

    #[test]
    fn fanout_event_timestamp_uses_canonical_millisecond_profile() {
        let created_at = arkret_canonical::format_timestamp_canonical(Utc::now());

        arkret_canonical::validate_timestamp_canonical(&created_at)
            .expect("fan-out Event Envelope timestamp must pass the shared validator");
        assert_eq!(created_at.len(), "2026-07-18T00:00:00.000Z".len());
        assert!(created_at.ends_with('Z'));
    }
}
