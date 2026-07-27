//! Personal-Agent aggregate Event fan-out.
//!
//! Provisioning accepts only the closed controller-signed Event pair carried
//! by the SDK request type. Older aggregate operations that do not yet carry a
//! signed Event fail closed instead of asking Soland to impersonate a
//! controller or writing a development-only proof shape into durable history.

use arkret_models_collaboration::agent_operations::AgentProvisionEvents;
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope,
    AccountabilityScopeKind,
};
use arkret_models_identity::claim_presentation::AgentSelectorClaim;
use arkret_wire::{Event, LatticeOpType};
use chrono::Utc;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};

use super::SessionRecord;
use crate::routing::events::event_log::submit_event_value;
use crate::state::AppState;

#[cfg(test)]
const SCOPE_EVENTS_QUERY_SCAN: &str = "ak.self.events.query.scan";
#[cfg(test)]
const SCOPE_EVENTS_STREAM_SUBSCRIBE: &str = "ak.self.events.stream.subscribe";
#[cfg(test)]
const SCOPE_EVENTS_COMMAND_SUBMIT: &str = "ak.self.events.command.submit";
#[cfg(test)]
const ACTION_MESSAGE_CREATE: &str = "ak.message.create";

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

/// Fan out the controller-owned provisioning facts. Agent Profile and Agent
/// PCR genesis are intentionally absent: the controller E2EE client authors
/// them after it has locally created the Agent PCR MLS state. Provisioning
/// records the global Agent scope ceiling but does not materialize Realm
/// grants, so only the accountability and selector event ids are returned.
pub(super) async fn fanout_provision_subevents(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    agent_slug: &str,
    events: AgentProvisionEvents,
) -> Result<(String, String), AppError> {
    let accountability = events.accountability_grant;
    let selector = events.selector_claim;
    if accountability.kind.as_str() != "ak.identity.accountability_grant"
        || selector.kind.as_str() != "ak.agent.selector_claim"
    {
        return Err(AppError::invalid_param(
            "provision_events must contain accountability_grant and selector_claim Events",
        ));
    }
    for event in [&accountability, &selector] {
        if event.actor_id.as_str() != session.actor || event.realm_id.as_str() != realm_id {
            return Err(AppError::capability_denied(
                "provision Events must be authored by the authenticated controller in its PCR",
            ));
        }
    }
    if selector.actor_seq <= accountability.actor_seq {
        return Err(AppError::invalid_param(
            "selector_claim actor_seq must follow accountability_grant actor_seq",
        ));
    }
    let accountability_payload: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&accountability.payload).map_err(|error| {
            AppError::invalid_param(format!("accountability payload invalid: {error}"))
        })?,
    )
    .map_err(|error| AppError::invalid_param(format!("accountability payload invalid: {error}")))?;
    if accountability_payload.issuer.as_str() != session.actor
        || accountability_payload.subject.as_str() != agent_id
        || !matches!(
            &accountability_payload.accountability_scope,
            AccountabilityScope::Single(AccountabilityScopeKind::AgentOperator)
        )
        || !matches!(
            accountability_payload.grant_status,
            AccountabilityGrantStatus::Active
        )
    {
        return Err(AppError::invalid_param(
            "accountability payload must actively bind the controller to the requested Agent",
        ));
    }
    accountability_payload
        .validate_lifecycle_at(Utc::now())
        .map_err(|error| {
            AppError::invalid_param(format!("accountability payload proof is invalid: {error}"))
        })?;
    let accountability_proof = &accountability_payload.proof;
    if accountability_proof.verification_method != session.actor
        && !accountability_proof
            .verification_method
            .starts_with(&format!("{}#", session.actor))
    {
        return Err(AppError::capability_denied(
            "accountability payload proof must be rooted in the authenticated controller",
        ));
    }
    let accountability_binding = accountability_payload
        .canonical_proof_binding_bytes()
        .map_err(|error| {
            AppError::invalid_param(format!(
                "accountability payload proof binding is invalid: {error}"
            ))
        })?;
    let accountability_issuer = accountability_payload.issuer.clone();
    // The enclosing Event has already passed the ordinary high-risk DID
    // freshness/root-anchor gate. Verify the nested proof against that same
    // active controller key without creating a second, divergent freshness
    // policy for one payload family.
    crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
        &accountability_binding,
        &accountability_proof.jws,
        &accountability_proof.verification_method,
        accountability_issuer.as_str(),
        state,
    )
    .await
    .map_err(|reason| {
        tracing::warn!(
            %reason,
            verification_method = %accountability_proof.verification_method,
            issuer = %accountability_issuer,
            "accountability payload proof verification failed"
        );
        AppError::invalid_param("accountability payload proof JWS verification failed")
            .with_wire_code("invalid_proof")
    })?;
    let selector_payload: AgentSelectorClaim =
        serde_json::from_value(serde_json::to_value(&selector.payload).map_err(|error| {
            AppError::invalid_param(format!("selector payload invalid: {error}"))
        })?)
        .map_err(|error| AppError::invalid_param(format!("selector payload invalid: {error}")))?;
    selector_payload
        .validate()
        .map_err(|error| AppError::invalid_param(format!("selector payload invalid: {error}")))?;
    if selector_payload.controller_subject.as_str() != session.actor
        || selector_payload.issuer.as_str() != session.actor
        || selector_payload.subject.as_str() != agent_id
        || selector_payload.agent_slug != agent_slug
        || !matches!(
            selector_payload.binding_state,
            arkret_models_identity::handle::HandleBindingState::Pending
        )
        || !matches!(
            selector_payload.visibility,
            arkret_models_identity::handle::HandleVisibility::Private
        )
        || selector_payload.issuer_service_id.is_some()
        || selector_payload.proofs.len() != 1
        || !selector_payload
            .source_refs
            .iter()
            .any(|source| source == accountability.event_id.as_str())
    {
        return Err(AppError::invalid_param(
            "selector payload does not bind the provision request and accountability Event",
        ));
    }
    let selector_proof = &selector_payload.proofs[0];
    if selector_proof.verification_method != session.actor
        && !selector_proof
            .verification_method
            .starts_with(&format!("{}#", session.actor))
    {
        return Err(AppError::capability_denied(
            "selector payload proof must be rooted in the authenticated controller",
        ));
    }
    let selector_binding = selector_payload
        .canonical_proof_binding_bytes(selector_proof)
        .map_err(|error| {
            AppError::invalid_param(format!(
                "selector payload proof binding is invalid: {error}"
            ))
        })?;
    crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
        &selector_binding,
        &selector_proof.jws,
        &selector_proof.verification_method,
        selector_payload.issuer.as_str(),
        state,
    )
    .await
    .map_err(|reason| {
        tracing::warn!(
            %reason,
            verification_method = %selector_proof.verification_method,
            issuer = %selector_payload.issuer,
            "selector payload proof verification failed"
        );
        AppError::invalid_param("selector payload proof JWS verification failed")
            .with_wire_code("invalid_proof")
    })?;
    let accountability_event = accountability.event_id.to_string();
    let selector_event = selector.event_id.to_string();
    for event in [accountability, selector] {
        let kind = event.kind.to_string();
        let envelope = serde_json::to_value(event).map_err(|error| {
            AppError::invalid_param(format!("provision Event invalid: {error}"))
        })?;
        submit_event_value(state, session, envelope)
            .await
            .map_err(|error| {
                agent_fanout_submit_error(&kind, error.status, error.code, error.message)
            })?;
    }
    Ok((accountability_event, selector_event))
}

async fn materialize_grant(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    grant_payload: Value,
) -> Result<String, AppError> {
    submit_agent_fanout_event(
        state,
        session,
        realm_id,
        "ak.capability.grant",
        grant_payload,
    )
    .await
}

/// Submit the exact controller-supplied, signed Capability Grant under the
/// canonical `{grant_id, grant}` Event payload wrapper.
pub(super) async fn attach_agent_grant_event(
    state: &AppState,
    session: &SessionRecord,
    agent_id: &str,
    supplied_grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
) -> Result<String, AppError> {
    let realm_id = supplied_grant
        .realm_id
        .as_ref()
        .ok_or_else(|| AppError::invalid_param("grant.realm_id is required"))?;
    if supplied_grant.issuer.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "grant.issuer must match the authenticated controller",
        ));
    }
    let grant = serde_json::to_value(supplied_grant)
        .map_err(|error| AppError::invalid_param(format!("grant is invalid: {error}")))?;
    if grant.get("subject").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::capability_denied(
            "grant.subject must match the managed Agent principal",
        ));
    }
    let payload = json!({ "grant_id": supplied_grant.id, "grant": grant });
    materialize_grant(state, session, realm_id.as_str(), payload).await
}

/// AKP-0016 — revoke a previously materialised participation grant
/// (idempotent; `ak.capability.revoke` is a no-op when the grant_id was
/// never granted).
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
    let expected_cell = format!("ak:cell:ak.component.agent.status.v1:{agent_id}");
    let effect = event.effects.first().filter(|_| event.effects.len() == 1);
    if effect.is_none_or(|effect| {
        effect.cell.as_str() != expected_cell
            || effect.op.op_type != LatticeOpType::Transition
            || effect.op.from.as_ref().and_then(Value::as_str) != Some(previous_status)
            || effect.op.to.as_ref().and_then(Value::as_str) != Some(next_status)
            || effect.op.reason.as_deref() != reason
    }) {
        return Err(AppError::invalid_param(
            "lifecycle_event must carry the exact Agent status transition effect",
        ));
    }
    Ok(())
}

/// Submit an already validated, controller-signed Event through ordinary Event
/// admission while preserving the reducer's wire error.
pub(super) async fn submit_signed_agent_event(
    state: &AppState,
    session: &SessionRecord,
    event: Event,
) -> Result<String, AppError> {
    let event_kind = event.kind.as_str().to_owned();
    let envelope = serde_json::to_value(&event)
        .map_err(|error| AppError::invalid_param(format!("signed Event invalid: {error}")))?;
    submit_event_value(state, session, envelope)
        .await
        .map_err(|error| {
            agent_fanout_submit_error(&event_kind, error.status, error.code, error.message)
        })?;
    Ok(event.event_id.to_string())
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
    event: Event,
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
        &event,
    )?;
    submit_signed_agent_event(state, session, event).await
}

#[cfg(test)]
mod tests {
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
    fn self_realm_owner_reconciles_before_capability_fanout() {
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
        assert!(projection.issuer_has_projected_capability(
            controller,
            realm_id,
            ACTION_MESSAGE_CREATE,
            realm_id,
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
            SCOPE_EVENTS_STREAM_SUBSCRIBE,
            SCOPE_EVENTS_QUERY_SCAN,
            SCOPE_EVENTS_COMMAND_SUBMIT,
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

    #[test]
    fn fanout_event_timestamp_uses_canonical_millisecond_profile() {
        let created_at = arkret_canonical::format_timestamp_canonical(Utc::now());

        arkret_canonical::validate_timestamp_canonical(&created_at)
            .expect("fan-out Event Envelope timestamp must pass the shared validator");
        assert_eq!(created_at.len(), "2026-07-18T00:00:00.000Z".len());
        assert!(created_at.ends_with('Z'));
    }
}
