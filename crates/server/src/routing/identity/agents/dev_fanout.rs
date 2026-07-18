//! Personal-Agent aggregate Event fan-out.
//!
//! Provisioning accepts only the closed controller-signed Event pair carried
//! by the SDK request type. Older aggregate operations that do not yet carry a
//! signed Event fail closed instead of asking Soland to impersonate a
//! controller or writing a development-only proof shape into durable history.

use arkret_sdk::{AccountabilityGrantPayload, AgentProvisionEvents, AgentSelectorClaim};
use chrono::{SecondsFormat, Utc};
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

/// Development-only delegated authoring for control facts that belong to the
/// Agent principal. The controller is the proof signer/executor; the Agent is
/// the principal of record and therefore owns actor_seq and the PCR stream.
async fn submit_managed_agent_control_event(
    _state: &AppState,
    _session: &SessionRecord,
    _realm_id: &str,
    _agent_id: &str,
    _authorization_ref: &str,
    _kind: &str,
    _payload: Value,
) -> Result<String, AppError> {
    Err(
        AppError::unsupported_feature("operation requires a controller-signed delegated SDK Event")
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
    let realm_id = soland_domain::identity::principal_control_realm_for_did(&session.actor);
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
        .realm_query_application()
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
    meta: &soland_application::events::RealmMetadata,
) -> Result<(), AppError> {
    if meta.owner_id != controller_id {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "self Realm owner does not match the authenticated controller",
        )
        .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
        .with_reason_code("self_realm_owner_mismatch"));
    }

    let mut projection = state.projection.lock();
    match projection.realm_states.get_mut(realm_id) {
        Some(realm) => match realm.owner.as_deref() {
            Some(owner) if owner != controller_id => {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    "self Realm projection owner does not match durable metadata",
                )
                .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
                .with_reason_code("self_realm_owner_mismatch"));
            }
            Some(_) => {}
            None => realm.owner = Some(controller_id.to_owned()),
        },
        None => {
            projection.realm_states.insert(
                realm_id.to_owned(),
                soland_domain::reducer::SolandRealmState {
                    realm_id: realm_id.to_owned(),
                    owner: Some(controller_id.to_owned()),
                    title: None,
                    deleted: meta.deleted,
                    archived: false,
                    frozen: false,
                    freeze_expires_at: None,
                    created_at: meta.created_at,
                    updated_at: meta.updated_at,
                    trust_domain: None,
                    terminal_state: None,
                    successor_realm_id: None,
                    default_strand_id: None,
                    active_profiles: Vec::new(),
                },
            );
        }
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
            arkret_sdk::AccountabilityScope::Single(
                arkret_sdk::AccountabilityScopeKind::AgentOperator
            )
        )
        || !matches!(
            accountability_payload.grant_status,
            arkret_sdk::AccountabilityGrantStatus::Active
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
            arkret_sdk::HandleBindingState::Pending
        )
        || !matches!(
            selector_payload.visibility,
            arkret_sdk::HandleVisibility::Private
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
    supplied_grant: &arkret_sdk::CapabilityGrant,
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

/// AKP-0016 — materialise a participation `effective=true` decision into a
/// durable reply/reaction capability grant for the agent over the scope
/// resource. Idempotent on the deterministic `grant_id` derived from the
/// (agent, scope_key) pair.
pub(super) async fn materialize_capability_grant(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    resource: Value,
    grant_id: &str,
) -> Result<String, AppError> {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let grant = json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": session.actor.clone(),
        "subject": agent_id,
        "actions": ["ak.message.create", "ak.reaction.add"],
        "resources": [resource],
        "issued_at": issued_at,
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": format!("{}#dev", session.actor),
            "alg": "EdDSA",
            "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": issued_at,
            "jws": "a..b",
        }],
    });
    let payload = json!({ "grant_id": grant_id, "grant": grant });
    materialize_grant(state, session, realm_id, payload).await
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
    state.authz.mark_projected_grant_revoked(grant_id);
    Ok(event_id)
}

/// AKP-0008 §4.11 — submit a durable lifecycle transition event
/// (`ak.self.agent.{pause,resume,deactivate}`) driving the FSM reducer.
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
) -> Result<String, AppError> {
    let status_changed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let transition = match event_kind {
        "ak.self.agent.pause" => "pause",
        "ak.self.agent.resume" => "resume",
        "ak.self.agent.deactivate" => "deactivate",
        other => other,
    };
    let mut payload = json!({
        "agent_id": agent_id,
        "controller_id": session.actor.clone(),
        "transition": transition,
        "previous_status": previous_status,
        "status_changed_at": status_changed_at,
    });
    if let Some(reason) = reason {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    if event_kind == "ak.self.agent.resume"
        && let Some(ack) = sidecar_exposure_ack
    {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("sidecar_exposure_ack".to_owned(), ack.clone());
    }
    submit_managed_agent_control_event(
        state,
        session,
        realm_id,
        agent_id,
        authorization_ref,
        event_kind,
        payload,
    )
    .await
}

/// AKP-0008 §4.11 — fan-out `ak.agent.key.revoke` for the agent's authorized
/// key(s) on deactivate. An Agent with no accepted key needs no synthetic
/// tombstone for an invented key id.
pub(super) async fn submit_revoke_agent_keys(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    key_ids: &[String],
    reason: Option<&str>,
) -> Result<(), AppError> {
    let revoked_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    for key_id in key_ids {
        let mut payload = json!({
            "agent_id": agent_id,
            "key_id": key_id,
            "revoked_by": session.actor.clone(),
            "revoked_at": revoked_at,
        });
        if let Some(reason) = reason {
            payload
                .as_object_mut()
                .expect("payload object")
                .insert("reason".to_owned(), json!(reason));
        }
        submit_managed_agent_control_event(
            state,
            session,
            realm_id,
            agent_id,
            authorization_ref,
            "ak.agent.key.revoke",
            payload,
        )
        .await?;
    }
    Ok(())
}

/// AKP-0008 §4.11 — on deactivate, fan-out `ak.capability.revoke` for every
/// grant id held by the agent.
pub(super) async fn submit_revoke_agent_grants(
    state: &AppState,
    session: &SessionRecord,
    grant_locations: &[(String, String)],
) -> Result<(), AppError> {
    for (grant_id, realm_id) in grant_locations {
        revoke_capability_grant(state, session, realm_id, grant_id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use soland_storage_postgres::Db;

    use super::*;

    fn realm_meta(owner: &str) -> soland_application::events::RealmMetadata {
        let now = chrono::Utc::now();
        soland_application::events::RealmMetadata {
            realm_id: String::new(),
            owner_id: owner.to_owned(),
            discoverability: "invite_only".to_owned(),
            history_visibility: "shared".to_owned(),
            deleted: false,
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

        let projection = state.projection.lock();
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
        let registry = soland_domain::artifacts::operation_ids();
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
        let registry = soland_domain::artifacts::operation_ids();
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
        let created_at = arkret_sdk::canonical::format_timestamp_millis_canonical(Utc::now());

        arkret_sdk::canonical::validate_timestamp_millis_canonical(&created_at)
            .expect("fan-out Event Envelope timestamp must pass the shared validator");
        assert_eq!(created_at.len(), "2026-07-18T00:00:00.000Z".len());
        assert!(created_at.ends_with('Z'));
    }
}
