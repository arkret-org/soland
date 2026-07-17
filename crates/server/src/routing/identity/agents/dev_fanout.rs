//! AKP-0008 — development-mode server-authored fan-out for the personal
//! agent provisioning / lifecycle surface (architecture option B).
//!
//! Soland materialises the durable sub-events required by the personal-agent
//! aggregate surfaces. Controller-owned accountability, selector and grant
//! events use the controller as `actor_id`; Agent control events retain the
//! Agent as `actor_id` and carry the controller as `executed_by` under the
//! exact DID-document delegation reference.
//!
//! The dev-proof envelope shape is the one accepted by
//! `validate_event_proofs` (event_log/validation.rs): `type="dev-proof"`,
//! `verification_method == actor_id#session.device_id`, and `payload_digest`
//! = the sha256 of the canonical payload bytes. Rooting the proof in the
//! authenticated device keeps development fan-out inside the B-model device
//! generation fence.

use arkret_sdk::{
    AccountabilityGrantPayload, AccountabilityScope, AgentSelectorClaim, Did, HandleBindingState,
    HandleVisibility, Hash, PayloadProof, canonical,
};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};

use super::SessionRecord;
use crate::error::{AppError, ErrorCode};
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
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<String, AppError> {
    let actor = session.actor.clone();
    let next_seq = state
        .persistence
        .events()
        .max_actor_seq(&actor)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
        + 1;
    let event_uuid = uuid::Uuid::now_v7();
    let event_id = format!("ak:event:{event_uuid}");
    let operation_alias = format!("ak:operation:{}", uuid::Uuid::now_v7());
    let payload_bytes = canonical::canonical_json_bytes(&payload).unwrap_or_default();
    let payload_digest = canonical::sha256_digest(&payload_bytes);
    let verification_method = format!("{}#{}", actor, session.device_id);
    // Envelope created_at MUST be canonical RFC3339 UTC with no fractional
    // seconds (exactly YYYY-MM-DDTHH:MM:SSZ) per canonical::validate_timestamp_canonical.
    let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let envelope = json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "actor_id": actor,
        "actor_seq": next_seq,
        "created_at": created_at,
        "hlc": state.hlc.now(),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "unsigned": { "local_operation_idempotency_alias": operation_alias },
        "proofs": [{
            "type": "dev-proof",
            "verification_method": verification_method,
            "payload_digest": payload_digest,
        }],
    });
    let outcome = submit_event_value(state, session, envelope)
        .await
        .map_err(|err| agent_fanout_submit_error(kind, err.status, err.code, err.message))?;
    Ok(outcome.event_id)
}

/// Development-only delegated authoring for control facts that belong to the
/// Agent principal. The controller is the proof signer/executor; the Agent is
/// the principal of record and therefore owns actor_seq and the PCR stream.
async fn submit_managed_agent_control_event(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    kind: &str,
    payload: Value,
) -> Result<String, AppError> {
    let next_seq = state
        .persistence
        .events()
        .max_actor_seq(agent_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
        + 1;
    let event_id = format!("ak:event:{}", uuid::Uuid::now_v7());
    let payload_bytes = canonical::canonical_json_bytes(&payload).unwrap_or_default();
    let payload_digest = canonical::sha256_digest(&payload_bytes);
    let envelope = json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "actor_id": agent_id,
        "actor_seq": next_seq,
        "created_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "hlc": state.hlc.now(),
        "prev_refs": [],
        "refs": [],
        "executed_by": session.actor,
        "authorization_ref": authorization_ref,
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": session.actor,
            "payload_digest": payload_digest,
        }],
    });
    let delegated_session = super::delegated_agent_session(session, agent_id);
    let outcome = submit_event_value(state, &delegated_session, envelope)
        .await
        .map_err(|err| agent_fanout_submit_error(kind, err.status, err.code, err.message))?;
    Ok(outcome.event_id)
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
    let realm_id =
        crate::routing::identity::recovery::principal_control_realm_for_did(&session.actor);
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
        .persistence
        .realm_meta()
        .get(&realm_id)
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
    meta: &soland_storage::RealmMetaRecord,
) -> Result<(), AppError> {
    if meta.owner != controller_id {
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
) -> Result<(String, String), AppError> {
    let controller = session.actor.clone();
    let controller_did = Did::new(controller.clone())
        .map_err(|error| AppError::internal(format!("controller DID invalid: {error}")))?;
    let agent_did = Did::new(agent_id.to_owned())
        .map_err(|error| AppError::internal(format!("agent DID invalid: {error}")))?;
    // 1. Accountability grant, issuer = controller and subject = Agent.
    let now_utc = Utc::now();
    let created_at = now_utc.to_rfc3339_opts(SecondsFormat::Secs, true);
    let accountability_unsigned = json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer": controller,
        "subject": agent_id,
        "accountability_scope": "agent_operator",
        "not_before": created_at,
        "grant_status": "active",
    });
    let accountability_proof =
        development_payload_proof(&accountability_unsigned, &controller, now_utc)?;
    let accountability_payload = serde_json::to_value(AccountabilityGrantPayload::new(
        controller_did.clone(),
        agent_did.clone(),
        AccountabilityScope::Single("agent_operator".to_owned()),
        now_utc,
        None,
        accountability_proof,
    ))
    .map_err(|error| {
        AppError::internal(format!(
            "accountability grant serialization failed: {error}"
        ))
    })?;
    let accountability_event = submit_agent_fanout_event(
        state,
        session,
        realm_id,
        "ak.identity.accountability_grant",
        accountability_payload,
    )
    .await?;

    // 2. Controller-scoped selector claim. It remains pending until the
    // controller client has bootstrapped the Agent PCR/Profile and recovery.
    let selector_unsigned = json!({
        "schema": "ak.schema.agent_selector_claim.v1",
        "controller_subject": controller,
        "agent_slug": agent_slug,
        "subject": agent_id,
        "issuer": controller,
        "binding_state": "pending",
        "visibility": "private",
        "created_at": created_at,
        "source_refs": [accountability_event],
    });
    let selector_proof = development_payload_proof(&selector_unsigned, &controller, now_utc)?;
    let selector_payload = serde_json::to_value(AgentSelectorClaim {
        schema: arkret_sdk::AGENT_SELECTOR_CLAIM_SCHEMA.to_owned(),
        controller_subject: controller_did.clone(),
        agent_slug: agent_slug.to_owned(),
        subject: agent_did,
        issuer: controller_did,
        issuer_service_id: None,
        binding_state: HandleBindingState::Pending,
        visibility: HandleVisibility::Private,
        audience: None,
        claim_scope: Default::default(),
        expires_at: None,
        created_at: now_utc,
        verified_at: None,
        source_refs: vec![accountability_event.clone()],
        proofs: vec![selector_proof],
    })
    .map_err(|error| {
        AppError::internal(format!(
            "agent selector claim serialization failed: {error}"
        ))
    })?;
    let selector_event = submit_agent_fanout_event(
        state,
        session,
        realm_id,
        "ak.agent.selector_claim",
        selector_payload,
    )
    .await?;

    Ok((accountability_event, selector_event))
}

fn development_payload_proof(
    payload: &Value,
    controller: &str,
    created_at: chrono::DateTime<Utc>,
) -> Result<PayloadProof, AppError> {
    let digest = canonical::canonical_sha256(payload)
        .map_err(|error| AppError::internal(format!("nested proof digest failed: {error}")))?;
    Ok(PayloadProof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{controller}#controller-key"),
        payload_digest: Hash::new(digest)
            .map_err(|error| AppError::internal(format!("proof digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
    })
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
    use std::collections::{BTreeMap, BTreeSet};

    use soland_storage::RealmMetaRecord;
    use soland_storage_postgres::Db;

    use super::*;

    fn realm_meta(owner: &str) -> RealmMetaRecord {
        let now = chrono::Utc::now();
        RealmMetaRecord {
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
            plaintext_visible_services: BTreeSet::new(),
            plaintext_visible_service_classes: BTreeMap::new(),
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
}
