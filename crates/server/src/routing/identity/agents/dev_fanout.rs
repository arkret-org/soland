//! CKP-0008 — development-mode server-authored fan-out for the personal
//! agent provisioning / lifecycle surface (architecture option B).
//!
//! In `development_mode` soland materialises the durable sub-events that a
//! production client (yougen, holding the controller key) would sign and
//! submit itself (option A). Every event authored here uses the
//! controller's own bearer session as the author, so the envelope passes
//! `actor_id == session.actor` and the controller realm-membership check.
//! Production (`development_mode == false`) NEVER reaches this module: the
//! callers gate every entry point on `state.config.development_mode`.
//!
//! The dev-proof envelope shape is the one accepted by
//! `validate_event_proofs` (event_log/validation.rs): `type="dev-proof"`,
//! `verification_method == actor_id`, and `payload_digest` = the sha256 of
//! the canonical payload bytes.

use chrono::{Duration, SecondsFormat, Utc};
use cokret_sdk::canonical;
use serde_json::{Value, json};

use super::SessionRecord;
use crate::error::AppError;
use crate::ids;
use crate::routing::events::event_log::submit_event_value;
use crate::state::AppState;

/// Deterministic self realm for a controller principal. Reuses the
/// principal-control realm derivation so the realm id is a stable
/// UUIDv7-shaped value and `realm_has_member_by_id` already treats the
/// controller as a member (no separate account -> self_realm mapping
/// table is required).
pub(super) fn self_realm_for_controller(controller_did: &str) -> String {
    crate::routing::identity::recovery::principal_control_realm_for_did(controller_did)
}

/// Build a dev-proof envelope authored by `session.actor` and submit it via
/// the shared internal event API. `actor_seq` is taken as
/// `max_actor_seq(actor) + 1` so concurrent fan-out events stay strictly
/// increasing.
async fn dev_submit_event(
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
    let event_id = format!("ck:event:{event_uuid}");
    let operation_alias = format!("ck:operation:{}", uuid::Uuid::now_v7());
    let payload_bytes = canonical::canonical_json_bytes(&payload).unwrap_or_default();
    let payload_digest = canonical::sha256_digest(&payload_bytes);
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
            "verification_method": actor,
            "payload_digest": payload_digest,
        }],
    });
    let outcome = submit_event_value(state, session, envelope)
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "dev fan-out submit failed for {kind}: {} ({})",
                err.message, err.code
            ))
        })?;
    Ok(outcome.event_id)
}

/// Idempotently ensure the controller's self realm exists in the realm
/// index. When absent, submit the controller-authored `ck.realm.create`
/// genesis event (the `realm_create` bootstrap path admits the creator as
/// the first member). Returns the self realm id.
pub(super) async fn ensure_self_realm(
    state: &AppState,
    session: &SessionRecord,
) -> Result<String, AppError> {
    let realm_id = self_realm_for_controller(&session.actor);
    if crate::routing::events::event_log::realm_is_indexed(state, &realm_id) {
        return Ok(realm_id);
    }
    let payload = self_realm_create_payload(&session.actor, &state.config.service_did, &realm_id);
    dev_submit_event(state, session, &realm_id, "ck.realm.create", payload).await?;
    Ok(realm_id)
}

/// Minimal `realm_create_payload` for a controller self realm. Mirrors the
/// `ck.schema.realm.v1` object the conformance harness submits; the realm
/// is private (invite join) since it only ever hosts the controller and
/// the agent identity sub-events.
fn self_realm_create_payload(controller_did: &str, service_did: &str, realm_id: &str) -> Value {
    json!({
        "object": {
            "id": realm_id,
            "schema": "ck.schema.realm.v1",
            "title": "Personal Agent Control",
            "summary": "Controller self realm hosting personal agent identity events.",
            "created_by": controller_did,
            "trust_domain": "ck:trust_domain:soland.local",
            "schema_refs": ["ck.schema.realm.v1"],
            "default_discoverability": "listed",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "plaintext_visible_services": [service_did],
            "security_class": "standard",
            "federation_policy": "restricted",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
                "type": "single_did",
                "did": controller_did,
                "recovery_members": ["did:web:recovery.soland.local"],
                "controller_organization": "did:web:organization.primary.soland.local",
                "recovery_controller_organizations": [
                    "did:web:organization.recovery.soland.local"
                ],
            },
            "created_at": "2026-05-02T00:00:00Z",
        },
    })
}

/// CKP-0008 §4.3 — fan-out the three durable provisioning sub-events for a
/// freshly provisioned agent (option B). Returns the submitted event ids
/// `(profile_event, accountability_event, capability_grant_id)`. The
/// initial capability grant carries `effective_after_first_authorized_key`
/// so the evaluator fails closed until pairing completes (§4.3.2).
pub(super) async fn fanout_provision_subevents(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_principal_id: &str,
    display_name: Option<&str>,
    requested_scope: &Value,
) -> Result<(String, String, String), AppError> {
    let controller = session.actor.clone();
    // 1. Agent actor profile (`ck.profile.create`), authored by the controller with the agent
    //    principal as the profile subject. The `profile_create_payload` def resolves to
    //    `state_payload`, so the profile object rides in `value` (the soland actor-profile reducer
    //    is not wired; list/get read the agent_principals table).
    let profile_payload = json!({
        "value": {
            "id": format!("ck:actor_profile:{agent_principal_id}"),
            "schema": "ck.schema.actor_profile.v1",
            "actor_id": agent_principal_id,
            "actor_kind": "agent",
            "display_name": display_name.unwrap_or("Agent"),
            "status": "active",
        },
    });
    let profile_event = dev_submit_event(
        state,
        session,
        realm_id,
        "ck.profile.create",
        profile_payload,
    )
    .await?;

    // 2. Accountability grant (`ck.identity.accountability_grant`), issuer = controller, subject =
    //    agent. Resolves to `state_payload`.
    let now_utc = Utc::now();
    let accountability_payload = json!({
        "value": {
            "issuer": controller,
            "subject": agent_principal_id,
            "accountability_scope": controller,
            "not_before": now_utc.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expires_at": (now_utc + Duration::days(365))
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            "grant_status": "active",
        },
    });
    let accountability_event = dev_submit_event(
        state,
        session,
        realm_id,
        "ck.identity.accountability_grant",
        accountability_payload,
    )
    .await?;

    // 3. Initial capability grant (`ck.capability.grant`), issuer = controller, subject = agent,
    //    flagged inactive until pairing.
    let actions = initial_grant_actions(requested_scope);
    let grant_id = ids::generate_grant_id();
    let grant_payload = capability_grant_payload(
        &grant_id,
        realm_id,
        &controller,
        agent_principal_id,
        &actions,
        true,
    );
    materialize_grant(state, session, realm_id, grant_payload).await?;
    Ok((profile_event, accountability_event, grant_id))
}

/// Expand `requested_scope` (the provision request DSL) into a minimal
/// capability action set. With no preset / explicit actions we grant the
/// least-privilege read-only baseline (CKP-0008 §4.7 `read_only`).
fn initial_grant_actions(requested_scope: &Value) -> Vec<String> {
    let mut actions: Vec<String> = requested_scope
        .get("actions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if actions.is_empty() {
        actions = vec![
            "ck.self.events.subscribe".to_owned(),
            "ck.event.read".to_owned(),
        ];
    }
    actions
}

/// Build a `capability_grant_payload` (`{grant_id, grant}`) whose embedded
/// `grant` satisfies `capability-grant.schema.json` (id / schema / issuer /
/// subject / actions / resources / proofs all required). The embedded proof
/// is a dev placeholder generic detached-JWS shape; the durable authority is
/// the controller-authored envelope proof, this inner proof only satisfies
/// the structural `minItems:1` schema requirement.
fn capability_grant_payload(
    grant_id: &str,
    realm_id: &str,
    issuer: &str,
    subject: &str,
    actions: &[String],
    effective_after_first_authorized_key: bool,
) -> Value {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut grant = json!({
        "id": grant_id,
        "schema": "ck.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": issuer,
        "subject": subject,
        "actions": actions,
        "resources": [{ "kind": "realm", "realm_id": realm_id }],
        "issued_at": issued_at,
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": format!("{issuer}#dev"),
            "alg": "EdDSA",
            "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": issued_at,
            "jws": "dev",
        }],
    });
    if effective_after_first_authorized_key {
        grant.as_object_mut().expect("grant object").insert(
            "effective_after_first_authorized_key".to_owned(),
            Value::Bool(true),
        );
    }
    json!({ "grant_id": grant_id, "grant": grant })
}

async fn materialize_grant(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    grant_payload: Value,
) -> Result<String, AppError> {
    dev_submit_event(
        state,
        session,
        realm_id,
        "ck.capability.grant",
        grant_payload,
    )
    .await
}

/// CKP-0008 §4.11 (dev option B) — attach a controller-supplied capability
/// grant (`POST /_cokret/self/agents/{id}/grants`). The supplied body is
/// normalised into a schema-valid embedded `grant` (filling required id /
/// schema / issuer / subject / resources / proofs when the caller omitted
/// them) under the canonical `{grant_id, grant}` wrapper, then submitted as
/// `ck.capability.grant` authored by the controller.
pub(super) async fn attach_agent_grant_event(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_principal_id: &str,
    grant_id: &str,
    supplied_grant: &Value,
) -> Result<String, AppError> {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut grant = supplied_grant.clone();
    let obj = grant
        .as_object_mut()
        .ok_or_else(|| AppError::invalid_param("grant must be an object"))?;
    obj.insert("id".to_owned(), Value::String(grant_id.to_owned()));
    obj.entry("schema".to_owned())
        .or_insert_with(|| Value::String("ck.schema.capability.v1".to_owned()));
    obj.insert("realm_id".to_owned(), Value::String(realm_id.to_owned()));
    obj.entry("issuer".to_owned())
        .or_insert_with(|| Value::String(session.actor.clone()));
    obj.entry("subject".to_owned())
        .or_insert_with(|| Value::String(agent_principal_id.to_owned()));
    obj.entry("actions".to_owned())
        .or_insert_with(|| json!(["ck.event.read"]));
    obj.entry("resources".to_owned())
        .or_insert_with(|| json!([{ "kind": "realm", "realm_id": realm_id }]));
    obj.entry("issued_at".to_owned())
        .or_insert_with(|| Value::String(issued_at.clone()));
    obj.entry("proofs".to_owned()).or_insert_with(|| {
        json!([{
            "kind": "detached_jws",
            "verification_method": format!("{}#dev", session.actor),
            "alg": "EdDSA",
            "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": issued_at,
            "jws": "dev",
        }])
    });
    let payload = json!({ "grant_id": grant_id, "grant": grant });
    materialize_grant(state, session, realm_id, payload).await
}

/// CKP-0008 §4.5 / D3 — submit the durable `ck.agent.key.authorize` event
/// authored by the controller. The payload satisfies
/// `agent_key_authorize_payload` (all required fields). The soland reducer
/// projects it into the agent-key state cell and clears
/// `effective_after_first_authorized_key` on the agent's pending grants.
pub(super) async fn submit_durable_key_authorize(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_principal_id: &str,
    verification_method: &str,
    key_id: &str,
) -> Result<String, AppError> {
    let controller = session.actor.clone();
    let now_utc = Utc::now();
    let payload = json!({
        "agent_principal_id": agent_principal_id,
        "key_id": key_id,
        "verification_method": verification_method,
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": ["ck.self.events.subscribe", "ck.message.create", "ck.reaction.add"],
            "resources": [{ "kind": "realm", "realm_id": realm_id }],
        },
        "audience": [state.config.service_did.clone()],
        "issued_at": now_utc.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": (now_utc + Duration::days(90))
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        "approval_evidence": {
            "kind": "pairing_request",
            "ref": format!("ck:event:{}", uuid::Uuid::now_v7()),
        },
    });
    dev_submit_event(state, session, realm_id, "ck.agent.key.authorize", payload).await
}

/// CKP-0016 — materialise a participation `effective=true` decision into a
/// durable reply/reaction capability grant for the agent over the scope
/// resource. Idempotent on the deterministic `grant_id` derived from the
/// (agent, scope_key) pair.
pub(super) async fn materialize_capability_grant(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_principal_id: &str,
    resource: Value,
    grant_id: &str,
) -> Result<String, AppError> {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let grant = json!({
        "id": grant_id,
        "schema": "ck.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": session.actor.clone(),
        "subject": agent_principal_id,
        "actions": ["ck.message.create", "ck.reaction.add"],
        "resources": [resource],
        "issued_at": issued_at,
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": format!("{}#dev", session.actor),
            "alg": "EdDSA",
            "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": issued_at,
            "jws": "dev",
        }],
    });
    let payload = json!({ "grant_id": grant_id, "grant": grant });
    materialize_grant(state, session, realm_id, payload).await
}

/// CKP-0016 — revoke a previously materialised participation grant
/// (idempotent; `ck.capability.revoke` is a no-op when the grant_id was
/// never granted).
pub(super) async fn revoke_capability_grant(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    grant_id: &str,
) -> Result<String, AppError> {
    let payload = json!({ "grant_id": grant_id });
    dev_submit_event(state, session, realm_id, "ck.capability.revoke", payload).await
}

/// CKP-0008 §4.11 — submit a durable lifecycle transition event
/// (`ck.self.agent.{pause,resume,deactivate}`) driving the FSM reducer.
pub(super) async fn submit_durable_agent_lifecycle(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_principal_id: &str,
    event_kind: &str,
    previous_status: &str,
    reason: Option<&str>,
) -> Result<String, AppError> {
    let status_changed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let transition = match event_kind {
        "ck.self.agent.pause" => "pause",
        "ck.self.agent.resume" => "resume",
        "ck.self.agent.deactivate" => "deactivate",
        other => other,
    };
    let mut payload = json!({
        "agent_principal_id": agent_principal_id,
        "controller_principal_id": session.actor.clone(),
        "transition": transition,
        "previous_status": previous_status,
        "status_changed_at": status_changed_at,
    });
    if event_kind != "ck.self.agent.deactivate" {
        payload.as_object_mut().expect("payload object").insert(
            "freshness_frontier".to_owned(),
            json!({ "captured_at": status_changed_at }),
        );
    }
    if let Some(reason) = reason {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    dev_submit_event(state, session, realm_id, event_kind, payload).await
}

/// CKP-0008 §4.11 — on deactivate, fan-out `ck.agent.key.revoke` for the
/// agent's authorized key(s). Best-effort over the keys the reducer
/// projected; revoking with no known key still emits a tombstone-safe
/// revoke for the canonical `key_id`.
pub(super) async fn submit_revoke_agent_keys(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_principal_id: &str,
    key_ids: &[String],
) -> Result<(), AppError> {
    let revoked_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let targets: Vec<String> = if key_ids.is_empty() {
        vec![default_agent_key_id(agent_principal_id)]
    } else {
        key_ids.to_vec()
    };
    for key_id in targets {
        let payload = json!({
            "agent_principal_id": agent_principal_id,
            "key_id": key_id,
            "revoked_by": session.actor.clone(),
            "revoked_at": revoked_at,
        });
        dev_submit_event(state, session, realm_id, "ck.agent.key.revoke", payload).await?;
    }
    Ok(())
}

/// CKP-0008 §4.11 — on deactivate, fan-out `ck.capability.revoke` for every
/// grant id held by the agent.
pub(super) async fn submit_revoke_agent_grants(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    grant_ids: &[String],
) -> Result<(), AppError> {
    for grant_id in grant_ids {
        revoke_capability_grant(state, session, realm_id, grant_id).await?;
    }
    Ok(())
}

/// Deterministic default agent key id used by the dev pairing fan-out so
/// authorize / revoke target the same key without a key inventory table.
pub(super) fn default_agent_key_id(agent_principal_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ck:agent_key:dev:v1:");
    hasher.update(agent_principal_id.as_bytes());
    let digest = hasher.finalize();
    format!("ck:agent_key:{}", hex::encode(&digest[..16]))
}
