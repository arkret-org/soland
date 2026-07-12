//! AKP-0008 — development-mode server-authored fan-out for the personal
//! agent provisioning / lifecycle surface (architecture option B).
//!
//! Soland materialises the durable sub-events required by the personal-agent
//! aggregate surfaces. Every event authored here uses the controller's own
//! authenticated session as the author, so the envelope passes
//! `actor_id == session.actor` and the controller realm-membership check.
//!
//! The dev-proof envelope shape is the one accepted by
//! `validate_event_proofs` (event_log/validation.rs): `type="dev-proof"`,
//! `verification_method == actor_id`, and `payload_digest` = the sha256 of
//! the canonical payload bytes.

use arkret_sdk::canonical;
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{Value, json};

use super::SessionRecord;
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::routing::events::event_log::submit_event_value;
use crate::state::AppState;

const SCOPE_EVENTS_QUERY_SCAN: &str = "ak.self.events.query.scan";
const SCOPE_EVENTS_STREAM_SUBSCRIBE: &str = "ak.self.events.stream.subscribe";
const SCOPE_EVENTS_COMMAND_SUBMIT: &str = "ak.self.events.command.submit";
const ACTION_EVENT_READ: &str = "ak.event.read";
const ACTION_MESSAGE_CREATE: &str = "ak.message.create";
const ACTION_REACTION_ADD: &str = "ak.reaction.add";

/// Deterministic self realm for a controller principal. Reuses the
/// principal-control realm derivation so the realm id is a stable
/// UUIDv7-shaped value and `realm_has_member_by_id` already treats the
/// controller as a member (no separate account -> self_realm mapping
/// table is required).
pub(super) fn self_realm_for_controller(controller_id: &str) -> String {
    crate::routing::identity::recovery::principal_control_realm_for_did(controller_id)
}

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

/// Idempotently ensure the controller's self realm exists in the realm
/// index. When absent, submit the controller-authored `ak.realm.create`
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
    let payload = self_realm_create_payload(&session.actor, &state.config.service_id, &realm_id);
    submit_agent_fanout_event(state, session, &realm_id, "ak.realm.create", payload).await?;
    Ok(realm_id)
}

/// Minimal `realm_create_payload` for a controller self realm. Mirrors the
/// `ak.schema.realm.v1` object the conformance harness submits; the realm
/// is private (invite join) since it only ever hosts the controller and
/// the agent identity sub-events.
fn self_realm_create_payload(controller_id: &str, service_id: &str, realm_id: &str) -> Value {
    json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Personal Agent Control",
            "summary": "Controller self realm hosting personal agent identity events.",
            "created_by": controller_id,
            "trust_domain": "ak:trust_domain:soland.local",
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "listed",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "plaintext_visible_services": [service_id],
            "security_class": "standard",
            "federation_policy": "restricted",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
                "type": "single_did",
                "did": controller_id,
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

/// AKP-0008 §4.3 — fan-out the three durable provisioning sub-events for a
/// freshly provisioned agent (option B). Returns the submitted event ids
/// `(profile_event, accountability_event, capability_grant_id)`. The
/// initial capability grant carries `effective_after_first_authorized_key`
/// so the evaluator fails closed until pairing completes (§4.3.2).
pub(super) async fn fanout_provision_subevents(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    display_name: Option<&str>,
    agent_slug: &str,
    avatar_blob_ref: Option<&str>,
    requested_scope: &Value,
) -> Result<(String, String, Vec<String>), AppError> {
    let controller = session.actor.clone();
    // 1. Agent actor profile (`ak.profile.create`), authored by the controller with the agent
    //    principal as the profile subject. The `profile_create_payload` def resolves to
    //    `state_payload`, so the profile object rides in `value` (the soland actor-profile reducer
    //    is not wired; list/get read the agent_principals table).
    let mut profile = json!({
        "id": format!("ak:actor_profile:{agent_id}"),
        "schema": "ak.schema.actor_profile.v1",
        "actor_id": agent_id,
        "actor_kind": "agent",
        "display_name": display_name.unwrap_or("Agent"),
        "agent_slug": agent_slug,
    });
    if let Some(avatar_blob_ref) = avatar_blob_ref {
        profile
            .as_object_mut()
            .expect("agent profile is an object")
            .insert(
                "avatar_blob_ref".to_owned(),
                Value::String(avatar_blob_ref.to_owned()),
            );
    }
    profile
        .as_object_mut()
        .expect("agent profile is an object")
        .insert("status".to_owned(), Value::String("active".to_owned()));
    let profile_payload = json!({ "value": profile });
    let profile_event = submit_agent_fanout_event(
        state,
        session,
        realm_id,
        "ak.profile.create",
        profile_payload,
    )
    .await?;

    // 2. Accountability grant (`ak.identity.accountability_grant`), issuer = controller, subject =
    //    agent. Resolves to `state_payload`.
    let now_utc = Utc::now();
    let accountability_payload = json!({
        "value": {
            "issuer": controller,
            "subject": agent_id,
            "accountability_scope": controller,
            "not_before": now_utc.to_rfc3339_opts(SecondsFormat::Secs, true),
            "expires_at": (now_utc + Duration::days(365))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            "grant_status": "active",
        },
    });
    let accountability_event = submit_agent_fanout_event(
        state,
        session,
        realm_id,
        "ak.identity.accountability_grant",
        accountability_payload,
    )
    .await?;

    // 3. Initial capability grant (`ak.capability.grant`), issuer = controller, subject = agent,
    //    flagged inactive until pairing.
    let actions = initial_grant_actions(requested_scope);
    let constraints = initial_grant_constraints(requested_scope, &actions);
    let mut grant_ids = Vec::new();
    if !actions.is_empty() {
        let grant_id = ids::generate_grant_id();
        let grant_payload = capability_grant_payload(
            &grant_id,
            realm_id,
            &controller,
            agent_id,
            &actions,
            &constraints,
            true,
        );
        materialize_grant(state, session, realm_id, grant_payload).await?;
        grant_ids.push(grant_id);
    }
    Ok((profile_event, accountability_event, grant_ids))
}

/// Re-issue the initial pending capability grant for a pairing renewal
/// (`ak.self.agent.command.renew_pairing`). The pairing-expiry cleanup
/// auto-revoked the provision-time grant, so a renewed pairing re-runs step 3
/// of [`fanout_provision_subevents`] with the persisted `requested_scope` —
/// same actions, same `effective_after_first_authorized_key=true` flag.
pub(super) async fn fanout_renewal_grants(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    requested_scope: &Value,
) -> Result<Vec<String>, AppError> {
    let controller = session.actor.clone();
    let actions = initial_grant_actions(requested_scope);
    let constraints = initial_grant_constraints(requested_scope, &actions);
    let mut grant_ids = Vec::new();
    if !actions.is_empty() {
        let grant_id = ids::generate_grant_id();
        let grant_payload = capability_grant_payload(
            &grant_id,
            realm_id,
            &controller,
            agent_id,
            &actions,
            &constraints,
            true,
        );
        materialize_grant(state, session, realm_id, grant_payload).await?;
        grant_ids.push(grant_id);
    }
    Ok(grant_ids)
}

/// Expand `requested_scope` (the provision request DSL) into a minimal
/// content capability action set. Service-surface actions may be present in
/// `agent_key_scope.actions`, but they are never materialized as
/// `ak.capability.grant.actions`. With no explicit actions we grant the
/// least-privilege read baseline (AKP-0008 §4.7 `read`).
fn initial_grant_actions(requested_scope: &Value) -> Vec<String> {
    let explicit_actions: Vec<String> = requested_scope
        .get("actions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if explicit_actions.is_empty() {
        return vec![ACTION_EVENT_READ.to_owned()];
    }
    explicit_actions
        .into_iter()
        .filter(|action| initial_capability_grant_action(action))
        .collect()
}

fn initial_grant_constraints(requested_scope: &Value, content_actions: &[String]) -> Vec<Value> {
    requested_scope
        .get("constraints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|constraint| {
            constraint
                .get("applies_to_actions")
                .and_then(Value::as_array)
                .is_none_or(|applies_to| {
                    applies_to.iter().any(|action| {
                        action
                            .as_str()
                            .is_some_and(|action| content_actions.iter().any(|item| item == action))
                    })
                })
        })
        .cloned()
        .collect()
}

fn initial_capability_grant_action(action: &str) -> bool {
    matches!(
        action,
        ACTION_EVENT_READ
            | ACTION_MESSAGE_CREATE
            | ACTION_REACTION_ADD
            | "ak.agent.draft.propose"
            | "ak.agent.action_request"
            | "ak.strand.create"
            | "ak.strand.update"
            | "ak.relation.create"
    )
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
    constraints: &[Value],
    effective_after_first_authorized_key: bool,
) -> Value {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut grant = json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
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
            "jws": "a..b",
        }],
    });
    if effective_after_first_authorized_key {
        grant.as_object_mut().expect("grant object").insert(
            "effective_after_first_authorized_key".to_owned(),
            Value::Bool(true),
        );
    }
    if !constraints.is_empty() {
        grant
            .as_object_mut()
            .expect("grant object")
            .insert("constraints".to_owned(), Value::Array(constraints.to_vec()));
    }
    json!({ "grant_id": grant_id, "grant": grant })
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

/// AKP-0008 §4.11 (dev option B) — attach a controller-supplied capability
/// grant (`POST /_arkret/self/agents/{id}/grants`). The supplied body is
/// normalised into a schema-valid embedded `grant` (filling required id /
/// schema / issuer / subject / resources / proofs when the caller omitted
/// them) under the canonical `{grant_id, grant}` wrapper, then submitted as
/// `ak.capability.grant` authored by the controller.
pub(super) async fn attach_agent_grant_event(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    grant_id: &str,
    supplied_grant: &Value,
) -> Result<String, AppError> {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut grant = supplied_grant.clone();
    let obj = grant
        .as_object_mut()
        .ok_or_else(|| AppError::invalid_param("grant must be an object"))?;
    obj.insert("id".to_owned(), Value::String(grant_id.to_owned()));
    obj.entry("schema".to_owned())
        .or_insert_with(|| Value::String("ak.schema.capability.v1".to_owned()));
    obj.insert("realm_id".to_owned(), Value::String(realm_id.to_owned()));
    obj.entry("issuer".to_owned())
        .or_insert_with(|| Value::String(session.actor.clone()));
    obj.entry("subject".to_owned())
        .or_insert_with(|| Value::String(agent_id.to_owned()));
    obj.entry("actions".to_owned())
        .or_insert_with(|| json!(["ak.event.read"]));
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
            "jws": "a..b",
        }])
    });
    let payload = json!({ "grant_id": grant_id, "grant": grant });
    materialize_grant(state, session, realm_id, payload).await
}

/// AKP-0008 §4.5 / D3 — submit the durable `ak.agent.key.authorize` event
/// authored by the controller. The payload satisfies
/// `agent_key_authorize_payload` (all required fields). The soland reducer
/// projects it into the agent-key state cell and clears
/// `effective_after_first_authorized_key` on the agent's pending grants.
pub(super) async fn submit_durable_key_authorize(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    verification_method: &str,
    key_id: &str,
) -> Result<String, AppError> {
    let controller = session.actor.clone();
    let now_utc = Utc::now();
    let payload = json!({
        "agent_id": agent_id,
        "key_id": key_id,
        "verification_method": verification_method,
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [
                SCOPE_EVENTS_STREAM_SUBSCRIBE,
                SCOPE_EVENTS_QUERY_SCAN,
                SCOPE_EVENTS_COMMAND_SUBMIT,
                ACTION_EVENT_READ,
                ACTION_MESSAGE_CREATE,
                ACTION_REACTION_ADD,
            ],
            "resources": [{ "kind": "realm", "realm_id": realm_id }],
        },
        "audience": [state.config.service_id.clone()],
        "issued_at": now_utc.to_rfc3339_opts(SecondsFormat::Secs, true),
        "expires_at": (now_utc + Duration::days(90))
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        "approval_evidence": {
            "kind": "approval_event",
            "ref": format!("ak:event:{}", uuid::Uuid::now_v7()),
        },
    });
    submit_agent_fanout_event(state, session, realm_id, "ak.agent.key.authorize", payload).await
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
    if event_kind != "ak.self.agent.deactivate" {
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
    if event_kind == "ak.self.agent.resume"
        && let Some(ack) = sidecar_exposure_ack
    {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("sidecar_exposure_ack".to_owned(), ack.clone());
    }
    submit_agent_fanout_event(state, session, realm_id, event_kind, payload).await
}

/// AKP-0008 §4.11 — on deactivate, fan-out `ak.agent.key.revoke` for the
/// agent's authorized key(s). Best-effort over the keys the reducer
/// projected; revoking with no known key still emits a tombstone-safe
/// revoke for the canonical `key_id`.
pub(super) async fn submit_revoke_agent_keys(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    key_ids: &[String],
) -> Result<(), AppError> {
    let revoked_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let targets: Vec<String> = if key_ids.is_empty() {
        vec![default_agent_key_id(agent_id)]
    } else {
        key_ids.to_vec()
    };
    for key_id in targets {
        let payload = json!({
            "agent_id": agent_id,
            "key_id": key_id,
            "revoked_by": session.actor.clone(),
            "revoked_at": revoked_at,
        });
        submit_agent_fanout_event(state, session, realm_id, "ak.agent.key.revoke", payload).await?;
    }
    Ok(())
}

/// AKP-0008 §4.11 — on deactivate, fan-out `ak.capability.revoke` for every
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
pub(super) fn default_agent_key_id(agent_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ak:agent_key:dev:v1:");
    hasher.update(agent_id.as_bytes());
    let digest = hasher.finalize();
    format!("ak:agent_key:{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
    fn initial_grant_default_uses_content_read_only() {
        let actions = initial_grant_actions(&Value::Null);

        assert_eq!(actions, vec![ACTION_EVENT_READ.to_owned()]);
    }

    #[test]
    fn runtime_agent_key_scope_service_actions_are_registered() {
        let registry = crate::artifacts::operation_ids();
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
        let registry = crate::artifacts::operation_ids();
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
    fn requested_scope_actions_filter_service_surface_from_content_grant() {
        let requested = json!({
            "actions": [SCOPE_EVENTS_STREAM_SUBSCRIBE, SCOPE_EVENTS_QUERY_SCAN, ACTION_MESSAGE_CREATE],
            "resources": [{ "kind": "realm", "realm_id": "ak:realm:test" }]
        });

        assert_eq!(
            initial_grant_actions(&requested),
            vec![ACTION_MESSAGE_CREATE.to_owned()]
        );
    }

    #[test]
    fn requested_scope_service_only_creates_no_content_grant() {
        let requested = json!({
            "actions": [SCOPE_EVENTS_STREAM_SUBSCRIBE, SCOPE_EVENTS_QUERY_SCAN],
            "resources": [{ "kind": "realm", "realm_id": "ak:realm:test" }]
        });

        assert!(initial_grant_actions(&requested).is_empty());
    }

    #[test]
    fn requested_scope_preserves_content_grant_constraints() {
        let requested = json!({
            "actions": [ACTION_MESSAGE_CREATE],
            "resources": [{ "kind": "operation", "operation": ACTION_MESSAGE_CREATE }],
            "constraints": [{
                "constraint_type": "claim_based",
                "effect": "require_review",
                "subtype": "accountability",
                "applies_to_actions": [ACTION_MESSAGE_CREATE],
                "controller_approval_required": true
            }]
        });

        let actions = initial_grant_actions(&requested);
        let constraints = initial_grant_constraints(&requested, &actions);
        let payload = capability_grant_payload(
            "ak:grant:01964137-0000-7000-8000-000000000001",
            "ak:realm:01964137-0000-7000-8000-000000000002",
            "did:web:controller.example",
            "did:web:agent.example",
            &actions,
            &constraints,
            true,
        );

        assert_eq!(payload["grant"]["constraints"], requested["constraints"]);
    }

    #[test]
    fn requested_scope_does_not_copy_service_only_constraints_to_content_grant() {
        let requested = json!({
            "actions": [ACTION_EVENT_READ, SCOPE_EVENTS_QUERY_SCAN],
            "resources": [{ "kind": "operation", "operation": ACTION_EVENT_READ }],
            "constraints": [{
                "constraint_type": "scope_limitation",
                "effect": "allow",
                "applies_to_actions": [SCOPE_EVENTS_QUERY_SCAN]
            }]
        });
        let actions = initial_grant_actions(&requested);

        assert!(initial_grant_constraints(&requested, &actions).is_empty());
    }
}
