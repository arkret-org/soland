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
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};

use super::SessionRecord;
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::routing::events::event_log::submit_event_value;
use crate::state::AppState;

#[cfg(test)]
const SCOPE_EVENTS_QUERY_SCAN: &str = "ak.self.events.query.scan";
#[cfg(test)]
const SCOPE_EVENTS_STREAM_SUBSCRIBE: &str = "ak.self.events.stream.subscribe";
#[cfg(test)]
const SCOPE_EVENTS_COMMAND_SUBMIT: &str = "ak.self.events.command.submit";
const ACTION_EVENT_READ: &str = "ak.event.read";
const ACTION_MESSAGE_CREATE: &str = "ak.message.create";
const ACTION_REACTION_ADD: &str = "ak.reaction.add";

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

/// Development-only delegated authoring for control facts that belong to the
/// Agent principal. The controller is the proof signer/executor; the Agent is
/// the principal of record and therefore owns actor_seq and the PCR stream.
async fn submit_managed_agent_control_event(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
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
    let authorization_ref =
        crate::routing::identity::managed_agent_pcr::controller_authorization_ref(agent_id);
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
    // issuing the initial grant so this aggregate stays correct even when a
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
    meta: &crate::state::RealmMetaRecord,
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
                crate::reducer::SolandRealmState {
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
/// them after it has locally created the Agent PCR MLS state. Returns
/// `(accountability_event, selector_event, capability_grant_ids)`. The
/// initial capability grant carries `effective_after_first_authorized_key`
/// so the evaluator fails closed until pairing completes (§4.3.2).
pub(super) async fn fanout_provision_subevents(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    agent_id: &str,
    agent_slug: &str,
    requested_scope: &Value,
) -> Result<(String, String, Vec<String>), AppError> {
    let controller = session.actor.clone();
    // 1. Accountability grant, issuer = controller and subject = Agent.
    let now_utc = Utc::now();
    let created_at = now_utc.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut accountability_payload = json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer": controller,
        "subject": agent_id,
        "accountability_scope": "agent_operator",
        "not_before": created_at,
        "grant_status": "active",
    });
    insert_nested_dev_proof(&mut accountability_payload, "proof", &controller)?;
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
    let mut selector_payload = json!({
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
    insert_nested_dev_proofs(&mut selector_payload, &controller)?;
    let selector_event = submit_agent_fanout_event(
        state,
        session,
        realm_id,
        "ak.agent.selector_claim",
        selector_payload,
    )
    .await?;

    // 3. Initial capability grant (`ak.capability.grant`), issuer = controller, subject = agent,
    //    flagged inactive until pairing.
    let actions = initial_grant_actions(requested_scope);
    let constraints = initial_grant_constraints(requested_scope, &actions);
    let mut grant_ids = Vec::new();
    for (grant_realm_id, resources) in
        initial_content_grant_resources_by_realm(requested_scope, &actions)?
    {
        let grant_id = ids::generate_grant_id();
        let grant_payload = capability_grant_payload(
            &grant_id,
            &grant_realm_id,
            &controller,
            agent_id,
            &actions,
            &resources,
            &constraints,
            true,
        );
        materialize_grant(state, session, &grant_realm_id, grant_payload).await?;
        grant_ids.push(grant_id);
    }
    Ok((accountability_event, selector_event, grant_ids))
}

fn insert_nested_dev_proof(
    payload: &mut Value,
    field: &str,
    controller: &str,
) -> Result<(), AppError> {
    let digest = canonical::canonical_sha256(payload)
        .map_err(|error| AppError::internal(format!("nested proof digest failed: {error}")))?;
    payload.as_object_mut().expect("payload object").insert(
        field.to_owned(),
        json!({
            "type": "dev-proof",
            "verification_method": controller,
            "payload_digest": digest,
        }),
    );
    Ok(())
}

fn insert_nested_dev_proofs(payload: &mut Value, controller: &str) -> Result<(), AppError> {
    let digest = canonical::canonical_sha256(payload)
        .map_err(|error| AppError::internal(format!("nested proofs digest failed: {error}")))?;
    payload.as_object_mut().expect("payload object").insert(
        "proofs".to_owned(),
        json!([{
            "type": "dev-proof",
            "verification_method": controller,
            "payload_digest": digest,
        }]),
    );
    Ok(())
}

/// Re-issue the initial pending capability grant for a pairing renewal
/// (`ak.self.agent.command.renew_pairing`). The pairing-expiry cleanup
/// auto-revoked the provision-time grant, so a renewed pairing re-runs step 3
/// of [`fanout_provision_subevents`] with the persisted `requested_scope` —
/// same actions, same `effective_after_first_authorized_key=true` flag.
pub(super) async fn fanout_renewal_grants(
    state: &AppState,
    session: &SessionRecord,
    agent_id: &str,
    requested_scope: &Value,
) -> Result<Vec<String>, AppError> {
    let controller = session.actor.clone();
    let actions = initial_grant_actions(requested_scope);
    let constraints = initial_grant_constraints(requested_scope, &actions);
    let mut grant_ids = Vec::new();
    for (grant_realm_id, resources) in
        initial_content_grant_resources_by_realm(requested_scope, &actions)?
    {
        let grant_id = ids::generate_grant_id();
        let grant_payload = capability_grant_payload(
            &grant_id,
            &grant_realm_id,
            &controller,
            agent_id,
            &actions,
            &resources,
            &constraints,
            true,
        );
        materialize_grant(state, session, &grant_realm_id, grant_payload).await?;
        grant_ids.push(grant_id);
    }
    Ok(grant_ids)
}

/// Expand `requested_scope` (the provision request DSL) into a minimal
/// content capability action set. Service-surface actions may be present in
/// `agent_key_scope.actions`, but they are never materialized as
/// `ak.capability.grant.actions`. An omitted/empty scope grants no implicit
/// content access.
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
    explicit_actions
        .into_iter()
        .filter(|action| initial_capability_grant_action(action))
        .collect()
}

pub(super) fn validate_initial_content_grant_scope(
    requested_scope: &Value,
) -> Result<(), AppError> {
    let actions = initial_grant_actions(requested_scope);
    initial_content_grant_resources_by_realm(requested_scope, &actions).map(|_| ())
}

fn initial_content_grant_resources_by_realm(
    requested_scope: &Value,
    content_actions: &[String],
) -> Result<Vec<(String, Vec<Value>)>, AppError> {
    if content_actions.is_empty() {
        return Ok(Vec::new());
    }

    let mut grouped = std::collections::BTreeMap::<String, Vec<Value>>::new();
    for resource in requested_scope
        .get("resources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = resource
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("requested_scope resource kind is missing"))?;
        if matches!(kind, "operation" | "service") {
            continue;
        }
        let realm_id = resource
            .get("realm_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::invalid_param(format!(
                    "requested_scope {kind} resource requires realm_id for a content grant"
                ))
            })?;
        let selector = match kind {
            "realm" => json!({
                "kind": "realm",
                "realm_id": realm_id,
                "match_scope": "realm_wide",
            }),
            "strand" | "space" | "object" => {
                let resource_ref = resource
                    .get("resource_ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AppError::invalid_param(format!(
                            "requested_scope {kind} resource requires resource_ref"
                        ))
                    })?;
                let expected_prefix = match kind {
                    "strand" => "ak:strand:",
                    "space" => "ak:space:",
                    "object" => "ak:",
                    _ => unreachable!(),
                };
                if !resource_ref.starts_with(expected_prefix) {
                    return Err(AppError::invalid_param(format!(
                        "requested_scope {kind} resource_ref has the wrong typed-id kind"
                    )));
                }
                let id_field = match kind {
                    "strand" => "strand_id",
                    "space" => "space_id",
                    "object" => "object_ref",
                    _ => unreachable!(),
                };
                let mut selector = serde_json::Map::new();
                selector.insert("kind".to_owned(), Value::String(kind.to_owned()));
                selector.insert("realm_id".to_owned(), Value::String(realm_id.to_owned()));
                selector.insert(id_field.to_owned(), Value::String(resource_ref.to_owned()));
                Value::Object(selector)
            }
            _ => {
                return Err(AppError::invalid_param(format!(
                    "requested_scope resource kind `{kind}` cannot back a content grant"
                )));
            }
        };
        grouped
            .entry(realm_id.to_owned())
            .or_default()
            .push(selector);
    }
    if grouped.is_empty() {
        return Err(AppError::invalid_param(
            "requested_scope content actions require at least one Realm-scoped content resource",
        ));
    }
    Ok(grouped.into_iter().collect())
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
    resources: &[Value],
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
        "resources": resources,
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
    submit_managed_agent_control_event(state, session, realm_id, agent_id, event_kind, payload)
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

    use serde_json::json;
    use soland_data::Db;

    use super::*;
    use crate::state::RealmMetaRecord;

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
    fn initial_grant_default_adds_no_content_access() {
        let actions = initial_grant_actions(&Value::Null);

        assert!(actions.is_empty());
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
            "resources": [{
                "kind": "realm",
                "realm_id": "ak:realm:01964137-0000-7000-8000-000000000002"
            }],
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
        let resources = initial_content_grant_resources_by_realm(&requested, &actions)
            .expect("content resources")
            .remove(0)
            .1;
        let payload = capability_grant_payload(
            "ak:grant:01964137-0000-7000-8000-000000000001",
            "ak:realm:01964137-0000-7000-8000-000000000002",
            "did:web:controller.example",
            "did:web:agent.example",
            &actions,
            &resources,
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

    #[test]
    fn requested_scope_content_grants_preserve_governed_realm() {
        let realm_id = "ak:realm:01964137-0000-7000-8000-000000000002";
        let requested = json!({
            "actions": [ACTION_EVENT_READ],
            "resources": [{ "kind": "realm", "realm_id": realm_id }]
        });
        let actions = initial_grant_actions(&requested);
        let grants = initial_content_grant_resources_by_realm(&requested, &actions)
            .expect("content scope must map to one grant");

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].0, realm_id);
        assert_eq!(grants[0].1[0]["realm_id"], realm_id);
        assert_eq!(grants[0].1[0]["match_scope"], "realm_wide");
    }

    #[test]
    fn requested_scope_rejects_content_actions_without_content_resources() {
        let requested = json!({
            "actions": [ACTION_EVENT_READ],
            "resources": [{
                "kind": "service",
                "service_id": "did:web:soland.example"
            }]
        });
        let actions = initial_grant_actions(&requested);

        assert!(initial_content_grant_resources_by_realm(&requested, &actions).is_err());
    }
}
