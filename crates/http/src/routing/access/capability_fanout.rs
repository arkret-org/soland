use arkret_event_draft::Operation;
use arkret_identifiers::{CellRef, Did, EventId, GrantId, OperationId, RealmId};
use arkret_state::lattice::CellState;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
// SOL-DRY-03 — the coauth↔soland fanout wire contract is shared via
// soland-contracts (same pattern as the sodmin admin seal DTOs); do not
// re-declare these shapes locally.
use soland_contracts::integration::capability_fanout::{
    CapabilityFanoutAuthzState, CapabilityFanoutBody, CapabilityFanoutResponse,
};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_http::util::{bearer_token, sha256_hex};

use crate::state::AppState;

const FANOUT_KIND: &str = "org.arkret.coauth.collaboration_capability.fanout.v1";
const SOURCE_DEVICE_ID: &str = "coauth-capability-fanout";
const DIGEST_HEADER: &str = "x-arkret-capability-fanout-digest";

#[derive(Clone, Debug)]
struct CapabilityFanoutDraft {
    operation: Operation,
    event_id: String,
    event_kind: String,
    operation_name: String,
    capability_grant_id: String,
    realm_id: String,
    subject: Option<String>,
}

pub(super) fn router() -> Router {
    Router::new().push(Router::with_path("authz/capability-fanout").post(submit_fanout))
}

// Deployment-local server-to-server product surface, mounted under the
// `/_soland/root/...` negative-space root (NOT the `/_arkret/*` protocol
// root). Per service-http-binding.md §2.1.3(b), a product / deployment-private
// capability between the Auth Server (coauth) and this Principal Server MUST
// live on the implementation's own root and MUST NOT occupy a `/_arkret/*`
// production trust-surface segment. coauth issues this fanout in its Auth-Server
// role — it holds no principal session, so the protocol `POST /_arkret/self/events`
// path (which requires `user_session` / `device_proof` / a principal-authorised
// delegated service signature, service-http-binding.md §2.1 row `self/events`
// + §189) is not an available caller surface. The reverse-DNS `org.arkret.soland.*`
// operation_id mirrors the device-signing-key directory read
// (`org.arkret.soland.gate.account.device_signing_keys.query`): both are
// deployment-internal S2S contracts, not spec operations. Trust boundary is
// registered in coauth `docs/{zh,en}/setup/principal-server.md`.
#[endpoint(
    operation_id = "org.arkret.soland.root.authz.capability_fanout.submit",
    tags("soland-local"),
    summary = "Materialize coauth-issued collaboration capability fanout (deployment-internal S2S)"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.root.authz.capability_fanout.submit")
)]
async fn submit_fanout(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CapabilityFanoutResponse> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_fanout_bearer(state, req)?;

    let body_value = body.into_inner();
    validate_header_digest(req, &body_value)?;
    super::validate_canonical_json_value(&body_value).map_err(AppError::invalid_param)?;
    let body: CapabilityFanoutBody = serde_json::from_value(body_value)
        .map_err(|error| AppError::bad_json(format!("invalid capability fanout body: {error}")))?;
    let draft = build_projectable_operation(idempotency_key(req), body)?;

    let duplicate = projection_event_duplicate(state, &draft).await?;
    if !duplicate {
        crate::routing::events::projection::project_accepted_operations_from_device(
            state,
            draft.operation.payload["issuer_service_id"]
                .as_str()
                .unwrap_or_default(),
            SOURCE_DEVICE_ID,
            std::slice::from_ref(&draft.operation),
        )
        .await;
    }

    let authz_state = authz_state_for_draft(state, &draft);
    ensure_materialized(&draft, &authz_state)?;

    json_ok(CapabilityFanoutResponse {
        accepted: (!duplicate)
            .then(|| draft.event_id.clone())
            .into_iter()
            .collect(),
        duplicate: duplicate
            .then(|| draft.event_id.clone())
            .into_iter()
            .collect(),
        event_id: draft.event_id,
        capability_grant_id: draft.capability_grant_id,
        operation: draft.operation_name,
        authz_state,
    })
}

fn require_fanout_bearer(state: &AppState, req: &Request) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::new(
            soland_http::error::ErrorCode::TemporarilyUnavailable,
            "capability fanout requires SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        )
        .with_status(StatusCode::SERVICE_UNAVAILABLE));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "capability fanout requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid capability fanout bearer",
        ));
    }
    Ok(())
}

fn validate_header_digest(req: &Request, body: &Value) -> Result<(), AppError> {
    let Some(expected) = req
        .headers()
        .get(DIGEST_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let actual = arkret_canonical::canonical_sha256(body)
        .map_err(|error| AppError::invalid_param(format!("fanout body digest failed: {error}")))?;
    if expected != actual {
        return Err(AppError::invalid_param(
            "x-arkret-capability-fanout-digest does not match body",
        ));
    }
    Ok(())
}

fn build_projectable_operation(
    idempotency_key: Option<String>,
    body: CapabilityFanoutBody,
) -> Result<CapabilityFanoutDraft, AppError> {
    let operation_name = body.operation;
    let issuer_service_id = body.issuer_service_id;
    let event_kind = body.event_kind;
    let event_id = body.event_id;
    let capability_grant_id = body.capability_grant_id;
    let principal_server_count = body.principal_servers.len();
    if body.kind != FANOUT_KIND {
        return Err(AppError::invalid_param(
            "unsupported capability fanout kind",
        ));
    }
    Did::new(issuer_service_id.clone())
        .map_err(|_| AppError::invalid_param("issuer_service_id must be a DID"))?;
    EventId::new(event_id.clone())
        .map_err(|_| AppError::invalid_param("event_id must be a ak:event id"))?;
    GrantId::new(capability_grant_id.clone())
        .map_err(|_| AppError::invalid_param("capability_grant_id must be a ak:grant id"))?;
    if principal_server_count > 256 {
        return Err(AppError::invalid_param("principal_servers is too large"));
    }

    let expected_event_kind = match operation_name.as_str() {
        "grant" => arkret_wire::events::EventKind::CAPABILITY_GRANT,
        "revoke" => arkret_wire::events::EventKind::CAPABILITY_REVOKE,
        _ => return Err(AppError::invalid_param("operation must be grant or revoke")),
    };
    if event_kind != expected_event_kind {
        return Err(AppError::invalid_param(
            "operation does not match event_kind",
        ));
    }

    let mut payload = body.payload;
    let payload_object = payload
        .as_object_mut()
        .ok_or_else(|| AppError::invalid_param("payload must be an object"))?;
    require_payload_grant_id(payload_object, &capability_grant_id)?;
    match payload_object.get("event_id").and_then(Value::as_str) {
        Some(existing) if existing != event_id => {
            return Err(AppError::invalid_param(
                "payload.event_id does not match event_id",
            ));
        }
        Some(_) => {}
        None => {
            payload_object.insert("event_id".to_owned(), Value::String(event_id.clone()));
        }
    }
    payload_object.insert(
        "issuer_service_id".to_owned(),
        Value::String(issuer_service_id.clone()),
    );

    let (realm_id, subject) = match operation_name.as_str() {
        "grant" => {
            validate_grant_payload(payload_object, &capability_grant_id, &issuer_service_id)?
        }
        "revoke" => validate_revoke_payload(payload_object)?,
        _ => unreachable!("operation checked above"),
    };
    let operation_id = operation_id_for_event_id(&event_id)?;
    let realm = RealmId::new(realm_id.clone())
        .map_err(|_| AppError::invalid_param("realm_id must be a ak:realm id"))?;
    let mut operation = Operation::create(
        operation_id,
        realm,
        expected_event_kind,
        Value::Object(payload_object.clone()),
    );
    operation.idempotency_key = idempotency_key;

    Ok(CapabilityFanoutDraft {
        operation,
        event_id,
        event_kind,
        operation_name,
        capability_grant_id,
        realm_id,
        subject,
    })
}

fn idempotency_key(req: &Request) -> Option<String> {
    req.headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn require_payload_grant_id(
    payload: &serde_json::Map<String, Value>,
    capability_grant_id: &str,
) -> Result<(), AppError> {
    match payload.get("grant_id").and_then(Value::as_str) {
        Some(value) if value == capability_grant_id => Ok(()),
        Some(_) => Err(AppError::invalid_param(
            "payload.grant_id does not match capability_grant_id",
        )),
        None => Err(AppError::invalid_param("payload.grant_id is required")),
    }
}

fn validate_grant_payload(
    payload: &serde_json::Map<String, Value>,
    capability_grant_id: &str,
    issuer_service_id: &str,
) -> Result<(String, Option<String>), AppError> {
    let grant = payload
        .get("grant")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("payload.grant must be an object"))?;
    let grant_id = grant
        .get("id")
        .or_else(|| grant.get("grant_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("payload.grant.id is required"))?;
    if grant_id != capability_grant_id {
        return Err(AppError::invalid_param(
            "payload.grant.id does not match capability_grant_id",
        ));
    }
    match grant.get("issuer").and_then(Value::as_str) {
        Some(issuer) if issuer == issuer_service_id => {}
        Some(_) => {
            return Err(AppError::invalid_param(
                "payload.grant.issuer does not match issuer_service_id",
            ));
        }
        None => return Err(AppError::invalid_param("payload.grant.issuer is required")),
    }
    let realm_id = grant
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("payload.grant.realm_id is required"))?;
    RealmId::new(realm_id.to_owned())
        .map_err(|_| AppError::invalid_param("payload.grant.realm_id must be a ak:realm id"))?;
    let subject = grant
        .get("subject")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("payload.grant.subject is required"))?;
    if grant
        .get("actions")
        .and_then(Value::as_array)
        .is_none_or(|actions| actions.is_empty() || actions.iter().any(|v| !v.is_string()))
    {
        return Err(AppError::invalid_param(
            "payload.grant.actions must be a non-empty string array",
        ));
    }
    let actions = grant["actions"]
        .as_array()
        .expect("validated actions array")
        .iter()
        .map(|value| value.as_str().expect("validated action string").to_owned())
        .collect::<Vec<_>>();
    let registry_digest = match grant.get("capability_action_registry_digest") {
        None => None,
        Some(Value::String(value)) if value.starts_with("sha256:") => {
            Some(arkret_identifiers::Hash::new(value.clone()).map_err(|_| {
                AppError::invalid_param(
                    "payload.grant.capability_action_registry_digest must be sha256",
                )
            })?)
        }
        Some(_) => {
            return Err(AppError::invalid_param(
                "payload.grant.capability_action_registry_digest must be sha256",
            ));
        }
    };
    arkret_policy::validate_capability_action_registry_binding(&actions, registry_digest.as_ref())
        .map_err(|_| {
            AppError::invalid_param("payload.grant capability registry basis is unavailable")
        })?;
    if grant
        .get("resources")
        .and_then(Value::as_array)
        .is_none_or(|resources| resources.is_empty())
    {
        return Err(AppError::invalid_param(
            "payload.grant.resources must be a non-empty array",
        ));
    }
    require_non_empty_proofs(grant, "payload.grant.proofs")?;
    Ok((realm_id.to_owned(), Some(subject.to_owned())))
}

fn validate_revoke_payload(
    payload: &serde_json::Map<String, Value>,
) -> Result<(String, Option<String>), AppError> {
    let realm_id = payload
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("payload.realm_id is required"))?;
    RealmId::new(realm_id.to_owned())
        .map_err(|_| AppError::invalid_param("payload.realm_id must be a ak:realm id"))?;
    require_non_empty_proofs(payload, "payload.proofs")?;
    Ok((realm_id.to_owned(), None))
}

fn require_non_empty_proofs(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), AppError> {
    if object
        .get("proofs")
        .and_then(Value::as_array)
        .is_none_or(|proofs| proofs.is_empty())
    {
        return Err(AppError::invalid_param(format!("{field} is required")));
    }
    Ok(())
}

fn operation_id_for_event_id(event_id: &str) -> Result<OperationId, AppError> {
    let Some(suffix) = event_id.strip_prefix("ak:event:") else {
        return Err(AppError::invalid_param("event_id must use ak:event prefix"));
    };
    OperationId::new(format!("ak:operation:{suffix}"))
        .map_err(|_| AppError::invalid_param("event_id does not map to a valid operation id"))
}

async fn projection_event_duplicate(
    state: &AppState,
    draft: &CapabilityFanoutDraft,
) -> Result<bool, AppError> {
    let existing = state
        .event_query_application()
        .projected_events()
        .await
        .map_err(|error| AppError::internal(format!("projection event lookup failed: {error}")))?
        .into_iter()
        .find(|record| record.event_id == draft.event_id);
    let Some(existing) = existing else {
        return Ok(false);
    };
    if existing.event_kind != draft.event_kind {
        return Err(AppError::conflict(
            "event_id already exists with a different event_kind",
        ));
    }
    Ok(true)
}

fn authz_state_for_draft(
    state: &AppState,
    draft: &CapabilityFanoutDraft,
) -> CapabilityFanoutAuthzState {
    let grant = state
        .authorization_application()
        .get_grant(&draft.capability_grant_id);
    let effective = match draft.subject.as_deref() {
        Some(subject) => state
            .authorization_application()
            .grants_for_subject(subject, &draft.realm_id)
            .iter()
            .any(|grant| grant.grant_id == draft.capability_grant_id),
        None => false,
    };
    let revoked = grant.as_ref().is_some_and(|grant| grant.revoked)
        || projected_capability_cell_revoked(state, &draft.capability_grant_id);
    CapabilityFanoutAuthzState {
        projected: grant.is_some() || revoked,
        effective,
        revoked,
        grant_present: grant.is_some(),
    }
}

fn projected_capability_cell_revoked(state: &AppState, grant_id: &str) -> bool {
    let Ok(cell_ref) = CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    )) else {
        return false;
    };
    let projection = state.projection_application().snapshot();
    let Some(CellState::Value(Value::Array(items))) = projection.cells.get(&cell_ref) else {
        return false;
    };
    items.iter().any(|item| {
        item.get("value")
            .unwrap_or(item)
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    })
}

fn ensure_materialized(
    draft: &CapabilityFanoutDraft,
    authz_state: &CapabilityFanoutAuthzState,
) -> Result<(), AppError> {
    match draft.operation_name.as_str() {
        "grant" if authz_state.projected && authz_state.effective && !authz_state.revoked => Ok(()),
        "revoke" if authz_state.projected && authz_state.revoked && !authz_state.effective => {
            Ok(())
        }
        _ => Err(AppError::internal(format!(
            "capability fanout did not materialize verifiable authz state: {}",
            json!({
                "event_id": draft.event_id,
                "capability_grant_id": draft.capability_grant_id,
                "operation": draft.operation_name,
                "authz_state": {
                    "projected": authz_state.projected,
                    "effective": authz_state.effective,
                    "revoked": authz_state.revoked,
                    "grant_present": authz_state.grant_present,
                }
            })
        ))),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const EVENT: &str = "ak:event:01970000-0000-7000-8000-000000000001";
    const GRANT: &str = "ak:grant:01970000-0000-7000-8000-000000000002";
    const REALM: &str = "ak:realm:01970000-0000-7000-8000-000000000003";
    const ISSUER: &str = "did:web:coauth.example";
    const SUBJECT: &str = "did:web:alice.example";

    fn grant_body() -> CapabilityFanoutBody {
        CapabilityFanoutBody {
            kind: FANOUT_KIND.to_owned(),
            operation: "grant".to_owned(),
            issuer_service_id: ISSUER.to_owned(),
            event_kind: arkret_wire::events::EventKind::CAPABILITY_GRANT.to_owned(),
            event_id: EVENT.to_owned(),
            capability_grant_id: GRANT.to_owned(),
            payload: json!({
                "grant_id": GRANT,
                "grant": {
                    "id": GRANT,
                    "schema": "ak.schema.capability.v1",
                    "realm_id": REALM,
                    "issuer": ISSUER,
                    "subject": SUBJECT,
                    "actions": ["ak.message.create"],
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                    "issued_at": "2026-01-01T00:00:00.000Z",
                    "proofs": [{ "kind": "detached_jws" }]
                }
            }),
            principal_servers: Vec::new(),
        }
    }

    #[test]
    fn grant_fanout_builds_capability_operation() {
        let draft = build_projectable_operation(None, grant_body()).unwrap();

        assert_eq!(draft.event_id, EVENT);
        assert_eq!(
            draft.operation.object_type,
            arkret_wire::events::EventKind::CAPABILITY_GRANT
        );
        assert_eq!(draft.realm_id, REALM);
        assert_eq!(draft.subject.as_deref(), Some(SUBJECT));
        assert_eq!(
            draft.operation.operation_id.to_string(),
            "ak:operation:01970000-0000-7000-8000-000000000001"
        );
        assert_eq!(draft.operation.payload["event_id"], EVENT);
    }

    #[test]
    fn grant_fanout_rejects_mismatched_grant_id() {
        let mut body = grant_body();
        body.payload["grant"]["id"] = json!("ak:grant:01970000-0000-7000-8000-0000000000aa");

        assert!(build_projectable_operation(None, body).is_err());
    }
}
