//! Invite addressing protocol surface.
//!
//! Implements the v1 private invite delivery endpoint and the body-only
//! online locator resolver from `sync/invite-addressing.md`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{Duration, SecondsFormat};
use cokret_sdk::{Did, InviteDeliveryRequest, canonical};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, SessionRecord};
use crate::wire::now;

const HEADER_CONTENT_DIGEST: &str = "content-digest";
const HEADER_SOURCE_SERVICE_DID: &str = "source-service-did";
const HEADER_DESTINATION_SERVICE_DID: &str = "destination-service-did";
const DEFAULT_LOCATOR_TTL_MINUTES: i64 = 15;

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("invites").post(peer_invites_submit))
}

pub(crate) fn open_router() -> Router {
    Router::new().push(Router::with_path("invite-locators/resolve").post(resolve_invite_locator))
}

#[endpoint(
    operation_id = "ck.peer.invites.submit",
    tags("peer"),
    summary = "Private Principal Server invite delivery"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.invites.submit"))]
async fn peer_invites_submit(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<Value>()
        .await
        .map_err(|_| AppError::bad_json("invalid ck.peer.invites.submit request body"))?;
    super::events::peer::validate_peer_request(state, req, Some(&body))?;
    validate_content_digest(req, &body)?;

    let delivery: InviteDeliveryRequest =
        serde_json::from_value(body.clone()).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "invalid ck.peer.invites.submit shape: {error}"
            ))
        })?;
    delivery.validate_minimal().map_err(|error| {
        super::events::peer::schema_violation(format!("invalid invite delivery request: {error}"))
    })?;

    let destination_service_did = required_header(req, HEADER_DESTINATION_SERVICE_DID)?;
    if destination_service_did != delivery.invite_address.recipient_service_did.as_str() {
        return Err(super::events::peer::cross_domain_replay(
            "Destination-Service-DID must equal invite_address.recipient_service_did",
        ));
    }

    validate_invite_delivery_consistency(&body, &delivery, state)?;
    let evidence_kind = body
        .pointer("/introduction_evidence/kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let receive_action = receive_action_for_evidence(evidence_kind);
    if receive_action != InviteReceiveAction::Notify {
        super::append_audit_log(
            state,
            None,
            "peer.invites.submit",
            json!({
                "idempotency_key": delivery.idempotency_key,
                "invitee": delivery.invite_address.subject_id,
                "recipient_service_did": delivery.invite_address.recipient_service_did,
                "introduction_kind": evidence_kind,
                "receive_action": receive_action.as_str()
            }),
            "deferred",
        )
        .await;
        return json_ok(json!({
            "status": "deferred",
            "received_at": now().to_rfc3339_opts(SecondsFormat::Millis, true)
        }));
    }

    let actor = body
        .pointer("/invite_event/actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.actor_id is required"))?
        .to_owned();
    let source_service_did = required_header(req, HEADER_SOURCE_SERVICE_DID)?;
    let trust_headers =
        crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
            .map_err(|violation| {
                super::events::peer::schema_violation(violation.message())
                    .with_wire_code(violation.error_code())
            })?;
    let request_hash = canonical::canonical_sha256(&body).map_err(|error| {
        super::events::peer::schema_violation(format!(
            "ck.peer.invites.submit body is not canonical-hashable: {error}"
        ))
    })?;
    let session = SessionRecord {
        token_hash: format!(
            "peer-invite:{}:{request_hash}",
            trust_headers.source_trust_domain
        ),
        actor,
        device_id: format!("peer-invite:{source_service_did}"),
        audience: state.config.service_did.clone(),
        expires_at: now() + Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    };

    let response =
        super::events::event_log::submit_event_value(state, &session, body["invite_event"].clone())
            .await
            .map_err(|error| {
                AppError::new(ErrorCode::SchemaViolation, error.message)
                    .with_status(error.status)
                    .with_wire_code(error.code)
            })?;

    let status = if response.status == "duplicate" {
        "duplicate"
    } else {
        "accepted"
    };
    super::append_audit_log(
        state,
        None,
        "peer.invites.submit",
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": response.event_id,
            "invitee": delivery.invite_address.subject_id,
            "recipient_service_did": delivery.invite_address.recipient_service_did,
            "introduction_kind": evidence_kind,
            "request_canonical_digest": request_hash,
        }),
        status,
    )
    .await;
    json_ok(json!({
        "status": status,
        "received_at": response.received_at.to_rfc3339_opts(SecondsFormat::Millis, true)
    }))
}

#[endpoint(
    operation_id = "ck.open.invite_locator.resolve",
    tags("open"),
    summary = "Resolve an online invite locator token"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.invite_locator.resolve"))]
async fn resolve_invite_locator(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    if locator_token_appears_in_url(req) {
        return Err(AppError::invalid_param(
            "locator_token must be sent in the JSON body, never in URL path or query",
        )
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation"));
    }
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<Value>()
        .await
        .map_err(|_| AppError::bad_json("invalid invite locator resolve request body"))?;
    let locator_token = body
        .get("locator_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| is_locator_token_shape(value))
        .ok_or_else(invite_locator_not_found)?;
    let locator_ref = decode_locator_token(locator_token).ok_or_else(invite_locator_not_found)?;
    let subject_id = locator_ref
        .get("subject_id")
        .and_then(Value::as_str)
        .filter(|value| Did::new((*value).to_owned()).is_ok())
        .ok_or_else(invite_locator_not_found)?;
    if locator_ref
        .get("nonce")
        .and_then(Value::as_str)
        .filter(|value| is_locator_token_shape(value))
        .is_none()
    {
        return Err(invite_locator_not_found());
    }
    if let Some(expires_at) = locator_ref
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        && expires_at <= now()
    {
        return Err(invite_locator_not_found());
    }

    let issued_at = now();
    let expires_at = locator_ref
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| issued_at + Duration::minutes(DEFAULT_LOCATOR_TTL_MINUTES));
    let locator_ref_digest = canonical::sha256_digest(locator_token.as_bytes());
    let mut unsigned_locator = json!({
        "schema": "ck.schema.principal_locator.v1",
        "subject_id": subject_id,
        "recipient_service_did": state.config.service_did,
        "issued_at": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "locator_ref_digest": locator_ref_digest,
    });
    if let Some(display_hint) = locator_ref.get("display_hint") {
        unsigned_locator["display_hint"] = display_hint.clone();
    }
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned_locator)
        .map_err(|error| AppError::internal(format!("principal locator canonicalize: {error}")))?;
    let payload_digest = canonical::sha256_digest(&canonical_bytes);
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&canonical_bytes, state.anchorer_signing_key().as_ref())
            .map_err(|error| AppError::internal(format!("principal locator sign: {error}")))?;
    let mut locator = unsigned_locator;
    locator["proofs"] = json!([{
        "proof_purpose": "recipient_service_acceptance",
        "proof": {
            "kind": "detached_jws",
            "verification_method": format!("{}#server-key-1", state.config.service_did),
            "alg": "EdDSA",
            "payload_digest": payload_digest,
            "created_at": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "jws": jws,
        }
    }]);
    json_ok(locator)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InviteReceiveAction {
    Notify,
    Deferred,
}

impl InviteReceiveAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::Deferred => "deferred",
        }
    }
}

fn receive_action_for_evidence(kind: &str) -> InviteReceiveAction {
    match kind {
        "locator_ref" | "shared_realm" | "same_principal_server" => InviteReceiveAction::Notify,
        "explicit_address" => InviteReceiveAction::Deferred,
        _ => InviteReceiveAction::Deferred,
    }
}

fn validate_invite_delivery_consistency(
    body: &Value,
    delivery: &InviteDeliveryRequest,
    state: &AppState,
) -> Result<(), AppError> {
    if delivery.invite_address.recipient_service_did.as_str() != state.config.service_did {
        return Err(super::events::peer::cross_domain_replay(
            "invite_address.recipient_service_did does not match this service",
        ));
    }
    if body.pointer("/invite_event/kind").and_then(Value::as_str)
        != Some(crate::kinds::CK_INVITE_CREATE)
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.kind must be ck.invite.create",
        ));
    }
    let payload = body
        .pointer("/invite_event/payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    if payload.get("invitee").and_then(Value::as_str)
        != Some(delivery.invite_address.subject_id.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invitee must equal invite_address.subject_id",
        ));
    }
    if payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_service_did"))
        .and_then(Value::as_str)
        != Some(delivery.invite_address.recipient_service_did.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invite_delivery_target.recipient_service_did must equal invite_address.recipient_service_did",
        ));
    }
    if let Some(service_type) = payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_service_type"))
        .and_then(Value::as_str)
        && service_type != "principal_server"
    {
        return Err(super::events::peer::schema_violation(
            "invite_delivery_target.recipient_service_type must be principal_server",
        ));
    }
    let evidence_digest =
        canonical::canonical_sha256(&body["introduction_evidence"]).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "introduction_evidence is not canonical-hashable: {error}"
            ))
        })?;
    if payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        != Some(evidence_digest.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.introduction_evidence_digest must equal digest(canonical_json(introduction_evidence))",
        ));
    }
    Ok(())
}

fn validate_content_digest(req: &Request, body: &Value) -> Result<(), AppError> {
    let header = required_header(req, HEADER_CONTENT_DIGEST)?;
    let canonical_bytes = canonical::canonical_json_bytes(body).map_err(|error| {
        super::events::peer::schema_violation(format!(
            "request body is not canonical-hashable: {error}"
        ))
    })?;
    let expected = format!("sha-256=:{}:", STANDARD.encode(canonical_bytes));
    if header != expected {
        crate::metrics::record_digest_mismatch("peer_invites_content_digest");
        return Err(super::events::peer::cross_domain_replay(
            "Content-Digest does not match the canonical request body",
        ));
    }
    Ok(())
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            super::events::peer::schema_violation(format!(
                "required federation header {name} missing"
            ))
        })
}

fn locator_token_appears_in_url(req: &Request) -> bool {
    req.uri()
        .query()
        .is_some_and(|query| query.contains("locator_token=") || query.contains("token="))
}

fn is_locator_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_locator_token(locator_token: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(locator_token.as_bytes()).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

fn invite_locator_not_found() -> AppError {
    AppError::not_found("invite locator not found")
}
