//! MIMI (Messaging Layer Interop) provider-facade handlers.
//!
//! Surfaces under `/_cokret/open/mimi/*` plus the well-known
//! `mimi-protocol-directory`. Writes from the MIMI side map into the
//! canonical Cokret reducer chain:
//!
//!   * `POST /mimi/strands/{strand_id}/messages` -> emits a `MessageRecord` + a `ck.message.create`
//!     projection event so the MIMI ingress shows up on the canonical Cokret timeline.
//!   * `POST /mimi/strands/{strand_id}/update` -> emits a `ck.mimi.room_binding` projection event
//!     whenever the update body carries a `room_binding` block.
//!   * `POST /mimi/strands/{strand_id}/notify` -> broadcasts a synthetic
//!     `ck.open.mimi.command.notify` projection event so live subscribers observe MIMI fanout.
//!   * `POST /mimi/report-abuse` -> persists the moderation report row AND emits a
//!     `ck.self.moderation.report` projection event so the audit timeline reflects the report.
//!
//! Each canonical event carries `payload.mimi_provenance` metadata
//! (provider id, original MIMI envelope hash, MIMI message id) so
//! the receiving Cokret consumer can prove the message arrived
//! through the MIMI facade rather than as a native signed Move.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Duration;
use cokret_sdk::models::proof_kind;
use cokret_sdk::{
    Did, EventId, Hash, MimiGroupInfoOutcome, MimiIdentifierQueryOutcome,
    MimiIdentifierQueryRequestBody, MimiKeyMaterialOutcome, MimiKeyMaterialRequestBody,
    MimiNotifyOutcome, MimiNotifyRequestBody, MimiProxyDownloadOutcome,
    MimiProxyDownloadRequestBody, MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
    MimiRequestConsentOutcome, MimiRequestConsentRequestBody, MimiRoomUpdateOutcome,
    MimiRoomUpdateRequestBody, MimiSubmitMessageOutcome, MimiSubmitMessageRequestBody,
    MimiUpdateConsentOutcome, MimiUpdateConsentRequestBody, Proof, RealmId, ReportId, canonical,
};
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::moderation::{
    moderation_request_source_ip_hash, moderation_request_source_service,
    validate_moderation_report_safety,
};
use super::{append_audit_log, now, sha256_hex};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::events::projection::{append_projection_event, projection_event_json};
use crate::routing::identity::consent::{
    materialize_mimi_consent_request, materialize_mimi_consent_update_by_id,
};
use crate::state::{
    AppState, CanonicalEventRecord, EventNotification, MessageRecord, ProjectionEventRecord,
};
use crate::{ids, kinds};

const EVENT_SCHEMA_ID: &str = "ck.schema.event.v1";
const MIMI_REASON_GOVERNANCE_BINDING_MISSING: &str = "mimi_governance_binding_missing";
const MIMI_REASON_GOVERNANCE_BINDING_MISMATCH: &str = "mimi_governance_binding_mismatch";
const MIMI_REASON_OBSERVER_WRITE_FORBIDDEN: &str = "mimi_observer_write_forbidden";
const MIMI_REASON_ROOM_STATE_INCOMPATIBLE: &str = "mimi_room_state_incompatible";
const MIMI_REASON_ROOM_BINDING_TRANSITION_INVALID: &str =
    "mimi_room_binding_status_transition_invalid";

struct MimiRoomBindingProjection {
    event_id: String,
    realm_id: String,
    binding: Value,
}

pub(super) fn router() -> Router {
    Router::with_path("mimi")
        .push(Router::with_path("provider-directory").get(mimi_provider_directory))
        .push(Router::with_path("key-material").post(mimi_key_material))
        .push(Router::with_path("strands/{strand_id}/update").post(mimi_room_update))
        .push(Router::with_path("strands/{strand_id}/notify").post(mimi_notify))
        .push(Router::with_path("strands/{strand_id}/messages").post(mimi_room_message))
        .push(Router::with_path("strands/{strand_id}/group-info").get(mimi_group_info))
        .push(Router::with_path("consent/request").post(mimi_consent_request))
        .push(Router::with_path("consent/update").post(mimi_consent_update))
        .push(Router::with_path("identifiers/query").post(mimi_identifiers_query))
        .push(Router::with_path("report-abuse").post(mimi_report_abuse))
        .push(Router::with_path("proxy-download").post(mimi_proxy_download))
}

pub(super) fn well_known_router() -> Router {
    Router::with_path(".well-known/mimi-protocol-directory").get(mimi_protocol_directory)
}

fn verify_mimi_write_service_proof(
    state: &AppState,
    req: &Request,
    body: &Value,
    room_uri: Option<&str>,
) -> Result<(), AppError> {
    let signature_present =
        req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some();
    if !signature_present {
        return Err(mimi_signature_error_required(
            "MIMI writes require RFC 9421 Signature and Signature-Input headers",
        ));
    }

    let body_bytes = cokret_sdk::canonical::canonical_json_bytes(body).map_err(|error| {
        AppError::invalid_param(format!("MIMI request body is not canonical JSON: {error}"))
    })?;
    let expected_content_digest = mimi_content_digest_header(&body_bytes);
    let content_digest = mimi_required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        return Err(mimi_signature_error_invalid(
            "Content-Digest does not cover the canonical MIMI request body",
        ));
    }
    let expected_request_digest = cokret_sdk::canonical::sha256_digest(&body_bytes);
    let request_digest = mimi_required_header(req, "request-canonical-digest")?;
    if request_digest != expected_request_digest {
        return Err(mimi_signature_error_invalid(
            "Request-Canonical-Digest does not match the canonical MIMI request body",
        ));
    }

    let source_service_did = mimi_required_header(req, "source-service-did")?;
    if !source_service_did.starts_with("did:") {
        return Err(mimi_signature_error_invalid(
            "Source-Service-DID must be a DID",
        ));
    }
    let destination_service_did = mimi_required_header(req, "destination-service-did")?;
    if destination_service_did != state.config.service_did {
        return Err(mimi_signature_error_invalid(
            "Destination-Service-DID does not match this service",
        ));
    }
    let provider_id = mimi_required_header(req, "provider-id")?;
    if !provider_id.starts_with("mimi://") {
        return Err(mimi_signature_error_invalid(
            "Provider-ID must be a MIMI provider URI",
        ));
    }
    let signed_room_uri = match room_uri {
        Some(expected) => {
            let observed = mimi_required_header(req, "mimi-room-uri")?;
            if observed != expected {
                return Err(mimi_signature_error_invalid(
                    "MIMI-Room-URI does not match the addressed room",
                ));
            }
            Some(observed)
        }
        None => None,
    };

    let signature_params = mimi_signature_params(req)?;
    let verification_method =
        mimi_validate_signature_params(&signature_params, &source_service_did, room_uri.is_some())?;
    let method = req.method().as_str().to_ascii_uppercase();
    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    let signature_base = mimi_http_signature_base(
        &method,
        &target_uri,
        &authority,
        &content_digest,
        &request_digest,
        &source_service_did,
        &destination_service_did,
        &provider_id,
        signed_room_uri.as_deref(),
        &signature_params,
    );
    mimi_verify_signature_header(state, req, &verification_method, &signature_base)
}

fn mimi_content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!("sha-256=:{}:", STANDARD.encode(raw))
}

fn mimi_required_header(req: &Request, name: &str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            mimi_signature_error_invalid(format!("missing required MIMI signature header: {name}"))
        })
}

fn mimi_signature_params(req: &Request) -> Result<String, AppError> {
    req.headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| mimi_signature_error_required("missing Signature-Input header"))?
        .strip_prefix("sig1=")
        .map(ToOwned::to_owned)
        .ok_or_else(|| mimi_signature_error_invalid("Signature-Input must carry sig1 parameters"))
}

fn mimi_signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    signature_params.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
}

fn mimi_validate_signature_params(
    signature_params: &str,
    source_service_did: &str,
    room_scoped: bool,
) -> Result<String, AppError> {
    for component in [
        "@method",
        "@target-uri",
        "@authority",
        "content-digest",
        "request-canonical-digest",
        "source-service-did",
        "destination-service-did",
        "provider-id",
    ] {
        let needle = format!("\"{component}\"");
        if !signature_params.contains(&needle) {
            return Err(mimi_signature_error_invalid(format!(
                "Signature-Input missing required MIMI component {component}"
            )));
        }
    }
    if room_scoped && !signature_params.contains("\"mimi-room-uri\"") {
        return Err(mimi_signature_error_invalid(
            "Signature-Input missing required MIMI component mimi-room-uri",
        ));
    }

    let verification_method = mimi_signature_param_value(signature_params, "keyid")
        .ok_or_else(|| mimi_signature_error_invalid("Signature-Input missing keyid"))?;
    let expected_prefix = format!("{source_service_did}#");
    if !verification_method.starts_with(&expected_prefix) {
        return Err(mimi_signature_error_invalid(
            "Signature-Input keyid must be controlled by Source-Service-DID",
        ));
    }
    if mimi_signature_param_value(signature_params, "alg").as_deref() != Some("ed25519") {
        return Err(mimi_signature_error_invalid(
            "Signature-Input alg must be ed25519",
        ));
    }

    let now = chrono::Utc::now().timestamp();
    let created = mimi_signature_param_value(signature_params, "created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            mimi_signature_error_window("Signature-Input missing required `created` parameter")
        })?;
    let expires = mimi_signature_param_value(signature_params, "expires")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            mimi_signature_error_window("Signature-Input missing required `expires` parameter")
        })?;
    if (created - now).abs() > 30 {
        return Err(mimi_signature_error_window(
            "signature created timestamp outside +/-30s clock-skew window",
        ));
    }
    if expires < created || expires - created > 300 {
        return Err(mimi_signature_error_window(
            "signature validity window exceeds 300s",
        ));
    }
    if expires < now {
        return Err(mimi_signature_error_window("signature is expired"));
    }
    Ok(verification_method)
}

#[allow(clippy::too_many_arguments)]
fn mimi_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: &str,
    request_digest: &str,
    source_service_did: &str,
    destination_service_did: &str,
    provider_id: &str,
    room_uri: Option<&str>,
    signature_params: &str,
) -> String {
    let room_component = room_uri
        .map(|room_uri| format!("\"mimi-room-uri\": {room_uri}\n"))
        .unwrap_or_default();
    format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"request-canonical-digest\": {request_digest}\n\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"provider-id\": {provider_id}\n\
         {room_component}\
         \"@signature-params\": {signature_params}",
    )
}

fn mimi_verify_signature_header(
    state: &AppState,
    req: &Request,
    verification_method: &str,
    signature_base: &str,
) -> Result<(), AppError> {
    let signature_header = mimi_required_header(req, "signature")?;
    let signature = mimi_decode_signature_header(&signature_header)
        .map_err(|message| mimi_signature_error_invalid(format!("signature decode: {message}")))?;
    let verifying_key = mimi_resolve_verifying_key(state, verification_method)?;
    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| mimi_signature_error_invalid("signature verification failed"))
}

fn mimi_decode_signature_header(value: &str) -> Result<ed25519_dalek::Signature, &'static str> {
    let signature_b64 = value
        .strip_prefix("sig1=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or("Signature header must use sig1=:base64: form")?;
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| "Signature header base64 is invalid")?;
    ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|_| "Signature header is not Ed25519 length")
}

fn mimi_resolve_verifying_key(
    state: &AppState,
    verification_method: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method) {
        return Ok(key);
    }
    if state.config.development_mode {
        let mut hasher = Sha256::new();
        hasher.update(b"soland:mimi-provider-key:");
        hasher.update(verification_method.as_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        return Ok(signing.verifying_key());
    }
    Err(mimi_signature_error_invalid(
        "MIMI provider verification key is unavailable",
    ))
}

fn mimi_signature_error_required(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("http_signature_required")
}

fn mimi_signature_error_invalid(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("http_signature_invalid")
}

fn mimi_signature_error_window(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("signature_window_invalid")
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "mimi_protocol_directory"))]
async fn mimi_protocol_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[endpoint(
    operation_id = "ck.open.mimi.query.provider_directory",
    tags("mimi"),
    summary = "Read the MIMI provider directory"
)]
#[tracing::instrument(skip_all, fields(op = "mimi_provider_directory"))]
async fn mimi_provider_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[endpoint(
    operation_id = "ck.open.mimi.exchange.request_key_material",
    tags("mimi"),
    summary = "Claim MIMI/MLS key material for a target identifier"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.exchange.request_key_material"))]
async fn mimi_key_material(
    body: JsonBody<MimiKeyMaterialRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiKeyMaterialOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi key material")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let target = body
        .get("target_identifier")
        .or_else(|| body.get("target_did"))
        .or_else(|| body.get("mimi_room_uri"))
        .or_else(|| body.get("strand_id"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.exchange.request_key_material",
        &body,
        json!({
            "target": target,
            "keypackage_claim_lifecycle": "single_use_required",
            "production_gap": "full_mls_keypackage_claim_not_implemented"
        }),
    );
    json_ok(MimiKeyMaterialOutcome {
        key_packages: Vec::new(),
        group_info: Value::Null,
        failures: json!([]),
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.command.update_room",
    tags("mimi"),
    summary = "Apply a MIMI room update (optionally persists `room_binding`)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.update_room"))]
async fn mimi_room_update(
    strand_id: PathParam<String>,
    body: JsonBody<MimiRoomUpdateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRoomUpdateOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi room update")?;
    let room_uri = mimi_room_uri(state, &room_id);
    verify_mimi_write_service_proof(state, req, &body, Some(&room_uri))?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    // If the update carries a `room_binding` block, persist it as a
    // `ck.mimi.room_binding` projection event so the Cokret
    // timeline observes the binding. Updates without a binding block
    // fall through to the receipt-only response. A binding block that
    // omits both `binding_scope.realm_id` and a top-level `realm_id`
    // is rejected; we never implicitly route to a default Realm.
    let update_payload = decode_mimi_update_payload(&body)?;
    let binding_event_id = match update_payload
        .as_ref()
        .and_then(mimi_room_binding_payload)
        .filter(|binding| binding.is_object())
    {
        Some(binding) => {
            let event_id = emit_mimi_room_binding_event(state, &room_id, binding)
                .await?
                .ok_or_else(|| {
                    AppError::invalid_param(
                        "room_binding requires `binding_scope.realm_id` or a top-level `realm_id`",
                    )
                    .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING)
                })?;
            Some(event_id)
        }
        _ => None,
    };

    let room_state_ref = binding_event_id
        .as_deref()
        .map(EventId::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("MIMI room state ref: {error}")))?;
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.update_room",
        &body,
        json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "truth_source": "cokret_signed_event_reducer",
            "status": "projected",
            "binding_emitted": binding_event_id.is_some(),
        }),
    );
    json_ok(MimiRoomUpdateOutcome {
        accepted: true,
        room_state_ref,
        rejected: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.command.notify",
    tags("mimi"),
    summary = "Fan out a MIMI notify (broadcasts a `ck.open.mimi.command.notify` ephemeral)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.notify"))]
async fn mimi_notify(
    strand_id: PathParam<String>,
    body: JsonBody<MimiNotifyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiNotifyOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi notify")?;
    let room_uri = mimi_room_uri(state, &room_id);
    verify_mimi_write_service_proof(state, req, &body, Some(&room_uri))?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    // Fan out a synthetic `ck.open.mimi.command.notify` projection event so live
    // subscribers observe the MIMI provider-to-provider
    // notification. The notify event is an ephemeral signal in the
    // spec's wire_scope taxonomy - we broadcast but don't persist
    // into projection_events so it doesn't pollute durable history.
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Cokret Realm")
            .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING)
    })?;
    let event_id = ids::generate_event_id();
    let notify_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ck.open.mimi.command.notify".to_owned(),
        operation_type: "mimi_facade_notify".to_owned(),
        operation_id: None,
        sender: None,
        payload: json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "mimi_room_id": room_id,
            "mimi_provider_id": mimi_provider_id(state),
            "notify_body": body.clone(),
            "facade": "soland.mimi.v1",
        }),
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        notify_record.realm_id.clone(),
        notify_record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&notify_record),
    ));

    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.notify",
        &body,
        json!({
            "delivery": "queued",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "broadcast_emitted": true,
            "broadcast_event_id": event_id,
        }),
    );
    json_ok(MimiNotifyOutcome {
        accepted: true,
        retry_after_ms: None,
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.command.submit_message",
    tags("mimi"),
    summary = "Submit a MIMI room message (mapped into ck.message.create projection)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.submit_message"))]
async fn mimi_room_message(
    strand_id: PathParam<String>,
    body: JsonBody<MimiSubmitMessageRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiSubmitMessageOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi submit message")?;
    let room_uri = mimi_room_uri(state, &room_id);
    verify_mimi_write_service_proof(state, req, &body, Some(&room_uri))?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let message = decode_mimi_message_payload(&body)?;
    let source_format = message
        .get("source_format")
        .or_else(|| {
            body.get("ciphertext")
                .and_then(|ciphertext| ciphertext.get("content_type"))
        })
        .and_then(|value| value.as_str())
        .unwrap_or("application/mimi-content");
    if !valid_mimi_content_type(source_format) {
        return Err(AppError::invalid_param("unsupported MIMI content type"));
    }
    let operation_id = ids::generate_operation_id();
    let event_id = ids::generate_event_id();
    let mimi_message_id = message
        .get("mimi_message_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "mimi-msg-{}",
                operation_id.trim_start_matches("ck:operation:")
            )
        });
    let original_hash = body
        .get("original_envelope_hash")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| cokret_sdk::canonical::sha256_digest(body.to_string().as_bytes()));

    // Map the MIMI message into the canonical Cokret timeline.
    // Append a MessageRecord + a `ck.message.create` projection event so
    // the message shows up in `GET /_cokret/self/events?realm_id=...`. The
    // MIMI provenance metadata is preserved verbatim under
    // `payload.mimi_provenance` so audit consumers can verify the
    // message arrived through the facade.
    let room_binding = latest_mimi_room_binding(state, &room_id)
        .await
        .ok_or_else(|| {
            AppError::not_found("MIMI room is not bound to any Cokret Realm")
                .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING)
        })?;
    enforce_mimi_submit_binding(&room_binding, &body, &message)?;
    let realm_id = room_binding.realm_id.clone();
    let sender = body
        .get("sender_actor_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            // Synthesize a stable sender DID from the MIMI provider
            // id + message id when the envelope omits one. Real
            // deployments will normalise this via the identifier
            // mapping layer per spec §10.
            format!("{}#mimi-anonymous", state.config.service_did,)
        });
    let mapped_content = map_mimi_message_content(&message, source_format)?;
    let thread_id = message
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| crate::routing::events::strand::strand_id_from_realm_id(&realm_id));
    let created_at = chrono::Utc::now();
    let mimi_provenance = json!({
        "facade": "soland.mimi.v1",
        "mimi_provider_id": mimi_provider_id(state),
        "mimi_room_uri": mimi_room_uri(state, &room_id),
        "mimi_room_id": room_id,
        "mimi_room_binding_ref": room_binding.event_id.clone(),
        "mimi_message_id": mimi_message_id,
        "original_envelope_hash": original_hash,
        "source_format": source_format,
        "accepted_at": created_at,
    });
    let message_record = MessageRecord {
        event_id: event_id.clone(),
        message_id: crate::routing::events::strand::message_id_from_event_id(&event_id),
        realm_id: realm_id.clone(),
        sender: sender.clone(),
        thread_id: thread_id.clone(),
        content: mapped_content.content.clone(),
        encrypted: mapped_content.encrypted,
        created_at,
    };
    if let Err(error) = state.persistence.messages().put(&message_record).await {
        tracing::error!(%error, "mimi: failed to persist MessageRecord");
    }
    let projection_payload = json!({
        "thread_id": thread_id.clone(),
        "content": mapped_content.content.clone(),
        "encrypted": mapped_content.encrypted,
        "mimi_provenance": mimi_provenance.clone(),
        "mimi_policy": mapped_content.policy.clone(),
        "quarantine": mapped_content.quarantine.clone(),
    });
    persist_mimi_canonical_message_event(
        state,
        &event_id,
        &realm_id,
        &sender,
        created_at,
        projection_payload.clone(),
    )
    .await?;
    let projection_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: kinds::CK_MESSAGE_CREATE.to_owned(),
        operation_type: "mimi_facade_ingress".to_owned(),
        operation_id: Some(operation_id.clone()),
        sender: Some(sender.clone()),
        payload: projection_payload,
        created_at,
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        projection_event_json(&projection_record),
    ));
    append_projection_event(state, projection_record).await;

    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.submit_message",
        &body,
        json!({
            "kind": "ck.mimi.mapping_receipt",
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "source_format": source_format,
            "target_format": "ck.message.create",
            "original_envelope_hash": original_hash,
            "mapped_operation_id": operation_id,
            "cokret_event_id": event_id,
            "mimi_message_id": mimi_message_id,
            "truth_source": "cokret_signed_event_reducer",
            "reducer_chain": "wired",
            "status": mapped_content.status,
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        }),
    );
    append_audit_log(
        state,
        Some(&sender),
        "mimi.submit_message",
        json!({
            "room_id": room_id,
            "realm_id": realm_id,
            "operation_id": operation_id,
            "event_id": event_id,
            "source_format": source_format,
            "mimi_message_id": mimi_message_id,
            "mimi_policy": mapped_content.policy,
            "quarantine": mapped_content.quarantine,
        }),
        mapped_content.status,
    )
    .await;
    let event_ref = EventId::new(event_id)
        .map_err(|error| AppError::internal(format!("MIMI mapped event ref: {error}")))?;
    json_ok(MimiSubmitMessageOutcome {
        event_ref: Some(event_ref),
        delivery: json!({
            "status": "accepted",
        }),
        rejected: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.query.group_info",
    tags("mimi"),
    summary = "Read a MIMI room's group info / projection"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.query.group_info"))]
async fn mimi_group_info(
    strand_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<MimiGroupInfoOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Cokret Realm")
            .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING)
    })?;
    let projection = mimi_room_projection(state, &room_id, &realm_id);
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.query.group_info",
        &json!({"room_id": room_id}),
        json!({
            "truth_source": "cokret_signed_event_reducer",
            "projection_only": true
        }),
    );
    json_ok(MimiGroupInfoOutcome {
        group_info: projection,
        room_binding_ref: None,
        proofs: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.command.request_consent",
    tags("mimi"),
    summary = "Open a MIMI consent request"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.request_consent"))]
async fn mimi_consent_request(
    body: JsonBody<MimiRequestConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRequestConsentOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi consent request")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let requester = body
        .get("requester_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi consent request requires requester_id"))?;
    let target_holder = mimi_consent_target_holder(&body);
    let scope = body
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("direct_message");
    let materialized = match target_holder {
        Some(holder) => {
            Some(materialize_mimi_consent_request(state, holder, requester, scope).await?)
        }
        None => None,
    };
    let consent_id = materialized
        .as_ref()
        .map(|cell| cell.cell_id.clone())
        .unwrap_or_else(|| ids::generate("mimi_consent"));
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.request_consent",
        &body,
        json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private",
            "holder_private_materialized": materialized.is_some(),
            "identifier_mapping": if materialized.is_some() { "holder_did" } else { "pending_invite_or_pairwise" }
        }),
    );
    json_ok(MimiRequestConsentOutcome {
        consent_id,
        status: "requested".to_owned(),
        challenge: None,
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.command.update_consent",
    tags("mimi"),
    summary = "Update a MIMI consent state"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.update_consent"))]
async fn mimi_consent_update(
    body: JsonBody<MimiUpdateConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiUpdateConsentOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi consent update")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let decision = body
        .get("decision")
        .and_then(|value| value.as_str())
        .unwrap_or("accept");
    let granted = matches!(decision, "accept" | "accepted" | "grant" | "granted");
    let revoked = matches!(decision, "deny" | "denied" | "revoke" | "revoked");
    if !granted && !revoked {
        return Err(AppError::invalid_param("unsupported MIMI consent decision"));
    }
    let consent_id = body
        .get("consent_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi consent update requires consent_id"))?;
    let actor_id = body
        .get("actor_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::invalid_param("mimi consent update requires actor_id"))?;
    let materialized =
        materialize_mimi_consent_update_by_id(state, consent_id, actor_id, granted).await?;
    let updated_at = now();
    let event_ref = materialized
        .as_ref()
        .and_then(|(_, event_ref)| event_ref.as_ref())
        .and_then(|event_ref| EventId::new(event_ref.clone()).ok());
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.update_consent",
        &body,
        json!({
            "consent_grants_space_capability": false,
            "membership_still_required": true,
            "holder_private_materialized": materialized.is_some(),
            "mapped_event_kind": if granted { "ck.consent.grant" } else { "ck.consent.revoke" }
        }),
    );
    json_ok(MimiUpdateConsentOutcome {
        status: if granted { "accepted" } else { "revoked" }.to_owned(),
        updated_at,
        event_ref,
    })
}

fn mimi_consent_target_holder(body: &Value) -> Option<&str> {
    body.get("target")
        .and_then(|target| {
            target
                .get("holder_did")
                .or_else(|| target.get("principal_did"))
                .or_else(|| target.get("did"))
        })
        .or_else(|| body.get("holder_did"))
        .or_else(|| body.get("target_did"))
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("did:"))
}

#[endpoint(
    operation_id = "ck.open.mimi.query.identifiers",
    tags("mimi"),
    summary = "Query opaque MIMI / DID identifier commitments"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.query.identifiers"))]
async fn mimi_identifiers_query(
    body: JsonBody<MimiIdentifierQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiIdentifierQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi identifiers query")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let identifiers = body
        .get("identifiers")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| AppError::missing_param("identifiers is required"))?;
    let mut matches = Vec::with_capacity(identifiers.len());
    for identifier in identifiers {
        let kind = identifier
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("identifier entries require kind"))?;
        if !matches!(
            kind,
            "mimi_uri" | "did" | "handle" | "phone" | "email" | "opaque"
        ) {
            return Err(AppError::invalid_param("identifier kind is unsupported"));
        }
        let commitment = identifier
            .get("identifier_commitment")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::invalid_param("identifier entries require identifier_commitment")
            })?;
        Hash::new(commitment.to_owned())
            .map_err(|_| AppError::invalid_param("identifier_commitment must be a hash"))?;
        matches.push(json!({
            "identifier_commitment": commitment,
            "matched": false,
        }));
    }
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.query.identifiers",
        &body,
        json!({
            "contact_graph_exposed": false,
            "connection_identifier_separated": true,
            "reachability_proof_returned": false,
            "mapping_policy": "opaque_fail_closed"
        }),
    );
    json_ok(MimiIdentifierQueryOutcome {
        matches,
        proofs: Vec::new(),
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ck.open.mimi.command.report_abuse",
    tags("mimi"),
    summary = "File a MIMI abuse report (mirrors as ck.self.moderation.report projection event)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.report_abuse"))]
async fn mimi_report_abuse(
    body: JsonBody<MimiReportAbuseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiReportAbuseOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi report abuse")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    // Extract room_id segment from MIMI URI
    // `mimi://provider/rooms/<id>` so we can look up a bound Realm if any.
    let mimi_room_id = body
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .and_then(|uri| uri.rsplit('/').next())
        .or_else(|| body.get("strand_id").and_then(Value::as_str))
        .map(str::to_owned);
    let bound_realm = match mimi_room_id.as_deref() {
        Some(id) => mimi_bound_realm_id(state, id).await,
        None => None,
    };
    let realm_id = if let Some(realm_id) = body.get("realm_id").and_then(Value::as_str) {
        realm_id.to_owned()
    } else if let Some(bound) = bound_realm {
        bound
    } else {
        return Err(AppError::invalid_param(
            "mimi report requires `realm_id` or a `mimi_room_uri` that resolves to a bound Cokret Realm",
        )
        .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING));
    };
    let reporter = body
        .get("reporter_did")
        .or_else(|| body.get("reporter"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi report requires reporter"))?;
    enforce_mimi_reporter_resolution(state, reporter, &body).await?;
    let target_ref = body
        .get("target_event_digest")
        .or_else(|| body.get("target_ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi report requires target_ref"))?;
    let evidence_package = body.get("evidence_package").unwrap_or(&Value::Null);
    let franking_proof = body
        .get("frank")
        .or_else(|| body.get("franking_proof"))
        .unwrap_or(&Value::Null);
    let source_service = moderation_request_source_service(req);
    let source_ip_hash = moderation_request_source_ip_hash(req);
    let safety = validate_moderation_report_safety(
        state,
        &realm_id,
        reporter,
        target_ref,
        None,
        evidence_package,
        franking_proof,
        source_service.as_deref(),
        &source_ip_hash,
    )
    .await?;
    let report_id = ids::generate_report_id();
    let mut report_fields = serde_json::Map::new();
    report_fields.insert("report_id".to_owned(), json!(report_id));
    report_fields.insert("kind".to_owned(), json!("mimi_abuse_report"));
    report_fields.insert("realm_id".to_owned(), json!(realm_id));
    report_fields.insert("effective_scope".to_owned(), safety.effective_scope.clone());
    report_fields.insert(
        "mimi_room_uri".to_owned(),
        body.get("mimi_room_uri").cloned().unwrap_or(Value::Null),
    );
    report_fields.insert(
        "provider_id".to_owned(),
        body.get("provider_id").cloned().unwrap_or(Value::Null),
    );
    report_fields.insert("target_event_digest".to_owned(), json!(target_ref));
    report_fields.insert("reporter".to_owned(), json!(reporter));
    if let Some(evidence_package) = safety.evidence_package.clone() {
        report_fields.insert("evidence_package".to_owned(), evidence_package);
    }
    if let Some(franking_proof) = safety.franking_proof.clone() {
        report_fields.insert("franking_proof".to_owned(), franking_proof);
    }
    report_fields.insert("created_at".to_owned(), json!(now()));
    if let Err(error) = state
        .persistence
        .moderation()
        .append_report(Value::Object(report_fields))
        .await
    {
        tracing::error!(%error, "failed to persist mimi abuse report");
    }

    // Also emit a `ck.self.moderation.report` projection event so the
    // audit timeline observes the report in the same shape native
    // Cokret reports use. The MIMI provenance is preserved under
    // `payload.mimi_provenance`.
    let mut projection_payload = serde_json::Map::new();
    projection_payload.insert("report_id".to_owned(), json!(report_id));
    projection_payload.insert("effective_scope".to_owned(), safety.effective_scope);
    projection_payload.insert("target_event_digest".to_owned(), json!(target_ref));
    if let Some(franking_proof) = safety.franking_proof {
        projection_payload.insert("franking_proof".to_owned(), franking_proof);
    }
    projection_payload.insert(
        "abuse_reason_code".to_owned(),
        body.get("abuse_reason_code")
            .cloned()
            .unwrap_or(Value::Null),
    );
    projection_payload.insert("evidence_encrypted".to_owned(), json!(true));
    if let Some(evidence_package) = safety.evidence_package {
        projection_payload.insert("evidence_package".to_owned(), evidence_package);
    }
    projection_payload.insert(
        "mimi_provenance".to_owned(),
        json!({
            "facade": "soland.mimi.v1",
            "mimi_room_uri": body.get("mimi_room_uri").cloned(),
            "mimi_provider_id": mimi_provider_id(state),
            "accepted_at": now(),
        }),
    );
    let report_event_id = ids::generate_event_id();
    let report_record = ProjectionEventRecord {
        event_id: report_event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ck.self.moderation.report".to_owned(),
        operation_type: "mimi_facade_report".to_owned(),
        operation_id: None,
        sender: Some(reporter.to_owned()),
        payload: Value::Object(projection_payload),
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        report_record.realm_id.clone(),
        report_record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&report_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(report_record)
        .await
    {
        tracing::error!(%error, "mimi: failed to mirror report into projection_events");
    }

    let routed_to = Did::new(state.config.service_did.clone()).map_or_else(
        |error| {
            tracing::warn!(%error, "mimi: service DID could not be represented in report outcome");
            Vec::new()
        },
        |did| vec![did],
    );
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.report_abuse",
        &body,
        json!({
            "e2ee_evidence_plaintext_required": false,
            "routed_to": [format!("{}#moderation", state.config.service_did)],
            "moderation_event_emitted": true,
            "report_event_id": report_event_id,
            "reporter_resolution": "holder_claim_or_consent",
        }),
    );
    let report_id = ReportId::new(report_id)
        .map_err(|error| AppError::internal(format!("MIMI report id: {error}")))?;
    json_ok(MimiReportAbuseOutcome {
        report_id,
        status: "queued".to_owned(),
        routed_to,
    })
}

async fn enforce_mimi_reporter_resolution(
    state: &AppState,
    reporter: &str,
    body: &Value,
) -> Result<(), AppError> {
    Did::new(reporter.to_owned())
        .map_err(|error| AppError::invalid_param(format!("invalid reporter DID: {error}")))?;
    if state
        .persistence
        .accounts()
        .get(reporter)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return Ok(());
    }
    let evidence = body.get("evidence_package").unwrap_or(&Value::Null);
    let has_holder_claim = evidence
        .get("reporter_holder_claim")
        .or_else(|| body.get("reporter_holder_claim"))
        .is_some_and(non_empty_json_value);
    let has_consent_proof = evidence
        .get("consent_proof")
        .or_else(|| evidence.get("consent_ref"))
        .or_else(|| body.get("consent_proof"))
        .or_else(|| body.get("consent_ref"))
        .is_some_and(non_empty_json_value);
    if has_holder_claim || has_consent_proof {
        return Ok(());
    }
    Err(AppError::capability_denied(
        "MIMI abuse reporter requires local account, holder claim, or consent proof",
    )
    .with_wire_code("mimi_reporter_resolution_required"))
}

#[endpoint(
    operation_id = "ck.open.mimi.command.proxy_download",
    tags("mimi"),
    summary = "Issue a proxy-download token for a MIMI blob (asset privacy policy honored)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.mimi.command.proxy_download"))]
async fn mimi_proxy_download(
    body: JsonBody<MimiProxyDownloadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiProxyDownloadOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi proxy download")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let asset_ref = body
        .get("asset_ref")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::missing_param("asset_ref is required"))?;
    enforce_mimi_proxy_download_egress_policy(state, asset_ref)?;
    let asset_policy = body
        .get("asset_privacy_policy")
        .and_then(|value| value.as_str())
        .unwrap_or("provider_proxy");
    let blob = state
        .persistence
        .blobs()
        .get(asset_ref)
        .await
        .ok()
        .flatten();
    let proxy_required = matches!(asset_policy, "provider_proxy" | "ohttp_relay");
    let download_ref = if proxy_required {
        mimi_proxy_download_ref(state, asset_ref)?
    } else {
        asset_ref.to_owned()
    };
    let mut headers = BTreeMap::new();
    if let Some(blob) = blob.as_ref() {
        headers.insert("content-type".to_owned(), blob.media_type.clone());
        headers.insert("content-length".to_owned(), blob.size_bytes.to_string());
    }
    let _receipt = mimi_receipt(
        state,
        "ck.open.mimi.command.proxy_download",
        &body,
        json!({
            "asset_privacy_policy": asset_policy,
            "direct_object_store_url_returned": false,
            "client_must_verify_content_hash": true
        }),
    );
    json_ok(MimiProxyDownloadOutcome {
        download_ref,
        headers,
        expires_at: Some(now() + Duration::minutes(5)),
    })
}

fn mimi_proxy_download_ref(state: &AppState, asset_ref: &str) -> Result<String, AppError> {
    let mut url = reqwest::Url::parse(&format!("{}/proxy-download", mimi_base_url(state)))
        .map_err(|error| AppError::internal(format!("MIMI proxy download URL invalid: {error}")))?;
    url.query_pairs_mut().append_pair("asset_ref", asset_ref);
    Ok(url.to_string())
}

fn enforce_mimi_proxy_download_egress_policy(
    state: &AppState,
    asset_ref: &str,
) -> Result<(), AppError> {
    if asset_ref.trim() != asset_ref || asset_ref.is_empty() {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: asset_ref must be a non-empty canonical reference",
        ));
    }
    let asset_ref = asset_ref.trim();
    if asset_ref.starts_with("ck:blob:") {
        return Ok(());
    }
    if asset_ref.starts_with("//") || asset_ref.contains('\\') {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: URL-like asset_ref is not allowed without an explicit http(s) scheme",
        ));
    }
    if asset_ref.contains("://") {
        return crate::security::validate_http_url_for_egress(
            asset_ref,
            "mimi proxy download",
            state.config.development_mode,
        )
        .map(|_| ())
        .map_err(mimi_proxy_download_egress_denied);
    }
    if asset_ref.contains(':') {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: non-blob URI scheme is not allowed",
        ));
    }
    Ok(())
}

fn mimi_proxy_download_egress_denied(error: impl Into<String>) -> AppError {
    AppError::capability_denied("MIMI proxy download asset_ref is denied by egress policy")
        .with_wire_code("egress_policy_denied")
        .with_reason_detail(error)
}

fn typed_body_value<T: Serialize>(body: T, context: &'static str) -> Result<Value, AppError> {
    serde_json::to_value(body)
        .map_err(|error| AppError::internal(format!("{context} request body serialize: {error}")))
}

async fn persist_mimi_canonical_message_event(
    state: &AppState,
    event_id: &str,
    realm_id: &str,
    actor_id: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: Value,
) -> Result<(), AppError> {
    let actor_seq = state
        .persistence
        .events()
        .max_actor_seq(actor_id)
        .await
        .map_err(|error| AppError::internal(format!("MIMI actor frontier lookup: {error}")))?
        .unwrap_or(0)
        + 1;
    let mut envelope = json!({
        "event_id": event_id,
        "kind": kinds::CK_MESSAGE_CREATE,
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "hlc": state.hlc.now(),
        "prev_refs": [],
        "payload": payload,
        "executed_by": state.config.service_did,
    });
    let canonical_source = mimi_event_canonical_source(&envelope);
    let canonical_bytes = canonical::canonical_json_bytes(&canonical_source).map_err(|error| {
        AppError::internal(format!("MIMI event canonicalization failed: {error}"))
    })?;
    let canonical_digest = canonical::sha256_digest(&canonical_bytes);
    let proof = mimi_event_proof(state, actor_id, &canonical_digest, created_at)?;
    envelope
        .as_object_mut()
        .ok_or_else(|| AppError::internal("MIMI event envelope is not an object"))?
        .insert("proofs".to_owned(), json!([proof]));
    let record = CanonicalEventRecord {
        event_id: event_id.to_owned(),
        actor_id: actor_id.to_owned(),
        actor_seq,
        realm_id: Some(realm_id.to_owned()),
        kind: kinds::CK_MESSAGE_CREATE.to_owned(),
        schema_id: EVENT_SCHEMA_ID.to_owned(),
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: created_at,
    };
    if let Err(error) = state.persistence.events().put(record).await {
        tracing::error!(%error, "mimi: failed to persist canonical message event");
        return Err(AppError::internal("MIMI canonical event store unavailable"));
    }
    Ok(())
}

fn mimi_event_canonical_source(envelope: &Value) -> Value {
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
}

fn mimi_event_proof(
    state: &AppState,
    actor_id: &str,
    event_digest: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Proof, AppError> {
    let verification_method = format!("{}#mimi-provider-facade-key", state.config.service_did);
    let binding = json!({
        "kind": "mimi_provider_service_proof",
        "event_digest": event_digest,
        "actor_id": actor_id,
        "verification_method": verification_method,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!(
            "MIMI proof binding canonicalization failed: {error}"
        ))
    })?;
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| {
                AppError::internal(format!("MIMI event proof signing failed: {error}"))
            })?;
    Ok(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(event_digest.to_owned())
            .map_err(|error| AppError::internal(format!("MIMI event digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        jws,
    })
}

fn decode_mimi_update_payload(body: &Value) -> Result<Option<Value>, AppError> {
    let Some(opaque) = body.get("update").and_then(|update| update.get("payload")) else {
        return Err(
            AppError::invalid_param("MIMI room update requires update.payload")
                .with_wire_code("mimi_payload_invalid"),
        );
    };
    decode_optional_mimi_opaque_json(opaque, "payload_digest", "MIMI room update payload")
}

fn mimi_room_binding_payload(update_payload: &Value) -> Option<&Value> {
    if update_payload.get("kind").and_then(Value::as_str) != Some("ck.mimi.room_binding") {
        return None;
    }
    update_payload.get("payload")
}

fn decode_mimi_message_payload(body: &Value) -> Result<Value, AppError> {
    let opaque = body
        .get("ciphertext")
        .ok_or_else(|| AppError::invalid_param("MIMI submit_message requires ciphertext"))?;
    decode_required_mimi_opaque_json(opaque, "ciphertext_digest", "MIMI ciphertext payload")
}

fn decode_optional_mimi_opaque_json(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Option<Value>, AppError> {
    let Some(bytes) = decode_mimi_opaque_bytes(opaque, digest_field, context, false)? else {
        return Ok(None);
    };
    let value =
        cokret_sdk::canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
            AppError::invalid_param(format!("{context} is not canonical JSON: {error}"))
                .with_wire_code("mimi_payload_invalid")
        })?;
    Ok(Some(value))
}

fn decode_required_mimi_opaque_json(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Value, AppError> {
    let bytes = decode_mimi_opaque_bytes(opaque, digest_field, context, true)?
        .expect("required opaque payload returns bytes");
    cokret_sdk::canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
        AppError::invalid_param(format!("{context} is not canonical JSON: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })
}

fn decode_mimi_opaque_bytes(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
    require_payload: bool,
) -> Result<Option<Vec<u8>>, AppError> {
    let digest = opaque
        .get(digest_field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::invalid_param(format!("{context} requires {digest_field}"))
                .with_wire_code("mimi_payload_invalid")
        })?;
    let payload = match opaque.get("payload").and_then(Value::as_str) {
        Some(payload) if !payload.trim().is_empty() => payload,
        _ if require_payload => {
            return Err(
                AppError::invalid_param(format!("{context} requires payload"))
                    .with_wire_code("mimi_payload_invalid"),
            );
        }
        _ => return Ok(None),
    };
    let bytes = cokret_sdk::base64url_decode(payload).map_err(|error| {
        AppError::invalid_param(format!("{context} payload is not base64url: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })?;
    let observed = cokret_sdk::canonical::sha256_digest(&bytes);
    if observed != digest {
        return Err(
            AppError::invalid_param(format!("{context} digest mismatch"))
                .with_wire_code("mimi_payload_digest_mismatch"),
        );
    }
    Ok(Some(bytes))
}

fn mimi_provider_directory_value(state: &AppState) -> Value {
    json!({
        "schema": "ck.schema.mimi_interop.v1",
        "service_did": state.config.service_did.clone(),
        "service_type": "mimi_provider_facade",
        "supported_profiles": ["ck.profile.mimi_interop.v1"],
        "mimi": {
            "protocol_draft": "draft-ietf-mimi-protocol-06",
            "content_draft": "draft-ietf-mimi-content-08",
            "room_policy_draft": "draft-ietf-mimi-room-policy-03",
            "identifier_draft": "draft-kohbrok-mimi-identifiers-01",
            "base_url": mimi_base_url(state),
            "provider_id": mimi_provider_id(state),
            "features": [
                "key_material",
                "room_update",
                "notify",
                "submit_message",
                "group_info",
                "consent",
                "identifier_query",
                "report_abuse",
                "proxy_download"
            ],
            "mls_cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "content_profiles": [
                "application/mimi-content",
                "text/plain;charset=utf-8",
                "text/markdown;variant=GFM-MIMI",
                "application/vnd.cokret.content+json"
            ],
            "room_policy_components": [
                "roles",
                "membership",
                "history_visibility",
                "join_rule",
                "message_expiration",
                "asset_privacy"
            ]
        },
        "proof": {
            "type": "dev_service_digest",
            "kid": format!("{}#mimi-provider", state.config.service_did),
            "alg": "sha256-dev",
            "sig": sha256_hex(format!("{}:ck.profile.mimi_interop.v1", state.config.service_did).as_bytes())
        }
    })
}

fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/_cokret/open/mimi",
        state.config.public_base_url.trim_end_matches('/')
    )
}

fn mimi_provider_id(state: &AppState) -> String {
    state
        .config
        .service_did
        .strip_prefix("did:web:")
        .map(|domain| format!("mimi://{}", domain.replace(':', "/")))
        .unwrap_or_else(|| format!("mimi://{}", state.config.service_did.replace(':', ".")))
}

fn mimi_room_uri(state: &AppState, room_id: &str) -> String {
    format!("{}/rooms/{room_id}", mimi_provider_id(state))
}

fn mimi_receipt(state: &AppState, operation_id: &str, body: &Value, extra: Value) -> Value {
    json!({
        "profile": "ck.profile.mimi_interop.v1",
        "operation_id": operation_id,
        "service_did": state.config.service_did,
        "provider_id": mimi_provider_id(state),
        "request_hash": cokret_sdk::canonical::sha256_digest(body.to_string().as_bytes()),
        "accepted_at": now(),
        "drafts": {
            "protocol": "draft-ietf-mimi-protocol-06",
            "content": "draft-ietf-mimi-content-08",
            "room_policy": "draft-ietf-mimi-room-policy-03",
            "identifiers": "draft-kohbrok-mimi-identifiers-01"
        },
        "extra": extra
    })
}

struct MimiMappedContent {
    content: Value,
    encrypted: bool,
    policy: Value,
    quarantine: Option<Value>,
    status: &'static str,
}

fn map_mimi_message_content(
    body: &Value,
    source_format: &str,
) -> Result<MimiMappedContent, AppError> {
    let mut content = mimi_content_payload(body, source_format);
    let content_kind = mimi_content_kind(body, &content).map(str::to_owned);
    let e2ee_boundary = mimi_e2ee_boundary(body, &content);
    let plaintext_detected = mimi_plaintext_detected(body) || mimi_plaintext_detected(&content);
    let transcript_binding = mimi_transcript_binding(body, &content).cloned();
    let explicit_downgrade = mimi_explicit_downgrade(body, &content);

    if e2ee_boundary && plaintext_detected && transcript_binding.is_none() && !explicit_downgrade {
        return Err(AppError::invalid_param(
            "MIMI E2EE plaintext requires transcript_binding or explicit e2ee_downgrade marker",
        )
        .with_wire_code("mimi_e2ee_boundary_unmarked"));
    }

    let mut policy = json!({
        "profile": "ck.profile.mimi_interop.v1",
        "e2ee_boundary": "none",
        "plaintext_detected": plaintext_detected,
        "plaintext_guard": "not_e2ee",
    });
    let mut encrypted = e2ee_boundary && !explicit_downgrade;

    if e2ee_boundary && explicit_downgrade {
        ensure_content_object(&mut content);
        let object = content.as_object_mut().expect("content object");
        object.insert(
            "ck.morph.e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        object.insert(
            "e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        policy = json!({
            "profile": "ck.profile.mimi_interop.v1",
            "e2ee_boundary": "explicit_downgrade",
            "plaintext_detected": plaintext_detected,
            "plaintext_guard": "marked_explicit_downgrade",
            "downgrade_marker": "mimi_bridge",
        });
        encrypted = false;
    } else if e2ee_boundary {
        if let Some(binding) = transcript_binding {
            ensure_content_object(&mut content);
            let object = content.as_object_mut().expect("content object");
            object.insert("transcript_binding".to_owned(), binding.clone());
            object.insert(
                "ck.morph.e2ee_boundary".to_owned(),
                Value::String("transcript_bound".to_owned()),
            );
            policy = json!({
                "profile": "ck.profile.mimi_interop.v1",
                "e2ee_boundary": "transcript_bound",
                "plaintext_detected": plaintext_detected,
                "plaintext_guard": "transcript_binding",
                "transcript_binding": binding,
            });
        } else {
            policy = json!({
                "profile": "ck.profile.mimi_interop.v1",
                "e2ee_boundary": "opaque_ciphertext",
                "plaintext_detected": false,
                "plaintext_guard": "opaque_ciphertext_only",
            });
        }
    }

    if let Some(kind) = content_kind
        .as_deref()
        .filter(|kind| !valid_mimi_content_kind(kind))
    {
        let quarantine_id = ids::generate("mimi_quarantine");
        let quarantine = json!({
            "quarantine_id": quarantine_id,
            "unknown_content_kind": kind,
            "reason": "unknown_mimi_content_kind",
            "raw_payload_hash": cokret_sdk::canonical::sha256_digest(content.to_string().as_bytes()),
        });
        let content = json!({
            "kind": "ck.content.unsupported",
            "body": "unsupported content from MIMI",
            "ck.morph.unknown_content_kind": kind,
            "quarantine": quarantine.clone(),
        });
        let mut policy = policy;
        if let Some(object) = policy.as_object_mut() {
            object.insert(
                "content_quarantine".to_owned(),
                Value::String("unknown_mimi_content_kind".to_owned()),
            );
        }
        return Ok(MimiMappedContent {
            content,
            encrypted: false,
            policy,
            quarantine: Some(quarantine),
            status: "quarantined",
        });
    }

    Ok(MimiMappedContent {
        content,
        encrypted,
        policy,
        quarantine: None,
        status: "mapped",
    })
}

fn mimi_content_payload(body: &Value, source_format: &str) -> Value {
    body.get("content").cloned().unwrap_or_else(|| {
        let text = body
            .get("body")
            .or_else(|| body.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        json!({
            "kind": "ck.content.text",
            "body": text,
            "raw_mimi_source_format": source_format,
        })
    })
}

fn ensure_content_object(content: &mut Value) {
    if !content.is_object() {
        let raw = content.clone();
        *content = json!({
            "kind": "ck.content.opaque",
            "raw_mimi_content": raw,
        });
    }
}

fn mimi_content_kind<'a>(body: &'a Value, content: &'a Value) -> Option<&'a str> {
    body.get("content_kind")
        .or_else(|| body.get("mimi_content_kind"))
        .and_then(Value::as_str)
        .or_else(|| content.get("kind").and_then(Value::as_str))
}

fn valid_mimi_content_kind(kind: &str) -> bool {
    matches!(
        kind,
        "m.text"
            | "text/plain"
            | "text/markdown"
            | "m.markdown"
            | "ck.message.text"
            | "ck.message.revise"
            | "ck.message.redact"
            | "ck.content.text"
            | "ck.content.composite"
            | "ck.content.markdown"
    )
}

fn mimi_e2ee_boundary(body: &Value, content: &Value) -> bool {
    truthy_field(body, "e2ee")
        || truthy_field(body, "encrypted")
        || truthy_field(content, "e2ee")
        || truthy_field(content, "encrypted")
        || encryption_profile_enabled(body.get("encryption_profile"))
        || encryption_profile_enabled(body.get("source_encryption"))
        || encryption_profile_enabled(content.get("encryption_profile"))
        || encryption_profile_enabled(content.get("source_encryption"))
}

fn truthy_field(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => matches!(
            value.as_str(),
            "true" | "e2ee" | "encrypted" | "mls" | "mls_rfc9420" | "mimi_mls"
        ),
        _ => false,
    }
}

fn encryption_profile_enabled(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|profile| !matches!(profile, "" | "none" | "plaintext" | "unencrypted"))
}

fn mimi_transcript_binding<'a>(body: &'a Value, content: &'a Value) -> Option<&'a Value> {
    body.get("transcript_binding")
        .or_else(|| body.get("mls_transcript_binding"))
        .or_else(|| content.get("transcript_binding"))
        .or_else(|| content.get("mls_transcript_binding"))
}

fn mimi_explicit_downgrade(body: &Value, content: &Value) -> bool {
    downgrade_marker(body.get("e2ee_downgrade"))
        || downgrade_marker(body.get("ck.morph.e2ee_downgrade"))
        || downgrade_marker(content.get("e2ee_downgrade"))
        || downgrade_marker(content.get("ck.morph.e2ee_downgrade"))
}

fn downgrade_marker(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|marker| marker == "mimi_bridge" || marker == "explicit")
}

fn mimi_plaintext_detected(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            if matches!(
                key.as_str(),
                "body" | "text" | "plain_text" | "markdown" | "html"
            ) {
                value.as_str().is_some_and(|text| !text.trim().is_empty())
            } else if matches!(
                key.as_str(),
                "ciphertext" | "ciphertext_hash" | "digest" | "hash" | "original_envelope_hash"
            ) {
                false
            } else {
                mimi_plaintext_detected(value)
            }
        }),
        Value::Array(values) => values.iter().any(mimi_plaintext_detected),
        _ => false,
    }
}

/// Look up which Cokret `realm_id` (if any) the MIMI `room_id` is
/// bound to. Scans the persistence projection event log for the
/// most recent `ck.mimi.room_binding` event whose
/// `payload.mimi_room_id` (or trailing segment of `mimi_room_uri`)
/// matches `room_id`. Returns `None` when no binding has been
/// recorded; callers translate that into a 404/400 rather than
/// silently routing the request at a hard-coded demo Realm.
async fn latest_mimi_room_binding(
    state: &AppState,
    room_id: &str,
) -> Option<MimiRoomBindingProjection> {
    let entries = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .ok()?;
    // Walk in reverse so the most-recently-recorded binding wins.
    for entry in entries.iter().rev() {
        if entry.event_kind != "ck.mimi.room_binding" {
            continue;
        }
        let payload_room = entry
            .payload
            .get("mimi_room_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                entry
                    .payload
                    .get("mimi_room_uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| uri.rsplit('/').next().map(ToOwned::to_owned))
            });
        let binding = entry.payload.get("binding").unwrap_or(&entry.payload);
        let binding_payload = mimi_room_binding_security_payload(binding);
        let binding_room = binding_payload
            .get("mimi_room_uri")
            .and_then(Value::as_str)
            .and_then(|uri| uri.rsplit('/').next().map(str::to_owned));
        if payload_room.as_deref() == Some(room_id) || binding_room.as_deref() == Some(room_id) {
            let realm_id = entry
                .payload
                .get("binding_scope")
                .and_then(|s| s.get("realm_id"))
                .and_then(Value::as_str)
                .or_else(|| {
                    binding_payload
                        .get("binding_scope")
                        .and_then(|s| s.get("realm_id"))
                        .and_then(Value::as_str)
                })
                .or_else(|| entry.payload.get("realm_id").and_then(Value::as_str))
                .or_else(|| binding_payload.get("realm_id").and_then(Value::as_str))?;
            return Some(MimiRoomBindingProjection {
                event_id: entry.event_id.clone(),
                realm_id: realm_id.to_owned(),
                binding: binding.clone(),
            });
        }
    }
    None
}

async fn mimi_bound_realm_id(state: &AppState, room_id: &str) -> Option<String> {
    latest_mimi_room_binding(state, room_id)
        .await
        .map(|binding| binding.realm_id)
}

fn enforce_mimi_submit_binding(
    room_binding: &MimiRoomBindingProjection,
    body: &Value,
    message: &Value,
) -> Result<(), AppError> {
    validate_mimi_room_binding_payload(&room_binding.binding)?;
    let binding_payload = mimi_room_binding_security_payload(&room_binding.binding);
    match binding_payload.get("status").and_then(Value::as_str) {
        Some("accepted") => {}
        Some(_) | None => {
            return Err(AppError::invalid_param(
                "MIMI room binding is not writable in its current state",
            )
            .with_wire_code(MIMI_REASON_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match binding_payload
        .get("local_provider_role")
        .and_then(Value::as_str)
    {
        Some("hub" | "follower") => {}
        Some("observer") => {
            return Err(
                AppError::capability_denied("MIMI observer binding cannot submit writes")
                    .with_wire_code(MIMI_REASON_OBSERVER_WRITE_FORBIDDEN),
            );
        }
        _ => {
            return Err(
                AppError::invalid_param("MIMI room binding has no writable provider role")
                    .with_wire_code(MIMI_REASON_ROOM_STATE_INCOMPATIBLE),
            );
        }
    }

    let Some(binding_group_id) = binding_payload
        .get("mls_group_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    let submit_group_id = mimi_submit_mls_group_id(body, message).ok_or_else(|| {
        AppError::invalid_param("MIMI submit_message is missing mls_group_id")
            .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISMATCH)
    })?;
    if submit_group_id != binding_group_id {
        return Err(AppError::invalid_param(
            "MIMI submit_message mls_group_id does not match room binding",
        )
        .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISMATCH));
    }
    let epoch = mimi_submit_epoch(body, message).ok_or_else(|| {
        AppError::invalid_param("MIMI submit_message is missing MLS epoch")
            .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISMATCH)
    })?;
    let governance_binding = mimi_governance_binding_candidate(binding_payload, body, message)
        .ok_or_else(|| {
            AppError::invalid_param("MIMI submit_message lacks governance_binding")
                .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING)
        })?;
    validate_mimi_submit_governance_binding(
        governance_binding,
        &room_binding.realm_id,
        binding_group_id,
        epoch,
        binding_payload
            .get("policy_root")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty()),
    )?;
    if !mimi_submit_has_covered_seals_cell(binding_payload, body, message, governance_binding) {
        return Err(AppError::invalid_param(
            "MIMI submit_message lacks covered_seals_cell evidence",
        )
        .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISSING));
    }
    Ok(())
}

fn validate_mimi_room_binding_payload(binding: &Value) -> Result<(), AppError> {
    let payload = mimi_room_binding_security_payload(binding);
    if payload
        .get("hub_provider")
        .and_then(Value::as_str)
        .map_or(true, |value| value.trim().is_empty())
    {
        return Err(
            AppError::invalid_param("MIMI room binding requires hub_provider")
                .with_wire_code(MIMI_REASON_ROOM_STATE_INCOMPATIBLE),
        );
    }
    match payload.get("local_provider_role").and_then(Value::as_str) {
        Some("hub" | "follower" | "observer") => {}
        _ => {
            return Err(AppError::invalid_param(
                "MIMI room binding requires a known local_provider_role",
            )
            .with_wire_code(MIMI_REASON_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match payload.get("status").and_then(Value::as_str) {
        Some("proposed" | "accepted" | "revoked" | "migrating") => Ok(()),
        _ => Err(
            AppError::invalid_param("MIMI room binding requires a lifecycle status")
                .with_wire_code(MIMI_REASON_ROOM_STATE_INCOMPATIBLE),
        ),
    }
}

async fn enforce_mimi_room_binding_transition(
    state: &AppState,
    room_id: &str,
    next_binding: &Value,
) -> Result<(), AppError> {
    let next_status = mimi_room_binding_status(next_binding)?;
    let previous = latest_mimi_room_binding(state, room_id).await;
    let previous_status = match previous.as_ref() {
        Some(previous) => Some(mimi_room_binding_status(&previous.binding)?),
        None => None,
    };
    if mimi_room_binding_transition_allowed(previous_status, next_status) {
        return Ok(());
    }
    let detail = previous_status
        .map(|status| format!("from={status};to={next_status}"))
        .unwrap_or_else(|| format!("from=<none>;to={next_status}"));
    Err(
        AppError::invalid_param("MIMI room binding status transition is not allowed")
            .with_wire_code(MIMI_REASON_ROOM_BINDING_TRANSITION_INVALID)
            .with_reason_detail(detail),
    )
}

fn mimi_room_binding_status(binding: &Value) -> Result<&str, AppError> {
    let payload = mimi_room_binding_security_payload(binding);
    payload
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| matches!(*status, "proposed" | "accepted" | "revoked" | "migrating"))
        .ok_or_else(|| {
            AppError::invalid_param("MIMI room binding requires a lifecycle status")
                .with_wire_code(MIMI_REASON_ROOM_STATE_INCOMPATIBLE)
        })
}

fn mimi_room_binding_transition_allowed(previous: Option<&str>, next: &str) -> bool {
    match (previous, next) {
        (None, "proposed" | "accepted") => true,
        (Some("proposed"), "accepted" | "revoked") => true,
        (Some("accepted"), "migrating" | "revoked") => true,
        (Some("migrating"), "accepted" | "revoked") => true,
        _ => false,
    }
}

fn mimi_room_binding_security_payload(binding: &Value) -> &Value {
    binding
        .get("payload")
        .filter(|payload| payload.is_object())
        .unwrap_or(binding)
}

fn mimi_submit_mls_group_id<'a>(body: &'a Value, message: &'a Value) -> Option<&'a str> {
    body.get("mls_group_id")
        .or_else(|| {
            body.get("ciphertext")
                .and_then(|ciphertext| ciphertext.get("mls_group_id"))
        })
        .or_else(|| message.get("mls_group_id"))
        .or_else(|| message.get("group_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn mimi_submit_epoch(body: &Value, message: &Value) -> Option<u64> {
    body.get("epoch")
        .or_else(|| {
            body.get("ciphertext")
                .and_then(|ciphertext| ciphertext.get("epoch"))
        })
        .or_else(|| message.get("epoch"))
        .and_then(Value::as_u64)
}

fn mimi_governance_binding_candidate<'a>(
    binding_payload: &'a Value,
    body: &'a Value,
    message: &'a Value,
) -> Option<&'a Value> {
    governance_binding_field(message)
        .or_else(|| {
            body.get("associated_data")
                .and_then(governance_binding_field)
        })
        .or_else(|| body.get("ciphertext").and_then(governance_binding_field))
        .or_else(|| governance_binding_field(body))
        .or_else(|| governance_binding_field(binding_payload))
}

fn governance_binding_field(value: &Value) -> Option<&Value> {
    value
        .get("governance_binding")
        .or_else(|| value.get("mls_governance_binding"))
}

fn validate_mimi_submit_governance_binding(
    binding: &Value,
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    expected_policy_root: Option<&str>,
) -> Result<(), AppError> {
    let error = |reason: &'static str| {
        AppError::invalid_param("MIMI submit_message governance_binding is not valid")
            .with_wire_code(MIMI_REASON_GOVERNANCE_BINDING_MISMATCH)
            .with_reason_detail(reason)
    };
    if binding.get("binding_version").and_then(Value::as_u64) != Some(1) {
        return Err(error("mls_governance_binding_version_invalid"));
    }
    if binding.get("encoding_profile").and_then(Value::as_str)
        != Some("cbor-deterministic-rfc8949-v1")
    {
        return Err(error("mls_governance_binding_encoding_profile_invalid"));
    }
    if binding.get("binding_profile").and_then(Value::as_str)
        != Some(crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE)
    {
        return Err(error("mls_governance_binding_profile_invalid"));
    }
    if binding.get("reducer_profile").and_then(Value::as_str)
        != Some(crate::kinds::MLS_REDUCER_PROFILE_V1)
    {
        return Err(error("mls_governance_binding_reducer_profile_invalid"));
    }
    if binding.get("mls_group_id").and_then(Value::as_str) != Some(group_id) {
        return Err(error("mls_governance_binding_group_mismatch"));
    }
    if binding.get("next_epoch").and_then(Value::as_u64) != Some(epoch) {
        return Err(error("mls_governance_binding_next_epoch_mismatch"));
    }
    if binding.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(error("mls_governance_binding_realm_mismatch"));
    }
    let Some(scope) = binding.get("effective_scope").and_then(Value::as_object) else {
        return Err(error("mls_governance_binding_scope_missing"));
    };
    if scope.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(error("mls_governance_binding_scope_mismatch"));
    }
    match scope.get("kind").and_then(Value::as_str) {
        Some("realm") => {
            if binding.get("circle_id").is_some() {
                return Err(error("mls_governance_binding_scope_mismatch"));
            }
        }
        Some("circle") => {
            let Some(circle_id) = scope.get("circle_id").and_then(Value::as_str) else {
                return Err(error("mls_governance_binding_scope_mismatch"));
            };
            if binding.get("circle_id").and_then(Value::as_str) != Some(circle_id) {
                return Err(error("mls_governance_binding_scope_mismatch"));
            }
        }
        _ => return Err(error("mls_governance_binding_scope_missing")),
    }
    let Some(frontier) = binding.get("membership_frontier").and_then(Value::as_array) else {
        return Err(error("mls_governance_binding_membership_frontier_missing"));
    };
    if frontier.is_empty()
        || frontier
            .iter()
            .any(|value| value.as_str().map_or(true, str::is_empty))
    {
        return Err(error("mls_governance_binding_membership_frontier_missing"));
    }
    let Some(policy_root) = binding
        .get("policy_root")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:"))
    else {
        return Err(error("mls_governance_binding_policy_root_missing"));
    };
    if let Some(expected_policy_root) = expected_policy_root
        && policy_root != expected_policy_root
    {
        return Err(error("mls_governance_binding_policy_root_mismatch"));
    }
    Ok(())
}

fn mimi_submit_has_covered_seals_cell(
    binding_payload: &Value,
    body: &Value,
    message: &Value,
    governance_binding: &Value,
) -> bool {
    let null = Value::Null;
    [
        governance_binding,
        message,
        body.get("associated_data").unwrap_or(&null),
        body.get("ciphertext").unwrap_or(&null),
        body,
        binding_payload,
    ]
    .into_iter()
    .any(|value| {
        value
            .get("covered_seals_cell")
            .or_else(|| value.get("covered_seals"))
            .is_some_and(non_empty_json_value)
    })
}

fn non_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(object) => !object.is_empty(),
    }
}

/// Emit a `ck.mimi.room_binding` projection event capturing the
/// binding state. Returns the generated event_id so the caller can
/// echo it back to the MIMI client. The binding payload is captured
/// verbatim under `payload.binding` and `mimi_room_id` is hoisted to
/// the top level so [`mimi_bound_realm_id`] can dispatch lookups
/// efficiently.
///
/// Returns `None` when the binding payload declares no Cokret
/// `realm_id` (neither under `binding_scope.realm_id` nor at the top
/// level). The caller is expected to surface that to the client as a
/// 400 rather than implicitly bind the room to some default Realm.
async fn emit_mimi_room_binding_event(
    state: &AppState,
    room_id: &str,
    binding: &Value,
) -> Result<Option<String>, AppError> {
    let event_id = ids::generate_event_id();
    let realm_id = binding
        .get("binding_scope")
        .and_then(|s| s.get("realm_id"))
        .and_then(Value::as_str)
        .or_else(|| binding.get("realm_id").and_then(Value::as_str))
        .map(str::to_owned);
    let Some(realm_id) = realm_id else {
        return Ok(None);
    };
    validate_mimi_room_binding_payload(binding)?;
    enforce_mimi_room_binding_transition(state, room_id, binding).await?;
    let mimi_room_uri_value = binding
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| mimi_room_uri(state, room_id));
    let record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ck.mimi.room_binding".to_owned(),
        operation_type: "mimi_facade_room_binding".to_owned(),
        operation_id: None,
        sender: None,
        payload: json!({
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri_value,
            "mimi_room_id": room_id,
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": binding
                    .get("binding_scope")
                    .and_then(|s| s.get("strand_id"))
                    .cloned()
                    .unwrap_or(Value::Null),
            },
            "binding": binding.clone(),
            "mimi_provenance": {
                "facade": "soland.mimi.v1",
                "mimi_provider_id": mimi_provider_id(state),
                "accepted_at": chrono::Utc::now(),
            },
        }),
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        record.realm_id.clone(),
        record.event_id.clone(),
        crate::routing::events::projection::projection_event_json(&record),
    ));
    if let Err(error) = state.persistence.projection_events().append(record).await {
        tracing::error!(%error, "mimi: failed to append room_binding to projection_events");
    }
    Ok(Some(event_id))
}

fn mimi_room_projection(state: &AppState, room_id: &str, realm_id: &str) -> Value {
    json!({
        "kind": "ck.mimi.room_binding",
        "profile": "ck.profile.mimi_interop.v1",
        "mimi_room_uri": mimi_room_uri(state, room_id),
        "binding_scope": {
            "realm_id": realm_id,
            "channel_id": Value::Null
        },
        "hub_provider": state.config.service_did.clone(),
        "local_provider_role": "hub",
        "mls_group_id": format!("mls:{}", room_id),
        "policy_root": cokret_sdk::canonical::sha256_digest(format!("{realm_id}:{room_id}:policy").as_bytes()),
        "status": "accepted",
        "canonical_truth": "cokret_signed_event_reducer"
    })
}

fn mimi_room_participants(state: &AppState, realm_id: &str) -> Vec<Value> {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return Vec::new();
    };
    state
        .realms
        .lock()
        .expect("realms lock")
        .get(&realm_id)
        .map(|realm| {
            realm
                .members
                .iter()
                .map(|did| {
                    json!({
                        "mimi_identifier": format!("{}/users/{}", mimi_provider_id(state), did.to_string().replace(':', ".")),
                        "did": did.to_string(),
                        "role": "member"
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn unsupported_mimi_draft(body: &Value) -> Option<&'static str> {
    for (field, expected, message) in [
        (
            "protocol_draft",
            "draft-ietf-mimi-protocol-06",
            "unsupported MIMI protocol draft",
        ),
        (
            "content_draft",
            "draft-ietf-mimi-content-08",
            "unsupported MIMI content draft",
        ),
        (
            "room_policy_draft",
            "draft-ietf-mimi-room-policy-03",
            "unsupported MIMI room policy draft",
        ),
        (
            "identifier_draft",
            "draft-kohbrok-mimi-identifiers-01",
            "unsupported MIMI identifier draft",
        ),
    ] {
        let value = body
            .get(field)
            .or_else(|| body.get("mimi").and_then(|mimi| mimi.get(field)))
            .and_then(|value| value.as_str());
        if value.is_some_and(|value| value != expected) {
            return Some(message);
        }
    }
    None
}

fn valid_mimi_room_id(room_id: &str) -> bool {
    !room_id.is_empty()
        && room_id.len() <= 256
        && room_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '~'))
}

fn valid_mimi_content_type(value: &str) -> bool {
    matches!(
        value,
        "application/mimi-content"
            | "text/plain;charset=utf-8"
            | "text/markdown;variant=GFM-MIMI"
            | "application/vnd.cokret.content+json"
    )
}
