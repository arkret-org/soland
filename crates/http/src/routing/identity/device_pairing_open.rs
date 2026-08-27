//! Server-mediated device-pairing short-link surface (mirrors the agent-pairing
//! `open` template). Mounted UNAUTHENTICATED under `/_arkret/open`:
//!
//! - `POST /_arkret/open/device-pairing/requests`         —
//!   `ak.open.device_pairing.command.stage.v1`
//! - `POST /_arkret/open/device-pairing/resolve`          —
//!   `ak.open.device_pairing.read.resolve.v1`
//! - `POST /_arkret/open/device-pairing/requests/status`  — `ak.open.device_pairing.read.status.v1`
//!
//! Security: the staged row is account-less and grants nothing until a verified
//! device drives the authenticated `ak.gate.account.command.pair_device.v1`. These
//! handlers take NO `AuthArgs` and never call `authenticated_session`. `resolve`
//! fails closed with a UNIFORM not-found for absent, wrong-code,
//! expired, and already-authorized records. `status` uses the same not-found for
//! absent/wrong-code credentials, while a valid credential can observe pending,
//! authorized, or expired.
//! The resolve token is accepted only in the JSON body, never the URL.

use arkret_identifiers::{DeviceId, EventId};
use arkret_models_collaboration::governance::agent_artifacts::{DeviceMetadata, PublicKey};
use arkret_models_collaboration::http_bodies::{
    DevicePairingBootstrap, DevicePairingCode, DevicePairingNonce, DevicePairingRequestId,
    DevicePairingResolveRequestBody, DevicePairingStageOutcome, DevicePairingStageRequestBody,
    DevicePairingState, DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::state::AppState;

/// Mounted under `/_arkret/open`.
pub(crate) fn open_router() -> Router {
    Router::with_path("device-pairing")
        .push(Router::with_path("requests").post(stage_device_pairing))
        .push(Router::with_path("resolve").post(resolve_device_pairing))
        .push(Router::with_path("requests/status").post(device_pairing_status))
}

/// Pairing window for a staged device-pairing short-link request.
const DEVICE_PAIRING_TTL_MINUTES: i64 = 10;
/// Keep expired rows briefly so a valid status credential can distinguish an
/// elapsed request from a typo, while ensuring opportunistic cleanup is bounded.
const DEVICE_PAIRING_EXPIRED_RETENTION_MINUTES: i64 = 60;

#[endpoint(
    operation_id = "ak.open.device_pairing.command.stage",
    summary = "Stage a device pairing short-link request",
    tags("device_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.device_pairing.command.stage.v1"))]
pub(super) async fn stage_device_pairing(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DevicePairingStageRequestBody>,
) -> JsonResult<DevicePairingStageOutcome> {
    reject_device_pairing_query(req)?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    validate_new_device_pubkey(&body.new_device_pubkey)?;
    let new_device_pubkey = serde_json::to_value(&body.new_device_pubkey)
        .map_err(|error| AppError::param_invalid(format!("new_device_pubkey invalid: {error}")))?;
    let device_metadata = body
        .device_metadata
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::param_invalid(format!("device_metadata invalid: {error}")))?;
    let display_name = body
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let now = chrono::Utc::now();
    let device_pairing_request_id =
        DevicePairingRequestId::new(format!("device_pairing_request:{}", uuid::Uuid::now_v7()))
            .map_err(|error| AppError::internal(error.to_string()))?;
    let pairing_code = generate_pairing_code();
    let gate_audience = gate_audience(&state.config().public_base_url)?;
    let server_nonce = generate_pairing_nonce();
    let expires_at = now + chrono::Duration::minutes(DEVICE_PAIRING_TTL_MINUTES);

    let record = soland_services::identity::DevicePairingState {
        device_pairing_request_id: device_pairing_request_id.as_str().to_owned(),
        pairing_code: pairing_code.as_str().to_owned(),
        new_device_pubkey,
        client_nonce: body.client_nonce.as_str().to_owned(),
        gate_audience: gate_audience.clone(),
        server_nonce: server_nonce.as_str().to_owned(),
        display_name,
        device_metadata,
        state: DevicePairingState::PendingAuthorization,
        device_id: None,
        authorized_by_actor_id: None,
        authorized_event_ref: None,
        created_at: now,
        expires_at,
    };
    state
        .device_pairings()
        .stage(record)
        .await
        .map_err(|error| AppError::internal(format!("device pairing stage failed: {error}")))?;

    // Opportunistic best-effort prune. `stage` is unauthenticated, so bound the
    // staged-row table by clearing expired rows on each write. Failure here is
    // non-fatal — expired rows are already inert (resolve/status reject them).
    let prune_before = now - chrono::Duration::minutes(DEVICE_PAIRING_EXPIRED_RETENTION_MINUTES);
    if let Err(error) = state
        .device_pairings()
        .prune_expired_before(prune_before)
        .await
    {
        tracing::debug!(%error, "device-pairing prune of expired rows failed");
    }

    json_ok(DevicePairingStageOutcome {
        device_pairing_request_id,
        pairing_code,
        gate_audience,
        server_nonce,
        expires_at,
    })
}

#[endpoint(
    operation_id = "ak.open.device_pairing.read.resolve",
    summary = "Resolve a device pairing bootstrap",
    tags("device_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.device_pairing.read.resolve.v1"))]
pub(super) async fn resolve_device_pairing(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DevicePairingBootstrap> {
    reject_device_pairing_query(req)?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<DevicePairingResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid device pairing resolve request body"))?;
    let pairing_token = body.pairing_token.trim();
    if !is_device_pairing_token_shape(pairing_token) {
        return Err(device_pairing_not_found());
    }
    let token = decode_device_pairing_token(pairing_token).ok_or_else(device_pairing_not_found)?;
    let device_pairing_request_id =
        DevicePairingRequestId::new(token.r).map_err(|_| device_pairing_not_found())?;
    let pairing_code = DevicePairingCode::new(token.c).map_err(|_| device_pairing_not_found())?;

    let record = state
        .device_pairings()
        .get(device_pairing_request_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("device pairing lookup failed: {error}")))?
        .ok_or_else(device_pairing_not_found)?;

    // Uniform anti-enumeration masking: a wrong code, an expired window, or an
    // already-authorized/expired row is indistinguishable from an unknown id.
    if record.pairing_code != pairing_code.as_str()
        || record.state != DevicePairingState::PendingAuthorization
        || record.expires_at <= chrono::Utc::now()
    {
        return Err(device_pairing_not_found());
    }

    let new_device_pubkey: PublicKey = serde_json::from_value(record.new_device_pubkey.clone())
        .map_err(|error| {
            AppError::internal(format!("stored new_device_pubkey invalid: {error}"))
        })?;
    let client_nonce = DevicePairingNonce::new(record.client_nonce.clone())
        .map_err(|error| AppError::internal(format!("stored client_nonce invalid: {error}")))?;
    let server_nonce = DevicePairingNonce::new(record.server_nonce.clone())
        .map_err(|error| AppError::internal(format!("stored server_nonce invalid: {error}")))?;
    let display_name = record
        .display_name
        .as_deref()
        .map(arkret_wire::NonEmptyString::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored display_name invalid: {error}")))?;
    let device_metadata: Option<DeviceMetadata> = record
        .device_metadata
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored device_metadata invalid: {error}")))?;

    json_ok(DevicePairingBootstrap {
        arkret_base_url: state
            .config()
            .public_base_url
            .trim_end_matches('/')
            .to_owned(),
        device_pairing_request_id: DevicePairingRequestId::new(record.device_pairing_request_id)
            .map_err(|error| {
                AppError::internal(format!("stored device_pairing_request_id invalid: {error}"))
            })?,
        pairing_code: DevicePairingCode::new(record.pairing_code)
            .map_err(|error| AppError::internal(format!("stored pairing_code invalid: {error}")))?,
        new_device_pubkey,
        client_nonce,
        gate_audience: record.gate_audience,
        server_nonce,
        display_name,
        device_metadata,
        expires_at: record.expires_at,
    })
}

#[endpoint(
    operation_id = "ak.open.device_pairing.read.status",
    summary = "Poll a device pairing request status",
    tags("device_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.device_pairing.read.status.v1"))]
pub(super) async fn device_pairing_status(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DevicePairingStatusOutcome> {
    reject_device_pairing_query(req)?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<DevicePairingStatusRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid device pairing status request body"))?;
    let record = state
        .device_pairings()
        .get(body.device_pairing_request_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("device pairing lookup failed: {error}")))?
        .ok_or_else(device_pairing_not_found)?;
    // Anti-enumeration: a code mismatch masks as an unknown request id.
    if record.pairing_code != body.pairing_code.as_str() {
        return Err(device_pairing_not_found());
    }
    device_pairing_status_outcome(&record, chrono::Utc::now())
}

/// Pure decision core for the status poll. An open request whose window has
/// elapsed is lazily reported `expired` without waiting for the prune write.
fn device_pairing_status_outcome(
    record: &soland_services::identity::DevicePairingState,
    now: chrono::DateTime<chrono::Utc>,
) -> JsonResult<DevicePairingStatusOutcome> {
    let (state, device_id, authorized_event_ref) = match record.state {
        DevicePairingState::PendingAuthorization => {
            if record.expires_at <= now {
                (DevicePairingState::Expired, None, None)
            } else {
                (DevicePairingState::PendingAuthorization, None, None)
            }
        }
        DevicePairingState::Authorized => {
            let device_id = DeviceId::new(
                record
                    .device_id
                    .as_deref()
                    .ok_or_else(|| {
                        AppError::internal("authorized device pairing missing device_id")
                    })?
                    .to_owned(),
            )
            .map_err(|error| AppError::internal(format!("stored device_id invalid: {error}")))?;
            let authorized_event_ref =
                EventId::new(record.authorized_event_ref.as_deref().ok_or_else(|| {
                    AppError::internal("authorized device pairing missing authorized_event_ref")
                })?)
                .map_err(|error| {
                    AppError::internal(format!("stored authorized_event_ref invalid: {error}"))
                })?;
            (
                DevicePairingState::Authorized,
                Some(device_id),
                Some(authorized_event_ref),
            )
        }
        DevicePairingState::Expired => (DevicePairingState::Expired, None, None),
    };
    json_ok(DevicePairingStatusOutcome {
        state,
        device_id,
        authorized_event_ref,
    })
}

// ── Local helpers (mirrors of the agent-pairing template) ────────────────────
//
// The agent-pairing equivalents live in `identity::agents::pairing` as
// `pub(super)` items and are not reachable from this sibling module, so small
// copies are kept here rather than widening their visibility.

/// Eight Crockford-style characters from exactly 40 OS-CSPRNG bits.
fn generate_pairing_code() -> DevicePairingCode {
    use rand::RngExt;
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = [0u8; 5];
    rand::rng().fill(&mut buf);
    let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
    let value: String = (0..8)
        .map(|index| ALPHABET[((bits >> (35 - index * 5)) & 0x1f) as usize] as char)
        .collect();
    DevicePairingCode::new(value).expect("generated code uses the normative alphabet")
}

fn generate_pairing_nonce() -> DevicePairingNonce {
    use rand::RngExt;
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    DevicePairingNonce::new(URL_SAFE_NO_PAD.encode(bytes))
        .expect("16 random bytes encode to the pairing nonce profile")
}

fn gate_audience(public_base_url: &str) -> Result<String, AppError> {
    let url = reqwest::Url::parse(public_base_url)
        .map_err(|error| AppError::internal(format!("public_base_url is invalid: {error}")))?;
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(AppError::internal(
            "public_base_url has no origin for device pairing",
        ));
    }
    Ok(origin)
}

fn reject_device_pairing_query(req: &Request) -> Result<(), AppError> {
    if req.uri().query().is_none() {
        return Ok(());
    }
    Err(AppError::param_invalid(
        "device pairing inputs must be sent in the JSON body, never in URL path or query",
    )
    .with_status(StatusCode::BAD_REQUEST)
    .with_wire_code("schema_violation"))
}

fn is_device_pairing_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevicePairingToken {
    c: String,
    r: String,
}

fn decode_device_pairing_token(pairing_token: &str) -> Option<DevicePairingToken> {
    let bytes = URL_SAFE_NO_PAD.decode(pairing_token.as_bytes()).ok()?;
    let token = serde_json::from_slice::<DevicePairingToken>(&bytes).ok()?;
    let canonical = arkret_canonical::canonical_json_bytes(&token).ok()?;
    (bytes == canonical).then_some(token)
}

fn device_pairing_not_found() -> AppError {
    AppError::not_found("device pairing token not found")
}

/// Validate the staged device key the same way `auth::device_pair` does before
/// authorizing: `kid` must be an `ak:device` id and `key` must be an Ed25519
/// raw 32-byte base64url key. Directory multibase is a distinct representation
/// and accepting it here would stage a request the proof verifier cannot use.
fn validate_new_device_pubkey(new_device_pubkey: &PublicKey) -> Result<(), AppError> {
    let public_key = new_device_pubkey.key.as_str().trim();
    let bytes = arkret_canonical::base64url_decode(public_key).map_err(|error| {
        AppError::param_invalid(format!(
            "new_device_pubkey.key must be a base64url Ed25519 key: {error}"
        ))
    })?;
    let _: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::param_invalid(format!(
            "new_device_pubkey.key decoded to {} bytes, expected 32",
            bytes.len()
        ))
    })?;
    DeviceId::new(new_device_pubkey.kid.as_str().to_owned())
        .map(|_| ())
        .map_err(|_| AppError::param_invalid("new_device_pubkey.kid must be a ak:device id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pairing_code_matches_the_normative_profile() {
        for _ in 0..128 {
            let code = generate_pairing_code();
            assert_eq!(code.as_str().len(), 8);
            assert!(
                code.as_str()
                    .bytes()
                    .all(|byte| b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&byte))
            );
        }
    }

    #[test]
    fn generated_pairing_nonce_has_128_bits_and_base64url_shape() {
        for _ in 0..64 {
            let nonce = generate_pairing_nonce();
            assert_eq!(URL_SAFE_NO_PAD.decode(nonce.as_str()).unwrap().len(), 16);
        }
    }

    #[test]
    fn pairing_token_requires_the_exact_canonical_envelope() {
        let canonical = br#"{"c":"7H2K9M4Q","r":"device_pairing_request:01964137-0000-7000-8000-0000000000c1"}"#;
        let token = URL_SAFE_NO_PAD.encode(canonical);
        let decoded = decode_device_pairing_token(&token).expect("canonical token");
        assert_eq!(decoded.c, "7H2K9M4Q");

        let noncanonical = br#"{"r":"device_pairing_request:01964137-0000-7000-8000-0000000000c1","c":"7H2K9M4Q"}"#;
        let token = URL_SAFE_NO_PAD.encode(noncanonical);
        assert!(decode_device_pairing_token(&token).is_none());
    }

    #[test]
    fn staged_pairing_key_rejects_directory_multibase() {
        let raw = arkret_canonical::base64url_encode([7_u8; 32]);
        let canonical: PublicKey = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "kid": "ak:device:01964137-0000-7000-8000-0000000000c1",
            "algorithm": "Ed25519",
            "key": raw
        }))
        .unwrap();
        assert!(validate_new_device_pubkey(&canonical).is_ok());

        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]);
        let noncanonical: PublicKey = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "kid": "ak:device:01964137-0000-7000-8000-0000000000c1",
            "algorithm": "Ed25519",
            "key": multibase
        }))
        .unwrap();
        assert!(validate_new_device_pubkey(&noncanonical).is_err());
    }
}
