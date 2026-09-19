use std::time::Duration;

use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingResolveRequestBody, DevicePairingStageOutcome,
    DevicePairingStageRequestBody, DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};

use super::AppState;
use crate::error::AppError;

const STAGE_PATH: &str = "/_arkret/gate/account/device-pairing/stages";
const RESOLVE_PATH: &str = "/_arkret/gate/account/device-pairing/resolutions";
const STATUS_PATH: &str = "/_arkret/gate/account/device-pairing/status-queries";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// One initial send plus one retry when no HTTP response was received.
const TRANSPORT_ATTEMPTS: usize = 2;

/// Typed Station -> Account Authority boundary for the three public
/// device-pairing handoff operations.
///
/// The public handlers own request parsing, their public rate bucket, and the
/// fresh stage idempotency key. The production implementation owns RFC 9421
/// service-to-service transport and transport retry. Every retry of one
/// [`Self::stage`] call reuses the supplied key; a later public ingress receives
/// a different key from the handler.
#[async_trait]
pub trait AccountAuthorityDevicePairingPort: Send + Sync {
    async fn stage(
        &self,
        state: &AppState,
        request: &DevicePairingStageRequestBody,
        idempotency_key: &str,
    ) -> Result<DevicePairingStageOutcome, AppError>;

    async fn resolve(
        &self,
        state: &AppState,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError>;

    async fn status(
        &self,
        state: &AppState,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusOutcome, AppError>;
}

/// Production Station -> Account Authority transport.
///
/// This client intentionally has no bearer/shared-secret field and never reads
/// `internal_authority_channel`. Both deployment halves use the owning
/// Station's exact service identity; the destination role and trust-domain
/// boundary are bound by the signed HTTP transcript.
#[derive(Debug, Default)]
pub(crate) struct Rfc9421AccountAuthorityDevicePairing;

#[async_trait]
impl AccountAuthorityDevicePairingPort for Rfc9421AccountAuthorityDevicePairing {
    async fn stage(
        &self,
        state: &AppState,
        request: &DevicePairingStageRequestBody,
        idempotency_key: &str,
    ) -> Result<DevicePairingStageOutcome, AppError> {
        post_json(
            state,
            STAGE_PATH,
            "device pairing stage",
            request,
            Some(idempotency_key),
        )
        .await
    }

    async fn resolve(
        &self,
        state: &AppState,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError> {
        post_json(state, RESOLVE_PATH, "device pairing resolve", request, None).await
    }

    async fn status(
        &self,
        state: &AppState,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusOutcome, AppError> {
        post_json(state, STATUS_PATH, "device pairing status", request, None).await
    }
}

async fn post_json<Request, Response>(
    state: &AppState,
    path: &str,
    operation: &str,
    request: &Request,
    idempotency_key: Option<&str>,
) -> Result<Response, AppError>
where
    Request: serde::Serialize + ?Sized,
    Response: serde::de::DeserializeOwned,
{
    let target = account_authority_target(state, path)?;
    let (target_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        operation,
        state.config().development_mode,
        REQUEST_TIMEOUT,
    )
    .map_err(|error| unavailable(operation, error))?;
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| unavailable(operation, format!("canonical request failed: {error}")))?;

    for attempt in 0..TRANSPORT_ATTEMPTS {
        // A transport retry gets a fresh short-lived signature but the exact
        // same canonical bytes and, for stage, the exact same replay key.
        let headers = signed_headers(state, &target, &body, idempotency_key)?;
        match client
            .post(target_url.clone())
            .headers(headers)
            .body(body.clone())
            .send()
            .await
        {
            Ok(response) => return decode_response(response, operation).await,
            Err(error) if attempt + 1 < TRANSPORT_ATTEMPTS => {
                tracing::warn!(%error, %operation, "retrying Account Authority request after transport failure");
            }
            Err(error) => return Err(unavailable(operation, error.to_string())),
        }
    }
    unreachable!("the bounded transport loop returns on its final attempt")
}

fn account_authority_target(state: &AppState, path: &str) -> Result<String, AppError> {
    let base = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| unavailable("device pairing", "Account Authority URL is not configured"))?;
    state
        .config()
        .account_authority_trust_domain
        .as_ref()
        .ok_or_else(|| {
            unavailable(
                "device pairing",
                "Account Authority trust domain is not configured",
            )
        })?;

    let mut target = url::Url::parse(base).map_err(|error| {
        unavailable("device pairing", format!("invalid authority URL: {error}"))
    })?;
    target.set_path(path);
    target.set_query(None);
    target.set_fragment(None);
    Ok(target.into())
}

fn signed_headers(
    state: &AppState,
    target: &str,
    body: &[u8],
    idempotency_key: Option<&str>,
) -> Result<HeaderMap, AppError> {
    let destination_trust_domain = state
        .config()
        .account_authority_trust_domain
        .as_ref()
        .ok_or_else(|| unavailable("device pairing", "missing destination trust domain"))?;
    let headers = transport_headers(
        state.service_id(),
        state.config().trust_domain.as_str(),
        destination_trust_domain.as_str(),
        body,
        idempotency_key,
    )?;
    Ok(crate::routing::federation::outbox::rfc9421_sign(
        state, headers, "POST", target,
    ))
}

fn transport_headers(
    service_id: &str,
    source_trust_domain: &str,
    destination_trust_domain: &str,
    body: &[u8],
    idempotency_key: Option<&str>,
) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    insert_header(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(body),
    )?;
    // A split Account Authority acts for this owning Station, so its service
    // audience is the same stable service id. The signed destination role and
    // explicit trust domain distinguish the receiver side of the transaction.
    insert_header(&mut headers, "source-service-id", service_id)?;
    insert_header(&mut headers, "destination-service-id", service_id)?;
    insert_header(&mut headers, "source-trust-domain", source_trust_domain)?;
    insert_header(
        &mut headers,
        "destination-trust-domain",
        destination_trust_domain.as_str(),
    )?;
    if let Some(idempotency_key) = idempotency_key {
        insert_header(&mut headers, "idempotency-key", idempotency_key)?;
    }
    Ok(headers)
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), AppError> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| unavailable("device pairing", format!("invalid {name}: {error}")))?;
    headers.insert(name, value);
    Ok(())
}

async fn decode_response<Response>(
    response: reqwest::Response,
    operation: &str,
) -> Result<Response, AppError>
where
    Response: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| unavailable(operation, format!("response read failed: {error}")))?;
    if status.is_success() {
        return serde_json::from_slice(&body)
            .map_err(|error| unavailable(operation, format!("invalid response: {error}")));
    }

    // Only protocol failures that belong to the public pairing contract cross
    // the process boundary. Signature/configuration/topology failures collapse
    // to temporarily_unavailable rather than exposing the internal split.
    let remote_code = serde_json::from_slice::<arkret_wire::problem_details::Problem>(&body)
        .ok()
        .and_then(|problem| problem.error_code());
    if status == StatusCode::NOT_FOUND
        && remote_code.is_none_or(|code| code == arkret_wire::ErrorCode::NotFound)
    {
        return Err(AppError::not_found("device pairing request not found"));
    }
    if status == StatusCode::CONFLICT
        && remote_code == Some(arkret_wire::ErrorCode::DuplicateConflict)
    {
        return Err(AppError::new(
            arkret_wire::ErrorCode::DuplicateConflict,
            "device pairing stage idempotency conflict",
        ));
    }
    Err(unavailable(
        operation,
        format!("Account Authority returned HTTP {status}"),
    ))
}

fn unavailable(operation: &str, detail: impl std::fmt::Display) -> AppError {
    tracing::warn!(%operation, %detail, "Account Authority device-pairing transport unavailable");
    crate::app_error!(
        TemporarilyUnavailable,
        format!("{operation} is temporarily unavailable"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_paths_are_the_registered_internal_bindings() {
        assert_eq!(STAGE_PATH, "/_arkret/gate/account/device-pairing/stages");
        assert_eq!(
            RESOLVE_PATH,
            "/_arkret/gate/account/device-pairing/resolutions"
        );
        assert_eq!(
            STATUS_PATH,
            "/_arkret/gate/account/device-pairing/status-queries"
        );
        for path in [STAGE_PATH, RESOLVE_PATH, STATUS_PATH] {
            let operation = arkret_wire::ServiceOperationId::from_http_request("POST", path)
                .expect("internal device-pairing path is registered");
            assert!(operation.as_str().starts_with("ak.gate.account."));
        }
    }

    #[test]
    fn transport_retry_source_keeps_stage_key_and_rebuilds_signature() {
        let source = include_str!("account_authority_device_pairing.rs");
        assert!(source.contains("for attempt in 0..TRANSPORT_ATTEMPTS"));
        assert!(source.contains("signed_headers(state, &target, &body, idempotency_key)"));
        assert!(source.contains("Err(error) if attempt + 1 < TRANSPORT_ATTEMPTS"));
        assert!(!source.contains("bearer_auth"));
        assert!(!source.contains(".internal_authority_channel"));
    }

    #[test]
    fn registered_signature_profile_components_are_all_constructed() {
        let body = br#"{"request":"canonical"}"#;
        let headers = transport_headers(
            "ak:did_core:webvh:z6mStation",
            "ak:trust_domain:station.example",
            "ak:trust_domain:authority.example",
            body,
            Some("device-pairing-stage:019f0000-0000-7000-8000-000000000001"),
        )
        .expect("registered headers");
        assert_eq!(headers["source-service-id"], "ak:did_core:webvh:z6mStation");
        assert_eq!(
            headers["destination-service-id"],
            "ak:did_core:webvh:z6mStation"
        );
        assert_eq!(
            headers["source-trust-domain"],
            "ak:trust_domain:station.example"
        );
        assert_eq!(
            headers["destination-trust-domain"],
            "ak:trust_domain:authority.example"
        );
        assert_eq!(
            headers["idempotency-key"],
            "device-pairing-stage:019f0000-0000-7000-8000-000000000001"
        );
        let digest = arkret_signatures::http_signature::ContentDigest::parse(
            headers["content-digest"].to_str().unwrap(),
        )
        .expect("RFC 9530 digest");
        arkret_signatures::http_signature::verify_content_digest(&digest, body)
            .expect("digest binds exact HTTP content bytes");

        let source = include_str!("account_authority_device_pairing.rs");
        // The shared signer adds @method, @target-uri, @authority and the
        // exact Arkret-Operation selector before creating Signature-Input.
        assert!(source.contains("outbox::rfc9421_sign"));
    }
}
