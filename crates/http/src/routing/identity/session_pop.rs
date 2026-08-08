//! RFC 9421 sender-constrained (PoP) verification for `/_arkret/self/*`.
//!
//! `ak.session.grant` binds a short-lived `session_public_key` to the
//! principal / device / audience (api-conventions.md §3.2). This hoop turns
//! "holds a bearer token" into "holds the bound signing key" for the
//! authenticated self surface:
//!
//! - When the client presents an RFC 9421 HTTP Message Signature, it MUST verify against the
//!   session's `session_public_key`: covered components, `content-digest` over the body, the
//!   `created`/`expires` window (≤300s, ±30s skew, same scale as the federation rail) and the
//!   `keyid` binding. Any failure is rejected as `unauthenticated`.
//! - On a high-security deployment (`sovereign_enclave_enabled`), protected self-surface operations
//!   are classified from the embedded operation registry and MUST be PoP-presented; unknown
//!   operations fail closed. Explicit public-projection exceptions are treated as unauthenticated
//!   when no valid proof is present.
//! - The session key the signature verifies against is sourced per inbound credential: for the ②
//!   grant+DPoP path it is the grant's `session_public_key` (read via introspection, since that
//!   session is request-scoped and never persisted); for a dev-login bearer it is the persisted
//!   `SessionRecord`'s key. Under ② the same Ed25519 device key backs both the DPoP `cnf.jkt`
//!   sender-constraint and this 9421 body-integrity layer.
//!
//! Bearer session validation itself still runs in the per-handler
//! `AuthArgs::authenticated_session`; this hoop only adds the PoP layer.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use arkret_signatures::http_signature::{
    Component, ContentDigest, Ed25519PublicKey, SignatureVerificationPolicy, public_key_from_bytes,
    verify_content_digest, verify_signed_http_message,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use salvo::prelude::*;
use sha2::{Digest, Sha256};
use soland_http::error::{AppError, ErrorCode};
use soland_http::util::bearer_token;

use crate::routing::federation::{signature_authority, signature_target_uri};
use crate::routing::identity::auth::session_credential_hash;
use crate::state::AppState;

/// Maximum PoP signature validity window in seconds (federation.md §3.2 /
/// api-conventions.md §3.2: `expires - created` MUST NOT exceed 300s).
const MAX_SIGNATURE_WINDOW_SECONDS: i64 = 300;
/// Accepted clock skew around `created` / `expires` (±30s, federation scale).
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Debug)]
struct SessionPopPolicy {
    bindings: Vec<(String, String, String)>,
    public_projection_operations: BTreeSet<String>,
}

static SESSION_POP_POLICY: OnceLock<SessionPopPolicy> = OnceLock::new();

/// Hoop mounted on the `self` surface. Continues the chain on success, renders
/// the canonical error envelope and stops on PoP failure.
#[handler]
pub async fn verify_session_pop(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    match enforce_session_pop(&state, req).await {
        Ok(()) => {
            ctrl.call_next(req, depot, res).await;
        }
        Err(error) => {
            error.write(req, depot, res).await;
        }
    }
}

async fn enforce_session_pop(state: &AppState, req: &mut Request) -> Result<(), AppError> {
    let presented = req.headers().contains_key("signature-input");
    if !presented {
        if pop_required(state, req) {
            return Err(AppError::unauthenticated(
                "RFC 9421 PoP signature required for this operation on this deployment",
            ));
        }
        if state.config().sovereign_enclave_enabled && is_public_projection_request(req) {
            req.headers_mut().remove(salvo::http::header::AUTHORIZATION);
            req.headers_mut().remove("dpop");
        }
        return Ok(());
    }

    // A signature is present: it MUST verify against the session signing key.
    let token = bearer_token(req).ok_or_else(|| {
        AppError::unauthenticated("PoP presentation requires a bearer session token")
    })?;
    let jwk = session_signing_key_jwk(state, req, token).await?;
    let (public_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk)?;

    soland_http::http_signature::reject_content_encoding(req, || {
        AppError::unauthenticated("PoP-signed JSON requests must not use Content-Encoding")
    })?;
    let body = req
        .payload()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::BadJson,
                format!("unable to read request body for PoP verification: {error}"),
            )
        })?
        .to_vec();
    if !body.is_empty() {
        let content_digest = req
            .headers()
            .get("content-digest")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                AppError::unauthenticated("PoP-signed request is missing Content-Digest")
            })?;
        let content_digest = ContentDigest::parse(content_digest).map_err(|error| {
            AppError::unauthenticated(format!("PoP Content-Digest is invalid: {error}"))
        })?;
        verify_content_digest(&content_digest, &body).map_err(|error| {
            AppError::unauthenticated(format!(
                "PoP Content-Digest does not match exact request bytes: {error}"
            ))
        })?;
        arkret_signatures::http_signature::validate_signed_canonical_json_body(false, &body)
            .map_err(|error| {
                AppError::unauthenticated(format!(
                    "PoP-signed request body is not canonical JSON: {error}"
                ))
            })?;
    }

    let method = req.method().as_str().to_owned();
    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let path = req.uri().path().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    // `content-digest` is mandatory only for body-bearing requests
    // (service-http-binding.md §2.5); a body-less signed GET need not carry it.
    let mut required_components = if body.is_empty() {
        vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ]
    } else {
        vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header("content-digest".to_owned()),
        ]
    };
    for header_name in ["idempotency-key", "x-arkret-wait-for"] {
        if req.headers().contains_key(header_name) {
            required_components.push(Component::Header(header_name.to_owned()));
        }
    }
    let policy = SignatureVerificationPolicy::new(required_components)
        .require_content_digest(!body.is_empty())
        .max_clock_skew_seconds(MAX_CLOCK_SKEW_SECONDS);

    let verified = verify_signed_http_message(
        &method,
        &target_uri,
        &authority,
        &path,
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        &body,
        &public_key,
        &policy,
        chrono::Utc::now().timestamp(),
    )
    .map_err(|error| {
        AppError::unauthenticated(format!("RFC 9421 PoP verification failed: {error}"))
    })?;

    // SDK policy enforces created/expires sanity + skew; the 300s upper bound on
    // the window is the protocol replay constant and is enforced here, in the
    // same way as the federation inbound rail.
    if verified.signature_input.expires - verified.signature_input.created
        > MAX_SIGNATURE_WINDOW_SECONDS
    {
        return Err(AppError::unauthenticated(
            "PoP signature validity window exceeds the 300s protocol maximum",
        ));
    }
    // keyid MUST point at the session's bound signing key (api-conventions.md
    // §3.2). The cryptographic binding is already enforced above by verifying
    // against the session key bytes; this rejects a mismatched selector.
    // Accept either the JWK's explicit `kid` or its RFC 7638 thumbprint, so a
    // client that selects by thumbprint and one that echoes the issued kid both
    // satisfy the binding.
    let key_id = &verified.signature_input.key_id;
    let key_id_bound = *key_id == thumbprint || explicit_kid.as_deref() == Some(key_id.as_str());
    if !key_id_bound {
        return Err(AppError::unauthenticated(
            "PoP signature keyid is not bound to the session signing key",
        ));
    }

    Ok(())
}

/// Resolve the session signing-key JWK that an RFC 9421 PoP signature MUST
/// verify against, for whichever inbound credential is being presented
/// (account-lifecycle.md §4.1 D6):
///
/// - **② grant + DPoP** (`DPoP` header present): the session is request-scoped and is NEVER
///   persisted as a local bearer, so the bound signing key is read from the grant's
///   `session_public_key` via session-grant introspection (cached ≤120s). The grant binds the same
///   Ed25519 device key as both the DPoP `cnf.jkt` and the 9421 `session_public_key`, so DPoP
///   supplies the per-request sender-constraint while this 9421 layer adds body integrity.
/// - **dev-login bearer**: the key comes from the persisted `SessionRecord`.
async fn session_signing_key_jwk(
    state: &AppState,
    req: &Request,
    token: &str,
) -> Result<String, AppError> {
    if super::auth_grant_dpop::is_grant_dpop_presentation(req) {
        let grant = super::auth_grant_dpop::introspect_session_grant_cached(state, token, false)
            .await
            .map_err(|(_, _, message)| AppError::unauthenticated(message))?;
        return Ok(grant.session_public_key.into_string());
    }
    let token_hash = session_credential_hash(token, state.service_id());
    let session = state
        .sessions()
        .session(&token_hash)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::unauthenticated("session not found for PoP presentation"))?;
    session.session_public_key.ok_or_else(|| {
        AppError::unauthenticated("session is not bound to a signing key for PoP presentation")
    })
}

/// Whether an unsigned request must be rejected on a high-security deployment.
/// The classifier comes from the embedded operation registry; an unknown self
/// operation fails closed.
fn pop_required(state: &AppState, req: &Request) -> bool {
    if !state.config().sovereign_enclave_enabled || req.method() == salvo::http::Method::OPTIONS {
        return false;
    }
    !is_public_projection_request(req)
}

fn is_public_projection_request(req: &Request) -> bool {
    let policy = session_pop_policy();
    policy.bindings.iter().any(|(method, path, operation_id)| {
        method == req.method().as_str()
            && path_template_matches(path, req.uri().path())
            && policy.public_projection_operations.contains(operation_id)
    })
}

fn session_pop_policy() -> &'static SessionPopPolicy {
    SESSION_POP_POLICY.get_or_init(|| {
        let bundle = arkret_schema::SpecArtifactBundle::load_embedded()
            .expect("embedded operation registry must load");
        let operation_registry = bundle
            .operation_registry
            .as_object()
            .expect("embedded operation registry must be an object");
        let policy = operation_registry
            .get("high_security_session_authentication_policy")
            .and_then(serde_json::Value::as_object)
            .expect("embedded operation registry must declare high-security session policy");
        let public_projection_operations = policy
            .get("unauthenticated_public_projection_operations")
            .and_then(serde_json::Value::as_array)
            .expect("high-security session policy public operation list must be an array")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("public projection operation id must be a string")
                    .to_owned()
            })
            .collect();
        let bindings = operation_registry
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .expect("embedded operation registry operations must be an array")
            .iter()
            .filter_map(|row| {
                let operation_id = row.get("operation_id")?.as_str()?;
                if !operation_id.starts_with("ak.self.") {
                    return None;
                }
                let (method, path) = row.get("http")?.as_str()?.split_once(' ')?;
                Some((method.to_owned(), path.to_owned(), operation_id.to_owned()))
            })
            .collect();
        SessionPopPolicy {
            bindings,
            public_projection_operations,
        }
    })
}

fn path_template_matches(template: &str, actual: &str) -> bool {
    let template_segments = template.trim_matches('/').split('/').collect::<Vec<_>>();
    let actual_segments = actual.trim_matches('/').split('/').collect::<Vec<_>>();
    template_segments.len() == actual_segments.len()
        && template_segments
            .iter()
            .zip(actual_segments)
            .all(|(expected, observed)| {
                (expected.starts_with('{') && expected.ends_with('}')) || *expected == observed
            })
}

/// Parse the stored session signing key JWK into its Ed25519 public key, the
/// explicit JWK `kid` (if any), and its RFC 7638 thumbprint. A presented keyid
/// is accepted if it matches either.
fn parse_session_jwk(jwk: &str) -> Result<(Ed25519PublicKey, Option<String>, String), AppError> {
    let value: serde_json::Value = serde_json::from_str(jwk)
        .map_err(|_| AppError::unauthenticated("session signing key is not valid JWK JSON"))?;
    let kty = value
        .get("kty")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let crv = value
        .get("crv")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if kty != "OKP" || crv != "Ed25519" {
        return Err(AppError::unauthenticated(
            "session signing key is not an Ed25519 OKP JWK",
        ));
    }
    let x = value
        .get("x")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::unauthenticated("session signing key JWK is missing x"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x.as_bytes())
        .map_err(|_| AppError::unauthenticated("session signing key JWK x is not base64url"))?;
    let public_key = public_key_from_bytes(&bytes).map_err(|_| {
        AppError::unauthenticated("session signing key JWK x is not a valid Ed25519 public key")
    })?;
    let explicit_kid = value
        .get("kid")
        .and_then(|value| value.as_str())
        .filter(|kid| !kid.is_empty())
        .map(ToOwned::to_owned);
    Ok((public_key, explicit_kid, jwk_thumbprint(x)))
}

/// RFC 7638 JWK thumbprint for an Ed25519 OKP key with base64url `x`.
fn jwk_thumbprint(x: &str) -> String {
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8037 §A.2 sample Ed25519 public key (a valid curve point).
    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    // RFC 8037 §A.3 thumbprint of the key above.
    const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

    #[test]
    fn thumbprint_matches_rfc8037_vector() {
        assert_eq!(jwk_thumbprint(RFC8037_X), RFC8037_THUMBPRINT);
    }

    #[test]
    fn jwk_without_kid_yields_thumbprint_only() {
        let jwk = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{RFC8037_X}\"}}");
        let (_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk).expect("valid JWK");
        assert_eq!(explicit_kid, None);
        assert_eq!(thumbprint, RFC8037_THUMBPRINT);
    }

    #[test]
    fn jwk_with_explicit_kid_is_surfaced_alongside_thumbprint() {
        let jwk = format!(
            "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{RFC8037_X}\",\"kid\":\"session-abc\"}}"
        );
        let (_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk).expect("valid JWK");
        assert_eq!(explicit_kid.as_deref(), Some("session-abc"));
        assert_eq!(thumbprint, RFC8037_THUMBPRINT);
    }

    #[test]
    fn rejects_non_ed25519_jwk() {
        let jwk = format!("{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{RFC8037_X}\"}}");
        assert!(parse_session_jwk(&jwk).is_err());
    }

    #[test]
    fn rejects_jwk_missing_x() {
        let jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"}";
        assert!(parse_session_jwk(jwk).is_err());
    }

    #[test]
    fn rejects_non_base64url_x() {
        let jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"not base64!!\"}";
        assert!(parse_session_jwk(jwk).is_err());
    }

    #[test]
    fn operation_path_templates_match_only_the_registered_shape() {
        assert!(path_template_matches(
            "/_arkret/self/realms/{realm_id}/strands",
            "/_arkret/self/realms/realm-1/strands"
        ));
        assert!(!path_template_matches(
            "/_arkret/self/realms/{realm_id}/strands",
            "/_arkret/self/realms/realm-1/links"
        ));
        assert!(!path_template_matches(
            "/_arkret/self/realms/{realm_id}/strands",
            "/_arkret/self/realms/realm-1/strands/extra"
        ));
    }

    #[test]
    fn embedded_policy_has_explicit_public_projection_exceptions() {
        let policy = session_pop_policy();
        assert!(
            policy
                .public_projection_operations
                .contains("ak.self.events.read.describe")
        );
        assert!(
            policy
                .public_projection_operations
                .contains("ak.self.account.read.describe")
        );
        assert!(
            !policy
                .public_projection_operations
                .contains("ak.self.events.read.scan")
        );
    }
}
