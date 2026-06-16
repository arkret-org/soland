//! RFC 9421 sender-constrained (PoP) verification for `/_cokret/self/*`.
//!
//! `ck.session.grant` binds a short-lived `session_public_key` to the
//! principal / device / audience (api-conventions.md §3.2). This hoop turns
//! "holds a bearer token" into "holds the bound signing key" for the
//! authenticated self surface:
//!
//! - When the client presents an RFC 9421 HTTP Message Signature, it MUST verify against the
//!   session's `session_public_key`: covered components, `content-digest` over the body, the
//!   `created`/`expires` window (≤300s, ±30s skew, same scale as the federation rail) and the
//!   `keyid` binding. Any failure is rejected as `unauthenticated`.
//! - On a high-security deployment (`sovereign_enclave_enabled`), writes and sensitive reads MUST
//!   be PoP-presented; bare bearer is rejected. On the default profile, bare bearer remains an
//!   accepted downgrade for low-sensitivity clients.
//! - The session key the signature verifies against is sourced per inbound credential: for the ②
//!   grant+DPoP path it is the grant's `session_public_key` (read via introspection, since that
//!   session is request-scoped and never persisted); for a dev-login bearer it is the persisted
//!   `SessionRecord`'s key. Under ② the same Ed25519 device key backs both the DPoP `cnf.jkt`
//!   sender-constraint and this 9421 body-integrity layer.
//!
//! Bearer session validation itself still runs in the per-handler
//! `AuthArgs::authenticated_session`; this hoop only adds the PoP layer.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::http_signature::{
    Component, Ed25519PublicKey, SignatureVerificationPolicy, public_key_from_bytes,
    verify_signed_http_message,
};
use salvo::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::{AppError, ErrorCode};
use crate::routing::federation::{signature_authority, signature_target_uri};
use crate::routing::identity::auth::session_token_hash;
use crate::routing::system::util::bearer_token;
use crate::state::AppState;

/// Maximum PoP signature validity window in seconds (federation.md §3.2 /
/// api-conventions.md §3.2: `expires - created` MUST NOT exceed 300s).
const MAX_SIGNATURE_WINDOW_SECONDS: i64 = 300;
/// Accepted clock skew around `created` / `expires` (±30s, federation scale).
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

/// Path fragments whose GET reads are sensitive (member rosters, private
/// projections, key backups, device inventory, moderation queues) and
/// therefore require PoP on high-security deployments (api-conventions.md
/// §3.2).
const SENSITIVE_READ_FRAGMENTS: &[&str] = &[
    "/members",
    "/projection",
    "/keys/backups",
    "/devices",
    "/moderation",
];

/// Hoop mounted on the `self` surface. Continues the chain on success, renders
/// the canonical error envelope and stops on PoP failure.
#[handler]
pub async fn verify_session_pop(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
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
        return Ok(());
    }

    // A signature is present: it MUST verify against the session signing key.
    let token = bearer_token(req).ok_or_else(|| {
        AppError::unauthenticated("PoP presentation requires a bearer session token")
    })?;
    let jwk = session_signing_key_jwk(state, req, token).await?;
    let (public_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk)?;

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

    let method = req.method().as_str().to_ascii_uppercase();
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
    let policy = if body.is_empty() {
        SignatureVerificationPolicy::new(vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ])
        .require_content_digest(false)
    } else {
        SignatureVerificationPolicy::service_ingest().require_content_digest(true)
    }
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
        let proof = super::auth_grant_dpop::session_grant_introspection_proof(req);
        let grant = super::auth_grant_dpop::introspect_session_grant_cached(
            state,
            token,
            proof.as_ref(),
            false,
        )
        .await
        .map_err(|(_, _, message)| AppError::unauthenticated(message))?;
        return Ok(grant.session_public_key);
    }
    let token_hash = session_token_hash(token, &state.config.service_did);
    let session = state
        .persistence
        .sessions()
        .get(&token_hash)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::unauthenticated("session not found for PoP presentation"))?;
    session.session_public_key.ok_or_else(|| {
        AppError::unauthenticated("session is not bound to a signing key for PoP presentation")
    })
}

/// Whether a bare-bearer (unsigned) request must be rejected: only on
/// high-security deployments, and only for writes / sensitive reads.
fn pop_required(state: &AppState, req: &Request) -> bool {
    if !state.config.sovereign_enclave_enabled {
        return false;
    }
    is_write(req.method()) || is_sensitive_read(req.uri().path())
}

fn is_write(method: &salvo::http::Method) -> bool {
    !matches!(
        *method,
        salvo::http::Method::GET | salvo::http::Method::HEAD | salvo::http::Method::OPTIONS
    )
}

fn is_sensitive_read(path: &str) -> bool {
    SENSITIVE_READ_FRAGMENTS
        .iter()
        .any(|fragment| path.contains(fragment))
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
    fn write_and_sensitive_classification() {
        assert!(is_write(&salvo::http::Method::POST));
        assert!(is_write(&salvo::http::Method::DELETE));
        assert!(!is_write(&salvo::http::Method::GET));
        assert!(is_sensitive_read("/_cokret/self/keys/backups"));
        assert!(is_sensitive_read("/_cokret/self/projection/strands"));
        assert!(!is_sensitive_read("/_cokret/self/realms/r1/links"));
    }
}
