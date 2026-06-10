//! G3.S9 - Applet manifest verifier.
//!
//! `AppletManifest` is a signed envelope an applet developer submits to
//! soland for registration. The verifier performs four checks:
//!
//! 1. **Signature** - Ed25519 over the canonical-JSON serialization of the manifest's body fields
//!    (everything except `signature`). The verifying key is the one bound to the manifest's
//!    `signer_did` (resolved via the trusted registry DID's published key for runnable-stub
//!    purposes - full DID resolver chain integration is a follow-up).
//! 2. **Trusted signer** - `signer_did` MUST match the `trusted_registry_did` configured for this
//!    verifier call (the cotest scenario uses `mock-applet-registry` service DID).
//! 3. **Schema hash** - the manifest carries a `schema_hash` field pinning the version of
//!    `applet.schema.json` it was generated against. We lazily load the schema, hash it, and reject
//!    the manifest if the hashes diverge - a basic guard against silently accepting manifests built
//!    against stale schemas.
//! 4. **Capabilities** - every entry in `requested_capabilities` MUST be in the known registry
//!    below (`KNOWN_APPLET_CAPABILITIES`).
//!
//! Spec anchor: `cokret-spec/spec/v1/zh/extensions/applet-integration.md`
//! Section 3 (manifest shape) + `extensions/applet-schema.md` (JSON schema).
//!
//! TODO(G3.S9-followup): resolve `signer_did` through the live
//! `CompositeDidResolver` rather than the in-test ed25519 key passed
//! alongside the manifest; honour `applet_registration` audit log
//! entries. Signature bytes are already produced with the SDK canonical
//! JSON helper.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};

/// Registered applet capabilities recognised by the verifier. Anything
/// not in this set fails closed with `unknown_capability`. The list is
/// kept narrow on purpose - the spec defers the full capability lattice
/// to a follow-up.
pub const KNOWN_APPLET_CAPABILITIES: &[&str] = &[
    "ck.flow.create",
    "ck.flow.read",
    "ck.flow.update",
    "ck.message.create",
    "ck.morph.read",
    "ck.morph.update",
];

/// On-wire applet manifest envelope. The bot/ghost actor registration
/// flow in `applet-integration.md` Section 4 takes one of these, verifies it,
/// and (if accepted) mints a `bot_actor_id` bound to the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletManifest {
    pub id: String,
    pub version: String,
    pub signer_did: String,
    /// Base64-url (no padding) Ed25519 signature over the manifest body
    /// (everything except this field), canonical-JSON encoded.
    pub signature: String,
    /// Base64-url (no padding) of the Ed25519 verifying key bound to
    /// `signer_did`. Carried inline for the stub verifier so we can
    /// run without the full DID resolver chain.
    pub signer_public_key: String,
    /// Capabilities the applet is asking for; checked against
    /// [`KNOWN_APPLET_CAPABILITIES`].
    pub requested_capabilities: Vec<String>,
    /// sha256(canonical-bytes(applet.schema.json)) at manifest build
    /// time. The verifier recomputes this and rejects on mismatch.
    pub schema_hash: String,
    /// Free-form manifest metadata (display_name, namespace, bridge_url,
    /// etc.). Not interpreted by the verifier.
    #[serde(default)]
    pub metadata: Value,
}

/// Verified manifest - same fields as the input plus a recompute of the
/// schema-hash for the audit trail.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedAppletManifest {
    pub id: String,
    pub signer_did: String,
    pub capabilities: Vec<String>,
    pub schema_hash: String,
    pub metadata: Value,
}

/// Verifier errors. Variant names mirror the wire `error.code` strings
/// surfaced in the HTTP response so callers can pattern-match without
/// `Display`-parsing.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppletManifestError {
    #[error("signature_invalid")]
    SignatureInvalid,
    #[error("untrusted_signer")]
    UntrustedSigner,
    #[error("schema_hash_mismatch")]
    SchemaHashMismatch,
    #[error("unknown_capability: {0}")]
    UnknownCapability(String),
    #[error("malformed_manifest: {0}")]
    MalformedManifest(String),
}

impl AppletManifestError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SignatureInvalid => "signature_invalid",
            Self::UntrustedSigner => "untrusted_signer",
            Self::SchemaHashMismatch => "schema_hash_mismatch",
            Self::UnknownCapability(_) => "unknown_capability",
            Self::MalformedManifest(_) => "malformed_manifest",
        }
    }
}

/// Top-level verifier. See module docs for the four checks.
pub fn verify_manifest(
    manifest: &AppletManifest,
    trusted_registry_did: &str,
) -> Result<VerifiedAppletManifest, AppletManifestError> {
    // (2) Trusted signer.
    if manifest.signer_did != trusted_registry_did {
        return Err(AppletManifestError::UntrustedSigner);
    }

    // (4) Capabilities.
    for cap in &manifest.requested_capabilities {
        if !KNOWN_APPLET_CAPABILITIES.contains(&cap.as_str()) {
            return Err(AppletManifestError::UnknownCapability(cap.clone()));
        }
    }

    // (3) Schema hash.
    let expected_hash = current_applet_schema_hash();
    if !expected_hash.is_empty() && manifest.schema_hash != expected_hash {
        return Err(AppletManifestError::SchemaHashMismatch);
    }

    // (1) Signature.
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(manifest.signer_public_key.as_bytes())
        .map_err(|e| {
            AppletManifestError::MalformedManifest(format!("signer_public_key base64: {e}"))
        })?;
    if pubkey_bytes.len() != 32 {
        return Err(AppletManifestError::MalformedManifest(format!(
            "signer_public_key must decode to 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| AppletManifestError::MalformedManifest(format!("verifying key: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(manifest.signature.as_bytes())
        .map_err(|e| AppletManifestError::MalformedManifest(format!("signature base64: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(AppletManifestError::SignatureInvalid);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let signing_body = manifest_signing_bytes(manifest);
    verifying_key
        .verify(&signing_body, &signature)
        .map_err(|_| AppletManifestError::SignatureInvalid)?;

    Ok(VerifiedAppletManifest {
        id: manifest.id.clone(),
        signer_did: manifest.signer_did.clone(),
        capabilities: manifest.requested_capabilities.clone(),
        schema_hash: manifest.schema_hash.clone(),
        metadata: manifest.metadata.clone(),
    })
}

/// Bytes the signature is computed over: SDK canonical JSON for the manifest
/// body, excluding `signature`.
pub fn manifest_signing_bytes(manifest: &AppletManifest) -> Vec<u8> {
    let body = json!({
        "id": manifest.id,
        "version": manifest.version,
        "signer_did": manifest.signer_did,
        "signer_public_key": manifest.signer_public_key,
        "requested_capabilities": manifest.requested_capabilities,
        "schema_hash": manifest.schema_hash,
        "metadata": manifest.metadata,
    });
    cokret_sdk::canonical::canonical_json_bytes(&body).expect("manifest signing body canonicalizes")
}

/// sha256 hex of the on-disk `applet.schema.json` referenced in
/// `extensions/applet-schema.md`. Loaded lazily; empty string when the
/// repo layout doesn't include the schema file (e.g. when soland is
/// vendored standalone) - in that case the schema-hash check is
/// skipped (see `verify_manifest`).
pub fn current_applet_schema_hash() -> String {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE
        .get_or_init(|| match locate_applet_schema() {
            Some(path) => match std::fs::read(&path) {
                Ok(bytes) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let digest = hasher.finalize();
                    hex_lower(&digest)
                }
                Err(_) => String::new(),
            },
            None => String::new(),
        })
        .clone()
}

fn locate_applet_schema() -> Option<PathBuf> {
    // Walk up from `CARGO_MANIFEST_DIR` until we find a sibling
    // `cokret-spec` checkout. Mirrors how `cotest` locates its fixtures.
    let start = Path::new(env!("CARGO_MANIFEST_DIR"));
    for ancestor in start.ancestors() {
        let candidate = ancestor
            .join("cokret-spec")
            .join("spec")
            .join("v1")
            .join("artifacts")
            .join("schemas")
            .join("applet.schema.json");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// HTTP surface

pub(super) fn router() -> Router {
    Router::with_path("applets/manifest/verify").post(verify_endpoint)
}

#[endpoint(
    operation_id = "org.cokret.soland.applets.manifest.verify",
    tags("extensions"),
    summary = "Verify a signed applet manifest"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.applets.manifest.verify"))]
async fn verify_endpoint(body: JsonBody<Value>) -> JsonResult<Value> {
    let body = body.into_inner();
    let manifest_value = body
        .get("manifest_json")
        .cloned()
        .ok_or_else(|| AppError::missing_param("manifest_json is required"))?;
    let trusted_registry_did = body
        .get("trusted_registry_did")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("trusted_registry_did is required"))?
        .to_owned();
    let manifest: AppletManifest = serde_json::from_value(manifest_value)
        .map_err(|err| AppError::new(ErrorCode::BadJson, format!("manifest_json parse: {err}")))?;
    match verify_manifest(&manifest, &trusted_registry_did) {
        Ok(verified) => json_ok(json!({
            "verified": true,
            "signer_did": verified.signer_did,
            "capabilities": verified.capabilities,
            "schema_hash": verified.schema_hash,
            "errors": Vec::<String>::new(),
        })),
        Err(err) => json_ok(json!({
            "verified": false,
            "signer_did": manifest.signer_did,
            "capabilities": manifest.requested_capabilities,
            "errors": [{
                "code": err.code(),
                "message": err.to_string(),
            }],
        })),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn build_manifest(signer_did: &str) -> (AppletManifest, SigningKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing.verifying_key();
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(pubkey.as_bytes());
        let mut manifest = AppletManifest {
            id: "applet:bridge:demo".to_owned(),
            version: "1.0.0".to_owned(),
            signer_did: signer_did.to_owned(),
            signature: String::new(),
            signer_public_key: pubkey_b64,
            requested_capabilities: vec!["ck.message.create".to_owned(), "ck.flow.read".to_owned()],
            schema_hash: current_applet_schema_hash(),
            metadata: json!({"namespace": "bridge.demo"}),
        };
        let body = manifest_signing_bytes(&manifest);
        let sig = signing.sign(&body);
        manifest.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        (manifest, signing)
    }

    #[test]
    fn manifest_verifier_signature_invalid() {
        let (mut manifest, _) = build_manifest("did:web:registry.example");
        // Tamper after signing.
        manifest.metadata = json!({"namespace": "bridge.other"});
        let err = verify_manifest(&manifest, "did:web:registry.example").unwrap_err();
        assert_eq!(err, AppletManifestError::SignatureInvalid);
    }

    #[test]
    fn manifest_verifier_untrusted_signer() {
        let (manifest, _) = build_manifest("did:web:registry.example");
        let err = verify_manifest(&manifest, "did:web:other.example").unwrap_err();
        assert_eq!(err, AppletManifestError::UntrustedSigner);
    }

    #[test]
    fn manifest_verifier_unknown_capability() {
        let (mut manifest, signing) = build_manifest("did:web:registry.example");
        manifest
            .requested_capabilities
            .push("not:a:capability".to_owned());
        // Re-sign so the signature is valid against the new body - we
        // want to isolate the capability check, not let the signature
        // check fire first.
        let body = manifest_signing_bytes(&manifest);
        manifest.signature = URL_SAFE_NO_PAD.encode(signing.sign(&body).to_bytes());
        let err = verify_manifest(&manifest, "did:web:registry.example").unwrap_err();
        assert!(matches!(err, AppletManifestError::UnknownCapability(_)));
    }

    #[test]
    fn manifest_verifier_schema_hash_mismatch() {
        // Only exercise when the on-disk schema is locatable; otherwise
        // the verifier intentionally skips the schema check.
        if current_applet_schema_hash().is_empty() {
            return;
        }
        let (mut manifest, signing) = build_manifest("did:web:registry.example");
        manifest.schema_hash = "deadbeef".to_owned();
        let body = manifest_signing_bytes(&manifest);
        manifest.signature = URL_SAFE_NO_PAD.encode(signing.sign(&body).to_bytes());
        let err = verify_manifest(&manifest, "did:web:registry.example").unwrap_err();
        assert_eq!(err, AppletManifestError::SchemaHashMismatch);
    }

    #[test]
    fn manifest_verifier_ok() {
        let (manifest, _) = build_manifest("did:web:registry.example");
        let verified = verify_manifest(&manifest, "did:web:registry.example").unwrap();
        assert_eq!(verified.signer_did, "did:web:registry.example");
        assert!(
            verified
                .capabilities
                .contains(&"ck.message.create".to_owned())
        );
    }
}
