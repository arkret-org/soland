//! G4.T3 — load `verified_profiles[]` from a cotest-produced artifact at
//! startup.
//!
//! Pipeline:
//! - cotest's `write-verified-profiles.mjs` parses Playwright's junit.xml
//!   from a joint-e2e run and emits `verified-profiles.json` next to it.
//!   Schema:
//!
//!   ```text
//!   {
//!     "version": "1",
//!     "generated_at": "<RFC3339>",
//!     "run_id": "<artifacts dir basename>",
//!     "verified": [
//!       {
//!         "profile_id": "...",
//!         "service_role": "principal_server" | "auth_server" | ...,
//!         "test_count": <int>,
//!         "spec_file": "...",
//!         "artifact_digest": "sha256:<hex>",
//!         "artifact_ref": "file:///.../verified-profiles.json",
//!         "cotest_issuer_did": "did:...",
//!         "signature": "<detached signature>",
//!         "valid_until": "<RFC3339>"
//!       }
//!     ]
//!   }
//!   ```
//! - soland reads the path from env var
//!   [`VERIFIED_PROFILES_ARTIFACT_ENV`] (`SOLAND_VERIFIED_PROFILES_ARTIFACT`)
//!   at startup, filters to entries whose `service_role` matches
//!   [`SOLAND_SERVICE_ROLE`] (`principal_server`), and stores them in
//!   [`crate::state::AppState::verified_profiles`].
//! - `describe.rs::apply_claim_level_partition` reads that vector and
//!   emits a `verified_profiles[]` array matching the wire schema
//!   `service-describe.schema.json#/properties/verified_profiles` (via
//!   the SDK's typed [`contrix_sdk::VerifiedProfileEntry`]).
//!
//! Dev-mode invariant (service-surface.md §3.0): when the env var is unset
//! OR the file is missing OR malformed, the loaded vector is empty and the
//! describe handler emits `verified_profiles: []`. The env var IS the
//! feature flag — there is no Cargo cfg switch.
//!
//! Cross-check: every loaded entry's `profile_id` MUST also appear in the
//! local `claimed_profiles[]` set (built in
//! `describe.rs::apply_claim_level_partition`). Entries that fail the
//! cross-check are dropped with a `warn!` line; the service does NOT crash.
//! Rationale: a verified-profiles artifact from a different soland build
//! could otherwise advertise profiles this binary does not actually
//! self-claim, which would be a silent broken-trust posture.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;

/// Env var soland reads at startup to locate the cotest
/// `verified-profiles.json` artifact. Absence / empty value disables the
/// loader (dev-mode invariant).
pub const VERIFIED_PROFILES_ARTIFACT_ENV: &str = "SOLAND_VERIFIED_PROFILES_ARTIFACT";

/// soland's role string in the cotest writer's `service_role` filter. Mirrors
/// the canonical role names in
/// `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json#/profile_role_map`.
pub const SOLAND_SERVICE_ROLE: &str = "principal_server";

/// Raw shape of the JSON file produced by `write-verified-profiles.mjs`.
#[derive(Debug, Deserialize)]
struct VerifiedProfilesArtifact {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    generated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    verified: Vec<RawVerifiedEntry>,
}

#[derive(Debug, Deserialize)]
struct RawVerifiedEntry {
    profile_id: String,
    #[serde(default)]
    service_role: Option<String>,
    #[serde(default)]
    test_count: Option<u64>,
    #[serde(default)]
    spec_file: Option<String>,
    #[serde(default)]
    artifact_digest: Option<String>,
    #[serde(default)]
    artifact_ref: Option<String>,
    #[serde(default)]
    cotest_issuer_did: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    valid_until: Option<DateTime<Utc>>,
}

/// In-memory representation of a loaded verified-profile entry, owned by
/// [`crate::state::AppState`]. The handler converts each entry into an SDK
/// [`contrix_sdk::VerifiedProfileEntry`] on the way out.
#[derive(Debug, Clone)]
pub struct VerifiedProfileDescriptor {
    pub profile_id: String,
    pub service_role: String,
    pub cotest_run_id: String,
    pub artifact_digest: String,
    pub artifact_ref: String,
    pub cotest_issuer_did: contrix_sdk::Did,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub test_count: u64,
    pub spec_file: Option<String>,
}

/// Read the artifact pointed to by [`VERIFIED_PROFILES_ARTIFACT_ENV`] (if
/// any) and return the entries whose `service_role` matches
/// [`SOLAND_SERVICE_ROLE`]. Logging policy:
///
/// - env var unset / empty → `debug!` (this is the normal dev posture)
/// - file missing → `warn!` + return empty
/// - file present but JSON parse fails → `warn!` + return empty
/// - parse OK → `info!` with the loaded count
///
/// The function never panics and never returns `Err`; the empty fallback IS
/// the dev-mode contract.
pub fn load_from_env() -> Arc<Vec<VerifiedProfileDescriptor>> {
    let path = match std::env::var(VERIFIED_PROFILES_ARTIFACT_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            tracing::debug!(
                target: "verified_profiles",
                env_var = VERIFIED_PROFILES_ARTIFACT_ENV,
                "verified-profiles artifact env var unset; verified_profiles=[] (dev-mode invariant)"
            );
            return Arc::new(Vec::new());
        }
    };
    Arc::new(load_from_path(&path))
}

/// Body of [`load_from_env`] split out for tests and the AppState
/// constructor — both want the same parse + filter + warn pipeline.
pub fn load_from_path(path: impl AsRef<Path>) -> Vec<VerifiedProfileDescriptor> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path.display(),
                %error,
                "verified-profiles artifact path is set but file is unreadable; verified_profiles=[]"
            );
            return Vec::new();
        }
    };
    let parsed: VerifiedProfilesArtifact = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path.display(),
                %error,
                "verified-profiles artifact failed to parse as JSON; verified_profiles=[]"
            );
            return Vec::new();
        }
    };

    let run_id = parsed.run_id.unwrap_or_default();
    let generated_at = parsed.generated_at.unwrap_or_else(Utc::now);
    let mut out = Vec::with_capacity(parsed.verified.len());
    let total_input = parsed.verified.len();
    for entry in parsed.verified {
        // Filter by service_role. Entries without a service_role field, or
        // with a role we don't recognise, MUST be dropped — silently
        // advertising another service's verified profile would be a
        // cross-binding lie.
        let role = match entry.service_role.as_deref() {
            Some(r) => r,
            None => {
                tracing::warn!(
                    target: "verified_profiles",
                    profile_id = %entry.profile_id,
                    "dropping verified-profile entry: missing service_role"
                );
                continue;
            }
        };
        if role != SOLAND_SERVICE_ROLE {
            continue;
        }
        let Some(artifact_digest) = valid_artifact_digest(entry.artifact_digest, &entry.profile_id)
        else {
            continue;
        };
        let Some(artifact_ref) =
            required_non_empty(entry.artifact_ref, "artifact_ref", &entry.profile_id)
        else {
            continue;
        };
        let Some(cotest_issuer_did_raw) = required_non_empty(
            entry.cotest_issuer_did,
            "cotest_issuer_did",
            &entry.profile_id,
        ) else {
            continue;
        };
        let cotest_issuer_did = match contrix_sdk::Did::new(cotest_issuer_did_raw) {
            Ok(did) => did,
            Err(error) => {
                tracing::warn!(
                    target: "verified_profiles",
                    profile_id = %entry.profile_id,
                    %error,
                    "dropping verified-profile entry: invalid cotest_issuer_did"
                );
                continue;
            }
        };
        let Some(signature) = required_non_empty(entry.signature, "signature", &entry.profile_id)
        else {
            continue;
        };
        out.push(VerifiedProfileDescriptor {
            profile_id: entry.profile_id,
            service_role: role.to_owned(),
            cotest_run_id: run_id.clone(),
            artifact_digest,
            artifact_ref,
            cotest_issuer_did,
            signature,
            timestamp: generated_at,
            valid_until: entry.valid_until,
            test_count: entry.test_count.unwrap_or(0),
            spec_file: entry.spec_file,
        });
    }

    tracing::info!(
        target: "verified_profiles",
        path = %path.display(),
        version = parsed.version.as_deref().unwrap_or(""),
        run_id = %run_id,
        loaded = out.len(),
        total_in_artifact = total_input,
        service_role = SOLAND_SERVICE_ROLE,
        "loaded verified-profile entries from artifact"
    );
    out
}

fn valid_artifact_digest(value: Option<String>, profile_id: &str) -> Option<String> {
    let hash = required_non_empty(value, "artifact_digest", profile_id)?;
    if hash.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) {
        return Some(hash);
    }
    tracing::warn!(
        target: "verified_profiles",
        profile_id = %profile_id,
        "dropping verified-profile entry: artifact_digest must match sha256:<64 lowercase hex>"
    );
    None
}

fn required_non_empty(value: Option<String>, field: &str, profile_id: &str) -> Option<String> {
    match value {
        Some(value) if !value.trim().is_empty() => Some(value),
        _ => {
            tracing::warn!(
                target: "verified_profiles",
                profile_id = %profile_id,
                field = %field,
                "dropping verified-profile entry: missing required field"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_env_var_yields_empty() {
        // SAFETY: tests run single-threaded by default for this crate; the
        // env var is local to the process.
        unsafe {
            std::env::remove_var(VERIFIED_PROFILES_ARTIFACT_ENV);
        }
        let v = load_from_env();
        assert!(v.is_empty());
    }

    #[test]
    fn malformed_json_yields_empty() {
        let dir = tempfile_dir();
        let path = dir.join("verified-profiles.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let v = load_from_path(&path);
        assert!(v.is_empty());
    }

    #[test]
    fn missing_file_yields_empty() {
        let v = load_from_path("Z:/definitely/nonexistent/verified-profiles.json");
        assert!(v.is_empty());
    }

    #[test]
    fn filters_to_principal_server_role() {
        let dir = tempfile_dir();
        let path = dir.join("verified-profiles.json");
        let mut f = std::fs::File::create(&path).unwrap();
        let payload = r#"{
            "version": "1",
            "generated_at": "2026-05-20T00:00:00Z",
            "run_id": "test-run",
            "verified": [
                 {
                     "profile_id": "cx.profile.principal_server.v1",
                     "service_role": "principal_server",
                     "test_count": 3,
                     "spec_file": "cotest/e2e/tests/conformance/profile-gates.spec.ts",
                     "artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                     "artifact_ref": "file:///tmp/verified-profiles.json",
                     "cotest_issuer_did": "did:web:cotest.example",
                     "signature": "eddsa-jcs-b64url:test-principal-signature",
                     "valid_until": "2026-06-20T00:00:00Z"
                 },
                 {
                     "profile_id": "cx.profile.auth_server.v1",
                     "service_role": "auth_server",
                     "test_count": 1,
                     "spec_file": "cotest/e2e/tests/sync/service-surface-contract.spec.ts",
                     "artifact_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                     "artifact_ref": "file:///tmp/verified-profiles.json",
                     "cotest_issuer_did": "did:web:cotest.example",
                     "signature": "eddsa-jcs-b64url:test-auth-signature"
                 }
            ]
        }"#;
        f.write_all(payload.as_bytes()).unwrap();
        let v = load_from_path(&path);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].profile_id, "cx.profile.principal_server.v1");
        assert_eq!(v[0].service_role, "principal_server");
        assert_eq!(v[0].cotest_run_id, "test-run");
        assert_eq!(
            v[0].artifact_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(v[0].artifact_ref, "file:///tmp/verified-profiles.json");
        assert_eq!(v[0].cotest_issuer_did.as_str(), "did:web:cotest.example");
        assert_eq!(v[0].signature, "eddsa-jcs-b64url:test-principal-signature");
        assert_eq!(
            v[0].valid_until.unwrap().to_rfc3339(),
            "2026-06-20T00:00:00+00:00"
        );
    }

    /// Per-test scratch dir — using the OS temp dir directly avoids pulling
    /// in a `tempfile` dev-dep just for these unit tests.
    fn tempfile_dir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("soland-verified-profiles-{}", uniq()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn uniq() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
