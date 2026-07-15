//! `cargo run --bin soland-rotate-drill -- ...`
//!
//! Notary signing-key rotation drill.
//!
//! Three modes — selected by exactly one of the mode flags:
//!
//! 1. `--rotate-drill` (default when no mode flag is set) — verifies the current fail-closed
//!    rotation boundary against a running Soland:
//!      - snapshots the active KeyStore-backed signing seed,
//!      - calls the authenticated rotate-signing-key admin route,
//!      - requires `501 unsupported_feature` while atomic WebVH/DID/bundle rotation is unavailable,
//!      - asserts the KeyStore seed remains byte-identical and usable.
//!
//!    Exit 0 on full PASS, 1 on any assertion fail, 2 on prerequisite/IO.
//!
//! 2. `--export-only` — used by `scripts/backup-drill.sh`. Loads the KeyStore-persisted notary seed
//!    referenced by an SDK `ServiceIdentityBundle` and writes a single-key JSON snapshot to
//!    `--output`.
//!
//! 3. `--import-only` — used by `scripts/restore-drill.sh`. Reads the JSON snapshot from `--input`
//!    and stores the seed back into the platform KeyStore under the same id.
//!
//! All three modes resolve the service DID and active signing `KeyRef` from a
//! verified SDK identity bundle:
//!   - `SOLAND_SERVICE_IDENTITY_BUNDLE` (or `--identity-bundle`)
//!   - `SOLAND_PUBLIC_BASE_URL` (or `--target`)
//!   - `SOLAND_ADMIN_BEARER` (or `--bearer`)
//!
//! The drill is intentionally self-contained (no shared state with the
//! soland server process beyond the platform KeyStore + the public HTTP
//! API), so it works in production whether soland is running locally or
//! in a Kubernetes pod.

use std::process::ExitCode;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    RotateDrill,
    ExportOnly,
    ImportOnly,
}

#[derive(Clone, Debug)]
struct Args {
    mode: Mode,
    identity_bundle: String,
    target_url: Option<String>,
    bearer: Option<String>,
    realm_id: Option<String>,
    output: Option<String>,
    input: Option<String>,
}

fn parse_args() -> anyhow::Result<Args> {
    let raw: Vec<String> = std::env::args().collect();
    let mut mode = Mode::RotateDrill;
    let mut identity_bundle = std::env::var("SOLAND_SERVICE_IDENTITY_BUNDLE").ok();
    let mut target_url = std::env::var("SOLAND_PUBLIC_BASE_URL").ok();
    let mut bearer = std::env::var("SOLAND_ADMIN_BEARER").ok();
    let mut realm_id: Option<String> = None;
    let mut output = None;
    let mut input = None;
    let mut explicit_mode = false;

    let mut i = 1;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "--rotate-drill" => {
                mode = Mode::RotateDrill;
                explicit_mode = true;
            }
            "--export-only" => {
                mode = Mode::ExportOnly;
                explicit_mode = true;
            }
            "--import-only" => {
                mode = Mode::ImportOnly;
                explicit_mode = true;
            }
            "--identity-bundle" => {
                i += 1;
                identity_bundle = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--identity-bundle needs a path"))?,
                );
            }
            "--target" => {
                i += 1;
                target_url = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--target needs a URL"))?,
                );
            }
            "--bearer" => {
                i += 1;
                bearer = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--bearer needs a value"))?,
                );
            }
            "--realm-id" => {
                i += 1;
                realm_id = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--realm-id needs a value"))?,
                );
            }
            "--output" => {
                i += 1;
                output = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--output needs a path"))?,
                );
            }
            "--input" => {
                i += 1;
                input = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--input needs a path"))?,
                );
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: soland-rotate-drill [--rotate-drill | --export-only | --import-only]\n\
                     \n\
                     mode flags (one of):\n\
                       --rotate-drill   end-to-end rotate-signing-key drill (default)\n\
                       --export-only    write KeyStore-persisted seed to --output\n\
                       --import-only    read seed from --input and write to KeyStore\n\
                     \n\
                     options:\n\
                       --identity-bundle <path>  validated SDK ServiceIdentityBundle (required)\n\
                       --target <url>          base URL of running soland (rotate-drill mode)\n\
                       --bearer <token>        admin session token (rotate-drill mode)\n\
                       --realm-id <id>         Realm id for the rotate endpoint path (required in rotate-drill mode)\n\
                       --output <path>         destination JSON for --export-only\n\
                       --input <path>          source JSON for --import-only\n\
                    "
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
        i += 1;
    }
    let _ = explicit_mode; // surfaced for clarity; default is rotate-drill.
    let identity_bundle = identity_bundle.ok_or_else(|| {
        anyhow::anyhow!(
            "--identity-bundle (or SOLAND_SERVICE_IDENTITY_BUNDLE) is required; the drill must not accept a configured service DID"
        )
    })?;
    Ok(Args {
        mode,
        identity_bundle,
        target_url,
        bearer,
        realm_id,
        output,
        input,
    })
}

fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[rotate-drill] arg parse failed: {e}");
            return ExitCode::from(2);
        }
    };
    let identity = match load_service_identity(&args.identity_bundle) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("[rotate-drill] identity bundle rejected: {error}");
            return ExitCode::from(2);
        }
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");

    let result = runtime.block_on(async {
        match args.mode {
            Mode::RotateDrill => run_rotate_drill(&args, &identity).await,
            Mode::ExportOnly => run_export_only(&args, &identity),
            Mode::ImportOnly => run_import_only(&args, &identity),
        }
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(DrillError::Io(e)) => {
            eprintln!("[rotate-drill] IO error: {e}");
            ExitCode::from(2)
        }
        Err(DrillError::Assertion(msg)) => {
            eprintln!("[rotate-drill] FAIL — {msg}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
enum DrillError {
    Io(String),
    Assertion(String),
}

const SERVICE_IDENTITY_KEYSTORE_APP: &str = "soland.service-identity";

#[derive(Debug)]
struct ResolvedServiceIdentity {
    service_id: String,
    signing_key_ref: String,
    signing_key_multibase: String,
}

fn load_service_identity(path: &str) -> anyhow::Result<ResolvedServiceIdentity> {
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("read identity bundle {path}: {error}"))?;
    let bundle: arkret_sdk::ServiceIdentityBundle = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("parse identity bundle {path}: {error}"))?;
    bundle
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid identity bundle {path}: {error}"))?;

    let identity = &bundle.identity.identity;
    if identity.service_id.method() != "webvh" {
        anyhow::bail!(
            "identity bundle service DID {} is not did:webvh",
            identity.service_id
        );
    }
    let signing_key_ref = identity.active_signing_key_ref.as_str();
    if signing_key_ref.starts_with("secret:") {
        anyhow::bail!(
            "active signing KeyRef {signing_key_ref} is an external secret; the KeyStore export/import drill requires a KeyStore-backed active signing key"
        );
    }
    let signing_key_multibase = bundle
        .identity
        .did_document
        .signing_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("identity bundle DID document has no assertion key"))?;

    Ok(ResolvedServiceIdentity {
        service_id: identity.service_id.to_string(),
        signing_key_ref: signing_key_ref.to_owned(),
        signing_key_multibase: signing_key_multibase.to_owned(),
    })
}

fn validate_seed_binding(
    identity: &ResolvedServiceIdentity,
    seed_bytes: &[u8],
) -> Result<[u8; 32], DrillError> {
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
        DrillError::Assertion(format!(
            "service signing seed must be 32 bytes (got {})",
            seed_bytes.len()
        ))
    })?;
    let actual = arkret_sdk::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
    );
    if actual != identity.signing_key_multibase {
        return Err(DrillError::Assertion(format!(
            "seed under active KeyRef {} does not match the service DID document",
            identity.signing_key_ref
        )));
    }
    Ok(seed)
}

// ── --export-only ───────────────────────────────────────────────────────

fn run_export_only(args: &Args, identity: &ResolvedServiceIdentity) -> Result<(), DrillError> {
    let output = args
        .output
        .as_deref()
        .ok_or_else(|| DrillError::Io("--export-only requires --output".to_owned()))?;
    let key_id = &identity.signing_key_ref;
    let store = arkret_sdk::durable_platform_keystore(SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|e| DrillError::Io(format!("durable KeyStore unavailable: {e}")))?;
    let bytes = store
        .load(&key_id)
        .map_err(|e| DrillError::Io(format!("KeyStore::load({key_id}): {e}")))?;
    validate_seed_binding(identity, &bytes)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let payload = serde_json::json!({
        "schema": "soland-rotate-drill.keystore-snapshot.v1",
        "service_id": identity.service_id,
        "key_id": key_id,
        "seed_b64": b64,
    });
    std::fs::write(output, serde_json::to_string_pretty(&payload).unwrap())
        .map_err(|e| DrillError::Io(format!("write {output}: {e}")))?;
    eprintln!("[rotate-drill] export OK -> {output} (key_id={key_id})");
    Ok(())
}

// ── --import-only ───────────────────────────────────────────────────────

fn run_import_only(args: &Args, identity: &ResolvedServiceIdentity) -> Result<(), DrillError> {
    let input = args
        .input
        .as_deref()
        .ok_or_else(|| DrillError::Io("--import-only requires --input".to_owned()))?;
    let raw =
        std::fs::read_to_string(input).map_err(|e| DrillError::Io(format!("read {input}: {e}")))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| DrillError::Io(format!("parse {input} as JSON: {e}")))?;
    if parsed
        .get("skipped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        eprintln!("[rotate-drill] import skipped — snapshot has skipped=true");
        return Ok(());
    }
    let schema = parsed.get("schema").and_then(|v| v.as_str());
    if schema != Some("soland-rotate-drill.keystore-snapshot.v1") {
        return Err(DrillError::Assertion(format!(
            "snapshot schema is unsupported: {}",
            schema.unwrap_or("<missing>")
        )));
    }
    let snapshot_service_id = parsed
        .get("service_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing service_id".to_owned()))?;
    if snapshot_service_id != identity.service_id {
        return Err(DrillError::Assertion(format!(
            "snapshot service_id {snapshot_service_id} does not match identity bundle {}",
            identity.service_id
        )));
    }
    let snapshot_key_id = parsed
        .get("key_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing key_id".to_owned()))?;
    if snapshot_key_id != identity.signing_key_ref {
        return Err(DrillError::Assertion(format!(
            "snapshot key_id {snapshot_key_id} does not match identity bundle KeyRef {}",
            identity.signing_key_ref
        )));
    }
    let seed_b64 = parsed
        .get("seed_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing seed_b64".to_owned()))?;
    let seed_bytes = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .map_err(|e| DrillError::Io(format!("seed_b64 decode: {e}")))?;
    validate_seed_binding(identity, &seed_bytes)?;
    let key_id = &identity.signing_key_ref;
    let store = arkret_sdk::durable_platform_keystore(SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|e| DrillError::Io(format!("durable KeyStore unavailable: {e}")))?;
    store
        .store(&key_id, &seed_bytes)
        .map_err(|e| DrillError::Io(format!("KeyStore::store({key_id}): {e}")))?;
    eprintln!("[rotate-drill] import OK ({key_id})");
    Ok(())
}

// ── --rotate-drill (default) ────────────────────────────────────────────

async fn run_rotate_drill(
    args: &Args,
    identity: &ResolvedServiceIdentity,
) -> Result<(), DrillError> {
    let target = args.target_url.as_deref().ok_or_else(|| {
        DrillError::Io("rotate-drill requires --target (or SOLAND_PUBLIC_BASE_URL)".to_owned())
    })?;
    let bearer = args.bearer.as_deref().ok_or_else(|| {
        DrillError::Io("rotate-drill requires --bearer (or SOLAND_ADMIN_BEARER)".to_owned())
    })?;
    let realm_id = args.realm_id.as_deref().ok_or_else(|| {
        DrillError::Io(
            "rotate-drill requires --realm-id (the Realm whose notary key is being rotated)"
                .to_owned(),
        )
    })?;

    eprintln!(
        "[rotate-drill] target={target} service_id={}",
        identity.service_id
    );

    // ── 1. snapshot the OLD signing seed from the KeyStore ─────────────
    // This is later compared byte-for-byte after the rejected request.
    let key_id = &identity.signing_key_ref;
    let store = arkret_sdk::durable_platform_keystore(SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|e| DrillError::Io(format!("durable KeyStore unavailable: {e}")))?;
    let old_seed_bytes = store
        .load(&key_id)
        .map_err(|e| DrillError::Io(format!("snapshot old seed: {e}")))?;
    let old_seed = validate_seed_binding(identity, &old_seed_bytes)?;
    let signing_key = SigningKey::from_bytes(&old_seed);
    eprintln!("[rotate-drill] step 1/3: snapshotted active seed (KeyRef only logged)");

    // ── 2. POST the rotate-signing-key endpoint ────────────────────────
    let url = format!(
        "{}/_soland/admin/realms/{}/notary/rotate-signing-key",
        target.trim_end_matches('/'),
        realm_id
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| DrillError::Io(format!("http client: {e}")))?;
    let resp = client
        .post(&url)
        .bearer_auth(bearer)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .map_err(|e| DrillError::Io(format!("POST {url}: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| DrillError::Io(format!("parse rotate response: {e}")))?;
    let wire_code = body
        .pointer("/error/code")
        .and_then(serde_json::Value::as_str);
    if status != reqwest::StatusCode::NOT_IMPLEMENTED || wire_code != Some("unsupported_feature") {
        return Err(DrillError::Assertion(format!(
            "rotate-signing-key must fail closed with 501 unsupported_feature; got {status}: {body}"
        )));
    }
    eprintln!("[rotate-drill] step 2/3: unsafe partial rotation rejected as unsupported_feature");

    // ── 3. verify rejection left key custody untouched ─────────────────
    let current_seed_bytes = store
        .load(&key_id)
        .map_err(|e| DrillError::Io(format!("reload keystore: {e}")))?;
    if current_seed_bytes != old_seed_bytes {
        return Err(DrillError::Assertion(
            "rejected rotation mutated the active KeyStore seed".to_owned(),
        ));
    }
    let probe_bytes = format!(
        "soland-rotate-drill probe v1 ({}) {}",
        identity.service_id,
        chrono::Utc::now().to_rfc3339()
    )
    .into_bytes();
    let probe_sig = signing_key.sign(&probe_bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    verifying_key
        .verify(&probe_bytes, &probe_sig)
        .map_err(|e| {
            DrillError::Assertion(format!(
                "unchanged active key failed its local signing probe: {e}"
            ))
        })?;
    eprintln!("[rotate-drill] step 3/3: active KeyStore seed is unchanged and usable");

    eprintln!("[rotate-drill] PASS — unsafe partial rotation failed closed at {target}");
    Ok(())
}
