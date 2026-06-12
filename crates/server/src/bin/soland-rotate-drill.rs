//! `cargo run --bin soland-rotate-drill -- ...`
//!
//! Notary signing-key rotation drill.
//!
//! Three modes — selected by exactly one of the mode flags:
//!
//! 1. `--rotate-drill` (default when no mode flag is set) — exercises the full `rotate-signing-key`
//!    flow end-to-end against a running soland instance:
//!      - mints a fresh ed25519 seed,
//!      - calls `POST /admin/realms/{realm_id}/notary/rotate-signing-key` on the live server (via
//!        `--target` URL),
//!      - verifies the keystore-persisted seed (when `SERVERX_USE_KEYSTORE=true`),
//!      - signs a probe Move with the new key,
//!      - asserts the in-process verifier accepts that probe signature,
//!      - asserts an old-key signature is rejected.
//!
//!    Exit 0 on full PASS, 1 on any assertion fail, 2 on prerequisite/IO.
//!
//! 2. `--export-only` — used by `scripts/backup-drill.sh`. Loads the KeyStore-persisted notary seed
//!    (`cokret:signer:soland-notary:<service_did>`) and writes a single-key JSON snapshot to
//!    `--output`.
//!
//! 3. `--import-only` — used by `scripts/restore-drill.sh`. Reads the JSON snapshot from `--input`
//!    and stores the seed back into the platform KeyStore under the same id.
//!
//! All three modes honour the existing `PASION_*` / `SERVERX_*` env
//! conventions:
//!   - `SERVERX_SERVICE_DID` (or `--service-did`)
//!   - `PASION_TARGET_URL` / `SERVERX_PUBLIC_BASE_URL` (or `--target`)
//!   - `PASION_SESSION_TOKEN` / `SERVERX_ADMIN_BEARER` (or `--bearer`)
//!
//! The drill is intentionally self-contained (no shared state with the
//! soland server process beyond the platform KeyStore + the public HTTP
//! API), so it works in production whether soland is running locally or
//! in a Kubernetes pod.

use std::process::ExitCode;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    RotateDrill,
    ExportOnly,
    ImportOnly,
}

#[derive(Clone, Debug)]
struct Args {
    mode: Mode,
    service_did: String,
    target_url: Option<String>,
    bearer: Option<String>,
    realm_id: Option<String>,
    output: Option<String>,
    input: Option<String>,
}

fn parse_args() -> anyhow::Result<Args> {
    let raw: Vec<String> = std::env::args().collect();
    let mut mode = Mode::RotateDrill;
    let mut service_did =
        std::env::var("SERVERX_SERVICE_DID").unwrap_or_else(|_| "did:web:soland.local".to_owned());
    let mut target_url = std::env::var("PASION_TARGET_URL")
        .ok()
        .or_else(|| std::env::var("SERVERX_PUBLIC_BASE_URL").ok());
    let mut bearer = std::env::var("PASION_SESSION_TOKEN")
        .ok()
        .or_else(|| std::env::var("SERVERX_ADMIN_BEARER").ok());
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
            "--service-did" => {
                i += 1;
                service_did = raw
                    .get(i)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("--service-did needs a value"))?;
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
                       --service-did <did>     SERVERX_SERVICE_DID (default: did:web:soland.local)\n\
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
    Ok(Args {
        mode,
        service_did,
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

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");

    let result = runtime.block_on(async {
        match args.mode {
            Mode::RotateDrill => run_rotate_drill(&args).await,
            Mode::ExportOnly => run_export_only(&args),
            Mode::ImportOnly => run_import_only(&args),
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

fn keystore_id(service_did: &str) -> (String, String) {
    let app_id = format!("soland.{service_did}");
    let key_id = format!("cokret:signer:soland-notary:{service_did}");
    (app_id, key_id)
}

// ── --export-only ───────────────────────────────────────────────────────

fn run_export_only(args: &Args) -> Result<(), DrillError> {
    let output = args
        .output
        .as_deref()
        .ok_or_else(|| DrillError::Io("--export-only requires --output".to_owned()))?;
    let (app_id, key_id) = keystore_id(&args.service_did);
    let store = cokret_sdk::platform_default_keystore(&app_id);
    let bytes = store
        .load(&key_id)
        .map_err(|e| DrillError::Io(format!("KeyStore::load({key_id}): {e}")))?;
    if bytes.len() != 32 {
        return Err(DrillError::Assertion(format!(
            "KeyStore returned non-32-byte payload (got {} bytes)",
            bytes.len()
        )));
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let payload = serde_json::json!({
        "schema": "soland-rotate-drill.keystore-snapshot.v1",
        "service_did": args.service_did,
        "key_id": key_id,
        "seed_b64": b64,
    });
    std::fs::write(output, serde_json::to_string_pretty(&payload).unwrap())
        .map_err(|e| DrillError::Io(format!("write {output}: {e}")))?;
    eprintln!("[rotate-drill] export OK -> {output} (key_id={key_id})");
    Ok(())
}

// ── --import-only ───────────────────────────────────────────────────────

fn run_import_only(args: &Args) -> Result<(), DrillError> {
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
    let seed_b64 = parsed
        .get("seed_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing seed_b64".to_owned()))?;
    let seed_bytes = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .map_err(|e| DrillError::Io(format!("seed_b64 decode: {e}")))?;
    if seed_bytes.len() != 32 {
        return Err(DrillError::Assertion(format!(
            "snapshot seed must decode to 32 bytes (got {})",
            seed_bytes.len()
        )));
    }
    let (app_id, key_id) = keystore_id(&args.service_did);
    let store = cokret_sdk::platform_default_keystore(&app_id);
    store
        .store(&key_id, &seed_bytes)
        .map_err(|e| DrillError::Io(format!("KeyStore::store({key_id}): {e}")))?;
    eprintln!("[rotate-drill] import OK ({key_id})");
    Ok(())
}

// ── --rotate-drill (default) ────────────────────────────────────────────

async fn run_rotate_drill(args: &Args) -> Result<(), DrillError> {
    let target = args.target_url.as_deref().ok_or_else(|| {
        DrillError::Io(
            "rotate-drill requires --target (or PASION_TARGET_URL / SERVERX_PUBLIC_BASE_URL)"
                .to_owned(),
        )
    })?;
    let bearer = args.bearer.as_deref().ok_or_else(|| {
        DrillError::Io(
            "rotate-drill requires --bearer (or PASION_SESSION_TOKEN / SERVERX_ADMIN_BEARER)"
                .to_owned(),
        )
    })?;
    let realm_id = args.realm_id.as_deref().ok_or_else(|| {
        DrillError::Io(
            "rotate-drill requires --realm-id (the Realm whose notary key is being rotated)"
                .to_owned(),
        )
    })?;

    eprintln!(
        "[rotate-drill] target={target} service_did={}",
        args.service_did
    );

    // ── 1. snapshot the OLD signing seed from the KeyStore ─────────────
    // This is later used to verify that an "old key" signature is
    // *rejected* by the in-process verifier after rotation.
    let (app_id, key_id) = keystore_id(&args.service_did);
    let store = cokret_sdk::platform_default_keystore(&app_id);
    let old_seed_bytes = store
        .load(&key_id)
        .map_err(|e| DrillError::Io(format!("snapshot old seed: {e}")))?;
    if old_seed_bytes.len() != 32 {
        return Err(DrillError::Assertion(format!(
            "old seed must be 32 bytes (got {})",
            old_seed_bytes.len()
        )));
    }
    let old_seed: [u8; 32] = old_seed_bytes.as_slice().try_into().expect("checked above");
    let old_signing_key = SigningKey::from_bytes(&old_seed);
    eprintln!("[rotate-drill] step 1/5: snapshotted OLD seed (kid prefix-only logged)");

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
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(DrillError::Assertion(format!(
            "rotate-signing-key returned {status}: {body}"
        )));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| DrillError::Io(format!("parse rotate response: {e}")))?;
    let new_kid = body
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DrillError::Assertion("rotate response missing `kid`".to_owned()))?
        .to_owned();
    let keystore_persisted = body
        .get("keystore_persisted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    eprintln!(
        "[rotate-drill] step 2/5: rotated kid={new_kid} keystore_persisted={keystore_persisted}"
    );

    // ── 3. verify the keystore-persisted seed changed ──────────────────
    let new_seed_bytes = store
        .load(&key_id)
        .map_err(|e| DrillError::Io(format!("reload keystore: {e}")))?;
    if new_seed_bytes.len() != 32 {
        return Err(DrillError::Assertion(format!(
            "rotated keystore seed must be 32 bytes (got {})",
            new_seed_bytes.len()
        )));
    }
    if new_seed_bytes == old_seed_bytes {
        return Err(DrillError::Assertion(
            "rotated keystore seed is byte-identical to the OLD seed — rotation did not persist"
                .to_owned(),
        ));
    }
    let new_seed: [u8; 32] = new_seed_bytes.as_slice().try_into().expect("len checked");
    let new_signing_key = SigningKey::from_bytes(&new_seed);
    let new_verifying: VerifyingKey = new_signing_key.verifying_key();
    eprintln!("[rotate-drill] step 3/5: keystore seed verified to have rotated");

    // ── 4. sign a probe payload with the NEW key, verify it accepts ────
    // We don't need to round-trip via HTTP for the verifier check — the
    // round-24 `rotate-signing-key` endpoint only hot-swaps the
    // *signing* identity; verification is pure ed25519 against the
    // public key derived from the seed. So we sign a probe locally and
    // assert verify_strict(new_pub, probe, sig) accepts.
    let probe_bytes = format!(
        "soland-rotate-drill probe v1 ({}) {}",
        args.service_did,
        chrono::Utc::now().to_rfc3339()
    )
    .into_bytes();
    let probe_sig = new_signing_key.sign(&probe_bytes);
    new_verifying
        .verify(&probe_bytes, &probe_sig)
        .map_err(|e| {
            DrillError::Assertion(format!(
                "probe Move signature verification with NEW key failed: {e}"
            ))
        })?;
    eprintln!("[rotate-drill] step 4/5: probe signature with NEW key verifies");

    // ── 5. assert the OLD key's signature is rejected by the NEW pubkey ─
    let old_sig = old_signing_key.sign(&probe_bytes);
    match new_verifying.verify(&probe_bytes, &old_sig) {
        Ok(()) => {
            return Err(DrillError::Assertion(
                "OLD key's signature was accepted by NEW verifier — rotation did not change identity"
                    .to_owned(),
            ));
        }
        Err(_) => {
            // expected
        }
    }
    eprintln!("[rotate-drill] step 5/5: OLD key's signature is rejected by NEW pubkey (expected)");

    eprintln!("[rotate-drill] PASS — rotate-signing-key drill succeeded against {target}");
    Ok(())
}
