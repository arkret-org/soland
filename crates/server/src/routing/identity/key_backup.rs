//! Encrypted key-backup CRUD.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cokret_sdk::{
    BackupClass, BackupId, DeviceId, Did, KEY_BACKUP_DELETE_DEVELOPMENT_PROOF_KIND, KeyBackup,
    KeyBackupDeleteDetachedJwsProof, KeyBackupDeleteProof, KeyBackupRecipientMethod,
    KeysBackupsDeleteRequestBody, KeysBackupsUnlockRequestBody,
};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::append_audit_log;
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{
    AppState, RecoveryPolicyRecord, RecoverySessionRecord, key_backup_daily_download_limit,
};
use crate::wire::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsReplaceOutcome,
};

mod delete;
mod handlers;
mod unlock;
mod validation;

use delete::*;
pub(in crate::routing) use handlers::did_recovery_first_backup_gate_satisfied as did_recovery_first_backup_gate_satisfied_for_actor;
use handlers::*;
use unlock::*;
use validation::*;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("keys/backups/{backup_id}")
                .put(put_key_backup)
                .delete(delete_key_backup),
        )
        .push(Router::with_path("keys/backups/{backup_id}/unlock").post(unlock_key_backup))
        .push(Router::with_path("keys/backups").get(list_key_backups))
}

const KEY_BACKUP_CLASSES: &[&str] = &["did_recovery", "secret_storage", "mls_history"];
const KEY_BACKUP_CONTENT_TYPES: &[&str] = &[
    "recovery_key_share",
    "self_signing_key",
    "user_signing_key",
    "recovery_secret",
    "mls_account_secret",
    "mls_private_plaintext",
    "mls_group_secrets_backup_key",
    "mls_group_state",
    "mls_epoch_secret",
    "pending_welcome",
    "private_account_state",
];
const KEY_BACKUP_AUTH_REQUIRED_SIGNED_FIELDS: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
];
const KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "recovery_session_id",
    "principal_id",
    "requesting_device_id",
    "backup_id",
    "backup_class",
    "series_id",
    "ciphertext_digest",
    "proof_kind",
    "proof_digest",
    "issued_at",
];

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const BACKUP_ID: &str = "ck:backup:01964137-0000-7000-8000-000000000001";
    const DEVICE_ID: &str = "ck:device:01964137-0000-7000-8000-000000000001";

    fn validate_key_backup_body(
        backup_id: &str,
        actor_id: &str,
        body: &Value,
    ) -> Result<(), AppError> {
        let typed_backup_id = BackupId::new(backup_id.to_owned()).map_err(|error| {
            AppError::invalid_param(format!(
                "backup_id must be a ck:backup:<uuidv7> typed id: {error}"
            ))
        })?;
        let backup = typed_key_backup_body(body)?;
        validate_key_backup_body_typed(&typed_backup_id, actor_id, &backup)
    }

    fn typed_key_backup_body(body: &Value) -> Result<KeyBackup, AppError> {
        serde_json::from_value(body.clone()).map_err(|error| {
            schema_error(format!(
                "key backup payload failed SDK type validation: {error}"
            ))
        })
    }

    fn key_backup_body(backup_class: &str, item_type: &str, encryption: Value) -> Value {
        let mut body = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR,
            "device_id": DEVICE_ID,
            "backup_class": backup_class,
            "backup_version": "kb_1",
            "created_at": "2026-05-30T00:00:00Z",
            "series_id": "ck:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "encryption": encryption,
            "contents": [{
                "item_type": item_type,
                "secret_id": "test-secret"
            }],
            "ciphertext": "AAAA",
            "ciphertext_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "domain_separation": {
                "hkdf_info": format!("cokret-key-backup/{backup_class}/test/v1"),
                "subdomain": "test",
                "aead_aad": {
                    "schema": "ck.schema.key_backup.v1",
                    "actor_id": ACTOR,
                    "device_id": DEVICE_ID,
                    "backup_class": backup_class,
                    "backup_version": "kb_1",
                    "created_at": "2026-05-30T00:00:00Z",
                    "item_types": [item_type]
                }
            },
            "auth_data": {
                "device_id": DEVICE_ID,
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "ssk_generation": 1,
                "signed_fields": [
                    "backup_id",
                    "actor_id",
                    "backup_class",
                    "backup_version",
                    "series_id",
                    "series_seq",
                    "encryption",
                    "domain_separation",
                    "contents",
                    "ciphertext_digest"
                ]
            }
        });
        if body["encryption"]["recipient_method"].as_str() == Some("passphrase_kdf") {
            body["encryption"]["key_commitment"] =
                json!("sha256:2222222222222222222222222222222222222222222222222222222222222222");
        }
        body
    }

    fn passphrase_encryption() -> Value {
        json!({
            "recipient_method": "passphrase_kdf",
            "recipient_key_ref": DEVICE_ID,
            "kdf": {
                "name": "argon2id",
                "salt": "salt",
                "params": {
                    "memory_kib": 65_536,
                    "iterations": 3,
                    "parallelism": 1
                }
            },
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ck.aead.xchacha20_poly1305.v1",
                "nonce": "nonce",
                "nonce_salt": "bm9uY2VzYWx0"
            }
        })
    }

    fn secret_storage_key_encryption() -> Value {
        json!({
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "mls_group_secrets_backup_key",
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ck.aead.xchacha20_poly1305.v1",
                "nonce": "nonce"
            }
        })
    }

    fn recovery_public_key_encryption() -> Value {
        json!({
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:web:alice.example#recovery",
            "aead": {
                "name": "chacha20_poly1305",
                "aead_profile": "ck.aead.chacha20_poly1305.v1",
                "enc": "ZW5jYXBzdWxhdGVka2V5"
            }
        })
    }

    #[test]
    fn mls_history_accepts_secret_storage_key() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );

        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("MLS history secret_storage_key backup should validate");
    }

    #[test]
    fn mls_history_accepts_recovery_public_key() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            recovery_public_key_encryption(),
        );

        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("MLS history recovery_public_key (HPKE) backup should validate");
    }

    #[test]
    fn recovery_public_key_requires_enc() {
        let mut enc = recovery_public_key_encryption();
        enc["aead"].as_object_mut().unwrap().remove("enc");
        let body = key_backup_body("secret_storage", "recovery_secret", enc);
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("recovery_public_key without aead.enc must be rejected");
        assert!(err.message.contains("enc"));
    }

    #[test]
    fn did_recovery_rejects_passphrase_kdf() {
        // Spec §5.0.1 first-backup gate: passphrase_kdf-only did_recovery forbidden.
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            passphrase_encryption(),
        );
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf did_recovery must be rejected");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("did_recovery"));
    }

    #[test]
    fn did_recovery_rejects_secret_storage_key() {
        // secret_storage_key is valid only for mls_history / secret_storage.
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            secret_storage_key_encryption(),
        );

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("secret_storage_key is not valid for did_recovery");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("secret_storage_key"));
    }

    // ── C-P5: recovery_policy_ref binding (structural) ──────────────────────

    const POLICY_REF: &str = "ck:policy:01964137-0000-7000-8000-0000000000aa";

    fn did_recovery_signed_fields() -> Value {
        json!([
            "backup_id",
            "actor_id",
            "backup_class",
            "backup_version",
            "series_id",
            "series_seq",
            "supersedes",
            "encryption",
            "domain_separation",
            "contents",
            "ciphertext_digest",
            "recovery_policy_ref"
        ])
    }

    fn did_recovery_auth_data() -> Value {
        json!({
            "device_id": DEVICE_ID,
            "verification_method": "did:web:alice.example#device",
            "signature_algorithm": "Ed25519",
            "signature": "c2lnbmF0dXJl",
            "ssk_generation": 1,
            "signed_fields": did_recovery_signed_fields()
        })
    }

    #[test]
    fn did_recovery_requires_recovery_policy_ref() {
        // Valid HPKE encryption, but no recovery_policy_ref → rejected.
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("did_recovery without recovery_policy_ref must be rejected");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("recovery_policy_ref"));
    }

    #[test]
    fn recovery_policy_ref_must_be_covered_by_signed_fields() {
        let mut body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        body["recovery_policy_ref"] = json!({ "policy_id": POLICY_REF, "policy_version": 1 });
        // signed_fields present but does NOT cover recovery_policy_ref.
        body["auth_data"] = json!({
            "device_id": DEVICE_ID,
            "verification_method": "did:web:alice.example#device",
            "signature_algorithm": "Ed25519",
            "signature": "c2lnbmF0dXJl",
            "ssk_generation": 1,
            "signed_fields": ["backup_id", "encryption"]
        });
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("recovery_policy_ref not covered by signed_fields must be rejected");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("signed_fields"));
    }

    #[test]
    fn did_recovery_with_recovery_policy_ref_validates() {
        let mut body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        body["recovery_policy_ref"] = json!({ "policy_id": POLICY_REF, "policy_version": 1 });
        body["auth_data"] = did_recovery_auth_data();
        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("did_recovery with well-formed signed recovery_policy_ref should validate");
    }

    #[test]
    fn passphrase_kdf_requires_nonce_salt_and_key_commitment() {
        // Drop nonce_salt -> reject.
        let mut enc = passphrase_encryption();
        enc["aead"].as_object_mut().unwrap().remove("nonce_salt");
        let body = key_backup_body("secret_storage", "recovery_secret", enc);
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf without nonce_salt must be rejected");
        assert!(err.message.contains("nonce_salt"));

        // Drop key_commitment -> reject.
        let mut body2 =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body2["encryption"]
            .as_object_mut()
            .unwrap()
            .remove("key_commitment");
        let err2 = validate_key_backup_body(BACKUP_ID, ACTOR, &body2)
            .expect_err("passphrase_kdf without key_commitment must be rejected");
        assert!(err2.message.contains("key_commitment"));
    }

    #[test]
    fn unsupported_recipient_method_is_rejected() {
        let mut encryption = passphrase_encryption();
        encryption["recipient_method"] = json!("unknown_magic_key");
        let body = key_backup_body("secret_storage", "recovery_secret", encryption);

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("unknown recipient methods must not pass schema validation");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("unknown_magic_key"));
    }

    #[test]
    fn passphrase_kdf_still_requires_kdf_metadata() {
        let mut encryption = passphrase_encryption();
        encryption.as_object_mut().unwrap().remove("kdf");
        let body = key_backup_body("secret_storage", "recovery_secret", encryption);

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf without kdf metadata is invalid");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("encryption.kdf"));
    }

    #[test]
    fn mls_history_rejects_passphrase_kdf() {
        let body = key_backup_body("mls_history", "mls_group_state", passphrase_encryption());

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("MLS history passphrase KDF backups are no longer supported");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("secret_storage_key"));
    }

    #[test]
    fn mls_history_rejects_plaintext_fields() {
        let mut body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );
        body["plaintext"] = json!("raw group state");

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("soland must store only opaque MLS backup ciphertext");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("plaintext"));
    }

    #[test]
    fn duplicate_backup_id_rejects_cross_actor_overwrite() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": "did:web:bob.example"
        });

        let err = key_backup_duplicate_for_actor(Some(&existing), ACTOR)
            .expect_err("other actor must not overwrite backup_id");

        assert_eq!(err.code, ErrorCode::CapabilityDenied);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
    }

    #[test]
    fn duplicate_backup_id_accepts_same_actor_retry() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR
        });

        let duplicate = key_backup_duplicate_for_actor(Some(&existing), ACTOR)
            .expect("same actor idempotent retry is allowed");

        assert!(duplicate);
    }

    #[test]
    fn delete_dev_proof_binds_actor_and_backup_id_exactly() {
        let proof = format!("dev-ssk-delete:v1:{ACTOR}:{BACKUP_ID}");

        assert!(is_development_delete_proof(&proof, BACKUP_ID, ACTOR));
        assert!(!is_development_delete_proof(
            &proof,
            BACKUP_ID,
            "did:web:bob.example"
        ));
        assert!(!is_development_delete_proof(
            &proof,
            "ck:backup:01964137-0000-7000-8000-000000000099",
            ACTOR
        ));
    }

    #[test]
    fn delete_jws_proof_transcript_is_stable() {
        let canonical = key_backup_delete_proof_canonical_bytes(ACTOR, BACKUP_ID)
            .expect("canonical delete proof transcript");
        let value: Value = serde_json::from_slice(&canonical).expect("canonical JSON");

        assert_eq!(value["kind"], "ck.key_backup.delete_proof.v1");
        assert_eq!(value["actor_id"], ACTOR);
        assert_eq!(value["backup_id"], BACKUP_ID);
        assert_eq!(
            cokret_sdk::canonical::sha256_digest(&canonical),
            "sha256:beb1dc1e9867b7414b8ee5a9102dabbda11f0bb5872a867876a568c2e480cc36"
        );
    }

    fn active_policy(policy_id: &str, version: u32) -> RecoveryPolicyRecord {
        let now = chrono::Utc::now();
        RecoveryPolicyRecord {
            policy_id: policy_id.to_owned(),
            principal_id: ACTOR.to_owned(),
            version,
            trust_domain: "https://local.host".to_owned(),
            allowed_proof_kinds: vec!["recovery_key".to_owned()],
            supersedes: None,
            expires_at: None,
            issued_at: now,
            raw_payload: json!({}),
            accepted_at: now,
            verification_method: format!("{ACTOR}#device"),
        }
    }

    fn did_recovery_delete_candidate(policy_id: &str, policy_version: u64) -> Value {
        let mut body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        body["recovery_policy_ref"] =
            json!({ "policy_id": policy_id, "policy_version": policy_version });
        body["auth_data"] = did_recovery_auth_data();
        body
    }

    #[test]
    fn delete_rejects_current_policy_did_recovery_backup() {
        let policy = active_policy(POLICY_REF, 1);
        let body = did_recovery_delete_candidate(POLICY_REF, 1);

        let err = ensure_key_backup_delete_is_retired_or_redundant(&body, Some(&policy))
            .expect_err("current did_recovery backup must be protected");

        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("key_backup_delete_not_retired")
        );
    }

    #[test]
    fn delete_allows_stale_policy_bound_backup() {
        let policy = active_policy("ck:policy:01964137-0000-7000-8000-0000000000bb", 2);
        let body = did_recovery_delete_candidate(POLICY_REF, 1);

        ensure_key_backup_delete_is_retired_or_redundant(&body, Some(&policy))
            .expect("non-active policy backup is provably stale");
    }

    #[test]
    fn delete_rejects_unclassified_mls_history_tail() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );

        let err = ensure_key_backup_delete_is_retired_or_redundant(&body, None)
            .expect_err("server cannot prove this mls_history backup is useless");

        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("key_backup_delete_not_retired")
        );
    }

    #[test]
    fn delete_allows_retention_expired_backup() {
        let mut body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );
        body["retention"] = json!({
            "delete_after": "2020-01-01T00:00:00Z",
            "legal_hold": false
        });

        ensure_key_backup_delete_is_retired_or_redundant(&body, None)
            .expect("expired non-held backup may be deleted");
    }

    #[test]
    fn delete_rejects_non_tail_even_when_policy_stale() {
        let older = did_recovery_delete_candidate(POLICY_REF, 1);
        let mut newer = older.clone();
        newer["backup_id"] = json!("ck:backup:01964137-0000-7000-8000-000000000099");
        newer["series_seq"] = json!(1);
        newer["supersedes"] = older["backup_id"].clone();
        newer["supersedes_digest"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let owned = vec![older.clone(), newer];
        let err = ensure_key_backup_delete_is_series_tail(ACTOR, &older, &owned)
            .expect_err("non-tail chain link must not be individually deleted");

        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("failed_precondition")
        );
    }

    // ── §7.6 genesis-envelope shape ──────────────────────────────────────

    #[test]
    fn genesis_envelope_rejects_supersedes() {
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes"] = json!("ck:backup:01964137-0000-7000-8000-0000000000ff");

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        let err = validate_series_genesis_shape_typed(&backup)
            .expect_err("genesis envelope carrying `supersedes` must be series_chain_broken");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("series_chain_broken")
        );
        assert!(err.message.contains("`supersedes`"));
    }

    #[test]
    fn genesis_envelope_rejects_supersedes_digest() {
        // Spec key-management.md §7.6 — genesis MUST NOT carry
        // `supersedes_digest` even when `supersedes` itself is absent.
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes_digest"] =
            json!("sha256:3333333333333333333333333333333333333333333333333333333333333333");

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        let err = validate_series_genesis_shape_typed(&backup).expect_err(
            "genesis envelope carrying `supersedes_digest` must be series_chain_broken",
        );
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("series_chain_broken")
        );
        assert!(err.message.contains("supersedes_digest"));
    }

    #[test]
    fn genesis_envelope_tolerates_null_predecessor_fields() {
        // Spec §7.6 phrases genesis as `supersedes == null`; an explicit
        // JSON null is equivalent to absence, not a chain claim.
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes"] = Value::Null;
        body["supersedes_digest"] = Value::Null;

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        validate_series_genesis_shape_typed(&backup)
            .expect("explicit null predecessor fields are equivalent to absence");
    }

    // ── §7.8 download-quota clamp ────────────────────────────────────────

    #[test]
    fn download_limit_defaults_and_clamps_to_spec_range() {
        use crate::state::{
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT, KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
        };

        // Unset → spec default (64).
        assert_eq!(
            crate::state::clamp_key_backup_daily_download_limit(None),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT
        );
        // In-range values are honored as-is.
        assert_eq!(
            crate::state::clamp_key_backup_daily_download_limit(Some(100)),
            100
        );
        // Outside the spec-allowed [16, 256] range the value is clamped —
        // §7.8 forbids relaxing past the ceiling, and a sub-floor value
        // would break a single legitimate long-series restore.
        assert_eq!(
            crate::state::clamp_key_backup_daily_download_limit(Some(1)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN
        );
        assert_eq!(
            crate::state::clamp_key_backup_daily_download_limit(Some(100_000)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX
        );
    }

    #[test]
    fn list_metadata_redacts_ciphertext_and_kdf_material() {
        let metadata = key_backup_metadata_for_list(key_backup_body(
            "secret_storage",
            "recovery_secret",
            passphrase_encryption(),
        ));

        assert!(metadata.get("ciphertext").is_none());
        assert!(metadata.pointer("/encryption/key_commitment").is_none());
        assert_eq!(
            metadata["encryption"]["recipient_method"],
            json!("passphrase_kdf")
        );
        assert!(metadata.pointer("/encryption/kdf").is_none());
        assert!(metadata.pointer("/encryption/aead").is_none());
        assert!(metadata.pointer("/auth_data/signature").is_none());
    }
}
