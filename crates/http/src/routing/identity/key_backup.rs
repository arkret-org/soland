//! Encrypted key-backup CRUD.

use arkret_identifiers::{BackupId, EventId};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupKdfName, KeyBackupRecipientMethod, KeyBackupUnlockProof,
    KeysBackupsDeleteRequestBody, KeysBackupsUnlockRequestBody,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};

use super::append_audit_log;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsReplaceOutcome,
};

mod delete;
mod handlers;
mod unlock;
mod validation;

use delete::*;
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
        .push(
            // key-management.md §7.8.1 step 1: the server mints every freshness
            // value for a high-risk delete. Without this endpoint the DELETE
            // below has nothing valid to consume.
            Router::with_path("keys/backups/{backup_id}/delete-challenge")
                .post(issue_key_backup_delete_challenge),
        )
        .push(Router::with_path("keys/backups/{backup_id}/unlock").post(unlock_key_backup))
        .push(Router::with_path("keys/backups").get(list_key_backups))
        .push(
            Router::with_path("keys/backup-series/erase")
                .post(super::recovery::backup_series_erase_command),
        )
}

pub(crate) fn admin_router() -> Router {
    Router::with_path("key-backups").get(list_key_backups_admin)
}

const KEY_BACKUP_CLASSES: &[&str] = &["secret_storage", "mls_history"];
const KEY_BACKUP_CONTENT_TYPES: &[&str] = &[
    "recovery_key_share",
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
    "backup_kind",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
];
#[cfg(test)]
mod tests {
    use arkret_identifiers::DidCoreId;
    use serde_json::json;

    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-000000000001";
    const DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

    fn validate_key_backup_body(
        backup_id: &str,
        actor_id: &str,
        body: &Value,
    ) -> Result<(), AppError> {
        let typed_backup_id = BackupId::new(backup_id.to_owned()).map_err(|error| {
            AppError::param_invalid(format!(
                "backup_id must be a ak:backup:<uuidv7> typed id: {error}"
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

    fn key_backup_body(backup_kind: &str, item_kind: &str, encryption: Value) -> Value {
        let recipient_method = encryption["recipient_method"].clone();
        let recipient_key_ref = encryption
            .get("recipient_key_ref")
            .cloned()
            .unwrap_or(Value::Null);
        let mut body = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR,
            "device_id": DEVICE_ID,
            "backup_kind": backup_kind,
            "backup_version": "kb_1",
            "created_at": "2026-05-30T00:00:00.000Z",
            "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "encryption": encryption,
            "contents": [{
                "item_kind": item_kind,
                "secret_id": "test-secret"
            }],
            "ciphertext": "AAAA",
            "ciphertext_digest": "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c",
            "domain_separation": {
                "hkdf_info": format!("arkret-key-backup/{backup_kind}/test/v1"),
                "subdomain": "test",
                "aead_aad": {
                    "schema": "ak.schema.key_backup.v1",
                    "actor_id": ACTOR,
                    "device_id": DEVICE_ID,
                    "backup_kind": backup_kind,
                    "backup_version": "kb_1",
                    "created_at": "2026-05-30T00:00:00.000Z",
                    "item_kinds": [item_kind],
                    "recipient_method": recipient_method,
                    "recipient_key_ref": recipient_key_ref
                }
            },
            "auth_data": {
                "device_id": DEVICE_ID,
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "device_authorize_event_id": "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD",
                "signed_fields": [
                    "backup_id",
                    "actor_id",
                    "backup_kind",
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
                "aead_profile": "ak.aead.xchacha20_poly1305.v1",
                "nonce": "nonce",
                "nonce_salt": "bm9uY2Vfc2FsdF9maXh0dXJl"
            }
        })
    }

    fn secret_storage_key_encryption() -> Value {
        json!({
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "mls_group_secrets_backup_key",
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ak.aead.xchacha20_poly1305.v1",
                "nonce": "nonce"
            }
        })
    }

    fn recovery_public_key_encryption() -> Value {
        json!({
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:web:alice.example#recovery",
            "aead": {
                // Absent hpke_suite selector denotes the v1 default-MUST HPKE suite
                // ak.hpke_x25519_aead_chacha20poly1305.v1, whose AEAD is chacha20_poly1305.
                "name": "chacha20_poly1305",
                "aead_profile": "ak.aead.chacha20_poly1305.v1",
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
    fn auth_data_rejects_missing_device_trust_anchor() {
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["auth_data"]
            .as_object_mut()
            .unwrap()
            .remove("device_authorize_event_id");

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("key backup auth_data must have a device trust anchor");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("device_authorize_event_id"));
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
        // The SDK encryption type validation gate fires first and rejects the
        // missing kdf ("passphrase_kdf requires `kdf`") before soland's domain check.
        assert!(err.message.contains("kdf"));
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
    }

    #[test]
    fn duplicate_backup_id_rejects_cross_actor_overwrite() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": "did:web:bob.example"
        });

        let err = key_backup_idempotent_retry(Some(&existing), ACTOR, &existing)
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

        let duplicate = key_backup_idempotent_retry(Some(&existing), ACTOR, &existing)
            .expect("same actor idempotent retry is allowed");

        assert!(duplicate);
    }

    #[test]
    fn duplicate_backup_id_rejects_different_content() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR,
            "ciphertext": "first"
        });
        let incoming = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR,
            "ciphertext": "second"
        });

        let err = key_backup_idempotent_retry(Some(&existing), ACTOR, &incoming)
            .expect_err("same id with different content must conflict");

        assert_eq!(err.code, ErrorCode::DuplicateConflict);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
    }

    fn delete_challenge_fixture() -> arkret_models_crypto::KeysBackupsDeleteChallenge {
        arkret_models_crypto::KeysBackupsDeleteChallenge {
            challenge_id: arkret_wire::Base64UrlString::new("Y2hhbGxlbmdlLWlk").unwrap(),
            challenge: arkret_wire::Base64UrlString::new("Y2hhbGxlbmdlLWJ5dGVz").unwrap(),
            nonce: arkret_wire::Base64UrlString::new("bm9uY2UtYnl0ZXM").unwrap(),
            operation: "ak.self.keys.backups.resource.delete".to_owned(),
            principal_id: DidCoreId::new(ACTOR.to_owned()).unwrap(),
            backup_id: BackupId::new(BACKUP_ID.to_owned()).unwrap(),
            audience: arkret_wire::NonEmptyString::new("https://soland.test").unwrap(),
            service_id: DidCoreId::new("ak:did_core:web:soland.test".to_owned()).unwrap(),
            request_id: arkret_wire::Base64UrlString::new("cmVxdWVzdC1pZA").unwrap(),
            issued_at: "2026-08-01T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-08-01T00:05:00.000Z".parse().unwrap(),
        }
    }

    /// §7.8.1 step 2: the transcript's key set is fixed, and an absent `reason`
    /// is encoded as JSON `null` rather than omitted.
    ///
    /// Omitting the key would make "no reason given" and "reason tampered away"
    /// produce different bytes on different implementations — which is exactly
    /// the kind of divergence the canonical form exists to prevent.
    #[test]
    fn delete_intent_transcript_has_the_fixed_key_set_and_null_reason() {
        let transcript = delete_challenge_fixture().delete_intent_transcript(None);
        let object = transcript.as_object().expect("transcript is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "audience",
                "backup_id",
                "challenge",
                "challenge_id",
                "context",
                "expires_at",
                "issued_at",
                "nonce",
                "operation",
                "principal_id",
                "reason",
                "request_id",
                "service_id",
            ]
        );
        assert_eq!(object["context"], "ak.keys.backup_delete.v1");
        assert_eq!(object["operation"], "ak.self.keys.backups.resource.delete");
        assert!(
            object["reason"].is_null(),
            "an absent reason MUST be encoded as JSON null, not omitted"
        );
    }

    /// §7.8.1 step 5: tampering with any transcript field MUST make signature
    /// verification fail. The digest is what the signature covers, so this
    /// states that property at the digest.
    #[test]
    fn tampering_any_transcript_field_changes_the_delete_intent_digest() {
        let base = delete_challenge_fixture();
        let baseline = base.delete_intent_digest(None).expect("digest");

        // `reason` is signed, so adding one moves the digest.
        assert_ne!(
            baseline,
            base.delete_intent_digest(Some("device lost"))
                .expect("digest")
        );

        let mut tampered_backup = base.clone();
        tampered_backup.backup_id =
            BackupId::new("ak:backup:01964137-0000-7000-8000-000000000099".to_owned()).unwrap();
        assert_ne!(
            baseline,
            tampered_backup.delete_intent_digest(None).unwrap()
        );

        let mut tampered_audience = base.clone();
        tampered_audience.audience = arkret_wire::NonEmptyString::new("https://evil.test").unwrap();
        assert_ne!(
            baseline,
            tampered_audience.delete_intent_digest(None).unwrap()
        );

        let mut tampered_nonce = base.clone();
        tampered_nonce.nonce = arkret_wire::Base64UrlString::new("b3RoZXItbm9uY2U").unwrap();
        assert_ne!(baseline, tampered_nonce.delete_intent_digest(None).unwrap());

        let mut tampered_service = base.clone();
        tampered_service.service_id =
            DidCoreId::new("ak:did_core:web:other.test".to_owned()).unwrap();
        assert_ne!(
            baseline,
            tampered_service.delete_intent_digest(None).unwrap()
        );

        // The freshness window is signed too, so a replayed challenge cannot be
        // re-dated into a fresh one.
        let mut tampered_window = base;
        tampered_window.expires_at = "2026-08-01T01:00:00.000Z".parse().unwrap();
        assert_ne!(
            baseline,
            tampered_window.delete_intent_digest(None).unwrap()
        );
    }

    // ── §7.6 genesis-envelope shape ──────────────────────────────────────

    #[test]
    fn genesis_envelope_rejects_supersedes() {
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes"] = json!("ak:backup:01964137-0000-7000-8000-0000000000ff");

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
        use soland_services::runtime_guards::{
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT, KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
        };

        // Unset → spec default (64).
        assert_eq!(
            soland_services::runtime_guards::clamp_key_backup_daily_download_limit(None),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT
        );
        // In-range values are honored as-is.
        assert_eq!(
            soland_services::runtime_guards::clamp_key_backup_daily_download_limit(Some(100)),
            100
        );
        // Outside the spec-allowed [16, 256] range the value is clamped —
        // §7.8 forbids relaxing past the ceiling, and a sub-floor value
        // would break a single legitimate long-series restore.
        assert_eq!(
            soland_services::runtime_guards::clamp_key_backup_daily_download_limit(Some(1)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN
        );
        assert_eq!(
            soland_services::runtime_guards::clamp_key_backup_daily_download_limit(Some(100_000)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX
        );
    }

    #[test]
    fn list_metadata_redacts_ciphertext_and_kdf_material() {
        let metadata = serde_json::to_value(
            key_backup_summary_for_list(key_backup_body(
                "secret_storage",
                "private_account_state",
                passphrase_encryption(),
            ))
            .unwrap(),
        )
        .unwrap();

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
