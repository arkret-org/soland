use arkret_crypto::account_data_crypto::AccountDataEncryptedValue;
use arkret_identifiers::{Did, RealmId};
use serde_json::{Map, Value};

const ACCOUNT_DATA_TYPE_AGENT_DRAFT: &str = "ak.agent.draft.v1";
const ACCOUNT_DATA_TYPE_AGENT_PARTICIPATION: &str = "ak.agent.participation.v1";
const ACCOUNT_DATA_TYPE_BLOCKLIST: &str = "ak.account.blocklist";
const ACCOUNT_DATA_TYPE_CLIENT_UI_STATE: &str = "ak.client.ui_state";
const ACCOUNT_DATA_TYPE_COLLECTIONS_STICKERS: &str = "ak.collections.stickers";
const ACCOUNT_DATA_TYPE_DND_SCHEDULE: &str = "ak.dnd_schedule";
const ACCOUNT_DATA_TYPE_INVITE_QUARANTINE: &str = "ak.account.invite_quarantine";
const ACCOUNT_DATA_TYPE_PRESENCE_PREFERENCE: &str = "ak.presence.preference";
const ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY: &str = "ak.presence.visibility";
const ACCOUNT_DATA_TYPE_PUSH_RULES: &str = "ak.push_rules";
const ACCOUNT_DATA_TYPE_READ_RECEIPT_PREFERENCES: &str = "ak.read_receipt.preferences";
const ACCOUNT_DATA_TYPE_TAGS_REALM: &str = "ak.tags.realm";

const EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS: &[&str] = &[
    ACCOUNT_DATA_TYPE_BLOCKLIST,
    ACCOUNT_DATA_TYPE_CLIENT_UI_STATE,
    ACCOUNT_DATA_TYPE_COLLECTIONS_STICKERS,
    ACCOUNT_DATA_TYPE_DND_SCHEDULE,
    ACCOUNT_DATA_TYPE_INVITE_QUARANTINE,
    ACCOUNT_DATA_TYPE_PRESENCE_PREFERENCE,
    ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY,
    ACCOUNT_DATA_TYPE_PUSH_RULES,
    ACCOUNT_DATA_TYPE_READ_RECEIPT_PREFERENCES,
];

const SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    arkret_wire::constants::ACCOUNT_DATA_TYPE_CONTACTS_ACTOR,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_CONTACTS_REALM,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_REMINDER,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_SNOOZE,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_SAVED,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_DRAFT,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
];

// `ak.agent.sidecar_projection.v1` is intentionally absent: the exchange
// projection is a controller-device-local fold cache and never registers an
// account-data key surface (zh/models/sidecar.md §7.2.4).
const AGENT_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    ACCOUNT_DATA_TYPE_AGENT_DRAFT,
    arkret_wire::constants::ACCOUNT_DATA_TYPE_AGENT_SIDECAR_VIEW_STATE,
    ACCOUNT_DATA_TYPE_AGENT_PARTICIPATION,
];

/// Account-data key prefixes that were removed from the registry and MUST stay
/// hard-rejected. Without this guard a retired prefix falls through to the
/// permissive unregistered-key fallback at the end of
/// [`validate_encrypted_account_data_key`], silently reopening the key space
/// to every session (fail-open). `ak.agent.sidecar_projection.v1` was retired
/// on 2026-07-23: the exchange projection is a controller-device-local
/// Event-fold cache and never an account-data surface (zh/models/sidecar.md
/// §7.2.4, forbidden-wire-fields.json `sidecar_exchange_binding`).
const RETIRED_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &["ak.agent.sidecar_projection.v1"];

/// True when `data_type` is a retired private account-data key (bare prefix or
/// prefix with a `:`-delimited tail). Retired keys are rejected on write /
/// read / delete, and legacy stored rows remain controller-private so agent
/// sessions never observe them.
pub(crate) fn is_retired_encrypted_account_data_key(data_type: &str) -> bool {
    RETIRED_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .any(|prefix| {
            data_type
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
}

const FORBIDDEN_PLAINTEXT_FIELDS: &[&str] = &[
    "body",
    "target_ref",
    "collection_title",
    "note",
    "message_payload",
    "content",
    "blind_tokens",
    "shard_key",
    "transfer_id",
    "blob_ref",
    "filename",
    "media_type",
    "plaintext_size_bytes",
    "content_digest",
    "recipient_device_ids",
    "content_key",
    "local_path",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountDataEncryptionError {
    InvalidKeyPattern,
    ValueMustBeObject,
    PlaintextField,
    MissingEncryptedCarrier,
    InvalidEnvelopeMetadata,
}

impl AccountDataEncryptionError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::InvalidKeyPattern => {
                "account_data.set key must use registered private key pattern"
            }
            Self::ValueMustBeObject => {
                "private account_data content must be an encrypted envelope object"
            }
            Self::PlaintextField => "private account_data content must not expose plaintext fields",
            Self::MissingEncryptedCarrier => {
                "private account_data content requires encrypted envelope metadata"
            }
            Self::InvalidEnvelopeMetadata => {
                "private account_data encrypted envelope metadata is invalid"
            }
        }
    }
}

pub(crate) fn encrypted_account_data_prefix(data_type: &str) -> Option<&'static str> {
    if let Some(key) = EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS
        .iter()
        .copied()
        .find(|key| data_type == *key)
    {
        return Some(key);
    }
    if data_type
        .strip_prefix(ACCOUNT_DATA_TYPE_TAGS_REALM)
        .is_some_and(|rest| rest.starts_with('.'))
    {
        return Some(ACCOUNT_DATA_TYPE_TAGS_REALM);
    }
    if let Some(prefix) = SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .copied()
        .find(|prefix| {
            data_type
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with(':'))
        })
    {
        return Some(prefix);
    }
    AGENT_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .copied()
        .find(|prefix| {
            data_type
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
}

pub(crate) fn validate_encrypted_account_data_key(
    data_type: &str,
) -> Result<(), AccountDataEncryptionError> {
    // Retired prefixes are hard-rejected before any other rule so they can
    // never reach the unregistered-key fallback below (fail closed for new
    // writes, reads, and deletes alike).
    if is_retired_encrypted_account_data_key(data_type) {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    if EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS.contains(&data_type) {
        return Ok(());
    }
    if data_type
        .strip_prefix(ACCOUNT_DATA_TYPE_BLOCKLIST)
        .is_some_and(|rest| rest.starts_with('.'))
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(realm_id) = data_type.strip_prefix("ak.tags.realm.") {
        return RealmId::new(realm_id.to_owned())
            .map(|_| ())
            .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern);
    }
    if SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .any(|prefix| {
            data_type
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with(':'))
        })
    {
        return arkret_models_collaboration::objects::productivity::validate_private_account_data_key(data_type)
            .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(rest) = data_type
        .strip_prefix(ACCOUNT_DATA_TYPE_AGENT_DRAFT)
        .or_else(|| {
            data_type
                .strip_prefix(arkret_wire::constants::ACCOUNT_DATA_TYPE_AGENT_SIDECAR_VIEW_STATE)
        })
        .or_else(|| data_type.strip_prefix(ACCOUNT_DATA_TYPE_AGENT_PARTICIPATION))
    {
        return validate_agent_private_key_tail(rest);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_encrypted_account_data_value(
    data_type: &str,
    value: &Value,
) -> Result<(), AccountDataEncryptionError> {
    validate_encrypted_account_data_value_for_actor(data_type, value, None)
}

pub(crate) fn validate_encrypted_account_data_value_for_actor(
    data_type: &str,
    value: &Value,
    expected_actor_id: Option<&str>,
) -> Result<(), AccountDataEncryptionError> {
    if encrypted_account_data_prefix(data_type).is_none() {
        return Ok(());
    }
    let object = value
        .as_object()
        .ok_or(AccountDataEncryptionError::ValueMustBeObject)?;
    if object
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    if is_account_data_set_operation_payload(object) {
        reject_operation_plaintext_fields(object)?;
        for field in ["body", "encrypted_payload", "encrypted_content"] {
            if let Some(carrier) = object.get(field) {
                return validate_encrypted_carrier(data_type, carrier, expected_actor_id);
            }
        }
        return Err(AccountDataEncryptionError::MissingEncryptedCarrier);
    }
    reject_content_plaintext_fields(object)?;
    if validate_encrypted_carrier(data_type, value, expected_actor_id).is_ok() {
        return Ok(());
    }
    for field in ["encrypted_payload", "encrypted_content"] {
        if let Some(carrier) = object.get(field) {
            return validate_encrypted_carrier(data_type, carrier, expected_actor_id);
        }
    }
    if object.contains_key("ciphertext") {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }
    Err(AccountDataEncryptionError::MissingEncryptedCarrier)
}

fn validate_agent_private_key_tail(rest: &str) -> Result<(), AccountDataEncryptionError> {
    let tail = rest
        .strip_prefix(':')
        .filter(|tail| !tail.is_empty())
        .ok_or(AccountDataEncryptionError::InvalidKeyPattern)?;
    if tail
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#'))
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(actor_id) = tail.split(':').next()
        && actor_id.starts_with("did:")
    {
        Did::new(actor_id.to_owned()).map_err(|_| AccountDataEncryptionError::InvalidKeyPattern)?;
    }
    Ok(())
}

fn is_account_data_set_operation_payload(object: &Map<String, Value>) -> bool {
    object.get("key").and_then(Value::as_str).is_some()
}

fn reject_operation_plaintext_fields(
    object: &Map<String, Value>,
) -> Result<(), AccountDataEncryptionError> {
    if FORBIDDEN_PLAINTEXT_FIELDS
        .iter()
        .filter(|field| **field != "body")
        .any(|field| object.contains_key(*field))
    {
        Err(AccountDataEncryptionError::PlaintextField)
    } else {
        Ok(())
    }
}

fn reject_content_plaintext_fields(
    object: &Map<String, Value>,
) -> Result<(), AccountDataEncryptionError> {
    if object.iter().any(|(field, value)| {
        field_is_forbidden_plaintext(field) || contains_forbidden_field(value)
    }) {
        Err(AccountDataEncryptionError::PlaintextField)
    } else {
        Ok(())
    }
}

fn contains_forbidden_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(field, value)| {
            field_is_forbidden_plaintext(field) || contains_forbidden_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_field),
        _ => false,
    }
}

fn field_is_forbidden_plaintext(field: &str) -> bool {
    FORBIDDEN_PLAINTEXT_FIELDS.contains(&field)
}

fn validate_encrypted_carrier(
    data_type: &str,
    value: &Value,
    expected_actor_id: Option<&str>,
) -> Result<(), AccountDataEncryptionError> {
    validate_encrypted_envelope_metadata(data_type, value, expected_actor_id)
}

fn validate_encrypted_envelope_metadata(
    data_type: &str,
    value: &Value,
    expected_actor_id: Option<&str>,
) -> Result<(), AccountDataEncryptionError> {
    let envelope: AccountDataEncryptedValue = serde_json::from_value(value.clone())
        .map_err(|_| AccountDataEncryptionError::InvalidEnvelopeMetadata)?;
    arkret_crypto::account_data_crypto::validate_account_data_encrypted_value(
        &envelope,
        expected_actor_id.unwrap_or(&envelope.aad.actor_id),
        data_type,
    )
    .map_err(|_| AccountDataEncryptionError::InvalidEnvelopeMetadata)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn private_key() -> &'static str {
        "ak.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }

    fn encrypted_envelope(data_type: &str) -> Value {
        serde_json::to_value(
            arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
                &[7u8; 32],
                "did:web:alice.example",
                data_type,
                &json!({"private": true}),
                [9u8; 24],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn conformance_marker() -> Value {
        json!({
            "client_side_conformance": {
                "encrypted_account_data": true,
                "profile_id": "ak.profile.e2ee_client.v1",
                "plaintext_schema_id": "ak.schema.personal_productivity.v1",
                "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            },
            "content_type": "application/vnd.arkret.account-data+json",
            "ciphertext": "opaque-client-envelope"
        })
    }

    #[test]
    fn encrypted_account_data_accepts_spec_envelope_metadata() {
        validate_encrypted_account_data_value(private_key(), &encrypted_envelope(private_key()))
            .unwrap();
    }

    #[test]
    fn encrypted_account_data_rejects_cross_actor_aad() {
        let error = validate_encrypted_account_data_value_for_actor(
            private_key(),
            &encrypted_envelope(private_key()),
            Some("did:web:bob.example"),
        )
        .unwrap_err();
        assert_eq!(error, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn encrypted_account_data_rejects_client_side_marker() {
        let error = validate_encrypted_account_data_value(private_key(), &conformance_marker())
            .unwrap_err();
        assert_eq!(error, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn encrypted_account_data_rejects_plaintext_fields() {
        let err = validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "filename": "private.pdf",
                "encrypted_payload": encrypted_envelope(private_key())
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn encrypted_account_data_rejects_incomplete_envelope_metadata() {
        let err =
            validate_encrypted_account_data_value(private_key(), &json!({"ciphertext": "opaque"}))
                .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn unregistered_account_data_is_not_reinterpreted() {
        validate_encrypted_account_data_value(
            "com.example.client.ui_state",
            &json!({"local_name": "Acme"}),
        )
        .unwrap();
    }

    #[test]
    fn standard_encrypted_account_data_requires_encrypted_carrier() {
        for key in [
            ACCOUNT_DATA_TYPE_BLOCKLIST,
            ACCOUNT_DATA_TYPE_CLIENT_UI_STATE,
            ACCOUNT_DATA_TYPE_COLLECTIONS_STICKERS,
            ACCOUNT_DATA_TYPE_DND_SCHEDULE,
            ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY,
            ACCOUNT_DATA_TYPE_PRESENCE_PREFERENCE,
            ACCOUNT_DATA_TYPE_PUSH_RULES,
            ACCOUNT_DATA_TYPE_READ_RECEIPT_PREFERENCES,
        ] {
            let err =
                validate_encrypted_account_data_value(key, &json!({"enabled": true})).unwrap_err();
            assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
        }

        let err = validate_encrypted_account_data_value(
            "ak.contacts.realm.ak:realm:0196419b-0000-7000-8000-000000000000",
            &json!({"local_name": "Acme"}),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);

        let err = validate_encrypted_account_data_value(
            ACCOUNT_DATA_TYPE_INVITE_QUARANTINE,
            &json!({"invite_event_id": "ak:event:0196419b-0000-7000-8000-000000000000"}),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
    }

    #[test]
    fn retired_sidecar_projection_prefix_is_hard_rejected() {
        for key in [
            "ak.agent.sidecar_projection.v1",
            "ak.agent.sidecar_projection.v1:did:web:alice.example",
            "ak.agent.sidecar_projection.v1:did:web:alice.example:ak:realm:0196419b-0000-7000-8000-000000000000:ak:strand:0196419b-0000-7000-8000-000000000001",
        ] {
            assert!(is_retired_encrypted_account_data_key(key));
            assert_eq!(
                validate_encrypted_account_data_key(key).unwrap_err(),
                AccountDataEncryptionError::InvalidKeyPattern
            );
        }
        // Unrelated keys are not swept up by the retired-prefix guard.
        assert!(!is_retired_encrypted_account_data_key(
            "ak.agent.sidecar_view_state.v1:did:web:alice.example"
        ));
    }

    #[test]
    fn legacy_blocklist_key_alias_is_rejected() {
        let err = validate_encrypted_account_data_key("ak.account.blocklist.v1").unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::InvalidKeyPattern);
    }

    #[test]
    fn account_data_set_body_may_carry_encrypted_envelope() {
        validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "key": private_key(),
                "owner": "did:web:alice.example",
                "body": encrypted_envelope(private_key()),
                "updated_at": "2026-06-18T00:00:00.000Z"
            }),
        )
        .unwrap();

        let err = validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "key": private_key(),
                "owner": "did:web:alice.example",
                "body": {"collection_title": "Leaks"},
                "updated_at": "2026-06-18T00:00:00.000Z"
            }),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn reminder_rejects_plaintext_note_and_target_ref() {
        let key = "ak.reminders.v1:local-reminder-1";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "reminder",
                "target_ref": "ak:message:01904100-0000-7000-8000-000000000001",
                "remind_at": "2026-06-19T08:00:00.000Z",
                "note": "private reminder note",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn snooze_rejects_plaintext_target_ref() {
        let key = "ak.snooze.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "snooze",
                "target_ref": "ak:strand:01904100-0000-7000-8000-000000000001",
                "snooze_expires_at": "2026-06-19T09:00:00.000Z",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn scheduled_send_rejects_plaintext_message_payload() {
        let key = "ak.scheduled_send.v1:ak:message:01904100-0000-7000-8000-000000000001";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "scheduled_send",
                "planned_message_id": "ak:message:01904100-0000-7000-8000-000000000001",
                "send_at": "2026-06-19T08:00:00.000Z",
                "message_payload": {
                    "message_id": "ak:message:01904100-0000-7000-8000-000000000001",
                    "content": {"kind": "ak.content.text", "body": "secret"}
                },
                "message_payload_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn search_index_manifest_rejects_plaintext_manifest_fields() {
        let key = "ak.search.index_manifest.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "shards": [{
                    "shard_key": "term-derived-key",
                    "blob_ref": "ak:blob:sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "ciphertext_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                }],
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }
}
