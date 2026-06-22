use std::sync::OnceLock;

use cokret_sdk::{Did, Hash, ProtocolSchemaRegistry, RealmId};
use serde_json::{Map, Value};

const CLIENT_SIDE_CONFORMANCE: &str = "client_side_conformance";
const ACCOUNT_DATA_TYPE_AGENT_DRAFT: &str = "ck.agent.draft.v1";
const ACCOUNT_DATA_TYPE_AGENT_SIDECAR_PROJECTION: &str = "ck.agent.sidecar_projection.v1";
const ACCOUNT_DATA_TYPE_AGENT_PARTICIPATION: &str = "ck.agent.participation.v1";
const ACCOUNT_DATA_TYPE_BLOCKLIST: &str = "ck.account.blocklist";
const ACCOUNT_DATA_TYPE_DND_SCHEDULE: &str = "ck.dnd_schedule";
const ACCOUNT_DATA_TYPE_INVITE_QUARANTINE: &str = "ck.account.invite_quarantine";
const ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY: &str = "ck.presence.visibility";
const ACCOUNT_DATA_TYPE_PUSH_RULES: &str = "ck.push_rules";
const ACCOUNT_DATA_TYPE_TAGS_REALM: &str = "ck.tags.realm";

const EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS: &[&str] = &[
    ACCOUNT_DATA_TYPE_BLOCKLIST,
    ACCOUNT_DATA_TYPE_DND_SCHEDULE,
    ACCOUNT_DATA_TYPE_INVITE_QUARANTINE,
    ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY,
    ACCOUNT_DATA_TYPE_PUSH_RULES,
];

const SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    cokret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_ACTOR,
    cokret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_REALM,
    cokret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
    cokret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
    cokret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
    cokret_sdk::ACCOUNT_DATA_TYPE_SAVED,
    cokret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
    cokret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
    cokret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
];

const AGENT_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    ACCOUNT_DATA_TYPE_AGENT_DRAFT,
    ACCOUNT_DATA_TYPE_AGENT_SIDECAR_PROJECTION,
    ACCOUNT_DATA_TYPE_AGENT_PARTICIPATION,
];

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

const MARKER_TOP_LEVEL_FIELDS: &[&str] = &[
    CLIENT_SIDE_CONFORMANCE,
    "ciphertext",
    "content_type",
    "version",
    "payload_digest",
    "aad_digest",
];

const MARKER_FIELDS: &[&str] = &[
    "encrypted_account_data",
    "payload_digest",
    "plaintext_schema_id",
    "profile_id",
    "validated_at",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountDataEncryptionError {
    InvalidKeyPattern,
    ValueMustBeObject,
    PlaintextField,
    MissingEncryptedCarrier,
    InvalidEnvelopeMetadataOrMarker,
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
                "private account_data content requires encrypted envelope metadata or client-side conformance marker"
            }
            Self::InvalidEnvelopeMetadataOrMarker => {
                "private account_data encrypted envelope metadata or client-side conformance marker is invalid"
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
    if EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS.contains(&data_type) {
        return Ok(());
    }
    if data_type
        .strip_prefix(ACCOUNT_DATA_TYPE_BLOCKLIST)
        .is_some_and(|rest| rest.starts_with('.'))
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(realm_id) = data_type.strip_prefix("ck.tags.realm.") {
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
        return cokret_sdk::validate_private_account_data_key(data_type)
            .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(rest) = data_type
        .strip_prefix(ACCOUNT_DATA_TYPE_AGENT_DRAFT)
        .or_else(|| data_type.strip_prefix(ACCOUNT_DATA_TYPE_AGENT_SIDECAR_PROJECTION))
        .or_else(|| data_type.strip_prefix(ACCOUNT_DATA_TYPE_AGENT_PARTICIPATION))
    {
        return validate_agent_private_key_tail(rest);
    }
    Ok(())
}

pub(crate) fn validate_encrypted_account_data_value(
    data_type: &str,
    value: &Value,
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
                return validate_encrypted_carrier(carrier);
            }
        }
        return Err(AccountDataEncryptionError::MissingEncryptedCarrier);
    }
    reject_content_plaintext_fields(object)?;
    if validate_encrypted_carrier(value).is_ok() {
        return Ok(());
    }
    for field in ["encrypted_payload", "encrypted_content"] {
        if let Some(carrier) = object.get(field) {
            return validate_encrypted_carrier(carrier);
        }
    }
    if object.contains_key("ciphertext") || object.contains_key(CLIENT_SIDE_CONFORMANCE) {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
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

fn validate_encrypted_carrier(value: &Value) -> Result<(), AccountDataEncryptionError> {
    validate_encrypted_envelope_metadata(value)
        .or_else(|_| validate_client_side_conformance_marker(value))
}

fn validate_encrypted_envelope_metadata(value: &Value) -> Result<(), AccountDataEncryptionError> {
    static REGISTRY: OnceLock<Option<ProtocolSchemaRegistry>> = OnceLock::new();

    let registry = REGISTRY
        .get_or_init(|| {
            cokret_sdk::schema::schema_registry_from_default_spec_artifacts()
                .ok()
                .flatten()
        })
        .as_ref()
        .ok_or(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker)?;
    registry
        .validate_value(cokret_sdk::ENCRYPTED_ENVELOPE_SCHEMA, value)
        .map_err(|_| AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker)
}

fn validate_client_side_conformance_marker(
    value: &Value,
) -> Result<(), AccountDataEncryptionError> {
    let object = value
        .as_object()
        .ok_or(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker)?;
    if object
        .keys()
        .any(|field| !MARKER_TOP_LEVEL_FIELDS.contains(&field.as_str()))
    {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
    }
    let marker = object
        .get(CLIENT_SIDE_CONFORMANCE)
        .and_then(Value::as_object)
        .ok_or(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker)?;
    if marker
        .keys()
        .any(|field| !MARKER_FIELDS.contains(&field.as_str()))
    {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
    }
    if marker
        .get("encrypted_account_data")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
    }
    let payload_digest = marker
        .get("payload_digest")
        .or_else(|| object.get("payload_digest"))
        .and_then(Value::as_str)
        .ok_or(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker)?;
    Hash::new(payload_digest.to_owned())
        .map_err(|_| AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker)?;
    if let Some(schema_id) = marker.get("plaintext_schema_id").and_then(Value::as_str)
        && !schema_id.starts_with("ck.schema.")
    {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
    }
    if marker
        .get("profile_id")
        .and_then(Value::as_str)
        .is_some_and(|profile_id| !profile_id.starts_with("ck.profile."))
    {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
    }
    if object
        .get("ciphertext")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn private_key() -> &'static str {
        "ck.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }

    fn encrypted_envelope() -> Value {
        json!({
            "scheme": "mls-rfc9420",
            "version": "1.0",
            "group_id": "testGroup",
            "epoch": 1,
            "content_type": "application/vnd.cokret.account-data+json",
            "ciphertext": "b3BhcXVl",
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "event_kind": "ck.account_data.set"
            },
            "key_ref": {
                "algorithm": "MLS",
                "group_state_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            },
            "aad_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "payload_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        })
    }

    fn conformance_marker() -> Value {
        json!({
            "client_side_conformance": {
                "encrypted_account_data": true,
                "profile_id": "ck.profile.e2ee_client.v1",
                "plaintext_schema_id": "ck.schema.personal_productivity.v1",
                "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            },
            "content_type": "application/vnd.cokret.account-data+json",
            "ciphertext": "opaque-client-envelope"
        })
    }

    #[test]
    fn encrypted_account_data_accepts_spec_envelope_metadata() {
        validate_encrypted_account_data_value(private_key(), &encrypted_envelope()).unwrap();
    }

    #[test]
    fn encrypted_account_data_accepts_client_side_marker() {
        validate_encrypted_account_data_value(private_key(), &conformance_marker()).unwrap();
    }

    #[test]
    fn encrypted_account_data_rejects_plaintext_fields() {
        let err = validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "filename": "private.pdf",
                "encrypted_payload": encrypted_envelope()
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

        assert_eq!(
            err,
            AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker
        );
    }

    #[test]
    fn unregistered_account_data_is_not_reinterpreted() {
        validate_encrypted_account_data_value("client.ui", &json!({"local_name": "Acme"})).unwrap();
    }

    #[test]
    fn standard_encrypted_account_data_requires_encrypted_carrier() {
        for key in [
            ACCOUNT_DATA_TYPE_BLOCKLIST,
            ACCOUNT_DATA_TYPE_DND_SCHEDULE,
            ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY,
            ACCOUNT_DATA_TYPE_PUSH_RULES,
        ] {
            let err =
                validate_encrypted_account_data_value(key, &json!({"enabled": true})).unwrap_err();
            assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
        }

        let err = validate_encrypted_account_data_value(
            "ck.contacts.realm.ck:realm:0196419b-0000-7000-8000-000000000000",
            &json!({"local_name": "Acme"}),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);

        let err = validate_encrypted_account_data_value(
            ACCOUNT_DATA_TYPE_INVITE_QUARANTINE,
            &json!({"invite_event_id": "ck:event:0196419b-0000-7000-8000-000000000000"}),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
    }

    #[test]
    fn legacy_blocklist_key_alias_is_rejected() {
        let err = validate_encrypted_account_data_key("ck.account.blocklist.v1").unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::InvalidKeyPattern);
    }

    #[test]
    fn account_data_set_body_may_carry_encrypted_marker() {
        validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "key": private_key(),
                "owner": "did:web:alice.example",
                "body": conformance_marker(),
                "updated_at": "2026-06-18T00:00:00Z"
            }),
        )
        .unwrap();

        let err = validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "key": private_key(),
                "owner": "did:web:alice.example",
                "body": {"collection_title": "Leaks"},
                "updated_at": "2026-06-18T00:00:00Z"
            }),
        )
        .unwrap_err();
        assert_eq!(
            err,
            AccountDataEncryptionError::InvalidEnvelopeMetadataOrMarker
        );
    }

    #[test]
    fn reminder_rejects_plaintext_note_and_target_ref() {
        let key = "ck.reminders.v1:local-reminder-1";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &conformance_marker()).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "reminder",
                "target_ref": "ck:message:01904100-0000-7000-8000-000000000001",
                "remind_at": "2026-06-19T08:00:00Z",
                "note": "private reminder note",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": conformance_marker()
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn snooze_rejects_plaintext_target_ref() {
        let key = "ck.snooze.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &conformance_marker()).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "snooze",
                "target_ref": "ck:strand:01904100-0000-7000-8000-000000000001",
                "snooze_expires_at": "2026-06-19T09:00:00Z",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": conformance_marker()
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn scheduled_send_rejects_plaintext_message_payload() {
        let key = "ck.scheduled_send.v1:ck:message:01904100-0000-7000-8000-000000000001";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &conformance_marker()).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "scheduled_send",
                "planned_message_id": "ck:message:01904100-0000-7000-8000-000000000001",
                "send_at": "2026-06-19T08:00:00Z",
                "message_payload": {
                    "message_id": "ck:message:01904100-0000-7000-8000-000000000001",
                    "content": {"kind": "ck.content.text", "body": "secret"}
                },
                "message_payload_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": conformance_marker()
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn search_index_manifest_rejects_plaintext_manifest_fields() {
        let key = "ck.search.index_manifest.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &conformance_marker()).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "shards": [{
                    "shard_key": "term-derived-key",
                    "blob_ref": "ck:blob:sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "ciphertext_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                }],
                "encrypted_payload": conformance_marker()
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }
}
