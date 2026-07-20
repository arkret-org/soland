use serde_json::json;

use super::*;

// ── Validate_canonical_json_value vectors ────────────────────────────

#[test]
fn validator_accepts_sorted_snake_case_keys() {
    let value = json!({"actor_id": "x", "kind": "y"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_sdk_canonical_encoding() {
    let value = json!({"a": 1, "b": 2});
    assert!(validate_canonical_json_value(&value).is_ok());
    let canonical = arkret_core::canonical::canonical_json_string(&value).unwrap();
    assert_eq!(canonical, r#"{"a":1,"b":2}"#);
}

#[test]
fn validator_rejects_camel_case_keys() {
    let value = json!({"actorId": "x"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_accepts_dollar_prefixed_json_schema_keys() {
    let value = json!({"$id": "schema-1", "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_rejects_empty_key() {
    let value = json!({"": "value"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_leading_underscore() {
    let value = json!({"_private": 1});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_trailing_underscore() {
    let value = json!({"bad_": 1});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_double_underscore() {
    let value = json!({"a__b": 1});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_accepts_rfc3339_utc_z_timestamp() {
    let value = json!({"created_at": "2026-04-29T12:00:00Z"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_event_bound_fixed_millisecond_timestamp() {
    let value = json!({"object": {"created_at": "2026-04-29T12:00:00.123Z"}});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_rejects_noncanonical_timestamp_precision() {
    let value = json!({"created_at": "2026-04-29T12:00:00.123456Z"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_non_utc_timestamp() {
    let value = json!({"created_at": "2026-04-29T12:00:00+05:00"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_date_only_in_at_field() {
    let value = json!({"created_at": "2026-04-29"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_ignores_non_at_timestamp_fields() {
    // Fields not ending in _at should not be validated as timestamps.
    let value = json!({"description": "not a timestamp"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_dotted_patch_path_keys() {
    // event-and-patch.md §4.2.1: `patch` map keys are dotted snake_case
    // patch *paths*, not canonical JSON field names.
    let value = json!({
        "target_ref": "ak:morph:01904100-0000-7000-8000-7191ddd787e5",
        "patch": {"metadata.title": "Backfill v2"},
    });
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_rejects_non_snake_case_patch_path_segment() {
    // A camelCase segment is not a valid §4.2.1 identifier.
    let value = json!({"patch": {"metadata.Title": "x"}});
    assert!(validate_canonical_json_value(&value).is_err());
}

// ── DID service endpoint validation vectors ──────────────────────────

#[test]
fn did_service_endpoint_rejects_empty_endpoint_in_production() {
    let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": ""}]});
    assert!(validate_did_document_services("did:web:example.com", &doc, false).is_err());
}

#[test]
fn did_service_endpoint_accepts_absolute_url() {
    let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": "https://example.com/api"}]});
    assert!(validate_did_document_services("did:web:example.com", &doc, false).is_ok());
}

#[test]
fn did_service_endpoint_accepts_path() {
    let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": "/_arkret"}]});
    assert!(validate_did_document_services("did:web:example.com", &doc, false).is_ok());
}

#[test]
fn did_service_endpoint_rejects_relative_path() {
    let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": "api/v1"}]});
    assert!(validate_did_document_services("did:web:example.com", &doc, false).is_err());
}

#[test]
fn did_web_requires_service_in_production() {
    let doc = json!({"id": "did:web:example.com"});
    assert!(validate_did_document_services("did:web:example.com", &doc, false).is_err());
}

#[test]
fn did_web_accepts_missing_service_in_development() {
    let doc = json!({"id": "did:web:example.com"});
    assert!(validate_did_document_services("did:web:example.com", &doc, true).is_ok());
}
