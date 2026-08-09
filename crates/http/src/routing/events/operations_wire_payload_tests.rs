use serde_json::json;

use super::*;

#[test]
fn consent_revoke_empty_observed_dots_rejected() {
    let err = validate_consent_revoke_payload(&json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dots": [],
    }))
    .unwrap_err();
    assert_eq!(err.0, arkret_wire::ErrorCode::SCHEMA_VIOLATION);
}

#[test]
fn consent_revoke_accepts_non_empty_observed_dots() {
    validate_consent_revoke_payload(&json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dots": [
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1:1"
        ],
    }))
    .unwrap();
}

#[test]
fn consent_revoke_rejects_untyped_consent_id() {
    let err = validate_consent_revoke_payload(&json!({
        "consent_id": "cid",
        "observed_dots": [
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1:1"
        ],
    }))
    .unwrap_err();
    assert_eq!(err.0, arkret_wire::ErrorCode::SCHEMA_VIOLATION);
}
