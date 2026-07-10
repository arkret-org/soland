//! MIU-SOL-1 (R3.2, arkret-spec @ b56cab1) — `ck.member.identity.update`
//! payload deny check for the removed handle fields.
//!
//! `MemberIdentity` no longer carries handle lifecycle: `primary_handle`
//! (top-level), `handles[]` (the deleted `VerifiedHandle` array), and the
//! `verified_handle` `$def` are all gone. Handle lifecycle lives solely on
//! `ck.schema.handle_claim.v1`. Any envelope still carrying one of these
//! fields — at the payload top level or inside the plaintext
//! `identity_payload.member_identity` carrier — MUST be rejected as a
//! `schema_violation` with reason
//! `member_identity_handle_field_forbidden`.

use serde_json::Value;

use super::WireRejection;
use crate::error::reasons;

/// Fields that MemberIdentity / its update payload MUST NOT carry post-R3.2.
const FORBIDDEN_HANDLE_FIELDS: &[&str] = &["primary_handle", "handles", "verified_handle"];

/// Reject a `ck.member.identity.update` payload that still carries any
/// removed handle field. Checks the payload top level and the plaintext
/// `identity_payload.member_identity` carrier (encrypted carriers are
/// opaque and skipped).
pub fn validate_member_identity_update_payload(payload: &Value) -> Result<(), WireRejection> {
    deny_forbidden_fields(payload, "payload")?;
    if let Some(carrier) = payload
        .get("identity_payload")
        .and_then(|carrier| carrier.get("member_identity"))
    {
        deny_forbidden_fields(carrier, "payload.identity_payload.member_identity")?;
    }
    Ok(())
}

fn deny_forbidden_fields(object: &Value, location: &str) -> Result<(), WireRejection> {
    let Some(map) = object.as_object() else {
        return Ok(());
    };
    for field in FORBIDDEN_HANDLE_FIELDS {
        if map.contains_key(*field) {
            return Err(WireRejection::new(
                reasons::MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN,
                format!(
                    "{location}.{field} is forbidden; MemberIdentity no longer carries handle \
                     lifecycle (use ak.schema.handle_claim.v1)"
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_clean_payload() {
        let payload = json!({
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "segment": "member_identity",
            "identity_payload": {
                "member_identity": {
                    "subject_id": "did:web:alice-principal.example",
                    "display_profile": {"display_name": "Alice"}
                }
            }
        });
        assert!(validate_member_identity_update_payload(&payload).is_ok());
    }

    #[test]
    fn rejects_top_level_primary_handle() {
        let payload = json!({
            "segment": "member_identity",
            "primary_handle": "alice:acme.example"
        });
        let err = validate_member_identity_update_payload(&payload).unwrap_err();
        assert_eq!(err.reason, reasons::MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN);
    }

    #[test]
    fn rejects_handles_array_inside_carrier() {
        let payload = json!({
            "segment": "member_identity",
            "identity_payload": {
                "member_identity": {
                    "subject_id": "did:web:alice-principal.example",
                    "handles": []
                }
            }
        });
        let err = validate_member_identity_update_payload(&payload).unwrap_err();
        assert_eq!(err.reason, reasons::MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN);
    }

    #[test]
    fn rejects_verified_handle() {
        let payload = json!({"verified_handle": {"handle": "alice:acme.example"}});
        let err = validate_member_identity_update_payload(&payload).unwrap_err();
        assert_eq!(err.reason, reasons::MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN);
    }
}
