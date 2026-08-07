//! MIU-SOL-1 (R3.2, arkret-spec @ b56cab1) — `ak.member.identity.update`
//! payload deny check for the removed handle fields.
//!
//! `MemberIdentity` no longer carries handle lifecycle: `primary_handle`
//! (top-level), `handles[]` (the deleted `VerifiedHandle` array), and the
//! `verified_handle` `$def` are all gone. Handle lifecycle lives solely on
//! `ak.schema.handle_claim.v1`. Any envelope still carrying one of these
//! fields — at the payload top level or inside the plaintext
//! `identity_payload.member_identity` carrier — MUST be rejected as a
//! `schema_violation`.

use serde_json::Value;

use super::WireRejection;

/// Fields that MemberIdentity / its update payload MUST NOT carry post-R3.2.
const FORBIDDEN_HANDLE_FIELDS: &[&str] = &["primary_handle", "handles", "verified_handle"];

/// Reject a `ak.member.identity.update` payload that still carries any
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
            return Err(WireRejection::new(format!(
                "{location}.{field} is forbidden; MemberIdentity no longer carries handle \
                 lifecycle (use ak.schema.handle_claim.v1)"
            )));
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
            "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
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
        assert!(validate_member_identity_update_payload(&payload).is_err());
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
        assert!(validate_member_identity_update_payload(&payload).is_err());
    }

    #[test]
    fn rejects_verified_handle() {
        let payload = json!({"verified_handle": {"handle": "alice:acme.example"}});
        assert!(validate_member_identity_update_payload(&payload).is_err());
    }
}
