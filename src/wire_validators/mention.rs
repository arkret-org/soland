//! HC-SOL-3 / SEC-SOL-1 (R3.2, cokret-spec @ b56cab1) — mention
//! reference shape v2 validator.
//!
//! The spec mention node (`models/flow-and-message.md §9.4`,
//! `identity/identity-handles.md §3.8.1`) was rewritten wire-breaking:
//!
//! - Authoritative field: `subject_id` (principal DID). It is the ONLY field that participates in
//!   actor attribution, authorization, resolution and render lookup.
//! - Audit metadata (MAY): `handle_at_time` / `display_name_at_time` / `mention_text_original` /
//!   `resolved_at`. Verifier / reducer / policy engine MUST ignore these for trust decisions
//!   (SEC-SOL-1 — soland's authz / audit / federation paths never read them).
//! - The pre-R3.2 fields `subject` / `handle` / `display_snapshot` are GONE; an envelope carrying
//!   any of them MUST be rejected as a `schema_violation` with reason
//!   `mention_reference_legacy_shape`.
//!
//! NOTE: soland also accepts a separate deployment-local message-mention
//! convention (`{type: "actor"|"flow", ...}`) validated by
//! `routing::events::operations::validate_mentions`; that shape is left
//! intact. This validator targets the spec actor mention-reference object
//! (the one carrying `subject_id`).

use serde_json::Value;

use super::WireRejection;
use crate::error::reasons;

/// Legacy pre-R3.2 mention reference fields. Their presence on a mention
/// reference object is a hard reject.
const LEGACY_MENTION_FIELDS: &[&str] = &["subject", "handle", "display_snapshot"];

/// Validate one mention-reference object. A mention reference is only
/// subject to this check when it looks like the spec subject-reference
/// shape — i.e. it carries `subject_id` and/or one of the legacy fields.
/// Other object shapes (the soland `{type: "actor"|"flow"}` convention)
/// are passed through untouched.
pub fn validate_mention_reference(mention: &Value) -> Result<(), WireRejection> {
    let Some(map) = mention.as_object() else {
        return Ok(());
    };
    for field in LEGACY_MENTION_FIELDS {
        if map.contains_key(*field) {
            return Err(WireRejection::new(
                reasons::MENTION_REFERENCE_LEGACY_SHAPE,
                format!(
                    "mention reference field `{field}` is the removed pre-R3.2 shape; use \
                     subject_id (authoritative) + handle_at_time / display_name_at_time / \
                     mention_text_original (audit metadata only)"
                ),
            ));
        }
    }
    Ok(())
}

/// Validate every mention reference inside a message content body. Scans
/// `content.mentions[]` and rejects any element carrying the legacy shape.
pub fn validate_content_mention_references(content: &Value) -> Result<(), WireRejection> {
    let Some(mentions) = content.get("mentions").and_then(Value::as_array) else {
        return Ok(());
    };
    for mention in mentions {
        validate_mention_reference(mention)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_v2_subject_id_shape() {
        let mention = json!({
            "subject_id": "did:web:alice-principal.example",
            "handle_at_time": "alice:acme.example",
            "display_name_at_time": "Alice",
            "mention_text_original": "@alice:acme.example",
            "resolved_at": "2026-05-28T10:00:00Z"
        });
        assert!(validate_mention_reference(&mention).is_ok());
    }

    #[test]
    fn passes_through_soland_actor_convention() {
        // The deployment-local `{type: "actor", did}` shape carries none of
        // the legacy mention-reference fields, so it is untouched here.
        let mention = json!({"type": "actor", "did": "did:web:alice.example"});
        assert!(validate_mention_reference(&mention).is_ok());
    }
}
