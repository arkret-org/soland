//! Contrix v1 protocol-compliant ID generation.
//!
//! All typed object IDs follow the format `cx:<kind>:<uuid>` where `<uuid>`
//! is RFC 9562 UUID version 7 (48-bit Unix-millisecond timestamp + 4-bit
//! version=7 + 12-bit rand_a + 2-bit variant=10 + 62-bit rand_b), serialized
//! as the canonical 36-character lowercase hex form
//! `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` where N ∈ {8,9,a,b}.
//!
//! See `contrix-spec/spec/v1/zh/conformance/encoding.md` §4.

use uuid::Uuid;

/// Generate a new typed wire ID with the given kind prefix.
///
/// Format: `cx:<kind>:<uuid-v7-36-char-lowercase-hex>`
pub fn generate(kind: &str) -> String {
    format!("cx:{}:{}", kind, Uuid::now_v7())
}

pub fn generate_space_id() -> String {
    generate("space")
}

pub fn generate_event_id() -> String {
    generate("event")
}

pub fn generate_operation_id() -> String {
    generate("operation")
}

pub fn generate_relation_id() -> String {
    generate("relation")
}

pub fn generate_grant_id() -> String {
    generate("grant")
}

pub fn generate_invite_id() -> String {
    generate("invite")
}

pub fn generate_snapshot_id() -> String {
    generate("snapshot")
}

pub fn generate_report_id() -> String {
    generate("report")
}

pub fn generate_notification_id() -> String {
    generate("notification")
}

pub fn generate_view_id() -> String {
    generate("view")
}

pub fn generate_request_id() -> String {
    generate("req")
}

/// Convert a wire-form `cx:<kind>:<uuid>` typed ID to its raw `Uuid` for
/// PostgreSQL `uuid` column storage. Returns `None` if the input is not a
/// well-formed typed ID with a parseable UUID segment. The kind segment is
/// not validated here; callers that care MUST check it separately (the kind
/// is canonical bytes of the wire value, see encoding.md §4).
pub fn parse_typed_uuid(typed: &str, expected_kind: &str) -> Option<Uuid> {
    let prefix = format!("cx:{}:", expected_kind);
    let rest = typed.strip_prefix(&prefix)?;
    Uuid::parse_str(rest).ok()
}

/// Kind-agnostic helper: parse the trailing UUID part of any
/// `cx:<kind>:<uuid>` typed ID. Returns `None` if the string has no
/// `cx:<kind>:` prefix or the trailing segment is not a valid UUID.
/// Use this at persistence boundaries where the column is `UUID` but the
/// in-memory value carries the typed wire form.
pub fn typed_uuid_part(typed: &str) -> Option<Uuid> {
    let mut iter = typed.splitn(3, ':');
    let scheme = iter.next()?;
    if scheme != "cx" {
        return None;
    }
    let _kind = iter.next()?;
    let uuid_str = iter.next()?;
    Uuid::parse_str(uuid_str).ok()
}

/// Same as `typed_uuid_part`, but panics with a descriptive message on
/// malformed input. Use only at persistence boundaries that have already
/// been validated upstream (e.g. SDK `*Id::new` validators); production
/// code that handles untrusted input MUST use `typed_uuid_part` and
/// propagate the `None` case as a typed error.
pub fn typed_uuid_part_or_panic(typed: &str) -> Uuid {
    typed_uuid_part(typed)
        .unwrap_or_else(|| panic!("malformed typed wire ID at persistence boundary: {typed:?}"))
}

/// Format a raw `Uuid` back to a typed wire ID `cx:<kind>:<uuid>`.
pub fn format_typed_uuid(kind: &str, uuid: &Uuid) -> String {
    format!("cx:{}:{}", kind, uuid)
}

/// Percent-encode reserved characters in a **cell subject** segment.
///
/// Per Contrix v1 (spec encoding §9.5), composite cell subjects are joined
/// with `|`. Raw DIDs and identifiers may contain `|` themselves, which
/// would collide with the separator. We encode `%`, `|`, and ASCII control
/// characters using percent-escape (`%XX`) so that segments roundtrip
/// uniquely. This helper is reducer-internal subject encoding, not a
/// wire-format builder.
pub fn subject_segment_encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'%' | b'|' => {
                out.push('%');
                out.push_str(&format!("{:02X}", byte));
            }
            0x00..=0x1F | 0x7F => {
                out.push('%');
                out.push_str(&format!("{:02X}", byte));
            }
            _ => out.push(byte as char),
        }
    }
    out
}

/// Compose a canonical composite **state subject** from segments.
///
/// Each segment is percent-encoded for `%` and `|`, then joined with `|`.
/// An empty input yields an empty key. The result is a reducer-internal
/// slot key; the wire-canonical form is
/// `base64url(sha256(canonical_json([segments])))` per spec encoding §9.5.
pub fn subject_compose<I, S>(segments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let parts: Vec<String> = segments
        .into_iter()
        .map(|s| subject_segment_encode(s.as_ref()))
        .collect();
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_format_is_cx_kind_uuid() {
        let id = generate_space_id();
        assert!(id.starts_with("cx:space:"));
        let uuid_part = &id["cx:space:".len()..];
        // 36-char canonical UUID form: 8-4-4-4-12 hex with dashes
        assert_eq!(uuid_part.len(), 36);
        let parsed = Uuid::parse_str(uuid_part).expect("uuid parse");
        // version 7
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[test]
    fn all_generators_produce_valid_prefixes() {
        assert!(generate_space_id().starts_with("cx:space:"));
        assert!(generate_event_id().starts_with("cx:event:"));
        assert!(generate_operation_id().starts_with("cx:operation:"));
        assert!(generate_relation_id().starts_with("cx:relation:"));
        assert!(generate_grant_id().starts_with("cx:grant:"));
        assert!(generate_invite_id().starts_with("cx:invite:"));
        assert!(generate_snapshot_id().starts_with("cx:snapshot:"));
        assert!(generate_report_id().starts_with("cx:report:"));
        assert!(generate_notification_id().starts_with("cx:notification:"));
        assert!(generate_view_id().starts_with("cx:view:"));
        assert!(generate_request_id().starts_with("cx:req:"));
    }

    #[test]
    fn ids_are_globally_unique() {
        let ids: std::collections::HashSet<String> =
            (0..1000).map(|_| generate_space_id()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn ids_are_lexicographically_sortable_by_time() {
        let id1 = generate_space_id();
        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = generate_space_id();
        // UUIDv7 is monotonic by ms timestamp; later IDs sort lexicographically after.
        assert!(id2 > id1);
    }

    #[test]
    fn parse_typed_uuid_roundtrip() {
        let id = generate_event_id();
        let raw = parse_typed_uuid(&id, "event").expect("parse");
        let back = format_typed_uuid("event", &raw);
        assert_eq!(id, back);
    }

    #[test]
    fn parse_typed_uuid_rejects_wrong_kind() {
        let id = generate_event_id();
        assert!(parse_typed_uuid(&id, "space").is_none());
    }

    #[test]
    fn subject_segment_escapes_separator_and_percent() {
        assert_eq!(subject_segment_encode("did:web:alice"), "did:web:alice");
        assert_eq!(subject_segment_encode("a|b"), "a%7Cb");
        assert_eq!(subject_segment_encode("100%"), "100%25");
        assert_eq!(subject_segment_encode("a%7Cb"), "a%257Cb");
    }

    #[test]
    fn subject_compose_avoids_collision() {
        let direct = subject_compose(["a|b", "c"]);
        let split = subject_compose(["a", "b", "c"]);
        assert_ne!(direct, split, "encoding must prevent separator collision");
        assert_eq!(direct, "a%7Cb|c");
        assert_eq!(split, "a|b|c");
    }

    #[test]
    fn subject_compose_empty_segments_preserved() {
        assert_eq!(subject_compose::<_, &str>([]), "");
        assert_eq!(subject_compose(["", "x"]), "|x");
    }
}
