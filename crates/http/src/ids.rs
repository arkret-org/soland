//! Arkret v1 protocol-compliant ID generation.
//!
//! Producer-allocated typed IDs use RFC 9562 UUIDv7 tokens. Event-derived IDs
//! (`event`, `realm`, `space`, `circle`, `strand`, and peers) instead retain
//! the complete 264-bit, 44-character Event token and must never pass through
//! the UUID persistence helpers in this module.
//!
//! See `arkret-spec/spec/v1/zh/conformance/encoding.md` §4.

/// Typed wire identifiers are owned by the SDK `arkret` (identifiers) crate.
/// soland re-exports them so the whole server shares one validated newtype per
/// id-kind instead of maintaining parallel local copies.
///
/// - [`RealmId`] is the SDK security-boundary id and validates `ak:realm:`.
/// - [`SpaceContainerId`] is the SDK Space container id and validates `ak:space:`.
pub use arkret_identifiers::{RealmId, SpaceId as SpaceContainerId};
use uuid::Uuid;

/// Generate a new typed wire ID with the given kind prefix.
///
/// Format: `ak:<kind>:<uuid-v7-36-char-lowercase-hex>`. Delegates to the SDK
/// [`arkret_identifiers::new_prefixed_uuid7`] so the canonical lowercase UUIDv7 wire
/// form is produced by the single shared primitive.
/// Generators exist only for producer-allocated kinds. The event-derived kinds
/// (`realm`, `space`, `event`, `relation`, `circle`, `strand`, `message`,
/// `morph`, `view`, `actor_profile`) have no generator at all: their ids come
/// from the create Event, so a server that minted one would be naming an object
/// no receiver can agree with (spec `zh/models/common-fields.md` section 6.0).
pub fn generate(kind: &str) -> String {
    arkret_identifiers::new_prefixed_uuid7(&format!("ak:{kind}:"))
}

pub fn generate_operation_id() -> String {
    generate("operation")
}

/// Surrogate primary-key id for the `accounts` row (`ak:account:<uuid7>`).
/// Distinct from the account's `actor_id` DID: the DID is the protocol
/// identity, this is the stable internal row handle the PK is built on.
pub fn generate_account_id() -> String {
    generate("account")
}

pub fn generate_install_id() -> String {
    generate("install")
}

pub fn generate_snapshot_id() -> String {
    generate("snapshot")
}

/// Notification id helper. Spec uses the full `ak:notification:` kind.
pub fn generate_notification_id() -> String {
    generate("notification")
}

pub fn generate_request_id() -> String {
    generate("request")
}

/// Convert a wire-form `ak:<kind>:<uuid>` typed ID to its raw `Uuid` for
/// PostgreSQL `uuid` column storage. Returns `None` if the input is not a
/// well-formed typed ID with a parseable UUID segment. The kind segment is
/// not validated here; callers that care MUST check it separately (the kind
/// is canonical bytes of the wire value, see encoding.md §4).
pub fn parse_typed_uuid(typed: &str, expected_kind: &str) -> Option<Uuid> {
    let prefix = format!("ak:{}:", expected_kind);
    let rest = typed.strip_prefix(&prefix)?;
    Uuid::parse_str(rest).ok()
}

/// Kind-agnostic helper: parse the trailing UUID part of any
/// `ak:<kind>:<uuid>` typed ID. Returns `None` if the string has no
/// `ak:<kind>:` prefix or the trailing segment is not a valid UUID.
/// Use this at persistence boundaries where the column is `UUID` but the
/// in-memory value carries the typed wire form.
pub fn typed_uuid_part(typed: &str) -> Option<Uuid> {
    let mut iter = typed.splitn(3, ':');
    let scheme = iter.next()?;
    if scheme != "ak" {
        return None;
    }
    let _kind = iter.next()?;
    let uuid_str = iter.next()?;
    Uuid::parse_str(uuid_str).ok()
}

/// Same as `typed_uuid_part`, but panics with a descriptive message on
/// malformed input.
///
/// SOL-COR-02: this variant is reserved for IDs the server **itself**
/// generated (via the `generate_*` helpers above) or that arrived through an
/// SDK strong-typed producer-allocated newtype (`OperationId`/`SealId::new`/...), where
/// a malformed value would be an internal invariant violation rather than bad
/// client input. The name documents that contract: callers MUST guarantee the
/// value cannot be an unvalidated client string; request parsing must use SDK
/// strong types and return a transport schema error before reaching this helper.
pub fn typed_uuid_part_expect_internal(typed: &str) -> Uuid {
    typed_uuid_part(typed).unwrap_or_else(|| {
        panic!("malformed typed wire ID at internal persistence boundary: {typed:?}")
    })
}

/// Format a raw `Uuid` back to a typed wire ID `ak:<kind>:<uuid>`.
pub fn format_typed_uuid(kind: &str, uuid: &Uuid) -> String {
    format!("ak:{}:{}", kind, uuid)
}

/// Percent-encode reserved characters in a **cell subject** segment.
///
/// Per Arkret v1 (spec encoding §9.5), composite cell subjects are joined
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

    fn fixture_realm_id() -> String {
        let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
            b"soland-http-id-fixture",
        ))
        .unwrap();
        RealmId::from_event_id(&arkret_identifiers::EventId::from_event_digest(&digest).unwrap())
            .to_string()
    }

    #[test]
    fn parse_typed_uuid_roundtrip() {
        let id = generate_operation_id();
        let raw = parse_typed_uuid(&id, "operation").expect("parse");
        let back = format_typed_uuid("operation", &raw);
        assert_eq!(id, back);
    }

    #[test]
    fn parse_typed_uuid_rejects_wrong_kind() {
        let id = generate_operation_id();
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

    #[test]
    fn realm_id_accepts_wire_form() {
        let wire = fixture_realm_id();
        let id = RealmId::new(wire.clone()).expect("realm id parse");
        assert_eq!(id.as_str(), wire);
        assert_eq!(id.to_string(), wire);
        assert_eq!(<RealmId as AsRef<str>>::as_ref(&id), wire.as_str());
    }

    #[test]
    fn realm_id_round_trips_through_serde() {
        let id = RealmId::new(fixture_realm_id()).expect("realm id");
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: RealmId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn realm_id_fromstr_matches_new() {
        let wire = fixture_realm_id();
        let via_fromstr: RealmId = wire.parse().expect("FromStr");
        let via_new = RealmId::new(wire.clone()).expect("new");
        assert_eq!(via_fromstr, via_new);
    }

    #[test]
    fn space_container_id_rejects_bad_kind() {
        assert!(SpaceContainerId::new(fixture_realm_id()).is_err());
        assert!(SpaceContainerId::new("ak:space:01914b2e-7a6d-7cc2-98eb-07c7c9ff4b55").is_err());
        assert!(SpaceContainerId::new("").is_err());
    }
}
