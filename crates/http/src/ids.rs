//! Arkret v1 protocol-compliant ID generation.
//!
//! All typed object IDs follow the format `ak:<kind>:<uuid>` where `<uuid>`
//! is RFC 9562 UUID version 7 (48-bit Unix-millisecond timestamp + 4-bit
//! version=7 + 12-bit rand_a + 2-bit variant=10 + 62-bit rand_b), serialized
//! as the canonical 36-character lowercase hex form
//! `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` where N ∈ {8,9,a,b}.
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

/// Generators for kinds whose ids the server must NOT mint.
///
/// These five kinds are `id_source: event_derived`: their ids come from the
/// create Event, so a UUIDv7 minted here is rejected by the typed-id
/// constructor and, if it got through, would name an object no receiver can
/// agree with.
///
/// They are still here because five call sites author a whole object graph and
/// wire the ids between its members before any envelope exists — converting
/// them means reordering each into build-then-derive, which is real work per
/// site rather than a rename. Every remaining caller is a known defect; see
/// `arkret-work/work/active/2026-08-05-event-derived-object-id.md`.
///
/// Do not add callers.
pub fn generate_space_id() -> String {
    generate("space")
}

pub fn generate_realm_id() -> String {
    generate("realm")
}

pub fn generate_event_id() -> String {
    generate("event")
}

pub fn generate_relation_id() -> String {
    generate("relation")
}

pub fn generate_circle_id() -> String {
    generate("circle")
}

/// A locally-minted correlation token for a server-side record that stands
/// behind no Event.
///
/// It is deliberately its own kind rather than a fabricated `ak:event:` id:
/// an Event id is content-bound, so minting one would claim an Event that was
/// never authored and that no receiver could resolve.
pub fn generate_local_ref() -> String {
    generate("local_ref")
}

pub fn generate_operation_id() -> String {
    generate("operation")
}

pub fn generate_grant_id() -> String {
    generate("grant")
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

pub fn generate_invite_id() -> String {
    generate("invite")
}

pub fn generate_snapshot_id() -> String {
    generate("snapshot")
}

pub fn generate_report_id() -> String {
    generate("report")
}

pub fn generate_read_cursor_id() -> String {
    generate("read_cursor")
}

/// Notification id helper. Spec uses the full `ak:notification:` kind.
pub fn generate_notification_id() -> String {
    generate("notification")
}

pub fn generate_view_id() -> String {
    generate("view")
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
/// SDK strong-typed newtype (`RealmId`/`OperationId`/`SealId::new`/...), where
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

    #[test]
    fn id_format_is_ak_kind_uuid() {
        let id = generate_space_id();
        assert!(id.starts_with("ak:space:"));
        let uuid_part = &id["ak:space:".len()..];
        // 36-char canonical UUID form: 8-4-4-4-12 hex with dashes
        assert_eq!(uuid_part.len(), 36);
        let parsed = Uuid::parse_str(uuid_part).expect("uuid parse");
        // version 7
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[test]
    fn all_generators_produce_valid_prefixes() {
        assert!(generate_realm_id().starts_with("ak:realm:"));
        assert!(generate_space_id().starts_with("ak:space:"));
        assert!(generate_event_id().starts_with("ak:event:"));
        assert!(generate_operation_id().starts_with("ak:operation:"));
        assert!(generate_relation_id().starts_with("ak:relation:"));
        assert!(generate_grant_id().starts_with("ak:grant:"));
        assert!(generate_invite_id().starts_with("ak:invite:"));
        assert!(generate_snapshot_id().starts_with("ak:snapshot:"));
        assert!(generate_report_id().starts_with("ak:report:"));
        assert!(generate_notification_id().starts_with("ak:notification:"));
        assert!(generate_view_id().starts_with("ak:view:"));
        assert!(generate_request_id().starts_with("ak:request:"));
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

    #[test]
    fn realm_id_accepts_wire_form() {
        let wire = generate_realm_id();
        let id = RealmId::new(wire.clone()).expect("realm id parse");
        assert_eq!(id.as_str(), wire);
        assert_eq!(id.to_string(), wire);
        assert_eq!(<RealmId as AsRef<str>>::as_ref(&id), wire.as_str());
    }

    #[test]
    fn realm_id_rejects_wrong_kind_and_bad_uuid() {
        let space = generate_space_id();
        assert!(RealmId::new(space).is_err());
        // Non-Realm kinds and malformed UUIDs are rejected.
        assert!(RealmId::new("ak:strand:00000000-0000-8000-8000-000000000000").is_err());
        assert!(RealmId::new("ak:realm:not-a-uuid").is_err());
        assert!(RealmId::new("ak:realm:00000000-0000-0000-0000-000000000000").is_err());
        assert!(RealmId::new("").is_err());
    }

    #[test]
    fn realm_id_round_trips_through_serde() {
        let id = RealmId::new(generate_realm_id()).expect("realm id");
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: RealmId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn realm_id_fromstr_matches_new() {
        let wire = generate_realm_id();
        let via_fromstr: RealmId = wire.parse().expect("FromStr");
        let via_new = RealmId::new(wire.clone()).expect("new");
        assert_eq!(via_fromstr, via_new);
    }

    #[test]
    fn space_container_id_accepts_wire_form() {
        let wire = generate_space_id();
        let id = SpaceContainerId::new(wire.clone()).expect("space-container id parse");
        assert_eq!(id.as_str(), wire);
    }

    #[test]
    fn space_container_id_rejects_bad_kind() {
        assert!(SpaceContainerId::new(generate_realm_id()).is_err());
        assert!(SpaceContainerId::new("ak:space:not-a-uuid").is_err());
        assert!(SpaceContainerId::new("").is_err());
    }

    #[test]
    fn space_container_id_round_trips_through_serde() {
        let id = SpaceContainerId::new(generate_space_id()).expect("space id");
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: SpaceContainerId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }
}
