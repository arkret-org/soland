//! Contrix v1 protocol-compliant ID generation.
//!
//! All typed object IDs follow the format `cx:<kind>:<uuid>` where `<uuid>`
//! is RFC 9562 UUID version 7 (48-bit Unix-millisecond timestamp + 4-bit
//! version=7 + 12-bit rand_a + 2-bit variant=10 + 62-bit rand_b), serialized
//! as the canonical 36-character lowercase hex form
//! `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` where N ∈ {8,9,a,b}.
//!
//! See `contrix-spec/spec/v1/zh/conformance/encoding.md` §4.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::ErrorCode;

/// Generate a new typed wire ID with the given kind prefix.
///
/// Format: `cx:<kind>:<uuid-v7-36-char-lowercase-hex>`
pub fn generate(kind: &str) -> String {
    format!("cx:{}:{}", kind, Uuid::now_v7())
}

pub fn generate_space_id() -> String {
    generate("space")
}

pub fn generate_realm_id() -> String {
    generate("realm")
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

/// CXP-0007 (spec b7d35be) — generate a new `cx:circle:<uuid7>` identifier
/// for the Circle primitive. Used by `POST /api/v1/circles` to mint the new
/// Circle's typed wire id before submitting `cx.circle.create`.
pub fn generate_circle_id() -> String {
    generate("circle")
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

pub fn generate_read_cursor_id() -> String {
    generate("read_cursor")
}

/// Notification id helper. Spec uses `cx:notification:` (id-kind-registry), not
/// `cx:notification:`. Callers haven't landed yet but the helper is the
/// spec-correct shape.
pub fn generate_notification_id() -> String {
    generate("notif")
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

/// Validate that `s` matches the canonical typed-wire shape
/// `cx:<expected_kind>:<UUIDv7-36-char-canonical>` per encoding.md §4.
///
/// The kind segment MUST equal `expected_kind` byte-for-byte. The trailing
/// UUID MUST parse as a valid RFC 9562 UUID and carry version=7. Anything
/// else returns `ErrorCode::InvalidParam` — the constructor is the only
/// place the wire form is validated; downstream code SHOULD use the typed
/// `RealmId` / `SpaceContainerId` newtypes and accept the validation has
/// already happened.
fn validate_typed_id(s: &str, expected_kind: &str) -> Result<(), ErrorCode> {
    let prefix = format!("cx:{}:", expected_kind);
    let rest = s.strip_prefix(&prefix).ok_or(ErrorCode::InvalidParam)?;
    let parsed = Uuid::parse_str(rest).map_err(|_| ErrorCode::InvalidParam)?;
    if parsed.get_version_num() != 7 {
        return Err(ErrorCode::InvalidParam);
    }
    Ok(())
}

/// Typed wire identifier for a v1 protocol Realm (`cx:realm:<UUIDv7>`).
///
/// Replaces the old untyped `Space.id` security-boundary identifier per
/// Realm/Space inversion (R1.2; see contrix-spec/spec/v1/zh/models/realm-and-space.md).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RealmId(String);

impl RealmId {
    /// Construct from a wire string. Returns `ErrorCode::InvalidParam` if
    /// `s` is not `cx:realm:<UUIDv7-canonical>`.
    pub fn new<S: Into<String>>(s: S) -> Result<Self, ErrorCode> {
        let owned = s.into();
        validate_typed_id(&owned, "realm")?;
        Ok(Self(owned))
    }

    /// Parse a wire string into a `RealmId`. Mirror of `new` for callers
    /// that prefer an explicit `parse` verb.
    pub fn parse(s: &str) -> Result<Self, ErrorCode> {
        Self::new(s.to_owned())
    }

    /// Mint a fresh `RealmId` with a server-side UUIDv7. Use only at
    /// reducer-internal mint sites; wire ingress MUST go through `parse`.
    pub fn generate() -> Self {
        Self(generate_realm_id())
    }

    /// Borrow the canonical wire form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the typed ID and return the owned wire string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RealmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RealmId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for RealmId {
    type Err = ErrorCode;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for RealmId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RealmId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(|_| {
            serde::de::Error::custom(
                "invalid RealmId: expected cx:realm:<UUIDv7-canonical-36-char>",
            )
        })
    }
}

/// Typed wire identifier for a v1 protocol Space-container
/// (`cx:space:<UUIDv7>`).
///
/// Replaces the old untyped `Place.id` per the Realm/Space inversion
/// (R1.2; see realm-and-space.md). The wire `cx:space:` prefix is
/// **preserved** — only the security-boundary semantics moved to
/// `RealmId`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpaceContainerId(String);

impl SpaceContainerId {
    /// Construct from a wire string. Returns `ErrorCode::InvalidParam` if
    /// `s` is not `cx:space:<UUIDv7-canonical>`.
    pub fn new<S: Into<String>>(s: S) -> Result<Self, ErrorCode> {
        let owned = s.into();
        validate_typed_id(&owned, "space")?;
        Ok(Self(owned))
    }

    /// Parse a wire string into a `SpaceContainerId`.
    pub fn parse(s: &str) -> Result<Self, ErrorCode> {
        Self::new(s.to_owned())
    }

    /// Mint a fresh `SpaceContainerId` with a server-side UUIDv7.
    pub fn generate() -> Self {
        Self(generate_space_id())
    }

    /// Borrow the canonical wire form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the typed ID and return the owned wire string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SpaceContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SpaceContainerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for SpaceContainerId {
    type Err = ErrorCode;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SpaceContainerId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SpaceContainerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(|_| {
            serde::de::Error::custom(
                "invalid SpaceContainerId: expected cx:space:<UUIDv7-canonical-36-char>",
            )
        })
    }
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
        assert!(generate_realm_id().starts_with("cx:realm:"));
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
        assert!(generate_request_id().starts_with("cx:request:"));
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
        let id = RealmId::parse(&wire).expect("realm id parse");
        assert_eq!(id.as_str(), wire);
        assert_eq!(id.to_string(), wire);
        assert_eq!(<RealmId as AsRef<str>>::as_ref(&id), wire.as_str());
    }

    #[test]
    fn realm_id_rejects_wrong_kind_and_bad_uuid() {
        let space = generate_space_id();
        assert!(RealmId::parse(&space).is_err());
        assert!(RealmId::parse("cx:realm:not-a-uuid").is_err());
        assert!(RealmId::parse("cx:realm:00000000-0000-0000-0000-000000000000").is_err());
        assert!(RealmId::parse("").is_err());
    }

    #[test]
    fn realm_id_round_trips_through_serde() {
        let id = RealmId::generate();
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: RealmId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn realm_id_fromstr_matches_parse() {
        let wire = generate_realm_id();
        let via_fromstr: RealmId = wire.parse().expect("FromStr");
        let via_parse = RealmId::parse(&wire).expect("parse");
        assert_eq!(via_fromstr, via_parse);
    }

    #[test]
    fn space_container_id_accepts_wire_form() {
        let wire = generate_space_id();
        let id = SpaceContainerId::parse(&wire).expect("space-container id parse");
        assert_eq!(id.as_str(), wire);
    }

    #[test]
    fn space_container_id_rejects_realm_kind() {
        let realm = generate_realm_id();
        assert!(SpaceContainerId::parse(&realm).is_err());
        assert!(SpaceContainerId::parse("cx:place:00000000-0000-7000-8000-000000000000").is_err());
    }

    #[test]
    fn space_container_id_round_trips_through_serde() {
        let id = SpaceContainerId::generate();
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: SpaceContainerId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }
}
