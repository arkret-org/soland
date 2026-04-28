//! Contrix v1 protocol-compliant ID generation.
//!
//! All IDs follow the format `cx:<kind>:<ulid>` where ULID is Crockford base32
//! encoded (26 characters, no i/l/o/u).

use ulid::Ulid;

/// Generate a new ID with the given kind prefix.
///
/// Format: `cx:<kind>:<26-char-crockford-ulid>` (lowercase)
pub fn generate(kind: &str) -> String {
    // ULID uses Crockford base32; spec requires lowercase
    format!("cx:{}:{}", kind, Ulid::new().to_string().to_ascii_lowercase())
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

pub fn generate_commit_id() -> String {
    generate("commit")
}

pub fn generate_entity_id() -> String {
    generate("entity")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_format_is_cx_kind_ulid() {
        let id = generate_space_id();
        assert!(id.starts_with("cx:space:"));
        let ulid_part = &id["cx:space:".len()..];
        assert_eq!(ulid_part.len(), 26);
        // Crockford base32: 0-9, a-h, j-k, m-n, p-t, v-z (no i, l, o, u)
        assert!(ulid_part
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='h' | 'j'..='k' | 'm'..='n' | 'p'..='t' | 'v'..='z')));
    }

    #[test]
    fn all_generators_produce_valid_prefixes() {
        assert!(generate_space_id().starts_with("cx:space:"));
        assert!(generate_event_id().starts_with("cx:event:"));
        assert!(generate_operation_id().starts_with("cx:operation:"));
        assert!(generate_commit_id().starts_with("cx:commit:"));
        assert!(generate_entity_id().starts_with("cx:entity:"));
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
        // ULIDs generated later should sort after earlier ones
        assert!(id2 > id1);
    }
}
