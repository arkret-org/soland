use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentCellKey {
    pub holder: String,
    pub peer: String,
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantDot {
    pub dot: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentCellRecord {
    pub holder: String,
    pub peer: String,
    pub scope: String,
    pub cell_id: String,
    pub requested_at: Option<DateTime<Utc>>,
    pub grant_dots: BTreeMap<String, ConsentGrantDot>,
    pub revoked_dots: BTreeSet<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ContactRecord {
    pub requester: String,
    pub target: String,
    pub basis_id: Option<String>,
    pub version: Option<u64>,
    pub granted_to_target_scopes: Vec<String>,
    pub granted_to_requester_scopes: Vec<String>,
    pub status: String,
    pub request_event_ref: Option<String>,
    pub response_event_ref: Option<String>,
    pub tombstone_event_ref: Option<String>,
    pub message: Option<String>,
    pub peer_service_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Returns the deterministic principal-control Realm identifier for a DID.
pub fn principal_control_realm_for_did(principal_did: &str) -> String {
    arkret_identifiers::principal_control_realm_id(principal_did).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_control_realm_is_stable_and_did_scoped() {
        let alice = principal_control_realm_for_did("did:web:alice.example");
        assert_eq!(
            alice,
            principal_control_realm_for_did("did:web:alice.example")
        );
        assert_ne!(
            alice,
            principal_control_realm_for_did("did:web:bob.example")
        );
        assert!(alice.starts_with("ak:realm:"));
        assert_eq!(alice.len(), "ak:realm:".len() + 44);
    }
}
