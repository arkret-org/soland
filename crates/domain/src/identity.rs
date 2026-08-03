use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};

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

#[derive(Clone, Debug)]
pub struct DirectConversationBindingRecord {
    pub participants_unordered: Vec<String>,
    pub realm_id: String,
    pub main_strand_id: String,
    pub binding_event_ref: String,
    pub state: String,
    /// Durable coordinator-only reservation data for an unfinished authoring
    /// stage. Active canonical bindings never depend on this field.
    pub authoring_context: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Returns the deterministic principal-control Realm identifier for a DID.
pub fn principal_control_realm_for_did(principal_did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ak:realm:principal-control:v1:");
    hasher.update(principal_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let group = |slice: &[u8]| -> String {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!(
        "ak:realm:{}-{}-{}-{}-{}",
        group(&bytes[0..4]),
        group(&bytes[4..6]),
        group(&bytes[6..8]),
        group(&bytes[8..10]),
        group(&bytes[10..16]),
    )
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
    }
}
