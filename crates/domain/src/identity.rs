use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::contact_operations::{
    ContactBasisEvidenceBundle, PeerContactMirrorReceipt, PeerContactSubmitOutcome,
    RequestAcceptanceReceipt,
};
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
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    pub request_mirror_receipts: Vec<PeerContactMirrorReceipt>,
    pub basis_evidence: Option<ContactBasisEvidenceBundle>,
    pub basis_evidence_history: Vec<ContactBasisEvidenceBundle>,
    pub control_outcomes: Vec<PeerContactSubmitOutcome>,
    pub response_event_ref: Option<String>,
    pub tombstone_event_ref: Option<String>,
    pub message: Option<String>,
    pub peer_service_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
