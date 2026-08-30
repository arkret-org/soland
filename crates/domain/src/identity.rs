use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, DidCoreId, EventId, Hash};
use arkret_models_collaboration::contact_operations::{
    ContactRoundEvidenceBundle, PeerContactMirrorReceipt, PeerContactSubmitOutcome,
    RequestAcceptanceReceipt,
};
use arkret_wire::ActorId;
use chrono::{DateTime, Utc};

/// A consent cell is addressed by its subject: `consent_id` is the cell
/// subject of exactly one holder (`consent-model.md` section 3.1), so the
/// durable key is `(holder, cell_id)`. `(peer, consent_scope)` is the intent
/// carried by the cell's dots, not part of its address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentCellKey {
    pub holder_principal_id: DidCoreId,
    pub cell_id: CellRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantDot {
    pub dot: String,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_at: DateTime<Utc>,
}

/// One holder-private `ak.component.consent.grant.v1` or_set cell.
///
/// `peer` and `consent_scope` are the intent frozen by the cell's first
/// accepted grant; every later dot on the same `consent_id` MUST carry that
/// same intent (`consent-model.md` sections 3.1 and 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentCellRecord {
    pub cell_id: CellRef,
    pub holder_principal_id: DidCoreId,
    pub peer_principal_id: DidCoreId,
    pub consent_scope: String,
    pub grant_dots: BTreeMap<String, ConsentGrantDot>,
    pub revoked_dots: BTreeSet<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ContactRecord {
    pub requester_id: ActorId,
    pub target_id: ActorId,
    pub contact_round_id: Option<Hash>,
    pub version: Option<u64>,
    pub granted_to_target_scopes: Vec<String>,
    pub granted_to_requester_scopes: Vec<String>,
    pub status: String,
    pub request_event_ref: Option<EventId>,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    pub request_mirror_receipts: Vec<PeerContactMirrorReceipt>,
    pub contact_round_evidence: Option<ContactRoundEvidenceBundle>,
    pub contact_round_evidence_history: Vec<ContactRoundEvidenceBundle>,
    pub control_outcomes: Vec<PeerContactSubmitOutcome>,
    pub response_event_ref: Option<EventId>,
    pub tombstone_event_ref: Option<EventId>,
    pub message: Option<String>,
    pub peer_host_id: Option<DidCoreId>,
    /// Exact carrier retained from the verified introduction or shared-Realm
    /// Station route. It is re-verified before routing and is not a cached
    /// endpoint authority.
    pub peer_service_resolution: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
