use arkret_identifiers::{DidCoreId, EventId, Hash};
use arkret_models_collaboration::contact_operations::{
    ContactRoundEvidenceBundle, PeerContactMirrorReceipt, PeerContactSubmitOutcome,
    RequestAcceptanceReceipt,
};
use arkret_wire::ActorId;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestSlotState {
    pub owner_id: ActorId,
    pub peer_id: ActorId,
    pub accepted_sequence: u64,
    pub head_digest: Hash,
    /// The slot's accepted Contact Event prefix: every committed Event this
    /// slot's CAS sequence accepted (the owner's requests, the peer requests it
    /// consumed and the owner's responses), strictly ascending by EventId
    /// UTF-8 bytes. It is the exact `cas_revision` / glare
    /// `observed_commit_event_ids` observation of the next CAS
    /// (contact-and-direct-conversation.md section 2), frozen in the same
    /// transaction as the accepting Commit.
    pub accepted_event_refs: Vec<EventId>,
}

impl ContactRequestSlotState {
    /// The slot's accepted prefix extended by `observed`, strictly ascending
    /// and duplicate-free.
    #[must_use]
    pub fn prefix_with(&self, observed: &[EventId]) -> Vec<EventId> {
        contact_event_prefix(self.accepted_event_refs.iter().chain(observed))
    }
}

/// One Contact Event prefix, strictly ascending by EventId UTF-8 bytes.
pub fn contact_event_prefix<'a>(refs: impl IntoIterator<Item = &'a EventId>) -> Vec<EventId> {
    let mut prefix: Vec<EventId> = refs.into_iter().cloned().collect();
    prefix.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    prefix.dedup();
    prefix
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ContactRecord {
    pub requester_id: ActorId,
    pub target_id: ActorId,
    pub contact_round_id: Option<Hash>,
    pub granted_to_target_scopes: Vec<String>,
    pub granted_to_requester_scopes: Vec<String>,
    pub status: String,
    /// Whether the target holder's directional `pending_incoming` head passed
    /// the shared first-contact admission chokepoint. The source holder's
    /// `pending_outgoing` head remains durable even when this is false.
    pub pending_incoming_admitted: bool,
    pub request_event_ref: Option<EventId>,
    /// Station-internal directional request-slot CAS heads. These are not
    /// Contact-round continuity and never cross the wire by themselves.
    pub request_slot_states: Vec<ContactRequestSlotState>,
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
