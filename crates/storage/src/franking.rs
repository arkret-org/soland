//! Durable local work for publishing an already received encrypted Event's
//! existing `ak.moderation.franking_proof` carrier. Nothing here is wire.

use arkret_wire::{DidCoreId, Event, EventId, RealmId};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct PendingFrankingProof {
    pub realm_id: RealmId,
    pub target_event_id: EventId,
    pub received_by: DidCoreId,
    pub received_at: DateTime<Utc>,
    /// Fixed once. A retry never changes the signed Event or its nonce.
    pub prepared_event: Option<Event>,
    /// The receiving service method resolved and verified at `received_at`.
    pub verification_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct PreparedFrankingProof {
    pub realm_id: RealmId,
    pub target_event_id: EventId,
    pub received_by: DidCoreId,
    pub event: Event,
    pub verification_key: Vec<u8>,
}
