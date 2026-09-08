use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, DidCoreId, EventId, Hash};
use arkret_models_collaboration::account_lifecycle::ConsentPeer;
use arkret_models_collaboration::contact_operations::{
    ContactRoundEvidenceBundle, PeerContactMirrorReceipt, PeerContactSubmitOutcome,
    RequestAcceptanceReceipt,
};
use arkret_wire::{AccountId, ActorId};
use chrono::{DateTime, Utc};

/// A consent cell is addressed by its subject: `consent_id` is the cell
/// subject of exactly one holder (`consent-model.md` section 3.1), so the
/// durable key is `(holder, cell_id)`. `(peer, consent_scope)` is the intent
/// carried by the cell's dots, not part of its address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentCellKey {
    pub holder_account_id: AccountId,
    pub cell_id: CellRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantDot {
    pub dot: String,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_at: DateTime<Utc>,
}

impl ConsentGrantDot {
    /// Consent windows are closed at both ends: `[not_before, expires_at]`.
    /// `granted_at` records the signed Event time for audit and does not move
    /// either caller-supplied boundary.
    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        self.not_before.is_none_or(|not_before| not_before <= at)
            && self.expires_at.is_none_or(|expires_at| at <= expires_at)
    }
}

/// One holder-private `ak.component.consent.grant.v1` or_set cell.
///
/// `peer` and `consent_scope` are the intent frozen by the cell's first
/// accepted grant; every later dot on the same `consent_id` MUST carry that
/// same intent (`consent-model.md` sections 3.1 and 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentCellRecord {
    pub cell_id: CellRef,
    pub holder_account_id: AccountId,
    pub peer: ConsentPeer,
    pub consent_scope: String,
    pub grant_dots: BTreeMap<String, ConsentGrantDot>,
    pub revoked_dots: BTreeSet<String>,
    pub updated_at: DateTime<Utc>,
}

impl ConsentCellRecord {
    pub fn has_active_grant_at(&self, at: DateTime<Utc>) -> bool {
        self.grant_dots
            .iter()
            .any(|(dot, grant)| !self.revoked_dots.contains(dot) && grant.is_active_at(at))
    }
}

#[cfg(test)]
mod consent_time_tests {
    use super::*;

    fn at(second: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(second, 0).unwrap()
    }

    fn dot() -> ConsentGrantDot {
        ConsentGrantDot {
            dot: "event:0".to_owned(),
            not_before: Some(at(20)),
            expires_at: Some(at(30)),
            granted_at: at(10),
        }
    }

    #[test]
    fn consent_window_uses_signed_closed_boundaries() {
        let grant = dot();
        assert!(!grant.is_active_at(at(19)));
        assert!(grant.is_active_at(at(20)));
        assert!(grant.is_active_at(at(25)));
        assert!(grant.is_active_at(at(30)));
        assert!(!grant.is_active_at(at(31)));
    }

    #[test]
    fn missing_or_revoked_grant_is_no_consent() {
        let holder = AccountId::new(
            DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let mut cell = ConsentCellRecord {
            cell_id: CellRef::new(
                "ak:cell:ak.component.consent.grant.v1:ak:consent:01964137-0000-7000-8000-000000000001"
                    .to_owned(),
            )
            .unwrap(),
            holder_account_id: holder,
            peer: ConsentPeer::Actor {
                actor_id: ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:web:peer.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:peer-station.example").unwrap(),
                )),
            },
            consent_scope: "invite".to_owned(),
            grant_dots: BTreeMap::new(),
            revoked_dots: BTreeSet::new(),
            updated_at: at(10),
        };
        assert!(!cell.has_active_grant_at(at(25)));
        cell.grant_dots.insert("event:0".to_owned(), dot());
        assert!(cell.has_active_grant_at(at(25)));
        cell.revoked_dots.insert("event:0".to_owned());
        assert!(!cell.has_active_grant_at(at(25)));
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestSlotState {
    pub owner_id: ActorId,
    pub peer_id: ActorId,
    pub accepted_sequence: u64,
    pub head_digest: Hash,
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
