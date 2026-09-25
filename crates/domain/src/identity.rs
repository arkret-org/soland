use std::collections::BTreeMap;

use arkret_identifiers::{ConsentId, DidCoreId, EventId, Hash};
use arkret_models_collaboration::contact_operations::{
    ContactRoundEvidenceBundle, PeerContactMirrorReceipt, PeerContactSubmitOutcome,
    RequestAcceptanceReceipt,
};
use arkret_models_collaboration::events_payloads::ConsentPeer;
use arkret_wire::{AccountId, ActorId};
use chrono::{DateTime, Utc};

/// Durable address of one holder's consent grant set.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentGrantKey {
    pub holder_account_id: AccountId,
    pub consent_id: ConsentId,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Local audit/read mirror of confirmed consent grants.
/// Retained revoked tags are audit history, not protocol tombstone state.
///
/// `peer` and `consent_scope` are the intent frozen by the first
/// accepted grant; every later dot on the same `consent_id` MUST carry that
/// same intent (`consent-model.md` sections 3.1 and 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantRecord {
    pub consent_id: ConsentId,
    pub holder_account_id: AccountId,
    pub peer: ConsentPeer,
    pub consent_scope: String,
    /// Current Seq-confirmed tagged set, including signed validity windows.
    pub active_grants: BTreeMap<String, ConsentGrantDot>,
    /// Query audit only; never an authorization input or a join tombstone set.
    pub revoked_grants: BTreeMap<String, ConsentGrantDot>,
    pub updated_at: DateTime<Utc>,
}

impl ConsentGrantRecord {
    /// Apply an exact committed removal to the active set. The returned audit
    /// is retained only for the holder's existing consent query contract.
    pub fn revoke_grants(&mut self, tags: impl IntoIterator<Item = String>) {
        for tag in tags {
            if let Some(grant) = self.active_grants.remove(&tag) {
                self.revoked_grants.insert(tag, grant);
            }
        }
    }

    pub fn has_active_grant_at(&self, at: DateTime<Utc>) -> bool {
        self.active_grants
            .values()
            .any(|grant| grant.is_active_at(at))
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
        let mut grants = ConsentGrantRecord {
            consent_id: ConsentId::new(
                "ak:consent:01964137-0000-7000-8000-000000000001".to_owned(),
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
            active_grants: BTreeMap::new(),
            revoked_grants: BTreeMap::new(),
            updated_at: at(10),
        };
        assert!(!grants.has_active_grant_at(at(25)));
        grants.active_grants.insert("event:0".to_owned(), dot());
        assert!(grants.has_active_grant_at(at(25)));
        grants.revoke_grants(["event:0".to_owned()]);
        assert!(!grants.has_active_grant_at(at(25)));
        assert!(grants.active_grants.is_empty());
        assert_eq!(grants.revoked_grants.len(), 1);
        // Audit retention does not prevent a separately signed regrant.
        let mut regrant = dot();
        regrant.dot = "later:0".to_owned();
        grants.active_grants.insert(regrant.dot.clone(), regrant);
        assert!(grants.has_active_grant_at(at(25)));
        assert_eq!(grants.revoked_grants.len(), 1);
    }
}

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
