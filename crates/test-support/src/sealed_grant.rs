//! Seed a capability grant as an accepted protocol fact.
//!
//! A grant is not a row a fixture can invent. `capabilities.md` §12.1 makes it
//! an or_set add on `ak.component.capability.grant.v1`, projected from an
//! accepted `ak.capability.grant` Control Move, and the Seal that covers that
//! Move names the Move's digest — which is the canonical digest of the Event
//! that produced it.
//!
//! Fixtures used to assemble those three pieces by hand, and the seam always
//! opened in the same place: the sealed cell and the Seal were written, but no
//! `CanonicalEvent` was, and the "Move digest" was a literal
//! (`sha256:4141…`). The state looks right to a reader of the cell log and to
//! the runtime authz index, so the tests pass — until something asks the Seal
//! to be a real Seal. Feed such a fixture to a successor Seal and NotaryWorker
//! correctly refuses it: the completeness root cannot be recomputed over a
//! covered digest that names no Event.
//!
//! So this module never authors the pieces separately. It starts from the
//! `ak.capability.grant` Event the formal admission path already accepted and,
//! in the order the protocol does:
//!
//! 1. take the Move digest **from that Event's canonical digest**, never from a literal;
//! 2. seal the projected cell op under that digest, then refresh the runtime authz index *from the
//!    durable cell* rather than inserting a second copy.

use std::collections::BTreeMap;

use arkret_identifiers::{CellRef, EventId, GrantId, Hash, Hlc, RealmId, SealId};
use arkret_state::lattice::CellState;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::compute_state_root;
use arkret_wire::{Seal, SealBasis};
use sha2::{Digest, Sha256};
use soland_http::state::AppState;
use soland_services::projection::ProjectionService;

use crate::AppStateTestExt as _;

/// What the fixture put on record. Every id here is real: the Seal covers
/// `move_id`, and `move_id` is the canonical digest of the stored `event_id`.
#[derive(Clone, Debug)]
pub struct SealedCapabilityGrant {
    pub grant_id: String,
    pub event_id: EventId,
    pub move_id: Hash,
    pub seal_id: SealId,
    pub seal_basis: SealBasis,
}

/// Seal the canonical create Event that already produced `grant_id`.
///
/// Formal install/admission paths have already authored and accepted the
/// capability Event. A test that needs a frozen CBA view must seal that exact
/// Move; authoring a second Event with the same object id creates two OR-set
/// variants and correctly makes the grant conflict/inactive.
pub async fn seal_accepted_capability_grant(
    state: &AppState,
    realm_id: &str,
    grant_id: &str,
    predecessors: Vec<SealId>,
) -> SealedCapabilityGrant {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let grant = GrantId::new(grant_id.to_owned()).expect("fixture grant id");
    let event_id = EventId::from_token_bytes(grant.token_bytes())
        .expect("Event-derived grant token retypes as an Event id");
    let record = state
        .test_persistence()
        .events()
        .get(event_id.as_str())
        .await
        .expect("fixture canonical Event lookup")
        .expect("accepted capability grant producer Event");
    let event: arkret_wire::Event =
        serde_json::from_value(record.envelope).expect("accepted capability grant envelope");
    assert_eq!(
        event.kind.as_str(),
        arkret_wire::EventKind::CapabilityGrant.as_str()
    );
    assert_eq!(event.realm_id, realm);
    assert_eq!(event.event_id, event_id);

    let canonical_digest = event
        .event_digest_with_digest_suite(record.digest_suite)
        .expect("accepted capability grant Event digest");
    assert_eq!(canonical_digest, record.canonical_digest);
    let move_id = Hash::new(canonical_digest).expect("fixture Move digest");
    let writes = state
        .test_projection()
        .lock()
        .project_registered_cell_writes(&event, record.digest_suite)
        .expect("accepted capability grant registered projection");
    let [write] = writes.as_slice() else {
        panic!("capability grant must project exactly one cell write");
    };
    let direct = write
        .as_direct()
        .expect("capability grant projection is a direct cell write");
    let expected_cell = CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .expect("capability grant cell ref");
    assert_eq!(direct.cell_id, expected_cell);
    let projected_op = direct.op.clone();
    let op = IssuedOp {
        issuer_id: event.actor_id.clone(),
        op: arkret_state::lattice::SealedOp::new(move_id.clone(), projected_op),
    };
    let state_root = state_root_for(state, &realm, &predecessors, &expected_cell, &op);

    let signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
        state.notary_signing_key().to_bytes(),
        state.service_did(),
        state.service_verification_method("notary-key").unwrap(),
    );
    let seal = Seal::sign_single(
        realm.clone(),
        predecessors,
        vec![move_id.clone()],
        state_root,
        fixture_hlc_after(event.created_at, &format!("{grant_id}:accepted-seal")),
        arkret_canonical::DigestSuite::Sha256,
        &signer,
    )
    .expect("fixture accepted grant Seal");

    state
        .test_put_seal(&seal, arkret_canonical::DigestSuite::Sha256)
        .expect("fixture accepted grant Seal put");
    state
        .test_append_sealed_effects(&realm, &seal.id, &[(expected_cell, op)])
        .expect("fixture accepted grant sealed effects");
    state.test_refresh_grant_from_sealed_cells(&realm, grant_id);

    SealedCapabilityGrant {
        grant_id: grant_id.to_owned(),
        event_id,
        move_id,
        seal_id: seal.id.clone(),
        seal_basis: seal.seal_basis(),
    }
}

fn state_root_for(
    state: &AppState,
    realm: &RealmId,
    predecessors: &[SealId],
    cell: &CellRef,
    op: &IssuedOp,
) -> Hash {
    let registry = ProjectionService::sdk_cell_registry();
    let binding = registry
        .resolve(realm, cell)
        .expect("capability grant cell family is registered");
    let mut post_state = if predecessors.is_empty() {
        BTreeMap::new()
    } else {
        state
            .test_effective_state_at(predecessors, realm)
            .expect("fixture predecessor Seal state is valid")
    };
    insert_new_grant_cell(
        &mut post_state,
        cell.clone(),
        arkret_state::join_cell(binding.lattice.as_ref(), cell, std::slice::from_ref(op)),
    );
    compute_state_root(&post_state, arkret_canonical::DigestSuite::Sha256)
        .expect("fixture grant post-state root")
}

fn insert_new_grant_cell(
    post_state: &mut BTreeMap<CellRef, CellState>,
    cell: CellRef,
    joined: CellState,
) {
    assert!(
        !post_state.contains_key(&cell),
        "the event-derived grant cell is already present at the predecessor frontier"
    );
    post_state.insert(cell, joined);
}

/// A deterministic HLC whose physical component is strictly after an
/// already-authored Event. Historical capability evaluation uses the Seal's
/// timestamp, so a fixed epoch before the grant's `issued_at` would make an
/// otherwise valid grant correctly appear inactive.
fn fixture_hlc_after(created_at: chrono::DateTime<chrono::Utc>, seed: &str) -> Hlc {
    let digest = Sha256::digest(seed.as_bytes());
    let unix_ms = created_at.timestamp_millis().max(0) as u64 + 1;
    Hlc::new(format!(
        "{unix_ms:012x}-0000-{:08x}",
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]),
    ))
    .expect("fixture post-Event HLC")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant_cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.capability.grant.v1:ak:grant:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
                .to_owned(),
        )
        .unwrap()
    }

    #[test]
    fn event_derived_grant_cell_is_inserted_once() {
        let cell = grant_cell();
        let joined = CellState::Value(serde_json::json!([{"value": "grant"}]));
        let mut post_state = BTreeMap::new();

        insert_new_grant_cell(&mut post_state, cell.clone(), joined.clone());

        assert_eq!(post_state.get(&cell), Some(&joined));
    }

    #[test]
    #[should_panic(
        expected = "the event-derived grant cell is already present at the predecessor frontier"
    )]
    fn predecessor_cannot_replay_the_event_derived_grant_cell() {
        let cell = grant_cell();
        let joined = CellState::Value(serde_json::json!([{"value": "grant"}]));
        let mut post_state = BTreeMap::from([(cell.clone(), joined.clone())]);

        insert_new_grant_cell(&mut post_state, cell, joined);
    }
}
