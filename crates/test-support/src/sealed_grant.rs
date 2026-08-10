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
//! So this module builds all three from one input, in the order the protocol
//! does:
//!
//! 1. author the `ak.capability.grant` Event and persist it as a `CanonicalEventRecord`;
//! 2. take the Move digest **from that Event's canonical digest**, never from a literal;
//! 3. seal the projected cell op under that digest, then refresh the runtime authz index *from the
//!    durable cell* rather than inserting a second copy.
//!
//! A fixture that only needs to read grant history, and will never be asked to
//! produce a successor Seal, can use [`seed_historical_capability_grant`] —
//! named so the difference is visible at the call site rather than discovered
//! later by a notary.

use std::collections::BTreeMap;

use arkret_identifiers::{CellRef, DidFullId, EventId, GrantId, Hash, Hlc, RealmId, SealId};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::compute_state_root;
use arkret_wire::{Seal, SealBasis};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland_http::state::AppState;
use soland_services::projection::ProjectionService;

use crate::AppStateTestExt as _;

/// The notary identity fixture grant Seals are signed with.
const FIXTURE_NOTARY_SEED: [u8; 32] = [0x21; 32];
const FIXTURE_NOTARY_DID: &str = "did:web:alice.example";
const FIXTURE_NOTARY_VERIFICATION_METHOD: &str = "did:web:alice.example#extension-test-notary";

/// What a caller wants granted. Everything the protocol requires is derived;
/// nothing here is a digest or an id the caller has to invent.
pub struct CapabilityGrantFixture<'a> {
    pub realm_id: &'a str,
    pub grant_id: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub actions: &'a [&'a str],
    /// Resource selectors, in the spec's `resources[]` shape. Realm-wide is the
    /// common case; pass it explicitly so the scope is visible in the test.
    pub resources: Value,
    /// Grant constraints, or `Value::Array(vec![])` for none.
    pub constraints: Value,
}

impl<'a> CapabilityGrantFixture<'a> {
    /// A Realm-wide, unconstrained grant — the shape most fixtures want.
    pub fn realm_wide(
        realm_id: &'a str,
        grant_id: &'a str,
        issuer: &'a str,
        subject: &'a str,
        actions: &'a [&'a str],
    ) -> Self {
        Self {
            realm_id,
            grant_id,
            issuer,
            subject,
            actions,
            resources: json!([{
                "kind": "realm",
                "realm_id": realm_id,
                "match_scope": "realm_wide"
            }]),
            constraints: json!([]),
        }
    }
}

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

/// Seed `fixture` as an accepted, notarizable capability grant.
///
/// `predecessors` are the Seal ids this Seal extends; pass an empty slice for a
/// genesis basis. The returned Seal can carry a successor because the Event
/// behind its covered Move actually exists.
pub async fn seed_sealed_capability_grant(
    state: &AppState,
    fixture: CapabilityGrantFixture<'_>,
    predecessors: Vec<SealId>,
) -> SealedCapabilityGrant {
    let realm = RealmId::new(fixture.realm_id.to_owned()).expect("fixture Realm id");
    let body = grant_body(&fixture);

    // 1. The Event is authored first: its canonical digest IS the Move digest, so there is no
    //    opportunity to invent one.
    let event = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::CapabilityGrant.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        arkret_wire::DidCoreId::from(
            arkret_wire::project_full_id_to_core_id(
                &DidFullId::new(fixture.issuer.to_owned()).expect("fixture grant issuer DID"),
            )
            .expect("fixture grant issuer projection"),
        ),
        0,
        fixture_hlc(fixture.grant_id),
        json!({ "object": body.clone() }),
    )
    .expect("fixture capability grant Event");
    let canonical_digest = event.event_digest().expect("fixture Event digest");
    let move_id = Hash::new(canonical_digest.clone()).expect("fixture Move digest");

    persist_canonical_event(state, &event, fixture.realm_id, &canonical_digest).await;

    // 2. The cell op is tagged with that same digest.
    let (cell, op) = grant_cell_op(fixture.grant_id, fixture.issuer, &move_id, body);
    let state_root = state_root_for(&realm, &cell, &op);

    let signer = Ed25519PayloadSigner::from_did_key_seed(
        FIXTURE_NOTARY_SEED,
        DidFullId::new(FIXTURE_NOTARY_DID.to_owned()).expect("fixture notary DID"),
        arkret_wire::DidUrl::new(FIXTURE_NOTARY_VERIFICATION_METHOD)
            .expect("fixture notary verification method"),
    );
    let seal = Seal::sign_single(
        realm.clone(),
        predecessors,
        vec![move_id.clone()],
        state_root,
        fixture_hlc(&format!("{}:seal", fixture.grant_id)),
        &signer,
    )
    .expect("fixture grant Seal");

    state.test_put_seal(&seal).expect("fixture grant Seal put");
    state
        .test_append_sealed_effects(&realm, &seal.id, &[(cell, op)])
        .expect("fixture grant sealed effects");
    // 3. The runtime index is DERIVED from the durable cell. Inserting a separately-built `Grant`
    //    here would be a second source of truth that can disagree with what the cell projects.
    state.test_refresh_grant_from_sealed_cells(&realm, fixture.grant_id);

    SealedCapabilityGrant {
        grant_id: fixture.grant_id.to_owned(),
        event_id: event.event_id.clone(),
        move_id,
        seal_id: seal.id.clone(),
        seal_basis: seal.seal_basis(),
    }
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
        .event_digest()
        .expect("accepted capability grant Event digest");
    assert_eq!(canonical_digest, record.canonical_digest);
    let move_id = Hash::new(canonical_digest).expect("fixture Move digest");
    let writes = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
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
    assert_eq!(direct.cell, expected_cell);
    let op = IssuedOp {
        issuer: event.actor_id.clone(),
        op: arkret_state::lattice::SealedOp::new(move_id.clone(), direct.op.clone()),
    };
    let state_root = state_root_for(&realm, &expected_cell, &op);

    let signer = Ed25519PayloadSigner::from_did_key_seed(
        FIXTURE_NOTARY_SEED,
        DidFullId::new(FIXTURE_NOTARY_DID.to_owned()).expect("fixture notary DID"),
        arkret_wire::DidUrl::new(FIXTURE_NOTARY_VERIFICATION_METHOD)
            .expect("fixture notary verification method"),
    );
    let seal = Seal::sign_single(
        realm.clone(),
        predecessors,
        vec![move_id.clone()],
        state_root,
        fixture_hlc_after(event.created_at, &format!("{grant_id}:accepted-seal")),
        &signer,
    )
    .expect("fixture accepted grant Seal");

    state
        .test_put_seal(&seal)
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

/// Seed a grant for tests that only read authorization history.
///
/// Deliberately named: this writes the cell and the Seal but **no** Event, so
/// the Seal is not notarizable and must never be handed to a successor-Seal
/// path. Use [`seed_sealed_capability_grant`] anywhere the Seal is part of the
/// scenario rather than just its projected state.
pub fn seed_historical_capability_grant(
    state: &AppState,
    fixture: CapabilityGrantFixture<'_>,
) -> SealedCapabilityGrant {
    let realm = RealmId::new(fixture.realm_id.to_owned()).expect("fixture Realm id");
    let body = grant_body(&fixture);
    let move_id = historical_move_id(fixture.grant_id);
    let (cell, op) = grant_cell_op(fixture.grant_id, fixture.issuer, &move_id, body);
    let state_root = state_root_for(&realm, &cell, &op);

    let signer = Ed25519PayloadSigner::from_did_key_seed(
        FIXTURE_NOTARY_SEED,
        DidFullId::new(FIXTURE_NOTARY_DID.to_owned()).expect("fixture notary DID"),
        arkret_wire::DidUrl::new(FIXTURE_NOTARY_VERIFICATION_METHOD)
            .expect("fixture notary verification method"),
    );
    let seal = Seal::sign_single(
        realm.clone(),
        Vec::new(),
        vec![move_id.clone()],
        state_root,
        fixture_hlc(&format!("{}:historical", fixture.grant_id)),
        &signer,
    )
    .expect("fixture historical grant Seal");

    state
        .test_put_seal(&seal)
        .expect("fixture historical grant Seal put");
    state
        .test_append_sealed_effects(&realm, &seal.id, &[(cell, op)])
        .expect("fixture historical grant sealed effects");
    state.test_refresh_grant_from_sealed_cells(&realm, fixture.grant_id);

    SealedCapabilityGrant {
        grant_id: fixture.grant_id.to_owned(),
        // No Event exists; the id is the historical marker itself.
        event_id: EventId::new(format!(
            "ak:event:{}",
            "00000000-0000-7000-8000-000000000000"
        ))
        .expect("historical marker event id"),
        move_id,
        seal_id: seal.id.clone(),
        seal_basis: seal.seal_basis(),
    }
}

fn grant_body(fixture: &CapabilityGrantFixture<'_>) -> Value {
    json!({
        "grant_id": fixture.grant_id,
        "schema": arkret_wire::SchemaId::CAPABILITY_V1,
        "realm_id": fixture.realm_id,
        "issuer": fixture.issuer,
        "subject": fixture.subject,
        "actions": fixture.actions,
        "resources": fixture.resources,
        "constraints": fixture.constraints,
        "capability_action_registry_digest":
            arkret_policy::current_capability_action_registry_digest()
                .expect("embedded capability action registry digest"),
        "issued_at": "2026-01-01T00:00:00.000Z"
    })
}

fn grant_cell_op(grant_id: &str, issuer: &str, move_id: &Hash, body: Value) -> (CellRef, IssuedOp) {
    let cell = CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .expect("capability grant cell ref");
    let op = IssuedOp {
        issuer: arkret_wire::DidCoreId::from(
            arkret_wire::project_full_id_to_core_id(
                &DidFullId::new(issuer.to_owned()).expect("fixture grant issuer DID"),
            )
            .expect("fixture grant issuer projection"),
        ),
        op: arkret_state::lattice::SealedOp::new(
            move_id.clone(),
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Add,
                tag: Some(move_id.to_string()),
                value: Some(body),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    };
    (cell, op)
}

fn state_root_for(realm: &RealmId, cell: &CellRef, op: &IssuedOp) -> Hash {
    let registry = ProjectionService::sdk_cell_registry();
    let binding = registry
        .resolve(realm, cell)
        .expect("capability grant cell family is registered");
    let joined = arkret_state::join_cell(binding.lattice.as_ref(), cell, std::slice::from_ref(op));
    compute_state_root(&BTreeMap::from([(cell.clone(), joined)])).expect("fixture grant state root")
}

async fn persist_canonical_event(
    state: &AppState,
    event: &arkret_wire::Event,
    realm_id: &str,
    canonical_digest: &str,
) {
    let envelope = serde_json::to_value(event).expect("fixture Event envelope");
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            actor_seq: event.actor_seq,
            realm_id: Some(realm_id.to_owned()),
            kind: arkret_wire::EventKind::CapabilityGrant.as_str().to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: canonical_digest.to_owned(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event
                    .digest_payload()
                    .expect("fixture Event digest payload"),
            )
            .expect("fixture Event canonical bytes"),
            envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .expect("fixture canonical Event put");
}

/// Deterministic per-fixture HLC so repeated seeding is stable.
fn fixture_hlc(seed: &str) -> Hlc {
    let digest = Sha256::digest(seed.as_bytes());
    Hlc::new(format!(
        "0196419b{:04x}-0000-{:08x}",
        u16::from_be_bytes([digest[0], digest[1]]),
        u32::from_be_bytes([digest[2], digest[3], digest[4], digest[5]]),
    ))
    .expect("fixture HLC")
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

/// The historical-view Move digest. It is derived from the grant id rather than
/// from an Event precisely because there is no Event.
fn historical_move_id(grant_id: &str) -> Hash {
    let digest = Sha256::digest(format!("historical-capability-grant:{grant_id}").as_bytes());
    Hash::new(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
    .expect("historical Move digest")
}
