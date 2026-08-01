//! The accepted governance basis an integration-test Event has to cite.
//!
//! `event-auth-state-resolution.md` §4(1) makes a data-plane Event a DataEvent
//! (`seal_ref` + `auth_context`, never `seal_basis`) and §5 makes a
//! control-plane Event a Control Move (`seal_basis`, never `seal_ref` /
//! `auth_context`). Both forms name a Seal, and for a DataEvent that Seal is
//! not a token: §4.1(3) / §4.3(2) make the verifier resolve the actor's whole
//! effective capability set from the state the Seal covers. soland does exactly
//! that (`capability_refs.rs::data_event_state_at_seal_ref` →
//! `arkret_state::effective_state_at`, which joins the cell log filtered by the
//! Seal's covered Control-Move digests), so an empty Seal authorizes nothing.
//!
//! A fixture Realm that is seeded straight into `AppState` — rather than
//! bootstrapped through `ak.realm.create` over HTTP — therefore has to be given
//! a genuinely sealed genesis unit before any Event it hosts can be admitted.
//! That is what this module builds:
//!
//! 1. the registered `ak.component.realm.authority_root.v1` singleton of `realm-and-space.md` §2.5
//!    — the only authority genesis establishes, whose controller holds effective `ak.realm.owner`;
//! 2. the owner's own first governance grant
//!    ([`soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS`]), `issuer == subject`,
//!    one Realm-wide resource selector, a typed `realm_root` authority ref, and the embedded
//!    `capability-action-registry.json` digest;
//! 3. an explicit content grant carrying only requested data-plane actions not already covered by
//!    the owner bootstrap grant;
//! 4. the `ak.component.covered_seals.v1` accumulator of `encryption-and-audit.md` §2.5.2, so an
//!    MLS-backed DataEvent clears the governance-binding gate.
//!
//! (1)-(3) and (4) land in **two** Seals, `S0` then `S1`, because one Seal
//! cannot hold both: (4)'s or-set element value is the Seal ref that (1)-(3)
//! were admitted under, and §2.5.1's `covered_seal_refs` visibility constraint
//! (plus plain content addressing — `S.id` transitively commits every Move in
//! `covered_set(S)`) means no Move can ever name the Seal that admits it. The
//! basis used to put all four in one Seal with (4) naming that Seal's own id: a
//! state no reducer can produce, whose `state_root` had to be computed with (4)
//! excluded. Every E2EE fixture then cleared the §2.5.2 gate on evidence a live
//! Realm can never present.
//!
//! The basis is keyed by `(realm_id, subject, data-plane actions)`, and that is
//! what keeps both Seals self-consistent: `S0.predecessor_refs` stays empty so
//! its `control_event_set_root` is exactly its `delta`'s root, `S1` declares the
//! cumulative root over `covered_set(S0) ∪ {(4)}`, and both `state_root`s are
//! the genuine [`compute_state_root`] of every op the Seal covers — (4)
//! included, now that its value is fixed before `S1` is hashed. A single
//! per-Realm Seal would have to grow its covered set every time a new actor
//! appeared, and every such growth invalidates both roots.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use arkret_identifiers::{CellRef, Did, Hash, Hlc, RealmId, SealId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::compute_state_root;
use arkret_wire::{Seal, SealBasis};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland_http::state::AppState;
use soland_services::projection::ProjectionService;

use crate::AppStateTestExt as _;

/// The notary key every fixture basis Seal is signed with.
const FIXTURE_NOTARY_SEED: [u8; 32] = [0x53; 32];
const FIXTURE_NOTARY_DID: &str = "did:web:alice.example";
const FIXTURE_NOTARY_VERIFICATION_METHOD: &str = "did:web:alice.example#fixture-notary";
const FIXTURE_BASIS_HLC: &str = "0196419b0000-0000-51c0a1ed";
/// The MLS group id the fixture Realm basis seeds `covered_seals_cell` under.
/// The cell is keyed by the group id (the registered `payload.mls_group_id`
/// subject) — never by the Realm id — so E2EE fixture ciphertexts consuming
/// this basis MUST carry this value in `encrypted_content.group_id`.
pub const FIXTURE_MLS_GROUP_ID: &str = "fixtureMlsGroup01";

/// One fixture Realm's accepted governance basis for one subject.
///
/// Two Seals, because one cannot express this state: the accumulator write of
/// (4) names the Seal that carries (1)-(3), and a Move can only name a Seal that
/// already existed when it was authored.
#[derive(Clone)]
struct RealmBasis {
    /// `S0` — the governance unit (1)-(3). Its Moves are what put the fixture
    /// Realm's capability / authority cells into accepted control state, so
    /// `encryption-and-audit.md` §2.5.2 puts `S0` in `M`.
    governance_seal: Seal,
    governance_ops: Vec<(CellRef, IssuedOp)>,
    /// `S1` — the head, built on `S0`, carrying the `covered_seals_cell` write
    /// that attests `S0`. Fixture Events cite this one.
    seal: Seal,
    ops: Vec<(CellRef, IssuedOp)>,
}

type BasisKey = (String, String, String, Vec<String>);

static REALM_BASES: LazyLock<Mutex<BTreeMap<BasisKey, RealmBasis>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn realm_basis(
    realm_id: &str,
    subject: &str,
    notary: &str,
    data_plane_actions: &[&str],
) -> RealmBasis {
    let key = (
        realm_id.to_owned(),
        subject.to_owned(),
        notary.to_owned(),
        data_plane_actions
            .iter()
            .map(|action| (*action).to_owned())
            .collect(),
    );
    REALM_BASES
        .lock()
        .expect("fixture basis cache")
        .entry(key)
        .or_insert_with(|| build_realm_basis(realm_id, subject, notary, data_plane_actions))
        .clone()
}

/// The Seal a fixture Event names in `seal_ref` / `seal_basis`.
pub fn realm_basis_seal(realm_id: &str, subject: &str, data_plane_actions: &[&str]) -> Seal {
    realm_basis(realm_id, subject, &fixture_notary_did(), data_plane_actions).seal
}

/// The service DID every fixture Realm designates as its notary.
///
/// A Control Move submitted to this service has its proposal receipt minted
/// here, and `NotaryWorker::authority_set_ref_for_events` only issues one when
/// the Realm's notary profile names the service.
fn fixture_notary_did() -> String {
    crate::app_state(crate::app_config()).service_id().clone()
}

/// The single-leaf `seal_basis` a Control Move of `realm_id` cites.
pub fn realm_basis_seal_basis(
    realm_id: &str,
    subject: &str,
    data_plane_actions: &[&str],
) -> SealBasis {
    let seal = realm_basis_seal(realm_id, subject, data_plane_actions);
    SealBasis {
        leaves: vec![seal.id],
        control_event_set_root: seal.control_event_set_root,
        state_root: seal.state_root,
    }
}

/// Put the genesis unit of `realm_id` in place for `subject`.
///
/// A DataEvent `seal_ref` MUST resolve to a verified control-plane Seal of the
/// same Realm (`event-auth-state-resolution.md` §4.3(1)) **and** the governance
/// state that Seal covers MUST authorize the Event's derived writes, so both
/// the Seal object and its sealed cell effects have to exist before the Event
/// is admitted. The cell writes are OR-Set adds under a fixed tag, so repeating
/// this for the same Realm/subject/action set is idempotent.
pub async fn seed_realm_basis(
    state: &AppState,
    realm_id: &str,
    subject: &str,
    data_plane_actions: &[&str],
) -> SealId {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let basis = realm_basis(realm_id, subject, state.service_id(), data_plane_actions);
    state
        .test_put_seal(&basis.governance_seal)
        .expect("fixture governance basis Seal");
    state
        .test_append_sealed_effects(&realm, &basis.governance_seal.id, &basis.governance_ops)
        .expect("fixture governance basis sealed effects");
    state
        .test_put_seal(&basis.seal)
        .expect("fixture basis Seal");
    state
        .test_append_sealed_effects(&realm, &basis.seal.id, &basis.ops)
        .expect("fixture basis sealed effects");
    seed_realm_genesis_event(state, realm_id, subject).await;
    // Accepting a capability Event is what fills the projected grant index the
    // governance predicates read. Sealing the basis directly skips that, so a
    // Realm whose sealed basis plainly grants an action would still answer
    // `missing_capability`.
    let owner_bootstrap_actions = soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS;
    let explicit_content_actions = data_plane_actions
        .iter()
        .copied()
        .filter(|action| !owner_bootstrap_actions.contains(action))
        .collect::<Vec<_>>();
    for (slot, actions, aggregate_admin) in [
        ("owner-grant", owner_bootstrap_actions.as_slice(), true),
        ("content-grant", explicit_content_actions.as_slice(), false),
    ] {
        if actions.is_empty() {
            continue;
        }
        let grant_id = fixture_grant_id(realm_id, subject, slot);
        let body = grant_body(&grant_id, realm_id, subject, actions, aggregate_admin);
        if let Some(grant) =
            soland_domain::reducer::engine_grant_from_cell_body(&grant_id, &body, false)
        {
            state.upsert_projected_grant_for_test(grant);
        }
    }
    basis.seal.id
}

/// Store the Realm's canonical `ak.realm.create`.
///
/// The Control Proposal decision policy is read from this Event, so a Realm
/// without one answers `quorum_unreachable` on every Control Move. A fixture
/// that stands a Realm up out of band still owes it its genesis Event.
pub async fn seed_realm_genesis_event(state: &AppState, realm_id: &str, subject: &str) {
    let genesis_event_id = format!(
        "ak:event:{}",
        realm_id
            .strip_prefix("ak:realm:")
            .expect("fixture Realm id is typed")
    );
    // A Realm has exactly one canonical create and the store enforces that, so
    // skip when this Realm already has one — whether from a previous call here
    // or from a fixture that authored its own genesis Event.
    if state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .expect("fixture Realm genesis lookup")
        .iter()
        .any(|record| record.kind == arkret_wire::EventKind::REALM_CREATE)
    {
        return;
    }
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(genesis_event_id.clone()).expect("fixture genesis Event id"),
        arkret_wire::EventKind::REALM_CREATE,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(realm_id.to_owned()).expect("fixture Realm id"),
        },
        Did::new(subject.to_owned()).expect("fixture genesis actor DID"),
        0,
        Hlc::new(FIXTURE_BASIS_HLC).expect("fixture genesis HLC"),
        serde_json::json!({"object": {"id": realm_id, "created_by": subject}}),
        chrono::Utc::now(),
    )
    .expect("fixture genesis Event");
    event.event_id =
        arkret_wire::EventId::new(genesis_event_id.clone()).expect("fixture genesis Event id");
    let canonical_digest = event.event_digest().expect("fixture genesis Event digest");
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: genesis_event_id,
            actor_id: subject.to_owned(),
            actor_seq: 0,
            realm_id: Some(realm_id.to_owned()),
            kind: arkret_wire::EventKind::REALM_CREATE.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest,
            canonical_bytes: Vec::new(),
            envelope: serde_json::to_value(&event).expect("fixture genesis envelope"),
            received_at: chrono::Utc::now(),
        })
        .await
        .expect("fixture Realm genesis Event");
}

/// Give `event` the CBA envelope shape its kind's registry row declares.
///
/// `event-auth-state-resolution.md` §3 puts `plane` on the cell family, and the
/// event-kind registry row carries the plane every derived write of that kind
/// lands in — the same descriptor soland's admission reads through
/// `arkret_schema::validate_registered_cell_writes_in_context`.
///
/// Two closed exceptions carry no basis field at all and are listed by §5, not
/// derived from the kind's plane: the `ak.realm.create` genesis anchor unit and
/// the B-model `ak.device.reanchor`, which fixes its frontier in
/// `payload.pre_fence_basis`. Non-reducer-input kinds carry no CBA field either
/// (`Event::validate_for_submit_structural`).
pub fn apply_registered_cba_plane(
    event: &mut arkret_wire::Event,
    verification_method: &str,
    data_plane_actions: &[&str],
) {
    let Some(descriptor) = event.kind.descriptor().filter(|row| row.reducer_input) else {
        return;
    };
    if matches!(
        event.kind.as_str(),
        arkret_wire::EventKind::REALM_CREATE | "ak.device.reanchor"
    ) {
        return;
    }
    let basis = realm_basis_seal(
        event.realm_id.as_str(),
        event.actor_id.as_str(),
        data_plane_actions,
    );
    match descriptor.plane {
        Some("data") => {
            event.seal_ref = Some(basis.id);
            event.auth_context = Some(arkret_wire::AuthContext {
                did: event.actor_id.clone(),
                key_id: verification_method
                    .split_once('#')
                    .map_or_else(|| verification_method.to_owned(), |(_, key)| key.to_owned()),
                key_epoch: 0,
                credential_epoch: None,
            });
        }
        Some("control") => {
            event.seal_basis = Some(SealBasis {
                leaves: vec![basis.id],
                control_event_set_root: basis.control_event_set_root,
                state_root: basis.state_root,
            });
        }
        _ => {}
    }
}

fn build_realm_basis(
    realm_id: &str,
    subject: &str,
    notary: &str,
    data_plane_actions: &[&str],
) -> RealmBasis {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let issuer = Did::new(subject.to_owned()).expect("fixture grant issuer DID");
    let notary = Did::new(notary.to_owned()).expect("fixture notary DID");
    let authority_root_move = fixture_move_id(realm_id, subject, "authority-root");
    let notary_move = fixture_move_id(realm_id, subject, "notary");
    let owner_move = fixture_move_id(realm_id, subject, "owner-grant");
    let content_move = fixture_move_id(realm_id, subject, "content-grant");
    let covered_move = fixture_move_id(realm_id, subject, "mls-commit");

    let owner_grant_id = fixture_grant_id(realm_id, subject, "owner-grant");
    let content_grant_id = fixture_grant_id(realm_id, subject, "content-grant");
    let owner_bootstrap_actions = soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS;
    let explicit_content_actions = data_plane_actions
        .iter()
        .copied()
        .filter(|action| !owner_bootstrap_actions.contains(action))
        .collect::<Vec<_>>();
    let mut ops = vec![
        (
            CellRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned())
                .expect("fixture authority-root cell id"),
            issued_op(
                &issuer,
                &authority_root_move,
                arkret_wire::LatticeOp {
                    op_type: arkret_wire::LatticeOpType::Set,
                    tag: None,
                    value: Some(
                        serde_json::to_value(
                            arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(
                                issuer.clone(),
                                arkret_policy::current_capability_action_registry_digest()
                                    .expect("embedded capability action registry digest"),
                            ),
                        )
                        .expect("fixture authority-root value"),
                    ),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
        ),
        // `event-kind-registry.json` gives `ak.realm.create` five cell writes,
        // and `ak.component.notary.v1` is one of them. A genesis unit without it
        // leaves the Realm with no proposal authority, so every Control Move
        // against this basis answers `quorum_unreachable`.
        (
            CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned())
                .expect("fixture notary cell id"),
            issued_op(
                &issuer,
                &notary_move,
                arkret_wire::LatticeOp {
                    op_type: arkret_wire::LatticeOpType::Set,
                    tag: None,
                    value: Some(
                        serde_json::to_value(arkret_wire::notary::NotaryValue::single_did(
                            notary.clone(),
                        ))
                        .expect("fixture notary value"),
                    ),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
        ),
        (
            capability_grant_cell(&owner_grant_id),
            issued_op(
                &issuer,
                &owner_move,
                or_set_add(
                    owner_move.as_str(),
                    grant_body(
                        &owner_grant_id,
                        realm_id,
                        subject,
                        &owner_bootstrap_actions,
                        true,
                    ),
                ),
            ),
        ),
    ];
    if !explicit_content_actions.is_empty() {
        ops.push((
            capability_grant_cell(&content_grant_id),
            issued_op(
                &issuer,
                &content_move,
                or_set_add(
                    content_move.as_str(),
                    grant_body(
                        &content_grant_id,
                        realm_id,
                        subject,
                        &explicit_content_actions,
                        false,
                    ),
                ),
            ),
        ));
    }

    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        FIXTURE_NOTARY_SEED,
        Did::new(FIXTURE_NOTARY_DID.to_owned()).expect("fixture notary DID"),
        arkret_wire::DidUrl::new(FIXTURE_NOTARY_VERIFICATION_METHOD)
            .expect("fixture notary verification method"),
    );
    // `Seal.delta` is a sorted, unique digest list
    // (`arkret_wire::Seal::validate_structural`), and `delta_control_root`
    // hashes it as a set, so the order is part of the wire contract rather
    // than a formatting choice.
    let mut governance_delta = vec![
        authority_root_move.clone(),
        notary_move.clone(),
        owner_move.clone(),
    ];
    if !explicit_content_actions.is_empty() {
        governance_delta.push(content_move.clone());
    }
    governance_delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let governance_seal = Seal::sign_single(
        realm.clone(),
        Vec::new(),
        governance_delta.clone(),
        sealed_state_root(&realm, &ops),
        Hlc::new(FIXTURE_BASIS_HLC).expect("fixture basis HLC"),
        &signer,
    )
    .expect("fixture governance basis Seal signs");
    let governance_ops = std::mem::take(&mut ops);

    // `encryption-and-audit.md` §2.5.2 — the accumulator element value is the
    // governance Seal ref itself; the tag is the commit batch digest and is
    // never compared against a Seal id (`arkret_state::mls_move`).
    // `covered_seals_cell` is keyed by the MLS group id (the registered
    // `payload.mls_group_id` subject), so E2EE fixture ciphertexts consuming
    // this basis MUST name [`FIXTURE_MLS_GROUP_ID`] in
    // `encrypted_content.group_id`.
    let covered_ops = vec![(
        arkret_state::mls_move::covered_seals_cell_id(FIXTURE_MLS_GROUP_ID)
            .expect("fixture covered_seals cell id"),
        issued_op(
            &issuer,
            &covered_move,
            or_set_add(
                covered_move.as_str(),
                Value::String(governance_seal.id.to_string()),
            ),
        ),
    )];

    // §2.5.1 `covered_seal_refs` visibility: the accumulator write names a Seal
    // its own Move could actually have seen, so it lands in a SECOND Seal built
    // on the governance one. That is the only reducer-reachable shape, and it is
    // what makes this basis self-consistent for the first time: with the
    // accumulator value fixed before the head Seal is hashed, the head's
    // `state_root` covers every op, instead of excluding the one member whose
    // value used to depend on the enclosing Seal's own id.
    let covered_set = governance_delta
        .iter()
        .cloned()
        .chain(std::iter::once(covered_move.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let all_ops = governance_ops
        .iter()
        .cloned()
        .chain(covered_ops.iter().cloned())
        .collect::<Vec<_>>();
    let seal = Seal::sign_single_kind_with_control_root(
        realm.clone(),
        vec![governance_seal.id.clone()],
        vec![covered_move],
        // `control_event_set_root` is cumulative over predecessor coverage ∪
        // delta, not over `delta` alone.
        arkret_state::state::control_event_set_root(&covered_set)
            .expect("fixture basis control event set root"),
        sealed_state_root(&realm, &all_ops),
        Hlc::new(FIXTURE_BASIS_HLC).expect("fixture basis HLC"),
        arkret_wire::SealKind::Normal,
        &signer,
    )
    .expect("fixture basis head Seal signs");

    RealmBasis {
        governance_seal,
        governance_ops,
        seal,
        ops: covered_ops,
    }
}

/// The `state_root` a notary would commit for these sealed effects: join every
/// covered op under the Realm's registered lattice, then Merkleize the result.
fn sealed_state_root(realm: &RealmId, ops: &[(CellRef, IssuedOp)]) -> Hash {
    let registry = ProjectionService::sdk_cell_registry();
    let mut grouped: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
    for (cell, op) in ops {
        grouped.entry(cell.clone()).or_default().push(op.clone());
    }
    let mut post_state = BTreeMap::new();
    for (cell, cell_ops) in grouped {
        let binding = registry
            .resolve(realm, &cell)
            .expect("fixture cell family is registered");
        post_state.insert(
            cell.clone(),
            arkret_state::join_cell(binding.lattice.as_ref(), &cell, &cell_ops),
        );
    }
    compute_state_root(&post_state).expect("fixture state_root")
}

fn capability_grant_cell(grant_id: &str) -> CellRef {
    CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .expect("fixture capability grant cell id")
}

/// A deterministic Control-Move digest for one member of the genesis unit.
fn fixture_move_id(realm_id: &str, subject: &str, slot: &str) -> Hash {
    Hash::new(format!(
        "sha256:{}",
        fixture_basis_digest_hex(realm_id, subject, slot)
    ))
    .expect("fixture Control Move digest")
}

/// A deterministic `ak:grant:` id, so re-seeding the same Realm/subject writes
/// the same OR-Set cell instead of piling up look-alike grants.
fn fixture_grant_id(realm_id: &str, subject: &str, slot: &str) -> String {
    let hex = fixture_basis_digest_hex(realm_id, subject, slot);
    format!(
        "ak:grant:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn fixture_basis_digest_hex(realm_id: &str, subject: &str, slot: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:test-support:realm-basis:");
    hasher.update(slot.as_bytes());
    hasher.update(b"\x00");
    hasher.update(realm_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(subject.as_bytes());
    hex::encode(hasher.finalize())
}

fn or_set_add(tag: &str, value: Value) -> arkret_wire::LatticeOp {
    arkret_wire::LatticeOp {
        op_type: arkret_wire::LatticeOpType::Add,
        tag: Some(tag.to_owned()),
        value: Some(value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    }
}

fn issued_op(issuer: &Did, move_id: &Hash, op: arkret_wire::LatticeOp) -> IssuedOp {
    IssuedOp {
        issuer: issuer.clone(),
        op: arkret_state::lattice::SealedOp::new(move_id.clone(), op),
    }
}

/// The `ak.capability.grant` payload the OR-Set element carries.
///
/// `capabilities.md` §3 fixes the body; `soland_domain::reducer`'s
/// `engine_grant_from_capability_cell_state` is the reader, and it drops any
/// element whose actions are unregistered, whose resource selector is malformed
/// or whose aggregate-admin registry binding does not resolve — so a fixture
/// that gets this wrong produces a silently empty capability set, not an error.
fn grant_body(
    grant_id: &str,
    realm_id: &str,
    subject: &str,
    actions: &[&str],
    aggregate_admin: bool,
) -> Value {
    let mut body = serde_json::json!({
        "grant_id": grant_id,
        "schema": arkret_wire::SchemaId::CAPABILITY_V1,
        "realm_id": realm_id,
        "issuer": subject,
        "subject": subject,
        "actions": actions,
        "resources": [{
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }],
        "issued_at": "2026-01-01T00:00:00.000Z"
    });
    if aggregate_admin {
        body["capability_action_registry_digest"] = Value::String(
            arkret_policy::current_capability_action_registry_digest()
                .expect("embedded capability action registry digest")
                .to_string(),
        );
    }
    body
}
