//! `invite-addressing.md` §7 step 4 — the Realm capability closure a private
//! invite delivery is evaluated against.
//!
//! The receiving Station is by definition not yet a federation peer of the
//! inviting Realm, so `ak.peer.seals.read.*` fails closed for it and the
//! authority closure cannot be fetched. It travels inside the request as
//! `cba_proof_bundles[]` instead, and this module turns that transport material
//! into the deterministic joined control view the ordinary Control Move
//! authorization evaluation already runs against
//! (`event-auth-state-resolution.md` §6.3.1).
//!
//! Three invariants shape every function here:
//!
//! * The bundle is not authoritative. Every Seal is re-identified from its own canonical bytes and
//!   every cell op is re-derived by this Station's reducer; nothing is trusted because the sender
//!   put it in the request.
//! * Nothing here becomes accepted state. The Seal and cell stores below are process-local, live
//!   for the duration of one request, and are dropped afterwards. No Realm is materialised, no
//!   projection is written, no frontier advances.
//! * The result is a function of `(invite_event, cba_proof_bundles)` alone. No holder row, receive
//!   policy, consent cell or quota is read, which is what lets step 4 report a precise, registered
//!   outcome instead of joining the holder-indistinguishable class.
//!
//! The local branch — the invitee lives on the inviting Station — does not come
//! through here at all. It runs the same verifier over this Station's own
//! accepted state, because serialising accepted state into a bundle and reading
//! it straight back adds no guarantee (`invite-addressing.md` §7).

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{CellStore, MemoryCellStore, MemorySealStore, SealStore};
use arkret_wire::{CbaProofBundle, Event, Seal};
use soland_http::error::AppError;

use crate::routing::events::event_log::{
    CbaBundleClosure, cba_proof_bundles_for_targets, digest_suite_from_hash,
};
use crate::state::AppState;

/// The one cell `capabilities.md` §3.2 admits as the Realm authority source and
/// the only cell the invite Control Move's authorization evaluation reads.
///
/// Selecting the transported Control Moves by this cell keeps the bundle
/// proportional to the fact under proof rather than to the Realm's whole
/// control history; `cba-profiles.md` §5 explicitly allows a bounded verifiable
/// subset of what the target Seal covers.
const INVITE_AUTHORITY_CELL: &str = arkret_wire::REALM_AUTHORITY_ROOT_CELL;

/// Build the `cba_proof_bundles[]` an outbound private invite delivery carries.
///
/// The inviting Station is a member of the Realm and holds the whole accepted
/// closure, so this is a local read. One bundle per `seal_basis.leaves` entry,
/// which is exactly the coverage `invite-addressing.md` §7 step 4 requires of
/// the receiver's admission check.
pub(super) async fn build_invite_capability_bundles(
    state: &AppState,
    invite_event: &Event,
) -> Result<Vec<CbaProofBundle>, AppError> {
    let leaves = invite_capability_leaves(invite_event)?;
    let targets = leaves.iter().cloned().collect::<BTreeSet<_>>();
    let bundles = cba_proof_bundles_for_targets(
        state,
        &targets,
        CbaBundleClosure::WithControlMovesWriting(INVITE_AUTHORITY_CELL),
    )
    .await
    .map_err(|error| {
        AppError::internal(format!(
            "invite capability bundle construction failed: {error}"
        ))
    })?;
    for bundle in &bundles {
        bundle.validate_structural().map_err(|error| {
            AppError::internal(format!(
                "constructed invite capability bundle is invalid: {error}"
            ))
        })?;
    }
    Ok(bundles)
}

/// `seal_basis.leaves` of the invite Control Move.
///
/// An `ak.invite.create` without a basis names no accepted pre-state at all, so
/// there is nothing for step 4 to evaluate against and no closure that could
/// repair it.
pub(super) fn invite_capability_leaves(invite_event: &Event) -> Result<Vec<SealId>, AppError> {
    let leaves = invite_event
        .seal_basis
        .as_ref()
        .map(|basis| basis.leaves.clone())
        .unwrap_or_default();
    if leaves.is_empty() {
        return Err(schema_violation(
            "invite_event carries no seal_basis.leaves to resolve its Realm capability against",
        ));
    }
    Ok(leaves)
}

/// Step 4's closure for the peer branch: the joined control view the request's
/// bundles resolve to.
///
/// Reads nothing about the holder and writes nothing anywhere.
pub(super) async fn invite_capability_closure_from_bundles(
    state: &AppState,
    invite_event: &Event,
    bundles: &[CbaProofBundle],
) -> Result<BTreeMap<CellRef, CellState>, AppError> {
    let realm_id = &invite_event.realm_id;
    let leaves = invite_capability_leaves(invite_event)?;
    let seals_by_id = admit_invite_capability_bundles(bundles, &leaves, realm_id)?;

    // Throwaway stores. `MemorySealStore::put` re-derives each Seal id from its
    // canonical bytes, so a Seal whose content does not match the id the basis
    // names never enters the view.
    let seal_store = MemorySealStore::default();
    let cell_store = MemoryCellStore::default();
    let registry = soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry()
        .map_err(|error| {
        AppError::new(
            soland_http::error::ErrorCode::UnsupportedProfile,
            format!("the Realm reducer profile is not implemented here: {error}"),
        )
    })?;

    let control_moves = index_control_moves_by_digest(bundles)?;
    for seal_id in acceptance_order(&seals_by_id)? {
        let seal = &seals_by_id[&seal_id];
        let digest_suite =
            digest_suite_from_hash(&seal.control_event_set_root).map_err(schema_violation)?;
        // The pre-state each covered Control Move is reduced against is the
        // view its own accepting Seal's predecessors resolve to, exactly as the
        // accept path does when this Station seals a Move of its own.
        let pre_state = arkret_state::effective_state_at(
            &seal.predecessor_refs,
            realm_id,
            &seal_store,
            &cell_store,
            &registry,
        )
        .await
        .map_err(|error| dependency_missing(&seals_by_id, &leaves, &error.to_string()))?;
        let mut ops: Vec<(CellRef, IssuedOp)> = Vec::new();
        for digest in &seal.delta {
            let Some(control_move) = control_moves.get(digest) else {
                continue;
            };
            // The Move's own digest names the suite it was accepted under,
            // which is the one its derived `digest_of` members were projected
            // with. That is not always the Seal's root suite: a Seal carrying
            // `ak.realm.digest_suite.transition` seals under the new suite
            // while its delta still hashes under the old one.
            let event_digest_suite = digest_suite_from_hash(digest).map_err(schema_violation)?;
            let writes = state
                .projections()
                .project_cell_writes_with_digest_suite(control_move, event_digest_suite)
                .map_err(|error| {
                    schema_violation(format!(
                        "transported Control Move {digest} has no registered reducer output: {error}"
                    ))
                })?;
            for write in writes {
                let resolved = state
                    .projections()
                    .resolve_projected_cell_write(&write, realm_id, &pre_state)
                    .map_err(|error| {
                        schema_violation(format!(
                            "transported Control Move {digest} cell write is unresolvable: {error}"
                        ))
                    })?;
                for effect in resolved {
                    ops.push((
                        effect.cell_id.clone(),
                        IssuedOp {
                            issuer_id: control_move.actor_id.clone(),
                            op: SealedOp::from_projection(digest.clone(), &effect),
                        },
                    ));
                }
            }
        }
        seal_store
            .put(seal, digest_suite)
            .await
            .map_err(|error| schema_violation(format!("transported Seal is invalid: {error}")))?;
        cell_store
            .append_sealed_effects(realm_id, &seal.id, &ops)
            .await
            .map_err(|error| {
                AppError::internal(format!("invite capability closure replay failed: {error}"))
            })?;
    }

    arkret_state::effective_state_at(&leaves, realm_id, &seal_store, &cell_store, &registry)
        .await
        .map_err(|error| dependency_missing(&seals_by_id, &leaves, &error.to_string()))
}

/// `invite-addressing.md` §7 step 4 bundle admission.
///
/// Runs before any object is replayed, and only over material the sender
/// supplied: bounds, canonical order, single-Realm membership, and the two
/// binding rules the ruling adds — every `target_seal_ref` is one of the invite
/// Control Move's own basis leaves, and every leaf is covered by some bundle.
fn admit_invite_capability_bundles(
    bundles: &[CbaProofBundle],
    leaves: &[SealId],
    realm_id: &RealmId,
) -> Result<BTreeMap<SealId, Seal>, AppError> {
    if bundles.is_empty()
        || bundles.len()
            > arkret_models_collaboration::governance::invite_addressing::MAX_INVITE_DELIVERY_CBA_BUNDLES
    {
        return Err(limit_exceeded(
            "invite delivery carries an out-of-range cba_proof_bundles count",
        ));
    }
    let leaf_set = leaves.iter().cloned().collect::<BTreeSet<_>>();
    let mut previous: Option<&str> = None;
    let mut covered = BTreeSet::new();
    let mut seals_by_id: BTreeMap<SealId, Seal> = BTreeMap::new();
    for bundle in bundles {
        bundle.validate_structural().map_err(|error| {
            schema_violation(format!("invite capability bundle is invalid: {error}"))
        })?;
        if previous.is_some_and(|last| last >= bundle.target_seal_ref.as_str()) {
            return Err(schema_violation(
                "invite capability bundles must be strictly sorted by target_seal_ref",
            ));
        }
        previous = Some(bundle.target_seal_ref.as_str());
        if !leaf_set.contains(&bundle.target_seal_ref) {
            return Err(schema_violation(
                "invite capability bundle target_seal_ref is not an invite_event.seal_basis leaf",
            ));
        }
        covered.insert(bundle.target_seal_ref.clone());
        for seal in &bundle.seals {
            if &seal.realm_id != realm_id {
                return Err(schema_violation(
                    "invite capability bundle carries a Seal from another Realm",
                ));
            }
            match seals_by_id.get(&seal.id) {
                Some(existing) if existing != seal => {
                    return Err(schema_violation(
                        "invite capability bundles disagree on one Seal's canonical content",
                    ));
                }
                Some(_) => {}
                None => {
                    seals_by_id.insert(seal.id.clone(), seal.clone());
                }
            }
        }
    }
    if covered != leaf_set {
        let missing = leaf_set
            .difference(&covered)
            .map(|leaf| leaf.as_str().to_owned())
            .collect::<Vec<_>>();
        return Err(AppError::new(
            soland_http::error::ErrorCode::DependencyMissing,
            "invite_event.seal_basis has leaves no cba_proof_bundle covers",
        )
        .with_wire_detail("missing_seal_refs", missing)
        .with_wire_detail("missing_event_digests", Vec::<String>::new()));
    }
    if seals_by_id.len() > arkret_wire::cba_proof_bundle::MAX_BUNDLE_SEALS {
        return Err(limit_exceeded(
            "invite capability bundles exceed the v1 Seal closure bound",
        ));
    }
    Ok(seals_by_id)
}

/// Every transported Control Move keyed by the digests a Seal delta can name it
/// under.
///
/// A Seal's delta is written under the digest suite that Seal's own roots use,
/// which the receiver has no Realm projection to look up, so both registered
/// suites are indexed and the Seal decides which one applies.
fn index_control_moves_by_digest(
    bundles: &[CbaProofBundle],
) -> Result<BTreeMap<Hash, Event>, AppError> {
    let mut out = BTreeMap::new();
    for bundle in bundles {
        for control_move in &bundle.control_moves {
            for suite in [
                arkret_canonical::DigestSuite::Sha256,
                arkret_canonical::DigestSuite::Blake3,
            ] {
                let Ok(digest) = control_move.event_digest_with_digest_suite(suite) else {
                    continue;
                };
                let Ok(digest) = Hash::new(digest) else {
                    continue;
                };
                match out.get(&digest) {
                    Some(existing) if existing != control_move => {
                        return Err(schema_violation(
                            "invite capability bundles carry two Control Moves with one digest",
                        ));
                    }
                    _ => {
                        out.insert(digest, control_move.clone());
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Seals ordered so every predecessor present in the closure is replayed first.
///
/// The cell log is batched per accepting Seal and register joins are sensitive
/// to that batch order, so replaying a successor before its predecessor would
/// change the joined value.
fn acceptance_order(seals_by_id: &BTreeMap<SealId, Seal>) -> Result<Vec<SealId>, AppError> {
    let mut emitted = BTreeSet::new();
    let mut order = Vec::with_capacity(seals_by_id.len());
    while order.len() < seals_by_id.len() {
        let mut progressed = false;
        for (seal_id, seal) in seals_by_id {
            if emitted.contains(seal_id) {
                continue;
            }
            if seal.predecessor_refs.iter().any(|predecessor| {
                seals_by_id.contains_key(predecessor) && !emitted.contains(predecessor)
            }) {
                continue;
            }
            emitted.insert(seal_id.clone());
            order.push(seal_id.clone());
            progressed = true;
        }
        if !progressed {
            return Err(schema_violation(
                "invite capability bundle Seal predecessors form a cycle",
            ));
        }
    }
    Ok(order)
}

/// `cba-profiles.md` §5 — an incomplete closure is reported with the exact
/// Seals the sender still owes, never as an opaque authorization failure.
fn dependency_missing(
    seals_by_id: &BTreeMap<SealId, Seal>,
    leaves: &[SealId],
    detail: &str,
) -> AppError {
    let mut missing = BTreeSet::new();
    for leaf in leaves {
        if !seals_by_id.contains_key(leaf) {
            missing.insert(leaf.as_str().to_owned());
        }
    }
    for seal in seals_by_id.values() {
        for predecessor in &seal.predecessor_refs {
            if !seals_by_id.contains_key(predecessor) {
                missing.insert(predecessor.as_str().to_owned());
            }
        }
    }
    AppError::new(
        soland_http::error::ErrorCode::DependencyMissing,
        "the invite capability closure is incomplete",
    )
    .with_private_detail(detail.to_owned())
    .with_wire_detail(
        "missing_seal_refs",
        missing.into_iter().collect::<Vec<String>>(),
    )
    .with_wire_detail("missing_event_digests", Vec::<String>::new())
}

fn schema_violation(message: impl Into<String>) -> AppError {
    AppError::new(soland_http::error::ErrorCode::SchemaViolation, message)
}

fn limit_exceeded(message: impl Into<String>) -> AppError {
    AppError::new(soland_http::error::ErrorCode::LimitExceeded, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_REALM: &str = "ak:realm:AS6APqej-Rh7QFhSceTHVNyMDqcQte46AfERL21Hkt5_";
    const FIXTURE_SUBJECT: &str = "ak:did_core:web:inviter.example";
    const FIXTURE_STATION: &str = "ak:did_core:web:inviter-station.example";

    /// One real, structurally valid single-Seal bundle, built from the same
    /// fixture basis builder the development conformance adapter uses.
    fn fixture_bundle(id_domain: &str) -> CbaProofBundle {
        let signer = soland_services::conformance_basis::ConformanceNotarySigner::ed25519(
            arkret_identifiers::Did::new("did:web:inviter-station.example".to_owned())
                .expect("fixture notary DID"),
            arkret_wire::DidUrl::new("did:web:inviter-station.example#notary-key".to_owned())
                .expect("fixture notary verification method"),
            [0x53; 32],
        )
        .expect("fixture notary signer");
        let basis = soland_services::conformance_basis::build_realm_basis(
            FIXTURE_REALM,
            FIXTURE_SUBJECT,
            soland_services::conformance_basis::RealmBasisFixtureOptions {
                station_id: FIXTURE_STATION,
                notary_signer: &signer,
                install_notary: true,
                data_plane_actions: &[],
                fixture_id_domain: id_domain,
            },
        )
        .expect("fixture Realm basis");
        CbaProofBundle {
            target_seal_ref: basis.seal.id.clone(),
            seals: vec![basis.seal],
            control_moves: Vec::new(),
            inclusion_proofs: Vec::new(),
            availability_proofs: Vec::new(),
        }
    }

    fn realm() -> RealmId {
        RealmId::new(FIXTURE_REALM.to_owned()).expect("fixture Realm id")
    }

    /// §7 step 4 — a delivery that carries no bundle at all cannot be evaluated
    /// and is not a closure gap the sender could be told to fill in.
    #[test]
    fn an_empty_bundle_list_is_out_of_range() {
        let bundle = fixture_bundle("soland:invite-capability-test:empty:");
        let leaves = vec![bundle.target_seal_ref.clone()];
        let error = admit_invite_capability_bundles(&[], &leaves, &realm())
            .expect_err("an empty cba_proof_bundles list must be refused");
        assert_eq!(error.wire_code(), "limit_exceeded");
    }

    /// §7 step 4 — `cba_proof_bundles` is bounded at 64 because
    /// `seal_basis.leaves` is, and each bundle serves exactly one leaf.
    #[test]
    fn more_bundles_than_the_basis_can_have_leaves_is_out_of_range() {
        let over_limit = arkret_models_collaboration::governance::invite_addressing::MAX_INVITE_DELIVERY_CBA_BUNDLES
            + 1;
        let mut bundles = (0..over_limit)
            .map(|index| fixture_bundle(&format!("soland:invite-capability-test:bulk-{index}:")))
            .collect::<Vec<_>>();
        bundles.sort_by(|left, right| left.target_seal_ref.cmp(&right.target_seal_ref));
        let leaves = bundles
            .iter()
            .map(|bundle| bundle.target_seal_ref.clone())
            .collect::<Vec<_>>();
        let error = admit_invite_capability_bundles(&bundles, &leaves, &realm())
            .expect_err("more than 64 bundles must be refused");
        assert_eq!(error.wire_code(), "limit_exceeded");
    }

    /// §7 step 4 — a bundle pointing at a Seal outside the invite Control
    /// Move's own basis is over-disclosure and amplification input, never a
    /// missing dependency (`cba-profiles.md` §5).
    #[test]
    fn a_bundle_target_outside_the_basis_leaves_is_a_schema_violation() {
        let bundle = fixture_bundle("soland:invite-capability-test:foreign-target:");
        let other = fixture_bundle("soland:invite-capability-test:foreign-leaf:");
        assert_ne!(bundle.target_seal_ref, other.target_seal_ref);
        let leaves = vec![other.target_seal_ref.clone()];
        let error = admit_invite_capability_bundles(&[bundle], &leaves, &realm())
            .expect_err("a bundle target outside seal_basis.leaves must be refused");
        assert_eq!(error.wire_code(), "schema_violation");
    }

    /// §7 step 4 — every leaf MUST be covered. An uncovered leaf is a real
    /// closure gap, so it is reported with the exact Seal the sender still
    /// owes rather than as an opaque authorization failure.
    #[test]
    fn an_uncovered_basis_leaf_names_the_missing_seal() {
        let bundle = fixture_bundle("soland:invite-capability-test:covered:");
        let uncovered = fixture_bundle("soland:invite-capability-test:uncovered:");
        let leaves = vec![
            bundle.target_seal_ref.clone(),
            uncovered.target_seal_ref.clone(),
        ];
        let error = admit_invite_capability_bundles(&[bundle], &leaves, &realm())
            .expect_err("an uncovered seal_basis leaf must be refused");
        assert_eq!(error.wire_code(), "dependency_missing");
        assert!(
            format!("{error:?}").contains(uncovered.target_seal_ref.as_str()),
            "the response must name the exact missing Seal: {error:?}"
        );
    }

    /// §7 step 4 — a Seal from another Realm is a permanent `schema_violation`,
    /// not a dependency the sender can fill in.
    #[test]
    fn a_cross_realm_seal_is_a_schema_violation() {
        let bundle = fixture_bundle("soland:invite-capability-test:cross-realm:");
        let leaves = vec![bundle.target_seal_ref.clone()];
        let other_realm =
            RealmId::new("ak:realm:AS6BPqej-Rh7QFhSceTHVNyMDqcQte46AfERL21Hkt5_".to_owned())
                .expect("second fixture Realm id");
        let error = admit_invite_capability_bundles(&[bundle], &leaves, &other_realm)
            .expect_err("a cross-Realm Seal must be refused");
        assert_eq!(error.wire_code(), "schema_violation");
    }

    /// An `ak.invite.create` with no `seal_basis` names no accepted pre-state,
    /// so there is nothing for step 4 to evaluate and no bundle that repairs it.
    #[test]
    fn an_invite_without_a_seal_basis_has_no_capability_to_evaluate() {
        let event: Event = serde_json::from_value(serde_json::json!({
            "event_id": "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E3",
            "kind": arkret_wire::EventKind::InviteCreate.as_str(),
            "realm_id": FIXTURE_REALM,
            "scope_ref": { "kind": "realm", "realm_id": FIXTURE_REALM },
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": FIXTURE_SUBJECT, "station_id": FIXTURE_STATION
            }},
            "actor_seq": 0,
            "created_at": "2026-08-21T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": {},
            "proofs": []
        }))
        .expect("fixture invite Event");
        let error = invite_capability_leaves(&event)
            .expect_err("an invite Control Move without a basis cannot be authorized");
        assert_eq!(error.wire_code(), "schema_violation");
    }
}
