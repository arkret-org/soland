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

use arkret_identifiers::{CellRef, RealmId, SealId};
use arkret_state::lattice::CellState;
use arkret_wire::{
    Base64UrlString, CbaProofBundle, Event, Seal, SemanticRefProof, SemanticRefProofKind,
    SemanticRefProofRootField,
};
use soland_http::error::AppError;

use crate::routing::events::event_log::{cba_proof_bundles_for_targets, digest_suite_from_hash};
use crate::state::AppState;

/// The one cell `capabilities.md` §3.2 admits as the Realm authority source and
/// the only cell the invite Control Move's authorization evaluation reads.
///
/// §3.2 also fixes the shape of the evidence for it: the root-authority branch
/// MUST run off that cell's registered inclusion proof under the same Seal
/// basis. It is not a Control Move replay. The Event that writes this cell is
/// `ak.realm.create`, a `seal_basis`-exempt anchor unit
/// (`event-auth-state-resolution.md` §5) that
/// `cba-proof-bundle.schema.json` forbids `control_moves[]` from carrying.
const INVITE_AUTHORITY_CELL: &str = arkret_wire::REALM_AUTHORITY_ROOT_CELL;

/// Build the `cba_proof_bundles[]` an outbound private invite delivery carries.
///
/// The inviting Station is a member of the Realm and holds the whole accepted
/// closure, so this is a local read. One bundle per `seal_basis.leaves` entry,
/// which is exactly the coverage `invite-addressing.md` §7 step 4 requires of
/// the receiver's admission check, and each bundle carries the authority-root
/// cell's inclusion proof under that leaf's own `state_root`.
pub(super) async fn build_invite_capability_bundles(
    state: &AppState,
    invite_event: &Event,
) -> Result<Vec<CbaProofBundle>, AppError> {
    let realm_id = &invite_event.realm_id;
    let leaves = invite_capability_leaves(invite_event)?;
    let targets = leaves.iter().cloned().collect::<BTreeSet<_>>();
    let mut bundles = cba_proof_bundles_for_targets(state, &targets)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "invite capability bundle construction failed: {error}"
            ))
        })?;
    for bundle in &mut bundles {
        let proof =
            authority_root_inclusion_proof(state, realm_id, &bundle.target_seal_ref).await?;
        bundle.inclusion_proofs = vec![proof];
        bundle.validate_structural().map_err(|error| {
            AppError::internal(format!(
                "constructed invite capability bundle is invalid: {error}"
            ))
        })?;
    }
    Ok(bundles)
}

/// The authority-root cell's RFC 6962 branch under one accepted Seal's
/// `state_root`.
///
/// The leaf preimage travels with the branch because the receiver holds no
/// projection for this Realm: it has to recompute the leaf from bytes it was
/// given and then recompute the root, and a bare digest would let it verify
/// membership of a value it cannot read.
async fn authority_root_inclusion_proof(
    state: &AppState,
    realm_id: &RealmId,
    target_seal_ref: &SealId,
) -> Result<SemanticRefProof, AppError> {
    let seal = state
        .projections()
        .seal_by_id(target_seal_ref)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "read invite capability Seal {target_seal_ref}: {error}"
            ))
        })?
        .ok_or_else(|| {
            AppError::internal(format!(
                "invite capability Seal {target_seal_ref} is unavailable"
            ))
        })?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(&seal)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "resolve digest suite for invite capability Seal {target_seal_ref}: {error}"
            ))
        })?
        .seal_digest_suite;
    let cell = authority_root_cell_ref();
    let seal_slice = std::slice::from_ref(target_seal_ref);
    let effective = state
        .projections()
        .effective_state_at(seal_slice, realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "resolve invite capability authority root at {target_seal_ref}: {error}"
            ))
        })?;
    // The authority-root cell is a `cas_register`, so its `state_root` leaf is
    // built from the active head set rather than from the joined value
    // (`event-auth-state-resolution.md` §6.2.1). Both the branch and the
    // preimage therefore come from the same governance view.
    let cas_heads = state
        .projections()
        .effective_cas_heads_at(seal_slice, realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "resolve invite capability CAS heads at {target_seal_ref}: {error}"
            ))
        })?;
    let view = arkret_state::GovernanceView::new(&effective, &cas_heads);
    let proof =
        arkret_state::state_inclusion_proof(view, &cell, digest_suite).map_err(|error| {
            AppError::internal(format!(
                "build invite capability authority-root inclusion proof: {error}"
            ))
        })?;
    let preimage = arkret_state::state_leaf_canonical_preimage(view, &cell).map_err(|error| {
        AppError::internal(format!(
            "build invite capability authority-root leaf preimage: {error}"
        ))
    })?;
    Ok(SemanticRefProof {
        kind: SemanticRefProofKind::Rfc6962Merkle,
        root_field: SemanticRefProofRootField::StateRoot,
        root_digest: seal.state_root.clone(),
        leaf_canonical_preimage_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
            &preimage,
        ))
        .map_err(|error| {
            AppError::internal(format!("encode authority-root leaf preimage: {error}"))
        })?,
        leaf_digest: proof.leaf_digest,
        audit_path: proof.inclusion_proof,
        leaf_index: proof.leaf_index,
        leaf_count: proof.leaf_count,
    })
}

fn authority_root_cell_ref() -> CellRef {
    CellRef::new(INVITE_AUTHORITY_CELL.to_owned())
        .expect("the authority-root cell ref constant is well-formed")
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
/// `capabilities.md` §3.2 closes the evidence for the root-authority branch to
/// one shape — the authority-root cell's registered inclusion proof under the
/// same Seal basis — so this resolves the cell out of each bundle's branch
/// against that bundle's own target Seal `state_root` and never replays a
/// Control Move to reconstruct it. Reads nothing about the holder and writes
/// nothing anywhere.
pub(super) async fn invite_capability_closure_from_bundles(
    _state: &AppState,
    invite_event: &Event,
    bundles: &[CbaProofBundle],
) -> Result<BTreeMap<CellRef, CellState>, AppError> {
    let realm_id = &invite_event.realm_id;
    let leaves = invite_capability_leaves(invite_event)?;
    let seals_by_id = admit_invite_capability_bundles(bundles, &leaves, realm_id)?;

    // Every leaf is a basis leaf of the same Control Move, so they must agree on
    // the authority root. Disagreement is a broken closure rather than a merge
    // problem: the receiver has no accepted state to break the tie with, and
    // silently picking one branch would let a sender choose the controller.
    let mut agreed: Option<serde_json::Value> = None;
    for bundle in bundles {
        let seal = seals_by_id.get(&bundle.target_seal_ref).ok_or_else(|| {
            dependency_missing(
                &seals_by_id,
                &leaves,
                "a bundle does not carry its own target Seal",
            )
        })?;
        let Some(value) = authority_root_value_from_bundle(bundle, seal)? else {
            // No branch for the cell at all. The narrowest registered outcome
            // for that is `realm_authority_root_missing`, which the shared
            // authorization evaluator raises from an empty closure; inventing a
            // second spelling for it here would widen the closed table in
            // `invite-addressing.md` §7 step 4.
            return Ok(BTreeMap::new());
        };
        match &agreed {
            Some(existing) if existing != &value => {
                return Err(schema_violation(
                    "invite capability bundles disagree on the Realm authority root",
                ));
            }
            _ => agreed = Some(value),
        }
    }

    Ok(agreed
        .map(|value| BTreeMap::from([(authority_root_cell_ref(), CellState::Value(value))]))
        .unwrap_or_default())
}

/// Resolve the authority-root cell out of one bundle's inclusion proofs.
///
/// `Ok(None)` means the bundle carries no branch for this cell — a missing
/// authority root, not a malformed one. A branch that is present but does not
/// reconstruct the Seal's signed `state_root`, or whose preimage is not the
/// canonical leaf its digest claims, is a `schema_violation`: the bundle is
/// unsigned transport, so every byte of it has to be re-derived here.
fn authority_root_value_from_bundle(
    bundle: &CbaProofBundle,
    seal: &Seal,
) -> Result<Option<serde_json::Value>, AppError> {
    let digest_suite = digest_suite_from_hash(&seal.state_root).map_err(schema_violation)?;
    let cell = authority_root_cell_ref();
    for proof in &bundle.inclusion_proofs {
        if proof.root_field != SemanticRefProofRootField::StateRoot
            || proof.root_digest != seal.state_root
        {
            continue;
        }
        let preimage =
            arkret_canonical::base64url_decode(proof.leaf_canonical_preimage_b64u.as_str())
                .map_err(|error| {
                    schema_violation(format!(
                        "invite capability inclusion proof preimage is not base64url: {error}"
                    ))
                })?;
        let leaf: serde_json::Value = serde_json::from_slice(&preimage).map_err(|error| {
            schema_violation(format!(
                "invite capability inclusion proof preimage is not JSON: {error}"
            ))
        })?;
        if leaf.get("cell").and_then(serde_json::Value::as_str) != Some(INVITE_AUTHORITY_CELL) {
            continue;
        }
        // The preimage is what the leaf digest commits to, so it must be the
        // canonical encoding and not merely an equivalent one.
        let canonical = arkret_canonical::canonical_json_bytes(&leaf).map_err(|error| {
            schema_violation(format!(
                "invite capability inclusion proof preimage is not canonicalizable: {error}"
            ))
        })?;
        if canonical != preimage {
            return Err(schema_violation(
                "invite capability inclusion proof preimage is not canonical bytes",
            ));
        }
        let state_object = leaf
            .get("state")
            .cloned()
            .ok_or_else(|| schema_violation("invite capability leaf carries no state"))?;
        // §6.2.1's two leaf shapes. The authority-root cell is a
        // `cas_register`, so in practice this is the head set; the value branch
        // stays because the leaf definition is shared and a sender that ships
        // the wrong shape must fail on the digest, not on a missing key.
        let value = match (state_object.get("heads"), state_object.get("value")) {
            (Some(heads), None) => {
                arkret_state::causal_register_leaf_value(heads).map_err(|error| {
                    schema_violation(format!(
                        "invite capability leaf head set has no single value: {error}"
                    ))
                })?
            }
            (None, Some(value)) => value.clone(),
            _ => {
                return Err(schema_violation(
                    "invite capability leaf state is not one closed §6.2.1 shape",
                ));
            }
        };
        let recomputed =
            arkret_state::state_leaf_hash_from_state_object(&cell, state_object, digest_suite)
                .map_err(|error| {
                    schema_violation(format!(
                        "invite capability leaf digest is unrecomputable: {error}"
                    ))
                })?;
        if recomputed != proof.leaf_digest {
            return Err(schema_violation(
                "invite capability inclusion proof leaf digest does not match its preimage",
            ));
        }
        if !arkret_state::verify_state_inclusion_proof(
            &proof.leaf_digest,
            proof.leaf_index,
            proof.leaf_count,
            &proof.audit_path,
            &seal.state_root,
            digest_suite,
        )
        .map_err(|error| {
            schema_violation(format!(
                "invite capability inclusion proof is unverifiable: {error}"
            ))
        })? {
            return Err(schema_violation(
                "invite capability inclusion proof does not reconstruct the Seal state_root",
            ));
        }
        return Ok(Some(value));
    }
    Ok(None)
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
