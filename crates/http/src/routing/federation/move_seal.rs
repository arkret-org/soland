//! Move / Seal verification, application, and local notary administration.
//!
//! JWS shape verification rejects mangled, empty, or sentinel signatures
//! and validates the protected-header `alg`. In production mode, full
//! Ed25519 verification runs against the public key resolved from the
//! `verification_method` DID URL.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{Hash, RealmId, SealId};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_state::state::{SealEffect, SealReject, StoreError, control_event_set_root};
use arkret_wire::{ActorId, DidCoreId, Event, NotarySig, Seal};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

struct DeviceGenerationEventSealContext {
    actor_id: ActorId,
    principal_id: DidCoreId,
    current_generation_ref: Option<u64>,
    records: Vec<soland_services::events::AcceptedEvent>,
    accepted_frontier_refs: Vec<SealId>,
    cas_frontier_refs: Vec<SealId>,
    generation_fence: Option<crate::notary::FirstGenerationEventSealRequirement>,
    bootstrap_required_delta: Vec<Hash>,
    bootstrap_device_id: String,
    bootstrap_device_public_key: String,
}

fn member_cell_for_actor(actor: &ActorId) -> Result<arkret_identifiers::CellRef, AppError> {
    let key = actor
        .canonical_key()
        .map_err(|error| seal_admission_error(format!("member Actor invalid: {error}")))?;
    let subject = arkret_wire::composite_subject(&[key])
        .map_err(|error| seal_admission_error(format!("member cell subject invalid: {error}")))?;
    arkret_identifiers::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
        .map_err(|error| seal_admission_error(format!("member cell invalid: {error}")))
}

pub(crate) async fn verified_availability_dependency_writes(
    state: &AppState,
    seal: &Seal,
) -> Result<Vec<soland_storage::GovernanceDependencyWrite>, AppError> {
    let store = state.persistence().governance_dependency_store();
    let mut dependencies_by_key = BTreeMap::new();
    for digest in &seal.availability_receipt_digests {
        let selector = GovernanceDependencySelector::AvailabilityReceipt {
            content_digest: digest.clone(),
        };
        let receipt_dependency = store
            .get(&seal.realm_id, &selector)
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("availability receipt lookup failed: {error}"),
                )
            })?
            .ok_or_else(|| {
                seal_admission_error(
                    "Seal commits an availability receipt that is not durably available",
                )
            })?;
        let evidence_digest = match &receipt_dependency {
            GovernanceDependency::AvailabilityReceipt {
                availability_receipt,
                ..
            } => availability_receipt.holder_signer_evidence_digest.clone(),
            _ => {
                return Err(seal_admission_error(
                    "availability receipt selector resolved to another dependency kind",
                ));
            }
        };
        let receipt_key = receipt_dependency
            .selector()
            .canonical_sort_key()
            .map_err(|error| seal_admission_error(error.to_string()))?;
        dependencies_by_key
            .entry(receipt_key)
            .or_insert(receipt_dependency);
        let evidence_selector =
            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: evidence_digest,
            };
        let evidence_dependency = store
            .get(&seal.realm_id, &evidence_selector)
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("availability signer evidence lookup failed: {error}"),
                )
            })?
            .ok_or_else(|| {
                seal_admission_error(
                    "availability receipt signer evidence is not durably available",
                )
            })?;
        let evidence_key = evidence_dependency
            .selector()
            .canonical_sort_key()
            .map_err(|error| seal_admission_error(error.to_string()))?;
        dependencies_by_key
            .entry(evidence_key)
            .or_insert(evidence_dependency);
    }
    let dependencies = dependencies_by_key.into_values().collect::<Vec<_>>();
    let (replay_context, events) = state
        .projections()
        .seal_dependency_replay_context(seal)
        .map_err(app_error_from_seal_reject)?;
    arkret::verify_seal_availability_dependencies_default(
        seal,
        &events,
        &replay_context,
        &dependencies,
    )
    .map_err(|error| seal_admission_error(error.to_string()))?;
    dependencies
        .into_iter()
        .enumerate()
        .map(|(edge_index, item)| {
            Ok(soland_storage::GovernanceDependencyWrite {
                realm_id: seal.realm_id.clone(),
                source: soland_storage::GovernanceDependencySource::Seal(seal.id.clone()),
                edge_index: u64::try_from(edge_index)
                    .map_err(|error| seal_admission_error(error.to_string()))?,
                item,
            })
        })
        .collect()
}

pub(crate) async fn validate_accepted_fork_resolution_records(
    state: &AppState,
    seal: &Seal,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), AppError> {
    for digest in &seal.delta {
        let Some(event) = state.projections().control_event(digest).map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("load accepted fork-resolution Move: {error}"),
            )
        })?
        else {
            continue;
        };
        if event.kind != arkret_wire::EventKind::ForkResolution {
            continue;
        }
        let _record =
            arkret_models_collaboration::events_payloads::ForkResolutionRecord::from_accepted_seal(
                &event,
                seal,
                digest_suite,
            )
            .map_err(|error| seal_admission_error(error.to_string()))?;
        // The accepted control-cell projection authorizes local normalization
        // only. It does not prove that any particular peer has aligned its
        // exact sibling scope, so confirmed evidence remains fail-closed until
        // the frontier worker supplies that separate per-peer proof.
    }
    Ok(())
}

/// Map an SDK [`SealReject`] onto an [`AppError`].
///
/// Every reject reason routes through the canonical Arkret error
/// registry:
///
/// - `UnknownPredecessor`, coverage mismatches, `Structural`, `MissingControlEvent`,
///   `ControlMoveRejected`, `seal_basis` rejects, `StateRootMismatch` ->
///   [`ErrorCode::SchemaViolation`] (handler-level rejects of a structurally invalid seal
///   envelope).
/// - `Store` → [`ErrorCode::InternalError`] (durable-store IO failure).
///
/// The resulting `AppError` is rendered with HTTP `409 Conflict` to match
/// the peer-event admission mapping — the registry default for
/// `SchemaViolation` is `422`, but seal rejects are conceptually a causal /
/// state-machine conflict, so `409` remains the wire status here. Call sites
/// that need a different status can override after conversion via
/// `.with_status(...)`.
fn app_error_from_seal_reject(reject: SealReject) -> AppError {
    let code = match &reject {
        SealReject::UnknownPredecessor
        | SealReject::DeltaAlreadyCovered
        | SealReject::Structural(_)
        | SealReject::MissingControlEvent { .. }
        | SealReject::ControlMoveRejected { .. }
        | SealReject::MissingSealBasis { .. }
        | SealReject::SealBasisOutsideClosure { .. }
        | SealReject::ControlEventSetRootMismatch { .. }
        | SealReject::CompletenessRootMismatch { .. }
        | SealReject::CoveredSetMismatch
        | SealReject::StateRootMismatch { .. } => ErrorCode::SchemaViolation,
        SealReject::Store(_) => ErrorCode::InternalError,
    };
    AppError::new(code, reject.to_string()).with_status(StatusCode::CONFLICT)
}

pub(super) fn api_admin_router() -> Router {
    Router::with_path("admin/seals/sign").post(admin_sign_seal)
}

// The notary uses `select_jws_verifier` which switches between
// shape-only (dev mode) and real ed25519 (production) based on
// `state.config().development_mode`.

/// Pick the Control Move proof verifier based on `config.development_mode`.
///
/// Returns a closure of the exact type `verify_control_move` / `apply_seal`
/// expect (`Fn(&Event) -> Result<(), String> + Copy`). The closure captures
/// `&AppState` by reference so the production branch can reach the DID
/// resolver chain; `&AppState` is `Copy`, so the closure is `Copy` too —
/// required by `apply_seal`'s `F: Copy` bound for batch verification.
///
/// The v1 control plane has no separate Move envelope: a Control Move is an
/// [`Event`] carrying `seal_basis`, so the transcript each proof signs is the
/// canonical Event proof binding (`encoding.md` §6), not a Move body. The
/// caller's `verify_control_move` has already run
/// `Event::validate_proof_bindings`, which pins every `proof.event_digest` to
/// the recomputed Event digest; this closure owns only the cryptographic
/// check.
pub fn select_jws_verifier(
    state: &AppState,
) -> impl Fn(&Event) -> Result<(), String> + Copy + use<'_> {
    move |event| verify_control_move_proofs(state, event)
}

/// Verify every proof on a Control Move against its canonical binding bytes.
///
/// `encoding.md` §6: the signed transcript names `actor_id` (the record
/// subject) even under delegated execution; only the resolved signer DID
/// switches to `executed_by`. The verification method MUST be rooted in that
/// signer so a Control Move cannot be admitted on a key that belongs to
/// somebody else.
fn verify_control_move_proofs(state: &AppState, event: &Event) -> Result<(), String> {
    if event.proofs.is_empty() {
        return Err("Control Move carries no proofs".to_owned());
    }
    let signer_root = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .signing_principal_id()
        .as_str()
        .to_owned();
    for proof in event
        .proofs
        .iter()
        .filter_map(arkret_wire::EventProof::as_producer)
    {
        // `did-usage-and-verification.md` §2.2: the method MUST be a DID URL
        // under the signer, never the bare signer DID. Event actor identities
        // are stable CoreIds while verification methods are rooted in Dids,
        // so compare the canonical DID projection instead of string prefixes.
        if !control_move_verification_method_matches_signer(
            &proof.verification_method,
            &signer_root,
        ) {
            return Err(format!(
                "Control Move proof verification method {} is not rooted in the signer {signer_root}",
                proof.verification_method
            ));
        }
        let canonical_bytes = proof
            .canonical_binding_bytes(&event.actor_id)
            .map_err(|error| format!("proof binding canonicalization failed: {error}"))?;
        if state.config().development_mode {
            crate::jws_verify::verify_jws_shape(
                &canonical_bytes,
                &proof.jws,
                &proof.verification_method,
                &signer_root,
            )?;
        } else {
            crate::jws_verify::verify_did_controlled_jws(
                &canonical_bytes,
                &proof.jws,
                &proof.verification_method,
                &signer_root,
                state,
            )?;
        }
    }
    Ok(())
}

fn control_move_verification_method_matches_signer(
    verification_method: &arkret_wire::DidUrl,
    signer_root: &str,
) -> bool {
    let Some((controller, _)) = verification_method.as_str().rsplit_once('#') else {
        return false;
    };
    let Ok(controller) = arkret_wire::Did::new(controller.to_owned()) else {
        return false;
    };
    arkret_wire::project_did_to_core_id(&controller)
        .is_ok_and(|controller_core| controller_core.as_str() == signer_root)
}

fn seal_admission_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message.into()).with_status(StatusCode::CONFLICT)
}

fn device_generation_fenced(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::PolicyViolation, message.into())
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("device_generation_fenced")
}

async fn device_generation_event_seal_context(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Option<DeviceGenerationEventSealContext>, AppError> {
    let records = state
        .event_queries()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("canonical Event store unavailable: {error}"),
            )
        })?;
    let bootstrap = records
        .iter()
        .filter(|record| {
            record.kind == arkret_wire::EventKind::RealmCreate.as_str()
                && record
                    .envelope
                    .pointer("/payload/object/purpose")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|purpose| {
                        matches!(
                            purpose,
                            "principal_control" | "agent_control" | "applet_managed_control"
                        )
                    })
        })
        .collect::<Vec<_>>();
    if bootstrap.is_empty() {
        return Ok(None);
    }
    if bootstrap.len() != 1 {
        return Err(seal_admission_error(
            "principal-control Realm has an ambiguous bootstrap anchor",
        ));
    }
    let bootstrap = bootstrap[0];
    let actor_id = serde_json::from_str::<ActorId>(&bootstrap.actor_id).map_err(|error| {
        seal_admission_error(format!(
            "principal-control bootstrap actor_id is invalid: {error}"
        ))
    })?;
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id.as_str(), &actor_id.to_string())
    {
        return Err(seal_admission_error(
            "principal-control bootstrap is stored outside the accepted actor PCR",
        ));
    }
    let principal_id = actor_id.signing_principal_id().clone();
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        principal_id.as_str(),
    )
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("device generation state unavailable: {error}"),
        )
    })?;
    if generation.as_ref().is_some_and(|generation| {
        generation.status
            == crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted
    }) {
        return Err(device_generation_fenced(
            "Seal admission is closed while the B-model generation slot is conflicted",
        ));
    }

    let bootstrap_authorizes = records
        .iter()
        .filter(|record| {
            record.actor_id == actor_id.to_string()
                && record.kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
                && record
                    .envelope
                    .get("prev_refs")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|refs| {
                        refs.len() == 1 && refs[0].as_str() == Some(bootstrap.event_id.as_str())
                    })
        })
        .collect::<Vec<_>>();
    if bootstrap_authorizes.len() != 1 {
        return Err(seal_admission_error(
            "principal-control Realm has an incomplete or ambiguous bootstrap unit",
        ));
    }
    let bootstrap_authorize = bootstrap_authorizes[0];
    let bootstrap_payload = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
    >(
        bootstrap_authorize
            .envelope
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|error| {
        seal_admission_error(format!(
            "stored bootstrap device authorization payload is invalid: {error}"
        ))
    })?;
    let bootstrap_required_delta = [
        bootstrap.canonical_digest.as_str(),
        bootstrap_authorize.canonical_digest.as_str(),
    ]
    .into_iter()
    .map(|digest| Hash::new(digest.to_owned()))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| seal_admission_error(format!("invalid bootstrap Event digest: {error}")))?;

    let generation_fence = if generation.is_some() {
        crate::routing::events::event_log::governance_proof::first_generation_event_seal_requirement(
            state, &records,
        )
        .await?
    } else {
        None
    };
    if generation_fence
        .as_ref()
        .is_some_and(|requirement| requirement.principal_id != principal_id)
    {
        return Err(seal_admission_error(
            "active re-anchor belongs to a different principal",
        ));
    }
    let cas_frontier_refs = state
        .projections()
        .realm_seal_leaves(realm_id)
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("Seal frontier unavailable: {error}"),
            )
        })?;
    let accepted_frontier_refs = if let Some(requirement) = &generation_fence {
        requirement.accepted_frontier_refs.clone()
    } else {
        cas_frontier_refs.clone()
    };

    Ok(Some(DeviceGenerationEventSealContext {
        actor_id,
        principal_id,
        current_generation_ref: generation.map(|generation| generation.current_ref),
        records,
        accepted_frontier_refs,
        cas_frontier_refs,
        generation_fence,
        bootstrap_required_delta,
        bootstrap_device_id: bootstrap_payload.device_id.as_str().to_owned(),
        bootstrap_device_public_key: bootstrap_payload.device_public_key_did.to_string(),
    }))
}

fn validate_bootstrap_first_seal(
    current: &BTreeSet<Hash>,
    target: &BTreeSet<Hash>,
    required_delta: &[Hash],
) -> Result<bool, AppError> {
    let required = required_delta.iter().cloned().collect::<BTreeSet<_>>();
    if required.len() != required_delta.len() {
        return Err(seal_admission_error(
            "bootstrap Seal required delta contains duplicates",
        ));
    }
    let covered_required = current.intersection(&required).count();
    if covered_required != 0 && covered_required != required.len() {
        return Err(seal_admission_error(
            "accepted Seal coverage contains a partial principal bootstrap unit",
        ));
    }
    if covered_required == required.len() {
        return Ok(false);
    }
    if !required.is_subset(target) {
        return Err(seal_admission_error(
            "first principal-control Seal target omits the bootstrap unit",
        ));
    }
    Ok(true)
}

fn device_verification_method_matches(
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    verification_method: &str,
) -> bool {
    // `did-usage-and-verification.md` §2.2: a proof `verification_method` MUST
    // be a DID URL with a `#fragment`; a DID without URL components never names a concrete
    // verification method.
    let Some(fragment) = device_public_key.strip_prefix("did:key:") else {
        return false;
    };
    let did_key = device_public_key;
    if verification_method == format!("{did_key}#{fragment}") {
        return true;
    }
    arkret_wire::DidUrl::new(verification_method.to_owned()).is_ok_and(|method| {
        session_device_verification_method_matches(principal_id, device_id, &method)
    })
}

pub(crate) fn session_device_verification_method_matches(
    principal_id: &str,
    device_id: &str,
    verification_method: &arkret_wire::DidUrl,
) -> bool {
    let Some((_, fragment)) = verification_method.as_str().rsplit_once('#') else {
        return false;
    };
    if fragment != device_id {
        return false;
    }
    let Ok(did) = arkret_identity::verification_method_did(verification_method) else {
        return false;
    };
    arkret_wire::project_did_to_core_id(&did).is_ok_and(|core_id| core_id.as_str() == principal_id)
}

fn first_seal_signer_matches(
    signer_device_id: &str,
    signer_public_key: &str,
    required_device_id: &str,
    required_public_key: &str,
) -> bool {
    signer_device_id == required_device_id && signer_public_key == required_public_key
}

fn verify_device_seal_signature(
    seal: &Seal,
    device_public_key: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), AppError> {
    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(device_generation_fenced(
            "B-model Seal requires one identifiable current-generation device signature",
        ));
    };
    let canonical_bytes = seal
        .canonical_bytes_for_id()
        .map_err(|error| seal_admission_error(format!("Seal canonical bytes: {error}")))?;
    let expected_digest = arkret_canonical::digest(digest_suite, &canonical_bytes);
    if signature.payload_digest.as_str() != expected_digest {
        return Err(device_generation_fenced(
            "B-model device Seal signature payload_digest mismatch",
        ));
    }
    let multibase = device_public_key.strip_prefix("did:key:").ok_or_else(|| {
        device_generation_fenced("B-model device Seal key must be a canonical did:key")
    })?;
    let key = arkret_canonical::decode_ed25519_multibase(multibase).map_err(|error| {
        device_generation_fenced(format!("B-model device Seal key is invalid: {error}"))
    })?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &signature.jws,
            &canonical_bytes,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_vec(),
            },
        )
        .map_err(|error| {
            device_generation_fenced(format!("B-model device Seal signature is invalid: {error}"))
        })
}

fn ordinary_event_device_id(record: &soland_services::events::AcceptedEvent) -> Option<String> {
    let verification_method = record
        .envelope
        .get("proofs")
        .and_then(serde_json::Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(|proof| proof.get("verification_method"))
        .and_then(serde_json::Value::as_str)?;
    let (controller, fragment) = verification_method.rsplit_once('#')?;
    let controller = arkret_wire::Did::new(controller.to_owned()).ok()?;
    let actor = serde_json::from_str::<ActorId>(&record.actor_id).ok()?;
    if arkret_wire::project_did_to_core_id(&controller)
        .ok()?
        .as_str()
        != actor.signing_principal_id().as_str()
    {
        return None;
    }
    Some(str::trim(fragment))
        .filter(|fragment| !fragment.is_empty())
        .map(|fragment| {
            if fragment.starts_with("ak:device:") {
                fragment.to_owned()
            } else {
                format!("ak:device:{fragment}")
            }
        })
}

async fn try_apply_device_generation_event_seal(
    state: &AppState,
    seal: &Seal,
) -> Result<Option<SealEffect>, AppError> {
    let digest_suites = state
        .projections()
        .seal_digest_suites(seal)
        .map_err(app_error_from_seal_reject)?;
    seal.validate_id(digest_suites.seal_digest_suite)
        .map_err(|error| seal_admission_error(format!("Seal id: {error}")))?;
    seal.validate_structural()
        .map_err(|error| seal_admission_error(format!("Seal structure: {error}")))?;
    let Some(initial_context) = device_generation_event_seal_context(state, &seal.realm_id).await?
    else {
        return Ok(None);
    };
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(
            initial_context.principal_id.as_str(),
        );
    let _guard = generation_lock.lock().await;
    if let Some(existing) = state.projections().seal_by_id(&seal.id).map_err(|error| {
        AppError::new(
            ErrorCode::InternalError,
            format!("Seal lookup failed: {error}"),
        )
    })? {
        if existing != *seal {
            return Err(seal_admission_error(
                "Seal id already exists with different signature material",
            ));
        }
        return Ok(Some(committed_seal_effect(seal)));
    }
    let Some(mut context) = device_generation_event_seal_context(state, &seal.realm_id).await?
    else {
        return Err(seal_admission_error(
            "principal-control Realm disappeared during Seal admission",
        ));
    };
    if !state
        .projections()
        .seal_predecessors_known(&seal.predecessor_refs)
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("Seal predecessor lookup failed: {error}"),
            )
        })?
    {
        return Err(seal_admission_error(
            "B-model Event Seal has an unknown predecessor",
        ));
    }
    let mut expected_frontier = context.accepted_frontier_refs.clone();
    expected_frontier.sort();
    if seal.predecessor_refs != expected_frontier {
        return Err(device_generation_fenced(
            "B-model Event Seal predecessors differ from the complete accepted generation frontier",
        ));
    }
    let predecessor_coverage = state
        .projections()
        .predecessor_covered_events(&seal.predecessor_refs)
        .map_err(app_error_from_seal_reject)?;
    if seal
        .delta
        .iter()
        .any(|digest| predecessor_coverage.contains(digest))
    {
        return Err(seal_admission_error(
            "B-model Event Seal delta repeats predecessor coverage",
        ));
    }
    let mut target = predecessor_coverage.clone();
    target.extend(seal.delta.iter().cloned());
    let declared = seal
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared.len() != seal.covered_event_digests.len() || declared != target {
        return Err(seal_admission_error(
            "B-model Event Seal covered_event_digests must equal predecessor coverage plus delta",
        ));
    }
    let expected_control_root = control_event_set_root(&target, digest_suites.seal_digest_suite)
        .map_err(app_error_from_seal_reject)?;
    let mut completeness_events = Vec::with_capacity(context.records.len());
    let mut available_digests = BTreeSet::new();
    for record in &context.records {
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            seal_admission_error(format!(
                "stored B-model Event {} is invalid: {error}",
                record.event_id
            ))
        })?;
        let parsed_digest = Hash::new(
            event
                .event_digest_with_digest_suite(record.digest_suite)
                .map_err(|error| {
                    seal_admission_error(format!(
                        "stored B-model Event {} digest failed: {error}",
                        record.event_id
                    ))
                })?,
        )
        .map_err(|error| {
            seal_admission_error(format!(
                "stored B-model Event {} digest is invalid: {error}",
                record.event_id
            ))
        })?;
        if parsed_digest.as_str() != record.canonical_digest {
            return Err(seal_admission_error(format!(
                "stored B-model Event {} canonical digest {} differs from parsed digest {}",
                record.event_id, record.canonical_digest, parsed_digest
            )));
        }
        available_digests.insert(parsed_digest);
        completeness_events.push((event, record.digest_suite));
    }
    let missing = target
        .difference(&available_digests)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let sources = target
            .difference(&available_digests)
            .map(|digest| {
                if seal.delta.contains(digest) {
                    "delta"
                } else {
                    "predecessor"
                }
            })
            .collect::<Vec<_>>();
        return Err(seal_admission_error(format!(
            "B-model Event Seal coverage contains unresolved {} canonical digests: {}",
            sources.join(","),
            missing.join(",")
        )));
    }
    let expected_completeness_root = arkret_state::control_event_completeness_root(
        &completeness_events,
        &target,
        digest_suites.seal_digest_suite,
    )
    .map_err(app_error_from_seal_reject)?;
    if seal.control_event_set_root != expected_control_root
        || seal.completeness_root != expected_completeness_root
    {
        return Err(seal_admission_error(
            "B-model Event Seal control/completeness root mismatch",
        ));
    }
    let expected_notary_seq = if seal.predecessor_refs.is_empty() {
        0
    } else {
        let mut maximum = None;
        for predecessor in &seal.predecessor_refs {
            let value = state
                .projections()
                .seal_by_id(predecessor)
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::InternalError,
                        format!("Seal predecessor lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| seal_admission_error("B-model Event Seal predecessor is missing"))?;
            maximum = Some(maximum.map_or(value.notary_seq, |current: u64| {
                current.max(value.notary_seq)
            }));
        }
        maximum
            .and_then(|sequence| sequence.checked_add(1))
            .ok_or_else(|| seal_admission_error("B-model Event Seal notary_seq overflow"))?
    };
    if seal.notary_seq != expected_notary_seq {
        return Err(seal_admission_error(
            "B-model Event Seal notary_seq does not follow its predecessors",
        ));
    }

    let recovery_first = context
        .generation_fence
        .as_ref()
        .map(|requirement| {
            crate::notary::validate_first_generation_event_seal(
                &seal.predecessor_refs,
                &predecessor_coverage,
                &target,
                requirement,
            )
        })
        .transpose()
        .map_err(|error| seal_admission_error(error.to_string()))?
        .unwrap_or(false);
    if recovery_first
        && let Some(requirement) = &context.generation_fence
        && requirement.payload.pre_fence_seal_frontier.is_none()
    {
        arkret_models_collaboration::events_payloads::device_identity::validate_device_reanchor_recovery_first_seal(
            &requirement.payload,
            &seal.predecessor_refs,
            &seal.delta,
            &requirement.reanchor_digest,
            &requirement.replacement_authorize_digest,
        )
        .map_err(|error| seal_admission_error(format!("recovery-first Event Seal: {error}")))?;
    }
    let bootstrap_first = if context.generation_fence.is_none() {
        validate_bootstrap_first_seal(
            &predecessor_coverage,
            &target,
            &context.bootstrap_required_delta,
        )?
    } else {
        false
    };

    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(device_generation_fenced(
            "B-model Event Seal requires one identifiable device signature",
        ));
    };
    let devices = state
        .identities()
        .devices_for_actor(context.principal_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("device inventory unavailable: {error}"),
            )
        })?;
    let signer = devices
        .iter()
        .find(|device| {
            let Some(public_key) = device
                .payload
                .get("device_public_key")
                .and_then(serde_json::Value::as_str)
            else {
                return false;
            };
            device_verification_method_matches(
                context.principal_id.as_str(),
                &device.device_id,
                public_key,
                &signature.verification_method,
            )
        })
        .ok_or_else(|| {
            device_generation_fenced("B-model Event Seal signer is not an authorized device")
        })?;
    let signer_public_key = signer
        .payload
        .get("device_public_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| device_generation_fenced("B-model Event Seal signer key is missing"))?;
    if signer.revoked_at.is_some()
        || signer.verification_state != "verified"
        || context
            .current_generation_ref
            .as_ref()
            .is_some_and(|generation| {
                signer
                    .payload
                    .get("authorized_generation_ref")
                    .and_then(serde_json::Value::as_u64)
                    != Some(*generation)
            })
    {
        return Err(device_generation_fenced(
            "B-model Event Seal signer does not belong to the active device generation",
        ));
    }
    if recovery_first {
        let requirement = context
            .generation_fence
            .as_ref()
            .expect("recovery-first Seal has a generation fence");
        if !first_seal_signer_matches(
            &signer.device_id,
            signer_public_key,
            &requirement.replacement_device_id,
            &requirement.replacement_device_public_key,
        ) {
            return Err(device_generation_fenced(
                "first new-generation Seal must be signed by the replacement recovery device",
            ));
        }
    }
    if bootstrap_first
        && !first_seal_signer_matches(
            &signer.device_id,
            signer_public_key,
            &context.bootstrap_device_id,
            &context.bootstrap_device_public_key,
        )
    {
        return Err(device_generation_fenced(
            "first principal-control Seal must be signed by the bootstrap device",
        ));
    }
    verify_device_seal_signature(seal, signer_public_key, digest_suites.seal_digest_suite)?;

    let quarantined =
        crate::routing::identity::device_generation::quarantined_generation_event_digests(
            state,
            context.principal_id.as_str(),
        )
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("device generation quarantine state unavailable: {error}"),
            )
        })?;
    let admitted_generation_ref = context.current_generation_ref;
    let mut admitted_frontier = context.accepted_frontier_refs.clone();
    admitted_frontier.sort();
    let mut admitted_cas_frontier = context.cas_frontier_refs.clone();
    admitted_cas_frontier.sort();
    let admitted_reanchor_digest = context
        .generation_fence
        .as_ref()
        .map(|requirement| requirement.reanchor_digest.clone());
    let mut records_by_digest = BTreeMap::new();
    for record in context.records.drain(..) {
        if records_by_digest
            .insert(record.canonical_digest.clone(), record)
            .is_some()
        {
            return Err(seal_admission_error(
                "canonical Event history contains duplicate digests",
            ));
        }
    }
    let mut anchor_event_ids = context
        .bootstrap_required_delta
        .iter()
        .filter_map(|digest| records_by_digest.get(digest.as_str()))
        .map(|record| record.event_id.clone())
        .collect::<BTreeSet<_>>();
    for record in records_by_digest.values().filter(|record| {
        record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR
            && !quarantined.contains(&record.canonical_digest)
    }) {
        anchor_event_ids.insert(record.event_id.clone());
        if let Some(authorize) = soland_services::events::paired_replacement_authorize(
            record,
            records_by_digest.values(),
        ) {
            anchor_event_ids.insert(authorize.event_id.clone());
        }
    }
    let mut new_ops: Vec<(
        arkret_identifiers::CellRef,
        arkret_state::lattice::ordered_log::IssuedOp,
    )> = Vec::new();
    for digest in &seal.delta {
        if quarantined.contains(digest.as_str()) {
            return Err(device_generation_fenced(
                "B-model Event Seal delta contains quarantined generation history",
            ));
        }
        let record = records_by_digest.get(digest.as_str()).ok_or_else(|| {
            seal_admission_error(format!(
                "B-model Event Seal delta digest {} is not a canonical Event",
                digest.as_str()
            ))
        })?;
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            seal_admission_error(format!(
                "stored Event {} is invalid: {error}",
                record.event_id
            ))
        })?;
        let event_digest_suite = if seal.predecessor_refs.is_empty()
            && event.kind == arkret_wire::EventKind::RealmCreate
        {
            arkret_canonical::DigestSuite::Sha256
        } else {
            digest_suites.event_digest_suite
        };
        if record.digest_suite != event_digest_suite {
            return Err(seal_admission_error(format!(
                "stored Event {} digest suite differs from the verified Seal context",
                record.event_id
            )));
        }
        let recomputed = event
            .event_digest_with_digest_suite(event_digest_suite)
            .map_err(|error| {
                seal_admission_error(format!(
                    "stored Event {} digest failed: {error}",
                    record.event_id
                ))
            })?;
        if recomputed != record.canonical_digest || recomputed != digest.as_str() {
            return Err(seal_admission_error(format!(
                "stored Event {} canonical digest mismatch",
                record.event_id
            )));
        }
        if event.realm_id.as_str() != seal.realm_id.as_str() || event.seal_ref.is_some() {
            return Err(seal_admission_error(
                "B-model Event Seal delta must contain control Events from the same Realm",
            ));
        }
        // v1 has no producer `effects[]`: whether an Event is control material
        // is decided by its registered contract, not by an envelope array.
        let projects_writes = registered_event_projects_writes(state, &event, event_digest_suite)?;
        if !projects_writes && !anchor_event_ids.contains(&record.event_id) {
            return Err(seal_admission_error(
                "B-model Event Seal delta contains a non-control Event",
            ));
        }
        if event.actor_id == context.actor_id
            && !anchor_event_ids.contains(&record.event_id)
            && record.envelope.get("executed_by").is_none()
        {
            let device_id = ordinary_event_device_id(record).ok_or_else(|| {
                device_generation_fenced(
                    "B-model Event Seal delta contains an Event without a device signer",
                )
            })?;
            let event_device = devices
                .iter()
                .find(|device| device.device_id == device_id)
                .ok_or_else(|| {
                    device_generation_fenced(
                        "B-model Event Seal delta contains an Event from an unknown device",
                    )
                })?;
            if event_device.revoked_at.is_some()
                || event_device.verification_state != "verified"
                || context
                    .current_generation_ref
                    .as_ref()
                    .is_some_and(|generation| {
                        event_device
                            .payload
                            .get("authorized_generation_ref")
                            .and_then(serde_json::Value::as_u64)
                            != Some(*generation)
                    })
            {
                return Err(device_generation_fenced(
                    "B-model Event Seal delta contains an Event from an older device generation",
                ));
            }
        }
        // The membership `from` is the frozen pre-state of the member cell, not
        // a producer-declared value: read it off the ops accumulated for this
        // Seal delta so far.
        let member_cell = member_cell_for_actor(&event.actor_id)?;
        let mut accumulated: BTreeMap<
            arkret_identifiers::CellRef,
            Vec<arkret_state::lattice::ordered_log::IssuedOp>,
        > = BTreeMap::new();
        for (cell, issued) in &new_ops {
            accumulated
                .entry(cell.clone())
                .or_default()
                .push(issued.clone());
        }
        let invite_accept_from = accumulated
            .get(&member_cell)
            .and_then(|ops| ops.last())
            .and_then(|issued| issued.op.op.to.as_ref())
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| Some("leave".to_owned()));
        new_ops.extend(
            crate::routing::events::event_log::governance_proof::canonical_event_ops(
                state,
                &seal.realm_id,
                &event,
                digest,
                &accumulated,
                invite_accept_from.as_deref(),
                event_digest_suite,
            )?,
        );
    }

    let refreshed = device_generation_event_seal_context(state, &seal.realm_id)
        .await?
        .ok_or_else(|| {
            device_generation_fenced("B-model device generation disappeared during Seal admission")
        })?;
    let mut refreshed_frontier = refreshed.accepted_frontier_refs.clone();
    refreshed_frontier.sort();
    let mut refreshed_cas_frontier = refreshed.cas_frontier_refs.clone();
    refreshed_cas_frontier.sort();
    if refreshed.current_generation_ref != admitted_generation_ref
        || refreshed_frontier != admitted_frontier
        || refreshed_cas_frontier != admitted_cas_frontier
        || refreshed
            .generation_fence
            .as_ref()
            .map(|requirement| &requirement.reanchor_digest)
            != admitted_reanchor_digest.as_ref()
    {
        return Err(device_generation_fenced(
            "B-model device generation or accepted frontier changed during Seal admission",
        ));
    }

    let availability_dependency_writes =
        verified_availability_dependency_writes(state, seal).await?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    match state.projections().commit_event_seal_if_frontier(
        seal,
        digest_suite,
        &context.cas_frontier_refs,
        &new_ops,
        &target,
        &BTreeSet::new(),
        &availability_dependency_writes,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(device_generation_fenced(
                "B-model device generation Seal lost the atomic frontier compare-and-swap",
            ));
        }
        Err(StoreError::Conflict(error)) => return Err(seal_admission_error(error)),
        Err(error) => {
            return Err(AppError::new(
                ErrorCode::InternalError,
                format!("commit Event Seal atomically: {error}"),
            ));
        }
    }
    if state.storage_mode() == "memory" {
        validate_accepted_fork_resolution_records(state, seal, digest_suite).await?;
    }
    Ok(Some(committed_seal_effect(seal)))
}

/// Decide whether an accepted Event is registered control material using the
/// same frozen reducer authority state as admission and Seal application.
///
/// Capability Grant writes include receiver-derived authority audit members.
/// A resolver-free projection therefore cannot distinguish an unresolved
/// parent from a non-control Event and must not be used at this boundary.
fn registered_event_projects_writes(
    state: &AppState,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<bool, AppError> {
    state
        .projections()
        .project_cell_writes_with_digest_suite(event, digest_suite)
        .map(|writes| !writes.is_empty())
        .map_err(|error| {
            seal_admission_error(format!(
                "stored Event {} registered projection failed: {error}",
                event.event_id
            ))
        })
}

pub(crate) async fn apply_agent_event_seal(
    state: &AppState,
    seal: &Seal,
    agent_record: &soland_services::identity::AgentPairingState,
    session_device_id: &str,
) -> Result<SealEffect, AppError> {
    let digest_suites = state
        .projections()
        .seal_digest_suites(seal)
        .map_err(app_error_from_seal_reject)?;
    seal.validate_id(digest_suites.seal_digest_suite)
        .map_err(|error| seal_admission_error(format!("Agent PCR Seal id: {error}")))?;
    seal.validate_structural()
        .map_err(|error| seal_admission_error(format!("Agent PCR Seal structure: {error}")))?;
    crate::jws_verify::verify_replay_window(&seal.hlc, state.config().jws_replay_window_seconds)
        .map_err(|error| seal_admission_error(format!("Agent PCR Seal replay_window: {error}")))?;
    // `Seal.kind` is an in-memory classification and is intentionally absent
    // from the v1 wire schema / signed canonical body. This admission path
    // proves compaction semantics below by requiring exact cumulative coverage,
    // roots, state, and delta, then normalizes the accepted local value so
    // runtime DAG consumers can classify it without trusting an unsigned field.
    let accepted_seal = seal.clone();
    let seal = &accepted_seal;
    if seal.realm_id.as_str() != agent_record.principal_control_realm_id {
        return Err(seal_admission_error(
            "Agent PCR Seal Realm differs from the accepted Agent binding",
        ));
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        agent_record,
        chrono::Utc::now(),
    )
    .await?;

    let admission_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(
            seal.realm_id.as_str(),
        );
    let _guard = admission_lock.lock().await;
    if let Some(existing) = state.projections().seal_by_id(&seal.id).map_err(|error| {
        AppError::new(
            ErrorCode::InternalError,
            format!("Agent PCR Seal lookup failed: {error}"),
        )
    })? {
        if existing != *seal {
            return Err(seal_admission_error(
                "Agent PCR Seal id already exists with different signature material",
            ));
        }
        return Ok(committed_seal_effect(seal));
    }

    let mut leaves = state
        .projections()
        .realm_seal_leaves(&seal.realm_id)
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("Agent PCR Seal frontier unavailable: {error}"),
            )
        })?;
    leaves.sort();
    if seal.predecessor_refs != leaves {
        return Err(seal_admission_error(
            "Agent PCR Seal predecessors differ from the complete accepted frontier",
        ));
    }
    let current = state
        .projections()
        .predecessor_covered_events(&leaves)
        .map_err(app_error_from_seal_reject)?;

    let records = state
        .event_queries()
        .realm_events_newest_first(seal.realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("Agent PCR Event history unavailable: {error}"),
            )
        })?;
    let mut events = Vec::with_capacity(records.len());
    let mut event_digest_suites = BTreeMap::new();
    for record in records {
        let event = serde_json::from_value::<Event>(record.envelope).map_err(|error| {
            seal_admission_error(format!(
                "stored Agent PCR Event {} is invalid: {error}",
                record.event_id
            ))
        })?;
        let digest = event
            .event_digest_with_digest_suite(record.digest_suite)
            .map_err(|error| {
                seal_admission_error(format!(
                    "stored Agent PCR Event {} digest failed: {error}",
                    event.event_id
                ))
            })?;
        if digest != record.canonical_digest {
            return Err(seal_admission_error(format!(
                "stored Agent PCR Event {} canonical digest mismatch",
                event.event_id
            )));
        }
        event_digest_suites.insert(event.event_id.clone(), record.digest_suite);
        events.push(event);
    }
    let material = arkret_bootstrap::materialize_agent_pcr_control(&events, &|event| {
        let event_digest_suite = event_digest_suites
            .get(&event.event_id)
            .copied()
            .ok_or_else(|| "Agent PCR Event has no frozen digest suite".to_owned())?;
        state
            .projections()
            .project_cell_writes_with_digest_suite(event, event_digest_suite)
    })
    .map_err(|error| {
        let kinds = events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>()
            .join(",");
        seal_admission_error(format!(
            "Agent PCR control material is invalid: {error}; loaded {} Realm Events ({kinds})",
            events.len()
        ))
    })?;
    let record_controller_id = arkret_wire::DidCoreId::new(agent_record.controller_id.clone())
        .or_else(|_| {
            arkret_wire::Did::new(agent_record.controller_id.clone())
                .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        })
        .map_err(|error| {
            device_generation_fenced(format!(
                "accepted Agent controller identity is invalid: {error}"
            ))
        })?;
    if material.realm_id != seal.realm_id
        || material.agent_id.signing_principal_id().as_str() != agent_record.id
        || material.controller_id.signing_principal_id() != &record_controller_id
        || material.authorization_ref.as_str() != agent_record.controller_authorization_ref.as_str()
    {
        return Err(device_generation_fenced(
            "Agent PCR Seal authority differs from the accepted Agent delegation",
        ));
    }

    let target = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !current.is_subset(&target) {
        return Err(seal_admission_error(
            "Agent PCR accepted coverage is not a subset of canonical history",
        ));
    }
    let expected_delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if expected_delta.is_empty() || seal.delta != expected_delta {
        return Err(seal_admission_error(
            "Agent PCR Seal delta must equal all newly accepted canonical Events",
        ));
    }
    let declared = seal
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared.len() != seal.covered_event_digests.len() || declared != target {
        return Err(seal_admission_error(
            "Agent PCR Seal coverage differs from canonical Event history",
        ));
    }
    let expected_control_root = control_event_set_root(&target, digest_suites.seal_digest_suite)
        .map_err(app_error_from_seal_reject)?;
    let completeness_events = events
        .iter()
        .map(|event| {
            event_digest_suites
                .get(&event.event_id)
                .copied()
                .map(|digest_suite| (event.clone(), digest_suite))
                .ok_or_else(|| {
                    seal_admission_error("Agent PCR Event has no frozen completeness digest suite")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_completeness_root = arkret_state::control_event_completeness_root(
        &completeness_events,
        &target,
        digest_suites.seal_digest_suite,
    )
    .map_err(app_error_from_seal_reject)?;
    if seal.control_event_set_root != expected_control_root
        || seal.completeness_root != expected_completeness_root
    {
        return Err(seal_admission_error(
            "Agent PCR Seal control/completeness root mismatch",
        ));
    }
    if seal.state_root != material.state_root {
        return Err(seal_admission_error(format!(
            "Agent PCR Seal state_root mismatch: submitted {}, expected {}",
            seal.state_root, material.state_root
        )));
    }
    let expected_notary_seq = leaves
        .iter()
        .map(|leaf| {
            state
                .projections()
                .seal_by_id(leaf)
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::InternalError,
                        format!("Agent PCR predecessor lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| seal_admission_error("Agent PCR predecessor is missing"))
                .map(|predecessor| predecessor.notary_seq)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .map_or(Ok(0), |sequence| {
            sequence
                .checked_add(1)
                .ok_or_else(|| seal_admission_error("Agent PCR Seal notary_seq overflow"))
        })?;
    if seal.notary_seq != expected_notary_seq {
        return Err(seal_admission_error(
            "Agent PCR Seal notary_seq does not follow its predecessors",
        ));
    }

    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(device_generation_fenced(
            "Agent PCR Seal requires one controller-device signature",
        ));
    };
    if !session_device_verification_method_matches(
        &agent_record.controller_id,
        session_device_id,
        &signature.verification_method,
    ) {
        return Err(device_generation_fenced(
            "Agent PCR Seal signer differs from the authenticated controller device",
        ));
    }
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: agent_record.controller_id.clone(),
            device_id: session_device_id.to_owned(),
        })
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("controller device lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| device_generation_fenced("controller device is not registered"))?;
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        &agent_record.controller_id,
    )
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("controller device generation unavailable: {error}"),
        )
    })?;
    if device.revoked_at.is_some()
        || device.verification_state != "verified"
        || generation.as_ref().is_some_and(|generation| {
            generation.status
                != crate::routing::identity::device_generation::DeviceGenerationStatus::Active
                || device
                    .payload
                    .get("authorized_generation_ref")
                    .and_then(serde_json::Value::as_u64)
                    != Some(generation.current_ref)
        })
    {
        return Err(device_generation_fenced(
            "Agent PCR Seal signer is not an active controller device",
        ));
    }
    let public_key = device
        .payload
        .get("device_public_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| device_generation_fenced("controller device signing key is missing"))?;
    verify_device_seal_signature(seal, public_key, digest_suites.seal_digest_suite)?;

    let delta = seal.delta.iter().cloned().collect::<BTreeSet<_>>();
    let new_ops = material
        .event_ops
        .iter()
        .filter(|(_, issued)| delta.contains(&issued.op.move_id))
        .cloned()
        .collect::<Vec<_>>();
    let availability_dependency_writes =
        verified_availability_dependency_writes(state, seal).await?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    match state.projections().commit_event_seal_if_frontier(
        seal,
        digest_suite,
        &leaves,
        &new_ops,
        &target,
        &BTreeSet::new(),
        &availability_dependency_writes,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(seal_admission_error(
                "Agent PCR Seal lost the atomic frontier compare-and-swap",
            ));
        }
        Err(StoreError::Conflict(error)) => return Err(seal_admission_error(error)),
        Err(error) => {
            return Err(AppError::new(
                ErrorCode::InternalError,
                format!("commit Agent PCR Seal atomically: {error}"),
            ));
        }
    }
    if state.storage_mode() == "memory" {
        validate_accepted_fork_resolution_records(state, seal, digest_suite).await?;
    }
    Ok(committed_seal_effect(seal))
}

pub(crate) async fn apply_inbound_seal(
    state: &AppState,
    seal: &Seal,
) -> Result<SealEffect, AppError> {
    let delta_entries = seal
        .delta
        .iter()
        .map(|digest| digest.as_str().to_owned())
        .collect::<Vec<_>>();
    validate_seal_delta_entries(&delta_entries).map_err(|(code, reason)| {
        AppError::new(code, reason).with_status(StatusCode::BAD_REQUEST)
    })?;
    crate::jws_verify::verify_replay_window(&seal.hlc, state.config().jws_replay_window_seconds)
        .map_err(|error| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("seal replay_window: {error}"),
            )
            .with_status(StatusCode::CONFLICT)
        })?;
    if let Some(effect) = try_apply_device_generation_event_seal(state, seal).await? {
        return Ok(effect);
    }
    verify_realm_notary_seal(state, seal).await?;
    let verifier = select_jws_verifier(state);
    let context = if seal.predecessor_refs.is_empty() {
        let events_with_digests = seal
            .delta
            .iter()
            .map(|digest| {
                state
                    .projections()
                    .control_event(digest)
                    .map_err(|error| {
                        AppError::new(
                            ErrorCode::InternalError,
                            format!("load first-Seal Control Move: {error}"),
                        )
                    })?
                    .map(|event| (digest.clone(), event))
                    .ok_or_else(|| {
                        seal_admission_error(format!("first Seal is missing Control Move {digest}"))
                    })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let events = arkret_state::deterministic_order(events_with_digests)
            .into_iter()
            .map(|(_, event)| event)
            .collect::<Vec<_>>();
        arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
            .map_err(|error| seal_admission_error(error.to_string()))?;
        arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
    } else {
        arkret_wire::event_envelope::EventSubmitContext::Standard
    };
    let expected_store_frontier = state
        .projections()
        .realm_seal_leaves(&seal.realm_id)
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("Seal frontier unavailable before atomic admission: {error}"),
            )
        })?;
    let prepared = state
        .projections()
        .prepare_seal_in_context(seal, verifier, context)
        .map_err(app_error_from_seal_reject)?;
    let governance_dependencies = verified_availability_dependency_writes(state, seal).await?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    match state.projections().commit_event_seal_if_frontier(
        seal,
        digest_suite,
        &expected_store_frontier,
        &prepared.new_ops,
        &prepared.covered_event_digests,
        &BTreeSet::new(),
        &governance_dependencies,
    ) {
        Ok(true) => {
            if state.storage_mode() == "memory" {
                validate_accepted_fork_resolution_records(state, seal, digest_suite).await?;
            }
            Ok(prepared.effect)
        }
        Ok(false) => Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Seal frontier changed during atomic admission".to_owned(),
        )
        .with_status(StatusCode::CONFLICT)),
        Err(StoreError::Conflict(error)) => Err(seal_admission_error(error)),
        Err(error) => Err(AppError::new(
            ErrorCode::InternalError,
            format!("commit inbound Seal atomically: {error}"),
        )),
    }
}

async fn verify_realm_notary_seal(state: &AppState, seal: &Seal) -> Result<(), AppError> {
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    let notary = crate::notary::NotaryWorker::for_service(state.service_id().clone())
        .notary_value_for_seal(state, seal)
        .map_err(|error| {
            AppError::new(
                ErrorCode::DirectoryGovernanceProofSignatureInvalid,
                format!("resolve Seal notary authority: {error}"),
            )
        })?;
    let canonical_bytes = seal.canonical_bytes_for_id().map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("derive Seal signature transcript: {error}"),
        )
    })?;
    let signatures = match (&notary, &seal.notary_signature) {
        (arkret_wire::notary::NotaryValue::SingleSigner { .. }, NotarySig::Single(signature))
        | (arkret_wire::notary::NotaryValue::OpenSet { .. }, NotarySig::Single(signature))
        | (arkret_wire::notary::NotaryValue::Mixed { .. }, NotarySig::Single(signature)) => {
            std::slice::from_ref(signature)
        }
        (arkret_wire::notary::NotaryValue::Threshold { .. }, NotarySig::Multi(multi))
        | (arkret_wire::notary::NotaryValue::Mixed { .. }, NotarySig::Multi(multi)) => {
            multi.signatures.as_slice()
        }
        _ => {
            return Err(AppError::new(
                ErrorCode::DirectoryGovernanceProofSignatureInvalid,
                "Seal signature shape does not match the frozen notary value".to_owned(),
            ));
        }
    };
    let methods = signatures
        .iter()
        .map(|signature| signature.verification_method.clone())
        .collect::<BTreeSet<_>>();
    if !notary.proposal_quorum_met(&methods) {
        return Err(AppError::new(
            ErrorCode::DirectoryGovernanceProofSignatureInvalid,
            "Seal signatures do not satisfy the frozen notary quorum".to_owned(),
        ));
    }
    for signature in signatures {
        let descriptor = notary
            .signer_descriptor(&signature.verification_method)
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::DirectoryGovernanceProofSignatureInvalid,
                    "Seal signature method is absent from the frozen notary value".to_owned(),
                )
            })?;
        arkret_signatures::verify_frozen_notary_signature(
            signature,
            descriptor,
            &canonical_bytes,
            digest_suite,
        )
        .map_err(|error| {
            AppError::new(
                ErrorCode::DirectoryGovernanceProofSignatureInvalid,
                error.to_string(),
            )
        })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RejectedControlEventEntry {
    pub event_digest: String,
    /// The reason the signed `ControlProposalDecision` carries. Operators and
    /// tests read this; `reason` below is free-form diagnostics that must not
    /// be parsed.
    pub reason_code: arkret_wire::ControlProposalRejectReason,
    pub reason: String,
}

/// Request body for `POST /_soland/admin/seals/sign`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SignSealRequestBody {
    /// Realm whose pending Moves should be batch-sealed.
    pub realm_id: String,
    /// Maximum number of pending Control Moves to consume in this pass.
    /// Default 100 if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_control_moves: Option<usize>,
}

/// Response body for the local notary signing operation. `seal_id` remains
/// absent when there were no pending Moves to seal.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SignSealOutcome {
    /// `true` if a Seal was published; `false` if nothing was pending.
    pub published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_id: Option<String>,
    #[serde(default)]
    pub accepted_event_digests: Vec<String>,
    #[serde(default)]
    pub rejected_events: Vec<RejectedControlEventEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_state_root: Option<String>,
}

/// Admin endpoint that triggers one
/// signing pass by the in-process notary worker. Useful for tests and
/// for ops to manually flush pending Moves into a Seal without a
/// background ticker. Production deploys will eventually wire a
/// periodic ticker to call the same worker function.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.seals.sign",
    tags("federation")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.seals.sign"))]
async fn admin_sign_seal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SignSealRequestBody>,
) -> JsonResult<SignSealOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let SignSealRequestBody {
        realm_id,
        max_control_moves,
    } = body.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::SchemaViolation, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    if device_generation_event_seal_context(state, &realm)
        .await?
        .is_some()
    {
        return Err(device_generation_fenced(
            "service notary signing is disabled for B-model principal-control Realms",
        ));
    }
    let limit = max_control_moves.unwrap_or(100).min(1000);

    match crate::notary::run_one_signing_pass(state, &realm, limit).await {
        Ok(Some(outcome)) => {
            let rejected = outcome
                .rejected_events
                .into_iter()
                .map(|(digest, rejection)| RejectedControlEventEntry {
                    event_digest: digest.as_str().to_owned(),
                    reason_code: rejection.reason,
                    reason: rejection.detail,
                })
                .collect();
            json_ok(SignSealOutcome {
                published: true,
                seal_id: Some(outcome.seal_id.as_str().to_owned()),
                accepted_event_digests: outcome
                    .accepted_event_digests
                    .into_iter()
                    .map(|m| m.as_str().to_owned())
                    .collect(),
                rejected_events: rejected,
                post_state_root: Some(outcome.post_state_root.as_str().to_owned()),
            })
        }
        Ok(None) => json_ok(SignSealOutcome {
            published: false,
            seal_id: None,
            accepted_event_digests: vec![],
            rejected_events: vec![],
            post_state_root: None,
        }),
        Err(crate::notary::NotaryError::NotAuthorized(_)) => Err(AppError::new(
            ErrorCode::PolicyViolation,
            "not authorized to sign seals for this realm".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN)),
        Err(e) => Err(AppError::new(ErrorCode::InternalError, e.to_string())
            .with_status(StatusCode::CONFLICT)),
    }
}

/// The effect of a Seal that is already committed — an idempotent re-submit, or
/// a Seal this process just wrote.
///
/// `Seal.delta` *is* the accepted set here, and it is already the wire order:
/// `Seal::validate_structural` requires it byte-wise ascending and unique, which
/// is exactly what
/// `service-operation-dtos.schema.json#/$defs/EventSealSubmitOutcome` defines
/// `accepted_event_digests` to be. Four call sites spelled this literal out; one
/// function keeps them from drifting into reducer apply order, which is a
/// different sequence (causal, then digest-descending) that no client can
/// reproduce.
fn committed_seal_effect(seal: &Seal) -> SealEffect {
    SealEffect {
        seal: seal.id.clone(),
        accepted_event_digests: seal.delta.clone(),
        post_state_root: seal.state_root.clone(),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Seal delta digest validation.
// ────────────────────────────────────────────────────────────────────────

/// Validate every entry in a Seal `delta[]` is shaped as
/// `sha256:<64 lowercase hex>`.
///
/// Receivers MUST recompute and verify entries.
pub(crate) fn validate_seal_delta_entries(delta: &[String]) -> Result<(), (ErrorCode, String)> {
    for entry in delta {
        if !is_sha256_digest(entry) {
            return Err((
                ErrorCode::SchemaViolation,
                format!(
                    "seal delta entries must match sha256:<64 lowercase hex>; \
                     got {entry:?}"
                ),
            ));
        }
    }
    Ok(())
}

fn is_sha256_digest(s: &str) -> bool {
    s.starts_with("sha256:") && arkret_identifiers::Hash::new(s.to_owned()).is_ok()
}

#[cfg(test)]
mod seal_delta_tests {
    use super::*;

    #[test]
    fn b_model_control_classification_projects_capability_grant_with_frozen_authority() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id =
            RealmId::new("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned())
                .unwrap();
        let issuer_did = arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap();
        let issuer = arkret_wire::project_did_to_core_id(&issuer_did).unwrap();
        let subject_did = arkret_identifiers::Did::new("did:web:agent.example".to_owned()).unwrap();
        let subject = arkret_wire::project_did_to_core_id(&subject_did).unwrap();
        let event = crate::test_event::raw_event(
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            issuer.clone(),
            1,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce3".to_owned()).unwrap(),
            serde_json::json!({
                "grant": {
                    "schema": "ak.schema.capability.v1",
                    "realm_id": realm_id,
                    "issuer_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(issuer, state.service_core_id().clone())),
                    "subject": arkret_wire::ActorId::account(arkret_wire::AccountId::new(subject, state.service_core_id().clone())),
                    "actions": ["ak.strand.read"],
                    "resources": [{
                        "kind": "realm",
                        "realm_id": realm_id,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-08-25T00:00:00.000Z",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm_id,
                        "cell_ref": arkret_wire::REALM_AUTHORITY_ROOT_CELL,
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }]
                }
            }),
        )
        .unwrap();

        assert!(
            registered_event_projects_writes(
                &state,
                &event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .expect("direct-root grant is registered control material")
        );
    }

    #[test]
    fn seal_delta_rejects_event_id_form() {
        let entries = vec!["ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned()];
        let err = validate_seal_delta_entries(&entries).unwrap_err();
        assert_eq!(err.0, ErrorCode::SchemaViolation);
    }

    #[test]
    fn seal_delta_accepts_sha256() {
        let entries = vec![format!("sha256:{}", "a".repeat(64))];
        validate_seal_delta_entries(&entries).unwrap();
    }

    #[test]
    fn bootstrap_first_seal_rejects_missing_and_partial_anchor_units() {
        let create = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let authorize = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let required = vec![create.clone(), authorize.clone()];
        assert!(
            validate_bootstrap_first_seal(
                &BTreeSet::new(),
                &std::iter::once(create.clone()).collect(),
                &required,
            )
            .is_err()
        );
        assert!(
            validate_bootstrap_first_seal(
                &std::iter::once(create).collect(),
                &std::iter::once(authorize).collect(),
                &required,
            )
            .is_err()
        );
    }

    #[test]
    fn first_recovery_seal_binding_rejects_another_current_device() {
        assert!(first_seal_signer_matches(
            "ak:device:recovery",
            "did:key:z6MkRecovery",
            "ak:device:recovery",
            "did:key:z6MkRecovery",
        ));
        assert!(!first_seal_signer_matches(
            "ak:device:other",
            "did:key:z6MkOther",
            "ak:device:recovery",
            "did:key:z6MkRecovery",
        ));
    }

    #[test]
    fn device_seal_signature_requires_the_bound_device_key() {
        use arkret_signatures::Ed25519DetachedJwsSigner;

        let signer = Ed25519DetachedJwsSigner::from_seed(
            [7u8; 32],
            "did:webvh:z6mkfixture:alice.example#ak:device:recovery",
        );
        let public_key = format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &signer.verifying_key().to_bytes(),
            )
        );
        let wrong_signer = Ed25519DetachedJwsSigner::from_seed(
            [8u8; 32],
            "did:webvh:z6mkfixture:alice.example#ak:device:other",
        );
        let wrong_public_key = format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &wrong_signer.verifying_key().to_bytes(),
            )
        );
        let empty_root = arkret_state::state::compute_state_root(
            &BTreeMap::new(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let placeholder_id = SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap();
        let placeholder_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let mut seal = Seal {
            id: placeholder_id,
            realm_id: RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned(),
            )
            .unwrap(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root: empty_root.clone(),
            state_root: empty_root.clone(),
            completeness_root: empty_root,
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(arkret_wire::SealSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:webvh:z6mkfixture:alice.example#ak:device:recovery",
                )
                .unwrap(),
                payload_digest: placeholder_digest,
                jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
            }),
            sealed_at: chrono::Utc::now(),
            hlc: arkret_identifiers::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        };
        let canonical_bytes = seal.canonical_bytes_for_id().unwrap();
        seal.id =
            Seal::id_from_canonical_bytes(&canonical_bytes, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        seal.notary_signature = NotarySig::Single(arkret_wire::SealSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:webvh:z6mkfixture:alice.example#ak:device:recovery",
            )
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                &canonical_bytes,
            ))
            .unwrap(),
            jws: signer.sign_detached_jws(&canonical_bytes),
        });

        verify_device_seal_signature(&seal, &public_key, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        assert!(
            verify_device_seal_signature(
                &seal,
                &wrong_public_key,
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err()
        );
        assert!(
            verify_device_seal_signature(
                &seal,
                public_key.strip_prefix("did:key:").unwrap(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err()
        );
    }

    #[test]
    fn device_verification_method_is_bound_to_device_id_or_key() {
        let did = arkret_wire::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let principal = arkret_wire::project_did_to_core_id(&did).unwrap();
        let device = "ak:device:recovery";
        let key = "did:key:z6MkRecovery";
        assert!(device_verification_method_matches(
            principal.as_str(),
            device,
            key,
            &format!("{did}#{device}"),
        ));
        assert!(device_verification_method_matches(
            principal.as_str(),
            device,
            key,
            "did:key:z6MkRecovery#z6MkRecovery",
        ));
        assert!(!device_verification_method_matches(
            principal.as_str(),
            device,
            key,
            &format!("{did}#ak:device:other"),
        ));
    }

    // did-usage-and-verification.md §2.2 — a proof `verification_method` MUST
    // be a DID URL with a `#fragment`. A bare `did:key:<mb>` (or the bare
    // principal DID) names no concrete verification method.
    #[test]
    fn device_verification_method_rejects_dids_without_fragments() {
        let did = "did:webvh:z6mkfixture:alice.example";
        let principal =
            arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did.to_owned()).unwrap())
                .unwrap();
        let device = "ak:device:recovery";
        let key = "did:key:z6MkRecovery";

        assert!(!device_verification_method_matches(
            principal.as_str(),
            device,
            key,
            key,
        ));
        assert!(!device_verification_method_matches(
            principal.as_str(),
            device,
            key,
            did
        ));
    }

    #[test]
    fn session_device_method_projects_did_to_authenticated_core() {
        let method = arkret_wire::DidUrl::new(
            "did:webvh:z6Mkfull:alice.example#ak:device:0196419b-0000-7000-8000-000000000001"
                .to_owned(),
        )
        .unwrap();
        let core = arkret_wire::project_did_to_core_id(
            &arkret_wire::Did::new("did:webvh:z6Mkfull:alice.example".to_owned()).unwrap(),
        )
        .unwrap();
        assert!(session_device_verification_method_matches(
            core.as_str(),
            "ak:device:0196419b-0000-7000-8000-000000000001",
            &method,
        ));
        assert!(!session_device_verification_method_matches(
            core.as_str(),
            "ak:device:0196419b-0000-7000-8000-000000000002",
            &method,
        ));
    }

    #[test]
    fn control_move_method_projects_did_to_signer_core() {
        let method = arkret_wire::DidUrl::new(
            "did:webvh:z6Mkfull:alice.example#ak:device:0196419b-0000-7000-8000-000000000001"
                .to_owned(),
        )
        .unwrap();
        assert!(control_move_verification_method_matches_signer(
            &method,
            "ak:did_core:webvh:z6Mkfull",
        ));
        assert!(!control_move_verification_method_matches_signer(
            &method,
            "ak:did_core:webvh:z6Mkother",
        ));
    }

    // did-usage-and-verification.md §2.2 — a Control Move proof must name a
    // verification method rooted in the signer as a `#fragment` DID URL; the
    // bare signer DID is not a verification method.
    #[test]
    fn control_move_proof_rejects_signer_did_without_fragment() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let actor_did = arkret_identifiers::Did::new("did:web:alice.example").unwrap();
        let realm_id =
            RealmId::new("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned())
                .unwrap();
        let issued_at = chrono::Utc::now();
        let mut event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            crate::test_actor_id(&actor_did),
            1,
            arkret_identifiers::Hlc::new("019f00000000-0000-a11ce001").unwrap(),
            serde_json::json!({}),
            issued_at,
        )
        .unwrap();
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let proof = |verification_method: &str| arkret_wire::ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(verification_method.to_owned())
                .expect("fixture verification method is a DID URL"),
            event_digest: event_digest.clone(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        };

        // §2.2 — the bare signer DID is no longer merely rejected at runtime:
        // `Proof.verification_method` is a typed `DidUrl`, so a fragment-less
        // value cannot be built at all. Pin that at the type boundary, which is
        // where the guarantee now lives.
        assert!(
            arkret_wire::DidUrl::new(actor_did.as_str().to_owned()).is_err(),
            "a bare signer DID must not be constructible as a verification method"
        );

        event.proofs = vec![proof(&format!("{}.evil#device-1", actor_did.as_str())).into()];
        assert!(
            verify_control_move_proofs(&state, &event).is_err(),
            "a sibling DID sharing the signer prefix must not be accepted"
        );

        // The `#fragment` form still gets past the rooting gate and fails
        // later, in the signature check.
        event.proofs = vec![proof(&format!("{}#device-1", actor_did.as_str())).into()];
        let error = verify_control_move_proofs(&state, &event)
            .expect_err("the placeholder JWS cannot verify");
        assert!(!error.contains("is not rooted in the signer"), "{error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_cell_subject_encodes_the_full_actor_and_separates_stations() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local = ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            crate::test_event::station_id(),
        ));
        let foreign = ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let cell = member_cell_for_actor(&local).unwrap();
        assert_ne!(cell, member_cell_for_actor(&foreign).unwrap());
        let event = crate::test_event::raw_event(
            arkret_wire::EventKind::InviteAccept.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id: RealmId::new("ak:realm:AUNpwW417vtZcK0hWrtv9UDvU8aC0UKocKAIMZ8xszoU").unwrap() },
            principal, 0, arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce2").unwrap(),
            serde_json::json!({"invite_id":"ak:invite:AXqb6Ch5W-jqD8aHcLfUSGkwP47dnrsU4phA2YK03WoF"}),
        ).unwrap();
        let writes = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(writes.iter().any(|write| write.cell_id == cell));
        assert!(!cell.as_str().contains('{'));
    }

    #[test]
    fn rejected_control_event_entry_serializes() {
        // Control-plane rejects are keyed by canonical `event_digest`
        // (§6.3.2), not by a Move id: v1 has no Move object.
        let r = RejectedControlEventEntry {
            event_digest: "sha256:00".to_owned(),
            reason_code: arkret_wire::ControlProposalRejectReason::SchemaViolation,
            reason: "bad sig".to_owned(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("event_digest"));
        assert!(!s.contains("move_id"));
        assert!(s.contains("reason"));
        // The classified reason travels as a value, not as prose an operator
        // (or a client) would have to pattern-match.
        assert!(s.contains(r#""reason_code":"schema_violation""#), "{s}");
    }
}
