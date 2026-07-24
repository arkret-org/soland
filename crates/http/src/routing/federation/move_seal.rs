//! Move / Seal wire endpoints.
//!
//! Surfaces:
//! - `POST /_soland/peer/moves`   — submit a Move; verifier validates structural shape + signature
//!   payload_digest + effect-shape against the cell registry, then stashes pending in
//!   [`MoveStore`].
//! - `POST /_soland/peer/seals` — submit a Seal; runs `apply_seal` end-to-end: structural →
//!   predecessor known → delta coverage check → batch-verify Moves → atomic effect append →
//!   recompute state_root → persist.
//!
//! Both endpoints back onto in-memory SDK store implementations on
//! [`AppState`]. Production deployments will swap to Pg-backed
//! implementations behind the same application service; handlers never
//! receive the underlying Move/Seal/Cell stores or registry.
//!
//! JWS shape verification rejects mangled, empty, or sentinel signatures
//! and validates the protected-header `alg`. In production mode, full
//! Ed25519 verification runs against the public key resolved from the
//! `verification_method` DID URL.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{MoveId, RealmId, SealId};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_state::lattice::SealedOp;
use arkret_state::state::{SealEffect, SealReject, StoreError, control_event_set_root};
use arkret_wire::{Event, Move, NotarySig, Seal, SealKind};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use salvo::oapi::extract::JsonBody;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

struct DeviceGenerationEventSealContext {
    principal_id: String,
    current_generation_ref: Option<String>,
    records: Vec<soland_services::events::CanonicalEventRecord>,
    accepted_frontier_refs: Vec<SealId>,
    cas_frontier_refs: Vec<SealId>,
    generation_fence: Option<crate::notary::FirstGenerationEventSealRequirement>,
    bootstrap_required_delta: Vec<MoveId>,
    bootstrap_device_id: String,
    bootstrap_device_public_key: String,
}

/// Map an SDK [`SealReject`] onto an [`AppError`].
///
/// Every reject reason routes through the canonical Arkret error
/// registry:
///
/// - `UnknownPredecessor`, coverage mismatches, `Structural`, `MissingMove`, `MoveRejected`,
///   `StateRootMismatch` -> [`ErrorCode::SchemaViolation`] (handler-level rejects of a structurally
///   invalid seal envelope).
/// - `Store` → [`ErrorCode::InternalError`] (durable-store IO failure).
///
/// The resulting `AppError` is rendered with HTTP `409 Conflict` to match
/// the prior in-handler mapping at `submit_seal` — the registry default
/// for `SchemaViolation` is `422`, but seal-rejects are conceptually a
/// causal / state-machine conflict so `409` is the historical wire status
/// here. Call sites that need a different status can override after
/// conversion via `.with_status(...)`.
fn app_error_from_seal_reject(reject: SealReject) -> AppError {
    let code = match &reject {
        SealReject::UnknownPredecessor
        | SealReject::DeltaAlreadyCovered
        | SealReject::Structural(_)
        | SealReject::MissingMove { .. }
        | SealReject::MoveRejected { .. }
        | SealReject::ControlEventSetRootMismatch { .. }
        | SealReject::CoveredSetMismatch
        | SealReject::StateRootMismatch { .. } => ErrorCode::SchemaViolation,
        SealReject::Store(_) => ErrorCode::InternalError,
    };
    AppError::new(code, reject.to_string()).with_status(StatusCode::CONFLICT)
}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("moves").post(submit_move))
        .push(Router::with_path("seals").post(submit_seal))
}

pub(super) fn api_admin_router() -> Router {
    Router::with_path("admin/seals/sign").post(admin_sign_seal)
}

// The notary uses `select_jws_verifier` which switches between
// shape-only (dev mode) and real ed25519 (production) based on
// `state.config().development_mode`.

/// Pick the JWS verifier based on `config.development_mode`. Returns a
/// closure of the exact type
/// `verify_move` / `apply_seal` expect (`Fn(&[u8], &str, &str, &str)
/// -> Result<(), String> + Copy`). The closure captures `&AppState` by
/// reference so the production branch can reach the DID resolver chain;
/// `&AppState` is `Copy`, so the closure is `Copy` too — required by
/// `apply_seal`'s `F: Copy` bound for batch verify_move calls.
pub fn select_jws_verifier(
    state: &AppState,
) -> impl Fn(&[u8], &str, &str, &str) -> Result<(), String> + Copy + use<'_> {
    move |canonical_bytes, jws, vm, issuer| {
        if state.config().development_mode {
            crate::jws_verify::verify_jws_shape(canonical_bytes, jws, vm, issuer)
        } else {
            crate::jws_verify::verify_jws_ed25519(canonical_bytes, jws, vm, issuer, state)
        }
    }
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
            record.kind == arkret_wire::events::EventKind::REALM_CREATE
                && record
                    .envelope
                    .pointer("/payload/object/fields/purpose")
                    .and_then(serde_json::Value::as_str)
                    == Some("principal_control")
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
    let principal_id = bootstrap.actor_id.clone();
    let expected_realm =
        soland_services::identity::principal_control_realm_for_did(&principal_id);
    if expected_realm != realm_id.as_str() {
        return Err(seal_admission_error(
            "principal-control bootstrap is stored under a non-deterministic Realm",
        ));
    }
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        &principal_id,
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
            record.actor_id == principal_id
                && record.kind == arkret_wire::events::EventKind::DEVICE_AUTHORIZE
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
    if bootstrap_payload.principal_id.as_str() != principal_id {
        return Err(seal_admission_error(
            "bootstrap device authorization principal differs from the Realm principal",
        ));
    }
    let bootstrap_required_delta = [
        bootstrap.canonical_digest.as_str(),
        bootstrap_authorize.canonical_digest.as_str(),
    ]
    .into_iter()
    .map(|digest| MoveId::new(digest.to_owned()))
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
        principal_id,
        current_generation_ref: generation.map(|generation| generation.current_ref),
        records,
        accepted_frontier_refs,
        cas_frontier_refs,
        generation_fence,
        bootstrap_required_delta,
        bootstrap_device_id: bootstrap_payload.device_id.as_str().to_owned(),
        bootstrap_device_public_key: bootstrap_payload.device_public_key.to_string(),
    }))
}

fn validate_bootstrap_first_seal(
    current: &BTreeSet<MoveId>,
    target: &BTreeSet<MoveId>,
    required_delta: &[MoveId],
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
    verification_method == format!("{principal_id}#{device_id}")
        || verification_method == format!("did:key:{device_public_key}#{device_public_key}")
        || verification_method == format!("did:key:{device_public_key}")
}

fn first_seal_signer_matches(
    signer_device_id: &str,
    signer_public_key: &str,
    required_device_id: &str,
    required_public_key: &str,
) -> bool {
    signer_device_id == required_device_id && signer_public_key == required_public_key
}

fn verify_device_seal_signature(seal: &Seal, device_public_key: &str) -> Result<(), AppError> {
    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(device_generation_fenced(
            "B-model Seal requires one identifiable current-generation device signature",
        ));
    };
    if signature.alg != "EdDSA" {
        return Err(device_generation_fenced(
            "B-model device Seal signature must use EdDSA",
        ));
    }
    let canonical_bytes = seal
        .canonical_bytes_for_id()
        .map_err(|error| seal_admission_error(format!("Seal canonical bytes: {error}")))?;
    let expected_digest = arkret_canonical::sha256_digest(&canonical_bytes);
    if signature.payload_digest.as_str() != expected_digest {
        return Err(device_generation_fenced(
            "B-model device Seal signature payload_digest mismatch",
        ));
    }
    let key = arkret_canonical::decode_ed25519_multibase(device_public_key).map_err(|error| {
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

fn ordinary_event_device_id(
    record: &soland_services::events::CanonicalEventRecord,
) -> Option<String> {
    let verification_method = record
        .envelope
        .get("proofs")
        .and_then(serde_json::Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(|proof| proof.get("verification_method"))
        .and_then(serde_json::Value::as_str)?;
    verification_method
        .strip_prefix(record.actor_id.as_str())
        .and_then(|suffix| suffix.strip_prefix('#'))
        .map(str::trim)
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
    seal.validate_id()
        .map_err(|error| seal_admission_error(format!("Seal id: {error}")))?;
    seal.validate_structural()
        .map_err(|error| seal_admission_error(format!("Seal structure: {error}")))?;
    let Some(initial_context) = device_generation_event_seal_context(state, &seal.realm_id).await?
    else {
        return Ok(None);
    };
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(
            &initial_context.principal_id,
        );
    let _guard = generation_lock.lock().await;
    if let Some(existing) = state
        .projections()
        .seal_by_id(&seal.id)
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("Seal lookup failed: {error}"),
            )
        })?
    {
        if existing != *seal {
            return Err(seal_admission_error(
                "Seal id already exists with different signature material",
            ));
        }
        return Ok(Some(SealEffect {
            seal: seal.id.clone(),
            accepted_move_ids: seal.delta.clone(),
            rejected_moves: Vec::new(),
            post_state_root: seal.state_root.clone(),
        }));
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
    let expected_control_root =
        control_event_set_root(&target).map_err(app_error_from_seal_reject)?;
    if seal.control_event_set_root != expected_control_root
        || seal.completeness_root != expected_control_root
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
        && requirement.payload.pre_fence_basis.is_none()
    {
        arkret_models_collaboration::events_payloads::device_identity::validate_device_reanchor_recovery_first_seal(
            &requirement.payload,
            &seal.predecessor_refs,
            &seal.delta,
            &requirement.reanchor_digest,
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

    let devices = state
        .identities()
        .devices_for_actor(&context.principal_id)
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("device inventory unavailable: {error}"),
            )
        })?;
    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(device_generation_fenced(
            "B-model Event Seal requires one identifiable device signature",
        ));
    };
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
                &context.principal_id,
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
                    .and_then(serde_json::Value::as_str)
                    != Some(generation.as_str())
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
    verify_device_seal_signature(seal, signer_public_key)?;

    let quarantined =
        crate::routing::identity::device_generation::quarantined_generation_event_digests(
            state,
            &context.principal_id,
        )
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("device generation quarantine state unavailable: {error}"),
            )
        })?;
    let admitted_generation_ref = context.current_generation_ref.clone();
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
        record.kind == "ak.device.reanchor" && !quarantined.contains(&record.canonical_digest)
    }) {
        anchor_event_ids.insert(record.event_id.clone());
        if let Some(authorize_id) = record
            .envelope
            .pointer("/payload/replacement_authorize_event_id")
            .and_then(serde_json::Value::as_str)
        {
            anchor_event_ids.insert(authorize_id.to_owned());
        }
    }
    let mut new_ops: Vec<(arkret_identifiers::CellRef, SealedOp)> = Vec::new();
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
        let recomputed = event.event_digest().map_err(|error| {
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
        if event.effects.is_empty() && !anchor_event_ids.contains(&record.event_id) {
            return Err(seal_admission_error(
                "B-model Event Seal delta contains a non-control Event",
            ));
        }
        if record.actor_id == context.principal_id
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
                            .and_then(serde_json::Value::as_str)
                            != Some(generation.as_str())
                    })
            {
                return Err(device_generation_fenced(
                    "B-model Event Seal delta contains an Event from an older device generation",
                ));
            }
        }
        new_ops.extend(
            crate::routing::events::event_log::governance_proof::canonical_event_ops(
                &event, digest,
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

    match state
        .projections()
        .commit_event_seal_if_frontier(seal, &context.cas_frontier_refs, &new_ops, &target)
    {
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
    Ok(Some(SealEffect {
        seal: seal.id.clone(),
        accepted_move_ids: seal.delta.clone(),
        rejected_moves: Vec::new(),
        post_state_root: seal.state_root.clone(),
    }))
}

pub(crate) async fn apply_managed_agent_event_seal(
    state: &AppState,
    seal: &Seal,
    agent_record: &soland_services::identity::AgentPairingState,
    session_device_id: &str,
) -> Result<SealEffect, AppError> {
    seal.validate_id()
        .map_err(|error| seal_admission_error(format!("managed Agent PCR Seal id: {error}")))?;
    seal.validate_structural().map_err(|error| {
        seal_admission_error(format!("managed Agent PCR Seal structure: {error}"))
    })?;
    crate::jws_verify::verify_replay_window(&seal.hlc, state.config().jws_replay_window_seconds)
        .map_err(|error| {
            seal_admission_error(format!("managed Agent PCR Seal replay_window: {error}"))
        })?;
    // `Seal.kind` is an in-memory classification and is intentionally absent
    // from the v1 wire schema / signed canonical body. This admission path
    // proves compaction semantics below by requiring exact cumulative coverage,
    // roots, state, and delta, then normalizes the accepted local value so
    // runtime DAG consumers can classify it without trusting an unsigned field.
    let mut accepted_seal = seal.clone();
    accepted_seal.kind = SealKind::Compaction;
    let seal = &accepted_seal;
    if seal.realm_id.as_str() != agent_record.principal_control_realm_id {
        return Err(seal_admission_error(
            "managed Agent PCR Seal Realm differs from the accepted Agent binding",
        ));
    }
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
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
    if let Some(mut existing) = state
        .projections()
        .seal_by_id(&seal.id)
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("managed Agent PCR Seal lookup failed: {error}"),
            )
        })?
    {
        existing.kind = SealKind::Compaction;
        if existing != *seal {
            return Err(seal_admission_error(
                "managed Agent PCR Seal id already exists with different signature material",
            ));
        }
        return Ok(SealEffect {
            seal: seal.id.clone(),
            accepted_move_ids: seal.delta.clone(),
            rejected_moves: Vec::new(),
            post_state_root: seal.state_root.clone(),
        });
    }

    let mut leaves = state
        .projections()
        .realm_seal_leaves(&seal.realm_id)
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("managed Agent PCR Seal frontier unavailable: {error}"),
            )
        })?;
    leaves.sort();
    if seal.predecessor_refs != leaves {
        return Err(seal_admission_error(
            "managed Agent PCR Seal predecessors differ from the complete accepted frontier",
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
                format!("managed Agent PCR Event history unavailable: {error}"),
            )
        })?;
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let event = serde_json::from_value::<Event>(record.envelope).map_err(|error| {
            seal_admission_error(format!(
                "stored managed Agent PCR Event {} is invalid: {error}",
                record.event_id
            ))
        })?;
        let digest = event.event_digest().map_err(|error| {
            seal_admission_error(format!(
                "stored managed Agent PCR Event {} digest failed: {error}",
                event.event_id
            ))
        })?;
        if digest != record.canonical_digest {
            return Err(seal_admission_error(format!(
                "stored managed Agent PCR Event {} canonical digest mismatch",
                event.event_id
            )));
        }
        events.push(event);
    }
    let material =
        arkret_bootstrap::materialize_managed_agent_pcr_control(&events).map_err(|error| {
            seal_admission_error(format!(
                "managed Agent PCR control material is invalid: {error}"
            ))
        })?;
    if material.realm_id != seal.realm_id
        || material.agent_id.as_str() != agent_record.id
        || material.controller_id.as_str() != agent_record.controller_id
        || material.authorization_ref != agent_record.controller_authorization_ref
    {
        return Err(device_generation_fenced(
            "managed Agent PCR Seal authority differs from the accepted Agent delegation",
        ));
    }

    let target = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !current.is_subset(&target) {
        return Err(seal_admission_error(
            "managed Agent PCR accepted coverage is not a subset of canonical history",
        ));
    }
    let expected_delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if expected_delta.is_empty() || seal.delta != expected_delta {
        return Err(seal_admission_error(
            "managed Agent PCR Seal delta must equal all newly accepted canonical Events",
        ));
    }
    let declared = seal
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared.len() != seal.covered_event_digests.len() || declared != target {
        return Err(seal_admission_error(
            "managed Agent PCR Seal coverage differs from canonical Event history",
        ));
    }
    let expected_root = control_event_set_root(&target).map_err(app_error_from_seal_reject)?;
    if seal.control_event_set_root != expected_root || seal.completeness_root != expected_root {
        return Err(seal_admission_error(
            "managed Agent PCR Seal control/completeness root mismatch",
        ));
    }
    if seal.state_root != material.state_root {
        return Err(seal_admission_error(format!(
            "managed Agent PCR Seal state_root mismatch: submitted {}, expected {}",
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
                        format!("managed Agent PCR predecessor lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| seal_admission_error("managed Agent PCR predecessor is missing"))
                .map(|predecessor| predecessor.notary_seq)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .map_or(Ok(0), |sequence| {
            sequence
                .checked_add(1)
                .ok_or_else(|| seal_admission_error("managed Agent PCR Seal notary_seq overflow"))
        })?;
    if seal.notary_seq != expected_notary_seq {
        return Err(seal_admission_error(
            "managed Agent PCR Seal notary_seq does not follow its predecessors",
        ));
    }

    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(device_generation_fenced(
            "managed Agent PCR Seal requires one controller-device signature",
        ));
    };
    let expected_method = format!("{}#{session_device_id}", agent_record.controller_id);
    if signature.verification_method != expected_method {
        return Err(device_generation_fenced(
            "managed Agent PCR Seal signer differs from the authenticated controller device",
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
                    .and_then(serde_json::Value::as_str)
                    != Some(generation.current_ref.as_str())
        })
    {
        return Err(device_generation_fenced(
            "managed Agent PCR Seal signer is not an active controller device",
        ));
    }
    let public_key = device
        .payload
        .get("device_public_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| device_generation_fenced("controller device signing key is missing"))?;
    verify_device_seal_signature(seal, public_key)?;

    let delta = seal.delta.iter().cloned().collect::<BTreeSet<_>>();
    let new_ops = material
        .event_ops
        .iter()
        .filter(|(_, op)| delta.contains(&op.move_id))
        .cloned()
        .collect::<Vec<_>>();
    match state
        .projections()
        .commit_event_seal_if_frontier(seal, &leaves, &new_ops, &target)
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(seal_admission_error(
                "managed Agent PCR Seal lost the atomic frontier compare-and-swap",
            ));
        }
        Err(StoreError::Conflict(error)) => return Err(seal_admission_error(error)),
        Err(error) => {
            return Err(AppError::new(
                ErrorCode::InternalError,
                format!("commit managed Agent PCR Seal atomically: {error}"),
            ));
        }
    }
    Ok(SealEffect {
        seal: seal.id.clone(),
        accepted_move_ids: seal.delta.clone(),
        rejected_moves: Vec::new(),
        post_state_root: seal.state_root.clone(),
    })
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
    let verifier = select_jws_verifier(state);
    state
        .projections()
        .apply_seal(seal, verifier)
        .map_err(app_error_from_seal_reject)
}

/// Response from `POST /_soland/peer/moves`.
///
/// `state` is one of `pending` / `rejected` so callers can distinguish
/// "we've stashed it for the next notary batch" from "verifier said no
/// before we even reached the queue".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitMoveOutcome {
    pub move_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.moves.submit"))]
async fn submit_move(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Move>,
) -> JsonResult<SubmitMoveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::federation::ensure_private_inbound_write_rail_local(state)?;
    let _session = aa.authenticated_session(state, req).await?;
    let move_obj = body.into_inner();

    // Verifier needs the per-Seal pre-state. For the submit-time
    // pre-check we use the current effective state under the existing
    // leaves; the actual deciding pre-state is computed by apply_seal
    // when the notary signs the next batch. This catches obvious
    // failures (bad sig, bad effect shape) early without committing
    // the Move to sealed storage.
    let pre_state = std::collections::BTreeMap::new();
    let verifier = select_jws_verifier(state);
    if let Err(reject) = state
        .projections()
        .verify_move(&move_obj, &pre_state, verifier)
    {
        return Ok(salvo::writing::Json(SubmitMoveOutcome {
            move_id: move_obj.id.as_str().to_owned(),
            state: "rejected".to_owned(),
            reason: Some(reject.to_string()),
        }));
    }
    // Replay-window check on Move.hlc.
    // The hlc is part of canonical_bytes_for_id (signed envelope), so it
    // can't be forged without invalidating verify_move; we trust it here.
    // Window=0 (test config) bypasses entirely; per-cell-family overrides
    // pick the tightest window across the Move's touched cells.
    if let Err(reject) = crate::jws_verify::verify_replay_window_for_move(
        &move_obj,
        state.config().jws_replay_window_seconds,
        &state.config().jws_replay_window_per_family,
    ) {
        return Ok(salvo::writing::Json(SubmitMoveOutcome {
            move_id: move_obj.id.as_str().to_owned(),
            state: "rejected".to_owned(),
            reason: Some(format!("replay_window: {reject}")),
        }));
    }

    state
        .projections()
        .put_pending_move(&move_obj)
        .map_err(|e| {
            AppError::new(ErrorCode::InternalError, e.to_string())
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;
    super::federation::broadcast_move_to_peers(state, move_obj.id.as_str()).await;

    json_ok(SubmitMoveOutcome {
        move_id: move_obj.id.as_str().to_owned(),
        state: "pending".to_owned(),
        reason: None,
    })
}

/// Response from `POST /_soland/peer/seals`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitSealOutcome {
    pub seal_id: String,
    pub accepted_move_ids: Vec<String>,
    pub rejected_moves: Vec<RejectedMoveEntry>,
    pub post_state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectedMoveEntry {
    pub move_id: String,
    pub reason: String,
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.seals.submit"))]
async fn submit_seal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Seal>,
) -> JsonResult<SubmitSealOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::federation::ensure_private_inbound_write_rail_local(state)?;
    let _session = aa.authenticated_session(state, req).await?;
    let seal = body.into_inner();

    // The shared admission path selects the canonical Event rail for a
    // B-model principal-control Realm and the legacy Move rail elsewhere.
    // Device-generation Seals always receive real device-key verification,
    // including in development mode.
    let effect = apply_inbound_seal(state, &seal).await?;

    let rejected = effect
        .rejected_moves
        .into_iter()
        .map(|(id, reason)| RejectedMoveEntry {
            move_id: id.as_str().to_owned(),
            reason,
        })
        .collect();

    // Refresh ProjectionState::cells from CellStore
    // for the sealed Realm so cell-keyed read paths
    // (read_receipt_policy / member.state / etc.) see the new effective
    // state immediately. Lock failures are non-fatal — read paths fall
    // back to the durable-event scan.
    //
    // Capture mls.epoch before the reload so we can detect a
    // shift after the reload writes the new value.
    let mls_epoch_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.mls.epoch.v1:{}",
        seal.realm_id.as_str()
    ))
    .ok();
    let prev_epoch_value: Option<serde_json::Value> = mls_epoch_cell
        .as_ref()
        .and_then(|cell_id| state.projections().cell_value(cell_id));
    if let Err(error) = state
        .projections()
        .reload_cells_from_store(&seal.realm_id)
    {
        tracing::warn!(error = %error, "failed to refresh ProjectionState::cells after apply_seal");
    }
    // Post-apply_seal mid-stream control frames.
    // 1. Frontier — every successful Seal advances the frontier.
    let _ = state.publish_event_notification(crate::state::EventNotification::frontier(
        seal.realm_id.as_str().to_owned(),
        effect.seal.as_str().to_owned(),
        effect.post_state_root.as_str().to_owned(),
    ));
    // 2. EpochRotation — only if mls.epoch cell value changed.
    if let Some(cell_id) = mls_epoch_cell {
        let new_epoch_value: Option<serde_json::Value> = {
            let proj = state.projections().snapshot();
            proj.cell_value(&cell_id).cloned()
        };
        if let Some(new_epoch) = new_epoch_value
            && prev_epoch_value.as_ref() != Some(&new_epoch)
        {
            let _ =
                state.publish_event_notification(crate::state::EventNotification::epoch_rotation(
                    seal.realm_id.as_str().to_owned(),
                    prev_epoch_value,
                    new_epoch,
                ));
        }
    }

    super::federation::broadcast_seal_to_peers(state, effect.seal.as_str()).await;

    json_ok(SubmitSealOutcome {
        seal_id: effect.seal.as_str().to_owned(),
        accepted_move_ids: effect
            .accepted_move_ids
            .into_iter()
            .map(|m| m.as_str().to_owned())
            .collect(),
        rejected_moves: rejected,
        post_state_root: effect.post_state_root.as_str().to_owned(),
    })
}

/// Request body for `POST /_soland/admin/seals/sign`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignSealRequestBody {
    /// Realm whose pending Moves should be batch-sealed.
    pub realm_id: String,
    /// Maximum number of pending Control Moves to consume in this pass.
    /// Default 100 if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_control_moves: Option<usize>,
}

/// Response body — mirrors `SubmitSealOutcome` but reports `None` when
/// there were no pending Moves to seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignSealOutcome {
    /// `true` if a Seal was published; `false` if nothing was pending.
    pub published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_id: Option<String>,
    #[serde(default)]
    pub accepted_move_ids: Vec<String>,
    #[serde(default)]
    pub rejected_moves: Vec<RejectedMoveEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_state_root: Option<String>,
}

/// Admin endpoint that triggers one
/// signing pass by the in-process notary worker. Useful for tests and
/// for ops to manually flush pending Moves into a Seal without a
/// background ticker. Production deploys will eventually wire a
/// periodic ticker to call the same worker function.
#[handler]
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

    match crate::notary::run_one_signing_pass(state, &realm, limit) {
        Ok(Some(outcome)) => {
            super::federation::broadcast_seal_to_peers(state, outcome.seal_id.as_str()).await;
            let rejected = outcome
                .rejected_moves
                .into_iter()
                .map(|(id, reason)| RejectedMoveEntry {
                    move_id: id.as_str().to_owned(),
                    reason,
                })
                .collect();
            json_ok(SignSealOutcome {
                published: true,
                seal_id: Some(outcome.seal_id.as_str().to_owned()),
                accepted_move_ids: outcome
                    .accepted_move_ids
                    .into_iter()
                    .map(|m| m.as_str().to_owned())
                    .collect(),
                rejected_moves: rejected,
                post_state_root: Some(outcome.post_state_root.as_str().to_owned()),
            })
        }
        Ok(None) => json_ok(SignSealOutcome {
            published: false,
            seal_id: None,
            accepted_move_ids: vec![],
            rejected_moves: vec![],
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

// ────────────────────────────────────────────────────────────────────────
// Seal delta digest validation.
// ────────────────────────────────────────────────────────────────────────

/// Validate every entry in a Seal `delta[]` is shaped as
/// `sha256:<64 lowercase hex>` — never a `ak:event:<uuid>` form.
///
/// Receivers MUST recompute and verify entries; the strict shape check
/// here guards against the removed event-id form that was permitted in
/// pre-T04 spec drafts.
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
    fn seal_delta_rejects_event_id_form() {
        let entries = vec!["ak:event:01904100-0000-7000-8000-000000000001".to_owned()];
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
        let create = MoveId::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let authorize = MoveId::new(format!("sha256:{}", "b".repeat(64))).unwrap();
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
            "z6MkRecovery",
            "ak:device:recovery",
            "z6MkRecovery",
        ));
        assert!(!first_seal_signer_matches(
            "ak:device:other",
            "z6MkOther",
            "ak:device:recovery",
            "z6MkRecovery",
        ));
    }

    #[test]
    fn device_seal_signature_requires_the_bound_device_key() {
        use arkret_signatures::Ed25519DetachedJwsSigner;

        let signer = Ed25519DetachedJwsSigner::from_seed(
            [7u8; 32],
            "did:webvh:z6mkfixture:alice.example#ak:device:recovery",
        );
        let public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &signer.verifying_key().to_bytes(),
        );
        let wrong_signer = Ed25519DetachedJwsSigner::from_seed(
            [8u8; 32],
            "did:webvh:z6mkfixture:alice.example#ak:device:other",
        );
        let wrong_public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &wrong_signer.verifying_key().to_bytes(),
        );
        let empty_root = arkret_state::state::compute_state_root(&BTreeMap::new()).unwrap();
        let placeholder_id = SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap();
        let placeholder_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let mut seal = Seal {
            id: placeholder_id,
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-a11ce0000001".to_owned())
                .unwrap(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root: empty_root.clone(),
            state_root: empty_root.clone(),
            completeness_root: empty_root,
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(arkret_wire::MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:alice.example#ak:device:recovery"
                    .to_owned(),
                payload_digest: placeholder_digest,
                created_at: chrono::Utc::now(),
                jws: "eyJhbGciOiJFZERTQSJ9..AA".to_owned(),
            }),
            sealed_at: chrono::Utc::now(),
            hlc: arkret_identifiers::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: arkret_wire::SealKind::Normal,
        };
        let canonical_bytes = seal.canonical_bytes_for_id().unwrap();
        seal.id = Seal::id_from_canonical_bytes(&canonical_bytes).unwrap();
        seal.notary_signature = NotarySig::Single(arkret_wire::MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#ak:device:recovery"
                .to_owned(),
            payload_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                &canonical_bytes,
            ))
            .unwrap(),
            created_at: chrono::Utc::now(),
            jws: signer.sign_detached_jws(&canonical_bytes),
        });

        verify_device_seal_signature(&seal, &public_key).unwrap();
        assert!(verify_device_seal_signature(&seal, &wrong_public_key).is_err());
    }

    #[test]
    fn device_verification_method_is_bound_to_device_id_or_key() {
        let principal = "did:webvh:z6mkfixture:alice.example";
        let device = "ak:device:recovery";
        let key = "z6MkRecovery";
        assert!(device_verification_method_matches(
            principal,
            device,
            key,
            &format!("{principal}#{device}"),
        ));
        assert!(device_verification_method_matches(
            principal,
            device,
            key,
            &format!("did:key:{key}"),
        ));
        assert!(!device_verification_method_matches(
            principal,
            device,
            key,
            &format!("{principal}#ak:device:other"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rejected_move_entry_serializes() {
        let r = RejectedMoveEntry {
            move_id: "sha256:00".to_owned(),
            reason: "bad sig".to_owned(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("move_id"));
        assert!(s.contains("reason"));
    }

    #[test]
    fn submit_move_response_serializes_pending_without_reason() {
        let r = SubmitMoveOutcome {
            move_id: "sha256:11".to_owned(),
            state: "pending".to_owned(),
            reason: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"state\":\"pending\""));
        assert!(!s.contains("reason"));
    }

    #[test]
    fn submit_move_response_includes_reason_on_reject() {
        let r = SubmitMoveOutcome {
            move_id: "sha256:22".to_owned(),
            state: "rejected".to_owned(),
            reason: Some("payload_digest mismatch".to_owned()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["state"], json!("rejected"));
        assert_eq!(v["reason"], json!("payload_digest mismatch"));
    }
}

