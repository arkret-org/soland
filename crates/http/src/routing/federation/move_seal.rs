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
use arkret_wire::{ActorId, DidCoreId, Event, Seal};
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
    accepted_head_ref: Option<SealId>,
    cas_head_ref: Option<SealId>,
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
                crate::app_error!(
                    FrontierUnavailable,
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
            } => availability_receipt
                .holder_signer_evidence_ref
                .content_digest()
                .map_err(|error| seal_admission_error(error.to_string()))?,
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
                crate::app_error!(
                    FrontierUnavailable,
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
        .await
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

/// Verify every `ak.fork.resolution` an accepted Seal covers, apply its verdict
/// to the local read surface, and record the scope-bound resolution it settles.
///
/// This is the first of the two phases that clear confirmed fork evidence
/// (`sync/federation.md` §4.5.3), and it clears nothing on any peer: an
/// accepted verdict says nothing about whether a particular replica has aligned
/// its sibling set with it.
///
/// Locally it says everything. The verdict and the read-surface subtraction it
/// implies land in one transaction, after which the disputed scope reads back
/// as exactly the winner or as the empty set — through the one
/// `accepted_events` projection that ordinary reads, the published frontier,
/// the reducer's input and the sibling-position disclosure all share, so the
/// verdict cannot reach one of them and miss another. Nothing is deleted: the
/// canonical bytes a Seal pinned and the reducer output it produced are
/// retained, because normalization governs what is read, not what is kept.
pub(crate) async fn validate_accepted_fork_resolution_records(
    state: &AppState,
    seal: &Seal,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), AppError> {
    for digest in &seal.delta {
        let Some(event) = state
            .projections()
            .control_event(digest)
            .await
            .map_err(|error| {
                crate::app_error!(
                    InternalError,
                    format!("load accepted fork-resolution Move: {error}"),
                )
            })?
        else {
            continue;
        };
        if event.kind != arkret_wire::EventKind::ForkResolution {
            continue;
        }
        let record =
            arkret_models_collaboration::events_payloads::ForkResolutionRecord::from_accepted_seal(
                &event,
                seal,
                digest_suite,
            )
            .map_err(|error| seal_admission_error(error.to_string()))?;
        // The Move can only name its collision variants; the bytes behind a
        // reference live in a typed governance-dependency record that has to be
        // resolved and independently re-verified before the claim means
        // anything. A record we do not hold is a dependency miss, not a licence
        // to adjudicate on the inline arm alone.
        let records = resolved_collision_variant_records(state, &event, digest_suite).await?;
        record
            .validate_collision_evidence(&event, &records, digest_suite)
            .map_err(|error| seal_admission_error(error.to_string()))?;
        let scope = fork_normalization_scope(&event, &record, &records, seal, digest_suite)?;
        record_fork_resolution_normalization(state, &event, &record, &scope).await?;
    }
    Ok(())
}

async fn resolved_collision_variant_records(
    state: &AppState,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<
    BTreeMap<
        arkret_identifiers::CollisionVariantRecordId,
        arkret_models_collaboration::events_payloads::state::CollisionVariantRecord,
    >,
    AppError,
> {
    let selectors =
        arkret_models_collaboration::governance_dependencies::fork_resolution_variant_record_selectors(
            event,
        )
        .map_err(|error| seal_admission_error(error.to_string()))?;
    let store = state.persistence().governance_dependency_store();
    let mut records = BTreeMap::new();
    for selector in selectors {
        let dependency = store
            .get(&event.realm_id, &selector)
            .await
            .map_err(|error| {
                crate::app_error!(FrontierUnavailable,
                    format!("collision variant record lookup failed: {error}"),
                )
            })?
            .ok_or_else(|| {
                crate::app_error!(DependencyMissing,
                    "fork resolution references a collision variant record that is not durably                      available",
                )
            })?;
        let GovernanceDependency::CollisionVariantRecord {
            collision_variant_record,
            ..
        } = dependency
        else {
            return Err(seal_admission_error(
                "collision variant selector resolved to another dependency kind",
            ));
        };
        collision_variant_record
            .validate(digest_suite)
            .map_err(|error| seal_admission_error(error.to_string()))?;
        records.insert(
            collision_variant_record.collision_variant_record_id.clone(),
            *collision_variant_record,
        );
    }
    Ok(records)
}

/// The exact read-surface subtraction one verdict implies.
///
/// The subject fixes what is governed and the verdict fixes what survives; the
/// SDK payload validator has already refused every other pairing, so the arms
/// below are total. A collision winner is named by index into the Move's own
/// evidence and can only be carried as complete canonical bytes — two variants
/// of one hash are by construction indistinguishable by id.
///
/// The covering Seal is a parameter because a collision winner is not merely
/// kept in or subtracted from the read surface: spec section 6.3.3 point 3
/// admits it, and requires that admission to be a pure function of the winner's
/// bytes and this Seal. `sealed_at` is the timestamp the admitted Event is
/// stored under, so a receiver that held only the loser ends up byte-identical
/// to one that held the winner all along.
fn fork_normalization_scope(
    event: &Event,
    record: &arkret_models_collaboration::events_payloads::ForkResolutionRecord,
    records: &BTreeMap<
        arkret_identifiers::CollisionVariantRecordId,
        arkret_models_collaboration::events_payloads::state::CollisionVariantRecord,
    >,
    seal: &Seal,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<soland_services::federation::FederationForkNormalizationScope, AppError> {
    use arkret_models_collaboration::events_payloads::{
        ForkResolutionConflictEvidence, ForkResolutionSubject, ForkResolutionVariantLocator,
        ForkResolutionVerdict,
    };
    use soland_services::federation::FederationForkNormalizationScope;

    match (&record.subject, &record.verdict) {
        (
            ForkResolutionSubject::EventSiblingPosition {
                actor_id,
                actor_seq,
            },
            verdict,
        ) => {
            let winner_event_id = match verdict {
                ForkResolutionVerdict::SiblingWinner {
                    winner_event_id, ..
                } => Some(winner_event_id.as_str().to_owned()),
                ForkResolutionVerdict::VoidAll { .. } => None,
                ForkResolutionVerdict::CollisionWinner { .. } => {
                    return Err(seal_admission_error(
                        "collision verdict cannot govern an Event sibling position",
                    ));
                }
            };
            Ok(FederationForkNormalizationScope::SiblingPosition {
                actor_id: actor_id.to_string(),
                actor_seq: *actor_seq,
                winner_event_id,
            })
        }
        (ForkResolutionSubject::EventIdCollision { event_id }, verdict) => {
            let winner_canonical_bytes = match verdict {
                ForkResolutionVerdict::VoidAll { .. } => None,
                ForkResolutionVerdict::CollisionWinner { winner_index, .. } => {
                    let ForkResolutionConflictEvidence::FullHashCollision { variants } =
                        &record.conflict_evidence
                    else {
                        return Err(seal_admission_error(
                            "collision verdict without full-hash collision evidence",
                        ));
                    };
                    let locator = variants.get(usize::from(*winner_index)).ok_or_else(|| {
                        seal_admission_error("collision winner index is out of range")
                    })?;
                    Some(match locator {
                        ForkResolutionVariantLocator::InlineCanonicalBytes {
                            canonical_event_bytes_b64u,
                        } => arkret_canonical::base64url_decode(
                            canonical_event_bytes_b64u.as_str(),
                        )
                        .map_err(|error| seal_admission_error(error.to_string()))?,
                        ForkResolutionVariantLocator::CollisionVariantRecord {
                            collision_variant_record_id,
                            ..
                        } => records
                            .get(collision_variant_record_id)
                            .ok_or_else(|| {
                                crate::app_error!(
                                    DependencyMissing,
                                    "fork resolution winner names a collision variant record that is not durably available",
                                )
                            })?
                            .canonical_event_bytes_for_locator(event, locator, digest_suite)
                            .map_err(|error| seal_admission_error(error.to_string()))?,
                    })
                }
                ForkResolutionVerdict::SiblingWinner { .. } => {
                    return Err(seal_admission_error(
                        "sibling verdict cannot govern a colliding Event identity",
                    ));
                }
            };
            Ok(FederationForkNormalizationScope::EventIdCollision {
                event_id: event_id.as_str().to_owned(),
                winner_sealed_at_ms: winner_canonical_bytes
                    .is_some()
                    .then(|| seal.sealed_at.timestamp_millis()),
                winner_canonical_bytes,
            })
        }
    }
}

async fn record_fork_resolution_normalization(
    state: &AppState,
    event: &Event,
    record: &arkret_models_collaboration::events_payloads::ForkResolutionRecord,
    scope: &soland_services::federation::FederationForkNormalizationScope,
) -> Result<(), AppError> {
    let cell_subject_key = record
        .subject
        .cell_subject_key()
        .map_err(|error| seal_admission_error(error.to_string()))?;
    let conflict_evidence_digest = arkret_canonical::canonical_sha256(&record.conflict_evidence)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let normalization = soland_services::federation::FederationFrontierResolutionRecord {
        realm_id: event.realm_id.as_str().to_owned(),
        cell_subject_key: cell_subject_key.to_string(),
        subject: serde_json::to_value(&record.subject)
            .map_err(|error| AppError::internal(error.to_string()))?,
        verdict: serde_json::to_value(&record.verdict)
            .map_err(|error| AppError::internal(error.to_string()))?,
        conflict_evidence_digest,
        resolution_event_digest: record.resolution_event_digest.as_str().to_owned(),
        normalized_at: chrono::Utc::now().timestamp(),
    };
    state
        .federation()
        .record_frontier_local_normalization(&normalization, scope)
        .await
        .map_err(|error| seal_admission_error(error.to_string()))?;
    reproject_admitted_collision_winner(state, scope).await
}

/// Rebuild the projection row of an Event this verdict just admitted.
///
/// The durable half of the admission runs inside the normalization
/// transaction, which can restore the canonical read surface but not the
/// projection timeline: the timeline row is reducer output, and the storage
/// layer has no reducer. So it is rebuilt here, from the bytes now stored,
/// through the same Event -> Operation mapper the live submit path uses.
/// Skipping this would leave the identity readable as a canonical Event and
/// invisible in every timeline, subscription and cursor that reads
/// `projection_events` — which is most of the read surface.
///
/// `received_at` is the covering Seal's `sealed_at`, the same value the admitted
/// Event carries, because `event-auth-state-resolution.md` section 6.3.3 point 3
/// requires the projection a loser-holding Station derives to match the one a
/// Station that always held the winner has.
///
/// Nothing to do for a sibling-position subject, for `void_all`, for a Station
/// that holds no variant of the identity, or for an Event kind that has no
/// projection row; the append itself is idempotent on `event_pk`.
async fn reproject_admitted_collision_winner(
    state: &AppState,
    scope: &soland_services::federation::FederationForkNormalizationScope,
) -> Result<(), AppError> {
    use soland_services::federation::FederationForkNormalizationScope;

    let FederationForkNormalizationScope::EventIdCollision {
        event_id,
        winner_sealed_at_ms: Some(sealed_at_ms),
        ..
    } = scope
    else {
        return Ok(());
    };
    let received_at = chrono::DateTime::from_timestamp_millis(*sealed_at_ms)
        .ok_or_else(|| seal_admission_error("fork resolution winner sealed_at is out of range"))?;
    let Some(admitted) = state
        .event_queries()
        .accepted_event(event_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("load admitted collision winner: {error}"),
            )
        })?
    else {
        return Ok(());
    };
    let Some(operation) =
        crate::routing::events::event_log::projection_operation_from_canonical_record(&admitted)
    else {
        return Ok(());
    };
    let mut projected =
        crate::routing::events::projection::projection_event_from_operation(&operation, None);
    projected.received_at = received_at;
    crate::routing::events::projection::persist_and_publish_projection_event(state, projected)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("reproject admitted collision winner: {error}"),
            )
        })?;
    Ok(())
}

/// Missing replay dependencies remain pending. A concurrent head change is a
/// state mismatch; malformed Seal conclusions are structural rejections.
fn app_error_from_seal_reject(reject: SealReject) -> AppError {
    let code = match &reject {
        SealReject::UnknownPredecessor
        | SealReject::MissingControlEvent { .. }
        | SealReject::CommandPending { .. } => ErrorCode::FrontierUnavailable,
        SealReject::ConfirmedHeadChanged => ErrorCode::StateMismatch,
        SealReject::DeltaAlreadyCovered
        | SealReject::Structural(_)
        | SealReject::MissingSealBasis { .. }
        | SealReject::SealBasisOutsideClosure { .. }
        | SealReject::ControlEventSetRootMismatch { .. }
        | SealReject::CoveredSetMismatch
        | SealReject::StateRootMismatch { .. } => ErrorCode::SchemaViolation,
        SealReject::Store(_) => ErrorCode::InternalError,
    };
    AppError::from_rejection(code, reject.to_string())
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
    for proof in event.proofs.iter() {
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
    crate::app_error!(SchemaViolation, message.into())
}

fn device_generation_fenced(message: impl Into<String>) -> AppError {
    crate::app_error!(PolicyViolation, message.into()).with_wire_code("device_generation_fenced")
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
            crate::app_error!(
                FrontierUnavailable,
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
    let bound_pcr = if bootstrap
        .envelope
        .pointer("/payload/object/purpose")
        .and_then(serde_json::Value::as_str)
        == Some("principal_control")
    {
        if let Some(account) = actor_id.as_account_id() {
            state
                .persistence()
                .principal_resolution_by_account_id(account)
                .await
                .map_err(|error| {
                    seal_admission_error(format!("principal resolution unavailable: {error}"))
                })?
                .is_some_and(|resolution| &resolution.pcr_realm_id == realm_id)
        } else {
            false
        }
    } else {
        state
            .projections()
            .snapshot()
            .realm_is_principal_control_for_actor(realm_id.as_str(), &actor_id.to_string())
    };
    if !bound_pcr {
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
        crate::app_error!(
            FrontierUnavailable,
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
    let cas_head_ref = state
        .projections()
        .realm_seal_head(realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("Seal frontier unavailable: {error}"),
            )
        })?;
    let accepted_head_ref = if let Some(requirement) = &generation_fence {
        requirement.accepted_head_ref.clone()
    } else {
        cas_head_ref.clone()
    };

    Ok(Some(DeviceGenerationEventSealContext {
        actor_id,
        principal_id,
        current_generation_ref: generation.map(|generation| generation.current_ref),
        records,
        accepted_head_ref,
        cas_head_ref,
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
    let signature = &seal.notary_signature;
    let canonical_bytes = seal
        .commit_transcript_bytes(digest_suite)
        .map_err(|error| seal_admission_error(format!("Seal commit transcript: {error}")))?;
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
        .await
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
    if let Some(existing) = state
        .projections()
        .seal_by_id(&seal.id)
        .await
        .map_err(
            |error| crate::app_error!(InternalError, format!("Seal lookup failed: {error}"),),
        )?
    {
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
        .seal_predecessor_known(seal.predecessor_ref.as_ref())
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("Seal predecessor lookup failed: {error}"),
            )
        })?
    {
        return Err(seal_admission_error(
            "B-model Event Seal has an unknown predecessor",
        ));
    }
    if seal.predecessor_ref != context.accepted_head_ref {
        return Err(device_generation_fenced(
            "B-model Event Seal predecessors differ from the complete accepted generation frontier",
        ));
    }
    let predecessor_coverage = state
        .projections()
        .predecessor_covered_events(seal.predecessor_ref.as_ref())
        .await
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
    if !seal.covered_event_digests.is_empty()
        && (declared.len() != seal.covered_event_digests.len() || declared != target)
    {
        return Err(seal_admission_error(
            "B-model Event Seal covered_event_digests must equal predecessor coverage plus delta",
        ));
    }
    let expected_control_root = control_event_set_root(&target, digest_suites.seal_digest_suite)
        .map_err(app_error_from_seal_reject)?;
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
    if seal.control_event_set_root != expected_control_root {
        return Err(seal_admission_error(
            "B-model Event Seal control_event_set_root mismatch",
        ));
    }
    let expected_notary_seq = if let Some(predecessor) = seal.predecessor_ref.as_ref() {
        let value = state
            .projections()
            .seal_by_id(predecessor)
            .await
            .map_err(|error| {
                crate::app_error!(
                    InternalError,
                    format!("Seal predecessor lookup failed: {error}"),
                )
            })?
            .ok_or_else(|| seal_admission_error("B-model Event Seal predecessor is missing"))?;
        value
            .notary_seq
            .checked_add(1)
            .ok_or_else(|| seal_admission_error("B-model Event Seal notary_seq overflow"))?
    } else {
        0
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
                seal.predecessor_ref.as_ref(),
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
            seal.predecessor_ref.as_ref(),
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

    let signature = &seal.notary_signature;
    let devices = state
        .identities()
        .devices_for_actor(context.principal_id.as_str())
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("device inventory unavailable: {error}"),
            )
        })?;
    let signer = devices
        .iter()
        .find(|device| {
            let Some(public_key) = device
                .payload
                .get("device_public_key_did")
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
        .get("device_public_key_did")
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

    let admitted_generation_ref = context.current_generation_ref;
    let admitted_head_ref = context.accepted_head_ref.clone();
    let admitted_cas_head_ref = context.cas_head_ref.clone();
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
    for record in records_by_digest
        .values()
        .filter(|record| record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR)
    {
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
        arkret_state::state_model::ordered_log::IssuedOp,
    )> = Vec::new();
    // Every Event in one Seal delta resolves against the exact, frozen
    // predecessor frontier. `effective_state_at` preserves Seal batches for
    // causal-register cells; rebuilding this map from only `new_ops` would make the
    // first patch after a predecessor Seal observe `null`.
    let predecessor_state = state
        .projections()
        .effective_state_at(seal.predecessor_ref.as_slice(), &seal.realm_id)
        .await
        .map_err(|error| {
            seal_admission_error(format!(
                "resolve B-model Event Seal predecessor state: {error}"
            ))
        })?;
    for digest in &seal.delta {
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
        let event_digest_suite = if seal.predecessor_ref.is_none()
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
        if event.realm_id.as_str() != seal.realm_id.as_str() || event.auth_context.is_some() {
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
            Vec<arkret_state::state_model::ordered_log::IssuedOp>,
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
            crate::routing::events::event_log::governance_proof::canonical_event_ops_with_frozen_pre_state(
                state,
                &seal.realm_id,
                &event,
                digest,
                &predecessor_state,
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
    if refreshed.current_generation_ref != admitted_generation_ref
        || refreshed.accepted_head_ref != admitted_head_ref
        || refreshed.cas_head_ref != admitted_cas_head_ref
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
        .await
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    match state
        .projections()
        .commit_event_seal_if_head(
            seal,
            digest_suite,
            context.cas_head_ref.as_ref(),
            &new_ops,
            &target,
            &availability_dependency_writes,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(device_generation_fenced(
                "B-model device generation Seal lost the atomic frontier compare-and-swap",
            ));
        }
        Err(StoreError::Conflict(error)) => return Err(seal_admission_error(error)),
        Err(error) => {
            return Err(crate::app_error!(
                InternalError,
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
        .await
        .map_err(app_error_from_seal_reject)?;
    seal.validate_id(digest_suites.seal_digest_suite)
        .map_err(|error| seal_admission_error(format!("Agent PCR Seal id: {error}")))?;
    seal.validate_structural()
        .map_err(|error| seal_admission_error(format!("Agent PCR Seal structure: {error}")))?;
    crate::jws_verify::verify_replay_window(&seal.hlc, state.config().jws_replay_window_seconds)
        .map_err(|error| seal_admission_error(format!("Agent PCR Seal replay_window: {error}")))?;
    // Ordinary successors derive coverage from the accepted basis and delta.
    // Only an explicit compaction coverage set needs the additional equality check.
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
    if let Some(existing) = state
        .projections()
        .seal_by_id(&seal.id)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("Agent PCR Seal lookup failed: {error}"),
            )
        })?
    {
        if existing != *seal {
            return Err(seal_admission_error(
                "Agent PCR Seal id already exists with different signature material",
            ));
        }
        return Ok(committed_seal_effect(seal));
    }

    let head = state
        .projections()
        .realm_seal_head(&seal.realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("Agent PCR Seal frontier unavailable: {error}"),
            )
        })?;
    let leaves = head.iter().cloned().collect::<Vec<_>>();
    if seal.predecessor_ref != head {
        return Err(seal_admission_error(
            "Agent PCR Seal predecessors differ from the complete accepted frontier",
        ));
    }
    let current = state
        .projections()
        .predecessor_covered_events(head.as_ref())
        .await
        .map_err(app_error_from_seal_reject)?;

    if seal.delta.is_empty() || seal.delta.iter().any(|digest| current.contains(digest)) {
        return Err(seal_admission_error(
            "Agent PCR Seal delta must contain new Control Events",
        ));
    }
    let mut selected_coverage = current.clone();
    selected_coverage.extend(seal.delta.iter().cloned());

    let records = state
        .event_queries()
        .realm_events_newest_first(seal.realm_id.as_str())
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("Agent PCR Event history unavailable: {error}"),
            )
        })?;
    let mut events = Vec::with_capacity(records.len());
    let mut events_by_digest = BTreeMap::new();
    let mut event_digest_suites = BTreeMap::new();
    for record in records {
        let stored_digest = Hash::new(record.canonical_digest.clone())
            .map_err(|error| seal_admission_error(format!("stored Agent PCR digest: {error}")))?;
        if !selected_coverage.contains(&stored_digest) {
            continue;
        }
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
        if events_by_digest
            .insert(stored_digest, (event.clone(), record.digest_suite))
            .is_some()
        {
            return Err(seal_admission_error(
                "duplicate canonical Event digest in Agent PCR history",
            ));
        }
        events.push(event);
    }
    let ordered = crate::routing::identity::agent_pcr::resolve_agent_pcr_ordered_history(
        state,
        seal.clone(),
        &events_by_digest,
    )
    .await?;
    let material = arkret_bootstrap::materialize_agent_pcr_control(&ordered.units, &|event| {
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
    let record_controller_principal_id =
        arkret_wire::DidCoreId::new(agent_record.controller_principal_id.clone())
            .or_else(|_| {
                arkret_wire::Did::new(agent_record.controller_principal_id.clone())
                    .and_then(|did| arkret_wire::project_did_to_core_id(&did))
            })
            .map_err(|error| {
                device_generation_fenced(format!(
                    "accepted Agent controller identity is invalid: {error}"
                ))
            })?;
    if material.realm_id != seal.realm_id
        || material.agent_id.signing_principal_id().as_str() != agent_record.id
        || material.controller_actor_id.signing_principal_id() != &record_controller_principal_id
        || material.authorization_ref.as_str() != agent_record.controller_authorization_ref.as_str()
    {
        return Err(device_generation_fenced(
            "Agent PCR Seal authority differs from the accepted Agent delegation",
        ));
    }
    if material.command_results != ordered.committed_command_results {
        return Err(seal_admission_error(
            "Agent PCR signed command results do not match deterministic replay",
        ));
    }

    let target = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if target != selected_coverage {
        return Err(seal_admission_error(
            "Agent PCR Seal basis and delta do not resolve to the exact canonical Control Events",
        ));
    }
    let expected_delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if expected_delta.is_empty() || seal.delta != expected_delta {
        return Err(seal_admission_error(
            "Agent PCR Seal delta must equal its newly selected canonical Events",
        ));
    }
    let declared = seal
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !seal.covered_event_digests.is_empty()
        && (declared.len() != seal.covered_event_digests.len() || declared != target)
    {
        return Err(seal_admission_error(
            "Agent PCR Seal coverage differs from canonical Event history",
        ));
    }
    let expected_control_root = control_event_set_root(&target, digest_suites.seal_digest_suite)
        .map_err(app_error_from_seal_reject)?;
    if seal.control_event_set_root != expected_control_root {
        return Err(seal_admission_error(
            "Agent PCR Seal control_event_set_root mismatch",
        ));
    }
    if seal.state_root != material.state_root {
        return Err(seal_admission_error(format!(
            "Agent PCR Seal state_root mismatch: submitted {}, expected {}",
            seal.state_root, material.state_root
        )));
    }
    let mut predecessor_sequences = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        let predecessor = state
            .projections()
            .seal_by_id(leaf)
            .await
            .map_err(|error| {
                crate::app_error!(
                    InternalError,
                    format!("Agent PCR predecessor lookup failed: {error}"),
                )
            })?
            .ok_or_else(|| seal_admission_error("Agent PCR predecessor is missing"))?;
        predecessor_sequences.push(predecessor.notary_seq);
    }
    let expected_notary_seq =
        predecessor_sequences
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

    let signature = &seal.notary_signature;
    if !session_device_verification_method_matches(
        &agent_record.controller_principal_id,
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
            actor_id: agent_record.controller_principal_id.clone(),
            device_id: session_device_id.to_owned(),
        })
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("controller device lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| device_generation_fenced("controller device is not registered"))?;
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        &agent_record.controller_principal_id,
    )
    .await
    .map_err(|error| {
        crate::app_error!(
            FrontierUnavailable,
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
        .get("device_public_key_did")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| device_generation_fenced("controller device signing key is missing"))?;
    verify_device_seal_signature(seal, public_key, digest_suites.seal_digest_suite)?;

    let frozen_key = arkret_canonical::decode_ed25519_multibase(
        public_key
            .strip_prefix("did:key:")
            .ok_or_else(|| device_generation_fenced("controller device key is not did:key"))?,
    )
    .map_err(|error| device_generation_fenced(error.to_string()))?;
    let mut accepted_signer = soland_services::identity::ed25519_notary_signer_descriptor(
        material.controller_actor_id.signing_principal_id().clone(),
        signature.verification_method.clone(),
        &frozen_key,
    )
    .map_err(|error| seal_admission_error(error.to_string()))?;
    accepted_signer.actor_id = material.controller_actor_id.clone();

    let delta = seal.delta.iter().cloned().collect::<BTreeSet<_>>();
    let new_ops = material
        .event_ops
        .iter()
        .filter(|(_, issued)| delta.contains(&issued.op.event_id.event_digest()))
        .cloned()
        .collect::<Vec<_>>();
    let availability_dependency_writes =
        verified_availability_dependency_writes(state, seal).await?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .await
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    // Keep the exact verified key before committing the frontier. An orphaned
    // retention row cannot authorize anything without its accepted Seal.
    state
        .persistence()
        .governance_dependency_store()
        .put_agent_seal_signer_exact(&seal.id, &accepted_signer)
        .await
        .map_err(|error| AppError::internal(format!("retain Agent Seal signer: {error}")))?;
    match state
        .projections()
        .commit_event_seal_if_head(
            seal,
            digest_suite,
            head.as_ref(),
            &new_ops,
            &target,
            &availability_dependency_writes,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(seal_admission_error(
                "Agent PCR Seal lost the atomic frontier compare-and-swap",
            ));
        }
        Err(StoreError::Conflict(error)) => return Err(seal_admission_error(error)),
        Err(error) => {
            return Err(crate::app_error!(
                InternalError,
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
    validate_seal_delta_entries(&delta_entries)
        .map_err(|(code, reason)| AppError::from_rejection(code, reason))?;
    crate::jws_verify::verify_replay_window(&seal.hlc, state.config().jws_replay_window_seconds)
        .map_err(|error| {
            crate::app_error!(SchemaViolation, format!("seal replay_window: {error}"),)
        })?;
    if let Some(effect) = try_apply_device_generation_event_seal(state, seal).await? {
        return Ok(effect);
    }
    verify_realm_notary_seal(state, seal).await?;
    let verifier = select_jws_verifier(state);
    let context = if seal.predecessor_ref.is_none() {
        let [result] = seal.command_results.as_slice() else {
            return Err(seal_admission_error(
                "first Seal must contain one registered command unit",
            ));
        };
        if result.outcome != arkret_wire::CommandOutcome::Committed {
            return Err(seal_admission_error(
                "first Seal command unit must be committed",
            ));
        }
        let mut events = Vec::with_capacity(result.unit_event_digests.len());
        for digest in &result.unit_event_digests {
            let event = state
                .projections()
                .control_event(digest)
                .await
                .map_err(|error| {
                    crate::app_error!(
                        InternalError,
                        format!("load first-Seal Control Move: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    seal_admission_error(format!("first Seal is missing Control Move {digest}"))
                })?;
            events.push(event);
        }
        arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
            .map_err(|error| seal_admission_error(error.to_string()))?;
        arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
    } else {
        arkret_wire::event_envelope::EventSubmitContext::Standard
    };
    let expected_store_head = state
        .projections()
        .realm_seal_head(&seal.realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("Seal frontier unavailable before atomic admission: {error}"),
            )
        })?;
    let prepared = state
        .projections()
        .prepare_seal_in_context(seal, verifier, context)
        .await
        .map_err(app_error_from_seal_reject)?;
    let governance_dependencies = verified_availability_dependency_writes(state, seal).await?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .await
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    match state
        .projections()
        .commit_event_seal_if_head(
            seal,
            digest_suite,
            expected_store_head.as_ref(),
            &prepared.new_ops,
            &prepared.covered_event_digests,
            &governance_dependencies,
        )
        .await
    {
        Ok(true) => {
            if state.storage_mode() == "memory" {
                validate_accepted_fork_resolution_records(state, seal, digest_suite).await?;
            }
            crate::routing::events::event_log::publish_confirmed_realm_bootstrap(
                state,
                &seal.realm_id,
            )
            .await
            .map_err(|error| {
                AppError::internal(format!("confirmed bootstrap projection: {error}"))
            })?;
            crate::routing::events::projection::publish_confirmed_seal_commands(state, seal)
                .await
                .map_err(|error| {
                    AppError::internal(format!("confirmed command projection: {error}"))
                })?;
            Ok(prepared.effect)
        }
        Ok(false) => Err(crate::app_error!(
            FrontierUnavailable,
            "Seal frontier changed during atomic admission".to_owned(),
        )),
        Err(StoreError::Conflict(error)) => Err(seal_admission_error(error)),
        Err(error) => Err(crate::app_error!(
            InternalError,
            format!("commit inbound Seal atomically: {error}"),
        )),
    }
}

async fn verify_realm_notary_seal(state: &AppState, seal: &Seal) -> Result<(), AppError> {
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .await
        .map_err(app_error_from_seal_reject)?
        .seal_digest_suite;
    let notary = crate::notary::NotaryWorker::for_service(state.service_id().clone())
        .notary_value_for_seal(state, seal)
        .await
        .map_err(|error| {
            crate::app_error!(
                DirectoryGovernanceProofSignatureInvalid,
                format!("resolve Seal notary authority: {error}"),
            )
        })?;
    arkret_signatures::verify_seal_signature(seal, &notary, digest_suite).map_err(|error| {
        crate::app_error!(DirectoryGovernanceProofSignatureInvalid, error.to_string())
    })?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RejectedControlEventEntry {
    pub event_digest: String,
    /// The exact registered reason committed by the Seal command outcome.
    pub reason_code: arkret_wire::ReasonCode,
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
    let realm = RealmId::new(realm_id.clone())
        .map_err(|e| crate::app_error!(SchemaViolation, format!("invalid realm_id: {e}")))?;
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
        Err(crate::notary::NotaryError::NotAuthorized(_)) => Err(crate::app_error!(
            PolicyViolation,
            "not authorized to sign seals for this realm".to_owned(),
        )),
        Err(e) => Err(crate::app_error!(InternalError, e.to_string())),
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

    #[tokio::test]
    async fn inbound_seal_authentication_precedes_every_state_write() {
        use soland_services::conformance_basis::{
            ConformanceNotarySigner, build_conformance_realm_basis,
        };
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm = RealmId::new("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC").unwrap();
        let signer = ConformanceNotarySigner::ed25519(
            arkret_wire::Did::new("did:web:notary.example").unwrap(),
            arkret_wire::DidUrl::new("did:web:notary.example#notary-key").unwrap(),
            [0x53; 32],
        )
        .unwrap();
        let basis = build_conformance_realm_basis(
            realm.as_str(),
            "ak:did_core:web:owner.example",
            state.service_id(),
            &signer,
            true,
            &[],
        )
        .unwrap();
        let projections = state.projections();
        projections
            .conformance_put_seal(&basis.seal, arkret_canonical::DigestSuite::Sha256)
            .await
            .unwrap();
        projections
            .conformance_append_confirmed_effects(&realm, &basis.seal.id, &basis.ops)
            .await
            .unwrap();
        let before = projections.realm_seal_basis_leaves(&realm).await.unwrap();
        let before_state = projections
            .effective_state_at(&before, &realm)
            .await
            .unwrap();
        let mut candidate = basis.seal.clone();
        candidate.predecessor_ref = Some(basis.seal.id.clone());
        candidate.delta.clear();
        candidate.notary_seq += 1;
        candidate.sealed_at = chrono::Utc::now();
        candidate.hlc = arkret_wire::Hlc::new(format!(
            "{:012x}-0000-aabbccee",
            candidate.sealed_at.timestamp_millis(),
        ))
        .unwrap();
        fn sign(seal: &mut Seal, method: arkret_wire::DidUrl, seed: [u8; 32]) {
            let body = seal.canonical_bytes_for_id().unwrap();
            seal.id = Seal::id_from_canonical_bytes(&body, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            let bytes = seal
                .commit_transcript_bytes(arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            seal.notary_signature = arkret_wire::SealSignature {
                verification_method: method.clone(),
                payload_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_digest_with_suite(&bytes, "sha256").unwrap(),
                )
                .unwrap(),
                jws: soland_services::identity::sign_ed25519_frozen_notary_jws(
                    &bytes,
                    &method,
                    &ed25519_dalek::SigningKey::from_bytes(&seed),
                )
                .unwrap(),
            };
        }
        sign(
            &mut candidate,
            signer.descriptor.verification_method.clone(),
            signer.signing_seed,
        );
        candidate
            .validate_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        candidate.validate_structural().unwrap();
        verify_realm_notary_seal(&state, &candidate)
            .await
            .expect("authorized signature verifies");
        for unauthorized_method in [false, true] {
            let mut forged = candidate.clone();
            if unauthorized_method {
                forged.state_root =
                    arkret_wire::Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
            }
            let method = if unauthorized_method {
                arkret_wire::DidUrl::new("did:web:attacker.example#notary-key").unwrap()
            } else {
                signer.descriptor.verification_method.clone()
            };
            sign(&mut forged, method, [0x71; 32]);
            forged
                .validate_id(arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            forged.validate_structural().unwrap();
            let error = apply_inbound_seal(&state, &forged)
                .await
                .expect_err("untrusted Seal rejected");
            assert_eq!(
                error.wire_code(),
                "directory_governance_proof_signature_invalid"
            );
            assert!(projections.seal_by_id(&forged.id).await.unwrap().is_none());
            assert_eq!(
                projections.realm_seal_basis_leaves(&realm).await.unwrap(),
                before
            );
            assert_eq!(
                projections
                    .effective_state_at(&before, &realm)
                    .await
                    .unwrap(),
                before_state
            );
        }
    }

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
            arkret_state::GovernanceView::new(&BTreeMap::new()),
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
            predecessor_ref: None,
            delta: Vec::new(),
            data_delta: Vec::new(),
            data_event_set_root: arkret_wire::empty_data_event_set_root(
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
            control_event_set_root: empty_root.clone(),
            state_root: empty_root.clone(),
            notary_seq: 0,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: arkret_wire::SealSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:webvh:z6mkfixture:alice.example#ak:device:recovery",
                )
                .unwrap(),
                payload_digest: placeholder_digest,
                jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
            },
            sealed_at: chrono::Utc::now(),
            hlc: arkret_identifiers::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            configuration_ref: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0; 32],
            ),
            command_results: Vec::new(),
            authorization_closures: Vec::new(),
            data_closure_announcements: Vec::new(),
            data_closures: Vec::new(),
            existence_anchors: Vec::new(),
        };
        let canonical_bytes = seal.canonical_bytes_for_id().unwrap();
        seal.id =
            Seal::id_from_canonical_bytes(&canonical_bytes, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        let transcript = seal
            .commit_transcript_bytes(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        seal.notary_signature = arkret_wire::SealSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:webvh:z6mkfixture:alice.example#ak:device:recovery",
            )
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                &transcript,
            ))
            .unwrap(),
            jws: signer.sign_detached_jws(&transcript),
        };

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
            reason_code: arkret_wire::ReasonCode::CallStateTransitionInvalid,
            reason: "call transition is invalid".to_owned(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("event_digest"));
        assert!(!s.contains("move_id"));
        assert!(s.contains("reason"));
        // The classified reason travels as a value, not as prose an operator
        // (or a client) would have to pattern-match.
        assert!(
            s.contains(r#""reason_code":"call_state_transition_invalid""#),
            "{s}"
        );
    }
}
