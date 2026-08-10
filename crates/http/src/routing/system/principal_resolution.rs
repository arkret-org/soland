use arkret_models_identity::{
    DidDocument, PrincipalCurrentResolutionEvent, PrincipalGenesisEvent,
    PrincipalResolutionCellProof, PrincipalResolutionEvidence, PrincipalResolutionProjection,
    PrincipalResolutionUpdateEvent, ResolutionCommitment, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionDidBindingMethodProofKind, ResolutionMethodEvidenceBoundary,
    ResolutionMethodHistoryEvidence,
};
use arkret_wire::{CellRef, CoreId, Did, Event, FullId, Hash};
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::PinnedDidVersionStatus;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

const RESOLUTION_CELL: &str = "ak:cell:ak.component.identity.resolution.v1:null";
const MAX_HISTORY_DEPTH: usize = 256;

pub(super) fn open_router() -> Router {
    Router::with_path("principals/{principal_id}/resolution").get(open_principal_resolution)
}

#[salvo::oapi::endpoint(operation_id = "ak.open.identity.read.resolution", tags("identity"))]
async fn open_principal_resolution(
    principal_id: PathParam<String>,
    history_depth: QueryParam<usize, false>,
    after_resolution_event_ref: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<PrincipalResolutionEvidence> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let principal_id = CoreId::new(principal_id.into_inner())
        .map_err(|_| AppError::not_found("principal resolution not found"))?;
    let history_depth = history_depth.into_inner().unwrap_or(0);
    if history_depth > MAX_HISTORY_DEPTH {
        return Err(AppError::invalid_param(
            "history_depth exceeds the maximum of 256",
        ));
    }
    let record = state
        .persistence()
        .current_principal_resolution(&principal_id)
        .await
        .map_err(|error| AppError::internal(format!("principal resolution store failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution not found"))?;
    let event_digest = Hash::new(record.current_event.event_digest().map_err(|error| {
        AppError::internal(format!(
            "stored principal resolution Event is invalid: {error}"
        ))
    })?)
    .map_err(|error| AppError::internal(format!("stored Event digest is invalid: {error}")))?;
    let accepted_seal = state
        .projections()
        .seal_covering_event(&event_digest)
        .map_err(|error| AppError::internal(format!("principal resolution Seal failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution evidence is not sealed"))?;
    let cell_ref = CellRef::new(RESOLUTION_CELL.to_owned())
        .map_err(|error| AppError::internal(format!("resolution cell id is invalid: {error}")))?;
    let effective_state = state
        .projections()
        .effective_state_at(
            std::slice::from_ref(&accepted_seal.id),
            &record.principal_control_realm_id,
        )
        .map_err(|error| {
            AppError::internal(format!("principal resolution state proof failed: {error}"))
        })?;
    let sealed_value = effective_state
        .get(&cell_ref)
        .and_then(|cell| match cell {
            arkret_state::lattice::CellState::Value(value) => Some(value),
            arkret_state::lattice::CellState::Bottom(_) => None,
        })
        .ok_or_else(|| AppError::not_found("principal resolution cell is unavailable"))?;
    let sealed_projection: arkret_models_identity::PrincipalResolutionProjection =
        serde_json::from_value(sealed_value.clone()).map_err(|error| {
            AppError::internal(format!(
                "sealed principal resolution cell is invalid: {error}"
            ))
        })?;
    if sealed_projection != record.projection {
        return Err(AppError::internal(
            "principal resolution read index does not match the accepted Seal",
        ));
    }
    let proof =
        arkret_state::state_inclusion_proof(&effective_state, &cell_ref).map_err(|error| {
            AppError::internal(format!(
                "principal resolution inclusion proof failed: {error}"
            ))
        })?;

    let requested_cursor = after_resolution_event_ref.into_inner();
    if let Some(cursor) = requested_cursor.as_deref() {
        // A cursor is a known ancestor that bounds disclosure. Validate it
        // independently, but always read predecessors from the accepted
        // current head so the returned evidence cannot skip the current
        // Event's immediate predecessor.
        state
            .persistence()
            .principal_resolution_history(&principal_id, Some(cursor), 0)
            .await
            .map_err(|error| {
                if error.is_not_found() {
                    AppError::not_found("principal resolution history cursor not found")
                } else {
                    AppError::internal(format!(
                        "principal resolution history cursor check failed: {error}"
                    ))
                }
            })?;
    }
    let cursor_is_current = requested_cursor
        .as_deref()
        .is_some_and(|cursor| cursor == record.current_event.event_id.as_str());
    let history_result = if history_depth > 0 && !cursor_is_current {
        state
            .persistence()
            .principal_resolution_history(
                &principal_id,
                Some(record.current_event.event_id.as_str()),
                history_depth.saturating_add(1),
            )
            .await
            .map_err(|error| {
                if error.is_not_found() {
                    AppError::not_found("principal resolution history cursor not found")
                } else {
                    AppError::internal(format!("principal resolution history failed: {error}"))
                }
            })?
    } else {
        Vec::new()
    };
    let predecessors = bounded_resolution_predecessors(
        history_result,
        history_depth,
        requested_cursor.as_deref(),
        record.current_event.event_id.as_str(),
        record.genesis_event.event_id.as_str(),
    )?;
    if record.genesis_event.kind != arkret_wire::EventKind::RealmCreate {
        return Err(AppError::internal(
            "principal resolution index genesis is not a Realm create Event",
        ));
    }
    let current_resolution_event = if record.current_event.event_id == record.genesis_event.event_id
    {
        PrincipalCurrentResolutionEvent::Genesis(PrincipalGenesisEvent(
            record.current_event.clone(),
        ))
    } else {
        if record.current_event.kind != arkret_wire::EventKind::IdentityResolutionUpdate {
            return Err(AppError::internal(
                "principal resolution index current head is not a resolution update Event",
            ));
        }
        PrincipalCurrentResolutionEvent::Update(PrincipalResolutionUpdateEvent(
            record.current_event.clone(),
        ))
    };

    let method_history_evidence = principal_method_history_evidence(
        state,
        &record.projection,
        &record.genesis_event,
        &record.current_event,
        &predecessors,
    )
    .await?;

    json_ok(PrincipalResolutionEvidence {
        principal_id: record.principal_id,
        principal_control_realm_id: record.principal_control_realm_id,
        principal_genesis_event: PrincipalGenesisEvent(record.genesis_event),
        current_resolution_event,
        predecessor_resolution_events: predecessors,
        resolution_cell_proof: PrincipalResolutionCellProof {
            cell_ref: cell_ref.to_string(),
            cell_value: record.projection,
            seal_id: accepted_seal.id.to_string(),
            state_root: accepted_seal.state_root.clone(),
            leaf_digest: proof.leaf_digest,
            leaf_index: proof.leaf_index,
            leaf_count: proof.leaf_count,
            inclusion_proof: proof.inclusion_proof,
        },
        accepted_seal,
        method_history_evidence: Some(method_history_evidence),
    })
}

fn bounded_resolution_predecessors(
    history_result: Vec<Event>,
    history_depth: usize,
    requested_cursor: Option<&str>,
    current_event_ref: &str,
    genesis_event_ref: &str,
) -> Result<Vec<PrincipalResolutionUpdateEvent>, AppError> {
    let cursor_is_current = requested_cursor == Some(current_event_ref);
    if let Some(cursor) = requested_cursor
        && !cursor_is_current
        && !history_result
            .iter()
            .any(|event| event.event_id.as_str() == cursor)
    {
        return Err(AppError::invalid_param(
            "after_resolution_event_ref is not reachable within history_depth; increase the bounded depth",
        ));
    }
    if history_depth == 0 || cursor_is_current {
        return Ok(Vec::new());
    }
    history_result
        .into_iter()
        .take_while(|event| requested_cursor.is_none_or(|cursor| event.event_id.as_str() != cursor))
        .filter(|event| event.event_id.as_str() != genesis_event_ref)
        .take(history_depth)
        .map(|event| {
            if event.kind != arkret_wire::EventKind::IdentityResolutionUpdate {
                return Err(AppError::internal(
                    "principal resolution history contains a non-resolution Event",
                ));
            }
            Ok(PrincipalResolutionUpdateEvent(event))
        })
        .collect()
}

async fn principal_method_history_evidence(
    state: &AppState,
    projection: &PrincipalResolutionProjection,
    genesis_event: &Event,
    current_event: &Event,
    predecessors: &[PrincipalResolutionUpdateEvent],
) -> Result<ResolutionMethodHistoryEvidence, AppError> {
    let full_id = Did::new(projection.full_id.to_string()).map_err(|error| {
        AppError::internal(format!("stored principal full_id is invalid: {error}"))
    })?;
    let boundary = method_evidence_boundary(
        state,
        projection,
        genesis_event,
        current_event,
        predecessors,
        full_id.method(),
    )
    .await?;
    match full_id.method() {
        "webvh" => {
            let history_head =
                Hash::new(projection.method_history_head.clone()).map_err(|error| {
                    AppError::internal(format!(
                        "stored did:webvh method-history head is invalid: {error}"
                    ))
                })?;
            let pinned = state
                .dids()
                .resolve_pinned_webvh_state(&full_id, &projection.version_id, &history_head)
                .await
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::TemporarilyUnavailable,
                        format!("current principal did:webvh history is unverifiable: {error}"),
                    )
                })?;
            if pinned.status != PinnedDidVersionStatus::Current {
                return Err(AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    "principal did:webvh commitment is not the current verified method head",
                ));
            }
            let document: DidDocument =
                serde_json::from_value(pinned.document).map_err(|error| {
                    AppError::internal(format!(
                        "resolved principal DID document is invalid: {error}"
                    ))
                })?;
            let document_digest = canonical_document_digest(&document)?;
            let witness_proofs_digest = canonical_digest(&Vec::<serde_json::Value>::new())?;
            Ok(ResolutionMethodHistoryEvidence::WebvhLog {
                adapter_version: "did:webvh:1.0".to_owned(),
                boundary,
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "webvh".to_owned(),
                    document_digest,
                    method_proofs: vec![ResolutionDidBindingMethodProof {
                        kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                        history_head: projection.method_history_head.clone(),
                        witnesses: Vec::new(),
                        witness_proofs_digest,
                    }],
                },
            })
        }
        "web" | "key" => {
            let resolved = state.dids().resolve_did(&full_id).await.map_err(|error| {
                AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    format!("current principal DID document is unverifiable: {error}"),
                )
            })?;
            let document: DidDocument =
                serde_json::from_value(serde_json::to_value(resolved).map_err(|error| {
                    AppError::internal(format!("resolved principal DID encode failed: {error}"))
                })?)
                .map_err(|error| {
                    AppError::internal(format!(
                        "resolved principal DID document is invalid: {error}"
                    ))
                })?;
            let document_digest = canonical_document_digest(&document)?;
            let evidence = ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: full_id.method().to_owned(),
                document_digest,
                method_proofs: Vec::new(),
            };
            if full_id.method() == "web" {
                validate_did_web_coordinates(projection, &evidence.document_digest)?;
                Ok(ResolutionMethodHistoryEvidence::DidWebDocument {
                    adapter_version: "did:web:1".to_owned(),
                    boundary,
                    evidence,
                })
            } else {
                validate_did_key_coordinates(projection, &projection.full_id)?;
                Ok(ResolutionMethodHistoryEvidence::DidKeyExpansion {
                    adapter_version: "did:key:1".to_owned(),
                    boundary,
                    evidence,
                })
            }
        }
        method => Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("principal DID method {method:?} has no active resolution evidence adapter"),
        )),
    }
}

async fn method_evidence_boundary(
    state: &AppState,
    projection: &PrincipalResolutionProjection,
    genesis_event: &Event,
    current_event: &Event,
    predecessors: &[PrincipalResolutionUpdateEvent],
    method: &str,
) -> Result<ResolutionMethodEvidenceBoundary, AppError> {
    let current = ResolutionCommitment {
        full_id: projection.full_id.clone(),
        method_history_head: projection.method_history_head.clone(),
        version_id: projection.version_id.clone(),
    };
    // did:web and did:key have no native mutable history. Their evidence
    // boundary is the one independently verified current state even when PCR
    // resolution Events are selectively disclosed.
    let from = if method != "webvh" {
        current.clone()
    } else if current_event.kind == arkret_wire::EventKind::RealmCreate {
        genesis_resolution_commitment(genesis_event)?
    } else {
        let oldest = predecessors
            .last()
            .map(|event| &event.0)
            .unwrap_or(current_event);
        let oldest_payload = resolution_update_payload(oldest)?;
        if oldest_payload.previous_resolution_event_ref == genesis_event.event_id.as_str() {
            genesis_resolution_commitment(genesis_event)?
        } else {
            let predecessor = state
                .event_queries()
                .canonical_event(&oldest_payload.previous_resolution_event_ref)
                .await
                .map_err(|error| {
                    AppError::internal(format!(
                        "principal resolution boundary Event lookup failed: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::TemporarilyUnavailable,
                        "principal resolution boundary Event is unavailable",
                    )
                })?;
            let predecessor: Event =
                serde_json::from_value(predecessor.envelope).map_err(|error| {
                    AppError::internal(format!(
                        "principal resolution boundary Event is invalid: {error}"
                    ))
                })?;
            if predecessor.kind != arkret_wire::EventKind::IdentityResolutionUpdate
                || predecessor.realm_id != genesis_event.realm_id
                || predecessor.actor_id != genesis_event.actor_id
                || predecessor.event_id.as_str() != oldest_payload.previous_resolution_event_ref
            {
                return Err(AppError::internal(
                    "principal resolution boundary Event is outside the PCR resolution chain",
                ));
            }
            let predecessor = resolution_update_payload(&predecessor)?.next;
            if predecessor.method_history_head != oldest_payload.previous_method_history_head {
                return Err(AppError::internal(
                    "principal resolution boundary head does not match its successor guard",
                ));
            }
            predecessor
        }
    };
    Ok(ResolutionMethodEvidenceBoundary {
        from_method_history_head: from.method_history_head,
        from_version_id: from.version_id,
        to_method_history_head: current.method_history_head,
        to_version_id: current.version_id,
    })
}

fn genesis_resolution_commitment(event: &Event) -> Result<ResolutionCommitment, AppError> {
    serde_json::from_value(
        event
            .payload
            .get("object")
            .and_then(serde_json::Value::as_object)
            .and_then(|object| object.get("initial_resolution"))
            .cloned()
            .ok_or_else(|| AppError::internal("PCR genesis omits initial_resolution"))?,
    )
    .map_err(|error| AppError::internal(format!("PCR genesis resolution is invalid: {error}")))
}

fn resolution_update_payload(
    event: &Event,
) -> Result<arkret_models_identity::PrincipalResolutionUpdatePayload, AppError> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
        AppError::internal(format!(
            "stored principal resolution update payload encode failed: {error}"
        ))
    })?)
    .map_err(|error| {
        AppError::internal(format!(
            "stored principal resolution update payload is invalid: {error}"
        ))
    })
}

fn canonical_document_digest(document: &DidDocument) -> Result<Hash, AppError> {
    canonical_digest(document)
}

fn canonical_digest(value: &impl serde::Serialize) -> Result<Hash, AppError> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("canonical digest is invalid: {error}")))
}

fn validate_did_web_coordinates(
    projection: &PrincipalResolutionProjection,
    document_digest: &Hash,
) -> Result<(), AppError> {
    validate_synthetic_coordinates(
        projection,
        document_digest,
        "synthetic-jcs-sha256:",
        "did:web",
    )
}

fn validate_did_key_coordinates(
    projection: &PrincipalResolutionProjection,
    full_id: &FullId,
) -> Result<(), AppError> {
    let digest = Hash::new(arkret_canonical::sha256_digest(full_id.as_str().as_bytes()))
        .map_err(|error| AppError::internal(format!("did:key digest is invalid: {error}")))?;
    validate_synthetic_coordinates(projection, &digest, "synthetic-full-id-sha256:", "did:key")
}

fn validate_synthetic_coordinates(
    projection: &PrincipalResolutionProjection,
    digest: &Hash,
    version_prefix: &str,
    method: &str,
) -> Result<(), AppError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| AppError::internal("canonical SHA-256 digest lost its suite prefix"))?;
    if projection.method_history_head != digest.as_str()
        || projection.version_id != format!("{version_prefix}{hex}")
    {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("stored {method} commitment does not match the active adapter"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_wire::{ActorId, Hlc, ScopeRef};
    use chrono::{TimeZone as _, Utc};

    use super::*;

    fn history_fixture() -> (Event, Event, Event) {
        let actor =
            ActorId::from(CoreId::new("ak:did_core:webvh:z6mkfixture").expect("principal core id"));
        let genesis = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor.clone(),
            0,
            Hlc::new("019f00000000-0000-00000021").unwrap(),
            serde_json::json!({"object": {"purpose": "principal_control"}}),
            Utc.with_ymd_and_hms(2026, 8, 10, 3, 0, 0).unwrap(),
        )
        .unwrap();
        let update = |seq, predecessor: &Event, hlc: &str| {
            arkret_wire::test_support::raw_event_at(
                arkret_wire::EventKind::IdentityResolutionUpdate.as_str(),
                ScopeRef::Realm {
                    realm_id: genesis.realm_id.clone(),
                },
                actor.clone(),
                seq,
                Hlc::new(hlc).unwrap(),
                serde_json::json!({
                    "previous_resolution_event_ref": predecessor.event_id,
                    "previous_method_history_head": format!("head-{seq}")
                }),
                Utc.with_ymd_and_hms(2026, 8, 10, 3, 0, seq as u32).unwrap(),
            )
            .unwrap()
        };
        let first = update(1, &genesis, "019f00000000-0001-00000021");
        let second = update(2, &first, "019f00000000-0002-00000021");
        (genesis, first, second)
    }

    #[test]
    fn current_cursor_returns_an_empty_predecessor_segment() {
        let (genesis, _, current) = history_fixture();
        let selected = bounded_resolution_predecessors(
            Vec::new(),
            0,
            Some(current.event_id.as_str()),
            current.event_id.as_str(),
            genesis.event_id.as_str(),
        )
        .unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn cursor_beyond_requested_depth_fails_instead_of_emitting_partial_evidence() {
        let (genesis, first, current) = history_fixture();
        assert!(
            bounded_resolution_predecessors(
                vec![first.clone()],
                1,
                Some(genesis.event_id.as_str()),
                current.event_id.as_str(),
                genesis.event_id.as_str(),
            )
            .is_err()
        );
        let selected = bounded_resolution_predecessors(
            vec![first, genesis.clone()],
            1,
            Some(genesis.event_id.as_str()),
            current.event_id.as_str(),
            genesis.event_id.as_str(),
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
    }
}
