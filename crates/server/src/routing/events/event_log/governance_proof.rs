use std::collections::{BTreeMap, BTreeSet};

use arkret_core::models::EffectiveScope as GovernanceScope;
use arkret_core::move_event::{LatticeOp, LatticeOpType};
use arkret_core::{
    CellId, CellRef, Event, Hash, MaterializedMlsGovernanceProofBundle,
    MlsGovernanceBindingPayload, MlsGovernanceControlStateLeaf, MlsGovernanceControlStateValue,
    MlsGovernanceProofBundle, MlsGovernanceProofRequest, MoveId, SealId,
    build_mls_governance_proof_chunks, derive_mls_capability_root,
    derive_mls_discussion_metadata_digest, derive_mls_policy_root,
    is_mls_membership_frontier_component,
};
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::compute_state_root;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::*;

const SUPPORTED_REDUCER_PROFILE: &str = "ak.reducer.v1";

#[endpoint(
    operation_id = "ak.self.events.query.mls_governance_proof",
    tags("events"),
    summary = "Materialize a verifiable full-profile MLS governance binding"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.query.mls_governance_proof"))]
pub(super) async fn mls_governance_proof(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MlsGovernanceProofRequest>,
) -> JsonResult<MlsGovernanceProofBundle> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    request
        .validate()
        .map_err(|error| AppError::invalid_param(format!("invalid proof request: {error}")))?;
    if request.reducer_profile != SUPPORTED_REDUCER_PROFILE {
        return Err(AppError::new(
            ErrorCode::ProfileUnsupported,
            "requested MLS governance reducer profile is unsupported",
        ));
    }

    let realm_value = request.realm_id.as_str();
    let own_pcr = soland_domain::identity::principal_control_realm_for_did(&session.actor);
    let managed_agent_pcr =
        crate::routing::identity::managed_agent_pcr::controller_manages_agent_pcr(
            state,
            &session.actor,
            realm_value,
        )
        .await?;
    let realm_accessible = realm_value == own_pcr
        || managed_agent_pcr
        || crate::routing::spaces::space::realm_id_accessible(state, realm_value, Some(&session))
            .await;
    if !realm_accessible || !scope_visible_to_session(state, &request.effective_scope, &session) {
        return Err(AppError::not_found("realm not found"));
    }

    let materialized = materialize_governance_proof(state, &request).await?;
    let chunks = build_mls_governance_proof_chunks(&request, &materialized).map_err(|error| {
        let message = error.to_string();
        if message.contains("expected_bundle_digest") {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "requested MLS governance proof manifest is no longer available",
            )
        } else if message.contains(ErrorCode::MLS_GOVERNANCE_PROOF_BOUNDS_EXCEEDED) {
            AppError::new(ErrorCode::MlsGovernanceProofBoundsExceeded, message)
        } else {
            proof_state_error(message)
        }
    })?;
    let chunk = chunks
        .get(request.chunk_index as usize)
        .cloned()
        .ok_or_else(|| AppError::invalid_param("chunk_index is outside chunk_manifest"))?;
    json_ok(chunk)
}

fn scope_visible_to_session(
    state: &AppState,
    scope: &GovernanceScope,
    session: &SessionRecord,
) -> bool {
    match scope {
        GovernanceScope::Realm { .. } => true,
        GovernanceScope::Circle { circle_id, .. } => state
            .projection
            .lock()
            .circle_scope_visible_to_actor(circle_id.as_str(), &session.actor),
        _ => false,
    }
}

struct MaterializedRealmControl {
    events: Vec<Event>,
    joined: BTreeMap<CellRef, CellState>,
    seal_view: crate::notary::MaterializedEventSealView,
    covered_event_digests: Vec<MoveId>,
}

async fn materialize_realm_control(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<MaterializedRealmControl, AppError> {
    let stats = state
        .events_store()
        .realm_event_stats(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("canonical Event bounds preflight unavailable: {error}"),
            )
        })?;
    if stats.count > arkret_core::MLS_GOVERNANCE_MAX_COVERED_EVENT_DIGESTS as u64
        || stats.canonical_bytes > arkret_core::MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u64
    {
        return Err(AppError::new(
            ErrorCode::MlsGovernanceProofBoundsExceeded,
            "Realm Event history exceeds MLS governance proof materialization bounds",
        ));
    }
    let realm_records = state
        .events_store()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("canonical Realm Event store unavailable: {error}"),
            )
        })?;
    if realm_records.iter().any(|record| {
        record
            .envelope
            .get("effects")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|effects| {
                effects.iter().any(|effect| {
                    effect.get("cell").and_then(serde_json::Value::as_str)
                        == Some(arkret_bootstrap::MANAGED_AGENT_PRINCIPAL_CONTROL_CREATE_CELL)
                })
            })
    }) {
        return materialize_managed_agent_realm_control(state, realm_id, &realm_records);
    }
    let generation_fence = first_generation_event_seal_requirement(state, &realm_records).await?;
    let principal_control_actor = realm_records
        .iter()
        .find(|record| {
            record.kind == arkret_core::events::EventKind::REALM_CREATE
                && record
                    .envelope
                    .pointer("/payload/object/fields/purpose")
                    .and_then(serde_json::Value::as_str)
                    == Some("principal_control")
        })
        .map(|record| record.actor_id.clone());
    let active_device_generation = if let Some(principal_id) = &principal_control_actor {
        crate::routing::identity::device_generation::current_device_generation(state, principal_id)
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("device generation state unavailable: {error}"),
                )
            })?
    } else {
        None
    };
    let device_generation_seal_required = active_device_generation.is_some();
    let generation_devices = if let Some(principal_id) = &principal_control_actor
        && active_device_generation.is_some()
    {
        state
            .devices_store()
            .list_for_actor_including_revoked(principal_id)
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("device generation inventory unavailable: {error}"),
                )
            })?
    } else {
        Vec::new()
    };
    let preserved_generation_coverage = if let Some(requirement) = &generation_fence
        && !requirement.accepted_frontier_refs.is_empty()
    {
        arkret_state::leaf_union_proof(
            &requirement.accepted_frontier_refs,
            state.seal_store.as_ref(),
        )
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("accepted generation Seal coverage unavailable: {error}"),
            )
        })?
        .into_iter()
        .flat_map(|proof| proof.covered_event_digests)
        .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let mut quarantined_digests = BTreeSet::new();
    for actor in realm_records
        .iter()
        .filter(|record| record.kind == "ak.device.reanchor")
        .map(|record| record.actor_id.as_str())
        .collect::<BTreeSet<_>>()
    {
        quarantined_digests.extend(
            crate::routing::identity::device_generation::quarantined_generation_event_digests(
                state, actor,
            )
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("device generation quarantine state unavailable: {error}"),
                )
            })?,
        );
    }
    let mut events = Vec::new();
    let mut ops_by_cell: BTreeMap<CellRef, Vec<SealedOp>> = BTreeMap::new();
    let mut event_ops = Vec::new();
    let mut covered = BTreeSet::new();
    let mut identity_anchor_event_ids = realm_records
        .iter()
        .filter(|record| {
            record.kind == "ak.device.reanchor"
                && !quarantined_digests.contains(&record.canonical_digest)
        })
        .flat_map(|record| {
            std::iter::once(record.event_id.clone()).chain(
                record
                    .envelope
                    .pointer("/payload/replacement_authorize_event_id")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
            )
        })
        .collect::<BTreeSet<_>>();
    for bootstrap in realm_records.iter().filter(|record| {
        record.kind == arkret_core::events::EventKind::REALM_CREATE
            && record
                .envelope
                .pointer("/payload/object/fields/purpose")
                .and_then(serde_json::Value::as_str)
                == Some("principal_control")
    }) {
        identity_anchor_event_ids.insert(bootstrap.event_id.clone());
        identity_anchor_event_ids.extend(
            realm_records
                .iter()
                .filter(|record| {
                    record.kind == arkret_core::events::EventKind::DEVICE_AUTHORIZE
                        && record
                            .envelope
                            .get("prev_refs")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|refs| {
                                refs.len() == 1
                                    && refs[0].as_str() == Some(bootstrap.event_id.as_str())
                            })
                })
                .map(|record| record.event_id.clone()),
        );
    }

    for record in &realm_records {
        if quarantined_digests.contains(&record.canonical_digest) {
            continue;
        }
        if let (Some(principal_id), Some(generation)) =
            (&principal_control_actor, &active_device_generation)
            && record.actor_id == principal_id.as_str()
            && !identity_anchor_event_ids.contains(&record.event_id)
            && record.envelope.get("executed_by").is_none()
            && !preserved_generation_coverage
                .iter()
                .any(|digest| digest.as_str() == record.canonical_digest)
        {
            let signer_device_id = event_signer_device_id(record);
            let current_generation_signer = signer_device_id.as_ref().is_some_and(|device_id| {
                generation_devices.iter().any(|device| {
                    device.device_id == device_id.as_str()
                        && device.revoked_at.is_none()
                        && device.verification_state == "verified"
                        && device
                            .payload
                            .get("authorized_generation_ref")
                            .and_then(serde_json::Value::as_str)
                            == Some(generation.current_ref.as_str())
                })
            });
            if !current_generation_signer {
                continue;
            }
        }
        let mut event =
            serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    format!(
                        "stored Event {} is not a canonical envelope: {error}",
                        record.event_id
                    ),
                )
            })?;
        if (event.effects.is_empty()
            && !identity_anchor_event_ids.contains(record.event_id.as_str()))
            || event.seal_ref.is_some()
        {
            continue;
        }
        if event.effective_scope.is_none() {
            event.effective_scope = Some(GovernanceScope::Realm {
                realm_id: realm_id.clone(),
            });
        }
        let digest = event.event_digest().map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored Event {} digest failed: {error}", event.event_id),
            )
        })?;
        if digest != record.canonical_digest {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!("stored Event {} canonical digest mismatch", event.event_id),
            ));
        }
        let move_id = MoveId::new(digest).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored Event {} has an invalid digest: {error}",
                    event.event_id
                ),
            )
        })?;
        if !covered.insert(move_id.clone()) {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "duplicate canonical Event digest in Realm control history",
            ));
        }
        for (cell, op) in canonical_event_ops(&event, &move_id)? {
            ops_by_cell
                .entry(cell.clone())
                .or_default()
                .push(op.clone());
            event_ops.push((cell, op));
        }
        events.push(event);
    }
    if let Some(requirement) = &generation_fence {
        for digest in &requirement.required_delta {
            covered.insert(digest.clone());
        }
    }
    if covered.is_empty() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm has no accepted Control Event material",
        ));
    }

    let mut joined = BTreeMap::new();
    for (cell, mut ops) in ops_by_cell {
        ops.sort_by(|left, right| right.move_id.as_str().cmp(left.move_id.as_str()));
        let binding = state
            .cell_registry
            .resolve(realm_id, &cell)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::ProfileUnsupported,
                    format!("no lattice registered for governance cell {cell}: {error}"),
                )
            })?;
        let resolved = binding.lattice.join(&cell, &ops);
        if matches!(resolved, CellState::Bottom(_)) {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!("governance cell {cell} is in Bottom state"),
            ));
        }
        joined.insert(cell, resolved);
    }
    let state_root = compute_state_root(&joined).map_err(|error| {
        AppError::new(
            ErrorCode::StateMismatch,
            format!("governance state root failed: {error}"),
        )
    })?;
    let covered_event_digests = covered.iter().cloned().collect::<Vec<_>>();
    let seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        realm_id,
        &covered_event_digests,
        &state_root,
        &event_ops,
        device_generation_seal_required,
        generation_fence.as_ref(),
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("accepted Event Seal materialization failed: {error}"),
        )
    })?;

    Ok(MaterializedRealmControl {
        events,
        joined,
        seal_view,
        covered_event_digests,
    })
}

fn materialize_managed_agent_realm_control(
    state: &AppState,
    realm_id: &RealmId,
    records: &[soland_storage::CanonicalEventRecord],
) -> Result<MaterializedRealmControl, AppError> {
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let mut event =
            serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    format!(
                        "stored managed Agent PCR Event {} is not canonical: {error}",
                        record.event_id
                    ),
                )
            })?;
        // `effective_scope` is reducer-managed accepted output and therefore
        // absent from the producer-signed submit envelope. Managed PCR Events
        // are closed over their own Realm, so materialize the same authoritative
        // Realm scope that the ordinary Realm proof path stamps above. The field
        // is excluded from producer canonical bytes and does not alter the
        // accepted digest or controller signature.
        if event.effective_scope.is_none() {
            event.effective_scope = Some(GovernanceScope::Realm {
                realm_id: realm_id.clone(),
            });
        }
        let digest = event.event_digest().map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored managed Agent PCR Event {} digest failed: {error}",
                    record.event_id
                ),
            )
        })?;
        if digest != record.canonical_digest {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored managed Agent PCR Event {} canonical digest mismatch",
                    record.event_id
                ),
            ));
        }
        events.push(event);
    }
    let material =
        arkret_bootstrap::materialize_managed_agent_pcr_control(&events).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("managed Agent PCR control material is invalid: {error}"),
            )
        })?;
    if &material.realm_id != realm_id {
        return Err(AppError::new(
            ErrorCode::StateMismatch,
            "managed Agent PCR material resolved to a different Realm",
        ));
    }
    let seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        realm_id,
        &material.covered_event_digests,
        &material.state_root,
        &material.event_ops,
        true,
        None,
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("accepted managed Agent PCR Seal materialization failed: {error}"),
        )
    })?;
    Ok(MaterializedRealmControl {
        events,
        joined: material.joined,
        seal_view,
        covered_event_digests: material.covered_event_digests,
    })
}

pub(crate) async fn materialize_realm_event_seal(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<crate::notary::MaterializedEventSealView, AppError> {
    Ok(materialize_realm_control(state, realm_id).await?.seal_view)
}

async fn materialize_governance_proof(
    state: &AppState,
    request: &MlsGovernanceProofRequest,
) -> Result<MaterializedMlsGovernanceProofBundle, AppError> {
    let MaterializedRealmControl {
        events,
        joined,
        seal_view,
        covered_event_digests,
    } = materialize_realm_control(state, &request.realm_id).await?;
    let control_state = joined
        .iter()
        .filter_map(|(cell, state)| match state {
            CellState::Value(value) => Some(MlsGovernanceControlStateLeaf {
                cell: cell.clone(),
                state: MlsGovernanceControlStateValue {
                    value: value.clone(),
                },
            }),
            CellState::Bottom(_) => None,
        })
        .collect::<Vec<_>>();
    let policy_root = derive_mls_policy_root(&joined).map_err(proof_state_error)?;
    let capability_root = derive_mls_capability_root(&joined).map_err(proof_state_error)?;
    let discussion_metadata_digest =
        derive_mls_discussion_metadata_digest(&control_state).map_err(proof_state_error)?;

    let mut frontier_events = events
        .into_iter()
        .filter(|event| event.effective_scope.as_ref() == Some(&request.effective_scope))
        .filter(|event| {
            event.effects.iter().any(|effect| {
                CellId::from_ref(&effect.cell)
                    .map(|cell| is_mls_membership_frontier_component(cell.component()))
                    .unwrap_or(false)
            })
        })
        .collect::<Vec<_>>();
    frontier_events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    if frontier_events.is_empty() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm/scope has no materialized membership frontier Event",
        ));
    }
    let membership_frontier = frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let governance_binding = match &request.effective_scope {
        GovernanceScope::Realm { .. } => MlsGovernanceBindingPayload::realm(
            request.realm_id.clone(),
            request.mls_group_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            membership_frontier,
            policy_root,
            capability_root,
            discussion_metadata_digest,
            request.binding_profile.clone(),
            request.reducer_profile.clone(),
        ),
        GovernanceScope::Circle { circle_id, .. } => MlsGovernanceBindingPayload::circle(
            request.realm_id.clone(),
            circle_id.clone(),
            request.mls_group_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            membership_frontier,
            policy_root,
            capability_root,
            discussion_metadata_digest,
            request.binding_profile.clone(),
            request.reducer_profile.clone(),
        ),
        _ => {
            return Err(AppError::new(
                ErrorCode::ProfileUnsupported,
                "unsupported MLS governance effective scope",
            ));
        }
    }
    .map_err(proof_state_error)?;

    let anchor_position = seal_view
        .seal_path
        .iter()
        .position(|seal| seal.id == request.trusted_anchor_seal_id)
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::MlsGovernanceAnchorUnreachable,
                "requested trusted anchor is not in the accepted Seal ancestry",
            )
        })?;
    let seal_path = seal_view.seal_path[anchor_position..].to_vec();
    let mut prior = BTreeSet::new();
    for seal in &seal_path {
        if seal.id != request.trusted_anchor_seal_id
            && seal.predecessor_refs.iter().any(|predecessor| {
                predecessor != &request.trusted_anchor_seal_id && !prior.contains(predecessor)
            })
        {
            return Err(AppError::new(
                ErrorCode::MlsGovernanceAnchorUnreachable,
                "requested trusted anchor cannot bridge every accepted Seal predecessor",
            ));
        }
        prior.insert(seal.id.clone());
    }

    Ok(MaterializedMlsGovernanceProofBundle {
        bundle_version: arkret_core::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        proof_request_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
            .expect("zero sha256 digest is valid"),
        bundle_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
            .expect("zero sha256 digest is valid"),
        materialization_profile: arkret_core::MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
            .to_owned(),
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        reducer_profile: request.reducer_profile.clone(),
        governance_binding,
        trusted_anchor_seal_id: request.trusted_anchor_seal_id.clone(),
        accepted_seal_id: seal_view.accepted_seal.id,
        seal_path,
        covered_event_digests: covered_event_digests
            .into_iter()
            .map(|digest| Hash::new(digest.as_str().to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(proof_state_error)?,
        control_state,
        frontier_events,
    })
}

fn event_signer_device_id(record: &CanonicalEventRecord) -> Option<String> {
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

pub(crate) async fn first_generation_event_seal_requirement(
    state: &AppState,
    records: &[CanonicalEventRecord],
) -> Result<Option<crate::notary::FirstGenerationEventSealRequirement>, AppError> {
    let actors = records
        .iter()
        .filter(|record| record.kind == "ak.device.reanchor")
        .map(|record| record.actor_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut requirement = None;
    for actor in actors {
        let generation =
            crate::routing::identity::device_generation::current_device_generation(state, actor)
                .await
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::FrontierUnavailable,
                        format!("device generation state unavailable: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::StateMismatch,
                        "device re-anchor history has no B-model generation state",
                    )
                })?;
        if generation.status
            == crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted
        {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "device_reanchor_conflict: generation Seal materialization is quarantined",
            ));
        }
        let candidates = records
            .iter()
            .filter(|record| {
                record.actor_id == actor
                    && record.kind == "ak.device.reanchor"
                    && record
                        .envelope
                        .pointer("/payload/new_device_generation")
                        .and_then(serde_json::Value::as_str)
                        == Some(generation.current_ref.as_str())
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        if candidates.len() != 1 || requirement.is_some() {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "canonical Realm history has ambiguous active device re-anchor units",
            ));
        }
        let reanchor = candidates[0];
        let payload = serde_json::from_value::<arkret_core::DeviceReanchorPayload>(
            reanchor
                .envelope
                .get("payload")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored device re-anchor payload is invalid: {error}"),
            )
        })?;
        let authorize = records
            .iter()
            .find(|record| {
                record.event_id == payload.replacement_authorize_event_id.as_str()
                    && record.kind == arkret_core::events::EventKind::DEVICE_AUTHORIZE
                    && record.canonical_digest == payload.replacement_authorize_digest.as_str()
                    && record
                        .envelope
                        .get("prev_refs")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|refs| {
                            refs.len() == 1 && refs[0].as_str() == Some(reanchor.event_id.as_str())
                        })
            })
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    "active device re-anchor replacement authorization is missing",
                )
            })?;
        let authorize_payload = serde_json::from_value::<arkret_core::DeviceAuthorizePayload>(
            authorize
                .envelope
                .get("payload")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored replacement device authorization payload is invalid: {error}"),
            )
        })?;
        if authorize_payload.principal_id.as_str() != actor {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "replacement device authorization principal differs from the re-anchor actor",
            ));
        }
        let predecessor_refs = payload
            .pre_fence_basis
            .clone()
            .map(|basis| basis.leaves)
            .unwrap_or_default()
            .into_iter()
            .map(|leaf| SealId::new(leaf.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    format!("stored pre-fence Seal leaf is invalid: {error}"),
                )
            })?;
        let realm_id = RealmId::new(reanchor.realm_id.clone().ok_or_else(|| {
            AppError::new(
                ErrorCode::StateMismatch,
                "stored re-anchor is missing its principal-control Realm",
            )
        })?)
        .map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored re-anchor Realm id is invalid: {error}"),
            )
        })?;
        let accepted_frontier_refs =
            crate::routing::identity::device_generation::accepted_device_generation_seal_leaves(
                state, actor, &realm_id,
            )
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("accepted generation Seal frontier unavailable: {error}"),
                )
            })?;
        let reanchor_digest = Hash::new(reanchor.canonical_digest.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored re-anchor digest is invalid: {error}"),
            )
        })?;
        let required_delta = [
            reanchor_digest.as_str(),
            authorize.canonical_digest.as_str(),
        ]
        .into_iter()
        .map(|digest| MoveId::new(digest.to_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored re-anchor unit digest is invalid: {error}"),
            )
        })?;
        requirement = Some(crate::notary::FirstGenerationEventSealRequirement {
            payload,
            reanchor_digest,
            predecessor_refs,
            accepted_frontier_refs,
            required_delta,
            principal_id: actor.to_owned(),
            replacement_device_id: authorize_payload.device_id.as_str().to_owned(),
            replacement_device_public_key: authorize_payload.device_public_key.to_string(),
        });
    }
    Ok(requirement)
}

/// Expand the reducer-defined Realm genesis writes into the control-state
/// operations covered by the create Event digest.
///
/// `ak.realm.create` atomically seeds the ordered create log, the creator's
/// membership FSM cell, and the Realm notary cell. Those latter two writes are
/// reducer semantics derived from the signed `payload.object`; clients are not
/// required to duplicate them in `effects[]`. The proof materializer must
/// therefore reconstruct the same three cells instead of treating the literal
/// producer effect list as the complete reducer output.
pub(crate) fn canonical_event_ops(
    event: &Event,
    move_id: &MoveId,
) -> Result<Vec<(CellRef, SealedOp)>, AppError> {
    if event.kind.as_str() != arkret_core::events::EventKind::REALM_CREATE {
        return Ok(event
            .effects
            .iter()
            .map(|effect| {
                (
                    effect.cell.clone(),
                    SealedOp::new(move_id.clone(), effect.op.clone()),
                )
            })
            .collect());
    }

    let object = event
        .payload
        .get("object")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::StateMismatch,
                "Realm create proof material is missing payload.object",
            )
        })?;
    let created_by = object
        .get("created_by")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::StateMismatch,
                "Realm create proof material is missing created_by",
            )
        })?;
    if created_by != event.actor_id.as_str() {
        return Err(AppError::new(
            ErrorCode::StateMismatch,
            "Realm create proof material has created_by/actor_id drift",
        ));
    }
    let notary = object.get("notary").cloned().ok_or_else(|| {
        AppError::new(
            ErrorCode::StateMismatch,
            "Realm create proof material is missing the genesis notary value",
        )
    })?;
    let notary_value =
        serde_json::from_value::<arkret_core::NotaryValue>(notary.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("Realm create proof notary value is invalid: {error}"),
            )
        })?;
    notary_value.validate().map_err(|error| {
        AppError::new(
            ErrorCode::StateMismatch,
            format!("Realm create proof notary value is invalid: {error}"),
        )
    })?;

    let create_cell = CellRef::new(format!(
        "ak:cell:ak.component.realm.create.v1:{}",
        event.realm_id.as_str()
    ))
    .map_err(proof_state_error)?;
    let producer_create_cell = if object
        .get("fields")
        .and_then(serde_json::Value::as_object)
        .and_then(|fields| fields.get("purpose"))
        .and_then(serde_json::Value::as_str)
        == Some("principal_control")
    {
        let principal_cell = CellRef::new(arkret_bootstrap::PRINCIPAL_CONTROL_CREATE_CELL)
            .map_err(proof_state_error)?;
        let managed_agent_cell =
            CellRef::new(arkret_bootstrap::MANAGED_AGENT_PRINCIPAL_CONTROL_CREATE_CELL)
                .map_err(proof_state_error)?;
        let principal_count = event
            .effects
            .iter()
            .filter(|effect| effect.cell == principal_cell)
            .count();
        let managed_agent_count = event
            .effects
            .iter()
            .filter(|effect| effect.cell == managed_agent_cell)
            .count();
        match (principal_count, managed_agent_count) {
            (1, 0) => principal_cell,
            (0, 1) => managed_agent_cell,
            _ => {
                return Err(AppError::new(
                    ErrorCode::StateMismatch,
                    "Principal Control Realm create proof material must contain exactly one canonical create-log effect",
                ));
            }
        }
    } else {
        create_cell.clone()
    };
    if !event
        .effects
        .iter()
        .any(|effect| effect.cell == producer_create_cell)
    {
        return Err(AppError::new(
            ErrorCode::StateMismatch,
            "Realm create proof material omits the create-log effect",
        ));
    }

    let notary_cell = CellRef::new(format!(
        "ak:cell:ak.component.notary.v1:{}",
        event.realm_id.as_str()
    ))
    .map_err(proof_state_error)?;
    let member_cell = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{created_by}"))
        .map_err(proof_state_error)?;
    let mut entry = serde_json::Value::Object(object.clone());
    if let Some(entry) = entry.as_object_mut() {
        entry.insert(
            "entry_id".to_owned(),
            serde_json::Value::String(event.event_id.as_str().to_owned()),
        );
    }

    let mut result = event
        .effects
        .iter()
        .filter(|effect| {
            effect.cell != producer_create_cell
                && effect.cell != notary_cell
                && effect.cell != member_cell
        })
        .map(|effect| {
            (
                effect.cell.clone(),
                SealedOp::new(move_id.clone(), effect.op.clone()),
            )
        })
        .collect::<Vec<_>>();
    result.extend([
        (
            create_cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Append,
                    tag: None,
                    value: Some(entry),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: Some(event.actor_seq),
                },
            ),
        ),
        (
            member_cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Transition,
                    tag: None,
                    value: None,
                    // Realm creation is the sole bootstrap exception that
                    // directly establishes creator membership. Model that
                    // derived write from the membership FSM's normative
                    // logical initial state (`leave`), not from `invite`.
                    from: Some(serde_json::json!("leave")),
                    to: Some(serde_json::json!("join")),
                    reason: Some("realm_genesis".to_owned()),
                    issuer_seq: None,
                },
            ),
        ),
        (
            notary_cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(notary),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
        ),
    ]);
    Ok(result)
}

fn proof_state_error(error: impl std::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::StateMismatch,
        format!("MLS governance proof state mismatch: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_agent_pcr_create() -> Event {
        let realm_id = RealmId::new("ak:realm:01999999-0000-7000-8000-00000000cafe").unwrap();
        let actor_id = arkret_core::Did::new("did:web:agent.example").unwrap();
        let mut event = Event::new(
            arkret_core::events::EventKind::REALM_CREATE,
            realm_id.clone(),
            actor_id.clone(),
            1,
            arkret_core::Hlc::new("01980b44cc00-0000-aabbcce1").unwrap(),
            serde_json::json!({
                "object": {
                    "id": realm_id,
                    "created_by": actor_id,
                    "fields": {"purpose": "principal_control"},
                    "notary": {"type": "single_did", "did": actor_id},
                }
            }),
        )
        .unwrap();
        event.effects = vec![
            arkret_bootstrap::managed_agent_principal_control_create_effect(
                &event.realm_id,
                event.actor_seq,
            )
            .unwrap(),
        ];
        event
    }

    #[test]
    fn governance_materializer_accepts_managed_agent_create_marker() {
        let event = managed_agent_pcr_create();
        let move_id = MoveId::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let ops = canonical_event_ops(&event, &move_id).unwrap();
        assert_eq!(ops.len(), 3);
        assert!(ops.iter().any(|(cell, _)| {
            cell.as_str() == format!("ak:cell:ak.component.realm.create.v1:{}", event.realm_id)
        }));
        assert!(ops.iter().all(|(cell, _)| {
            cell.as_str() != arkret_bootstrap::MANAGED_AGENT_PRINCIPAL_CONTROL_CREATE_CELL
        }));
    }

    #[test]
    fn governance_materializer_rejects_legacy_managed_agent_create_effect() {
        let mut event = managed_agent_pcr_create();
        event.effects = vec![arkret_core::Effect {
            cell: CellRef::new(format!(
                "ak:cell:ak.component.realm.create.v1:{}",
                event.realm_id
            ))
            .unwrap(),
            op: LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(event.payload["object"].clone()),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        }];
        let move_id = MoveId::new(format!("sha256:{}", "22".repeat(32))).unwrap();
        assert!(canonical_event_ops(&event, &move_id).is_err());
    }
}
