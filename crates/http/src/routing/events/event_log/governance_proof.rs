use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, MAX_GOVERNANCE_DEPENDENCY_SELECTORS,
};
use arkret_models_crypto::{
    MlsEpochHead, MlsGovernanceBindingPayload, MlsGovernanceFrontierOutcome,
    MlsGovernanceFrontierRequestBody, MlsGovernanceProofBundle, MlsGovernanceProofRequestBody,
    ProposedMlsGroupGenesisBinding,
};
use arkret_state::mls_governance_proof::{
    MlsGovernanceVerificationCheckpoint, MlsGroupGenesisBinding,
};
use arkret_state::state::control_event_set_root;
use arkret_state::state_model::ordered_log::IssuedOp;
use arkret_state::state_model::{ResolvedCellState, StateWrite};
#[cfg(test)]
use arkret_wire::cbs::LatticeOp;
use arkret_wire::cbs::LatticeOpType;
use arkret_wire::{Event, ScopeRef as GovernanceScope};
use salvo::oapi::extract::JsonBody;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.seals.read.mls_governance_proof",
    tags("seals")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.seals.read.mls_governance_proof.v1"))]
pub(super) async fn mls_governance_proof(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MlsGovernanceFrontierRequestBody>,
) -> JsonResult<MlsGovernanceFrontierOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    request.validate().map_err(super::current_query_error)?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_READ_MLS_GOVERNANCE_PROOF_V1,
    )?;

    let realm_id = request.effective_scope.realm_id_opt().ok_or_else(|| {
        AppError::param_invalid("MLS governance proof scope does not name a Realm")
    })?;
    let realm_value = realm_id.as_str();
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let own_pcr = durable_account_owns_pcr(state, &session_actor, realm_id).await?;
    let agent_pcr = if let Some(account_id) = session_actor.as_account_id() {
        crate::routing::identity::agent_pcr::agent_record_for_controller_account_pcr(
            state,
            account_id,
            realm_value,
        )
        .await?
        .is_some()
    } else {
        false
    };
    let realm_accessible = own_pcr
        || agent_pcr
        || crate::routing::spaces::space::realm_id_accessible(state, realm_value, Some(&session))
            .await;
    if !realm_accessible || !scope_visible_to_session(state, &request.effective_scope, &session) {
        return Err(AppError::not_found("realm not found"));
    }

    json_ok(materialize_self_governance_frontier(state, &request).await?)
}

async fn materialize_self_governance_frontier(
    state: &AppState,
    request: &MlsGovernanceFrontierRequestBody,
) -> Result<MlsGovernanceFrontierOutcome, AppError> {
    let realm_id = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| AppError::param_invalid("MLS frontier requires a Realm"))?;
    let accepted = state
        .projections()
        .effective_state_at(&request.seal_basis.leaves, realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let live_digest_suite = state
        .projections()
        .seal_basis_digest_suite(realm_id, &request.seal_basis.leaves)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let genesis = group_genesis_binding(
        &accepted,
        &request.effective_scope,
        &request.mls_group_id,
        request.proposed_group_genesis_binding.as_ref(),
        request.previous_epoch,
        request.next_epoch,
    )?;
    let digest =
        arkret_state::mls_governance_proof::mls_security_frontier_digest_from_accepted_state(
            &request.effective_scope,
            &accepted,
            &genesis,
            &request.local_mls_leaves,
        )
        .map_err(map_governance_frontier_error)?;
    let epoch_cell = arkret_state::mls_cells::mls_epoch_cell_id(
        &request.effective_scope,
        request.mls_group_id.as_str(),
    )
    .map_err(map_governance_frontier_error)?;
    let epoch_head = match accepted.get(&epoch_cell) {
        None => None,
        Some(ResolvedCellState::Sequenced(state)) => Some(
            serde_json::from_value::<MlsEpochHead>(state.value.clone())
                .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?,
        ),
        Some(_) => {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "MLS epoch has no winning accepted value"
            ));
        }
    };
    let governance_binding = match &request.effective_scope {
        GovernanceScope::Realm { realm_id } => MlsGovernanceBindingPayload::realm(
            realm_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            digest,
            genesis.content_scheme,
            genesis.durability_policy,
            arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_wire::CORE_REDUCER_PROFILE,
        ),
        GovernanceScope::Circle {
            realm_id,
            circle_id,
        } => MlsGovernanceBindingPayload::circle(
            realm_id.clone(),
            circle_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            digest,
            genesis.content_scheme,
            genesis.durability_policy,
            arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_wire::CORE_REDUCER_PROFILE,
        ),
        _ => {
            return Err(AppError::param_invalid(
                "MLS frontier scope is not Realm or Circle",
            ));
        }
    }
    .map_err(map_governance_frontier_error)?;
    let outcome = MlsGovernanceFrontierOutcome {
        query_digest: request
            .query_digest()
            .map_err(map_governance_frontier_error)?,
        live_digest_suite,
        governance_binding,
        epoch_head,
    };
    outcome
        .validate_for_request(request)
        .map_err(map_governance_frontier_error)?;
    Ok(outcome)
}

pub(super) async fn validate_transition_leaf_input(
    state: &AppState,
    event: &Event,
    leaves: Option<&[arkret_wire::mls_transition::MlsSecurityFrontierLeaf]>,
) -> Result<(), AppError> {
    arkret_wire::event_submission::validate_mls_submission_leaves(event, leaves)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let Some(leaves) = leaves else {
        return Ok(());
    };
    let binding: MlsGovernanceBindingPayload = serde_json::from_value(
        event
            .payload
            .get("governance_binding")
            .cloned()
            .ok_or_else(|| AppError::param_invalid("MLS transition binding is missing"))?,
    )
    .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let basis = event
        .seal_basis
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("MLS transition requires an exact Seal basis"))?;
    if binding.effective_scope() != &event.scope_ref {
        return Err(AppError::param_invalid(
            "MLS input scope does not bind the Event",
        ));
    }
    let accepted = state
        .projections()
        .effective_state_at(&basis.leaves, &event.realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let group_id = arkret_wire::Base64UrlString::new(binding.mls_group_id().to_owned())
        .map_err(AppError::param_invalid)?;
    let proposal = (event.kind == arkret_wire::EventKind::MlsGenesis).then(|| {
        ProposedMlsGroupGenesisBinding {
            content_scheme: binding.content_scheme(),
            durability_policy: binding.durability_policy(),
        }
    });
    let genesis = group_genesis_binding(
        &accepted,
        binding.effective_scope(),
        &group_id,
        proposal.as_ref(),
        binding.previous_epoch(),
        binding.next_epoch(),
    )?;
    if genesis.content_scheme != binding.content_scheme()
        || genesis.durability_policy != binding.durability_policy()
    {
        return Err(crate::app_error!(
            StateMismatch,
            "MLS transition changes the accepted Genesis key schedule"
        ));
    }
    let digest =
        arkret_state::mls_governance_proof::mls_security_frontier_digest_from_accepted_state(
            binding.effective_scope(),
            &accepted,
            &genesis,
            leaves,
        )
        .map_err(map_governance_frontier_error)?;
    if &digest != binding.security_frontier_digest() {
        return Err(crate::app_error!(
            StateMismatch,
            "MLS public leaf input does not reproduce the signed security frontier"
        ));
    }
    Ok(())
}

pub(super) fn scope_visible_to_session(
    state: &AppState,
    scope: &GovernanceScope,
    session: &SessionRecord,
) -> bool {
    match scope {
        GovernanceScope::Realm { .. } => true,
        GovernanceScope::Circle { circle_id, .. } => {
            crate::routing::identity::session_actor::session_actor_from_credential(state, session)
                .is_ok_and(|actor| {
                    state
                        .projections()
                        .snapshot()
                        .circle_scope_visible_to_actor(circle_id.as_str(), &actor.to_string())
                })
        }
        _ => false,
    }
}

struct MaterializedRealmControl {
    seal_view: crate::notary::MaterializedEventSealView,
}

fn authoritative_notary(
    joined: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<Option<arkret_wire::notary::NotaryValue>, AppError> {
    // `joined` is the portable control-state map used for Seal state-root
    // verification, so its keys must remain byte-identical to signed Event
    // effects. Realm-singleton cells therefore use the canonical `null` wire
    // subject here. Only the process-wide ProjectionState cache rewrites that
    // subject to `realm_id` to prevent cross-Realm aliasing.
    let notary_cell =
        CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned()).map_err(proof_state_error)?;
    let Some(ResolvedCellState::Sequenced(state)) = joined.get(&notary_cell) else {
        return Ok(None);
    };
    let notary = serde_json::from_value::<arkret_wire::notary::NotaryValue>(state.value.clone())
        .map_err(|error| {
            proof_state_error(format!("invalid materialized Realm notary: {error}"))
        })?;
    notary.validate().map_err(proof_state_error)?;
    Ok(Some(notary))
}

async fn apply_authoritative_event_seal_path(
    state: &AppState,
    realm_id: &RealmId,
    authoritative_notary: &arkret_wire::notary::NotaryValue,
    event_ops: &[(CellRef, IssuedOp)],
    available_control_digests: &BTreeSet<Hash>,
    seals: &[arkret_wire::Seal],
) -> Result<(), AppError> {
    for seal in seals {
        let digest_suites = state
            .projections()
            .seal_digest_suites(seal)
            .await
            .map_err(proof_state_error)?;
        seal.validate_id(digest_suites.seal_digest_suite)
            .map_err(|error| {
                proof_state_error(format!("authoritative Event Seal id is invalid: {error}"))
            })?;
        seal.validate_structural().map_err(|error| {
            proof_state_error(format!(
                "authoritative Event Seal structure is invalid: {error}"
            ))
        })?;
        if &seal.realm_id != realm_id {
            return Err(proof_state_error(
                "authoritative Event Seal path crosses Realm boundaries",
            ));
        }
        if let Some(existing) = state
            .projections()
            .seal_by_id(&seal.id)
            .await
            .map_err(|error| proof_state_error(format!("read Event Seal: {error}")))?
        {
            if existing != *seal {
                return Err(proof_state_error(
                    "authoritative Event Seal id already has different signature material",
                ));
            }
            continue;
        }

        let head = state
            .projections()
            .realm_seal_head(realm_id)
            .await
            .map_err(|error| proof_state_error(format!("read Event Seal frontier: {error}")))?;
        let leaves = head.iter().cloned().collect::<Vec<_>>();
        if seal.predecessor_ref != head {
            return Err(proof_state_error(
                "authoritative Event Seal predecessors differ from the local frontier",
            ));
        }
        let current = if head.is_none() {
            BTreeSet::new()
        } else {
            state
                .projections()
                .predecessor_covered_events(head.as_ref())
                .await
                .map_err(|error| {
                    proof_state_error(format!("read Event Seal predecessor coverage: {error}"))
                })?
        };
        if seal.delta.iter().any(|digest| current.contains(digest)) {
            return Err(proof_state_error(
                "authoritative Event Seal delta repeats predecessor coverage",
            ));
        }
        if seal
            .delta
            .iter()
            .any(|digest| !available_control_digests.contains(digest))
        {
            return Err(crate::app_error!(
                DependencyMissing,
                "authoritative Event Seal delta references a Control Event that is not accepted",
            ));
        }
        let mut target = current;
        target.extend(seal.delta.iter().cloned());
        let declared = seal
            .covered_event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !seal.covered_event_digests.is_empty()
            && (declared.len() != seal.covered_event_digests.len() || declared != target)
        {
            return Err(proof_state_error(
                "authoritative Event Seal coverage differs from predecessor coverage plus delta",
            ));
        }
        let expected_control_root =
            control_event_set_root(&target, digest_suites.seal_digest_suite)
                .map_err(proof_state_error)?;
        if seal.control_event_set_root != expected_control_root {
            return Err(proof_state_error(
                "authoritative Event Seal control_event_set_root mismatch",
            ));
        }

        let mut ops_by_cell: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
        for (cell, op) in event_ops
            .iter()
            .filter(|(_, issued)| target.contains(&issued.op.event_id.event_digest()))
        {
            ops_by_cell
                .entry(cell.clone())
                .or_default()
                .push(op.clone());
        }
        let target_state = join_control_state_batches(state, realm_id, &ops_by_cell, &target)
            .await
            .map_err(|error| {
                proof_state_error(format!("resolve authoritative Event Seal state: {error}"))
            })?;
        let expected_state_root = target_state
            .state_root(digest_suites.seal_digest_suite)
            .map_err(proof_state_error)?;
        if seal.state_root != expected_state_root {
            return Err(proof_state_error(format!(
                "authoritative Event Seal state_root mismatch: submitted {}, expected {}",
                seal.state_root, expected_state_root
            )));
        }
        let mut predecessor_sequences = Vec::with_capacity(leaves.len());
        for leaf in &leaves {
            let predecessor = state
                .projections()
                .seal_by_id(leaf)
                .await
                .map_err(|error| proof_state_error(format!("read Seal predecessor: {error}")))?
                .ok_or_else(|| proof_state_error("Event Seal predecessor is missing"))?;
            predecessor_sequences.push(predecessor.notary_seq);
        }
        let expected_notary_seq =
            predecessor_sequences
                .into_iter()
                .max()
                .map_or(Ok(0), |sequence| {
                    sequence
                        .checked_add(1)
                        .ok_or_else(|| proof_state_error("Event Seal notary_seq overflow"))
                })?;
        if seal.notary_seq != expected_notary_seq {
            return Err(proof_state_error(
                "authoritative Event Seal notary_seq does not follow its predecessors",
            ));
        }

        arkret_signatures::verify_seal_signature(
            seal,
            &authoritative_notary,
            digest_suites.seal_digest_suite,
        )
        .map_err(proof_state_error)?;

        let delta = seal.delta.iter().cloned().collect::<BTreeSet<_>>();
        let new_ops = event_ops
            .iter()
            .filter(|(_, issued)| delta.contains(&issued.op.event_id.event_digest()))
            .cloned()
            .collect::<Vec<_>>();
        let seal_digest_suite = state
            .projections()
            .seal_digest_suites(seal)
            .await
            .map_err(proof_state_error)?
            .seal_digest_suite;
        let confirmed_device_control =
            crate::routing::identity::device_generation::candidate_device_control_projection(
                state,
                seal,
                seal_digest_suite,
            )
            .await
            .map_err(proof_state_error)?;
        match state
            .projections()
            .commit_event_seal_if_head(
                seal,
                seal_digest_suite,
                head.as_ref(),
                &new_ops,
                &target,
                &[],
                confirmed_device_control.as_ref(),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(proof_state_error(
                    "authoritative Event Seal frontier changed during backfill",
                ));
            }
            Err(error) => {
                return Err(proof_state_error(format!(
                    "commit authoritative Event Seal: {error}"
                )));
            }
        }
        if state.storage_mode() == "memory" {
            crate::routing::federation::move_seal::validate_accepted_fork_resolution_records(
                state,
                seal,
                digest_suites.seal_digest_suite,
            )
            .await?;
        }
    }
    Ok(())
}

async fn materialize_realm_control(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<MaterializedRealmControl, AppError> {
    materialize_realm_control_with_transported_seals(state, realm_id, None).await
}

async fn materialize_realm_control_with_transported_seals(
    state: &AppState,
    realm_id: &RealmId,
    transported_seals: Option<&[arkret_wire::Seal]>,
) -> Result<MaterializedRealmControl, AppError> {
    let realm_records = state
        .event_queries()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("canonical Realm Event store unavailable: {error}"),
            )
        })?;
    if realm_records.iter().any(|record| {
        record.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && record
                .envelope
                .pointer("/payload/object/purpose")
                .and_then(serde_json::Value::as_str)
                == Some("agent_control")
            && record
                .envelope
                .get("executed_by")
                .is_some_and(|executed_by| {
                    serde_json::from_value::<arkret_wire::ActorId>(executed_by.clone()).is_ok()
                })
    }) {
        return materialize_agent_realm_control(state, realm_id, &realm_records).await;
    }
    let generation_fence = first_generation_event_seal_requirement(state, &realm_records).await?;
    let principal_control_actor = realm_records
        .iter()
        .find(|record| {
            record.kind == arkret_wire::EventKind::RealmCreate.as_str()
                && record
                    .envelope
                    .pointer("/payload/object/purpose")
                    .and_then(serde_json::Value::as_str)
                    == Some("principal_control")
        })
        .map(|record| canonical_actor(&record.actor_id))
        .transpose()?;
    let active_device_generation = if let Some(principal_id) = &principal_control_actor {
        crate::routing::identity::device_generation::current_device_generation(
            state,
            principal_id.signing_principal_id().as_str(),
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
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
            .identities()
            .devices_for_actor(principal_id.signing_principal_id().as_str())
            .await
            .map_err(|error| {
                crate::app_error!(
                    FrontierUnavailable,
                    format!("device generation inventory unavailable: {error}"),
                )
            })?
    } else {
        Vec::new()
    };
    let preserved_generation_coverage = if let Some(requirement) = &generation_fence
        && requirement.accepted_head_ref.is_some()
    {
        state
            .projections()
            .seal_leaf_union_proof(requirement.accepted_head_ref.as_slice())
            .await
            .map_err(|error| {
                crate::app_error!(
                    FrontierUnavailable,
                    format!("accepted generation Seal coverage unavailable: {error}"),
                )
            })?
            .into_iter()
            .flat_map(|proof| proof.covered_event_digests)
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let mut events = Vec::new();
    // Candidate Events are replayed on top of the accepted predecessor Seal
    // state. The Event query only supplies envelopes; the Cell store is the
    // authoritative source for the already sealed effects.
    let mut ops_by_cell: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
    let mut event_ops = Vec::new();
    let mut sealed_move_ids = BTreeSet::new();
    for cell in state
        .projections()
        .realm_cells(realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("read sealed Realm cells for governance replay: {error}"),
            )
        })?
    {
        let ops = state
            .projections()
            .state_writes_for_cell(realm_id, &cell)
            .await
            .map_err(|error| {
                crate::app_error!(
                    FrontierUnavailable,
                    format!("read sealed governance pre-state for {cell}: {error}"),
                )
            })?;
        if !ops.is_empty() {
            sealed_move_ids.extend(ops.iter().map(|issued| issued.op.event_id.event_digest()));
            event_ops.extend(ops.iter().cloned().map(|issued| (cell.clone(), issued)));
            ops_by_cell.insert(cell, ops);
        }
    }
    let mut covered = BTreeSet::new();
    let mut identity_anchor_event_ids = realm_records
        .iter()
        .filter(|record| record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR)
        .flat_map(|record| {
            std::iter::once(record.event_id.clone()).chain(
                soland_services::events::paired_replacement_authorize(record, realm_records.iter())
                    .map(|paired| paired.event_id.clone()),
            )
        })
        .collect::<BTreeSet<_>>();
    for bootstrap in realm_records.iter().filter(|record| {
        record.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && record
                .envelope
                .pointer("/payload/object/purpose")
                .and_then(serde_json::Value::as_str)
                == Some("principal_control")
    }) {
        identity_anchor_event_ids.insert(bootstrap.event_id.clone());
        identity_anchor_event_ids.extend(
            realm_records
                .iter()
                .filter(|record| {
                    record.kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
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

    // The query is newest-first, while transition transitions across distinct Seal
    // bases must be reduced in causal acceptance order. Move digests are
    // content hashes and therefore cannot be used as transition ordering.
    for record in realm_records.iter().rev() {
        if let (Some(principal_id), Some(generation)) =
            (&principal_control_actor, &active_device_generation)
            && record.actor_id == principal_id.to_string()
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
                            .and_then(serde_json::Value::as_u64)
                            == Some(generation.current_ref)
                })
            });
            if !current_generation_signer {
                continue;
            }
        }
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!(
                    "stored Event {} is not a canonical envelope: {error}",
                    record.event_id
                ),
            )
        })?;
        let requires_invite_membership_validation =
            event.kind == arkret_wire::EventKind::InviteAccept;
        // v1 has no producer `effects[]`: whether a stored Event contributes
        // governance writes is decided by its registered contract, not by an
        // array on the envelope.
        let projects_writes = state
            .projections()
            .project_accepted_cell_writes_with_digest_suite(&event, record.digest_suite)
            .map(|writes| !writes.is_empty())
            .unwrap_or(false);
        if (!projects_writes
            && !identity_anchor_event_ids.contains(record.event_id.as_str())
            && !requires_invite_membership_validation)
            || event.auth_context.is_some()
        {
            continue;
        }
        let digest = event
            .event_digest_with_digest_suite(record.digest_suite)
            .map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!("stored Event {} digest failed: {error}", event.event_id),
                )
            })?;
        if digest != record.canonical_digest {
            return Err(crate::app_error!(
                StateMismatch,
                format!("stored Event {} canonical digest mismatch", event.event_id),
            ));
        }
        let move_id = Hash::new(digest).map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!(
                    "stored Event {} has an invalid digest: {error}",
                    event.event_id
                ),
            )
        })?;
        if !covered.insert(move_id.clone()) {
            return Err(crate::app_error!(
                StateMismatch,
                "duplicate canonical Event digest in Realm control history",
            ));
        }
        // The canonical Event envelope is immutable. The Cell store is the
        // authoritative record of which control Moves are already sealed.
        // They remain part of cumulative Seal coverage and state-root
        // verification, but must not be projected into the successor's
        // candidate batch: doing so destroys the predecessor/candidate
        // boundary used by causal-state resolution and can manufacture a
        // conflict from one historical write.
        if sealed_move_ids.contains(&move_id) {
            continue;
        }
        let invite_accept_from = if requires_invite_membership_validation {
            let member_cell = CellRef::new(format!(
                "ak:cell:ak.component.member.state.v1:{}",
                arkret_wire::composite_subject(&[event
                    .actor_id
                    .canonical_key()
                    .map_err(proof_state_error)?])
                .map_err(proof_state_error)?
            ))
            .map_err(proof_state_error)?;
            match ops_by_cell.get(&member_cell) {
                None => Some("leave".to_owned()),
                Some(ops) => {
                    let binding = state
                        .projections()
                        .resolve_cell(realm_id, &member_cell)
                        .map_err(|error| {
                            crate::app_error!(
                                UnsupportedProfile,
                                format!(
                                    "no state model registered for governance cell \
                                         {member_cell}: {error}"
                                ),
                            )
                        })?;
                    let resolved =
                        arkret_state::join_cell(binding.model.as_ref(), &member_cell, ops)
                            .map_err(|error| {
                                crate::app_error!(
                                    StateMismatch,
                                    format!("governance member cell resolution failed: {error}"),
                                )
                            })?;
                    match resolved {
                        ResolvedCellState::Sequenced(
                            arkret_state::state_model::SequencedStateValue {
                                value: serde_json::Value::String(value),
                                ..
                            },
                        ) => Some(value),
                        ResolvedCellState::Sequenced(_) => {
                            return Err(crate::app_error!(
                                StateMismatch,
                                format!(
                                    "governance member cell {member_cell} is not a string state"
                                ),
                            ));
                        }
                        ResolvedCellState::Causal(_)
                        | ResolvedCellState::Value(_)
                        | ResolvedCellState::Bottom(_) => {
                            return Err(crate::app_error!(
                                StateMismatch,
                                format!(
                                    "governance member cell {member_cell} is not sequenced state"
                                ),
                            ));
                        }
                    }
                }
            }
        } else {
            None
        };
        for (cell, issued) in canonical_event_ops(
            state,
            realm_id,
            &event,
            &move_id,
            &ops_by_cell,
            invite_accept_from.as_deref(),
            record.digest_suite,
        )? {
            ops_by_cell
                .entry(cell.clone())
                .or_default()
                .push(issued.clone());
            event_ops.push((cell, issued));
        }
        events.push(event);
    }
    if let Some(requirement) = &generation_fence {
        for digest in &requirement.required_delta {
            covered.insert(digest.clone());
        }
    }
    if covered.is_empty() {
        if let Some(head) = crate::notary::ensure_realm_seal_head(state, realm_id)
            .await
            .map_err(|error| {
                crate::app_error!(
                    FrontierUnavailable,
                    format!("accepted Realm Seal frontier is unavailable: {error}"),
                )
            })?
        {
            let seal_view = crate::notary::materialized_event_seal_view(state, head)
                .await
                .map_err(|error| {
                    crate::app_error!(
                        FrontierUnavailable,
                        format!("accepted Realm Seal path is unavailable: {error}"),
                    )
                })?;
            return Ok(MaterializedRealmControl { seal_view });
        }
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm has no accepted Control Event material",
        ));
    }
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
    let joined = join_control_state_batches(state, realm_id, &ops_by_cell, &covered).await?;
    let state_root = joined.state_root(digest_suite).map_err(|error| {
        crate::app_error!(
            StateMismatch,
            format!("governance state root failed: {error}"),
        )
    })?;
    let covered_event_digests = covered.iter().cloned().collect::<Vec<_>>();
    if let Some(seals) = transported_seals {
        let authoritative_notary = authoritative_notary(&joined.cells)?.ok_or_else(|| {
            proof_state_error("transported Event Seal path has no frozen notary authority")
        })?;
        apply_authoritative_event_seal_path(
            state,
            realm_id,
            &authoritative_notary,
            &event_ops,
            &covered,
            seals,
        )
        .await?;
    }
    let seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        realm_id,
        &covered_event_digests,
        &state_root,
        &event_ops,
        device_generation_seal_required,
        generation_fence.as_ref(),
    );
    let seal_view = seal_view.await.map_err(|error| {
        crate::app_error!(
            FrontierUnavailable,
            format!("accepted Event Seal materialization failed: {error}"),
        )
    })?;

    Ok(MaterializedRealmControl { seal_view })
}

async fn materialize_agent_realm_control(
    state: &AppState,
    realm_id: &RealmId,
    records: &[soland_services::events::AcceptedEvent],
) -> Result<MaterializedRealmControl, AppError> {
    let accepted_seal = crate::notary::ensure_realm_seal_head(state, realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("accepted Agent PCR Seal is unavailable: {error}"),
            )
        })?
        .ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "Agent PCR has no accepted Seal command history",
            )
        })?;
    let mut events_by_digest = BTreeMap::new();
    let mut event_digest_suites = BTreeMap::new();
    for record in records {
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!(
                    "stored Agent PCR Event {} is not canonical: {error}",
                    record.event_id
                ),
            )
        })?;
        // `scope_ref` is producer-signed and part of the canonical digest
        // transcript (`conformance/encoding.md` §6), so nothing may stamp it
        // here. Managed PCR Events are closed over their own Realm; a stored
        // Event whose signed scope names another Realm is not proof material
        // for this one.
        let event_realm_id = event.scope_ref.realm_id_opt().unwrap_or(&event.realm_id);
        if event_realm_id != realm_id {
            return Err(crate::app_error!(
                StateMismatch,
                format!(
                    "stored Agent PCR Event {} is scoped to another Realm",
                    record.event_id
                ),
            ));
        }
        let digest = event
            .event_digest_with_digest_suite(record.digest_suite)
            .map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!(
                        "stored Agent PCR Event {} digest failed: {error}",
                        record.event_id
                    ),
                )
            })?;
        if digest != record.canonical_digest {
            return Err(crate::app_error!(
                StateMismatch,
                format!(
                    "stored Agent PCR Event {} canonical digest mismatch",
                    record.event_id
                ),
            ));
        }
        let digest = Hash::new(digest).map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!("stored Agent PCR Event digest is invalid: {error}"),
            )
        })?;
        event_digest_suites.insert(event.event_id.clone(), record.digest_suite);
        if events_by_digest
            .insert(digest, (event, record.digest_suite))
            .is_some()
        {
            return Err(crate::app_error!(
                StateMismatch,
                "duplicate canonical Event digest in Agent PCR history",
            ));
        }
    }
    let ordered = crate::routing::identity::agent_pcr::resolve_agent_pcr_ordered_history(
        state,
        accepted_seal.clone(),
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
            .project_accepted_cell_writes_with_digest_suite(event, event_digest_suite)
            .map_err(|error| error.to_string())
    })
    .map_err(|error| {
        crate::app_error!(
            StateMismatch,
            format!("Agent PCR control material is invalid: {error}"),
        )
    })?;
    if &material.realm_id != realm_id {
        return Err(crate::app_error!(
            StateMismatch,
            "Agent PCR material resolved to a different Realm",
        ));
    }
    if material.command_results != ordered.committed_command_results {
        return Err(crate::app_error!(
            StateMismatch,
            "accepted Agent PCR command results do not match deterministic replay",
        ));
    }
    if accepted_seal.state_root != material.state_root {
        return Err(crate::app_error!(
            StateMismatch,
            "accepted Agent PCR Seal state_root does not match deterministic replay",
        ));
    }
    let accepted_coverage = state
        .projections()
        .predecessor_covered_events(Some(&accepted_seal.id))
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("accepted Agent PCR coverage is unavailable: {error}"),
            )
        })?;
    if material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != accepted_coverage
    {
        return Err(crate::app_error!(
            StateMismatch,
            "accepted Agent PCR Seal coverage does not match deterministic replay",
        ));
    }
    Ok(MaterializedRealmControl {
        seal_view: ordered.seal_view,
    })
}

pub(crate) async fn materialize_realm_event_seal(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<crate::notary::MaterializedEventSealView, AppError> {
    Ok(materialize_realm_control(state, realm_id).await?.seal_view)
}

pub(crate) async fn accept_federated_event_seal_path(
    state: &AppState,
    realm_id: &RealmId,
    seals: &[arkret_wire::Seal],
) -> Result<(), AppError> {
    if seals.is_empty() {
        return Ok(());
    }
    materialize_realm_control_with_transported_seals(state, realm_id, Some(seals)).await?;
    Ok(())
}

pub(in crate::routing) async fn materialize_governance_frontier(
    state: &AppState,
    request: &MlsGovernanceProofRequestBody,
) -> Result<MlsGovernanceProofBundle, AppError> {
    // Public LeafNode coordinates are query-bound. The SDK materializer checks
    // them against replayed governance, and the receiver independently checks
    // the outcome against its own RFC 9420 current or pending group state.
    let leaves = request.local_mls_leaves.clone();
    let checkpoint = load_governance_checkpoint(state, request).await?;
    let accepted = state
        .projections()
        .effective_state_at(&request.proof_target_basis.leaves, &checkpoint.realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let group_genesis_binding = group_genesis_binding(
        &accepted,
        &request.effective_scope,
        &request.mls_group_id,
        request.proposed_group_genesis_binding.as_ref(),
        request.previous_epoch,
        request.next_epoch,
    )?;
    arkret::materialize_mls_governance_frontier(
        request,
        &checkpoint,
        &group_genesis_binding,
        &leaves,
        crate::routing::governance_history::historical_governance_key_verifier(state.clone()),
    )
    .await
    .map_err(map_governance_frontier_error)
}

async fn load_governance_checkpoint(
    state: &AppState,
    request: &MlsGovernanceProofRequestBody,
) -> Result<MlsGovernanceVerificationCheckpoint, AppError> {
    let realm_id = request.effective_scope.realm_id_opt().ok_or_else(|| {
        AppError::param_invalid("MLS governance proof scope does not name a Realm")
    })?;
    let mut seals = BTreeMap::new();
    let mut pending = request.proof_target_basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if seals.contains_key(&seal_id) {
            continue;
        }
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "requested target Seal closure is unavailable",
                )
            })?;
        if seal.realm_id != *realm_id {
            return Err(crate::app_error!(
                MlsGovernanceAnchorUnreachable,
                "requested Seal closure crosses the Realm boundary",
            ));
        }
        pending.extend(seal.predecessor_ref.iter().cloned());
        seals.insert(seal_id, seal);
    }
    ensure_target_dominates_base(request, &seals)?;

    let mut events = BTreeMap::new();
    for seal in seals.values() {
        for digest in &seal.delta {
            let event = state
                .projections()
                .control_event_by_digest(digest)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "requested target checkpoint has a missing Control Event",
                    )
                })?;
            if let Some(previous) = events.insert(digest.clone(), event.clone())
                && previous != event
            {
                return Err(proof_state_error(
                    "one Control Event digest resolves to different accepted bytes",
                ));
            }
        }
    }
    let dependencies = load_checkpoint_dependencies(state, realm_id, &seals, &events).await?;
    arkret::verify_mls_governance_closure(
        realm_id,
        &request.proof_target_basis,
        &seals.into_values().collect::<Vec<_>>(),
        &events.into_values().collect::<Vec<_>>(),
        &dependencies,
        crate::routing::governance_history::historical_governance_key_verifier(state.clone()),
    )
    .await
    .map(|verified| verified.checkpoint)
    .map_err(map_governance_frontier_error)
}

pub(crate) async fn load_verified_governance_checkpoint(
    state: &AppState,
    realm_id: &RealmId,
    basis: &arkret_wire::SealBasis,
) -> Result<MlsGovernanceVerificationCheckpoint, AppError> {
    basis
        .validate_protocol_bounds()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let mut seals = BTreeMap::new();
    let mut pending = basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if seals.contains_key(&seal_id) {
            continue;
        }
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "trusted RHRK base Seal closure is unavailable locally",
                )
            })?;
        if seal.realm_id != *realm_id {
            return Err(crate::app_error!(
                MlsGovernanceAnchorUnreachable,
                "trusted RHRK base Seal closure crosses the Realm boundary",
            ));
        }
        pending.extend(seal.predecessor_ref.iter().cloned());
        seals.insert(seal_id, seal);
    }
    let mut events = BTreeMap::new();
    for seal in seals.values() {
        for digest in &seal.delta {
            let event = state
                .projections()
                .control_event_by_digest(digest)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "trusted RHRK base checkpoint has a missing local Control Event",
                    )
                })?;
            if let Some(previous) = events.insert(digest.clone(), event.clone())
                && previous != event
            {
                return Err(proof_state_error(
                    "one trusted RHRK base Event digest resolves to different local bytes",
                ));
            }
        }
    }
    let dependencies = load_checkpoint_dependencies(state, realm_id, &seals, &events).await?;
    arkret::verify_mls_governance_closure(
        realm_id,
        basis,
        &seals.into_values().collect::<Vec<_>>(),
        &events.into_values().collect::<Vec<_>>(),
        &dependencies,
        crate::routing::governance_history::historical_governance_key_verifier(state.clone()),
    )
    .await
    .map(|verified| verified.checkpoint)
    .map_err(map_governance_frontier_error)
}

fn ensure_target_dominates_base(
    request: &MlsGovernanceProofRequestBody,
    seals: &BTreeMap<SealId, arkret_wire::Seal>,
) -> Result<(), AppError> {
    let base = request
        .proof_base_basis
        .leaves
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut reached = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = request.proof_target_basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        if base.contains(&seal_id) {
            reached.insert(seal_id);
            continue;
        }
        let seal = seals.get(&seal_id).ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "requested target Seal closure is incomplete",
            )
        })?;
        if seal.predecessor_ref.is_none() {
            return Err(crate::app_error!(
                MlsGovernanceAnchorUnreachable,
                "proof target basis does not dominate proof base basis",
            ));
        }
        pending.extend(seal.predecessor_ref.iter().cloned());
    }
    if reached != base {
        return Err(crate::app_error!(
            MlsGovernanceAnchorUnreachable,
            "proof target basis does not reach every proof base leaf",
        ));
    }
    Ok(())
}

async fn load_checkpoint_dependencies(
    state: &AppState,
    realm_id: &RealmId,
    seals: &BTreeMap<SealId, arkret_wire::Seal>,
    events: &BTreeMap<Hash, Event>,
) -> Result<Vec<GovernanceDependency>, AppError> {
    let mut dependencies = BTreeMap::new();
    let mut queue = Vec::new();
    for seal in seals.values() {
        load_source_dependencies(
            state,
            realm_id,
            soland_storage::GovernanceDependencySource::Seal(seal.id.clone()),
            &mut dependencies,
            &mut queue,
        )
        .await?;
    }
    for digest in events.keys() {
        load_source_dependencies(
            state,
            realm_id,
            soland_storage::GovernanceDependencySource::Event(digest.clone()),
            &mut dependencies,
            &mut queue,
        )
        .await?;
    }
    let mut cursor = 0;
    while cursor < queue.len() {
        let selectors = queue[cursor].dependency_selectors().map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("governance dependency closure is invalid: {error}")
            )
        })?;
        cursor += 1;
        for selector in selectors {
            let item = state
                .persistence()
                .governance_dependency_store()
                .get(realm_id, &selector)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "transitive governance replay dependency is unavailable",
                    )
                })?;
            insert_checkpoint_dependency(&mut dependencies, &mut queue, item)?;
        }
    }
    Ok(dependencies.into_values().collect())
}

fn references_retained_account_device_control(
    evidence_ref: Option<&arkret_wire::SignerEvidenceRef>,
    dependencies: &[GovernanceDependency],
) -> bool {
    evidence_ref.is_some_and(|evidence_ref| {
        dependencies.iter().any(|dependency| {
            let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence: evidence,
                ..
            } = dependency
            else {
                return false;
            };
            matches!(
                evidence.as_ref(),
                arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. }
            ) && evidence
                .evidence_ref()
                .is_ok_and(|retained_ref| &retained_ref == evidence_ref)
        })
    })
}

pub(crate) async fn verify_retained_control_event_proofs(
    state: &AppState,
    event: &Event,
    digest: &Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), String> {
    let dependencies = load_checkpoint_dependencies(
        state,
        &event.realm_id,
        &BTreeMap::new(),
        &BTreeMap::from([(digest.clone(), event.clone())]),
    )
    .await
    .map_err(|error| error.to_string())?;
    let uses_account_device_control = references_retained_account_device_control(
        event
            .producer_proof
            .as_ref()
            .and_then(|proof| proof.signer_resolution_evidence_ref.as_ref()),
        &dependencies,
    );
    if uses_account_device_control {
        let producer = crate::routing::events::event_log::submit::verify_historical_producer(
            state,
            event,
            digest_suite,
        )
        .await?;
        let authorization = producer
            .account_device_control_authorization()
            .ok_or_else(|| {
                "historical Control producer did not retain its verified device authorization"
                    .to_owned()
            })?;
        arkret::verify_retained_governance_event_auxiliary_proofs(
            event,
            digest_suite,
            &dependencies,
            producer.signer().signing_principal_id(),
            producer.verification_method(),
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: producer.key().to_vec(),
            },
            |method, at| {
                if method != producer.verification_method()
                    || !authorization.authorization_contains(at)
                {
                    return Err(arkret_wire::WireError::Protocol(
                        "Control auxiliary proof is outside the verified device authority"
                            .to_owned(),
                    ));
                }
                Ok(arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: producer.key().to_vec(),
                })
            },
        )
        .map_err(|error| error.to_string())?;
        return Ok(());
    }
    arkret::verify_retained_governance_event_proofs(
        event,
        digest_suite,
        &dependencies,
        crate::routing::governance_history::historical_governance_key_verifier(state.clone()),
    )
    .await
    .map_err(|error| error.to_string())
}

async fn load_source_dependencies(
    state: &AppState,
    realm_id: &RealmId,
    source: soland_storage::GovernanceDependencySource,
    dependencies: &mut BTreeMap<(String, Vec<u8>), GovernanceDependency>,
    queue: &mut Vec<GovernanceDependency>,
) -> Result<(), AppError> {
    let rows = state
        .persistence()
        .governance_dependency_store()
        .list_for_source(realm_id, &source)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    for row in rows {
        insert_checkpoint_dependency(dependencies, queue, row.item)?;
    }
    Ok(())
}

fn insert_checkpoint_dependency(
    dependencies: &mut BTreeMap<(String, Vec<u8>), GovernanceDependency>,
    queue: &mut Vec<GovernanceDependency>,
    item: GovernanceDependency,
) -> Result<(), AppError> {
    let key = item
        .selector()
        .canonical_sort_key()
        .map(|(kind, bytes)| (kind.to_owned(), bytes))
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(previous) = dependencies.get(&key) {
        if canonical::canonical_json_bytes(previous)
            .map_err(|error| AppError::internal(error.to_string()))?
            != canonical::canonical_json_bytes(&item)
                .map_err(|error| AppError::internal(error.to_string()))?
        {
            return Err(proof_state_error(
                "one governance dependency selector resolves to different bytes",
            ));
        }
        return Ok(());
    }
    if dependencies.len() >= MAX_GOVERNANCE_DEPENDENCY_SELECTORS {
        return Err(crate::app_error!(
            MlsGovernanceProofBoundsExceeded,
            "governance dependency closure exceeds the protocol object limit",
        ));
    }
    dependencies.insert(key, item.clone());
    queue.push(item);
    Ok(())
}

fn group_genesis_binding(
    accepted: &BTreeMap<CellRef, ResolvedCellState>,
    effective_scope: &GovernanceScope,
    mls_group_id: &arkret_wire::Base64UrlString,
    proposal: Option<&ProposedMlsGroupGenesisBinding>,
    previous_epoch: u64,
    next_epoch: u64,
) -> Result<MlsGroupGenesisBinding, AppError> {
    let key_schedule_cell =
        arkret_state::mls_cells::key_schedule_cell_id(effective_scope, mls_group_id.as_str())
            .map_err(map_governance_frontier_error)?;
    match accepted.get(&key_schedule_cell) {
        Some(ResolvedCellState::Sequenced(state)) => {
            if proposal.is_some() {
                return Err(crate::app_error!(
                    MlsGenesisBindingProposalMismatch,
                    "accepted MLS Genesis exists at the requested basis; omit the proposal"
                ));
            }
            let binding: MlsGovernanceBindingPayload = serde_json::from_value(state.value.clone())
                .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
            if binding.effective_scope() != effective_scope
                || binding.mls_group_id() != mls_group_id.as_str()
            {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "accepted MLS key schedule scope mismatch"
                ));
            }
            let genesis = MlsGroupGenesisBinding {
                content_scheme: binding.content_scheme(),
                durability_policy: binding.durability_policy(),
            };
            genesis.validate().map_err(map_governance_frontier_error)?;
            Ok(genesis)
        }
        Some(_) => Err(crate::app_error!(
            FrontierUnavailable,
            "MLS key schedule has no accepted winner"
        )),
        None if previous_epoch == 0 && next_epoch == 0 => {
            let proposal = proposal.ok_or_else(|| {
                crate::app_error!(
                    MlsGenesisBindingProposalRequired,
                    "pre-Genesis query requires proposed_group_genesis_binding"
                )
            })?;
            MlsGroupGenesisBinding::from_proposal(proposal).map_err(|error| {
                crate::app_error!(MlsGenesisBindingProposalMismatch, error.to_string())
            })
        }
        None => Err(crate::app_error!(
            FrontierUnavailable,
            "MLS successor has no accepted Genesis"
        )),
    }
}

fn map_governance_frontier_error(error: arkret_wire::WireError) -> AppError {
    let code = match error.error_code() {
        Some(ErrorCode::LimitExceeded) => ErrorCode::LimitExceeded,
        Some(ErrorCode::MlsGovernanceProofBoundsExceeded) => {
            ErrorCode::MlsGovernanceProofBoundsExceeded
        }
        Some(ErrorCode::MlsGovernanceAnchorUnreachable) => {
            ErrorCode::MlsGovernanceAnchorUnreachable
        }
        Some(ErrorCode::FrontierUnavailable | ErrorCode::DependencyMissing) => {
            ErrorCode::FrontierUnavailable
        }
        _ => ErrorCode::StateMismatch,
    };
    AppError::from_rejection(code, error.to_string())
}

fn canonical_actor(value: &str) -> Result<arkret_wire::ActorId, AppError> {
    serde_json::from_str(value).map_err(|error| {
        crate::app_error!(StateMismatch, format!("stored ActorId is invalid: {error}"),)
    })
}

fn event_signer_device_id(record: &AcceptedEvent) -> Option<String> {
    let verification_method = record
        .envelope
        .get("producer_proof")
        .and_then(serde_json::Value::as_object)
        .and_then(|proof| proof.get("verification_method"))
        .and_then(serde_json::Value::as_str)?;
    let actor = canonical_actor(&record.actor_id).ok()?;
    verification_method_device_id(actor.signing_principal_id().as_str(), verification_method)
}

fn verification_method_device_id(actor_id: &str, verification_method: &str) -> Option<String> {
    let (controller, fragment) = verification_method.rsplit_once('#')?;
    let controller = arkret_wire::Did::new(controller.to_owned()).ok()?;
    if arkret_wire::project_did_to_core_id(&controller)
        .ok()?
        .as_str()
        != actor_id
    {
        return None;
    }
    let fragment = fragment.trim();
    if fragment.is_empty() {
        return None;
    }
    Some(if fragment.starts_with("ak:device:") {
        fragment.to_owned()
    } else {
        format!("ak:device:{fragment}")
    })
}

pub(crate) async fn first_generation_event_seal_requirement(
    state: &AppState,
    records: &[AcceptedEvent],
) -> Result<Option<crate::notary::FirstGenerationEventSealRequirement>, AppError> {
    let actors = records
        .iter()
        .filter(|record| record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR)
        .map(|record| record.actor_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut requirement = None;
    for actor in actors {
        let actor_id = canonical_actor(actor)?;
        let principal_id = actor_id.signing_principal_id();
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
        })?
        .ok_or_else(|| {
            crate::app_error!(
                StateMismatch,
                "device re-anchor history has no B-model generation state",
            )
        })?;
        if generation.status
            == crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted
        {
            return Err(crate::app_error!(
                StateMismatch,
                "device_reanchor_conflict: generation Seal materialization is quarantined",
            ));
        }
        // The fence exists for exactly the window in which the successor
        // generation is accepted but not yet sealed. `current_device_generation`
        // reports the Seal-confirmed generation, and a re-anchor always declares
        // `previous + 1`, so the active fence is the re-anchor that establishes
        // `current_ref + 1`. Once its first-generation Seal commits, the
        // confirmed generation becomes that number and the fence releases on its
        // own. Matching `current_ref` instead would only ever select a re-anchor
        // whose Seal is already accepted, which is the same as no fence at all.
        let fenced_generation = generation.current_ref.checked_add(1).ok_or_else(|| {
            crate::app_error!(StateMismatch, "device generation counter overflow")
        })?;
        let candidates = records
            .iter()
            .filter(|record| {
                record.actor_id == actor
                    && record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR
                    && record
                        .envelope
                        .pointer("/payload/new_device_generation")
                        .and_then(serde_json::Value::as_u64)
                        == Some(fenced_generation)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        if candidates.len() != 1 || requirement.is_some() {
            return Err(crate::app_error!(
                StateMismatch,
                "canonical Realm history has ambiguous active device re-anchor units",
            ));
        }
        let reanchor = candidates[0];
        let payload = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload,
        >(
            reanchor
                .envelope
                .get("payload")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!("stored device re-anchor payload is invalid: {error}"),
            )
        })?;
        let authorize = soland_services::events::paired_replacement_authorize(reanchor, records)
            .ok_or_else(|| {
                crate::app_error!(
                    StateMismatch,
                    "active device re-anchor replacement authorization is missing",
                )
            })?;
        let authorize_payload = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
        >(
            authorize
                .envelope
                .get("payload")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!("stored replacement device authorization payload is invalid: {error}"),
            )
        })?;
        let replacement_payload_digest =
            soland_services::events::replacement_authorize_payload_digest(
                &authorize.envelope,
                &authorize.canonical_digest,
            )
            .map_err(|message| crate::app_error!(StateMismatch, message))?;
        if replacement_payload_digest != payload.replacement_authorize_payload_digest {
            return Err(crate::app_error!(
                StateMismatch,
                "stored replacement device authorization does not match the re-anchor payload digest",
            ));
        }
        if authorize.actor_id != actor {
            return Err(crate::app_error!(
                StateMismatch,
                "replacement device authorization principal differs from the re-anchor actor",
            ));
        }
        let predecessor_heads = payload
            .pre_fence_seal_frontier
            .clone()
            .map(|basis| basis.leaves)
            .unwrap_or_default()
            .into_iter()
            .map(|leaf| SealId::new(leaf.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!("stored pre-fence Seal leaf is invalid: {error}"),
                )
            })?;
        let realm_id = RealmId::new(reanchor.realm_id.clone().ok_or_else(|| {
            crate::app_error!(
                StateMismatch,
                "stored re-anchor is missing its principal-control Realm",
            )
        })?)
        .map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!("stored re-anchor Realm id is invalid: {error}"),
            )
        })?;
        let predecessor_ref = match predecessor_heads.as_slice() {
            [] => None,
            [head] => Some(head.clone()),
            _ => {
                return Err(crate::app_error!(
                    StateMismatch,
                    "stored pre-fence Seal basis has multiple heads for one Realm",
                ));
            }
        };
        let accepted_head_ref =
            crate::routing::identity::device_generation::accepted_device_generation_seal_head(
                state,
                principal_id.as_str(),
                &realm_id,
            )
            .await
            .map_err(|error| {
                crate::app_error!(
                    FrontierUnavailable,
                    format!("accepted generation Seal frontier unavailable: {error}"),
                )
            })?;
        let reanchor_digest = Hash::new(reanchor.canonical_digest.clone()).map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!("stored re-anchor digest is invalid: {error}"),
            )
        })?;
        let replacement_authorize_digest =
            Hash::new(authorize.canonical_digest.clone()).map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!("stored re-anchor unit digest is invalid: {error}"),
                )
            })?;
        let required_delta = vec![
            reanchor_digest.clone(),
            replacement_authorize_digest.clone(),
        ];
        requirement = Some(crate::notary::FirstGenerationEventSealRequirement {
            payload,
            reanchor_digest,
            replacement_authorize_digest,
            predecessor_ref,
            accepted_head_ref,
            required_delta,
            principal_id: principal_id.clone(),
            replacement_device_id: authorize_payload.device_id.as_str().to_owned(),
            replacement_device_public_key: authorize_payload.device_public_key_did.to_string(),
        });
    }
    Ok(requirement)
}

async fn join_control_state_batches(
    state: &AppState,
    realm_id: &RealmId,
    ops_by_cell: &BTreeMap<CellRef, Vec<IssuedOp>>,
    covered: &BTreeSet<Hash>,
) -> Result<arkret_state::JoinedView, AppError> {
    let mut joined = arkret_state::JoinedView::default();
    for (cell, projected_ops) in ops_by_cell {
        let persisted = state
            .projections()
            .confirmed_write_batches_for_cell(realm_id, cell)
            .await
            .map_err(|error| {
                crate::app_error!(
                    FrontierUnavailable,
                    format!("read governance cell {cell} Seal batches: {error}"),
                )
            })?;
        let mut persisted_digests = BTreeSet::new();
        let mut batches = persisted
            .into_iter()
            .filter_map(|(_, ops)| {
                let ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.event_id.event_digest()))
                    .inspect(|issued| {
                        persisted_digests.insert(issued.op.event_id.clone());
                    })
                    .collect::<Vec<_>>();
                (!ops.is_empty()).then_some(ops)
            })
            .collect::<Vec<_>>();
        let candidate_batch = projected_ops
            .iter()
            .filter(|issued| {
                covered.contains(&issued.op.event_id.event_digest())
                    && !persisted_digests.contains(&issued.op.event_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !candidate_batch.is_empty() {
            batches.push(candidate_batch);
        }
        if batches.is_empty() {
            continue;
        }
        let binding = state
            .projections()
            .resolve_cell(realm_id, cell)
            .map_err(|error| {
                crate::app_error!(
                    UnsupportedProfile,
                    format!("no state model registered for governance cell {cell}: {error}"),
                )
            })?;
        if binding.execution != arkret_wire::EventCellExecution::Security
            || binding.state_model != arkret_state::state_model::StateModelKind::SequencedState
        {
            return Err(crate::app_error!(
                UnsupportedProfile,
                format!("governance cell {cell} is not sequenced security state"),
            ));
        }
        let resolved = arkret_state::join_cell_seal_batches(binding.model.as_ref(), cell, &batches)
            .map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!("governance cell {cell} state resolution failed: {error}"),
                )
            })?;
        if !matches!(resolved, ResolvedCellState::Sequenced(_)) {
            return Err(crate::app_error!(
                StateMismatch,
                format!("governance cell {cell} did not resolve to sequenced state"),
            ));
        }
        joined.cells.insert(cell.clone(), resolved);
    }
    Ok(joined)
}

fn issued_security_write(event: &Event, cell: CellRef, op: StateWrite) -> (CellRef, IssuedOp) {
    (
        cell,
        IssuedOp {
            issuer_id: event.actor_id.clone(),
            op,
        },
    )
}

/// Canonical sealed effects for one Event, each tagged with the Event's actor.
///
/// The issuer must travel with the op: `ordered_log` keys its slots by
/// `(cell, actor_id, issuer_seq)`, so a store that received issuer-less ops
/// would have to invent one.
pub(crate) fn canonical_event_ops(
    state: &AppState,
    realm_id: &RealmId,
    event: &Event,
    move_id: &Hash,
    accumulated: &BTreeMap<CellRef, Vec<IssuedOp>>,
    invite_accept_from: Option<&str>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<(CellRef, IssuedOp)>, AppError> {
    Ok(canonical_event_sealed_ops(
        state,
        realm_id,
        event,
        move_id,
        accumulated,
        None,
        invite_accept_from,
        digest_suite,
    )?
    .into_iter()
    .map(|(cell, op)| issued_security_write(event, cell, op))
    .collect())
}

/// Canonical sealed effects for a verifier that already resolved the exact
/// predecessor Seal frontier. This keeps B-model Seal admission on the same
/// projection implementation without flattening predecessor Seal batches back
/// into an `causal_register` history.
pub(crate) fn canonical_event_ops_with_frozen_pre_state(
    state: &AppState,
    realm_id: &RealmId,
    event: &Event,
    move_id: &Hash,
    frozen_pre_state: &BTreeMap<CellRef, ResolvedCellState>,
    invite_accept_from: Option<&str>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<(CellRef, IssuedOp)>, AppError> {
    Ok(canonical_event_sealed_ops(
        state,
        realm_id,
        event,
        move_id,
        &BTreeMap::new(),
        Some(frozen_pre_state),
        invite_accept_from,
        digest_suite,
    )?
    .into_iter()
    .map(|(cell, op)| issued_security_write(event, cell, op))
    .collect())
}

/// Join the ops accumulated so far into the frozen pre-state the registered
/// projections read.
///
/// `event-and-patch.md` §2.4.2 keeps `transition_to`, `apply_patch`,
/// `remove_observed` and `reset` unresolved until a receiver supplies the
/// pre-state, precisely so a producer cannot assert a prior state it never
/// observed. Replaying the Realm's accepted control history in order is what
/// makes this the same value every receiver computes. A cell with no
/// accumulated op is simply absent: the resolver reads an absent cell as the
/// null pre-state. Ordinary causal-register concurrency always has one winner;
/// Bottom is reserved for explicitly registered cross-Cell domain invariants.
fn frozen_governance_pre_state(
    state: &AppState,
    realm_id: &RealmId,
    accumulated: &BTreeMap<CellRef, Vec<IssuedOp>>,
) -> Result<BTreeMap<CellRef, ResolvedCellState>, AppError> {
    let mut pre_state = BTreeMap::new();
    for (cell, ops) in accumulated {
        let binding = state
            .projections()
            .resolve_cell(realm_id, cell)
            .map_err(|error| {
                crate::app_error!(
                    UnsupportedProfile,
                    format!("no state model registered for governance cell {cell}: {error}"),
                )
            })?;
        let resolved =
            arkret_state::join_cell(binding.model.as_ref(), cell, ops).map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!("governance cell {cell} state resolution failed: {error}"),
                )
            })?;
        pre_state.insert(cell.clone(), resolved);
    }
    Ok(pre_state)
}

fn canonical_event_sealed_ops(
    state: &AppState,
    realm_id: &RealmId,
    event: &Event,
    move_id: &Hash,
    accumulated: &BTreeMap<CellRef, Vec<IssuedOp>>,
    supplied_pre_state: Option<&BTreeMap<CellRef, ResolvedCellState>>,
    invite_accept_from: Option<&str>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<(CellRef, StateWrite)>, AppError> {
    // v1 carries no producer `effects[]`: every write is derived from
    // `kind + payload` by the registered contract.
    let projected = state
        .projections()
        .project_accepted_cell_writes_with_digest_suite(event, digest_suite)
        .map_err(|error| {
            crate::app_error!(
                StateMismatch,
                format!(
                    "stored Event {} does not project its registered cell writes: {error}",
                    event.event_id
                ),
            )
        })?;

    let computed_pre_state;
    let pre_state = if let Some(pre_state) = supplied_pre_state {
        pre_state
    } else {
        computed_pre_state = frozen_governance_pre_state(state, realm_id, accumulated)?;
        &computed_pre_state
    };
    let mut resolved: Vec<(CellRef, StateWrite)> = Vec::with_capacity(projected.len());
    for write in &projected {
        // The pre-state-dependent grammars are resolved by the one shared
        // implementation; a second copy here would be a second answer to a
        // rule that has to agree byte-for-byte with `verify_control_move`.
        let effects = state
            .projections()
            .resolve_projected_write(write, realm_id, pre_state)
            .map_err(|error| {
                crate::app_error!(
                    StateMismatch,
                    format!(
                        "stored Event {} cannot resolve its registered write on {}: {error:?}",
                        event.event_id, write.cell_id
                    ),
                )
            })?;
        for effect in effects {
            resolved.push((
                effect.cell_id.clone(),
                StateWrite::from_projection(move_id.clone(), &effect),
            ));
        }
    }

    if event.kind == arkret_wire::EventKind::InviteAccept {
        let from = invite_accept_from.ok_or_else(|| {
            crate::app_error!(
                StateMismatch,
                "invite acceptance proof material is missing prior membership state",
            )
        })?;
        let member_cell = CellRef::new(format!(
            "ak:cell:ak.component.member.state.v1:{}",
            arkret_wire::composite_subject(&[event
                .actor_id
                .canonical_key()
                .map_err(proof_state_error)?])
            .map_err(proof_state_error)?
        ))
        .map_err(proof_state_error)?;
        let member_ops = resolved
            .iter()
            .filter(|(cell, _)| cell == &member_cell)
            .collect::<Vec<_>>();
        let expected_from = serde_json::json!(from);
        let expected_to = serde_json::json!("join");
        if member_ops.len() != 1
            || member_ops[0].1.op.op_type != LatticeOpType::Transition
            || member_ops[0].1.op.from.as_ref() != Some(&expected_from)
            || member_ops[0].1.op.to.as_ref() != Some(&expected_to)
        {
            return Err(crate::app_error!(
                StateMismatch,
                "invite acceptance member transition does not match prior membership state",
            ));
        }
    } else if event.kind == arkret_wire::EventKind::RealmCreate {
        // Only the genesis targets are asserted; the state model ops come from the
        // registered `effect_projection`.
        let expected = arkret_bootstrap::expected_realm_create_cells(event);
        let actual: std::collections::BTreeSet<String> = resolved
            .iter()
            .map(|(cell, _)| cell.as_str().to_owned())
            .collect();
        if resolved.len() != expected.len() || actual != expected {
            return Err(crate::app_error!(
                StateMismatch,
                "Realm create proof material does not derive the canonical registered genesis cells",
            ));
        }
    }

    Ok(resolved)
}

fn proof_state_error(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        StateMismatch,
        format!("MLS governance proof state mismatch: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_device_control_dependency() -> (arkret_wire::SignerEvidenceRef, GovernanceDependency)
    {
        let evidence: arkret_models_identity::AuthenticatedSignerResolutionEvidence =
            serde_json::from_value(serde_json::json!({
                "kind": "account_device_control",
                "signer_id": "ak:did_core:webvh:z6mkfixture-control.example",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture-control.example",
                    "station_id": "ak:did_core:web:station.example"
                },
                "device_id": "ak:device:019b0000-0000-7000-8000-000000000001",
                "verification_method": "did:webvh:z6mkfixture-control.example#ak:device:019b0000-0000-7000-8000-000000000001",
                "authorization_event_ref": "ak:event:AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
                "authorized_generation_ref": 1,
                "generation_event_ref": "ak:event:AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
                "confirmation_seal_ref": "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pcr_genesis_event_ref": "ak:event:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
                "principal_inception": {
                    "did": "did:webvh:z6mkfixture-control.example",
                    "did_method": "webvh",
                    "seq": 0,
                    "operation": {
                        "type": "create",
                        "root_verification_method": "did:webvh:z6mkfixture-control.example#root-1"
                    }
                },
                "history_event_refs": [
                    "ak:event:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
                    "ak:event:AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"
                ],
                "history_seal_refs": [
                    "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ]
            }))
            .unwrap();
        let reference = evidence.evidence_ref().unwrap();
        let selector = arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: reference.content_digest().unwrap(),
        };
        (
            reference,
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector,
                authenticated_signer_resolution_evidence: Box::new(evidence),
            },
        )
    }

    #[test]
    fn retained_account_device_control_dispatch_requires_exact_root_reference() {
        let (reference, dependency) = account_device_control_dependency();
        assert!(references_retained_account_device_control(
            Some(&reference),
            std::slice::from_ref(&dependency),
        ));
        assert!(!references_retained_account_device_control(
            None,
            std::slice::from_ref(&dependency),
        ));
        let other = arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:sha256:{}",
            "0".repeat(64)
        ))
        .unwrap();
        assert!(!references_retained_account_device_control(
            Some(&other),
            std::slice::from_ref(&dependency),
        ));

        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector,
            authenticated_signer_resolution_evidence,
        } = dependency
        else {
            unreachable!();
        };
        let mut altered = serde_json::to_value(authenticated_signer_resolution_evidence).unwrap();
        altered["authorized_generation_ref"] = serde_json::json!(2);
        let altered = serde_json::from_value(altered).unwrap();
        let altered_dependency = GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector,
            authenticated_signer_resolution_evidence: Box::new(altered),
        };
        assert!(!references_retained_account_device_control(
            Some(&reference),
            &[altered_dependency],
        ));
    }

    #[test]
    fn genesis_binding_uses_exact_accepted_key_schedule() {
        let realm_id =
            RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        let scope = GovernanceScope::Realm {
            realm_id: realm_id.clone(),
        };
        let group =
            arkret_wire::Base64UrlString::new(scope.canonical_mls_group_id().unwrap()).unwrap();
        let proposal = ProposedMlsGroupGenesisBinding {
            content_scheme: arkret_wire::ContentScheme::MlsRfc9420,
            durability_policy: None,
        };
        let mut accepted = BTreeMap::new();
        assert!(group_genesis_binding(&accepted, &scope, &group, None, 0, 0).is_err());
        assert!(group_genesis_binding(&accepted, &scope, &group, Some(&proposal), 0, 0).is_ok());
        assert!(group_genesis_binding(&accepted, &scope, &group, None, 1, 2).is_err());
        let binding = MlsGovernanceBindingPayload::realm(
            realm_id,
            0,
            0,
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
            arkret_wire::ContentScheme::MlsExporterAeadV1,
            Some(arkret_wire::DurabilityPolicy::None),
            arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_wire::CORE_REDUCER_PROFILE,
        )
        .unwrap();
        accepted.insert(
            arkret_state::mls_cells::key_schedule_cell_id(&scope, group.as_str()).unwrap(),
            ResolvedCellState::Sequenced(arkret_state::state_model::SequencedStateValue {
                revision_event_id: EventId::new(
                    "ak:event:AUNpwW417vtZcK0hWrtv9UDvU8aC0UKocKAIMZ8xszoU",
                )
                .unwrap(),
                value: serde_json::to_value(binding).unwrap(),
            }),
        );
        let current = group_genesis_binding(&accepted, &scope, &group, None, 1, 2).unwrap();
        assert_eq!(
            current.content_scheme,
            arkret_wire::ContentScheme::MlsExporterAeadV1
        );
        assert_eq!(
            current.durability_policy,
            Some(arkret_wire::DurabilityPolicy::None)
        );
        assert!(group_genesis_binding(&accepted, &scope, &group, Some(&proposal), 0, 0).is_err());
    }

    #[test]
    fn event_signer_device_projects_did_method_controller_to_actor_core() {
        let did = arkret_wire::Did::new("did:webvh:z6Mkfull:alice.example".to_owned()).unwrap();
        let core_id = arkret_wire::project_did_to_core_id(&did).unwrap();

        assert_eq!(
            verification_method_device_id(
                core_id.as_str(),
                "did:webvh:z6Mkfull:alice.example#ak:device:primary",
            )
            .as_deref(),
            Some("ak:device:primary"),
        );
        assert!(
            verification_method_device_id(
                core_id.as_str(),
                "did:webvh:z6Mkother:bob.example#ak:device:primary",
            )
            .is_none()
        );
    }

    fn issued_set(move_byte: u8, value: serde_json::Value) -> IssuedOp {
        IssuedOp {
            issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
                "did:web:alice.example",
            )),
            op: StateWrite::new(
                Hash::new(format!("sha256:{}", format!("{move_byte:02x}").repeat(32))).unwrap(),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(value),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
        }
    }

    #[test]
    fn authoritative_notary_lookup_uses_canonical_wire_singleton_cell() {
        let notary = crate::test_notary("did:web:notary.example", 41);
        let mut joined = BTreeMap::new();
        joined.insert(
            CellRef::new("ak:cell:ak.component.notary.v1:null".to_owned()).unwrap(),
            ResolvedCellState::Sequenced(arkret_state::state_model::SequencedStateValue {
                revision_event_id: EventId::new(
                    "ak:event:AUNpwW417vtZcK0hWrtv9UDvU8aC0UKocKAIMZ8xszoU",
                )
                .unwrap(),
                value: serde_json::to_value(&notary).unwrap(),
            }),
        );

        assert_eq!(authoritative_notary(&joined).unwrap(), Some(notary));
    }

    #[tokio::test]
    async fn governance_join_resolves_sequenced_selector_without_bottom() {
        let state = test_state();
        let realm_id =
            RealmId::new("ak:realm:AdTN7L96rpQaXNqcIhMcXo5a1ucoPGnWeIyG7qhFPYFy").unwrap();
        let selector_cell = CellRef::new(
            "ak:cell:ak.component.agent.selector_claim.v1:conflicted-selector".to_owned(),
        )
        .unwrap();
        let selector_ops = vec![
            issued_set(1, serde_json::json!({"subject": "did:web:first.example"})),
            issued_set(2, serde_json::json!({"subject": "did:web:second.example"})),
        ];
        let covered = selector_ops
            .iter()
            .map(|issued| issued.op.event_id.event_digest())
            .collect::<BTreeSet<_>>();
        let ops_by_cell = BTreeMap::from([(selector_cell.clone(), selector_ops)]);

        let joined = join_control_state_batches(&state, &realm_id, &ops_by_cell, &covered)
            .await
            .expect("sequenced selector writes resolve in confirmed order");

        assert!(matches!(
            joined.cells.get(&selector_cell),
            Some(ResolvedCellState::Sequenced(_))
        ));
    }

    #[tokio::test]
    async fn governance_join_resolves_sequenced_accountability_without_bottom() {
        let state = test_state();
        let realm_id =
            RealmId::new("ak:realm:Abojx_8QbHf40nUbyT3-uQrA2pKjNAbzZskY4Nc35U8S").unwrap();
        let accountability_cell = CellRef::new(
            "ak:cell:ak.component.identity.accountability.v1:did:web:agent.example".to_owned(),
        )
        .unwrap();
        let accountability_ops = vec![
            issued_set(
                3,
                serde_json::json!({"controller": "did:web:first.example"}),
            ),
            issued_set(
                4,
                serde_json::json!({"controller": "did:web:second.example"}),
            ),
        ];
        let covered = accountability_ops
            .iter()
            .map(|issued| issued.op.event_id.event_digest())
            .collect::<BTreeSet<_>>();
        let ops_by_cell = BTreeMap::from([(accountability_cell.clone(), accountability_ops)]);

        let joined = join_control_state_batches(&state, &realm_id, &ops_by_cell, &covered)
            .await
            .expect("sequenced accountability writes resolve in confirmed order");

        assert!(matches!(
            joined.cells.get(&accountability_cell),
            Some(ResolvedCellState::Sequenced(_))
        ));
    }

    fn test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        )
    }

    fn agent_pcr_create() -> Event {
        let realm_id =
            RealmId::new("ak:realm:AZiVojGkhKKjoBSA6eV96sZAm4u3Ze_3uMmkr30F6ZQZ").unwrap();
        let actor_did = arkret_identifiers::Did::new("did:web:agent.example").unwrap();
        let genesis = arkret_models_collaboration::events_payloads::RealmGenesis::agent_control(
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap(),
            arkret_models_identity::ResolutionCommitment {
                did: actor_did.clone(),
                method_history_head: format!("sha256:{}", "8".repeat(64)),
                version_id: "1-Qmfixture".to_owned(),
            },
            arkret_identifiers::TrustDomainId::new("ak:trust_domain:agent-pcr".to_owned()).unwrap(),
            vec![arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned()],
            arkret_wire::CORE_REDUCER_PROFILE,
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::SecurityClass::HighAssurance,
            arkret_wire::EncryptionProfile::MlsRfc9420,
            crate::test_notary("did:web:agent.example", 42),
        )
        .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
                .to_value()
                .unwrap();
        crate::test_event::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id(&actor_did),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1").unwrap(),
            payload,
        )
        .unwrap()
    }

    /// The v1 wire carries no producer `effects[]`, so the canonical
    /// genesis cells of a Agent PCR create are whatever the registered
    /// contract derives — and the create-log target is the wire singleton
    /// (`realm-and-space.md` §2.8.3), never a per-Realm subject. A per-Realm
    /// variant would both fork the `state_root` leaf set and turn a per-Realm
    /// genesis singleton into a deployment-wide shared key.
    #[test]
    fn governance_materializer_derives_the_canonical_genesis_cells() {
        let state = test_state();
        let event = agent_pcr_create();
        let realm_id = event.realm_id.clone();
        let move_id = Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let ops = canonical_event_ops(
            &state,
            &realm_id,
            &event,
            &move_id,
            &BTreeMap::new(),
            None,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        let derived = ops
            .iter()
            .map(|(cell, _)| cell.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let expected = arkret_bootstrap::expected_realm_create_cells(&event);
        assert_eq!(ops.len(), expected.len());
        assert_eq!(derived, expected);
        assert!(!derived.contains(&format!(
            "ak:cell:ak.component.realm.create.v1:{}",
            event.realm_id
        )));
    }

    /// A producer cannot name a cell at all, so the only way the materializer
    /// can go wrong is by inventing writes for an Event whose registered
    /// contract will not evaluate. `event-and-patch.md` §2.4.2 makes that an
    /// outright rejection, not a partial op set.
    #[test]
    fn governance_materializer_rejects_a_realm_create_it_cannot_project() {
        let state = test_state();
        let mut event = agent_pcr_create();
        let realm_id = event.realm_id.clone();
        event.payload.remove("object");
        let move_id = Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap();
        assert!(
            canonical_event_ops(
                &state,
                &realm_id,
                &event,
                &move_id,
                &BTreeMap::new(),
                None,
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err()
        );
    }

    /// `invite_accept`'s membership transition reads its `from` off the frozen
    /// pre-state, never off the producer: the registered projection is a bare
    /// `transition_to` that carries no `from` at all
    /// (`event-and-patch.md` §2.4.2).
    #[test]
    fn governance_materializer_uses_the_frozen_invite_accept_membership() {
        let state = test_state();
        let realm_id =
            RealmId::new("ak:realm:AUNpwW417vtZcK0hWrtv9UDvU8aC0UKocKAIMZ8xszoU").unwrap();
        let actor_did = arkret_identifiers::Did::new("did:web:invitee_id.example").unwrap();
        let event = crate::test_event::raw_event(
            arkret_wire::EventKind::InviteAccept.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id(&actor_did),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce2").unwrap(),
            serde_json::json!({
                "invite_id": "ak:invite:AXqb6Ch5W-jqD8aHcLfUSGkwP47dnrsU4phA2YK03WoF"
            }),
        )
        .unwrap();
        let projected = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        // Two registered writes: the invite lifecycle transition (an explicit
        // pending -> accepted, resolvable without any pre-state) and the
        // membership transition, whose `from` is deliberately absent.
        assert_eq!(projected.len(), 2);
        let member_cell = projected
            .iter()
            .find(|write| {
                write
                    .cell_id
                    .as_str()
                    .starts_with("ak:cell:ak.component.member.state.v1:")
            })
            .expect("registered member cell")
            .cell_id
            .clone();
        let member_write = projected
            .iter()
            .find(|write| write.cell_id == member_cell)
            .expect("invite accept writes the member state cell");
        assert!(matches!(
            &member_write.op,
            arkret_wire::cbs::ProjectedOp::TransitionTo { to }
                if to == &serde_json::json!("join")
        ));

        let move_id = Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap();
        for prior_state in ["leave", "knock"] {
            // The member-state transition starts at its registered `initial_state`
            // (`leave`), so the frozen pre-state for that case is the cell with
            // no accumulated op at all; `knock` needs one accepted transition
            // into it first.
            let prior_ops = if prior_state == "leave" {
                Vec::new()
            } else {
                vec![IssuedOp {
                    issuer_id: arkret_wire::ActorId::service(crate::test_actor_id(&actor_did)),
                    op: StateWrite::new(
                        move_id.clone(),
                        LatticeOp {
                            op_type: LatticeOpType::Transition,
                            tag: None,
                            value: None,
                            from: Some(serde_json::json!("leave")),
                            to: Some(serde_json::json!(prior_state)),
                            reason: None,
                            issuer_seq: None,
                        },
                    ),
                }]
            };
            let mut accumulated = BTreeMap::new();
            accumulated.insert(member_cell.clone(), prior_ops);
            let ops = canonical_event_ops(
                &state,
                &realm_id,
                &event,
                &move_id,
                &accumulated,
                Some(prior_state),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();

            assert_eq!(ops.len(), 2);
            let (_, member_op) = ops
                .iter()
                .find(|(cell, _)| cell == &member_cell)
                .expect("invite accept seals the member state cell");
            assert_eq!(member_op.op.op.op_type, LatticeOpType::Transition);
            assert_eq!(member_op.op.op.from, Some(serde_json::json!(prior_state)));
            assert_eq!(member_op.op.op.to, Some(serde_json::json!("join")));
        }
    }
}
