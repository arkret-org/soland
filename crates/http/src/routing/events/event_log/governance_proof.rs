use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, Hash, MoveId, SealId};
use arkret_models_crypto::{
    MaterializedMlsGovernanceProofBundle, MlsGovernanceBindingPayload,
    MlsGovernanceControlStateLeaf, MlsGovernanceControlStateValue, MlsGovernanceProofBundle,
    MlsGovernanceProofRequestBodyBody, build_mls_governance_proof_chunks,
    derive_mls_discussion_metadata_digest, is_mls_membership_frontier_component,
};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::mls_governance_proof::{derive_mls_capability_root, derive_mls_policy_root};
use arkret_state::state::{compute_state_root, control_event_set_root};
#[cfg(test)]
use arkret_wire::move_event::LatticeOp;
use arkret_wire::move_event::LatticeOpType;
use arkret_wire::{CellId, EffectiveScope as GovernanceScope, Event, NotarySig};
use salvo::oapi::extract::JsonBody;

use super::*;

const SUPPORTED_REDUCER_PROFILE: &str = "ak.reducer.v1";

#[salvo::oapi::endpoint(
    operation_id = "ak.self.events.query.mls_governance_proof",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.query.mls_governance_proof"))]
pub(super) async fn mls_governance_proof(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MlsGovernanceProofRequestBodyBody>,
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
    let own_pcr = soland_services::identity::principal_control_realm_for_did(&session.actor);
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
            .projections()
            .snapshot()
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

async fn backfill_authoritative_event_seals(
    state: &AppState,
    realm_id: &RealmId,
    joined: &BTreeMap<CellRef, CellState>,
    event_ops: &[(CellRef, IssuedOp)],
) -> Result<bool, AppError> {
    if !state.config().development_mode {
        return Ok(false);
    }
    let authority_dids = authoritative_notary_dids(realm_id, joined)?;
    let Some(peer) = crate::routing::federation::federation::configured_peer_targets(state)
        .into_iter()
        .find(|peer| {
            peer.did != *state.service_id() && authority_dids.iter().any(|did| did == &peer.did)
        })
    else {
        return Ok(false);
    };
    let mut url = reqwest::Url::parse(&format!(
        "{}/_soland/peer/federation/seals",
        peer.url.trim_end_matches('/')
    ))
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("authoritative Seal backfill URL is invalid: {error}"),
        )
    })?;
    url.query_pairs_mut()
        .append_pair("realm_id", realm_id.as_str());
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url.as_str(),
        "authoritative Event Seal backfill",
        true,
        std::time::Duration::from_secs(30),
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("authoritative Seal backfill target is unavailable: {error}"),
        )
    })?;
    let response = client.get(url).send().await.map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("authoritative Seal backfill request failed: {error}"),
        )
    })?;
    if !response.status().is_success() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            format!(
                "authoritative Seal backfill returned HTTP {}",
                response.status()
            ),
        ));
    }
    let outcome = response
        .json::<crate::routing::federation::federation::FederationSealsOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("authoritative Seal backfill response is invalid: {error}"),
            )
        })?;
    if outcome.seals.is_empty() {
        return Ok(false);
    }
    apply_authoritative_event_seal_path(
        state,
        realm_id,
        &authority_dids,
        event_ops,
        &outcome.seals,
    )
    .await?;
    Ok(true)
}

fn authoritative_notary_dids(
    realm_id: &RealmId,
    joined: &BTreeMap<CellRef, CellState>,
) -> Result<Vec<String>, AppError> {
    let notary_cell = CellRef::new(format!(
        "ak:cell:ak.component.notary.v1:{}",
        realm_id.as_str()
    ))
    .map_err(proof_state_error)?;
    let Some(CellState::Value(value)) = joined.get(&notary_cell) else {
        return Ok(Vec::new());
    };
    let notary = serde_json::from_value::<arkret_wire::notary::NotaryValue>(value.clone())
        .map_err(|error| {
            proof_state_error(format!("invalid materialized Realm notary: {error}"))
        })?;
    let authority_dids = match notary {
        arkret_wire::notary::NotaryValue::SingleDid { did, .. } => vec![did.to_string()],
        arkret_wire::notary::NotaryValue::Threshold { members, .. }
        | arkret_wire::notary::NotaryValue::OpenSet { members } => {
            members.into_iter().map(|did| did.to_string()).collect()
        }
        arkret_wire::notary::NotaryValue::Mixed {
            did,
            recovery_members,
        } => std::iter::once(did.to_string())
            .chain(
                recovery_members
                    .into_iter()
                    .map(|member| member.to_string()),
            )
            .collect(),
    };
    Ok(authority_dids)
}

async fn apply_authoritative_event_seal_path(
    state: &AppState,
    realm_id: &RealmId,
    authority_dids: &[String],
    event_ops: &[(CellRef, IssuedOp)],
    seals: &[arkret_wire::Seal],
) -> Result<(), AppError> {
    for seal in seals {
        seal.validate_id().map_err(|error| {
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
        crate::jws_verify::verify_replay_window(
            &seal.hlc,
            state.config().jws_replay_window_seconds,
        )
        .map_err(|error| {
            proof_state_error(format!("authoritative Event Seal replay window: {error}"))
        })?;
        if let Some(existing) = state
            .projections()
            .seal_by_id(&seal.id)
            .map_err(|error| proof_state_error(format!("read Event Seal: {error}")))?
        {
            if existing != *seal {
                return Err(proof_state_error(
                    "authoritative Event Seal id already has different signature material",
                ));
            }
            continue;
        }

        let mut leaves = state
            .projections()
            .realm_seal_leaves(realm_id)
            .map_err(|error| proof_state_error(format!("read Event Seal frontier: {error}")))?;
        leaves.sort();
        if seal.predecessor_refs != leaves {
            return Err(proof_state_error(
                "authoritative Event Seal predecessors differ from the local frontier",
            ));
        }
        let current = if leaves.is_empty() {
            BTreeSet::new()
        } else {
            state
                .projections()
                .predecessor_covered_events(&leaves)
                .map_err(|error| {
                    proof_state_error(format!("read Event Seal predecessor coverage: {error}"))
                })?
        };
        if seal.delta.iter().any(|digest| current.contains(digest)) {
            return Err(proof_state_error(
                "authoritative Event Seal delta repeats predecessor coverage",
            ));
        }
        let mut target = current;
        target.extend(seal.delta.iter().cloned());
        let declared = seal
            .covered_event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if declared.len() != seal.covered_event_digests.len() || declared != target {
            return Err(proof_state_error(
                "authoritative Event Seal coverage differs from predecessor coverage plus delta",
            ));
        }
        let expected_control_root = control_event_set_root(&target).map_err(proof_state_error)?;
        if seal.control_event_set_root != expected_control_root
            || seal.completeness_root != expected_control_root
        {
            return Err(proof_state_error(
                "authoritative Event Seal control/completeness root mismatch",
            ));
        }

        let mut ops_by_cell: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
        for (cell, op) in event_ops
            .iter()
            .filter(|(_, issued)| target.contains(&issued.op.move_id))
        {
            ops_by_cell
                .entry(cell.clone())
                .or_default()
                .push(op.clone());
        }
        let mut target_state = BTreeMap::new();
        for (cell, ops) in ops_by_cell {
            let binding = state
                .projections()
                .resolve_cell(realm_id, &cell)
                .map_err(|error| {
                    proof_state_error(format!(
                        "resolve authoritative Event Seal cell {cell}: {error}"
                    ))
                })?;
            let resolved = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops);
            if matches!(resolved, CellState::Bottom(_)) {
                return Err(proof_state_error(format!(
                    "authoritative Event Seal cell {cell} resolves to Bottom"
                )));
            }
            target_state.insert(cell, resolved);
        }
        let expected_state_root = compute_state_root(&target_state).map_err(proof_state_error)?;
        if seal.state_root != expected_state_root {
            return Err(proof_state_error(format!(
                "authoritative Event Seal state_root mismatch: submitted {}, expected {}",
                seal.state_root, expected_state_root
            )));
        }
        let expected_notary_seq = leaves
            .iter()
            .map(|leaf| {
                state
                    .projections()
                    .seal_by_id(leaf)
                    .map_err(|error| proof_state_error(format!("read Seal predecessor: {error}")))?
                    .ok_or_else(|| proof_state_error("Event Seal predecessor is missing"))
                    .map(|predecessor| predecessor.notary_seq)
            })
            .collect::<Result<Vec<_>, _>>()?
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

        let canonical_bytes = seal.canonical_bytes_for_id().map_err(proof_state_error)?;
        let signatures = match &seal.notary_signature {
            NotarySig::Single(signature) => std::slice::from_ref(signature),
            NotarySig::Multi(multi) => multi.signatures.as_slice(),
            NotarySig::Threshold(_) => {
                return Err(AppError::new(
                    ErrorCode::ProfileUnsupported,
                    "threshold authoritative Event Seal backfill is unsupported",
                ));
            }
        };
        if signatures.is_empty() {
            return Err(proof_state_error(
                "authoritative Event Seal has no signatures",
            ));
        }
        for signature in signatures {
            let signer = arkret_identity::verification_method_did(&signature.verification_method)
                .map_err(proof_state_error)?;
            if !authority_dids.iter().any(|did| did == signer.as_str()) {
                return Err(proof_state_error(format!(
                    "Event Seal signer {signer} is not authorized by the Realm notary cell"
                )));
            }
            verify_authoritative_event_seal_signature(
                state,
                signature,
                signer.as_str(),
                &canonical_bytes,
            )
            .await?;
        }

        let delta = seal.delta.iter().cloned().collect::<BTreeSet<_>>();
        let new_ops = event_ops
            .iter()
            .filter(|(_, issued)| delta.contains(&issued.op.move_id))
            .cloned()
            .collect::<Vec<_>>();
        match state
            .projections()
            .commit_event_seal_if_frontier(seal, &leaves, &new_ops, &target)
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
    }
    Ok(())
}

async fn verify_authoritative_event_seal_signature(
    state: &AppState,
    signature: &arkret_wire::MoveSignature,
    signer: &str,
    canonical_bytes: &[u8],
) -> Result<(), AppError> {
    let expected_method = format!("{signer}#notary-key");
    if signature.alg != "EdDSA" || signature.verification_method != expected_method {
        return Err(proof_state_error(
            "authoritative Event Seal signature is not bound to the notary key",
        ));
    }
    let expected_digest =
        Hash::new(arkret_canonical::sha256_digest(canonical_bytes)).map_err(proof_state_error)?;
    if signature.payload_digest != expected_digest {
        return Err(proof_state_error(
            "authoritative Event Seal signature payload_digest mismatch",
        ));
    }

    let cached_key = state
        .federation_peer_verification_method_key(&expected_method)
        .or_else(|| state.federation_peer_verifying_key(signer));
    let result = if let Some(key) = cached_key {
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &signature.jws,
                canonical_bytes,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_bytes().to_vec(),
                },
            )
            .map_err(|error| error.to_string())
    } else {
        crate::jws_verify::verify_jws_ed25519_async(
            canonical_bytes,
            &signature.jws,
            &signature.verification_method,
            signer,
            state,
        )
        .await
    };
    result.map_err(|error| {
        proof_state_error(format!(
            "verify authoritative Event Seal signature: {error}"
        ))
    })
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
    let stats = state
        .event_queries()
        .realm_event_stats(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("canonical Event bounds preflight unavailable: {error}"),
            )
        })?;
    if stats.count
        > arkret_models_crypto::mls_governance_proof::MLS_GOVERNANCE_MAX_COVERED_EVENT_DIGESTS
            as u64
        || stats.canonical_bytes
            > arkret_models_crypto::mls_governance_proof::MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u64
    {
        return Err(AppError::new(
            ErrorCode::MlsGovernanceProofBoundsExceeded,
            "Realm Event history exceeds MLS governance proof materialization bounds",
        ));
    }
    let realm_records = state
        .event_queries()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("canonical Realm Event store unavailable: {error}"),
            )
        })?;
    if realm_records.iter().any(|record| {
        record.kind == arkret_wire::events::EventKind::REALM_CREATE
            && record
                .envelope
                .pointer("/payload/object/fields/purpose")
                .and_then(serde_json::Value::as_str)
                == Some("principal_control")
            && record
                .envelope
                .get("executed_by")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|executed_by| !executed_by.is_empty())
    }) {
        return materialize_managed_agent_realm_control(state, realm_id, &realm_records);
    }
    let generation_fence = first_generation_event_seal_requirement(state, &realm_records).await?;
    let principal_control_actor = realm_records
        .iter()
        .find(|record| {
            record.kind == arkret_wire::events::EventKind::REALM_CREATE
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
            .identities()
            .devices_for_actor(principal_id)
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
        state
            .projections()
            .seal_leaf_union_proof(&requirement.accepted_frontier_refs)
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
    let mut ops_by_cell: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
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
        record.kind == arkret_wire::events::EventKind::REALM_CREATE
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
                    record.kind == arkret_wire::events::EventKind::DEVICE_AUTHORIZE
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

    // The query is newest-first, while FSM transitions across distinct Seal
    // bases must be reduced in causal acceptance order. Move digests are
    // content hashes and therefore cannot be used as transition ordering.
    for record in realm_records.iter().rev() {
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
        let requires_invite_membership_validation =
            event.kind.as_str() == arkret_wire::events::EventKind::INVITE_ACCEPT;
        if (event.effects.is_empty()
            && !identity_anchor_event_ids.contains(record.event_id.as_str())
            && !requires_invite_membership_validation)
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
        let invite_accept_from = if requires_invite_membership_validation {
            let member_cell = CellRef::new(format!(
                "ak:cell:ak.component.member.state.v1:{}",
                event.actor_id
            ))
            .map_err(proof_state_error)?;
            match ops_by_cell.get(&member_cell) {
                None => Some("leave".to_owned()),
                Some(ops) => {
                    let binding = state
                        .projections()
                        .resolve_cell(realm_id, &member_cell)
                        .map_err(|error| {
                            AppError::new(
                                ErrorCode::ProfileUnsupported,
                                format!(
                                    "no lattice registered for governance cell \
                                         {member_cell}: {error}"
                                ),
                            )
                        })?;
                    match arkret_state::join_cell(binding.lattice.as_ref(), &member_cell, ops) {
                        CellState::Value(serde_json::Value::String(value)) => Some(value),
                        CellState::Value(_) => {
                            return Err(AppError::new(
                                ErrorCode::StateMismatch,
                                format!(
                                    "governance member cell {member_cell} is not a string state"
                                ),
                            ));
                        }
                        CellState::Bottom(_) => {
                            return Err(AppError::new(
                                ErrorCode::StateMismatch,
                                format!("governance member cell {member_cell} is in Bottom state"),
                            ));
                        }
                    }
                }
            }
        } else {
            None
        };
        for (cell, issued) in canonical_event_ops(&event, &move_id, invite_accept_from.as_deref())?
        {
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
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm has no accepted Control Event material",
        ));
    }

    let mut joined = BTreeMap::new();
    for (cell, ops) in ops_by_cell {
        let binding = state
            .projections()
            .resolve_cell(realm_id, &cell)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::ProfileUnsupported,
                    format!("no lattice registered for governance cell {cell}: {error}"),
                )
            })?;
        let resolved = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops);
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
    if let Some(seals) = transported_seals {
        let authority_dids = authoritative_notary_dids(realm_id, &joined)?;
        apply_authoritative_event_seal_path(state, realm_id, &authority_dids, &event_ops, seals)
            .await?;
    }
    let mut seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        realm_id,
        &covered_event_digests,
        &state_root,
        &event_ops,
        device_generation_seal_required,
        generation_fence.as_ref(),
    );
    if matches!(seal_view, Err(crate::notary::NotaryError::NotAuthorized(_)))
        && backfill_authoritative_event_seals(state, realm_id, &joined, &event_ops).await?
    {
        seal_view = crate::notary::ensure_materialized_event_seal(
            state,
            realm_id,
            &covered_event_digests,
            &state_root,
            &event_ops,
            device_generation_seal_required,
            generation_fence.as_ref(),
        );
    }
    let seal_view = seal_view.map_err(|error| {
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
    records: &[soland_services::events::CanonicalEventRecord],
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

async fn materialize_governance_proof(
    state: &AppState,
    request: &MlsGovernanceProofRequestBodyBody,
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
        bundle_version: arkret_models_crypto::mls_governance_proof::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        proof_request_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
            .expect("zero sha256 digest is valid"),
        bundle_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
            .expect("zero sha256 digest is valid"),
        materialization_profile: arkret_models_crypto::mls_governance_proof::MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
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
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored device re-anchor payload is invalid: {error}"),
            )
        })?;
        let authorize = records
            .iter()
            .find(|record| {
                record.event_id == payload.replacement_authorize_event_id.as_str()
                    && record.kind == arkret_wire::events::EventKind::DEVICE_AUTHORIZE
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

/// Canonical sealed effects for one Event, each tagged with the Event's actor.
///
/// The issuer must travel with the op: `ordered_log` keys its slots by
/// `(cell, actor_id, issuer_seq)`, so a store that received issuer-less ops
/// would have to invent one.
pub(crate) fn canonical_event_ops(
    event: &Event,
    move_id: &MoveId,
    invite_accept_from: Option<&str>,
) -> Result<Vec<(CellRef, IssuedOp)>, AppError> {
    Ok(
        canonical_event_sealed_ops(event, move_id, invite_accept_from)?
            .into_iter()
            .map(|(cell, op)| {
                (
                    cell,
                    IssuedOp {
                        issuer: event.actor_id.clone(),
                        op,
                    },
                )
            })
            .collect(),
    )
}

fn canonical_event_sealed_ops(
    event: &Event,
    move_id: &MoveId,
    invite_accept_from: Option<&str>,
) -> Result<Vec<(CellRef, SealedOp)>, AppError> {
    if event.kind.as_str() == arkret_wire::events::EventKind::INVITE_ACCEPT {
        let from = invite_accept_from.ok_or_else(|| {
            AppError::new(
                ErrorCode::StateMismatch,
                "invite acceptance proof material is missing prior membership state",
            )
        })?;
        let member_cell = CellRef::new(format!(
            "ak:cell:ak.component.member.state.v1:{}",
            event.actor_id
        ))
        .map_err(proof_state_error)?;
        let member_effects = event
            .effects
            .iter()
            .filter(|effect| effect.cell == member_cell)
            .collect::<Vec<_>>();
        let expected_from = serde_json::json!(from);
        let expected_to = serde_json::json!("join");
        if member_effects.len() != 1
            || member_effects[0].op.op_type != LatticeOpType::Transition
            || member_effects[0].op.from.as_ref() != Some(&expected_from)
            || member_effects[0].op.to.as_ref() != Some(&expected_to)
        {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "invite acceptance member effect does not match prior membership state",
            ));
        }
    } else if event.kind.as_str() == arkret_wire::events::EventKind::REALM_CREATE {
        let expected = arkret_bootstrap::realm_create_effects(event).map_err(proof_state_error)?;
        if event.effects != expected {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "Realm create proof material does not carry the canonical four-effect set",
            ));
        }
    }

    Ok(event
        .effects
        .iter()
        .map(|effect| {
            (
                effect.cell.clone(),
                SealedOp::new(move_id.clone(), effect.op.clone()),
            )
        })
        .collect())
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
        let actor_id = arkret_identifiers::Did::new("did:web:agent.example").unwrap();
        let mut event = Event::new(
            arkret_wire::events::EventKind::REALM_CREATE,
            realm_id.clone(),
            actor_id.clone(),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1").unwrap(),
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
        event.effects = arkret_bootstrap::realm_create_effects(&event).unwrap();
        event
    }

    #[test]
    fn governance_materializer_accepts_explicit_managed_agent_create_effects() {
        let event = managed_agent_pcr_create();
        let move_id = MoveId::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let ops = canonical_event_ops(&event, &move_id, None).unwrap();
        assert_eq!(ops.len(), 4);
        assert!(
            ops.iter()
                .any(|(cell, _)| { cell.as_str() == arkret_bootstrap::REALM_CREATE_CELL })
        );
        assert!(ops.iter().all(|(cell, _)| {
            cell.as_str() != format!("ak:cell:ak.component.realm.create.v1:{}", event.realm_id)
        }));
    }

    #[test]
    fn governance_materializer_rejects_legacy_managed_agent_create_effect() {
        let mut event = managed_agent_pcr_create();
        event.effects = vec![arkret_wire::Effect {
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
        assert!(canonical_event_ops(&event, &move_id, None).is_err());
    }

    #[test]
    fn governance_materializer_uses_signed_invite_accept_membership() {
        let realm_id = RealmId::new("ak:realm:01999999-0000-7000-8000-00000000fade").unwrap();
        let actor_id = arkret_identifiers::Did::new("did:web:invitee.example").unwrap();
        let mut event = Event::new(
            arkret_wire::events::EventKind::INVITE_ACCEPT,
            realm_id,
            actor_id.clone(),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce2").unwrap(),
            serde_json::json!({
                "invite_id": "ak:invite:01999999-0000-7000-8000-00000000fade"
            }),
        )
        .unwrap();
        let move_id = MoveId::new(format!("sha256:{}", "33".repeat(32))).unwrap();

        for prior_state in ["leave", "invite"] {
            event.effects = vec![arkret_wire::Effect {
                cell: CellRef::new(format!("ak:cell:ak.component.member.state.v1:{actor_id}"))
                    .unwrap(),
                op: LatticeOp {
                    op_type: LatticeOpType::Transition,
                    tag: None,
                    value: None,
                    from: Some(serde_json::json!(prior_state)),
                    to: Some(serde_json::json!("join")),
                    reason: Some("invite_accept".to_owned()),
                    issuer_seq: None,
                },
            }];
            let ops = canonical_event_ops(&event, &move_id, Some(prior_state)).unwrap();

            assert_eq!(ops.len(), 1);
            assert_eq!(
                ops[0].0.as_str(),
                format!("ak:cell:ak.component.member.state.v1:{actor_id}")
            );
            assert_eq!(ops[0].1.op.op.op_type, LatticeOpType::Transition);
            assert_eq!(ops[0].1.op.op.from, Some(serde_json::json!(prior_state)));
            assert_eq!(ops[0].1.op.op.to, Some(serde_json::json!("join")));
        }
    }
}
