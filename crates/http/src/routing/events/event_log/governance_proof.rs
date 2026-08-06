use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_models_crypto::{
    MaterializedMlsGovernanceProofBundle, MlsGovernanceControlStateLeaf,
    MlsGovernanceControlStateValue, MlsGovernanceProofBundle, MlsGovernanceProofRequestBodyBody,
    build_mls_governance_proof_chunks, is_mls_membership_frontier_component,
};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{BottomMode, compute_state_root, control_event_set_root};
#[cfg(test)]
use arkret_wire::cba::LatticeOp;
use arkret_wire::cba::LatticeOpType;
use arkret_wire::{CORE_REDUCER_PROFILE, CellId, Event, NotarySig, ScopeRef as GovernanceScope};
use salvo::oapi::extract::JsonBody;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.events.read.mls_governance_proof",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.mls_governance_proof"))]
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
    if request.reducer_profile != CORE_REDUCER_PROFILE {
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
    covered_event_digests: Vec<Hash>,
}

async fn backfill_authoritative_event_seals(
    state: &AppState,
    realm_id: &RealmId,
    joined: &BTreeMap<CellRef, CellState>,
    event_ops: &[(CellRef, IssuedOp)],
    available_control_digests: &BTreeSet<Hash>,
    control_events: &[Event],
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
        available_control_digests,
        control_events,
        &outcome.seals,
    )
    .await?;
    Ok(true)
}

fn authoritative_notary_dids(
    _realm_id: &RealmId,
    joined: &BTreeMap<CellRef, CellState>,
) -> Result<Vec<String>, AppError> {
    // `joined` is the portable control-state map used for Seal state-root
    // verification, so its keys must remain byte-identical to signed Event
    // effects. Realm-singleton cells therefore use the canonical `null` wire
    // subject here. Only the process-wide ProjectionState cache rewrites that
    // subject to `realm_id` to prevent cross-Realm aliasing.
    let notary_cell =
        CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned()).map_err(proof_state_error)?;
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
    available_control_digests: &BTreeSet<Hash>,
    control_events: &[Event],
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
        if seal
            .delta
            .iter()
            .any(|digest| !available_control_digests.contains(digest))
        {
            return Err(AppError::new(
                ErrorCode::DependencyMissing,
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
        let expected_control_root = control_event_set_root(&target).map_err(proof_state_error)?;
        let expected_completeness_root =
            arkret_state::control_event_completeness_root(control_events, &target)
                .map_err(proof_state_error)?;
        if seal.control_event_set_root != expected_control_root
            || seal.completeness_root != expected_completeness_root
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
        let target_state = join_control_state_batches(state, realm_id, &ops_by_cell, &target)
            .map_err(|error| {
                proof_state_error(format!("resolve authoritative Event Seal state: {error}"))
            })?;
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

pub(crate) async fn verify_authoritative_event_seal_signature(
    state: &AppState,
    signature: &arkret_wire::PayloadSignature,
    signer: &str,
    canonical_bytes: &[u8],
) -> Result<(), AppError> {
    let expected_method = format!("{signer}#notary-key");
    if signature.verification_method != expected_method {
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
        crate::jws_verify::verify_did_controlled_jws_async(
            canonical_bytes,
            &signature.jws,
            &signature.verification_method,
            signer,
            state,
        )
        .await
    };
    result.map_err(|error| {
        AppError::new(
            ErrorCode::SignatureInvalid,
            format!("verify authoritative Event Seal signature: {error}"),
        )
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
        record.kind == arkret_wire::EventKind::REALM_CREATE
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
            record.kind == arkret_wire::EventKind::REALM_CREATE
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
                soland_services::events::paired_replacement_authorize(record, realm_records.iter())
                    .map(|paired| paired.event_id.clone()),
            )
        })
        .collect::<BTreeSet<_>>();
    for bootstrap in realm_records.iter().filter(|record| {
        record.kind == arkret_wire::EventKind::REALM_CREATE
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
                    record.kind == arkret_wire::EventKind::DEVICE_AUTHORIZE
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
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored Event {} is not a canonical envelope: {error}",
                    record.event_id
                ),
            )
        })?;
        let requires_invite_membership_validation =
            event.kind.as_str() == arkret_wire::EventKind::INVITE_ACCEPT;
        // v1 has no producer `effects[]`: whether a stored Event contributes
        // governance writes is decided by its registered contract, not by an
        // array on the envelope.
        let projects_writes = state
            .projections()
            .project_accepted_cell_writes(&event)
            .map(|writes| !writes.is_empty())
            .unwrap_or(false);
        if (!projects_writes
            && !identity_anchor_event_ids.contains(record.event_id.as_str())
            && !requires_invite_membership_validation)
            || event.seal_ref.is_some()
        {
            continue;
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
        let move_id = Hash::new(digest).map_err(|error| {
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
        for (cell, issued) in canonical_event_ops(
            state,
            realm_id,
            &event,
            &move_id,
            &ops_by_cell,
            invite_accept_from.as_deref(),
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
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm has no accepted Control Event material",
        ));
    }
    let completeness_events = realm_records
        .iter()
        .filter(|record| {
            covered
                .iter()
                .any(|digest| digest.as_str() == record.canonical_digest)
        })
        .map(|record| {
            serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    format!(
                        "covered Event {} is not a canonical envelope: {error}",
                        record.event_id
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let joined = join_control_state_batches(state, realm_id, &ops_by_cell, &covered)?;
    let state_root = compute_state_root(&joined).map_err(|error| {
        AppError::new(
            ErrorCode::StateMismatch,
            format!("governance state root failed: {error}"),
        )
    })?;
    let covered_event_digests = covered.iter().cloned().collect::<Vec<_>>();
    let completeness_root =
        arkret_state::control_event_completeness_root(&completeness_events, &covered)
            .map_err(proof_state_error)?;
    if let Some(seals) = transported_seals {
        let authority_dids = authoritative_notary_dids(realm_id, &joined)?;
        apply_authoritative_event_seal_path(
            state,
            realm_id,
            &authority_dids,
            &event_ops,
            &covered,
            &completeness_events,
            seals,
        )
        .await?;
    }
    let mut seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        realm_id,
        &covered_event_digests,
        &state_root,
        &completeness_root,
        &event_ops,
        device_generation_seal_required,
        generation_fence.as_ref(),
    );
    if matches!(seal_view, Err(crate::notary::NotaryError::NotAuthorized(_)))
        && backfill_authoritative_event_seals(
            state,
            realm_id,
            &joined,
            &event_ops,
            &covered,
            &completeness_events,
        )
        .await?
    {
        seal_view = crate::notary::ensure_materialized_event_seal(
            state,
            realm_id,
            &covered_event_digests,
            &state_root,
            &completeness_root,
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
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored managed Agent PCR Event {} is not canonical: {error}",
                    record.event_id
                ),
            )
        })?;
        // `scope_ref` is producer-signed and part of the canonical digest
        // transcript (`conformance/encoding.md` §6), so nothing may stamp it
        // here. Managed PCR Events are closed over their own Realm; a stored
        // Event whose signed scope names another Realm is not proof material
        // for this one.
        if event.scope_ref.realm_id() != realm_id {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored managed Agent PCR Event {} is scoped to another Realm",
                    record.event_id
                ),
            ));
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
    let material = arkret_bootstrap::materialize_managed_agent_pcr_control(&events, &|event| {
        state.projections().project_accepted_cell_writes(event)
    })
    .map_err(|error| {
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
    let managed_covered = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let completeness_root =
        arkret_state::control_event_completeness_root(&events, &managed_covered)
            .map_err(proof_state_error)?;
    let seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        realm_id,
        &material.covered_event_digests,
        &material.state_root,
        &completeness_root,
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
    let mut frontier_events = events
        .into_iter()
        .filter(|event| event.scope_ref == request.effective_scope)
        .filter(|event| {
            // The touched cells come from the registered contract, not from a
            // producer array; only the cell targets matter here, so the
            // unresolved projection is enough.
            state
                .projections()
                .project_accepted_cell_writes(event)
                .map(|writes| {
                    writes.iter().any(|write| {
                        CellId::from_ref(&write.cell)
                            .map(|cell| is_mls_membership_frontier_component(cell.component()))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    frontier_events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    if frontier_events.is_empty() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm/scope has no materialized membership frontier Event",
        ));
    }
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
    // Validate that the exact trusted anchor bridges the complete accepted
    // Seal ancestry. The bundle materializes this proof only; the MLS client
    // owns the current/pending leaf set and combines it with the verified
    // control state to derive the unique security_frontier_digest.
    drop(prior);

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
        let authorize = soland_services::events::paired_replacement_authorize(reanchor, records)
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
        let replacement_payload_digest =
            soland_services::events::replacement_authorize_payload_digest(
                &authorize.envelope,
                &authorize.canonical_digest,
            )
            .map_err(|message| AppError::new(ErrorCode::StateMismatch, message))?;
        if replacement_payload_digest != payload.replacement_authorize_payload_digest
        {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "stored replacement device authorization does not match the re-anchor payload digest",
            ));
        }
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
        let replacement_authorize_digest = Hash::new(authorize.canonical_digest.clone())
            .map_err(|error| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    format!("stored re-anchor unit digest is invalid: {error}"),
                )
            })?;
        let required_delta = vec![reanchor_digest.clone(), replacement_authorize_digest.clone()];
        requirement = Some(crate::notary::FirstGenerationEventSealRequirement {
            payload,
            reanchor_digest,
            replacement_authorize_digest,
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

fn join_control_state_batches(
    state: &AppState,
    realm_id: &RealmId,
    ops_by_cell: &BTreeMap<CellRef, Vec<IssuedOp>>,
    covered: &BTreeSet<Hash>,
) -> Result<BTreeMap<CellRef, CellState>, AppError> {
    let mut joined = BTreeMap::new();
    for (cell, projected_ops) in ops_by_cell {
        let persisted = state
            .projections()
            .sealed_op_batches_for_cell(realm_id, cell)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    format!("read governance cell {cell} Seal batches: {error}"),
                )
            })?;
        let mut persisted_digests = BTreeSet::new();
        let mut batches = persisted
            .into_iter()
            .filter_map(|(_, ops)| {
                let ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .inspect(|issued| {
                        persisted_digests.insert(issued.op.move_id.clone());
                    })
                    .collect::<Vec<_>>();
                (!ops.is_empty()).then_some(ops)
            })
            .collect::<Vec<_>>();
        let candidate_batch = projected_ops
            .iter()
            .filter(|issued| {
                covered.contains(&issued.op.move_id)
                    && !persisted_digests.contains(&issued.op.move_id)
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
                AppError::new(
                    ErrorCode::ProfileUnsupported,
                    format!("no lattice registered for governance cell {cell}: {error}"),
                )
            })?;
        let bottom_mode = binding.bottom_mode;
        let resolved =
            arkret_state::join_cell_seal_batches(binding.lattice.as_ref(), cell, &batches);
        // `event-auth-state-resolution.md` §9.1.1: an exposed Bottom remains
        // part of the materialized governance view (and is omitted from the
        // state-root leaf set by `compute_state_root`). Only reject-mode cells
        // — plus an impossible Bottom from an inert lattice — fail closed.
        // Rejecting every Bottom here lets one ambiguous, unrelated selector
        // poison all later controller-PCR authorization and Seal material.
        if matches!(resolved, CellState::Bottom(_)) && bottom_mode != BottomMode::Expose {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!("governance cell {cell} is in Bottom state"),
            ));
        }
        joined.insert(cell.clone(), resolved);
    }
    Ok(joined)
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
) -> Result<Vec<(CellRef, IssuedOp)>, AppError> {
    Ok(canonical_event_sealed_ops(
        state,
        realm_id,
        event,
        move_id,
        accumulated,
        invite_accept_from,
    )?
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
/// null pre-state, and a ⊥ cell against that cell family's declared
/// `bottom_mode`.
fn frozen_governance_pre_state(
    state: &AppState,
    realm_id: &RealmId,
    accumulated: &BTreeMap<CellRef, Vec<IssuedOp>>,
) -> Result<BTreeMap<CellRef, CellState>, AppError> {
    let mut pre_state = BTreeMap::new();
    for (cell, ops) in accumulated {
        let binding = state
            .projections()
            .resolve_cell(realm_id, cell)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::ProfileUnsupported,
                    format!("no lattice registered for governance cell {cell}: {error}"),
                )
            })?;
        pre_state.insert(
            cell.clone(),
            arkret_state::join_cell(binding.lattice.as_ref(), cell, ops),
        );
    }
    Ok(pre_state)
}

fn canonical_event_sealed_ops(
    state: &AppState,
    realm_id: &RealmId,
    event: &Event,
    move_id: &Hash,
    accumulated: &BTreeMap<CellRef, Vec<IssuedOp>>,
    invite_accept_from: Option<&str>,
) -> Result<Vec<(CellRef, SealedOp)>, AppError> {
    // v1 carries no producer `effects[]`: every write is derived from
    // `kind + payload` by the registered contract.
    let projected = state
        .projections()
        .project_accepted_cell_writes(event)
        .map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored Event {} does not project its registered cell writes: {error}",
                    event.event_id
                ),
            )
        })?;

    let pre_state = frozen_governance_pre_state(state, realm_id, accumulated)?;
    let mut resolved: Vec<(CellRef, SealedOp)> = Vec::with_capacity(projected.len());
    for write in &projected {
        // The pre-state-dependent grammars are resolved by the one shared
        // implementation; a second copy here would be a second answer to a
        // rule that has to agree byte-for-byte with `verify_control_move`.
        let effects = state
            .projections()
            .resolve_projected_write(write, realm_id, &pre_state)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::StateMismatch,
                    format!(
                        "stored Event {} cannot resolve its registered write on {}: {error:?}",
                        event.event_id, write.cell
                    ),
                )
            })?;
        for effect in effects {
            resolved.push((
                effect.cell.clone(),
                SealedOp::from_projection(move_id.clone(), &effect),
            ));
        }
    }

    if event.kind.as_str() == arkret_wire::EventKind::INVITE_ACCEPT {
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
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "invite acceptance member transition does not match prior membership state",
            ));
        }
    } else if event.kind.as_str() == arkret_wire::EventKind::REALM_CREATE {
        // Only the genesis targets are asserted; the lattice ops come from the
        // registered `effect_projection`.
        let expected = arkret_bootstrap::expected_realm_create_cells(event);
        let actual: std::collections::BTreeSet<String> = resolved
            .iter()
            .map(|(cell, _)| cell.as_str().to_owned())
            .collect();
        if resolved.len() != expected.len() || actual != expected {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "Realm create proof material does not derive the canonical registered genesis cells",
            ));
        }
    }

    Ok(resolved)
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

    fn issued_set(move_byte: u8, value: serde_json::Value) -> IssuedOp {
        IssuedOp {
            issuer: arkret_identifiers::Did::new("did:web:alice.example").unwrap(),
            op: SealedOp::new(
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
        let realm_id = RealmId::new("ak:realm:01999999-0000-8000-8000-00000000a11c").unwrap();
        let notary = "did:web:notary.example";
        let mut joined = BTreeMap::new();
        joined.insert(
            CellRef::new("ak:cell:ak.component.notary.v1:null".to_owned()).unwrap(),
            CellState::Value(serde_json::json!({
                "kind": "single_did",
                "did": notary,
            })),
        );

        assert_eq!(
            authoritative_notary_dids(&realm_id, &joined).unwrap(),
            vec![notary.to_owned()]
        );
    }

    #[test]
    fn governance_join_preserves_exposed_bottom_without_poisoning_the_realm() {
        let state = test_state();
        let realm_id = RealmId::new("ak:realm:01999999-0000-8000-8000-00000000b077").unwrap();
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
            .map(|issued| issued.op.move_id.clone())
            .collect::<BTreeSet<_>>();
        let ops_by_cell = BTreeMap::from([(selector_cell.clone(), selector_ops)]);

        let joined = join_control_state_batches(&state, &realm_id, &ops_by_cell, &covered)
            .expect("bottom=expose must not make unrelated governance unavailable");

        assert!(matches!(
            joined.get(&selector_cell),
            Some(CellState::Bottom(_))
        ));
        assert_eq!(
            compute_state_root(&joined).unwrap(),
            compute_state_root(&BTreeMap::new()).unwrap(),
            "an exposed Bottom is omitted from the governance state-root leaves"
        );
    }

    #[test]
    fn governance_join_still_fails_closed_for_rejected_bottom() {
        let state = test_state();
        let realm_id = RealmId::new("ak:realm:01999999-0000-8000-8000-00000000b078").unwrap();
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
            .map(|issued| issued.op.move_id.clone())
            .collect::<BTreeSet<_>>();
        let ops_by_cell = BTreeMap::from([(accountability_cell.clone(), accountability_ops)]);

        let error = join_control_state_batches(&state, &realm_id, &ops_by_cell, &covered)
            .expect_err("bottom=reject must remain fail closed");

        assert_eq!(error.code, ErrorCode::StateMismatch);
        assert!(error.to_string().contains(accountability_cell.as_str()));
    }

    fn test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        )
    }

    fn managed_agent_pcr_create() -> Event {
        let realm_id = RealmId::new("ak:realm:01999999-0000-8000-8000-00000000cafe").unwrap();
        let actor_id = arkret_identifiers::Did::new("did:web:agent.example").unwrap();
        Event::new(
            arkret_wire::EventKind::REALM_CREATE,
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id.clone(),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1").unwrap(),
            serde_json::json!({
                "object": {
                    "id": realm_id,
                    "created_by": actor_id,
                    "capability_action_registry_digest":
                        arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "fields": {"purpose": "principal_control"},
                    "notary": {"kind": "single_did", "did": actor_id},
                    "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
                }
            }),
        )
        .unwrap()
    }

    /// The v1 wire carries no producer `effects[]`, so the canonical
    /// genesis cells of a managed Agent PCR create are whatever the registered
    /// contract derives — and the create-log target is the wire singleton
    /// (`realm-and-space.md` §2.8.3), never a per-Realm subject. A per-Realm
    /// variant would both fork the `state_root` leaf set and turn a per-Realm
    /// genesis singleton into a deployment-wide shared key.
    #[test]
    fn governance_materializer_derives_the_canonical_genesis_cells() {
        let state = test_state();
        let event = managed_agent_pcr_create();
        let realm_id = event.realm_id.clone();
        let move_id = Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let ops = canonical_event_ops(&state, &realm_id, &event, &move_id, &BTreeMap::new(), None)
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

    /// Fail-closed replaces the old "reject the producer's legacy effect"
    /// premise: a producer can no longer name a cell at all, so the only way
    /// the materializer can go wrong is by inventing writes for an Event whose
    /// registered contract will not evaluate. `event-and-patch.md` §2.4.2 makes
    /// that an outright rejection, not a partial op set.
    #[test]
    fn governance_materializer_rejects_a_realm_create_it_cannot_project() {
        let state = test_state();
        let mut event = managed_agent_pcr_create();
        let realm_id = event.realm_id.clone();
        event.payload.remove("object");
        let move_id = Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap();
        assert!(
            canonical_event_ops(&state, &realm_id, &event, &move_id, &BTreeMap::new(), None)
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
        let realm_id = RealmId::new("ak:realm:01999999-0000-8000-8000-00000000fade").unwrap();
        let actor_id = arkret_identifiers::Did::new("did:web:invitee.example").unwrap();
        let event = Event::new(
            arkret_wire::EventKind::INVITE_ACCEPT,
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id.clone(),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce2").unwrap(),
            serde_json::json!({
                "invite_id": "ak:invite:01999999-0000-7000-8000-00000000fade"
            }),
        )
        .unwrap();
        let member_cell =
            CellRef::new(format!("ak:cell:ak.component.member.state.v1:{actor_id}")).unwrap();

        let projected = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        // Two registered writes: the invite lifecycle transition (an explicit
        // pending -> accepted, resolvable without any pre-state) and the
        // membership transition, whose `from` is deliberately absent.
        assert_eq!(projected.len(), 2);
        let member_write = projected
            .iter()
            .find(|write| write.cell == member_cell)
            .expect("invite accept writes the member state cell");
        assert!(matches!(
            &member_write.op,
            arkret_wire::cba::ProjectedOp::TransitionTo { to }
                if to == &serde_json::json!("join")
        ));

        let move_id = Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap();
        for prior_state in ["leave", "invite"] {
            // The member-state fsm starts at its registered `initial_state`
            // (`leave`), so the frozen pre-state for that case is the cell with
            // no accumulated op at all; `invite` needs one accepted transition
            // into it first.
            let prior_ops = if prior_state == "leave" {
                Vec::new()
            } else {
                vec![IssuedOp {
                    issuer: actor_id.clone(),
                    op: SealedOp::new(
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
