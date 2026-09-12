use serde_json::{Value, json};
use soland_services::delivery::BlobState as BlobRecord;
use soland_services::events::AcceptedEvent;

use super::*;
use crate::state::AppState;
use crate::wire::now;

pub(crate) async fn realm_state_snapshot_manifest_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<arkret_state::RealmStateSnapshotManifest, soland_http::error::AppError> {
    let realm_id_value = arkret_identifiers::RealmId::new(realm_id.to_owned())
        .map_err(|_| soland_http::error::AppError::param_invalid("invalid realm_id"))?;
    {
        let realms = state.realm_directory().snapshot();
        if realms.get(&realm_id_value).is_none() {
            return Err(soland_http::error::AppError::not_found("not found"));
        }
    }

    let head = state
        .projections()
        .realm_seal_head(&realm_id_value)
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let created_at = now();
    let mut events = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| record.realm_id.as_deref() == Some(realm_id))
        .filter(is_realm_scope_event)
        .collect::<Vec<_>>();
    events.sort_by(|a, b| {
        (a.actor_id.as_str(), a.actor_seq, a.event_id.as_str()).cmp(&(
            b.actor_id.as_str(),
            b.actor_seq,
            b.event_id.as_str(),
        ))
    });

    let mut replay_events = events
        .iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    replay_events.sort_by_key(|event| event.event_id.token_bytes());
    let mut authority_refs = std::collections::BTreeSet::new();
    authority_refs.extend(head.iter().cloned());
    for event in &replay_events {
        if let Some(context) = &event.auth_context {
            authority_refs.extend(context.authority_refs.iter().cloned());
        }
    }
    let closure = state
        .projections()
        .seal_basis_closure(&authority_refs.iter().cloned().collect::<Vec<_>>())
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let mut closure_command_refs = std::collections::BTreeSet::new();
    for seal_id in &closure {
        let seal = state
            .projections()
            .seal_by_id(seal_id)
            .await
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                soland_http::error::AppError::conflict("snapshot authority dependency is pending")
            })?;
        closure_command_refs.extend(
            seal.authorization_closures
                .iter()
                .map(|closure| closure.command_event_id.clone()),
        );
    }
    // A projection cache created before a closure cannot certify reclassified
    // ordinary state. Keep the original history available while that rebuild
    // is pending; never export an older projection as the new context.
    if !closure_command_refs.is_empty() {
        return Err(soland_http::error::AppError::conflict(
            "snapshot eligibility reclassification is pending",
        ));
    }
    let eligibility_context = arkret_state::SnapshotEligibilityContext {
        authority_refs: authority_refs.into_iter().collect(),
        closure_command_refs: closure_command_refs.into_iter().collect(),
        reducer_contract_digest: arkret_identifiers::Hash::new(
            arkret_wire::CANONICAL_REDUCER_CONTRACT_DIGEST,
        )
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
    };
    let confirmed_prefix = state
        .projections()
        .seal_basis_closure(&head.iter().cloned().collect::<Vec<_>>())
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let projection_events =
        snapshot_projection_events(state, &realm_id_value, &events, &confirmed_prefix).await?;
    let evidence = arkret_state::SnapshotReplayEvidence {
        eligibility_context: eligibility_context.clone(),
        replay_events,
        replay_authority_refs: closure.into_iter().collect(),
    };
    let (items, conflict_records) = reducer_cell_items(
        state,
        &realm_id_value,
        &projection_events,
        &head.iter().cloned().collect::<Vec<_>>(),
    )
    .await?;
    if state
        .projections()
        .realm_seal_head(&realm_id_value)
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
        != head
    {
        return Err(soland_http::error::AppError::conflict(
            "snapshot authority changed during preparation",
        ));
    }
    let end_events = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| record.realm_id.as_deref() == Some(realm_id))
        .filter(is_realm_scope_event)
        .map(|record| (record.event_id, record.canonical_digest))
        .collect::<std::collections::BTreeSet<_>>();
    let start_events = events
        .iter()
        .map(|record| (record.event_id.clone(), record.canonical_digest.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    if start_events != end_events {
        return Err(soland_http::error::AppError::conflict(
            "snapshot input frontier changed during preparation",
        ));
    }
    let state_digest = arkret_state::state_digest_from_items_with_digest_suite(
        &items,
        state.projections().realm_digest_suite(realm_id),
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let realm_state_snapshot_id = arkret_identifiers::RealmStateSnapshotId::new(
        crate::ids::generate_realm_state_snapshot_id(),
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let built_chunks = arkret_state::build_realm_state_snapshot_chunks_with_auxiliary_lists(
        &realm_state_snapshot_id,
        arkret_wire::CORE_REDUCER_PROFILE,
        items,
        arkret_state::DEFAULT_REALM_STATE_SNAPSHOT_CHUNK_BYTES,
        evidence,
        arkret_state::SnapshotAuxiliaryLists {
            conflict_records,
            ..Default::default()
        },
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    persist_realm_state_snapshot_chunk_blobs(state, realm_id, &built_chunks).await?;
    let chunk_payloads = built_chunks
        .iter()
        .map(|chunk| chunk.payload.clone())
        .collect::<Vec<_>>();
    // `realm-state-snapshot-schema.md` section 3: bottom cells are not leaves; their only
    // commitment is the conflict_records digest, so it is carried whenever the
    // list is non-empty rather than left for a high-assurance profile to add.
    let conflict_records_digest = if chunk_payloads
        .iter()
        .any(|chunk| !chunk.conflict_records.is_empty())
    {
        Some(
            arkret_state::realm_state_snapshot_conflict_records_digest(
                &chunk_payloads,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        )
    } else {
        None
    };
    let chunk_descriptors = built_chunks
        .iter()
        .map(|chunk| chunk.descriptor.clone())
        .collect::<Vec<_>>();

    let frontier_event_ids = realm_state_snapshot_frontier_event_ids(&events)?;
    let event_set_entries = events
        .iter()
        .map(realm_state_snapshot_event_set_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let event_set_commitment = arkret_state::event_set_commitment(
        arkret_state::EventSetCommitmentAlgorithm::MerkleEventSetV1,
        &event_set_entries,
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let timeline_hlc = realm_state_snapshot_timeline_hlc(state, &events, created_at)?;
    let service_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let auth_state_digest = realm_state_snapshot_auth_state_digest(
        state.service_id(),
        realm_id,
        &frontier_event_ids,
        created_at,
    )?;
    let verification_method = state
        .service_verification_method("realm-state-snapshot-key-1")
        .map_err(|error| {
            soland_http::error::AppError::internal(format!(
                "snapshot verification method is invalid: {error}"
            ))
        })?;
    let mut manifest = arkret_state::RealmStateSnapshotManifest {
        eligibility_context,
        id: realm_state_snapshot_id,
        realm_id: realm_id_value,
        reducer_profile: arkret_wire::CORE_REDUCER_PROFILE.to_owned(),
        schema_profile_refs: vec![
            arkret_wire::ProfileId::CORE_EVENT_STORE_V1.to_owned(),
            arkret_wire::ProfileId::STATION_EVENTS_API_V1.to_owned(),
        ],
        state_digest,
        frontier: arkret_state::RealmStateSnapshotFrontier {
            event_ids: frontier_event_ids.clone(),
            timeline_hlc,
        },
        event_set_commitment,
        chunks: chunk_descriptors,
        security_class: arkret_state::RealmStateSnapshotSecurityClass::Standard,
        verification_hints: Some(arkret_state::RealmStateSnapshotVerificationHints {
            verification_profile: arkret_state::RealmStateSnapshotSecurityClass::Standard,
            inclusion_proof_url: None,
            challenge_window_seconds: None,
            conflict_records_digest,
            soft_failed_digest: None,
            quarantined_digest: None,
            erasure_stubs_digest: None,
        }),
        created_by: arkret_wire::ActorId::service(service_id.clone()),
        created_at,
        authority_binding: arkret_state::AuthorityBinding {
            authority_kind:
                arkret_state::RealmStateSnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest,
            auth_frontier: frontier_event_ids,
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: arkret_state::DetachedJwsProof::ed25519(
            verification_method.clone(),
            arkret_identifiers::Hash::new(arkret_state::EMPTY_SHA256_DIGEST.to_owned())
                .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
            created_at,
            "header..signature".to_owned(),
        ),
    };
    let canonical_bytes = manifest
        .unsigned_canonical_bytes()
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let payload_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&canonical_bytes))
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &canonical_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(soland_http::error::AppError::internal)?;
    manifest.signature = arkret_state::DetachedJwsProof::ed25519(
        verification_method,
        payload_digest,
        created_at,
        jws,
    );
    Ok(manifest)
}

async fn persist_realm_state_snapshot_chunk_blobs(
    state: &AppState,
    realm_id: &str,
    chunks: &[arkret_state::BuiltRealmStateSnapshotChunk],
) -> Result<(), soland_http::error::AppError> {
    for chunk in chunks {
        let blob_ref = chunk.descriptor.chunk_ref.as_str();
        // The content-addressed chunk ref is the sole carrier of the chunk
        // digest; there is no sibling digest field to read it from
        // (`conformance/encoding.md` §4.0.1).
        let Some(sha256) = blob_ref.strip_prefix("ak:blob:sha256:") else {
            return Err(soland_http::error::AppError::internal(
                "snapshot chunk ref is not a sha256 content address",
            ));
        };
        let storage_key = state.deliveries().object_key_for_sha256(sha256);
        state
            .deliveries()
            .put_object(&storage_key, chunk.canonical_bytes.clone())
            .await
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
        let record = BlobRecord {
            sha256: sha256.to_owned(),
            size_bytes: chunk.canonical_bytes.len() as i64,
            storage_backend: state.deliveries().object_storage_backend_name(),
            storage_key,
            media_type: "application/json".to_owned(),
            filename: None,
            realm_id: Some(realm_id.to_owned()),
            encryption: None,
            legal_hold: false,
            redacted: false,
            visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
            uploaded_by: state.service_id().clone(),
            created_at: now(),
        };
        state
            .deliveries()
            .store_blob(blob_ref, record)
            .await
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    }
    Ok(())
}

/// Admission preserves replay evidence; only a committed unit contributes effects.
async fn snapshot_projection_events(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    events: &[AcceptedEvent],
    confirmed_prefix: &std::collections::BTreeSet<arkret_identifiers::SealId>,
) -> Result<Vec<AcceptedEvent>, soland_http::error::AppError> {
    let internal =
        |error: &dyn std::fmt::Display| soland_http::error::AppError::internal(error.to_string());
    let mut eligible = Vec::new();
    for record in events {
        let digest = record
            .canonical_digest
            .parse()
            .map_err(|error| internal(&error))?;
        if let Some(proposal) = state
            .projections()
            .control_proposal_snapshot(&digest)
            .await
            .map_err(|error| internal(&error))?
        {
            if snapshot_unit_is_committed(&proposal.command_decisions, confirmed_prefix)? {
                eligible.push(record.clone());
            }
            continue;
        }
        let event: arkret_wire::Event =
            serde_json::from_value(record.envelope.clone()).map_err(|error| internal(&error))?;
        if event.auth_context.is_none() || event.seal_basis.is_some() {
            return Err(soland_http::error::AppError::conflict(
                "snapshot command-unit dependency is pending",
            ));
        }
        for write in state
            .projections()
            .project_accepted_cell_writes_with_digest_suite(&event, record.digest_suite)
            .map_err(|error| internal(&error))?
        {
            let binding = state
                .projections()
                .resolve_cell(realm_id, &write.cell_id)
                .map_err(|error| internal(&error))?;
            if binding.execution != arkret_wire::EventCellExecution::Data {
                return Err(soland_http::error::AppError::conflict(
                    "snapshot command-unit dependency is pending",
                ));
            }
        }
        eligible.push(record.clone());
    }
    Ok(eligible)
}

fn snapshot_unit_is_committed(
    decisions: &[arkret_state::SealCommandEventDecision],
    confirmed_prefix: &std::collections::BTreeSet<arkret_identifiers::SealId>,
) -> Result<bool, soland_http::error::AppError> {
    let mut decisions = decisions
        .iter()
        .filter(|decision| confirmed_prefix.contains(&decision.seal_id));
    let Some(decision) = decisions.next() else {
        return Ok(false);
    };
    if decisions.next().is_some() {
        return Err(soland_http::error::AppError::conflict(
            "snapshot command has multiple terminal decisions",
        ));
    }
    Ok(decision.outcome == arkret_wire::CommandOutcome::Committed)
}

/// Snapshot complete model states without exposing out-of-scope Cell writes.
async fn reducer_cell_items(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    events: &[AcceptedEvent],
    leaves: &[arkret_identifiers::SealId],
) -> Result<
    (
        Vec<arkret_state::RealmStateSnapshotMaterializedItem>,
        Vec<arkret_state::RealmStateSnapshotConflictRecord>,
    ),
    soland_http::error::AppError,
> {
    let internal =
        |error: &dyn std::fmt::Display| soland_http::error::AppError::internal(error.to_string());
    if leaves.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let values = state
        .projections()
        .effective_state_at(leaves, realm_id)
        .await
        .map_err(|error| internal(&error))?;
    let visible_ids: std::collections::BTreeSet<_> =
        events.iter().map(|event| event.event_id.as_str()).collect();
    let mut values = values;
    let mut data_write_ids = std::collections::BTreeSet::new();
    for cell in state
        .projections()
        .realm_cells(realm_id)
        .await
        .map_err(|error| internal(&error))?
    {
        let binding = state
            .projections()
            .resolve_cell(realm_id, &cell)
            .map_err(|error| internal(&error))?;
        if binding.execution != arkret_wire::EventCellExecution::Data {
            continue;
        }
        let writes = state
            .projections()
            .state_writes_for_cell(realm_id, &cell)
            .await
            .map_err(|error| internal(&error))?
            .into_iter()
            .filter(|write| visible_ids.contains(write.op.event_id.as_str()))
            .collect::<Vec<_>>();
        data_write_ids.extend(
            writes
                .iter()
                .map(|write| (cell.clone(), write.op.event_id.clone())),
        );
        if !writes.is_empty() {
            values.insert(
                cell.clone(),
                arkret_state::join_cell(binding.model.as_ref(), &cell, &writes)
                    .map_err(|error| internal(&error))?,
            );
        }
    }
    for record in events {
        let event: arkret_wire::Event =
            serde_json::from_value(record.envelope.clone()).map_err(|error| internal(&error))?;
        if !event.kind.is_reducer_input() {
            continue;
        }
        let writes = state
            .projections()
            .project_accepted_cell_writes_with_digest_suite(
                &event,
                arkret_canonical::digest_suite(
                    event
                        .event_id
                        .event_digest()
                        .as_str()
                        .split_once(':')
                        .expect("typed Event digest")
                        .0,
                )
                .map_err(|error| internal(&error))?,
            )
            .map_err(|error| internal(&error))?;
        for write in writes {
            let binding = state
                .projections()
                .resolve_cell(realm_id, &write.cell_id)
                .map_err(|error| internal(&error))?;
            if binding.execution == arkret_wire::EventCellExecution::Data
                && !data_write_ids.contains(&(write.cell_id, event.event_id.clone()))
            {
                return Err(soland_http::error::AppError::conflict(
                    "complete ordinary Cell projection is pending",
                ));
            }
        }
    }
    let mut items = Vec::with_capacity(values.len());
    let mut conflict_records = Vec::new();
    for (cell, cell_state) in values {
        if let arkret_state::state_model::ResolvedCellState::Sequenced(sequenced) = &cell_state
            && !visible_ids.contains(sequenced.revision_event_id.as_str())
        {
            continue;
        }
        if matches!(
            cell_state,
            arkret_state::state_model::ResolvedCellState::Bottom(_)
        ) {
            conflict_records.push(arkret_state::RealmStateSnapshotConflictRecord::BottomCell {
                cell_ref: cell,
            });
        } else {
            items.push(
                arkret_state::RealmStateSnapshotMaterializedItem::from_resolved(cell, &cell_state)
                    .map_err(|error| internal(&error))?,
            );
        }
    }
    Ok((items, conflict_records))
}

/// Whether an accepted Event writes Realm-scope state
/// (`realm-state-snapshot-schema.md` §3).
///
/// A v1 snapshot has no scope selector, so it commits exactly the
/// `scope_ref.kind ∈ {realm, realm_genesis}` half of the Realm's log. Circle-
/// and Sidecar-scope Events are bootstrapped by their own scope's sync path;
/// putting them in the Realm frontier would publish their ids to every Realm
/// member and make `state_digest` depend on who is asking.
///
/// Unrecognised scope kinds are out, not in: `ScopeRef` is `#[non_exhaustive]`
/// and a future kind that defaulted to Realm-wide would leak by omission.
fn is_realm_scope_event(record: &AcceptedEvent) -> bool {
    matches!(
        record
            .envelope
            .get("scope_ref")
            .and_then(|scope| scope.get("kind"))
            .and_then(Value::as_str),
        Some("realm" | "realm_genesis")
    )
}

fn realm_state_snapshot_event_set_leaf(
    record: &AcceptedEvent,
) -> Result<arkret_state::EventSetLeaf, soland_http::error::AppError> {
    let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone())
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    Ok(arkret_state::EventSetLeaf {
        event_id: arkret_identifiers::EventId::new(record.event_id.clone())
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        event_digest: arkret_identifiers::Hash::new(record.canonical_digest.clone())
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        actor_id: serde_json::from_str::<arkret_wire::ActorId>(&record.actor_id)
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        actor_seq: record.actor_seq,
        hlc: event.hlc,
    })
}

fn realm_state_snapshot_frontier_event_ids(
    events: &[AcceptedEvent],
) -> Result<Vec<arkret_identifiers::EventId>, soland_http::error::AppError> {
    let mut heads = std::collections::BTreeSet::new();
    let mut covered = std::collections::BTreeSet::new();
    for record in events {
        let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone())
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
        heads.insert(event.event_id);
        covered.extend(event.prev_refs);
        for digest in event.causal_refs {
            covered.insert(
                arkret_identifiers::EventId::from_event_digest(&digest)
                    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
            );
        }
    }
    // Sequence height and digest order never prove that a concurrent branch
    // was observed. Only explicit edges inside this input cut cover a head.
    heads.retain(|event_id| !covered.contains(event_id));
    let mut heads = heads.into_iter().collect::<Vec<_>>();
    heads.sort_by_key(arkret_identifiers::EventId::token_bytes);
    Ok(heads)
}

fn realm_state_snapshot_timeline_hlc(
    state: &AppState,
    events: &[AcceptedEvent],
    fallback: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_identifiers::Hlc, soland_http::error::AppError> {
    let max_received_at = events
        .iter()
        .map(|record| record.received_at)
        .max()
        .unwrap_or(fallback);
    received_at_hlc(state, max_received_at)
}

fn received_at_hlc(
    state: &AppState,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_identifiers::Hlc, soland_http::error::AppError> {
    let node_hash = sha256_hex(state.service_id().as_bytes());
    let node = &node_hash[..8];
    arkret_identifiers::Hlc::new(format!("{:012x}-0000-{node}", at.timestamp_millis()))
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))
}

fn realm_state_snapshot_auth_state_digest(
    service_id: &str,
    realm_id: &str,
    frontier_event_ids: &[arkret_identifiers::EventId],
    checked_at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_identifiers::Hash, soland_http::error::AppError> {
    let commitment = json!({
        "profile": arkret_wire::DomainSeparationId::REALM_STATE_SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1,
        "issuer_id": service_id,
        "realm_id": realm_id,
        "frontier_event_ids": frontier_event_ids,
        "checked_at": checked_at,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&commitment)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&bytes))
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))
}

pub(crate) fn generate_invite_token(invite_id: &str, realm_id: &str, invitee_id: &str) -> String {
    format!(
        "ak:invite-token:{}",
        sha256_hex(format!("{invite_id}:{realm_id}:{invitee_id}").as_bytes())
    )
}

#[cfg(test)]
mod frontier_tests {
    use super::*;

    #[test]
    fn snapshot_effects_require_one_committed_decision_in_the_frozen_prefix() {
        let seal_id: arkret_identifiers::SealId = format!("ak:seal:sha256:{}", "01".repeat(32))
            .parse()
            .unwrap();
        let prefix = std::collections::BTreeSet::from([seal_id.clone()]);
        let mut decision = arkret_state::SealCommandEventDecision {
            seal_id,
            command_index: 0,
            member_index: 1,
            outcome: arkret_wire::CommandOutcome::Committed,
            reason_code: None,
        };
        assert!(!snapshot_unit_is_committed(&[], &prefix).unwrap());
        assert!(
            !snapshot_unit_is_committed(
                std::slice::from_ref(&decision),
                &std::collections::BTreeSet::new(),
            )
            .unwrap()
        );
        assert!(snapshot_unit_is_committed(std::slice::from_ref(&decision), &prefix).unwrap());
        decision.outcome = arkret_wire::CommandOutcome::Rejected;
        assert!(!snapshot_unit_is_committed(std::slice::from_ref(&decision), &prefix).unwrap());
        assert!(snapshot_unit_is_committed(&[decision.clone(), decision], &prefix).is_err());
    }

    fn event(
        seq: u64,
        seed: u8,
        prev: &[&AcceptedEvent],
        causal: &[&AcceptedEvent],
    ) -> AcceptedEvent {
        let mut event = arkret_wire::test_support::raw_event_at(
            "ak.test.data",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [1; 32],
                )),
            },
            "ak:did_core:web:frontier-author.example".parse().unwrap(),
            "ak:did_core:web:frontier-station.example".parse().unwrap(),
            seq,
            "019f00000000-0000-00000001".parse().unwrap(),
            json!({"seed": seed}),
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        event.prev_refs = prev
            .iter()
            .map(|record| record.event_id.parse().unwrap())
            .collect();
        event.causal_refs = causal
            .iter()
            .map(|record| record.canonical_digest.parse().unwrap())
            .collect();
        let digest_suite = arkret_canonical::DigestSuite::Sha256;
        let digest = event.event_digest_with_digest_suite(digest_suite).unwrap();
        event.event_id = arkret_wire::EventId::from_event_digest(&digest.parse().unwrap()).unwrap();
        AcceptedEvent {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            actor_seq: seq,
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.to_string(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite,
            canonical_digest: digest,
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(&event).unwrap(),
            received_at: event.created_at,
        }
    }

    fn ids(events: &[&AcceptedEvent]) -> Vec<arkret_identifiers::EventId> {
        let mut ids = events
            .iter()
            .map(|event| event.event_id.parse().unwrap())
            .collect::<Vec<_>>();
        ids.sort_by_key(arkret_identifiers::EventId::token_bytes);
        ids
    }

    #[test]
    fn snapshot_event_set_uses_only_the_optional_signed_event_hlc() {
        let mut record = event(0, 9, &[], &[]);
        let leaf = realm_state_snapshot_event_set_leaf(&record).unwrap();
        assert_eq!(
            leaf.hlc.as_ref().map(|hlc| hlc.as_str()),
            Some("019f00000000-0000-00000001")
        );
        let mut envelope: arkret_wire::Event =
            serde_json::from_value(record.envelope.clone()).unwrap();
        envelope.hlc = None;
        let digest = envelope
            .event_digest_with_digest_suite(record.digest_suite)
            .unwrap();
        envelope.event_id =
            arkret_wire::EventId::from_event_digest(&digest.parse().unwrap()).unwrap();
        record.event_id = envelope.event_id.to_string();
        record.canonical_digest = digest;
        record.canonical_bytes =
            arkret_canonical::canonical_json_bytes(&envelope.digest_payload().unwrap()).unwrap();
        record.envelope = serde_json::to_value(envelope).unwrap();
        let first = realm_state_snapshot_event_set_leaf(&record).unwrap();
        assert!(first.hlc.is_none());
        assert!(serde_json::to_value(&first).unwrap().get("hlc").is_none());
        record.received_at += chrono::Duration::hours(24);
        let later = realm_state_snapshot_event_set_leaf(&record).unwrap();
        for algorithm in [
            arkret_state::EventSetCommitmentAlgorithm::OrderedEventIdSha256V1,
            arkret_state::EventSetCommitmentAlgorithm::MerkleEventSetV1,
        ] {
            assert_eq!(
                arkret_state::event_set_commitment(algorithm.clone(), std::slice::from_ref(&first))
                    .unwrap(),
                arkret_state::event_set_commitment(algorithm, std::slice::from_ref(&later))
                    .unwrap(),
            );
        }
    }

    #[test]
    fn snapshot_frontier_keeps_sibling_and_lower_sequence_branch_heads() {
        let root = event(0, 1, &[], &[]);
        let left = event(1, 2, &[&root], &[]);
        let right = event(1, 3, &[&root], &[]);
        assert_eq!(
            realm_state_snapshot_frontier_event_ids(&[root.clone(), left.clone(), right.clone()])
                .unwrap(),
            ids(&[&left, &right]),
        );
        let left_next = event(2, 4, &[&left], &[]);
        let mut cut = vec![root, left, right.clone(), left_next.clone()];
        let expected = ids(&[&right, &left_next]);
        assert_eq!(
            realm_state_snapshot_frontier_event_ids(&cut).unwrap(),
            expected
        );
        cut.reverse();
        assert_eq!(
            realm_state_snapshot_frontier_event_ids(&cut).unwrap(),
            expected
        );
    }

    #[test]
    fn snapshot_frontier_covers_only_explicit_prev_and_causal_references() {
        let root = event(0, 1, &[], &[]);
        let left = event(1, 2, &[&root], &[]);
        let right = event(1, 3, &[&root], &[]);
        let merge = event(2, 4, &[&left], &[&right]);
        assert_eq!(
            realm_state_snapshot_frontier_event_ids(&[root, left, right, merge.clone()]).unwrap(),
            ids(&[&merge]),
        );
        assert!(
            realm_state_snapshot_frontier_event_ids(&[])
                .unwrap()
                .is_empty()
        );
    }
}
