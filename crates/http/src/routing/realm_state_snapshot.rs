use serde_json::{Value, json};
use soland_services::delivery::BlobState as BlobRecord;
use soland_services::events::AcceptedEvent;

use super::*;
use crate::state::AppState;
use crate::wire::now;

pub(crate) async fn realm_state_snapshot_manifest_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<arkret_state::RealmRealmStateSnapshotStateManifest, soland_http::error::AppError> {
    let realm_id_value = arkret_identifiers::RealmId::new(realm_id.to_owned())
        .map_err(|_| soland_http::error::AppError::param_invalid("invalid realm_id"))?;
    {
        let realms = state.realm_directory().snapshot();
        if realms.get(&realm_id_value).is_none() {
            return Err(soland_http::error::AppError::not_found("not found"));
        }
    }

    let mut events = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| record.realm_id.as_deref() == Some(realm_id))
        .collect::<Vec<_>>();
    events.sort_by(|a, b| {
        (a.actor_id.as_str(), a.actor_seq, a.event_id.as_str()).cmp(&(
            b.actor_id.as_str(),
            b.actor_seq,
            b.event_id.as_str(),
        ))
    });

    let (items, conflict_records) = reducer_cell_items(state, &realm_id_value).await?;
    let state_digest = arkret_state::state_digest_from_items(&items)
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
        .map(|record| realm_state_snapshot_event_set_leaf(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    let event_set_commitment = arkret_state::event_set_commitment(
        arkret_state::EventSetCommitmentAlgorithm::MerkleEventSetV1,
        &event_set_entries,
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let created_at = now();
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
    let mut manifest = arkret_state::RealmRealmStateSnapshotStateManifest {
        id: realm_state_snapshot_id,
        realm_id: realm_id_value,
        reducer_profile: arkret_wire::CORE_REDUCER_PROFILE.to_owned(),
        schema_profile_refs: vec![
            arkret_wire::ProfileId::CORE_EVENT_STORE_V1.to_owned(),
            arkret_wire::ProfileId::STATION_EVENTS_API_V1.to_owned(),
        ],
        state_digest,
        frontier: arkret_state::RealmRealmStateSnapshotStateFrontier {
            event_ids: frontier_event_ids.clone(),
            timeline_hlc,
        },
        event_set_commitment,
        chunks: chunk_descriptors,
        security_class: arkret_state::RealmRealmStateSnapshotStateSecurityClass::Standard,
        verification_hints: Some(
            arkret_state::RealmRealmStateSnapshotStateVerificationHints {
                verification_profile:
                    arkret_state::RealmRealmStateSnapshotStateSecurityClass::Standard,
                inclusion_proof_url: None,
                challenge_window_seconds: None,
                conflict_records_digest,
                soft_failed_digest: None,
                quarantined_digest: None,
                erasure_stubs_digest: None,
            },
        ),
        created_by: arkret_wire::ActorId::service(service_id.clone()),
        created_at,
        authority_binding: arkret_state::AuthorityBinding {
            authority_kind:
                arkret_state::RealmRealmStateSnapshotStateAuthorityKind::RealmPolicySnapshotIssuer,
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
    chunks: &[arkret_state::BuiltRealmStateRealmRealmStateSnapshotStateChunk],
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

/// The reducer cells behind `items[]` (`realm-state-snapshot-schema.md` section 3).
///
/// A snapshot ships the reducer's own state, never rendered objects: every
/// written Realm-scope cell under the Seal leaves covering the frontier, with
/// the `event-auth-state-resolution.md` section 6.2.1 state object of its
/// registered lattice — the complete active head set for a `cas_register`
/// cell, the joined value for every other lattice. Section 4 then makes each
/// snapshot leaf byte-identical to that cell's `state_root` leaf.
///
/// Membership follows section 6.2.1 rather than a settled value: a CAS cell is
/// in as soon as it has one active head (so a slot released to `null` and a
/// cell in `⊥` both appear), any other cell is in when its join is a
/// determinate value, and only a never-written cell is absent. A non-CAS cell
/// whose join is `⊥` has no leaf; it is returned as a `bottom_cell` conflict
/// record so a restoring receiver fails closed on it instead of reading it as
/// never written.
///
/// A Realm with no Seal yet has no governance view to materialize and
/// contributes no cells. Data-plane cells are not yet exported here: this
/// Station's reducer keeps them in projection tables rather than in the cell
/// store the Seal view reads, which the cross-repo task tracks.
async fn reducer_cell_items(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
) -> Result<
    (
        Vec<arkret_state::RealmRealmStateSnapshotStateMaterializedItem>,
        Vec<arkret_state::RealmRealmStateSnapshotStateConflictRecord>,
    ),
    soland_http::error::AppError,
> {
    let internal =
        |error: &dyn std::fmt::Display| soland_http::error::AppError::internal(error.to_string());
    let leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .await
        .map_err(|error| internal(&error))?;
    if leaves.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let values = state
        .projections()
        .effective_state_at(&leaves, realm_id)
        .await
        .map_err(|error| internal(&error))?;
    let heads_by_cell = state
        .projections()
        .effective_cas_heads_at(&leaves, realm_id)
        .await
        .map_err(|error| internal(&error))?;

    let mut items = Vec::with_capacity(values.len() + heads_by_cell.len());
    let mut conflict_records = Vec::new();
    for (cell, cell_state) in values {
        if arkret_wire::is_registered_cas_register_cell(cell.as_str()) {
            // A CAS cell's state is its head set, taken from the identity half
            // below; its joined value here would lose the write identities.
            continue;
        }
        match cell_state {
            arkret_state::lattice::CellState::Value(value) => items.push(
                arkret_state::RealmRealmStateSnapshotStateMaterializedItem::value(cell, value)
                    .map_err(|error| internal(&error))?,
            ),
            arkret_state::lattice::CellState::Bottom(_) => conflict_records.push(
                arkret_state::RealmRealmStateSnapshotStateConflictRecord::BottomCell {
                    cell_ref: cell,
                },
            ),
        }
    }
    for (cell, heads) in heads_by_cell {
        if heads.is_empty() {
            continue;
        }
        items.push(
            arkret_state::RealmRealmStateSnapshotStateMaterializedItem::cas_cell(cell, &heads)
                .map_err(|error| internal(&error))?,
        );
    }
    Ok((items, conflict_records))
}

fn realm_state_snapshot_event_set_leaf(
    state: &AppState,
    record: &AcceptedEvent,
) -> Result<arkret_state::EventSetLeaf, soland_http::error::AppError> {
    Ok(arkret_state::EventSetLeaf {
        event_id: arkret_identifiers::EventId::new(record.event_id.clone())
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        event_digest: arkret_identifiers::Hash::new(record.canonical_digest.clone())
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        actor_id: serde_json::from_str::<arkret_wire::ActorId>(&record.actor_id)
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        actor_seq: record.actor_seq,
        hlc: event_hlc_or_received_at(state, record)?,
    })
}

fn realm_state_snapshot_frontier_event_ids(
    events: &[AcceptedEvent],
) -> Result<Vec<arkret_identifiers::EventId>, soland_http::error::AppError> {
    let mut by_actor: std::collections::BTreeMap<&str, &AcceptedEvent> =
        std::collections::BTreeMap::new();
    for record in events {
        by_actor
            .entry(record.actor_id.as_str())
            .and_modify(|current| {
                if (record.actor_seq, record.event_id.as_str())
                    > (current.actor_seq, current.event_id.as_str())
                {
                    *current = record;
                }
            })
            .or_insert(record);
    }
    by_actor
        .values()
        .map(|record| {
            arkret_identifiers::EventId::new(record.event_id.clone())
                .map_err(|error| soland_http::error::AppError::internal(error.to_string()))
        })
        .collect()
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

fn event_hlc_or_received_at(
    state: &AppState,
    record: &AcceptedEvent,
) -> Result<arkret_identifiers::Hlc, soland_http::error::AppError> {
    if let Some(hlc) = record.envelope.get("hlc").and_then(Value::as_str)
        && let Ok(parsed) = arkret_identifiers::Hlc::new(hlc.to_owned())
    {
        return Ok(parsed);
    }
    received_at_hlc(state, record.received_at)
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

pub(crate) fn device_inventory_to_json(
    device: &soland_services::identity::DeviceIdentity,
) -> serde_json::Value {
    json!({
        "actor": device.actor_id,
        "device_id": device.device_id,
        "display_name": device.display_name,
        "verification": device.verification_state,
        "verification_state": device.verification_state,
        "payload": device.payload,
        "created_at": device.created_at,
        "updated_at": device.updated_at,
        "revoked_at": device.revoked_at,
    })
}

pub(crate) fn generate_invite_token(invite_id: &str, realm_id: &str, invitee_id: &str) -> String {
    format!(
        "ak:invite-token:{}",
        sha256_hex(format!("{invite_id}:{realm_id}:{invitee_id}").as_bytes())
    )
}
