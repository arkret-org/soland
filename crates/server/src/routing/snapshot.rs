use serde_json::{Value, json};

use super::*;
use crate::state::{AppState, BlobRecord, CanonicalEventRecord, DeviceInventoryRecord};
use crate::wire::now;

pub(crate) async fn snapshot_manifest_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<arkret_sdk::SnapshotManifest, crate::error::AppError> {
    let realm_id_value = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|_| crate::error::AppError::invalid_param("invalid realm_id"))?;
    {
        let realms = state.realms.lock();
        if realms.get(&realm_id_value).is_none() {
            return Err(crate::error::AppError::not_found("not found"));
        }
    }

    let mut events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?
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

    let items = events
        .iter()
        .map(snapshot_item_from_event)
        .collect::<Result<Vec<_>, _>>()?;
    let state_digest = arkret_sdk::state_digest_from_items(&items)
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    let snapshot_id = arkret_sdk::SnapshotId::new(crate::ids::generate_snapshot_id())
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    let built_chunks = arkret_sdk::build_snapshot_chunks(
        &snapshot_id,
        arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
        items.clone(),
        arkret_sdk::DEFAULT_SNAPSHOT_CHUNK_BYTES,
    )
    .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    persist_snapshot_chunk_blobs(state, realm_id, &built_chunks).await?;
    let chunk_descriptors = built_chunks
        .iter()
        .map(|chunk| chunk.descriptor.clone())
        .collect::<Vec<_>>();

    let frontier_event_ids = snapshot_frontier_event_ids(&events)?;
    let event_set_entries = events
        .iter()
        .map(|record| snapshot_event_set_leaf(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    let event_set_commitment = arkret_sdk::event_set_commitment(
        arkret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
        &event_set_entries,
        frontier_event_ids.clone(),
    )
    .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    let created_at = now();
    let timeline_hlc = snapshot_timeline_hlc(state, &events, created_at)?;
    let service_did = arkret_sdk::Did::new(state.config.service_did.clone())
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    let auth_state_digest = snapshot_auth_state_digest(
        &state.config.service_did,
        realm_id,
        &frontier_event_ids,
        created_at,
    )?;
    let verification_method = format!("{}#snapshot-key-1", state.config.service_did);
    let mut manifest = arkret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id: realm_id_value,
        reducer_profile: arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
        schema_profile_refs: vec![
            "ak.profile.core_event_store.v1".to_owned(),
            "ak.profile.principal_server_events_api.v1".to_owned(),
        ],
        state_digest,
        frontier: arkret_sdk::SnapshotFrontier {
            event_ids: frontier_event_ids.clone(),
            timeline_hlc,
        },
        event_set_commitment,
        chunks: chunk_descriptors,
        security_class: arkret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: Some(arkret_sdk::SnapshotVerificationHints {
            verification_profile: arkret_sdk::SnapshotSecurityClass::Standard,
            inclusion_proof_url: None,
            challenge_window_seconds: None,
            witness_quorum: None,
            conflict_records_digest: None,
            soft_failed_digest: None,
            quarantined_digest: None,
        }),
        created_by: service_did.clone(),
        created_at,
        authority_binding: arkret_sdk::AuthorityBinding {
            issuer: service_did,
            authority_kind: arkret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest,
            auth_frontier: frontier_event_ids,
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: arkret_sdk::DetachedJwsProof::eddsa(
            verification_method.clone(),
            arkret_sdk::Hash::new(arkret_sdk::EMPTY_SHA256_DIGEST.to_owned())
                .map_err(|error| crate::error::AppError::internal(error.to_string()))?,
            created_at,
            "header..signature".to_owned(),
        ),
    };
    arkret_sdk::sign_snapshot_manifest_ed25519(
        &mut manifest,
        state.notary_signing_key().as_ref(),
        verification_method,
        created_at,
    )
    .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    Ok(manifest)
}

async fn persist_snapshot_chunk_blobs(
    state: &AppState,
    realm_id: &str,
    chunks: &[arkret_sdk::BuiltSnapshotChunk],
) -> Result<(), crate::error::AppError> {
    for chunk in chunks {
        let blob_ref = chunk.descriptor.chunk_ref.as_str();
        let Some(sha256) = chunk.descriptor.digest.as_str().strip_prefix("sha256:") else {
            return Err(crate::error::AppError::internal(
                "snapshot chunk digest is not sha256",
            ));
        };
        let storage_key = state.object_storage.object_key_for_sha256(sha256);
        state
            .object_storage
            .put(&storage_key, chunk.canonical_bytes.clone())
            .await
            .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
        let record = BlobRecord {
            sha256: sha256.to_owned(),
            size_bytes: chunk.canonical_bytes.len() as i64,
            storage_backend: state.object_storage.backend_name().to_owned(),
            storage_key,
            media_type: "application/json".to_owned(),
            filename: None,
            realm_id: Some(realm_id.to_owned()),
            encryption: None,
            legal_hold: false,
            redacted: false,
            visibility: arkret_sdk::BlobVisibility::RealmBound,
            uploaded_by: state.config.service_did.clone(),
            created_at: now(),
        };
        state
            .persistence
            .blobs()
            .put(blob_ref, &record)
            .await
            .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    }
    Ok(())
}

fn snapshot_item_from_event(
    record: &CanonicalEventRecord,
) -> Result<arkret_sdk::SnapshotMaterializedItem, crate::error::AppError> {
    let event_id = arkret_sdk::EventId::new(record.event_id.clone())
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    Ok(arkret_sdk::SnapshotMaterializedItem {
        kind: "ak.event.accepted".to_owned(),
        id: record.event_id.clone(),
        object: json!({
            "event_id": record.event_id,
            "actor_id": record.actor_id,
            "actor_seq": record.actor_seq,
            "realm_id": record.realm_id,
            "kind": record.kind,
            "schema_id": record.schema_id,
            "canonical_digest": record.canonical_digest,
            "received_at": record.received_at,
            "envelope": record.envelope,
        }),
        source_event_id: event_id,
    })
}

fn snapshot_event_set_leaf(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<arkret_sdk::EventSetLeaf, crate::error::AppError> {
    Ok(arkret_sdk::EventSetLeaf {
        event_id: arkret_sdk::EventId::new(record.event_id.clone())
            .map_err(|error| crate::error::AppError::internal(error.to_string()))?,
        event_digest: arkret_sdk::Hash::new(record.canonical_digest.clone())
            .map_err(|error| crate::error::AppError::internal(error.to_string()))?,
        actor_id: arkret_sdk::Did::new(record.actor_id.clone())
            .map_err(|error| crate::error::AppError::internal(error.to_string()))?,
        actor_seq: record.actor_seq,
        hlc: event_hlc_or_received_at(state, record)?,
    })
}

fn snapshot_frontier_event_ids(
    events: &[CanonicalEventRecord],
) -> Result<Vec<arkret_sdk::EventId>, crate::error::AppError> {
    let mut by_actor: std::collections::BTreeMap<&str, &CanonicalEventRecord> =
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
            arkret_sdk::EventId::new(record.event_id.clone())
                .map_err(|error| crate::error::AppError::internal(error.to_string()))
        })
        .collect()
}

fn snapshot_timeline_hlc(
    state: &AppState,
    events: &[CanonicalEventRecord],
    fallback: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_sdk::Hlc, crate::error::AppError> {
    let max_received_at = events
        .iter()
        .map(|record| record.received_at)
        .max()
        .unwrap_or(fallback);
    received_at_hlc(state, max_received_at)
}

fn event_hlc_or_received_at(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<arkret_sdk::Hlc, crate::error::AppError> {
    if let Some(hlc) = record.envelope.get("hlc").and_then(Value::as_str)
        && let Ok(parsed) = arkret_sdk::Hlc::new(hlc.to_owned())
    {
        return Ok(parsed);
    }
    received_at_hlc(state, record.received_at)
}

fn received_at_hlc(
    state: &AppState,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_sdk::Hlc, crate::error::AppError> {
    let node_hash = sha256_hex(state.config.service_did.as_bytes());
    let node = &node_hash[..8];
    arkret_sdk::Hlc::new(format!("{:012x}-0000-{node}", at.timestamp_millis()))
        .map_err(|error| crate::error::AppError::internal(error.to_string()))
}

fn snapshot_auth_state_digest(
    service_did: &str,
    realm_id: &str,
    frontier_event_ids: &[arkret_sdk::EventId],
    checked_at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_sdk::Hash, crate::error::AppError> {
    let commitment = json!({
        "profile": "ak.snapshot.auth_state.issuer_local.v1",
        "issuer": service_did,
        "realm_id": realm_id,
        "frontier_event_ids": frontier_event_ids,
        "checked_at": checked_at,
    });
    let bytes = arkret_sdk::canonical::canonical_json_bytes(&commitment)
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&bytes))
        .map_err(|error| crate::error::AppError::internal(error.to_string()))
}

pub(crate) fn device_inventory_to_json(device: &DeviceInventoryRecord) -> serde_json::Value {
    json!({
        "actor": device.actor,
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

pub(crate) fn generate_invite_token(invite_id: &str, realm_id: &str, invitee: &str) -> String {
    format!(
        "ak:invite-token:{}",
        sha256_hex(format!("{invite_id}:{realm_id}:{invitee}").as_bytes())
    )
}
