use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock};

pub use arkret_core::DeviceGenerationStatus;
use arkret_core::{MoveId, RealmId, SealId};
use serde_json::Value;
use soland_storage::{CanonicalEventRecord, PersistenceError};

use crate::state::AppState;

const DEVICE_GENERATION_ADMISSION_LOCK_SHARDS: usize = 1024;

static DEVICE_GENERATION_ADMISSION_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> =
    OnceLock::new();

pub fn device_generation_admission_lock(scope_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = DEVICE_GENERATION_ADMISSION_LOCKS.get_or_init(|| {
        (0..DEVICE_GENERATION_ADMISSION_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    scope_id.hash(&mut hasher);
    locks[(hasher.finish() as usize) % DEVICE_GENERATION_ADMISSION_LOCK_SHARDS].clone()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceGenerationView {
    pub current_ref: String,
    pub status: DeviceGenerationStatus,
}

pub async fn current_device_generation(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<DeviceGenerationView>, PersistenceError> {
    let records = state
        .event_query_application()
        .accepted_events_for_actor(principal_id)
        .await
        .map_err(|error| PersistenceError::Internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    generation_view_from_records(state, principal_id, &records).await
}

async fn generation_view_from_records(
    state: &AppState,
    principal_id: &str,
    records: &[CanonicalEventRecord],
) -> Result<Option<DeviceGenerationView>, PersistenceError> {
    let Some(mut last_unconflicted) =
        bootstrap_generation_ref(state, principal_id, records).await?
    else {
        return Ok(None);
    };
    let mut status = DeviceGenerationStatus::Active;
    let mut slots = BTreeMap::<u64, Vec<&CanonicalEventRecord>>::new();
    for record in records
        .iter()
        .filter(|record| record.actor_id == principal_id && record.kind == "ak.device.reanchor")
    {
        let Some(version_id) = record
            .envelope
            .pointer("/payload/did_version_id")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(version_number) = version_id
            .split_once('-')
            .and_then(|(number, _)| number.parse::<u64>().ok())
        else {
            continue;
        };
        slots.entry(version_number).or_default().push(record);
    }
    for candidates in slots.into_values() {
        let fingerprints = candidates
            .iter()
            .filter_map(|record| reanchor_unit_fingerprint(record, records))
            .collect::<BTreeSet<_>>();
        if fingerprints.len() != 1 {
            status = DeviceGenerationStatus::Conflicted;
            continue;
        }
        let candidate = candidates[0];
        let previous = candidate
            .envelope
            .pointer("/payload/previous_device_generation")
            .and_then(Value::as_str);
        let next = candidate
            .envelope
            .pointer("/payload/new_device_generation")
            .and_then(Value::as_str);
        if previous == Some(last_unconflicted.as_str())
            && let Some(next) = next
        {
            last_unconflicted = next.to_owned();
            status = DeviceGenerationStatus::Active;
        }
    }
    Ok(Some(DeviceGenerationView {
        current_ref: last_unconflicted,
        status,
    }))
}

async fn bootstrap_generation_ref(
    state: &AppState,
    principal_id: &str,
    records: &[CanonicalEventRecord],
) -> Result<Option<String>, PersistenceError> {
    let bootstrap = records.iter().find(|record| {
        record.actor_id == principal_id
            && record.kind == arkret_core::events::EventKind::REALM_CREATE
            && record
                .envelope
                .pointer("/payload/object/fields/purpose")
                .and_then(Value::as_str)
                == Some("principal_control")
            && record
                .envelope
                .get("refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter().any(|reference| {
                        reference.get("role").and_then(Value::as_str) == Some("did_inception")
                    })
                })
    });
    let Some(bootstrap) = bootstrap else {
        return Ok(None);
    };
    let paired = records.iter().any(|record| {
        record.actor_id == principal_id
            && record.kind == arkret_core::events::EventKind::DEVICE_AUTHORIZE
            && record
                .envelope
                .get("prev_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.len() == 1 && refs[0].as_str() == Some(bootstrap.event_id.as_str())
                })
    });
    if !paired {
        return Ok(None);
    }
    let mut entries = state
        .did_application()
        .log_events(principal_id)
        .await
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    entries.sort_by_key(|entry| entry.seq);
    let is_external_enrollment_model = entries.first().is_some_and(|entry| {
        entry
            .operation
            .get("state")
            .or_else(|| entry.operation.get("did_document"))
            .and_then(|document| document.get("service"))
            .and_then(Value::as_array)
            .is_some_and(|services| {
                services.iter().any(|service| {
                    service.get("type").and_then(Value::as_str)
                        == Some(arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
                        && service
                            .get("serviceEndpoint")
                            .and_then(Value::as_str)
                            .is_some_and(|authority| authority != principal_id)
                })
            })
    });
    if !is_external_enrollment_model {
        return Ok(None);
    }
    Ok(entries
        .first()
        .and_then(|entry| entry.operation.get("versionId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

fn reanchor_unit_fingerprint(
    reanchor: &CanonicalEventRecord,
    records: &[CanonicalEventRecord],
) -> Option<String> {
    let authorize_id = reanchor
        .envelope
        .pointer("/payload/replacement_authorize_event_id")
        .and_then(Value::as_str)?;
    let authorize_digest = reanchor
        .envelope
        .pointer("/payload/replacement_authorize_digest")
        .and_then(Value::as_str)?;
    let authorize = records.iter().find(|record| {
        record.event_id == authorize_id
            && record.kind == arkret_core::events::EventKind::DEVICE_AUTHORIZE
            && record.canonical_digest == authorize_digest
            && record
                .envelope
                .get("prev_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.len() == 1 && refs[0].as_str() == Some(reanchor.event_id.as_str())
                })
    })?;
    Some(format!(
        "{}\u{0}{}\u{0}{}",
        reanchor
            .envelope
            .pointer("/payload/did_version_id")
            .and_then(Value::as_str)?,
        reanchor.canonical_digest,
        authorize.canonical_digest,
    ))
}

pub async fn authorized_generation_for_event(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<Option<String>, PersistenceError> {
    let records = state
        .event_query_application()
        .accepted_events_for_actor(&record.actor_id)
        .await
        .map_err(|error| PersistenceError::Internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    let predecessor = record
        .envelope
        .get("prev_refs")
        .and_then(Value::as_array)
        .and_then(|refs| (refs.len() == 1).then(|| refs[0].as_str()).flatten());
    if let Some(predecessor) = predecessor
        && let Some(reanchor) = records.iter().find(|candidate| {
            candidate.event_id == predecessor && candidate.kind == "ak.device.reanchor"
        })
    {
        return Ok(reanchor
            .envelope
            .pointer("/payload/new_device_generation")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned));
    }
    Ok(
        generation_view_from_records(state, &record.actor_id, &records)
            .await?
            .filter(|view| view.status == DeviceGenerationStatus::Active)
            .map(|view| view.current_ref),
    )
}

pub async fn quarantined_generation_event_digests(
    state: &AppState,
    principal_id: &str,
) -> Result<BTreeSet<String>, PersistenceError> {
    let records = state
        .event_query_application()
        .accepted_events_for_actor(principal_id)
        .await
        .map_err(|error| PersistenceError::Internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    Ok(quarantined_generation_event_digests_from_records(
        principal_id,
        &records,
    ))
}

fn persistence_event_record(
    record: soland_application::events::AcceptedEvent,
) -> CanonicalEventRecord {
    CanonicalEventRecord {
        event_id: record.event_id,
        actor_id: record.actor_id,
        actor_seq: record.actor_seq,
        realm_id: record.realm_id,
        kind: record.kind,
        schema_id: record.schema_id,
        canonical_digest: record.canonical_digest,
        canonical_bytes: record.canonical_bytes,
        envelope: record.envelope,
        received_at: record.received_at,
    }
}

fn quarantined_generation_event_digests_from_records(
    principal_id: &str,
    records: &[CanonicalEventRecord],
) -> BTreeSet<String> {
    let mut slots = BTreeMap::<u64, Vec<&CanonicalEventRecord>>::new();
    for record in records
        .iter()
        .filter(|record| record.actor_id == principal_id && record.kind == "ak.device.reanchor")
    {
        let Some(version_number) = record
            .envelope
            .pointer("/payload/did_version_id")
            .and_then(Value::as_str)
            .and_then(|version| version.split_once('-'))
            .and_then(|(number, _)| number.parse::<u64>().ok())
        else {
            continue;
        };
        slots.entry(version_number).or_default().push(record);
    }
    let mut quarantined_ids = BTreeSet::new();
    for candidates in slots.into_values() {
        let fingerprints = candidates
            .iter()
            .filter_map(|record| reanchor_unit_fingerprint(record, records))
            .collect::<BTreeSet<_>>();
        if fingerprints.len() == 1 && candidates.len() == 1 {
            continue;
        }
        for candidate in candidates {
            quarantined_ids.insert(candidate.event_id.clone());
            if let Some(authorize_id) = candidate
                .envelope
                .pointer("/payload/replacement_authorize_event_id")
                .and_then(Value::as_str)
            {
                quarantined_ids.insert(authorize_id.to_owned());
            }
        }
    }
    loop {
        let descendants = records
            .iter()
            .filter(|record| !quarantined_ids.contains(&record.event_id))
            .filter(|record| {
                record
                    .envelope
                    .get("prev_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|refs| {
                        refs.iter().any(|reference| {
                            reference
                                .as_str()
                                .is_some_and(|id| quarantined_ids.contains(id))
                        })
                    })
            })
            .map(|record| record.event_id.clone())
            .collect::<Vec<_>>();
        if descendants.is_empty() {
            break;
        }
        quarantined_ids.extend(descendants);
    }
    records
        .iter()
        .filter(|record| quarantined_ids.contains(&record.event_id))
        .map(|record| record.canonical_digest.clone())
        .collect()
}

pub async fn accepted_device_generation_seal_leaves(
    state: &AppState,
    principal_id: &str,
    realm_id: &RealmId,
) -> Result<Vec<SealId>, PersistenceError> {
    let quarantined = quarantined_generation_event_digests(state, principal_id).await?;
    let raw_leaves = state.seal_store.list_leaves(realm_id).map_err(|error| {
        PersistenceError::Internal(format!("Seal frontier unavailable: {error}"))
    })?;
    if quarantined.is_empty() {
        return Ok(raw_leaves);
    }
    let quarantined = quarantined
        .into_iter()
        .map(MoveId::new)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| {
            PersistenceError::Internal(format!("quarantined Event digest is invalid: {error}"))
        })?;
    let mut accepted = BTreeSet::new();
    let mut pending = raw_leaves;
    let mut visited = BTreeSet::new();
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        let coverage = arkret_state::leaf_union_proof(
            std::slice::from_ref(&seal_id),
            state.seal_store.as_ref(),
        )
        .map_err(|error| PersistenceError::Internal(format!("Seal coverage unavailable: {error}")))?
        .into_iter()
        .flat_map(|proof| proof.covered_event_digests)
        .collect::<BTreeSet<_>>();
        if coverage.is_disjoint(&quarantined) {
            accepted.insert(seal_id);
            continue;
        }
        let seal = state
            .seal_store
            .get(&seal_id)
            .map_err(|error| {
                PersistenceError::Internal(format!("Seal lookup unavailable: {error}"))
            })?
            .ok_or_else(|| PersistenceError::Internal(format!("Seal {seal_id} is missing")))?;
        pending.extend(seal.predecessor_refs);
    }
    let accepted_snapshot = accepted.iter().cloned().collect::<Vec<_>>();
    for seal_id in accepted_snapshot {
        let mut ancestors = state
            .seal_store
            .get(&seal_id)
            .map_err(|error| {
                PersistenceError::Internal(format!("Seal lookup unavailable: {error}"))
            })?
            .map(|seal| seal.predecessor_refs)
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        while let Some(ancestor) = ancestors.pop() {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            accepted.remove(&ancestor);
            if let Some(seal) = state.seal_store.get(&ancestor).map_err(|error| {
                PersistenceError::Internal(format!("Seal lookup unavailable: {error}"))
            })? {
                ancestors.extend(seal.predecessor_refs);
            }
        }
    }
    Ok(accepted.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn record(id: &str, kind: &str, digest: &str, envelope: Value) -> CanonicalEventRecord {
        CanonicalEventRecord {
            event_id: id.to_owned(),
            actor_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
            actor_seq: 1,
            realm_id: None,
            kind: kind.to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: digest.to_owned(),
            canonical_bytes: Vec::new(),
            envelope,
            received_at: Utc::now(),
        }
    }

    #[test]
    fn same_height_siblings_and_causal_successors_are_all_quarantined() {
        let principal = "did:webvh:z6mkfixture:alice.example";
        let reanchor_a = "ak:event:01904100-0000-7000-8000-000000000001";
        let authorize_a = "ak:event:01904100-0000-7000-8000-000000000002";
        let reanchor_b = "ak:event:01904100-0000-7000-8000-000000000003";
        let authorize_b = "ak:event:01904100-0000-7000-8000-000000000004";
        let successor = "ak:event:01904100-0000-7000-8000-000000000005";
        let higher = "ak:event:01904100-0000-7000-8000-000000000006";
        let records = vec![
            record(
                reanchor_a,
                "ak.device.reanchor",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                json!({"payload": {
                    "did_version_id": "2-A",
                    "replacement_authorize_event_id": authorize_a,
                    "replacement_authorize_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }}),
            ),
            record(
                authorize_a,
                "ak.device.authorize",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                json!({"prev_refs": [reanchor_a]}),
            ),
            record(
                reanchor_b,
                "ak.device.reanchor",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                json!({"payload": {
                    "did_version_id": "2-B",
                    "replacement_authorize_event_id": authorize_b,
                    "replacement_authorize_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }}),
            ),
            record(
                authorize_b,
                "ak.device.authorize",
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                json!({"prev_refs": [reanchor_b]}),
            ),
            record(
                successor,
                "ak.profile.update",
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                json!({"prev_refs": [authorize_a]}),
            ),
            record(
                higher,
                "ak.device.reanchor",
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                json!({"payload": {
                    "did_version_id": "3-C",
                    "replacement_authorize_event_id": "ak:event:01904100-0000-7000-8000-000000000007",
                    "replacement_authorize_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                }}),
            ),
            record(
                "ak:event:01904100-0000-7000-8000-000000000007",
                "ak.device.authorize",
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                json!({"prev_refs": [higher]}),
            ),
        ];
        let quarantined = quarantined_generation_event_digests_from_records(principal, &records);
        assert_eq!(quarantined.len(), 5);
        assert!(
            quarantined.contains(
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            )
        );
        assert!(
            !quarantined.contains(
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
        );
    }
}
