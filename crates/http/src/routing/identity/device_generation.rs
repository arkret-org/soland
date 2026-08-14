use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash as _, Hasher};
use std::sync::{Arc, OnceLock};

use arkret_identifiers::{Hash, RealmId, SealId};
pub use arkret_models_crypto::keys::DeviceGenerationStatus;
use serde_json::Value;
use soland_services::ServiceError;
use soland_services::events::CanonicalEventRecord;

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
    pub current_ref: u64,
    pub status: DeviceGenerationStatus,
}

pub async fn current_device_generation(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<DeviceGenerationView>, ServiceError> {
    let records = state
        .event_queries()
        .accepted_events_for_actor(principal_id)
        .await
        .map_err(|error| ServiceError::internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    generation_view_from_records(state, principal_id, &records).await
}

/// Resolve the exact accepted device authorization tuple used by every
/// revocation-sensitive durable write. The returned selector is derived from
/// accepted local state; it is never accepted from an authoring payload.
pub async fn active_device_revocation_gate_selector(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<soland_storage::DeviceRevocationGateSelector, ServiceError> {
    let principal_id =
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?;
    let principal_server_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| {
            ServiceError::Internal(format!("local Principal Server id is invalid: {error}"))
        })?;
    let device_id = arkret_identifiers::DeviceId::new(device_id.to_owned())
        .map_err(|error| ServiceError::SchemaViolation(format!("device id is invalid: {error}")))?;
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal_id.to_string(),
            device_id: device_id.to_string(),
        })
        .await?
        .ok_or_else(|| ServiceError::NotFound("device authorization is unavailable".to_owned()))?;
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Err(ServiceError::Conflict(
            "device authorization is not active".to_owned(),
        ));
    }
    let target_device_authorize_event_id = device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its accepted Event id".to_owned(),
            )
        })?;
    let target_device_authorize_event_id = arkret_identifiers::EventId::new(
        target_device_authorize_event_id.to_owned(),
    )
    .map_err(|error| {
        ServiceError::SchemaViolation(format!("device authorization Event id is invalid: {error}"))
    })?;
    let authorize_event = state
        .event_queries()
        .canonical_event(target_device_authorize_event_id.as_str())
        .await
        .map_err(|error| ServiceError::Internal(error.to_string()))?
        .ok_or_else(|| {
            ServiceError::Conflict("accepted device authorization Event is unavailable".to_owned())
        })?;
    let event_principal_server_id = authorize_event
        .envelope
        .get("principal_server_id")
        .and_then(Value::as_str);
    let event_device_id = authorize_event
        .envelope
        .pointer("/payload/device_id")
        .and_then(Value::as_str);
    if authorize_event.actor_id != principal_id.as_str()
        || authorize_event.kind != arkret_wire::EventKind::DeviceAuthorize.as_str()
        || event_principal_server_id != Some(principal_server_id.as_str())
        || event_device_id != Some(device_id.as_str())
    {
        return Err(ServiceError::Conflict(
            "accepted device authorization Event does not bind the current authority tuple"
                .to_owned(),
        ));
    }
    let generation = current_device_generation(state, principal_id.as_str())
        .await?
        .filter(|generation| generation.status == DeviceGenerationStatus::Active)
        .ok_or_else(|| ServiceError::Conflict("device generation is not active".to_owned()))?;
    let target_device_generation_ref = generation.current_ref;
    let authorized_generation_ref = device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its generation binding".to_owned(),
            )
        })?;
    if authorized_generation_ref != target_device_generation_ref {
        return Err(ServiceError::Conflict(
            "device authorization is outside the current generation".to_owned(),
        ));
    }
    Ok(soland_storage::DeviceRevocationGateSelector {
        principal_id: principal_id.to_string(),
        principal_server_id: principal_server_id.to_string(),
        device_id: device_id.to_string(),
        target_device_authorize_event_id: target_device_authorize_event_id.to_string(),
        target_device_generation_ref,
    })
}

async fn generation_view_from_records(
    _state: &AppState,
    principal_id: &str,
    records: &[CanonicalEventRecord],
) -> Result<Option<DeviceGenerationView>, ServiceError> {
    let Some(mut last_unconflicted) = bootstrap_generation_ref(principal_id, records) else {
        return Ok(None);
    };
    let mut status = DeviceGenerationStatus::Active;
    let mut slots = BTreeMap::<u64, Vec<&CanonicalEventRecord>>::new();
    for record in records
        .iter()
        .filter(|record| record.actor_id == principal_id && record.kind == "ak.device.reanchor")
    {
        let Some(new_generation) = record
            .envelope
            .pointer("/payload/new_device_generation")
            .and_then(Value::as_u64)
        else {
            continue;
        };
        slots.entry(new_generation).or_default().push(record);
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
            .and_then(Value::as_u64);
        let next = candidate
            .envelope
            .pointer("/payload/new_device_generation")
            .and_then(Value::as_u64);
        if previous == Some(last_unconflicted)
            && let Some(next) = next
        {
            last_unconflicted = next;
            status = DeviceGenerationStatus::Active;
        }
    }
    Ok(Some(DeviceGenerationView {
        current_ref: last_unconflicted,
        status,
    }))
}

fn bootstrap_generation_ref(principal_id: &str, records: &[CanonicalEventRecord]) -> Option<u64> {
    let bootstrap = records.iter().find(|record| {
        record.actor_id == principal_id
            && record.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && record
                .envelope
                .pointer("/payload/object/purpose")
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
        return None;
    };
    let paired = records.iter().any(|record| {
        record.actor_id == principal_id
            && record.kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
            && record
                .envelope
                .get("prev_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.len() == 1 && refs[0].as_str() == Some(bootstrap.event_id.as_str())
                })
    });
    if !paired {
        return None;
    }
    Some(1)
}

fn reanchor_unit_fingerprint(
    reanchor: &CanonicalEventRecord,
    records: &[CanonicalEventRecord],
) -> Option<String> {
    let authorize = soland_services::events::paired_replacement_authorize(reanchor, records)?;
    Some(format!(
        "{}\u{0}{}\u{0}{}",
        reanchor
            .envelope
            .pointer("/principal_server_id")
            .and_then(Value::as_str)?,
        reanchor.canonical_digest,
        authorize.canonical_digest,
    ))
}

pub async fn authorized_generation_for_event(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<Option<u64>, ServiceError> {
    let records = state
        .event_queries()
        .accepted_events_for_actor(&record.actor_id)
        .await
        .map_err(|error| ServiceError::internal(error.to_string()))?
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
            .and_then(Value::as_u64));
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
) -> Result<BTreeSet<String>, ServiceError> {
    let records = state
        .event_queries()
        .accepted_events_for_actor(principal_id)
        .await
        .map_err(|error| ServiceError::internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    Ok(quarantined_generation_event_digests_from_records(
        principal_id,
        &records,
    ))
}

fn persistence_event_record(
    record: soland_services::events::AcceptedEvent,
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
        let Some(new_generation) = record
            .envelope
            .pointer("/payload/new_device_generation")
            .and_then(Value::as_u64)
        else {
            continue;
        };
        slots.entry(new_generation).or_default().push(record);
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
            if let Some(authorize) =
                soland_services::events::paired_replacement_authorize(candidate, records)
            {
                quarantined_ids.insert(authorize.event_id.clone());
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
) -> Result<Vec<SealId>, ServiceError> {
    let quarantined = quarantined_generation_event_digests(state, principal_id).await?;
    let raw_leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .map_err(|error| ServiceError::internal(format!("Seal frontier unavailable: {error}")))?;
    if quarantined.is_empty() {
        return Ok(raw_leaves);
    }
    let quarantined = quarantined
        .into_iter()
        .map(Hash::new)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| {
            ServiceError::internal(format!("quarantined Event digest is invalid: {error}"))
        })?;
    let mut accepted = BTreeSet::new();
    let mut pending = raw_leaves;
    let mut visited = BTreeSet::new();
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        let coverage = state
            .projections()
            .seal_leaf_union_proof(std::slice::from_ref(&seal_id))
            .map_err(|error| ServiceError::internal(format!("Seal coverage unavailable: {error}")))?
            .into_iter()
            .flat_map(|proof| proof.covered_event_digests)
            .collect::<BTreeSet<_>>();
        if coverage.is_disjoint(&quarantined) {
            accepted.insert(seal_id);
            continue;
        }
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .map_err(|error| ServiceError::internal(format!("Seal lookup unavailable: {error}")))?
            .ok_or_else(|| ServiceError::internal(format!("Seal {seal_id} is missing")))?;
        pending.extend(seal.predecessor_refs);
    }
    let accepted_snapshot = accepted.iter().cloned().collect::<Vec<_>>();
    for seal_id in accepted_snapshot {
        let mut ancestors = state
            .projections()
            .seal_by_id(&seal_id)
            .map_err(|error| ServiceError::internal(format!("Seal lookup unavailable: {error}")))?
            .map(|seal| seal.predecessor_refs)
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        while let Some(ancestor) = ancestors.pop() {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            accepted.remove(&ancestor);
            if let Some(seal) = state.projections().seal_by_id(&ancestor).map_err(|error| {
                ServiceError::internal(format!("Seal lookup unavailable: {error}"))
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
            actor_id: "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
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
        let principal = "ak:did_core:webvh:z6mkfixture:alice.example";
        let reanchor_a = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let authorize_a = "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let reanchor_b = "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
        let authorize_b = "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
        let successor = "ak:event:AVWVGlDqGwJJ7DILnxJ4oq7JGdtoXGIQaK4PoiEf2yBZ";
        let higher = "ak:event:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3";
        let records = vec![
            record(
                reanchor_a,
                "ak.device.reanchor",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                json!({"principal_server_id": "ak:did_core:webvh:z6mkservera", "payload": {
                    "new_device_generation": 2,
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
                json!({"principal_server_id": "ak:did_core:webvh:z6mkserverb", "payload": {
                    "new_device_generation": 2,
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
                json!({"principal_server_id": "ak:did_core:webvh:z6mkservera", "payload": {
                    "new_device_generation": 3,
                }}),
            ),
            record(
                "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN",
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
