use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash as _, Hasher};
use std::sync::{Arc, OnceLock};

use arkret_identifiers::{Hash, RealmId, SealId};
pub use arkret_models_crypto::keys::DeviceGenerationStatus;
use serde_json::Value;
use soland_services::ServiceError;
use soland_services::events::AcceptedEvent;

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
    let principal_id =
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?;
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| ServiceError::Internal(format!("local Station id is invalid: {error}")))?;
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id.clone(),
        station_id,
    ));
    let records = state
        .event_queries()
        .accepted_events_for_actor(&actor_id.to_string())
        .await
        .map_err(|error| ServiceError::internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    generation_view_from_records(state, &actor_id.to_string(), &records).await
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
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| ServiceError::Internal(format!("local Station id is invalid: {error}")))?;
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
    let Some((target_device_authorize_event_id, authorized_generation_ref)) =
        verified_device_authorization_binding(&device)?
    else {
        return Err(ServiceError::NotFound(
            "device authorization is not active".to_owned(),
        ));
    };
    let authorize_event = state
        .event_queries()
        .canonical_event(target_device_authorize_event_id.as_str())
        .await
        .map_err(|error| ServiceError::Internal(error.to_string()))?
        .ok_or_else(|| {
            ServiceError::Conflict("accepted device authorization Event is unavailable".to_owned())
        })?;
    let event_device_id = authorize_event
        .envelope
        .pointer("/payload/device_id")
        .and_then(Value::as_str);
    if !accepted_authorization_binds_authority_tuple(
        authorize_event.actor_id.as_str(),
        authorize_event.kind.as_str(),
        event_device_id,
        principal_id.as_str(),
        station_id.as_str(),
        device_id.as_str(),
    ) {
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
    if authorized_generation_ref != target_device_generation_ref {
        return Err(ServiceError::Conflict(
            "device authorization is outside the current generation".to_owned(),
        ));
    }
    Ok(soland_storage::DeviceRevocationGateSelector {
        principal_id,
        station_id,
        device_id: device_id.to_string(),
        target_device_authorize_event_id: target_device_authorize_event_id.to_string(),
        target_device_generation_ref,
    })
}

/// `device-lifecycle.md` — the accepted `ak.device.authorize` Event a derived
/// selector points at MUST re-verify the whole local account-authority tuple
/// verbatim before the selector may be used: the same principal actor, the
/// `ak.device.authorize` kind, this exact Station, and the same
/// device. The same all-or-nothing re-check covers genesis, pairing and
/// re-anchor writers, because all three reach durable state only through this
/// selector. A selector is never partially trusted: one mismatched member is a
/// conflict, and the caller MUST NOT fall back to a placeholder Event id,
/// Station or device.
fn accepted_authorization_binds_authority_tuple(
    event_actor_id: &str,
    event_kind: &str,
    event_device_id: Option<&str>,
    principal_id: &str,
    station_id: &str,
    device_id: &str,
) -> bool {
    let expected_actor = arkret_identifiers::DidCoreId::new(principal_id.to_owned())
        .ok()
        .zip(arkret_identifiers::DidCoreId::new(station_id.to_owned()).ok())
        .map(|(principal_id, station_id)| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id))
        });
    expected_actor.is_some_and(|expected_actor| {
        serde_json::from_str::<arkret_wire::ActorId>(event_actor_id)
            .is_ok_and(|actor_id| actor_id == expected_actor)
    }) && event_kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
        && event_device_id == Some(device_id)
}

pub(crate) fn verified_device_authorization_binding(
    device: &soland_services::identity::DeviceIdentity,
) -> Result<Option<(arkret_identifiers::EventId, u64)>, ServiceError> {
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Ok(None);
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
    let authorized_generation_ref = device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its generation binding".to_owned(),
            )
        })?;
    Ok(Some((
        target_device_authorize_event_id,
        authorized_generation_ref,
    )))
}

async fn generation_view_from_records(
    _state: &AppState,
    actor_id: &str,
    records: &[AcceptedEvent],
) -> Result<Option<DeviceGenerationView>, ServiceError> {
    let Some(mut last_unconflicted) = bootstrap_generation_ref(actor_id, records) else {
        return Ok(None);
    };
    let mut status = DeviceGenerationStatus::Active;
    let mut slots = BTreeMap::<u64, Vec<&AcceptedEvent>>::new();
    for record in records.iter().filter(|record| {
        record.actor_id == actor_id && record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR
    }) {
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

fn bootstrap_generation_ref(actor_id: &str, records: &[AcceptedEvent]) -> Option<u64> {
    let bootstrap = records.iter().find(|record| {
        record.actor_id == actor_id
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
    let bootstrap = bootstrap?;
    let paired = records.iter().any(|record| {
        record.actor_id == actor_id
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
    reanchor: &AcceptedEvent,
    records: &[AcceptedEvent],
) -> Option<String> {
    let authorize = soland_services::events::paired_replacement_authorize(reanchor, records)?;
    let actor_id = serde_json::from_str::<arkret_wire::ActorId>(&reanchor.actor_id).ok()?;
    let station_id = actor_id.as_account_id()?.station_id.as_str();
    Some(format!(
        "{}\u{0}{}\u{0}{}",
        station_id, reanchor.canonical_digest, authorize.canonical_digest,
    ))
}

pub async fn authorized_generation_for_event(
    state: &AppState,
    record: &AcceptedEvent,
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
            candidate.event_id == predecessor
                && candidate.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR
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
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?,
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            ServiceError::Internal(format!("local Station id is invalid: {error}"))
        })?,
    ));
    let records = state
        .event_queries()
        .accepted_events_for_actor(&actor_id.to_string())
        .await
        .map_err(|error| ServiceError::internal(error.to_string()))?
        .into_iter()
        .map(persistence_event_record)
        .collect::<Vec<_>>();
    Ok(quarantined_generation_event_digests_from_records(
        &actor_id.to_string(),
        &records,
    ))
}

fn persistence_event_record(record: soland_services::events::AcceptedEvent) -> AcceptedEvent {
    AcceptedEvent {
        event_id: record.event_id,
        actor_id: record.actor_id,
        actor_seq: record.actor_seq,
        realm_id: record.realm_id,
        kind: record.kind,
        schema_id: record.schema_id,
        digest_suite: record.digest_suite,
        canonical_digest: record.canonical_digest,
        canonical_bytes: record.canonical_bytes,
        envelope: record.envelope,
        received_at: record.received_at,
    }
}

fn quarantined_generation_event_digests_from_records(
    actor_id: &str,
    records: &[AcceptedEvent],
) -> BTreeSet<String> {
    let mut slots = BTreeMap::<u64, Vec<&AcceptedEvent>>::new();
    for record in records.iter().filter(|record| {
        record.actor_id == actor_id && record.kind == arkret_wire::event_kind_str::DEVICE_REANCHOR
    }) {
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
        .await
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
            .await
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
            .await
            .map_err(|error| ServiceError::internal(format!("Seal lookup unavailable: {error}")))?
            .ok_or_else(|| ServiceError::internal(format!("Seal {seal_id} is missing")))?;
        pending.extend(seal.predecessor_refs);
    }
    let accepted_snapshot = accepted.iter().cloned().collect::<Vec<_>>();
    for seal_id in accepted_snapshot {
        let mut ancestors = state
            .projections()
            .seal_by_id(&seal_id)
            .await
            .map_err(|error| ServiceError::internal(format!("Seal lookup unavailable: {error}")))?
            .map(|seal| seal.predecessor_refs)
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        while let Some(ancestor) = ancestors.pop() {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            accepted.remove(&ancestor);
            if let Some(seal) =
                state
                    .projections()
                    .seal_by_id(&ancestor)
                    .await
                    .map_err(|error| {
                        ServiceError::internal(format!("Seal lookup unavailable: {error}"))
                    })?
            {
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

    fn device(
        verification_state: &str,
        payload: Value,
    ) -> soland_services::identity::DeviceIdentity {
        soland_services::identity::DeviceIdentity {
            actor_id: "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000030".to_owned(),
            display_name: None,
            verification_state: verification_state.to_owned(),
            payload,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn absent_authorization_and_malformed_verified_projection_are_distinct() {
        assert_eq!(
            verified_device_authorization_binding(&device("unverified", json!({}))).unwrap(),
            None
        );

        let malformed = verified_device_authorization_binding(&device(
            "verified",
            json!({"authorized_generation_ref": 1}),
        ));
        assert!(matches!(malformed, Err(ServiceError::SchemaViolation(_))));

        let malformed = verified_device_authorization_binding(&device(
            "verified",
            json!({
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
            }),
        ));
        assert!(matches!(malformed, Err(ServiceError::SchemaViolation(_))));
    }

    const TUPLE_PRINCIPAL: &str = "ak:did_core:webvh:z6mkfixture:alice.example";
    const TUPLE_STATION: &str = "ak:did_core:web:soland.example";
    const TUPLE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000030";

    fn binds_tuple(
        actor_id: &str,
        kind: &str,
        station_id: Option<&str>,
        device_id: Option<&str>,
    ) -> bool {
        let actor_id = station_id
            .and_then(|station_id| {
                arkret_identifiers::DidCoreId::new(actor_id.to_owned())
                    .ok()
                    .zip(arkret_identifiers::DidCoreId::new(station_id.to_owned()).ok())
            })
            .map(|(principal_id, station_id)| {
                arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id))
                    .to_string()
            })
            .unwrap_or_default();
        accepted_authorization_binds_authority_tuple(
            &actor_id,
            kind,
            device_id,
            TUPLE_PRINCIPAL,
            TUPLE_STATION,
            TUPLE_DEVICE,
        )
    }

    /// The canonical positive: every member of the authority tuple matches.
    #[test]
    fn accepted_authorization_binds_the_exact_authority_tuple() {
        assert!(binds_tuple(
            TUPLE_PRINCIPAL,
            arkret_wire::EventKind::DeviceAuthorize.as_str(),
            Some(TUPLE_STATION),
            Some(TUPLE_DEVICE),
        ));
    }

    /// One mismatched member — actor, kind, Station or device — is
    /// enough to reject. Nothing is trusted partially, and a missing member is
    /// never treated as a wildcard.
    #[test]
    fn a_single_authority_tuple_mismatch_rejects_the_selector() {
        let authorize = arkret_wire::EventKind::DeviceAuthorize.as_str();
        assert!(!binds_tuple(
            "ak:did_core:webvh:z6mkfixture:mallory.example",
            authorize,
            Some(TUPLE_STATION),
            Some(TUPLE_DEVICE),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            arkret_wire::event_kind_str::DEVICE_REANCHOR,
            Some(TUPLE_STATION),
            Some(TUPLE_DEVICE),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            Some("ak:did_core:web:other-server.example"),
            Some(TUPLE_DEVICE),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            None,
            Some(TUPLE_DEVICE)
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            Some(TUPLE_STATION),
            Some("ak:device:01904100-0000-7000-8000-000000000031"),
        ));
        assert!(!binds_tuple(
            TUPLE_PRINCIPAL,
            authorize,
            Some(TUPLE_STATION),
            None
        ));
    }

    /// The generation half of the same re-check: the projection's
    /// `authorized_generation_ref` is read back verbatim so the caller can
    /// compare it with the account's current active generation and reject an
    /// authorization that sits outside it.
    #[test]
    fn verified_projection_surfaces_the_authorized_generation_ref() {
        let binding = verified_device_authorization_binding(&device(
            "verified",
            json!({
                "device_authorize_event_id":
                    "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa",
                "authorized_generation_ref": 3
            }),
        ))
        .expect("well-formed verified projection")
        .expect("verified device carries a binding");
        assert_eq!(binding.1, 3);
    }

    fn fixture_account_actor() -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_identifiers::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::DidCoreId::new(TUPLE_STATION.to_owned()).unwrap(),
        ))
    }

    fn record(id: &str, kind: &str, digest: &str, envelope: Value) -> AcceptedEvent {
        AcceptedEvent {
            event_id: id.to_owned(),
            actor_id: fixture_account_actor().to_string(),
            actor_seq: 1,
            realm_id: None,
            kind: kind.to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: digest.to_owned(),
            canonical_bytes: Vec::new(),
            envelope,
            received_at: Utc::now(),
        }
    }

    #[test]
    fn same_height_siblings_and_causal_successors_are_all_quarantined() {
        let actor = fixture_account_actor().to_string();
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
                json!({"payload": {
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
                json!({"payload": {
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
                json!({"payload": {
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
        let quarantined = quarantined_generation_event_digests_from_records(&actor, &records);
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
