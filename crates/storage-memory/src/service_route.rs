use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::{
    ServiceResolutionArtifactKey, ServiceResolutionLastSeenFloor, ServiceResolutionRecord,
    ServiceRouteCacheEntry, ServiceRouteHandoverNotice, ServiceRouteNoticeState,
};
use arkret_wire::{Hash, RealmId, ServiceId};
use soland_storage::{
    MonotonicRouteWrite, PersistenceError, PersistenceResult, ServiceResolutionForkEvidence,
    ServiceResolutionMirrorCommit, ServiceResolutionMirrorEntry, ServiceRouteStore,
    ServiceRouteStoredKey,
};

use super::{Arc, Mutex, async_trait};

type ServiceKey = (String, String);
type NoticeKey = (String, String, String);
type TransportKey = (String, String, String);
type ArtifactKey = (String, String, String);

#[derive(Default)]
struct RouteState {
    floors: BTreeMap<ServiceKey, ServiceResolutionLastSeenFloor>,
    notices: BTreeMap<NoticeKey, ServiceRouteNoticeState>,
    mirrors_by_request: BTreeMap<TransportKey, ServiceResolutionMirrorEntry>,
    request_by_artifact: BTreeMap<ArtifactKey, TransportKey>,
    quarantine: BTreeMap<(String, String, String, String, String), ServiceResolutionForkEvidence>,
    cache: BTreeMap<ServiceKey, ServiceRouteCacheEntry>,
}

#[derive(Clone, Default)]
pub struct MemoryServiceRouteStore {
    state: Arc<Mutex<RouteState>>,
}

impl MemoryServiceRouteStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn service_key(service_id: &ServiceId, service_kind: &str) -> ServiceKey {
    (service_id.as_str().to_owned(), service_kind.to_owned())
}

fn artifact_key(key: &ServiceResolutionArtifactKey) -> PersistenceResult<String> {
    arkret_canonical::canonical_json_string(key)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn record_digest(value: &ServiceResolutionRecord) -> PersistenceResult<Hash> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn notice_digest(value: &ServiceRouteHandoverNotice) -> PersistenceResult<Hash> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn advance_mirror_sequence(
    state: &mut RouteState,
    entry: &ServiceResolutionMirrorEntry,
) -> Result<(), ServiceResolutionMirrorCommit> {
    if let Some(record) = entry.request.service_resolution_record.as_ref() {
        let digest = record_digest(record)
            .expect("validated service-resolution artifacts are canonically serializable");
        let key = service_key(&record.record.service_id, &record.record.service_kind);
        match state.floors.get(&key) {
            None if record.record.record_sequence == 0 => {}
            Some(current)
                if current.record_sequence == record.record.record_sequence
                    && current.record_digest == digest =>
            {
                return Ok(());
            }
            Some(current) if current.record_sequence == record.record.record_sequence => {
                return Err(ServiceResolutionMirrorCommit::SequenceConflict {
                    accepted_digest: current.record_digest.clone(),
                });
            }
            Some(current)
                if record.record.record_sequence == current.record_sequence + 1
                    && record.record.previous_record_digest.as_ref()
                        == Some(&current.record_digest) => {}
            _ => return Err(ServiceResolutionMirrorCommit::SequenceRejected),
        }
        state.floors.insert(
            key,
            ServiceResolutionLastSeenFloor {
                service_id: record.record.service_id.clone(),
                service_kind: record.record.service_kind.clone(),
                record_sequence: record.record.record_sequence,
                record_digest: digest,
                verified_at: entry.accepted_at,
            },
        );
        return Ok(());
    }

    if let Some(notice) = entry.request.service_route_handover_notice.as_ref() {
        let floor_key = service_key(&notice.notice.service_id, &notice.notice.service_kind);
        let Some(floor) = state.floors.get(&floor_key) else {
            return Err(ServiceResolutionMirrorCommit::SequenceRejected);
        };
        if notice.notice.from_record_sequence != floor.record_sequence
            || notice.notice.from_record_digest != floor.record_digest
        {
            return Err(ServiceResolutionMirrorCommit::SequenceRejected);
        }
        let digest = notice_digest(notice)
            .expect("validated service-route notices are canonically serializable");
        let key = (
            notice.notice.service_id.as_str().to_owned(),
            notice.notice.service_kind.clone(),
            notice.notice.handover_id.clone(),
        );
        match state.notices.get(&key) {
            None if notice.notice.notice_revision == 0 => {}
            Some(current)
                if current.notice_revision == notice.notice.notice_revision
                    && current.notice_digest == digest =>
            {
                return Ok(());
            }
            Some(current) if current.notice_revision == notice.notice.notice_revision => {
                return Err(ServiceResolutionMirrorCommit::SequenceConflict {
                    accepted_digest: current.notice_digest.clone(),
                });
            }
            Some(current)
                if notice.notice.notice_revision == current.notice_revision + 1
                    && notice.notice.previous_notice_digest.as_ref()
                        == Some(&current.notice_digest) => {}
            _ => return Err(ServiceResolutionMirrorCommit::SequenceRejected),
        }
        state.notices.insert(
            key,
            ServiceRouteNoticeState {
                service_id: notice.notice.service_id.clone(),
                service_kind: notice.notice.service_kind.clone(),
                handover_id: notice.notice.handover_id.clone(),
                notice_revision: notice.notice.notice_revision,
                notice_digest: digest,
                state: notice.notice.state,
                from_record_sequence: notice.notice.from_record_sequence,
                from_record_digest: notice.notice.from_record_digest.clone(),
                expires_at: notice.notice.expires_at,
                verified_at: entry.accepted_at,
            },
        );
        return Ok(());
    }

    Err(ServiceResolutionMirrorCommit::SequenceRejected)
}

#[async_trait]
impl ServiceRouteStore for MemoryServiceRouteStore {
    async fn list_stored_route_keys(
        &self,
        after: Option<&ServiceRouteStoredKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteStoredKey>> {
        let state = self.state.lock();
        let mut keys = BTreeSet::new();
        keys.extend(state.floors.keys().cloned());
        keys.extend(
            state
                .notices
                .keys()
                .map(|(service_id, service_kind, _)| (service_id.clone(), service_kind.clone())),
        );
        keys.extend(state.quarantine.values().map(|entry| {
            (
                entry.service_id.as_str().to_owned(),
                entry.service_kind.clone(),
            )
        }));
        keys.extend(state.cache.keys().cloned());
        let after = after.map(|key| (key.service_id.as_str(), key.service_kind.as_str()));
        keys.into_iter()
            .filter(|(service_id, service_kind)| {
                after.is_none_or(|after| (service_id.as_str(), service_kind.as_str()) > after)
            })
            .take(limit.clamp(1, 256))
            .map(|(service_id, service_kind)| {
                Ok(ServiceRouteStoredKey {
                    service_id: ServiceId::new(service_id)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                    service_kind,
                })
            })
            .collect()
    }

    async fn notice_states(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteNoticeState>> {
        let mut states = self
            .state
            .lock()
            .notices
            .values()
            .filter(|state| &state.service_id == service_id && state.service_kind == service_kind)
            .cloned()
            .collect::<Vec<_>>();
        states.sort_by(|left, right| {
            right
                .verified_at
                .cmp(&left.verified_at)
                .then_with(|| left.handover_id.cmp(&right.handover_id))
        });
        states.truncate(limit.clamp(1, 256));
        Ok(states)
    }

    async fn handover_mirror_entries(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionMirrorEntry>> {
        let mut entries = self
            .state
            .lock()
            .mirrors_by_request
            .values()
            .filter(|entry| {
                entry
                    .request
                    .service_route_handover_notice
                    .as_ref()
                    .is_some_and(|notice| {
                        &notice.notice.service_id == service_id
                            && notice.notice.service_kind == service_kind
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| right.accepted_at.cmp(&left.accepted_at));
        entries.truncate(limit.clamp(1, 256));
        Ok(entries)
    }

    async fn quarantine_evidence(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionForkEvidence>> {
        let mut entries = self
            .state
            .lock()
            .quarantine
            .values()
            .filter(|entry| &entry.service_id == service_id && entry.service_kind == service_kind)
            .cloned()
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| right.quarantined_at.cmp(&left.quarantined_at));
        entries.truncate(limit.clamp(1, 256));
        Ok(entries)
    }

    async fn last_seen_floor(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceResolutionLastSeenFloor>> {
        Ok(self
            .state
            .lock()
            .floors
            .get(&service_key(service_id, service_kind))
            .cloned())
    }

    async fn advance_last_seen_floor(
        &self,
        floor: ServiceResolutionLastSeenFloor,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        let key = service_key(&floor.service_id, &floor.service_kind);
        let mut state = self.state.lock();
        let outcome = match state.floors.get(&key) {
            Some(current) if current.record_sequence > floor.record_sequence => {
                MonotonicRouteWrite::Stale
            }
            Some(current)
                if current.record_sequence == floor.record_sequence
                    && current.record_digest == floor.record_digest =>
            {
                MonotonicRouteWrite::Replay
            }
            Some(current) if current.record_sequence == floor.record_sequence => {
                MonotonicRouteWrite::Conflict {
                    accepted_digest: current.record_digest.clone(),
                }
            }
            _ => {
                state.floors.insert(key, floor);
                MonotonicRouteWrite::Applied
            }
        };
        Ok(outcome)
    }

    async fn notice_state(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<ServiceRouteNoticeState>> {
        Ok(self
            .state
            .lock()
            .notices
            .get(&(
                service_id.as_str().to_owned(),
                service_kind.to_owned(),
                handover_id.to_owned(),
            ))
            .cloned())
    }

    async fn advance_notice_state(
        &self,
        next: ServiceRouteNoticeState,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        let key = (
            next.service_id.as_str().to_owned(),
            next.service_kind.clone(),
            next.handover_id.clone(),
        );
        let mut state = self.state.lock();
        let outcome = match state.notices.get(&key) {
            Some(current) if current.notice_revision > next.notice_revision => {
                MonotonicRouteWrite::Stale
            }
            Some(current)
                if current.notice_revision == next.notice_revision
                    && current.notice_digest == next.notice_digest =>
            {
                MonotonicRouteWrite::Replay
            }
            Some(current) if current.notice_revision == next.notice_revision => {
                MonotonicRouteWrite::Conflict {
                    accepted_digest: current.notice_digest.clone(),
                }
            }
            _ => {
                state.notices.insert(key, next);
                MonotonicRouteWrite::Applied
            }
        };
        Ok(outcome)
    }

    async fn commit_mirror(
        &self,
        entry: ServiceResolutionMirrorEntry,
    ) -> PersistenceResult<ServiceResolutionMirrorCommit> {
        entry.validate()?;
        let transport = (
            entry.source_service_id.as_str().to_owned(),
            entry.realm_id.as_str().to_owned(),
            entry.request_id.as_str().to_owned(),
        );
        let artifact = (
            entry.source_service_id.as_str().to_owned(),
            entry.realm_id.as_str().to_owned(),
            artifact_key(&entry.artifact_key)?,
        );
        let mut state = self.state.lock();
        if let Some(current) = state.mirrors_by_request.get(&transport) {
            return Ok(if current.request_digest == entry.request_digest {
                ServiceResolutionMirrorCommit::Replay(current.ack.clone())
            } else {
                ServiceResolutionMirrorCommit::TransportConflict
            });
        }
        if let Some(request_key) = state.request_by_artifact.get(&artifact) {
            let current = state
                .mirrors_by_request
                .get(request_key)
                .expect("artifact index points to mirror entry");
            return Ok(ServiceResolutionMirrorCommit::ArtifactConflict {
                accepted_digest: current.artifact_digest.clone(),
            });
        }
        if let Err(outcome) = advance_mirror_sequence(&mut state, &entry) {
            return Ok(outcome);
        }
        state
            .request_by_artifact
            .insert(artifact, transport.clone());
        state.mirrors_by_request.insert(transport, entry.clone());
        Ok(ServiceResolutionMirrorCommit::Stored(entry.ack))
    }

    async fn successor_records(
        &self,
        source_service_id: &ServiceId,
        realm_id: &RealmId,
        target_service_id: &ServiceId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionRecord>> {
        let state = self.state.lock();
        let mut records: Vec<_> = state
            .mirrors_by_request
            .values()
            .filter(|entry| {
                &entry.source_service_id == source_service_id && &entry.realm_id == realm_id
            })
            .filter_map(|entry| entry.request.service_resolution_record.as_ref())
            .filter(|record| {
                &record.record.service_id == target_service_id
                    && record.record.service_kind == service_kind
                    && record.record.record_sequence > after_sequence
            })
            .cloned()
            .collect();
        records.sort_by_key(|record| record.record.record_sequence);
        records.truncate(limit);
        Ok(records)
    }

    async fn latest_notice(
        &self,
        source_service_id: &ServiceId,
        realm_id: &RealmId,
        target_service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverNotice>> {
        Ok(self
            .state
            .lock()
            .mirrors_by_request
            .values()
            .filter(|entry| {
                &entry.source_service_id == source_service_id && &entry.realm_id == realm_id
            })
            .filter_map(|entry| entry.request.service_route_handover_notice.as_ref())
            .filter(|notice| {
                &notice.notice.service_id == target_service_id
                    && notice.notice.service_kind == service_kind
            })
            .max_by_key(|notice| notice.notice.notice_revision)
            .cloned())
    }

    async fn quarantine_fork(
        &self,
        evidence: ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()> {
        let key = (
            evidence.service_id.as_str().to_owned(),
            evidence.service_kind.clone(),
            evidence.artifact_family.clone(),
            evidence.artifact_key.clone(),
            evidence.conflicting_digest.as_str().to_owned(),
        );
        self.state.lock().quarantine.entry(key).or_insert(evidence);
        Ok(())
    }

    async fn is_quarantined(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<bool> {
        Ok(self.state.lock().quarantine.values().any(|evidence| {
            &evidence.service_id == service_id && evidence.service_kind == service_kind
        }))
    }

    async fn route_cache(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteCacheEntry>> {
        Ok(self
            .state
            .lock()
            .cache
            .get(&service_key(service_id, service_kind))
            .cloned())
    }

    async fn put_route_cache(&self, entry: ServiceRouteCacheEntry) -> PersistenceResult<()> {
        self.state
            .lock()
            .cache
            .insert(service_key(&entry.service_id, &entry.service_kind), entry);
        Ok(())
    }

    async fn evict_route_cache(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<()> {
        self.state
            .lock()
            .cache
            .remove(&service_key(service_id, service_kind));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::{ServiceResolutionPublishAckCore, ServiceResolutionRecordCore};
    use arkret_wire::{Base64UrlString, DidUrl, FullId, Hash, ProtocolSignature, RequestId};
    use chrono::{Duration, TimeZone as _, Utc};

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn record() -> ServiceResolutionRecord {
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
        let full_id = FullId::new("did:web:route.example").unwrap();
        ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id: ServiceId::from(
                    arkret_wire::project_full_id_to_core_id(&full_id).unwrap(),
                ),
                service_kind: "principal_server".to_owned(),
                full_id,
                method_history_head: "head-1".to_owned(),
                version_id: "1-head-1".to_owned(),
                resolution_event_ref: "did-web-entry-sha256:fixture".to_owned(),
                record_sequence: 0,
                previous_record_digest: None,
                current_record_url: "https://route.example/_arkret/open/services/id/resolution"
                    .to_owned(),
                base_url: "https://route.example/".to_owned(),
                describe_digest: hash('d'),
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new("did:web:route.example#assertion-1").unwrap(),
                created_at: issued_at,
                jws: Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        }
    }

    fn mirror(request_id: &str, artifact_digest: Hash) -> ServiceResolutionMirrorEntry {
        let source = ServiceId::new("ak:did_core:web:source.example").unwrap();
        let realm_id =
            RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1").unwrap();
        let request = arkret_models_identity::ServiceResolutionPublishRequest {
            request_id: RequestId::new(request_id).unwrap(),
            realm_id: realm_id.clone(),
            artifact_digest: artifact_digest.clone(),
            service_resolution_record: Some(record()),
            service_route_handover_notice: None,
        };
        let request_digest = request.canonical_digest().unwrap();
        let artifact_key = request.validate().unwrap();
        let accepted_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        let ack = arkret_models_identity::ServiceResolutionPublishAck {
            ack: ServiceResolutionPublishAckCore {
                request_id: request.request_id.clone(),
                source_service_id: source.clone(),
                receiver_service_id: ServiceId::new("ak:did_core:web:mirror.example").unwrap(),
                realm_id: realm_id.clone(),
                request_digest: request_digest.clone(),
                artifact_key: artifact_key.clone(),
                artifact_digest: artifact_digest.clone(),
                accepted_at,
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new("did:web:mirror.example#assertion-1").unwrap(),
                created_at: accepted_at,
                jws: Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        };
        ServiceResolutionMirrorEntry {
            source_service_id: source,
            realm_id,
            request_id: request.request_id.clone(),
            request_digest,
            artifact_key,
            artifact_digest,
            request,
            ack,
            accepted_at,
        }
    }

    #[tokio::test]
    async fn floor_survives_cache_eviction() {
        let store = MemoryServiceRouteStore::new();
        let record = record();
        let digest = hash('a');
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 2, 0).unwrap();
        let floor = ServiceResolutionLastSeenFloor {
            service_id: record.record.service_id.clone(),
            service_kind: record.record.service_kind.clone(),
            record_sequence: 7,
            record_digest: digest,
            verified_at: now,
        };
        assert_eq!(
            store.advance_last_seen_floor(floor.clone()).await.unwrap(),
            MonotonicRouteWrite::Applied
        );
        let restarted = store.clone();
        restarted
            .evict_route_cache(&floor.service_id, &floor.service_kind)
            .await
            .unwrap();
        assert_eq!(
            restarted
                .last_seen_floor(&floor.service_id, &floor.service_kind)
                .await
                .unwrap(),
            Some(floor)
        );
    }

    #[tokio::test]
    async fn floor_rejects_rollback_and_quarantines_same_sequence_fork() {
        let store = MemoryServiceRouteStore::new();
        let record = record();
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 2, 0).unwrap();
        let floor = ServiceResolutionLastSeenFloor {
            service_id: record.record.service_id.clone(),
            service_kind: record.record.service_kind.clone(),
            record_sequence: 7,
            record_digest: hash('a'),
            verified_at: now,
        };
        store.advance_last_seen_floor(floor.clone()).await.unwrap();
        let mut rollback = floor.clone();
        rollback.record_sequence = 6;
        assert_eq!(
            store.advance_last_seen_floor(rollback).await.unwrap(),
            MonotonicRouteWrite::Stale
        );
        let mut fork = floor.clone();
        fork.record_digest = hash('b');
        assert_eq!(
            store.advance_last_seen_floor(fork.clone()).await.unwrap(),
            MonotonicRouteWrite::Conflict {
                accepted_digest: floor.record_digest.clone()
            }
        );
        store
            .quarantine_fork(ServiceResolutionForkEvidence {
                service_id: floor.service_id.clone(),
                service_kind: floor.service_kind.clone(),
                artifact_family: "service_resolution_record".to_owned(),
                artifact_key: "7".to_owned(),
                accepted_digest: floor.record_digest,
                conflicting_digest: fork.record_digest,
                evidence: serde_json::json!({"reason": "same_sequence_different_digest"}),
                quarantined_at: now,
            })
            .await
            .unwrap();
        assert!(
            store
                .is_quarantined(&floor.service_id, &floor.service_kind)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn dual_idempotency_replays_exact_ack_and_rejects_both_conflict_classes() {
        let store = MemoryServiceRouteStore::new();
        let artifact_digest =
            Hash::new(arkret_canonical::canonical_sha256(&record()).unwrap()).unwrap();
        let first = mirror(
            "ak:request:019f0000-0000-7000-8000-000000000001",
            artifact_digest.clone(),
        );
        assert!(matches!(
            store.commit_mirror(first.clone()).await.unwrap(),
            ServiceResolutionMirrorCommit::Stored(_)
        ));
        let floor = store
            .last_seen_floor(
                &first
                    .request
                    .service_resolution_record
                    .as_ref()
                    .unwrap()
                    .record
                    .service_id,
                "principal_server",
            )
            .await
            .unwrap()
            .expect("stored ACK and floor commit atomically");
        assert_eq!(floor.record_sequence, 0);
        assert_eq!(floor.record_digest, artifact_digest);
        assert!(matches!(
            store.commit_mirror(first.clone()).await.unwrap(),
            ServiceResolutionMirrorCommit::Replay(_)
        ));
        let mut transport_conflict = first.clone();
        transport_conflict
            .request
            .service_resolution_record
            .as_mut()
            .unwrap()
            .record
            .base_url = "https://conflicting-route.example/".to_owned();
        let conflicting_artifact_digest = Hash::new(
            arkret_canonical::canonical_sha256(
                transport_conflict
                    .request
                    .service_resolution_record
                    .as_ref()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        transport_conflict.request.artifact_digest = conflicting_artifact_digest.clone();
        transport_conflict.artifact_digest = conflicting_artifact_digest.clone();
        transport_conflict.request_digest = transport_conflict.request.canonical_digest().unwrap();
        transport_conflict.ack.ack.request_digest = transport_conflict.request_digest.clone();
        transport_conflict.ack.ack.artifact_digest = conflicting_artifact_digest;
        assert_eq!(
            store.commit_mirror(transport_conflict).await.unwrap(),
            ServiceResolutionMirrorCommit::TransportConflict
        );
        let artifact_conflict = mirror(
            "ak:request:019f0000-0000-7000-8000-000000000002",
            artifact_digest,
        );
        assert!(matches!(
            store.commit_mirror(artifact_conflict).await.unwrap(),
            ServiceResolutionMirrorCommit::ArtifactConflict { .. }
        ));
    }

    #[tokio::test]
    async fn admin_reads_are_bounded_sorted_and_local_only() {
        let store = MemoryServiceRouteStore::new();
        let route = record();
        let service_id = route.record.service_id.clone();
        let service_kind = route.record.service_kind.clone();
        let now = route.record.issued_at;
        store
            .advance_last_seen_floor(ServiceResolutionLastSeenFloor {
                service_id: service_id.clone(),
                service_kind: service_kind.clone(),
                record_sequence: 0,
                record_digest: hash('a'),
                verified_at: now,
            })
            .await
            .unwrap();
        store
            .quarantine_fork(ServiceResolutionForkEvidence {
                service_id: service_id.clone(),
                service_kind: service_kind.clone(),
                artifact_family: "service_resolution_record".to_owned(),
                artifact_key: "0".to_owned(),
                accepted_digest: hash('a'),
                conflicting_digest: hash('b'),
                evidence: serde_json::json!({"source": "verified_test"}),
                quarantined_at: now,
            })
            .await
            .unwrap();

        let keys = store.list_stored_route_keys(None, 1).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].service_id, service_id);
        assert_eq!(keys[0].service_kind, service_kind);
        let quarantine = store
            .quarantine_evidence(&service_id, &service_kind, 1)
            .await
            .unwrap();
        assert_eq!(quarantine.len(), 1);
        assert_eq!(quarantine[0].evidence["source"], "verified_test");
    }
}
