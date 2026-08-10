use std::sync::Arc;

use arkret_models_identity::{
    ServiceResolutionLastSeenFloor, ServiceResolutionRecord, ServiceRouteCacheEntry,
};
use arkret_wire::{Hash, ServiceId};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use soland_storage::{MonotonicRouteWrite, ServiceResolutionForkEvidence, ServiceRouteStore};

use crate::{ServiceError, ServiceResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSource {
    CurrentRecord,
    ScheduledNotice,
    RealmPeerMirror,
    ConfiguredMirror,
}

#[derive(Clone, Debug)]
pub struct VerifiedRouteCandidate {
    pub source: RouteSource,
    /// The fetcher MUST have independently verified the target proof, method
    /// history and full-id projection before returning this value.
    pub record: ServiceResolutionRecord,
}

#[async_trait]
pub trait ServiceRouteFetcher: Send + Sync {
    async fn fetch_current(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;

    async fn fetch_notice_candidate(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;

    async fn fetch_realm_peer_mirror(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;

    async fn fetch_configured_mirror(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;
}

pub struct ServiceRouteResolver {
    store: Arc<dyn ServiceRouteStore>,
    fetcher: Arc<dyn ServiceRouteFetcher>,
    cache_ttl: Duration,
}

impl ServiceRouteResolver {
    pub fn new(store: Arc<dyn ServiceRouteStore>, fetcher: Arc<dyn ServiceRouteFetcher>) -> Self {
        Self {
            store,
            fetcher,
            cache_ttl: Duration::minutes(5),
        }
    }

    pub async fn resolve(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        now: DateTime<Utc>,
        force_refresh: bool,
    ) -> ServiceResult<ServiceRouteCacheEntry> {
        if !force_refresh
            && let Some(entry) = self.store.route_cache(service_id, service_kind).await?
            && entry.is_routable_at(now)
        {
            return Ok(entry);
        }
        self.store
            .evict_route_cache(service_id, service_kind)
            .await?;

        if let Some(candidate) = self.fetcher.fetch_current(service_id, service_kind).await?
            && let Ok(entry) = self.accept(service_id, service_kind, candidate, now).await
        {
            return Ok(entry);
        }
        if let Some(candidate) = self
            .fetcher
            .fetch_notice_candidate(service_id, service_kind)
            .await?
            && let Ok(entry) = self.accept(service_id, service_kind, candidate, now).await
        {
            return Ok(entry);
        }
        if let Some(candidate) = self
            .fetcher
            .fetch_realm_peer_mirror(service_id, service_kind)
            .await?
            && let Ok(entry) = self.accept(service_id, service_kind, candidate, now).await
        {
            return Ok(entry);
        }
        if let Some(candidate) = self
            .fetcher
            .fetch_configured_mirror(service_id, service_kind)
            .await?
            && let Ok(entry) = self.accept(service_id, service_kind, candidate, now).await
        {
            return Ok(entry);
        }
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service route is fork-quarantined".to_owned(),
            ));
        }
        Err(ServiceError::NotFound(
            "verified service route unavailable".to_owned(),
        ))
    }

    async fn accept(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        candidate: VerifiedRouteCandidate,
        now: DateTime<Utc>,
    ) -> ServiceResult<ServiceRouteCacheEntry> {
        let record = candidate.record;
        let projected = arkret_wire::project_full_id_to_core_id(&record.record.full_id)
            .map(ServiceId::from)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if &projected != service_id
            || &record.record.service_id != service_id
            || record.record.service_kind != service_kind
            || now >= record.record.expires_at
            || record.record.refresh_after >= record.record.expires_at
        {
            return Err(ServiceError::SchemaViolation(
                "route candidate changes core, kind, or freshness boundary".to_owned(),
            ));
        }
        let digest = Hash::new(
            arkret_canonical::canonical_sha256(&record)
                .map_err(|error| ServiceError::Internal(error.to_string()))?,
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        if let Some(floor) = self.store.last_seen_floor(service_id, service_kind).await? {
            if record.record.record_sequence == floor.record_sequence
                && digest != floor.record_digest
            {
                self.store
                    .quarantine_fork(ServiceResolutionForkEvidence {
                        service_id: service_id.clone(),
                        service_kind: service_kind.to_owned(),
                        artifact_family: "service_resolution_record".to_owned(),
                        artifact_key: record.record.record_sequence.to_string(),
                        accepted_digest: floor.record_digest,
                        conflicting_digest: digest,
                        evidence: serde_json::json!({"source": format!("{:?}", candidate.source)}),
                        quarantined_at: now,
                    })
                    .await?;
                return Err(ServiceError::Conflict("service route fork".to_owned()));
            }
            let exact_replay = record.record.record_sequence == floor.record_sequence
                && digest == floor.record_digest;
            let exact_successor = record.record.record_sequence == floor.record_sequence + 1
                && record.record.previous_record_digest.as_ref() == Some(&floor.record_digest);
            if !exact_replay && !exact_successor {
                return Err(ServiceError::Conflict(
                    "service route gap or rollback".to_owned(),
                ));
            }
        }
        match self
            .store
            .advance_last_seen_floor(ServiceResolutionLastSeenFloor {
                service_id: service_id.clone(),
                service_kind: service_kind.to_owned(),
                record_sequence: record.record.record_sequence,
                record_digest: digest.clone(),
                verified_at: now,
            })
            .await?
        {
            MonotonicRouteWrite::Applied | MonotonicRouteWrite::Replay => {}
            MonotonicRouteWrite::Stale => {
                return Err(ServiceError::Conflict("service route rollback".to_owned()));
            }
            MonotonicRouteWrite::Conflict { .. } => {
                return Err(ServiceError::Conflict("service route fork".to_owned()));
            }
        }
        let entry = ServiceRouteCacheEntry {
            service_id: service_id.clone(),
            service_kind: service_kind.to_owned(),
            full_id: record.record.full_id,
            method_history_head: record.record.method_history_head,
            record_sequence: record.record.record_sequence,
            record_digest: digest,
            base_url: record.record.base_url,
            current_record_url: record.record.current_record_url,
            describe_digest: record.record.describe_digest,
            verified_at: now,
            refresh_after: record.record.refresh_after,
            expires_at: record.record.expires_at,
            cached_at: now,
            cache_expires_at: std::cmp::min(record.record.expires_at, now + self.cache_ttl),
        };
        self.store.put_route_cache(entry.clone()).await?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::ServiceResolutionRecordCore;
    use arkret_wire::{Base64UrlString, DidUrl, FullId, ProtocolSignature};
    use chrono::TimeZone as _;
    use parking_lot::Mutex;
    use soland_storage_memory::MemoryServiceRouteStore;

    use super::*;

    struct FakeFetcher {
        current: Option<ServiceResolutionRecord>,
        notice: Option<ServiceResolutionRecord>,
        peer: Option<ServiceResolutionRecord>,
        configured: Option<ServiceResolutionRecord>,
        calls: Mutex<Vec<RouteSource>>,
    }

    impl FakeFetcher {
        fn candidate(
            &self,
            source: RouteSource,
            record: &Option<ServiceResolutionRecord>,
        ) -> Option<VerifiedRouteCandidate> {
            self.calls.lock().push(source);
            record
                .clone()
                .map(|record| VerifiedRouteCandidate { source, record })
        }
    }

    #[async_trait]
    impl ServiceRouteFetcher for FakeFetcher {
        async fn fetch_current(
            &self,
            _: &ServiceId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(self.candidate(RouteSource::CurrentRecord, &self.current))
        }
        async fn fetch_notice_candidate(
            &self,
            _: &ServiceId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(self.candidate(RouteSource::ScheduledNotice, &self.notice))
        }
        async fn fetch_realm_peer_mirror(
            &self,
            _: &ServiceId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(self.candidate(RouteSource::RealmPeerMirror, &self.peer))
        }
        async fn fetch_configured_mirror(
            &self,
            _: &ServiceId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(self.candidate(RouteSource::ConfiguredMirror, &self.configured))
        }
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn record(full: &str, sequence: u64, previous: Option<Hash>) -> ServiceResolutionRecord {
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
        let full_id = FullId::new(full).unwrap();
        ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id: ServiceId::from(
                    arkret_wire::project_full_id_to_core_id(&full_id).unwrap(),
                ),
                service_kind: "principal_server".to_owned(),
                full_id,
                method_history_head: format!("head-{sequence}"),
                version_id: format!("v-{sequence}"),
                resolution_event_ref: format!("did-webvh-entry-{sequence}"),
                record_sequence: sequence,
                previous_record_digest: previous,
                current_record_url: "https://route.example/_arkret/open/services/id/resolution"
                    .to_owned(),
                base_url: "https://route.example/".to_owned(),
                describe_digest: hash('d'),
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new(format!("{full}#assertion-1")).unwrap(),
                created_at: issued_at,
                jws: Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        }
    }

    fn record_digest(record: &ServiceResolutionRecord) -> Hash {
        Hash::new(arkret_canonical::canonical_sha256(record).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn same_core_handover_advances_without_rebind() {
        let store = Arc::new(MemoryServiceRouteStore::new());
        let first = record("did:webvh:z6mksame:old.example", 0, None);
        let expected = first.record.service_id.clone();
        let first_fetcher = Arc::new(FakeFetcher {
            current: Some(first.clone()),
            notice: None,
            peer: None,
            configured: None,
            calls: Mutex::new(Vec::new()),
        });
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        ServiceRouteResolver::new(store.clone(), first_fetcher.clone())
            .resolve(&expected, "principal_server", now, true)
            .await
            .unwrap();
        assert_eq!(
            *first_fetcher.calls.lock(),
            vec![RouteSource::CurrentRecord]
        );

        let successor = record(
            "did:webvh:z6mksame:new.example",
            1,
            Some(record_digest(&first)),
        );
        let successor_fetcher = Arc::new(FakeFetcher {
            current: Some(successor),
            notice: None,
            peer: None,
            configured: None,
            calls: Mutex::new(Vec::new()),
        });
        let entry = ServiceRouteResolver::new(store, successor_fetcher)
            .resolve(
                &expected,
                "principal_server",
                now + Duration::seconds(1),
                true,
            )
            .await
            .unwrap();
        assert_eq!(entry.record_sequence, 1);
        assert_eq!(
            arkret_wire::project_full_id_to_core_id(&entry.full_id).unwrap(),
            expected.into()
        );
    }

    #[tokio::test]
    async fn new_core_is_rejected_and_ordered_fallback_remains_scoped() {
        let store = Arc::new(MemoryServiceRouteStore::new());
        let accepted = record("did:webvh:z6mkexpected:route.example", 0, None);
        let expected = accepted.record.service_id.clone();
        let wrong = record("did:webvh:z6mkother:route.example", 0, None);
        let fetcher = Arc::new(FakeFetcher {
            current: Some(wrong),
            notice: None,
            peer: None,
            configured: Some(accepted),
            calls: Mutex::new(Vec::new()),
        });
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        let entry = ServiceRouteResolver::new(store, fetcher.clone())
            .resolve(&expected, "principal_server", now, true)
            .await
            .unwrap();
        assert_eq!(entry.service_id, expected);
        assert_eq!(
            *fetcher.calls.lock(),
            vec![
                RouteSource::CurrentRecord,
                RouteSource::ScheduledNotice,
                RouteSource::RealmPeerMirror,
                RouteSource::ConfiguredMirror,
            ]
        );
    }
}
