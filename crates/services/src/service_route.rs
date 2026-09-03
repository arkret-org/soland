use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_identity::{
    ServiceResolutionCarrier, ServiceResolutionLastSeenFloor, ServiceResolutionRecord,
    ServiceRouteCacheEntry,
};
use arkret_wire::{DidCoreId, Hash, TrustDomainId};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use soland_storage::{MonotonicRouteWrite, ServiceResolutionForkEvidence, ServiceRouteStore};

use crate::{ServiceError, ServiceResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSource {
    CurrentRecord,
    ScheduledNotice,
}

#[derive(Clone, Debug)]
pub struct VerifiedRouteCandidate {
    pub source: RouteSource,
    /// The fetcher MUST have independently verified the target proof, method
    /// history and DID projection before returning this value.
    pub record: ServiceResolutionRecord,
    /// Dynamic endpoint metadata independently fetched from the authenticated
    /// record's base URL and reverse-bound to its stable describe projection.
    pub description: VerifiedServiceDescribeMetadata,
}

#[derive(Clone, Debug)]
pub struct VerifiedServiceDescribeMetadata {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub service_resolution: arkret_models_identity::ResolutionCommitment,
    pub http_json_base_url: String,
    pub route_binding_digest: Hash,
    pub trust_domain: TrustDomainId,
    pub protocol_version: String,
}

/// Fully usable implementation-local route. The signed cache entry remains
/// the durable route coordinate; describe metadata is a short-lived second-hop
/// confirmation and never becomes an authorization root.
#[derive(Clone, Debug)]
pub struct ResolvedServiceRoute {
    pub cache_entry: ServiceRouteCacheEntry,
    pub trust_domain: TrustDomainId,
    pub protocol_version: String,
    pub describe_verified_at: DateTime<Utc>,
    pub describe_cache_expires_at: DateTime<Utc>,
}

impl ResolvedServiceRoute {
    #[must_use]
    pub fn is_routable_at(&self, now: DateTime<Utc>) -> bool {
        self.cache_entry.is_routable_at(now) && now < self.describe_cache_expires_at
    }

    pub fn require_trust_domain(&self, expected: Option<&str>) -> ServiceResult<()> {
        if let Some(expected) = expected
            && self.trust_domain.as_str() != expected
        {
            return Err(ServiceError::Conflict(
                "verified ServiceDescribe trust_domain conflicts with accepted binding".to_owned(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
pub trait ServiceRouteFetcher: Send + Sync {
    async fn fetch_carrier(
        &self,
        _carrier: &ServiceResolutionCarrier,
        _service_id: &DidCoreId,
        _service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(None)
    }

    async fn fetch_current(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;

    async fn fetch_notice_candidate(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;
}

pub struct ServiceRouteResolver {
    store: Arc<dyn ServiceRouteStore>,
    fetcher: Arc<dyn ServiceRouteFetcher>,
    cache_ttl: Duration,
    describe_cache_ttl: Duration,
    resolved_routes: parking_lot::Mutex<BTreeMap<(String, String), ResolvedServiceRoute>>,
}

impl ServiceRouteResolver {
    pub fn new(store: Arc<dyn ServiceRouteStore>, fetcher: Arc<dyn ServiceRouteFetcher>) -> Self {
        Self {
            store,
            fetcher,
            cache_ttl: Duration::minutes(5),
            describe_cache_ttl: Duration::minutes(1),
            resolved_routes: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }

    /// Resolve both the authenticated signed route and its short-lived
    /// role-scoped ServiceDescribe confirmation.
    pub async fn resolve_route(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        force_refresh: bool,
    ) -> ServiceResult<ResolvedServiceRoute> {
        let cached_route = if force_refresh {
            None
        } else {
            self.resolved_routes
                .lock()
                .get(&(service_id.to_string(), service_kind.to_owned()))
                .cloned()
        };
        if let Some(route) = cached_route
            && route.is_routable_at(now)
            && !self.store.is_quarantined(service_id, service_kind).await?
            && self
                .store
                .route_cache(service_id, service_kind)
                .await?
                .is_some_and(|entry| {
                    entry.record_digest == route.cache_entry.record_digest
                        && entry.is_routable_at(now)
                })
        {
            return Ok(route);
        }
        // A durable route cache alone cannot satisfy a second-hop request
        // after restart or describe expiry. Re-fetch the authenticated current
        // record so its base URL can be confirmed again.
        let entry = self.resolve(service_id, service_kind, now, true).await?;
        let route = self
            .resolved_routes
            .lock()
            .get(&(service_id.to_string(), service_kind.to_owned()))
            .cloned()
            .ok_or_else(|| {
                ServiceError::Internal(
                    "verified route accepted without ServiceDescribe metadata".to_owned(),
                )
            })?;
        if route.cache_entry.record_digest != entry.record_digest || !route.is_routable_at(now) {
            return Err(ServiceError::Conflict(
                "ServiceDescribe metadata does not match the accepted route".to_owned(),
            ));
        }
        Ok(route)
    }

    pub async fn resolve(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        force_refresh: bool,
    ) -> ServiceResult<ServiceRouteCacheEntry> {
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service route is fork-quarantined".to_owned(),
            ));
        }
        if !force_refresh
            && let Some(entry) = self.store.route_cache(service_id, service_kind).await?
            && entry.is_routable_at(now)
        {
            return Ok(entry);
        }
        self.resolved_routes
            .lock()
            .remove(&(service_id.to_string(), service_kind.to_owned()));
        // Keep the authenticated locator for refresh and retry, but make the
        // previous route unusable until a fresh record has been verified.
        if let Some(mut entry) = self.store.route_cache(service_id, service_kind).await? {
            entry.cache_expires_at = std::cmp::min(entry.cache_expires_at, now);
            self.store.put_route_cache(entry).await?;
        }

        if let Some(candidate) = self.fetcher.fetch_current(service_id, service_kind).await? {
            match self.accept(service_id, service_kind, candidate, now).await {
                Ok(entry) => return Ok(entry),
                Err(ServiceError::SchemaViolation(_)) => {}
                Err(error) => return Err(error),
            }
        }
        if let Some(candidate) = self
            .fetcher
            .fetch_notice_candidate(service_id, service_kind)
            .await?
        {
            match self.accept(service_id, service_kind, candidate, now).await {
                Ok(entry) => return Ok(entry),
                Err(ServiceError::SchemaViolation(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Err(ServiceError::NotFound(
            "verified service route unavailable".to_owned(),
        ))
    }

    /// Resolve an exact carrier retained by the business authorization that
    /// triggered this send. This is the contact/invite path where the carrier
    /// is not yet present in a Realm member projection.
    pub async fn resolve_carrier(
        &self,
        carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<ServiceRouteCacheEntry> {
        let candidate = self
            .fetcher
            .fetch_carrier(carrier, service_id, service_kind)
            .await?
            .ok_or_else(|| {
                ServiceError::NotFound("verified service carrier unavailable".to_owned())
            })?;
        self.accept(service_id, service_kind, candidate, now).await
    }

    async fn accept(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        candidate: VerifiedRouteCandidate,
        now: DateTime<Utc>,
    ) -> ServiceResult<ServiceRouteCacheEntry> {
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service route is fork-quarantined".to_owned(),
            ));
        }
        let description = candidate.description;
        let record = candidate.record;
        let projected = arkret_wire::project_did_to_core_id(&record.record.did)
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
        validate_describe_metadata(&record, &description, service_id, service_kind)?;
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
                self.store
                    .evict_route_cache(service_id, service_kind)
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
        let floor = ServiceResolutionLastSeenFloor {
            service_id: service_id.clone(),
            service_kind: service_kind.to_owned(),
            record_sequence: record.record.record_sequence,
            record_digest: digest.clone(),
            verified_at: now,
        };
        let entry = ServiceRouteCacheEntry {
            service_id: service_id.clone(),
            service_kind: service_kind.to_owned(),
            did: record.record.did,
            method_history_head: record.record.method_history_head,
            version_id: record.record.version_id,
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
        match self.store.publish_route_cache(floor, entry.clone()).await? {
            MonotonicRouteWrite::Applied | MonotonicRouteWrite::Replay => {}
            MonotonicRouteWrite::Stale => {
                return Err(ServiceError::Conflict("service route rollback".to_owned()));
            }
            MonotonicRouteWrite::Conflict { accepted_digest } => {
                self.store
                    .quarantine_fork(ServiceResolutionForkEvidence {
                        service_id: service_id.clone(),
                        service_kind: service_kind.to_owned(),
                        artifact_family: "service_resolution_record".to_owned(),
                        artifact_key: entry.record_sequence.to_string(),
                        accepted_digest,
                        conflicting_digest: entry.record_digest.clone(),
                        evidence: serde_json::json!({"source": format!("{:?}", candidate.source), "race": true}),
                        quarantined_at: now,
                    })
                    .await?;
                self.store
                    .evict_route_cache(service_id, service_kind)
                    .await?;
                return Err(ServiceError::Conflict("service route fork".to_owned()));
            }
        }
        let describe_cache_expires_at = std::cmp::min(
            entry.cache_expires_at,
            std::cmp::min(entry.expires_at, now + self.describe_cache_ttl),
        );
        self.resolved_routes.lock().insert(
            (service_id.to_string(), service_kind.to_owned()),
            ResolvedServiceRoute {
                cache_entry: entry.clone(),
                trust_domain: description.trust_domain,
                protocol_version: description.protocol_version,
                describe_verified_at: now,
                describe_cache_expires_at,
            },
        );
        Ok(entry)
    }
}

fn validate_describe_metadata(
    record: &ServiceResolutionRecord,
    description: &VerifiedServiceDescribeMetadata,
    service_id: &DidCoreId,
    service_kind: &str,
) -> ServiceResult<()> {
    if &description.service_id != service_id
        || description.service_kind != service_kind
        || description.service_resolution.did != record.record.did
        || description.service_resolution.method_history_head != record.record.method_history_head
        || description.service_resolution.version_id != record.record.version_id
        || description.http_json_base_url != record.record.base_url
        || description.route_binding_digest != record.record.describe_digest
    {
        return Err(ServiceError::SchemaViolation(
            "ServiceDescribe does not reverse-bind to the signed service resolution record"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::ServiceResolutionRecordCore;
    use arkret_wire::{Base64UrlString, Did, DidUrl, ProtocolSignature};
    use chrono::TimeZone as _;
    use parking_lot::Mutex;
    use soland_storage_postgres::PgServiceRouteStore;
    use soland_storage_postgres::test_database::TestDatabase;

    use super::*;

    struct FakeFetcher {
        current: Option<ServiceResolutionRecord>,
        notice: Option<ServiceResolutionRecord>,
        calls: Mutex<Vec<RouteSource>>,
    }

    impl FakeFetcher {
        fn candidate(
            &self,
            source: RouteSource,
            record: &Option<ServiceResolutionRecord>,
        ) -> Option<VerifiedRouteCandidate> {
            self.calls.lock().push(source);
            record.clone().map(|record| VerifiedRouteCandidate {
                source,
                description: description(&record),
                record,
            })
        }
    }

    #[async_trait]
    impl ServiceRouteFetcher for FakeFetcher {
        async fn fetch_current(
            &self,
            _: &DidCoreId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(self.candidate(RouteSource::CurrentRecord, &self.current))
        }
        async fn fetch_notice_candidate(
            &self,
            _: &DidCoreId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(self.candidate(RouteSource::ScheduledNotice, &self.notice))
        }
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn record(full: &str, sequence: u64, previous: Option<Hash>) -> ServiceResolutionRecord {
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
        let did = Did::new(full).unwrap();
        ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
                service_kind: "station".to_owned(),
                did,
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

    struct RetainedLocatorFetcher {
        store: Arc<PgServiceRouteStore>,
        current: Option<ServiceResolutionRecord>,
        now: DateTime<Utc>,
    }

    #[async_trait]
    impl ServiceRouteFetcher for RetainedLocatorFetcher {
        async fn fetch_current(
            &self,
            service_id: &DidCoreId,
            service_kind: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            let locator = self
                .store
                .route_cache(service_id, service_kind)
                .await?
                .expect("refresh must retain its authenticated locator");
            assert!(!locator.is_routable_at(self.now));
            assert_eq!(
                locator.current_record_url,
                "https://route.example/_arkret/open/services/id/resolution"
            );
            Ok(self.current.clone().map(|record| VerifiedRouteCandidate {
                source: RouteSource::CurrentRecord,
                description: description(&record),
                record,
            }))
        }

        async fn fetch_notice_candidate(
            &self,
            _: &DidCoreId,
            _: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn route_refresh_failure_retains_locator_without_reusing_stale_authority() {
        let database = TestDatabase::lease().await;
        let store = Arc::new(PgServiceRouteStore {
            pool: database.pool(),
        });
        let first = record("did:webvh:z6mkrefresh:route.example", 0, None);
        let expected = first.record.service_id.clone();
        let now = first.record.issued_at + Duration::minutes(1);
        ServiceRouteResolver::new(
            store.clone(),
            Arc::new(FakeFetcher {
                current: Some(first.clone()),
                notice: None,
                calls: Mutex::new(Vec::new()),
            }),
        )
        .resolve_route(&expected, "station", now, true)
        .await
        .unwrap();

        let retry_at = now + Duration::seconds(1);
        let unavailable = ServiceRouteResolver::new(
            store.clone(),
            Arc::new(RetainedLocatorFetcher {
                store: store.clone(),
                current: None,
                now: retry_at,
            }),
        );
        assert!(
            unavailable
                .resolve_route(&expected, "station", retry_at, true)
                .await
                .is_err()
        );
        assert!(
            unavailable
                .resolve_route(&expected, "station", retry_at, false)
                .await
                .is_err()
        );
        assert!(
            !store
                .route_cache(&expected, "station")
                .await
                .unwrap()
                .unwrap()
                .is_routable_at(retry_at)
        );

        let successor = record(
            "did:webvh:z6mkrefresh:route.example",
            1,
            Some(record_digest(&first)),
        );
        let restarted = ServiceRouteResolver::new(
            store.clone(),
            Arc::new(RetainedLocatorFetcher {
                store,
                current: Some(successor),
                now: retry_at,
            }),
        );
        let refreshed = restarted
            .resolve_route(&expected, "station", retry_at, false)
            .await
            .unwrap();
        assert_eq!(refreshed.cache_entry.record_sequence, 1);
        assert!(refreshed.is_routable_at(retry_at));
    }

    fn description(record: &ServiceResolutionRecord) -> VerifiedServiceDescribeMetadata {
        VerifiedServiceDescribeMetadata {
            service_id: record.record.service_id.clone(),
            service_kind: record.record.service_kind.clone(),
            service_resolution: arkret_models_identity::ResolutionCommitment {
                did: record.record.did.clone(),
                method_history_head: record.record.method_history_head.clone(),
                version_id: record.record.version_id.clone(),
            },
            http_json_base_url: record.record.base_url.clone(),
            route_binding_digest: record.record.describe_digest.clone(),
            trust_domain: TrustDomainId::new("ak:trust_domain:route.example").unwrap(),
            protocol_version: "1".to_owned(),
        }
    }

    #[tokio::test]
    async fn same_core_handover_advances_without_rebind() {
        let database = TestDatabase::lease().await;
        let store = Arc::new(PgServiceRouteStore {
            pool: database.pool(),
        });
        let first = record("did:webvh:z6mksame:old.example", 0, None);
        let expected = first.record.service_id.clone();
        let first_fetcher = Arc::new(FakeFetcher {
            current: Some(first.clone()),
            notice: None,
            calls: Mutex::new(Vec::new()),
        });
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        ServiceRouteResolver::new(store.clone(), first_fetcher.clone())
            .resolve(&expected, "station", now, true)
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
            calls: Mutex::new(Vec::new()),
        });
        let entry = ServiceRouteResolver::new(store, successor_fetcher)
            .resolve(&expected, "station", now + Duration::seconds(1), true)
            .await
            .unwrap();
        assert_eq!(entry.record_sequence, 1);
        assert_eq!(
            arkret_wire::project_did_to_core_id(&entry.did).unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn new_core_is_rejected_without_an_authorized_route_source() {
        let database = TestDatabase::lease().await;
        let store = Arc::new(PgServiceRouteStore {
            pool: database.pool(),
        });
        let accepted = record("did:webvh:z6mkexpected:route.example", 0, None);
        let expected = accepted.record.service_id.clone();
        let wrong = record("did:webvh:z6mkother:route.example", 0, None);
        let fetcher = Arc::new(FakeFetcher {
            current: Some(wrong),
            notice: None,
            calls: Mutex::new(Vec::new()),
        });
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        let error = ServiceRouteResolver::new(store, fetcher.clone())
            .resolve(&expected, "station", now, true)
            .await
            .unwrap_err();
        assert!(matches!(error, ServiceError::NotFound(_)));
        assert_eq!(
            *fetcher.calls.lock(),
            vec![RouteSource::CurrentRecord, RouteSource::ScheduledNotice]
        );
    }

    #[tokio::test]
    async fn quarantine_is_checked_before_disposable_cache() {
        let database = TestDatabase::lease().await;
        let store = Arc::new(PgServiceRouteStore {
            pool: database.pool(),
        });
        let accepted = record("did:webvh:z6mkquarantined:route.example", 0, None);
        let expected = accepted.record.service_id.clone();
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        let seed_fetcher = Arc::new(FakeFetcher {
            current: Some(accepted.clone()),
            notice: None,
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ServiceRouteResolver::new(store.clone(), seed_fetcher.clone());
        resolver
            .resolve_route(&expected, "station", now, true)
            .await
            .unwrap();
        store
            .quarantine_fork(ServiceResolutionForkEvidence {
                service_id: expected.clone(),
                service_kind: "station".to_owned(),
                artifact_family: "service_resolution_record".to_owned(),
                artifact_key: "0".to_owned(),
                accepted_digest: record_digest(&accepted),
                conflicting_digest: hash('f'),
                evidence: serde_json::json!({"test": "cache_must_not_bypass_quarantine"}),
                quarantined_at: now,
            })
            .await
            .unwrap();
        let error = resolver
            .resolve_route(&expected, "station", now, false)
            .await
            .unwrap_err();
        assert!(matches!(error, ServiceError::Conflict(_)));
        assert_eq!(seed_fetcher.calls.lock().len(), 1);
    }

    #[tokio::test]
    async fn fork_fails_closed_without_trying_the_notice_source() {
        let database = TestDatabase::lease().await;
        let store = Arc::new(PgServiceRouteStore {
            pool: database.pool(),
        });
        let accepted = record("did:webvh:z6mkforked:old.example", 0, None);
        let expected = accepted.record.service_id.clone();
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        let seed_fetcher = Arc::new(FakeFetcher {
            current: Some(accepted.clone()),
            notice: None,
            calls: Mutex::new(Vec::new()),
        });
        ServiceRouteResolver::new(store.clone(), seed_fetcher)
            .resolve(&expected, "station", now, true)
            .await
            .unwrap();

        let fork = record("did:webvh:z6mkforked:new.example", 0, None);
        let fetcher = Arc::new(FakeFetcher {
            current: Some(fork),
            notice: None,
            calls: Mutex::new(Vec::new()),
        });
        let error = ServiceRouteResolver::new(store.clone(), fetcher.clone())
            .resolve(&expected, "station", now + Duration::seconds(1), true)
            .await
            .unwrap_err();
        assert!(matches!(error, ServiceError::Conflict(_)));
        assert_eq!(*fetcher.calls.lock(), vec![RouteSource::CurrentRecord]);
        assert!(store.is_quarantined(&expected, "station").await.unwrap());
    }

    #[test]
    fn valid_record_rejects_mismatched_describe_and_trust_domain() {
        let record = record("did:webvh:z6mkdescribe:route.example", 0, None);
        let mut mismatched = description(&record);
        mismatched.service_resolution.version_id = "other-version".to_owned();
        let error = validate_describe_metadata(
            &record,
            &mismatched,
            &record.record.service_id,
            &record.record.service_kind,
        )
        .unwrap_err();
        assert!(matches!(error, ServiceError::SchemaViolation(_)));

        let now = record.record.issued_at + Duration::minutes(1);
        let route = ResolvedServiceRoute {
            cache_entry: ServiceRouteCacheEntry {
                service_id: record.record.service_id.clone(),
                service_kind: record.record.service_kind.clone(),
                did: record.record.did.clone(),
                method_history_head: record.record.method_history_head.clone(),
                version_id: record.record.version_id.clone(),
                record_sequence: 0,
                record_digest: record_digest(&record),
                base_url: record.record.base_url.clone(),
                current_record_url: record.record.current_record_url.clone(),
                describe_digest: record.record.describe_digest.clone(),
                verified_at: now,
                refresh_after: record.record.refresh_after,
                expires_at: record.record.expires_at,
                cached_at: now,
                cache_expires_at: now + Duration::minutes(1),
            },
            trust_domain: TrustDomainId::new("ak:trust_domain:route.example").unwrap(),
            protocol_version: "1".to_owned(),
            describe_verified_at: now,
            describe_cache_expires_at: now + Duration::minutes(1),
        };
        assert!(
            route
                .require_trust_domain(Some("ak:trust_domain:other.example"))
                .is_err()
        );
        route
            .require_trust_domain(Some("ak:trust_domain:route.example"))
            .unwrap();
    }

    #[tokio::test]
    async fn resolved_route_cache_honours_describe_expiry() {
        let database = TestDatabase::lease().await;
        let store = Arc::new(PgServiceRouteStore {
            pool: database.pool(),
        });
        let accepted = record("did:webvh:z6mkcache:route.example", 0, None);
        let expected = accepted.record.service_id.clone();
        let fetcher = Arc::new(FakeFetcher {
            current: Some(accepted),
            notice: None,
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ServiceRouteResolver::new(store, fetcher.clone());
        let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 1, 0).unwrap();
        let first = resolver
            .resolve_route(&expected, "station", now, true)
            .await
            .unwrap();
        assert!(first.is_routable_at(now + Duration::seconds(59)));
        resolver
            .resolve_route(&expected, "station", now + Duration::seconds(59), false)
            .await
            .unwrap();
        assert_eq!(fetcher.calls.lock().len(), 1);

        resolver
            .resolve_route(&expected, "station", now + Duration::seconds(60), false)
            .await
            .unwrap();
        assert_eq!(fetcher.calls.lock().len(), 2);
    }
}
