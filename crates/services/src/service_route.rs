use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceResolutionCarrier, ServiceRouteCacheEntry,
};
use arkret_wire::{DidCoreId, Hash, TrustDomainId};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use soland_storage::{MonotonicRouteWrite, ServiceResolutionForkEvidence, ServiceRouteStore};

use crate::{ServiceError, ServiceResult};
#[derive(Clone, Debug)]
pub struct VerifiedRouteCandidate {
    pub evidence: AuthenticatedServiceResolution,
    pub description: VerifiedServiceDescribeMetadata,
}
#[derive(Clone, Debug)]
pub struct VerifiedServiceDescribeMetadata {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub service_resolution: arkret_models_identity::ResolutionCommitment,
    pub http_json_base_url: String,
    pub trust_domain: TrustDomainId,
    pub protocol_version: String,
}
#[derive(Clone, Debug)]
pub struct ResolvedServiceRoute {
    pub cache_entry: ServiceRouteCacheEntry,
    pub trust_domain: TrustDomainId,
    pub protocol_version: String,
    pub describe_verified_at: DateTime<Utc>,
    pub describe_cache_expires_at: DateTime<Utc>,
}
impl ResolvedServiceRoute {
    pub fn is_routable_at(&self, now: DateTime<Utc>) -> bool {
        self.cache_entry.is_routable_at(now) && now < self.describe_cache_expires_at
    }
    pub fn require_trust_domain(&self, expected: Option<&str>) -> ServiceResult<()> {
        if expected.is_some_and(|v| v != self.trust_domain.as_str()) {
            return Err(ServiceError::Conflict(
                "verified describe trust domain conflicts with binding".into(),
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
}
pub struct ServiceRouteResolver {
    store: Arc<dyn ServiceRouteStore>,
    fetcher: Arc<dyn ServiceRouteFetcher>,
    resolved_routes: parking_lot::Mutex<BTreeMap<(String, String), ResolvedServiceRoute>>,
}
impl ServiceRouteResolver {
    pub fn new(store: Arc<dyn ServiceRouteStore>, fetcher: Arc<dyn ServiceRouteFetcher>) -> Self {
        Self {
            store,
            fetcher,
            resolved_routes: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }
    pub async fn resolve_route(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        force_refresh: bool,
    ) -> ServiceResult<ResolvedServiceRoute> {
        let key = (service_id.to_string(), service_kind.to_owned());
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service DID is fork-quarantined".into(),
            ));
        }
        let cached = if force_refresh {
            None
        } else {
            self.resolved_routes.lock().get(&key).cloned()
        };
        if let Some(route) = cached {
            if route.is_routable_at(now)
                && self
                    .store
                    .route_cache(service_id, service_kind)
                    .await?
                    .is_some_and(|c| {
                        c.method_history_head == route.cache_entry.method_history_head
                            && c.is_routable_at(now)
                    })
            {
                return Ok(route);
            }
        }
        self.resolve(service_id, service_kind, now, true).await?;
        self.resolved_routes
            .lock()
            .get(&key)
            .cloned()
            .ok_or_else(|| ServiceError::Internal("verified describe missing".into()))
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
                "service DID is fork-quarantined".into(),
            ));
        }
        if !force_refresh {
            if let Some(c) = self.store.route_cache(service_id, service_kind).await? {
                if c.is_routable_at(now) {
                    return Ok(c);
                }
            }
        }
        let candidate = self
            .fetcher
            .fetch_current(service_id, service_kind)
            .await?
            .ok_or_else(|| ServiceError::NotFound("verified service route unavailable".into()))?;
        self.accept(service_id, service_kind, candidate, now).await
    }
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
            .ok_or_else(|| ServiceError::NotFound("verified service carrier unavailable".into()))?;
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
                "service DID is fork-quarantined".into(),
            ));
        }
        let p = candidate
            .evidence
            .projection()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let d = candidate.description;
        if p.service_id != *service_id
            || p.service_kind != service_kind
            || d.service_id != *service_id
            || d.service_kind != service_kind
            || d.service_resolution.did != p.did
            || d.service_resolution.method_history_head != p.method_history_head
            || d.service_resolution.version_id != p.version_id
            || d.http_json_base_url != p.base_url
        {
            return Err(ServiceError::SchemaViolation(
                "describe disagrees with verified DID route".into(),
            ));
        }
        let entry = ServiceRouteCacheEntry {
            service_id: p.service_id,
            service_kind: p.service_kind,
            did: p.did,
            method_history_head: p.method_history_head,
            version_id: p.version_id,
            base_url: p.base_url,
            verified_at: now,
            cache_expires_at: now + Duration::seconds(300),
        };
        match self
            .store
            .publish_route_cache(candidate.evidence.clone(), entry.clone())
            .await?
        {
            MonotonicRouteWrite::Applied | MonotonicRouteWrite::Replay => {}
            MonotonicRouteWrite::Stale => {
                return Err(ServiceError::Conflict(
                    "service DID rollback or missing native history".into(),
                ));
            }
            MonotonicRouteWrite::Conflict { accepted_digest } => {
                self.store
                    .quarantine_fork(ServiceResolutionForkEvidence {
                        service_id: service_id.clone(),
                        service_kind: service_kind.to_owned(),
                        artifact_family: "did_method".into(),
                        artifact_key: entry.version_id.clone(),
                        accepted_digest,
                        conflicting_digest: Hash::new(entry.method_history_head.clone())
                            .map_err(|e| ServiceError::Internal(e.to_string()))?,
                        evidence: serde_json::to_value(candidate.evidence)
                            .map_err(|e| ServiceError::Internal(e.to_string()))?,
                        quarantined_at: now,
                    })
                    .await?;
                return Err(ServiceError::Conflict("service DID fork".into()));
            }
        }
        self.resolved_routes.lock().insert(
            (service_id.to_string(), service_kind.to_owned()),
            ResolvedServiceRoute {
                cache_entry: entry.clone(),
                trust_domain: d.trust_domain,
                protocol_version: d.protocol_version,
                describe_verified_at: now,
                describe_cache_expires_at: entry.cache_expires_at,
            },
        );
        Ok(entry)
    }
}
