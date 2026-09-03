use std::sync::Arc;

use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionMethodEvidenceBoundary,
    ResolutionMethodHistoryEvidence, ServiceResolutionCarrier, ServiceRouteHandoverState,
};
use arkret_wire::{BindingKind, Did, DidCoreId, Hash, ServiceKind};
use async_trait::async_trait;
use chrono::Utc;
use soland_services::identity::{DidService, PinnedDidVersionStatus};
use soland_services::service_route::{
    RouteSource, ServiceRouteFetcher, VerifiedRouteCandidate, VerifiedServiceDescribeMetadata,
};
use soland_services::{ServiceError, ServiceResult};
use soland_storage::ServiceRouteStore;

/// Fetches only carriers retained by an effective business binding. It never
/// derives a URL from a service core id and never treats a configured endpoint
/// as resolution evidence.
pub(crate) struct VerifiedBindingRouteFetcher {
    dids: DidService,
    route_store: Arc<dyn ServiceRouteStore>,
    transport: arkret_http_client::ServiceResolutionFetcher,
    development_mode: bool,
}

impl VerifiedBindingRouteFetcher {
    pub(crate) fn new(
        dids: DidService,
        route_store: Arc<dyn ServiceRouteStore>,
        development_mode: bool,
    ) -> Self {
        let egress = if development_mode {
            arkret_egress_policy::OutboundPolicy::local_development()
        } else {
            arkret_egress_policy::OutboundPolicy::public_https()
        };
        Self {
            dids,
            route_store,
            transport: arkret_http_client::ServiceResolutionFetcher::with_egress_policy(egress),
            development_mode,
        }
    }

    async fn verify_carrier(
        &self,
        carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<VerifiedRouteCandidate> {
        let materialized = self
            .transport
            .materialize(carrier, service_id)
            .await
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let fetched_authenticated = materialized.authenticated_resolution().cloned();
        let record = materialized.record().clone();
        if record.record.service_kind != service_kind {
            return Err(ServiceError::SchemaViolation(
                "service resolution kind does not match the business binding".to_owned(),
            ));
        }
        validate_route_binding(&record, self.development_mode)?;
        let did = Did::new(record.record.did.to_string())
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if let Some(authenticated) = fetched_authenticated {
            arkret_identity::verify_authenticated_service_resolution_history(
                &authenticated,
                service_id,
                Utc::now(),
            )
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            if did.method() == "webvh" {
                self.confirm_webvh_resolution_against_independent_state(
                    &record,
                    &authenticated.normalized_did_document,
                )
                .await?;
            }
            return self.finish_verified_candidate(record, service_kind).await;
        }
        let (document, method_history_evidence) = match did.method() {
            "webvh" => {
                return Err(ServiceError::SchemaViolation(
                    "inline WebVH service resolution omits complete method-history evidence"
                        .to_owned(),
                ));
            }
            "web" => {
                let resolved = self
                    .dids
                    .resolve_did(&did)
                    .await
                    .map_err(ServiceError::SchemaViolation)?;
                let document: DidDocument = serde_json::from_value(
                    serde_json::to_value(resolved)
                        .map_err(|error| ServiceError::Internal(error.to_string()))?,
                )
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
                let digest = canonical_document_digest(&document)?;
                validate_synthetic_method_coordinates(
                    &record,
                    &digest,
                    "synthetic-jcs-sha256:",
                    "did-web-document-sha256:",
                )?;
                (
                    document,
                    non_history_evidence(&record, digest, "web", false),
                )
            }
            "key" => {
                let resolved = self
                    .dids
                    .resolve_did(&did)
                    .await
                    .map_err(ServiceError::SchemaViolation)?;
                let document: DidDocument = serde_json::from_value(
                    serde_json::to_value(resolved)
                        .map_err(|error| ServiceError::Internal(error.to_string()))?,
                )
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
                let did_digest = Hash::new(arkret_canonical::sha256_digest(
                    record.record.did.as_str().as_bytes(),
                ))
                .map_err(|error| ServiceError::Internal(error.to_string()))?;
                validate_synthetic_method_coordinates(
                    &record,
                    &did_digest,
                    "synthetic-did-sha256:",
                    "did-key-did-sha256:",
                )?;
                let document_digest = canonical_document_digest(&document)?;
                (
                    document,
                    non_history_evidence(&record, document_digest, "key", true),
                )
            }
            method => {
                return Err(ServiceError::SchemaViolation(format!(
                    "service resolution method {method:?} has no active adapter"
                )));
            }
        };
        let authenticated = AuthenticatedServiceResolution {
            service_resolution_record: record.clone(),
            method_history_evidence,
            normalized_did_document: document,
        };
        arkret_signatures::service_resolution::verify_authenticated_service_resolution(
            &authenticated,
            service_id,
            Utc::now(),
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        self.finish_verified_candidate(record, service_kind).await
    }

    async fn confirm_webvh_resolution_against_independent_state(
        &self,
        record: &arkret_models_identity::ServiceResolutionRecord,
        embedded_document: &DidDocument,
    ) -> ServiceResult<()> {
        let did = Did::new(record.record.did.to_string())
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let history_head = Hash::new(record.record.method_history_head.clone())
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let history_hex = history_head
            .as_str()
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                ServiceError::SchemaViolation("webvh service history head is not sha256".to_owned())
            })?;
        if record.record.resolution_event_ref != format!("did-webvh-entry-sha256:{history_hex}") {
            return Err(ServiceError::SchemaViolation(
                "webvh service resolution event ref does not match its history head".to_owned(),
            ));
        }
        let Ok(pinned) = self
            .dids
            .resolve_pinned_webvh_state(&did, &record.record.version_id, &history_head)
            .await
        else {
            return Ok(());
        };
        if pinned.status != PinnedDidVersionStatus::Current {
            return Err(ServiceError::SchemaViolation(
                "service resolution is not at the current verified method-history head".to_owned(),
            ));
        }
        let independently_resolved: DidDocument = serde_json::from_value(pinned.document)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if arkret_canonical::canonical_json_bytes(&independently_resolved)
            .map_err(|error| ServiceError::Internal(error.to_string()))?
            != arkret_canonical::canonical_json_bytes(embedded_document)
                .map_err(|error| ServiceError::Internal(error.to_string()))?
        {
            return Err(ServiceError::SchemaViolation(
                "embedded service DID document disagrees with independently verified history"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    async fn finish_verified_candidate(
        &self,
        record: arkret_models_identity::ServiceResolutionRecord,
        service_kind: &str,
    ) -> ServiceResult<VerifiedRouteCandidate> {
        let registered_kind = ServiceKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == service_kind && kind.valid_in("service_describe"))
            .ok_or_else(|| {
                ServiceError::SchemaViolation(format!(
                    "service resolution kind {service_kind:?} has no role-scoped describe surface"
                ))
            })?;
        let description = self
            .transport
            .fetch_describe(&record.record.base_url, registered_kind)
            .await
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let description = validate_service_describe(&record, description, registered_kind)?;
        if Utc::now() >= record.record.expires_at {
            return Err(ServiceError::SchemaViolation(
                "service resolution expired while confirming ServiceDescribe".to_owned(),
            ));
        }
        Ok(VerifiedRouteCandidate {
            source: RouteSource::CurrentRecord,
            record,
            description,
        })
    }
}

fn validate_service_describe(
    record: &arkret_models_identity::ServiceResolutionRecord,
    description: arkret_models_discovery::ServiceDescribe,
    expected_kind: ServiceKind,
) -> ServiceResult<VerifiedServiceDescribeMetadata> {
    use arkret_models_identity::service_identity::CanonicalServiceUrl;

    description
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if description.protocol_version.as_str() != arkret_wire::PROTOCOL_VERSION
        || description.service_id != record.record.service_id
        || description.service_kind != expected_kind
        || description.service_resolution.did != record.record.did
        || description.service_resolution.method_history_head != record.record.method_history_head
        || description.service_resolution.version_id != record.record.version_id
    {
        return Err(ServiceError::SchemaViolation(
            "ServiceDescribe identity or resolution commitment does not match the verified record"
                .to_owned(),
        ));
    }
    let mut http_json_bindings = description
        .transport_bindings
        .iter()
        .filter(|binding| binding.kind() == BindingKind::HttpJson);
    let binding = http_json_bindings.next().ok_or_else(|| {
        ServiceError::SchemaViolation(
            "ServiceDescribe has no selected http_json binding".to_owned(),
        )
    })?;
    if http_json_bindings.next().is_some() {
        return Err(ServiceError::SchemaViolation(
            "ServiceDescribe has multiple http_json bindings".to_owned(),
        ));
    }
    let advertised_base_raw = binding.base_url();
    let advertised_base = CanonicalServiceUrl::canonicalize(advertised_base_raw)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if advertised_base.as_str() != advertised_base_raw
        || advertised_base.as_str() != record.record.base_url
    {
        return Err(ServiceError::SchemaViolation(
            "ServiceDescribe http_json base does not match the signed record target".to_owned(),
        ));
    }
    let route_binding_digest = arkret_models_identity::route_binding_describe_digest(
        &description.service_id,
        description.service_kind.as_str(),
        &description.service_resolution,
        advertised_base.as_str(),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    if route_binding_digest != record.record.describe_digest {
        return Err(ServiceError::SchemaViolation(
            "ServiceDescribe route-binding projection digest does not match the signed record"
                .to_owned(),
        ));
    }
    Ok(VerifiedServiceDescribeMetadata {
        service_id: description.service_id,
        service_kind: description.service_kind.as_str().to_owned(),
        service_resolution: description.service_resolution,
        http_json_base_url: advertised_base.to_string(),
        route_binding_digest,
        trust_domain: description.trust_domain,
        protocol_version: description.protocol_version.to_string(),
    })
}

fn canonical_document_digest(document: &DidDocument) -> ServiceResult<Hash> {
    arkret_identity::document_canonical_digest(document)
        .map_err(|error| ServiceError::Internal(error.to_string()))
}

fn validate_route_binding(
    record: &arkret_models_identity::ServiceResolutionRecord,
    development_mode: bool,
) -> ServiceResult<()> {
    use arkret_models_identity::service_identity::CanonicalServiceUrl;

    let base = CanonicalServiceUrl::canonicalize(&record.record.base_url)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if base.to_string() != record.record.base_url {
        return Err(ServiceError::SchemaViolation(
            "service resolution base_url is not canonical".to_owned(),
        ));
    }
    if !development_mode {
        base.require_https()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    }
    let expected_record_url = format!(
        "{}{}",
        base,
        arkret_models_identity::canonical_service_current_record_path(&record.record.service_id)
            .trim_start_matches('/')
    );
    if record.record.current_record_url != expected_record_url {
        return Err(ServiceError::SchemaViolation(
            "service resolution current_record_url is not derived from base_url".to_owned(),
        ));
    }
    let digest = arkret_models_identity::route_binding_describe_digest(
        &record.record.service_id,
        &record.record.service_kind,
        &arkret_models_identity::ResolutionCommitment {
            did: record.record.did.clone(),
            method_history_head: record.record.method_history_head.clone(),
            version_id: record.record.version_id.clone(),
        },
        &record.record.base_url,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    if digest != record.record.describe_digest {
        return Err(ServiceError::SchemaViolation(
            "service resolution describe route-binding digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn evidence_boundary(
    record: &arkret_models_identity::ServiceResolutionRecord,
) -> ResolutionMethodEvidenceBoundary {
    ResolutionMethodEvidenceBoundary {
        from_method_history_head: record.record.method_history_head.clone(),
        from_version_id: record.record.version_id.clone(),
        to_method_history_head: record.record.method_history_head.clone(),
        to_version_id: record.record.version_id.clone(),
    }
}

fn non_history_evidence(
    record: &arkret_models_identity::ServiceResolutionRecord,
    document_digest: Hash,
    method: &str,
    did_key: bool,
) -> ResolutionMethodHistoryEvidence {
    let evidence = ResolutionDidBindingEvidenceReceipt {
        kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
        method: method.to_owned(),
        document_digest,
        method_proofs: Vec::new(),
    };
    if did_key {
        ResolutionMethodHistoryEvidence::DidKeyExpansion {
            boundary: evidence_boundary(record),
            evidence,
        }
    } else {
        ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary: evidence_boundary(record),
            evidence,
        }
    }
}

fn validate_synthetic_method_coordinates(
    record: &arkret_models_identity::ServiceResolutionRecord,
    digest: &Hash,
    version_prefix: &str,
    event_prefix: &str,
) -> ServiceResult<()> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| ServiceError::Internal("canonical hash lost sha256 prefix".to_owned()))?;
    if record.record.method_history_head != digest.as_str()
        || record.record.version_id != format!("{version_prefix}{hex}")
        || record.record.resolution_event_ref != format!("{event_prefix}{hex}")
    {
        return Err(ServiceError::SchemaViolation(
            "service resolution synthetic method coordinates do not match the active adapter"
                .to_owned(),
        ));
    }
    Ok(())
}

#[async_trait]
impl ServiceRouteFetcher for VerifiedBindingRouteFetcher {
    async fn fetch_carrier(
        &self,
        carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        self.verify_carrier(carrier, service_id, service_kind)
            .await
            .map(Some)
    }

    async fn fetch_current(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        let Some(cache) = self
            .route_store
            .route_cache(service_id, service_kind)
            .await?
        else {
            return Ok(None);
        };
        // Expiry prevents routing through this entry, not fetching a new
        // signed record from its previously authenticated locator.
        let carrier = ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: cache.current_record_url,
            pinned_record_digest: None,
        };
        self.verify_carrier(&carrier, service_id, service_kind)
            .await
            .map(Some)
    }

    async fn fetch_notice_candidate(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        let Some(floor) = self
            .route_store
            .last_seen_floor(service_id, service_kind)
            .await?
        else {
            return Ok(None);
        };
        let states = self
            .route_store
            .notice_states(service_id, service_kind, 32)
            .await?;
        let entries = self
            .route_store
            .handover_mirror_entries(service_id, service_kind, 32)
            .await?;
        let now = Utc::now();

        for state in states.into_iter().filter(|state| {
            state.state == ServiceRouteHandoverState::Scheduled
                && state.expires_at > now
                && state.from_record_sequence == floor.record_sequence
                && state.from_record_digest == floor.record_digest
        }) {
            let Some(notice) = entries.iter().find_map(|entry| {
                let notice = entry.request.service_route_handover_notice.as_ref()?;
                (entry.artifact_digest == state.notice_digest
                    && notice.notice.handover_id == state.handover_id
                    && notice.notice.notice_revision == state.notice_revision)
                    .then_some(notice)
            }) else {
                continue;
            };
            if notice
                .notice
                .not_before
                .is_none_or(|not_before| now < not_before)
            {
                continue;
            }
            let Some(current_record_url) = notice.notice.candidate_record_url.clone() else {
                continue;
            };
            let carrier = ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url,
                pinned_record_digest: None,
            };
            let mut candidate = self
                .verify_carrier(&carrier, service_id, service_kind)
                .await?;
            if candidate.record.record.record_sequence != floor.record_sequence + 1
                || candidate.record.record.previous_record_digest.as_ref()
                    != Some(&floor.record_digest)
            {
                return Err(ServiceError::SchemaViolation(
                    "scheduled service route candidate is not the continuous formal successor"
                        .to_owned(),
                ));
            }
            candidate.source = RouteSource::ScheduledNotice;
            return Ok(Some(candidate));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_discovery::{ServiceDescribe, TransportBinding};
    use arkret_models_identity::{
        ResolutionCommitment, ServiceResolutionRecord, ServiceResolutionRecordCore,
    };
    use arkret_wire::{Base64UrlString, Did, DidUrl, ProtocolSignature, TrustDomainId};
    use chrono::{Duration, TimeZone as _};

    use super::*;

    fn fixture() -> (ServiceResolutionRecord, ServiceDescribe) {
        let did = Did::new("did:webvh:z6mkdescribe:route.example").unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let base_url = "https://route.example/";
        let commitment = ResolutionCommitment {
            did: did.clone(),
            method_history_head: "head-0".to_owned(),
            version_id: "version-0".to_owned(),
        };
        let mut description = ServiceDescribe::development(
            did.clone(),
            TrustDomainId::new("ak:trust_domain:route.example").unwrap(),
            ServiceKind::Station,
            vec!["ak.operation_bundle.station.describe.v1".to_owned()],
            vec![TransportBinding::HttpJson {
                base_url: base_url.to_owned(),
                extension_profile_required: (),
            }],
        );
        description.service_resolution = commitment.clone();
        #[derive(serde::Serialize)]
        struct Projection<'a> {
            service_id: &'a DidCoreId,
            service_kind: ServiceKind,
            service_resolution: &'a ResolutionCommitment,
            http_json_base_url: &'a str,
        }
        let describe_digest = Hash::new(
            arkret_canonical::canonical_sha256(&Projection {
                service_id: &service_id,
                service_kind: ServiceKind::Station,
                service_resolution: &commitment,
                http_json_base_url: base_url,
            })
            .unwrap(),
        )
        .unwrap();
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
        let record = ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id,
                service_kind: "station".to_owned(),
                did: did.clone(),
                method_history_head: commitment.method_history_head.clone(),
                version_id: commitment.version_id.clone(),
                resolution_event_ref: "fixture".to_owned(),
                record_sequence: 0,
                previous_record_digest: None,
                current_record_url: format!("{base_url}_arkret/open/services/fixture/resolution"),
                base_url: base_url.to_owned(),
                describe_digest,
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new(format!("{did}#assertion-1")).unwrap(),
                created_at: issued_at,
                jws: Base64UrlString::new("AA").unwrap(),
            },
        };
        (record, description)
    }

    #[test]
    fn valid_record_rejects_describe_commitment_and_base_mismatch() {
        let (record, description) = fixture();
        validate_service_describe(&record, description.clone(), ServiceKind::Station).unwrap();

        let mut wrong_commitment = description.clone();
        wrong_commitment.service_resolution.version_id = "other-version".to_owned();
        assert!(
            validate_service_describe(&record, wrong_commitment, ServiceKind::Station).is_err()
        );

        let mut wrong_base = description;
        let TransportBinding::HttpJson { base_url, .. } = &mut wrong_base.transport_bindings[0]
        else {
            panic!("fixture transport must be HTTP JSON")
        };
        *base_url = "https://other.example/".to_owned();
        assert!(validate_service_describe(&record, wrong_base, ServiceKind::Station).is_err());
    }
}
