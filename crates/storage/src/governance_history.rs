use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome, GovernanceDependencySelector,
    validate_history_source_signer_dependency_closure,
};
use arkret_models_collaboration::history_key::{
    ArchiveAuthorizationTuple, HistoryGovernanceTraversalIntent,
    HistoryGovernanceTraversalRetention, HistoryKeyResponseSendRequest,
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, PeerHistoryTraversalAccess,
    SelfHistoryTraversalAccess,
};
use arkret_models_identity::{AgentSignerEvidence, AuthenticatedSignerResolutionEvidence};
use arkret_wire::{Event, EventProof, Hash, HistoryEffectiveScope, RealmId, Seal, SealId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{PersistenceError, PersistenceResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactWriteOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageCasOutcome {
    Applied,
    ExactReplay,
    Mismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GovernanceDependencySource {
    Seal(SealId),
    Event(Hash),
}

impl GovernanceDependencySource {
    pub fn storage_parts(&self) -> (&'static str, &str) {
        match self {
            Self::Seal(id) => ("seal", id.as_str()),
            Self::Event(digest) => ("event", digest.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GovernanceDependencyWrite {
    pub realm_id: RealmId,
    pub source: GovernanceDependencySource,
    pub edge_index: u64,
    pub item: GovernanceDependency,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GovernanceDependencyEdgeRecord {
    pub edge_index: u64,
    pub item: GovernanceDependency,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GovernanceDependencyCanonical {
    pub dependency_kind: &'static str,
    /// Exact selector value used by self/peer resolve. This is a digest for
    /// content-addressed families and the producer ID for collision records.
    pub selector_value: String,
    /// Internal CAS/retention integrity digest. For collision records this is
    /// deliberately *not* the Realm-suite locator digest; only the SDK can
    /// compute that digest with the Realm's active suite and compare it with
    /// the signed locator.
    pub object_digest: Hash,
    pub canonical_bytes: Vec<u8>,
    pub object_json: serde_json::Value,
}

pub fn governance_dependency_canonical(
    item: &GovernanceDependency,
) -> PersistenceResult<GovernanceDependencyCanonical> {
    GovernanceDependencyResolveOutcome {
        items: vec![item.clone()],
        missing_selectors: Vec::new(),
    }
    .validate()
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;

    let (dependency_kind, selector_value, object_digest, object_json) = match item {
        GovernanceDependency::AppletInstallationAuthority {
            selector: GovernanceDependencySelector::AppletInstallationAuthority { content_digest },
            applet_installation_authority,
        } => (
            "applet_installation_authority",
            content_digest.as_str().to_owned(),
            content_digest.clone(),
            serde_json::to_value(applet_installation_authority),
        ),
        GovernanceDependency::AvailabilityReceipt {
            selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
            availability_receipt,
        } => {
            availability_receipt
                .validate_structural()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let digest_suite = content_digest
                .digest_suite()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let computed_digest = availability_receipt
                .full_receipt_digest(|bytes| {
                    Ok(Hash::new(arkret_canonical::canonical::digest(
                        digest_suite,
                        bytes,
                    ))?)
                })
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if content_digest != &computed_digest {
                return Err(PersistenceError::SchemaViolation(
                    "availability receipt selector digest mismatch".to_owned(),
                ));
            }
            (
                "availability_receipt",
                content_digest.as_str().to_owned(),
                content_digest.clone(),
                serde_json::to_value(availability_receipt),
            )
        }
        GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector:
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest },
            authenticated_signer_resolution_evidence,
        } => {
            authenticated_signer_resolution_evidence
                .validate_attester_binding()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if authenticated_signer_resolution_evidence
                .canonical_sha256_digest()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                != *content_digest
            {
                return Err(PersistenceError::SchemaViolation(
                    "authenticated signer evidence selector digest mismatch".to_owned(),
                ));
            }
            (
                "authenticated_signer_resolution_evidence",
                content_digest.as_str().to_owned(),
                content_digest.clone(),
                serde_json::to_value(authenticated_signer_resolution_evidence),
            )
        }
        GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
            selector:
                GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence { content_digest },
            minimal_metadata_mls_leaf_signer_evidence,
        } => {
            minimal_metadata_mls_leaf_signer_evidence
                .validate()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if minimal_metadata_mls_leaf_signer_evidence
                .canonical_sha256_digest()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                != *content_digest
            {
                return Err(PersistenceError::SchemaViolation(
                    "minimal-metadata signer evidence selector digest mismatch".to_owned(),
                ));
            }
            (
                "minimal_metadata_mls_leaf_signer_evidence",
                content_digest.as_str().to_owned(),
                content_digest.clone(),
                serde_json::to_value(minimal_metadata_mls_leaf_signer_evidence),
            )
        }
        GovernanceDependency::CollisionVariantRecord {
            selector:
                GovernanceDependencySelector::CollisionVariantRecord {
                    collision_variant_record_id,
                },
            collision_variant_record,
        } => {
            collision_variant_record
                .validate_structural()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if collision_variant_record_id != &collision_variant_record.collision_variant_record_id
            {
                return Err(PersistenceError::SchemaViolation(
                    "collision variant record selector id mismatch".to_owned(),
                ));
            }
            let object_json = serde_json::to_value(collision_variant_record)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let canonical_bytes = arkret_canonical::canonical_json_bytes(&object_json)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let object_digest = Hash::new(arkret_canonical::sha256_digest(&canonical_bytes))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            (
                "collision_variant_record",
                collision_variant_record_id.as_str().to_owned(),
                object_digest,
                Ok(object_json),
            )
        }
        _ => {
            return Err(PersistenceError::SchemaViolation(
                "governance dependency item branch does not match its selector".to_owned(),
            ));
        }
    };
    let object_json = object_json.map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&object_json)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    if canonical_bytes.len() > 8 * 1024 * 1024 {
        return Err(PersistenceError::SchemaViolation(
            "governance dependency object exceeds 8 MiB".to_owned(),
        ));
    }
    Ok(GovernanceDependencyCanonical {
        dependency_kind,
        selector_value,
        object_digest,
        canonical_bytes,
        object_json,
    })
}

pub fn governance_signer_evidence_canonical(
    item: &GovernanceDependency,
) -> PersistenceResult<GovernanceDependencyCanonical> {
    let canonical = governance_dependency_canonical(item)?;
    if !matches!(
        item,
        GovernanceDependency::AuthenticatedSignerResolutionEvidence { .. }
            | GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence { .. }
    ) {
        return Err(PersistenceError::SchemaViolation(
            "unscoped governance dependency CAS accepts signer evidence only".to_owned(),
        ));
    }
    Ok(canonical)
}

pub fn governance_dependency_selector_parts(
    selector: &GovernanceDependencySelector,
) -> PersistenceResult<(&'static str, Hash)> {
    GovernanceDependencyResolveOutcome {
        items: Vec::new(),
        missing_selectors: vec![selector.clone()],
    }
    .validate()
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    Ok(match selector {
        GovernanceDependencySelector::AppletInstallationAuthority { content_digest } => {
            ("applet_installation_authority", content_digest.clone())
        }
        GovernanceDependencySelector::AvailabilityReceipt { content_digest } => {
            ("availability_receipt", content_digest.clone())
        }
        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest } => (
            "authenticated_signer_resolution_evidence",
            content_digest.clone(),
        ),
        GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence { content_digest } => (
            "minimal_metadata_mls_leaf_signer_evidence",
            content_digest.clone(),
        ),
        GovernanceDependencySelector::CollisionVariantRecord { .. } => {
            return Err(PersistenceError::SchemaViolation(
                "collision variant record selector is producer-ID-addressed, not digest-addressed"
                    .to_owned(),
            ));
        }
    })
}

/// Storage lookup key for every governance dependency family. Collision
/// records are intentionally keyed by their producer-allocated ID; their
/// locator digest is independently verified by the SDK against the full JCS
/// record (including `proof`).
pub fn governance_dependency_selector_storage_parts(
    selector: &GovernanceDependencySelector,
) -> PersistenceResult<(&'static str, String)> {
    GovernanceDependencyResolveOutcome {
        items: Vec::new(),
        missing_selectors: vec![selector.clone()],
    }
    .validate()
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    Ok(match selector {
        GovernanceDependencySelector::AppletInstallationAuthority { content_digest } => (
            "applet_installation_authority",
            content_digest.as_str().to_owned(),
        ),
        GovernanceDependencySelector::AvailabilityReceipt { content_digest } => {
            ("availability_receipt", content_digest.as_str().to_owned())
        }
        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest } => (
            "authenticated_signer_resolution_evidence",
            content_digest.as_str().to_owned(),
        ),
        GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence { content_digest } => (
            "minimal_metadata_mls_leaf_signer_evidence",
            content_digest.as_str().to_owned(),
        ),
        GovernanceDependencySelector::CollisionVariantRecord {
            collision_variant_record_id,
        } => (
            "collision_variant_record",
            collision_variant_record_id.as_str().to_owned(),
        ),
    })
}

#[async_trait]
pub trait GovernanceDependencyStore: Send + Sync {
    async fn put_unscoped_signer_evidence_exact(
        &self,
        item: GovernanceDependency,
    ) -> PersistenceResult<ExactWriteOutcome>;

    async fn get_unscoped_signer_evidence(
        &self,
        selector: &GovernanceDependencySelector,
    ) -> PersistenceResult<Option<GovernanceDependency>>;

    async fn get_historical_agent_signer_evidence(
        &self,
        key: &HistoricalAgentSignerEvidenceKey,
    ) -> PersistenceResult<Option<GovernanceDependency>>;

    async fn put_realm_object_exact(
        &self,
        realm_id: &RealmId,
        item: GovernanceDependency,
    ) -> PersistenceResult<ExactWriteOutcome>;

    async fn put_exact(
        &self,
        write: GovernanceDependencyWrite,
    ) -> PersistenceResult<ExactWriteOutcome>;

    async fn get(
        &self,
        realm_id: &RealmId,
        selector: &GovernanceDependencySelector,
    ) -> PersistenceResult<Option<GovernanceDependency>>;

    async fn list_for_source(
        &self,
        realm_id: &RealmId,
        source: &GovernanceDependencySource,
    ) -> PersistenceResult<Vec<GovernanceDependencyEdgeRecord>>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HistoricalAgentSignerEvidenceKey {
    pub agent_id: arkret_wire::DidCoreId,
    pub verification_method: arkret_wire::DidUrl,
    pub event_id: arkret_wire::EventId,
    pub receiver_id: arkret_wire::DidCoreId,
}

pub fn historical_agent_signer_evidence_key(
    item: &GovernanceDependency,
) -> PersistenceResult<Option<HistoricalAgentSignerEvidenceKey>> {
    governance_signer_evidence_canonical(item)?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence,
        ..
    } = item
    else {
        return Ok(None);
    };
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        ..
    } = authenticated_signer_resolution_evidence.as_ref()
    else {
        return Ok(None);
    };
    let AgentSignerEvidence::HistoricalEvent {
        event_admission_receipt,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        return Ok(None);
    };
    Ok(Some(HistoricalAgentSignerEvidenceKey {
        agent_id: signer_id.clone(),
        verification_method: verification_method.clone(),
        event_id: event_admission_receipt.event_id.clone(),
        receiver_id: event_admission_receipt.receiver_id.clone(),
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryTraversalAccess {
    SelfAccess(SelfHistoryTraversalAccess),
    PeerAccess(PeerHistoryTraversalAccess),
}

impl HistoryTraversalAccess {
    pub fn storage_parts(&self) -> (&'static str, &Hash) {
        match self {
            Self::SelfAccess(SelfHistoryTraversalAccess::RequestReceipt {
                request_receipt_digest,
            }) => ("request_receipt", request_receipt_digest),
            Self::SelfAccess(SelfHistoryTraversalAccess::ArchiveReplica {
                archive_replica_digest,
            }) => ("archive_replica", archive_replica_digest),
            Self::PeerAccess(PeerHistoryTraversalAccess::PendingArchiveReplica {
                pending_archive_replica_digest,
            }) => ("pending_archive_replica", pending_archive_replica_digest),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HistoryTraversalPin {
    Seal {
        seal_id: SealId,
        object_digest: Hash,
    },
    ControlEvent {
        event_digest: Hash,
        object_digest: Hash,
    },
    GovernanceDependency {
        selector: GovernanceDependencySelector,
        object_digest: Hash,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum HistoryTraversalRetainedObject {
    Seal(Seal),
    ControlEvent(Event),
    GovernanceDependency(GovernanceDependency),
}

/// Validate the exact source signer-evidence closure bound by a history
/// response and materialize the retention pins that keep it resolvable.
pub fn history_source_signer_retained_dependencies(
    source: &HistoryKeyResponseSendRequest,
    dependencies: &[GovernanceDependency],
) -> PersistenceResult<Vec<(HistoryTraversalPin, HistoryTraversalRetainedObject)>> {
    validate_history_source_signer_dependency_closure(source, dependencies)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    dependencies
        .iter()
        .map(|dependency| {
            let selector = dependency.selector().clone();
            let (_, object_digest) = governance_dependency_selector_parts(&selector)?;
            Ok((
                HistoryTraversalPin::GovernanceDependency {
                    selector,
                    object_digest,
                },
                HistoryTraversalRetainedObject::GovernanceDependency(dependency.clone()),
            ))
        })
        .collect()
}

/// Select and validate the exact source and release-service signer evidence
/// carried by one response-stream record, then materialize their retention pins.
pub fn history_response_signer_retained_dependencies(
    record: &arkret_models_collaboration::history_key::HistoryKeyResponseRecord,
    dependencies: &[GovernanceDependency],
) -> PersistenceResult<Vec<(HistoryTraversalPin, HistoryTraversalRetainedObject)>> {
    let closure = arkret_models_collaboration::governance_dependencies::
        history_response_record_signer_dependency_closure(record, dependencies)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mut selected = closure.source_signer_dependencies;
    for dependency in closure.release_service_signer_dependencies {
        if !selected.contains(&dependency) {
            selected.push(dependency);
        }
    }
    if selected.len() != dependencies.len() {
        return Err(PersistenceError::SchemaViolation(
            "history response signer dependency set contains surplus evidence".to_owned(),
        ));
    }
    selected
        .into_iter()
        .map(|dependency| {
            let selector = dependency.selector().clone();
            let (_, object_digest) = governance_dependency_selector_parts(&selector)?;
            Ok((
                HistoryTraversalPin::GovernanceDependency {
                    selector,
                    object_digest,
                },
                HistoryTraversalRetainedObject::GovernanceDependency(dependency),
            ))
        })
        .collect()
}

pub fn history_lost_signer_retained_dependencies(
    lost_record: &arkret_models_collaboration::history_key::HistoryKeyResponseLostRecord,
    dependencies: &[GovernanceDependency],
) -> PersistenceResult<Vec<(HistoryTraversalPin, HistoryTraversalRetainedObject)>> {
    let selected = arkret_models_collaboration::governance_dependencies::
        history_response_lost_signer_dependency_closure(lost_record, dependencies)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if selected.len() != dependencies.len() {
        return Err(PersistenceError::SchemaViolation(
            "history lost signer dependency set contains surplus evidence".to_owned(),
        ));
    }
    let [dependency] = selected.as_slice() else {
        return Err(PersistenceError::SchemaViolation(
            "history lost record requires exactly one release-service signer evidence".to_owned(),
        ));
    };
    let selector = dependency.selector().clone();
    let (_, object_digest) = governance_dependency_selector_parts(&selector)?;
    Ok(vec![(
        HistoryTraversalPin::GovernanceDependency {
            selector,
            object_digest,
        },
        HistoryTraversalRetainedObject::GovernanceDependency(dependency.clone()),
    )])
}

#[derive(Clone, Debug, PartialEq)]
pub struct HistoryTraversalRetainedObjectRecord {
    pub pin: HistoryTraversalPin,
    pub object: HistoryTraversalRetainedObject,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HistoryTraversalRetainedObjectCanonical {
    pub object_kind: &'static str,
    pub object_ref: String,
    pub object_digest: Hash,
    pub canonical_bytes: Vec<u8>,
    pub object_json: serde_json::Value,
}

pub fn history_traversal_retained_object_from_json(
    object_kind: &str,
    object_json: serde_json::Value,
) -> PersistenceResult<HistoryTraversalRetainedObject> {
    match object_kind {
        "seal" => serde_json::from_value(object_json)
            .map(HistoryTraversalRetainedObject::Seal)
            .map_err(|error| PersistenceError::Internal(error.to_string())),
        "control_event" => serde_json::from_value(object_json)
            .map(HistoryTraversalRetainedObject::ControlEvent)
            .map_err(|error| PersistenceError::Internal(error.to_string())),
        "governance_dependency" => serde_json::from_value(object_json)
            .map(HistoryTraversalRetainedObject::GovernanceDependency)
            .map_err(|error| PersistenceError::Internal(error.to_string())),
        kind => Err(PersistenceError::Internal(format!(
            "stored history traversal retained object kind is invalid: {kind}"
        ))),
    }
}

pub fn history_traversal_retained_object_canonical(
    object: &HistoryTraversalRetainedObject,
) -> PersistenceResult<HistoryTraversalRetainedObjectCanonical> {
    let (object_kind, object_ref, object_digest, canonical_bytes) = match object {
        HistoryTraversalRetainedObject::Seal(seal) => {
            seal.validate_structural()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let canonical_bytes = arkret_canonical::canonical_json_bytes(seal)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let object_digest = Hash::new(arkret_canonical::sha256_digest(&canonical_bytes))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            (
                "seal",
                seal.id.as_str().to_owned(),
                object_digest,
                canonical_bytes,
            )
        }
        HistoryTraversalRetainedObject::ControlEvent(event) => {
            let event_digest_suite = event
                .proofs
                .iter()
                .find_map(EventProof::as_producer)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "retained Control Event omits its producer proof".to_owned(),
                    )
                })?
                .event_digest
                .digest_suite()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            // Canonical storage has no covering Seal or complete anchor unit.
            // Validate the proof regime and byte binding here; the retained-cut
            // verifier owns context-sensitive CBS validation before replay.
            match event.proofs.as_slice() {
                [EventProof::Producer(producer)] => producer
                    .validate_direct_signer_resolution_evidence()
                    .and_then(|_| {
                        event.validate_proof_bindings_with_digest_suite(event_digest_suite)
                    }),
                _ => event.validate_station_admission_binding(event_digest_suite),
            }
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            event
                .verify_event_id_matches_content_with_digest_suite(event_digest_suite)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let event_digest = Hash::new(
                event
                    .event_digest_with_digest_suite(event_digest_suite)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            )
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let preimage = arkret_wire::AvailabilityReceipt::event_bytes_digest_preimage(event)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let canonical_bytes = preimage
                .strip_prefix(b"ak.availability_event_bytes.v1\0")
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "accepted Event bytes preimage has an invalid domain separator".to_owned(),
                    )
                })?
                .to_vec();
            let object_digest = Hash::new(arkret_canonical::digest(event_digest_suite, &preimage))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            (
                "control_event",
                event_digest.as_str().to_owned(),
                object_digest,
                canonical_bytes,
            )
        }
        HistoryTraversalRetainedObject::GovernanceDependency(item) => {
            let canonical = governance_dependency_canonical(item)?;
            let selector = item.selector();
            let selector_bytes = arkret_canonical::canonical_json_bytes(selector)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let object_ref = String::from_utf8(selector_bytes)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let canonical_bytes = arkret_canonical::canonical_json_bytes(item)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            (
                "governance_dependency",
                object_ref,
                canonical.object_digest,
                canonical_bytes,
            )
        }
    };
    let object_json = serde_json::from_slice(&canonical_bytes)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    if canonical_bytes.len() > 8 * 1_024 * 1_024 {
        return Err(PersistenceError::SchemaViolation(
            "history traversal retained object exceeds 8 MiB".to_owned(),
        ));
    }
    Ok(HistoryTraversalRetainedObjectCanonical {
        object_kind,
        object_ref,
        object_digest,
        canonical_bytes,
        object_json,
    })
}

impl HistoryTraversalPin {
    pub fn storage_parts(&self) -> PersistenceResult<(&'static str, String, &Hash)> {
        match self {
            Self::Seal {
                seal_id,
                object_digest,
            } => Ok(("seal", seal_id.as_str().to_owned(), object_digest)),
            Self::ControlEvent {
                event_digest,
                object_digest,
            } => Ok((
                "control_event",
                event_digest.as_str().to_owned(),
                object_digest,
            )),
            Self::GovernanceDependency {
                selector,
                object_digest,
            } => {
                let (_, selector_digest) = governance_dependency_selector_parts(selector)?;
                if &selector_digest != object_digest {
                    return Err(PersistenceError::SchemaViolation(
                        "governance dependency pin object digest mismatch".to_owned(),
                    ));
                }
                let canonical = arkret_canonical::canonical_json_bytes(selector)
                    .map_err(|error| PersistenceError::Internal(error.to_string()))?;
                let object_ref = String::from_utf8(canonical)
                    .map_err(|error| PersistenceError::Internal(error.to_string()))?;
                Ok(("governance_dependency", object_ref, object_digest))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HistoryTraversalRetentionWrite {
    pub access: HistoryTraversalAccess,
    pub retention: HistoryGovernanceTraversalRetention,
    pub pins: Vec<HistoryTraversalPin>,
    pub objects: Vec<HistoryTraversalRetainedObject>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HistoryTraversalRetentionRecord {
    pub write: HistoryTraversalRetentionWrite,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HistoryTraversalCanonical {
    pub realm_id: RealmId,
    pub retention_kind: &'static str,
    pub expires_at: Option<DateTime<Utc>>,
    pub trusted_history_base_basis: serde_json::Value,
    pub trusted_current_basis: serde_json::Value,
    pub target_basis: serde_json::Value,
    pub traversal_intent_json: serde_json::Value,
    pub retained_objects: Vec<HistoryTraversalRetainedObjectCanonical>,
}

pub fn history_traversal_canonical(
    write: &HistoryTraversalRetentionWrite,
) -> PersistenceResult<HistoryTraversalCanonical> {
    write
        .retention
        .validate_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if write.pins.len() > 4_096 || write.objects.len() != write.pins.len() {
        return Err(PersistenceError::SchemaViolation(
            "history traversal retention requires one retained object per pin within 4096 items"
                .to_owned(),
        ));
    }
    let (
        realm_id,
        retention_kind,
        expires_at,
        trusted_history_base_basis,
        trusted_current_basis,
        target_basis,
    ) = match &write.retention.traversal_intent {
        HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
            effective_scope,
            trusted_history_base_basis,
            trusted_current_basis,
            target_basis,
            retention,
            ..
        } => {
            if !matches!(
                &write.access,
                HistoryTraversalAccess::SelfAccess(
                    SelfHistoryTraversalAccess::RequestReceipt { .. }
                )
            ) {
                return Err(PersistenceError::SchemaViolation(
                    "member traversal retention requires request-receipt access".to_owned(),
                ));
            }
            (
                effective_scope_realm(effective_scope),
                "request_expiring",
                Some(retention.expires_at),
                trusted_history_base_basis,
                trusted_current_basis,
                target_basis,
            )
        }
        HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
            effective_scope,
            trusted_history_base_basis,
            trusted_current_basis,
            target_basis,
            ..
        } => {
            if matches!(
                &write.access,
                HistoryTraversalAccess::SelfAccess(
                    SelfHistoryTraversalAccess::RequestReceipt { .. }
                )
            ) {
                return Err(PersistenceError::SchemaViolation(
                    "archive traversal retention requires archive-replica access".to_owned(),
                ));
            }
            (
                effective_scope_realm(effective_scope),
                "archive_lifetime",
                None,
                trusted_history_base_basis,
                trusted_current_basis,
                target_basis,
            )
        }
    };
    let mut pin_keys = std::collections::BTreeSet::new();
    let mut object_keys = std::collections::BTreeMap::new();
    let mut retained_objects = Vec::with_capacity(write.objects.len());
    for (pin, object) in write.pins.iter().zip(&write.objects) {
        let (kind, object_ref, object_digest) = pin.storage_parts()?;
        if !pin_keys.insert((kind, object_ref.clone(), object_digest.as_str().to_owned())) {
            return Err(PersistenceError::SchemaViolation(
                "history traversal pins must be unique".to_owned(),
            ));
        }
        let canonical = history_traversal_retained_object_canonical(object)?;
        if canonical.object_kind != kind
            || canonical.object_ref != object_ref
            || canonical.object_digest != *object_digest
        {
            return Err(PersistenceError::SchemaViolation(
                "history traversal retained object does not match its exact pin".to_owned(),
            ));
        }
        let object_key = (
            canonical.object_kind,
            canonical.object_digest.as_str().to_owned(),
        );
        if let Some((stored_ref, stored_bytes)) = object_keys.get(&object_key) {
            if stored_ref != &canonical.object_ref || stored_bytes != &canonical.canonical_bytes {
                return Err(PersistenceError::SchemaViolation(
                    "history traversal retained object digest collision".to_owned(),
                ));
            }
        } else {
            object_keys.insert(
                object_key,
                (
                    canonical.object_ref.clone(),
                    canonical.canonical_bytes.clone(),
                ),
            );
        }
        retained_objects.push(canonical);
    }
    Ok(HistoryTraversalCanonical {
        realm_id: realm_id.clone(),
        retention_kind,
        expires_at,
        trusted_history_base_basis: serde_json::to_value(trusted_history_base_basis)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        trusted_current_basis: serde_json::to_value(trusted_current_basis)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        target_basis: serde_json::to_value(target_basis)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        traversal_intent_json: serde_json::to_value(&write.retention.traversal_intent)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        retained_objects,
    })
}

fn effective_scope_realm(scope: &HistoryEffectiveScope) -> &RealmId {
    match scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    }
}

#[async_trait]
pub trait HistoryTraversalRetentionStore: Send + Sync {
    async fn persist_exact(
        &self,
        write: HistoryTraversalRetentionWrite,
    ) -> PersistenceResult<ExactWriteOutcome>;

    async fn get(
        &self,
        retention_digest: &Hash,
    ) -> PersistenceResult<Option<HistoryTraversalRetentionRecord>>;

    /// Access credentials and retained traversal content have distinct digests.
    async fn get_by_access(
        &self,
        access: &HistoryTraversalAccess,
    ) -> PersistenceResult<Option<HistoryTraversalRetentionRecord>>;

    async fn resolve_retained_object(
        &self,
        retention_digest: &Hash,
        pin: &HistoryTraversalPin,
    ) -> PersistenceResult<Option<HistoryTraversalRetainedObjectRecord>>;

    async fn release(&self, retention_digest: &Hash) -> PersistenceResult<bool>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRhrkAcquisitionState {
    Pending,
    Ready,
    Accepted,
}

impl PendingRhrkAcquisitionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Accepted => "accepted",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingRhrkAcquisitionInput {
    pub acquisition_digest: Hash,
    pub archive_replica_digest: Hash,
    pub archive_replica: OrganizationRecoveryArchiveReplica,
    pub next_attempt_at: DateTime<Utc>,
}

pub fn rhrk_archive_authorization_tuple(
    replica: &OrganizationRecoveryArchiveReplica,
) -> ArchiveAuthorizationTuple {
    let archive = &replica.archive;
    ArchiveAuthorizationTuple {
        recovery_key_id: archive.recovery_key_id.clone(),
        key_agreement_ref: archive.key_agreement_ref.clone(),
        method_controller_principal_id: archive.method_controller_principal_id.clone(),
        holder_service_id: archive.holder_service_id.clone(),
        holder_signing_ref: archive.holder_signing_ref.clone(),
        accepted_key_evidence_ref: archive.accepted_key_evidence_ref.clone(),
        holder_trusted_basis: archive.holder_trusted_basis.clone(),
    }
}

pub fn rhrk_archive_authorization_tuple_digest(
    replica: &OrganizationRecoveryArchiveReplica,
) -> PersistenceResult<Hash> {
    rhrk_archive_authorization_tuple(replica)
        .archive_authorization_tuple_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
}

pub fn rhrk_archive_replica_digest(
    replica: &OrganizationRecoveryArchiveReplica,
) -> PersistenceResult<Hash> {
    replica
        .archive_replica_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
}

impl PendingRhrkAcquisitionInput {
    pub fn validate(&self) -> PersistenceResult<()> {
        self.archive_replica
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let expected_digest = rhrk_archive_replica_digest(&self.archive_replica)?;
        if self.archive_replica_digest != expected_digest
            || self.acquisition_digest != self.archive_replica_digest
        {
            return Err(PersistenceError::SchemaViolation(
                "pending RHRK identity does not match the canonical archive replica digest"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn validate_rhrk_acceptance(
    input: &PendingRhrkAcquisitionInput,
    outcome: &OrganizationRecoveryArchiveReplicaOutcome,
) -> PersistenceResult<()> {
    outcome
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if outcome.archive_replica_digest != input.archive_replica_digest
        || outcome.holder_service_id != input.archive_replica.holder_service_id
    {
        return Err(PersistenceError::SchemaViolation(
            "RHRK acceptance outcome does not bind its pending archive replica".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingRhrkAcquisitionRecord {
    pub input: PendingRhrkAcquisitionInput,
    pub state: PendingRhrkAcquisitionState,
    pub attempt_count: u64,
    pub claim_token: Option<String>,
    pub claim_until: Option<DateTime<Utc>>,
    pub ready_at: Option<DateTime<Utc>>,
    pub archive_sequence: Option<u64>,
    pub accepted_outcome: Option<OrganizationRecoveryArchiveReplicaOutcome>,
    pub last_error_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait PendingRhrkAcquisitionStore: Send + Sync {
    async fn enqueue_exact(
        &self,
        input: PendingRhrkAcquisitionInput,
        now: DateTime<Utc>,
    ) -> PersistenceResult<ExactWriteOutcome>;

    async fn get(
        &self,
        acquisition_digest: &Hash,
    ) -> PersistenceResult<Option<PendingRhrkAcquisitionRecord>>;

    async fn list_accepted_for_authority(
        &self,
        effective_scope: &HistoryEffectiveScope,
        method_controller_principal_id: &arkret_wire::DidCoreId,
        holder_service_id: &arkret_wire::DidCoreId,
        from_epoch: u64,
        to_epoch: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRhrkAcquisitionRecord>>;

    async fn list_accepted_for_archive_query(
        &self,
        query: &OrganizationRecoveryArchiveListQuery,
        method_controller_principal_id: &arkret_wire::DidCoreId,
        after_archive_sequence: Option<u64>,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRhrkAcquisitionRecord>>;

    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        claim_token: &str,
        claim_until: DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRhrkAcquisitionRecord>>;

    async fn record_retry(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        next_attempt_at: DateTime<Utc>,
        error_code: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<StorageCasOutcome>;

    async fn mark_ready(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        ready_at: DateTime<Utc>,
    ) -> PersistenceResult<StorageCasOutcome>;

    async fn mark_accepted(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        outcome: OrganizationRecoveryArchiveReplicaOutcome,
    ) -> PersistenceResult<StorageCasOutcome>;
}
