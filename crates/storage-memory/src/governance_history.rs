use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use soland_storage::{
    ExactWriteOutcome, GovernanceDependencyCanonical, GovernanceDependencyEdgeRecord,
    GovernanceDependencySource, GovernanceDependencyStore, GovernanceDependencyWrite,
    HistoricalAgentSignerEvidenceKey, HistoryTraversalRetainedObject,
    HistoryTraversalRetainedObjectCanonical, HistoryTraversalRetainedObjectRecord,
    HistoryTraversalRetentionRecord, HistoryTraversalRetentionStore,
    HistoryTraversalRetentionWrite, PendingRrkAcquisitionInput, PendingRrkAcquisitionRecord,
    PendingRrkAcquisitionState, PendingRrkAcquisitionStore, PersistenceError, PersistenceResult,
    StorageCasOutcome, governance_dependency_canonical, governance_dependency_selector_parts,
    governance_signer_evidence_canonical, historical_agent_signer_evidence_key,
    history_traversal_canonical, history_traversal_retained_object_from_json,
    rrk_semantically_same, validate_rrk_acceptance,
};

use super::{Arc, BTreeMap, Mutex};

type DependencyObjectKey = (String, String, String);
type DependencySourceKey = (String, String, String);

#[derive(Clone, Default)]
pub(crate) struct GovernanceDependencyData {
    objects: BTreeMap<DependencyObjectKey, (GovernanceDependencyCanonical, GovernanceDependency)>,
    unscoped_signer_evidence:
        BTreeMap<(String, String), (GovernanceDependencyCanonical, GovernanceDependency)>,
    historical_agent_signer_evidence: BTreeMap<HistoricalAgentSignerEvidenceKey, (String, String)>,
    edges: BTreeMap<DependencySourceKey, BTreeMap<u64, (String, String)>>,
}

#[derive(Clone, Default)]
pub struct MemoryGovernanceDependencyStore {
    pub(crate) data: Arc<Mutex<GovernanceDependencyData>>,
}

pub(crate) fn stage_governance_dependency_exact(
    data: &mut GovernanceDependencyData,
    write: &GovernanceDependencyWrite,
) -> PersistenceResult<ExactWriteOutcome> {
    let canonical = governance_dependency_canonical(&write.item)?;
    let (source_kind, source_ref) = write.source.storage_parts();
    let object_key = (
        write.realm_id.as_str().to_owned(),
        canonical.dependency_kind.to_owned(),
        canonical.object_digest.as_str().to_owned(),
    );
    let source_key = (
        write.realm_id.as_str().to_owned(),
        source_kind.to_owned(),
        source_ref.to_owned(),
    );
    let edge_value = (
        canonical.dependency_kind.to_owned(),
        canonical.object_digest.as_str().to_owned(),
    );
    if let Some((stored, stored_item)) = data.objects.get(&object_key)
        && (stored.canonical_bytes != canonical.canonical_bytes
            || stored.object_json != canonical.object_json
            || stored_item != &write.item)
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: governance dependency object differs".to_owned(),
        ));
    }
    let edges = data.edges.get(&source_key);
    if let Some(stored) = edges.and_then(|edges| edges.get(&write.edge_index)) {
        return if stored == &edge_value {
            Ok(ExactWriteOutcome::ExactReplay)
        } else {
            Err(PersistenceError::Conflict(
                "duplicate_conflict: governance dependency edge index differs".to_owned(),
            ))
        };
    }
    if edges.is_some_and(|edges| edges.values().any(|stored| stored == &edge_value)) {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: governance dependency edge moved index".to_owned(),
        ));
    }
    data.objects
        .entry(object_key)
        .or_insert((canonical, write.item.clone()));
    data.edges
        .entry(source_key)
        .or_default()
        .insert(write.edge_index, edge_value);
    Ok(ExactWriteOutcome::Inserted)
}

#[async_trait::async_trait]
impl GovernanceDependencyStore for MemoryGovernanceDependencyStore {
    async fn put_unscoped_signer_evidence_exact(
        &self,
        item: GovernanceDependency,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let canonical = governance_signer_evidence_canonical(&item)?;
        let key = (
            canonical.dependency_kind.to_owned(),
            canonical.object_digest.as_str().to_owned(),
        );
        let historical_key = historical_agent_signer_evidence_key(&item)?;
        let mut data = self.data.lock();
        if let Some((stored, stored_item)) = data.unscoped_signer_evidence.get(&key) {
            return if stored == &canonical && stored_item == &item {
                Ok(ExactWriteOutcome::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: unscoped signer evidence differs".to_owned(),
                ))
            };
        }
        if let Some(historical_key) = historical_key.as_ref()
            && let Some(existing) = data.historical_agent_signer_evidence.get(historical_key)
            && existing != &key
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: historical Agent signer evidence tuple differs".to_owned(),
            ));
        }
        let historical_object_key = key.clone();
        data.unscoped_signer_evidence.insert(key, (canonical, item));
        if let Some(historical_key) = historical_key {
            data.historical_agent_signer_evidence
                .insert(historical_key, historical_object_key);
        }
        Ok(ExactWriteOutcome::Inserted)
    }

    async fn get_unscoped_signer_evidence(
        &self,
        selector: &GovernanceDependencySelector,
    ) -> PersistenceResult<Option<GovernanceDependency>> {
        let (kind, digest) = governance_dependency_selector_parts(selector)?;
        if !matches!(
            selector,
            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { .. }
                | GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence { .. }
        ) {
            return Err(PersistenceError::SchemaViolation(
                "unscoped governance dependency lookup accepts signer evidence only".to_owned(),
            ));
        }
        Ok(self
            .data
            .lock()
            .unscoped_signer_evidence
            .get(&(kind.to_owned(), digest.as_str().to_owned()))
            .map(|(_, item)| item.clone()))
    }

    async fn get_historical_agent_signer_evidence(
        &self,
        key: &HistoricalAgentSignerEvidenceKey,
    ) -> PersistenceResult<Option<GovernanceDependency>> {
        let data = self.data.lock();
        let Some(object_key) = data.historical_agent_signer_evidence.get(key) else {
            return Ok(None);
        };
        data.unscoped_signer_evidence
            .get(object_key)
            .map(|(_, item)| item.clone())
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "historical Agent signer evidence index references a missing object".to_owned(),
                )
            })
            .map(Some)
    }

    async fn put_realm_object_exact(
        &self,
        realm_id: &arkret_wire::RealmId,
        item: GovernanceDependency,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let canonical = governance_dependency_canonical(&item)?;
        let key = (
            realm_id.as_str().to_owned(),
            canonical.dependency_kind.to_owned(),
            canonical.object_digest.as_str().to_owned(),
        );
        let mut data = self.data.lock();
        if let Some((stored, stored_item)) = data.objects.get(&key) {
            return if stored == &canonical && stored_item == &item {
                Ok(ExactWriteOutcome::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: governance dependency object differs".to_owned(),
                ))
            };
        }
        data.objects.insert(key, (canonical, item));
        Ok(ExactWriteOutcome::Inserted)
    }

    async fn put_exact(
        &self,
        write: GovernanceDependencyWrite,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let mut data = self.data.lock();
        stage_governance_dependency_exact(&mut data, &write)
    }

    async fn get(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &GovernanceDependencySelector,
    ) -> PersistenceResult<Option<GovernanceDependency>> {
        let (kind, digest) = governance_dependency_selector_parts(selector)?;
        Ok(self
            .data
            .lock()
            .objects
            .get(&(
                realm_id.as_str().to_owned(),
                kind.to_owned(),
                digest.as_str().to_owned(),
            ))
            .map(|(_, item)| item.clone()))
    }

    async fn list_for_source(
        &self,
        realm_id: &arkret_wire::RealmId,
        source: &GovernanceDependencySource,
    ) -> PersistenceResult<Vec<GovernanceDependencyEdgeRecord>> {
        let (source_kind, source_ref) = source.storage_parts();
        let data = self.data.lock();
        let Some(edges) = data.edges.get(&(
            realm_id.as_str().to_owned(),
            source_kind.to_owned(),
            source_ref.to_owned(),
        )) else {
            return Ok(Vec::new());
        };
        edges
            .iter()
            .map(|(edge_index, (kind, digest))| {
                data.objects
                    .get(&(realm_id.as_str().to_owned(), kind.clone(), digest.clone()))
                    .map(|(_, item)| GovernanceDependencyEdgeRecord {
                        edge_index: *edge_index,
                        item: item.clone(),
                    })
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "governance dependency edge references missing object".to_owned(),
                        )
                    })
            })
            .collect()
    }
}

#[derive(Default)]
struct HistoryTraversalData {
    records: BTreeMap<String, StoredHistoryTraversalRetention>,
    access: BTreeMap<(String, String), String>,
    objects: BTreeMap<(String, String), MemoryRetainedObject>,
}

#[derive(Clone)]
struct StoredHistoryTraversalRetention {
    access: soland_storage::HistoryTraversalAccess,
    retention: arkret_models_collaboration::history_key::HistoryGovernanceTraversalRetention,
    pins: Vec<soland_storage::HistoryTraversalPin>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
struct MemoryRetainedObject {
    canonical: HistoryTraversalRetainedObjectCanonical,
    object: HistoryTraversalRetainedObject,
    references: u64,
}

fn hydrate_retention(
    data: &HistoryTraversalData,
    stored: &StoredHistoryTraversalRetention,
) -> PersistenceResult<HistoryTraversalRetentionRecord> {
    let objects = stored
        .pins
        .iter()
        .map(|pin| {
            let (kind, _, digest) = pin.storage_parts()?;
            data.objects
                .get(&(kind.to_owned(), digest.as_str().to_owned()))
                .map(|stored| stored.object.clone())
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "history traversal pin references a missing retained object".to_owned(),
                    )
                })
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    Ok(HistoryTraversalRetentionRecord {
        write: HistoryTraversalRetentionWrite {
            access: stored.access.clone(),
            retention: stored.retention.clone(),
            pins: stored.pins.clone(),
            objects,
        },
        created_at: stored.created_at,
    })
}

#[derive(Clone, Default)]
pub struct MemoryHistoryTraversalRetentionStore {
    data: Arc<Mutex<HistoryTraversalData>>,
    transaction_gate: Arc<Mutex<()>>,
}

impl MemoryHistoryTraversalRetentionStore {
    pub(crate) fn transaction_gate(&self) -> Arc<Mutex<()>> {
        self.transaction_gate.clone()
    }

    pub(crate) fn persist_exact_locked(
        &self,
        write: HistoryTraversalRetentionWrite,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let canonical = history_traversal_canonical(&write)?;
        let retention_digest = write.retention.traversal_intent_digest.as_str().to_owned();
        let (access_kind, access_digest) = write.access.storage_parts();
        let access_key = (access_kind.to_owned(), access_digest.as_str().to_owned());
        let mut data = self.data.lock();
        if let Some(record) = data.records.get(&retention_digest) {
            let stored = hydrate_retention(&data, record)?;
            return if stored.write.access == write.access
                && stored.write.retention == write.retention
                && stored.write.pins == write.pins
                && history_traversal_canonical(&stored.write)? == canonical
            {
                Ok(ExactWriteOutcome::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: history traversal retention differs".to_owned(),
                ))
            };
        }
        if data
            .access
            .get(&access_key)
            .is_some_and(|stored| stored != &retention_digest)
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: traversal access is already bound".to_owned(),
            ));
        }
        for object_canonical in &canonical.retained_objects {
            let key = (
                object_canonical.object_kind.to_owned(),
                object_canonical.object_digest.as_str().to_owned(),
            );
            if let Some(stored) = data.objects.get(&key)
                && (stored.canonical != *object_canonical || stored.references == u64::MAX)
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: retained object digest has different bytes".to_owned(),
                ));
            }
        }
        let normalized_objects = canonical
            .retained_objects
            .iter()
            .map(|object| {
                history_traversal_retained_object_from_json(
                    object.object_kind,
                    object.object_json.clone(),
                )
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        for (object_canonical, normalized) in
            canonical.retained_objects.iter().zip(normalized_objects)
        {
            let key = (
                object_canonical.object_kind.to_owned(),
                object_canonical.object_digest.as_str().to_owned(),
            );
            if let Some(stored) = data.objects.get_mut(&key) {
                stored.references += 1;
            } else {
                data.objects.insert(
                    key,
                    MemoryRetainedObject {
                        canonical: object_canonical.clone(),
                        object: normalized,
                        references: 1,
                    },
                );
            }
        }
        data.access.insert(access_key, retention_digest.clone());
        data.records.insert(
            retention_digest,
            StoredHistoryTraversalRetention {
                access: write.access,
                retention: write.retention,
                pins: write.pins,
                created_at: chrono::Utc::now(),
            },
        );
        Ok(ExactWriteOutcome::Inserted)
    }

    pub(crate) fn append_response_signer_dependencies_locked(
        &self,
        retention_digest: &arkret_wire::Hash,
        record: &arkret_models_collaboration::history_key::HistoryKeyResponseRecord,
        dependencies: &[GovernanceDependency],
    ) -> PersistenceResult<()> {
        let additions =
            soland_storage::history_response_signer_retained_dependencies(record, dependencies)?;
        self.append_signer_dependency_additions_locked(retention_digest, additions)
    }

    pub(crate) fn append_lost_signer_dependencies_locked(
        &self,
        retention_digest: &arkret_wire::Hash,
        lost_record: &arkret_models_collaboration::history_key::HistoryKeyResponseLostRecord,
        dependencies: &[GovernanceDependency],
    ) -> PersistenceResult<()> {
        let additions =
            soland_storage::history_lost_signer_retained_dependencies(lost_record, dependencies)?;
        self.append_signer_dependency_additions_locked(retention_digest, additions)
    }

    fn append_signer_dependency_additions_locked(
        &self,
        retention_digest: &arkret_wire::Hash,
        additions: Vec<(
            soland_storage::HistoryTraversalPin,
            soland_storage::HistoryTraversalRetainedObject,
        )>,
    ) -> PersistenceResult<()> {
        let canonical = additions
            .iter()
            .map(|(_, object)| soland_storage::history_traversal_retained_object_canonical(object))
            .collect::<PersistenceResult<Vec<_>>>()?;
        let mut data = self.data.lock();
        let existing_pins = data
            .records
            .get(retention_digest.as_str())
            .ok_or_else(|| {
                PersistenceError::NotFound(
                    "history source response traversal retention is unavailable".to_owned(),
                )
            })?
            .pins
            .clone();
        let additions = additions
            .into_iter()
            .zip(canonical)
            .filter(|((pin, _), _)| !existing_pins.contains(pin))
            .collect::<Vec<_>>();
        if existing_pins.len() + additions.len() > 4_096 {
            return Err(PersistenceError::SchemaViolation(
                "history traversal retention exceeds 4096 pinned objects".to_owned(),
            ));
        }
        for ((..), object) in &additions {
            let key = (
                object.object_kind.to_owned(),
                object.object_digest.as_str().to_owned(),
            );
            if let Some(stored) = data.objects.get(&key)
                && (stored.canonical != *object || stored.references == u64::MAX)
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: retained source evidence digest has different bytes"
                        .to_owned(),
                ));
            }
        }
        for ((pin, object), canonical) in additions {
            let key = (
                canonical.object_kind.to_owned(),
                canonical.object_digest.as_str().to_owned(),
            );
            if let Some(stored) = data.objects.get_mut(&key) {
                stored.references += 1;
            } else {
                data.objects.insert(
                    key,
                    MemoryRetainedObject {
                        canonical,
                        object,
                        references: 1,
                    },
                );
            }
            data.records
                .get_mut(retention_digest.as_str())
                .expect("validated retention disappeared")
                .pins
                .push(pin);
        }
        Ok(())
    }

    pub(crate) fn validate_release_locked(
        &self,
        retention_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<bool> {
        let data = self.data.lock();
        let Some(record) = data.records.get(retention_digest.as_str()) else {
            return Ok(false);
        };
        for pin in &record.pins {
            let (kind, _, digest) = pin.storage_parts()?;
            let Some(object) = data
                .objects
                .get(&(kind.to_owned(), digest.as_str().to_owned()))
            else {
                return Err(PersistenceError::Internal(
                    "history traversal pin references a missing retained object".to_owned(),
                ));
            };
            if object.references == 0 {
                return Err(PersistenceError::Internal(
                    "history traversal retained object reference count is invalid".to_owned(),
                ));
            }
        }
        Ok(true)
    }

    pub(crate) fn release_locked(
        &self,
        retention_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<bool> {
        // The same aggregate transaction gate prevents this preflight from becoming stale.
        if !self.validate_release_locked(retention_digest)? {
            return Ok(false);
        }
        let mut data = self.data.lock();
        let record = data
            .records
            .get(retention_digest.as_str())
            .cloned()
            .expect("validated history traversal retention disappeared");
        data.records.remove(retention_digest.as_str());
        let (kind, digest) = record.access.storage_parts();
        data.access
            .remove(&(kind.to_owned(), digest.as_str().to_owned()));
        for pin in &record.pins {
            let (kind, _, digest) = pin.storage_parts()?;
            let key = (kind.to_owned(), digest.as_str().to_owned());
            let remove = match data.objects.get_mut(&key) {
                Some(object) if object.references <= 1 => true,
                Some(object) => {
                    object.references -= 1;
                    false
                }
                None => false,
            };
            if remove {
                data.objects.remove(&key);
            }
        }
        Ok(true)
    }
}

#[async_trait::async_trait]
impl HistoryTraversalRetentionStore for MemoryHistoryTraversalRetentionStore {
    async fn persist_exact(
        &self,
        write: HistoryTraversalRetentionWrite,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let gate = self.transaction_gate.clone();
        let _guard = gate.lock();
        self.persist_exact_locked(write)
    }

    async fn get(
        &self,
        retention_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<Option<HistoryTraversalRetentionRecord>> {
        let gate = self.transaction_gate.clone();
        let _guard = gate.lock();
        let data = self.data.lock();
        data.records
            .get(retention_digest.as_str())
            .map(|stored| hydrate_retention(&data, stored))
            .transpose()
    }

    async fn resolve_retained_object(
        &self,
        retention_digest: &arkret_wire::Hash,
        pin: &soland_storage::HistoryTraversalPin,
    ) -> PersistenceResult<Option<HistoryTraversalRetainedObjectRecord>> {
        let gate = self.transaction_gate.clone();
        let _guard = gate.lock();
        let data = self.data.lock();
        let Some(retention) = data.records.get(retention_digest.as_str()) else {
            return Ok(None);
        };
        if !retention.pins.contains(pin) {
            return Ok(None);
        }
        let (kind, _, digest) = pin.storage_parts()?;
        let Some(object) = data
            .objects
            .get(&(kind.to_owned(), digest.as_str().to_owned()))
        else {
            return Err(PersistenceError::Internal(
                "history traversal retained object is missing".to_owned(),
            ));
        };
        Ok(Some(HistoryTraversalRetainedObjectRecord {
            pin: pin.clone(),
            object: object.object.clone(),
            canonical_bytes: object.canonical.canonical_bytes.clone(),
        }))
    }

    async fn release(&self, retention_digest: &arkret_wire::Hash) -> PersistenceResult<bool> {
        let gate = self.transaction_gate.clone();
        let _guard = gate.lock();
        self.release_locked(retention_digest)
    }
}

#[derive(Clone, Default)]
pub struct MemoryPendingRrkAcquisitionStore {
    data: Arc<Mutex<BTreeMap<String, PendingRrkAcquisitionRecord>>>,
}

#[async_trait::async_trait]
impl PendingRrkAcquisitionStore for MemoryPendingRrkAcquisitionStore {
    async fn enqueue_exact(
        &self,
        input: PendingRrkAcquisitionInput,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ExactWriteOutcome> {
        input.validate()?;
        let mut data = self.data.lock();
        if let Some(record) = data.get(input.acquisition_digest.as_str()) {
            return if record.input == input {
                Ok(ExactWriteOutcome::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: pending RRK acquisition differs".to_owned(),
                ))
            };
        }
        for record in data.values() {
            if rrk_semantically_same(&record.input.archive_replica, &input.archive_replica)? {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: pending RRK semantic tuple already exists".to_owned(),
                ));
            }
        }
        data.insert(
            input.acquisition_digest.as_str().to_owned(),
            PendingRrkAcquisitionRecord {
                input,
                state: PendingRrkAcquisitionState::Pending,
                attempt_count: 0,
                claim_token: None,
                claim_until: None,
                ready_at: None,
                archive_sequence: None,
                accepted_outcome: None,
                last_error_code: None,
                created_at: now,
                updated_at: now,
            },
        );
        Ok(ExactWriteOutcome::Inserted)
    }

    async fn get(
        &self,
        acquisition_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<Option<PendingRrkAcquisitionRecord>> {
        Ok(self.data.lock().get(acquisition_digest.as_str()).cloned())
    }

    async fn list_accepted_for_authority(
        &self,
        effective_scope: &arkret_wire::HistoryEffectiveScope,
        holder_principal_id: &arkret_wire::DidCoreId,
        holder_id: &arkret_wire::DidCoreId,
        from_epoch: u64,
        to_epoch: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRrkAcquisitionRecord>> {
        if from_epoch > to_epoch || !(1..=65_537).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "invalid accepted RRK authority query bounds".to_owned(),
            ));
        }
        let mut records = self
            .data
            .lock()
            .values()
            .filter(|record| record.state == PendingRrkAcquisitionState::Accepted)
            .filter(|record| {
                let archive = &record.input.archive_replica.archive;
                &archive.effective_scope == effective_scope
                    && &archive.holder_principal_id == holder_principal_id
                    && &archive.holder_id == holder_id
                    && from_epoch <= archive.epoch
                    && archive.epoch <= to_epoch
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            let left_replica = &left.input.archive_replica;
            let right_replica = &right.input.archive_replica;
            left_replica
                .archive
                .epoch
                .cmp(&right_replica.archive.epoch)
                .then_with(|| {
                    left_replica
                        .container_event_ref
                        .as_str()
                        .as_bytes()
                        .cmp(right_replica.container_event_ref.as_str().as_bytes())
                })
                .then_with(|| {
                    left.input
                        .archive_replica_digest
                        .as_str()
                        .as_bytes()
                        .cmp(right.input.archive_replica_digest.as_str().as_bytes())
                })
        });
        records.truncate(limit);
        Ok(records)
    }

    async fn list_accepted_for_archive_query(
        &self,
        query: &arkret_models_collaboration::history_key::OrganizationRecoveryArchiveListQuery,
        holder_principal_id: &arkret_wire::DidCoreId,
        after_archive_sequence: Option<u64>,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRrkAcquisitionRecord>> {
        if !(1..=4_097).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "invalid accepted RRK archive query limit".to_owned(),
            ));
        }
        let mut records = self
            .data
            .lock()
            .values()
            .filter(|record| record.state == PendingRrkAcquisitionState::Accepted)
            .filter(|record| {
                record.accepted_outcome.as_ref().is_some_and(|outcome| {
                    after_archive_sequence.is_none_or(|after| outcome.archive_sequence > after)
                })
            })
            .filter(|record| {
                let archive = &record.input.archive_replica.archive;
                &archive.holder_principal_id == holder_principal_id
                    && archive.effective_scope == query.effective_scope
                    && archive.recovery_key_id == query.recovery_key_id
                    && archive.key_agreement_ref == query.key_agreement_ref
                    && archive.accepted_key_evidence_ref == query.accepted_key_evidence_ref
                    && archive.holder_trusted_basis == query.holder_trusted_basis
                    && query.from_epoch.is_none_or(|from| archive.epoch >= from)
                    && query.to_epoch.is_none_or(|to| archive.epoch <= to)
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by_key(|record| {
            record
                .accepted_outcome
                .as_ref()
                .map(|outcome| outcome.archive_sequence)
                .unwrap_or_default()
        });
        records.truncate(limit);
        Ok(records)
    }

    async fn claim_due(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        claim_token: &str,
        claim_until: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRrkAcquisitionRecord>> {
        if claim_token.is_empty() || claim_until <= now || !(1..=4_096).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "invalid pending RRK claim bounds".to_owned(),
            ));
        }
        let mut data = self.data.lock();
        let mut due = data
            .iter()
            .filter(|(_, record)| {
                record.state != PendingRrkAcquisitionState::Accepted
                    && record.input.next_attempt_at <= now
                    && record.claim_until.is_none_or(|until| until <= now)
                    && record.attempt_count < i64::MAX as u64
            })
            .map(|(digest, record)| (record.input.next_attempt_at, digest.clone()))
            .collect::<Vec<_>>();
        due.sort_unstable();
        let mut claimed = Vec::new();
        for (_, digest) in due.into_iter().take(limit) {
            let record = data.get_mut(&digest).expect("due RRK row disappeared");
            record.attempt_count += 1;
            record.claim_token = Some(claim_token.to_owned());
            record.claim_until = Some(claim_until);
            record.updated_at = now;
            claimed.push(record.clone());
        }
        Ok(claimed)
    }

    async fn record_retry(
        &self,
        acquisition_digest: &arkret_wire::Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
        error_code: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<StorageCasOutcome> {
        if claim_token.is_empty() || error_code.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "pending RRK retry token and error code must be non-empty".to_owned(),
            ));
        }
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(acquisition_digest.as_str()) else {
            return Ok(StorageCasOutcome::Mismatch);
        };
        if record.attempt_count == expected_attempt_count
            && record.claim_token.is_none()
            && record.input.next_attempt_at == next_attempt_at
            && record.last_error_code.as_deref() == Some(error_code)
        {
            return Ok(StorageCasOutcome::ExactReplay);
        }
        if record.state == PendingRrkAcquisitionState::Accepted
            || record.attempt_count != expected_attempt_count
            || record.claim_token.as_deref() != Some(claim_token)
        {
            return Ok(StorageCasOutcome::Mismatch);
        }
        record.input.next_attempt_at = next_attempt_at;
        record.claim_token = None;
        record.claim_until = None;
        record.last_error_code = Some(error_code.to_owned());
        record.updated_at = now;
        Ok(StorageCasOutcome::Applied)
    }

    async fn mark_ready(
        &self,
        acquisition_digest: &arkret_wire::Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        ready_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<StorageCasOutcome> {
        if claim_token.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "pending RRK ready claim token must be non-empty".to_owned(),
            ));
        }
        let mut data = self.data.lock();
        let Some(existing) = data.get(acquisition_digest.as_str()) else {
            return Ok(StorageCasOutcome::Mismatch);
        };
        if existing.state == PendingRrkAcquisitionState::Ready
            && existing.attempt_count == expected_attempt_count
            && existing.ready_at == Some(ready_at)
        {
            return Ok(StorageCasOutcome::ExactReplay);
        }
        if existing.state != PendingRrkAcquisitionState::Pending
            || existing.attempt_count != expected_attempt_count
            || existing.claim_token.as_deref() != Some(claim_token)
        {
            return Ok(StorageCasOutcome::Mismatch);
        }
        let next_archive_sequence = data
            .values()
            .filter_map(|record| record.archive_sequence)
            .max()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                PersistenceError::Conflict("RRK archive sequence exhausted".to_owned())
            })?;
        let Some(record) = data.get_mut(acquisition_digest.as_str()) else {
            return Ok(StorageCasOutcome::Mismatch);
        };
        record.state = PendingRrkAcquisitionState::Ready;
        record.ready_at = Some(ready_at);
        record.archive_sequence = Some(next_archive_sequence);
        record.last_error_code = None;
        record.updated_at = ready_at;
        Ok(StorageCasOutcome::Applied)
    }

    async fn mark_accepted(
        &self,
        acquisition_digest: &arkret_wire::Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        outcome: arkret_models_collaboration::history_key::OrganizationRecoveryArchiveReplicaOutcome,
    ) -> PersistenceResult<StorageCasOutcome> {
        if claim_token.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "pending RRK acceptance claim token must be non-empty".to_owned(),
            ));
        }
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(acquisition_digest.as_str()) else {
            return Ok(StorageCasOutcome::Mismatch);
        };
        validate_rrk_acceptance(&record.input, &outcome)?;
        if record.state == PendingRrkAcquisitionState::Accepted
            && record.attempt_count == expected_attempt_count
            && record.accepted_outcome.as_ref() == Some(&outcome)
        {
            return Ok(StorageCasOutcome::ExactReplay);
        }
        if record.state != PendingRrkAcquisitionState::Ready
            || record.attempt_count != expected_attempt_count
            || record.claim_token.as_deref() != Some(claim_token)
            || record.archive_sequence != Some(outcome.archive_sequence)
            || record
                .ready_at
                .is_none_or(|ready_at| outcome.accepted_at < ready_at)
        {
            return Ok(StorageCasOutcome::Mismatch);
        }
        record.state = PendingRrkAcquisitionState::Accepted;
        record.claim_token = None;
        record.claim_until = None;
        record.accepted_outcome = Some(outcome.clone());
        record.last_error_code = None;
        record.updated_at = outcome.accepted_at;
        Ok(StorageCasOutcome::Applied)
    }
}
