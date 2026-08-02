use super::{
    Arc, BTreeMap, BackupSeriesEraseProgressRecord, Mutex, PersistenceError, PersistenceResult,
    RecoveryPolicyRecord, RecoveryPolicyStore, RecoverySessionRecord, RecoverySessionStore,
    SecurityTransactionRecord, SecurityTransactionStepAttemptRecord,
    SecurityTransactionStepOutcomeRecord, SecurityTransactionStore, async_trait,
    recovery_active_policy_locked,
};
#[derive(Default)]
pub(crate) struct MemoryRecoveryPolicyStore {
    data: Mutex<BTreeMap<String, RecoveryPolicyRecord>>,
}
impl MemoryRecoveryPolicyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl RecoveryPolicyStore for MemoryRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        Ok(self.data.lock().get(policy_id).cloned())
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let data = self.data.lock();
        Ok(recovery_active_policy_locked(&data, principal_id))
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let data = self.data.lock();
        let mut out: Vec<RecoveryPolicyRecord> = data
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.version));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        if data.contains_key(&record.policy_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if data.values().any(|existing| {
            existing.principal_id == record.principal_id && existing.version == record.version
        }) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = recovery_active_policy_locked(&data, &record.principal_id) {
            if record.version <= active.version {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy version {} is not greater than active {}",
                    record.version, active.version
                )));
            }
            if record.supersedes.as_deref() != Some(active.policy_id.as_str()) {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy supersedes {:?} does not match active `{}`",
                    record.supersedes, active.policy_id
                )));
            }
        } else if record.version != 1 {
            return Err(PersistenceError::Conflict(format!(
                "recovery genesis policy for `{}` must have version=1",
                record.principal_id
            )));
        }
        data.insert(record.policy_id.clone(), record);
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct MemoryRecoverySessionStore {
    by_id: Arc<Mutex<BTreeMap<String, RecoverySessionRecord>>>,
}
impl MemoryRecoverySessionStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn shared_data(&self) -> Arc<Mutex<BTreeMap<String, RecoverySessionRecord>>> {
        self.by_id.clone()
    }
}
#[async_trait]
impl RecoverySessionStore for MemoryRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        Ok(self.by_id.lock().get(recovery_session_id).cloned())
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock();
        if by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already exists",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock();
        if !by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }
}

pub(crate) struct MemorySecurityTransactionStore {
    sessions: Arc<Mutex<BTreeMap<String, RecoverySessionRecord>>>,
    by_id: Mutex<BTreeMap<String, SecurityTransactionRecord>>,
    step_attempts: Mutex<BTreeMap<(String, String), SecurityTransactionStepAttemptRecord>>,
    step_outcomes: Mutex<BTreeMap<(String, String), SecurityTransactionStepOutcomeRecord>>,
    backup_erase_progress: Mutex<BTreeMap<String, BackupSeriesEraseProgressRecord>>,
}

impl MemorySecurityTransactionStore {
    pub(crate) fn new(sessions: Arc<Mutex<BTreeMap<String, RecoverySessionRecord>>>) -> Self {
        Self {
            sessions,
            by_id: Mutex::new(BTreeMap::new()),
            step_attempts: Mutex::new(BTreeMap::new()),
            step_outcomes: Mutex::new(BTreeMap::new()),
            backup_erase_progress: Mutex::new(BTreeMap::new()),
        }
    }
}

fn security_transaction_step_key(step: arkret_wire::SecurityTransactionStep) -> String {
    serde_json::to_value(step)
        .expect("security transaction step serializes")
        .as_str()
        .expect("security transaction step is a string")
        .to_owned()
}

#[async_trait]
impl SecurityTransactionStore for MemorySecurityTransactionStore {
    async fn create(
        &self,
        record: SecurityTransactionRecord,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        arkret_canonical::canonical::verify_digest(
            &record.canonical_request,
            record.resource.request_digest.as_str(),
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let transaction_id = record.resource.transaction_id.as_str();
        let mut sessions = self.sessions.lock();
        let mut by_id = self.by_id.lock();
        if let Some(existing) = by_id.get(transaction_id) {
            if existing.canonical_request == record.canonical_request {
                return Ok(existing.clone());
            }
            return Err(PersistenceError::Conflict(format!(
                "transaction_id `{transaction_id}` already exists with different canonical bytes"
            )));
        }
        if let arkret_wire::SecurityTransactionBinding::Recovery(binding) = &record.resource.binding
        {
            let session_id = binding.recovery_session_id().as_str();
            let session = sessions.get_mut(session_id).ok_or_else(|| {
                PersistenceError::NotFound(format!("recovery_session_id `{session_id}` not found"))
            })?;
            if session.principal_id != record.resource.principal_id.as_str()
                || session.state != "verified"
                || session.expires_at <= chrono::Utc::now()
            {
                return Err(PersistenceError::Conflict(
                    "recovery session is not a current verified session for the transaction principal"
                        .to_owned(),
                ));
            }
            if let Some(bound) = &session.transaction_id {
                return Err(PersistenceError::Conflict(format!(
                    "recovery session is already bound to `{bound}`"
                )));
            }
            session.transaction_id = Some(transaction_id.to_owned());
            session.updated_at = chrono::Utc::now();
        }
        by_id.insert(transaction_id.to_owned(), record.clone());
        Ok(record)
    }

    async fn get(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<SecurityTransactionRecord>> {
        Ok(self.by_id.lock().get(transaction_id).cloned())
    }

    async fn update(&self, record: SecurityTransactionRecord) -> PersistenceResult<()> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let transaction_id = record.resource.transaction_id.as_str();
        let mut by_id = self.by_id.lock();
        let existing = by_id.get(transaction_id).ok_or_else(|| {
            PersistenceError::NotFound(format!("transaction_id `{transaction_id}` not found"))
        })?;
        super::validate_security_transaction_update(existing, &record)?;
        by_id.insert(transaction_id.to_owned(), record);
        Ok(())
    }

    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>> {
        Ok(self
            .step_outcomes
            .lock()
            .get(&(
                transaction_id.to_owned(),
                security_transaction_step_key(step),
            ))
            .cloned())
    }

    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepAttemptRecord>> {
        Ok(self
            .step_attempts
            .lock()
            .get(&(
                transaction_id.to_owned(),
                security_transaction_step_key(step),
            ))
            .cloned())
    }

    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptRecord,
    ) -> PersistenceResult<SecurityTransactionStepAttemptRecord> {
        let key = (
            attempt.transaction_id.clone(),
            security_transaction_step_key(attempt.step),
        );
        if !self.by_id.lock().contains_key(&attempt.transaction_id) {
            return Err(PersistenceError::NotFound(format!(
                "transaction_id `{}` not found",
                attempt.transaction_id
            )));
        }
        let mut attempts = self.step_attempts.lock();
        if let Some(existing) = attempts.get(&key) {
            if existing.canonical_request == attempt.canonical_request {
                return Ok(existing.clone());
            }
            return Err(PersistenceError::Conflict(format!(
                "security transaction step {:?} already began with different canonical bytes",
                attempt.step
            )));
        }
        attempts.insert(key, attempt.clone());
        Ok(attempt)
    }

    async fn accept_step(
        &self,
        record: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeRecord,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord> {
        let transaction_id = record.resource.transaction_id.as_str();
        if outcome.transaction_id != transaction_id {
            return Err(PersistenceError::SchemaViolation(
                "security transaction step outcome belongs to a different transaction".to_owned(),
            ));
        }
        let key = (
            transaction_id.to_owned(),
            security_transaction_step_key(outcome.step),
        );
        let mut sessions = self.sessions.lock();
        let mut by_id = self.by_id.lock();
        let attempts = self.step_attempts.lock();
        let mut outcomes = self.step_outcomes.lock();
        if let Some(existing) = outcomes.get(&key) {
            if existing.canonical_request == outcome.canonical_request {
                return Ok(existing.clone());
            }
            return Err(PersistenceError::Conflict(format!(
                "security transaction step {:?} already has different canonical request bytes",
                outcome.step
            )));
        }
        let existing = by_id.get(transaction_id).ok_or_else(|| {
            PersistenceError::NotFound(format!("transaction_id `{transaction_id}` not found"))
        })?;
        let attempt = attempts.get(&key).ok_or_else(|| {
            PersistenceError::Conflict(format!(
                "security transaction step {:?} was not durably begun",
                outcome.step
            ))
        })?;
        if attempt.canonical_request != outcome.canonical_request {
            return Err(PersistenceError::Conflict(format!(
                "security transaction step {:?} outcome changed the durable request bytes",
                outcome.step
            )));
        }
        super::validate_security_transaction_update(existing, &record)?;
        if record.resource.accepted_steps.len() != existing.resource.accepted_steps.len() + 1
            || record.resource.accepted_steps.last().map(|step| step.step) != Some(outcome.step)
        {
            return Err(PersistenceError::SchemaViolation(
                "accepted step outcome must match the single appended transaction step".to_owned(),
            ));
        }
        if record.resource.state == arkret_wire::SecurityTransactionState::Completed
            && let arkret_wire::SecurityTransactionBinding::Recovery(binding) =
                &record.resource.binding
        {
            let session_id = binding.recovery_session_id().as_str();
            let recovery_session = sessions.get_mut(session_id).ok_or_else(|| {
                PersistenceError::NotFound(format!("recovery_session_id `{session_id}` not found"))
            })?;
            if recovery_session.transaction_id.as_deref() != Some(transaction_id)
                || recovery_session.state != "verified"
            {
                return Err(PersistenceError::Conflict(
                    "terminal recovery transaction does not own a verified recovery session"
                        .to_owned(),
                ));
            }
            recovery_session.state = "completed".to_owned();
            recovery_session.updated_at = chrono::Utc::now();
        }
        by_id.insert(transaction_id.to_owned(), record);
        outcomes.insert(key, outcome.clone());
        Ok(outcome)
    }

    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<BackupSeriesEraseProgressRecord>> {
        Ok(self
            .backup_erase_progress
            .lock()
            .get(transaction_id)
            .cloned())
    }

    async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord> {
        super::validate_backup_erase_progress_initial(&progress)?;
        if !self.by_id.lock().contains_key(&progress.transaction_id) {
            return Err(PersistenceError::NotFound(format!(
                "transaction_id `{}` not found",
                progress.transaction_id
            )));
        }
        let mut records = self.backup_erase_progress.lock();
        if let Some(existing) = records.get(&progress.transaction_id) {
            if existing.canonical_request == progress.canonical_request {
                return Ok(existing.clone());
            }
            return Err(PersistenceError::Conflict(
                "backup erase already began with different canonical bytes".to_owned(),
            ));
        }
        records.insert(progress.transaction_id.clone(), progress.clone());
        Ok(progress)
    }

    async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord> {
        let mut records = self.backup_erase_progress.lock();
        let existing = records.get(&progress.transaction_id).ok_or_else(|| {
            PersistenceError::NotFound(format!(
                "backup erase progress for transaction `{}` not found",
                progress.transaction_id
            ))
        })?;
        super::validate_backup_erase_progress_update(existing, &progress)?;
        records.insert(progress.transaction_id.clone(), progress.clone());
        Ok(progress)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AcceptedStep, AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, BackupId,
        BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
        BackupSeriesId, CanonicalEncoding, CanonicalPublicMaterial, DeviceId, Did, DidUrl, Event,
        EventId, EventInitialSubmission, EventsSubmitBatchRequestBody, Hash, Hlc, LeaseBasisRef,
        PayloadProof, PreparedEventUnit, RealmId, RiskTier, SchemaId, ScopeRef, SealId,
        SecurityRotationTransactionCreateRequest, SecurityTransactionBinding,
        SecurityTransactionCreateRequest, SecurityTransactionState, SecurityTransactionStep,
        TransactionId, proof_kind,
    };
    use chrono::{Duration, Utc};
    use serde_json::json;

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn canonical_material(binding: &BackupRotationBinding) -> CanonicalPublicMaterial {
        let backup_kind = match binding.backup_kind {
            BackupRotationKind::SecretStorage => "secret_storage",
            BackupRotationKind::MlsHistory => "mls_history",
        };
        let value = serde_json::Value::Array(
            binding
                .new_backups
                .iter()
                .map(|backup| {
                    json!({
                        "actor_id": "did:web:alice.example",
                        "backup_id": backup.backup_id,
                        "backup_kind": backup_kind,
                        "ciphertext_digest": backup.ciphertext_digest,
                        "series_id": binding.new_series_id,
                    })
                })
                .collect(),
        );
        let bytes = arkret_canonical::canonical_json_bytes(&value).unwrap();
        CanonicalPublicMaterial {
            canonical_encoding: CanonicalEncoding::CanonicalJson,
            value,
            canonical_bytes_base64url: arkret_canonical::base64url_encode(&bytes),
            digest: Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap(),
        }
    }

    fn erase_authorization_lease() -> AuthorizationLease {
        let scope_ref = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:019a7360-0000-7000-8000-000000000100").unwrap(),
        };
        let authority_set_policy = AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.backup_erase.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: "ak:event:019a7360-0000-7000-8000-000000000111".to_owned(),
                source_digest: hash('e'),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "backup_erase".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec!["ak.keys.backup_series.erase".to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new(
                        "did:web:principal.example#backup-erase-authority",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        };
        let now = Utc::now();
        let mut lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:019a7360-0000-7000-8000-000000000112",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:019a7360-0000-7000-8000-000000000113").unwrap(),
            scope_ref,
            action: "ak.keys.backup_series.erase".to_owned(),
            authorization_rule_id: "backup_erase".to_owned(),
            risk_tier: RiskTier::High,
            issued_at: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            authority_set_ref: AuthoritySetRef {
                authority_set_id: authority_set_policy.authority_set_id.clone(),
                authority_set_digest: authority_set_policy.digest().unwrap(),
            },
            authority_set_policy,
            proofs: Vec::new(),
        };
        let digest = lease.lease_digest().unwrap();
        lease.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:principal.example#backup-erase-authority",
            )
            .unwrap(),
            payload_digest: digest,
            created_at: lease.issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        lease
    }

    fn initial_erase_progress(
        transaction: &SecurityTransactionRecord,
    ) -> BackupSeriesEraseProgressRecord {
        let SecurityTransactionBinding::SecurityRotation(binding) = &transaction.resource.binding
        else {
            panic!("test transaction must be a security rotation");
        };
        let request = arkret_models_crypto::BackupSeriesEraseRequestBody {
            transaction_id: transaction.resource.transaction_id.clone(),
            transaction_request_digest: transaction.resource.request_digest.clone(),
            prepared_plan_digest: transaction.resource.prepared_plan_digest.clone(),
            erase_confirmation_digest: binding.erase_confirmation_digest.clone(),
            series: binding.backup_rotations.clone(),
            authorization_lease: erase_authorization_lease(),
            cba_proof_bundles: Vec::new(),
        };
        request.validate_structural().unwrap();
        let canonical_request = arkret_canonical::canonical_json_bytes(&request).unwrap();
        let request_digest =
            Hash::new(arkret_canonical::sha256_digest(&canonical_request)).unwrap();
        let series_results = request
            .series
            .iter()
            .map(|binding| {
                let mut remaining_backups = binding.old_backups.clone();
                remaining_backups
                    .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
                arkret_models_crypto::BackupSeriesEraseResult {
                    backup_kind: binding.backup_kind,
                    previous_series_id: binding.previous_series_id.clone(),
                    new_series_id: binding.new_series_id.clone(),
                    status: arkret_models_crypto::BackupSeriesEraseResultStatus::Pending,
                    erased_backups: Vec::new(),
                    remaining_backups,
                    reason_code: None,
                }
            })
            .collect();
        BackupSeriesEraseProgressRecord {
            transaction_id: transaction.resource.transaction_id.as_str().to_owned(),
            canonical_request,
            outcome: arkret_models_crypto::BackupSeriesEraseOutcome {
                transaction_id: transaction.resource.transaction_id.clone(),
                request_digest,
                status: arkret_models_crypto::BackupSeriesEraseStatus::Partial,
                series_results,
                confirmation: None,
            },
        }
    }

    fn event_unit(service_id: &Did, event_id: EventId, kind: &str) -> PreparedEventUnit {
        let authorization_lease = erase_authorization_lease();
        let event = Event::new_with_id_at(
            event_id,
            kind,
            authorization_lease.scope_ref.clone(),
            authorization_lease.actor_id.clone(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"fixture": true}),
            Utc::now(),
        )
        .unwrap();
        let request = EventsSubmitBatchRequestBody {
            events: vec![EventInitialSubmission {
                event,
                authorization_lease: Some(authorization_lease),
                cba_proof_bundles: Vec::new(),
                control_proposal_receipt: None,
            }],
        };
        PreparedEventUnit::new(service_id.clone(), serde_json::to_value(request).unwrap()).unwrap()
    }

    fn initial_rotation() -> SecurityTransactionRecord {
        let service_id = Did::new("did:web:principal.example").unwrap();
        let secret_binding = BackupRotationBinding {
            backup_kind: BackupRotationKind::SecretStorage,
            previous_series_id: BackupSeriesId::new(
                "ak:backup_series:019a7360-0000-7000-8000-000000000109",
            )
            .unwrap(),
            new_series_id: BackupSeriesId::new(
                "ak:backup_series:019a7360-0000-7000-8000-00000000010a",
            )
            .unwrap(),
            new_backups: vec![
                BackupObjectRef {
                    backup_id: BackupId::new("ak:backup:019a7360-0000-7000-8000-00000000010b")
                        .unwrap(),
                    ciphertext_digest: hash('b'),
                },
                BackupObjectRef {
                    backup_id: BackupId::new("ak:backup:019a7360-0000-7000-8000-00000000010c")
                        .unwrap(),
                    ciphertext_digest: hash('c'),
                },
            ],
            active_series_event_id: EventId::new("ak:event:019a7360-0000-7000-8000-00000000010d")
                .unwrap(),
            old_backups: vec![BackupObjectRef {
                backup_id: BackupId::new("ak:backup:019a7360-0000-7000-8000-00000000010e").unwrap(),
                ciphertext_digest: hash('9'),
            }],
        };
        let mls_binding = BackupRotationBinding {
            backup_kind: BackupRotationKind::MlsHistory,
            previous_series_id: BackupSeriesId::new(
                "ak:backup_series:019a7360-0000-7000-8000-000000000103",
            )
            .unwrap(),
            new_series_id: BackupSeriesId::new(
                "ak:backup_series:019a7360-0000-7000-8000-000000000104",
            )
            .unwrap(),
            new_backups: vec![
                BackupObjectRef {
                    backup_id: BackupId::new("ak:backup:019a7360-0000-7000-8000-000000000105")
                        .unwrap(),
                    ciphertext_digest: hash('5'),
                },
                BackupObjectRef {
                    backup_id: BackupId::new("ak:backup:019a7360-0000-7000-8000-000000000106")
                        .unwrap(),
                    ciphertext_digest: hash('6'),
                },
            ],
            active_series_event_id: EventId::new("ak:event:019a7360-0000-7000-8000-000000000107")
                .unwrap(),
            old_backups: vec![BackupObjectRef {
                backup_id: BackupId::new("ak:backup:019a7360-0000-7000-8000-000000000108").unwrap(),
                ciphertext_digest: hash('8'),
            }],
        };
        let transaction_id =
            TransactionId::new("ak:transaction:019a7360-0000-7000-8000-000000000101").unwrap();
        let revoke_event_id =
            EventId::new("ak:event:019a7360-0000-7000-8000-000000000102").unwrap();
        let request = SecurityTransactionCreateRequest::SecurityRotation(
            SecurityRotationTransactionCreateRequest::from_prepared_rotations(
                transaction_id,
                Did::new("did:web:alice.example").unwrap(),
                Utc::now() + Duration::hours(1),
                revoke_event_id.clone(),
                event_unit(&service_id, revoke_event_id, "ak.device.revoke"),
                hash('1'),
                vec![
                    BackupRotationPlan {
                        active_series_unit: event_unit(
                            &service_id,
                            secret_binding.active_series_event_id.clone(),
                            "ak.key_backup.active_series",
                        ),
                        encrypted_backup_material: canonical_material(&secret_binding),
                        binding: secret_binding,
                    },
                    BackupRotationPlan {
                        active_series_unit: event_unit(
                            &service_id,
                            mls_binding.active_series_event_id.clone(),
                            "ak.key_backup.active_series",
                        ),
                        encrypted_backup_material: canonical_material(&mls_binding),
                        binding: mls_binding,
                    },
                ],
            )
            .unwrap(),
        );
        let (resource, canonical_request) = request
            .into_initial_resource(service_id, Utc::now())
            .unwrap();
        SecurityTransactionRecord {
            canonical_request,
            resource,
        }
    }

    #[tokio::test]
    async fn accepted_step_persists_first_response_and_replays_identical_request() {
        let sessions = Arc::new(Mutex::new(BTreeMap::new()));
        let store = MemorySecurityTransactionStore::new(sessions);
        let initial = initial_rotation();
        store.create(initial.clone()).await.unwrap();

        let mut advanced = initial;
        advanced.resource.accepted_steps.push(AcceptedStep {
            step: SecurityTransactionStep::Revoke,
            prepared_material_digest: hash('4'),
            acceptor_id: "did:web:principal.example".to_owned(),
            output_ref: "ak:event:019a7360-0000-7000-8000-000000000102".to_owned(),
            output_digest: hash('5'),
            accepted_at: Utc::now(),
        });
        advanced.resource.state = SecurityTransactionState::Running;
        advanced.resource.next_required_step = Some(SecurityTransactionStep::UploadNewMaterial);
        advanced.resource.validate_structural().unwrap();
        let outcome = SecurityTransactionStepOutcomeRecord {
            transaction_id: advanced.resource.transaction_id.as_str().to_owned(),
            step: SecurityTransactionStep::Revoke,
            canonical_request: b"fixed-request".to_vec(),
            response: json!({"first": true}),
            participant_outcome: None,
        };
        store
            .begin_step(SecurityTransactionStepAttemptRecord {
                transaction_id: outcome.transaction_id.clone(),
                step: outcome.step,
                canonical_request: outcome.canonical_request.clone(),
            })
            .await
            .unwrap();
        let first = store
            .accept_step(advanced.clone(), outcome.clone())
            .await
            .unwrap();
        assert_eq!(first.response, json!({"first": true}));

        let mut replay = outcome;
        replay.response = json!({"first": false});
        let stored = store.accept_step(advanced, replay).await.unwrap();
        assert_eq!(stored.response, json!({"first": true}));

        let mut conflict = stored;
        conflict.canonical_request = b"different-request".to_vec();
        assert!(
            store
                .accept_step(initial_rotation(), conflict)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn backup_erase_progress_is_durable_monotonic_and_idempotent() {
        let sessions = Arc::new(Mutex::new(BTreeMap::new()));
        let store = MemorySecurityTransactionStore::new(sessions);
        let transaction = initial_rotation();
        store.create(transaction.clone()).await.unwrap();

        let initial = initial_erase_progress(&transaction);
        let stored = store.begin_backup_erase(initial.clone()).await.unwrap();
        assert_eq!(stored.outcome, initial.outcome);
        let replay = store.begin_backup_erase(initial.clone()).await.unwrap();
        assert_eq!(replay.outcome, initial.outcome);

        let mut advanced = initial;
        let erased = advanced.outcome.series_results[0]
            .remaining_backups
            .remove(0);
        advanced.outcome.series_results[0]
            .erased_backups
            .push(erased);
        advanced.outcome.series_results[0].status =
            arkret_models_crypto::BackupSeriesEraseResultStatus::Erased;
        let advanced = store.update_backup_erase(advanced).await.unwrap();
        assert_eq!(
            advanced.outcome.series_results[0].status,
            arkret_models_crypto::BackupSeriesEraseResultStatus::Erased
        );

        let mut resurrected = advanced;
        let erased = resurrected.outcome.series_results[0]
            .erased_backups
            .remove(0);
        resurrected.outcome.series_results[0]
            .remaining_backups
            .push(erased);
        resurrected.outcome.series_results[0].status =
            arkret_models_crypto::BackupSeriesEraseResultStatus::Pending;
        assert!(store.update_backup_erase(resurrected).await.is_err());
    }
}
