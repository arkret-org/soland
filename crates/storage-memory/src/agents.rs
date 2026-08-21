#[cfg(test)]
use soland_storage::AgentRuntimeSnapshotGuard;

use super::{
    AgentPairingCommitIntent, AgentParticipationStore, AgentPrincipalRecord,
    AgentProvisioningAbandonmentWriteOutcome, AgentRuntimeActivation, AgentRuntimeApprovalWrite,
    AgentRuntimeEnqueueOutcome, AgentRuntimeMessageRecord, AgentStore, Arc, CanonicalEventRecord,
    ConfirmAgentProvisioningAbandonment, EnqueueAgentRuntimeMessage,
    IssueAgentProvisioningAbandonmentChallenge, Mutex, PendingAgentPairingCommitIntent,
    PersistenceError, PersistenceResult, Utc, Value, agent_participation_record_key,
    apply_agent_provisioning_abandonment, apply_agent_provisioning_abandonment_challenge,
    async_trait, ids,
};
#[derive(Default)]
pub(crate) struct MemoryAgentParticipationStore {
    selections: Mutex<Vec<Value>>,
    ceilings: Mutex<Vec<Value>>,
}
impl MemoryAgentParticipationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl AgentParticipationStore for MemoryAgentParticipationStore {
    async fn compare_and_swap_selection(
        &self,
        record: Value,
        expected_version: u64,
    ) -> PersistenceResult<bool> {
        let target = agent_participation_record_key(&record);
        let mut guard = self.selections.lock();
        let current = guard
            .iter()
            .position(|existing| agent_participation_record_key(existing) == target);
        let current_version = current
            .and_then(|index| guard[index].get("version").and_then(Value::as_u64))
            .unwrap_or(0);
        if current_version != expected_version {
            return Ok(false);
        }
        let accepted_version = expected_version.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("agent participation version overflow".to_owned())
        })?;
        if record.get("version").and_then(Value::as_u64) != Some(accepted_version) {
            return Err(PersistenceError::Internal(
                "agent participation record has invalid next version".to_owned(),
            ));
        }
        if let Some(index) = current {
            guard[index] = record;
        } else {
            guard.push(record);
        }
        Ok(true)
    }

    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .selections
            .lock()
            .iter()
            .filter(|row| row.get("agent_id").and_then(Value::as_str) == Some(agent_id))
            .cloned()
            .collect())
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .ceilings
            .lock()
            .iter()
            .filter(|row| {
                row.get("scope_key")
                    .and_then(Value::as_str)
                    .map(|key| scope_keys.iter().any(|candidate| candidate == key))
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()> {
        let key = record
            .get("scope_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut guard = self.ceilings.lock();
        guard.retain(|existing| {
            existing
                .get("scope_key")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                != key
        });
        guard.push(record);
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct MemoryAgentStore {
    #[cfg(feature = "fault-injection")]
    fault_injector: Arc<crate::FaultInjector>,
    data: Mutex<std::collections::BTreeMap<String, AgentPrincipalRecord>>,
    runtime_messages: Mutex<std::collections::BTreeMap<String, AgentRuntimeMessageRecord>>,
    events: Arc<Mutex<std::collections::BTreeMap<String, CanonicalEventRecord>>>,
}
impl MemoryAgentStore {
    #[cfg(not(feature = "fault-injection"))]
    pub(crate) fn with_events(
        events: Arc<Mutex<std::collections::BTreeMap<String, CanonicalEventRecord>>>,
    ) -> Self {
        Self {
            events,
            ..Self::default()
        }
    }

    #[cfg(feature = "fault-injection")]
    pub(crate) fn with_events_and_fault_injector(
        events: Arc<Mutex<std::collections::BTreeMap<String, CanonicalEventRecord>>>,
        fault_injector: Arc<crate::FaultInjector>,
    ) -> Self {
        Self {
            events,
            fault_injector,
            ..Self::default()
        }
    }
}

fn managed_agent_genesis_is_accepted(
    events: &std::collections::BTreeMap<String, CanonicalEventRecord>,
    agent_id: &str,
    realm_id: &str,
) -> bool {
    events.values().any(|event| {
        event.actor_id == agent_id
            && event.realm_id.as_deref() == Some(realm_id)
            && event.kind == arkret_wire::EventKind::RealmCreate.as_str()
    })
}
#[async_trait]
impl AgentStore for MemoryAgentStore {
    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()> {
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(crate::FaultPoint::AgentPut, crate::FaultTiming::Before)?;
        let id = record.id.clone();
        let mut data = self.data.lock();
        if let Some(existing) = data.get(&id)
            && (existing.controller_id != record.controller_id
                || existing.principal_control_realm_id != record.principal_control_realm_id
                || existing.controller_authorization_ref != record.controller_authorization_ref)
        {
            return Err(PersistenceError::Conflict(format!(
                "Agent `{id}` controller/PCR authorization binding is immutable"
            )));
        }
        data.insert(id, record);
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(crate::FaultPoint::AgentPut, crate::FaultTiming::After)?;
        Ok(())
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        Ok(self.data.lock().get(agent_id).cloned())
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .find(|record| record.pairing_request_id.as_deref() == Some(pairing_request_id))
            .cloned())
    }

    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .filter(|record| record.controller_id == controller_id)
            .cloned()
            .collect())
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: arkret_models_collaboration::agent_operations::AgentLifecycleState,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        if let Some(record) = guard.get_mut(agent_id) {
            record.state = state;
            record.state_changed_at = Some(changed_at);
            record.updated_at = changed_at;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(&activation.agent_id) else {
            return Ok(false);
        };
        if record.approval_request_id.as_deref() != Some(&activation.approval_request_id)
            || !matches!(
                record.state,
                arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
                    | arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused
            )
            || record.runtime_key_binding_digest.as_deref()
                != Some(&activation.runtime_key_binding_digest)
            || record.pairing_request_id.as_deref() != Some(&activation.pairing_request_id)
            || record
                .pending_pairing_commit_intent
                .as_ref()
                .is_none_or(|intent| {
                    intent.request_digest != activation.paired_request_digest
                        || intent.authorize_event_id != activation.authorized_event_ref
                        || intent.signing_key_binding.as_ref()
                            != Some(&activation.authorized_signing_key_binding)
                })
        {
            return Ok(false);
        }
        // Runtime key activation records the authorization; it is not a
        // lifecycle transition, so the lifecycle `state` is left untouched
        // (key-management.md §3.6.1). runtime_state derives to ready.
        record.updated_at = activation.authorized_at;
        record.authorized_event_ref = Some(activation.authorized_event_ref.clone());
        record.authorized_verification_method =
            Some(activation.authorized_verification_method.clone());
        record.authorized_public_key_digest = Some(activation.authorized_public_key_digest.clone());
        record.authorized_signing_key_binding =
            Some(activation.authorized_signing_key_binding.clone());
        record.paired_pairing_request_id = Some(activation.pairing_request_id.clone());
        record.paired_request_digest = Some(activation.paired_request_digest.clone());
        record.pending_pairing_commit_intent = None;
        // Keep the approval and notification ids until the terminal account
        // delta is durable. They are internal correlation state and are not
        // exposed for an active/paused Agent. A retry can therefore finish the
        // notification cleanup after a crash without replaying activation.
        record.runtime_key_request = None;
        record.approval_requested_at = None;
        record.runtime_key_binding_digest = None;
        record.runtime_public_key_digest = None;
        record.runtime_attestation_digest = None;
        Ok(true)
    }

    async fn put_pairing_commit_intent_if_compatible(
        &self,
        intent: &AgentPairingCommitIntent,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(&intent.agent_id) else {
            return Ok(None);
        };
        if record.approval_request_id.as_deref() != Some(&intent.approval_request_id)
            || !matches!(
                record.state,
                arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
                    | arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused
            )
            || record.runtime_key_binding_digest.as_deref()
                != Some(&intent.runtime_key_binding_digest)
            || record.pairing_request_id.as_deref() != Some(&intent.pairing_request_id)
            || record.paired_pairing_request_id.as_deref() == Some(&intent.pairing_request_id)
            || record
                .pending_pairing_commit_intent
                .as_ref()
                .is_some_and(|existing| {
                    existing.request_digest != intent.request_digest
                        || existing.authorize_event_id != intent.authorize_event_id
                        || existing.signing_key_binding.as_ref()
                            != Some(&intent.signing_key_binding)
                })
        {
            return Ok(None);
        }
        record.pending_pairing_commit_intent = Some(PendingAgentPairingCommitIntent {
            request_digest: intent.request_digest.clone(),
            authorize_event_id: intent.authorize_event_id.clone(),
            signing_key_binding: Some(intent.signing_key_binding.clone()),
        });
        record.updated_at = Utc::now();
        Ok(Some(record.clone()))
    }

    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(agent_id) else {
            return Ok(false);
        };
        if record.approval_request_id.as_deref() != Some(approval_request_id)
            || record.authorized_event_ref.is_none()
        {
            return Ok(false);
        }
        record.approval_request_id = None;
        record.approval_notification_id = None;
        record.updated_at = Utc::now();
        Ok(true)
    }

    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(&write.agent_id) else {
            return Ok(None);
        };
        let pairing_handle_was_consumed =
            record.paired_pairing_request_id.as_deref() == Some(&write.pairing_request_id);
        if record.pairing_request_id.as_deref() != Some(&write.pairing_request_id)
            || pairing_handle_was_consumed
            || !matches!(
                record.state,
                arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
                    | arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused
            )
            || record
                .runtime_key_binding_digest
                .as_deref()
                .is_some_and(|digest| digest != write.runtime_key_binding_digest)
        {
            return Ok(None);
        }
        record
            .approval_request_id
            .get_or_insert_with(|| write.approval_request_id.clone());
        record.approval_notification_id.get_or_insert_with(|| {
            ids::typed_uuid_part_expect_internal(&write.approval_notification_id)
        });
        record
            .approval_requested_at
            .get_or_insert(write.approval_requested_at);
        record.controller_account_id = Some(ids::typed_uuid_part_expect_internal(
            &write.controller_account_id,
        ));
        record.recipient_service_id = Some(write.recipient_service_id.clone());
        record.runtime_key_binding_digest = Some(write.runtime_key_binding_digest.clone());
        record.runtime_public_key_digest = Some(write.runtime_public_key_digest.clone());
        record.runtime_attestation_digest = Some(write.runtime_attestation_digest.clone());
        record.runtime_key_request = Some(write.runtime_key_request.clone());
        record.updated_at = Utc::now();
        Ok(Some(record.clone()))
    }

    async fn issue_provisioning_abandonment_challenge(
        &self,
        command: &IssueAgentProvisioningAbandonmentChallenge,
    ) -> PersistenceResult<AgentProvisioningAbandonmentWriteOutcome> {
        // Keep the accepted-Event map locked until the Agent row mutation is
        // durable so a concurrent genesis commit cannot cross this decision.
        let events = self.events.lock();
        let genesis_accepted = managed_agent_genesis_is_accepted(
            &events,
            &command.agent_id,
            &command.principal_control_realm_id,
        );
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(&command.agent_id) else {
            return Ok(AgentProvisioningAbandonmentWriteOutcome::NotFound);
        };
        Ok(apply_agent_provisioning_abandonment_challenge(
            record,
            genesis_accepted,
            command,
        ))
    }

    async fn confirm_provisioning_abandonment(
        &self,
        command: &ConfirmAgentProvisioningAbandonment,
    ) -> PersistenceResult<AgentProvisioningAbandonmentWriteOutcome> {
        let events = self.events.lock();
        let genesis_accepted = managed_agent_genesis_is_accepted(
            &events,
            &command.agent_id,
            &command.principal_control_realm_id,
        );
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(&command.agent_id) else {
            return Ok(AgentProvisioningAbandonmentWriteOutcome::NotFound);
        };
        Ok(apply_agent_provisioning_abandonment(
            record,
            genesis_accepted,
            command,
        ))
    }

    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> PersistenceResult<AgentRuntimeEnqueueOutcome> {
        // Replay lookup deliberately precedes snapshot validation.  A retry
        // of an already durable write remains a Duplicate even after the
        // Agent rotates to a new runtime endpoint.
        let mut messages = self.runtime_messages.lock();
        if let Some(existing) = messages.get(&command.request_key) {
            return Ok(
                if existing.request_digest == command.request_digest
                    && existing.agent_id == command.snapshot.agent_id
                    && existing.content == command.content
                {
                    AgentRuntimeEnqueueOutcome::Duplicate(existing.clone())
                } else {
                    AgentRuntimeEnqueueOutcome::RequestConflict
                },
            );
        }

        let agents = self.data.lock();
        let Some(agent) = agents.get(&command.snapshot.agent_id) else {
            return Ok(AgentRuntimeEnqueueOutcome::SnapshotConflict);
        };
        if agent.state != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            || agent.authorized_verification_method.as_deref()
                != Some(command.snapshot.verification_method.as_str())
            || agent.authorized_event_ref.as_deref()
                != Some(command.snapshot.authorized_event_ref.as_str())
            || agent.updated_at != command.snapshot.updated_at
            || agent.authorized_signing_key_binding.is_none()
        {
            return Ok(AgentRuntimeEnqueueOutcome::SnapshotConflict);
        }
        let record = AgentRuntimeMessageRecord {
            message_id: uuid::Uuid::now_v7(),
            request_key: command.request_key.clone(),
            request_digest: command.request_digest.clone(),
            agent_id: command.snapshot.agent_id.clone(),
            verification_method: command.snapshot.verification_method.clone(),
            authorized_event_ref: command.snapshot.authorized_event_ref.clone(),
            content: command.content.clone(),
            enqueued_at: command.enqueued_at,
        };
        messages.insert(command.request_key.clone(), record.clone());
        Ok(AgentRuntimeEnqueueOutcome::Stored(record))
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::agent_operations::AgentLifecycleState;
    use arkret_wire::{DidUrl, OpaqueLocalId};

    use super::*;

    fn pending_agent() -> AgentPrincipalRecord {
        let now = Utc::now();
        let mut record = AgentPrincipalRecord::new(
            "did:web:agent.example".to_owned(),
            "did:web:controller.example".to_owned(),
            "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            DidUrl::new("did:web:agent.example#controller").unwrap(),
            AgentLifecycleState::Active,
            now,
        );
        record.pairing_request_id = Some(OpaqueLocalId::new("pairing-1").unwrap());
        record.approval_request_id = Some(OpaqueLocalId::new("approval-1").unwrap());
        record.runtime_key_binding_digest = Some("sha256:binding".to_owned());
        record
    }

    fn signing_key_binding() -> arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding
    {
        serde_json::from_value(serde_json::json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": "ak:did_core:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "agent_key_id": "runtime-1",
            "verification_method": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#key-1",
            "public_key": {
                "kty": "OKP",
                "algorithm": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "public_key_digest": format!("sha256:{}", "00".repeat(32)),
            "agent_key_authorize_event_id":
                "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "issued_at": "2026-07-27T00:00:00.000Z",
            "controller_id": "ak:did_core:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "controller_proof": {
                "kind": "controller_signature",
                "verification_method": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#controller-key-1",
                "jws": "proof"
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn participation_selection_compare_and_swap_is_atomic() {
        let store = MemoryAgentParticipationStore::new();
        let record = |version| {
            serde_json::json!({
                "agent_id": "did:web:agent.example",
                "scope_key": "realm:01904100-0000-7000-8000-000000000001",
                "version": version
            })
        };

        assert!(
            store
                .compare_and_swap_selection(record(1), 0)
                .await
                .unwrap()
        );
        assert!(
            !store
                .compare_and_swap_selection(record(1), 0)
                .await
                .unwrap()
        );
        assert!(
            store
                .compare_and_swap_selection(record(2), 1)
                .await
                .unwrap()
        );
        assert!(
            !store
                .compare_and_swap_selection(record(3), 1)
                .await
                .unwrap()
        );

        let rows = store
            .list_selections("did:web:agent.example")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["version"], 2);
    }

    #[tokio::test]
    async fn pairing_commit_intent_is_immutable_and_exact_retry_is_idempotent() {
        let store = MemoryAgentStore::default();
        store.put(pending_agent()).await.unwrap();
        let intent = AgentPairingCommitIntent {
            agent_id: "did:web:agent.example".to_owned(),
            approval_request_id: OpaqueLocalId::new("approval-1").unwrap(),
            runtime_key_binding_digest: "sha256:binding".to_owned(),
            pairing_request_id: OpaqueLocalId::new("pairing-1").unwrap(),
            request_digest: "sha256:request-a".to_owned(),
            authorize_event_id: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            signing_key_binding: signing_key_binding(),
        };

        assert!(
            store
                .put_pairing_commit_intent_if_compatible(&intent)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .put_pairing_commit_intent_if_compatible(&intent)
                .await
                .unwrap()
                .is_some()
        );

        let conflicting = AgentPairingCommitIntent {
            request_digest: "sha256:request-b".to_owned(),
            authorize_event_id: "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned(),
            ..intent.clone()
        };
        assert!(
            store
                .put_pairing_commit_intent_if_compatible(&conflicting)
                .await
                .unwrap()
                .is_none()
        );
        let stored = store
            .get("did:web:agent.example")
            .await
            .unwrap()
            .unwrap()
            .pending_pairing_commit_intent
            .unwrap();
        assert_eq!(stored.request_digest, "sha256:request-a");
        assert_eq!(
            stored.authorize_event_id,
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        );
        assert_eq!(
            stored.signing_key_binding.as_ref(),
            Some(&intent.signing_key_binding)
        );
    }

    #[tokio::test]
    async fn activation_requires_and_consumes_the_exact_commit_intent() {
        let store = MemoryAgentStore::default();
        store.put(pending_agent()).await.unwrap();
        let activation = AgentRuntimeActivation {
            agent_id: "did:web:agent.example".to_owned(),
            approval_request_id: OpaqueLocalId::new("approval-1").unwrap(),
            runtime_key_binding_digest: "sha256:binding".to_owned(),
            pairing_request_id: OpaqueLocalId::new("pairing-1").unwrap(),
            paired_request_digest: "sha256:request-a".to_owned(),
            authorized_event_ref: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                .to_owned(),
            authorized_verification_method: "did:web:agent.example#key-1".to_owned(),
            authorized_public_key_digest: format!("sha256:{}", "00".repeat(32)),
            authorized_signing_key_binding: signing_key_binding(),
            authorized_at: Utc::now(),
        };

        assert!(
            !store
                .activate_runtime_if_current(&activation)
                .await
                .unwrap()
        );
        store
            .put_pairing_commit_intent_if_compatible(&AgentPairingCommitIntent {
                agent_id: activation.agent_id.clone(),
                approval_request_id: activation.approval_request_id.clone(),
                runtime_key_binding_digest: activation.runtime_key_binding_digest.clone(),
                pairing_request_id: activation.pairing_request_id.clone(),
                request_digest: activation.paired_request_digest.clone(),
                authorize_event_id: activation.authorized_event_ref.clone(),
                signing_key_binding: activation.authorized_signing_key_binding.clone(),
            })
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .activate_runtime_if_current(&activation)
                .await
                .unwrap()
        );

        let stored = store.get("did:web:agent.example").await.unwrap().unwrap();
        assert!(stored.pending_pairing_commit_intent.is_none());
        assert_eq!(
            stored.paired_request_digest.as_deref(),
            Some("sha256:request-a")
        );
        assert_eq!(
            stored.authorized_event_ref.as_deref(),
            Some("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
        );
    }

    #[tokio::test]
    async fn runtime_inbox_is_snapshot_guarded_and_exactly_replayable() {
        let store = MemoryAgentStore::default();
        let mut agent = pending_agent();
        agent.authorized_event_ref =
            Some("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned());
        agent.authorized_verification_method = Some("did:web:agent.example#key-1".to_owned());
        agent.authorized_signing_key_binding = Some(signing_key_binding());
        let snapshot_at = agent.updated_at;
        store.put(agent).await.unwrap();
        let command = EnqueueAgentRuntimeMessage {
            request_key: "repair:request-1:recipient".to_owned(),
            request_digest: "sha256:repair-request".to_owned(),
            snapshot: AgentRuntimeSnapshotGuard {
                agent_id: "did:web:agent.example".to_owned(),
                verification_method: "did:web:agent.example#key-1".to_owned(),
                authorized_event_ref: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                    .to_owned(),
                updated_at: snapshot_at,
            },
            content: serde_json::json!({"kind": "agent_runtime_command", "seq": 1}),
            enqueued_at: Utc::now(),
        };

        assert!(matches!(
            store
                .enqueue_runtime_message_if_current(&command)
                .await
                .unwrap(),
            AgentRuntimeEnqueueOutcome::Stored(_)
        ));

        // A later runtime replacement does not invalidate exact replay of
        // the already durable result.
        let replacement_at = {
            let mut agents = store.data.lock();
            let agent = agents.get_mut("did:web:agent.example").unwrap();
            agent.updated_at += chrono::Duration::seconds(1);
            agent.authorized_verification_method = Some("did:web:agent.example#key-2".to_owned());
            agent.authorized_event_ref =
                Some("ak:event:AaMg8gb2OZt5kq0i89-BmIjSl66D9rHfVx-DBzklB4el".to_owned());
            agent.updated_at
        };
        let mut replay = command.clone();
        replay.snapshot.verification_method = "did:web:agent.example#key-2".to_owned();
        replay.snapshot.authorized_event_ref =
            "ak:event:AaMg8gb2OZt5kq0i89-BmIjSl66D9rHfVx-DBzklB4el".to_owned();
        replay.snapshot.updated_at = replacement_at;
        assert!(matches!(
            store
                .enqueue_runtime_message_if_current(&replay)
                .await
                .unwrap(),
            AgentRuntimeEnqueueOutcome::Duplicate(_)
        ));

        let mut conflicting = command.clone();
        conflicting.content["seq"] = serde_json::json!(2);
        assert_eq!(
            store
                .enqueue_runtime_message_if_current(&conflicting)
                .await
                .unwrap(),
            AgentRuntimeEnqueueOutcome::RequestConflict
        );

        let mut fresh = command;
        fresh.request_key = "repair:request-2:recipient".to_owned();
        assert_eq!(
            store
                .enqueue_runtime_message_if_current(&fresh)
                .await
                .unwrap(),
            AgentRuntimeEnqueueOutcome::SnapshotConflict
        );
        assert_eq!(store.runtime_messages.lock().len(), 1);
    }
}
