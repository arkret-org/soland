#[cfg(feature = "fault-injection")]
use super::Arc;
use super::{
    AgentPairingCommitIntent, AgentParticipationStore, AgentPrincipalRecord,
    AgentRuntimeActivation, AgentRuntimeApprovalWrite, AgentStore, Mutex,
    PendingAgentPairingCommitIntent, PersistenceError, PersistenceResult, Utc, Value,
    agent_participation_record_key, async_trait, ids,
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
}
impl MemoryAgentStore {
    #[cfg(not(feature = "fault-injection"))]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "fault-injection")]
    pub(crate) fn with_fault_injector(fault_injector: Arc<crate::FaultInjector>) -> Self {
        Self {
            fault_injector,
            ..Self::default()
        }
    }
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
                })
        {
            return Ok(None);
        }
        record.pending_pairing_commit_intent = Some(PendingAgentPairingCommitIntent {
            request_digest: intent.request_digest.clone(),
            authorize_event_id: intent.authorize_event_id.clone(),
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
            "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            DidUrl::new("did:web:agent.example#controller").unwrap(),
            AgentLifecycleState::Active,
            now,
        );
        record.pairing_request_id = Some(OpaqueLocalId::new("pairing-1").unwrap());
        record.approval_request_id = Some(OpaqueLocalId::new("approval-1").unwrap());
        record.runtime_key_binding_digest = Some("sha256:binding".to_owned());
        record
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
            authorize_event_id: "ak:event:01904100-0000-7000-8000-000000000001".to_owned(),
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
            authorize_event_id: "ak:event:01904100-0000-7000-8000-000000000002".to_owned(),
            ..intent
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
            "ak:event:01904100-0000-7000-8000-000000000001"
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
            authorized_event_ref: "ak:event:01904100-0000-7000-8000-000000000001".to_owned(),
            authorized_verification_method: "did:web:agent.example#key-1".to_owned(),
            authorized_public_key_digest: format!("sha256:{}", "00".repeat(32)),
            authorized_signing_key_binding: serde_json::from_value(serde_json::json!({
                "schema": "ak.schema.agent_signing_key_binding.v1",
                "agent_id": "did:web:agent.example",
                "agent_key_id": "runtime-1",
                "verification_method": "did:web:agent.example#key-1",
                "public_key": {
                    "kty": "OKP",
                    "alg": "Ed25519",
                    "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                "public_key_digest": format!("sha256:{}", "00".repeat(32)),
                "agent_key_authorize_event_id":
                    "ak:event:01904100-0000-7000-8000-000000000001",
                "issued_at": "2026-07-27T00:00:00.000Z",
                "controller_id": "did:web:controller.example",
                "controller_proof": {
                    "kind": "controller_signature",
                    "verification_method": "did:web:controller.example#key-1",
                    "jws": "proof"
                }
            }))
            .unwrap(),
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
            Some("ak:event:01904100-0000-7000-8000-000000000001")
        );
    }
}
