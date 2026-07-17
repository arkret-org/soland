use super::*;
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
    async fn put_selection(&self, record: Value) -> PersistenceResult<()> {
        let target = agent_participation_record_key(&record);
        let mut guard = self.selections.lock();
        guard.retain(|existing| agent_participation_record_key(existing) != target);
        guard.push(record);
        Ok(())
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
    data: Mutex<std::collections::BTreeMap<String, AgentPrincipalRecord>>,
}
impl MemoryAgentStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl AgentStore for MemoryAgentStore {
    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()> {
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
        state: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        if let Some(record) = guard.get_mut(agent_id) {
            record.state = state.to_owned();
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
                record.state.as_str(),
                "pending_runtime_key" | "active" | "paused"
            )
            || record.runtime_key_binding_digest.as_deref()
                != Some(&activation.runtime_key_binding_digest)
            || record.pairing_request_id.as_deref() != Some(&activation.pairing_request_id)
        {
            return Ok(false);
        }
        if record.state != "paused" {
            record.state = "active".to_owned();
        }
        record.updated_at = activation.authorized_at;
        record.authorized_event_ref = Some(activation.authorized_event_ref.clone());
        record.authorized_verification_method =
            Some(activation.authorized_verification_method.clone());
        record.authorized_public_key_digest = Some(activation.authorized_public_key_digest.clone());
        record.paired_pairing_request_id = Some(activation.pairing_request_id.clone());
        record.paired_request_digest = Some(activation.paired_request_digest.clone());
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
                record.state.as_str(),
                "pending_runtime_key" | "active" | "paused"
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
