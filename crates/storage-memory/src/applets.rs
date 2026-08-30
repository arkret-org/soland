use super::{
    AppletAuthoringPreviewRecord, AppletStore, AppletTransactionReplayBegin,
    AppletTransactionReplayRecord, BTreeMap, Mutex, PersistenceError, PersistenceResult, Value,
    async_trait,
};
pub(crate) struct MemoryAppletStore {
    pub(crate) identities: Mutex<BTreeMap<(String, String), Value>>,
    pub(crate) records: Mutex<BTreeMap<(String, String), Value>>,
    transactions: Mutex<BTreeMap<(String, String, String), AppletTransactionReplayRecord>>,
    pub(crate) authoring_previews: Mutex<BTreeMap<String, AppletAuthoringPreviewRecord>>,
}
impl MemoryAppletStore {
    pub(crate) fn new() -> Self {
        Self {
            identities: Mutex::new(BTreeMap::new()),
            records: Mutex::new(BTreeMap::new()),
            transactions: Mutex::new(BTreeMap::new()),
            authoring_previews: Mutex::new(BTreeMap::new()),
        }
    }
}
#[async_trait]
impl AppletStore for MemoryAppletStore {
    async fn get_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> PersistenceResult<Option<Value>> {
        Ok(self
            .identities
            .lock()
            .get(&(applet_id.to_owned(), target_station_id.to_owned()))
            .cloned())
    }

    async fn get(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> PersistenceResult<Option<Value>> {
        Ok(self
            .records
            .lock()
            .get(&(applet_id.to_owned(), effective_scope_key.to_owned()))
            .cloned())
    }

    async fn compare_and_swap(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool> {
        soland_storage::validate_applet_installation_record(expected)?;
        soland_storage::validate_applet_installation_record(&replacement)?;
        if soland_storage::applet_id_from_record(expected)? != applet_id
            || soland_storage::applet_id_from_record(&replacement)? != applet_id
            || soland_storage::applet_effective_scope_key_from_record(&replacement)?
                != effective_scope_key
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: Applet CAS cannot change applet_id or effective_scope"
                    .to_owned(),
            ));
        }
        let mut records = self.records.lock();
        let key = (applet_id.to_owned(), effective_scope_key.to_owned());
        if records.get(&key) != Some(expected) {
            return Ok(false);
        }
        records.insert(key, replacement);
        Ok(true)
    }

    async fn fence_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<soland_storage::AppletInstallationFenceOutcome> {
        soland_storage::validate_applet_installation_record(expected)?;
        soland_storage::validate_applet_installation_record(&replacement)?;
        if soland_storage::applet_id_from_record(expected)? != applet_id
            || soland_storage::applet_id_from_record(&replacement)? != applet_id
            || soland_storage::applet_effective_scope_key_from_record(&replacement)?
                != effective_scope_key
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: Applet fence cannot change applet_id or effective_scope"
                    .to_owned(),
            ));
        }
        let mut identities = self.identities.lock();
        let mut records = self.records.lock();
        let identity_key = (applet_id.to_owned(), target_station_id.to_owned());
        let identity = identities
            .get(&identity_key)
            .ok_or_else(|| PersistenceError::NotFound("applet managed identity".to_owned()))?;
        if !identity.is_object() {
            return Err(PersistenceError::Conflict(
                "schema_violation: Applet managed identity is not an object".to_owned(),
            ));
        }
        let installation_key = (applet_id.to_owned(), effective_scope_key.to_owned());
        if records.get(&installation_key) != Some(expected) {
            return Ok(soland_storage::AppletInstallationFenceOutcome::default());
        }
        records.insert(installation_key, replacement);
        let has_active = records.iter().any(|((candidate_applet_id, _), record)| {
            candidate_applet_id == applet_id
                && record
                    .get("revoked_at")
                    .is_none_or(serde_json::Value::is_null)
                && matches!(
                    record.get("status").and_then(serde_json::Value::as_str),
                    Some("installed" | "partially_installed")
                )
        });
        if has_active {
            return Ok(soland_storage::AppletInstallationFenceOutcome {
                updated: true,
                globally_fenced: false,
            });
        }
        identities
            .get_mut(&identity_key)
            .expect("identity existence validated while holding its map lock")
            .as_object_mut()
            .expect("identity object shape validated while holding its map lock")
            .insert(
                "globally_fenced_at".to_owned(),
                serde_json::Value::String(arkret_canonical::format_timestamp_canonical(fenced_at)),
            );
        Ok(soland_storage::AppletInstallationFenceOutcome {
            updated: true,
            globally_fenced: true,
        })
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.records.lock().values().cloned().collect())
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        let key = (
            record.applet_id.to_string(),
            record.source_id.clone(),
            record.idempotency_key.clone(),
        );
        let mut transactions = self.transactions.lock();
        if let Some(existing) = transactions.get(&key) {
            return Ok(AppletTransactionReplayBegin::Existing(existing.clone()));
        }
        transactions.insert(key, record);
        Ok(AppletTransactionReplayBegin::Fresh)
    }

    async fn complete_transaction_replay(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let key = (
            applet_id.to_owned(),
            source_id.to_owned(),
            idempotency_key.to_owned(),
        );
        let mut transactions = self.transactions.lock();
        let Some(record) = transactions.get_mut(&key) else {
            return Err(PersistenceError::NotFound(format!(
                "applet transaction replay missing for {source_id}/{idempotency_key}"
            )));
        };
        record.outcome = Some(outcome);
        record.completed_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn issue_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewRecord,
    ) -> PersistenceResult<AppletAuthoringPreviewRecord> {
        let mut previews = self.authoring_previews.lock();
        if let Some(current) = previews.get(&candidate.subject_key)
            && current.basis_digest == candidate.basis_digest
            && current.expires_at > candidate.issued_at
        {
            return Ok(current.clone());
        }
        previews.insert(candidate.subject_key.clone(), candidate.clone());
        Ok(candidate)
    }

    async fn current_authoring_preview(
        &self,
        subject_key: &str,
    ) -> PersistenceResult<Option<AppletAuthoringPreviewRecord>> {
        Ok(self.authoring_previews.lock().get(subject_key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(
        basis_digest: &str,
        request_digest: &str,
        issued_at: chrono::DateTime<chrono::Utc>,
    ) -> AppletAuthoringPreviewRecord {
        AppletAuthoringPreviewRecord {
            subject_key: "install-bot-subject".to_owned(),
            basis_digest: basis_digest.to_owned(),
            request_digest: request_digest.to_owned(),
            signed_request: serde_json::json!({"request_digest": request_digest}),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
        }
    }

    #[tokio::test]
    async fn authoring_preview_keeps_exact_current_winner_and_supersedes_changed_or_expired_input()
    {
        let store = MemoryAppletStore::new();
        let now = chrono::Utc::now();
        let first = preview("basis-a", "request-a", now);
        assert_eq!(
            store
                .issue_authoring_preview(first.clone())
                .await
                .unwrap()
                .request_digest,
            "request-a"
        );

        let same_basis_new_signature = preview(
            "basis-a",
            "request-a-new-signature",
            now + chrono::Duration::seconds(1),
        );
        assert_eq!(
            store
                .issue_authoring_preview(same_basis_new_signature)
                .await
                .unwrap()
                .signed_request,
            first.signed_request
        );

        let changed = preview("basis-b", "request-b", now + chrono::Duration::seconds(2));
        assert_eq!(
            store
                .issue_authoring_preview(changed)
                .await
                .unwrap()
                .request_digest,
            "request-b"
        );
        assert_eq!(
            store
                .current_authoring_preview("install-bot-subject")
                .await
                .unwrap()
                .unwrap()
                .request_digest,
            "request-b"
        );

        let expired_reissue = preview(
            "basis-b",
            "request-b-reissued",
            now + chrono::Duration::minutes(7),
        );
        assert_eq!(
            store
                .issue_authoring_preview(expired_reissue)
                .await
                .unwrap()
                .request_digest,
            "request-b-reissued"
        );
    }

    #[tokio::test]
    async fn stale_record_mutation_cannot_overwrite_a_concurrent_ghost_append() {
        let store = MemoryAppletStore::new();
        let applet_id = "ak:applet:01994137-0000-7000-8000-000000000001";
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
            )
            .unwrap(),
        };
        let scope_key = soland_storage::applet_effective_scope_key(&scope).unwrap();
        let original = serde_json::json!({
            "applet_id": applet_id,
            "effective_scope": scope.clone(),
            "status": "installed",
            "ghosts": []
        });
        store
            .records
            .lock()
            .insert((applet_id.to_owned(), scope_key.clone()), original.clone());
        let appended = serde_json::json!({
            "applet_id": applet_id,
            "effective_scope": scope.clone(),
            "status": "installed",
            "ghosts": [{"ghost_actor_id": "ak:did_core:webvh:z6mkghost"}],
        });
        assert!(
            store
                .compare_and_swap(applet_id, &scope_key, &original, appended.clone())
                .await
                .unwrap()
        );
        let stale_revoke = serde_json::json!({
            "applet_id": applet_id,
            "effective_scope": scope,
            "status": "revoked",
            "ghosts": []
        });
        assert!(
            !store
                .compare_and_swap(applet_id, &scope_key, &original, stale_revoke)
                .await
                .unwrap()
        );
        assert_eq!(
            store.get(applet_id, &scope_key).await.unwrap(),
            Some(appended)
        );
    }
}
