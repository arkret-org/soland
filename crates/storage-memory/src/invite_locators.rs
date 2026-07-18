use super::{
    BTreeMap, InviteLocatorInsertOutcome, InviteLocatorRecord, InviteLocatorStore, Mutex,
    PersistenceResult, Utc, async_trait,
};

pub(crate) struct MemoryInviteLocatorStore {
    by_id: Mutex<BTreeMap<String, InviteLocatorRecord>>,
}

impl MemoryInviteLocatorStore {
    pub(crate) fn new() -> Self {
        Self {
            by_id: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait]
impl InviteLocatorStore for MemoryInviteLocatorStore {
    async fn insert(
        &self,
        record: &InviteLocatorRecord,
        active_limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<InviteLocatorInsertOutcome> {
        let mut rows = self.by_id.lock();
        let active = rows
            .values()
            .filter(|row| {
                row.subject_id == record.subject_id
                    && row.expires_at > now
                    && row.revoked_at.is_none()
                    && row.consumed_at.is_none()
            })
            .count();
        if active >= active_limit {
            return Ok(InviteLocatorInsertOutcome::ActiveLimitReached);
        }
        if rows
            .values()
            .any(|row| row.token_digest == record.token_digest)
        {
            return Err(soland_storage::PersistenceError::Conflict(
                "invite locator token digest collision".to_owned(),
            ));
        }
        rows.insert(record.locator_id.clone(), record.clone());
        Ok(InviteLocatorInsertOutcome::Inserted)
    }

    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut rows = self.by_id.lock();
        let Some(row) = rows
            .values_mut()
            .find(|row| row.token_digest == token_digest)
        else {
            return Ok(None);
        };
        if row.expires_at <= now || row.revoked_at.is_some() || row.consumed_at.is_some() {
            return Ok(None);
        }
        if row.one_time_use {
            row.consumed_at = Some(now);
        }
        Ok(Some(row.clone()))
    }

    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        replacement: &InviteLocatorRecord,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut rows = self.by_id.lock();
        let Some(old) = rows.get_mut(old_locator_id) else {
            return Ok(None);
        };
        if old.subject_id != subject_id
            || old.expires_at <= now
            || old.revoked_at.is_some()
            || old.consumed_at.is_some()
        {
            return Ok(None);
        }
        old.revoked_at = Some(now);
        rows.insert(replacement.locator_id.clone(), replacement.clone());
        Ok(Some(replacement.clone()))
    }

    async fn revoke(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut rows = self.by_id.lock();
        let Some(row) = rows.get_mut(locator_id) else {
            return Ok(None);
        };
        if row.subject_id != subject_id || row.consumed_at.is_some() || row.expires_at <= now {
            return Ok(None);
        }
        row.revoked_at.get_or_insert(now);
        Ok(Some(row.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn record(locator_id: &str, digest: &str, one_time_use: bool) -> InviteLocatorRecord {
        let issued_at = Utc::now();
        InviteLocatorRecord {
            locator_id: locator_id.to_owned(),
            token_digest: digest.to_owned(),
            subject_id: "did:webvh:z6mkfixture:bob.example".to_owned(),
            recipient_service_id: "did:webvh:z6mkfixture:ps.example".to_owned(),
            issued_at,
            expires_at: issued_at + Duration::minutes(15),
            one_time_use,
            display_hint: None,
            revoked_at: None,
            consumed_at: None,
        }
    }

    #[tokio::test]
    async fn one_time_locator_resolves_only_once() {
        let store = MemoryInviteLocatorStore::new();
        let row = record(
            "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            "sha256:one",
            true,
        );
        let now = Utc::now();
        assert_eq!(
            store.insert(&row, 16, now).await.unwrap(),
            InviteLocatorInsertOutcome::Inserted
        );
        assert!(
            store
                .resolve_and_consume("sha256:one", now)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .resolve_and_consume("sha256:one", now)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rotate_revokes_old_digest_atomically() {
        let store = MemoryInviteLocatorStore::new();
        let old = record(
            "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            "sha256:old",
            false,
        );
        let replacement = record(
            "ak:invite_locator:0196419b-0000-7000-8000-000000000001",
            "sha256:new",
            false,
        );
        let now = Utc::now();
        store.insert(&old, 16, now).await.unwrap();
        store
            .rotate(&old.subject_id, &old.locator_id, &replacement, now)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .resolve_and_consume("sha256:old", now)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resolve_and_consume("sha256:new", now)
                .await
                .unwrap()
                .is_some()
        );
    }
}
