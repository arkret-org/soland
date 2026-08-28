use super::{
    BTreeMap, InviteLocatorInsertOutcome, InviteLocatorRecord, InviteLocatorRotateMutation,
    InviteLocatorStore, Mutex, PersistenceResult, Utc, async_trait,
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
        mutation: &InviteLocatorRotateMutation,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut rows = self.by_id.lock();
        if rows
            .values()
            .any(|row| row.token_digest == mutation.token_digest)
        {
            return Err(soland_storage::PersistenceError::Conflict(
                "invite locator token digest collision".to_owned(),
            ));
        }
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
        let replacement = mutation.apply_to(old);
        old.revoked_at = Some(now);
        rows.insert(replacement.locator_id.clone(), replacement.clone());
        Ok(Some(replacement))
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
    use chrono::Duration;

    use super::*;

    fn record(locator_id: &str, digest: &str, one_time_use: bool) -> InviteLocatorRecord {
        let issued_at = Utc::now();
        InviteLocatorRecord {
            locator_id: locator_id.to_owned(),
            token_digest: digest.to_owned(),
            subject_id: "ak:did_core:webvh:z6mkfixturebob".to_owned(),
            recipient_service_id: "ak:did_core:webvh:z6mkfixtureps".to_owned(),
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
        let now = Utc::now();
        let mutation = InviteLocatorRotateMutation {
            locator_id: "ak:invite_locator:0196419b-0000-7000-8000-000000000001".to_owned(),
            token_digest: "sha256:new".to_owned(),
            issued_at: now,
            ttl_seconds: None,
            one_time_use: None,
            display_hint: None,
        };
        store.insert(&old, 16, now).await.unwrap();
        store
            .rotate(&old.subject_id, &old.locator_id, &mutation, now)
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

    #[tokio::test]
    async fn rotate_preserves_lifetime_policy_and_hint_unless_overridden() {
        let store = MemoryInviteLocatorStore::new();
        let mut old = record(
            "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            "sha256:old",
            true,
        );
        old.display_hint = Some(
            arkret_models_collaboration::governance::invite_addressing::PrincipalLocatorDisplayHint {
            display_name_hint: Some("Alice".to_owned()),
            avatar_blob_ref: None,
        });
        let now = old.issued_at + Duration::seconds(30);
        store.insert(&old, 16, old.issued_at).await.unwrap();
        let preserved = store
            .rotate(
                &old.subject_id,
                &old.locator_id,
                &InviteLocatorRotateMutation {
                    locator_id: "ak:invite_locator:0196419b-0000-7000-8000-000000000001".to_owned(),
                    token_digest: "sha256:new".to_owned(),
                    issued_at: now,
                    ttl_seconds: None,
                    one_time_use: None,
                    display_hint: None,
                },
                now,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            preserved.expires_at - preserved.issued_at,
            Duration::minutes(15)
        );
        assert!(preserved.one_time_use);
        assert_eq!(preserved.display_hint, old.display_hint);

        let cleared = store
            .rotate(
                &old.subject_id,
                &preserved.locator_id,
                &InviteLocatorRotateMutation {
                    locator_id: "ak:invite_locator:0196419b-0000-7000-8000-000000000002".to_owned(),
                    token_digest: "sha256:newer".to_owned(),
                    issued_at: now + Duration::seconds(1),
                    ttl_seconds: Some(60),
                    one_time_use: Some(false),
                    display_hint: Some(None),
                },
                now + Duration::seconds(1),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cleared.expires_at - cleared.issued_at,
            Duration::seconds(60)
        );
        assert!(!cleared.one_time_use);
        assert_eq!(cleared.display_hint, None);
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_keeps_the_first_timestamp() {
        let store = MemoryInviteLocatorStore::new();
        let row = record(
            "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            "sha256:one",
            false,
        );
        let first = row.issued_at + Duration::seconds(1);
        let retry = first + Duration::seconds(1);
        store.insert(&row, 16, row.issued_at).await.unwrap();
        let initial = store
            .revoke(&row.subject_id, &row.locator_id, first)
            .await
            .unwrap()
            .unwrap();
        let repeated = store
            .revoke(&row.subject_id, &row.locator_id, retry)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(initial.revoked_at, Some(first));
        assert_eq!(repeated.revoked_at, Some(first));
    }
}
