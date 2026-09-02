use std::collections::BTreeMap;

use arkret_wire::AccountId;
use arkret_wire::receive_policy::EffectiveNewSourceQuota;
use chrono::{DateTime, Duration, Utc};

use super::{
    Arc, InviteNewSourceLedgerStore, Mutex, NewSourceAdmission, PersistenceResult, async_trait,
};

/// In-memory seen-source ledger.
///
/// The whole admission decision runs under one lock, which gives the
/// per-holder linearization `consent-model.md` section 6.1.1.4 requires: two
/// concurrent first contacts can never both observe an under-quota ledger.
#[derive(Default)]
pub(crate) struct MemoryInviteNewSourceLedgerStore {
    data: Arc<Mutex<BTreeMap<AccountId, BTreeMap<String, DateTime<Utc>>>>>,
}

impl MemoryInviteNewSourceLedgerStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl InviteNewSourceLedgerStore for MemoryInviteNewSourceLedgerStore {
    async fn admit_new_source(
        &self,
        holder: &AccountId,
        source_digest: &str,
        now: DateTime<Utc>,
        quota: &EffectiveNewSourceQuota,
    ) -> PersistenceResult<NewSourceAdmission> {
        let retention_floor = now - Duration::seconds(quota.retention_seconds as i64);
        let window_floor = now - Duration::seconds(quota.window_seconds as i64);
        let mut guard = self.data.lock();
        let ledger = guard.entry(holder.clone()).or_default();

        // Step 1: expired rows are both ignored and physically dropped.
        ledger.retain(|_, first_admitted_at| *first_admitted_at > retention_floor);

        // Step 2: a source already on the ledger is not a new source. It is
        // deliberately not re-timestamped, so an active harasser cannot keep
        // itself fresh forever.
        if ledger.contains_key(source_digest) {
            return Ok(NewSourceAdmission::Seen);
        }

        // Step 3: both sliding windows are counted straight off the timestamps.
        let rate = ledger
            .values()
            .filter(|first_admitted_at| **first_admitted_at > window_floor)
            .count() as u64;
        let total = ledger.len() as u64;
        if rate >= quota.new_sources_per_window || total >= quota.new_sources_per_retention {
            // Step 4: a denied source MUST NOT be recorded, or the next window
            // would misread it as seen.
            return Ok(NewSourceAdmission::Denied);
        }

        ledger.insert(source_digest.to_owned(), now);
        Ok(NewSourceAdmission::Admitted)
    }

    async fn delete_for_holder(&self, holder: &AccountId) -> PersistenceResult<()> {
        self.data.lock().remove(holder);
        Ok(())
    }

    async fn retained_source_count(&self, holder: &AccountId) -> PersistenceResult<usize> {
        Ok(self.data.lock().get(holder).map_or(0, BTreeMap::len))
    }
}
