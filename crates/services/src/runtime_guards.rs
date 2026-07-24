use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;

const PEER_KEYPACKAGE_CLAIM_WINDOW: Duration = Duration::seconds(60);
const PEER_KEYPACKAGE_CLAIM_MAX_PER_WINDOW: u32 = 5;
const PEER_KEYPACKAGE_CLAIM_TRACKER_MAX_ENTRIES: usize = 16_384;
const KEY_BACKUP_DOWNLOAD_WINDOW: Duration = Duration::hours(24);
const KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES: usize = 16_384;
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT: u32 = 64;
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN: u32 = 16;
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX: u32 = 256;
pub const MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES: usize = 64 * 1024;
const MODERATION_REPORT_RATE_WINDOW: Duration = Duration::minutes(10);
const MODERATION_REPORT_MAX_PER_REPORTER_WINDOW: u32 = 20;
const MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW: u32 = 80;
const MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW: u32 = 10;
const MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW: u32 = 80;
const MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW: u32 = 1;
const MODERATION_REPORT_RATE_TRACKER_MAX_ENTRIES: usize = 32_768;
const MODERATION_FRANKING_REPLAY_WINDOW: Duration = Duration::hours(24);
const MODERATION_FRANKING_REPLAY_MAX_ENTRIES: usize = 4096;
const AGENT_APPROVAL_NONCE_MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBackupDownloadOutcome {
    pub rate_limited: bool,
    pub count: u32,
    pub retry_after_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationReportRateOutcome {
    pub rate_limited: bool,
    pub bucket: Option<String>,
    pub count: u32,
    pub limit: u32,
    pub retry_after_ms: i64,
}

#[derive(Clone)]
pub struct RuntimeGuardService {
    inner: Arc<RuntimeGuards>,
}

struct RuntimeGuards {
    peer_keypackage_claims: Mutex<BTreeMap<(String, String), WindowRecord>>,
    key_backup_downloads: Mutex<BTreeMap<String, WindowRecord>>,
    moderation_reports: Mutex<BTreeMap<String, WindowRecord>>,
    moderation_franking_nonces: Mutex<BTreeMap<String, ReplayRecord>>,
    agent_approval_nonces: Mutex<BTreeMap<String, DateTime<Utc>>>,
}

#[derive(Clone, Copy)]
struct WindowRecord {
    count: u32,
    window_started_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
struct ReplayRecord {
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

impl Default for RuntimeGuardService {
    fn default() -> Self {
        Self {
            inner: Arc::new(RuntimeGuards {
                peer_keypackage_claims: Mutex::new(BTreeMap::new()),
                key_backup_downloads: Mutex::new(BTreeMap::new()),
                moderation_reports: Mutex::new(BTreeMap::new()),
                moderation_franking_nonces: Mutex::new(BTreeMap::new()),
                agent_approval_nonces: Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

impl RuntimeGuardService {
    pub fn peer_keypackage_claim_rate_limited(
        &self,
        source_service_id: &str,
        target_principal_id: &str,
    ) -> bool {
        let mut records = self.inner.peer_keypackage_claims.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - PEER_KEYPACKAGE_CLAIM_WINDOW);
        let key = (source_service_id.to_owned(), target_principal_id.to_owned());
        record_window_attempt(
            &mut records,
            key,
            now,
            PEER_KEYPACKAGE_CLAIM_WINDOW,
            PEER_KEYPACKAGE_CLAIM_TRACKER_MAX_ENTRIES,
        ) > PEER_KEYPACKAGE_CLAIM_MAX_PER_WINDOW
    }

    pub fn record_key_backup_download(
        &self,
        principal_id: &str,
        limit: u32,
    ) -> KeyBackupDownloadOutcome {
        let mut records = self.inner.key_backup_downloads.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - KEY_BACKUP_DOWNLOAD_WINDOW);
        let count = record_window_attempt(
            &mut records,
            principal_id.to_owned(),
            now,
            KEY_BACKUP_DOWNLOAD_WINDOW,
            KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES,
        );
        let rate_limited = count > limit;
        let retry_after_ms = records
            .get(principal_id)
            .filter(|_| rate_limited)
            .map(|record| {
                (record.window_started_at + KEY_BACKUP_DOWNLOAD_WINDOW - now)
                    .num_milliseconds()
                    .max(0)
            })
            .unwrap_or_default();
        KeyBackupDownloadOutcome {
            rate_limited,
            count,
            retry_after_ms,
        }
    }

    pub fn record_moderation_report_attempt(
        &self,
        reporter: &str,
        source_service: Option<&str>,
        realm_id: &str,
        source_ip_hash: &str,
        target_ref: &str,
    ) -> ModerationReportRateOutcome {
        let mut buckets = vec![
            (
                format!("reporter:{reporter}"),
                MODERATION_REPORT_MAX_PER_REPORTER_WINDOW,
            ),
            (
                format!("reporter_realm:{reporter}:{realm_id}"),
                MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
            ),
            (
                format!("source_ip:{source_ip_hash}:moderation_report"),
                MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW,
            ),
            (
                format!("reporter_target:{reporter}:{target_ref}"),
                MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW,
            ),
        ];
        if let Some(source_service) = source_service.filter(|value| !value.trim().is_empty()) {
            buckets.push((
                format!("source_service:{source_service}"),
                MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW,
            ));
            buckets.push((
                format!("reporter_source_service:{reporter}:{source_service}"),
                MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
            ));
        }

        let mut records = self.inner.moderation_reports.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - MODERATION_REPORT_RATE_WINDOW);
        let mut exceeded = None;
        for (bucket, limit) in buckets {
            let count = record_window_attempt(
                &mut records,
                bucket.clone(),
                now,
                MODERATION_REPORT_RATE_WINDOW,
                MODERATION_REPORT_RATE_TRACKER_MAX_ENTRIES,
            );
            if exceeded.is_none() && count > limit {
                let retry_after_ms = records
                    .get(&bucket)
                    .map(|record| {
                        (record.window_started_at + MODERATION_REPORT_RATE_WINDOW - now)
                            .num_milliseconds()
                            .max(0)
                    })
                    .unwrap_or_default();
                exceeded = Some(ModerationReportRateOutcome {
                    rate_limited: true,
                    bucket: Some(bucket),
                    count,
                    limit,
                    retry_after_ms,
                });
            }
        }
        exceeded.unwrap_or(ModerationReportRateOutcome {
            rate_limited: false,
            bucket: None,
            count: 0,
            limit: 0,
            retry_after_ms: 0,
        })
    }

    pub fn remember_moderation_franking_nonce(
        &self,
        realm_id: &str,
        received_by: &str,
        replay_nonce: &str,
    ) -> bool {
        let mut records = self.inner.moderation_franking_nonces.lock();
        let now = Utc::now();
        records.retain(|_, record| record.last_seen_at >= now - MODERATION_FRANKING_REPLAY_WINDOW);
        evict_oldest_entries(
            &mut records,
            MODERATION_FRANKING_REPLAY_MAX_ENTRIES,
            |record| record.first_seen_at.timestamp_millis(),
        );
        let key = format!("{realm_id}:{received_by}:{replay_nonce}");
        if let Some(record) = records.get_mut(&key) {
            record.last_seen_at = now;
            return false;
        }
        records.insert(
            key,
            ReplayRecord {
                first_seen_at: now,
                last_seen_at: now,
            },
        );
        true
    }

    pub fn remember_agent_approval_nonce(
        &self,
        agent_id: &str,
        authorization_ref: &str,
        request_id: &str,
        approval_nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> bool {
        let now = Utc::now();
        if expires_at <= now {
            return false;
        }
        let mut records = self.inner.agent_approval_nonces.lock();
        records.retain(|_, expiry| *expiry > now);
        let key = format!("{agent_id}:{authorization_ref}:{request_id}:{approval_nonce}");
        if records.contains_key(&key) || records.len() >= AGENT_APPROVAL_NONCE_MAX_ENTRIES {
            return false;
        }
        records.insert(key, expires_at);
        true
    }
}

pub fn key_backup_daily_download_limit() -> u32 {
    let configured = std::env::var("SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    clamp_key_backup_daily_download_limit(configured)
}

pub fn clamp_key_backup_daily_download_limit(configured: Option<u32>) -> u32 {
    configured
        .map(|value| {
            value.clamp(
                KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
                KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            )
        })
        .unwrap_or(KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
}

fn prune_window_records<K: Ord>(
    records: &mut BTreeMap<K, WindowRecord>,
    expires_before: DateTime<Utc>,
) {
    records.retain(|_, record| record.last_seen_at >= expires_before);
}

fn record_window_attempt<K: Ord + Clone>(
    records: &mut BTreeMap<K, WindowRecord>,
    key: K,
    now: DateTime<Utc>,
    window: Duration,
    max_entries: usize,
) -> u32 {
    if !records.contains_key(&key) {
        evict_oldest_entries(records, max_entries, |record| {
            record.last_seen_at.timestamp_millis()
        });
    }
    let record = records.entry(key).or_insert(WindowRecord {
        count: 0,
        window_started_at: now,
        last_seen_at: now,
    });
    if now - record.window_started_at > window {
        record.count = 0;
        record.window_started_at = now;
    }
    record.count = record.count.saturating_add(1);
    record.last_seen_at = now;
    record.count
}

fn evict_oldest_entries<K: Ord + Clone, V>(
    records: &mut BTreeMap<K, V>,
    max_entries: usize,
    timestamp: impl Fn(&V) -> i64,
) {
    while records.len() >= max_entries {
        let Some(oldest_key) = records
            .iter()
            .min_by_key(|(_, record)| timestamp(record))
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        records.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeGuardService;

    #[test]
    fn key_backup_download_quota_is_scoped_per_principal() {
        let service = RuntimeGuardService::default();
        for count in 1..=4 {
            let outcome = service.record_key_backup_download("did:web:alice.example", 4);
            assert!(!outcome.rate_limited);
            assert_eq!(outcome.count, count);
        }
        assert!(
            service
                .record_key_backup_download("did:web:alice.example", 4)
                .rate_limited
        );
        assert!(
            !service
                .record_key_backup_download("did:web:bob.example", 4)
                .rate_limited
        );
    }
}

