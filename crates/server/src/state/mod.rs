// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod app_state;
mod member_identity;
mod notification;
mod realm_directory;
mod records;
mod state_resolution;

pub use app_state::AppState;
pub(crate) use app_state::getrandom_seed;
pub(crate) use member_identity::display_state_digest;
pub use member_identity::{
    EffectiveIdentityEntry, HandleClaimDigestInput, HandleClaimEvidenceRecord,
    MemberIdentityEventRecord, MemberIdentityRegistry, MemberIdentityReplacementEdge,
    MemberIdentitySnapshot, MemberIdentitySubjectKey,
};
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, Mutex, SubscribeReconnectGate,
};
pub use realm_directory::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
#[cfg(test)]
pub(crate) use records::clamp_key_backup_daily_download_limit;
pub(crate) use records::key_backup_daily_download_limit;
pub use records::{
    ACCOUNT_LOCKOUT_DURATION, ACCOUNT_LOCKOUT_THRESHOLD, ACCOUNT_LOCKOUT_WINDOW, AccountDataRecord,
    AccountLifecycleRecord, AccountLocalpartRecord, AccountRecord, AgentSessionRecord, BlobRecord,
    CallSignalRelayRecord, CanonicalEventRecord, ConsentCellKey, ConsentCellRecord,
    ConsentGrantDot, ContactRecord, CursorRevocation, DeviceInventoryRecord, DeviceMessageRecord,
    DirectConversationBindingRecord, FailedLoginRecord, FederationFrontierExchangeRecord,
    FederationOutboxDeadLetterRecord, FederationOutboxRecord, FederationTransactionRecord,
    KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT, KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
    KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN, KEY_BACKUP_DOWNLOAD_WINDOW, KeyBackupDownloadOutcome,
    KeyBackupDownloadRecord, MODERATION_FRANKING_REPLAY_MAX_ENTRIES,
    MODERATION_FRANKING_REPLAY_WINDOW_SECS, MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES,
    MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
    MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW, MODERATION_REPORT_MAX_PER_REPORTER_WINDOW,
    MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW, MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW,
    MODERATION_REPORT_RATE_WINDOW_SECS, MessageRecord, ModerationFrankingReplayRecord,
    ModerationReportRateOutcome, ModerationReportRateRecord, MultisigPendingRecord,
    OrganizationPolicyRecord, OrganizationRecord, OutboundPushBridgeCacheRecord,
    PSI_HIT_BUCKET_SECS, PSI_PROBE_MAX_PER_WINDOW, PSI_PROBE_WINDOW, PolicyDocumentRecord,
    PresenceRecord, ProjectionEventRecord, PsiProbeOutcome, PsiProbeRecord, PushRuleRecord,
    ReadReceiptRelayRecord, RealmInviteRecord, RealmMetaRecord, RealmModerationPolicyRecord,
    RealmOrganizationStatementRecord, RecoveryPolicyRecord, RecoveryReceiptRecord,
    RecoverySessionRecord, RetentionPolicyRecord,
    RetentionTombstoneRecord, SessionRecord, SovereignAuditRecord, SovereignDeploymentState,
    SovereignEnclaveRecord, SovereignExternalAccountRecord, SovereignExternalInviteRecord,
    SovereignRealmRecord, SovereignStoreForwardRecord, TypingRecord, WebvhDocumentRecord,
    WebvhLogRecord,
};
