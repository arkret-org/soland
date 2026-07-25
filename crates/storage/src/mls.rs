use super::{PersistenceError, PersistenceResult, Uuid, Value, async_trait};
/// G3.S1 — durable KeyPackage row.
///
/// The Pg backend's `(actor_id, device_id, id)` composite key is what
/// enforces at-most-one row per `keypackage_id`. `try_claim` is the
/// CAS path — it returns `Ok(true)` on the first claim, `Ok(false)` if
/// the row is already claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackageRow {
    pub id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: String,
    pub actor_id: String,
    pub device_id: String,
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub capabilities_digest: String,
    pub device_signature: Value,
    pub last_resort: bool,
    pub last_resort_realm_id: Option<String>,
    pub lifetime_not_before: i64,
    pub lifetime_not_after: i64,
    /// MLS group id that claimed this row. `None` while claimable.
    pub claimed_by_mls_group_id: Option<String>,
    pub ssk_generation: Option<u64>,
    pub device_authorize_event_id: Option<String>,
    pub agent_key_authorize_event_id: Option<String>,
    /// Unix seconds at which the single-use claim was accepted.
    pub claimed_at: Option<i64>,
    /// Unix milliseconds for the claim authorization deadline. An unconsumed
    /// row is terminally revoked at or after this instant.
    pub claim_expires_at_unix_ms: Option<i64>,
    /// Unix seconds at which the target device consumed the accepted claim.
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

/// Durable terminal result for a peer KeyPackage claim request.
///
/// `(source_service_id, claim_request_id)` is the protocol idempotency key.
/// `request_digest` prevents a caller from reusing that key for a different
/// canonical request. `outcome` is the exact serialized success response and
/// is absent for the opaque `claim_failed` terminal state.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerKeyPackageClaimLedgerRecord {
    pub source_service_id: String,
    pub claim_request_id: String,
    pub request_digest: String,
    pub state: String,
    pub outcome: Option<Value>,
    /// Single-use KeyPackage transitioned by this ledger row. Absent for an
    /// opaque failure row.
    pub keypackage_id: Option<String>,
    /// Unix milliseconds for the protocol claim deadline, distinct from
    /// `expires_at` (Unix-second ledger retention).
    pub claim_expires_at_unix_ms: Option<i64>,
    pub expires_at: i64,
    pub updated_at: i64,
}

/// One candidate CAS attempt for a peer claim. The storage adapter must make
/// the KeyPackage transition and terminal ledger insert atomic.
pub struct PeerKeyPackageClaimAttempt<'a> {
    pub keypackage_id: &'a str,
    pub mls_group_id: &'a str,
    pub ssk_generation: Option<u64>,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub claimed_at: i64,
    pub claim_expires_at_unix_ms: i64,
    pub ledger: &'a PeerKeyPackageClaimLedgerRecord,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerKeyPackageClaimAttemptResult {
    Claimed(Box<MlsKeyPackageRow>),
    Existing(PeerKeyPackageClaimLedgerRecord),
    KeyPackageUnavailable,
}

pub struct MlsKeyPackageClaim<'a> {
    pub id: &'a str,
    pub mls_group_id: &'a str,
    pub intended_realm_id: Option<&'a str>,
    pub ssk_generation: Option<u64>,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub claimed_at: i64,
    pub claim_expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerKeyPackageClaimLedgerWriteResult {
    Inserted,
    Existing(PeerKeyPackageClaimLedgerRecord),
}
/// G3.S1 — durable Welcome envelope row (per recipient device).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeRecord {
    pub id: String,
    pub group_id: String,
    pub recipient_actor_id: String,
    pub recipient_device_id: String,
    pub welcome_bytes: Vec<u8>,
    pub key_package_id: String,
    pub epoch: u64,
    pub commit_ref: Option<String>,
    pub governance_binding: Value,
    pub enqueued_at: i64,
    pub delivered_at: Option<i64>,
}
/// G3.S1 — durable per-group commit epoch row. The protocol identity is
/// the tagged `effective_scope` plus `mls_group_id`; the row's `epoch`
/// is bumped monotonically by the CAS-protected `try_bump` path. `id`
/// is the database row identity, not the protocol identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCommitEpochRecord {
    pub id: Uuid,
    pub group_id: String,
    pub effective_scope: Value,
    pub epoch: u64,
    pub leader_actor_id: String,
    pub creator_device_id: String,
    pub genesis_event_ref: String,
    pub covered_seals: Vec<String>,
    pub governance_binding: Value,
    pub accepted_commit_ref: Option<String>,
    pub committed_at: i64,
    /// `true` once concurrent commits resolved the group's
    /// `covered_frontier_cell` to `⊥` (encryption-and-audit.md §2.5.2). Cleared
    /// when a resolving commit advances the epoch via `try_bump`.
    pub frontier_contested: bool,
}
/// G3.S1 — KeyPackage store. The `try_claim` CAS path is what
/// guarantees at-most-one Welcome per published KeyPackage.
#[async_trait]
pub trait MlsKeyPackageStore: Send + Sync {
    /// Insert a fresh KeyPackage row. Returns `Ok(false)` if the
    /// `id` is already present (re-publishes of the same id are
    /// idempotent — production fixtures sometimes resubmit on retry).
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool>;
    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    async fn get_by_ref(&self, keypackage_ref: &str)
    -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Atomically claim the named KeyPackage for `mls_group_id`. Returns
    /// `Ok(Some(record))` on success (with `claimed_by_mls_group_id` /
    /// claim-window fields filled in), `Ok(None)` if the row is already
    /// claimed or does not exist. The CAS check + update happens
    /// inside the store so two concurrent callers see at-most-one win.
    async fn try_claim(
        &self,
        claim: MlsKeyPackageClaim<'_>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Mark an already claimed ordinary KeyPackage consumed by the same MLS
    /// group. A consume at or after the claim deadline fails closed.
    async fn consume_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Read a peer claim ledger row without revealing KeyPackage inventory.
    async fn get_peer_claim(
        &self,
        source_service_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Atomically claim one ordinary KeyPackage and persist the exact terminal
    /// success outcome. Last-resort rows are never eligible on this path.
    async fn try_claim_peer(
        &self,
        attempt: PeerKeyPackageClaimAttempt<'_>,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult>;
    /// Persist a terminal outcome that does not transition a KeyPackage, such
    /// as the intentionally opaque `claim_failed` result.
    async fn record_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerRecord,
    ) -> PersistenceResult<PeerKeyPackageClaimLedgerWriteResult>;
    /// Revoke expired, still-unconsumed peer claims atomically with their
    /// ledger transitions. Returns newly revoked KeyPackage ids.
    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> PersistenceResult<Vec<String>>;
    /// Snapshot all rows. Diagnostics + the integration test rely on it.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>>;
    /// All rows claimed by `mls_group_id` (excluding the sentinel
    /// `"revoked"` claims). Ordered by `claimed_at` then `id` so callers
    /// get a stable leaf iteration order. Feeds the minimal-metadata
    /// author-credential admission view (encryption-and-audit.md §2.10.3).
    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>>;
}
/// G3.S1 — durable Welcome binding store. Delivery uses the standard
/// device-message stream; these rows support claim and consume validation.
#[async_trait]
pub trait MlsWelcomeStore: Send + Sync {
    async fn enqueue(&self, record: &MlsWelcomeRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsWelcomeRecord>>;
}
/// G3.S1 — per-group MLS commit epoch store.
pub struct MlsCommitEpochAdvance<'a> {
    pub effective_scope: &'a Value,
    pub group_id: &'a str,
    pub leader_actor_id: &'a str,
    pub covered_seals: &'a [String],
    pub governance_binding: &'a Value,
    pub accepted_commit_ref: &'a str,
    pub committed_at: i64,
}

pub struct MlsCommitGenesis<'a> {
    pub effective_scope: &'a Value,
    pub group_id: &'a str,
    pub leader_actor_id: &'a str,
    pub creator_device_id: &'a str,
    pub genesis_event_ref: &'a str,
    pub covered_seals: &'a [String],
    pub governance_binding: &'a Value,
    pub committed_at: i64,
}

#[async_trait]
pub trait MlsCommitStore: Send + Sync {
    async fn get(
        &self,
        effective_scope: &Value,
        group_id: &str,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    /// Initialize a group at epoch 0. Returns `Ok(None)` when the group
    /// already has an epoch row.
    async fn initialize_genesis(
        &self,
        genesis: MlsCommitGenesis<'_>,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    /// Atomically advance the group's epoch IFF `expected_prev_epoch`
    /// matches the existing row's current epoch.
    /// Returns `Ok(Some(new_record))` on success, `Ok(None)` on a
    /// missing genesis row or stale `expected_prev_epoch`.
    async fn try_bump(
        &self,
        expected_prev_epoch: u64,
        advance: MlsCommitEpochAdvance<'_>,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    /// §2.5.2 — flag the group's current epoch row as contested (`⊥`) after
    /// concurrent commits. A no-op (`Ok(None)`) when no epoch row exists or the
    /// stored epoch has already advanced past `epoch`.
    async fn mark_frontier_contested(
        &self,
        effective_scope: &Value,
        group_id: &str,
        epoch: u64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>>;
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct MlsCommitEpochStoreKey {
    pub effective_scope_kind: String,
    pub realm_id: String,
    pub circle_id: Option<String>,
    pub mls_group_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct MlsEffectiveScopeParts {
    pub kind: String,
    pub realm_id: String,
    pub circle_id: Option<String>,
}
impl MlsEffectiveScopeParts {
    fn store_key(&self, group_id: &str) -> MlsCommitEpochStoreKey {
        MlsCommitEpochStoreKey {
            effective_scope_kind: self.kind.clone(),
            realm_id: self.realm_id.clone(),
            circle_id: self.circle_id.clone(),
            mls_group_id: group_id.to_owned(),
        }
    }
}
#[doc(hidden)]
pub fn mls_epoch_key(
    effective_scope: &Value,
    group_id: &str,
) -> PersistenceResult<MlsCommitEpochStoreKey> {
    Ok(mls_effective_scope_parts(effective_scope)?.store_key(group_id))
}
#[doc(hidden)]
pub fn mls_effective_scope_parts(
    effective_scope: &Value,
) -> PersistenceResult<MlsEffectiveScopeParts> {
    let object = effective_scope.as_object().ok_or_else(|| {
        PersistenceError::Internal("MLS effective_scope must be an object".to_owned())
    })?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| PersistenceError::Internal("MLS effective_scope missing kind".to_owned()))?;
    let realm_id = object
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PersistenceError::Internal("MLS effective_scope missing realm_id".to_owned())
        })?;
    if realm_id.is_empty() {
        return Err(PersistenceError::Internal(
            "MLS effective_scope has empty realm_id".to_owned(),
        ));
    }
    match kind {
        "realm" => {
            if object.len() != 2 || object.contains_key("circle_id") {
                return Err(PersistenceError::Internal(
                    "MLS realm effective_scope must only contain kind and realm_id".to_owned(),
                ));
            }
            Ok(MlsEffectiveScopeParts {
                kind: kind.to_owned(),
                realm_id: realm_id.to_owned(),
                circle_id: None,
            })
        }
        "circle" => {
            let circle_id = object
                .get("circle_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PersistenceError::Internal("MLS effective_scope missing circle_id".to_owned())
                })?;
            if circle_id.is_empty() || object.len() != 3 {
                return Err(PersistenceError::Internal(
                    "MLS circle effective_scope must only contain kind, realm_id, and circle_id"
                        .to_owned(),
                ));
            }
            Ok(MlsEffectiveScopeParts {
                kind: kind.to_owned(),
                realm_id: realm_id.to_owned(),
                circle_id: Some(circle_id.to_owned()),
            })
        }
        _ => Err(PersistenceError::Internal(
            "MLS effective_scope has invalid kind".to_owned(),
        )),
    }
}
#[doc(hidden)]
pub fn db_ssk_generation(generation: Option<u64>) -> PersistenceResult<Option<i64>> {
    generation
        .map(|generation| {
            i64::try_from(generation)
                .map_err(|_| PersistenceError::Internal("ssk_generation exceeds i64".to_owned()))
        })
        .transpose()
}
