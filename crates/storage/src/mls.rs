use arkret_wire::{MlsGroupId, RealmId};

use super::{
    AccountPk, DeviceRevocationGateSelector, PersistenceError, PersistenceResult, Uuid, Value,
    async_trait,
};
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
    /// Service-local account that owns this KeyPackage. This is deliberately
    /// separate from `actor_id`: one principal may have more than one account.
    pub owner_account_pk: AccountPk,
    pub actor_id: String,
    pub device_id: Option<String>,
    pub endpoint_verification_method: Option<String>,
    pub intended_realm_id: Option<String>,
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub capabilities_digest: String,
    pub last_resort: bool,
    pub last_resort_realm_id: Option<String>,
    pub lifetime_not_before: i64,
    pub lifetime_not_after: i64,
    /// MLS group id that claimed this row. `None` while claimable.
    pub claimed_by_mls_group_id: Option<String>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistedKeyPackageReusePolicy {
    SingleUse,
    LastResort { bound_realm_id: Option<RealmId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistedKeyPackageClaimState {
    Available,
    Claimed {
        mls_group_id: MlsGroupId,
        claimed_at: i64,
        claim_expires_at_unix_ms: Option<i64>,
    },
    Consumed {
        mls_group_id: MlsGroupId,
        claimed_at: i64,
        claim_expires_at_unix_ms: Option<i64>,
        consumed_at: i64,
    },
    Retired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedKeyPackageLifecycle {
    pub reuse_policy: PersistedKeyPackageReusePolicy,
    pub claim_state: PersistedKeyPackageClaimState,
}

pub fn classify_key_package_lifecycle(
    last_resort: bool,
    last_resort_realm_id: Option<&str>,
    claimed_by_mls_group_id: Option<&str>,
    claimed_at: Option<i64>,
    claim_expires_at_unix_ms: Option<i64>,
    consumed_at: Option<i64>,
) -> Result<PersistedKeyPackageLifecycle, String> {
    const REVOKED_CLAIM_SENTINEL: &str = "revoked";
    const RETIRED_CLAIM_SENTINEL: &str = "retired";

    let reuse_policy = if last_resort {
        PersistedKeyPackageReusePolicy::LastResort {
            bound_realm_id: last_resort_realm_id
                .map(|value| {
                    RealmId::new(value.to_owned()).map_err(|error| {
                        format!("last-resort KeyPackage Realm id is invalid: {error}")
                    })
                })
                .transpose()?,
        }
    } else {
        if last_resort_realm_id.is_some() {
            return Err("ordinary KeyPackage must not carry last_resort_realm_id".to_owned());
        }
        PersistedKeyPackageReusePolicy::SingleUse
    };
    let claim_state = match claimed_by_mls_group_id {
        Some(REVOKED_CLAIM_SENTINEL) => {
            if claimed_at.is_some() || claim_expires_at_unix_ms.is_some() || consumed_at.is_some() {
                return Err(
                    "revoked KeyPackage must not carry claim or consumption timestamps".to_owned(),
                );
            }
            PersistedKeyPackageClaimState::Revoked
        }
        Some(RETIRED_CLAIM_SENTINEL) => {
            if last_resort
                || claimed_at.is_some()
                || claim_expires_at_unix_ms.is_some()
                || consumed_at.is_some()
            {
                return Err(
                    "retired KeyPackage must be ordinary, unused, and timestamp-free".to_owned(),
                );
            }
            PersistedKeyPackageClaimState::Retired
        }
        Some(group_id) if last_resort => {
            return Err(format!(
                "last-resort KeyPackage must not be claimed by MLS group `{group_id}`"
            ));
        }
        Some(group_id) => {
            let group_id = MlsGroupId::new(group_id.to_owned())
                .map_err(|error| format!("claimed KeyPackage MLS group id is invalid: {error}"))?;
            let claimed_at =
                claimed_at.ok_or_else(|| "claimed KeyPackage is missing claimed_at".to_owned())?;
            match consumed_at {
                Some(consumed_at) => PersistedKeyPackageClaimState::Consumed {
                    mls_group_id: group_id,
                    claimed_at,
                    claim_expires_at_unix_ms,
                    consumed_at,
                },
                None => PersistedKeyPackageClaimState::Claimed {
                    mls_group_id: group_id,
                    claimed_at,
                    claim_expires_at_unix_ms,
                },
            }
        }
        None => {
            if claimed_at.is_some() || claim_expires_at_unix_ms.is_some() || consumed_at.is_some() {
                return Err(
                    "available KeyPackage must not carry claim or consumption timestamps"
                        .to_owned(),
                );
            }
            PersistedKeyPackageClaimState::Available
        }
    };
    Ok(PersistedKeyPackageLifecycle {
        reuse_policy,
        claim_state,
    })
}

impl MlsKeyPackageRow {
    pub fn lifecycle(&self) -> Result<PersistedKeyPackageLifecycle, String> {
        classify_key_package_lifecycle(
            self.last_resort,
            self.last_resort_realm_id.as_deref(),
            self.claimed_by_mls_group_id.as_deref(),
            self.claimed_at,
            self.claim_expires_at_unix_ms,
            self.consumed_at,
        )
    }
}

#[cfg(test)]
mod key_package_lifecycle_tests {
    use super::*;

    #[test]
    fn ordinary_claim_and_consumption_are_explicit_states() {
        let claimed = classify_key_package_lifecycle(
            false,
            None,
            Some("group-a"),
            Some(10),
            Some(20_000),
            None,
        )
        .unwrap();
        assert!(matches!(
            claimed.claim_state,
            PersistedKeyPackageClaimState::Claimed {
                ref mls_group_id,
                ..
            } if mls_group_id.as_str() == "group-a"
        ));

        let consumed = classify_key_package_lifecycle(
            false,
            None,
            Some("group-a"),
            Some(10),
            Some(20_000),
            Some(15),
        )
        .unwrap();
        assert!(matches!(
            consumed.claim_state,
            PersistedKeyPackageClaimState::Consumed {
                consumed_at: 15,
                ..
            }
        ));
    }

    #[test]
    fn last_resort_binding_is_a_reuse_policy_not_a_group_claim() {
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let lifecycle =
            classify_key_package_lifecycle(true, Some(realm_id), None, None, None, None).unwrap();
        assert_eq!(
            lifecycle.reuse_policy,
            PersistedKeyPackageReusePolicy::LastResort {
                bound_realm_id: Some(RealmId::new(realm_id).unwrap())
            }
        );
        assert_eq!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
        );
    }

    #[test]
    fn invalid_column_combinations_fail_closed() {
        assert!(
            classify_key_package_lifecycle(false, Some("realm"), None, None, None, None).is_err()
        );
        assert!(
            classify_key_package_lifecycle(true, None, Some("group-a"), Some(1), None, None)
                .is_err()
        );
        assert!(
            classify_key_package_lifecycle(false, None, Some("group-a"), None, None, None).is_err()
        );
        assert!(
            classify_key_package_lifecycle(false, None, Some("revoked"), Some(1), None, Some(2))
                .is_err()
        );
        assert!(
            classify_key_package_lifecycle(
                false,
                None,
                Some("revoked"),
                Some(1),
                Some(2_000),
                None,
            )
            .is_err()
        );
    }
}

/// Durable terminal result for a peer KeyPackage claim request.
///
/// `(source_id, claim_request_id)` is the protocol idempotency key.
/// `request_digest` prevents a caller from reusing that key for a different
/// canonical request. `outcome` is the exact serialized success response and
/// is absent for the opaque `claim_failed` terminal state.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerKeyPackageClaimLedgerRecord {
    pub source_id: String,
    pub claim_request_id: String,
    pub request_digest: String,
    /// Durable use class of the claimed KeyPackage (`single_use`,
    /// `last_resort`, or `none` for an opaque failure/remote mirror without a
    /// local package row). This remains stable after the ledger reaches a
    /// terminal state and therefore must not be inferred from `state`.
    pub key_package_use: String,
    /// KeyPackage referenced by this ledger row. Absent for an opaque failure
    /// or a source-side mirror of a remote claim.
    pub keypackage_id: Option<String>,
    pub outcome: Option<Value>,
    pub terminal_receipt: Option<Value>,
    pub consume_receipt: Option<Value>,
    /// Unix milliseconds for the protocol claim deadline, distinct from
    /// `expires_at` (Unix-second ledger retention).
    pub claim_expires_at_unix_ms: Option<i64>,
    pub expires_at: i64,
    pub state: String,
    pub updated_at: i64,
}

/// One candidate CAS attempt for a peer claim. The storage adapter must make
/// the KeyPackage transition and terminal ledger insert atomic.
pub struct PeerKeyPackageClaimAttempt<'a> {
    pub keypackage_id: &'a str,
    pub mls_group_id: &'a str,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    pub claimed_at_unix_ms: i64,
    pub claim_expires_at_unix_ms: i64,
    pub ledger: &'a PeerKeyPackageClaimLedgerRecord,
}

pub struct PeerClaimTerminalTransition<'a> {
    pub source_id: &'a str,
    pub claim_request_id: &'a str,
    pub request_digest: &'a str,
    pub expected_outcome: &'a Value,
    pub terminal_state: &'a str,
    pub terminal_receipt: &'a Value,
    pub now_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerKeyPackageClaimAttemptResult {
    Claimed(Box<MlsKeyPackageRow>),
    Existing(Box<PeerKeyPackageClaimLedgerRecord>),
    KeyPackageUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsKeyPackageClaimTarget<'a> {
    Group(&'a str),
    Retire,
    Revoke,
}

pub struct MlsKeyPackageClaim<'a> {
    pub id: &'a str,
    pub target: MlsKeyPackageClaimTarget<'a>,
    pub intended_realm_id: Option<&'a str>,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    pub claimed_at: i64,
    pub claim_expires_at_unix_ms: Option<i64>,
}

/// Apply the storage-neutral acceptance rules for one KeyPackage claim.
///
/// Adapters remain responsible for revocation-gate reads, row locking and the
/// atomic write. Returning `None` is the CAS-loser/unavailable outcome.
pub fn apply_key_package_claim(
    row: &MlsKeyPackageRow,
    claim: &MlsKeyPackageClaim<'_>,
) -> Option<MlsKeyPackageRow> {
    if row.id != claim.id {
        return None;
    }
    let (group_id, terminal_without_claim, retiring) = match claim.target {
        MlsKeyPackageClaimTarget::Group(group_id) => (group_id, false, false),
        MlsKeyPackageClaimTarget::Retire => ("retired", true, true),
        MlsKeyPackageClaimTarget::Revoke => ("revoked", true, false),
    };
    if matches!(
        row.claimed_by_mls_group_id.as_deref(),
        Some("revoked" | "retired")
    ) || retiring && (row.last_resort || row.claimed_by_mls_group_id.is_some())
    {
        return None;
    }
    if !terminal_without_claim
        && (claim.claimed_at >= row.lifetime_not_after
            || claim
                .claim_expires_at_unix_ms
                .is_some_and(|expires_at_unix_ms| {
                    expires_at_unix_ms <= claim.claimed_at.saturating_mul(1000)
                        || expires_at_unix_ms > row.lifetime_not_after.saturating_mul(1000)
                }))
    {
        return None;
    }
    if row
        .claimed_by_mls_group_id
        .as_deref()
        .is_some_and(|claimed| claimed != group_id)
        && !(row.last_resort && !terminal_without_claim)
    {
        return None;
    }
    if claim
        .device_authorize_event_id
        .is_some_and(|event_id| row.device_authorize_event_id.as_deref() != Some(event_id))
        || claim
            .agent_key_authorize_event_id
            .is_some_and(|event_id| row.agent_key_authorize_event_id.as_deref() != Some(event_id))
    {
        return None;
    }

    let mut next = row.clone();
    if row.last_resort && !terminal_without_claim {
        let realm_id = claim.intended_realm_id?;
        if row
            .last_resort_realm_id
            .as_deref()
            .is_some_and(|bound_realm_id| bound_realm_id != realm_id)
        {
            return None;
        }
        if next.last_resort_realm_id.is_none() {
            next.last_resort_realm_id = Some(realm_id.to_owned());
        }
        return Some(next);
    }

    next.claimed_by_mls_group_id = Some(group_id.to_owned());
    next.claimed_at = (!terminal_without_claim).then_some(claim.claimed_at);
    next.claim_expires_at_unix_ms = if terminal_without_claim {
        None
    } else {
        claim.claim_expires_at_unix_ms
    };
    next.consumed_at = None;
    Some(next)
}

#[cfg(test)]
mod key_package_claim_transition_tests {
    use super::*;

    fn row(last_resort: bool) -> MlsKeyPackageRow {
        MlsKeyPackageRow {
            id: "kp-1".to_owned(),
            keypackage_ref: "ak:mls:keypackage:kp-1".to_owned(),
            keypackage_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            owner_account_pk: AccountPk(1),
            actor_id: "ak:did_core:web:agent.example".to_owned(),
            device_id: Some("ak:device:01904100-0000-7000-8000-000000000001".to_owned()),
            endpoint_verification_method: None,
            intended_realm_id: None,
            key_package_bytes: vec![1, 2, 3],
            capabilities: vec!["ak.mls.rfc9420".to_owned()],
            capabilities_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            last_resort,
            last_resort_realm_id: None,
            lifetime_not_before: 1,
            lifetime_not_after: 100,
            claimed_by_mls_group_id: None,
            device_authorize_event_id: Some("event-1".to_owned()),
            agent_key_authorize_event_id: None,
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: 1,
        }
    }

    fn claim<'a>(target: MlsKeyPackageClaimTarget<'a>) -> MlsKeyPackageClaim<'a> {
        MlsKeyPackageClaim {
            id: "kp-1",
            target,
            intended_realm_id: None,
            device_authorize_event_id: Some("event-1"),
            agent_key_authorize_event_id: None,
            device_revocation_gate: None,
            claimed_at: 10,
            claim_expires_at_unix_ms: Some(20_000),
        }
    }

    #[test]
    fn ordinary_claim_case_table_covers_acceptance_and_cas_losers() {
        let available = row(false);
        let accepted = apply_key_package_claim(
            &available,
            &claim(MlsKeyPackageClaimTarget::Group("group-a")),
        )
        .expect("available ordinary package is claimable");
        assert_eq!(accepted.claimed_by_mls_group_id.as_deref(), Some("group-a"));
        assert_eq!(accepted.claimed_at, Some(10));
        assert_eq!(accepted.claim_expires_at_unix_ms, Some(20_000));

        let renewed = apply_key_package_claim(
            &accepted,
            &claim(MlsKeyPackageClaimTarget::Group("group-a")),
        );
        assert!(renewed.is_some(), "same-group retry is idempotent renewal");
        assert!(
            apply_key_package_claim(
                &accepted,
                &claim(MlsKeyPackageClaimTarget::Group("group-b"))
            )
            .is_none(),
            "different group loses the CAS"
        );

        let mut expired = claim(MlsKeyPackageClaimTarget::Group("group-a"));
        expired.claimed_at = 100;
        assert!(apply_key_package_claim(&available, &expired).is_none());

        let mut wrong_event = claim(MlsKeyPackageClaimTarget::Group("group-a"));
        wrong_event.device_authorize_event_id = Some("event-2");
        assert!(apply_key_package_claim(&available, &wrong_event).is_none());
    }

    #[test]
    fn terminal_and_last_resort_transitions_share_one_oracle() {
        let ordinary = row(false);
        let retired = apply_key_package_claim(&ordinary, &claim(MlsKeyPackageClaimTarget::Retire))
            .expect("unused ordinary package may retire");
        assert_eq!(retired.claimed_by_mls_group_id.as_deref(), Some("retired"));
        assert!(
            apply_key_package_claim(&retired, &claim(MlsKeyPackageClaimTarget::Revoke)).is_none()
        );

        let reusable = row(true);
        assert!(
            apply_key_package_claim(
                &reusable,
                &claim(MlsKeyPackageClaimTarget::Group("group-a"))
            )
            .is_none(),
            "last-resort claim requires an intended realm"
        );
        let mut bound_claim = claim(MlsKeyPackageClaimTarget::Group("group-a"));
        bound_claim.intended_realm_id =
            Some("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K");
        let bound = apply_key_package_claim(&reusable, &bound_claim)
            .expect("last-resort package binds on first realm claim");
        assert_eq!(
            bound.last_resort_realm_id,
            bound_claim.intended_realm_id.map(str::to_owned)
        );
        assert!(bound.claimed_by_mls_group_id.is_none());
        assert!(
            apply_key_package_claim(&reusable, &claim(MlsKeyPackageClaimTarget::Retire)).is_none()
        );
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerKeyPackageClaimLedgerWriteResult {
    Inserted,
    Existing(Box<PeerKeyPackageClaimLedgerRecord>),
}
/// G3.S1 — durable Welcome envelope row (per closed recipient endpoint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeRecord {
    pub id: String,
    pub group_id: String,
    pub recipient_actor_id: String,
    pub recipient_device_id: Option<String>,
    pub recipient_endpoint_verification_method: Option<String>,
    pub intended_realm_id: Option<String>,
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
    pub governance_binding: Value,
    pub accepted_commit_ref: Option<String>,
    pub committed_at: i64,
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
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Read a peer claim ledger row without revealing KeyPackage inventory.
    async fn get_peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Resolve the unique durable ordinary single-use peer-claim fact that
    /// owns a KeyPackage. Reusable last-resort packages intentionally have
    /// multiple independent claim audit rows and are excluded.
    async fn get_peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
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
    /// Attach a signed receipt to an existing terminal peer-claim fact. This
    /// never creates a ledger row and therefore cannot fabricate a terminal
    /// state without the original durable request/outcome.
    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Replicate a destination-accepted consume fact into an existing source
    /// claim mirror. The signed consume time, rather than replication arrival
    /// time, is checked against the original claim deadline.
    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Atomically transition an existing source-side successful claim mirror
    /// to its signed terminal state while preserving its use class, claimed
    /// coordinates, and exact outcome. Returns `None` for a missing row,
    /// state/digest/outcome drift, or a non-terminal target.
    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransition<'_>,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Close expired peer claim audits atomically. Ordinary single-use claims
    /// revoke their KeyPackage and return its id; last-resort claims only move
    /// their independent audit to `expired` and never return the reusable
    /// KeyPackage id.
    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> PersistenceResult<Vec<String>>;
    /// Snapshot all rows. Diagnostics + the integration test rely on it.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>>;
    /// All rows claimed by `mls_group_id` (excluding the terminal sentinel
    /// `"revoked"` and `"retired"` states). Ordered by `claimed_at` then `id` so callers
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
    async fn discover(
        &self,
        query: &MlsWelcomeDiscoveryQuery,
    ) -> PersistenceResult<MlsWelcomeDiscoveryPage>;
}

#[derive(Clone, Debug)]
pub struct MlsWelcomeDiscoveryQuery {
    pub scope: Value,
    pub group_id: String,
    pub endpoint: Value,
    pub authority_context: Value,
    pub authorization_ref: String,
    pub membership_cells: Vec<String>,
    pub limit: u32,
    pub cursor: Option<String>,
    pub now: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug)]
pub struct MlsWelcomeDiscoveryPage {
    pub welcome_refs: Vec<String>,
    pub next_cursor: Option<String>,
}
/// G3.S1 — per-group MLS commit epoch store.
pub struct MlsCommitEpochAdvance<'a> {
    pub effective_scope: &'a Value,
    pub group_id: &'a str,
    pub leader_actor_id: &'a str,
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
    pub governance_binding: &'a Value,
    pub committed_at: i64,
}

#[async_trait]
pub trait MlsCommitStore: Send + Sync {
    /// Frozen endpoint authority for an exact public candidate, if available.
    async fn public_leaf_authorizations(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<Vec<arkret_models_crypto::MlsAcceptedLeafAuthorization>>>;

    /// Exact accepted public Genesis candidate, not a current membership result.
    async fn public_genesis_candidate(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<crate::MlsPublicGenesisRecord>>;

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
