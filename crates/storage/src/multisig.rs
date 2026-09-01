use super::{BTreeMap, MultisigPendingRecord, PersistenceResult, Value, async_trait};

/// Persistence-neutral state observed while holding the backend's row lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigLeaseState {
    pub claimed_by_node_id: Option<String>,
    pub claimed_until: Option<chrono::DateTime<chrono::Utc>>,
    pub claim_seq: i64,
}

impl From<&MultisigPendingRecord> for MultisigLeaseState {
    fn from(record: &MultisigPendingRecord) -> Self {
        Self {
            claimed_by_node_id: record.claimed_by_node_id.clone(),
            claimed_until: record.claimed_until,
            claim_seq: record.claim_seq,
        }
    }
}

/// Commands whose admission must be identical in every storage adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultisigLeaseCommand {
    TryClaim {
        node_id: String,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    },
    Release {
        node_id: String,
    },
    DeleteWithFence {
        node_id: String,
        claim_seq: i64,
    },
    RenewWithFence {
        node_id: String,
        claim_seq: i64,
        claimed_until: chrono::DateTime<chrono::Utc>,
    },
}

/// Pure decision emitted before a backend performs its write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultisigLeaseDecision {
    /// No row exists. The public API treats this as a rejected/no-op command.
    Missing,
    /// The row exists but the command has no authority to mutate it.
    Rejected { current_claim_seq: i64 },
    /// Replace the three lease fields atomically.
    Update(MultisigLeaseState),
    /// Delete the row while the backend lock is still held.
    Delete,
}

/// Classify a multisig watchdog lease command without performing persistence.
///
/// Memory calls this while holding its aggregate mutex. PostgreSQL calls it
/// after `SELECT .. FOR UPDATE`; the adapters retain their own locking and
/// write mechanics while sharing every business branch and fencing decision.
pub fn decide_multisig_lease(
    state: Option<&MultisigLeaseState>,
    command: &MultisigLeaseCommand,
) -> PersistenceResult<MultisigLeaseDecision> {
    let Some(state) = state else {
        return Ok(MultisigLeaseDecision::Missing);
    };
    match command {
        MultisigLeaseCommand::TryClaim {
            node_id,
            now,
            claimed_until,
        } => {
            let claimable = state.claimed_by_node_id.is_none()
                || state.claimed_until.is_none()
                || state.claimed_until.is_some_and(|deadline| deadline <= *now);
            if !claimable {
                return Ok(MultisigLeaseDecision::Rejected {
                    current_claim_seq: state.claim_seq,
                });
            }
            let claim_seq = state.claim_seq.checked_add(1).ok_or_else(|| {
                super::PersistenceError::Internal(
                    "multisig claim fencing sequence overflow".to_owned(),
                )
            })?;
            Ok(MultisigLeaseDecision::Update(MultisigLeaseState {
                claimed_by_node_id: Some(node_id.clone()),
                claimed_until: Some(*claimed_until),
                claim_seq,
            }))
        }
        MultisigLeaseCommand::Release { node_id } => {
            if state.claimed_by_node_id.as_deref() != Some(node_id) {
                return Ok(MultisigLeaseDecision::Rejected {
                    current_claim_seq: state.claim_seq,
                });
            }
            Ok(MultisigLeaseDecision::Update(MultisigLeaseState {
                claimed_by_node_id: None,
                claimed_until: None,
                claim_seq: state.claim_seq,
            }))
        }
        MultisigLeaseCommand::DeleteWithFence { node_id, claim_seq } => {
            if state.claimed_by_node_id.as_deref() == Some(node_id) && state.claim_seq == *claim_seq
            {
                Ok(MultisigLeaseDecision::Delete)
            } else {
                Ok(MultisigLeaseDecision::Rejected {
                    current_claim_seq: state.claim_seq,
                })
            }
        }
        MultisigLeaseCommand::RenewWithFence {
            node_id,
            claim_seq,
            claimed_until,
        } => {
            if state.claimed_by_node_id.as_deref() != Some(node_id) || state.claim_seq != *claim_seq
            {
                return Ok(MultisigLeaseDecision::Rejected {
                    current_claim_seq: state.claim_seq,
                });
            }
            Ok(MultisigLeaseDecision::Update(MultisigLeaseState {
                claimed_by_node_id: state.claimed_by_node_id.clone(),
                claimed_until: Some(*claimed_until),
                claim_seq: state.claim_seq,
            }))
        }
    }
}
/// MAL-11 — persistent multisig partial-signature buffer.
///
/// The notary coordinator writes partials to this store so they survive
/// restarts and can be picked up by a leader-election watchdog once the
/// threshold is met. The read-only admin endpoint exposes pending status.
/// The memory backend is test-only; the Pg backend writes to the
/// `multisig_pending` table.
#[async_trait]
pub trait MultisigPendingStore: Send + Sync {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()>;
    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>>;
    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MultisigPendingRecord>>;
    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool>;

    /// List every row across all Realms. Used by the leader-election
    /// watchdog to scan for threshold-met rows that need aggregation +
    /// publication.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>>;

    /// Atomically claim a row for `node_id` until `claimed_until` if (a)
    /// the row exists, (b) it is currently unclaimed or its existing lease
    /// has expired (relative to `now`).
    ///
    /// On success the row's monotonic `claim_seq` is bumped by 1 and the
    /// new value is returned alongside the success flag. The watchdog
    /// snapshots this value as its **fencing token**: any
    /// follow-up `delete_with_fence` / `renew_claim` it issues against
    /// the row carries the same `claim_seq`, and a stale leader (whose
    /// lease was silently re-issued to another node after a partition
    /// healed) finds its `claim_seq` no longer matches and is rejected
    /// at the row level. Returns `Ok((true, new_seq))` when this caller
    /// now owns the lease, `Ok((false, current_seq))` otherwise.
    async fn try_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)>;

    /// Release a held lease (called after the row was successfully
    /// aggregated + deleted, or when the caller decided to give up
    /// early). Idempotent — safe to call on a row that was already
    /// deleted.
    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()>;

    /// Fenced delete. Only deletes the row when both the lease holder
    /// *and* the fencing token match. A stale leader (one whose lease
    /// was superseded after a partition heal) carries a mismatched
    /// `claim_seq`, so this returns `Ok(false)` and the row stays intact
    /// for the live leader to publish. Returns `Ok(true)` iff the delete
    /// happened.
    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool>;

    /// Happy-path lease renewal during long aggregation. Pushes
    /// `claimed_until` forward without bumping `claim_seq` (so the
    /// watchdog's snapshotted fencing token stays valid). Only succeeds
    /// when the lease is still held by `node_id` AND the supplied
    /// `claim_seq` matches the row — a stale leader's renewal is
    /// rejected. Returns `Ok(true)` iff the renewal landed.
    async fn renew_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
}
#[doc(hidden)]
pub fn partials_to_jsonb(partials: &BTreeMap<String, Value>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in partials {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::{
        MultisigLeaseCommand, MultisigLeaseDecision, MultisigLeaseState, decide_multisig_lease,
    };

    #[test]
    fn lease_decision_table_covers_claim_release_renew_and_delete() {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let unclaimed = MultisigLeaseState {
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: 0,
        };
        let live = MultisigLeaseState {
            claimed_by_node_id: Some("node-a".to_owned()),
            claimed_until: Some(now + Duration::minutes(10)),
            claim_seq: 4,
        };
        let expired = MultisigLeaseState {
            claimed_until: Some(now),
            ..live.clone()
        };
        let claimed = |node_id: &str, claim_seq: i64, until| {
            MultisigLeaseDecision::Update(MultisigLeaseState {
                claimed_by_node_id: Some(node_id.to_owned()),
                claimed_until: Some(until),
                claim_seq,
            })
        };
        let rejected = |current_claim_seq| MultisigLeaseDecision::Rejected { current_claim_seq };
        let claim_until = now + Duration::minutes(20);
        let cases = [
            (
                "missing",
                None,
                MultisigLeaseCommand::TryClaim {
                    node_id: "node-b".to_owned(),
                    now,
                    claimed_until: claim_until,
                },
                MultisigLeaseDecision::Missing,
            ),
            (
                "unclaimed",
                Some(&unclaimed),
                MultisigLeaseCommand::TryClaim {
                    node_id: "node-b".to_owned(),
                    now,
                    claimed_until: claim_until,
                },
                claimed("node-b", 1, claim_until),
            ),
            (
                "live lease",
                Some(&live),
                MultisigLeaseCommand::TryClaim {
                    node_id: "node-b".to_owned(),
                    now,
                    claimed_until: claim_until,
                },
                rejected(4),
            ),
            (
                "exact expiry is claimable",
                Some(&expired),
                MultisigLeaseCommand::TryClaim {
                    node_id: "node-b".to_owned(),
                    now,
                    claimed_until: claim_until,
                },
                claimed("node-b", 5, claim_until),
            ),
            (
                "wrong-owner release",
                Some(&live),
                MultisigLeaseCommand::Release {
                    node_id: "node-b".to_owned(),
                },
                rejected(4),
            ),
            (
                "exact release",
                Some(&live),
                MultisigLeaseCommand::Release {
                    node_id: "node-a".to_owned(),
                },
                MultisigLeaseDecision::Update(MultisigLeaseState {
                    claimed_by_node_id: None,
                    claimed_until: None,
                    claim_seq: 4,
                }),
            ),
            (
                "stale renewal",
                Some(&live),
                MultisigLeaseCommand::RenewWithFence {
                    node_id: "node-a".to_owned(),
                    claim_seq: 3,
                    claimed_until: claim_until,
                },
                rejected(4),
            ),
            (
                "exact renewal",
                Some(&live),
                MultisigLeaseCommand::RenewWithFence {
                    node_id: "node-a".to_owned(),
                    claim_seq: 4,
                    claimed_until: claim_until,
                },
                claimed("node-a", 4, claim_until),
            ),
            (
                "stale delete",
                Some(&live),
                MultisigLeaseCommand::DeleteWithFence {
                    node_id: "node-a".to_owned(),
                    claim_seq: 3,
                },
                rejected(4),
            ),
            (
                "exact delete",
                Some(&live),
                MultisigLeaseCommand::DeleteWithFence {
                    node_id: "node-a".to_owned(),
                    claim_seq: 4,
                },
                MultisigLeaseDecision::Delete,
            ),
        ];

        for (name, state, command, expected) in cases {
            assert_eq!(
                decide_multisig_lease(state, &command).expect(name),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn claim_sequence_overflow_fails_closed() {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let state = MultisigLeaseState {
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: i64::MAX,
        };
        assert!(
            decide_multisig_lease(
                Some(&state),
                &MultisigLeaseCommand::TryClaim {
                    node_id: "node-a".to_owned(),
                    now,
                    claimed_until: now + Duration::minutes(1),
                },
            )
            .is_err()
        );
    }
}
