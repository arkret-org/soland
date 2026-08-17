use arkret_models_collaboration::account_lifecycle::{AccountStatusReceipt, AccountStatusRecord};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use soland_storage::{
    AccountStatusReplicaAppend, AccountStatusReplicaConflictKind, AccountStatusReplicaStore,
    PersistenceError, PersistenceResult,
};

use crate::{BTreeMap, Mutex, async_trait};

/// The durable replica head for one `(account_authority_id, account_id)` pair:
/// the accepted record and the receipt that acknowledged it.
type ReplicaHead = (AccountStatusRecord, AccountStatusReceipt);

#[derive(Default)]
pub struct MemoryAccountStatusReplicaStore {
    records: Mutex<BTreeMap<(String, String, u64), ReplicaHead>>,
}

impl MemoryAccountStatusReplicaStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AccountStatusReplicaStore for MemoryAccountStatusReplicaStore {
    async fn append(
        &self,
        record: &AccountStatusRecord,
        receipt: &AccountStatusReceipt,
    ) -> PersistenceResult<AccountStatusReplicaAppend> {
        receipt.validate_for_record(record).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "account-status record/receipt pair is invalid: {error}"
            ))
        })?;
        let authority = record.account_authority_id.to_string();
        let account = record.account_id.to_string();
        let mut records = self.records.lock();
        let head = replica_head(&records, &authority, &account);
        if let Some(outcome) = classify(record, head.as_ref()) {
            return Ok(outcome);
        }
        records.insert(
            (authority, account, record.status_seq),
            (record.clone(), receipt.clone()),
        );
        Ok(AccountStatusReplicaAppend::Accepted(receipt.clone()))
    }

    async fn current(
        &self,
        account_authority_id: &str,
        account_id: &str,
    ) -> PersistenceResult<Option<AccountStatusRecord>> {
        Ok(current(
            &self.records.lock(),
            account_authority_id,
            account_id,
        ))
    }

    async fn resolve(
        &self,
        account_authority_id: &str,
        account_id: &str,
        from_status_seq: u64,
        limit: u16,
    ) -> PersistenceResult<Vec<AccountStatusRecord>> {
        Ok(self
            .records
            .lock()
            .range(
                (
                    account_authority_id.to_owned(),
                    account_id.to_owned(),
                    from_status_seq,
                )
                    ..=(
                        account_authority_id.to_owned(),
                        account_id.to_owned(),
                        u64::MAX,
                    ),
            )
            .take(usize::from(limit))
            .map(|(_, (record, _))| record.clone())
            .collect())
    }

    async fn erasure_pending(&self, limit: u16) -> PersistenceResult<Vec<AccountStatusRecord>> {
        Ok(self
            .records
            .lock()
            .values()
            .map(|(record, _)| record)
            .filter(|record| record.status == AccountStatus::ErasurePending)
            .take(usize::from(limit))
            .cloned()
            .collect())
    }

    async fn receipt(
        &self,
        account_authority_id: &str,
        account_id: &str,
        status_seq: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>> {
        Ok(self
            .records
            .lock()
            .get(&(
                account_authority_id.to_owned(),
                account_id.to_owned(),
                status_seq,
            ))
            .map(|(_, receipt)| receipt.clone()))
    }
}

fn replica_head(
    records: &BTreeMap<(String, String, u64), ReplicaHead>,
    authority: &str,
    account: &str,
) -> Option<ReplicaHead> {
    records
        .range(
            (authority.to_owned(), account.to_owned(), 0)
                ..=(authority.to_owned(), account.to_owned(), u64::MAX),
        )
        .next_back()
        .map(|(_, head)| head.clone())
}

fn current(
    records: &BTreeMap<(String, String, u64), ReplicaHead>,
    authority: &str,
    account: &str,
) -> Option<AccountStatusRecord> {
    replica_head(records, authority, account).map(|(record, _)| record)
}

/// Classifies an already transport- and proof-verified submission against the
/// durable replica head, which the account-status replica decision table
/// declares to be the only comparison baseline. Rows are evaluated top to
/// bottom and the first match wins. `None` means the submission is admitted and
/// the caller must perform the advancing write; every other outcome classifies
/// the submission with zero replica, receipt and outbox writes.
fn classify(
    record: &AccountStatusRecord,
    head: Option<&ReplicaHead>,
) -> Option<AccountStatusReplicaAppend> {
    let Some((head_record, head_receipt)) = head else {
        // genesis_gap: an absent head requires the genesis record first.
        if record.status_seq > 1 {
            return Some(AccountStatusReplicaAppend::DependencyMissing {
                current_record: None,
                required_status_seq: 1,
            });
        }
        // genesis_admission.
        return None;
    };
    // binding_version_rollback is evaluated before every sequence row so a
    // rolled-back binding can never be written by the advance branch.
    if record.binding_version < head_record.binding_version {
        return Some(conflict(
            head_record,
            AccountStatusReplicaConflictKind::BindingRollback,
        ));
    }
    if record.status_seq == head_record.status_seq + 1 {
        // fork_predecessor_mismatch, otherwise advance.
        if record.previous_account_status_record_id.as_ref()
            != Some(&head_record.account_status_record_id)
        {
            return Some(conflict(
                head_record,
                AccountStatusReplicaConflictKind::Fork,
            ));
        }
        return admission_conflict(record, head_record).map(|kind| conflict(head_record, kind));
    }
    if record.status_seq == head_record.status_seq {
        // duplicate is the terminal ack only when the head already is the
        // submitted record; a different record at the head sequence forks.
        return Some(
            if record.account_status_record_id == head_record.account_status_record_id {
                AccountStatusReplicaAppend::Duplicate(head_receipt.clone())
            } else {
                conflict(head_record, AccountStatusReplicaConflictKind::Fork)
            },
        );
    }
    if record.status_seq < head_record.status_seq {
        // stale is unconditional. How much history this receiver still retains
        // for the submitted sequence is a local retention decision and must not
        // turn a below-head submission into a duplicate.
        return Some(AccountStatusReplicaAppend::Stale {
            current_record: head_record.clone(),
        });
    }
    // sequence_gap.
    Some(AccountStatusReplicaAppend::DependencyMissing {
        current_record: Some(head_record.clone()),
        required_status_seq: head_record.status_seq + 1,
    })
}

fn conflict(
    head: &AccountStatusRecord,
    kind: AccountStatusReplicaConflictKind,
) -> AccountStatusReplicaAppend {
    AccountStatusReplicaAppend::Conflict {
        current_record: Some(head.clone()),
        kind,
    }
}

/// Admission guards that refine the `advance` row: the submission is the exact
/// successor of the head, and these checks reject a successor whose binding or
/// status transition the receiver must not durably record.
fn admission_conflict(
    record: &AccountStatusRecord,
    head: &AccountStatusRecord,
) -> Option<AccountStatusReplicaConflictKind> {
    if record.binding_version == head.binding_version
        && (record.principal_authority != head.principal_authority
            || record.principal_control_realm_id != head.principal_control_realm_id)
    {
        return Some(AccountStatusReplicaConflictKind::Fork);
    }
    if head.status == AccountStatus::ErasurePending {
        return Some(AccountStatusReplicaConflictKind::ErasurePendingTerminal);
    }
    (!head.status.can_transition_to(record.status))
        .then_some(AccountStatusReplicaConflictKind::TransitionInvalid)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::account_lifecycle::{
        AccountStatusPrincipalAuthority, UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
    };
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    use arkret_signatures::account_status::{
        sign_account_status_receipt, sign_account_status_record,
    };
    use arkret_wire::{DidCoreId, DidUrl, NonEmptyString, RealmId, ReceiptId, SchemaId};
    use ed25519_dalek::SigningKey;

    use super::*;

    fn record(
        seq: u64,
        previous: Option<arkret_wire::AccountStatusRecordId>,
        binding_version: u64,
        status: AccountStatus,
        issued_second: u8,
    ) -> AccountStatusRecord {
        sign_account_status_record(
            UnsignedAccountStatusRecord {
                schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
                account_authority_id: DidCoreId::new("ak:did_core:web:authority.example").unwrap(),
                account_id: NonEmptyString::new("account-1").unwrap(),
                principal_authority: AccountStatusPrincipalAuthority {
                    principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    principal_server_id: DidCoreId::new("ak:did_core:web:principal.example")
                        .unwrap(),
                },
                principal_control_realm_id: RealmId::new(
                    "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
                )
                .unwrap(),
                binding_version,
                status_seq: seq,
                previous_account_status_record_id: previous,
                status,
                reason_code: None,
                reason: None,
                issued_at: format!("2026-08-16T00:00:{issued_second:02}.000Z")
                    .parse()
                    .unwrap(),
                effective_at: format!("2026-08-16T00:00:{issued_second:02}.000Z")
                    .parse()
                    .unwrap(),
                expires_at: None,
                verification_method: DidUrl::new("did:web:authority.example#account-status-key")
                    .unwrap(),
            },
            &SigningKey::from_bytes(&[51; 32]),
        )
        .unwrap()
    }

    fn receipt(record: &AccountStatusRecord, suffix: u8) -> AccountStatusReceipt {
        sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new(format!(
                    "ak:receipt:01904100-0000-7000-8000-{suffix:012}"
                ))
                .unwrap(),
                account_status_record_id: record.account_status_record_id.clone(),
                record_digest: record.payload_digest().unwrap(),
                account_authority_id: record.account_authority_id.clone(),
                account_id: record.account_id.clone(),
                status_seq: record.status_seq,
                receiver_service_id: DidCoreId::new("ak:did_core:web:receiver.example").unwrap(),
                accepted_at: format!("2026-08-16T00:01:{suffix:02}.000Z")
                    .parse()
                    .unwrap(),
                verification_method: DidUrl::new("did:web:receiver.example#notary-key").unwrap(),
            },
            &SigningKey::from_bytes(&[53; 32]),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn replica_is_monotonic_and_returns_the_original_duplicate_receipt() {
        let store = MemoryAccountStatusReplicaStore::new();
        let genesis = record(1, None, 1, AccountStatus::Active, 1);
        let first_receipt = receipt(&genesis, 1);
        assert!(matches!(
            store.append(&genesis, &first_receipt).await.unwrap(),
            AccountStatusReplicaAppend::Accepted(_)
        ));

        let retry_receipt = receipt(&genesis, 2);
        let AccountStatusReplicaAppend::Duplicate(stored_receipt) =
            store.append(&genesis, &retry_receipt).await.unwrap()
        else {
            panic!("exact replay must be duplicate");
        };
        assert_eq!(stored_receipt, first_receipt);

        let gap = record(
            3,
            Some(genesis.account_status_record_id.clone()),
            1,
            AccountStatus::Suspended,
            3,
        );
        assert!(matches!(
            store.append(&gap, &receipt(&gap, 3)).await.unwrap(),
            AccountStatusReplicaAppend::DependencyMissing {
                required_status_seq: 2,
                ..
            }
        ));
        assert_eq!(
            store
                .current(
                    genesis.account_authority_id.as_str(),
                    genesis.account_id.as_str()
                )
                .await
                .unwrap()
                .unwrap()
                .account_status_record_id,
            genesis.account_status_record_id
        );

        let fork = record(1, None, 1, AccountStatus::Active, 4);
        assert!(matches!(
            store.append(&fork, &receipt(&fork, 4)).await.unwrap(),
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::Fork,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn replica_distinguishes_binding_rollback_and_terminal_successor() {
        let store = MemoryAccountStatusReplicaStore::new();
        let genesis = record(1, None, 2, AccountStatus::Active, 11);
        store
            .append(&genesis, &receipt(&genesis, 11))
            .await
            .unwrap();

        let rollback = record(
            2,
            Some(genesis.account_status_record_id.clone()),
            1,
            AccountStatus::Locked,
            12,
        );
        assert!(matches!(
            store
                .append(&rollback, &receipt(&rollback, 12))
                .await
                .unwrap(),
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::BindingRollback,
                ..
            }
        ));

        let erasure = record(
            2,
            Some(genesis.account_status_record_id.clone()),
            2,
            AccountStatus::ErasurePending,
            13,
        );
        store
            .append(&erasure, &receipt(&erasure, 13))
            .await
            .unwrap();
        let successor = record(
            3,
            Some(erasure.account_status_record_id.clone()),
            2,
            AccountStatus::Active,
            14,
        );
        assert!(matches!(
            store
                .append(&successor, &receipt(&successor, 14))
                .await
                .unwrap(),
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::ErasurePendingTerminal,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn replica_rejects_a_receipt_bound_to_another_record() {
        let store = MemoryAccountStatusReplicaStore::new();
        let genesis = record(1, None, 1, AccountStatus::Active, 21);
        let other = record(1, None, 1, AccountStatus::Active, 22);
        assert!(matches!(
            store.append(&genesis, &receipt(&other, 21)).await,
            Err(PersistenceError::SchemaViolation(_))
        ));
        assert!(
            store
                .current(
                    genesis.account_authority_id.as_str(),
                    genesis.account_id.as_str()
                )
                .await
                .unwrap()
                .is_none()
        );
    }
}
