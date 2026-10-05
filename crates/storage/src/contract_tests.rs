use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::account_status::{
    AccountStatusReceipt, AccountStatusRecord, UnsignedAccountStatusReceipt,
    UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::{
    OrganizationControlProofKind, OrganizationRegistrationChallenge,
    OrganizationRegistrationOutcome, OrganizationRegistrationReceipt,
    OrganizationRegistrationScope, OrganizationRegistrationStatus,
};
use arkret_wire::{
    AccountStatusRecordId, Did, DidCoreId, DidUrl, Hash, PayloadProof, ProofContextId, RealmId,
    ReceiptId, SchemaId, project_did_to_core_id,
};
use chrono::{Duration, Utc};

use super::{
    AccountLocalpartStore, AccountPk, AccountRecord, AccountStatusReplicaAppend,
    AccountStatusReplicaConflictKind, AccountStatusReplicaStore, AccountStore,
    AppletIdentityCommit, AppletRecordCommit, AppletStore, AuthorityCommitStore,
    AuthorityCommitTransaction, AuthorityCommitWriteOutcome, CanonicalEventRecord,
    ContactProjectionCommit, ContactRecord, ContactStore, CurrentRealmAuthority,
    DeviceInventoryStore, DeviceKeyStore, DeviceMessageBatchCommitOutcome,
    DeviceMessageBatchInspection, DeviceMessageBatchItemRecord, DeviceMessageBatchRecord,
    DeviceMessageIntentRecord, DeviceMessageRecord, DeviceMessageStore,
    DeviceMessageTargetSnapshotGuard, DeviceRevocationGateSelector, EventBatchCommitRequest,
    EventCommitRequest, EventCommitUnitOfWork, EventStore, FederationOutboxClaim,
    FederationOutboxDeadLetterRecord, FederationOutboxOutcome, FederationOutboxPolicyResolution,
    FederationOutboxRecord, FederationOutboxRequeue, FederationOutboxState, FederationOutboxStore,
    FederationOutboxTransition, HandleClaimEvidenceRecord, IdempotencyRecord, IdempotencyStore,
    InviteReceivePolicyStore, MemberIdentityStore, MessageRecord, MessageStore,
    MimiConsentCorrelationRecord, MimiConsentCorrelationStore, MlsKeyPackageClaim,
    MlsKeyPackageClaimTarget, MlsKeyPackageRow, MlsKeyPackageStore, OneTimeKeyStore,
    OrganizationRegistrationEnsureCommit, OrganizationRegistrationLifecycleCommit,
    OrganizationRegistrationRefreshCommit, OrganizationRegistrationStore,
    OrganizationRegistrationTerminalReason, PeerClaimTerminalTransition,
    PeerKeyPackageClaimAttempt, PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceError, ProjectionEventStore,
    RealmFanoutAuthorityWitness, RealmFanoutBinding, RealmFanoutOutboxInput, RealmMetaRecord,
    RealmMetaStore, applet_effective_scope_key,
};

/// Shared account-localpart removal semantics for every persistence adapter.
///
/// A mismatched Account cannot delete the owner's row and receives a conflict;
/// deleting an absent exact association remains idempotent.
pub async fn assert_account_localpart_remove_contract(
    accounts: &dyn AccountStore,
    localparts: &dyn AccountLocalpartStore,
    namespace: &str,
) {
    let station_id = DidCoreId::new("ak:did_core:web:soland.example").unwrap();
    let owner_pk = accounts
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: DidCoreId::new(format!(
                "ak:did_core:web:{namespace}-localpart-owner.example"
            ))
            .unwrap(),
            station_id: station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: database_timestamp_now(),
        })
        .await
        .expect("create localpart owner Account");
    let other_pk = accounts
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: DidCoreId::new(format!(
                "ak:did_core:web:{namespace}-localpart-other.example"
            ))
            .unwrap(),
            station_id,
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: database_timestamp_now(),
        })
        .await
        .expect("create other localpart Account");
    let localpart = format!("audit-{namespace}");
    localparts
        .add(owner_pk, &localpart, true)
        .await
        .expect("assign localpart to owner");

    let error = localparts
        .remove(other_pk, &localpart)
        .await
        .expect_err("wrong-owner removal must conflict");
    assert!(matches!(error, PersistenceError::Conflict(_)));
    assert_eq!(
        localparts
            .owner_of(&localpart)
            .await
            .expect("read localpart after wrong-owner removal")
            .map(|record| record.account_pk),
        Some(owner_pk),
        "wrong-owner removal must preserve the exact owner association"
    );

    localparts
        .remove(owner_pk, &localpart)
        .await
        .expect("owner removes exact association");
    assert!(
        localparts
            .owner_of(&localpart)
            .await
            .expect("read removed localpart")
            .is_none()
    );
    localparts
        .remove(owner_pk, &localpart)
        .await
        .expect("absent removal is idempotent");
}

pub async fn assert_device_message_snapshot_guard_contract(
    inventory: &dyn DeviceInventoryStore,
    messages: &dyn DeviceMessageStore,
    namespace: &str,
    authorization_a: &DeviceRevocationGateSelector,
    authorization_b: &DeviceRevocationGateSelector,
) {
    let now = database_timestamp_now();
    let actor = authorization_a.principal_id.to_string();
    assert_eq!(authorization_a.principal_id, authorization_b.principal_id);
    let device_a = authorization_a.device_id.clone();
    let device_b = authorization_b.device_id.clone();
    let snapshot = || async {
        inventory
            .list_for_actor(&actor)
            .await
            .unwrap()
            .into_iter()
            .filter(|d| d.verification_state == "verified" && d.revoked_at.is_none())
            .map(|d| (d.device_id, d.updated_at))
            .collect::<Vec<_>>()
    };
    // Moving the target's inventory row is what invalidates a snapshot; a
    // metadata refresh through the production write path moves it the same
    // way a revocation does, without fabricating a revocation.
    let touch_target = |at: chrono::DateTime<Utc>| {
        let record = crate::DeviceInventoryMetadata {
            actor: actor.clone(),
            device_id: device_b.clone(),
            display_name: None,
            last_seen_at: Some(at),
            last_key_upload_at: None,
            updated_at: at,
        };
        async move { inventory.put_metadata(&record).await }
    };
    let stale_snapshot = snapshot().await;
    let request_key = format!("repair:{namespace}");
    let request_digest = format!("sha256:{namespace}");
    let expires_at = now + Duration::days(1);
    let mut batch = DeviceMessageBatchRecord {
        request_key: request_key.clone(),
        request_digest: request_digest.clone(),
        idempotency_expires_at: expires_at,
        per_device_queue_capacity: 10_000,
        target_snapshot_guard: Some(DeviceMessageTargetSnapshotGuard {
            recipient: actor.clone(),
            devices: stale_snapshot,
        }),
        device_revocation_gate: Some(authorization_a.clone()),
        sender_agent_guard: None,
        items: [&device_a, &device_b]
            .into_iter()
            .enumerate()
            .map(|(index, device_id)| DeviceMessageBatchItemRecord {
                message_key: format!("{namespace}:message:{index}"),
                intent_digest: format!("{namespace}:intent:{index}"),
                idempotency_expires_at: expires_at,
                message: Some(DeviceMessageRecord {
                    idempotency_key: request_key.clone(),
                    sender: format!("{actor}:sender"),
                    recipient: actor.clone(),
                    device_id: device_id.clone(),
                    recipient_device_authorization: if index == 0 {
                        authorization_a.clone()
                    } else {
                        authorization_b.clone()
                    },
                    position: index as i64 + 1,
                    // The queue must retain an unacknowledged delivery even
                    // after the former one-hour expiry window has elapsed.
                    envelope: test_device_message_envelope(
                        authorization_a,
                        if index == 0 {
                            authorization_a
                        } else {
                            authorization_b
                        },
                        now - Duration::hours(2),
                    ),
                }),
            })
            .collect(),
    };

    touch_target(now + Duration::seconds(1))
        .await
        .expect("move the target device row");
    assert_eq!(
        messages
            .commit_batch(batch.clone())
            .await
            .expect("snapshot conflict outcome"),
        DeviceMessageBatchCommitOutcome::SnapshotConflict
    );
    assert!(
        messages
            .list_after(&actor, &device_a, 0, 101)
            .await
            .expect("device A queue")
            .is_empty(),
        "snapshot conflict must enqueue zero targets"
    );

    batch.target_snapshot_guard = Some(DeviceMessageTargetSnapshotGuard {
        recipient: actor.clone(),
        devices: snapshot().await,
    });
    let stored = messages
        .commit_batch(batch.clone())
        .await
        .expect("commit guarded batch");
    assert!(matches!(stored, DeviceMessageBatchCommitOutcome::Stored(_)));

    let mut full = batch.clone();
    full.request_key.push_str(":full");
    full.request_digest.push_str(":full");
    full.per_device_queue_capacity = 1;
    full.items.truncate(1);
    full.items[0].message_key.push_str(":full");
    full.items[0].intent_digest.push_str(":full");
    assert_eq!(
        messages
            .commit_batch(full.clone())
            .await
            .expect("capacity rejection"),
        DeviceMessageBatchCommitOutcome::QueueAtCapacity,
        "full recipient queue must reject a fresh message without evicting the old one"
    );
    let full_intent = full
        .items
        .iter()
        .map(|item| DeviceMessageIntentRecord {
            message_key: item.message_key.clone(),
            intent_digest: item.intent_digest.clone(),
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        messages
            .inspect_batch(&full.request_key, &full.request_digest, &full_intent)
            .await
            .expect("capacity rejection leaves no request/message idempotency record"),
        DeviceMessageBatchInspection::Fresh { .. }
    ));

    touch_target(now + Duration::seconds(2))
        .await
        .expect("move the target device row after durable commit");
    let replay = messages
        .commit_batch(batch.clone())
        .await
        .expect("exact replay");
    assert!(matches!(
        replay,
        DeviceMessageBatchCommitOutcome::Duplicate(_)
    ));
    let mut conflict = batch;
    conflict.request_digest.push_str("-different");
    assert_eq!(
        messages
            .commit_batch(conflict)
            .await
            .expect("digest conflict"),
        DeviceMessageBatchCommitOutcome::RequestConflict
    );
    assert_eq!(
        messages
            .list_after(&actor, &device_a, 0, 101)
            .await
            .expect("unacknowledged two-hour-old delivery remains readable")
            .len(),
        1
    );
}

/// Complete closed human-device `DeviceMessageEnvelope` for queue contract
/// fixtures. The sender and recipient come from real device authorization
/// selectors; `sent_at` is floored to the canonical millisecond wire value.
pub fn test_device_message_envelope(
    sender: &DeviceRevocationGateSelector,
    recipient: &DeviceRevocationGateSelector,
    sent_at: chrono::DateTime<Utc>,
) -> arkret_models_collaboration::device_messages::DeviceMessageEnvelope {
    use arkret_models_collaboration::device_messages::{
        DeviceMessageEnvelope, DeviceMessageSender,
    };
    let sent_at = arkret_canonical::normalize_timestamp_canonical(sent_at);
    DeviceMessageEnvelope {
        device_message_id: arkret_wire::DeviceMessageId::new(crate::ids::generate(
            "device_message",
        ))
        .expect("generated device message id"),
        kind: arkret_wire::ProtocolKind::new("ak.test.device_message")
            .expect("test device message kind"),
        sender: DeviceMessageSender::Account {
            sender_account_id: arkret_wire::AccountId::new(
                sender.principal_id.clone(),
                sender.station_id.clone(),
            ),
            sender_device_id: arkret_wire::DeviceId::new(sender.device_id.clone())
                .expect("sender selector carries a typed device id"),
        },
        recipient_account_id: arkret_wire::AccountId::new(
            recipient.principal_id.clone(),
            recipient.station_id.clone(),
        ),
        recipient_device_id: arkret_wire::DeviceId::new(recipient.device_id.clone())
            .expect("recipient selector carries a typed device id"),
        sent_at,
        expires_at: sent_at + Duration::hours(1),
        content: BTreeMap::new(),
        unsigned: None,
    }
}

fn database_timestamp_now() -> chrono::DateTime<Utc> {
    chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current timestamp is representable")
}

pub async fn assert_organization_registration_store_contract(
    store: &dyn OrganizationRegistrationStore,
    namespace: &str,
) {
    // Registration receipts serialize timestamps through the canonical
    // millisecond wire format, so a sub-millisecond `now` would compare
    // unequal after a durable JSON round-trip.
    let now = arkret_canonical::normalize_timestamp_canonical(database_timestamp_now());
    // `project_did_to_core_id` drops the domain — and the namespace hash
    // it carries — so the namespace must also reach the SCID slot, or a rerun
    // on the same database reads the previous run's state as its own.
    let organization_did = test_webvh_did(
        &format!("zOrg{}", &test_hash_hex(namespace)[..12]),
        namespace,
    );
    let organization_id = project_did_to_core_id(&organization_did)
        .expect("organization DID projects through the registered adapter");
    let first_admin = test_did_core_id("zAdmin", namespace);
    let second_admin = test_did_core_id("zAdminNext", namespace);
    let first_scopes = vec![OrganizationRegistrationScope::OrganizationProfileManage];
    let second_scopes = vec![
        OrganizationRegistrationScope::OrganizationProfileManage,
        OrganizationRegistrationScope::OrganizationRealmEndorse,
    ];

    let challenge_1 = registration_challenge(
        namespace,
        "ensure-1",
        &organization_id,
        &organization_did,
        &first_admin,
        &first_scopes,
        now,
    );
    store
        .prepare_challenge(challenge_1.clone())
        .await
        .expect("prepare first challenge");
    assert!(
        store.prepare_challenge(challenge_1.clone()).await.is_err(),
        "prepare is intentionally non-idempotent"
    );
    let digest_1 = test_hash(&format!("{namespace}:request:ensure-1"));
    let first_outcome = registration_outcome(
        &organization_id,
        &organization_did,
        &first_admin,
        &first_scopes,
        1,
        OrganizationRegistrationStatus::Active,
        "version-1",
        now + Duration::seconds(1),
        true,
    );
    let created = store
        .ensure(OrganizationRegistrationEnsureCommit {
            challenge_id: challenge_1.challenge_id.clone(),
            canonical_request_digest: digest_1.clone(),
            expected_current_generation: None,
            new_outcome: Some(first_outcome.clone()),
            committed_at: now + Duration::seconds(1),
        })
        .await
        .expect("create first generation");
    assert!(created.created);
    assert_eq!(created, first_outcome);

    let replay = store
        .ensure(OrganizationRegistrationEnsureCommit {
            challenge_id: challenge_1.challenge_id.clone(),
            canonical_request_digest: digest_1.clone(),
            expected_current_generation: Some(999),
            new_outcome: None,
            committed_at: now + Duration::seconds(2),
        })
        .await
        .expect("exact digest replay returns committed outcome");
    assert!(!replay.created);
    assert_eq!(
        replay.registration_receipt,
        first_outcome.registration_receipt
    );
    assert!(
        store
            .ensure(OrganizationRegistrationEnsureCommit {
                challenge_id: challenge_1.challenge_id.clone(),
                canonical_request_digest: test_hash(&format!(
                    "{namespace}:request:ensure-1-competing"
                )),
                expected_current_generation: Some(1),
                new_outcome: None,
                committed_at: now + Duration::seconds(2),
            })
            .await
            .is_err(),
        "a consumed challenge rejects a different canonical digest"
    );

    let challenge_unchanged = registration_challenge(
        namespace,
        "ensure-unchanged",
        &organization_id,
        &organization_did,
        &first_admin,
        &first_scopes,
        now + Duration::seconds(3),
    );
    store
        .prepare_challenge(challenge_unchanged.clone())
        .await
        .expect("prepare unchanged-delegation challenge");
    let unchanged = store
        .ensure(OrganizationRegistrationEnsureCommit {
            challenge_id: challenge_unchanged.challenge_id.clone(),
            canonical_request_digest: test_hash(&format!("{namespace}:request:ensure-unchanged")),
            expected_current_generation: Some(1),
            new_outcome: None,
            committed_at: now + Duration::seconds(4),
        })
        .await
        .expect("unchanged active delegation reuses current receipt");
    assert!(!unchanged.created);
    assert_eq!(
        unchanged.registration_receipt,
        first_outcome.registration_receipt
    );

    let challenge_2 = registration_challenge(
        namespace,
        "ensure-2",
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        now + Duration::seconds(5),
    );
    store
        .prepare_challenge(challenge_2.clone())
        .await
        .expect("prepare replacement challenge");
    let second_outcome = registration_outcome(
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        2,
        OrganizationRegistrationStatus::Active,
        "version-2",
        now + Duration::seconds(6),
        true,
    );
    let ensure_2_digest = test_hash(&format!("{namespace}:request:ensure-2"));
    assert!(
        store
            .ensure(OrganizationRegistrationEnsureCommit {
                challenge_id: challenge_2.challenge_id.clone(),
                canonical_request_digest: ensure_2_digest.clone(),
                expected_current_generation: Some(0),
                new_outcome: Some(second_outcome.clone()),
                committed_at: now + Duration::seconds(6),
            })
            .await
            .is_err(),
        "generation replacement is CAS protected"
    );
    assert!(
        store
            .get_challenge(&challenge_2.challenge_id)
            .await
            .expect("read challenge after failed CAS")
            .expect("replacement challenge exists")
            .consumed_request_digest
            .is_none(),
        "failed transaction must not consume the challenge"
    );
    store
        .ensure(OrganizationRegistrationEnsureCommit {
            challenge_id: challenge_2.challenge_id.clone(),
            canonical_request_digest: ensure_2_digest,
            expected_current_generation: Some(1),
            new_outcome: Some(second_outcome.clone()),
            committed_at: now + Duration::seconds(6),
        })
        .await
        .expect("atomically supersede first generation");
    let generation_1 = store
        .get_generation(&organization_id, 1)
        .await
        .expect("read superseded generation")
        .expect("first generation exists");
    assert_eq!(generation_1.status, OrganizationRegistrationStatus::Revoked);
    assert_eq!(
        generation_1.terminal_reason,
        Some(OrganizationRegistrationTerminalReason::OrganizationRegistrationSuperseded)
    );
    let current = store
        .get_current(&organization_id)
        .await
        .expect("read second generation")
        .expect("registration exists");
    assert_eq!(current.generation.registration_generation, 2);
    assert_eq!(
        current.generation.status,
        OrganizationRegistrationStatus::Active
    );
    assert_eq!(
        store
            .get_outcome(&first_outcome.registration_receipt.registration_receipt_id)
            .await
            .expect("read immutable historical outcome"),
        Some(first_outcome.clone()),
        "superseding a generation must not rewrite its signed outcome"
    );
    let historical_replay = store
        .ensure(OrganizationRegistrationEnsureCommit {
            challenge_id: challenge_1.challenge_id.clone(),
            canonical_request_digest: digest_1,
            expected_current_generation: Some(2),
            new_outcome: None,
            committed_at: now + Duration::seconds(7),
        })
        .await
        .expect("historical exact replay remains available");
    assert!(!historical_replay.created);
    assert_eq!(
        historical_replay.registration_receipt,
        first_outcome.registration_receipt
    );

    let second_outcome_id = second_outcome
        .registration_receipt
        .registration_receipt_id
        .clone();
    assert!(
        store
            .mark_stale(
                &organization_id,
                2,
                "ak:organization_registration_receipt:wrong",
                now + Duration::seconds(8),
            )
            .await
            .is_err(),
        "stale transition is current-pointer CAS protected"
    );
    let stale = store
        .mark_stale(
            &organization_id,
            2,
            &second_outcome_id,
            now + Duration::seconds(8),
        )
        .await
        .expect("mark current registration stale");
    assert_eq!(
        stale.generation.status,
        OrganizationRegistrationStatus::Stale
    );

    let refresh_challenge = registration_challenge(
        namespace,
        "refresh-2",
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        now + Duration::seconds(9),
    );
    store
        .prepare_challenge(refresh_challenge.clone())
        .await
        .expect("prepare refresh challenge");
    let refreshed_outcome = registration_outcome(
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        2,
        OrganizationRegistrationStatus::Active,
        "version-2-refresh",
        now + Duration::seconds(10),
        false,
    );
    store
        .refresh(OrganizationRegistrationRefreshCommit {
            challenge_id: refresh_challenge.challenge_id.clone(),
            canonical_request_digest: test_hash(&format!("{namespace}:request:refresh-2")),
            expected_current_generation: 2,
            expected_current_outcome_id: second_outcome_id,
            outcome: refreshed_outcome.clone(),
            committed_at: now + Duration::seconds(10),
        })
        .await
        .expect("refresh stays in the current generation");
    let refreshed = store
        .get_current(&organization_id)
        .await
        .expect("read refreshed generation")
        .expect("registration exists");
    assert_eq!(refreshed.generation.registration_generation, 2);
    assert_eq!(
        refreshed.generation.status,
        OrganizationRegistrationStatus::Active
    );

    let refreshed_outcome_id = refreshed_outcome
        .registration_receipt
        .registration_receipt_id
        .clone();
    let revoked_outcome = registration_outcome(
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        2,
        OrganizationRegistrationStatus::Revoked,
        "version-2-revoked",
        now + Duration::seconds(11),
        false,
    );
    store
        .revoke(OrganizationRegistrationLifecycleCommit {
            organization_id: organization_id.clone(),
            expected_current_generation: 2,
            expected_current_outcome_id: refreshed_outcome_id,
            outcome: revoked_outcome.clone(),
            reason: OrganizationRegistrationTerminalReason::OrganizationRegistrationWithdrawn,
            committed_at: now + Duration::seconds(11),
        })
        .await
        .expect("revoke current generation");
    let revoked = store
        .get_current(&organization_id)
        .await
        .expect("read revoked generation")
        .expect("registration exists");
    assert_eq!(
        revoked.generation.status,
        OrganizationRegistrationStatus::Revoked
    );
    assert_eq!(
        revoked.generation.terminal_reason,
        Some(OrganizationRegistrationTerminalReason::OrganizationRegistrationWithdrawn)
    );

    let terminal_refresh_challenge = registration_challenge(
        namespace,
        "refresh-revoked",
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        now + Duration::seconds(12),
    );
    store
        .prepare_challenge(terminal_refresh_challenge.clone())
        .await
        .expect("prepare terminal refresh challenge");
    let impossible_refresh = registration_outcome(
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        2,
        OrganizationRegistrationStatus::Active,
        "version-2-impossible-refresh",
        now + Duration::seconds(13),
        false,
    );
    assert!(
        store
            .refresh(OrganizationRegistrationRefreshCommit {
                challenge_id: terminal_refresh_challenge.challenge_id.clone(),
                canonical_request_digest: test_hash(&format!(
                    "{namespace}:request:refresh-revoked"
                )),
                expected_current_generation: 2,
                expected_current_outcome_id: revoked_outcome
                    .registration_receipt
                    .registration_receipt_id
                    .clone(),
                outcome: impossible_refresh,
                committed_at: now + Duration::seconds(13),
            })
            .await
            .is_err(),
        "revoked is terminal for same-generation refresh"
    );
    assert!(
        store
            .get_challenge(&terminal_refresh_challenge.challenge_id)
            .await
            .expect("read rejected refresh challenge")
            .expect("refresh challenge exists")
            .consumed_request_digest
            .is_none()
    );

    let challenge_3 = registration_challenge(
        namespace,
        "ensure-3",
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        now + Duration::seconds(14),
    );
    store
        .prepare_challenge(challenge_3.clone())
        .await
        .expect("prepare post-revocation generation");
    let third_outcome = registration_outcome(
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        3,
        OrganizationRegistrationStatus::Active,
        "version-3",
        now + Duration::seconds(15),
        true,
    );
    store
        .ensure(OrganizationRegistrationEnsureCommit {
            challenge_id: challenge_3.challenge_id,
            canonical_request_digest: test_hash(&format!("{namespace}:request:ensure-3")),
            expected_current_generation: Some(2),
            new_outcome: Some(third_outcome.clone()),
            committed_at: now + Duration::seconds(15),
        })
        .await
        .expect("revocation opens the next generation");
    let deactivated_outcome = registration_outcome(
        &organization_id,
        &organization_did,
        &second_admin,
        &second_scopes,
        3,
        OrganizationRegistrationStatus::Revoked,
        "version-3-deactivated",
        now + Duration::seconds(16),
        false,
    );
    assert!(
        store
            .deactivate(OrganizationRegistrationLifecycleCommit {
                organization_id: organization_id.clone(),
                expected_current_generation: 3,
                expected_current_outcome_id: "ak:organization_registration_receipt:wrong"
                    .to_owned(),
                outcome: deactivated_outcome.clone(),
                reason: OrganizationRegistrationTerminalReason::ExternalDidDeactivated,
                committed_at: now + Duration::seconds(16),
            })
            .await
            .is_err(),
        "DID deactivation is current-pointer CAS protected"
    );
    assert_eq!(
        store
            .get_current(&organization_id)
            .await
            .expect("read registration after failed deactivation")
            .expect("registration exists")
            .generation
            .status,
        OrganizationRegistrationStatus::Active,
        "failed deactivation must leave the active generation intact"
    );
    store
        .deactivate(OrganizationRegistrationLifecycleCommit {
            organization_id: organization_id.clone(),
            expected_current_generation: 3,
            expected_current_outcome_id: third_outcome.registration_receipt.registration_receipt_id,
            outcome: deactivated_outcome,
            reason: OrganizationRegistrationTerminalReason::ExternalDidDeactivated,
            committed_at: now + Duration::seconds(16),
        })
        .await
        .expect("DID deactivation forces terminal revocation");
    let deactivated = store
        .get_current(&organization_id)
        .await
        .expect("read deactivated registration")
        .expect("registration exists");
    assert_eq!(
        deactivated.generation.status,
        OrganizationRegistrationStatus::Revoked
    );
    assert_eq!(
        deactivated.generation.terminal_reason,
        Some(OrganizationRegistrationTerminalReason::ExternalDidDeactivated)
    );
}

fn test_hash(seed: &str) -> Hash {
    Hash::new(
        arkret_canonical::canonical::canonical_sha256(&seed)
            .expect("contract test seed is canonicalizable"),
    )
    .expect("canonical sha256 is a valid hash")
}

fn test_hash_hex(seed: &str) -> String {
    test_hash(seed)
        .as_str()
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_owned()
}

fn test_webvh_did(label: &str, namespace: &str) -> Did {
    Did::new(format!(
        "did:webvh:{label}:{}.example",
        &test_hash_hex(namespace)[..20]
    ))
    .expect("contract test DID is valid")
}

fn test_did_core_id(label: &str, namespace: &str) -> DidCoreId {
    project_did_to_core_id(&test_webvh_did(label, namespace))
        .expect("contract test DID projects to a core id")
}

fn registration_challenge(
    namespace: &str,
    label: &str,
    organization_id: &DidCoreId,
    organization_did: &Did,
    local_admin_subject_id: &DidCoreId,
    scopes: &[OrganizationRegistrationScope],
    created_at: chrono::DateTime<Utc>,
) -> OrganizationRegistrationChallenge {
    let challenge_hash = test_hash_hex(&format!("{namespace}:challenge:{label}"));
    OrganizationRegistrationChallenge {
        challenge_id: format!("ak:organization_registration_challenge:{challenge_hash}"),
        organization_id: organization_id.clone(),
        organization_did: organization_did.clone(),
        purpose: ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1.to_owned(),
        nonce: challenge_hash[..32].to_owned(),
        audience_id: DidCoreId::new("ak:did_core:webvh:zService").expect("valid service core id"),
        origin: arkret_wire::WebOrigin::new("https://service.example")
            .expect("valid service origin"),
        trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:service.example")
            .expect("valid service trust domain"),
        local_admin_subject_id: local_admin_subject_id.clone(),
        requested_scopes: scopes.to_vec(),
        expires_at: created_at + Duration::seconds(300),
        created_at,
    }
}

#[allow(clippy::too_many_arguments)]
fn registration_outcome(
    organization_id: &DidCoreId,
    organization_did: &Did,
    local_admin_subject_id: &DidCoreId,
    scopes: &[OrganizationRegistrationScope],
    generation: u64,
    status: OrganizationRegistrationStatus,
    version_id: &str,
    issued_at: chrono::DateTime<Utc>,
    created: bool,
) -> OrganizationRegistrationOutcome {
    let issuer = DidCoreId::new("ak:did_core:webvh:zService").expect("valid service core id");
    let issuer_did = Did::new("did:webvh:zService:service.example").expect("valid service DID");
    let mut receipt = OrganizationRegistrationReceipt {
        registration_receipt_id: "ak:organization_registration_receipt:placeholder".to_owned(),
        organization_id: organization_id.clone(),
        organization_did: organization_did.clone(),
        registration_generation: generation,
        version_id: version_id.to_owned(),
        log_head_digest: test_hash(&format!(
            "{}:{generation}:{version_id}:log-head",
            organization_id.as_str()
        )),
        control_proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
        control_key_digest: test_hash(&format!(
            "{}:{generation}:{version_id}:control-key",
            organization_id.as_str()
        )),
        local_admin_subject_id: local_admin_subject_id.clone(),
        delegated_scopes: scopes.to_vec(),
        status,
        issued_at,
        expires_at: issued_at + Duration::days(30),
        issuer_id: issuer.clone(),
        proof: PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!("{issuer_did}#registry-key-1"))
                .expect("registry verification method is a DID URL"),
            payload_digest: test_hash("placeholder-payload"),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..contract-fixture".to_owned(),
        },
    };
    receipt.registration_receipt_id = receipt
        .expected_receipt_id()
        .expect("derive registration receipt id");
    receipt.proof.payload_digest = receipt
        .expected_payload_digest()
        .expect("derive registration receipt digest");
    let outcome = OrganizationRegistrationOutcome {
        registration_receipt: receipt,
        created,
    };
    outcome.validate().expect("contract outcome is valid");
    outcome
}

pub async fn assert_idempotency_store_contract(store: &dyn IdempotencyStore, namespace: &str) {
    let now = database_timestamp_now();
    let principal_id = DidCoreId::new(format!("ak:did_core:web:{namespace}.example"))
        .expect("idempotency principal id");
    let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id.clone(),
        DidCoreId::new(format!("ak:did_core:web:{namespace}-station.example")).unwrap(),
    ));
    let operation_id = "arkret://operations/contract/idempotency".to_owned();
    let idempotency_key = format!("idempotency:{namespace}");
    let first = IdempotencyRecord {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.clone(),
        request_hash: "sha256:first".to_owned(),
        response_status: 200,
        response_body: serde_json::json!({"accepted": true}),
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    store.record(&first).await.expect("record first response");
    assert_eq!(
        store
            .get(&authenticated_actor, &operation_id, &idempotency_key)
            .await
            .expect("read first response"),
        Some(first.clone())
    );

    let mut competing = first.clone();
    competing.request_hash = "sha256:competing".to_owned();
    competing.response_status = 409;
    store
        .record(&competing)
        .await
        .expect("record competing response");
    assert_eq!(
        store
            .get(&authenticated_actor, &operation_id, &idempotency_key)
            .await
            .expect("read first-writer response"),
        Some(first.clone()),
        "the first response must win a duplicate-key race"
    );

    let other_station_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id.clone(),
        DidCoreId::new(format!("ak:did_core:web:{namespace}-other-station.example")).unwrap(),
    ));
    let mut other_station = first.clone();
    other_station.authenticated_actor = other_station_actor.clone();
    other_station.response_body = serde_json::json!({"station": "other"});
    store
        .record(&other_station)
        .await
        .expect("record other Station");
    assert_eq!(
        store
            .get(&other_station_actor, &operation_id, &idempotency_key)
            .await
            .expect("read other Station"),
        Some(other_station),
        "the same principal and key at another Station is an independent scope"
    );

    let other_operation_id = "arkret://operations/contract/idempotency-other";
    let mut other_operation = first.clone();
    other_operation.operation_id = other_operation_id.to_owned();
    other_operation.response_body = serde_json::json!({"operation": "other"});
    store
        .record(&other_operation)
        .await
        .expect("record other operation");
    assert_eq!(
        store
            .get(&authenticated_actor, other_operation_id, &idempotency_key)
            .await
            .expect("read other operation"),
        Some(other_operation),
        "the same actor and key in another operation is an independent scope"
    );

    let reservation_key = format!("idempotency-reservation:{namespace}");
    let reservation = IdempotencyRecord {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: operation_id.clone(),
        idempotency_key: reservation_key.clone(),
        request_hash: "sha256:reserved".to_owned(),
        response_status: 102,
        response_body: serde_json::json!({"reservation_id": namespace}),
        created_at: now,
        expires_at: now + Duration::minutes(1),
    };
    store
        .record(&reservation)
        .await
        .expect("record first-writer reservation");
    let mut completed = reservation.clone();
    completed.response_status = 200;
    completed.response_body = serde_json::json!({"accepted": true});
    completed.expires_at = now + Duration::hours(1);
    let mut competing_reservation = reservation.clone();
    competing_reservation.response_body = serde_json::json!({"reservation_id": "competitor"});
    assert!(
        !store
            .complete_reservation(&competing_reservation, &completed)
            .await
            .expect("reject competing reservation completion"),
        "a worker that does not own the exact reservation must not complete it"
    );
    assert!(
        store
            .complete_reservation(&reservation, &completed)
            .await
            .expect("complete owned reservation"),
        "the exact reservation owner must atomically publish its terminal response"
    );
    assert_eq!(
        store
            .get(&authenticated_actor, &operation_id, &reservation_key)
            .await
            .expect("read completed reservation"),
        Some(completed),
        "reservation completion must replace the pending row exactly once"
    );
}

pub async fn assert_mimi_consent_correlation_store_contract(
    store: &dyn MimiConsentCorrelationStore,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let consent_id = format!("ak:consent:{namespace}");
    let first = MimiConsentCorrelationRecord {
        consent_id: consent_id.clone(),
        requester_actor_id: format!(
            "{{\"account_id\":{{\"principal_id\":\"ak:did_core:web:{namespace}-requester.example\",\"station_id\":\"ak:did_core:web:{namespace}-requester-station.example\"}},\"kind\":\"account\"}}"
        ),
        holder_account_id: format!(
            "{{\"principal_id\":\"ak:did_core:web:{namespace}-holder.example\",\"station_id\":\"ak:did_core:web:{namespace}-holder-station.example\"}}"
        ),
        purpose: "voice_call".to_owned(),
        strand_id: None,
        source_id: Some(format!("ak:did_core:web:{namespace}-provider.example")),
        created_at: now,
        expires_at: Some(now + Duration::hours(1)),
    };
    store.put(&first).await.expect("record MIMI correlation");
    assert_eq!(
        store.get(&consent_id).await.expect("read MIMI correlation"),
        Some(first.clone())
    );

    let mut competing = first.clone();
    competing.holder_account_id = format!(
        "{{\"principal_id\":\"ak:did_core:web:{namespace}-holder.example\",\"station_id\":\"ak:did_core:web:{namespace}-other-station.example\"}}"
    );
    store
        .put(&competing)
        .await
        .expect("record competing MIMI correlation");
    assert_eq!(
        store
            .get(&consent_id)
            .await
            .expect("read first-writer MIMI correlation"),
        Some(first),
        "the first private correlation must win a duplicate-id race"
    );
}

pub struct EventCommitContractStores<'a> {
    pub unit_of_work: &'a dyn EventCommitUnitOfWork,
    pub authority: &'a dyn AuthorityCommitStore,
    pub events: &'a dyn EventStore,
    pub projections: &'a dyn ProjectionEventStore,
    pub idempotency: &'a dyn IdempotencyStore,
    pub outbox: &'a dyn FederationOutboxStore,
    pub contacts: &'a dyn ContactStore,
    pub invite_policies: &'a dyn InviteReceivePolicyStore,
}

fn contract_realm_id(seed: &str) -> String {
    let digest = arkret_canonical::sha256_bytes(seed.as_bytes());
    let event_id =
        arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest);
    arkret_identifiers::RealmId::from_event_id(&event_id).to_string()
}

/// The genesis authority a contract Realm commits under.
///
/// A Realm id retypes the 33-byte token of the Event that created the Realm,
/// so the genesis authority reference is recoverable from the Realm id alone
/// and no fixture has to carry the same seed twice.
fn contract_genesis_authority(realm_id: &arkret_identifiers::RealmId) -> CurrentRealmAuthority {
    let genesis_event_ref = arkret_identifiers::EventIdentityKey::new(
        realm_id.digest_suite_code(),
        realm_id.digest_bytes(),
    )
    .event_id();
    CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: DidCoreId::new("ak:did_core:web:station.example")
            .expect("contract authority service id"),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis_event_ref,
        ),
        last_handoff_ref: None,
    }
}

/// The current Station's detached signature over a contract `RealmCommit`.
///
/// The adapter authenticates the signer by projecting the verification
/// method's controller to a service id, so the method has to name the same
/// service the genesis authority carries.
fn contract_authority_signature(
    created_at: chrono::DateTime<Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new("did:web:station.example#authority")
            .expect("contract authority verification method"),
        signed_digest: Hash::new(format!("sha256:{}", "3".repeat(64)))
            .expect("contract authority signed digest"),
        created_at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned())
            .expect("contract authority signature bytes"),
    }
}

/// One independent commit stream a contract drives.
///
/// A `RealmCommit` orders exactly one Event, so a contract that commits
/// several Events into one Realm owes a chained sequence: consecutive
/// `stream_position`s and a `previous_commit_ref` naming the current stream
/// head. Attempts the contract expects the adapter to roll back never advance
/// that head, so the next accepted Event reuses the position they claimed.
struct ContractCommitStream {
    authority: CurrentRealmAuthority,
    next_position: u64,
    previous_commit_ref: Option<arkret_wire::RealmCommitId>,
}

impl ContractCommitStream {
    fn new(realm_id: &str) -> Self {
        let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned())
            .expect("contract stream Realm id");
        Self {
            authority: contract_genesis_authority(&realm_id),
            next_position: 0,
            previous_commit_ref: None,
        }
    }

    /// Install the Realm's genesis authority. The adapter refuses to order an
    /// Event for a Realm whose current authority it cannot read, and
    /// installing the same genesis decision twice is the same decision.
    async fn install(&self, store: &dyn AuthorityCommitStore) {
        store
            .install_genesis_authority(&self.authority)
            .await
            .expect("install contract genesis authority");
    }

    /// Order `record` at the current stream head without advancing it, for an
    /// attempt the contract expects the adapter to reject or roll back.
    fn order(&self, record: &CanonicalEventRecord) -> AuthorityCommitTransaction {
        let event: arkret_wire::Event = serde_json::from_value(record.envelope.clone())
            .expect("contract canonical record carries its wire Event");
        let stream_ref = arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .expect("contract Event scope names one commit stream");
        let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("{}:{}", event.event_id, self.next_position).as_bytes(),
        ));
        AuthorityCommitTransaction {
            expected_authority: self.authority.clone(),
            commit: arkret_wire::RealmCommit {
                commit_id,
                realm_id: event.realm_id.clone(),
                stream_ref,
                stream_position: self.next_position,
                previous_commit_ref: self.previous_commit_ref.clone(),
                event_ref: event.event_id.clone(),
                governance_generation: self.authority.generation,
                authority_ref: self.authority.authority_ref.clone(),
                committed_at: record.received_at,
                signature: contract_authority_signature(record.received_at),
            },
            event,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        }
    }

    /// Order `record` and advance the stream head, for an attempt the contract
    /// expects the adapter to accept.
    fn accept(&mut self, record: &CanonicalEventRecord) -> AuthorityCommitTransaction {
        let transaction = self.order(record);
        self.next_position += 1;
        self.previous_commit_ref = Some(transaction.commit.commit_id.clone());
        transaction
    }
}

fn canonical_wire_event_record(
    event_kind: &str,
    actor_id: &str,
    realm_id: &str,
    sequence: u64,
    now: chrono::DateTime<Utc>,
) -> CanonicalEventRecord {
    let event_kind = if event_kind.is_empty() {
        arkret_wire::EventKind::MessageCreate.as_str()
    } else {
        event_kind
    };
    let actor_id =
        arkret_identifiers::DidCoreId::new(actor_id.to_owned()).expect("contract actor core id");
    let scope_ref = if event_kind == arkret_wire::EventKind::RealmCreate.as_str() {
        arkret_wire::ScopeRef::RealmGenesis
    } else {
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .expect("contract realm id"),
        }
    };
    // An Event id is derived from the Event's own bytes, so the fixture folds
    // its position in the contract's sequence into the payload: two Events
    // that differed in nothing else would otherwise share one id.
    let mut event = arkret_wire::test_support::raw_event_at(
        event_kind,
        scope_ref,
        actor_id.clone(),
        actor_id.clone(),
        serde_json::json!({"body": "contract", "sequence": sequence}),
        now,
    )
    .expect("contract wire event");
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .expect("contract event digest");
    // Every admitted Event carries exactly one producer proof. This fixture's
    // case is the storage boundary and not signature verification, so it
    // carries the structural-only detached JWS bound to these exact bytes.
    let event_digest = Hash::new(canonical_digest.clone()).expect("contract event digest hash");
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new(format!(
            "did:{}#contract-device",
            actor_id
                .as_str()
                .strip_prefix("ak:did_core:")
                .expect("contract actor core id carries the projected prefix")
        ))
        .expect("contract producer verification method"),
        event_digest: event_digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(now),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
    });
    let envelope = serde_json::to_value(&event).expect("contract wire event encodes");
    let decoded: arkret_wire::Event =
        serde_json::from_value(envelope.clone()).expect("contract Event decodes");
    assert_eq!(
        event.realm_id, decoded.realm_id,
        "wire Realm identity must round-trip"
    );
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &event.digest_payload().expect("contract digest payload"),
    )
    .expect("contract canonical bytes");
    CanonicalEventRecord {
        event_id: event.event_id.as_str().to_owned(),
        actor_id: event.actor_id.to_string(),
        realm_id: Some(event.realm_id.to_string()),
        kind: event_kind.to_owned(),
        schema_id: arkret_wire::EventKind::try_new(event_kind)
            .and_then(|kind| kind.descriptor())
            .and_then(|descriptor| descriptor.payload_schema_ref)
            .unwrap_or(arkret_wire::SchemaId::EVENT_PAYLOAD_V1)
            .to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: now,
    }
}

pub struct AppletFormalCommitContractStores<'a> {
    pub unit_of_work: &'a dyn EventCommitUnitOfWork,
    pub authority: &'a dyn AuthorityCommitStore,
    pub events: &'a dyn EventStore,
    pub applets: &'a dyn AppletStore,
}

fn contract_applet_id() -> arkret_wire::AppletId {
    arkret_wire::AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7()))
        .expect("contract Applet id")
}

fn contract_applet_record(
    applet_id: &arkret_wire::AppletId,
    install_marker: &str,
    ghosts: Vec<serde_json::Value>,
) -> serde_json::Value {
    let effective_scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(contract_realm_id("applet-install"))
            .expect("contract Applet Realm id"),
    };
    contract_applet_record_for_scope(applet_id, install_marker, effective_scope, ghosts)
}

fn contract_applet_record_for_scope(
    applet_id: &arkret_wire::AppletId,
    install_marker: &str,
    effective_scope: arkret_wire::ScopeRef,
    ghosts: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "applet_id": applet_id,
        "owner_actor_id": "ak:did_core:webvh:z6mkcontractowner",
        "effective_scope": effective_scope,
        "package": {"namespaces": {}},
        "status": "installed",
        "revoked_at": null,
        "install_body_digest": format!("sha256:{install_marker:0>64}"),
        "ghosts": ghosts,
    })
}

fn contract_applet_identity(applet_id: &arkret_wire::AppletId) -> serde_json::Value {
    let bot_suffix = applet_id
        .as_str()
        .strip_prefix("ak:applet:")
        .expect("typed Applet id has its registered prefix");
    serde_json::json!({
        "applet_id": applet_id,
        "bot_actor_id": contract_applet_actor(&format!("ak:did_core:web:bot-{bot_suffix}.example"))
    })
}

fn contract_applet_actor(principal_id: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal_id).expect("contract managed principal"),
        arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkcontractservice")
            .expect("contract Station"),
    ))
}

fn contract_applet_scope_key() -> String {
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(contract_realm_id("applet-install"))
            .expect("contract Applet Realm id"),
    };
    applet_effective_scope_key(&scope).expect("contract Applet effective scope key")
}

fn contract_ghost(
    ghost_actor_id: &str,
    protocol: &str,
    instance_id: &str,
    external_id: &str,
    request_marker: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ghost_actor_id": contract_applet_actor(ghost_actor_id),
        "managed_actor_provision_ref": "ak:event:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH",
        "principal_control_realm_id": "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH",
        "external_ref": {
            "protocol": protocol,
            "instance_id": instance_id,
            "external_id": external_id,
        },
        "display_name": null,
        "request_digest": format!("sha256:{request_marker:0>64}"),
        "profile_event_ref": "ak:event:AcP3yA5jKnY2j6Rjdt6KNHMLT9DtEnVBnszNpKxeX2gR",
        "accountability_grant_ref": "ak:event:AbAWwWC3ekOt5NnmX-QlGu2wvU1BPQmDeeubWjrKwye0",
        "authorization_ref": "ak:grant:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
        "created_at": "2026-08-25T00:00:00.000Z",
    })
}

fn contract_applet_event_request(
    stream: &mut ContractCommitStream,
    event: CanonicalEventRecord,
) -> EventCommitRequest {
    EventCommitRequest {
        authority_commit: stream.accept(&event),
        self_producer_guard: None,
        applet_producer_guard: None,
        widget_token_gate: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        parent_membership_admission: None,
        contact_projection: None,

        event,
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: Vec::new(),
        idempotency: None,
        outbox: Vec::new(),
        realm_fanout_source: None,
    }
}

/// One Applet authority Event group, ordered on its own commit stream.
///
/// A batch is all-or-nothing, so every group gets its own Realm: a group the
/// adapter rolls back leaves that stream empty and the retry of the same batch
/// replays the same chained positions, while two groups racing for one Applet
/// record never contend for a stream position and therefore fail on the Applet
/// compare-and-set the contract is actually asserting.
async fn contract_applet_event_group(
    authority: &dyn AuthorityCommitStore,
    namespace: &str,
    realm_seed: &str,
    group: &str,
    count: u64,
) -> Vec<EventCommitRequest> {
    let actor_id = format!("ak:did_core:web:{namespace}-{group}.example");
    let now = database_timestamp_now();
    let mut stream =
        ContractCommitStream::new(&contract_realm_id(&format!("{realm_seed}:{group}")));
    stream.install(authority).await;
    let realm_id = stream.authority.realm_id.to_string();
    let mut requests = Vec::new();
    for sequence in 0..count {
        let event = canonical_wire_event_record(
            arkret_wire::EventKind::AppletRegistration.as_str(),
            &actor_id,
            &realm_id,
            sequence,
            now + chrono::Duration::milliseconds(sequence as i64),
        );
        requests.push(contract_applet_event_request(&mut stream, event));
    }
    requests
}

fn contract_applet_batch(
    applet_id: &arkret_wire::AppletId,
    events: Vec<EventCommitRequest>,
    expected_record: Option<serde_json::Value>,
    record: serde_json::Value,
) -> EventBatchCommitRequest {
    let identity = contract_applet_identity(applet_id);
    let expected_identity = expected_record.as_ref().map(|_| identity.clone());
    EventBatchCommitRequest {
        events,
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: None,
        applet_record: Some(AppletRecordCommit {
            applet_id: applet_id.clone(),
            identity: AppletIdentityCommit {
                target_station_id: arkret_wire::DidCoreId::new(
                    "ak:did_core:webvh:z6mkcontractservice".to_owned(),
                )
                .expect("contract target Station id"),
                expected_record: expected_identity,
                record: identity,
            },
            expected_record,
            record,
        }),
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

fn contract_event_ids(batch: &EventBatchCommitRequest) -> Vec<String> {
    batch
        .events
        .iter()
        .map(|request| request.event.event_id.clone())
        .collect()
}

async fn assert_contract_event_group_visibility(
    store: &dyn EventStore,
    event_ids: &[String],
    expected: bool,
) {
    for event_id in event_ids {
        assert_eq!(
            store
                .contains(event_id)
                .await
                .expect("read Applet authority Event"),
            expected,
            "Applet authority Event group must be all-or-nothing: {event_id}"
        );
    }
}

async fn install_contract_applet(
    stores: &AppletFormalCommitContractStores<'_>,
    namespace: &str,
    realm_id: &str,
    applet_id: &arkret_wire::AppletId,
    record: serde_json::Value,
) {
    stores
        .unit_of_work
        .commit_event_batch(contract_applet_batch(
            applet_id,
            contract_applet_event_group(stores.authority, namespace, realm_id, "install", 1).await,
            None,
            record,
        ))
        .await
        .expect("install contract Applet record");
}

pub async fn assert_applet_formal_commit_transaction_contract(
    stores: AppletFormalCommitContractStores<'_>,
    namespace: &str,
) {
    // The target key cannot retarget a signed Bot Account or reinterpret a
    // service/principal scalar as an Account. Both adapters must roll back
    // the complete Event group when the identity fails this boundary.
    for case in ["foreign-station", "service-actor", "scalar-principal"] {
        let applet_id = contract_applet_id();
        let identity = contract_applet_identity(&applet_id);
        let actor: arkret_wire::ActorId = serde_json::from_value(identity["bot_actor_id"].clone())
            .expect("contract Bot has a full Account Actor");
        let invalid_actor = match case {
            "foreign-station" => {
                serde_json::json!(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    actor.signing_principal_id().clone(),
                    arkret_wire::DidCoreId::new("ak:did_core:web:foreign.example").unwrap(),
                ),))
            }
            "service-actor" => serde_json::json!(arkret_wire::ActorId::service(
                actor.signing_principal_id().clone(),
            )),
            _ => serde_json::json!(actor.signing_principal_id()),
        };
        let mut batch = contract_applet_batch(
            &applet_id,
            contract_applet_event_group(
                stores.authority,
                namespace,
                &contract_realm_id(&format!("{namespace}:{case}")),
                case,
                1,
            )
            .await,
            None,
            contract_applet_record(&applet_id, "1", Vec::new()),
        );
        batch.applet_record.as_mut().unwrap().identity.record["bot_actor_id"] = invalid_actor;
        let event_ids = contract_event_ids(&batch);
        stores
            .unit_of_work
            .commit_event_batch(batch)
            .await
            .expect_err("invalid Bot Account must reject the complete transaction");
        assert_contract_event_group_visibility(stores.events, &event_ids, false).await;
        assert!(
            stores
                .applets
                .get(applet_id.as_str(), &contract_applet_scope_key())
                .await
                .expect("read rejected Applet installation")
                .is_none()
        );
    }

    // A stale full-record CAS must roll back all four authority Events and the
    // managed authority claim. Reusing the same group on a fresh exact record
    // then proves that no hidden row from the failed transaction survived.
    let stale_applet_id = contract_applet_id();
    let stale_realm_id = contract_realm_id(&format!("{namespace}:stale"));
    let stale_base = contract_applet_record(&stale_applet_id, "1", Vec::new());
    install_contract_applet(
        &stores,
        namespace,
        &stale_realm_id,
        &stale_applet_id,
        stale_base.clone(),
    )
    .await;
    let committed_actor_id = format!("ak:did_core:web:{namespace}-committed.example");
    let committed_ghost =
        contract_ghost(&committed_actor_id, "bridge", "stale-cas", "committed", "2");
    let committed_record =
        contract_applet_record(&stale_applet_id, "1", vec![committed_ghost.clone()]);
    stores
        .unit_of_work
        .commit_event_batch(contract_applet_batch(
            &stale_applet_id,
            contract_applet_event_group(
                stores.authority,
                namespace,
                &stale_realm_id,
                "stale-winner",
                4,
            )
            .await,
            Some(stale_base.clone()),
            committed_record.clone(),
        ))
        .await
        .expect("commit the current Applet record mutation");
    let stale_actor_id = format!("ak:did_core:web:{namespace}-stale.example");
    let stale_ghost = contract_ghost(&stale_actor_id, "bridge", "stale-cas", "stale", "3");
    let stale_record = contract_applet_record(&stale_applet_id, "1", vec![stale_ghost.clone()]);
    let stale_batch = contract_applet_batch(
        &stale_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &stale_realm_id,
            "stale-loser",
            4,
        )
        .await,
        Some(stale_base),
        stale_record,
    );
    let stale_event_ids = contract_event_ids(&stale_batch);
    let stale_error = stores
        .unit_of_work
        .commit_event_batch(stale_batch.clone())
        .await
        .expect_err("stale Applet record CAS must fail");
    assert_eq!(
        stale_error.conflict_code(),
        Some(super::ConflictCode::CasConflict)
    );
    assert_eq!(
        stores
            .applets
            .get(stale_applet_id.as_str(), &contract_applet_scope_key())
            .await
            .expect("read current Applet record"),
        Some(committed_record.clone())
    );
    assert_contract_event_group_visibility(stores.events, &stale_event_ids, false).await;
    let merged_record =
        contract_applet_record(&stale_applet_id, "1", vec![committed_ghost, stale_ghost]);
    let mut fresh_retry = stale_batch;
    fresh_retry.applet_record = Some(AppletRecordCommit {
        applet_id: stale_applet_id.clone(),
        identity: AppletIdentityCommit {
            target_station_id: arkret_wire::DidCoreId::new(
                "ak:did_core:webvh:z6mkcontractservice".to_owned(),
            )
            .expect("contract target Station id"),
            expected_record: Some(contract_applet_identity(&stale_applet_id)),
            record: contract_applet_identity(&stale_applet_id),
        },
        expected_record: Some(committed_record),
        record: merged_record.clone(),
    });
    stores
        .unit_of_work
        .commit_event_batch(fresh_retry)
        .await
        .expect("fresh exact Applet record retry must commit");
    assert_contract_event_group_visibility(stores.events, &stale_event_ids, true).await;
    assert_eq!(
        stores
            .applets
            .get(stale_applet_id.as_str(), &contract_applet_scope_key())
            .await
            .expect("read merged Applet record"),
        Some(merged_record)
    );

    // Two batches for one external tuple race from the same exact record. One
    // whole four-Event authority group wins and the other leaves no prefix.
    let same_applet_id = contract_applet_id();
    let same_realm_id = contract_realm_id(&format!("{namespace}:same-external"));
    let same_base = contract_applet_record(&same_applet_id, "4", Vec::new());
    install_contract_applet(
        &stores,
        namespace,
        &same_realm_id,
        &same_applet_id,
        same_base.clone(),
    )
    .await;
    let same_actor_id = format!("ak:did_core:web:{namespace}-same.example");
    let same_ghost_left = contract_ghost(
        &same_actor_id,
        "bridge",
        "shared-instance",
        "shared-user",
        "5",
    );
    let same_ghost_right = contract_ghost(
        &same_actor_id,
        "bridge",
        "shared-instance",
        "shared-user",
        "6",
    );
    let same_left_record = contract_applet_record(&same_applet_id, "4", vec![same_ghost_left]);
    let same_right_record = contract_applet_record(&same_applet_id, "4", vec![same_ghost_right]);
    let same_left = contract_applet_batch(
        &same_applet_id,
        contract_applet_event_group(stores.authority, namespace, &same_realm_id, "same-left", 4)
            .await,
        Some(same_base.clone()),
        same_left_record.clone(),
    );
    let same_right = contract_applet_batch(
        &same_applet_id,
        contract_applet_event_group(stores.authority, namespace, &same_realm_id, "same-right", 4)
            .await,
        Some(same_base),
        same_right_record.clone(),
    );
    let same_left_ids = contract_event_ids(&same_left);
    let same_right_ids = contract_event_ids(&same_right);
    let (same_left_result, same_right_result) = tokio::join!(
        stores.unit_of_work.commit_event_batch(same_left),
        stores.unit_of_work.commit_event_batch(same_right)
    );
    assert_eq!(
        usize::from(same_left_result.is_ok()) + usize::from(same_right_result.is_ok()),
        1,
        "one external tuple must produce one durable authority group"
    );
    let same_loser_error = if same_left_result.is_ok() {
        same_right_result
            .as_ref()
            .expect_err("right same-tuple batch must lose the exact CAS")
    } else {
        same_left_result
            .as_ref()
            .expect_err("left same-tuple batch must lose the exact CAS")
    };
    assert_eq!(
        same_loser_error.conflict_code(),
        Some(super::ConflictCode::CasConflict)
    );
    let (same_winner_record, same_winner_ids, same_loser_ids) = if same_left_result.is_ok() {
        (same_left_record, same_left_ids, same_right_ids)
    } else {
        (same_right_record, same_right_ids, same_left_ids)
    };
    assert_eq!(
        stores
            .applets
            .get(same_applet_id.as_str(), &contract_applet_scope_key())
            .await
            .expect("read same-tuple Applet record"),
        Some(same_winner_record)
    );
    assert_contract_event_group_visibility(stores.events, &same_winner_ids, true).await;
    assert_contract_event_group_visibility(stores.events, &same_loser_ids, false).await;

    // Different Ghosts may race from the same observed record, but the losing
    // stale transaction cannot overwrite the committed registration. Retrying
    // against the exact winner then appends the second Ghost without loss.
    let different_applet_id = contract_applet_id();
    let different_realm_id = contract_realm_id(&format!("{namespace}:different-ghosts"));
    let different_base = contract_applet_record(&different_applet_id, "7", Vec::new());
    install_contract_applet(
        &stores,
        namespace,
        &different_realm_id,
        &different_applet_id,
        different_base.clone(),
    )
    .await;
    let different_left_actor_id = format!("ak:did_core:web:{namespace}-left.example");
    let different_right_actor_id = format!("ak:did_core:web:{namespace}-right.example");
    let different_left_ghost = contract_ghost(
        &different_left_actor_id,
        "bridge",
        "different-instance",
        "left-user",
        "8",
    );
    let different_right_ghost = contract_ghost(
        &different_right_actor_id,
        "bridge",
        "different-instance",
        "right-user",
        "9",
    );
    let different_left_record = contract_applet_record(
        &different_applet_id,
        "7",
        vec![different_left_ghost.clone()],
    );
    let different_right_record = contract_applet_record(
        &different_applet_id,
        "7",
        vec![different_right_ghost.clone()],
    );
    let different_left = contract_applet_batch(
        &different_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &different_realm_id,
            "different-left",
            4,
        )
        .await,
        Some(different_base.clone()),
        different_left_record.clone(),
    );
    let different_right = contract_applet_batch(
        &different_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &different_realm_id,
            "different-right",
            4,
        )
        .await,
        Some(different_base),
        different_right_record.clone(),
    );
    let different_left_ids = contract_event_ids(&different_left);
    let different_right_ids = contract_event_ids(&different_right);
    let (different_left_result, different_right_result) = tokio::join!(
        stores
            .unit_of_work
            .commit_event_batch(different_left.clone()),
        stores
            .unit_of_work
            .commit_event_batch(different_right.clone())
    );
    assert_eq!(
        usize::from(different_left_result.is_ok()) + usize::from(different_right_result.is_ok()),
        1,
        "one exact Applet record CAS must win"
    );
    let different_loser_error = if different_left_result.is_ok() {
        different_right_result
            .as_ref()
            .expect_err("right Ghost batch must lose the exact CAS")
    } else {
        different_left_result
            .as_ref()
            .expect_err("left Ghost batch must lose the exact CAS")
    };
    assert_eq!(
        different_loser_error.conflict_code(),
        Some(super::ConflictCode::CasConflict)
    );
    let (winner_record, winner_ghost, winner_ids, mut loser_batch, loser_ghost, loser_ids) =
        if different_left_result.is_ok() {
            (
                different_left_record,
                different_left_ghost,
                different_left_ids,
                different_right,
                different_right_ghost,
                different_right_ids,
            )
        } else {
            (
                different_right_record,
                different_right_ghost,
                different_right_ids,
                different_left,
                different_left_ghost,
                different_left_ids,
            )
        };
    assert_eq!(
        stores
            .applets
            .get(different_applet_id.as_str(), &contract_applet_scope_key())
            .await
            .expect("read concurrent Ghost winner"),
        Some(winner_record.clone()),
        "the losing stale CAS must not erase the committed Ghost"
    );
    assert_contract_event_group_visibility(stores.events, &winner_ids, true).await;
    assert_contract_event_group_visibility(stores.events, &loser_ids, false).await;
    let both_record =
        contract_applet_record(&different_applet_id, "7", vec![winner_ghost, loser_ghost]);
    let loser_mutation = loser_batch
        .applet_record
        .as_mut()
        .expect("losing batch carries Applet mutation");
    loser_mutation.expected_record = Some(winner_record);
    loser_mutation.record = both_record.clone();
    stores
        .unit_of_work
        .commit_event_batch(loser_batch)
        .await
        .expect("different Ghost retry on exact winner must commit");
    assert_contract_event_group_visibility(stores.events, &loser_ids, true).await;
    assert_eq!(
        stores
            .applets
            .get(different_applet_id.as_str(), &contract_applet_scope_key())
            .await
            .expect("read both concurrent Ghost registrations"),
        Some(both_record)
    );

    // Two first installs for distinct scopes can both observe no identity,
    // but only one insert-only managed identity winner may commit. The losing
    // aggregate leaves no Event prefix and can then reuse the exact durable
    // winner without manufacturing a second identity.
    let winner_applet_id = contract_applet_id();
    let winner_left_scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(contract_realm_id(&format!("{namespace}:winner-left")))
            .expect("contract first-winner left Realm id"),
    };
    let winner_right_scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(contract_realm_id(&format!(
            "{namespace}:winner-right"
        )))
        .expect("contract first-winner right Realm id"),
    };
    let winner_left_key = applet_effective_scope_key(&winner_left_scope)
        .expect("contract first-winner left scope key");
    let winner_right_key = applet_effective_scope_key(&winner_right_scope)
        .expect("contract first-winner right scope key");
    let winner_left_record =
        contract_applet_record_for_scope(&winner_applet_id, "12", winner_left_scope, Vec::new());
    let winner_right_record =
        contract_applet_record_for_scope(&winner_applet_id, "13", winner_right_scope, Vec::new());
    let winner_left = contract_applet_batch(
        &winner_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &contract_realm_id(&format!("{namespace}:winner-left-event")),
            "winner-left",
            1,
        )
        .await,
        None,
        winner_left_record.clone(),
    );
    let winner_right = contract_applet_batch(
        &winner_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &contract_realm_id(&format!("{namespace}:winner-right-event")),
            "winner-right",
            1,
        )
        .await,
        None,
        winner_right_record.clone(),
    );
    let winner_left_event_ids = contract_event_ids(&winner_left);
    let winner_right_event_ids = contract_event_ids(&winner_right);
    let (winner_left_result, winner_right_result) = tokio::join!(
        stores.unit_of_work.commit_event_batch(winner_left.clone()),
        stores.unit_of_work.commit_event_batch(winner_right.clone())
    );
    assert_eq!(
        usize::from(winner_left_result.is_ok()) + usize::from(winner_right_result.is_ok()),
        1,
        "concurrent first installs must persist one identity winner"
    );
    let (mut winner_retry, winner_loser_event_ids) = if winner_left_result.is_ok() {
        assert_eq!(
            winner_right_result
                .as_ref()
                .expect_err("right first install must lose")
                .conflict_code(),
            Some(super::ConflictCode::DuplicateConflict)
        );
        (winner_right, winner_right_event_ids)
    } else {
        assert_eq!(
            winner_left_result
                .as_ref()
                .expect_err("left first install must lose")
                .conflict_code(),
            Some(super::ConflictCode::DuplicateConflict)
        );
        (winner_left, winner_left_event_ids)
    };
    assert_contract_event_group_visibility(stores.events, &winner_loser_event_ids, false).await;
    winner_retry
        .applet_record
        .as_mut()
        .expect("first-winner retry carries Applet mutation")
        .identity
        .expected_record = Some(contract_applet_identity(&winner_applet_id));
    stores
        .unit_of_work
        .commit_event_batch(winner_retry)
        .await
        .expect("losing scope may reuse the exact accepted identity winner");
    assert_contract_event_group_visibility(stores.events, &winner_loser_event_ids, true).await;
    assert!(
        stores
            .applets
            .get(winner_applet_id.as_str(), &winner_left_key)
            .await
            .expect("read first-winner left installation")
            .is_some()
    );
    assert!(
        stores
            .applets
            .get(winner_applet_id.as_str(), &winner_right_key)
            .await
            .expect("read first-winner right installation")
            .is_some()
    );
    let accepted_identity = contract_applet_identity(&winner_applet_id);
    assert_eq!(
        stores
            .applets
            .get_identity(
                winner_applet_id.as_str(),
                "ak:did_core:webvh:z6mkcontractservice"
            )
            .await
            .expect("read accepted first-winner identity"),
        Some(accepted_identity.clone())
    );
    let conflicting_scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(contract_realm_id(&format!(
            "{namespace}:winner-conflict"
        )))
        .expect("contract conflicting winner Realm id"),
    };
    let conflicting_scope_key = applet_effective_scope_key(&conflicting_scope)
        .expect("contract conflicting winner scope key");
    let mut conflicting_winner = contract_applet_batch(
        &winner_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &contract_realm_id(&format!("{namespace}:winner-conflict-event")),
            "winner-conflict",
            1,
        )
        .await,
        None,
        contract_applet_record_for_scope(&winner_applet_id, "14", conflicting_scope, Vec::new()),
    );
    let conflicting_identity = serde_json::json!({
        "applet_id": winner_applet_id,
        "bot_actor_id": contract_applet_actor("ak:did_core:web:different-winner.example")
    });
    let conflicting_mutation = conflicting_winner
        .applet_record
        .as_mut()
        .expect("conflicting winner batch carries Applet mutation");
    conflicting_mutation.identity.expected_record = Some(accepted_identity.clone());
    conflicting_mutation.identity.record = conflicting_identity;
    assert_eq!(
        stores
            .unit_of_work
            .commit_event_batch(conflicting_winner)
            .await
            .expect_err("reuse with different identity bytes must fail")
            .conflict_code(),
        Some(super::ConflictCode::DuplicateConflict)
    );
    assert!(
        stores
            .applets
            .get(winner_applet_id.as_str(), &conflicting_scope_key)
            .await
            .expect("read rejected conflicting winner installation")
            .is_none()
    );
    assert_eq!(
        stores
            .applets
            .get_identity(
                winner_applet_id.as_str(),
                "ak:did_core:webvh:z6mkcontractservice"
            )
            .await
            .expect("re-read accepted identity after conflict"),
        Some(accepted_identity)
    );

    // The identity winner is independent of installations. Concurrently
    // revoking the last two exact scopes must therefore serialize on that
    // winner and persist exactly one global fence; neither adapter may leave
    // the identity unfenced through a write-skew.
    let fence_applet_id = contract_applet_id();
    let left_scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(contract_realm_id(&format!("{namespace}:fence-left")))
            .expect("contract left fence Realm id"),
    };
    let right_scope = arkret_wire::ScopeRef::Circle {
        realm_id: arkret_wire::RealmId::new(contract_realm_id(&format!("{namespace}:fence-right")))
            .expect("contract right fence Realm id"),
        circle_id: arkret_wire::CircleId::new(
            "ak:circle:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
        )
        .expect("contract right fence Circle id"),
    };
    let left_scope_key =
        applet_effective_scope_key(&left_scope).expect("contract left Applet effective scope key");
    let right_scope_key = applet_effective_scope_key(&right_scope)
        .expect("contract right Applet effective scope key");
    let left_record =
        contract_applet_record_for_scope(&fence_applet_id, "10", left_scope, Vec::new());
    let right_record =
        contract_applet_record_for_scope(&fence_applet_id, "11", right_scope, Vec::new());
    install_contract_applet(
        &stores,
        namespace,
        &contract_realm_id(&format!("{namespace}:fence-left-event")),
        &fence_applet_id,
        left_record.clone(),
    )
    .await;
    let mut right_install = contract_applet_batch(
        &fence_applet_id,
        contract_applet_event_group(
            stores.authority,
            namespace,
            &contract_realm_id(&format!("{namespace}:fence-right-event")),
            "fence-right-install",
            1,
        )
        .await,
        None,
        right_record.clone(),
    );
    right_install
        .applet_record
        .as_mut()
        .expect("right install carries Applet mutation")
        .identity
        .expected_record = Some(contract_applet_identity(&fence_applet_id));
    stores
        .unit_of_work
        .commit_event_batch(right_install)
        .await
        .expect("install second exact scope under the accepted identity winner");

    let left_fenced_at = database_timestamp_now();
    let right_fenced_at = left_fenced_at + chrono::Duration::milliseconds(1);
    let mut left_replacement = left_record.clone();
    left_replacement["status"] = serde_json::Value::String("revoked".to_owned());
    left_replacement["revoked_at"] =
        serde_json::Value::String(arkret_canonical::format_timestamp_canonical(left_fenced_at));
    let mut right_replacement = right_record.clone();
    right_replacement["status"] = serde_json::Value::String("revoked".to_owned());
    right_replacement["revoked_at"] = serde_json::Value::String(
        arkret_canonical::format_timestamp_canonical(right_fenced_at),
    );
    let target_station_id = "ak:did_core:webvh:z6mkcontractservice";
    let (left_outcome, right_outcome) = tokio::join!(
        stores.applets.fence_installation(
            fence_applet_id.as_str(),
            &left_scope_key,
            target_station_id,
            &left_record,
            left_replacement,
            left_fenced_at,
        ),
        stores.applets.fence_installation(
            fence_applet_id.as_str(),
            &right_scope_key,
            target_station_id,
            &right_record,
            right_replacement,
            right_fenced_at,
        )
    );
    let left_outcome = left_outcome.expect("fence left exact Applet scope");
    let right_outcome = right_outcome.expect("fence right exact Applet scope");
    assert!(left_outcome.updated && right_outcome.updated);
    assert_eq!(
        usize::from(left_outcome.globally_fenced) + usize::from(right_outcome.globally_fenced),
        1,
        "the last exact scope must persist exactly one global identity fence"
    );
    let fenced_identity = stores
        .applets
        .get_identity(fence_applet_id.as_str(), target_station_id)
        .await
        .expect("read globally fenced Applet identity")
        .expect("Applet identity winner remains durable after fencing");
    assert!(
        fenced_identity
            .get("globally_fenced_at")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "the identity winner must carry the terminal global fence"
    );
}

pub async fn assert_atomic_event_admission_contract(
    authority: &dyn AuthorityCommitStore,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let event_uuid = uuid::Uuid::now_v7();
    let atomic_realm_id = contract_realm_id(&format!(
        "atomic-authority-admission:{namespace}:{event_uuid}"
    ));
    let atomic_principal_id = format!("ak:did_core:web:atomic-{namespace}.example");
    let mut atomic_stream = ContractCommitStream::new(&atomic_realm_id);
    atomic_stream.install(authority).await;
    let atomic_event =
        canonical_wire_event_record("", &atomic_principal_id, &atomic_realm_id, 0, now);
    let atomic_event_id = arkret_wire::EventId::new(atomic_event.event_id.clone()).unwrap();
    let atomic_transaction = atomic_stream.accept(&atomic_event);
    assert_eq!(
        authority
            .admit_event_transaction(&atomic_transaction, now)
            .await
            .expect("atomically admit producer Event"),
        AuthorityCommitWriteOutcome::Committed
    );
    assert_eq!(
        authority
            .admit_event_transaction(&atomic_transaction, now)
            .await
            .expect("exact atomic admission retry"),
        AuthorityCommitWriteOutcome::Duplicate,
        "an exact retry replays the unique committed Event"
    );
    let failed_event = canonical_wire_event_record(
        "",
        &atomic_principal_id,
        &atomic_realm_id,
        1,
        now + Duration::milliseconds(1),
    );
    let failed_event_id = arkret_wire::EventId::new(failed_event.event_id.clone()).unwrap();
    let mut broken_transaction = atomic_stream.order(&failed_event);
    broken_transaction.commit.previous_commit_ref =
        Some(arkret_wire::RealmCommitId::from_digest([0xfe; 32]));
    assert!(
        authority
            .admit_event_transaction(&broken_transaction, now)
            .await
            .is_err(),
        "a wrong predecessor must reject the whole atomic admission"
    );
    assert!(
        authority
            .queued_event(&failed_event_id)
            .await
            .expect("inspect failed atomic admission")
            .is_none(),
        "a failed authority commit must roll back its newly queued Event"
    );
    assert!(
        authority
            .committed_event(&atomic_event_id)
            .await
            .expect("read exact atomic admission replay")
            .is_some()
    );
}

/// Two consecutive local Messages a domain writer admits: `accepted` extends
/// the stream head of an admitted ordinary collaboration Realm with an active
/// default discussion Strand, and `rollback` is the next Message after it.
///
/// Every Realm-stream Event kind is decided by its own typed writer at the
/// accepting cut, so the atomicity cases below need Events that pass their
/// writer; building that Realm is the adapter's job, not this contract's.
pub struct EventCommitContractMessages {
    pub accepted: EventCommitRequest,
    pub rollback: EventCommitRequest,
}

fn contract_outbox_record(
    id: &str,
    namespace: &str,
    idempotency_key: String,
    now: chrono::DateTime<Utc>,
) -> FederationOutboxRecord {
    FederationOutboxRecord {
        id: id.to_owned(),
        peer_id: DidCoreId::new(format!("ak:did_core:web:peer-{namespace}.example"))
            .expect("peer service id"),
        peer_url: Some("https://peer.example".to_owned()),
        endpoint: "/_arkret/peer/events".to_owned(),
        idempotency_key,
        payload_json: "{}".to_owned(),
        coalescing_key: None,
        coalescing_position: None,
        state: FederationOutboxState::Pending,
        leased_from_state: None,
        realm_fanout: None,
        attempts: 0,
        semantic_attempts: 0,
        next_attempt_at: now.timestamp(),
        last_http_status: None,
        last_error_code: None,
        last_response_excerpt: None,
        lease_owner: None,
        lease_token: None,
        lease_expires_at: None,
        policy_version: None,
        supersedes_outbox_id: None,
        created_at: now.timestamp(),
        completed_at: None,
    }
}

pub async fn assert_event_commit_unit_of_work_contract(
    stores: EventCommitContractStores<'_>,
    messages: EventCommitContractMessages,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let event_uuid = uuid::Uuid::now_v7();
    let realm_id = contract_realm_id(&format!("event-commit:{namespace}:{event_uuid}"));
    let principal_id = format!("ak:did_core:web:{namespace}.example");
    let idempotency_principal_id =
        DidCoreId::new(principal_id.clone()).expect("idempotency principal id");
    let idempotency_key = format!("event-commit:{namespace}:{event_uuid}");
    let outbox_id = format!("outbox:{namespace}:{event_uuid}");
    let EventCommitContractMessages {
        accepted: mut request,
        rollback: mut failed,
    } = messages;
    let event_id = request.event.event_id.clone();
    assert_eq!(
        request.projections.len(),
        1,
        "the accepted Message carries exactly its own projection record"
    );
    request.idempotency = Some(IdempotencyRecord {
        authenticated_actor: arkret_wire::ActorId::service(idempotency_principal_id.clone()),
        operation_id: "arkret://operations/contract/event-commit".to_owned(),
        idempotency_key: idempotency_key.clone(),
        request_hash: format!("sha256:{event_uuid}"),
        response_status: 200,
        response_body: serde_json::json!({"event_id": event_id}),
        created_at: now,
        expires_at: now + Duration::hours(1),
    });
    request.outbox = vec![contract_outbox_record(
        &outbox_id,
        namespace,
        format!("peer:{event_uuid}"),
        now,
    )];

    let outcome = stores
        .unit_of_work
        .commit_event(request)
        .await
        .expect("commit complete event unit of work");
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 1);
    assert!(stores.events.contains(&event_id).await.expect("read event"));
    let committed_event_id = arkret_wire::EventId::new(event_id.clone()).expect("typed Event id");
    let committed = stores
        .authority
        .committed_event(&committed_event_id)
        .await
        .expect("read committed Event pair")
        .expect("committed Event pair exists after atomic acceptance");
    assert_eq!(committed.event.event_id, committed_event_id);
    assert_eq!(committed.commit.event_ref, committed_event_id);
    assert!(
        stores
            .outbox
            .get(&outbox_id)
            .await
            .expect("read the unit's delivery intent")
            .is_some(),
        "the caller's delivery intent commits with the Event"
    );
    // Only the committed-replication intents the unit plans for remote joined
    // members are linked to their Event (`federation.md` section 4.1.1); this
    // founder-only Realm owes none, and a caller-supplied intent is not one.
    assert!(
        stores
            .events
            .federation_outbox_for_event(&event_id)
            .await
            .expect("read Event delivery intents")
            .is_empty()
    );
    assert!(
        stores
            .projections
            .snapshot_all()
            .await
            .expect("read projections")
            .iter()
            .any(|record| record.event_id == event_id)
    );
    assert!(
        stores
            .idempotency
            .get(
                &arkret_wire::ActorId::service(idempotency_principal_id.clone()),
                "arkret://operations/contract/event-commit",
                &idempotency_key,
            )
            .await
            .expect("read idempotency record")
            .is_some()
    );

    // The Contact cases below commit into their own contract Realm stream.
    let mut stream = ContractCommitStream::new(&realm_id);
    stream.install(stores.authority).await;

    // Contact admission installs the canonical Event, its Commit, the holder's
    // Contact row and the peer carrier in one unit. Reading them back only
    // through durable stores models a process restart with no in-memory
    // planning state.
    let contact_event = canonical_wire_event_record(
        arkret_wire::EventKind::ContactRequested.as_str(),
        &principal_id,
        &realm_id,
        2,
        now,
    );
    let contact_event_id = contact_event.event_id.clone();
    let contact_event_ref = arkret_wire::EventId::new(contact_event_id.clone()).unwrap();
    let contact_outbox_id = format!("contact-outbox:{namespace}:{event_uuid}");
    let contact_idempotency_key = format!("contact-commit:{namespace}:{event_uuid}");
    let contact_record = ContactRecord {
        requester_id: serde_json::from_str(&contact_event.actor_id).unwrap(),
        target_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:contact-peer-{namespace}.example")).unwrap(),
            DidCoreId::new("ak:did_core:web:peer-principal.example").unwrap(),
        )),
        contact_round_id: None,
        granted_to_target_scopes: vec!["direct_conversation".to_owned()],
        granted_to_requester_scopes: Vec::new(),
        status: "pending".to_owned(),
        pending_incoming_admitted: false,
        request_event_ref: Some(contact_event_ref.clone()),
        request_slot_states: vec![crate::ContactRequestSlotState {
            owner_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new(principal_id.clone()).unwrap(),
                DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            )),
            peer_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new(format!("ak:did_core:web:contact-peer-{namespace}.example"))
                    .unwrap(),
                DidCoreId::new("ak:did_core:web:peer-principal.example").unwrap(),
            )),
            accepted_sequence: 7,
            head_digest: Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap(),
            accepted_event_refs: Vec::new(),
        }],
        request_receipts: Vec::new(),
        request_mirror_receipts: Vec::new(),
        contact_round_evidence: None,
        contact_round_evidence_history: Vec::new(),
        control_outcomes: Vec::new(),
        response_event_ref: None,
        tombstone_event_ref: None,
        message: None,
        peer_host_id: Some(
            DidCoreId::new(format!(
                "ak:did_core:web:contact-service-{namespace}.example"
            ))
            .unwrap(),
        ),
        peer_service_resolution: None,
        created_at: now,
        updated_at: now,
    };
    let contact_commit = EventCommitRequest {
        authority_commit: stream.accept(&contact_event),
        self_producer_guard: None,
        applet_producer_guard: None,
        widget_token_gate: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        parent_membership_admission: None,
        contact_projection: Some(ContactProjectionCommit {
            completion_intent: None,
            record: contact_record.clone(),
            expected_updated_at: None,
            conflict_code: "contact_round_conflict".to_owned(),
            verified_mirror: None,
            invite_policy: None,
        }),

        event: contact_event,
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: Vec::new(),
        idempotency: Some(IdempotencyRecord {
            authenticated_actor: arkret_wire::ActorId::service(idempotency_principal_id.clone()),
            operation_id: "arkret://operations/contract/contact-commit".to_owned(),
            idempotency_key: contact_idempotency_key.clone(),
            request_hash: format!("sha256:contact-{event_uuid}"),
            response_status: 200,
            response_body: serde_json::json!({"status": "accepted"}),
            created_at: now,
            expires_at: now + Duration::hours(1),
        }),
        outbox: vec![FederationOutboxRecord::pending(
            contact_outbox_id.clone(),
            contact_record.peer_host_id.clone().unwrap(),
            "https://contact-peer.example".to_owned(),
            "/_arkret/peer/contacts".to_owned(),
            format!("peer-contact:{contact_event_id}"),
            "{}".to_owned(),
            now.timestamp(),
        )],
        realm_fanout_source: None,
    };
    stores
        .unit_of_work
        .commit_event(contact_commit.clone())
        .await
        .expect("Contact Event/projection/outbox commit atomically");
    stores
        .unit_of_work
        .commit_event(contact_commit)
        .await
        .expect("Contact response-loss replay observes the committed unit");
    assert!(stores.events.contains(&contact_event_id).await.unwrap());
    assert_eq!(
        stores
            .contacts
            .get(&contact_record.requester_id, &contact_record.target_id)
            .await
            .unwrap()
            .expect("the committed Contact row is visible with its Commit")
            .request_event_ref,
        Some(contact_event_ref.clone()),
    );
    assert!(
        stores
            .outbox
            .get(&contact_outbox_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        stores
            .idempotency
            .get(
                &arkret_wire::ActorId::service(idempotency_principal_id.clone()),
                "arkret://operations/contract/contact-commit",
                &contact_idempotency_key,
            )
            .await
            .unwrap()
            .is_some(),
        "Contact response-loss replay retains the first operation outcome"
    );

    let failed_contact_event = canonical_wire_event_record(
        arkret_wire::EventKind::ContactRequested.as_str(),
        &principal_id,
        &realm_id,
        3,
        now,
    );
    let failed_contact_event_id = failed_contact_event.event_id.clone();
    let failed_contact_outbox_id = format!("contact-outbox-failed:{namespace}:{event_uuid}");
    let mut conflicting_contact = contact_record.clone();
    conflicting_contact.updated_at = now + Duration::seconds(2);
    let failed_contact_commit = stores
        .unit_of_work
        .commit_event(EventCommitRequest {
            authority_commit: stream.accept(&failed_contact_event),
            self_producer_guard: None,
            applet_producer_guard: None,
            widget_token_gate: None,
            forwarded_producer_evidence: None,
            forwarded_agent_producer: None,
            agent_deployment_ceiling: arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
            parent_membership_admission: None,
            contact_projection: Some(ContactProjectionCommit {
                completion_intent: None,
                record: conflicting_contact,
                expected_updated_at: Some(now + Duration::seconds(1)),
                conflict_code: "contact_lineage_conflict".to_owned(),
                verified_mirror: None,
                invite_policy: None,
            }),

            event: failed_contact_event,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency: None,
            outbox: vec![FederationOutboxRecord::pending(
                failed_contact_outbox_id.clone(),
                contact_record.peer_host_id.clone().unwrap(),
                "https://contact-peer.example".to_owned(),
                "/_arkret/peer/contacts".to_owned(),
                format!("peer-contact:{failed_contact_event_id}"),
                "{}".to_owned(),
                now.timestamp(),
            )],
            realm_fanout_source: None,
        })
        .await;
    assert!(
        failed_contact_commit.is_err(),
        "a lost Contact row CAS refuses the whole accepting unit"
    );
    assert!(
        !stores
            .events
            .contains(&failed_contact_event_id)
            .await
            .unwrap()
    );
    assert!(
        stores
            .outbox
            .get(&failed_contact_outbox_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        stores
            .contacts
            .get(&contact_record.requester_id, &contact_record.target_id)
            .await
            .unwrap()
            .expect("the first Contact row survives the refused unit")
            .updated_at,
        contact_record.updated_at,
    );

    let rollback_uuid = uuid::Uuid::now_v7();
    let rollback_idempotency_key = format!("event-rollback:{namespace}:{rollback_uuid}");
    let rollback_outbox_id = format!("outbox-rollback:{namespace}:{rollback_uuid}");
    let rollback_event_id = failed.event.event_id.clone();
    // The Message itself passes its writer; the malformed projection record
    // written later in the same unit must take the Event, its Commit, the
    // idempotency outcome and the delivery intent down with it.
    let [projection] = failed.projections.as_mut_slice() else {
        panic!("the rollback Message carries exactly its own projection record");
    };
    projection.realm_id = "not-a-typed-realm-id".to_owned();
    failed.idempotency = Some(IdempotencyRecord {
        authenticated_actor: arkret_wire::ActorId::service(idempotency_principal_id.clone()),
        operation_id: "arkret://operations/contract/rollback".to_owned(),
        idempotency_key: rollback_idempotency_key.clone(),
        request_hash: format!("sha256:{rollback_uuid}"),
        response_status: 200,
        response_body: serde_json::json!({}),
        created_at: now,
        expires_at: now + Duration::hours(1),
    });
    failed.outbox = vec![contract_outbox_record(
        &rollback_outbox_id,
        namespace,
        format!("peer:{rollback_uuid}"),
        now,
    )];
    assert!(stores.unit_of_work.commit_event(failed).await.is_err());
    assert!(
        !stores
            .events
            .contains(&rollback_event_id)
            .await
            .expect("event rollback")
    );
    assert!(
        !stores
            .projections
            .snapshot_all()
            .await
            .expect("projection rollback")
            .iter()
            .any(|record| record.event_id == rollback_event_id)
    );
    assert!(
        stores
            .idempotency
            .get(
                &arkret_wire::ActorId::service(idempotency_principal_id.clone()),
                "arkret://operations/contract/rollback",
                &rollback_idempotency_key,
            )
            .await
            .expect("idempotency rollback")
            .is_none()
    );
    assert!(
        stores
            .outbox
            .get(&rollback_outbox_id)
            .await
            .expect("outbox rollback")
            .is_none()
    );
}

/// Every invariant the federation outbox owes the dispatcher, asserted
/// identically against the in-memory and PostgreSQL adapters:
///
/// 1. `(peer, idempotency_key)` re-enqueue is a no-op, not an error;
/// 2. claiming is exclusive — a second worker sees nothing;
/// 3. only the current lease holder may complete or reschedule a row;
/// 4. an expired lease is reclaimable by another worker;
/// 5. terminal state and its dead-letter row commit together;
/// 6. a superseded attempt and its replacement commit together;
/// 7. `policy_suppressed` only leaves that state through revalidation;
/// 8. Realm fanout route misses remain durable and authority loss is terminal;
/// 9. a monotonic coalescing lane retains one unfinished highest position.
pub async fn assert_federation_outbox_store_contract(
    store: &dyn FederationOutboxStore,
    namespace: &str,
) {
    let peer_id = DidCoreId::new(format!("ak:did_core:web:peer-{namespace}.example"))
        .expect("peer service id");
    let row = |suffix: &str, created_at: i64| {
        FederationOutboxRecord::pending(
            format!("outbox:{namespace}:{suffix}"),
            peer_id.clone(),
            "https://peer.example".to_owned(),
            "/_arkret/peer/events".to_owned(),
            format!("ak:outbox:event:{namespace}:{suffix}"),
            "{}".to_owned(),
            created_at,
        )
    };

    // (1) Re-enqueueing the same logical request collapses onto the first row.
    let first = row("first", 100);
    assert!(store.enqueue(&first).await.expect("enqueue"));
    let mut duplicate = first.clone();
    duplicate.id = format!("outbox:{namespace}:duplicate");
    assert!(
        !store.enqueue(&duplicate).await.expect("duplicate enqueue"),
        "a re-enqueue of the same (peer, key) is an idempotent no-op"
    );
    assert!(
        store
            .get(&duplicate.id)
            .await
            .expect("read duplicate")
            .is_none()
    );

    let claim = |token: &str, owner: &str, now: i64, lease: i64| FederationOutboxClaim {
        now_unix_secs: now,
        limit: 8,
        lease_owner: owner.to_owned(),
        lease_token: token.to_owned(),
        lease_duration_secs: lease,
    };

    // (2) Claiming is exclusive.
    let claimed = store
        .claim_due(&claim("token-a", "worker-a", 200, 60))
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, first.id);
    assert_eq!(claimed[0].state, FederationOutboxState::Leased);
    assert_eq!(claimed[0].lease_token.as_deref(), Some("token-a"));
    assert!(
        store
            .claim_due(&claim("token-b", "worker-b", 200, 60))
            .await
            .expect("concurrent claim")
            .is_empty(),
        "a leased row is invisible to a second worker until the lease expires"
    );

    // (3) Only the lease holder may write the attempt's result.
    let transition = |token: &str, outcome: FederationOutboxOutcome| FederationOutboxTransition {
        id: first.id.clone(),
        lease_token: token.to_owned(),
        attempts: 1,
        semantic_attempts: 0,
        last_http_status: Some(503),
        last_error_code: Some("retryable_http_status".to_owned()),
        last_response_excerpt: Some("unavailable".to_owned()),
        observed_at: 210,
        outcome,
    };
    assert!(
        !store
            .complete(&transition(
                "token-b",
                FederationOutboxOutcome::Retry {
                    next_attempt_at: 300,
                },
            ))
            .await
            .expect("stale-lease complete"),
        "a stale holder's late write MUST be dropped"
    );
    assert!(
        store
            .complete(&transition(
                "token-a",
                FederationOutboxOutcome::Retry {
                    next_attempt_at: 300,
                },
            ))
            .await
            .expect("holder complete")
    );
    let rescheduled = store
        .get(&first.id)
        .await
        .expect("read rescheduled")
        .expect("row present");
    assert_eq!(rescheduled.state, FederationOutboxState::Pending);
    assert_eq!(rescheduled.attempts, 1);
    assert_eq!(rescheduled.next_attempt_at, 300);
    assert!(rescheduled.lease_token.is_none());
    assert!(rescheduled.completed_at.is_none());

    // (4) An expired lease returns to the pool for another worker.
    assert_eq!(
        store
            .claim_due(&claim("token-c", "worker-a", 300, 10))
            .await
            .expect("reclaim")
            .len(),
        1
    );
    let takeover = store
        .claim_due(&claim("token-d", "worker-b", 400, 60))
        .await
        .expect("expired-lease takeover");
    assert_eq!(takeover.len(), 1, "an expired lease is claimable again");
    assert_eq!(takeover[0].lease_owner.as_deref(), Some("worker-b"));

    // (5) Terminal state and failure ledger land together.
    let dead_letter_id = format!("dead-letter:{namespace}");
    assert!(
        store
            .complete(&FederationOutboxTransition {
                id: first.id.clone(),
                lease_token: "token-d".to_owned(),
                attempts: 10,
                semantic_attempts: 0,
                last_http_status: Some(404),
                last_error_code: Some("terminal_http_status".to_owned()),
                last_response_excerpt: Some("not found".to_owned()),
                observed_at: 500,
                outcome: FederationOutboxOutcome::DeadLettered(Box::new(
                    FederationOutboxDeadLetterRecord {
                        id: dead_letter_id.clone(),
                        outbox_id: first.id.clone(),
                        peer_id: peer_id.clone(),
                        endpoint: "/_arkret/peer/events".to_owned(),
                        idempotency_key: first.idempotency_key.clone(),
                        last_http_status: Some(404),
                        attempts: 10,
                        response_excerpt: Some("not found".to_owned()),
                        reason: "terminal_http_status".to_owned(),
                        failed_at: 500,
                        requeued_outbox_id: None,
                        requeued_by: None,
                        requeue_reason: None,
                        requeue_request_digest: None,
                        requeued_at: None,
                    }
                )),
            })
            .await
            .expect("dead-letter transition")
    );
    let dead_lettered = store
        .get(&first.id)
        .await
        .expect("read dead-lettered")
        .expect("row present");
    assert_eq!(dead_lettered.state, FederationOutboxState::DeadLettered);
    assert_eq!(dead_lettered.completed_at, Some(500));
    assert!(
        store
            .dead_letter(&dead_letter_id)
            .await
            .expect("read dead letter")
            .is_some(),
        "the terminal state and its ledger row are one transaction"
    );
    let terminal_claims = store
        .claim_due(&claim("token-e", "worker-a", 10_000, 60))
        .await
        .expect("terminal claim");
    assert!(
        terminal_claims.iter().all(|row| row.id != first.id),
        "the terminal row is never claimed again"
    );

    // Operator replay mints a new intent under a new key, single-shot.
    let replay = row("replay", 600);
    assert!(
        store
            .requeue_dead_letter(&FederationOutboxRequeue {
                dead_letter_id: dead_letter_id.clone(),
                record: FederationOutboxRecord {
                    supersedes_outbox_id: Some(first.id.clone()),
                    ..replay.clone()
                },
                operator: "did:web:operator.example".to_owned(),
                reason: "peer restored".to_owned(),
                request_digest: format!("sha256:{}", "a".repeat(64)),
                requeued_at: 610,
            })
            .await
            .expect("requeue")
    );
    let requeued = store
        .dead_letter(&dead_letter_id)
        .await
        .expect("read requeued dead letter")
        .expect("dead letter present");
    assert_eq!(
        requeued.requeued_outbox_id.as_deref(),
        Some(replay.id.as_str())
    );
    assert_eq!(
        requeued.requeued_by.as_deref(),
        Some("did:web:operator.example")
    );
    assert!(
        !store
            .requeue_dead_letter(&FederationOutboxRequeue {
                dead_letter_id: dead_letter_id.clone(),
                record: row("replay-again", 620),
                operator: "did:web:operator.example".to_owned(),
                reason: "double click".to_owned(),
                request_digest: format!("sha256:{}", "b".repeat(64)),
                requeued_at: 620,
            })
            .await
            .expect("second requeue"),
        "a dead letter replays at most once"
    );

    // (6) A superseded attempt and its replacement land together.
    let superseded = row("superseded", 700);
    assert!(
        store
            .enqueue(&superseded)
            .await
            .expect("enqueue superseded")
    );
    let claimed = store
        .claim_due(&claim("token-f", "worker-a", 700, 60))
        .await
        .expect("claim superseded");
    let claimed_ids = claimed
        .iter()
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    assert!(claimed_ids.contains(&superseded.id.as_str()));
    let successor = FederationOutboxRecord {
        supersedes_outbox_id: Some(superseded.id.clone()),
        ..row("successor", 710)
    };
    assert!(
        store
            .complete(&FederationOutboxTransition {
                id: superseded.id.clone(),
                lease_token: "token-f".to_owned(),
                attempts: 1,
                semantic_attempts: 1,
                last_http_status: Some(200),
                last_error_code: Some("dependency_missing".to_owned()),
                last_response_excerpt: Some("partial".to_owned()),
                observed_at: 710,
                outcome: FederationOutboxOutcome::Superseded(Box::new(successor.clone())),
            })
            .await
            .expect("supersede transition")
    );
    assert_eq!(
        store
            .get(&superseded.id)
            .await
            .expect("read superseded")
            .expect("row present")
            .state,
        FederationOutboxState::Superseded
    );
    let stored_successor = store
        .get(&successor.id)
        .await
        .expect("read successor")
        .expect("successor present");
    assert_eq!(stored_successor.state, FederationOutboxState::Pending);
    assert_eq!(
        stored_successor.supersedes_outbox_id.as_deref(),
        Some(superseded.id.as_str())
    );

    // (7) Policy suppression is its own terminal state, and only revalidation
    // against a *changed* policy version can return the row to the queue.
    let suppressed = row("suppressed", 800);
    assert!(
        store
            .enqueue(&suppressed)
            .await
            .expect("enqueue suppressed")
    );
    let claimed = store
        .claim_due(&claim("token-g", "worker-a", 800, 60))
        .await
        .expect("claim suppressed");
    assert!(claimed.iter().any(|row| row.id == suppressed.id));
    assert!(
        store
            .complete(&FederationOutboxTransition {
                id: suppressed.id.clone(),
                lease_token: "token-g".to_owned(),
                attempts: 0,
                semantic_attempts: 0,
                last_http_status: None,
                last_error_code: Some("egress_policy_denied".to_owned()),
                last_response_excerpt: Some("denied".to_owned()),
                observed_at: 810,
                outcome: FederationOutboxOutcome::PolicySuppressed {
                    policy_version: "sha256:policy-v1".to_owned(),
                },
            })
            .await
            .expect("policy-suppress transition")
    );
    assert!(
        store
            .claim_due(&claim("token-h", "worker-a", 20_000, 60))
            .await
            .expect("suppressed claim")
            .iter()
            .all(|row| row.id != suppressed.id),
        "a suppressed row is not redelivered just because time passed"
    );
    assert!(
        store
            .policy_suppressed_stale("sha256:policy-v1", 8)
            .await
            .expect("unchanged policy sweep")
            .iter()
            .all(|row| row.id != suppressed.id),
        "an unchanged policy version produces no revalidation candidates"
    );
    let stale = store
        .policy_suppressed_stale("sha256:policy-v2", 8)
        .await
        .expect("changed policy sweep");
    assert!(stale.iter().any(|row| row.id == suppressed.id));
    assert!(
        store
            .resolve_policy_suppressed(
                &suppressed.id,
                &FederationOutboxPolicyResolution::Repin {
                    policy_version: "sha256:policy-v2".to_owned(),
                },
            )
            .await
            .expect("repin")
    );
    assert_eq!(
        store
            .get(&suppressed.id)
            .await
            .expect("read repinned")
            .expect("row present")
            .state,
        FederationOutboxState::PolicySuppressed,
        "a repin records the newer policy without releasing the row"
    );
    assert!(
        store
            .resolve_policy_suppressed(
                &suppressed.id,
                &FederationOutboxPolicyResolution::Release {
                    next_attempt_at: 900,
                },
            )
            .await
            .expect("release")
    );
    let released = store
        .get(&suppressed.id)
        .await
        .expect("read released")
        .expect("row present");
    assert_eq!(released.state, FederationOutboxState::Pending);
    assert_eq!(released.next_attempt_at, 900);
    assert!(released.policy_version.is_none());

    // (8) Realm fanout route misses remain durable without entering the
    // generic dead-letter lifecycle, and authority loss is terminal.
    let realm_id = contract_realm_id(&format!("fanout:{namespace}"));
    let source_event = canonical_wire_event_record(
        "",
        "ak:did_core:web:alice.example",
        &realm_id,
        0,
        database_timestamp_now(),
    );
    let route_missing = FederationOutboxRecord::realm_fanout(RealmFanoutOutboxInput {
        id: format!("outbox:{namespace}:pending-route"),
        peer_id: DidCoreId::new("ak:did_core:web:peer.example").expect("peer service id"),
        peer_url: None,
        endpoint: "/_arkret/peer/events".to_owned(),
        idempotency_key: format!("ak:outbox:event:{namespace}:pending-route"),
        payload_json: "{}".to_owned(),
        binding: RealmFanoutBinding {
            realm_id,
            source_event_ids: vec![source_event.event_id.clone()],
            authority_witnesses: vec![RealmFanoutAuthorityWitness {
                member_id: arkret_wire::ActorId::service(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                ),
                circle_membership_event_ref: None,
                membership_event_ref: source_event.event_id.clone(),
            }],
        },
        created_at: 1_000,
    });
    assert!(
        store
            .enqueue(&route_missing)
            .await
            .expect("enqueue missing-route fanout")
    );
    let claimed = store
        .claim_due(&claim("token-route-a", "worker-a", 1_000, 60))
        .await
        .expect("claim missing-route fanout");
    let claimed = claimed
        .iter()
        .find(|row| row.id == route_missing.id)
        .expect("missing-route row claimed");
    assert_eq!(
        claimed.leased_from_state,
        Some(FederationOutboxState::PendingRoute)
    );
    assert!(
        store
            .complete(&FederationOutboxTransition {
                id: route_missing.id.clone(),
                lease_token: "token-route-a".to_owned(),
                attempts: 1,
                semantic_attempts: 0,
                last_http_status: None,
                last_error_code: Some("service_route_unavailable".to_owned()),
                last_response_excerpt: None,
                observed_at: 1_001,
                outcome: FederationOutboxOutcome::RouteUnavailable {
                    next_attempt_at: 1_100,
                },
            })
            .await
            .expect("preserve missing-route fanout")
    );
    assert_eq!(
        store
            .get(&route_missing.id)
            .await
            .expect("read missing-route fanout")
            .expect("missing-route fanout present")
            .state,
        FederationOutboxState::PendingRoute
    );
    let claimed = store
        .claim_due(&claim("token-route-b", "worker-b", 1_100, 60))
        .await
        .expect("reclaim missing-route fanout");
    assert!(claimed.iter().any(|row| row.id == route_missing.id));
    let forbidden = store
        .complete(&FederationOutboxTransition {
            id: route_missing.id.clone(),
            lease_token: "token-route-b".to_owned(),
            attempts: 2,
            semantic_attempts: 0,
            last_http_status: Some(404),
            last_error_code: Some("terminal_http_status".to_owned()),
            last_response_excerpt: None,
            observed_at: 1_101,
            outcome: FederationOutboxOutcome::DeadLettered(Box::new(
                FederationOutboxDeadLetterRecord {
                    id: format!("dead-letter:{namespace}:realm"),
                    outbox_id: route_missing.id.clone(),
                    peer_id: route_missing.peer_id.clone(),
                    endpoint: route_missing.endpoint.clone(),
                    idempotency_key: route_missing.idempotency_key.clone(),
                    last_http_status: Some(404),
                    attempts: 2,
                    response_excerpt: None,
                    reason: "terminal_http_status".to_owned(),
                    failed_at: 1_101,
                    requeued_outbox_id: None,
                    requeued_by: None,
                    requeue_reason: None,
                    requeue_request_digest: None,
                    requeued_at: None,
                },
            )),
        })
        .await;
    assert!(
        forbidden.is_err(),
        "Realm fanout must never enter the generic dead-letter lifecycle"
    );
    assert!(
        store
            .complete(&FederationOutboxTransition {
                id: route_missing.id.clone(),
                lease_token: "token-route-b".to_owned(),
                attempts: 2,
                semantic_attempts: 0,
                last_http_status: None,
                last_error_code: Some("fanout_authority_lost".to_owned()),
                last_response_excerpt: None,
                observed_at: 1_102,
                outcome: FederationOutboxOutcome::CancelledAuthorityLost,
            })
            .await
            .expect("cancel authority-lost fanout")
    );
    assert_eq!(
        store
            .get(&route_missing.id)
            .await
            .expect("read cancelled fanout")
            .expect("cancelled fanout present")
            .state,
        FederationOutboxState::CancelledAuthorityLost
    );
    assert!(
        store
            .claim_due(&claim("token-route-c", "worker-c", 100_000, 60))
            .await
            .expect("claim after cancellation")
            .iter()
            .all(|row| row.id != route_missing.id),
        "later route or authority changes must not revive a cancelled intent"
    );

    // (9) Monotonic state fanout has exactly one unfinished row per target
    // lane. A newer head supersedes the old intent atomically; stale/equal
    // positions cannot replace it.
    let lane_key = format!("account-status:{namespace}:account-1");
    let lane_row = |suffix: &str, position: i64, created_at: i64| {
        FederationOutboxRecord::pending(
            format!("outbox:{namespace}:lane:{suffix}"),
            peer_id.clone(),
            "https://peer.example".to_owned(),
            "/_arkret/peer/account-status".to_owned(),
            format!("ak:outbox:account-status:{namespace}:{suffix}"),
            format!(r#"{{"status_seq":{position}}}"#),
            created_at,
        )
        .with_coalescing_lane(lane_key.clone(), position)
    };
    let lane_one = lane_row("one", 1, 2_000);
    let lane_three = lane_row("three", 3, 2_001);
    let lane_two = lane_row("two", 2, 2_002);
    assert!(store.enqueue(&lane_one).await.expect("enqueue lane head 1"));
    assert!(
        store
            .enqueue(&lane_three)
            .await
            .expect("enqueue lane head 3")
    );
    assert!(
        !store
            .enqueue(&lane_two)
            .await
            .expect("enqueue stale lane head"),
        "a stale position cannot replace the unfinished highest head"
    );
    assert_eq!(
        store
            .get(&lane_one.id)
            .await
            .expect("read superseded lane head")
            .expect("superseded lane head present")
            .state,
        FederationOutboxState::Superseded
    );
    let active_lane = store
        .snapshot_all()
        .await
        .expect("snapshot coalescing lane")
        .into_iter()
        .filter(|row| {
            row.peer_id == peer_id
                && row.coalescing_key.as_deref() == Some(lane_key.as_str())
                && matches!(
                    row.state,
                    FederationOutboxState::Pending
                        | FederationOutboxState::PendingRoute
                        | FederationOutboxState::Leased
                        | FederationOutboxState::PolicySuppressed
                )
        })
        .collect::<Vec<_>>();
    assert_eq!(active_lane.len(), 1);
    assert_eq!(active_lane[0].id, lane_three.id);
    assert_eq!(
        active_lane[0].supersedes_outbox_id.as_deref(),
        Some(lane_one.id.as_str())
    );

    let depth = store.state_depth().await.expect("state depth");
    assert!(
        depth
            .iter()
            .any(|bucket| bucket.state == FederationOutboxState::DeadLettered
                && bucket.peer_id == peer_id
                && bucket.depth >= 1)
    );
}

/// The Station Account that owns the contract KeyPackages.
///
/// A human KeyPackage binds one confirmed device authorization, so the owner
/// is exactly the Account that authorization names.
async fn mls_keypackage_contract_account(
    accounts: &dyn super::AccountStore,
    device: &DeviceRevocationGateSelector,
) -> AccountPk {
    accounts
        .put(&super::AccountRecord {
            pk: AccountPk(0),
            principal_id: device.principal_id.clone(),
            station_id: device.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: database_timestamp_now(),
        })
        .await
        .expect("register KeyPackage Account owner")
}

fn mls_keypackage_contract_row(
    namespace: &str,
    suffix: &str,
    owner_account_pk: AccountPk,
    device: &DeviceRevocationGateSelector,
) -> MlsKeyPackageRow {
    MlsKeyPackageRow {
        id: format!("{namespace}-keypackage-{suffix}"),
        keypackage_ref: format!("ak:mls:keypackage:{namespace}-{suffix}"),
        keypackage_digest:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        owner_account_pk,
        // The KeyPackage wire binds the cryptographic endpoint principal;
        // the exact Station Account is carried by owner_account_pk above.
        actor_id: device.principal_id.to_string(),
        device_id: Some(device.device_id.clone()),
        endpoint_verification_method: None,
        intended_realm_id: None,
        key_package_bytes: vec![1, 2, 3],
        capabilities: vec!["ak.mls.rfc9420".to_owned()],
        capabilities_digest:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        last_resort: false,
        last_resort_realm_id: None,
        lifetime_not_before: 1,
        lifetime_not_after: 100,
        claimed_by_mls_group_id: None,
        device_authorize_event_id: Some(device.authorization_ref.event_id.to_string()),
        agent_key_authorize_event_id: None,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: 1,
    }
}

/// The canonical MLS group id of a contract Realm named by `label`.
///
/// A group id is derived from its effective scope, never authored, so a
/// contract group is the one its Realm scope derives.
fn contract_mls_group_id(label: &str) -> String {
    arkret_wire::ScopeRef::Realm {
        realm_id: arkret_identifiers::RealmId::new(contract_realm_id(label))
            .expect("contract MLS Realm id"),
    }
    .canonical_mls_group_id()
    .expect("contract Realm scope derives an MLS group id")
    .as_str()
    .to_owned()
}

/// A claim of one contract KeyPackage under its owner's device authorization.
///
/// The revocation gate compares the whole committed reference, so the claim
/// carries the exact selector of the device that published the KeyPackage.
fn mls_claim<'a>(
    id: &'a str,
    target: MlsKeyPackageClaimTarget<'a>,
    device: &'a DeviceRevocationGateSelector,
) -> MlsKeyPackageClaim<'a> {
    MlsKeyPackageClaim {
        id,
        target,
        intended_realm_id: None,
        device_authorize_event_id: Some(device.authorization_ref.event_id.as_str()),
        agent_key_authorize_event_id: None,
        device_revocation_gate: Some(device.clone()),
        claimed_at: 10,
        claim_expires_at_unix_ms: Some(20_500),
    }
}

/// `device` is a confirmed, unrevoked device authorization the adapter's
/// current device inventory already carries; every KeyPackage here is
/// published and claimed under it.
pub async fn assert_mls_keypackage_retirement_contract(
    store: &dyn MlsKeyPackageStore,
    accounts: &dyn super::AccountStore,
    namespace: &str,
    device: &DeviceRevocationGateSelector,
) {
    let owner_account_pk = mls_keypackage_contract_account(accounts, device).await;
    let published = mls_keypackage_contract_row(namespace, "published", owner_account_pk, device);
    let claimed = mls_keypackage_contract_row(namespace, "claimed", owner_account_pk, device);
    let consumed = mls_keypackage_contract_row(namespace, "consumed", owner_account_pk, device);
    let late = mls_keypackage_contract_row(namespace, "late-consume", owner_account_pk, device);
    let revoked = mls_keypackage_contract_row(namespace, "revoked", owner_account_pk, device);
    for row in [&published, &claimed, &consumed, &late, &revoked] {
        assert!(store.put(row).await.expect("publish KeyPackage"));
    }

    let retired = store
        .try_claim(mls_claim(
            &published.id,
            MlsKeyPackageClaimTarget::Retire,
            device,
        ))
        .await
        .expect("retire published KeyPackage")
        .expect("published KeyPackage must retire");
    assert_eq!(retired.claimed_by_mls_group_id.as_deref(), Some("retired"));
    assert!(retired.claimed_at.is_none());
    assert!(retired.claim_expires_at_unix_ms.is_none());
    assert!(retired.consumed_at.is_none());
    let group_after_retirement = contract_mls_group_id(&format!("{namespace}:after-retirement"));
    assert!(
        store
            .try_claim(mls_claim(
                &published.id,
                MlsKeyPackageClaimTarget::Group(&group_after_retirement),
                device,
            ))
            .await
            .expect("query retired KeyPackage")
            .is_none()
    );

    let group_id = contract_mls_group_id(namespace);
    store
        .try_claim(mls_claim(
            &claimed.id,
            MlsKeyPackageClaimTarget::Group(&group_id),
            device,
        ))
        .await
        .expect("claim ordinary KeyPackage")
        .expect("ordinary KeyPackage must be claimable");
    assert!(
        store
            .try_claim(mls_claim(
                &claimed.id,
                MlsKeyPackageClaimTarget::Retire,
                device
            ))
            .await
            .expect("attempt to retire claimed KeyPackage")
            .is_none()
    );

    store
        .try_claim(mls_claim(
            &consumed.id,
            MlsKeyPackageClaimTarget::Group(&group_id),
            device,
        ))
        .await
        .expect("claim KeyPackage before consume")
        .expect("ordinary KeyPackage must be claimable");
    store
        .consume_claim(&consumed.id, &group_id, 15_000, None)
        .await
        .expect("consume KeyPackage")
        .expect("claimed KeyPackage must be consumable");
    store
        .try_claim(mls_claim(
            &late.id,
            MlsKeyPackageClaimTarget::Group(&group_id),
            device,
        ))
        .await
        .expect("claim KeyPackage for subsecond deadline check")
        .expect("ordinary KeyPackage must be claimable");
    assert!(
        store
            .consume_claim(&late.id, &group_id, 20_900, None)
            .await
            .expect("consume after fractional deadline")
            .is_none(),
        "a consume at 20.900s must not pass a 20.500s deadline"
    );
    let late = store
        .get(&late.id)
        .await
        .expect("reload late KeyPackage")
        .expect("late KeyPackage remains as terminal audit state");
    assert_eq!(
        late.lifecycle()
            .expect("valid late KeyPackage lifecycle")
            .claim_state,
        super::PersistedKeyPackageClaimState::Revoked
    );
    assert!(
        store
            .try_claim(mls_claim(
                &consumed.id,
                MlsKeyPackageClaimTarget::Retire,
                device
            ))
            .await
            .expect("attempt to retire consumed KeyPackage")
            .is_none()
    );

    store
        .try_claim(mls_claim(
            &revoked.id,
            MlsKeyPackageClaimTarget::Revoke,
            device,
        ))
        .await
        .expect("revoke published KeyPackage")
        .expect("published KeyPackage must be revocable");
    assert!(
        store
            .try_claim(mls_claim(
                &revoked.id,
                MlsKeyPackageClaimTarget::Retire,
                device
            ))
            .await
            .expect("attempt to retire revoked KeyPackage")
            .is_none()
    );

    let group_rows = store
        .list_claimed_by_group(&group_id)
        .await
        .expect("query claimed KeyPackages");
    assert_eq!(
        group_rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([claimed.id.as_str(), consumed.id.as_str()])
    );
    assert!(
        store
            .list_claimed_by_group("retired")
            .await
            .expect("query retired sentinel")
            .is_empty()
    );
    assert!(
        store
            .list_claimed_by_group("revoked")
            .await
            .expect("query revoked sentinel")
            .is_empty()
    );

    let replayed = store
        .get(&published.id)
        .await
        .expect("reload retired KeyPackage")
        .expect("retired KeyPackage remains durable");
    assert_eq!(
        replayed
            .lifecycle()
            .expect("valid retired lifecycle")
            .claim_state,
        super::PersistedKeyPackageClaimState::Retired
    );
    let revoked = store
        .get(&revoked.id)
        .await
        .expect("reload explicitly revoked KeyPackage")
        .expect("revoked KeyPackage remains durable");
    assert_eq!(
        revoked
            .lifecycle()
            .expect("valid revoked lifecycle")
            .claim_state,
        super::PersistedKeyPackageClaimState::Revoked
    );
}

/// `device` is a confirmed, unrevoked device authorization the adapter's
/// current device inventory already carries.
pub async fn assert_last_resort_claim_ledger_contract(
    store: &dyn MlsKeyPackageStore,
    accounts: &dyn super::AccountStore,
    namespace: &str,
    device: &DeviceRevocationGateSelector,
) {
    let owner_account_pk = mls_keypackage_contract_account(accounts, device).await;
    let mut keypackage =
        mls_keypackage_contract_row(namespace, "last-resort", owner_account_pk, device);
    keypackage.last_resort = true;
    let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
    keypackage.last_resort_realm_id = Some(realm_id.to_owned());
    store
        .put(&keypackage)
        .await
        .expect("publish last-resort KeyPackage");

    let ledger = |suffix: &str, welcome: &str| PeerKeyPackageClaimLedgerRecord {
        source_id: format!("ak:did_core:web:{namespace}.example"),
        claim_request_id: format!("local-last-resort:{namespace}-{suffix}"),
        request_digest: format!("sha256:{:0>64}", suffix),
        key_package_use: "last_resort".to_owned(),
        state: "last_resort_claimed".to_owned(),
        outcome: Some(serde_json::json!({
            "schema": "soland.last_resort_keypackage_claim.v1",
            "keypackage_id": keypackage.id,
            "keypackage_ref": keypackage.keypackage_ref,
            "keypackage_digest": keypackage.keypackage_digest,
            "claimant": format!("did:web:{namespace}.example"),
            "recipient_principal_id": "ak:did_core:web:bob.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000002",
            "realm_id": realm_id,
            "mls_group_id": format!("group-{namespace}"),
            "strand_id": format!("strand-{namespace}"),
            "nonce": suffix,
            "transaction_time": "2026-07-30T00:00:00Z",
            "response": {
                "claims": [{
                    "keypackage_ref": keypackage.keypackage_ref,
                    "welcome_ref": welcome,
                }]
            }
        })),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: Some(keypackage.id.clone()),
        claim_expires_at_unix_ms: Some(20_500),
        expires_at: i64::MAX,
        updated_at: 10,
    };
    let first = ledger("01", "welcome-01");
    let second = ledger("02", "welcome-02");
    let group_id = format!("group-{namespace}");

    for claim in [&first, &second] {
        assert!(matches!(
            store
                .try_claim_peer(PeerKeyPackageClaimAttempt {
                    keypackage_id: &keypackage.id,
                    mls_group_id: &group_id,
                    device_authorize_event_id: None,
                    agent_key_authorize_event_id: None,
                    device_revocation_gate: None,
                    claimed_at_unix_ms: 10_000,
                    claim_expires_at_unix_ms: 20_500,
                    ledger: claim,
                })
                .await
                .expect("claim reusable last-resort KeyPackage"),
            PeerKeyPackageClaimAttemptResult::Claimed(_)
        ));
    }
    assert_eq!(
        store
            .record_peer_claim_terminal(&first)
            .await
            .expect("replay first last-resort claim"),
        PeerKeyPackageClaimLedgerWriteResult::Existing(Box::new(first.clone()))
    );
    assert_eq!(
        store
            .get_peer_claim(&first.source_id, &first.claim_request_id)
            .await
            .expect("reload first last-resort claim"),
        Some(first.clone())
    );
    assert_eq!(
        store
            .get_peer_claim(&second.source_id, &second.claim_request_id)
            .await
            .expect("reload second last-resort claim"),
        Some(second.clone())
    );
    let concurrent_receipt = serde_json::json!({"receipt": "first-writer"});
    let (left, right) = tokio::join!(
        store.attach_peer_claim_consume_receipt(
            &first.source_id,
            &first.claim_request_id,
            &first.request_digest,
            &concurrent_receipt,
            11_000,
        ),
        store.attach_peer_claim_consume_receipt(
            &first.source_id,
            &first.claim_request_id,
            &first.request_digest,
            &concurrent_receipt,
            12_000,
        )
    );
    let attached = [
        left.expect("first concurrent last-resort consume"),
        right.expect("second concurrent last-resort consume"),
    ];
    assert_eq!(attached.iter().filter(|record| record.is_some()).count(), 1);
    let replayed = store
        .get_peer_claim(&first.source_id, &first.claim_request_id)
        .await
        .expect("reload concurrent last-resort consume winner")
        .expect("consume winner is durable");
    assert_eq!(replayed.state, "consumed");
    assert_eq!(replayed.consume_receipt, Some(concurrent_receipt));
    assert!(
        store
            .attach_peer_claim_consume_receipt(
                &second.source_id,
                &second.claim_request_id,
                &second.request_digest,
                &serde_json::json!({"receipt": "too-late"}),
                20_900,
            )
            .await
            .expect("late last-resort consume is checked atomically")
            .is_none()
    );
    let expired = store
        .get_peer_claim(&second.source_id, &second.claim_request_id)
        .await
        .expect("reload expired last-resort audit")
        .expect("expired last-resort audit remains durable");
    assert_eq!(expired.state, "expired");
    assert_eq!(expired.outcome, second.outcome.clone());
    assert!(expired.consume_receipt.is_none());
    assert!(
        store
            .revoke_expired_peer_claims(20_900)
            .await
            .expect("run expired-claim maintenance after atomic expiry")
            .is_empty()
    );
    let reusable = store
        .get(&keypackage.id)
        .await
        .expect("reload last-resort KeyPackage")
        .expect("last-resort KeyPackage remains durable");
    assert!(reusable.claimed_by_mls_group_id.is_none());
    assert_eq!(
        reusable
            .lifecycle()
            .expect("valid last-resort lifecycle")
            .claim_state,
        super::PersistedKeyPackageClaimState::Available
    );

    let mut delayed_source = ledger("03", "welcome-03");
    delayed_source.keypackage_id = None;
    assert_eq!(
        store
            .record_peer_claim_terminal(&delayed_source)
            .await
            .expect("record remote last-resort source mirror"),
        PeerKeyPackageClaimLedgerWriteResult::Inserted
    );
    assert!(
        store
            .revoke_expired_peer_claims(20_900)
            .await
            .expect("expire delayed source mirror")
            .is_empty()
    );
    let delayed_outcome = delayed_source.outcome.as_ref().expect("claim outcome");
    let delayed_receipt = serde_json::json!({"receipt": "signed-before-deadline"});
    let recovered = store
        .transition_peer_claim_consumed(
            &delayed_source.source_id,
            &delayed_source.claim_request_id,
            &delayed_source.request_digest,
            delayed_outcome,
            &delayed_receipt,
            20_400,
        )
        .await
        .expect("recover delayed consumed query")
        .expect("signed pre-deadline consume supersedes local expiry inference");
    assert_eq!(recovered.state, "consumed");
    assert_eq!(recovered.key_package_use, "last_resort");
    assert_eq!(recovered.keypackage_id, None);
    assert_eq!(recovered.outcome.as_ref(), Some(delayed_outcome));
    assert_eq!(recovered.consume_receipt, Some(delayed_receipt.clone()));
    assert!(
        store
            .transition_peer_claim_consumed(
                &delayed_source.source_id,
                &delayed_source.claim_request_id,
                &delayed_source.request_digest,
                delayed_outcome,
                &serde_json::json!({"receipt": "drift"}),
                20_400,
            )
            .await
            .expect("replay source consumed transition")
            .is_none()
    );

    let mut terminal_source = ledger("04", "welcome-04");
    terminal_source.keypackage_id = None;
    assert_eq!(
        store
            .record_peer_claim_terminal(&terminal_source)
            .await
            .expect("record remote terminal source mirror"),
        PeerKeyPackageClaimLedgerWriteResult::Inserted
    );
    let terminal_outcome = terminal_source.outcome.as_ref().expect("terminal outcome");
    assert!(
        store
            .transition_peer_claim_terminal(PeerClaimTerminalTransition {
                source_id: &terminal_source.source_id,
                claim_request_id: &terminal_source.claim_request_id,
                request_digest: &terminal_source.request_digest,
                expected_outcome: &serde_json::json!({"response": {"claims": ["drift"]}}),
                terminal_state: "revoked",
                terminal_receipt: &serde_json::json!({"receipt": "terminal"}),
                now_unix_ms: 19_000,
            },)
            .await
            .expect("reject terminal outcome drift")
            .is_none()
    );
    let terminal_receipt = serde_json::json!({"receipt": "terminal"});
    let terminal = store
        .transition_peer_claim_terminal(PeerClaimTerminalTransition {
            source_id: &terminal_source.source_id,
            claim_request_id: &terminal_source.claim_request_id,
            request_digest: &terminal_source.request_digest,
            expected_outcome: terminal_outcome,
            terminal_state: "revoked",
            terminal_receipt: &terminal_receipt,
            now_unix_ms: 19_000,
        })
        .await
        .expect("transition source mirror terminally")
        .expect("existing claimed source mirror must transition");
    assert_eq!(terminal.state, "revoked");
    assert_eq!(terminal.key_package_use, "last_resort");
    assert_eq!(terminal.keypackage_id, None);
    assert_eq!(terminal.outcome.as_ref(), Some(terminal_outcome));
    assert_eq!(terminal.terminal_receipt, Some(terminal_receipt.clone()));
    assert!(
        store
            .transition_peer_claim_terminal(PeerClaimTerminalTransition {
                source_id: &terminal_source.source_id,
                claim_request_id: &terminal_source.claim_request_id,
                request_digest: &terminal_source.request_digest,
                expected_outcome: terminal_outcome,
                terminal_state: "revoked",
                terminal_receipt: &terminal_receipt,
                now_unix_ms: 19_500,
            },)
            .await
            .expect("replay terminal source transition")
            .is_none()
    );
    let terminal_winner = store
        .get_peer_claim(
            &terminal_source.source_id,
            &terminal_source.claim_request_id,
        )
        .await
        .expect("reload terminal source winner")
        .expect("terminal source winner is durable");
    assert_eq!(terminal_winner, terminal);

    let late_attempt = ledger("05", "welcome-05");
    assert!(matches!(
        store
            .try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: &keypackage.id,
                mls_group_id: &group_id,
                device_authorize_event_id: None,
                agent_key_authorize_event_id: None,
                device_revocation_gate: None,
                claimed_at_unix_ms: 20_900,
                claim_expires_at_unix_ms: 20_500,
                ledger: &late_attempt,
            })
            .await
            .expect("claim after fractional deadline"),
        PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable
    ));
}

fn account_status_base_time() -> chrono::DateTime<Utc> {
    "2026-08-16T00:00:00.000Z"
        .parse()
        .expect("account-status fixture base timestamp")
}

fn account_status_fixture_proof(
    verification_method: &DidUrl,
    payload_digest: Hash,
    created_at: chrono::DateTime<Utc>,
) -> PayloadProof {
    PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..account-status-contract-fixture".to_owned(),
    }
}

fn account_status_record(
    account_id: &str,
    status_seq: u64,
    previous: Option<AccountStatusRecordId>,
    binding_version: u64,
    status: AccountStatus,
    issued_offset: i64,
) -> AccountStatusRecord {
    let issued_at = account_status_base_time() + Duration::seconds(issued_offset);
    let verification_method = DidUrl::new("did:web:authority.example#account-status-key")
        .expect("account authority verification method");
    let unsigned = UnsignedAccountStatusRecord {
        schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
        account_authority_id: DidCoreId::new("ak:did_core:web:authority.example")
            .expect("account authority core id"),
        account_id: arkret_wire::AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{account_id}.example"))
                .expect("principal core id"),
            DidCoreId::new("ak:did_core:web:principal.example").expect("Station core id"),
        ),
        principal_control_realm_id: RealmId::new(
            "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
        )
        .expect("principal control realm id"),
        binding_version,
        status_seq,
        previous_account_status_record_id: previous,
        status,
        reason_code: None,
        reason: None,
        issued_at,
        effective_at: issued_at,
        expires_at: None,
    };
    let proof = account_status_fixture_proof(
        &verification_method,
        unsigned.payload_digest().expect("record payload digest"),
        unsigned.issued_at,
    );
    unsigned
        .attach_proof(proof)
        .expect("account-status record fixture is valid")
}

fn account_status_receipt(record: &AccountStatusRecord, suffix: u32) -> AccountStatusReceipt {
    let accepted_at = account_status_base_time() + Duration::seconds(600 + i64::from(suffix));
    let unsigned = UnsignedAccountStatusReceipt {
        receipt_id: ReceiptId::new(format!("ak:receipt:01904100-0000-7000-8000-{suffix:012}"))
            .expect("account-status receipt id"),
        account_status_record_id: record.account_status_record_id.clone(),
        record_digest: record.payload_digest().expect("record payload digest"),
        account_authority_id: record.account_authority_id.clone(),
        account_id: record.account_id.clone(),
        status_seq: record.status_seq,
        receiver_id: DidCoreId::new("ak:did_core:web:receiver.example").expect("receiver core id"),
        accepted_at,
        verification_method: DidUrl::new("did:web:receiver.example#notary-key")
            .expect("receiver verification method"),
    };
    let proof = account_status_fixture_proof(
        &unsigned.verification_method,
        unsigned.payload_digest().expect("receipt payload digest"),
        unsigned.accepted_at,
    );
    unsigned
        .attach_proof(proof)
        .expect("account-status receipt fixture is valid")
}

/// Exercises every row of the canonical account-status replica decision table
/// (`account-status-replica-decision-table.json`, the machine-readable form of
/// `zh/identity/account-lifecycle.md` section 3.1) against one backend. The
/// durable replica head is the only comparison baseline, so every adapter must
/// return the same typed outcome for the same submission.
pub async fn assert_account_status_replica_decision_table_contract(
    store: &dyn AccountStatusReplicaStore,
    namespace: &str,
) {
    let account_label = format!("account-{namespace}");
    let genesis = account_status_record(&account_label, 1, None, 2, AccountStatus::Active, 1);
    let account_id = genesis.account_id.clone();
    let authority = genesis.account_authority_id.as_str().to_owned();
    let second = account_status_record(
        &account_label,
        2,
        Some(genesis.account_status_record_id.clone()),
        2,
        AccountStatus::Suspended,
        2,
    );
    let third = account_status_record(
        &account_label,
        3,
        Some(second.account_status_record_id.clone()),
        2,
        AccountStatus::Locked,
        3,
    );

    // genesis_gap: with no durable head a non-genesis submission stays
    // retryable behind required_status_seq = 1 and writes nothing.
    assert_eq!(
        store
            .append(&second, &account_status_receipt(&second, 1))
            .await
            .expect("classify a submission against an absent head"),
        AccountStatusReplicaAppend::DependencyMissing {
            current_record: None,
            required_status_seq: 1,
        }
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        None
    );
    assert_eq!(
        store
            .receipt(&authority, &account_id, 2)
            .await
            .expect("read the receipt for the rejected sequence"),
        None
    );

    // genesis_admission.
    let genesis_receipt = account_status_receipt(&genesis, 2);
    assert_eq!(
        store
            .append(&genesis, &genesis_receipt)
            .await
            .expect("admit the genesis record"),
        AccountStatusReplicaAppend::Accepted(genesis_receipt.clone())
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        Some(genesis.clone())
    );

    // duplicate: the durable head already is the submitted record, so the
    // originally accepted receipt is replayed and nothing is rewritten.
    assert_eq!(
        store
            .append(&genesis, &account_status_receipt(&genesis, 3))
            .await
            .expect("replay the durable head"),
        AccountStatusReplicaAppend::Duplicate(genesis_receipt.clone())
    );
    assert_eq!(
        store
            .receipt(&authority, &account_id, 1)
            .await
            .expect("read the genesis receipt"),
        Some(genesis_receipt.clone())
    );

    // fork_same_sequence: a different record at the head sequence.
    let rival_genesis = account_status_record(&account_label, 1, None, 2, AccountStatus::Active, 4);
    assert_eq!(
        store
            .append(&rival_genesis, &account_status_receipt(&rival_genesis, 4))
            .await
            .expect("classify a rival genesis record"),
        AccountStatusReplicaAppend::Conflict {
            current_record: Some(genesis.clone()),
            kind: AccountStatusReplicaConflictKind::Fork,
        }
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        Some(genesis.clone())
    );

    // fork_predecessor_mismatch: the next sequence that does not name the head.
    let forked_successor = account_status_record(
        &account_label,
        2,
        Some(rival_genesis.account_status_record_id.clone()),
        2,
        AccountStatus::Suspended,
        5,
    );
    assert_eq!(
        store
            .append(
                &forked_successor,
                &account_status_receipt(&forked_successor, 5)
            )
            .await
            .expect("classify a successor with a foreign predecessor"),
        AccountStatusReplicaAppend::Conflict {
            current_record: Some(genesis.clone()),
            kind: AccountStatusReplicaConflictKind::Fork,
        }
    );
    assert_eq!(
        store
            .receipt(&authority, &account_id, 2)
            .await
            .expect("read the receipt for the rejected sequence"),
        None
    );

    // sequence_gap.
    assert_eq!(
        store
            .append(&third, &account_status_receipt(&third, 6))
            .await
            .expect("classify a submission beyond the next sequence"),
        AccountStatusReplicaAppend::DependencyMissing {
            current_record: Some(genesis.clone()),
            required_status_seq: 2,
        }
    );
    assert_eq!(
        store
            .receipt(&authority, &account_id, 3)
            .await
            .expect("read the receipt for the rejected sequence"),
        None
    );

    // binding_version_rollback is evaluated before the advance row, so a rolled
    // back binding at head + 1 is rejected instead of advancing the chain.
    let rollback_successor = account_status_record(
        &account_label,
        2,
        Some(genesis.account_status_record_id.clone()),
        1,
        AccountStatus::Suspended,
        7,
    );
    assert_eq!(
        store
            .append(
                &rollback_successor,
                &account_status_receipt(&rollback_successor, 7)
            )
            .await
            .expect("classify a rolled back binding at the next sequence"),
        AccountStatusReplicaAppend::Conflict {
            current_record: Some(genesis.clone()),
            kind: AccountStatusReplicaConflictKind::BindingRollback,
        }
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        Some(genesis.clone())
    );
    assert_eq!(
        store
            .receipt(&authority, &account_id, 2)
            .await
            .expect("read the receipt for the rejected sequence"),
        None
    );

    // advance, twice, so the head sits above a retained history row.
    let second_receipt = account_status_receipt(&second, 8);
    assert_eq!(
        store
            .append(&second, &second_receipt)
            .await
            .expect("advance to the second record"),
        AccountStatusReplicaAppend::Accepted(second_receipt.clone())
    );
    let third_receipt = account_status_receipt(&third, 9);
    assert_eq!(
        store
            .append(&third, &third_receipt)
            .await
            .expect("advance to the third record"),
        AccountStatusReplicaAppend::Accepted(third_receipt)
    );
    let other_station_account = arkret_wire::AccountId::new(
        account_id.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other-station.example").expect("other Station"),
    );
    assert_eq!(
        store
            .current(&authority, &other_station_account)
            .await
            .expect("read another Station account"),
        None,
        "the same principal at another Station must not share the replica head"
    );
    assert!(
        store
            .resolve(&authority, &other_station_account, 1, 16)
            .await
            .expect("resolve another Station account")
            .is_empty()
    );
    assert_eq!(
        store
            .receipt(&authority, &other_station_account, 1)
            .await
            .expect("read another Station receipt"),
        None
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        Some(third.clone())
    );

    // stale is unconditional. The receiver still stores the byte-identical
    // history row for status_seq 2, and local retention must never turn a
    // below-head submission into a duplicate terminal ack.
    assert_eq!(
        store
            .receipt(&authority, &account_id, 2)
            .await
            .expect("read the retained history receipt"),
        Some(second_receipt.clone()),
        "the history row for the resubmitted sequence must still be retained"
    );
    assert_eq!(
        store
            .append(&second, &account_status_receipt(&second, 10))
            .await
            .expect("classify a byte-identical resubmission below the head"),
        AccountStatusReplicaAppend::Stale {
            current_record: third.clone(),
        }
    );
    assert_eq!(
        store
            .receipt(&authority, &account_id, 2)
            .await
            .expect("read the retained history receipt"),
        Some(second_receipt),
        "a stale classification must not rewrite the retained history row"
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        Some(third.clone())
    );

    // stale also covers a different record below the head: the head decides,
    // never the retained history row.
    let rival_second = account_status_record(
        &account_label,
        2,
        Some(genesis.account_status_record_id.clone()),
        2,
        AccountStatus::Suspended,
        11,
    );
    assert_eq!(
        store
            .append(&rival_second, &account_status_receipt(&rival_second, 11))
            .await
            .expect("classify a rival record below the head"),
        AccountStatusReplicaAppend::Stale {
            current_record: third.clone(),
        }
    );

    // binding_version_rollback still precedes the sequence rows below the head.
    let rollback_below_head = account_status_record(
        &account_label,
        2,
        Some(genesis.account_status_record_id.clone()),
        1,
        AccountStatus::Suspended,
        12,
    );
    assert_eq!(
        store
            .append(
                &rollback_below_head,
                &account_status_receipt(&rollback_below_head, 12)
            )
            .await
            .expect("classify a rolled back binding below the head"),
        AccountStatusReplicaAppend::Conflict {
            current_record: Some(third.clone()),
            kind: AccountStatusReplicaConflictKind::BindingRollback,
        }
    );
    assert_eq!(
        store
            .current(&authority, &account_id)
            .await
            .expect("read the replica head"),
        Some(third.clone())
    );
    assert_eq!(
        store
            .resolve(&authority, &account_id, 1, 16)
            .await
            .expect("resolve the durable chain"),
        vec![genesis, second, third]
    );
}

pub async fn assert_realm_meta_store_contract(store: &dyn RealmMetaStore, namespace: &str) {
    let now = database_timestamp_now();
    let realm_id = format!("ak:realm:{namespace}");
    let record = RealmMetaRecord {
        owner: format!("did:web:{namespace}-owner.example"),
        deleted: false,
        discoverability: "public".to_owned(),
        history_access: "all_history_for_current_members".to_owned(),
        preview_policy: Some(serde_json::json!({"enabled": true})),
        preview_policy_digest: Some(format!("sha256:{}", "2".repeat(64))),
        asset_privacy_policy: Some(serde_json::json!({"presign": "members"})),
        asset_privacy_policy_digest: Some(format!("sha256:{}", "3".repeat(64))),
        encryption_profile: Some("mls_rfc9420".to_owned()),
        plaintext_visible_services: std::collections::BTreeSet::from([
            "ak:service:directory".to_owned()
        ]),
        plaintext_visible_service_classes: std::collections::BTreeMap::from([(
            "ak:service:directory".to_owned(),
            std::collections::BTreeSet::from([arkret_wire::PlaintextDataClassKind::HistoryPreview]),
        )]),
        minimal_metadata_realm: true,
        created_at: now,
        updated_at: now,
    };
    store
        .put(&realm_id, &record)
        .await
        .expect("write realm meta");
    assert_eq!(
        store.get(&realm_id).await.expect("read realm meta"),
        Some(record.clone()),
        "realm meta must round-trip every field"
    );
    assert!(
        store
            .list()
            .await
            .expect("list realm meta")
            .iter()
            .any(|(id, meta)| id == &realm_id && meta == &record)
    );

    let mut updated = record.clone();
    updated.owner = format!("did:web:{namespace}-successor.example");
    updated.updated_at = now + Duration::seconds(1);
    store
        .put(&realm_id, &updated)
        .await
        .expect("overwrite realm meta");
    assert_eq!(
        store.get(&realm_id).await.expect("read updated realm meta"),
        Some(updated),
        "realm meta put must upsert in place"
    );

    store.delete(&realm_id).await.expect("delete realm meta");
    assert_eq!(
        store.get(&realm_id).await.expect("read deleted realm meta"),
        None
    );
}

pub async fn assert_message_store_contract(store: &dyn MessageStore, namespace: &str) {
    let now = database_timestamp_now();
    let realm_id = format!("ak:realm:{namespace}");
    let thread_id = format!("ak:strand:{namespace}");
    let first = MessageRecord {
        event_id: format!("ak:event:{namespace}-first"),
        message_id: format!("ak:message:{namespace}-first"),
        realm_id: realm_id.clone(),
        sender: format!("did:web:{namespace}-alice.example"),
        thread_id: thread_id.clone(),
        content: serde_json::json!({"body": "first"}),
        encrypted: false,
        created_at: now,
    };
    let second = MessageRecord {
        event_id: format!("ak:event:{namespace}-second"),
        message_id: format!("ak:message:{namespace}-second"),
        realm_id: realm_id.clone(),
        sender: format!("did:web:{namespace}-bob.example"),
        thread_id: thread_id.clone(),
        content: serde_json::json!({"body": "second"}),
        encrypted: true,
        created_at: now + Duration::seconds(1),
    };
    store.put(&first).await.expect("write first message");
    store.put(&second).await.expect("write second message");
    // Replayed projection writes must dedup idempotently, not double-store.
    store.put(&first).await.expect("replay first message");
    assert_eq!(
        store
            .get(&first.event_id)
            .await
            .expect("read first message"),
        Some(first.clone())
    );
    assert_eq!(
        store
            .list_for_realm(&realm_id, 100)
            .await
            .expect("list realm messages"),
        vec![second.clone(), first.clone()],
        "realm listing is newest first"
    );
    assert_eq!(
        store
            .list_for_realm(&realm_id, 1)
            .await
            .expect("list realm messages with limit"),
        vec![second.clone()]
    );
    assert_eq!(
        store
            .list_for_thread(&thread_id, 100)
            .await
            .expect("list thread messages"),
        vec![first.clone(), second.clone()],
        "thread listing is chronological"
    );

    store
        .delete(&first.event_id)
        .await
        .expect("delete first message");
    assert_eq!(
        store
            .get(&first.event_id)
            .await
            .expect("read deleted message"),
        None
    );
    assert_eq!(
        store
            .list_for_realm(&realm_id, 100)
            .await
            .expect("list realm messages after delete"),
        vec![second]
    );
}

pub async fn assert_device_key_store_contract(
    store: &dyn DeviceKeyStore,
    authorization: &DeviceRevocationGateSelector,
) {
    let actor = authorization.principal_id.to_string();
    let device_id = authorization.device_id.clone();
    let bundle = serde_json::json!({
        "device_id": device_id,
        "one_time_keys": {"curve25519:aaa": {"key": "aaa"}},
        "fallback_keys": {},
    });
    store
        .put(authorization, bundle.clone())
        .await
        .expect("write device key bundle");
    assert_eq!(
        store
            .get(&actor, &device_id)
            .await
            .expect("read device key bundle"),
        Some(bundle)
    );
    assert_eq!(
        store
            .get(&actor, "ak:device:01904100-0000-7000-8000-000000000099")
            .await
            .expect("read missing device key bundle"),
        None
    );

    let rotated = serde_json::json!({"device_id": device_id, "rotated": true});
    store
        .put(authorization, rotated.clone())
        .await
        .expect("overwrite device key bundle");
    assert_eq!(
        store
            .get(&actor, &device_id)
            .await
            .expect("read rotated device key bundle"),
        Some(rotated),
        "bundle upload must upsert in place"
    );
}

pub async fn assert_one_time_key_store_contract(
    store: &dyn OneTimeKeyStore,
    namespace: &str,
    authorization: &DeviceRevocationGateSelector,
) {
    let actor = authorization.principal_id.to_string();
    let device_id = authorization.device_id.clone();
    let key_a = serde_json::json!({"key_id": format!("curve25519:{namespace}-a"), "key": "a"});
    let key_b = serde_json::json!({"key_id": format!("curve25519:{namespace}-b"), "key": "b"});
    store
        .put(authorization, vec![key_a.clone(), key_b.clone()])
        .await
        .expect("seed one-time key pool");
    assert_eq!(
        store
            .claim(&actor, &device_id)
            .await
            .expect("claim first key"),
        Some(key_b),
        "claim pops the most recently pooled key exactly once"
    );
    assert_eq!(
        store
            .claim(&actor, &device_id)
            .await
            .expect("claim second key"),
        Some(key_a)
    );
    assert_eq!(
        store
            .claim(&actor, &device_id)
            .await
            .expect("claim drained pool"),
        None,
        "a drained pool stays drained"
    );

    let key_c = serde_json::json!({"key_id": format!("curve25519:{namespace}-c"), "key": "c"});
    store
        .put(authorization, vec![key_c.clone()])
        .await
        .expect("replace one-time key pool");
    assert_eq!(
        store
            .claim(&actor, &device_id)
            .await
            .expect("claim replaced key"),
        Some(key_c),
        "put replaces the pool left by earlier claims"
    );
    assert_eq!(
        store
            .claim(&actor, &device_id)
            .await
            .expect("claim drained again"),
        None
    );
}

pub async fn assert_member_identity_store_contract(
    store: &dyn MemberIdentityStore,
    namespace: &str,
) {
    let claim = HandleClaimEvidenceRecord {
        digest: format!("sha256:{}", "c".repeat(64)),
        subject_id: arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example"))
            .unwrap(),
        issuer_id: arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:{namespace}-issuer.example"
        ))
        .unwrap(),
        audience: Some("ak:service:directory".to_owned()),
        status: "verified".to_owned(),
        revocation_digest: None,
        fresh_until: database_timestamp_now() + Duration::minutes(5),
        visibility: Some("public".to_owned()),
        expires_at: Some(database_timestamp_now() + Duration::hours(1)),
        envelope: serde_json::json!({"subject_id": format!("ak:did_core:web:{namespace}.example")}),
    };
    store
        .put_handle_claim(&claim)
        .await
        .expect("cache handle claim");
    let mut revoked = claim.clone();
    revoked.status = "revoked".to_owned();
    revoked.revocation_digest = Some(format!("sha256:{}", "d".repeat(64)));
    store
        .put_handle_claim(&revoked)
        .await
        .expect("upsert revoked handle claim");
    assert_eq!(
        store
            .snapshot_handle_claims()
            .await
            .expect("snapshot handle claims")
            .into_iter()
            .filter(|row| row.subject_id == claim.subject_id)
            .collect::<Vec<_>>(),
        vec![revoked],
        "claim upsert replaces the row under the same digest"
    );
    assert_eq!(
        store
            .delete_handle_claims_for_subject(&claim.subject_id)
            .await
            .expect("invalidate handle claims"),
        1
    );
    assert!(
        store
            .snapshot_handle_claims()
            .await
            .expect("snapshot handle claims after invalidate")
            .iter()
            .all(|row| row.subject_id != claim.subject_id)
    );
}

/// Shared behaviour every `InviteNewSourceLedgerStore` backend must reproduce
/// (`identity/consent-model.md` sections 6.1.1.3 and 6.1.1.4).
///
/// The two backends have completely different concurrency stories -- one lock
/// versus one PostgreSQL transaction -- so the ledger contract has to be proved
/// on both rather than on the in-memory one alone.
pub async fn assert_invite_new_source_ledger_contract(
    ledger: &dyn super::InviteNewSourceLedgerStore,
    accounts: &dyn super::AccountStore,
    namespace: &str,
) {
    let holder = arkret_wire::AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{namespace}.example")).unwrap(),
        DidCoreId::new("ak:did_core:web:soland.example").unwrap(),
    );
    accounts
        .put(&super::AccountRecord {
            pk: AccountPk(0),
            principal_id: holder.principal_id.clone(),
            station_id: holder.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: database_timestamp_now(),
        })
        .await
        .expect("register new-source ledger holder");

    let now = database_timestamp_now();
    let quota = arkret_wire::receive_policy::EffectiveNewSourceQuota {
        window_seconds: 3_600,
        new_sources_per_window: 2,
        retention_seconds: 7_200,
        new_sources_per_retention: 3,
    };

    // Two first contacts fit under both ceilings.
    for suffix in ["a", "b"] {
        assert_eq!(
            ledger
                .admit_new_source(&holder, &format!("{namespace}-{suffix}"), now, &quota)
                .await
                .expect("admit new source"),
            super::NewSourceAdmission::Admitted,
            "a source inside both ceilings must be admitted"
        );
    }

    // An already-charged source is seen, not new, so it is admitted without
    // consuming quota.
    assert_eq!(
        ledger
            .admit_new_source(&holder, &format!("{namespace}-a"), now, &quota)
            .await
            .expect("re-admit seen source"),
        super::NewSourceAdmission::Seen
    );

    // The third distinct source is over the short window.
    assert_eq!(
        ledger
            .admit_new_source(&holder, &format!("{namespace}-c"), now, &quota)
            .await
            .expect("evaluate over-quota source"),
        super::NewSourceAdmission::Denied
    );
    assert_eq!(
        ledger
            .retained_source_count(&holder)
            .await
            .expect("count ledger rows"),
        2,
        "a denied source must not be written, or the next window would read it as seen"
    );

    // Sliding the short window forward frees rate but keeps the retention
    // total, so the previously denied source is now admitted.
    let later = now + Duration::seconds(4_000);
    assert_eq!(
        ledger
            .admit_new_source(&holder, &format!("{namespace}-c"), later, &quota)
            .await
            .expect("admit after the short window slid"),
        super::NewSourceAdmission::Admitted
    );

    // The retention total is now full: a fourth distinct source is denied even
    // though the short window has room.
    assert_eq!(
        ledger
            .admit_new_source(&holder, &format!("{namespace}-d"), later, &quota)
            .await
            .expect("evaluate over-retention source"),
        super::NewSourceAdmission::Denied
    );

    // Past the retention window every row expires, so a brand new contact is
    // admitted again and the expired rows are physically gone.
    let past_retention = now + Duration::seconds(12_000);
    assert_eq!(
        ledger
            .admit_new_source(&holder, &format!("{namespace}-e"), past_retention, &quota)
            .await
            .expect("admit after retention expiry"),
        super::NewSourceAdmission::Admitted
    );
    assert_eq!(
        ledger
            .retained_source_count(&holder)
            .await
            .expect("count ledger rows after prune"),
        1,
        "expired rows must be pruned, not merely ignored"
    );

    // Erasure drops the holder's whole ledger.
    ledger
        .delete_for_holder(&holder)
        .await
        .expect("delete ledger for holder");
    assert_eq!(
        ledger
            .retained_source_count(&holder)
            .await
            .expect("count ledger rows after erasure"),
        0
    );
}
