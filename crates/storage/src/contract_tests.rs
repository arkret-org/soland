use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPrincipalAuthority, AccountStatusReceipt, AccountStatusRecord,
    UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::{
    OrganizationControlProofKind, OrganizationRegistrationChallenge,
    OrganizationRegistrationOutcome, OrganizationRegistrationReceipt,
    OrganizationRegistrationScope, OrganizationRegistrationStatus, ServiceRouteHandoverNotice,
    ServiceRouteHandoverNoticeCore, ServiceRouteHandoverState,
};
use arkret_state::state::store::ControlProposalIngress;
use arkret_wire::{
    AccountStatusRecordId, DidCoreId, DidFullId, DidUrl, Hash, NonEmptyString, PayloadProof,
    ProofContextId, ProtocolSignature, RealmId, ReceiptId, SchemaId, project_full_id_to_core_id,
};
use chrono::{Duration, Utc};

use super::{
    AccountStatusReplicaAppend, AccountStatusReplicaConflictKind, AccountStatusReplicaStore,
    CanonicalEventRecord, ContactProjectionCommit, ContactRecord, ContactStore,
    ControlProposalAuthorityAckRecord, ControlProposalAuthorityAckStore, DeviceInventoryRecord,
    DeviceInventoryStore, DeviceKeyStore, DeviceMessageBatchCommitOutcome,
    DeviceMessageBatchItemRecord, DeviceMessageBatchRecord, DeviceMessageRecord,
    DeviceMessageStore, DeviceMessageTargetSnapshotGuard, DevicePairingAuthorizationCommit,
    DevicePairingRecord, DevicePairingStore, DeviceRevocationGateSelector, EventCommitRequest,
    EventCommitUnitOfWork, EventStore, ExactWriteOutcome, FederationOutboxClaim,
    FederationOutboxDeadLetterRecord, FederationOutboxOutcome, FederationOutboxPolicyResolution,
    FederationOutboxRecord, FederationOutboxRequeue, FederationOutboxState, FederationOutboxStore,
    FederationOutboxTransition, GovernanceDependencyStore, HandleClaimEvidenceRecord,
    IdempotencyRecord, IdempotencyStore, InviteReceivePolicyStore, MemberIdentityEventRecord,
    MemberIdentityReplacementEdge, MemberIdentityStore, MemberIdentitySubjectKey, MessageRecord,
    MessageStore, MimiConsentCorrelationRecord, MimiConsentCorrelationStore, MlsKeyPackageClaim,
    MlsKeyPackageClaimTarget, MlsKeyPackageRow, MlsKeyPackageStore, OneTimeKeyStore,
    OrganizationRegistrationEnsureCommit, OrganizationRegistrationLifecycleCommit,
    OrganizationRegistrationRefreshCommit, OrganizationRegistrationStore,
    OrganizationRegistrationTerminalReason, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, ProjectionEventRecord, ProjectionEventStore,
    RealmFanoutAuthorityWitness, RealmFanoutBinding, RealmMetaRecord, RealmMetaStore,
    ServiceRouteHandoverNoticeCommit, ServiceRouteHandoverNoticeRecord, ServiceRouteHandoverPlan,
    ServiceRouteHandoverPlanState, ServiceRouteHandoverPlanStore, ServiceRouteHandoverPlanWrite,
};

pub fn minimal_history_signer_evidence(
    namespace: &str,
) -> arkret_models_collaboration::governance_dependencies::GovernanceDependency {
    use arkret_models_collaboration::governance_dependencies::{
        GovernanceDependency, GovernanceDependencySelector,
    };
    use arkret_models_collaboration::history_key::{
        AuthorizationIncarnation, HistoryEffectiveScope, MinimalMetadataMlsLeafSignerEvidence,
    };
    use base64::Engine as _;

    let effective_scope = HistoryEffectiveScope::Realm {
        realm_id: RealmId::new("ak:realm:AfjSiYTXJZS-0ifVfy1f_uzsmJIBjDyN11_-dxnne50e")
            .expect("fixture Realm ID"),
    };
    let response_key = arkret_canonical::sha256_bytes(namespace.as_bytes());
    let leaf_node = format!("leaf-node:{namespace}").into_bytes();
    let b64 = |bytes: &[u8]| {
        arkret_wire::Base64UrlString::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        )
        .expect("fixture base64url")
    };
    let digest = |bytes: &[u8]| {
        Hash::new(arkret_canonical::sha256_digest(bytes)).expect("fixture SHA-256 digest")
    };
    let pairwise_actor_id =
        DidCoreId::new("ak:did_core:key:z6MkfixtureService").expect("fixture actor");
    let verification_method =
        DidUrl::new("did:key:z6MkfixtureService#history-response").expect("fixture method");
    let mut identity_link =
        arkret_models_collaboration::objects::profiles::IdentityLink {
            schema: arkret_wire::SchemaId::IDENTITY_LINK_V1.to_owned(),
            status: arkret_models_collaboration::objects::profiles::IdentityLinkStatus::Active,
            pairwise_actor_id: pairwise_actor_id.clone(),
            principal_id: DidCoreId::new("ak:did_core:web:alice.example")
                .expect("fixture principal"),
            device_id: arkret_wire::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000001",
            )
            .expect("fixture device"),
            realm_id: match &effective_scope {
                HistoryEffectiveScope::Realm { realm_id }
                | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id.clone(),
            },
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:example.test")
                .expect("fixture trust domain"),
            strand_id: None,
            track: None,
            mls_group_id: Some(
                effective_scope
                    .canonical_mls_group_id()
                    .expect("fixture MLS group"),
            ),
            mls_leaf_index: 1,
            mls_epoch: 7,
            response_signing_verification_method: verification_method.clone(),
            response_signing_algorithm: arkret_models_collaboration::objects::profiles::IdentityLinkResponseSigningAlgorithm::Ed25519,
            response_signing_public_key_b64u: b64(&response_key),
            response_signing_public_key_digest: digest(&response_key),
            effective_at: Utc::now(),
            expires_at: None,
            disclosure_policy_id: None,
            proof: arkret_models_collaboration::objects::profiles::IdentityLinkProof {
                verification_method: DidUrl::new("did:web:alice.example#identity-link")
                    .expect("fixture IdentityLink proof method"),
                signature_algorithm: "Ed25519".to_owned(),
                payload_digest: digest(b"placeholder IdentityLink payload"),
                signature: "fixture.signature".to_owned(),
            },
        };
    identity_link.proof.payload_digest = identity_link
        .canonical_payload_digest()
        .expect("fixture IdentityLink payload digest");
    identity_link
        .validate_minimal()
        .expect("valid fixture IdentityLink");
    let identity_link = arkret_canonical::canonical_json_bytes(&identity_link)
        .expect("fixture IdentityLink canonical bytes");
    let identity_link_signer_evidence_digest = digest(b"fixture IdentityLink signer evidence");
    let identity_link_signer_evidence_ref = arkret_wire::SignerEvidenceRef::new(format!(
        "ak:signer_evidence:{}",
        identity_link_signer_evidence_digest.as_ref()
    ))
    .expect("fixture IdentityLink signer evidence ref");
    let evidence = MinimalMetadataMlsLeafSignerEvidence {
        mls_group_id: effective_scope
            .canonical_mls_group_id()
            .expect("fixture MLS group"),
        effective_scope,
        epoch: 7,
        leaf_index: 1,
        pairwise_actor_id: pairwise_actor_id.clone(),
        source_actor_id: pairwise_actor_id,
        verification_method,
        response_signing_public_key_b64u: b64(&response_key),
        response_signing_public_key_digest: digest(&response_key),
        identity_link_canonical_bytes_b64u: b64(&identity_link),
        identity_link_digest: digest(&identity_link),
        identity_link_signer_evidence_ref,
        identity_link_signer_evidence_digest,
        leaf_node_canonical_bytes_b64u: b64(&leaf_node),
        leaf_node_digest: digest(&leaf_node),
        winning_group_state_transition_ref: arkret_wire::EventId::new(
            "ak:event:ARrXzX07X_prHPMAeOGPMrI4_sUFneJW2aYSvHN_-9aQ",
        )
        .expect("fixture transition Event"),
        winning_group_state_event_digest: digest(b"fixture group-state event"),
        winning_mls_transition_digest: digest(b"fixture MLS transition"),
        target_basis: arkret_wire::SealBasis {
            leaves: vec![arkret_wire::SealId::new(
                "ak:seal:sha256:272847e37a778e5a559a9d39a039350d544051b28227f016a5f4248ffec154a6",
            )
            .expect("fixture Seal")],
        },
        authorization_incarnation: AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref: arkret_wire::EventId::new(
                "ak:event:AWYr1ucW0vOccjnC8XMFGQK8PjKzaha_YpYb8B0uDY_y",
            )
            .expect("fixture incarnation Event"),
        },
    };
    evidence.validate().expect("valid minimal signer evidence");
    let content_digest = evidence
        .canonical_sha256_digest()
        .expect("fixture evidence digest");
    GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
        selector: GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
            content_digest,
        },
        minimal_metadata_mls_leaf_signer_evidence: evidence,
    }
}

pub async fn assert_governance_unscoped_signer_evidence_contract(
    store: &dyn GovernanceDependencyStore,
    namespace: &str,
) {
    let item = minimal_history_signer_evidence(namespace);
    let selector = item.selector().clone();
    assert_eq!(
        store
            .put_unscoped_signer_evidence_exact(item.clone())
            .await
            .expect("insert unscoped signer evidence"),
        ExactWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .put_unscoped_signer_evidence_exact(item.clone())
            .await
            .expect("exact retry unscoped signer evidence"),
        ExactWriteOutcome::ExactReplay
    );
    assert_eq!(
        store
            .get_unscoped_signer_evidence(&selector)
            .await
            .expect("read unscoped signer evidence"),
        Some(item.clone())
    );
    let realm_id = RealmId::new("ak:realm:AfjSiYTXJZS-0ifVfy1f_uzsmJIBjDyN11_-dxnne50e")
        .expect("fixture Realm ID");
    assert_eq!(
        store
            .put_realm_object_exact(&realm_id, item.clone())
            .await
            .expect("link signer evidence to Realm"),
        ExactWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .put_realm_object_exact(&realm_id, item.clone())
            .await
            .expect("exact retry Realm signer evidence"),
        ExactWriteOutcome::ExactReplay
    );
    assert_eq!(
        store
            .get(&realm_id, &selector)
            .await
            .expect("read Realm signer evidence"),
        Some(item.clone())
    );
    let mut changed = item;
    let arkret_models_collaboration::governance_dependencies::GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
        minimal_metadata_mls_leaf_signer_evidence,
        ..
    } = &mut changed
    else {
        unreachable!("fixture branch")
    };
    minimal_metadata_mls_leaf_signer_evidence.epoch += 1;
    assert!(
        store
            .put_unscoped_signer_evidence_exact(changed)
            .await
            .is_err(),
        "same selector digest with different bytes must fail closed"
    );
}

pub async fn assert_device_message_snapshot_guard_contract(
    inventory: &dyn DeviceInventoryStore,
    messages: &dyn DeviceMessageStore,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let actor = format!("ak:did_core:webvh:z{namespace}");
    let device_a = format!("ak:device:{}", uuid::Uuid::now_v7());
    let device_b = format!("ak:device:{}", uuid::Uuid::now_v7());
    for device_id in [&device_a, &device_b] {
        inventory
            .put(&DeviceInventoryRecord {
                actor: actor.clone(),
                device_id: device_id.clone(),
                display_name: None,
                verification_state: "verified".to_owned(),
                payload: serde_json::json!({"device_id": device_id}),
                created_at: now,
                updated_at: now,
                revoked_at: None,
            })
            .await
            .expect("seed verified target device");
    }
    let request_key = format!("repair:{namespace}");
    let request_digest = format!("sha256:{namespace}");
    let expires_at = now + Duration::days(1);
    let batch = DeviceMessageBatchRecord {
        request_key: request_key.clone(),
        request_digest: request_digest.clone(),
        idempotency_expires_at: expires_at,
        target_snapshot_guard: Some(DeviceMessageTargetSnapshotGuard {
            recipient: actor.clone(),
            devices: vec![(device_a.clone(), now), (device_b.clone(), now)],
        }),
        device_revocation_gate: Some(DeviceRevocationGateSelector {
            principal_id: actor.clone(),
            principal_server_id: "ak:did_core:web:soland.example".to_owned(),
            device_id: "sender-device".to_owned(),
            target_device_authorize_event_id: format!("ak:event:A{}", "a".repeat(43)),
            target_device_generation_ref: 1,
        }),
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
                    position: index as i64 + 1,
                    content: serde_json::json!({"kind":"ak.agent.runtime.command","content":{}}),
                    created_at: now,
                }),
            })
            .collect(),
    };

    let mut revoked = inventory
        .get(&actor, &device_b)
        .await
        .expect("read target device")
        .expect("target exists");
    revoked.revoked_at = Some(now + Duration::seconds(1));
    revoked.updated_at = now + Duration::seconds(1);
    inventory.put(&revoked).await.expect("revoke target device");
    assert_eq!(
        messages
            .commit_batch(batch.clone())
            .await
            .expect("snapshot conflict outcome"),
        DeviceMessageBatchCommitOutcome::SnapshotConflict
    );
    assert!(
        messages
            .list_after(&actor, &device_a, 0)
            .await
            .expect("device A queue")
            .is_empty(),
        "snapshot conflict must enqueue zero targets"
    );

    revoked.revoked_at = None;
    revoked.updated_at = now;
    inventory
        .put(&revoked)
        .await
        .expect("restore original snapshot");
    let stored = messages
        .commit_batch(batch.clone())
        .await
        .expect("commit guarded batch");
    assert!(matches!(stored, DeviceMessageBatchCommitOutcome::Stored(_)));

    revoked.revoked_at = Some(now + Duration::seconds(2));
    revoked.updated_at = now + Duration::seconds(2);
    inventory
        .put(&revoked)
        .await
        .expect("revoke after durable commit");
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
            .list_after(&actor, &device_a, 0)
            .await
            .expect("device A queue")
            .len(),
        1
    );
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
    // `project_full_id_to_core_id` drops the domain — and the namespace hash
    // it carries — so the namespace must also reach the SCID slot, or a rerun
    // on the same database reads the previous run's state as its own.
    let organization_full_id = test_full_id(
        &format!("zOrg{}", &test_hash_hex(namespace)[..12]),
        namespace,
    );
    let organization_id = project_full_id_to_core_id(&organization_full_id)
        .expect("organization full DID projects through the registered adapter");
    let first_admin = test_did("zAdmin", namespace);
    let second_admin = test_did("zAdminNext", namespace);
    let first_scopes = vec![OrganizationRegistrationScope::OrganizationProfileManage];
    let second_scopes = vec![
        OrganizationRegistrationScope::OrganizationProfileManage,
        OrganizationRegistrationScope::OrganizationRealmEndorse,
    ];

    let challenge_1 = registration_challenge(
        namespace,
        "ensure-1",
        &organization_id,
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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
        &organization_full_id,
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

fn test_full_id(label: &str, namespace: &str) -> DidFullId {
    DidFullId::new(format!(
        "did:webvh:{label}:{}.example",
        &test_hash_hex(namespace)[..20]
    ))
    .expect("contract test full DID is valid")
}

fn test_did(label: &str, namespace: &str) -> DidCoreId {
    project_full_id_to_core_id(&test_full_id(label, namespace))
        .expect("contract test full DID projects to a core id")
}

fn registration_challenge(
    namespace: &str,
    label: &str,
    organization_id: &DidCoreId,
    organization_full_id: &DidFullId,
    local_admin_subject: &DidCoreId,
    scopes: &[OrganizationRegistrationScope],
    created_at: chrono::DateTime<Utc>,
) -> OrganizationRegistrationChallenge {
    let challenge_hash = test_hash_hex(&format!("{namespace}:challenge:{label}"));
    OrganizationRegistrationChallenge {
        challenge_id: format!("ak:organization_registration_challenge:{challenge_hash}"),
        organization_id: organization_id.clone(),
        full_id: organization_full_id.clone(),
        purpose: ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1.to_owned(),
        nonce: challenge_hash[..32].to_owned(),
        audience: DidCoreId::new("ak:did_core:webvh:zService").expect("valid service core id"),
        origin: "https://service.example/".to_owned(),
        trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:service.example")
            .expect("valid service trust domain"),
        local_admin_subject: local_admin_subject.clone(),
        requested_scopes: scopes.to_vec(),
        expires_at: created_at + Duration::seconds(300),
        created_at,
    }
}

#[allow(clippy::too_many_arguments)]
fn registration_outcome(
    organization_id: &DidCoreId,
    organization_full_id: &DidFullId,
    local_admin_subject: &DidCoreId,
    scopes: &[OrganizationRegistrationScope],
    generation: u64,
    status: OrganizationRegistrationStatus,
    version_id: &str,
    issued_at: chrono::DateTime<Utc>,
    created: bool,
) -> OrganizationRegistrationOutcome {
    let issuer = DidCoreId::new("ak:did_core:webvh:zService").expect("valid service core id");
    let issuer_full =
        DidFullId::new("did:webvh:zService:service.example").expect("valid service DID");
    let mut receipt = OrganizationRegistrationReceipt {
        registration_receipt_id: "ak:organization_registration_receipt:placeholder".to_owned(),
        organization_id: organization_id.clone(),
        full_id: organization_full_id.clone(),
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
        local_admin_subject: local_admin_subject.clone(),
        delegated_scopes: scopes.to_vec(),
        status,
        issued_at,
        expires_at: issued_at + Duration::days(30),
        issuer_service_id: issuer.clone(),
        proof: PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!("{issuer_full}#registry-key-1"))
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
        organization_id: organization_id.clone(),
        full_id: organization_full_id.clone(),
        registration_generation: generation,
        version_id: version_id.to_owned(),
        registration_receipt: receipt,
        created,
    };
    outcome.validate().expect("contract outcome is valid");
    outcome
}

pub async fn assert_idempotency_store_contract(store: &dyn IdempotencyStore, namespace: &str) {
    let now = database_timestamp_now();
    let principal_id = format!("did:web:{namespace}.example");
    let idempotency_key = format!("idempotency:{namespace}");
    let first = IdempotencyRecord {
        principal_id: principal_id.clone(),
        idempotency_key: idempotency_key.clone(),
        service_id: "did:web:soland.example".to_owned(),
        request_hash: "sha256:first".to_owned(),
        response_status: 200,
        response_body: serde_json::json!({"accepted": true}),
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    store.record(&first).await.expect("record first response");
    assert_eq!(
        store
            .get(&principal_id, &idempotency_key)
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
            .get(&principal_id, &idempotency_key)
            .await
            .expect("read first-writer response"),
        Some(first),
        "the first response must win a duplicate-key race"
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
        requester_id: format!("did:web:{namespace}-requester.example"),
        target_kind: "did".to_owned(),
        target_id: format!("did:web:{namespace}-target.example"),
        purpose: "direct_message".to_owned(),
        strand_id: None,
        source_service_id: Some(format!("did:web:{namespace}-provider.example")),
        created_at: now,
        expires_at: Some(now + Duration::hours(1)),
    };
    store.put(&first).await.expect("record MIMI correlation");
    assert_eq!(
        store.get(&consent_id).await.expect("read MIMI correlation"),
        Some(first.clone())
    );

    let mut competing = first.clone();
    competing.target_id = format!("did:web:{namespace}-other-target.example");
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

pub async fn assert_control_proposal_authority_ack_store_contract(
    store: &dyn ControlProposalAuthorityAckStore,
    namespace: &str,
) {
    let first = ControlProposalAuthorityAckRecord {
        ack_key: format!("control-proposal-authority-ack:{namespace}"),
        request_hash: "sha256:first".to_owned(),
        response_body: serde_json::json!({"authority_ack": "first"}),
        created_at: database_timestamp_now(),
    };
    store
        .record(&first)
        .await
        .expect("record first authority Ack");
    assert_eq!(
        store
            .get(&first.ack_key)
            .await
            .expect("read first authority Ack"),
        Some(first.clone())
    );

    let mut competing = first.clone();
    competing.request_hash = "sha256:competing".to_owned();
    competing.response_body = serde_json::json!({"authority_ack": "competing"});
    store
        .record(&competing)
        .await
        .expect("record competing authority Ack");
    assert_eq!(
        store
            .get(&first.ack_key)
            .await
            .expect("read winning authority Ack"),
        Some(first),
        "proposal authority Acks are permanent first-writer-wins evidence"
    );
}

pub struct EventCommitContractStores<'a> {
    pub unit_of_work: &'a dyn EventCommitUnitOfWork,
    pub events: &'a dyn EventStore,
    pub projections: &'a dyn ProjectionEventStore,
    pub idempotency: &'a dyn IdempotencyStore,
    pub outbox: &'a dyn FederationOutboxStore,
    pub device_pairings: &'a dyn DevicePairingStore,
    pub contacts: &'a dyn ContactStore,
    pub invite_policies: &'a dyn InviteReceivePolicyStore,
}

fn contract_realm_id(seed: &str) -> String {
    let digest = arkret_canonical::sha256_bytes(seed.as_bytes());
    let event_id =
        arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest);
    arkret_identifiers::RealmId::from_event_id(&event_id).to_string()
}

fn canonical_wire_event_record(
    _event_id: &str,
    actor_id: &str,
    realm_id: &str,
    actor_seq: u64,
    now: chrono::DateTime<Utc>,
) -> CanonicalEventRecord {
    let actor_id = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(actor_id.to_owned()).expect("contract actor full id"),
    )
    .expect("contract actor core id");
    let event = arkret_wire::test_support::raw_event_at(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .expect("contract realm id"),
        },
        actor_id.clone(),
        actor_id.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .expect("contract HLC"),
        serde_json::json!({"body": "contract"}),
        now,
    )
    .expect("contract wire event");
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .expect("contract event digest");
    let envelope = serde_json::to_value(&event).expect("contract wire event encodes");
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &event.digest_payload().expect("contract digest payload"),
    )
    .expect("contract canonical bytes");
    CanonicalEventRecord {
        event_id: event.event_id.as_str().to_owned(),
        actor_id: actor_id.to_string(),
        actor_seq,
        realm_id: Some(realm_id.to_owned()),
        kind: "ak.message.create".to_owned(),
        schema_id: "arkret://events/message/create/v1".to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: now,
    }
}

fn contract_control_proposal_ack(
    record: &CanonicalEventRecord,
    realm_id: &str,
    now: chrono::DateTime<Utc>,
) -> arkret_wire::ControlProposalAck {
    let policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
        realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).expect("typed realm id"),
        proposal_digest: Hash::new(record.canonical_digest.clone()).expect("typed digest"),
        received_at: now,
        decision_due_at: now + policy.decision_window,
        absolute_due_at: now + policy.absolute_horizon,
        authority_set_ref: Hash::new(format!("sha256:{}", "a".repeat(64)))
            .expect("typed authority set ref"),
        signature: arkret_wire::PayloadSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:web:storage-contract.example#authority-1",
            )
            .expect("authority verification method"),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .expect("placeholder digest"),
            created_at: now,
            jws: "e30..c2ln".to_owned(),
            extra: std::collections::BTreeMap::new(),
        },
    };
    authority_ack.signature.payload_digest = authority_ack
        .authority_ack_digest()
        .expect("authority Ack digest");
    arkret_wire::ControlProposalAck::from_authority_acks(vec![authority_ack], policy)
        .expect("valid Control Proposal Ack")
}

pub async fn assert_event_commit_unit_of_work_contract(
    stores: EventCommitContractStores<'_>,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let event_uuid = uuid::Uuid::now_v7();
    let realm_id = contract_realm_id(&format!("event-commit:{namespace}:{event_uuid}"));
    let principal_id = format!("did:web:{namespace}.example");
    let idempotency_key = format!("event-commit:{namespace}:{event_uuid}");
    let outbox_id = format!("outbox:{namespace}:{event_uuid}");
    let event = canonical_wire_event_record("", &principal_id, &realm_id, 0, now);
    let event_id = event.event_id.clone();
    let control_proposal_ack = contract_control_proposal_ack(&event, &realm_id, now);
    let request = EventCommitRequest {
        device_pairing_authorization: None,
        contact_projection: None,
        event,
        control_proposal_ingress: Some(ControlProposalIngress::AckRequired(control_proposal_ack)),
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![ProjectionEventRecord {
            event_id: event_id.clone(),
            realm_id: realm_id.clone(),
            event_kind: "ak.message.create".to_owned(),
            operation_kind: "create".to_owned(),
            operation_id: None,
            sender: Some(principal_id.clone()),
            payload: serde_json::json!({"body": "contract"}),
            created_at: now,
            received_at: now,
        }],
        idempotency: Some(IdempotencyRecord {
            principal_id: principal_id.clone(),
            idempotency_key: idempotency_key.clone(),
            service_id: "did:web:soland.example".to_owned(),
            request_hash: format!("sha256:{event_uuid}"),
            response_status: 200,
            response_body: serde_json::json!({"event_id": event_id}),
            created_at: now,
            expires_at: now + Duration::hours(1),
        }),
        outbox: vec![FederationOutboxRecord {
            id: outbox_id.clone(),
            peer_did: format!("did:web:peer-{namespace}.example"),
            peer_url: Some("https://peer.example".to_owned()),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key: format!("peer:{event_uuid}"),
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
        }],
    };

    let outcome = stores
        .unit_of_work
        .commit_event(request)
        .await
        .expect("commit complete event unit of work");
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 1);
    assert!(stores.events.contains(&event_id).await.expect("read event"));
    let event_outbox = stores
        .events
        .federation_outbox_for_event(&event_id)
        .await
        .expect("read Event delivery intents");
    assert_eq!(event_outbox.len(), 1);
    assert_eq!(event_outbox[0].id, outbox_id);
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
            .get(&principal_id, &idempotency_key)
            .await
            .expect("read idempotency record")
            .is_some()
    );
    assert!(
        stores
            .outbox
            .get(&outbox_id)
            .await
            .expect("read outbox")
            .is_some()
    );

    // Accepted-device pairing is consumed in the exact Event unit of work.
    // A response-loss replay reaches the already-consumed staged row and must
    // fail without inserting a second Event/projection or reviving the row.
    let pairing_request_id = format!("device-pairing:{namespace}:{event_uuid}");
    let pairing_key_value = serde_json::json!({
        "algorithm": "Ed25519",
        "key": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "kid": "ak:device:01964137-0000-7000-8000-0000000000b2",
        "kty": "OKP"
    });
    let pairing_key =
        serde_json::from_value(pairing_key_value.clone()).expect("contract pairing public key");
    stores
        .device_pairings
        .put(DevicePairingRecord::new(
            pairing_request_id.clone(),
            "7H2K9M4Q".to_owned(),
            pairing_key_value,
            "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "https://account.example".to_owned(),
            "BBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            None,
            None,
            "pending_authorization".to_owned(),
            now,
            now + Duration::minutes(10),
        ))
        .await
        .expect("stage contract pairing");
    let pairing_event = canonical_wire_event_record("", &principal_id, &realm_id, 1, now);
    let pairing_event_id = pairing_event.event_id.clone();
    let pairing_ack = contract_control_proposal_ack(&pairing_event, &realm_id, now);
    let pairing_commit = EventCommitRequest {
        device_pairing_authorization: Some(DevicePairingAuthorizationCommit {
            device_pairing_request_id: pairing_request_id.clone(),
            pairing_code: "7H2K9M4Q".to_owned(),
            new_device_pubkey: pairing_key,
            device_id: "ak:device:01964137-0000-7000-8000-0000000000b2".to_owned(),
            authorized_by_actor_id: principal_id.clone(),
            authorized_event_ref: pairing_event_id.clone(),
            changed_at: now,
        }),
        contact_projection: None,
        event: pairing_event,
        control_proposal_ingress: Some(ControlProposalIngress::AckRequired(pairing_ack)),
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![ProjectionEventRecord {
            event_id: pairing_event_id.clone(),
            realm_id: realm_id.clone(),
            event_kind: "ak.device.authorize".to_owned(),
            operation_kind: "authorize".to_owned(),
            operation_id: None,
            sender: Some(principal_id.clone()),
            payload: serde_json::json!({"device_id": "ak:device:01964137-0000-7000-8000-0000000000b2"}),
            created_at: now,
            received_at: now,
        }],
        idempotency: None,
        outbox: Vec::new(),
    };
    stores
        .unit_of_work
        .commit_event(pairing_commit.clone())
        .await
        .expect("pairing Event and staged CAS commit together");
    assert!(
        stores
            .unit_of_work
            .commit_event(pairing_commit)
            .await
            .is_err(),
        "response-loss replay must not accept an already-consumed pairing"
    );
    assert!(
        stores
            .events
            .contains(&pairing_event_id)
            .await
            .expect("read paired Event")
    );
    assert_eq!(
        stores
            .projections
            .snapshot_all()
            .await
            .expect("read paired projections")
            .iter()
            .filter(|projection| projection.event_id == pairing_event_id)
            .count(),
        1,
        "response-loss replay must not duplicate the pairing projection"
    );
    let pairing = stores
        .device_pairings
        .get_by_request_id(&pairing_request_id)
        .await
        .expect("read consumed pairing")
        .expect("pairing row retained for status/audit");
    assert_eq!(pairing.state, "authorized");
    assert_eq!(
        pairing.authorized_event_ref.as_deref(),
        Some(pairing_event_id.as_str())
    );

    // Contact acceptance must expose its canonical Event, holder projection,
    // and peer carrier together. Reading all three back only through durable
    // stores models a process restart with no in-memory planning state.
    let contact_event = canonical_wire_event_record("", &principal_id, &realm_id, 2, now);
    let contact_event_id = contact_event.event_id.clone();
    let contact_outbox_id = format!("contact-outbox:{namespace}:{event_uuid}");
    let contact_idempotency_key = format!("contact-commit:{namespace}:{event_uuid}");
    let contact_record = ContactRecord {
        requester: principal_id.clone(),
        target: format!("did:web:contact-peer-{namespace}.example"),
        contact_round_id: None,
        version: None,
        granted_to_target_scopes: vec!["direct_conversation".to_owned()],
        granted_to_requester_scopes: Vec::new(),
        status: "pending".to_owned(),
        request_event_ref: Some(contact_event_id.clone()),
        request_receipts: Vec::new(),
        request_mirror_receipts: Vec::new(),
        contact_round_evidence: None,
        contact_round_evidence_history: Vec::new(),
        control_outcomes: Vec::new(),
        response_event_ref: None,
        tombstone_event_ref: None,
        message: None,
        peer_service_id: Some(format!("did:web:contact-service-{namespace}.example")),
        peer_service_resolution: None,
        created_at: now,
        updated_at: now,
    };
    let contact_commit = EventCommitRequest {
        device_pairing_authorization: None,
        contact_projection: Some(ContactProjectionCommit {
            record: contact_record.clone(),
            expected_updated_at: None,
            conflict_code: "contact_round_conflict".to_owned(),
            invite_policy: None,
        }),
        control_proposal_ingress: Some(ControlProposalIngress::AckRequired(
            contract_control_proposal_ack(&contact_event, &realm_id, now),
        )),
        event: contact_event,
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: Vec::new(),
        idempotency: Some(IdempotencyRecord {
            principal_id: principal_id.clone(),
            idempotency_key: contact_idempotency_key.clone(),
            service_id: "did:web:soland.example".to_owned(),
            request_hash: format!("sha256:contact-{event_uuid}"),
            response_status: 200,
            response_body: serde_json::json!({"status": "accepted"}),
            created_at: now,
            expires_at: now + Duration::hours(1),
        }),
        outbox: vec![FederationOutboxRecord::pending(
            contact_outbox_id.clone(),
            contact_record.peer_service_id.clone().unwrap(),
            "https://contact-peer.example".to_owned(),
            "/_arkret/peer/contacts".to_owned(),
            format!("peer-contact:{contact_event_id}"),
            "{}".to_owned(),
            now.timestamp(),
        )],
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
            .get(&contact_record.requester, &contact_record.target)
            .await
            .unwrap()
            .expect("Contact projection survives restart-equivalent read")
            .request_event_ref
            .as_deref(),
        Some(contact_event_id.as_str())
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
            .get(&principal_id, &contact_idempotency_key)
            .await
            .unwrap()
            .is_some(),
        "Contact response-loss replay retains the first operation outcome"
    );

    let failed_contact_event = canonical_wire_event_record("", &principal_id, &realm_id, 3, now);
    let failed_contact_event_id = failed_contact_event.event_id.clone();
    let failed_contact_outbox_id = format!("contact-outbox-failed:{namespace}:{event_uuid}");
    let mut conflicting_contact = contact_record.clone();
    conflicting_contact.updated_at = now + Duration::seconds(2);
    let failed_contact_commit = stores
        .unit_of_work
        .commit_event(EventCommitRequest {
            device_pairing_authorization: None,
            contact_projection: Some(ContactProjectionCommit {
                record: conflicting_contact,
                expected_updated_at: Some(now + Duration::seconds(1)),
                conflict_code: "contact_lineage_conflict".to_owned(),
                invite_policy: None,
            }),
            control_proposal_ingress: Some(ControlProposalIngress::AckRequired(
                contract_control_proposal_ack(&failed_contact_event, &realm_id, now),
            )),
            event: failed_contact_event,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency: None,
            outbox: vec![FederationOutboxRecord::pending(
                failed_contact_outbox_id.clone(),
                contact_record.peer_service_id.clone().unwrap(),
                "https://contact-peer.example".to_owned(),
                "/_arkret/peer/contacts".to_owned(),
                format!("peer-contact:{failed_contact_event_id}"),
                "{}".to_owned(),
                now.timestamp(),
            )],
        })
        .await;
    assert!(failed_contact_commit.is_err());
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
            .is_none(),
        "Contact CAS failure must roll back its peer carrier"
    );

    let rollback_uuid = uuid::Uuid::now_v7();
    let rollback_idempotency_key = format!("event-rollback:{namespace}:{rollback_uuid}");
    let rollback_outbox_id = format!("outbox-rollback:{namespace}:{rollback_uuid}");
    let rollback_event = canonical_wire_event_record("", &principal_id, &realm_id, 4, now);
    let rollback_event_id = rollback_event.event_id.clone();
    let rollback_ack = contract_control_proposal_ack(&rollback_event, &realm_id, now);
    let failed = EventCommitRequest {
        device_pairing_authorization: None,
        contact_projection: None,
        event: rollback_event,
        control_proposal_ingress: Some(ControlProposalIngress::AckRequired(rollback_ack)),
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![ProjectionEventRecord {
            event_id: rollback_event_id.clone(),
            realm_id: "not-a-typed-realm-id".to_owned(),
            event_kind: "ak.message.create".to_owned(),
            operation_kind: "create".to_owned(),
            operation_id: None,
            sender: Some(principal_id.clone()),
            payload: serde_json::json!({}),
            created_at: now,
            received_at: now,
        }],
        idempotency: Some(IdempotencyRecord {
            principal_id: principal_id.clone(),
            idempotency_key: rollback_idempotency_key.clone(),
            service_id: "did:web:soland.example".to_owned(),
            request_hash: format!("sha256:{rollback_uuid}"),
            response_status: 200,
            response_body: serde_json::json!({}),
            created_at: now,
            expires_at: now + Duration::hours(1),
        }),
        outbox: vec![FederationOutboxRecord {
            id: rollback_outbox_id.clone(),
            peer_did: format!("did:web:peer-{namespace}.example"),
            peer_url: Some("https://peer.example".to_owned()),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key: format!("peer:{rollback_uuid}"),
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
        }],
    };
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
            .get(&principal_id, &rollback_idempotency_key)
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
    let peer_did = format!("did:web:peer-{namespace}.example");
    let row = |suffix: &str, created_at: i64| {
        FederationOutboxRecord::pending(
            format!("outbox:{namespace}:{suffix}"),
            peer_did.clone(),
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
                        peer_did: peer_did.clone(),
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
    assert!(
        store
            .claim_due(&claim("token-e", "worker-a", 10_000, 60))
            .await
            .expect("terminal claim")
            .is_empty(),
        "a terminal row is never claimed again"
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
        "did:web:alice.example",
        &realm_id,
        0,
        database_timestamp_now(),
    );
    let route_missing = FederationOutboxRecord::realm_fanout(
        format!("outbox:{namespace}:pending-route"),
        "ak:did_core:web:peer.example".to_owned(),
        None,
        "/_arkret/peer/events".to_owned(),
        format!("ak:outbox:event:{namespace}:pending-route"),
        "{}".to_owned(),
        RealmFanoutBinding {
            realm_id,
            source_event_ids: vec![source_event.event_id.clone()],
            authority_witnesses: vec![RealmFanoutAuthorityWitness {
                member_id: "ak:did_core:web:alice.example".to_owned(),
                membership_event_ref: source_event.event_id.clone(),
                delivery_binding_frontier: source_event.event_id,
            }],
        },
        1_000,
    );
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
                    peer_did: route_missing.peer_did.clone(),
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
            peer_did.clone(),
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
            row.peer_did == peer_did
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
                && bucket.peer_did == peer_did
                && bucket.depth >= 1)
    );
}

/// §6.3 — the atomic Event batches must roll the **outbox** back too.
///
/// The ordinary single-Event path has committed its outbox rows transactionally
/// for a while; the Realm genesis and identity-anchor units did not, and an
/// Event accepted without its delivery intent is unroutable forever after a
/// crash. This asserts the joint rollback on both adapters by injecting a
/// failure in the outbox insert itself (a colliding primary key), so the Events
/// are known-good and only the delivery intent can be what aborts the batch.
pub async fn assert_atomic_batch_outbox_rollback_contract(
    events: &dyn EventStore,
    outbox: &dyn FederationOutboxStore,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let principal_id = format!("did:web:{namespace}.example");
    let realm_id = contract_realm_id(&format!("atomic-batch:{namespace}"));
    // The Realm genesis unit requires one Control Proposal Ack per Event. Supplying
    // them is what makes this test actually about the outbox: without them the
    // batch would abort on receipt cardinality and never reach the outbox
    // insert, so the rollback assertion below would pass for the wrong reason.
    let control_proposal_ack =
        |record: &CanonicalEventRecord| contract_control_proposal_ack(record, &realm_id, now);
    let colliding_id = format!("outbox:{namespace}:collision");
    // Two intents sharing one primary key: the first inserts, the second must
    // abort the batch.
    let colliding_outbox = |suffix: &str| {
        vec![
            FederationOutboxRecord::pending(
                colliding_id.clone(),
                format!("did:web:peer-{namespace}.example"),
                "https://peer.example".to_owned(),
                "/_arkret/peer/events".to_owned(),
                format!("ak:outbox:{namespace}:{suffix}:a"),
                "{}".to_owned(),
                now.timestamp(),
            ),
            FederationOutboxRecord::pending(
                colliding_id.clone(),
                format!("did:web:peer-{namespace}.example"),
                "https://peer.example".to_owned(),
                "/_arkret/peer/events".to_owned(),
                format!("ak:outbox:{namespace}:{suffix}:b"),
                "{}".to_owned(),
                now.timestamp(),
            ),
        ]
    };

    let bootstrap_record = canonical_wire_event_record("", &principal_id, &realm_id, 0, now);
    let bootstrap_event_id = bootstrap_record.event_id.clone();
    assert!(
        events
            .put_realm_bootstrap_batch_atomic(
                vec![bootstrap_record.clone()],
                vec![control_proposal_ack(&bootstrap_record)],
                colliding_outbox("bootstrap"),
            )
            .await
            .is_err(),
        "a failing outbox insert must abort the Realm genesis unit"
    );
    assert!(
        !events
            .contains(&bootstrap_event_id)
            .await
            .expect("bootstrap event rollback"),
        "the Realm genesis Events roll back with their delivery intents"
    );
    assert!(
        outbox
            .get(&colliding_id)
            .await
            .expect("bootstrap outbox rollback")
            .is_none(),
        "the partially-inserted delivery intent rolls back too"
    );

    let anchor_record = canonical_wire_event_record("", &principal_id, &realm_id, 0, now);
    let anchor_event_id = anchor_record.event_id.clone();
    assert!(
        events
            .put_identity_anchor_batch_atomic(
                vec![anchor_record.clone()],
                vec![control_proposal_ack(&anchor_record)],
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                colliding_outbox("anchor"),
            )
            .await
            .is_err(),
        "a failing outbox insert must abort the identity anchor unit"
    );
    assert!(
        !events
            .contains(&anchor_event_id)
            .await
            .expect("anchor event rollback"),
        "the identity anchor Events roll back with their delivery intents"
    );
    assert!(
        outbox
            .get(&colliding_id)
            .await
            .expect("anchor outbox rollback")
            .is_none()
    );

    // The happy path still commits both halves together.
    let committed_outbox_id = format!("outbox:{namespace}:committed");
    let committed_record = canonical_wire_event_record("", &principal_id, &realm_id, 0, now);
    let committed_event_id = committed_record.event_id.clone();
    events
        .put_realm_bootstrap_batch_atomic(
            vec![committed_record.clone()],
            vec![control_proposal_ack(&committed_record)],
            vec![FederationOutboxRecord::pending(
                committed_outbox_id.clone(),
                format!("did:web:peer-{namespace}.example"),
                "https://peer.example".to_owned(),
                "/_arkret/peer/events".to_owned(),
                format!("ak:outbox:{namespace}:committed"),
                "{}".to_owned(),
                now.timestamp(),
            )],
        )
        .await
        .expect("Realm genesis unit commits with its delivery intent");
    assert!(events.contains(&committed_event_id).await.expect("event"));
    assert!(
        outbox
            .get(&committed_outbox_id)
            .await
            .expect("outbox")
            .is_some(),
        "an accepted genesis unit always has its delivery intent"
    );
}

fn mls_keypackage_contract_row(namespace: &str, suffix: &str) -> MlsKeyPackageRow {
    MlsKeyPackageRow {
        id: format!("{namespace}-keypackage-{suffix}"),
        keypackage_ref: format!("ak:mls:keypackage:{namespace}-{suffix}"),
        keypackage_digest:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        actor_id: format!("did:web:{namespace}.example"),
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        key_package_bytes: vec![1, 2, 3],
        capabilities: vec!["ak.mls.rfc9420".to_owned()],
        capabilities_digest:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        device_signature: serde_json::json!({"kid": "contract", "sig": "AA"}),
        last_resort: false,
        last_resort_realm_id: None,
        lifetime_not_before: 1,
        lifetime_not_after: 100,
        claimed_by_mls_group_id: None,
        device_authorize_event_id: Some(
            "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD".to_owned(),
        ),
        agent_key_authorize_event_id: None,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: 1,
    }
}

fn mls_claim<'a>(id: &'a str, target: MlsKeyPackageClaimTarget<'a>) -> MlsKeyPackageClaim<'a> {
    MlsKeyPackageClaim {
        id,
        target,
        intended_realm_id: None,
        device_authorize_event_id: Some("ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"),
        agent_key_authorize_event_id: None,
        device_revocation_gate: Some(DeviceRevocationGateSelector {
            principal_id: "ak:did_core:web:contract.example".to_owned(),
            principal_server_id: "ak:did_core:web:soland.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            target_device_authorize_event_id:
                "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD".to_owned(),
            target_device_generation_ref: 1,
        }),
        claimed_at: 10,
        claim_expires_at_unix_ms: Some(20_000),
    }
}

pub async fn assert_mls_keypackage_retirement_contract(
    store: &dyn MlsKeyPackageStore,
    namespace: &str,
) {
    let published = mls_keypackage_contract_row(namespace, "published");
    let claimed = mls_keypackage_contract_row(namespace, "claimed");
    let consumed = mls_keypackage_contract_row(namespace, "consumed");
    let revoked = mls_keypackage_contract_row(namespace, "revoked");
    for row in [&published, &claimed, &consumed, &revoked] {
        assert!(store.put(row).await.expect("publish KeyPackage"));
    }

    let retired = store
        .try_claim(mls_claim(&published.id, MlsKeyPackageClaimTarget::Retire))
        .await
        .expect("retire published KeyPackage")
        .expect("published KeyPackage must retire");
    assert_eq!(retired.claimed_by_mls_group_id.as_deref(), Some("retired"));
    assert!(retired.claimed_at.is_none());
    assert!(retired.claim_expires_at_unix_ms.is_none());
    assert!(retired.consumed_at.is_none());
    assert!(
        store
            .try_claim(mls_claim(
                &published.id,
                MlsKeyPackageClaimTarget::Group("group-after-retirement"),
            ))
            .await
            .expect("query retired KeyPackage")
            .is_none()
    );

    let group_id = format!("group-{namespace}");
    store
        .try_claim(mls_claim(
            &claimed.id,
            MlsKeyPackageClaimTarget::Group(&group_id),
        ))
        .await
        .expect("claim ordinary KeyPackage")
        .expect("ordinary KeyPackage must be claimable");
    assert!(
        store
            .try_claim(mls_claim(&claimed.id, MlsKeyPackageClaimTarget::Retire,))
            .await
            .expect("attempt to retire claimed KeyPackage")
            .is_none()
    );

    store
        .try_claim(mls_claim(
            &consumed.id,
            MlsKeyPackageClaimTarget::Group(&group_id),
        ))
        .await
        .expect("claim KeyPackage before consume")
        .expect("ordinary KeyPackage must be claimable");
    store
        .consume_claim(&consumed.id, &group_id, 15, None)
        .await
        .expect("consume KeyPackage")
        .expect("claimed KeyPackage must be consumable");
    assert!(
        store
            .try_claim(mls_claim(&consumed.id, MlsKeyPackageClaimTarget::Retire,))
            .await
            .expect("attempt to retire consumed KeyPackage")
            .is_none()
    );

    store
        .try_claim(mls_claim(&revoked.id, MlsKeyPackageClaimTarget::Revoke))
        .await
        .expect("revoke published KeyPackage")
        .expect("published KeyPackage must be revocable");
    assert!(
        store
            .try_claim(mls_claim(&revoked.id, MlsKeyPackageClaimTarget::Retire,))
            .await
            .expect("attempt to retire revoked KeyPackage")
            .is_none()
    );

    let group_rows = store
        .list_claimed_by_group(&group_id)
        .await
        .expect("query claimed KeyPackages");
    assert_eq!(group_rows.len(), 2);
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
}

pub async fn assert_last_resort_claim_ledger_contract(
    store: &dyn MlsKeyPackageStore,
    namespace: &str,
) {
    let mut keypackage = mls_keypackage_contract_row(namespace, "last-resort");
    keypackage.last_resort = true;
    let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
    keypackage.last_resort_realm_id = Some(realm_id.to_owned());
    store
        .put(&keypackage)
        .await
        .expect("publish last-resort KeyPackage");

    let ledger = |suffix: &str, welcome: &str| PeerKeyPackageClaimLedgerRecord {
        source_service_id: format!("did:web:{namespace}.example"),
        claim_request_id: format!("local-last-resort:{namespace}-{suffix}"),
        request_digest: format!("sha256:{:0>64}", suffix),
        state: "last_resort_claimed".to_owned(),
        outcome: Some(serde_json::json!({
            "schema": "soland.last_resort_keypackage_claim.v1",
            "keypackage_id": keypackage.id,
            "keypackage_ref": keypackage.keypackage_ref,
            "keypackage_digest": keypackage.keypackage_digest,
            "claimant": format!("did:web:{namespace}.example"),
            "recipient_principal_id": "did:web:bob.example",
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
        claim_expires_at_unix_ms: None,
        expires_at: i64::MAX,
        updated_at: 10,
    };
    let first = ledger("01", "welcome-01");
    let second = ledger("02", "welcome-02");

    assert!(matches!(
        store
            .record_peer_claim_terminal(&first)
            .await
            .expect("record first last-resort claim"),
        PeerKeyPackageClaimLedgerWriteResult::Inserted
    ));
    assert!(matches!(
        store
            .record_peer_claim_terminal(&second)
            .await
            .expect("record second last-resort claim"),
        PeerKeyPackageClaimLedgerWriteResult::Inserted
    ));
    assert_eq!(
        store
            .record_peer_claim_terminal(&first)
            .await
            .expect("replay first last-resort claim"),
        PeerKeyPackageClaimLedgerWriteResult::Existing(Box::new(first.clone()))
    );
    assert_eq!(
        store
            .get_peer_claim(&first.source_service_id, &first.claim_request_id)
            .await
            .expect("reload first last-resort claim"),
        Some(first)
    );
    assert_eq!(
        store
            .get_peer_claim(&second.source_service_id, &second.claim_request_id)
            .await
            .expect("reload second last-resort claim"),
        Some(second)
    );
    assert!(
        store
            .revoke_expired_peer_claims(i64::MAX)
            .await
            .expect("run expired-claim maintenance")
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
    let unsigned = UnsignedAccountStatusRecord {
        schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
        account_authority_id: DidCoreId::new("ak:did_core:web:authority.example")
            .expect("account authority core id"),
        account_id: NonEmptyString::new(account_id).expect("account id is not empty"),
        principal_authority: AccountStatusPrincipalAuthority {
            principal_id: DidCoreId::new("ak:did_core:web:alice.example")
                .expect("principal core id"),
            principal_server_id: DidCoreId::new("ak:did_core:web:principal.example")
                .expect("principal server core id"),
        },
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
        verification_method: DidUrl::new("did:web:authority.example#account-status-key")
            .expect("account authority verification method"),
    };
    let proof = account_status_fixture_proof(
        &unsigned.verification_method,
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
        receiver_service_id: DidCoreId::new("ak:did_core:web:receiver.example")
            .expect("receiver core id"),
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
    let account_id = format!("account-{namespace}");
    let genesis = account_status_record(&account_id, 1, None, 2, AccountStatus::Active, 1);
    let authority = genesis.account_authority_id.as_str().to_owned();
    let second = account_status_record(
        &account_id,
        2,
        Some(genesis.account_status_record_id.clone()),
        2,
        AccountStatus::Suspended,
        2,
    );
    let third = account_status_record(
        &account_id,
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
    let rival_genesis = account_status_record(&account_id, 1, None, 2, AccountStatus::Active, 4);
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
        &account_id,
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
        &account_id,
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
        &account_id,
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
        &account_id,
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

/// Owner-side handover plan state must behave identically on every backend.
///
/// The assertions here are the ones a divergence would silently break: a plan
/// that can be opened twice, a notice chain that accepts a fork, or a basis
/// check that a backend forgot to apply would each let a deployment announce a
/// route move it cannot back up.
pub async fn assert_service_route_handover_plan_store_contract(
    store: &dyn ServiceRouteHandoverPlanStore,
    service_id: &DidCoreId,
) {
    // timestamptz is microsecond-precision; a nanosecond `now` would read back
    // unequal and turn an identical re-open into a rejection.
    let now = database_timestamp_now();
    let service_kind = "principal_server";
    let basis = digest_of("basis-record");
    let other_basis = digest_of("other-basis-record");

    let plan = handover_plan(service_id, service_kind, "h-1", &basis, now);
    assert_eq!(
        store.open_plan(plan.clone()).await.unwrap(),
        ServiceRouteHandoverPlanWrite::Applied
    );
    assert_eq!(
        store.open_plan(plan.clone()).await.unwrap(),
        ServiceRouteHandoverPlanWrite::Replay,
        "re-opening the identical plan is a replay, not a conflict"
    );

    // A second unfinished plan cannot start underneath a live one.
    let second = handover_plan(service_id, service_kind, "h-2", &basis, now);
    assert_eq!(
        store.open_plan(second).await.unwrap(),
        ServiceRouteHandoverPlanWrite::PlanAlreadyActive {
            handover_id: "h-1".to_owned()
        }
    );

    // A notice signed against a different basis is refused outright.
    let wrong_basis =
        handover_notice_record(service_id, service_kind, "h-1", 0, None, &other_basis);
    assert!(matches!(
        store
            .commit_notice(ServiceRouteHandoverNoticeCommit {
                notice: wrong_basis,
                expected_basis_digest: other_basis.clone(),
                expected_active_notice_digest: None,
                next_state: ServiceRouteHandoverPlanState::Publishing,
                updated_at: now,
            })
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::BasisChanged { .. }
    ));

    // Revision 0 advances the plan head.
    let revision_zero = handover_notice_record(service_id, service_kind, "h-1", 0, None, &basis);
    let revision_zero_digest = revision_zero.notice_digest.clone();
    assert_eq!(
        store
            .commit_notice(ServiceRouteHandoverNoticeCommit {
                notice: revision_zero.clone(),
                expected_basis_digest: basis.clone(),
                expected_active_notice_digest: None,
                next_state: ServiceRouteHandoverPlanState::Publishing,
                updated_at: now,
            })
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::Applied
    );
    let stored = store
        .plan(service_id, service_kind, "h-1")
        .await
        .unwrap()
        .expect("plan is stored");
    assert_eq!(stored.state, ServiceRouteHandoverPlanState::Publishing);
    assert_eq!(stored.active_notice_revision, Some(0));
    assert_eq!(
        stored.active_notice_digest.as_ref(),
        Some(&revision_zero_digest)
    );

    // The identical revision replays; a different one at the same revision is
    // a fork and must not overwrite.
    assert_eq!(
        store
            .commit_notice(ServiceRouteHandoverNoticeCommit {
                notice: revision_zero,
                expected_basis_digest: basis.clone(),
                expected_active_notice_digest: None,
                next_state: ServiceRouteHandoverPlanState::Publishing,
                updated_at: now,
            })
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::Replay
    );

    // A revision that skips ahead does not chain.
    let skipped = handover_notice_record(
        service_id,
        service_kind,
        "h-1",
        2,
        Some(revision_zero_digest.clone()),
        &basis,
    );
    assert!(matches!(
        store
            .commit_notice(ServiceRouteHandoverNoticeCommit {
                notice: skipped,
                expected_basis_digest: basis.clone(),
                expected_active_notice_digest: Some(revision_zero_digest.clone()),
                next_state: ServiceRouteHandoverPlanState::Publishing,
                updated_at: now,
            })
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::RevisionConflict { .. }
    ));

    // A guarded lifecycle transition needs the state it expects.
    assert_eq!(
        store
            .advance_plan_state(
                service_id,
                service_kind,
                "h-1",
                ServiceRouteHandoverPlanState::Draft,
                ServiceRouteHandoverPlanState::Preannounced,
                None,
                now,
            )
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::Rejected,
        "the plan already left Draft"
    );
    assert_eq!(
        store
            .advance_plan_state(
                service_id,
                service_kind,
                "h-1",
                ServiceRouteHandoverPlanState::Publishing,
                ServiceRouteHandoverPlanState::Failed,
                Some("audience publication exhausted its retry budget".to_owned()),
                now,
            )
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::Applied
    );

    // A terminal plan releases the slot and cannot be advanced again.
    assert!(
        store
            .active_plan(service_id, service_kind)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .advance_plan_state(
                service_id,
                service_kind,
                "h-1",
                ServiceRouteHandoverPlanState::Failed,
                ServiceRouteHandoverPlanState::Publishing,
                None,
                now,
            )
            .await
            .unwrap(),
        ServiceRouteHandoverPlanWrite::Rejected
    );

    let revisions = store
        .notices(service_id, service_kind, "h-1", 32)
        .await
        .unwrap();
    assert_eq!(revisions.len(), 1, "only the accepted revision is stored");
    assert_eq!(revisions[0].notice_revision, 0);

    // The slot is free again, so a follow-up handover can start.
    let follow_up = handover_plan(service_id, service_kind, "h-3", &basis, now);
    assert_eq!(
        store.open_plan(follow_up).await.unwrap(),
        ServiceRouteHandoverPlanWrite::Applied
    );
}

fn digest_of(seed: &str) -> Hash {
    Hash::new(arkret_canonical::canonical_sha256(&seed.to_owned()).unwrap()).unwrap()
}

fn handover_plan(
    service_id: &DidCoreId,
    service_kind: &str,
    handover_id: &str,
    basis: &Hash,
    now: chrono::DateTime<Utc>,
) -> ServiceRouteHandoverPlan {
    ServiceRouteHandoverPlan {
        service_id: service_id.clone(),
        service_kind: service_kind.to_owned(),
        handover_id: handover_id.to_owned(),
        basis_record_sequence: 7,
        basis_record_digest: basis.clone(),
        candidate_base_url: "https://new.example/".to_owned(),
        candidate_record_url: "https://new.example/_arkret/open/services/x/resolution".to_owned(),
        not_before: now + Duration::hours(1),
        cutover_at: now + Duration::hours(2),
        grace_until: now + Duration::hours(6),
        expires_at: now + Duration::hours(12),
        state: ServiceRouteHandoverPlanState::Draft,
        active_notice_revision: None,
        active_notice_digest: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn handover_notice_record(
    service_id: &DidCoreId,
    service_kind: &str,
    handover_id: &str,
    notice_revision: u32,
    previous_notice_digest: Option<Hash>,
    basis: &Hash,
) -> ServiceRouteHandoverNoticeRecord {
    // A fixed instant keeps the canonical digest stable across the replay
    // assertions; a wall clock would make the "identical bytes" case flaky.
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let expires_at = issued_at + Duration::hours(12);
    let scheduled = previous_notice_digest.is_none();
    let core = ServiceRouteHandoverNoticeCore {
        service_id: service_id.clone(),
        service_kind: service_kind.to_owned(),
        handover_id: handover_id.to_owned(),
        notice_revision,
        state: if scheduled {
            ServiceRouteHandoverState::Scheduled
        } else {
            ServiceRouteHandoverState::Cancelled
        },
        from_record_sequence: 7,
        from_record_digest: basis.clone(),
        candidate_base_url: scheduled.then(|| "https://new.example/".to_owned()),
        candidate_record_url: scheduled
            .then(|| "https://new.example/_arkret/open/services/x/resolution".to_owned()),
        issued_at,
        not_before: scheduled.then(|| issued_at + Duration::hours(1)),
        cutover_at: scheduled.then(|| issued_at + Duration::hours(2)),
        grace_until: scheduled.then(|| issued_at + Duration::hours(6)),
        previous_notice_digest: previous_notice_digest.clone(),
        expires_at,
    };
    let notice = ServiceRouteHandoverNotice {
        notice: core,
        proof: ProtocolSignature {
            verification_method: DidUrl::new(
                "did:webvh:zCXaWSDv1afiBoxDX5sVBU5an:route.example#assertion-1",
            )
            .unwrap(),
            created_at: issued_at,
            jws: arkret_wire::Base64UrlString::new("AA".to_owned()).unwrap(),
        },
    };
    ServiceRouteHandoverNoticeRecord {
        service_id: service_id.clone(),
        service_kind: service_kind.to_owned(),
        handover_id: handover_id.to_owned(),
        notice_revision,
        notice_digest: Hash::new(arkret_canonical::canonical_sha256(&notice).unwrap()).unwrap(),
        previous_notice_digest,
        state: notice.notice.state,
        notice,
        issued_at,
        expires_at,
    }
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
        aad_visibility_ceiling: arkret_models_crypto::EncryptedEnvelopeAadVisibility::RoutingDigest,
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

pub async fn assert_device_key_store_contract(store: &dyn DeviceKeyStore, namespace: &str) {
    let actor = format!("did:web:{namespace}.example");
    let device_id = format!("ak:device:{namespace}");
    let bundle = serde_json::json!({
        "device_id": device_id,
        "one_time_keys": {"curve25519:aaa": {"key": "aaa"}},
        "fallback_keys": {},
    });
    store
        .put(actor.clone(), device_id.clone(), bundle.clone())
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
            .get(&actor, &format!("ak:device:{namespace}-missing"))
            .await
            .expect("read missing device key bundle"),
        None
    );

    let rotated = serde_json::json!({"device_id": device_id, "rotated": true});
    store
        .put(actor.clone(), device_id.clone(), rotated.clone())
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

pub async fn assert_one_time_key_store_contract(store: &dyn OneTimeKeyStore, namespace: &str) {
    let actor = format!("did:web:{namespace}.example");
    let device_id = format!("ak:device:{namespace}");
    let key_a = serde_json::json!({"key_id": format!("curve25519:{namespace}-a"), "key": "a"});
    let key_b = serde_json::json!({"key_id": format!("curve25519:{namespace}-b"), "key": "b"});
    store
        .put(
            actor.clone(),
            device_id.clone(),
            vec![key_a.clone(), key_b.clone()],
        )
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
        .put(actor.clone(), device_id.clone(), vec![key_c.clone()])
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
    let subject = MemberIdentitySubjectKey {
        realm_id: format!("ak:realm:{namespace}"),
        actor_id: format!("did:web:{namespace}.example"),
        segment: "member_identity".to_owned(),
    };
    let first = MemberIdentityEventRecord {
        event_id: format!("ak:event:{namespace}-first"),
        subject: subject.clone(),
        payload_digest: format!("sha256:{}", "a".repeat(64)),
        replaces: Vec::new(),
        raw_event: serde_json::json!({"event_id": format!("ak:event:{namespace}-first")}),
    };
    let second = MemberIdentityEventRecord {
        event_id: format!("ak:event:{namespace}-second"),
        subject: subject.clone(),
        payload_digest: format!("sha256:{}", "b".repeat(64)),
        replaces: vec![MemberIdentityReplacementEdge {
            event_id: first.event_id.clone(),
            payload_digest: first.payload_digest.clone(),
        }],
        raw_event: serde_json::json!({"event_id": format!("ak:event:{namespace}-second")}),
    };
    store
        .put_event(&first)
        .await
        .expect("write first identity event");
    store
        .put_event(&second)
        .await
        .expect("write second identity event");
    // Replay re-projection must be idempotent.
    store
        .put_event(&first)
        .await
        .expect("replay first identity event");
    let events = store
        .snapshot_events()
        .await
        .expect("snapshot identity events");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.subject == subject)
            .cloned()
            .collect::<Vec<_>>(),
        vec![first.clone(), second.clone()],
        "snapshot returns every stored event once, in event_id order"
    );

    let claim = HandleClaimEvidenceRecord {
        digest: format!("sha256:{}", "c".repeat(64)),
        subject_id: format!("did:web:{namespace}.example"),
        issuer: format!("did:web:{namespace}-issuer.example"),
        issuer_service_id: Some(format!("did:web:{namespace}-issuer.example")),
        audience: Some("ak:service:directory".to_owned()),
        binding_state: "bound".to_owned(),
        visibility: Some("public".to_owned()),
        expires_at: Some(database_timestamp_now() + Duration::hours(1)),
        revoked: false,
        envelope: serde_json::json!({"subject": format!("did:web:{namespace}.example")}),
    };
    store
        .put_handle_claim(&claim)
        .await
        .expect("cache handle claim");
    let mut revoked = claim.clone();
    revoked.revoked = true;
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

pub struct DeviceRevocationSealSettlementStores<'a> {
    pub unit_of_work: &'a dyn EventCommitUnitOfWork,
    pub revocations: &'a dyn DeviceRevocationStore,
    pub control_events: &'a dyn arkret_state::state::ControlEventStore,
}

fn contract_device_revoke_fixture(
    namespace: &str,
) -> (
    EventCommitRequest,
    DeviceRevocationGateSelector,
    arkret_wire::Event,
    ControlProposalIngress,
) {
    let realm_id = contract_realm_id(&format!("device-revocation-seal:{namespace}"));
    let actor_id = arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example"))
        .expect("contract actor core id");
    let principal_server_id = arkret_wire::DidCoreId::new("ak:did_core:web:soland.example")
        .expect("contract principal server core id");
    let created_at = database_timestamp_now();
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceRevoke.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm_id.clone()).expect("contract realm id"),
        },
        actor_id.clone(),
        principal_server_id.clone(),
        0,
        arkret_wire::Hlc::new("019f00000000-0000-00000002").expect("contract HLC"),
        serde_json::json!({
            "principal_id": actor_id,
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "revoked_by": actor_id,
            "revoked_at": created_at,
            "reason": "seal settlement contract"
        }),
        created_at,
    )
    .expect("contract device revoke event");
    let canonical_digest = event.event_digest().expect("contract event digest");
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &event.digest_payload().expect("contract digest payload"),
    )
    .expect("contract canonical bytes");
    let record = CanonicalEventRecord {
        event_id: event.event_id.as_str().to_owned(),
        actor_id: actor_id.to_string(),
        actor_seq: event.actor_seq,
        realm_id: Some(realm_id.clone()),
        kind: event.kind.to_string(),
        schema_id: "arkret://events/device/revoke/v1".to_owned(),
        canonical_digest: canonical_digest.clone(),
        canonical_bytes,
        envelope: serde_json::to_value(&event).expect("contract wire event encodes"),
        received_at: created_at,
    };
    let control_proposal_ack = contract_control_proposal_ack(&record, &realm_id, created_at);
    let selector = DeviceRevocationGateSelector {
        principal_id: actor_id.to_string(),
        principal_server_id: principal_server_id.to_string(),
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        target_device_authorize_event_id: "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
            .to_owned(),
        target_device_generation_ref: 7,
    };
    let transition = DeviceRevocationTransition {
        selector: selector.clone(),
        proposal_event_id: record.event_id.clone(),
        proposal_digest: canonical_digest,
        control_proposal_ack: control_proposal_ack.clone(),
    };
    let ingress = ControlProposalIngress::AckRequired(control_proposal_ack);
    (
        EventCommitRequest {
            device_pairing_authorization: None,
            contact_projection: None,
            event: record,
            control_proposal_ingress: Some(ingress.clone()),
            device_revocation_transition: Some(transition),
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency: None,
            outbox: Vec::new(),
        },
        selector,
        event,
        ingress,
    )
}

fn contract_covering_seal(
    realm_id: &str,
    delta: Hash,
    sealed_at: chrono::DateTime<Utc>,
) -> arkret_wire::Seal {
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64))).expect("placeholder hash");
    let mut seal = arkret_wire::Seal {
        id: arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64)))
            .expect("placeholder Seal id"),
        realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).expect("contract realm id"),
        predecessor_refs: Vec::new(),
        delta: vec![delta],
        control_event_set_root: placeholder.clone(),
        state_root: placeholder.clone(),
        completeness_root: placeholder.clone(),
        notary_seq: 0,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: arkret_wire::NotarySig::Single(arkret_wire::SealSignature {
            verification_method: DidUrl::new("did:key:z6MkFixture#z6MkFixture")
                .expect("fixture verification method"),
            payload_digest: placeholder,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        }),
        sealed_at,
        hlc: arkret_wire::Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).expect("fixture HLC"),
        kind: Default::default(),
    };
    seal.id = seal.derive_id().expect("derive fixture Seal id");
    seal
}

/// Accepting a Seal over a pending device revocation must settle the gate to
/// `revoked` and stage the erase / MLS cleanup obligations — on both backends
/// through the same observable surface: the Postgres adapter derives this via
/// its `state_control_events` JOIN, and the memory adapter must derive the
/// identical view from its bound generic Control Event store.
pub async fn assert_device_revocation_seal_settlement_contract(
    stores: DeviceRevocationSealSettlementStores<'_>,
    namespace: &str,
) {
    let (request, selector, event, ingress) = contract_device_revoke_fixture(namespace);
    let proposal_digest = request.event.canonical_digest.clone();
    let proposal_event_id = request.event.event_id.clone();
    let realm_id = request.event.realm_id.clone().expect("revoke has a Realm");

    stores
        .control_events
        .put_pending_with_ingress(&event, &ingress)
        .expect("admit pending Control Move");
    let outcome = stores
        .unit_of_work
        .commit_event(request)
        .await
        .expect("commit accepted device revoke");
    assert!(outcome.event_inserted);
    assert!(matches!(
        stores
            .revocations
            .gate_status(&selector)
            .await
            .expect("gate status while pending"),
        DeviceRevocationGateStatus::Pending { ref blocking_proposal_digest }
            if blocking_proposal_digest == &proposal_digest
    ));

    let digest = Hash::new(proposal_digest.clone()).expect("typed proposal digest");
    let seal = contract_covering_seal(&realm_id, digest.clone(), database_timestamp_now());
    stores
        .control_events
        .mark_sealed(&digest, &seal)
        .expect("seal the accepted revoke");

    match stores
        .revocations
        .gate_status(&selector)
        .await
        .expect("gate status after seal")
    {
        DeviceRevocationGateStatus::Revoked { covering_seal_id } => {
            assert_eq!(covering_seal_id, seal.id.as_str());
        }
        other => panic!("sealed revocation gate must derive Revoked, got {other:?}"),
    }
    let targets = stores
        .revocations
        .list_targets(&selector)
        .await
        .expect("list targets after seal");
    assert_eq!(targets.len(), 1);
    match &targets[0].status {
        DeviceRevocationTargetStatus::Revoked {
            covering_seal_id, ..
        } => assert_eq!(covering_seal_id, seal.id.as_str()),
        other => panic!("sealed target must be Revoked, got {other:?}"),
    }

    let intent = stores
        .revocations
        .pending_cleanup_intents(usize::MAX)
        .await
        .expect("pending cleanup intents after seal")
        .into_iter()
        .find(|intent| intent.proposal_digest == proposal_digest)
        .expect("sealed revocation must stage a cleanup intent");
    assert_eq!(intent.proposal_event_id, proposal_event_id);
    assert_eq!(intent.covering_seal_id, seal.id.as_str());
    assert_eq!(intent.selector, selector);
    assert!(intent.material_cleanup_completed_at.is_none());
    assert!(intent.mls_obligation_completed_at.is_none());

    assert!(
        stores
            .revocations
            .complete_material_cleanup(&proposal_digest, database_timestamp_now())
            .await
            .expect("complete material cleanup")
    );
    assert!(
        stores
            .revocations
            .pending_cleanup_intents(usize::MAX)
            .await
            .expect("pending cleanup intents after material cleanup")
            .iter()
            .any(|intent| intent.proposal_digest == proposal_digest),
        "the durable task remains until the MLS step is acknowledged"
    );
    assert!(
        stores
            .revocations
            .complete_mls_obligation_by_event_id(&proposal_event_id, database_timestamp_now())
            .await
            .expect("complete MLS obligation by revoke Event id")
    );
    assert!(
        stores
            .revocations
            .pending_cleanup_intents(usize::MAX)
            .await
            .expect("pending cleanup intents after both completions")
            .iter()
            .all(|intent| intent.proposal_digest != proposal_digest)
    );
}
