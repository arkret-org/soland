use arkret_models_identity::{
    ORGANIZATION_REGISTRATION_CONTROL_PURPOSE, OrganizationControlProofKind,
    OrganizationRegistrationChallenge, OrganizationRegistrationOutcome,
    OrganizationRegistrationReceipt, OrganizationRegistrationScope, OrganizationRegistrationStatus,
};
use arkret_wire::{Did, Hash, PayloadProof};
use chrono::{Duration, Utc};

use super::{
    CanonicalEventRecord, EventCommitRequest, EventCommitUnitOfWork, EventStore,
    FederationOutboxClaim, FederationOutboxDeadLetterRecord, FederationOutboxOutcome,
    FederationOutboxPolicyResolution, FederationOutboxRecord, FederationOutboxRequeue,
    FederationOutboxState, FederationOutboxStore, FederationOutboxTransition, IdempotencyRecord,
    IdempotencyStore, MlsKeyPackageClaim, MlsKeyPackageClaimTarget, MlsKeyPackageRow,
    MlsKeyPackageStore, OrganizationRegistrationEnsureCommit,
    OrganizationRegistrationLifecycleCommit, OrganizationRegistrationRefreshCommit,
    OrganizationRegistrationStore, OrganizationRegistrationTerminalReason,
    PeerKeyPackageClaimLedgerRecord, PeerKeyPackageClaimLedgerWriteResult, ProjectionEventRecord,
    ProjectionEventStore, ProposalMemberReceiptRecord, ProposalMemberReceiptStore,
};

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
    let organization_id = test_did("zOrg", namespace);
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
                "ak:organization-registration-receipt:wrong",
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
                expected_current_outcome_id: "ak:organization-registration-receipt:wrong"
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

fn test_did(label: &str, namespace: &str) -> Did {
    Did::new(format!(
        "did:webvh:{label}:{}.example",
        &test_hash_hex(namespace)[..20]
    ))
    .expect("contract test DID is valid")
}

fn registration_challenge(
    namespace: &str,
    label: &str,
    organization_id: &Did,
    local_admin_subject: &Did,
    scopes: &[OrganizationRegistrationScope],
    created_at: chrono::DateTime<Utc>,
) -> OrganizationRegistrationChallenge {
    let challenge_hash = test_hash_hex(&format!("{namespace}:challenge:{label}"));
    OrganizationRegistrationChallenge {
        challenge_id: format!("ak:organization-registration-challenge:{challenge_hash}"),
        organization_id: organization_id.clone(),
        purpose: ORGANIZATION_REGISTRATION_CONTROL_PURPOSE.to_owned(),
        nonce: challenge_hash[..32].to_owned(),
        audience: Did::new("did:webvh:zService:service.example").expect("valid service DID"),
        origin: "https://service.example/".to_owned(),
        trust_domain: "service.example".to_owned(),
        local_admin_subject: local_admin_subject.clone(),
        requested_scopes: scopes.to_vec(),
        expires_at: created_at + Duration::seconds(300),
        created_at,
    }
}

#[allow(clippy::too_many_arguments)]
fn registration_outcome(
    organization_id: &Did,
    local_admin_subject: &Did,
    scopes: &[OrganizationRegistrationScope],
    generation: u64,
    status: OrganizationRegistrationStatus,
    version_id: &str,
    issued_at: chrono::DateTime<Utc>,
    created: bool,
) -> OrganizationRegistrationOutcome {
    let issuer = Did::new("did:webvh:zService:service.example").expect("valid service DID");
    let mut receipt = OrganizationRegistrationReceipt {
        registration_receipt_id: "ak:organization-registration-receipt:placeholder".to_owned(),
        organization_id: organization_id.clone(),
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
            alg: "EdDSA".to_owned(),
            verification_method: format!("{issuer}#registry-key-1"),
            payload_digest: test_hash("placeholder-payload"),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..contract-fixture".to_owned(),
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

pub async fn assert_proposal_member_receipt_store_contract(
    store: &dyn ProposalMemberReceiptStore,
    namespace: &str,
) {
    let first = ProposalMemberReceiptRecord {
        receipt_key: format!("proposal-member-receipt:{namespace}"),
        request_hash: "sha256:first".to_owned(),
        response_body: serde_json::json!({"member_receipt": "first"}),
        created_at: database_timestamp_now(),
    };
    store
        .record(&first)
        .await
        .expect("record first member receipt");
    assert_eq!(
        store
            .get(&first.receipt_key)
            .await
            .expect("read first member receipt"),
        Some(first.clone())
    );

    let mut competing = first.clone();
    competing.request_hash = "sha256:competing".to_owned();
    competing.response_body = serde_json::json!({"member_receipt": "competing"});
    store
        .record(&competing)
        .await
        .expect("record competing member receipt");
    assert_eq!(
        store
            .get(&first.receipt_key)
            .await
            .expect("read winning member receipt"),
        Some(first),
        "proposal member receipts are permanent first-writer-wins evidence"
    );
}

pub struct EventCommitContractStores<'a> {
    pub unit_of_work: &'a dyn EventCommitUnitOfWork,
    pub events: &'a dyn EventStore,
    pub projections: &'a dyn ProjectionEventStore,
    pub idempotency: &'a dyn IdempotencyStore,
    pub outbox: &'a dyn FederationOutboxStore,
}

fn canonical_wire_event_record(
    event_id: &str,
    actor_id: &str,
    realm_id: &str,
    actor_seq: u64,
    now: chrono::DateTime<Utc>,
) -> CanonicalEventRecord {
    let event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(event_id.to_owned()).expect("contract event id"),
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .expect("contract realm id"),
        },
        Did::new(actor_id.to_owned()).expect("contract actor DID"),
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
    let canonical_digest = event.event_digest().expect("contract event digest");
    let envelope = serde_json::to_value(&event).expect("contract wire event encodes");
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&envelope).expect("contract canonical bytes");
    CanonicalEventRecord {
        event_id: event_id.to_owned(),
        actor_id: actor_id.to_owned(),
        actor_seq,
        realm_id: Some(realm_id.to_owned()),
        kind: "ak.message.create".to_owned(),
        schema_id: "arkret://events/message/create/v1".to_owned(),
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: now,
    }
}

pub async fn assert_event_commit_unit_of_work_contract(
    stores: EventCommitContractStores<'_>,
    namespace: &str,
) {
    let now = database_timestamp_now();
    let event_uuid = uuid::Uuid::now_v7();
    let realm_uuid = uuid::Uuid::now_v7();
    let event_id = format!("ak:event:{event_uuid}");
    let realm_id = format!("ak:realm:{realm_uuid}");
    let principal_id = format!("did:web:{namespace}.example");
    let idempotency_key = format!("event-commit:{namespace}:{event_uuid}");
    let outbox_id = format!("outbox:{namespace}:{event_uuid}");
    let request = EventCommitRequest {
        event: canonical_wire_event_record(&event_id, &principal_id, &realm_id, 0, now),
        control_proposal_receipt: None,
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
            peer_url: "https://peer.example".to_owned(),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key: format!("peer:{event_uuid}"),
            payload_json: "{}".to_owned(),
            state: FederationOutboxState::Pending,
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

    let rollback_uuid = uuid::Uuid::now_v7();
    let rollback_event_id = format!("ak:event:{rollback_uuid}");
    let rollback_idempotency_key = format!("event-rollback:{namespace}:{rollback_uuid}");
    let rollback_outbox_id = format!("outbox-rollback:{namespace}:{rollback_uuid}");
    let failed = EventCommitRequest {
        event: canonical_wire_event_record(&rollback_event_id, &principal_id, &realm_id, 1, now),
        control_proposal_receipt: None,
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
            peer_url: "https://peer.example".to_owned(),
            endpoint: "/_arkret/peer/events".to_owned(),
            idempotency_key: format!("peer:{rollback_uuid}"),
            payload_json: "{}".to_owned(),
            state: FederationOutboxState::Pending,
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
/// 7. `policy_suppressed` only leaves that state through revalidation.
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
                outcome: FederationOutboxOutcome::DeadLettered(FederationOutboxDeadLetterRecord {
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
                }),
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
    let realm_id = format!("ak:realm:{}", uuid::Uuid::now_v7());
    // The Realm genesis unit requires one proposal receipt per Event. Supplying
    // them is what makes this test actually about the outbox: without them the
    // batch would abort on receipt cardinality and never reach the outbox
    // insert, so the rollback assertion below would pass for the wrong reason.
    let proposal_receipt = |record: &CanonicalEventRecord| arkret_wire::ControlProposalReceipt {
        kind: arkret_wire::ControlProposalReceiptKind::ProposalReceipt,
        realm_id: arkret_wire::RealmId::new(realm_id.clone()).expect("typed realm id"),
        proposal_digest: Hash::new(record.canonical_digest.clone()).expect("typed digest"),
        received_at: now,
        decision_due_at: now + Duration::hours(1),
        absolute_due_at: now + Duration::hours(24),
        defer_count: 0,
        authority_set_ref: Hash::new(format!("sha256:{}", "a".repeat(64)))
            .expect("typed authority set ref"),
        member_receipts: Vec::new(),
    };
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

    let bootstrap_event_id = format!("ak:event:{}", uuid::Uuid::now_v7());
    let bootstrap_record =
        canonical_wire_event_record(&bootstrap_event_id, &principal_id, &realm_id, 0, now);
    assert!(
        events
            .put_realm_bootstrap_batch_atomic(
                vec![bootstrap_record.clone()],
                vec![proposal_receipt(&bootstrap_record)],
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

    let anchor_event_id = format!("ak:event:{}", uuid::Uuid::now_v7());
    assert!(
        events
            .put_identity_anchor_batch_atomic(
                vec![canonical_wire_event_record(
                    &anchor_event_id,
                    &principal_id,
                    &realm_id,
                    0,
                    now,
                )],
                Vec::new(),
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
    let committed_event_id = format!("ak:event:{}", uuid::Uuid::now_v7());
    let committed_outbox_id = format!("outbox:{namespace}:committed");
    let committed_record =
        canonical_wire_event_record(&committed_event_id, &principal_id, &realm_id, 0, now);
    events
        .put_realm_bootstrap_batch_atomic(
            vec![committed_record.clone()],
            vec![proposal_receipt(&committed_record)],
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
        ssk_generation: Some(1),
        device_authorize_event_id: None,
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
        ssk_generation: Some(1),
        device_authorize_event_id: None,
        agent_key_authorize_event_id: None,
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
        .consume_claim(&consumed.id, &group_id, 15)
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
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
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
        PeerKeyPackageClaimLedgerWriteResult::Existing(first.clone())
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
