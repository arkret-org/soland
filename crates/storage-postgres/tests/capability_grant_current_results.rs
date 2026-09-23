mod support;

use std::sync::OnceLock;

use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CapabilityGrantCurrentResultStore, CapabilityGrantCurrentStatus, CurrentRealmAuthority,
    PersistenceError,
};
use soland_storage_postgres::{
    Db, PgAuthorityCommitStore, PgCapabilityGrantCurrentResultStore, PgPool,
};

const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

static TEST_POOL: OnceLock<PgPool> = OnceLock::new();

async fn test_pool() -> PgPool {
    if let Some(pool) = TEST_POOL.get() {
        return pool.clone();
    }
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool");
    let _ = TEST_POOL.set(pool.clone());
    pool
}

#[tokio::test]
async fn postgres_reads_capability_value_and_revision_from_one_current_row() {
    let pool = test_pool().await;
    let value = serde_json::json!({
        "id": GRANT_ID,
        "schema": "ak.schema.capability.v1",
        "realm_id": REALM_ID,
        "status": "active"
    });
    let now = chrono::Utc::now();
    let event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x44; 32]);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value,updated_at) \
         VALUES($1,$2,'active',$3,$4,$5,$6,$7,$8) \
         ON CONFLICT(realm_id,grant_id) DO UPDATE SET \
           status=EXCLUDED.status,current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id,current_stream_ref=EXCLUDED.current_stream_ref, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(REALM_ID)
    .bind::<Text, _>(GRANT_ID)
    .bind::<Text, _>(event_id.as_str())
    .bind::<Text, _>(COMMIT_ID)
    .bind::<Jsonb, _>(&serde_json::json!({"kind":"realm","realm_id":REALM_ID}))
    .bind::<BigInt, _>(41_i64)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    let realm_id = REALM_ID.parse().unwrap();
    let grant_id = GRANT_ID.parse().unwrap();
    let store = PgCapabilityGrantCurrentResultStore { pool };
    let record = store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .expect("current grant row");
    assert_eq!(record.status, CapabilityGrantCurrentStatus::Active);
    assert_eq!(record.value, value);
    assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
    assert_eq!(record.revision.stream_position, 41);

    let snapshot = store.snapshot_for_realm(&realm_id).await.unwrap();
    let listed = snapshot
        .into_iter()
        .find(|row| row.grant_id == grant_id)
        .expect("grant appears in the same-statement Realm snapshot");
    assert_eq!(listed.value, record.value);
    assert_eq!(listed.revision, record.revision);
}

fn fixture_did(core_id: &arkret_wire::DidCoreId) -> String {
    format!(
        "did:{}",
        core_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .expect("fixture core id")
    )
}

fn fixture_signature(
    service_id: &arkret_wire::DidCoreId,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(format!(
            "{}#authority",
            fixture_did(service_id)
        ))
        .unwrap(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

fn producer_event(
    kind: arkret_wire::EventKind,
    realm_id: &arkret_wire::RealmId,
    actor_id: &arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id.clone(),
        station_id.clone(),
        payload,
        created_at,
    )
    .unwrap();
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(format!("{}#device", fixture_did(actor_id)))
            .unwrap(),
        event_digest: digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(created_at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

fn transaction(
    authority: &CurrentRealmAuthority,
    event: &arkret_wire::Event,
    stream_position: u64,
    previous_commit_ref: Option<arkret_wire::RealmCommitId>,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> AuthorityCommitTransaction {
    let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{stream_position}", event.event_id).as_bytes(),
    ));
    AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        commit: arkret_wire::RealmCommit {
            commit_id,
            realm_id: event.realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position,
            previous_commit_ref,
            event_ref: event.event_id.clone(),
            governance_generation: authority.generation,
            authority_ref: authority.authority_ref.clone(),
            committed_at,
            signature: fixture_signature(&authority.service_id, committed_at),
        },
        event: event.clone(),
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    }
}

#[tokio::test]
async fn authority_transaction_materializes_grant_and_rolls_back_stale_cas() {
    let pool = test_pool().await;
    let realm_seed = format!("capability-current:{}", uuid::Uuid::now_v7());
    let realm_event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(realm_seed.as_bytes()),
    );
    let realm_id = arkret_wire::RealmId::from_event_id(&realm_event_id);
    let station_id = arkret_wire::DidCoreId::new("ak:did_core:web:grant-station.example").unwrap();
    let actor_id = arkret_wire::DidCoreId::new("ak:did_core:web:grant-author.example").unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor_id.clone(),
        station_id.clone(),
    ));
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: station_id.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            arkret_identifiers::EventIdentityKey::new(
                realm_id.digest_suite_code(),
                realm_id.digest_bytes(),
            )
            .event_id(),
        ),
        last_handoff_ref: None,
    };
    let authority_store = PgAuthorityCommitStore { pool: pool.clone() };
    authority_store
        .install_genesis_authority(&authority)
        .await
        .unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-21T00:00:00Z")
        .unwrap()
        .to_utc();
    let root_commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        b"capability-root-current",
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO realm_authority_root_current_results \
         (realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) \
         VALUES($1,$2,0,0,$3,$4,0,$5)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&actor).unwrap())
    .bind::<Text, _>(realm_event_id.as_str())
    .bind::<Text, _>(root_commit_id.as_str())
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let create = producer_event(
        arkret_wire::EventKind::CapabilityGrant,
        &realm_id,
        &actor_id,
        &station_id,
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id.clone(),
                "issuer_id": actor.clone(),
                "subject": actor,
                "actions": ["ak.message.create"],
                "resources": [{"kind":"realm", "realm_id":realm_id.clone()}],
                "issuer_authority_refs": [{
                    "kind":"realm_root",
                    "realm_id":realm_id.clone(),
                    "authority_event_ref":realm_event_id.clone(),
                    "authority_generation":0
                }],
                "issued_at": "2026-09-21T00:00:00.000Z"
            }
        }),
        now,
    );
    let create_tx = transaction(&authority, &create, 0, None, now);
    let stale_agent_guard = soland_storage::SelfProducerCommitGuard::Agent {
        pcr_realm_id: realm_id.clone(),
        agent_id: actor_id.clone(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: create.event_id.clone(),
            commit_id: create_tx.commit.commit_id.clone(),
            stream_ref: create_tx.commit.stream_ref.clone(),
            stream_position: 0,
        },
        verification_method: create
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone(),
    };
    assert!(
        authority_store
            .admit_self_event_transaction(&create_tx, &stale_agent_guard, now)
            .await
            .is_err()
    );
    assert!(
        authority_store
            .queued_event(&create.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        authority_store
            .stream_head(&create_tx.commit.stream_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        authority_store
            .admit_event_transaction(&create_tx, now)
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Committed
    );
    let grant_id = arkret_wire::GrantId::from_event_id(&create.event_id);
    let current_store = PgCapabilityGrantCurrentResultStore { pool: pool.clone() };
    let created = current_store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.status, CapabilityGrantCurrentStatus::Active);
    assert_eq!(created.revision.commit_id, create_tx.commit.commit_id);

    assert_eq!(
        authority_store
            .admit_event_transaction(&create_tx, now)
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Duplicate
    );
    assert_eq!(
        current_store
            .get(&realm_id, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        created.revision
    );

    let stale = producer_event(
        arkret_wire::EventKind::CapabilityRevoke,
        &realm_id,
        &actor_id,
        &station_id,
        serde_json::json!({
            "grant_id": grant_id.clone(),
            "expected_revision": {
                "commit_id": COMMIT_ID,
                "stream_position": 999
            }
        }),
        now + chrono::TimeDelta::seconds(1),
    );
    let stale_tx = transaction(
        &authority,
        &stale,
        1,
        Some(create_tx.commit.commit_id.clone()),
        now + chrono::TimeDelta::seconds(1),
    );
    assert!(matches!(
        authority_store
            .admit_event_transaction(&stale_tx, now)
            .await,
        Err(PersistenceError::Conflict(_))
    ));
    assert!(
        authority_store
            .queued_event(&stale.event_id)
            .await
            .unwrap()
            .is_none(),
        "CAS failure must roll back the queued Event"
    );
    assert_eq!(
        current_store
            .get(&realm_id, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        created.revision
    );

    let revoke = producer_event(
        arkret_wire::EventKind::CapabilityRevoke,
        &realm_id,
        &actor_id,
        &station_id,
        serde_json::json!({
            "grant_id": grant_id,
            "expected_revision": created.revision
        }),
        now + chrono::TimeDelta::seconds(2),
    );
    let revoke_tx = transaction(
        &authority,
        &revoke,
        1,
        Some(create_tx.commit.commit_id.clone()),
        now + chrono::TimeDelta::seconds(2),
    );
    assert_eq!(
        authority_store
            .admit_event_transaction(&revoke_tx, now)
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Committed
    );
    let revoked = current_store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.status, CapabilityGrantCurrentStatus::Revoked);
    assert_eq!(revoked.revision.commit_id, revoke_tx.commit.commit_id);
    assert_eq!(revoked.source.event_id, revoke.event_id);
    assert_eq!(revoked.value["status"], "revoked");
    assert_eq!(
        revoked.value["revoked_by"],
        serde_json::to_value(&revoke.actor_id).unwrap()
    );
}
