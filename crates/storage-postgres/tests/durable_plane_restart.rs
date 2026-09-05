//! Restart-semantics integration tests for the five data planes that used to
//! be memory-only in production (realm_meta, messages, device_keys,
//! one_time_keys, member identity). Each case writes through one connection
//! pool, drops it, reconnects with a fresh pool (equivalent to a process
//! restart) and verifies the rows survive.
//!
//! Every case requires `DATABASE_URL`; without one they fail rather than skip,
//! because a silent skip here would leave the durable planes unverified.

use soland_storage::contract_tests::{
    assert_device_key_store_contract, assert_member_identity_store_contract,
    assert_message_store_contract, assert_one_time_key_store_contract,
    assert_realm_meta_store_contract, minimal_history_signer_evidence,
};
use soland_storage::{
    DeviceKeyStore, GovernanceDependencyStore, MemberIdentityEventRecord, MemberIdentityStore,
    MemberIdentitySubjectKey, MessageRecord, MessageStore, OneTimeKeyStore, RealmMetaRecord,
    RealmMetaStore,
};
use soland_storage_postgres::{
    Db, PgDeviceKeyStore, PgGovernanceDependencyStore, PgMemberIdentityStore, PgMessageStore,
    PgOneTimeKeyStore, PgPool, PgRealmMetaStore,
};

/// Build a fresh pool against the configured database. Migrations are
/// idempotent, so a second `Db::connect` behaves like a restarted process
/// attaching to the same database.
/// The database these contracts run against.
///
/// Same rule as `test_database::configured_url`: `SOLAND_TEST_DATABASE_URL`
/// wins, `DATABASE_URL` is the fallback. It is spelled again here rather than
/// called because an integration test links the library *without* `cfg(test)`,
/// and a crate cannot enable its own `test-support` feature for its own
/// `tests/` targets. Keep the two in step -- reading only `DATABASE_URL`, as
/// this did until 2026-09-05, made the documented way of running the suite
/// fail 48 contract tests with a message naming the other variable.
fn configured_url() -> String {
    for key in ["SOLAND_TEST_DATABASE_URL", "DATABASE_URL"] {
        if let Ok(value) = std::env::var(key)
            && !value.trim().is_empty()
        {
            return value;
        }
    }
    panic!(
        "{}",
        concat!(
            "no test database is configured: set SOLAND_TEST_DATABASE_URL or DATABASE_URL ",
            "to a PostgreSQL instance. These contract tests are the only proof the Postgres ",
            "adapters honour the storage contracts, so they fail rather than skip."
        )
    );
}

async fn fresh_pool() -> PgPool {
    Db::connect(Some(&configured_url()), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool")
}

/// `Db::connect` re-runs the embedded migrations on every call; two
/// concurrent first-time migration runs race on catalog rows (`pg_type`
/// duplicate key), so every case holds this guard for its whole duration,
/// matching the `store_contracts.rs` pattern.
static DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Round every timestamp through Postgres precision (microseconds) so stored
/// rows compare equal to the in-memory originals.
fn database_now() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    chrono::DateTime::from_timestamp_micros(now.timestamp_micros()).expect("micros round-trip")
}

#[tokio::test]
async fn postgres_realm_meta_survives_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgRealmMetaStore { pool: pool.clone() };
    let namespace = format!("postgres-realm-meta-{}", uuid::Uuid::now_v7());
    assert_realm_meta_store_contract(&store, &namespace).await;

    let realm_id = format!("ak:realm:{namespace}-restart");
    let now = database_now();
    let record = RealmMetaRecord {
        owner: format!("did:web:{namespace}-owner.example"),
        deleted: false,
        discoverability: "public".to_owned(),
        history_access: "since_join".to_owned(),
        preview_policy: None,
        preview_policy_digest: None,
        asset_privacy_policy: None,
        asset_privacy_policy_digest: None,
        encryption_profile: Some("mls_rfc9420".to_owned()),
        plaintext_visible_services: Default::default(),
        plaintext_visible_service_classes: Default::default(),
        minimal_metadata_realm: false,
        created_at: now,
        updated_at: now,
    };
    store
        .put(&realm_id, &record)
        .await
        .expect("write realm meta before restart");
    drop(pool);

    // After a restart the Realm owner must still resolve; this is the read
    // startup hydration performs before lawful controller-issued Agent grants
    // can pass the `grant_exceeds_issuer_authority` check.
    let restarted_pool = fresh_pool().await;
    let restarted = PgRealmMetaStore {
        pool: restarted_pool,
    };
    assert_eq!(
        restarted
            .get(&realm_id)
            .await
            .expect("read realm meta after restart"),
        Some(record),
        "realm owner must survive restart"
    );
}

#[tokio::test]
async fn postgres_messages_survive_restart_and_dedup() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgMessageStore { pool: pool.clone() };
    let namespace = format!("postgres-messages-{}", uuid::Uuid::now_v7());
    assert_message_store_contract(&store, &namespace).await;
    drop(pool);

    // The contract leaves `second` in place; after a restart the snapshot
    // projection (`messages_for_realm`) must still see it, and replaying the
    // same Event id must dedup instead of double-storing.
    let restarted_pool = fresh_pool().await;
    let restarted = PgMessageStore {
        pool: restarted_pool,
    };
    let realm_id = format!("ak:realm:{namespace}");
    let listed = restarted
        .list_for_realm(&realm_id, 100)
        .await
        .expect("list realm messages after restart");
    assert_eq!(
        listed.len(),
        1,
        "snapshot message projection survives restart"
    );
    let replayed = MessageRecord {
        content: serde_json::json!({"body": "replayed-with-different-content"}),
        ..listed[0].clone()
    };
    restarted
        .put(&replayed)
        .await
        .expect("replay projected message after restart");
    let after_replay = restarted
        .list_for_realm(&realm_id, 100)
        .await
        .expect("list realm messages after replay");
    assert_eq!(after_replay, listed, "idempotency dedup survives restart");
}

#[tokio::test]
async fn postgres_device_keys_survive_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgDeviceKeyStore { pool: pool.clone() };
    let namespace = format!("postgres-device-keys-{}", uuid::Uuid::now_v7());
    assert_device_key_store_contract(&store, &namespace).await;
    drop(pool);

    let restarted_pool = fresh_pool().await;
    let restarted = PgDeviceKeyStore {
        pool: restarted_pool,
    };
    let actor = format!("did:web:{namespace}.example");
    let device_id = format!("ak:device:{namespace}");
    let bundle = restarted
        .get(&actor, &device_id)
        .await
        .expect("read device key bundle after restart")
        .expect("uploaded device key bundle survives restart");
    assert_eq!(bundle["rotated"], serde_json::json!(true));
}

#[tokio::test]
async fn postgres_one_time_keys_claim_survives_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgOneTimeKeyStore { pool: pool.clone() };
    let namespace = format!("postgres-one-time-keys-{}", uuid::Uuid::now_v7());
    assert_one_time_key_store_contract(&store, &namespace).await;

    let actor = format!("did:web:{namespace}-restart.example");
    let device_id = format!("ak:device:{namespace}-restart");
    let pooled =
        serde_json::json!({"key_id": format!("curve25519:{namespace}-restart"), "key": "restart"});
    store
        .put(actor.clone(), device_id.clone(), vec![pooled.clone()])
        .await
        .expect("pool one-time key before restart");
    drop(pool);

    let restarted_pool = fresh_pool().await;
    let restarted = PgOneTimeKeyStore {
        pool: restarted_pool,
    };
    assert_eq!(
        restarted
            .claim(&actor, &device_id)
            .await
            .expect("claim one-time key after restart"),
        Some(pooled),
        "claim must return a key from the pre-restart pool"
    );
    assert_eq!(
        restarted
            .claim(&actor, &device_id)
            .await
            .expect("claim drained pool after restart"),
        None
    );
}

#[tokio::test]
async fn postgres_member_identity_survives_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let store = PgMemberIdentityStore { pool: pool.clone() };
    let namespace = format!("postgres-member-identity-{}", uuid::Uuid::now_v7());
    assert_member_identity_store_contract(&store, &namespace).await;

    // The contract invalidates its handle claims at the end; stage one
    // restart-specific event to read back through a fresh pool.
    let restart_event = MemberIdentityEventRecord {
        event_id: format!("ak:event:{namespace}-restart"),
        subject: MemberIdentitySubjectKey {
            realm_id: format!("ak:realm:{namespace}"),
            actor_id: format!("ak:did_core:web:{namespace}.example"),
            segment: "member_identity".to_owned(),
        },
        payload_digest: format!("sha256:{}", "d".repeat(64)),
        replaces: Vec::new(),
        raw_event: serde_json::json!({"event_id": format!("ak:event:{namespace}-restart")}),
    };
    store
        .put_event(&restart_event)
        .await
        .expect("write member identity event before restart");
    drop(pool);

    let restarted_pool = fresh_pool().await;
    let restarted = PgMemberIdentityStore {
        pool: restarted_pool,
    };
    let events = restarted
        .snapshot_events()
        .await
        .expect("snapshot member identity events after restart");
    assert!(
        events.iter().any(|event| event == &restart_event),
        "accepted member identity events must survive restart"
    );
}

#[tokio::test]
async fn postgres_unscoped_signer_evidence_survives_restart() {
    let _db_guard = DB_GUARD.lock().await;
    let pool = fresh_pool().await;
    let namespace = format!("postgres-signer-evidence-{}", uuid::Uuid::now_v7());
    let item = minimal_history_signer_evidence(&namespace);
    let selector = item.selector().clone();
    let store = PgGovernanceDependencyStore { pool: pool.clone() };
    store
        .put_unscoped_signer_evidence_exact(item.clone())
        .await
        .expect("write signer evidence before restart");
    drop(store);
    drop(pool);

    let restarted_pool = fresh_pool().await;
    let restarted = PgGovernanceDependencyStore {
        pool: restarted_pool,
    };
    assert_eq!(
        restarted
            .get_unscoped_signer_evidence(&selector)
            .await
            .expect("read signer evidence after restart"),
        Some(item),
        "signer evidence CAS must survive restart"
    );
}
