//! A real accepted PCR ProfileCreate for grant-admission fixtures. The
//! governed Realm may share this database, but the profile still has its own
//! PCR, producer proof, covering Commit, and typed current result.

use arkret_wire::{ActorId, DetachedSignatureContext, Did, DidUrl, EventKind, RealmCommitId};
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use soland_storage::{ActorProfileAdmissionWrite, ActorProfileStore, AuthorityCommitTransaction};
use soland_storage_postgres::{PgActorProfileStore, PgPersistenceStore, PgPool};

pub async fn accepted_human_profile(pool: &PgPool, station_did: Did) -> ActorId {
    let fixture = crate::pcr_genesis::PcrGenesisFixture::new(station_did.clone());
    let mut conn = pool.get().await.expect("test database connection");
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) \
         ON CONFLICT(singleton) DO NOTHING",
    )
    .bind::<Text, _>(fixture.history.account.station_id.as_str())
    .execute(&mut *conn)
    .await
    .expect("hosted Station device inventory");
    drop(conn);
    let persistence = PgPersistenceStore::new(pool.clone());
    fixture
        .admit_founding_device(&persistence)
        .await
        .expect("accepted PCR founding device");
    let account = fixture.history.account.clone();
    let previous = &fixture.unit.transactions[1].commit;
    let at = previous.committed_at + chrono::TimeDelta::seconds(1);
    let event = crate::device_authorization_history::sign_event(
        arkret_wire::test_support::raw_event_at(
            EventKind::ProfileCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: fixture.unit.transactions[1].event.realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({"object": {
                "principal_id": account.principal_id,
                "actor_kind": "user",
                "display_name": "PG Human grant subject"
            }}),
            at,
        )
        .expect("valid ProfileCreate Event"),
        fixture.history.device_verification_method.clone(),
        fixture.history.founding_device_signing_seed,
    );
    let mut commit = previous.clone();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:profile", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = at;
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"])
        .expect("unsigned PCR Commit");
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).expect("Station authority method"),
        at,
        &SigningKey::from_bytes(&crate::device_authorization_history::STATION_AUTHORITY_SEED),
    )
    .expect("signed PCR Commit");
    PgActorProfileStore { pool: pool.clone() }
        .admit_profile(ActorProfileAdmissionWrite {
            commit: AuthorityCommitTransaction {
                expected_authority: fixture.unit.transactions[1].expected_authority.clone(),
                event,
                commit,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        })
        .await
        .expect("accepted PCR ProfileCreate current");
    ActorId::account(account)
}
