#[path = "../../test-support/src/device_authorization_history.rs"]
mod device_history_fixture;
mod support;

use arkret_models_collaboration::events_payloads::device_authorize_payload_digest;
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_identity::{
    IdentityBindingPurpose, IdentityCreationControlProofKind, PCR_GENESIS_UNIT_KINDS,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};
use arkret_wire::{
    DidCoreId, Hash, IdempotencyKey, PcrGenesisUnit, RealmCommitAuthorityRef, TrustDomainId,
    WebOrigin,
};
use diesel::sql_types::{BigInt, Text, Uuid};
use diesel_async::RunQueryDsl;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority,
    PcrGenesisCommitOutcome, PcrGenesisCommitUnit,
};
use soland_storage_postgres::{Db, PgAuthorityCommitStore};

#[derive(diesel::QueryableByName)]
struct StationRow {
    #[diesel(sql_type = Text)]
    station_id: String,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn hash(value: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).unwrap()
}

fn unit(station: DidCoreId) -> PcrGenesisCommitUnit {
    let options = device_history_fixture::DeviceHistoryFixtureOptions {
        local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
        ..Default::default()
    };
    let fixture = device_history_fixture::DeviceHistoryFixture::new_with(station.clone(), options);
    let created_at = fixture.commits[0].committed_at;
    let evidence = arkret_signatures::webvh::sign_registration_did_evidence_draft(
        &fixture.inception,
        created_at,
        &[70; 32],
    )
    .unwrap()
    .accept(created_at)
    .unwrap();
    let create = fixture.events[0].clone();
    let authorize = fixture.events[1].clone();
    let authorize_value =
        serde_json::Value::Object(authorize.payload.clone().into_iter().collect());
    let create_digest =
        Hash::new(arkret_canonical::canonical_sha256(&create.payload).unwrap()).unwrap();
    let authorize_digest =
        device_authorize_payload_digest(&authorize_value, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    let proof = arkret_signatures::webvh::sign_identity_creation_control_proof(
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: "fixture-challenge".to_owned(),
            challenge: "fixture-challenge-value".to_owned(),
            purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
            account_subject: hash("fixture-account"),
            principal_id: fixture.account.principal_id.clone(),
            did: fixture.did.clone(),
            registration_anchor_digest: fixture.registration_anchor.canonical_digest().unwrap(),
            did_version_id: evidence.version_id.clone(),
            control_key_digest: evidence.control_key_digest.clone(),
            pcr_realm_id: create.realm_id.clone(),
            realm_create_payload_digest: create_digest,
            founding_authorize_payload_digest: authorize_digest,
            initial_session_request_digest: hash("fixture-initial-session"),
            genesis_unit_kinds: PCR_GENESIS_UNIT_KINDS,
            identity_creation_lease_id: "fixture-lease".to_owned(),
            lease_fence: 1,
            dpop_jkt: "fixture-thumbprint".to_owned(),
            audience_id: station.clone(),
            origin: WebOrigin::new("https://principal.example").unwrap(),
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            issued_at: created_at,
            expires_at: created_at + chrono::TimeDelta::minutes(5),
            verification_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &ed25519_dalek::SigningKey::from_bytes(&[70; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        })
        .unwrap(),
        &[70; 32],
    )
    .unwrap();
    let submission = PcrGenesisAdmissionInput {
        account_authority_id: station.clone(),
        principal_id: fixture.account.principal_id.clone(),
        did: fixture.did.clone(),
        pcr_realm_id: create.realm_id.clone(),
        did_version_id: evidence.version_id.clone(),
        control_key_digest: evidence.control_key_digest.clone(),
        idempotency_key: IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
        registration_request_digest: hash("fixture-registration"),
        principal_registration_anchor: fixture.registration_anchor,
        registration_did_evidence: evidence,
        identity_creation_control_proof: proof,
        genesis_unit: PcrGenesisUnit::new(create.clone(), authorize.clone()).unwrap(),
    };
    let authority = CurrentRealmAuthority {
        realm_id: create.realm_id.clone(),
        generation: 0,
        service_id: station,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(create.event_id.clone()),
        last_handoff_ref: None,
    };
    let transactions = [
        (create, fixture.commits[0].clone()),
        (authorize, fixture.commits[1].clone()),
    ]
    .map(|(event, commit)| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    });
    let exact_request_body = serde_json::to_vec(&submission).unwrap();
    PcrGenesisCommitUnit {
        submission,
        exact_request_body,
        transactions,
    }
}

#[tokio::test]
async fn founding_device_conflict_rolls_back_both_commits_and_exact_replay_is_stable() {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,'ak:did_core:web:pcr-contract.example') ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<StationRow>(&mut *conn)
            .await
            .unwrap();
    let unit = unit(DidCoreId::new(station.station_id.clone()).unwrap());
    unit.validate().unwrap();
    let device_id = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::DeviceAuthorizePayload,
    >(serde_json::Value::Object(
        unit.submission
            .genesis_unit
            .founding_authorize()
            .payload
            .clone()
            .into_iter()
            .collect(),
    ))
    .unwrap()
    .device_id;
    let principal = unit.submission.principal_id.as_str();
    diesel::sql_query(
        "INSERT INTO devices(id,station_id,actor_id,device_id,payload) VALUES($1,$2,$3,$4,'{}'::jsonb)",
    )
    .bind::<Uuid, _>(uuid::Uuid::now_v7())
    .bind::<Text, _>(&station.station_id)
    .bind::<Text, _>(principal)
    .bind::<Text, _>(device_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let at = unit.transactions[0].commit.committed_at;
    assert!(
        store
            .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.admit_pcr_genesis_unit(&unit, at).await.is_err());
    assert!(
        store
            .current_authority(&unit.submission.pcr_realm_id)
            .await
            .unwrap()
            .is_none()
    );
    for transaction in &unit.transactions {
        assert!(
            store
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut conn = pool.get().await.unwrap();
    let remaining =
        diesel::sql_query("SELECT COUNT(*) AS count FROM pcr_genesis_units WHERE realm_id=$1")
            .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(remaining.count, 0);
    let resolution = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(principal)
    .bind::<Text, _>(&station.station_id)
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(resolution.count, 0);
    let realm_root = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(realm_root.count, 0);
    diesel::sql_query("DELETE FROM devices WHERE actor_id=$1 AND device_id=$2")
        .bind::<Text, _>(principal)
        .bind::<Text, _>(device_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    let committed = store.admit_pcr_genesis_unit(&unit, at).await.unwrap();
    let PcrGenesisCommitOutcome::Committed(result) = committed else {
        panic!("first PCR genesis must commit");
    };
    assert_eq!(
        store
            .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap(),
        Some(result.clone()),
    );
    assert_eq!(
        store.admit_pcr_genesis_unit(&unit, at).await.unwrap(),
        PcrGenesisCommitOutcome::Duplicate(result),
    );
    let mut changed = unit;
    changed.exact_request_body.push(b' ');
    assert!(
        store
            .pcr_genesis_replay(&changed.submission, &changed.exact_request_body)
            .await
            .is_err()
    );
    assert!(store.admit_pcr_genesis_unit(&changed, at).await.is_err());
}
