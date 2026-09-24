#[path = "../../test-support/src/device_authorization_history.rs"]
mod device_history_fixture;
mod support;

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizePayload, device_authorize_payload_digest,
};
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_crypto::{
    AcceptedSecurityTransactionStep, BackupActiveSeriesPointer, BackupObjectRef,
    BackupRotationBinding, BackupRotationKind, BackupRotationPlan, PreparedEventBatchRequest,
    PreparedEventUnit, SecurityRotationRevokeCommandOutcome, SecurityRotationRevokeCommandResult,
    SecurityRotationRevokeProposal, SecurityRotationTransactionCreateRequest,
    SecurityTransactionAcceptor, SecurityTransactionCreateRequest, SecurityTransactionPreparedPlan,
    SecurityTransactionStep, SecurityTransactionTerminalOutcome,
};
use arkret_models_identity::{
    IdentityBindingPurpose, IdentityCreationControlProofKind, PCR_GENESIS_UNIT_KINDS,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};
use arkret_wire::{
    BackupId, BackupSeriesId, CanonicalPublicMaterial, DetachedSignatureContext, DeviceId,
    DidCoreId, DidUrl, EventKind, Hash, IdempotencyKey, PcrGenesisUnit, RealmCommitAuthorityRef,
    RealmCommitId, RealmId, TransactionId, TrustDomainId, WebOrigin,
};
use device_history_fixture::{DeviceHistoryFixture, DeviceHistoryFixtureOptions};
use diesel::sql_types::{BigInt, Jsonb, Text, Uuid};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer, SigningKey};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, DeviceRevocationStore,
    KeyBackupListPosition, KeyBackupListQuery, KeyBackupStore, PcrGenesisCommitOutcome,
    PcrGenesisCommitUnit, PersistenceError, RevokeCommandTerminalWrite, RevokeProposalCommitWrite,
    SecurityTransactionRecord, SecurityTransactionStepOutcomeRecord, SecurityTransactionStore,
};
use soland_storage_postgres::{
    Db, PgAuthorityCommitStore, PgDeviceRevocationStore, PgKeyBackupStore, PgPool,
    PgSecurityTransactionStore,
};

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

#[derive(diesel::QueryableByName)]
struct DeviceCurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Every durable row a PCR genesis admission can write for one Realm and its
/// principal.
#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct GenesisFootprint {
    #[diesel(sql_type = BigInt)]
    genesis_units: i64,
    #[diesel(sql_type = BigInt)]
    realm_authorities: i64,
    #[diesel(sql_type = BigInt)]
    canonical_events: i64,
    #[diesel(sql_type = BigInt)]
    realm_commits: i64,
    #[diesel(sql_type = BigInt)]
    authority_roots: i64,
    #[diesel(sql_type = BigInt)]
    principal_resolutions: i64,
    #[diesel(sql_type = BigInt)]
    devices: i64,
    #[diesel(sql_type = BigInt)]
    device_generations: i64,
    #[diesel(sql_type = BigInt)]
    device_authorizations: i64,
}

const NO_FOOTPRINT: GenesisFootprint = GenesisFootprint {
    genesis_units: 0,
    realm_authorities: 0,
    canonical_events: 0,
    realm_commits: 0,
    authority_roots: 0,
    principal_resolutions: 0,
    devices: 0,
    device_generations: 0,
    device_authorizations: 0,
};

const ACCEPTED_FOOTPRINT: GenesisFootprint = GenesisFootprint {
    genesis_units: 1,
    realm_authorities: 1,
    canonical_events: 2,
    realm_commits: 2,
    authority_roots: 1,
    principal_resolutions: 1,
    devices: 1,
    device_generations: 1,
    device_authorizations: 1,
};

async fn footprint(
    pool: &PgPool,
    realm_id: &RealmId,
    principal_id: &DidCoreId,
) -> GenesisFootprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT \
           (SELECT COUNT(*) FROM pcr_genesis_units WHERE realm_id=$1) AS genesis_units, \
           (SELECT COUNT(*) FROM realm_authorities WHERE realm_id=$1) AS realm_authorities, \
           (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS canonical_events, \
           (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS realm_commits, \
           (SELECT COUNT(*) FROM realm_authority_root_current_results WHERE realm_id=$1) \
             AS authority_roots, \
           (SELECT COUNT(*) FROM principal_resolutions WHERE principal_id=$2) \
             AS principal_resolutions, \
           (SELECT COUNT(*) FROM devices WHERE actor_id=$2) AS devices, \
           (SELECT COUNT(*) FROM pcr_device_generation_current_results WHERE realm_id=$1) \
             AS device_generations, \
           (SELECT COUNT(*) FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
             AS device_authorizations",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(principal_id.as_str())
    .get_result::<GenesisFootprint>(&mut *conn)
    .await
    .unwrap()
}

async fn unit_footprint(pool: &PgPool, unit: &PcrGenesisCommitUnit) -> GenesisFootprint {
    footprint(
        pool,
        &unit.submission.pcr_realm_id,
        &unit.submission.principal_id,
    )
    .await
}

/// Contract database pool and the singleton Station every fixture commits for.
async fn contract_store() -> (PgPool, DidCoreId) {
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
    drop(conn);
    (pool, DidCoreId::new(station.station_id).unwrap())
}

fn page_fixture(
    id: &str,
    actor: &arkret_wire::ActorId,
    series: &str,
    seq: u64,
    previous: Option<&str>,
) -> serde_json::Value {
    let mut page = serde_json::json!({
        "backup_id":id, "actor_id":actor, "backup_kind":"secret_storage", "backup_version":"kb_1",
        "created_at":"2026-09-09T00:00:00.000Z", "series_id":series, "series_seq":seq,
        "encryption":{"recipient_method":"secret_storage_key", "recipient_key_ref":"backup-key", "aead":{"name":"xchacha20_poly1305", "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"secret_storage"},
        "contents":[{"item_kind":"recovery_key_share", "secret_id":"share"}],
        "ciphertext":"AAAA", "ciphertext_digest":"sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c",
        "auth_data":{
            "device_id":"ak:device:01904100-0000-7000-8000-000000000001",
            "verification_method":"did:web:backup.example#device-signer",
            "signature_algorithm":"Ed25519", "signature":"AAAA",
            "device_authorize_event_id":"ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
        }
    });
    if let Some(previous) = previous {
        page["supersedes_id"] = serde_json::json!(previous);
        page["supersedes_digest"] = serde_json::json!(
            "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"
        );
    }
    page
}

fn hash(value: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).unwrap()
}

fn fixture(station: &DidCoreId) -> DeviceHistoryFixture {
    let options = DeviceHistoryFixtureOptions {
        local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
        ..Default::default()
    };
    DeviceHistoryFixture::new_with(device_history_fixture::did_web_station(station), options)
}

fn unit(station: DidCoreId) -> PcrGenesisCommitUnit {
    let fixture = fixture(&station);
    assemble(station, fixture)
}

/// Re-author the genesis pair around a founding authorize payload that
/// claims `generation`.
///
/// The SDK refuses to build a registration-anchor possession transcript for any
/// generation other than one, so the candidate device signs the exact canonical
/// transcript with only that member changed. The root-committed descriptor
/// digest, both producer proofs, the derived PCR id and the commit chain are
/// all recomputed; the only defect left is the claimed generation.
fn reauthor_founding_generation(fixture: &mut DeviceHistoryFixture, generation: u64) {
    let payload = &fixture.events[1].payload;
    let typed: DeviceAuthorizePayload = serde_json::from_value(serde_json::Value::Object(
        payload.clone().into_iter().collect(),
    ))
    .unwrap();
    let transcript = typed
        .device_possession_signature_input(&fixture.account)
        .unwrap();
    let registered = br#""authorized_generation_ref":1,"#;
    let at = transcript
        .windows(registered.len())
        .position(|window| window == registered)
        .expect("the possession transcript carries the registration generation");
    let mut claimed = transcript[..at].to_vec();
    claimed.extend(format!(r#""authorized_generation_ref":{generation},"#).as_bytes());
    claimed.extend(&transcript[at + registered.len()..]);
    let device_signature = SigningKey::from_bytes(&fixture.founding_device_signing_seed)
        .sign(&claimed)
        .to_bytes();

    let mut payload = payload.clone();
    payload.insert(
        "authorized_generation_ref".to_owned(),
        serde_json::json!(generation),
    );
    payload.insert(
        "device_signature".to_owned(),
        serde_json::json!(arkret_canonical::base64url_encode(device_signature)),
    );
    let payload = serde_json::Value::Object(payload.into_iter().collect());
    let digest =
        device_authorize_payload_digest(&payload, arkret_canonical::DigestSuite::Sha256).unwrap();

    let mut create = fixture.events[0].clone();
    let descriptor = create
        .payload
        .get_mut("object")
        .and_then(|object| object.get_mut("founding_device_descriptor"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("a PCR create carries its founding device descriptor");
    assert!(descriptor.contains_key("founding_authorize_payload_digest"));
    descriptor.insert(
        "founding_authorize_payload_digest".to_owned(),
        serde_json::to_value(digest).unwrap(),
    );
    let root_seed = DeviceHistoryFixtureOptions::default().root_seed;
    let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&root_seed)
            .verifying_key()
            .to_bytes(),
    );
    let create = device_history_fixture::sign_event(
        create,
        DidUrl::new(format!("did:key:{root}#{root}")).unwrap(),
        root_seed,
    );
    let authorize = fixture.raw_event(EventKind::DeviceAuthorize, payload, &create.realm_id);
    let authorize = device_history_fixture::sign_event(
        authorize,
        fixture.device_verification_method.clone(),
        fixture.founding_device_signing_seed,
    );
    fixture.events.clear();
    fixture.commits.clear();
    fixture.append(vec![create, authorize]);
}

/// Relay the fixture's genesis pair and its commits as the complete unit the
/// governance Station admits.
fn assemble(station: DidCoreId, fixture: DeviceHistoryFixture) -> PcrGenesisCommitUnit {
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
        genesis_unit: PcrGenesisUnit {
            events: [create.clone(), authorize.clone()],
        },
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
    let mut conn = pool.get().await.unwrap();
    let generation = diesel::sql_query(
        "SELECT current_commit_id,value FROM pcr_device_generation_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
    .get_result::<DeviceCurrentRow>(&mut *conn)
    .await
    .unwrap();
    let authorization = diesel::sql_query(
        "SELECT current_commit_id,value FROM pcr_device_authorization_current_results \
         WHERE realm_id=$1 AND device_id=$2",
    )
    .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
    .bind::<Text, _>(device_id.as_str())
    .get_result::<DeviceCurrentRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        generation.current_commit_id,
        result.commits[1].commit_id.as_str()
    );
    assert_eq!(
        authorization.current_commit_id,
        result.commits[1].commit_id.as_str()
    );
    assert_eq!(
        generation.value,
        serde_json::json!({"current_device_generation_ref":1})
    );
    assert_eq!(authorization.value["authorized_generation_ref"], 1);
    assert_eq!(
        authorization.value["device_authorize_event_id"],
        serde_json::json!(unit.transactions[1].event.event_id)
    );
    assert!(authorization.value.get("device_id").is_none());
    drop(conn);
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

fn is_duplicate_conflict<T>(outcome: &Result<T, PersistenceError>) -> bool {
    matches!(outcome, Err(PersistenceError::Conflict(code)) if code == "duplicate_conflict")
}

fn unrelated_commit_id() -> RealmCommitId {
    RealmCommitId::from_digest(arkret_canonical::sha256_bytes(b"unrelated-commit"))
}

/// A genesis unit whose Commit pair is not the exact ordered chain over its
/// Event pair (`authority-commit-log.md` section 3) is rejected before any
/// durable write.
#[tokio::test]
async fn misbound_genesis_commit_chain_is_rejected_with_no_durable_write() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cases: [(&str, fn(&mut PcrGenesisCommitUnit)); 7] = [
        (
            "authorize commit does not chain to the create commit",
            |unit| {
                unit.transactions[1].commit.previous_commit_ref = Some(unrelated_commit_id());
            },
        ),
        ("authorize commit omits its predecessor", |unit| {
            unit.transactions[1].commit.previous_commit_ref = None;
        }),
        ("create commit claims a predecessor", |unit| {
            unit.transactions[0].commit.previous_commit_ref = Some(unrelated_commit_id());
        }),
        ("authorize commit skips a stream position", |unit| {
            unit.transactions[1].commit.stream_position = 2;
        }),
        ("create commit is not at stream position zero", |unit| {
            unit.transactions[0].commit.stream_position = 1;
            unit.transactions[1].commit.stream_position = 2;
        }),
        ("authorize commit orders the create Event", |unit| {
            unit.transactions[1].commit.event_ref = unit.transactions[0].event.event_id.clone();
        }),
        (
            "authorize commit claims a later governance generation",
            |unit| {
                unit.transactions[1].commit.governance_generation = 1;
            },
        ),
    ];
    for (case, corrupt) in cases {
        let mut unit = unit(station.clone());
        unit.validate().unwrap();
        corrupt(&mut unit);
        assert!(unit.validate().is_err(), "{case}: storage validation");
        let at = unit.transactions[0].commit.committed_at;
        let rejected = store.admit_pcr_genesis_unit(&unit, at).await;
        assert!(
            matches!(rejected, Err(PersistenceError::SchemaViolation(_))),
            "{case}: {rejected:?}"
        );
        assert_eq!(unit_footprint(&pool, &unit).await, NO_FOOTPRINT, "{case}");
        assert_eq!(
            store
                .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
                .await
                .unwrap(),
            None,
            "{case}: a rejected unit leaves no receipt"
        );
    }
}

/// `device-lifecycle.md` section 5: a `registration_anchor` authorize MUST
/// carry `authorized_generation_ref = 1`, the value the genesis unit
/// initializes. A fully re-signed unit claiming any other generation is
/// rejected with no durable write.
#[tokio::test]
async fn founding_authorize_generation_other_than_one_is_rejected_with_no_durable_write() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };

    let mut registered = fixture(&station);
    let original = registered.events.clone();
    reauthor_founding_generation(&mut registered, 1);
    assert_eq!(
        registered.events, original,
        "re-authoring at the registered generation reproduces the exact unit"
    );
    assemble(station.clone(), registered).validate().unwrap();

    for generation in [2, 7] {
        let mut claimed = fixture(&station);
        reauthor_founding_generation(&mut claimed, generation);
        let unit = assemble(station.clone(), claimed);
        let reason = unit.validate().unwrap_err().to_string();
        assert!(
            reason.contains("device_authorize_registration_generation_ref_must_be_one"),
            "generation {generation}: {reason}"
        );
        let at = unit.transactions[0].commit.committed_at;
        let rejected = store.admit_pcr_genesis_unit(&unit, at).await;
        assert!(
            matches!(
                &rejected,
                Err(PersistenceError::SchemaViolation(reason))
                    if reason.contains("device_authorize_registration_generation_ref_must_be_one")
            ),
            "generation {generation}: {rejected:?}"
        );
        assert_eq!(
            unit_footprint(&pool, &unit).await,
            NO_FOOTPRINT,
            "generation {generation}"
        );
    }
}

/// `account-lifecycle.md` section 2.1.2: the same idempotency key with
/// different bytes, or the same PCR under a different key, is a zero-write
/// `duplicate_conflict`; only the exact first request replays its outcome.
#[tokio::test]
async fn reused_genesis_realm_or_idempotency_key_is_a_zero_write_duplicate_conflict() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let accepted = unit(station.clone());
    let at = accepted.transactions[0].commit.committed_at;
    let PcrGenesisCommitOutcome::Committed(result) =
        store.admit_pcr_genesis_unit(&accepted, at).await.unwrap()
    else {
        panic!("first PCR genesis must commit");
    };
    assert_eq!(unit_footprint(&pool, &accepted).await, ACCEPTED_FOOTPRINT);

    let rekey = |mut unit: PcrGenesisCommitUnit, key: IdempotencyKey| {
        unit.submission.idempotency_key = key;
        unit.exact_request_body = serde_json::to_vec(&unit.submission).unwrap();
        unit.validate().unwrap();
        unit
    };

    let same_realm = rekey(
        accepted.clone(),
        IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    let replayed = store
        .pcr_genesis_replay(&same_realm.submission, &same_realm.exact_request_body)
        .await;
    assert!(is_duplicate_conflict(&replayed), "{replayed:?}");
    let admitted = store.admit_pcr_genesis_unit(&same_realm, at).await;
    assert!(is_duplicate_conflict(&admitted), "{admitted:?}");
    assert_eq!(unit_footprint(&pool, &accepted).await, ACCEPTED_FOOTPRINT);
    let mut conn = pool.get().await.unwrap();
    let foreign_key_receipts = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM pcr_genesis_units WHERE idempotency_key=$1",
    )
    .bind::<Text, _>(same_realm.submission.idempotency_key.to_string())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(foreign_key_receipts.count, 0);
    drop(conn);

    let same_key = rekey(
        unit(station.clone()),
        accepted.submission.idempotency_key.clone(),
    );
    let replayed = store
        .pcr_genesis_replay(&same_key.submission, &same_key.exact_request_body)
        .await;
    assert!(is_duplicate_conflict(&replayed), "{replayed:?}");
    let admitted = store.admit_pcr_genesis_unit(&same_key, at).await;
    assert!(is_duplicate_conflict(&admitted), "{admitted:?}");
    assert_eq!(unit_footprint(&pool, &same_key).await, NO_FOOTPRINT);

    assert_eq!(
        store.admit_pcr_genesis_unit(&accepted, at).await.unwrap(),
        PcrGenesisCommitOutcome::Duplicate(result),
    );
    assert_eq!(unit_footprint(&pool, &accepted).await, ACCEPTED_FOOTPRINT);
}

#[tokio::test]
async fn security_rotation_revoke_proposal_is_one_atomic_pcr_write() {
    use arkret_models_collaboration::events_payloads::DeviceRevokePayload;
    use arkret_wire::RealmCommit;

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let authorizer = fixture.founding_device_id.clone();
    let device_method = fixture.device_verification_method.clone();
    let device_seed = fixture.founding_device_signing_seed;
    let station_did = fixture.station_did.clone();
    let genesis = assemble(station.clone(), fixture);
    let realm_id = genesis.submission.pcr_realm_id.clone();
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let device_status = PgDeviceRevocationStore { pool: pool.clone() };
    assert!(
        device_status
            .pcr_device_active(&account, &authorizer, at)
            .await
            .unwrap()
    );
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let initial_pointer = backups
        .confirmed_active_series_for_device(&account, &authorizer, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        initial_pointer.authority_commit_id,
        genesis.transactions[1].commit.commit_id
    );
    assert!(matches!(
        initial_pointer.secret_storage,
        BackupActiveSeriesPointer::Absent {}
    ));
    let list_query = KeyBackupListQuery {
        actor_id: arkret_wire::ActorId::account(account.clone()).to_string(),
        backup_kind: None,
        series_id: None,
        after: None,
        limit: 51,
    };
    let confirmed_page = backups
        .confirmed_list_page_for_device(&account, &authorizer, at, &list_query)
        .await
        .unwrap();
    assert_eq!(confirmed_page.active_series, initial_pointer);
    assert!(confirmed_page.page.payloads.is_empty());
    assert_eq!(confirmed_page.page.revision, 0);
    let mut wrong_actor = list_query.clone();
    wrong_actor.actor_id = "different-account".to_owned();
    assert!(
        backups
            .confirmed_list_page_for_device(&account, &authorizer, at, &wrong_actor)
            .await
            .is_err()
    );

    let actor = arkret_wire::ActorId::account(account.clone());
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let first_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let second_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    backups
        .put(
            first_id.clone(),
            page_fixture(&first_id, &actor, &series, 0, None),
        )
        .await
        .unwrap();
    backups
        .put(
            second_id.clone(),
            page_fixture(&second_id, &actor, &series, 1, Some(&first_id)),
        )
        .await
        .unwrap();
    let mut first_query = list_query.clone();
    first_query.limit = 1;
    let first_page = backups
        .confirmed_list_page_for_device(&account, &authorizer, at, &first_query)
        .await
        .unwrap();
    assert_eq!(first_page.active_series, initial_pointer);
    assert_eq!(first_page.page.revision, 2);
    assert_eq!(first_page.page.payloads.len(), 1);
    assert_eq!(first_page.page.payloads[0]["backup_id"], first_id);
    first_query.after = Some(KeyBackupListPosition {
        backup_kind: "secret_storage".to_owned(),
        series_id: series,
        series_seq: 0,
        backup_id: first_id,
    });
    let second_page = backups
        .confirmed_list_page_for_device(&account, &authorizer, at, &first_query)
        .await
        .unwrap();
    assert_eq!(second_page.active_series, initial_pointer);
    assert_eq!(second_page.page.revision, first_page.page.revision);
    assert_eq!(second_page.page.payloads.len(), 1);
    assert_eq!(second_page.page.payloads[0]["backup_id"], second_id);

    let target = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let payload = serde_json::json!({
        "device_id": target,
        "revoked_by": authorizer,
        "revoked_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "reason": "security_rotation"
    });
    let _: DeviceRevokePayload = serde_json::from_value(payload.clone()).unwrap();
    let revoke = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            payload,
        )
        .unwrap(),
        device_method.clone(),
        device_seed,
    );
    let active_series = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({"fixture":"prepared-only"}),
        )
        .unwrap(),
        device_method.clone(),
        device_seed,
    );
    let mut covering: RealmCommit = genesis.transactions[1].commit.clone();
    covering.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:revoke", revoke.event_id).as_bytes(),
    ));
    covering.stream_position += 1;
    covering.previous_commit_ref = Some(genesis.transactions[1].commit.commit_id.clone());
    covering.event_ref = revoke.event_id.clone();
    covering.committed_at += chrono::TimeDelta::seconds(1);
    let station_key = SigningKey::from_bytes(&[83; 32]);
    let unsigned = arkret_canonical::canonical::unsigned_value(&covering, &["signature"]).unwrap();
    covering.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#authority", station_did)).unwrap(),
        covering.committed_at,
        &station_key,
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &covering.signature,
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: station_key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();

    let revoke_unit = PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        PreparedEventBatchRequest {
            events: vec![revoke.clone()],
        },
    )
    .unwrap();
    let active_unit = PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        PreparedEventBatchRequest {
            events: vec![active_series.clone()],
        },
    )
    .unwrap();
    let backup =
        |suffix: &str| BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap();
    let binding = BackupRotationBinding {
        backup_kind: BackupRotationKind::SecretStorage,
        previous_series_id: BackupSeriesId::new(format!(
            "ak:backup_series:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        new_series_id: BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        new_backups: vec![BackupObjectRef {
            backup_id: backup("new"),
            ciphertext_digest: hash("new-backup"),
        }],
        active_series_event_id: active_series.event_id.clone(),
        old_backups: vec![BackupObjectRef {
            backup_id: backup("old"),
            ciphertext_digest: hash("old-backup"),
        }],
    };
    let rotation = BackupRotationPlan {
        binding,
        encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
            serde_json::json!({"fixture":"ciphertext"}),
        )
        .unwrap(),
        active_series_unit: active_unit,
    };
    let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        authorizer.clone(),
        at + chrono::TimeDelta::hours(1),
        revoke_unit,
        hash("new-secret"),
        vec![rotation],
    )
    .unwrap();
    let plan = SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
    let (initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(request)
        .into_initial_resource(plan, at)
        .unwrap();
    let initial_record = SecurityTransactionRecord {
        resource: initial.clone(),
        canonical_request: canonical_request.clone(),
    };
    let transaction_id = initial.transaction_id.clone();
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    transactions.create(initial_record).await.unwrap();
    let awaiting = |ids: Vec<String>| ids.contains(&transaction_id.to_string());
    assert!(
        awaiting(transactions.rotations_awaiting_worker(1000).await.unwrap()),
        "a created rotation awaits its coordinator-owned revoke"
    );
    let mut proposed = initial;
    proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    let write = RevokeProposalCommitWrite {
        transaction: SecurityTransactionRecord {
            resource: proposed,
            canonical_request,
        },
        commit: AuthorityCommitTransaction {
            expected_authority: genesis.transactions[1].expected_authority.clone(),
            event: revoke.clone(),
            commit: covering.clone(),
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        queued_at: at,
    };
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE pcr_device_conflict_index_cuts SET conflict_revision=1 WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    assert!(
        backups
            .confirmed_active_series_for_device(&account, &authorizer, at)
            .await
            .is_err()
    );
    assert!(
        backups
            .confirmed_list_page_for_device(&account, &authorizer, at, &list_query)
            .await
            .is_err()
    );
    assert!(
        transactions
            .commit_revoke_proposal(write.clone())
            .await
            .is_err()
    );
    let committed =
        diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE commit_id=$1")
            .bind::<Text, _>(covering.commit_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(committed.count, 0);
    diesel::sql_query(
        "UPDATE pcr_device_conflict_index_cuts SET conflict_revision=0 WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    let mut bad_authorizer = write.clone();
    bad_authorizer.transaction.resource.authorizing_device_id = Some(target.clone());
    assert_eq!(
        transactions
            .commit_revoke_proposal(bad_authorizer)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::FailedPrecondition),
        "a producer other than the authorizing device is a registered precondition failure"
    );
    let mut bad_proof = write.clone();
    bad_proof.commit.event.producer_proof.as_mut().unwrap().jws = "invalid".to_owned();
    let bad_proof = transactions
        .commit_revoke_proposal(bad_proof)
        .await
        .unwrap_err();
    assert!(
        matches!(bad_proof, PersistenceError::SchemaViolation(_)),
        "an Event other than the prepared unit is refused before any read: {bad_proof}"
    );
    diesel::sql_query(
        "UPDATE pcr_device_generation_current_results SET value=jsonb_build_object('current_device_generation_ref',2) WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    assert!(
        transactions
            .commit_revoke_proposal(write.clone())
            .await
            .is_err()
    );
    diesel::sql_query(
        "UPDATE pcr_device_generation_current_results SET value=jsonb_build_object('current_device_generation_ref',1) WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    let before = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM pcr_device_revocation_proposals WHERE event_id=$1",
    )
    .bind::<Text, _>(revoke.event_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        before.count, 0,
        "rejected proposal leaked its immutable dot"
    );
    assert_eq!(
        transactions
            .commit_revoke_proposal(write.clone())
            .await
            .unwrap(),
        covering
    );
    assert_eq!(
        transactions.commit_revoke_proposal(write).await.unwrap(),
        covering
    );
    assert!(
        awaiting(transactions.rotations_awaiting_worker(1000).await.unwrap()),
        "a pending proposal still awaits its terminal decision"
    );
    let dots = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM pcr_device_revocation_proposals WHERE event_id=$1",
    )
    .bind::<Text, _>(revoke.event_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(dots.count, 1);
    let stored = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.resource.revoke_proposal.unwrap().covering_commit_id,
        covering.commit_id
    );

    let mut accepted = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let request_digest = accepted
        .resource
        .security_rotation_plan()
        .unwrap()
        .revoke_unit
        .request_digest
        .clone();
    accepted
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            prepared_material_digest: request_digest,
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            output_ref: covering.commit_id.to_string(),
            output_digest: hash("revoke-command-accepted"),
            accepted_at: at + chrono::TimeDelta::seconds(2),
        });
    accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
        result: SecurityRotationRevokeCommandResult::Accepted,
        decided_at: at + chrono::TimeDelta::seconds(2),
    });
    let terminal = RevokeCommandTerminalWrite {
        step_outcome: Some(SecurityTransactionStepOutcomeRecord {
            transaction_id: transaction_id.to_string(),
            step: SecurityTransactionStep::Revoke,
            canonical_request: b"revoke-worker-request".to_vec(),
            response: serde_json::to_value(&accepted.resource).unwrap(),
            participant_outcome: None,
        }),
        transaction: accepted,
    };
    let mut incomplete = terminal.clone();
    incomplete.step_outcome = None;
    assert!(
        transactions
            .commit_revoke_command_terminal(incomplete)
            .await
            .is_err()
    );
    let before_terminal = diesel::sql_query("SELECT COUNT(*) AS count FROM security_transaction_step_outcomes WHERE transaction_id=$1 AND step='revoke'")
        .bind::<Uuid,_>(uuid::Uuid::parse_str(transaction_id.as_str().strip_prefix("ak:transaction:").unwrap()).unwrap())
        .get_result::<CountRow>(&mut *conn).await.unwrap();
    assert_eq!(before_terminal.count, 0);
    let decided = transactions
        .commit_revoke_command_terminal(terminal.clone())
        .await
        .unwrap();
    assert!(
        awaiting(transactions.rotations_awaiting_worker(1000).await.unwrap()),
        "an accepted revoke stays queued for the worker-owned upload step"
    );
    assert_eq!(
        decided
            .resource
            .revoke_command_outcome
            .as_ref()
            .unwrap()
            .result,
        SecurityRotationRevokeCommandResult::Accepted
    );
    assert_eq!(
        transactions
            .commit_revoke_command_terminal(terminal)
            .await
            .unwrap()
            .resource,
        decided.resource,
    );
    let terminal_rows = diesel::sql_query("SELECT COUNT(*) AS count FROM security_transaction_step_outcomes WHERE transaction_id=$1 AND step='revoke'")
        .bind::<Uuid,_>(uuid::Uuid::parse_str(transaction_id.as_str().strip_prefix("ak:transaction:").unwrap()).unwrap())
        .get_result::<CountRow>(&mut *conn).await.unwrap();
    assert_eq!(terminal_rows.count, 1);
    // A decided proposal for another target does not revoke the authorizer.
    assert!(
        device_status
            .pcr_device_active(&account, &authorizer, at)
            .await
            .unwrap()
    );

    let reject_target = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let reject_event = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({
                "device_id": reject_target,
                "revoked_by": authorizer,
                "revoked_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "reason": "security_rotation"
            }),
        )
        .unwrap(),
        device_method.clone(),
        device_seed,
    );
    let mut reject_commit = covering.clone();
    reject_commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:rejected", reject_event.event_id).as_bytes(),
    ));
    reject_commit.stream_position += 1;
    reject_commit.previous_commit_ref = Some(covering.commit_id.clone());
    reject_commit.event_ref = reject_event.event_id.clone();
    reject_commit.committed_at += chrono::TimeDelta::seconds(1);
    let unsigned =
        arkret_canonical::canonical::unsigned_value(&reject_commit, &["signature"]).unwrap();
    reject_commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#authority", station_did)).unwrap(),
        reject_commit.committed_at,
        &station_key,
    )
    .unwrap();
    let reject_request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        authorizer.clone(),
        at + chrono::TimeDelta::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            PreparedEventBatchRequest {
                events: vec![reject_event.clone()],
            },
        )
        .unwrap(),
        hash("second-secret"),
        decided
            .resource
            .security_rotation_plan()
            .unwrap()
            .backup_rotations
            .clone(),
    )
    .unwrap();
    let reject_plan =
        SecurityTransactionPreparedPlan::SecurityRotation(reject_request.prepared_plan.clone());
    let (reject_initial, reject_request_bytes) =
        SecurityTransactionCreateRequest::SecurityRotation(reject_request)
            .into_initial_resource(reject_plan, at)
            .unwrap();
    let reject_id = reject_initial.transaction_id.clone();
    transactions
        .create(SecurityTransactionRecord {
            resource: reject_initial.clone(),
            canonical_request: reject_request_bytes.clone(),
        })
        .await
        .unwrap();
    let mut reject_proposed = reject_initial;
    reject_proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: reject_event.event_id.clone(),
        covering_commit_id: reject_commit.commit_id.clone(),
    });
    transactions
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: reject_proposed,
                canonical_request: reject_request_bytes,
            },
            commit: AuthorityCommitTransaction {
                expected_authority: genesis.transactions[1].expected_authority.clone(),
                event: reject_event.clone(),
                commit: reject_commit.clone(),
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        })
        .await
        .unwrap();
    let mut rejected = transactions.get(reject_id.as_str()).await.unwrap().unwrap();
    rejected.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: reject_event.event_id,
        covering_commit_id: reject_commit.commit_id.clone(),
        result: SecurityRotationRevokeCommandResult::Rejected,
        decided_at: at + chrono::TimeDelta::seconds(3),
    });
    rejected.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Aborted {
        completed_at: at + chrono::TimeDelta::seconds(3),
        reason_code: Some("rejected".to_owned()),
    });
    let rejected_write = RevokeCommandTerminalWrite {
        transaction: rejected,
        step_outcome: None,
    };
    let rejected_result = transactions
        .commit_revoke_command_terminal(rejected_write.clone())
        .await
        .unwrap();
    assert_eq!(
        rejected_result
            .resource
            .revoke_command_outcome
            .as_ref()
            .unwrap()
            .result,
        SecurityRotationRevokeCommandResult::Rejected
    );
    assert_eq!(
        transactions
            .commit_revoke_command_terminal(rejected_write.clone())
            .await
            .unwrap()
            .resource,
        rejected_result.resource
    );
    let mut changed_terminal = rejected_write;
    changed_terminal
        .transaction
        .resource
        .revoke_command_outcome
        .as_mut()
        .unwrap()
        .decided_at += chrono::TimeDelta::seconds(1);
    assert_eq!(
        transactions
            .commit_revoke_command_terminal(changed_terminal)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::DuplicateConflict),
        "a different terminal for the same proposal is a duplicate conflict"
    );
    assert_eq!(
        transactions
            .get(reject_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource,
        rejected_result.resource,
    );
    let rejected_rows = diesel::sql_query("SELECT COUNT(*) AS count FROM security_transaction_step_outcomes WHERE transaction_id=$1 AND step='revoke'")
        .bind::<Uuid,_>(uuid::Uuid::parse_str(reject_id.as_str().strip_prefix("ak:transaction:").unwrap()).unwrap())
        .get_result::<CountRow>(&mut *conn).await.unwrap();
    assert_eq!(rejected_rows.count, 0);
    assert!(
        device_status
            .pcr_device_active(&account, &authorizer, at)
            .await
            .unwrap()
    );
}

/// Station-sign one PCR successor Commit for `event` directly after `previous`.
fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:successor", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

struct PointerAuthor {
    account: arkret_wire::AccountId,
    realm_id: RealmId,
    method: DidUrl,
    seed: [u8; 32],
}

impl PointerAuthor {
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        series: &BackupSeriesId,
        version: u64,
        previous: Vec<BackupSeriesId>,
        source: &RealmCommitId,
        authorize_event_id: &arkret_wire::EventId,
        generation: u64,
        signing_seed: [u8; 32],
    ) -> serde_json::Value {
        use arkret_models_collaboration::events_payloads::{
            ControllerBackupTrustAnchor, UnsignedKeyBackupActiveSeries,
        };
        let unsigned = UnsignedKeyBackupActiveSeries::new(
            arkret_wire::ActorId::account(self.account.clone()),
            arkret_models_crypto::BackupKind::SecretStorage,
            series.clone(),
            version,
            previous,
            source.clone(),
            chrono::DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            self.method.clone(),
            ControllerBackupTrustAnchor {
                authorize_event_id: authorize_event_id.clone(),
                generation_ref: generation,
            },
        )
        .unwrap();
        let signature = SigningKey::from_bytes(&signing_seed)
            .sign(&unsigned.signing_payload_bytes().unwrap())
            .to_bytes();
        serde_json::to_value(
            unsigned
                .attach_signature(
                    arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                        signature,
                    ))
                    .unwrap(),
                )
                .unwrap(),
        )
        .unwrap()
    }

    fn event(&self, payload: serde_json::Value, nonce: u32) -> arkret_wire::Event {
        let mut event = arkret_wire::test_support::raw_event(
            EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            self.account.principal_id.clone(),
            self.account.station_id.clone(),
            payload,
        )
        .unwrap();
        event.created_at += chrono::TimeDelta::milliseconds(i64::from(nonce));
        device_history_fixture::sign_event(event, self.method.clone(), self.seed)
    }
}

#[derive(diesel::QueryableByName)]
struct PointerFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    pointers: i64,
}

async fn pointer_footprint(pool: &PgPool, realm_id: &RealmId) -> (i64, i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
                (SELECT COUNT(*) FROM key_backup_active_series_current_results WHERE realm_id=$1) \
                  AS pointers",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PointerFootprint>(&mut *conn)
    .await
    .unwrap();
    (row.events, row.commits, row.pointers)
}

#[tokio::test]
async fn key_backup_active_series_pointer_unit_commits_only_at_the_active_device_cut() {
    use soland_storage::{KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite};

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let author = PointerAuthor {
        account: fixture.account.clone(),
        realm_id: RealmId::new(fixture.events[0].realm_id.to_string()).unwrap(),
        method: fixture.device_verification_method.clone(),
        seed: fixture.founding_device_signing_seed,
    };
    let device = fixture.founding_device_id.clone();
    let station_did = fixture.station_did.clone();
    let did = fixture.did.clone();
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let head = genesis.transactions[1].commit.clone();
    let authorize_id = genesis.transactions[1].event.event_id.clone();
    let create_id = genesis.transactions[0].event.event_id.clone();
    let authority = genesis.transactions[1].expected_authority.clone();
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let series = BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let write = |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        KeyBackupActiveSeriesCommitWrite {
            commit: AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event,
                commit,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        }
    };
    let baseline = pointer_footprint(&pool, &author.realm_id).await;
    assert_eq!(baseline, (2, 2, 0));

    // Every rejected candidate leaves no Event, Commit or pointer behind.
    let mut rejected = Vec::new();
    let other_seed = [91; 32];
    let cases: [(&str, serde_json::Value); 6] = [
        (
            "stale generation",
            author.record(
                &series,
                1,
                vec![],
                &head.commit_id,
                &authorize_id,
                2,
                author.seed,
            ),
        ),
        (
            "non-current authorization Event",
            author.record(
                &series,
                1,
                vec![],
                &head.commit_id,
                &create_id,
                1,
                author.seed,
            ),
        ),
        (
            "foreign record signature",
            author.record(
                &series,
                1,
                vec![],
                &head.commit_id,
                &authorize_id,
                1,
                other_seed,
            ),
        ),
        (
            "unaccepted source checkpoint",
            author.record(
                &series,
                1,
                vec![],
                &unrelated_commit_id(),
                &authorize_id,
                1,
                author.seed,
            ),
        ),
        (
            "source before device authorization",
            author.record(
                &series,
                1,
                vec![],
                &genesis.transactions[0].commit.commit_id,
                &authorize_id,
                1,
                author.seed,
            ),
        ),
        (
            "first pointer version gap",
            author.record(
                &series,
                2,
                vec![],
                &head.commit_id,
                &authorize_id,
                1,
                author.seed,
            ),
        ),
    ];
    for (nonce, (label, payload)) in cases.into_iter().enumerate() {
        let event = author.event(payload, nonce as u32 + 1);
        let commit = station_successor(&head, &event, &station_did, 1);
        rejected.push((
            label,
            backups
                .commit_active_series_pointer(write(event, commit))
                .await,
        ));
    }
    let valid = author.record(
        &series,
        1,
        vec![],
        &head.commit_id,
        &authorize_id,
        1,
        author.seed,
    );
    // A different device fragment has no current authorization at this cut.
    let foreign_method = author_with_method(
        &author,
        DidUrl::new(format!(
            "{did}#{}",
            DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap()
        ))
        .unwrap(),
    );
    let foreign_payload = foreign_method.record(
        &series,
        1,
        vec![],
        &head.commit_id,
        &authorize_id,
        1,
        author.seed,
    );
    let foreign_event = foreign_method.event(foreign_payload, 20);
    let foreign_commit = station_successor(&head, &foreign_event, &station_did, 1);
    rejected.push((
        "unauthorized device method",
        backups
            .commit_active_series_pointer(write(foreign_event, foreign_commit))
            .await,
    ));
    // The Commit must extend the confirmed PCR head, not an older position.
    let event = author.event(valid.clone(), 30);
    let mut behind = station_successor(&genesis.transactions[0].commit, &event, &station_did, 1);
    behind.stream_position = head.stream_position + 1;
    rejected.push((
        "Commit behind head",
        backups
            .commit_active_series_pointer(write(event, behind))
            .await,
    ));
    // A tampered producer proof is rejected even when the record is valid.
    let mut tampered = author.event(valid.clone(), 31);
    tampered.producer_proof.as_mut().unwrap().jws = "invalid".to_owned();
    let tampered_commit = station_successor(&head, &tampered, &station_did, 1);
    rejected.push((
        "tampered producer proof",
        backups
            .commit_active_series_pointer(write(tampered, tampered_commit))
            .await,
    ));
    // An incomplete conflict-index cut cannot prove the device is active.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE pcr_device_conflict_index_cuts SET conflict_revision=1 WHERE realm_id=$1",
    )
    .bind::<Text, _>(author.realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    let marker_event = author.event(valid.clone(), 32);
    let marker_commit = station_successor(&head, &marker_event, &station_did, 1);
    rejected.push((
        "incomplete conflict marker",
        backups
            .commit_active_series_pointer(write(marker_event, marker_commit))
            .await,
    ));
    diesel::sql_query(
        "UPDATE pcr_device_conflict_index_cuts SET conflict_revision=0 WHERE realm_id=$1",
    )
    .bind::<Text, _>(author.realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    let expected_reasons = [
        ("stale generation", "backup_revision_stale"),
        (
            "non-current authorization Event",
            "device authorization that is not current",
        ),
        (
            "foreign record signature",
            "signature does not match the device key",
        ),
        (
            "unaccepted source checkpoint",
            "source checkpoint is not an accepted PCR Commit",
        ),
        (
            "source before device authorization",
            "source checkpoint is not an accepted PCR Commit",
        ),
        (
            "first pointer version gap",
            "key_backup_active_series_pointer_version_gap",
        ),
        ("unauthorized device method", "has no current authorization"),
        (
            "Commit behind head",
            "does not extend the confirmed PCR head",
        ),
        (
            "tampered producer proof",
            "producer proof does not match the device key",
        ),
        ("incomplete conflict marker", "status inputs are incomplete"),
    ];
    assert_eq!(rejected.len(), expected_reasons.len());
    for ((label, outcome), (expected_label, reason)) in rejected.iter().zip(expected_reasons) {
        assert_eq!(*label, expected_label);
        let error = outcome
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{label} was accepted"))
            .to_string();
        assert!(
            error.contains(reason),
            "{label} failed for another reason: {error}"
        );
    }
    assert_eq!(
        pointer_footprint(&pool, &author.realm_id).await,
        baseline,
        "a rejected pointer candidate left a durable write"
    );
    assert!(matches!(
        backups
            .confirmed_active_series_for_device(&author.account, &device, at)
            .await
            .unwrap()
            .unwrap()
            .secret_storage,
        BackupActiveSeriesPointer::Absent {}
    ));

    // The generic authority path still refuses the pointer kind.
    let first = author.event(valid, 40);
    let first_commit = station_successor(&head, &first, &station_did, 1);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_event_transaction(&write(first.clone(), first_commit.clone()).commit, at)
            .await
            .is_err()
    );

    let committed = backups
        .commit_active_series_pointer(write(first.clone(), first_commit.clone()))
        .await
        .unwrap();
    assert_eq!(
        committed,
        KeyBackupActiveSeriesCommitOutcome::Committed(first_commit.clone())
    );
    assert_eq!(
        backups
            .commit_active_series_pointer(write(first.clone(), first_commit.clone()))
            .await
            .unwrap(),
        KeyBackupActiveSeriesCommitOutcome::Duplicate(first_commit.clone())
    );
    let mut other_commit = station_successor(&head, &first, &station_did, 2);
    other_commit.commit_id = unrelated_commit_id();
    assert!(
        backups
            .commit_active_series_pointer(write(first.clone(), other_commit))
            .await
            .is_err(),
        "the same Event under a different Commit is not a replay"
    );
    assert_eq!(pointer_footprint(&pool, &author.realm_id).await, (3, 3, 1));
    let active = backups
        .confirmed_active_series_for_device(&author.account, &device, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.authority_commit_id, first_commit.commit_id);
    assert_eq!(
        active.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: series.clone(),
            series_pointer_version: 1,
        }
    );
    let page = backups
        .confirmed_list_page_for_device(
            &author.account,
            &device,
            at,
            &KeyBackupListQuery {
                actor_id: arkret_wire::ActorId::account(author.account.clone()).to_string(),
                backup_kind: None,
                series_id: None,
                after: None,
                limit: 50,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.active_series, active);

    // Successor: exactly +1 with the prior series retained. A same-version
    // fork and a version gap at the new head are both rejected.
    let next_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let fork = author.event(
        author.record(
            &next_series,
            1,
            vec![],
            &first_commit.commit_id,
            &authorize_id,
            1,
            author.seed,
        ),
        50,
    );
    let fork_commit = station_successor(&first_commit, &fork, &station_did, 1);
    assert!(
        backups
            .commit_active_series_pointer(write(fork, fork_commit))
            .await
            .is_err()
    );
    let gap = author.event(
        author.record(
            &next_series,
            3,
            vec![series.clone()],
            &first_commit.commit_id,
            &authorize_id,
            1,
            author.seed,
        ),
        51,
    );
    let gap_commit = station_successor(&first_commit, &gap, &station_did, 1);
    assert!(
        backups
            .commit_active_series_pointer(write(gap, gap_commit))
            .await
            .is_err()
    );
    assert_eq!(pointer_footprint(&pool, &author.realm_id).await, (3, 3, 1));
    // An earlier accepted checkpoint under the same generation is not stale.
    let second = author.event(
        author.record(
            &next_series,
            2,
            vec![series.clone()],
            &head.commit_id,
            &authorize_id,
            1,
            author.seed,
        ),
        52,
    );
    let second_commit = station_successor(&first_commit, &second, &station_did, 1);
    backups
        .commit_active_series_pointer(write(second, second_commit.clone()))
        .await
        .unwrap();

    // A fresh pool reads the same durable pointer and status cut.
    let restarted = Db::connect(Some(&support::contract_database_url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let reread = PgKeyBackupStore { pool: restarted }
        .confirmed_active_series_for_device(&author.account, &device, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reread.authority_commit_id, second_commit.commit_id);
    assert_eq!(
        reread.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: next_series,
            series_pointer_version: 2,
        }
    );
    assert!(
        PgDeviceRevocationStore { pool: pool.clone() }
            .pcr_device_active(&author.account, &device, at)
            .await
            .unwrap()
    );

    // The account-scoped read that freezes delete/unlock bases names the same
    // durable pointer and PCR head.
    assert_eq!(
        backups
            .confirmed_active_series(&author.account)
            .await
            .unwrap()
            .unwrap(),
        reread
    );
    // A typed row that lags the latest accepted pointer Commit, or is missing
    // while one exists, is unavailable -- never the older pointer or Absent.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE key_backup_active_series_current_results \
         SET current_commit_id=$2,current_event_id=$3,current_stream_position=$4 \
         WHERE realm_id=$1",
    )
    .bind::<Text, _>(author.realm_id.as_str())
    .bind::<Text, _>(first_commit.commit_id.as_str())
    .bind::<Text, _>(first.event_id.as_str())
    .bind::<BigInt, _>(first_commit.stream_position as i64)
    .execute(&mut *conn)
    .await
    .unwrap();
    assert!(
        backups
            .confirmed_active_series(&author.account)
            .await
            .is_err(),
        "a lagging typed pointer must not be served"
    );
    diesel::sql_query("DELETE FROM key_backup_active_series_current_results WHERE realm_id=$1")
        .bind::<Text, _>(author.realm_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        backups
            .confirmed_active_series(&author.account)
            .await
            .is_err(),
        "a missing typed pointer after an accepted pointer Commit is not Absent"
    );
}

fn author_with_method(author: &PointerAuthor, method: DidUrl) -> PointerAuthor {
    PointerAuthor {
        account: author.account.clone(),
        realm_id: author.realm_id.clone(),
        method,
        seed: author.seed,
    }
}

/// Install one accepted `accepted_device` authorization as durable PCR state.
///
/// FIXTURE ONLY: Soland has no registered accepted-device admission unit yet
/// (it needs the Account Authority pairing ledger of device-lifecycle.md
/// §2.1/§5.2.2), and the generic authority path refuses the kind. This writes
/// exactly the rows that unit must produce -- the committed Event, its
/// Station-signed Commit, the typed authorization current value and the
/// advanced conflict-index marker -- so the same-cut status reader can be
/// exercised with a second device. It proves nothing about pairing admission.
async fn install_accepted_device_fixture(
    pool: &PgPool,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) {
    let mut conn = pool.get().await.unwrap();
    let token = soland_storage::ids::parse_event_id(event.event_id.as_str()).unwrap();
    let canonical =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    diesel::sql_query(
        "INSERT INTO canonical_events \
         (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) \
         VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9,$9)",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<diesel::sql_types::Binary, _>(token[1..].to_vec())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&event.scope_ref).unwrap())
    .bind::<Text, _>(event.kind.as_str())
    .bind::<diesel::sql_types::Binary, _>(canonical)
    .bind::<Jsonb, _>(serde_json::to_value(event).unwrap())
    .bind::<diesel::sql_types::Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO realm_commits \
         (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) \
         SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(commit.realm_id.as_str())
    .bind::<Text, _>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).unwrap())
    .bind::<BigInt, _>(commit.stream_position as i64)
    .bind::<diesel::sql_types::Nullable<Text>, _>(
        commit.previous_commit_ref.as_ref().map(|id| id.as_str()),
    )
    .bind::<Jsonb, _>(serde_json::to_value(commit).unwrap())
    .bind::<diesel::sql_types::Timestamptz, _>(commit.committed_at)
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .execute(&mut *conn)
    .await
    .unwrap();
    let mut value = serde_json::to_value(&event.payload).unwrap();
    let device_id = value.as_object_mut().unwrap().remove("device_id").unwrap();
    value["device_authorize_event_id"] = serde_json::to_value(&event.event_id).unwrap();
    diesel::sql_query(
        "INSERT INTO pcr_device_authorization_current_results \
         (realm_id,device_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind::<Text, _>(commit.realm_id.as_str())
    .bind::<Text, _>(device_id.as_str().unwrap())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(commit.stream_position as i64)
    .bind::<Jsonb, _>(value)
    .bind::<diesel::sql_types::Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
    let advanced = diesel::sql_query(
        "UPDATE pcr_device_conflict_index_cuts SET pcr_head_commit_id=$2,updated_at=$4 \
         WHERE realm_id=$1 AND pcr_head_commit_id=$3",
    )
    .bind::<Text, _>(commit.realm_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(commit.previous_commit_ref.as_ref().unwrap().as_str())
    .bind::<diesel::sql_types::Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
    assert_eq!(advanced, 1);
}

#[tokio::test]
async fn accepted_revoke_terminal_stops_only_the_target_of_two_active_devices() {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use soland_storage::{KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite};

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let did = fixture.did.clone();
    let station_did = fixture.station_did.clone();
    let device_a = fixture.founding_device_id.clone();
    let author_a = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: fixture.device_verification_method.clone(),
        seed: fixture.founding_device_signing_seed,
    };
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let authority = genesis.transactions[1].expected_authority.clone();
    let authorize_a = genesis.transactions[1].event.event_id.clone();
    let status = PgDeviceRevocationStore { pool: pool.clone() };
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };

    // Device B is approved by A under the current generation.
    let device_b = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let seed_b = [97; 32];
    let payload_b = device_history_fixture::possession_with(
        &account,
        device_history_fixture::DeviceAuthorizationSpec {
            device_id: device_b.clone(),
            signing_seed: seed_b,
            hpke_seed: [7; 32],
            authorized_by: DeviceOrPrincipalRef::DeviceId(device_a.clone()),
            not_before: at,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::AcceptedDevice,
            authorized_generation_ref: 1,
            applet_id: None,
        },
    );
    arkret_signatures::verify_device_authorize_possession(&payload_b, &account).unwrap();
    let authorize_b = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::to_value(&payload_b).unwrap(),
        )
        .unwrap(),
        author_a.method.clone(),
        author_a.seed,
    );
    let commit_b = station_successor(
        &genesis.transactions[1].commit,
        &authorize_b,
        &station_did,
        1,
    );
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_event_transaction(&tx(authorize_b.clone(), commit_b.clone()), at)
            .await
            .is_err(),
        "generic admission must not authorize an accepted device"
    );
    install_accepted_device_fixture(&pool, &authorize_b, &commit_b).await;
    let now = commit_b.committed_at;
    assert!(
        status
            .pcr_device_active(&account, &device_a, now)
            .await
            .unwrap()
    );
    assert!(
        status
            .pcr_device_active(&account, &device_b, now)
            .await
            .unwrap()
    );
    let author_b = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: DidUrl::new(format!("{did}#{device_b}")).unwrap(),
        seed: seed_b,
    };

    // B, as an active device, may select the first series at this cut.
    let series_one =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let pointer_b = author_b.event(
        author_b.record(
            &series_one,
            1,
            vec![],
            &commit_b.commit_id,
            &authorize_b.event_id,
            1,
            seed_b,
        ),
        1,
    );
    let pointer_b_commit = station_successor(&commit_b, &pointer_b, &station_did, 1);
    assert!(matches!(
        backups
            .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
                commit: tx(pointer_b, pointer_b_commit.clone()),
                queued_at: now,
            })
            .await
            .unwrap(),
        KeyBackupActiveSeriesCommitOutcome::Committed(_)
    ));

    // A proposes revoking B through the SecurityRotation proposal unit.
    let revoke = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({
                "device_id": device_b,
                "revoked_by": device_a,
                "revoked_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "reason": "security_rotation"
            }),
        )
        .unwrap(),
        author_a.method.clone(),
        author_a.seed,
    );
    let covering = station_successor(&pointer_b_commit, &revoke, &station_did, 1);
    let rotation_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let rotation_pointer = author_a.event(
        author_a.record(
            &rotation_series,
            2,
            vec![series_one.clone()],
            &covering.commit_id,
            &authorize_a,
            1,
            author_a.seed,
        ),
        2,
    );
    let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        device_a.clone(),
        now + chrono::TimeDelta::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            PreparedEventBatchRequest {
                events: vec![revoke.clone()],
            },
        )
        .unwrap(),
        hash("rotated-secret"),
        vec![BackupRotationPlan {
            binding: BackupRotationBinding {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: series_one.clone(),
                new_series_id: rotation_series.clone(),
                new_backups: vec![BackupObjectRef {
                    backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7()))
                        .unwrap(),
                    ciphertext_digest: hash("rotated-backup"),
                }],
                active_series_event_id: rotation_pointer.event_id.clone(),
                old_backups: vec![BackupObjectRef {
                    backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7()))
                        .unwrap(),
                    ciphertext_digest: hash("old-backup"),
                }],
            },
            encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
                serde_json::json!({"fixture":"ciphertext"}),
            )
            .unwrap(),
            active_series_unit: PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                PreparedEventBatchRequest {
                    events: vec![rotation_pointer.clone()],
                },
            )
            .unwrap(),
        }],
    )
    .unwrap();
    let plan = SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
    let (initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(request)
        .into_initial_resource(plan, now)
        .unwrap();
    let transaction_id = initial.transaction_id.clone();
    transactions
        .create(SecurityTransactionRecord {
            resource: initial.clone(),
            canonical_request: canonical_request.clone(),
        })
        .await
        .unwrap();
    let mut proposed = initial;
    proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    transactions
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: proposed,
                canonical_request,
            },
            commit: tx(revoke.clone(), covering.clone()),
            queued_at: now,
        })
        .await
        .unwrap();

    // Pending: B stops authenticating and cannot move the pointer; A goes on.
    let pending_at = covering.committed_at;
    assert!(
        !status
            .pcr_device_active(&account, &device_b, pending_at)
            .await
            .unwrap()
    );
    assert!(
        status
            .pcr_device_active(&account, &device_a, pending_at)
            .await
            .unwrap()
    );
    assert!(
        backups
            .confirmed_active_series_for_device(&account, &device_b, pending_at)
            .await
            .is_err()
    );
    let pending_pointer = author_b.event(
        author_b.record(
            &rotation_series,
            2,
            vec![series_one.clone()],
            &covering.commit_id,
            &authorize_b.event_id,
            1,
            seed_b,
        ),
        3,
    );
    let pending_commit = station_successor(&covering, &pending_pointer, &station_did, 1);
    let refused = backups
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: tx(pending_pointer, pending_commit),
            queued_at: pending_at,
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("not active at the PCR cut"), "{refused}");

    // The accepted terminal result revokes B; it never touches A.
    let mut accepted = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let request_digest = accepted
        .resource
        .security_rotation_plan()
        .unwrap()
        .revoke_unit
        .request_digest
        .clone();
    let decided_at = pending_at + chrono::TimeDelta::seconds(1);
    accepted
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            prepared_material_digest: request_digest,
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            output_ref: covering.commit_id.to_string(),
            output_digest: hash("revoke-command-accepted"),
            accepted_at: decided_at,
        });
    accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
        result: SecurityRotationRevokeCommandResult::Accepted,
        decided_at,
    });
    transactions
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                transaction_id: transaction_id.to_string(),
                step: SecurityTransactionStep::Revoke,
                canonical_request: b"revoke-worker-request".to_vec(),
                response: serde_json::to_value(&accepted.resource).unwrap(),
                participant_outcome: None,
            }),
            transaction: accepted,
        })
        .await
        .unwrap();
    assert!(
        !status
            .pcr_device_active(&account, &device_b, decided_at)
            .await
            .unwrap()
    );
    assert!(
        status
            .pcr_device_active(&account, &device_a, decided_at)
            .await
            .unwrap()
    );
    assert!(
        backups
            .confirmed_active_series_for_device(&account, &device_b, decided_at)
            .await
            .is_err()
    );

    // The rotation reserved its own pointer Event: the self path cannot
    // switch it outside the rotation's switch step, and writes nothing.
    let before_reserved = pointer_footprint(&pool, &realm_id).await;
    let reserved = backups
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: tx(
                rotation_pointer.clone(),
                station_successor(&covering, &rotation_pointer, &station_did, 2),
            ),
            queued_at: decided_at,
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        reserved.contains("reserved by a SecurityRotation"),
        "{reserved}"
    );
    assert_eq!(pointer_footprint(&pool, &realm_id).await, before_reserved);

    // A, still active, commits an unreserved successor pointer. Its source
    // is the covering Commit; the generation did not move, so it is fresh.
    let free_pointer = author_a.event(
        author_a.record(
            &rotation_series,
            2,
            vec![series_one.clone()],
            &covering.commit_id,
            &authorize_a,
            1,
            author_a.seed,
        ),
        4,
    );
    let pointer_a_commit = station_successor(&covering, &free_pointer, &station_did, 2);
    backups
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: tx(free_pointer, pointer_a_commit.clone()),
            queued_at: decided_at,
        })
        .await
        .unwrap();
    let after = backups
        .confirmed_active_series_for_device(&account, &device_a, decided_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.authority_commit_id, pointer_a_commit.commit_id);
    assert_eq!(
        after.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: rotation_series,
            series_pointer_version: 2,
        }
    );
    // A fresh pool rebuilds the same fold from durable rows only.
    let restarted = Db::connect(Some(&support::contract_database_url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let restarted_status = PgDeviceRevocationStore { pool: restarted };
    assert!(
        !restarted_status
            .pcr_device_active(&account, &device_b, decided_at)
            .await
            .unwrap()
    );
    assert!(
        restarted_status
            .pcr_device_active(&account, &device_a, decided_at)
            .await
            .unwrap()
    );
}

/// One `secret_storage` envelope of `series`, signed by `author`'s device key
/// with the device's current authorization, chained after `predecessor`.
#[allow(clippy::too_many_arguments)]
fn signed_backup(
    author: &PointerAuthor,
    device_id: &DeviceId,
    authorize_event_id: &arkret_wire::EventId,
    series: &BackupSeriesId,
    seq: u64,
    predecessor: Option<&arkret_models_crypto::KeyBackup>,
    signing_seed: [u8; 32],
) -> arkret_models_crypto::KeyBackup {
    let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let mut value = page_fixture(
        &backup_id,
        &arkret_wire::ActorId::account(author.account.clone()),
        series.as_str(),
        seq,
        None,
    );
    value["auth_data"]["device_id"] = serde_json::json!(device_id);
    value["auth_data"]["verification_method"] = serde_json::json!(author.method);
    value["auth_data"]["device_authorize_event_id"] = serde_json::json!(authorize_event_id);
    if let Some(previous) = predecessor {
        value["supersedes_id"] = serde_json::json!(previous.backup_id);
        value["supersedes_digest"] = serde_json::json!(arkret_canonical::sha256_digest(
            previous.signing_payload_bytes().unwrap()
        ));
    }
    let mut backup: arkret_models_crypto::KeyBackup = serde_json::from_value(value).unwrap();
    let signature = SigningKey::from_bytes(&signing_seed)
        .sign(&backup.signing_payload_bytes().unwrap())
        .to_bytes();
    backup.auth_data.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature)).unwrap();
    backup
}

#[derive(diesel::QueryableByName)]
struct RotationFootprintRow {
    #[diesel(sql_type = BigInt)]
    backups: i64,
    #[diesel(sql_type = BigInt)]
    outcomes: i64,
    #[diesel(sql_type = BigInt)]
    attempts: i64,
}

/// Replacement envelopes stored in `series`, and the step outcome/attempt
/// rows of `transaction_id`.
async fn rotation_footprint(
    pool: &PgPool,
    series: &BackupSeriesId,
    transaction_id: &TransactionId,
) -> (i64, i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let uuid = uuid::Uuid::parse_str(
        transaction_id
            .as_str()
            .strip_prefix("ak:transaction:")
            .unwrap(),
    )
    .unwrap();
    let row = diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM key_backups WHERE series_id=$1) AS backups, \
                (SELECT COUNT(*) FROM security_transaction_step_outcomes WHERE transaction_id=$2) \
                  AS outcomes, \
                (SELECT COUNT(*) FROM security_transaction_step_attempts WHERE transaction_id=$2) \
                  AS attempts",
    )
    .bind::<Text, _>(series.as_str())
    .bind::<Uuid, _>(uuid)
    .get_result::<RotationFootprintRow>(&mut *conn)
    .await
    .unwrap();
    (row.backups, row.outcomes, row.attempts)
}

/// Append the worker's evidence for `step` exactly as the Station does.
fn with_rotation_step(
    record: &SecurityTransactionRecord,
    evidence: soland_storage::RotationStepEvidence,
    station: &DidCoreId,
    accepted_at: chrono::DateTime<chrono::Utc>,
    step: SecurityTransactionStep,
) -> (SecurityTransactionRecord, SecurityTransactionStepOutcomeRecord) {
    let mut next = record.clone();
    next.resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            prepared_material_digest: evidence.prepared_material_digest,
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            output_ref: evidence.output_ref,
            output_digest: evidence.output_digest,
            accepted_at,
        });
    let outcome = SecurityTransactionStepOutcomeRecord {
        transaction_id: next.resource.transaction_id.to_string(),
        step,
        canonical_request: next.canonical_request.clone(),
        response: serde_json::to_value(&next.resource).unwrap(),
        participant_outcome: None,
    };
    (next, outcome)
}

#[tokio::test]
async fn security_rotation_worker_units_and_local_commit_are_atomic() {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use soland_storage::{
        KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite,
        RotationPointerSwitchWrite, RotationUploadCommitWrite, rotation_switch_step_evidence,
        rotation_upload_step_evidence,
    };

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let station_did = fixture.station_did.clone();
    let device_a = fixture.founding_device_id.clone();
    let author_a = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: fixture.device_verification_method.clone(),
        seed: fixture.founding_device_signing_seed,
    };
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let authority = genesis.transactions[1].expected_authority.clone();
    let authorize_a = genesis.transactions[1].event.event_id.clone();
    let status = PgDeviceRevocationStore { pool: pool.clone() };
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };

    // Two further devices B and C, both approved by A under generation 1.
    let mut head = genesis.transactions[1].commit.clone();
    let mut install = async |seed: [u8; 32], hpke: [u8; 32]| {
        let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let payload = device_history_fixture::possession_with(
            &account,
            device_history_fixture::DeviceAuthorizationSpec {
                device_id: device.clone(),
                signing_seed: seed,
                hpke_seed: hpke,
                authorized_by: DeviceOrPrincipalRef::DeviceId(device_a.clone()),
                not_before: at,
                expires_at: None,
                binding: DeviceAuthorizationBindingKind::AcceptedDevice,
                authorized_generation_ref: 1,
                applet_id: None,
            },
        );
        let event = device_history_fixture::sign_event(
            arkret_wire::test_support::raw_event(
                EventKind::DeviceAuthorize.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::to_value(&payload).unwrap(),
            )
            .unwrap(),
            author_a.method.clone(),
            author_a.seed,
        );
        let commit = station_successor(&head, &event, &station_did, 1);
        install_accepted_device_fixture(&pool, &event, &commit).await;
        head = commit;
        device
    };
    let device_b = install([97; 32], [7; 32]).await;
    let device_c = install([98; 32], [8; 32]).await;
    let now = head.committed_at;

    // A selects the first series; it holds one old envelope.
    let series_one =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let pointer_one = author_a.event(
        author_a.record(&series_one, 1, vec![], &head.commit_id, &authorize_a, 1, author_a.seed),
        1,
    );
    let pointer_one_commit = station_successor(&head, &pointer_one, &station_did, 1);
    assert!(matches!(
        backups
            .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
                commit: tx(pointer_one, pointer_one_commit.clone()),
                queued_at: now,
            })
            .await
            .unwrap(),
        KeyBackupActiveSeriesCommitOutcome::Committed(_)
    ));
    head = pointer_one_commit;
    let old = signed_backup(&author_a, &device_a, &authorize_a, &series_one, 0, None, author_a.seed);
    backups
        .put(old.backup_id.to_string(), serde_json::to_value(&old).unwrap())
        .await
        .unwrap();

    // Build a rotation that revokes `target` and replaces series_one with a
    // two-envelope series signed by `signing_seed` under A's method.
    let mut nonce = 10;
    let mut rotation = async |target: &DeviceId, signing_seed: [u8; 32]| {
        nonce += 1;
        let revoke = device_history_fixture::sign_event(
            arkret_wire::test_support::raw_event(
                EventKind::DeviceRevoke.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::json!({
                    "device_id": target,
                    "revoked_by": device_a,
                    "revoked_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "reason": "security_rotation"
                }),
            )
            .unwrap(),
            author_a.method.clone(),
            author_a.seed,
        );
        let covering = station_successor(&head, &revoke, &station_did, 1);
        let series =
            BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
        let first = signed_backup(&author_a, &device_a, &authorize_a, &series, 0, None, signing_seed);
        let second = signed_backup(
            &author_a,
            &device_a,
            &authorize_a,
            &series,
            1,
            Some(&first),
            signing_seed,
        );
        let pointer = author_a.event(
            author_a.record(
                &series,
                2,
                vec![series_one.clone()],
                &covering.commit_id,
                &authorize_a,
                1,
                author_a.seed,
            ),
            nonce,
        );
        let refs = [&first, &second]
            .iter()
            .map(|backup| BackupObjectRef {
                backup_id: backup.backup_id.clone(),
                ciphertext_digest: backup.ciphertext_digest.clone(),
            })
            .collect();
        let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
            account.clone(),
            device_a.clone(),
            now + chrono::TimeDelta::hours(1),
            PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                PreparedEventBatchRequest {
                    events: vec![revoke.clone()],
                },
            )
            .unwrap(),
            hash("rotated-secret"),
            vec![BackupRotationPlan {
                binding: BackupRotationBinding {
                    backup_kind: BackupRotationKind::SecretStorage,
                    previous_series_id: series_one.clone(),
                    new_series_id: series.clone(),
                    new_backups: refs,
                    active_series_event_id: pointer.event_id.clone(),
                    old_backups: vec![BackupObjectRef {
                        backup_id: old.backup_id.clone(),
                        ciphertext_digest: old.ciphertext_digest.clone(),
                    }],
                },
                encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
                    serde_json::json!({"backups": [first, second]}),
                )
                .unwrap(),
                active_series_unit: PreparedEventUnit::new(
                    arkret_canonical::DigestSuite::Sha256,
                    PreparedEventBatchRequest {
                        events: vec![pointer.clone()],
                    },
                )
                .unwrap(),
            }],
        )
        .unwrap();
        let plan =
            SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
        let (initial, canonical_request) =
            SecurityTransactionCreateRequest::SecurityRotation(request)
                .into_initial_resource(plan, now)
                .unwrap();
        let record = transactions
            .create(SecurityTransactionRecord {
                resource: initial,
                canonical_request,
            })
            .await
            .unwrap();
        // The revoke proposal and its accepted terminal, as the worker does.
        let mut proposed = record.clone();
        proposed.resource.revoke_proposal = Some(SecurityRotationRevokeProposal {
            proposal_event_id: revoke.event_id.clone(),
            covering_commit_id: covering.commit_id.clone(),
        });
        transactions
            .commit_revoke_proposal(RevokeProposalCommitWrite {
                transaction: proposed.clone(),
                commit: tx(revoke.clone(), covering.clone()),
                queued_at: now,
            })
            .await
            .unwrap();
        let decided_at = covering.committed_at;
        let mut accepted = proposed;
        accepted
            .resource
            .accepted_steps
            .push(AcceptedSecurityTransactionStep {
                prepared_material_digest: accepted
                    .resource
                    .security_rotation_plan()
                    .unwrap()
                    .revoke_unit
                    .request_digest
                    .clone(),
                acceptor: SecurityTransactionAcceptor::Principal {
                    principal_id: station.clone(),
                },
                output_ref: covering.commit_id.to_string(),
                output_digest: hash("revoke-command-accepted"),
                accepted_at: decided_at,
            });
        accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
            proposal_event_id: revoke.event_id.clone(),
            covering_commit_id: covering.commit_id.clone(),
            result: SecurityRotationRevokeCommandResult::Accepted,
            decided_at,
        });
        let decided = transactions
            .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
                step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                    transaction_id: accepted.resource.transaction_id.to_string(),
                    step: SecurityTransactionStep::Revoke,
                    canonical_request: accepted.canonical_request.clone(),
                    response: serde_json::to_value(&accepted.resource).unwrap(),
                    participant_outcome: None,
                }),
                transaction: accepted,
            })
            .await
            .unwrap();
        head = covering.clone();
        (decided, series, pointer, covering)
    };

    // A rotation whose replacement envelopes are not signed by A's key is
    // refused by the upload unit with no envelope, step or attempt written.
    let (forged, forged_series, _, _) = rotation(&device_c, [0x66; 32]).await;
    let forged_plan = forged.resource.security_rotation_plan().unwrap().clone();
    let (forged_next, forged_outcome) = with_rotation_step(
        &forged,
        rotation_upload_step_evidence(&forged_plan).unwrap(),
        &station,
        now,
        SecurityTransactionStep::UploadNewMaterial,
    );
    let before = rotation_footprint(&pool, &forged_series, &forged.resource.transaction_id).await;
    let refused = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: forged_next,
            step_outcome: forged_outcome,
        })
        .await
        .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(soland_storage::ConflictCode::SignatureInvalid),
        "{refused}"
    );
    assert_eq!(
        rotation_footprint(&pool, &forged_series, &forged.resource.transaction_id).await,
        before
    );
    let unchanged = transactions
        .get(forged.resource.transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.resource.accepted_steps.len(), 1);
    // The worker then stops the rotation; its accepted revoke stays.
    let mut aborted = unchanged;
    aborted.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Aborted {
        completed_at: now,
        reason_code: Some("proof_invalid".to_owned()),
    });
    transactions.update(aborted).await.unwrap();

    // The genuine rotation revokes B.
    let (decided, series, pointer, covering) = rotation(&device_b, author_a.seed).await;
    let transaction_id = decided.resource.transaction_id.clone();
    let plan = decided.resource.security_rotation_plan().unwrap().clone();
    assert!(
        !status
            .pcr_device_active(&account, &device_b, covering.committed_at)
            .await
            .unwrap()
    );

    // The generic accepted-step writer cannot stand in for the worker unit.
    let evidence = rotation_upload_step_evidence(&plan).unwrap();
    let (upload_next, upload_outcome) = with_rotation_step(
        &decided,
        evidence.clone(),
        &station,
        covering.committed_at,
        SecurityTransactionStep::UploadNewMaterial,
    );
    assert!(
        transactions
            .accept_step(upload_next.clone(), upload_outcome.clone())
            .await
            .is_err()
    );
    // The switch cannot run before the upload step is accepted.
    let early = station_successor(&covering, &pointer, &station_did, 1);
    let (early_next, early_outcome) = with_rotation_step(
        &decided,
        rotation_switch_step_evidence(&plan, &early).unwrap(),
        &station,
        covering.committed_at,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    );
    assert!(
        transactions
            .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
                transaction: early_next,
                step_outcome: early_outcome,
                commit: tx(pointer.clone(), early),
                queued_at: covering.committed_at,
            })
            .await
            .is_err()
    );
    // A reserved id that already holds other bytes refuses the whole upload.
    let reserved_id = &plan.backup_rotations[0].binding.new_backups[0].backup_id;
    let squatter = {
        let mut value = serde_json::to_value(signed_backup(
            &author_a,
            &device_a,
            &authorize_a,
            &BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap(),
            0,
            None,
            author_a.seed,
        ))
        .unwrap();
        value["backup_id"] = serde_json::json!(reserved_id);
        value
    };
    backups
        .put(reserved_id.to_string(), squatter.clone())
        .await
        .unwrap();
    let before = rotation_footprint(&pool, &series, &transaction_id).await;
    let squatted = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: upload_next.clone(),
            step_outcome: upload_outcome.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        squatted.conflict_code(),
        Some(soland_storage::ConflictCode::DuplicateConflict),
        "{squatted}"
    );
    assert_eq!(rotation_footprint(&pool, &series, &transaction_id).await, before);
    assert_eq!(backups.get(reserved_id.as_str()).await.unwrap(), Some(squatter));
    assert!(backups.delete(reserved_id.as_str()).await.unwrap());

    // Upload: both envelopes and accepted_steps[1] in one write.
    let uploaded = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: upload_next.clone(),
            step_outcome: upload_outcome.clone(),
        })
        .await
        .unwrap();
    assert_eq!(uploaded.resource.accepted_steps.len(), 2);
    assert_eq!(uploaded.resource.accepted_steps[1].output_ref, evidence.output_ref);
    assert_eq!(rotation_footprint(&pool, &series, &transaction_id).await, (2, 2, 2));
    // An exact replay computed later reads the first stored result.
    let (replay_next, replay_outcome) = with_rotation_step(
        &decided,
        evidence,
        &station,
        covering.committed_at + chrono::TimeDelta::seconds(9),
        SecurityTransactionStep::UploadNewMaterial,
    );
    let replayed = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: replay_next,
            step_outcome: replay_outcome,
        })
        .await
        .unwrap();
    assert_eq!(replayed.resource, uploaded.resource);
    assert_eq!(rotation_footprint(&pool, &series, &transaction_id).await, (2, 2, 2));
    // The pointer still names series_one: nothing switched yet.
    let before_switch = backups
        .confirmed_active_series_for_device(&account, &device_a, covering.committed_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before_switch.authority_commit_id, covering.commit_id);
    assert!(matches!(
        &before_switch.secret_storage,
        BackupActiveSeriesPointer::Active { active_series_id, series_pointer_version: 1 }
            if *active_series_id == series_one
    ));

    // A Commit signed at a stale head is retryable and writes nothing.
    let stale = station_successor(
        &commit_at_position(&pool, &realm_id, 1).await,
        &pointer,
        &station_did,
        3,
    );
    let (stale_next, stale_outcome) = with_rotation_step(
        &uploaded,
        rotation_switch_step_evidence(&plan, &stale).unwrap(),
        &station,
        covering.committed_at,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    );
    let pointers = pointer_footprint(&pool, &realm_id).await;
    let moved = transactions
        .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
            transaction: stale_next,
            step_outcome: stale_outcome,
            commit: tx(pointer.clone(), stale),
            queued_at: covering.committed_at,
        })
        .await
        .unwrap_err();
    assert_eq!(
        moved.conflict_code(),
        Some(soland_storage::ConflictCode::TemporarilyUnavailable),
        "{moved}"
    );
    assert_eq!(pointer_footprint(&pool, &realm_id).await, pointers);

    // Switch: Event, Commit, pointer v2 and accepted_steps[2] together.
    let switch_commit = station_successor(&covering, &pointer, &station_did, 2);
    let switch_evidence = rotation_switch_step_evidence(&plan, &switch_commit).unwrap();
    let (switch_next, switch_outcome) = with_rotation_step(
        &uploaded,
        switch_evidence.clone(),
        &station,
        switch_commit.committed_at,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    );
    let switched = transactions
        .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
            transaction: switch_next.clone(),
            step_outcome: switch_outcome.clone(),
            commit: tx(pointer.clone(), switch_commit.clone()),
            queued_at: switch_commit.committed_at,
        })
        .await
        .unwrap();
    assert_eq!(switched.resource.accepted_steps.len(), 3);
    assert_eq!(
        switched.resource.accepted_steps[2].output_ref,
        switch_commit.commit_id.to_string()
    );
    let (events, commits, pointer_rows) = pointers;
    assert_eq!(
        pointer_footprint(&pool, &realm_id).await,
        (events + 1, commits + 1, pointer_rows)
    );
    let after = backups
        .confirmed_active_series_for_device(&account, &device_a, switch_commit.committed_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.authority_commit_id, switch_commit.commit_id);
    assert_eq!(
        after.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: series.clone(),
            series_pointer_version: 2,
        }
    );
    // Exact replay of the switch returns the first result and adds nothing.
    let replayed = transactions
        .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
            transaction: switch_next,
            step_outcome: switch_outcome,
            commit: tx(pointer, switch_commit),
            queued_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(replayed.resource, switched.resource);
    assert_eq!(
        pointer_footprint(&pool, &realm_id).await,
        (events + 1, commits + 1, pointer_rows)
    );
    assert_eq!(
        transactions
            .get(transaction_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource
            .next_required_step()
            .unwrap(),
        Some(SecurityTransactionStep::EraseOldMaterial)
    );

    // Erase, as the worker accepts it once the old series is gone.
    let switched_record = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let erase_request = arkret_models_crypto::BackupSeriesEraseRequestBody {
        transaction_id: transaction_id.clone(),
        transaction_request_digest: switched_record.resource.request_digest.clone(),
        prepared_plan_digest: switched_record.resource.prepared_plan_digest.clone(),
        erase_confirmation_digest: plan.erase_confirmation_digest.clone(),
        series: vec![plan.backup_rotations[0].binding.clone()],
        authority_commit_id: after.authority_commit_id.clone(),
    };
    let erase_bytes = arkret_canonical::canonical_json_bytes(&erase_request).unwrap();
    transactions
        .begin_step(soland_storage::SecurityTransactionStepAttemptRecord {
            transaction_id: transaction_id.to_string(),
            step: SecurityTransactionStep::EraseOldMaterial,
            canonical_request: erase_bytes.clone(),
        })
        .await
        .unwrap();
    let mut erased = switched_record.clone();
    erased
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            prepared_material_digest: plan.erase_confirmation_digest.clone(),
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            output_ref: plan.erase_confirmation_digest.to_string(),
            output_digest: plan.erase_confirmation_digest.clone(),
            accepted_at: switched_record.resource.accepted_steps[2].accepted_at
                + chrono::TimeDelta::seconds(1),
        });
    transactions
        .accept_step(
            erased.clone(),
            SecurityTransactionStepOutcomeRecord {
                transaction_id: transaction_id.to_string(),
                step: SecurityTransactionStep::EraseOldMaterial,
                canonical_request: erase_bytes,
                response: serde_json::to_value(&erased.resource).unwrap(),
                participant_outcome: None,
            },
        )
        .await
        .unwrap();
    let erased = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        erased.resource.next_required_step().unwrap(),
        Some(SecurityTransactionStep::LocalCommit)
    );

    // local_commit: the attestation is verified only against the attesting
    // device's current accepted PCR authorization key, under a DID URL of the
    // Account's principal DID whose fragment is exactly that device.
    let (did, _) = author_a.method.as_str().rsplit_once('#').unwrap();
    let method_of = |device: &DeviceId| DidUrl::new(format!("{did}#{device}")).unwrap();
    let local_commit = |device: &DeviceId,
                        method: DidUrl,
                        seed: [u8; 32],
                        committed_at: chrono::DateTime<chrono::Utc>| {
        let artifact = arkret_models_crypto::SecurityRotationLocalCommit {
            schema: arkret_wire::SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1.to_owned(),
            transaction_id: transaction_id.clone(),
            transaction_request_digest: erased.resource.request_digest.clone(),
            prepared_plan_digest: erased.resource.prepared_plan_digest.clone(),
            local_commit_digest: plan.local_commit_digest.clone(),
            device_id: device.clone(),
            committed_at,
        };
        let mut attestation = arkret_models_crypto::ClientStepAttestation {
            step: SecurityTransactionStep::LocalCommit,
            output_ref: plan.local_commit_digest.to_string(),
            transaction_id: transaction_id.clone(),
            transaction_request_digest: erased.resource.request_digest.clone(),
            prepared_plan_digest: erased.resource.prepared_plan_digest.clone(),
            artifact: arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotation(
                artifact.clone(),
            ),
            auth_data: arkret_models_crypto::ClientStepAttestationAuthData {
                verification_method: method,
                signature_algorithm: "Ed25519".to_owned(),
                signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
            },
        };
        let signature = SigningKey::from_bytes(&seed)
            .sign(&attestation.signing_bytes().unwrap())
            .to_bytes();
        attestation.auth_data.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature))
                .unwrap();
        let digest = attestation.attestation_digest().unwrap();
        let mut next = erased.clone();
        next.resource
            .accepted_steps
            .push(AcceptedSecurityTransactionStep {
                prepared_material_digest: digest.clone(),
                acceptor: SecurityTransactionAcceptor::Principal {
                    principal_id: station.clone(),
                },
                output_ref: plan.local_commit_digest.to_string(),
                output_digest: digest,
                accepted_at: committed_at,
            });
        next.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
            completed_at: committed_at,
            receipt_id: None,
            completion_attestation: None,
        });
        let continue_request = arkret_models_crypto::SecurityTransactionContinueRequest {
            request_digest: erased.resource.request_digest.clone(),
            prepared_plan_digest: erased.resource.prepared_plan_digest.clone(),
            expected_accepted_step_count: 4,
            client_attestation: attestation.clone(),
        };
        soland_storage::RotationLocalCommitWrite {
            step_outcome: SecurityTransactionStepOutcomeRecord {
                transaction_id: transaction_id.to_string(),
                step: SecurityTransactionStep::LocalCommit,
                canonical_request: arkret_canonical::canonical_json_bytes(&continue_request)
                    .unwrap(),
                response: serde_json::to_value(&next.resource).unwrap(),
                participant_outcome: Some(serde_json::to_value(&artifact).unwrap()),
            },
            transaction: next,
            attestation,
        }
    };
    let committed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let footprint = rotation_footprint(&pool, &series, &transaction_id).await;
    let refused_with = async |write: soland_storage::RotationLocalCommitWrite| {
        let error = transactions
            .commit_rotation_local_commit(write)
            .await
            .unwrap_err();
        let unchanged = transactions
            .get(transaction_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.resource, erased.resource, "{error}");
        error.conflict_code()
    };
    // The generic accepted-step writer cannot accept a local commit.
    let genuine = local_commit(&device_a, method_of(&device_a), author_a.seed, committed_at);
    assert!(
        transactions
            .accept_step(genuine.transaction.clone(), genuine.step_outcome.clone())
            .await
            .is_err()
    );
    // A key that is not the device's accepted authorization key.
    assert_eq!(
        refused_with(local_commit(
            &device_a,
            method_of(&device_a),
            [0x66; 32],
            committed_at
        ))
        .await,
        Some(soland_storage::ConflictCode::SignatureInvalid)
    );
    // A method naming another device, or not a DID of this principal.
    assert_eq!(
        refused_with(local_commit(
            &device_a,
            method_of(&device_c),
            author_a.seed,
            committed_at
        ))
        .await,
        Some(soland_storage::ConflictCode::SignatureInvalid)
    );
    assert_eq!(
        refused_with(local_commit(
            &device_a,
            DidUrl::new(format!("did:web:other.example#{device_a}")).unwrap(),
            author_a.seed,
            committed_at
        ))
        .await,
        Some(soland_storage::ConflictCode::SignatureInvalid)
    );
    // The revoked device B, even with its own authorized key and method.
    assert_eq!(
        refused_with(local_commit(
            &device_b,
            method_of(&device_b),
            [97; 32],
            committed_at
        ))
        .await,
        Some(soland_storage::ConflictCode::DeviceRevoked)
    );
    assert_eq!(rotation_footprint(&pool, &series, &transaction_id).await, footprint);

    // The genuine local commit completes the rotation in one write.
    let completed = transactions
        .commit_rotation_local_commit(genuine.clone())
        .await
        .unwrap();
    assert_eq!(completed.resource, genuine.transaction.resource);
    assert!(matches!(
        completed.resource.terminal_outcome,
        Some(SecurityTransactionTerminalOutcome::Completed { .. })
    ));
    let (backups_n, outcomes, attempts) = footprint;
    assert_eq!(
        rotation_footprint(&pool, &series, &transaction_id).await,
        (backups_n, outcomes + 1, attempts + 1)
    );
    // Exact replay reads the first result; other bytes are a conflict.
    assert_eq!(
        transactions
            .commit_rotation_local_commit(genuine)
            .await
            .unwrap()
            .resource,
        completed.resource
    );
    let other = local_commit(
        &device_a,
        method_of(&device_a),
        author_a.seed,
        committed_at + chrono::TimeDelta::seconds(1),
    );
    assert_eq!(
        transactions
            .commit_rotation_local_commit(other)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(
        transactions
            .get(transaction_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource,
        completed.resource
    );
}

/// The PCR Commit at `position`, read back from durable rows.
async fn commit_at_position(
    pool: &PgPool,
    realm_id: &RealmId,
    position: i64,
) -> arkret_wire::RealmCommit {
    #[derive(diesel::QueryableByName)]
    struct CommitRow {
        #[diesel(sql_type = Jsonb)]
        commit_json: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_position=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<BigInt, _>(position)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .unwrap();
    serde_json::from_value(row.commit_json).unwrap()
}
