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
    assert!(
        transactions
            .commit_revoke_proposal(bad_authorizer)
            .await
            .is_err()
    );
    let mut bad_proof = write.clone();
    bad_proof.commit.event.producer_proof.as_mut().unwrap().jws = "invalid".to_owned();
    assert!(
        transactions
            .commit_revoke_proposal(bad_proof)
            .await
            .is_err()
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
    assert!(
        transactions
            .commit_revoke_command_terminal(changed_terminal)
            .await
            .is_err()
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
