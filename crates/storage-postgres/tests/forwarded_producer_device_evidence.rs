//! The governance Station retains a cross-Station producer's complete
//! `producer_device_evidence` in the transaction that writes the Event's first
//! RealmCommit (device-lifecycle §8.2.2), and nowhere else.

#[path = "support/ordinary_realm.rs"]
mod ordinary_realm;

use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_wire::{AccountId, DeviceId, Did, DidKey, DidUrl, EventId, NonEmptyString, ServiceKind};
use chrono::{Duration, Utc};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use soland_storage::{EventCommitRequest, EventCommitUnitOfWork, ForwardedProducerDeviceEvidence};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};

const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-00000000e0a1";
const OTHER_DEVICE: &str = "ak:device:0196419b-0000-7000-8000-00000000e0a2";

/// Complete evidence attesting `device` of `account`, signed by a registered
/// Station. The storage boundary re-binds it; the governance Station verified
/// the signatures before admission.
fn evidence(account: &AccountId, device: &str) -> AccountDeviceSignerEvidence {
    let registered_at = Utc::now() - Duration::hours(1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://forwarder.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_time: registered_at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let station =
        arkret_wire::project_did_to_core_id(&Did::new(inception.did.clone()).unwrap()).unwrap();
    let attested_at =
        chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
    let public = SigningKey::from_bytes(&[0x72; 32])
        .verifying_key()
        .to_bytes();
    let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
        DeviceProjectionAttestationCore {
            account_id: account.clone(),
            device_id: DeviceId::new(device).unwrap(),
            device_signing_key_did: DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)
            ))
            .unwrap(),
            hpke_key: NonEmptyString::new("hpke-forwarded").unwrap(),
            device_authorize_event_id: EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .unwrap(),
            authorized_generation_ref: 1,
            device_status: DeviceStatus::Active,
            authorization_window: DeviceAuthorizationWindow {
                not_before: registered_at,
                expires_at: None,
            },
            attested_at,
            expires_at: attested_at + Duration::minutes(5),
        },
        DidUrl::new(inception.did_key_id.clone()).unwrap(),
        &SigningKey::from_bytes(&inception.did_key_seed),
    )
    .unwrap();
    AccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution: arkret_identity::build_authenticated_webvh_service_resolution(
            station,
            "station".into(),
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
            vec![inception.log_entry.clone()],
            vec![],
            attested_at,
        )
        .unwrap(),
    }
}

/// Rebind the fixture Event's producer proof to a human device method.
/// The proof method is outside the Event identity preimage.
fn signed_by_device(request: &mut EventCommitRequest, device: &str) {
    let event = &mut request.authority_commit.event;
    let proof = event.producer_proof.as_mut().unwrap();
    proof.verification_method = DidUrl::new(format!(
        "did:{}#{device}",
        ordinary_realm::FOUNDER
            .strip_prefix("ak:did_core:")
            .unwrap()
    ))
    .unwrap();
    request.event.envelope = serde_json::to_value(&*event).unwrap();
}

async fn evidence_rows(pool: &PgPool) -> Vec<(String, String)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        commit_id: String,
        #[diesel(sql_type = Text)]
        evidence_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT commit_id,evidence_ref FROM forwarded_producer_device_evidence ORDER BY commit_id",
    )
    .load::<Row>(&mut conn)
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.commit_id, row.evidence_ref))
    .collect()
}

async fn commit_count(pool: &PgPool, commit_id: &str) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM realm_commits WHERE commit_id=$1")
        .bind::<Text, _>(commit_id)
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

#[tokio::test]
async fn forwarded_evidence_is_retained_with_the_first_commit_or_not_at_all() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "forwarded-producer-evidence").await;
    let producer = AccountId::new(ordinary_realm::founder(), ordinary_realm::station());
    let mut request = discussion.message_after(
        &discussion.head.authority_commit,
        "forwarded message",
        discussion.committed_at(),
    );
    signed_by_device(&mut request, DEVICE);
    let commit_id = request.authority_commit.commit.commit_id.to_string();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());

    // Evidence for another device of the producer cannot ride along: the
    // whole Event, Commit and audit row roll back together.
    let mut mismatched = request.clone();
    mismatched.forwarded_producer_evidence =
        Some(ForwardedProducerDeviceEvidence::new(evidence(&producer, OTHER_DEVICE)).unwrap());
    assert!(uow.commit_event(mismatched).await.is_err());
    assert_eq!(commit_count(&pool, &commit_id).await, 0);
    assert!(evidence_rows(&pool).await.is_empty());

    // A local producer guard and forwarded evidence never describe one Event.
    let mut both = request.clone();
    both.forwarded_producer_evidence =
        Some(ForwardedProducerDeviceEvidence::new(evidence(&producer, DEVICE)).unwrap());
    both.self_producer_guard = Some(soland_storage::SelfProducerCommitGuard::HumanDevice(
        soland_storage::DeviceRevocationGateSelector {
            principal_id: producer.principal_id.clone(),
            station_id: producer.station_id.clone(),
            device_id: DEVICE.to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: discussion.head.authority_commit.event.event_id.clone(),
                commit_id: discussion.head.authority_commit.commit.commit_id.clone(),
                stream_ref: discussion.head.authority_commit.commit.stream_ref.clone(),
                stream_position: discussion.head.authority_commit.commit.stream_position,
            },
        },
    ));
    assert!(uow.commit_event(both).await.is_err());
    assert_eq!(commit_count(&pool, &commit_id).await, 0);
    assert!(evidence_rows(&pool).await.is_empty());

    let retained = ForwardedProducerDeviceEvidence::new(evidence(&producer, DEVICE)).unwrap();
    request.forwarded_producer_evidence = Some(retained.clone());
    uow.commit_event(request.clone()).await.unwrap();
    let rows = evidence_rows(&pool).await;
    assert_eq!(
        rows,
        vec![(
            commit_id.clone(),
            serde_json::to_value(&retained.evidence_ref)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        )]
    );

    // The exact replay of the admitted unit writes no second audit row.
    let _ = uow.commit_event(request).await;
    assert_eq!(evidence_rows(&pool).await, rows);
}
