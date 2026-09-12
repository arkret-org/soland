use arkret::historical_producer::AuthenticatedHistoricalProducerSource;
use arkret_canonical::DigestSuite;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence as Evidence;
use arkret_signatures::webvh::{ServiceInceptionInput, prepare_service_inception};
use arkret_wire::{
    AccountId, ActorId, DeviceId, Did, DidCoreId, DidKey, DidUrl, Event, EventId, Hash, Hlc,
    NonEmptyString, RealmId, ScopeRef,
};
use chrono::{DateTime, Duration, TimeZone as _};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;

use super::*;

struct Fixture {
    root: Evidence,
    dependency: Evidence,
    actor: ActorId,
    device_key: SigningKey,
    at: DateTime<Utc>,
}

impl Fixture {
    fn new() -> Self {
        Self::at(Utc.timestamp_opt(Utc::now().timestamp() - 60, 0).unwrap())
    }
    fn at(at: DateTime<Utc>) -> Self {
        let endpoint = "https://producer-source.example/".parse().unwrap();
        let mut rng = ChaChaRng::seed_from_u64(991);
        let inception = prepare_service_inception(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "station",
                also_known_as: &[],
                version_time: at,
                did_key_fragment: Some("assertion-1"),
            },
        )
        .unwrap();
        let station_did = Did::new(inception.did.clone()).unwrap();
        let station = arkret_wire::project_did_to_core_id(&station_did).unwrap();
        let document = serde_json::from_value(inception.log_entry["state"].clone()).unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            station.clone(),
            "station".to_owned(),
            document,
            vec![inception.log_entry.clone()],
            Vec::new(),
            at,
        )
        .unwrap();
        let method = DidUrl::new(inception.did_key_id.clone()).unwrap();
        let dependency = Evidence::Service {
            signer_id: station.clone(),
            verification_method: method.clone(),
            authenticated_resolution: resolution,
        };
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:webvh:zdeviceholder").unwrap(),
            station,
        );
        let device = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let device_key = SigningKey::from_bytes(&[33; 32]);
        let core = DeviceProjectionAttestationCore {
            account_id: account.clone(),
            device_id: device.clone(),
            device_signing_key_did: DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &device_key.verifying_key().to_bytes()
                )
            ))
            .unwrap(),
            hpke_key: NonEmptyString::new("hpke-key").unwrap(),
            device_authorize_event_id: EventId::from_digest(DigestSuite::Sha256, [1; 32]),
            authorized_generation_ref: 7,
            device_status: DeviceStatus::Active,
            authorization_window: DeviceAuthorizationWindow {
                not_before: at,
                expires_at: Some(at + Duration::hours(1)),
            },
            attested_at: at,
            expires_at: at + Duration::minutes(5),
        };
        let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
            core,
            method,
            &SigningKey::from_bytes(&inception.did_key_seed),
        )
        .unwrap();
        let root = Evidence::AccountDevice {
            signer_id: account.principal_id.clone(),
            verification_method: DidUrl::new(format!(
                "did:webvh:zdeviceholder:holder.example#{device}"
            ))
            .unwrap(),
            device_projection_attestation: attestation,
            attester_signer_evidence_ref: dependency.evidence_ref().unwrap(),
        };
        Self {
            root,
            dependency,
            actor: ActorId::account(account),
            device_key,
            at,
        }
    }
    fn source(&self) -> AuthenticatedHistoricalProducerSource {
        AuthenticatedHistoricalProducerSource::authenticate(
            &self.root.evidence_ref().unwrap(),
            &self.actor,
            &self.root,
            std::slice::from_ref(&self.dependency),
            self.at,
        )
        .unwrap()
    }
    fn event(&self, at: DateTime<Utc>) -> Event {
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir")
                    .unwrap(),
            },
            self.actor.clone(),
            0,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({"message_id":"m1","content":{"type":"text","body":"hello"}}),
            at,
        )
        .unwrap();
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.event_id = EventId::from_event_digest(&digest).unwrap();
        let mut proof = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: self.root.verification_method().clone(),
            event_digest: digest,
            signer_resolution_evidence_ref: Some(self.root.evidence_ref().unwrap()),
            created_at: at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &self.device_key,
        )
        .unwrap();
        event.proofs = vec![proof];
        event
    }
}

fn request(fixture: &Fixture) -> EventCommitRequest {
    let event = fixture.event(fixture.at);
    let producer = fixture
        .source()
        .verify_event(&event, DigestSuite::Sha256)
        .unwrap();
    EventCommitRequest {
        publication_event: None,
        mls_public_producer: None,
        mls_public_genesis: None,
        mls_frontier_leaves: None,
        replicated: false,
        event: soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.canonical_key().unwrap(),
            actor_seq: event.actor_seq,
            realm_id: Some(match &event.scope_ref {
                ScopeRef::Realm { realm_id } => realm_id.to_string(),
                _ => unreachable!(),
            }),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(event).unwrap(),
            received_at: Utc::now(),
        },
        membership_compensation_evidence: None,
        governance_dependencies: vec![],
        device_pairing_authorization: None,
        contact_projection: None,
        consent_projection: None,
        control_proposal_ingress: None,
        device_revocation_transition: None,
        device_revocation_gate: None,
        historical_producer: Some(producer),
        projections: vec![],
        idempotency: None,
        outbox: vec![],
    }
}

async fn check(pool: &PgPool, request: &EventCommitRequest) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await.unwrap();
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        enforce_event_gate(conn, request).await?;
        Ok(())
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

#[tokio::test]
async fn historical_producer_gate_uses_verified_source_and_exact_known_revocation() {
    let db = crate::TestDatabase::lease().await;
    let pool = db.pool();
    let fixture = Fixture::new();
    let request = request(&fixture);
    // Real WebVH and source/Event signatures above authenticate the producer.
    // This persistence test deliberately has no local account/device mirror.
    check(&pool, &request).await.unwrap();
    let mut replaced_proof = request.clone();
    replaced_proof.event.envelope["proofs"][0]["jws"] = serde_json::json!("e30..forged");
    assert!(check(&pool, &replaced_proof).await.is_err());
    let core = request
        .historical_producer
        .as_ref()
        .unwrap()
        .device_authorization()
        .unwrap();
    let selector = DeviceRevocationGateSelector {
        principal_id: core.account_id.principal_id.clone(),
        station_id: core.account_id.station_id.clone(),
        device_id: core.device_id.to_string(),
        target_device_authorize_event_id: core.device_authorize_event_id.to_string(),
        target_device_generation_ref: core.authorized_generation_ref,
    };
    let mut conflicting_modes = request.clone();
    conflicting_modes.device_revocation_gate = Some(selector.clone());
    assert!(check(&pool, &conflicting_modes).await.is_err());
    // Seed the durable, already-admitted revocation observation boundary.
    // These rows test transaction gating, not revocation signature admission.
    let digest = format!("sha256:{}", "a".repeat(64));
    let mut conn = pg_conn(&pool).await.unwrap();
    sql_query("INSERT INTO state_control_events(event_digest,digest_suite,realm_id,event_json,ingress_class,command_unit_event_digests) VALUES($1,'sha256',$2,$3,'{}',$4)")
        .bind::<Text,_>(&digest).bind::<Text,_>(request.event.realm_id.as_ref().unwrap())
        .bind::<Jsonb,_>(&request.event.envelope).bind::<Jsonb,_>(serde_json::json!([digest]))
        .execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO device_revocation_targets(proposal_digest,principal_id,station_id,device_id,target_device_authorize_event_id,target_device_generation_ref,proposal_event_id,accepted_at,acceptance_seq,control_proposal_ack) VALUES($1,$2,$3,$4,$5,$6,$7,NOW(),1,'{}')")
        .bind::<Text,_>(&digest).bind::<Text,_>(selector.principal_id.as_str())
        .bind::<Text,_>(selector.station_id.as_str()).bind::<Text,_>(&selector.device_id)
        .bind::<Text,_>(&selector.target_device_authorize_event_id)
        .bind::<BigInt,_>(i64::try_from(selector.target_device_generation_ref).unwrap())
        .bind::<Text,_>(&request.event.event_id).execute(&mut *conn).await.unwrap();
    drop(conn);
    assert!(check(&pool, &request).await.is_err());
    let mut conn = pg_conn(&pool).await.unwrap();
    sql_query("UPDATE device_revocation_targets SET target_device_authorize_event_id=$2 WHERE proposal_digest=$1")
        .bind::<Text,_>(&digest).bind::<Text,_>(EventId::from_digest(DigestSuite::Sha256,[2;32]).as_str())
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    check(&pool, &request).await.unwrap();
}

#[tokio::test]
async fn historical_producer_live_gate_preserves_original_authorization_deadline() {
    let db = crate::TestDatabase::lease().await;
    let pool = db.pool();
    let fixture = Fixture::new();
    check(&pool, &request(&fixture)).await.unwrap();
    let expired = Fixture::at(fixture.at - Duration::hours(2));
    let expired_request = request(&expired);
    // Historical source + Event verification still succeeds. A new live write
    // after the original grant deadline does not, even with an old created_at.
    assert!(check(&pool, &expired_request).await.is_err());
    let core = expired_request
        .historical_producer
        .as_ref()
        .unwrap()
        .device_authorization()
        .unwrap();
    assert!(!live_window_allows(
        &core.authorization_window,
        expired.at - Duration::seconds(1)
    ));
    assert!(!live_window_allows(
        &core.authorization_window,
        expired.at + Duration::hours(1)
    ));
}
