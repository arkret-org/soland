//! Real PG source and a registered TCP PeerScan execute the production recovery
//! helper. The session is the already-authenticated state-port context; this
//! does not claim a live OIDC/DPoP middleware or subprocess-crash test.
#[path = "../../../storage-postgres/tests/support/historical_human.rs"]
mod historical_human;

use std::io::{Read, Write};
use std::sync::Arc;

use arkret_models_collaboration::authority_commit::{
    PeerStreamScanOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_models_identity::session_credential::{
    SessionGrantCredentialClass, SessionGrantDeviceBinding, SessionGrantHolderBinding,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DidUrl, EventAdmissionSubmission, EventKind,
    StreamScanDirection, StreamScanRequest,
};
use chrono::{Duration, Utc};
use soland_services::identity::{
    SessionEndpointState, SessionGrantAuthorizationState, SessionIdentityState,
};
use soland_services::service_route::{
    ServiceRouteFetcher, VerifiedRouteCandidate, VerifiedServiceDescribeMetadata,
};
use soland_storage::{
    AccountPk, AccountRecord, AuthorityCommitStore, CommittedReplica, CommittedReplicaRole,
    EventCommitUnitOfWork, ForwardedProducerDeviceEvidence, ReplicaAnchorInstall,
};
use soland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPersistenceStore, PgPool,
};

use super::*;

struct VerifiedSourceRoute(VerifiedRouteCandidate);
#[async_trait::async_trait]
impl ServiceRouteFetcher for VerifiedSourceRoute {
    async fn fetch_current(
        &self,
        id: &DidCoreId,
        kind: &str,
    ) -> soland_services::ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok((id == &self.0.evidence.service_id && kind == "station").then(|| self.0.clone()))
    }
}

/// Preserve the same accepted fixture identity, original method history and PG
/// store across the local test-crate type boundary (as the native replay test).
fn station(url: String) -> (AppState, PgPool, Arc<dyn soland_storage::PersistenceStore>) {
    let mut external = soland_test_support::app_config();
    external.public_base_url = url.clone();
    external.notary_signing_key_seed = Some([83; 32]);
    external.seed_demo_data = false;
    external.development_mode = true;
    let (leased, pool) = soland_test_support::app_state_with_pool(external.clone());
    let local = crate::config::AppConfig {
        public_base_url: url,
        notary_signing_key_seed: Some([83; 32]),
        seed_demo_data: false,
        development_mode: true,
        ..crate::config::AppConfig::test_default()
    };
    assert_eq!(local.trust_domain, external.trust_domain);
    let state = AppState::new_with_service_identity(
        local,
        soland_storage_postgres::Db {
            pool: Some(pool.clone()),
        },
        Arc::new(PgPersistenceStore::new(pool.clone())),
        soland_test_support::fixture_service_identity(&external),
        leased.service_resolution_commitment().as_ref().clone(),
        [83; 32],
    );
    use soland_test_support::AppStateTestExt as _;
    let keep_lease = leased.test_persistence();
    (state, pool, keep_lease)
}

async fn foreign_request(
    origin: &AppState,
    joining: &historical_human::HumanFixture,
    governor: &historical_human::HumanFixture,
    previous: &soland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: serde_json::Value,
) -> soland_storage::EventCommitRequest {
    let at = previous.commit.committed_at + Duration::seconds(1);
    let event = historical_human::signed_ordinary_event(joining, previous, kind, payload, at);
    let mut request = historical_human::request_for_event(joining, previous, event, at);
    let unsigned = arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest {
        branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(request.authority_commit.event.clone()),
        producer_device_evidence: None,
        producer_agent_evidence: None,
        mls_genesis_material: None,
    };
    let body_digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(&unsigned)
            .unwrap();
    let evidence = super::fresh_producer_device_evidence(
        origin,
        &request.authority_commit.event,
        &governor.pcr.history.account.station_id,
        &body_digest,
    )
    .await
    .unwrap()
    .unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_human_signer_fact(
        &evidence,
        &request.authority_commit.event,
        &joining.pcr.history.account.station_id,
        &governor.pcr.history.account.station_id,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    request.authority_commit.producer_signer_fact = Some(fact.clone());
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.commit.committed_at = core.attested_at;
    request.self_producer_guard = None;
    request.forwarded_producer_evidence =
        Some(ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap());
    historical_human::seal_commit(
        &mut request.authority_commit.commit,
        &governor.pcr.history.station_did,
    );
    request.realm_fanout_source = Some(EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

async fn authenticated_context(
    pool: &PgPool,
    human: &historical_human::HumanFixture,
) -> SessionIdentityState {
    use soland_storage::IdentityStoreRegistry;
    let account = &human.pcr.history.account;
    let persistence = PgPersistenceStore::new(pool.clone());
    let pk = persistence
        .accounts()
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: "forward-recovery-reader".into(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    let device = human.pcr.history.founding_device_id.clone();
    SessionIdentityState {
        token_hash: "authenticated-state-port-public-fixture".into(),
        account_pk: Some(pk),
        actor: account.principal_id.to_string(),
        endpoint: SessionEndpointState::HumanDevice {
            device_id: device.to_string(),
        },
        audience: account.station_id.to_string(),
        session_public_key: None,
        session_grant: Some(SessionGrantAuthorizationState {
            grant_id: arkret_identifiers::SessionGrantId::from_issuance_digest([0x64; 32]),
            revocation_ref: "public-state-port-context".into(),
            account_id: account.clone(),
            issuer_id: account.station_id.clone(),
            scopes: vec![],
            credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice {
                device_binding: device.to_string(),
            },
            device_binding: Some(SessionGrantDeviceBinding {
                device_id: device,
                authorization_event_id: human.guard.authorization_ref.event_id.clone(),
                model_generation_ref: 1,
            }),
            cnf_jkt: "public-state-port-holder".into(),
        }),
        expires_at: Utc::now() + Duration::hours(1),
        created_at: Utc::now(),
        revoked_at: None,
    }
}

/// Exercise real producer preflight and atomic bootstrap admission on the same
/// default worker stack used by the server. Authentication is represented by
/// the already-authenticated state-port context, not a dev-login credential.
#[test]
fn ordinary_realm_bootstrap_and_event_admission_fit_default_worker_stack() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (state, pool, _lease) = station("https://bootstrap-default-stack.internal/".into());
    let (human, session) = runtime.block_on(async {
        let human = historical_human::HumanFixture::new(&pool, state.service_did()).await;
        let session = authenticated_context(&pool, &human).await;
        (human, session)
    });
    let http = crate::service(state.clone());
    runtime.block_on(async {
        tokio::spawn(async move {
            let request =
                SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(human.unit.submission.clone());
            let response = salvo::test::TestClient::post("http://server/_arkret/self/events")
                .add_header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    true,
                )
                .json(&serde_json::to_value(&request).unwrap())
                .send(&http)
                .await;
            assert_eq!(
                response.status_code,
                Some(salvo::http::StatusCode::UNAUTHORIZED)
            );
            let outcome = state
                .authority()
                .submit_self(&session, request.clone(), &human.unit.exact_request_body)
                .await
                .unwrap();
            outcome.validate_for_request(&request).unwrap();
            let committed = state
                .authority_commits()
                .committed_event(&human.unit.transactions.last().unwrap().event.event_id)
                .await
                .unwrap()
                .unwrap();
            let mut previous = human.unit.transactions.last().unwrap().clone();
            previous.commit = committed.commit;
            previous.event = committed.event;
            let next = human.next(&previous, human.pcr.history.founding_device_signing_seed);
            let submission = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(
                next.authority_commit.event,
            ));
            let body = serde_json::to_vec(&submission).unwrap();
            let outcome = state
                .authority()
                .submit_self(&session, submission, &body)
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                soland_services::authority_commit::SelfAuthoritySubmitOutcome::Ordinary(
                    arkret_wire::AuthoritySubmitOutcome::Accepted {
                        status: arkret_wire::AuthorityCommitStatus::Committed,
                        ..
                    }
                )
            ));
        })
        .await
        .unwrap();
    });
}

/// The same real CA/leaf fixture used by federation_outbox. Production egress
/// loads this explicit trust store and keeps certificate/hostname validation.
/// The driver must supply SSL_CERT_FILE; missing trust is a failure, not a skip.
struct RegisteredTlsPeer {
    listener: std::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
}

fn registered_tls_peer() -> Arc<RegisteredTlsPeer> {
    let expected = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../server/tests/fixtures/outbox-test-ca.pem")
        .canonicalize()
        .unwrap();
    let configured = std::env::var_os("SSL_CERT_FILE")
        .and_then(|path| std::path::Path::new(&path).canonicalize().ok());
    assert_eq!(
        configured.as_deref(),
        Some(expected.as_path()),
        "recovery executor requires the checked-in federation outbox test CA"
    );
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../../server/tests/fixtures/outbox-test-cert.der").to_vec(),
    );
    let private_key =
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("../../../server/tests/fixtures/outbox-test-key.der").to_vec(),
        ));
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap(),
    );
    Arc::new(RegisteredTlsPeer {
        listener: std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        tls,
    })
}

async fn tcp_scan(
    listener: Arc<RegisteredTlsPeer>,
    page: PeerStreamScanOutcome,
    expected: StreamScanRequest,
    from: AccountId,
    to: DidCoreId,
) -> usize {
    tokio::task::spawn_blocking(move || {
    let (stream, _) = listener.listener.accept().unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    let mut stream = rustls::StreamOwned::new(
        rustls::ServerConnection::new(listener.tls.clone()).unwrap(), stream,
    );
    let mut bytes = Vec::new();
    let mut buf = [0u8; 2048];
    let end = loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        assert!(bytes.len() < 1024 * 1024);
        if let Some(p) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(header.starts_with("POST /_arkret/peer/streams/scan HTTP/1.1"));
    let fields = header
        .lines()
        .filter_map(|v| {
            v.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        fields.get("source-service-id"),
        Some(&from.station_id.to_string())
    );
    assert_eq!(fields.get("destination-service-id"), Some(&to.to_string()));
    assert!(
        fields.contains_key("signature-input")
            && fields.contains_key("signature")
            && fields.contains_key("content-digest")
    );
    let length = fields["content-length"].parse::<usize>().unwrap();
    assert!(length < 1024 * 1024);
    while bytes.len() < end + length {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    let actual: StreamScanRequest = serde_json::from_slice(&bytes[end..end + length]).unwrap();
    assert_eq!(actual, expected);
    let body = arkret_canonical::canonical_json_bytes(&page).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    assert!(!stream.conn.is_handshaking());
    1
    }).await.unwrap()
}

#[tokio::test]
async fn accepted_forward_witness_reopens_then_executes_registered_prefix_without_new_submission() {
    let listener = registered_tls_peer();
    let base = format!("https://{}/", listener.listener.local_addr().unwrap());
    let (governor_state, governor_pool, _governor_lease) = station(base.clone());
    let (origin, origin_pool, _origin_lease) =
        station("https://forward-recovery-origin.internal/".into());
    let mut governor =
        historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
    // The existing closed bootstrap facet must explicitly authorize the Origin
    // to receive plaintext. Membership/action grants alone grant no such right.
    // Author this before the unit is accepted; never patch accepted state.
    let disclosure_index = governor
        .unit
        .transactions
        .iter()
        .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
        .unwrap();
    assert!(disclosure_index > 0);
    assert_eq!(
        governor
            .unit
            .transactions
            .iter()
            .filter(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
            .count(),
        1
    );
    let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(
            serde_json::to_value(&governor.unit.transactions[disclosure_index].event.payload).unwrap(),
        ).unwrap();
    assert_eq!(disclosure.services.len(), 1);
    assert_eq!(
        disclosure.services[0].service_id,
        governor_state.service_core_id()
    );
    assert_ne!(governor_state.service_core_id(), origin.service_core_id());
    disclosure.services.push(
        serde_json::from_value(serde_json::json!({
            "service_id":origin.service_core_id(), "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["accepted original recovery fixture"],
            "visibility":"private_plaintext"
        }))
        .unwrap(),
    );
    let disclosure_event = historical_human::signed_ordinary_event(
        &governor,
        &governor.unit.transactions[disclosure_index - 1],
        EventKind::RealmPlaintextVisibleServices,
        disclosure.to_value().unwrap(),
        governor.unit.transactions[disclosure_index]
            .commit
            .committed_at,
    );
    governor.unit.transactions[disclosure_index].event = disclosure_event;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let mut previous_commit = None;
    for (index, transaction) in governor.unit.transactions.iter_mut().enumerate() {
        transaction.commit.event_ref = transaction.event.event_id.clone();
        transaction.producer_signer_fact = source
            .prepare_human_signer_fact(&transaction.event, transaction.commit.committed_at)
            .await
            .unwrap();
        assert!(transaction.producer_signer_fact.is_some());
        transaction.commit.producer_signer_fact_digest = transaction
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        transaction.commit.previous_commit_ref = previous_commit;
        historical_human::seal_commit(&mut transaction.commit, &governor.pcr.history.station_did);
        previous_commit = Some(transaction.commit.commit_id.clone());
        governor.unit.submission.events[index] =
            EventAdmissionSubmission::new(transaction.event.clone());
    }
    governor.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(governor.unit.submission.clone()),
    )
    .unwrap();
    governor.admit(&governor_pool).await;
    assert_eq!(
        source
            .accepted_plaintext_visible_services(&governor.unit.transactions[0].event.realm_id,)
            .await
            .unwrap(),
        Some(disclosure)
    );
    let human = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
    let actor = ActorId::account(human.pcr.history.account.clone());
    let previous = governor.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + Duration::seconds(1);
    let owner = ActorId::account(governor.pcr.history.account.clone());
    let strand_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::StrandCreate,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1", "realm_id":previous.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"forward recovery fixture discussion"}, "state":"active",
            "created_by":owner, "created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let strand = historical_human::request_for_event(&governor, previous, strand_event, at);
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    // Membership is not an action grant. Read the actual accepted root cut,
    // then admit the owner's narrow Grant before the foreign member joins. The
    // Grant grants no membership; MessageCreate still runs after the real join.
    #[derive(diesel::QueryableByName)]
    struct RootCut {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        controller_actor_id: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Text)]
        authority_event_ref: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        authority_generation: i64,
    }
    use diesel_async::RunQueryDsl as _;
    let root_cut = {
        let mut conn = governor_pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT controller_actor_id, authority_event_ref, authority_generation \
             FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(strand.authority_commit.event.realm_id.as_str())
        .get_result::<RootCut>(&mut *conn)
        .await
        .unwrap()
    };
    assert_eq!(
        serde_json::from_value::<ActorId>(root_cut.controller_actor_id).unwrap(),
        owner
    );
    let root_generation = u64::try_from(root_cut.authority_generation).unwrap();
    let previous = &strand.authority_commit;
    let grant_at = previous.commit.committed_at + Duration::seconds(1);
    let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::json!({"grant": {
            "schema":"ak.schema.capability.v1",
            "realm_id":previous.event.realm_id,
            "issuer_id":owner,
            "subject":actor,
            "actions":["ak.message.create"],
            "resources":[{"kind":"realm","realm_id":previous.event.realm_id}],
            "issuer_authority_refs":[{
                "kind":"realm_root","realm_id":previous.event.realm_id,
                "authority_event_ref":root_cut.authority_event_ref,
                "authority_generation":root_generation
            }],
            "issued_at":arkret_canonical::format_timestamp_canonical(grant_at)
        }}))
        .unwrap();
    let grant_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::CapabilityGrant,
        serde_json::to_value(grant_payload).unwrap(),
        grant_at,
    );
    let mut grant = historical_human::request_for_event(&governor, previous, grant_event, grant_at);
    // This is a fresh PG source candidate, not a cached authorizing capability.
    // The UOW independently prepares and compares it under its admission locks.
    let grant_fact = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    }
    .prepare_human_signer_fact(&grant.authority_commit.event, grant_at)
    .await
    .unwrap()
    .unwrap();
    grant.authority_commit.commit.producer_signer_fact_digest = Some(grant_fact.digest().unwrap());
    grant.authority_commit.producer_signer_fact = Some(grant_fact);
    historical_human::seal_commit(
        &mut grant.authority_commit.commit,
        &governor.pcr.history.station_did,
    );
    uow.commit_event(grant.clone()).await.unwrap();
    let previous = &grant.authority_commit;
    let join = foreign_request(&origin, &human, &governor, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"real forward recovery membership"})).await;
    uow.commit_event(join.clone()).await.unwrap();
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    store
        .install_committed_replica(&CommittedReplica {
            local_service_id: human.pcr.history.account.station_id.clone(),
            authority: join.authority_commit.expected_authority.clone(),
            event: join.authority_commit.event.clone(),
            commit: join.authority_commit.commit.clone(),
            producer_signer_fact: join.authority_commit.producer_signer_fact.clone(),
            genesis_event_ref: None,
            role: CommittedReplicaRole::OpeningJoin {
                member_account_id: human.pcr.history.account.clone(),
            },
            received_at: join.authority_commit.commit.committed_at,
            welcomes: vec![],
        })
        .await
        .unwrap();
    let realm = &join.authority_commit.event.realm_id;
    let material = source
        .member_station_bootstrap_material(
            realm,
            &human.pcr.history.account,
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
    let snapshot = soland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        DidUrl::new(format!("{}#authority", governor.pcr.history.station_did)).unwrap(),
        &key,
        Utc::now(),
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    store
        .install_replica_anchor(&ReplicaAnchorInstall {
            realm_id: realm.clone(),
            join_commit_id: join.authority_commit.commit.commit_id.clone(),
            governance_generation: material.governance_generation,
            snapshot_head: material.visible_stream_heads[0].clone(),
            visible_stream_heads: material.visible_stream_heads,
            current_state_entries: material.current_state_entries,
            verified_snapshot: snapshot,
        })
        .await
        .unwrap();
    let target = foreign_request(&origin, &human, &governor, &join.authority_commit, EventKind::MessageCreate,
        serde_json::json!({"strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id),"track_name":"discussion","content":{"kind":"ak.content.text","body":"accepted original transport fixture","format":"plain"}})).await;
    uow.commit_event(target.clone()).await.unwrap();
    let event = &target.authority_commit.event;
    let commit = &target.authority_commit.commit;
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let intent = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.clone()));
    store.queue_event(event, commit.committed_at).await.unwrap();
    store
        .retain_forwarded_submission(event, &intent, commit.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(event, commit, commit.committed_at)
        .await
        .unwrap();
    drop(store);
    let reopened = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    let queued = reopened
        .queued_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert!(queued.committed.is_none());
    let witness = queued.forward_attempt.unwrap();
    assert_eq!(witness.accepted_commit, Some(commit.clone()));
    assert_eq!(witness.original_submission, Some(intent));
    let session = authenticated_context(&origin_pool, &human).await;
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            &governor_state,
        )
        .await
        .unwrap();
    let boundary = route.method_history_evidence.boundary();
    let description = VerifiedServiceDescribeMetadata {
        service_id: governor_state.service_core_id(),
        service_kind: "station".into(),
        service_resolution: ResolutionCommitment {
            did: governor_state.service_did(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
        },
        http_json_base_url: base,
        trust_domain: governor_state.config().trust_domain.clone(),
        protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
        supported_operation_bundles: vec![
            arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                .unwrap()
                .operation_bundle_id
                .into(),
        ],
    };
    origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            evidence: route,
            description,
        },
    )));
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([0x71; 32])).unwrap();
    let bundle = crate::routing::realm_join::local_authority_bundle(&governor_state, realm, &nonce)
        .await
        .unwrap();
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for sig in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
        &commit.signature,
    ] {
        keys.insert_at(
            &sig.verification_method,
            sig.created_at,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        );
    }
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(Utc::now(), nonce),
        &keys,
    )
    .unwrap();
    let mut located = crate::routing::realm_join::LocatedRealmAuthority {
        bundle,
        authority,
        keys,
    };
    let scan = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::After(Some(join.authority_commit.commit.stream_position)),
        limit: 128,
    };
    let soland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("actually joined Origin is authorized for the real peer prefix")
    };
    page.validate_for_request(&scan).unwrap();
    let original_target = page
        .committed_events
        .iter()
        .find(|row| row.commit().commit_id == commit.commit_id)
        .unwrap();
    let arkret_wire::CommittedEventView::Full(original_target) = original_target else {
        panic!("the explicitly authorized plaintext target must be a real Full row")
    };
    assert_eq!(&original_target.event, event);
    assert_eq!(&original_target.commit, commit);
    let archived_fact = source.human_signer_fact(event, commit).await.unwrap();
    assert!(archived_fact.is_some());
    assert_eq!(archived_fact, target.authority_commit.producer_signer_fact);
    assert_eq!(
        page.producer_signer_facts
            .iter()
            .find(|entry| entry.target.commit_id == commit.commit_id)
            .map(|entry| &entry.producer_signer_fact),
        archived_fact.as_ref(),
    );
    assert!(target.authority_commit.producer_signer_fact.is_some());
    let before_head = reopened
        .held_stream_head_commit(&commit.stream_ref)
        .await
        .unwrap();
    let mut withheld_page = page.clone();
    let target_row = withheld_page
        .committed_events
        .iter_mut()
        .find(|row| row.commit().event_ref == event.event_id)
        .unwrap();
    *target_row =
        arkret_wire::CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
            commit: commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        });
    withheld_page
        .producer_signer_facts
        .retain(|entry| entry.target.commit_id != commit.commit_id);
    withheld_page.validate_for_request(&scan).unwrap();
    let fault_server = tokio::spawn(tcp_scan(
        listener.clone(),
        withheld_page,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    let refused = super::super::replica_anchor::ensure_forwarded_target(
        &origin,
        &governor_state.service_core_id(),
        event,
        Some(commit),
        &mut located,
        &session,
    )
    .await
    .unwrap_err();
    assert!(refused.contains("withheld"));
    assert_eq!(fault_server.await.unwrap(), 1);
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        before_head
    );
    assert!(
        reopened
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .forward_attempt
            .as_ref()
            .unwrap()
            .accepted_commit
            .as_ref(),
        Some(commit)
    );
    let mut bad_fact_page = page.clone();
    bad_fact_page
        .producer_signer_facts
        .iter_mut()
        .find(|entry| entry.target.commit_id == commit.commit_id)
        .unwrap()
        .producer_signer_fact
        .key
        .governance_generation += 1;
    let fault_server = tokio::spawn(tcp_scan(
        listener.clone(),
        bad_fact_page,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session
        )
        .await
        .is_err()
    );
    assert_eq!(fault_server.await.unwrap(), 1);
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        before_head
    );
    assert!(
        reopened
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let server = tokio::spawn(tcp_scan(
        listener.clone(),
        page,
        scan,
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    let recovered = super::super::replica_anchor::ensure_forwarded_target(
        &origin,
        &governor_state.service_core_id(),
        event,
        Some(commit),
        &mut located,
        &session,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(recovered, *commit);
    assert_eq!(server.await.unwrap(), 1);
    let installed = reopened
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installed.event, *event);
    assert_eq!(installed.commit, *commit);
    assert_eq!(
        reopened.human_signer_fact(event, commit).await.unwrap(),
        target.authority_commit.producer_signer_fact
    );
    let held = reopened
        .held_stream_head_commit(&commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held, *commit);
    // The held branch performs no network operation. It revalidates the exact
    // original/fact/prefix and caller disclosure, not today's producer key.
    assert_eq!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session
        )
        .await
        .unwrap(),
        Some(commit.clone())
    );
    let mut fork = commit.clone();
    fork.committed_at += Duration::milliseconds(1);
    historical_human::seal_commit(&mut fork, &governor.pcr.history.station_did);
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(&fork),
            &mut located,
            &session
        )
        .await
        .is_err()
    );
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        Some(held.clone())
    );
    let mut expired = session.clone();
    expired.expires_at = Utc::now() - Duration::seconds(1);
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &expired
        )
        .await
        .is_err()
    );
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        Some(held)
    );
}

fn station_with_webvh(
    url: String,
) -> (AppState, PgPool, Arc<dyn soland_storage::PersistenceStore>) {
    let mut external = soland_test_support::app_config();
    external.public_base_url = url.clone();
    external.notary_signing_key_seed = Some([83; 32]);
    external.seed_demo_data = false;
    external.development_mode = true;
    external.did_resolver_allow_methods.push("webvh".into());
    let (leased, pool) = soland_test_support::app_state_with_pool(external.clone());
    let local = crate::config::AppConfig {
        public_base_url: url,
        notary_signing_key_seed: Some([83; 32]),
        seed_demo_data: false,
        development_mode: true,
        did_resolver_allow_methods: external.did_resolver_allow_methods.clone(),
        ..crate::config::AppConfig::test_default()
    };
    assert_eq!(local.trust_domain, external.trust_domain);
    let state = AppState::new_with_service_identity(
        local,
        soland_storage_postgres::Db {
            pool: Some(pool.clone()),
        },
        Arc::new(PgPersistenceStore::new(pool.clone())),
        soland_test_support::fixture_service_identity(&external),
        leased.service_resolution_commitment().as_ref().clone(),
        [83; 32],
    );
    use soland_test_support::AppStateTestExt as _;
    let keep_lease = leased.test_persistence();
    (state, pool, keep_lease)
}

fn seal_service_commit(commit: &mut arkret_wire::RealmCommit, governor: &AppState) {
    let body =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&body).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        governor.service_verification_method("notary-key").unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed()),
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
}
#[tokio::test]
async fn accepted_own_opening_join_without_anchor_uses_original_peer_fact_then_signed_bootstrap() {
    let listener = registered_tls_peer();
    let base = format!("https://{}/", listener.listener.local_addr().unwrap());
    let (governor_state, governor_pool, _governor_lease) = station_with_webvh(base.clone());
    let (origin, origin_pool, _origin_lease) =
        station_with_webvh("https://forward-recovery-origin.internal/".into());
    let mut governor =
        historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
    // The existing closed bootstrap facet must explicitly authorize the Origin
    // to receive plaintext. Membership/action grants alone grant no such right.
    // Author this before the unit is accepted; never patch accepted state.
    let disclosure_index = governor
        .unit
        .transactions
        .iter()
        .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
        .unwrap();
    assert!(disclosure_index > 0);
    assert_eq!(
        governor
            .unit
            .transactions
            .iter()
            .filter(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
            .count(),
        1
    );
    let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(
            serde_json::to_value(&governor.unit.transactions[disclosure_index].event.payload).unwrap(),
        ).unwrap();
    assert_eq!(disclosure.services.len(), 1);
    assert_eq!(
        disclosure.services[0].service_id,
        governor_state.service_core_id()
    );
    assert_ne!(governor_state.service_core_id(), origin.service_core_id());
    disclosure.services.push(
        serde_json::from_value(serde_json::json!({
            "service_id":origin.service_core_id(), "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["accepted original recovery fixture"],
            "visibility":"private_plaintext"
        }))
        .unwrap(),
    );
    let disclosure_event = historical_human::signed_ordinary_event(
        &governor,
        &governor.unit.transactions[disclosure_index - 1],
        EventKind::RealmPlaintextVisibleServices,
        disclosure.to_value().unwrap(),
        governor.unit.transactions[disclosure_index]
            .commit
            .committed_at,
    );
    governor.unit.transactions[disclosure_index].event = disclosure_event;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let mut previous_commit = None;
    for (index, transaction) in governor.unit.transactions.iter_mut().enumerate() {
        transaction.commit.event_ref = transaction.event.event_id.clone();
        transaction.producer_signer_fact = source
            .prepare_human_signer_fact(&transaction.event, transaction.commit.committed_at)
            .await
            .unwrap();
        assert!(transaction.producer_signer_fact.is_some());
        transaction.commit.producer_signer_fact_digest = transaction
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        transaction.commit.previous_commit_ref = previous_commit;
        seal_service_commit(&mut transaction.commit, &governor_state);
        previous_commit = Some(transaction.commit.commit_id.clone());
        governor.unit.submission.events[index] =
            EventAdmissionSubmission::new(transaction.event.clone());
    }
    governor.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(governor.unit.submission.clone()),
    )
    .unwrap();
    governor.admit(&governor_pool).await;
    assert_eq!(
        source
            .accepted_plaintext_visible_services(&governor.unit.transactions[0].event.realm_id,)
            .await
            .unwrap(),
        Some(disclosure)
    );
    let human = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
    let actor = ActorId::account(human.pcr.history.account.clone());
    let previous = governor.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + Duration::seconds(1);
    let owner = ActorId::account(governor.pcr.history.account.clone());
    let strand_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::StrandCreate,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1", "realm_id":previous.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"forward recovery fixture discussion"}, "state":"active",
            "created_by":owner, "created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let mut strand = historical_human::request_for_event(&governor, previous, strand_event, at);
    seal_service_commit(&mut strand.authority_commit.commit, &governor_state);
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    // Membership is not an action grant. Read the actual accepted root cut,
    // then admit the owner's narrow Grant before the foreign member joins. The
    // Grant grants no membership; MessageCreate still runs after the real join.
    #[derive(diesel::QueryableByName)]
    struct RootCut {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        controller_actor_id: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Text)]
        authority_event_ref: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        authority_generation: i64,
    }
    use diesel_async::RunQueryDsl as _;
    let root_cut = {
        let mut conn = governor_pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT controller_actor_id, authority_event_ref, authority_generation \
             FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(strand.authority_commit.event.realm_id.as_str())
        .get_result::<RootCut>(&mut *conn)
        .await
        .unwrap()
    };
    assert_eq!(
        serde_json::from_value::<ActorId>(root_cut.controller_actor_id).unwrap(),
        owner
    );
    let root_generation = u64::try_from(root_cut.authority_generation).unwrap();
    let previous = &strand.authority_commit;
    let grant_at = previous.commit.committed_at + Duration::seconds(1);
    let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::json!({"grant": {
            "schema":"ak.schema.capability.v1",
            "realm_id":previous.event.realm_id,
            "issuer_id":owner,
            "subject":actor,
            "actions":["ak.message.create"],
            "resources":[{"kind":"realm","realm_id":previous.event.realm_id}],
            "issuer_authority_refs":[{
                "kind":"realm_root","realm_id":previous.event.realm_id,
                "authority_event_ref":root_cut.authority_event_ref,
                "authority_generation":root_generation
            }],
            "issued_at":arkret_canonical::format_timestamp_canonical(grant_at)
        }}))
        .unwrap();
    let grant_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::CapabilityGrant,
        serde_json::to_value(grant_payload).unwrap(),
        grant_at,
    );
    let mut grant = historical_human::request_for_event(&governor, previous, grant_event, grant_at);
    // This is a fresh PG source candidate, not a cached authorizing capability.
    // The UOW independently prepares and compares it under its admission locks.
    let grant_fact = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    }
    .prepare_human_signer_fact(&grant.authority_commit.event, grant_at)
    .await
    .unwrap()
    .unwrap();
    grant.authority_commit.commit.producer_signer_fact_digest = Some(grant_fact.digest().unwrap());
    grant.authority_commit.producer_signer_fact = Some(grant_fact);
    seal_service_commit(&mut grant.authority_commit.commit, &governor_state);
    uow.commit_event(grant.clone()).await.unwrap();
    let previous = &grant.authority_commit;
    let mut join = foreign_request(&origin, &human, &governor, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"real forward recovery membership"})).await;
    seal_service_commit(&mut join.authority_commit.commit, &governor_state);
    uow.commit_event(join.clone()).await.unwrap();
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    let realm = &join.authority_commit.event.realm_id;
    let event = &join.authority_commit.event;
    let commit = &join.authority_commit.commit;
    let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
    let session = authenticated_context(&origin_pool, &human).await;
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            &governor_state,
        )
        .await
        .unwrap();
    let boundary = route.method_history_evidence.boundary();
    let description = VerifiedServiceDescribeMetadata {
        service_id: governor_state.service_core_id(),
        service_kind: "station".into(),
        service_resolution: ResolutionCommitment {
            did: governor_state.service_did(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
        },
        http_json_base_url: base,
        trust_domain: governor_state.config().trust_domain.clone(),
        protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
        supported_operation_bundles: vec![
            arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                .unwrap()
                .operation_bundle_id
                .into(),
        ],
    };
    origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            evidence: route,
            description,
        },
    )));
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([0x71; 32])).unwrap();
    let bundle = crate::routing::realm_join::local_authority_bundle(&governor_state, realm, &nonce)
        .await
        .unwrap();
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for sig in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
        &commit.signature,
    ] {
        keys.insert_at(
            &sig.verification_method,
            sig.created_at,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        );
    }
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(Utc::now(), nonce),
        &keys,
    )
    .unwrap();
    let mut located = crate::routing::realm_join::LocatedRealmAuthority {
        bundle,
        authority,
        keys,
    };
    store
        .record_remote_authority(&located.current_authority(), &origin.service_core_id())
        .await
        .unwrap();
    store.queue_event(event, commit.committed_at).await.unwrap();
    let intent = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.clone()));
    store
        .retain_forwarded_submission(event, &intent, commit.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(event, commit, commit.committed_at)
        .await
        .unwrap();
    assert!(
        store
            .replica_anchor_for_stream(&commit.stream_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let no_write = opening_footprint(&origin_pool, realm).await;
    // A bare original or the wrong authenticated Account never starts a scan.
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            None,
            &mut located,
            &session,
        )
        .await
        .is_err()
    );
    let mut other_session = session.clone();
    other_session.session_grant.as_mut().unwrap().account_id = governor.pcr.history.account.clone();
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &other_session,
        )
        .await
        .is_err()
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let scan = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::After(None),
        limit: 128,
    };
    let soland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("Gov accepted member grants its routed Station the opening floor");
    };
    page.validate_for_request(&scan).unwrap();
    let full = page
        .committed_events
        .iter()
        .find(|item| item.commit().commit_id == commit.commit_id)
        .unwrap();
    assert!(
        matches!(full, arkret_wire::CommittedEventView::Full(view) if view.event == *event && view.commit == *commit)
    );
    let archived = source
        .human_signer_fact(event, commit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        page.producer_signer_facts
            .iter()
            .find(|f| f.target.commit_id == commit.commit_id)
            .unwrap()
            .producer_signer_fact,
        archived
    );
    let mut withheld = page.clone();
    withheld.committed_events = vec![arkret_wire::CommittedEventView::Withheld(
        arkret_wire::CommittedEventWithheldView {
            commit: commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        },
    )];
    withheld.producer_signer_facts.clear();
    let reply = tokio::spawn(tcp_scan(
        listener.clone(),
        withheld,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
        .is_err()
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let mut missing_fact = page.clone();
    missing_fact.producer_signer_facts.clear();
    let reply = tokio::spawn(tcp_scan(
        listener.clone(),
        missing_fact,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
        .is_err()
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let response_listener = listener.clone();
    let response_governor = governor_state.clone();
    let response_pool = governor_pool.clone();
    let response_account = human.pcr.history.account.clone();
    let response_commit = commit.clone();
    let history_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let response_stop = history_stop.clone();
    let reply = tokio::spawn(async move {
        assert_eq!(
            tcp_scan(
                response_listener.clone(),
                page,
                scan,
                response_account.clone(),
                response_governor.service_core_id()
            )
            .await,
            1
        );
        assert_eq!(
            tcp_opening_bootstrap(
                response_listener,
                response_governor,
                response_pool,
                response_account,
                response_commit,
                response_stop,
            )
            .await,
            1
        );
        2
    });
    let original = super::super::replica_anchor::ensure_forwarded_target(
        &origin,
        &governor_state.service_core_id(),
        event,
        Some(commit),
        &mut located,
        &session,
    )
    .await;
    history_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let original = original.unwrap().unwrap();
    assert_eq!(original, *commit);
    assert_eq!(reply.await.unwrap(), 2);
    let held = store
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.event, *event);
    assert_eq!(held.commit, *commit);
    assert_eq!(
        store.human_signer_fact(event, commit).await.unwrap(),
        Some(archived)
    );
    let anchor = store
        .replica_anchor_for_stream(&commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert!(anchor.anchored_head.is_some());
    assert_eq!(anchor.join_commit, *commit);
    let before_replay = opening_footprint(&origin_pool, realm).await;
    assert_eq!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
        .unwrap(),
        Some(commit.clone())
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, before_replay);
}
#[tokio::test]
async fn accepted_own_leave_returns_original_bound_result_after_terminal_membership_and_keeps_reads_closed()
 {
    let listener = registered_tls_peer();
    let base = format!("https://{}/", listener.listener.local_addr().unwrap());
    let (governor_state, governor_pool, _governor_lease) = station_with_webvh(base.clone());
    let (origin, origin_pool, _origin_lease) =
        station_with_webvh("https://forward-recovery-origin.internal/".into());
    let mut governor =
        historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
    // The existing closed bootstrap facet must explicitly authorize the Origin
    // to receive plaintext. Membership/action grants alone grant no such right.
    // Author this before the unit is accepted; never patch accepted state.
    let disclosure_index = governor
        .unit
        .transactions
        .iter()
        .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
        .unwrap();
    assert!(disclosure_index > 0);
    assert_eq!(
        governor
            .unit
            .transactions
            .iter()
            .filter(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
            .count(),
        1
    );
    let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(
            serde_json::to_value(&governor.unit.transactions[disclosure_index].event.payload).unwrap(),
        ).unwrap();
    assert_eq!(disclosure.services.len(), 1);
    assert_eq!(
        disclosure.services[0].service_id,
        governor_state.service_core_id()
    );
    assert_ne!(governor_state.service_core_id(), origin.service_core_id());
    disclosure.services.push(
        serde_json::from_value(serde_json::json!({
            "service_id":origin.service_core_id(), "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["accepted original recovery fixture"],
            "visibility":"private_plaintext"
        }))
        .unwrap(),
    );
    let disclosure_event = historical_human::signed_ordinary_event(
        &governor,
        &governor.unit.transactions[disclosure_index - 1],
        EventKind::RealmPlaintextVisibleServices,
        disclosure.to_value().unwrap(),
        governor.unit.transactions[disclosure_index]
            .commit
            .committed_at,
    );
    governor.unit.transactions[disclosure_index].event = disclosure_event;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let mut previous_commit = None;
    for (index, transaction) in governor.unit.transactions.iter_mut().enumerate() {
        transaction.commit.event_ref = transaction.event.event_id.clone();
        transaction.producer_signer_fact = source
            .prepare_human_signer_fact(&transaction.event, transaction.commit.committed_at)
            .await
            .unwrap();
        assert!(transaction.producer_signer_fact.is_some());
        transaction.commit.producer_signer_fact_digest = transaction
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        transaction.commit.previous_commit_ref = previous_commit;
        seal_service_commit(&mut transaction.commit, &governor_state);
        previous_commit = Some(transaction.commit.commit_id.clone());
        governor.unit.submission.events[index] =
            EventAdmissionSubmission::new(transaction.event.clone());
    }
    governor.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(governor.unit.submission.clone()),
    )
    .unwrap();
    governor.admit(&governor_pool).await;
    assert_eq!(
        source
            .accepted_plaintext_visible_services(&governor.unit.transactions[0].event.realm_id,)
            .await
            .unwrap(),
        Some(disclosure)
    );
    let human = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
    let actor = ActorId::account(human.pcr.history.account.clone());
    let previous = governor.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + Duration::seconds(1);
    let owner = ActorId::account(governor.pcr.history.account.clone());
    let strand_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::StrandCreate,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1", "realm_id":previous.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"forward recovery fixture discussion"}, "state":"active",
            "created_by":owner, "created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let mut strand = historical_human::request_for_event(&governor, previous, strand_event, at);
    seal_service_commit(&mut strand.authority_commit.commit, &governor_state);
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    // Membership is not an action grant. Read the actual accepted root cut,
    // then admit the owner's narrow Grant before the foreign member joins. The
    // Grant grants no membership; MessageCreate still runs after the real join.
    #[derive(diesel::QueryableByName)]
    struct RootCut {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        controller_actor_id: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Text)]
        authority_event_ref: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        authority_generation: i64,
    }
    use diesel_async::RunQueryDsl as _;
    let root_cut = {
        let mut conn = governor_pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT controller_actor_id, authority_event_ref, authority_generation \
             FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(strand.authority_commit.event.realm_id.as_str())
        .get_result::<RootCut>(&mut *conn)
        .await
        .unwrap()
    };
    assert_eq!(
        serde_json::from_value::<ActorId>(root_cut.controller_actor_id).unwrap(),
        owner
    );
    let root_generation = u64::try_from(root_cut.authority_generation).unwrap();
    let previous = &strand.authority_commit;
    let grant_at = previous.commit.committed_at + Duration::seconds(1);
    let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::json!({"grant": {
            "schema":"ak.schema.capability.v1",
            "realm_id":previous.event.realm_id,
            "issuer_id":owner,
            "subject":actor,
            "actions":["ak.message.create"],
            "resources":[{"kind":"realm","realm_id":previous.event.realm_id}],
            "issuer_authority_refs":[{
                "kind":"realm_root","realm_id":previous.event.realm_id,
                "authority_event_ref":root_cut.authority_event_ref,
                "authority_generation":root_generation
            }],
            "issued_at":arkret_canonical::format_timestamp_canonical(grant_at)
        }}))
        .unwrap();
    let grant_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::CapabilityGrant,
        serde_json::to_value(grant_payload).unwrap(),
        grant_at,
    );
    let mut grant = historical_human::request_for_event(&governor, previous, grant_event, grant_at);
    // This is a fresh PG source candidate, not a cached authorizing capability.
    // The UOW independently prepares and compares it under its admission locks.
    let grant_fact = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    }
    .prepare_human_signer_fact(&grant.authority_commit.event, grant_at)
    .await
    .unwrap()
    .unwrap();
    grant.authority_commit.commit.producer_signer_fact_digest = Some(grant_fact.digest().unwrap());
    grant.authority_commit.producer_signer_fact = Some(grant_fact);
    seal_service_commit(&mut grant.authority_commit.commit, &governor_state);
    uow.commit_event(grant.clone()).await.unwrap();
    let previous = &grant.authority_commit;
    let mut join = foreign_request(&origin, &human, &governor, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"real forward recovery membership"})).await;
    seal_service_commit(&mut join.authority_commit.commit, &governor_state);
    uow.commit_event(join.clone()).await.unwrap();
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    let realm = &join.authority_commit.event.realm_id;
    let event = &join.authority_commit.event;
    let commit = &join.authority_commit.commit;
    let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
    let session = authenticated_context(&origin_pool, &human).await;
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            &governor_state,
        )
        .await
        .unwrap();
    let boundary = route.method_history_evidence.boundary();
    let description = VerifiedServiceDescribeMetadata {
        service_id: governor_state.service_core_id(),
        service_kind: "station".into(),
        service_resolution: ResolutionCommitment {
            did: governor_state.service_did(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
        },
        http_json_base_url: base,
        trust_domain: governor_state.config().trust_domain.clone(),
        protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
        supported_operation_bundles: vec![
            arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                .unwrap()
                .operation_bundle_id
                .into(),
        ],
    };
    origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            evidence: route,
            description,
        },
    )));
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([0x71; 32])).unwrap();
    let bundle = crate::routing::realm_join::local_authority_bundle(&governor_state, realm, &nonce)
        .await
        .unwrap();
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for sig in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
        &commit.signature,
    ] {
        keys.insert_at(
            &sig.verification_method,
            sig.created_at,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        );
    }
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(Utc::now(), nonce),
        &keys,
    )
    .unwrap();
    let mut located = crate::routing::realm_join::LocatedRealmAuthority {
        bundle,
        authority,
        keys,
    };
    store
        .record_remote_authority(&located.current_authority(), &origin.service_core_id())
        .await
        .unwrap();
    store.queue_event(event, commit.committed_at).await.unwrap();
    let intent = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.clone()));
    store
        .retain_forwarded_submission(event, &intent, commit.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(event, commit, commit.committed_at)
        .await
        .unwrap();
    assert!(
        store
            .replica_anchor_for_stream(&commit.stream_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let no_write = opening_footprint(&origin_pool, realm).await;
    // A bare original or the wrong authenticated Account never starts a scan.
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            None,
            &mut located,
            &session,
        )
        .await
        .is_err()
    );
    let mut other_session = session.clone();
    other_session.session_grant.as_mut().unwrap().account_id = governor.pcr.history.account.clone();
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &other_session,
        )
        .await
        .is_err()
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let scan = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::After(None),
        limit: 128,
    };
    let soland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("Gov accepted member grants its routed Station the opening floor");
    };
    page.validate_for_request(&scan).unwrap();
    let full = page
        .committed_events
        .iter()
        .find(|item| item.commit().commit_id == commit.commit_id)
        .unwrap();
    assert!(
        matches!(full, arkret_wire::CommittedEventView::Full(view) if view.event == *event && view.commit == *commit)
    );
    let archived = source
        .human_signer_fact(event, commit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        page.producer_signer_facts
            .iter()
            .find(|f| f.target.commit_id == commit.commit_id)
            .unwrap()
            .producer_signer_fact,
        archived
    );
    let mut withheld = page.clone();
    withheld.committed_events = vec![arkret_wire::CommittedEventView::Withheld(
        arkret_wire::CommittedEventWithheldView {
            commit: commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        },
    )];
    withheld.producer_signer_facts.clear();
    let reply = tokio::spawn(tcp_scan(
        listener.clone(),
        withheld,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
        .is_err()
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let mut missing_fact = page.clone();
    missing_fact.producer_signer_facts.clear();
    let reply = tokio::spawn(tcp_scan(
        listener.clone(),
        missing_fact,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
        .is_err()
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let response_listener = listener.clone();
    let response_governor = governor_state.clone();
    let response_pool = governor_pool.clone();
    let response_account = human.pcr.history.account.clone();
    let response_commit = commit.clone();
    let history_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let response_stop = history_stop.clone();
    let reply = tokio::spawn(async move {
        assert_eq!(
            tcp_scan(
                response_listener.clone(),
                page,
                scan,
                response_account.clone(),
                response_governor.service_core_id()
            )
            .await,
            1
        );
        assert_eq!(
            tcp_opening_bootstrap(
                response_listener,
                response_governor,
                response_pool,
                response_account,
                response_commit,
                response_stop,
            )
            .await,
            1
        );
        2
    });
    let original = super::super::replica_anchor::ensure_forwarded_target(
        &origin,
        &governor_state.service_core_id(),
        event,
        Some(commit),
        &mut located,
        &session,
    )
    .await;
    history_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let original = original.unwrap().unwrap();
    assert_eq!(original, *commit);
    assert_eq!(reply.await.unwrap(), 2);
    let held = store
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.event, *event);
    assert_eq!(held.commit, *commit);
    assert_eq!(
        store.human_signer_fact(event, commit).await.unwrap(),
        Some(archived)
    );
    let anchor = store
        .replica_anchor_for_stream(&commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert!(anchor.anchored_head.is_some());
    assert_eq!(anchor.join_commit, *commit);
    let before_replay = opening_footprint(&origin_pool, realm).await;
    assert_eq!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
        .unwrap(),
        Some(commit.clone())
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, before_replay);
    // Author, sign and admit the real own leave on Gov; Origin keeps its frozen
    // request and the authentic original acceptance without yet installing it.
    let mut leave = foreign_request(&origin, &human, &governor, &join.authority_commit,
        EventKind::MemberState, serde_json::json!({"realm_id":realm,"member_id":actor,"membership":"leave","reason":"original own leave recovery"})).await;
    seal_service_commit(&mut leave.authority_commit.commit, &governor_state);
    uow.commit_event(leave.clone()).await.unwrap();
    let le = &leave.authority_commit.event;
    let lc = &leave.authority_commit.commit;
    let original_fact = source.human_signer_fact(le, lc).await.unwrap().unwrap();
    assert_eq!(
        Some(original_fact.clone()),
        leave.authority_commit.producer_signer_fact
    );
    store.queue_event(le, lc.committed_at).await.unwrap();
    let intent = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(le.clone()));
    store
        .retain_forwarded_submission(le, &intent, lc.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(le, lc, lc.committed_at)
        .await
        .unwrap();
    let scan = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: lc.stream_ref.clone(),
        direction: StreamScanDirection::After(Some(commit.stream_position)),
        limit: 128,
    };
    let soland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("terminating peer interval unavailable")
    };
    assert_eq!(page.committed_events.len(), 1);
    let arkret_wire::CommittedEventView::Full(full) = &page.committed_events[0] else {
        panic!("terminating original is withheld")
    };
    assert_eq!(full.event, *le);
    assert_eq!(full.commit, *lc);
    assert_eq!(page.producer_signer_facts.len(), 1);
    assert_eq!(
        page.producer_signer_facts[0].producer_signer_fact,
        original_fact
    );
    let (rl, rg, rp, ra) = (
        listener.clone(),
        governor_state.clone(),
        governor_pool.clone(),
        human.pcr.history.account.clone(),
    );
    let reply = tokio::spawn(async move {
        assert_eq!(
            tcp_scan(rl.clone(), page, scan, ra, rg.service_core_id()).await,
            1
        );
        tcp_original_service_history_once(rl, rg, rp).await
    });
    assert_eq!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            le,
            Some(lc),
            &mut located,
            &session
        )
        .await
        .unwrap(),
        Some(lc.clone())
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(
        store
            .committed_event(&le.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        *lc
    );
    assert_eq!(
        store.human_signer_fact(le, lc).await.unwrap(),
        Some(original_fact.clone())
    );
    assert!(
        !store
            .accepted_current_member_joined(realm, &actor)
            .await
            .unwrap()
    );
    assert!(
        store
            .accepted_own_leave_bound_result(
                le,
                lc,
                &human.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap()
    );
    let read = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: lc.stream_ref.clone(),
        direction: StreamScanDirection::Before(Some(lc.stream_position + 1)),
        limit: 1,
    };
    assert!(matches!(
        store
            .scan_stream_for_account(&read, &human.pcr.history.account, &origin.service_core_id())
            .await
            .unwrap(),
        soland_storage::AccountStreamScan::NotAuthorized
    ));
    // The governor has a real later Full, but the departed peer's original
    // interval ends at the leave, including its terminal node only.
    let future_at = lc.committed_at + Duration::seconds(1);
    let future_event = historical_human::signed_ordinary_event(
        &governor,
        &leave.authority_commit,
        EventKind::MessageCreate,
        serde_json::json!({
            "strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id),
            "track_name":"discussion","content":{"kind":"ak.content.text","body":"future owner original","format":"plain"}
        }),
        future_at,
    );
    let mut future = historical_human::request_for_event(
        &governor,
        &leave.authority_commit,
        future_event,
        future_at,
    );
    let future_fact = source
        .prepare_human_signer_fact(&future.authority_commit.event, future_at)
        .await
        .unwrap()
        .unwrap();
    future.authority_commit.commit.producer_signer_fact_digest =
        Some(future_fact.digest().unwrap());
    future.authority_commit.producer_signer_fact = Some(future_fact);
    seal_service_commit(&mut future.authority_commit.commit, &governor_state);
    uow.commit_event(future.clone()).await.unwrap();
    let future_read = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: lc.stream_ref.clone(),
        direction: StreamScanDirection::After(Some(lc.stream_position)),
        limit: 1,
    };
    let soland_storage::PeerStreamScan::Page(no_future) = source
        .scan_stream_for_peer(
            &future_read,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("terminal interval read unavailable")
    };
    assert!(no_future.committed_events.is_empty());
    assert!(
        store
            .committed_event(&future.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let before = opening_footprint(&origin_pool, realm).await;
    assert_eq!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            le,
            Some(lc),
            &mut located,
            &session
        )
        .await
        .unwrap(),
        Some(lc.clone())
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, before);
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            le,
            None,
            &mut located,
            &session
        )
        .await
        .is_err()
    );
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            le,
            Some(lc),
            &mut located,
            &other_session
        )
        .await
        .is_err()
    );
    assert!(
        !store
            .accepted_own_leave_bound_result(
                le,
                lc,
                &governor.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap()
    );
    let mismatch = historical_human::signed_ordinary_event(
        &human,
        &join.authority_commit,
        EventKind::MemberState,
        serde_json::json!({"realm_id":realm,"member_id":owner,"membership":"leave"}),
        lc.committed_at,
    );
    assert!(
        !store
            .accepted_own_leave_bound_result(
                &mismatch,
                lc,
                &human.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap()
    );
    // Removing an original fact is a negative only: no fallback to today's key
    // and no eligibility from a bare accepted witness.
    {
        let mut conn = origin_pool.get().await.unwrap();
        diesel::sql_query(
            "UPDATE agent_producer_signer_keys SET human_source_fact=NULL WHERE commit_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(lc.commit_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    assert!(
        !store
            .accepted_own_leave_bound_result(
                le,
                lc,
                &human.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap()
    );
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            le,
            Some(lc),
            &mut located,
            &session
        )
        .await
        .is_err()
    );
    {
        let mut conn = origin_pool.get().await.unwrap();
        diesel::sql_query(
            "UPDATE agent_producer_signer_keys SET human_source_fact=$2 WHERE commit_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(lc.commit_id.as_str())
        .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&original_fact).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    assert_eq!(opening_footprint(&origin_pool, realm).await, before);
    // Corrupt durable coordinates only as a negative, then restore the original.
    {
        let mut conn = origin_pool.get().await.unwrap();
        diesel::sql_query("UPDATE replica_stream_anchors SET join_commit_id=$2 WHERE realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .bind::<diesel::sql_types::Text, _>(lc.commit_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    assert!(
        !store
            .accepted_own_leave_bound_result(
                le,
                lc,
                &human.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap()
    );
    assert!(
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            le,
            Some(lc),
            &mut located,
            &session
        )
        .await
        .is_err()
    );
    {
        let mut conn = origin_pool.get().await.unwrap();
        diesel::sql_query("UPDATE replica_stream_anchors SET join_commit_id=$2 WHERE realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .bind::<diesel::sql_types::Text, _>(commit.commit_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        diesel::sql_query("UPDATE member_state_current_results SET current_commit_id=$3,current_stream_position=$4 WHERE realm_id=$1 AND member_id=$2")
          .bind::<diesel::sql_types::Text,_>(realm.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).bind::<diesel::sql_types::Text,_>(commit.commit_id.as_str()).bind::<diesel::sql_types::BigInt,_>(i64::try_from(commit.stream_position).unwrap()).execute(&mut *conn).await.unwrap();
    }
    assert!(
        !store
            .accepted_own_leave_bound_result(
                le,
                lc,
                &human.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap()
    );
    {
        let mut conn = origin_pool.get().await.unwrap();
        diesel::sql_query("UPDATE member_state_current_results SET current_commit_id=$3,current_stream_position=$4 WHERE realm_id=$1 AND member_id=$2")
          .bind::<diesel::sql_types::Text,_>(realm.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).bind::<diesel::sql_types::Text,_>(lc.commit_id.as_str()).bind::<diesel::sql_types::BigInt,_>(i64::try_from(lc.stream_position).unwrap()).execute(&mut *conn).await.unwrap();
    }
    assert_eq!(opening_footprint(&origin_pool, realm).await, before);
    assert!(matches!(
        store
            .scan_stream_for_account(&read, &human.pcr.history.account, &origin.service_core_id())
            .await
            .unwrap(),
        soland_storage::AccountStreamScan::NotAuthorized
    ));
}

async fn tcp_opening_bootstrap(
    listener: Arc<RegisteredTlsPeer>,
    governor: AppState,
    pool: PgPool,
    from: AccountId,
    expected: arkret_wire::RealmCommit,
    history_stop: Arc<std::sync::atomic::AtomicBool>,
) -> usize {
    use soland_storage::DeliveryPolicyStoreRegistry as _;
    let records = PgPersistenceStore::new(pool.clone())
        .webvh()
        .list_log_events(governor.service_did().as_str())
        .await
        .unwrap();
    assert!(!records.is_empty());
    let mut log = Vec::new();
    for record in records {
        log.extend(arkret_canonical::canonical_json_bytes(&record.operation).unwrap());
        log.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &governor.service_did(),
        &log,
        None,
    )
    .unwrap();
    let document = arkret_canonical::canonical_json_bytes(&verified.log.head_state).unwrap();
    let log_url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::log_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    let doc_url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::document_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    let base = reqwest::Url::parse(&governor.config().public_base_url).unwrap();
    assert_eq!(log_url.origin(), base.origin());
    assert_eq!(doc_url.origin(), base.origin());
    tokio::task::spawn_blocking(move || {
    let (stream, _) = listener.listener.accept().unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    let mut stream = rustls::StreamOwned::new(
        rustls::ServerConnection::new(listener.tls.clone()).unwrap(), stream,
    );
    let mut bytes = Vec::new();
    let mut buf = [0u8; 2048];
    let end = loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        assert!(bytes.len() < 1024 * 1024);
        if let Some(p) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(header.starts_with("POST /_arkret/peer/realm-joins/bootstrap HTTP/1.1"));
    let fields = header
        .lines()
        .filter_map(|v| {
            v.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        fields.get("source-service-id"),
        Some(&from.station_id.to_string())
    );
    assert_eq!(fields.get("destination-service-id"), Some(&governor.service_core_id().to_string()));
    assert!(
        fields.contains_key("signature-input")
            && fields.contains_key("signature")
            && fields.contains_key("content-digest")
    );
    let length = fields["content-length"].parse::<usize>().unwrap();
    assert!(length < 1024 * 1024);
    while bytes.len() < end + length {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    let actual: arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapRequestBody =
        serde_json::from_slice(&bytes[end..end + length]).unwrap();
    assert_eq!(actual.realm_id, expected.realm_id);
    assert_eq!(actual.member_account_id, from);
    assert_eq!(actual.membership_commit_id, expected.commit_id);
    let outcome = tokio::runtime::Handle::current().block_on(async {
        let store = PgAuthorityCommitStore { pool };
        let material = store.member_station_bootstrap_material(
            &actual.realm_id, &actual.member_account_id, &actual.membership_commit_id,
        ).await.unwrap().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
        let snapshot = soland_services::authority_commit::build_signed_realm_state_snapshot(
            &material, governor.service_verification_method("notary-key").unwrap(),
            &key, Utc::now(),
        ).unwrap();
        let nonce = crate::routing::realm_join::nonce_for_request(&actual.request_id).unwrap();
        let authority_bundle = crate::routing::realm_join::local_authority_bundle(
            &governor, &actual.realm_id, &nonce,
        ).await.unwrap();
        arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapOutcome {
            request_id: actual.request_id, visible_stream_heads: snapshot.visible_stream_heads.clone(), snapshot, authority_bundle,
        }
    });
    let body = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    assert!(!stream.conn.is_handshaking());
    drop(stream);
    listener.listener.set_nonblocking(true).unwrap();
    let mut history_requests = 0;
    while !history_stop.load(std::sync::atomic::Ordering::SeqCst) {
        let socket = match listener.listener.accept() {
            Ok((socket, _)) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Err(error) => panic!("history listener: {error}"),
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        socket.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(listener.tls.clone()).unwrap(), socket);
        let mut request = Vec::new();
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
            assert!(request.len() < 1024 * 1024);
            if request.windows(4).any(|v| v == b"\r\n\r\n") { break; }
        }
        let request = std::str::from_utf8(&request).unwrap();
        let line = request.lines().next().unwrap();
        let body = if line == format!("GET {} HTTP/1.1", log_url.path()) {
            &log
        } else {
            assert_eq!(line, format!("GET {} HTTP/1.1", doc_url.path()));
            &document
        };
        let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
        assert!(!stream.conn.is_handshaking());
        history_requests += 1;
    }
    assert!(history_requests > 0);
    listener.listener.set_nonblocking(false).unwrap();
    1
    }).await.unwrap()
}

async fn opening_footprint(pool: &PgPool, realm: &arkret_wire::RealmId) -> (i64, i64, i64, i64) {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Counts {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        events: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        commits: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        anchors: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        facts: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let c = diesel::sql_query(
        "SELECT (SELECT count(*) FROM canonical_events WHERE realm_id=$1 AND state='committed') AS events, \
         (SELECT count(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
         (SELECT count(*) FROM replica_stream_anchors WHERE realm_id=$1) AS anchors, \
         (SELECT count(*) FROM agent_producer_signer_keys f JOIN realm_commits c ON c.commit_id=f.commit_id \
          WHERE c.realm_id=$1 AND f.human_source_fact IS NOT NULL) AS facts"
    ).bind::<diesel::sql_types::Text,_>(realm.as_str())
     .get_result::<Counts>(&mut *conn).await.unwrap();
    (c.events, c.commits, c.anchors, c.facts)
}

/// Serve the newly encountered signature's genuine method-native history.
/// No caller-provided key directory replaces the production resolver here.
async fn tcp_original_service_history_once(
    listener: Arc<RegisteredTlsPeer>,
    governor: AppState,
    pool: PgPool,
) -> usize {
    use soland_storage::DeliveryPolicyStoreRegistry as _;
    let records = PgPersistenceStore::new(pool)
        .webvh()
        .list_log_events(governor.service_did().as_str())
        .await
        .unwrap();
    assert!(!records.is_empty());
    let mut log = Vec::new();
    for record in records {
        log.extend(arkret_canonical::canonical_json_bytes(&record.operation).unwrap());
        log.push(b'\n');
    }
    arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &governor.service_did(),
        &log,
        None,
    )
    .unwrap();
    let url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::log_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        url.origin(),
        reqwest::Url::parse(&governor.config().public_base_url)
            .unwrap()
            .origin()
    );
    tokio::task::spawn_blocking(move || {
        let (socket,_)=listener.listener.accept().unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        socket.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut stream=rustls::StreamOwned::new(rustls::ServerConnection::new(listener.tls.clone()).unwrap(),socket);
        let mut request=Vec::new();let mut buf=[0u8;2048];
        loop {let n=stream.read(&mut buf).unwrap();assert!(n>0);request.extend_from_slice(&buf[..n]);assert!(request.len()<1024*1024);if request.windows(4).any(|v|v==b"\r\n\r\n"){break;}}
        assert_eq!(std::str::from_utf8(&request).unwrap().lines().next().unwrap(),format!("GET {} HTTP/1.1",url.path()));
        let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",log.len());
        stream.write_all(header.as_bytes()).unwrap();stream.write_all(&log).unwrap();stream.flush().unwrap();
        assert!(!stream.conn.is_handshaking());1
    }).await.unwrap()
}
