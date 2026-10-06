//! Real PG source and a registered TCP PeerScan execute the production recovery
//! helper. The session is the already-authenticated state-port context; this
//! does not claim a live OIDC/DPoP middleware or subprocess-crash test.
#[path = "../../../storage-postgres/tests/support/historical_human.rs"]
mod historical_human;

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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

async fn tcp_scan(
    listener: Arc<tokio::net::TcpListener>,
    page: PeerStreamScanOutcome,
    expected: StreamScanRequest,
    from: AccountId,
    to: DidCoreId,
) -> usize {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let mut buf = [0u8; 2048];
    let end = loop {
        let n = stream.read(&mut buf).await.unwrap();
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
        let n = stream.read(&mut buf).await.unwrap();
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
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    1
}

#[tokio::test]
async fn accepted_forward_witness_reopens_then_executes_registered_prefix_without_new_submission() {
    let listener = Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let (governor_state, governor_pool, _governor_lease) = station(base.clone());
    let (origin, origin_pool, _origin_lease) =
        station("https://forward-recovery-origin.internal/".into());
    let governor =
        historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
    governor.admit(&governor_pool).await;
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
    let previous = &strand.authority_commit;
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
