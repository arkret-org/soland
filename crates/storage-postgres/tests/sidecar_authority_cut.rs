//! Native Sidecar cut preserves exact controller identity and parent authority.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
#[path = "support/sidecar_agent.rs"]
mod sidecar_agent;

use arkret_wire::{AccountId, EventKind, SidecarId};
use soland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use soland_storage_postgres::sidecar_authority_cut::read;
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPersistenceStore,
};

async fn accepted_controller(
    pool: &soland_storage_postgres::PgPool,
    station_did: arkret_wire::Did,
) -> pcr_genesis::PcrGenesisFixture {
    use diesel_async::RunQueryDsl;
    let principal = pcr_genesis::PcrGenesisFixture::new(station_did);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<diesel::sql_types::Text, _>(principal.history.account.station_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    principal
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    principal
}

#[tokio::test]
async fn sidecar_cut_requires_exact_controller_and_current_parent_join() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = ordinary_realm::station();
    let station_did = device_authorization_history::did_web_station(&station);
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = principal.history.account.clone();
    let realm = ordinary_realm::bootstrap_unit_for_account(
        "sidecar-participant-cut",
        &controller,
        &station_did,
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let last = realm.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        last,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        last.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(create.clone()).await.unwrap();
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let cut = read(&pool, realm_id, &sidecar, &controller)
        .await
        .unwrap()
        .unwrap();
    assert!(cut.desired_agent_ids.is_empty());
    assert_eq!(cut.authority_stream_head.len(), 2);
    assert!(
        cut.authority_stream_head
            .contains(&create.authority_commit.event.event_id)
    );
    assert_eq!(cut.visible_stream_heads.len(), 1);
    assert_eq!(
        cut.visible_stream_heads[0].commit_id,
        create.authority_commit.commit.commit_id
    );
    assert_eq!(
        cut.participant_authority_digest,
        arkret_models_collaboration::agent_sidecar::sidecar_participant_authority_digest(
            &sidecar,
            realm_id,
            &controller,
            &[]
        )
        .unwrap()
    );
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm_id, &controller)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(
        |row| matches!(row, arkret_wire::TypedCurrentResult::Value {
        selector: arkret_wire::CurrentSelector::Sidecar { sidecar_id }, ..
    } if sidecar_id == &sidecar)
    ));
    let another_station = AccountId::new(
        controller.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:foreign-controller.example").unwrap(),
    );
    assert!(
        read(&pool, realm_id, &sidecar, &another_station)
            .await
            .unwrap()
            .is_none()
    );
    let unknown = SidecarId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [113; 32],
    ));
    assert!(
        read(&pool, realm_id, &unknown, &controller)
            .await
            .unwrap()
            .is_none()
    );
    let leave = ordinary_realm::next_request(
        &create.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"realm_id":realm_id,"member_id":arkret_wire::ActorId::account(controller.clone()),
            "membership":"leave","reason":"Sidecar authority current matrix"}),
        create.authority_commit.commit.committed_at,
    );
    uow.commit_event(leave).await.unwrap();
    assert!(
        read(&pool, realm_id, &sidecar, &controller)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn desired_agents_require_owned_active_key_and_exact_realm_membership() {
    use soland_storage::{ActorProfileStore, AgentControlAdmissionWrite};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = ordinary_realm::station();
    let station_did = device_authorization_history::did_web_station(&station);
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_for_account(
        "sidecar-agent-matrix",
        controller,
        &station_did,
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        parent,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(create.clone()).await.unwrap();
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let (agent, genesis, provision_ref) = provision_owned_agent(&pool, &principal).await;
    let no_key = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(no_key.desired_agent_ids.is_empty());
    assert!(no_key.authority_stream_head.contains(&provision_ref));
    let agent_did = arkret_wire::Did::new(format!(
        "did:{}",
        agent
            .principal_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap()
    ))
    .unwrap();
    let delegation = format!("{agent_did}#managed-controller");
    let key_event = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        sidecar_agent::agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            genesis.commit.committed_at,
        ),
        genesis.commit.committed_at,
    );
    let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station_did, 1);
    let profiles = soland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    profiles
        .admit_agent_control_event(AgentControlAdmissionWrite {
            commit: soland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: key_event.clone(),
                commit: key_commit.clone(),
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: key_commit.committed_at,
        })
        .await
        .unwrap();
    let not_joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(not_joined.desired_agent_ids.is_empty());
    assert!(
        not_joined
            .authority_stream_head
            .contains(&key_event.event_id)
    );
    let join = ordinary_realm::next_request(
        &create.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id": arkret_wire::ActorId::account(agent.clone()), "membership":"join",
            "agent_controller_binding": {"controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}}),
        key_commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    uow.commit_event(join.clone()).await.unwrap();
    let joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.desired_agent_ids, vec![agent.principal_id.clone()]);
    assert!(
        joined
            .authority_stream_head
            .contains(&join.authority_commit.event.event_id)
    );
    assert_ne!(
        joined.participant_authority_digest,
        not_joined.participant_authority_digest
    );
    let controller_leave = ordinary_realm::next_request(
        &join.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),"membership":"leave"}),
        join.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    uow.commit_event(controller_leave.clone()).await.unwrap();
    assert!(
        read(&pool, realm_id, &sidecar, controller)
            .await
            .unwrap()
            .is_none()
    );
    let controller_rejoin = ordinary_realm::next_request(
        &controller_leave.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),"membership":"join"}),
        controller_leave.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    uow.commit_event(controller_rejoin.clone()).await.unwrap();
    let stale_generation = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(stale_generation.desired_agent_ids.is_empty());
    assert!(
        stale_generation
            .authority_stream_head
            .contains(&controller_rejoin.authority_commit.event.event_id)
    );
    assert!(
        stale_generation
            .authority_stream_head
            .contains(&join.authority_commit.event.event_id)
    );
    let leave = ordinary_realm::next_request_for_actor(
        &controller_rejoin.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(agent.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"leave"}),
        controller_rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    uow.commit_event(leave.clone()).await.unwrap();
    let left = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(left.desired_agent_ids.is_empty());
    assert!(
        left.authority_stream_head
            .contains(&leave.authority_commit.event.event_id)
    );
    assert_eq!(
        left.participant_authority_digest,
        not_joined.participant_authority_digest
    );
    let fresh_join = ordinary_realm::next_request(
        &leave.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":controller_rejoin.authority_commit.event.event_id}}),
        leave.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    uow.commit_event(fresh_join.clone()).await.unwrap();
    let fresh = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh.desired_agent_ids, vec![agent.principal_id]);
    assert!(
        fresh
            .authority_stream_head
            .contains(&fresh_join.authority_commit.event.event_id)
    );
}

#[tokio::test]
async fn sidecar_snapshot_lists_and_scans_keep_private_stream_coordinates() {
    use arkret_wire::{ActorId, CommitStreamRef, StreamScanDirection, StreamScanRequest};
    use soland_storage::{AccountRealmStreamList, AccountStreamScan};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = ordinary_realm::station();
    let did = device_authorization_history::did_web_station(&station);
    let principal = accepted_controller(&pool, did.clone()).await;
    let controller = &principal.history.account;
    let unit =
        ordinary_realm::bootstrap_unit_for_account("sidecar-stream-disclosure", controller, &did);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = unit.transactions.last().unwrap();
    let realm = parent.event.realm_id.clone();
    let actor = ActorId::account(controller.clone());
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = ordinary_realm::next_request(
        parent,
        EventKind::StrandCreate,
        &controller.principal_id,
        serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Sidecar source"},
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(parent.commit.committed_at)}}),
        parent.commit.committed_at,
    );
    uow.commit_event(strand.clone()).await.unwrap();
    let source = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let create = ordinary_realm::next_request(
        &strand.authority_commit,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    uow.commit_event(create.clone()).await.unwrap();
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let stream = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let mut attach_event = ordinary_realm::event_for_actor(
        EventKind::SidecarContextAttach,
        arkret_wire::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        },
        actor.clone(),
        serde_json::json!({"sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":source},"version":1}),
        parent.commit.committed_at,
    );
    attach_event.semantic_refs = vec![arkret_wire::SemanticRef::new(
        create.authority_commit.event.event_id.to_string(),
        "after",
    )];
    ordinary_realm::reseal(&mut attach_event);
    let mut attach = ordinary_realm::request_for_event(
        &create.authority_commit,
        attach_event,
        parent.commit.committed_at,
    );
    attach.authority_commit.commit.stream_ref = stream.clone();
    attach.authority_commit.commit.stream_position = 0;
    attach.authority_commit.commit.previous_commit_ref = None;
    uow.commit_event(attach.clone()).await.unwrap();
    let foreign = AccountId::new(
        controller.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:sidecar-foreign.example").unwrap(),
    );
    let mut join = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::MemberState,
        ActorId::account(foreign.clone()),
        serde_json::json!({"member_id":ActorId::account(foreign.clone()),"membership":"join"}),
        parent.commit.committed_at,
    );
    join.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        join.authority_commit.event.clone(),
    ));
    uow.commit_event(join.clone()).await.unwrap();
    let snapshot = store
        .realm_state_snapshot_material_for_account(&realm, controller)
        .await
        .unwrap()
        .unwrap();
    let foreign_snapshot = store
        .realm_state_snapshot_material_for_account(&realm, &foreign)
        .await
        .unwrap()
        .unwrap();
    assert!(
        snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stream
                && head.stream_position == 0
                && head.commit_id == attach.authority_commit.commit.commit_id)
    );
    assert!(
        snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref == stream && floor.oldest_position == 0)
    );
    assert!(snapshot.current_state_entries.iter().any(|row| matches!(row, arkret_wire::TypedCurrentResult::Value {selector:arkret_wire::CurrentSelector::SidecarContext {sidecar_id,..},source_stream_ref,revision,..} if sidecar_id == &sidecar && source_stream_ref == &stream && revision.stream_position == 0)));
    assert!(
        !foreign_snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stream)
    );
    assert!(
        !foreign_snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(
                row,
                arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::Sidecar { .. }
                        | arkret_wire::CurrentSelector::SidecarContext { .. },
                    ..
                }
            ))
    );
    let AccountRealmStreamList::Listed(streams) = store
        .list_realm_streams_for_account(&realm, controller, &station)
        .await
        .unwrap()
    else {
        panic!("controller streams must be proved")
    };
    assert!(
        streams
            .iter()
            .any(|row| row.stream_ref == stream && row.next_position == 1)
    );
    for direction in [
        StreamScanDirection::After(None),
        StreamScanDirection::Before(None),
    ] {
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction,
            limit: 1,
        };
        let AccountStreamScan::Page(page) = store
            .scan_stream_for_account(&request, controller, &station)
            .await
            .unwrap()
        else {
            panic!("controller scan must be served")
        };
        page.validate_for_request(&request).unwrap();
        assert_eq!(page.committed_events.len(), 1);
        assert_eq!(
            page.committed_events[0].commit(),
            &attach.authority_commit.commit
        );
        assert!(matches!(
            store
                .scan_stream_for_account(&request, &foreign, &station)
                .await
                .unwrap(),
            AccountStreamScan::NotAuthorized
        ));
        let AccountStreamScan::Page(peer) = store
            .scan_stream_for_peer(&request, &station, &station)
            .await
            .unwrap()
        else {
            panic!("controller Station's peer scan must be served")
        };
        peer.validate_for_request(&request).unwrap();
        assert_eq!(
            peer.committed_events[0].commit(),
            &attach.authority_commit.commit
        );
        assert!(matches!(
            store
                .scan_stream_for_peer(&request, &foreign.station_id, &station)
                .await
                .unwrap(),
            AccountStreamScan::NotAuthorized
        ));
    }
}

async fn provision_owned_agent(
    pool: &soland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
) -> (
    arkret_wire::AccountId,
    soland_storage::AuthorityCommitTransaction,
    arkret_wire::EventId,
) {
    use arkret_wire::{ActorId, RealmId};
    use soland_storage::{
        ActorProfileStore, AgentPcrGenesisAdmissionWrite, AgentProvisionAdmissionWrite,
        AuthorityCommitTransaction, CurrentRealmAuthority,
    };
    let controller = principal.history.account.clone();
    let station = controller.station_id.clone();
    let station_did = device_authorization_history::did_web_station(&station);
    let controller_realm = principal.unit.transactions[0].event.realm_id.clone();
    let controller_head = principal.unit.transactions[1].commit.clone();
    let controller_authority = principal.unit.transactions[1].expected_authority.clone();
    let controller_method = principal.history.device_verification_method.clone();
    let controller_seed = principal.history.founding_device_signing_seed;
    let profiles = soland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let agent_did = arkret_wire::Did::new(format!(
        "did:web:dc-agent-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let agent = AccountId::new(agent_id.clone(), station.clone());
    let delegation = format!("{agent_did}#managed-controller");
    let genesis = device_authorization_history::sign_event(
        arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
            payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: agent_did.clone(),
                    method_history_head: format!("sha256:{}", "c".repeat(64)),
                    version_id: "1-agent".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new(
                    "ak:trust_domain:pcr-contract.example".to_owned(),
                )
                .unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
            executed_by: ActorId::account(controller.clone()),
            authorization_ref: arkret_wire::AuthorizationRef::new(delegation.clone()).unwrap(),
            created_at: controller_head.committed_at,
        })
        .unwrap()
        .into_event(),
        controller_method.clone(),
        controller_seed,
    );
    let agent_pcr = RealmId::from_event_id(&genesis.event_id);
    let provision = sidecar_agent::agent_provision_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        &agent_id,
        &agent_pcr,
        &delegation,
        controller_head.committed_at,
    );
    let provision_commit =
        sidecar_agent::station_successor(&controller_head, &provision, &station_did, 1);
    let transaction =
        |authority: CurrentRealmAuthority,
         event: arkret_wire::Event,
         commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority,
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: transaction(
                controller_authority,
                provision.clone(),
                provision_commit.clone(),
            ),
            queued_at: provision_commit.committed_at,
        })
        .await
        .unwrap();
    let genesis_commit = sidecar_agent::station_genesis_commit(
        &controller_head,
        &genesis,
        &station_did,
        provision_commit.committed_at + chrono::TimeDelta::seconds(1),
    );
    profiles
        .admit_agent_pcr_genesis(AgentPcrGenesisAdmissionWrite {
            commit: transaction(
                CurrentRealmAuthority {
                    realm_id: agent_pcr.clone(),
                    generation: 0,
                    service_id: station.clone(),
                    authority_ref: genesis_commit.authority_ref.clone(),
                    last_handoff_ref: None,
                },
                genesis.clone(),
                genesis_commit.clone(),
            ),
            queued_at: genesis_commit.committed_at,
        })
        .await
        .unwrap();

    (
        agent,
        transaction(
            CurrentRealmAuthority {
                realm_id: agent_pcr,
                generation: 0,
                service_id: station,
                authority_ref: genesis_commit.authority_ref.clone(),
                last_handoff_ref: None,
            },
            genesis,
            genesis_commit,
        ),
        provision.event_id,
    )
}
