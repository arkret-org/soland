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
#[path = "support/sidecar_exchange_controls.rs"]
mod sidecar_exchange_controls;
#[path = "support/sidecar_readiness.rs"]
mod sidecar_readiness;

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

/// Exercise the real PG read ports with an RFC public group and accepted
/// handshake Events while the desired Agent has no consumed Welcome.
async fn pending_agent_handshake_reads(
    pool: &soland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    head: &soland_storage::AuthorityCommitTransaction,
    sidecar: &SidecarId,
    sidecar_genesis: &arkret_wire::EventId,
    agent: &AccountId,
) -> (
    soland_storage::AuthorityCommitTransaction,
    arkret_mls::ArkretMlsGroup,
    arkret_mls::MlsPublicGroupTracker,
) {
    use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_wire::{ActorId, CommitStreamRef, CommittedEventView, ScopeRef};
    use soland_storage::{
        AccountStreamScan, MlsMemberGroupStateMaterialRead, MlsStateInstallation,
    };

    let controller = &principal.history.account;
    let realm = &head.event.realm_id;
    let at = head.commit.committed_at;
    let actor = ActorId::account(controller.clone());
    let cut = read(pool, realm, sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
    let binding = |base, previous, next| {
        MlsGovernanceBindingPayload::sidecar(
            realm.clone(),
            sidecar.clone(),
            base,
            previous,
            next,
            0,
            cut.participant_authority_digest.clone(),
            cut.authority_stream_head.clone(),
        )
        .unwrap()
    };
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        principal.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed),
        ),
    )
    .unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &binding(None, 0, 0))
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let blob = |bytes: &[u8]| {
        arkret_wire::BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(bytes),
        ))
        .unwrap()
    };
    let authorization = principal
        .history
        .events
        .iter()
        .find(|event| event.kind == EventKind::DeviceAuthorize)
        .unwrap();
    let genesis_payload = serde_json::json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": blob(&info), "ratchet_tree_ref": blob(&tree),
        "creator_leaf_authority": {
            "leaf_signature_key_b64u": arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed)
                    .verifying_key().as_bytes(),
            ),
            "endpoint": {"kind":"device", "device_id": principal.history.founding_device_id},
            "authorization_event_ref": authorization.event_id,
        },
        "governance_binding": binding(None, 0, 0),
        "created_at": arkret_canonical::format_timestamp_canonical(at),
    });
    let make_request = |kind, payload, previous: &soland_storage::AuthorityCommitTransaction| {
        let mut event =
            ordinary_realm::event_for_actor(kind, scope.clone(), actor.clone(), payload, at);
        if event.kind == EventKind::SidecarContextAttach {
            event.semantic_refs = vec![arkret_wire::SemanticRef::new(
                sidecar_genesis.to_string(),
                "after",
            )];
        }
        let event = device_authorization_history::sign_event(
            event,
            principal.history.device_verification_method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let mut request = ordinary_realm::request_for_event(previous, event, at);
        request.authority_commit.commit.stream_ref = stream.clone();
        if previous.commit.stream_ref == stream {
            request.authority_commit.commit.stream_position = previous.commit.stream_position + 1;
            request.authority_commit.commit.previous_commit_ref =
                Some(previous.commit.commit_id.clone());
        } else {
            request.authority_commit.commit.stream_position = 0;
            request.authority_commit.commit.previous_commit_ref = None;
        }
        request
    };
    let state = |base, epoch, public_state| MlsStateInstallation {
        effective_scope: scope.clone(),
        base,
        epoch,
        public_state,
        member_principals: [actor.clone()].into_iter().collect(),
        consumed_proposals: Vec::new(),
        public_blobs: Vec::new(),
    };
    let public_blob = |bytes: &[u8]| {
        let sha256 = arkret_canonical::sha256_digest(bytes)
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        soland_storage::MlsPublicBlob {
            blob_ref: blob(bytes),
            size_bytes: i64::try_from(bytes.len()).unwrap(),
            storage_backend: "local".to_owned(),
            storage_key: format!("sha256/{sha256}"),
            sha256,
        }
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut genesis = make_request(EventKind::MlsGenesis, genesis_payload, head);
    genesis.authority_commit.mls_state = Some(state(None, 0, tracker.export_state().unwrap()));
    genesis
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .public_blobs = vec![public_blob(&info), public_blob(&tree)];
    uow.commit_event(genesis.clone()).await.unwrap();
    let envelope = group
        .self_update_commit_with_governance_binding(&binding(
            Some(genesis.authority_commit.event.event_id.clone()),
            0,
            1,
        ))
        .unwrap();
    let wire = arkret_canonical::base64url_decode(&envelope.commit).unwrap();
    tracker.process_public_handshake(&wire).unwrap();
    let payload = MlsCommitPayload::new(
        genesis.authority_commit.event.event_id.clone(),
        0,
        &envelope,
        binding(Some(genesis.authority_commit.event.event_id.clone()), 0, 1),
    )
    .unwrap();
    let mut commit = make_request(
        EventKind::MlsCommit,
        serde_json::to_value(payload).unwrap(),
        &genesis.authority_commit,
    );
    commit.authority_commit.mls_state = Some(state(
        Some(soland_storage::MlsInstalledBase {
            current_mls_commit_event_ref: genesis.authority_commit.event.event_id.clone(),
            epoch: 0,
        }),
        1,
        tracker.export_state().unwrap(),
    ));
    commit
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .public_blobs = vec![public_blob(&tracker.ratchet_tree_bytes().unwrap())];
    let groups = soland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
    let base = soland_storage::MlsGroupCurrentStore::current(&groups, &scope)
        .await
        .unwrap()
        .unwrap()
        .value;
    uow.commit_event(commit.clone()).await.unwrap();
    group
        .install_accepted_commit(
            &arkret_wire::CommittedEventFullView {
                event: commit.authority_commit.event.clone(),
                commit: commit.authority_commit.commit.clone(),
            },
            &base,
        )
        .unwrap();
    let strand = ordinary_realm::next_request(
        head,
        EventKind::StrandCreate,
        &controller.principal_id,
        serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Pending Sidecar source"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(strand.clone()).await.unwrap();
    let context = make_request(
        EventKind::SidecarContextAttach,
        serde_json::json!({
            "sidecar_id":sidecar,
            "source_context_ref":{"kind":"strand","strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id)},
            "version":1,
        }),
        &commit.authority_commit,
    );
    uow.commit_event(context.clone()).await.unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let request = arkret_wire::StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 10,
    };
    let AccountStreamScan::Page(page) = store
        .scan_stream_for_account(&request, agent, &controller.station_id)
        .await
        .unwrap()
    else {
        panic!("desired Agent must be able to verify its restricted handshakes before consume")
    };
    assert_eq!(page.committed_events.len(), 3);
    assert!(
        matches!(&page.committed_events[0], CommittedEventView::Full(row) if row.event == genesis.authority_commit.event)
    );
    assert!(
        matches!(&page.committed_events[1], CommittedEventView::Full(row) if row.event == commit.authority_commit.event)
    );
    assert!(
        matches!(&page.committed_events[2], CommittedEventView::Withheld(row) if row.commit == context.authority_commit.commit)
    );
    let material =
        arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody {
            realm_id: realm.clone(),
            effective_scope: scope,
            mls_group_id: group.group_id().clone(),
            epoch: Default::default(),
            group_state_event_id: genesis.authority_commit.event.event_id.clone(),
            caller_actor_id: Some(ActorId::account(agent.clone())),
            target_commit_event_ref: Some(commit.authority_commit.event.event_id.clone()),
            target_epoch: Some(1),
            group_info_ref: blob(&info),
            ratchet_tree_ref: blob(&tree),
            max_response_bytes: None,
        };
    assert!(
        matches!(store.mls_member_group_state_material_read(&material, &controller.station_id, None).await.unwrap(),
        MlsMemberGroupStateMaterialRead::Authorized {genesis:Some(row)} if row.event == genesis.authority_commit.event)
    );
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm, agent)
        .await
        .unwrap()
        .unwrap();
    assert!(
        snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stream)
    );
    let public_rows: Vec<_> = snapshot.current_state_entries.iter().filter(|row| matches!(row,
        arkret_wire::TypedCurrentResult::Value {source_stream_ref,..} if source_stream_ref == &stream)).collect();
    assert_eq!(public_rows.len(), 1);
    assert!(
        matches!(public_rows[0], arkret_wire::TypedCurrentResult::Value {
        selector: arkret_wire::CurrentSelector::MlsGroup {scope_ref}, value, ..
    } if scope_ref == &material.effective_scope
        && value["genesis_event_ref"] == serde_json::to_value(&genesis.authority_commit.event.event_id).unwrap()
        && value["epoch"] == 1)
    );
    assert!(
        !snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(row,
        arkret_wire::TypedCurrentResult::Value {selector:
            arkret_wire::CurrentSelector::Sidecar {sidecar_id}
            | arkret_wire::CurrentSelector::SidecarContext {sidecar_id,..}, ..}
            if sidecar_id == sidecar))
    );
    let foreign = AccountId::new(
        agent.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:wrong-sidecar-station.example").unwrap(),
    );
    assert!(matches!(
        store
            .scan_stream_for_account(&request, &foreign, &controller.station_id)
            .await
            .unwrap(),
        AccountStreamScan::NotAuthorized
    ));
    (context.authority_commit, group, tracker)
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
    // The v1 ingress has no Agent cleanup carrier. An invalidated Agent
    // self-leave cannot rewrite canonical membership or revive its generation.
    let error = uow.commit_event(leave.clone()).await.unwrap_err();
    assert!(error.to_string().contains("unsupported_feature"));
    let left = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(left.desired_agent_ids.is_empty());
    assert!(
        !left
            .authority_stream_head
            .contains(&leave.authority_commit.event.event_id)
    );
    assert_eq!(
        left.authority_stream_head,
        stale_generation.authority_stream_head
    );
    assert_eq!(
        left.participant_authority_digest,
        stale_generation.participant_authority_digest
    );
    let fresh_join = ordinary_realm::next_request(
        &controller_rejoin.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":controller_rejoin.authority_commit.event.event_id}}),
        controller_rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    // A new controller generation cannot turn the existing Agent join into
    // another join without an accepted canonical leave transition.
    let error = uow.commit_event(fresh_join.clone()).await.unwrap_err();
    assert!(error.to_string().contains("invalid_membership_transition"));
    let fresh = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(fresh.desired_agent_ids.is_empty());
    assert!(
        !fresh
            .authority_stream_head
            .contains(&fresh_join.authority_commit.event.event_id)
    );
    assert_eq!(
        fresh.authority_stream_head,
        stale_generation.authority_stream_head
    );
    assert_eq!(
        fresh.participant_authority_digest,
        stale_generation.participant_authority_digest
    );
}

#[tokio::test]
async fn pending_sidecar_handshake_reads_keep_content_private_and_reject_stale_authority() {
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
    pending_agent_handshake_reads(
        &pool,
        &principal,
        &join.authority_commit,
        &sidecar,
        &create.authority_commit.event.event_id,
        &agent,
    )
    .await;
    let renewed_at = key_commit.committed_at + chrono::TimeDelta::seconds(2);
    let mut renewed_authorization =
        sidecar_agent::agent_key_authorization(&agent_did, &controller.principal_id, renewed_at);
    renewed_authorization["supersedes"] = serde_json::json!([{
        "key_id":key_event.payload["key_id"],
        "authorized_event_ref":key_event.event_id,
    }]);
    let renewal = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        renewed_authorization,
        renewed_at,
    );
    let renewal_commit = sidecar_agent::station_successor(&key_commit, &renewal, &station_did, 2);
    profiles
        .admit_agent_control_event(AgentControlAdmissionWrite {
            commit: soland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: renewal,
                commit: renewal_commit.clone(),
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: renewal_commit.committed_at,
        })
        .await
        .unwrap();
    let current_cut = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current_cut.desired_agent_ids,
        vec![agent.principal_id.clone()]
    );
    let stale = arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar,
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 10,
    };
    assert!(matches!(
        store
            .scan_stream_for_account(&stale, &agent, &controller.station_id)
            .await
            .unwrap(),
        soland_storage::AccountStreamScan::NotAuthorized
    ));
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm_id, &agent)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stale.stream_ref)
    );
    assert!(
        !snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(row,
        arkret_wire::TypedCurrentResult::Value {source_stream_ref,..}
        if source_stream_ref == &stale.stream_ref))
    );
}

/// Real accepted Sidecar Add, original Welcome and signed durable receipt.
/// The PG consume port takes serving-layer verified receipts as its input.
#[tokio::test]
async fn consumed_sidecar_agent_requires_exact_controller_owner_and_consume_digest() {
    use soland_storage::{ActorProfileStore, AgentControlAdmissionWrite};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let resolution = sidecar_readiness::attestor_resolution();
    let station_did = resolution.normalized_did_document.id.clone();
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
    let agent_did = arkret_wire::Did::new(format!(
        "did:webvh:{}:sidecar-agent.example",
        arkret_canonical::multibase::sha256_multihash_base58btc(uuid::Uuid::now_v7().as_bytes())
    ))
    .unwrap();
    let (agent, genesis, provision_ref) =
        provision_owned_agent_with_did(&pool, &principal, agent_did.clone()).await;
    let no_key = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(no_key.desired_agent_ids.is_empty());
    assert!(no_key.authority_stream_head.contains(&provision_ref));
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
    let (head, mut group, mut tracker) = pending_agent_handshake_reads(
        &pool,
        &principal,
        &join.authority_commit,
        &sidecar,
        &create.authority_commit.event.event_id,
        &agent,
    )
    .await;
    use arkret_models_crypto::{
        KeyOperationSignature, KeyPackageConsumeReceipt, MlsGovernanceBindingPayload,
        RecipientMlsDurableReceipt, RecipientMlsDurableSigner,
    };
    use arkret_wire::{ActorId, ScopeRef};
    use diesel::sql_types::{BigInt, Jsonb, Text};
    use diesel_async::RunQueryDsl;
    use soland_storage::{MlsGroupCurrentStore, MlsKeyPackageStore};
    let scope = ScopeRef::Sidecar {
        realm_id: realm_id.clone(),
        sidecar_id: sidecar.clone(),
    };
    let cut = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    let actor = ActorId::account(agent.clone());
    let method = arkret_wire::DidUrl::new(format!("{agent_did}#runtime-1")).unwrap();
    let identity = arkret_mls::ArkretMlsIdentity::new_agent(
        actor.clone(),
        method.clone(),
        key_event.event_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]),
        ),
    )
    .unwrap();
    let mut package = identity.key_package_record().unwrap();
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    #[derive(diesel::QueryableByName)]
    struct LocalAccount {
        #[diesel(sql_type=BigInt)]
        pk: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let owner = diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
        .bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller.station_id.as_str())
        .get_result::<LocalAccount>(&mut conn).await.unwrap().pk;
    drop(conn);
    // Materialize the serving layer's local endpoint index from the same
    // accepted Agent PCR and runtime authorization used by the cut above.
    let mut record = soland_storage::AgentPrincipalRecord::new(
        agent.principal_id.to_string(),
        controller.principal_id.to_string(),
        genesis.event.realm_id.to_string(),
        arkret_wire::DidUrl::new(delegation.clone()).unwrap(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
        genesis.commit.committed_at,
    );
    record.controller_account_pk = Some(soland_storage::AccountPk(owner));
    record.authorized_event_ref = Some(key_event.event_id.to_string());
    record.authorized_verification_method = Some(method.to_string());
    record.authorized_key_event = Some(key_event.clone());
    let evidence = arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence(
        agent.principal_id.clone(), method.clone(),
        serde_json::from_value(serde_json::json!({
            "kty":"OKP", "crv":"Ed25519", "x":arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x61;32]).verifying_key().as_bytes())
        })).unwrap(), key_commit.commit_id.clone(), key_commit.committed_at,
    ).unwrap();
    record.signer_resolution_evidence_ref = Some(evidence.signer_evidence_ref().unwrap());
    record.current_signer_evidence = Some(evidence);
    record.authorized_public_key_digest =
        Some(arkret_canonical::canonical_sha256(&key_event.payload["public_key"]).unwrap());

    soland_storage::AgentStore::put(
        &soland_storage_postgres::PgAgentStore { pool: pool.clone() },
        record,
    )
    .await
    .unwrap();
    let packages = soland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() };
    packages
        .put(&soland_storage::MlsKeyPackageRow {
            id: package.keypackage_id.clone(),
            keypackage_ref: package.keypackage_ref.to_string(),
            keypackage_digest: package.keypackage_ref.to_string(),
            owner_account_pk: soland_storage::AccountPk(owner),
            actor_id: agent.principal_id.to_string(),
            device_id: None,
            endpoint_verification_method: Some(method.to_string()),
            intended_realm_id: None,
            key_package_bytes: arkret_canonical::base64url_decode(&package.keypackage).unwrap(),
            capabilities: package.capabilities.clone(),
            capabilities_digest: arkret_canonical::canonical_sha256(&package.capabilities).unwrap(),
            last_resort: false,
            last_resort_realm_id: None,
            lifetime_not_before: now.timestamp() - 1,
            lifetime_not_after: now.timestamp() + 3600,
            claimed_by_mls_group_id: None,
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(key_event.event_id.to_string()),
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: now.timestamp(),
        })
        .await
        .unwrap();
    let claim_id = arkret_wire::KeypackageClaimId::new(format!(
        "ak:keypackage_claim:{}",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let request_id =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([39; 32])).unwrap();
    let claim_outcome = sidecar_readiness::claim_outcome(
        &package,
        &claim_id,
        &request_id,
        controller,
        &agent,
        &method,
        &key_event.event_id,
        &scope,
        now,
    );
    let ledger = soland_storage::PeerKeyPackageClaimLedgerRecord {
        source_id: controller.station_id.to_string(),
        claim_request_id: request_id.to_string(),
        request_digest: format!("sha256:{}", "6".repeat(64)),
        key_package_use: "single_use".into(),
        keypackage_id: Some(package.keypackage_id.clone()),
        outcome: Some(serde_json::to_value(&claim_outcome).unwrap()),
        terminal_receipt: None,
        consume_receipt: None,
        claim_expires_at_unix_ms: Some(now.timestamp_millis() + 3_000_000),
        expires_at: now.timestamp() + 86400,
        state: "claimed".into(),
        updated_at: now.timestamp(),
    };
    let group_id = scope.canonical_mls_group_id().unwrap();
    assert!(matches!(
        packages
            .try_claim_peer(soland_storage::PeerKeyPackageClaimAttempt {
                keypackage_id: &package.keypackage_id,
                mls_group_id: group_id.as_str(),
                device_authorize_event_id: None,
                agent_key_authorize_event_id: Some(key_event.event_id.as_str()),
                device_revocation_gate: None,
                claimed_at_unix_ms: now.timestamp_millis(),
                claim_expires_at_unix_ms: now.timestamp_millis() + 3_000_000,
                ledger: &ledger,
            })
            .await
            .unwrap(),
        soland_storage::PeerKeyPackageClaimAttemptResult::Claimed(_)
    ));
    package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    package.claim_id = Some(claim_id.to_string());
    let groups = soland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
    let base = groups.current(&scope).await.unwrap().unwrap().value;
    let binding = MlsGovernanceBindingPayload::sidecar(
        realm_id.clone(),
        sidecar.clone(),
        Some(base.current_mls_commit_event_ref.clone()),
        base.epoch,
        base.epoch + 1,
        0,
        cut.participant_authority_digest.clone(),
        cut.authority_stream_head.clone(),
    )
    .unwrap();
    let add = group
        .add_member_with_governance_binding(&package, &binding)
        .unwrap();
    let transition = tracker
        .process_public_handshake(&arkret_canonical::base64url_decode(&add.commit.commit).unwrap())
        .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = transition
    else {
        panic!("real Add required")
    };
    let event = device_authorization_history::sign_event(
        ordinary_realm::event_for_actor(
            EventKind::MlsCommit,
            scope.clone(),
            ActorId::account(controller.clone()),
            serde_json::to_value(
                arkret_models_crypto::MlsCommitPayload::new(
                    base.current_mls_commit_event_ref.clone(),
                    base.current_key_access_revision,
                    &add.commit,
                    binding,
                )
                .unwrap(),
            )
            .unwrap(),
            head.commit.committed_at,
        ),
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    let mut request = ordinary_realm::request_for_event(&head, event, head.commit.committed_at);
    request.authority_commit.commit.stream_ref = head.commit.stream_ref.clone();
    request.authority_commit.commit.stream_position = head.commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(head.commit.commit_id.clone());
    let tree = tracker.ratchet_tree_bytes().unwrap();
    let sha256 = arkret_canonical::sha256_digest(&tree)
        .strip_prefix("sha256:")
        .unwrap()
        .to_owned();
    let leaf = |l: arkret_mls::MlsPublicEndpointLeaf| soland_storage::MlsProposalLeafProvenance {
        leaf_index: l.leaf_index,
        actor_id: l.actor_id,
        signature_key: l.signature_key,
    };
    request.authority_commit.mls_state = Some(soland_storage::MlsStateInstallation {
        effective_scope: scope.clone(),
        base: Some(soland_storage::MlsInstalledBase {
            current_mls_commit_event_ref: base.current_mls_commit_event_ref.clone(),
            epoch: base.epoch,
        }),
        epoch: base.epoch + 1,
        public_state: tracker.export_state().unwrap(),
        member_principals: tracker
            .leaves()
            .unwrap()
            .into_iter()
            .map(|l| l.actor_id)
            .collect(),
        consumed_proposals: consumed_proposals
            .into_iter()
            .map(|p| soland_storage::MlsConsumedProposalInstallation {
                ordinal: p.ordinal,
                proposal_ref: p.proposal_ref,
                proposal_type: p.proposal_type,
                proposal_wire: p.proposal_wire,
                sender_leaf: leaf(p.sender_leaf),
                target_before: p.target_before.map(leaf),
                target_after: p.target_after.map(leaf),
            })
            .collect(),
        public_blobs: vec![soland_storage::MlsPublicBlob {
            blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:sha256:{sha256}")).unwrap(),
            size_bytes: tree.len() as i64,
            storage_backend: "local".into(),
            storage_key: format!("sha256/{sha256}"),
            sha256,
        }],
    });
    let placeholder = arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: principal.history.device_verification_method.clone(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at: now,
        sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
    };
    let mut delivery = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: realm_id.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: request.authority_commit.event.event_id.clone(),
        recipient_actor_id: actor,
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: method.clone(),
        },
        keypackage_claim_ref: claim_id.clone(),
        ciphertext_b64: add.welcome.ciphertext_b64,
        producer_proof: placeholder,
    };
    let mut unsigned = serde_json::to_value(&delivery).unwrap();
    unsigned.as_object_mut().unwrap().remove("producer_proof");
    delivery.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        principal.history.device_verification_method.clone(),
        now,
        &ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed),
    )
    .unwrap();
    request.authority_commit.welcomes = vec![soland_storage::VerifiedMlsWelcome {
        delivery: delivery.clone(),
        claim: Some(soland_storage::MlsWelcomeClaimLedgerKey {
            source_id: ledger.source_id.clone(),
            claim_request_id: ledger.claim_request_id.clone(),
            request_digest: ledger.request_digest.clone(),
        }),
        roster_witness: Some(sidecar_readiness::add_witness(
            claim_outcome,
            &delivery,
            &base,
            request.authority_commit.commit.stream_position,
            tracker
                .leaves()
                .unwrap()
                .into_iter()
                .find(|l| l.actor_id == arkret_wire::ActorId::account(agent.clone()))
                .unwrap()
                .signature_key,
            resolution,
        )),
    }];
    request.authority_commit.recipient_queue_capacity = 8;
    uow.commit_event(request.clone()).await.unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: request.authority_commit.event.clone(),
        commit: request.authority_commit.commit.clone(),
    };
    group.install_accepted_commit(&accepted, &base).unwrap();
    let mut recipient_group = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity, &delivery, &accepted,
    )
    .unwrap();
    let device_authorization = principal
        .history
        .events
        .iter()
        .find(|e| e.kind == EventKind::DeviceAuthorize)
        .unwrap();
    let bindings = tracker
        .leaves()
        .unwrap()
        .into_iter()
        .map(|l| {
            let is_controller = l.actor_id == ActorId::account(controller.clone());
            arkret_mls::MlsVerifiedLeafBinding {
                leaf_index: l.leaf_index,
                actor_id: l.actor_id,
                signature_key: l.signature_key,
                endpoint: if is_controller {
                    arkret_models_crypto::MlsEndpointIdentity::human_device(
                        controller.principal_id.clone(),
                        principal.history.founding_device_id.clone(),
                    )
                } else {
                    arkret_models_crypto::MlsEndpointIdentity::agent_runtime(
                        agent.principal_id.clone(),
                        method.clone(),
                        key_event.event_id.clone(),
                    )
                    .unwrap()
                },
                device_authorize_event_id: is_controller
                    .then(|| device_authorization.event_id.clone()),
            }
        })
        .collect();
    recipient_group
        .install_verified_leaf_bindings(bindings)
        .unwrap();
    assert_eq!(
        recipient_group.export_state_record().unwrap().epoch,
        base.epoch + 1
    );
    let status = || {
        store.sidecar_access_cut(
            realm_id,
            &sidecar,
            controller,
            &principal.history.founding_device_id,
        )
    };
    assert!(
        status().await.unwrap().unwrap().1.is_empty(),
        "Add without durable consume stays pending"
    );
    let durable = recipient_group
        .identity()
        .sign_recipient_mls_durable_receipt(RecipientMlsDurableReceipt {
            domain: arkret_wire::NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
            )
            .unwrap(),
            claim_request_id: request_id,
            key_package_ref: arkret_wire::NonEmptyString::new(package.keypackage_ref.to_string())
                .unwrap(),
            recipient: RecipientMlsDurableSigner::Agent {
                recipient_agent_id: agent.principal_id.clone(),
                recipient_agent_verification_method: method.clone(),
                agent_key_authorize_event_id: key_event.event_id.clone(),
            },
            recipient_id: controller.station_id.clone(),
            realm_id: realm_id.clone(),
            mls_group_id: group_id.clone(),
            mls_epoch: base.epoch + 1,
            welcome_ref: delivery.welcome_id.clone(),
            welcome_digest: delivery.durable_receipt_digest().unwrap(),
            durable_at: now,
            signature: KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(method.to_string()).unwrap(),
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
            },
        })
        .unwrap();
    let consume = recipient_group
        .identity()
        .signed_key_packages_consume_request(claim_id.clone(), durable.clone())
        .unwrap();
    let mut receipt = KeyPackageConsumeReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::KEYPACKAGE_CONSUME_RECEIPT_V1,
        )
        .unwrap(),
        request_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&consume.unsigned()).unwrap(),
        )
        .unwrap(),
        claim_id,
        recipient_durable_receipt: durable,
        consumed_at: now,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(format!(
                "{station_did}#{}",
                station_did.as_str().strip_prefix("did:key:").unwrap()
            ))
            .unwrap(),
            signature_algorithm: None,
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
    };
    use ed25519_dalek::Signer;
    receipt.signature.sig = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
        ed25519_dalek::SigningKey::from_bytes(&[83; 32])
            .sign(&receipt.canonical_signing_bytes().unwrap())
            .to_bytes(),
    ))
    .unwrap();
    assert_ne!(receipt.request_digest.as_str(), ledger.request_digest);
    let receipt_json = serde_json::to_value(&receipt).unwrap();
    packages
        .consume_claim(
            &package.keypackage_id,
            group_id.as_str(),
            now.timestamp_millis(),
            Some(&receipt_json),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status().await.unwrap().unwrap().1,
        vec![agent.principal_id.clone()]
    );
    let mut conn = pool.get().await.unwrap();
    for (label, mutation) in [
        (
            "owner Station",
            "station_id='ak:did_core:web:wrong-sidecar-owner.example'",
        ),
        (
            "owner principal",
            "principal_id='ak:did_core:web:wrong-sidecar-owner.example'",
        ),
    ] {
        diesel::sql_query(format!("UPDATE accounts SET {mutation} WHERE pk=$1"))
            .bind::<BigInt, _>(owner)
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        assert!(status().await.unwrap().unwrap().1.is_empty(), "{label}");
        conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE accounts SET principal_id=$2,station_id=$3 WHERE pk=$1")
            .bind::<BigInt, _>(owner)
            .bind::<Text, _>(controller.principal_id.as_str())
            .bind::<Text, _>(controller.station_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
    }
    let mut wrong_digest = receipt_json.clone();
    wrong_digest["request_digest"] = serde_json::json!(ledger.request_digest);
    diesel::sql_query("UPDATE peer_keypackage_claims SET consume_receipt=$1 WHERE source_id=$2 AND claim_request_id=$3")
        .bind::<Jsonb,_>(wrong_digest).bind::<Text,_>(&ledger.source_id).bind::<Text,_>(&ledger.claim_request_id).execute(&mut conn).await.unwrap();
    drop(conn);
    assert!(
        status().await.unwrap().unwrap().1.is_empty(),
        "claim digest cannot stand in for consume digest"
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE peer_keypackage_claims SET consume_receipt=$1 WHERE source_id=$2 AND claim_request_id=$3")
        .bind::<Jsonb,_>(receipt_json).bind::<Text,_>(&ledger.source_id).bind::<Text,_>(&ledger.claim_request_id).execute(&mut conn).await.unwrap();
    drop(conn);
    assert_eq!(
        status().await.unwrap().unwrap().1,
        vec![agent.principal_id.clone()]
    );
    sidecar_exchange_controls::assert_current(
        &pool,
        &principal,
        &sidecar,
        &request.authority_commit,
        &mut group,
        &agent.principal_id,
    )
    .await;
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
    let agent_did = arkret_wire::Did::new(format!(
        "did:web:dc-agent-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    provision_owned_agent_with_did(pool, principal, agent_did).await
}

async fn provision_owned_agent_with_did(
    pool: &soland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent_did: arkret_wire::Did,
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
    let station_did = principal.history.station_did.clone();
    let controller_realm = principal.unit.transactions[0].event.realm_id.clone();
    let controller_head = principal.unit.transactions[1].commit.clone();
    let controller_authority = principal.unit.transactions[1].expected_authority.clone();
    let controller_method = principal.history.device_verification_method.clone();
    let controller_seed = principal.history.founding_device_signing_seed;
    let profiles = soland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
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

/// Storage admission only: accepted controller/Agent units are real; RFC
/// verification and publication signatures are covered by HTTP/MLS suites.
#[tokio::test]
async fn encrypted_agent_join_rechecks_claimability_and_writes_nothing_on_refusal() {
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;
    use soland_storage::{ActorProfileStore, AgentControlAdmissionWrite, MlsKeyPackageStore};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = ordinary_realm::station();
    let station_did = device_authorization_history::did_web_station(&station);
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_with_history_for_account(
        "agent-mls-join",
        "invite",
        "since_join",
        controller,
        &station_did,
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let realm_id = &parent.event.realm_id;
    let (agent, genesis, _) = provision_owned_agent(&pool, &principal).await;
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

    let at = key_commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let mut group = ordinary_realm::next_request(
        parent,
        EventKind::MlsGenesis,
        &controller.principal_id,
        serde_json::json!({
            "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref":format!("ak:blob:sha256:{}", "3".repeat(64)),
            "ratchet_tree_ref":format!("ak:blob:sha256:{}", "4".repeat(64)),
            "creator_leaf_authority":{
                "leaf_signature_key_b64u":arkret_canonical::base64url_encode(
                    ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed).verifying_key().as_bytes()),
                "endpoint":{"kind":"device","device_id":principal.history.founding_device_id},
                "authorization_event_ref":principal.unit.transactions[1].event.event_id
            },
            "governance_binding":arkret_models_crypto::MlsGovernanceBindingPayload::realm(realm_id.clone(),None,0,0,0).unwrap(),
            "created_at":arkret_canonical::format_timestamp_canonical(at)
        }),
        at,
    );
    // The storage boundary consumes an already verified installation, just
    // as the founding-unit storage matrix does. No RFC verification is claimed.
    group.authority_commit.mls_state = Some(soland_storage::MlsStateInstallation {
        effective_scope: group.authority_commit.event.scope_ref.clone(),
        base: None,
        epoch: 0,
        public_state: b"storage-verified-public-state".to_vec(),
        member_principals: std::collections::BTreeSet::from([arkret_wire::ActorId::account(
            controller.clone(),
        )]),
        consumed_proposals: Vec::new(),
        public_blobs: Vec::new(),
    });
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(group.clone()).await.unwrap();
    let join = ordinary_realm::next_request(
        &group.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({
            "realm_id":realm_id,"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}
        }),
        at,
    );
    #[derive(diesel::QueryableByName, Debug, PartialEq)]
    struct Footprint {
        #[diesel(sql_type=BigInt)]
        events: i64,
        #[diesel(sql_type=BigInt)]
        commits: i64,
        #[diesel(sql_type=BigInt)]
        members: i64,
        #[diesel(sql_type=BigInt)]
        revision: i64,
        #[diesel(sql_type=BigInt)]
        covered: i64,
        #[diesel(sql_type=BigInt)]
        epoch: i64,
    }
    async fn footprint(
        pool: &soland_storage_postgres::PgPool,
        realm: &arkret_wire::RealmId,
    ) -> Footprint {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("SELECT (SELECT COUNT(*) FROM canonical_events) AS events, \
            (SELECT COUNT(*) FROM realm_commits) AS commits, \
            (SELECT COUNT(*) FROM member_state_current_results) AS members, \
            (SELECT (value->>'current_key_access_revision')::bigint FROM mls_group_current_results WHERE realm_id=$1) AS revision, \
            (SELECT (value->>'covered_key_access_revision')::bigint FROM mls_group_current_results WHERE realm_id=$1) AS covered, \
            (SELECT (value->>'epoch')::bigint FROM mls_group_current_results WHERE realm_id=$1) AS epoch")
            .bind::<Text,_>(realm.as_str()).get_result(&mut *conn).await.unwrap()
    }
    let before = footprint(&pool, realm_id).await;
    assert!(
        uow.commit_event(join.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("claimable membership KeyPackage")
    );
    assert_eq!(footprint(&pool, realm_id).await, before);
    #[derive(diesel::QueryableByName)]
    struct Account {
        #[diesel(sql_type=BigInt)]
        pk: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let wrong_owner=diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) \
        ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(agent.station_id.as_str())
        .get_result::<Account>(&mut *conn).await.unwrap().pk;
    let owner =
        diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
            .bind::<Text, _>(controller.principal_id.as_str())
            .bind::<Text, _>(controller.station_id.as_str())
            .get_result::<Account>(&mut *conn)
            .await
            .unwrap()
            .pk;
    drop(conn);
    let packages = soland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() };
    let package = soland_storage::MlsKeyPackageRow {
        id: "agent-membership-package".into(),
        keypackage_ref: format!("sha256:{}", "7".repeat(64)),
        keypackage_digest: format!("sha256:{}", "7".repeat(64)),
        owner_account_pk: soland_storage::AccountPk(owner),
        actor_id: agent.principal_id.to_string(),
        device_id: None,
        endpoint_verification_method: Some(format!("{agent_did}#runtime-1")),
        intended_realm_id: None,
        key_package_bytes: b"verified-published-keypackage".to_vec(),
        capabilities: vec!["ak.content.v1".into(), "mimi.content.v1".into()],
        capabilities_digest: format!("sha256:{}", "8".repeat(64)),
        last_resort: false,
        last_resort_realm_id: None,
        lifetime_not_before: at.timestamp() - 1,
        lifetime_not_after: at.timestamp() + 3600,
        claimed_by_mls_group_id: None,
        device_authorize_event_id: None,
        agent_key_authorize_event_id: Some(key_event.event_id.to_string()),
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: at.timestamp(),
    };
    packages.put(&package).await.unwrap();
    let mut mutations = vec![
        "lifetime_not_after=0",
        "claimed_by_mls_group_id='already-claimed',claimed_at=1,claim_expires_at_unix_ms=2",
        "capabilities='[]'::jsonb",
        "actor_id='ak:did_core:web:foreign-agent.example'",
        "agent_key_authorize_event_id=(SELECT id FROM canonical_events WHERE kind='ak.realm.create' ORDER BY pk LIMIT 1)",
        "endpoint_verification_method='did:web:wrong-agent.example#runtime-1'",
        "agent_key_authorize_event_id=NULL,endpoint_verification_method='did:web:pairwise.example#key',intended_realm_id='another-realm'",
    ].into_iter().map(str::to_owned).collect::<Vec<_>>();
    mutations.push(format!("owner_account_pk={wrong_owner}"));
    for mutation in mutations {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(format!(
            "UPDATE mls_key_packages SET {mutation} WHERE id=$1"
        ))
        .bind::<Text, _>(&package.id)
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        let before = footprint(&pool, realm_id).await;
        assert!(
            uow.commit_event(join.clone()).await.is_err(),
            "mutation {mutation}"
        );
        assert_eq!(
            footprint(&pool, realm_id).await,
            before,
            "mutation {mutation}"
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("DELETE FROM mls_key_packages WHERE id=$1")
            .bind::<Text, _>(&package.id)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        packages.put(&package).await.unwrap();
    }
    let mut stale_payload = serde_json::to_value(&join.authority_commit.event.payload).unwrap();
    // A valid current KeyPackage does not revive an old controller generation.
    stale_payload["agent_controller_binding"]["controller_membership_generation_ref"] =
        serde_json::to_value(key_event.event_id.clone()).unwrap();
    let stale = ordinary_realm::next_request(
        &group.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        stale_payload,
        at,
    );
    let before = footprint(&pool, realm_id).await;
    assert!(uow.commit_event(stale).await.is_err());
    assert_eq!(footprint(&pool, realm_id).await, before);
    uow.commit_event(join.clone()).await.unwrap();
    let after = footprint(&pool, realm_id).await;
    assert_eq!(after.events, before.events + 1);
    assert_eq!(after.commits, before.commits + 1);
    assert_eq!(after.members, before.members + 1);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.covered, before.covered);
    assert_eq!(after.epoch, before.epoch);
}
