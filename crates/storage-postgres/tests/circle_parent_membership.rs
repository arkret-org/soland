//! `ak.vector.circle.parent_membership_revision.v1` on real PostgreSQL.
//!
//! A Circle join binds the exact parent Realm join revision (`circle.md`
//! section 9.1). Admission refuses any other revision, and effective Circle
//! membership compares the two durable typed currents of one cut: a parent
//! leave, ban or rejoin invalidates the old Circle join without any Circle
//! Event or rewritten canonical row, and only an explicit new Circle join
//! bound to the new revision restores it.

#[path = "support/accepted_pcr_account.rs"]
mod accepted_pcr_account;
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use arkret_wire::{ActorId, CircleId, CommitStreamRef, EventKind, ScopeRef};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
use soland_storage::{
    AccountStreamScan, AuthorityCommitStore, AuthorityCommitTransaction, ConflictCode,
    EventCommitRequest, EventCommitUnitOfWork, PersistenceError,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

fn remote_member(label: &str) -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:circle-parent-member-station.example")
            .unwrap(),
    ))
}

fn sourced(mut request: EventCommitRequest) -> EventCommitRequest {
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

fn realm_membership(
    previous: &AuthorityCommitTransaction,
    writer: &ActorId,
    member: &ActorId,
    state: &str,
    reason: &str,
) -> EventCommitRequest {
    sourced(ordinary_realm::next_request_for_actor(
        previous,
        EventKind::MemberState,
        writer.clone(),
        json!({"realm_id":previous.event.realm_id,"member_id":member,"membership":state,
            "reason":reason}),
        previous.commit.committed_at,
    ))
}

/// One Circle-stream Event by `actor` after `previous`, which is either the
/// Circle stream head or a Realm-stream Commit when the Circle stream is new.
fn circle_request(
    previous: &AuthorityCommitTransaction,
    circle: &CircleId,
    actor: &ActorId,
    payload: Value,
) -> EventCommitRequest {
    // Distinct transitions with equal payloads are distinct signed Events;
    // the content address includes created_at, not the later Commit cursor.
    let at = previous.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let event = ordinary_realm::event_for_actor(
        EventKind::CircleMemberState,
        ScopeRef::Circle {
            realm_id: previous.event.realm_id.clone(),
            circle_id: circle.clone(),
        },
        actor.clone(),
        payload,
        at,
    );
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    let stream = CommitStreamRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    sourced(request)
}

fn circle_membership(
    circle: &CircleId,
    member: &ActorId,
    state: &str,
    expected: Value,
    parent: Option<&Value>,
) -> Value {
    let mut payload = json!({"circle_id":circle,"member_id":member,"membership":state,
        "expected_membership":expected});
    if let Some(parent) = parent {
        payload["parent_membership_revision"] = parent.clone();
    }
    payload
}

#[derive(diesel::QueryableByName)]
struct EffectiveRow {
    #[diesel(sql_type = Bool)]
    effective: bool,
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// The canonical Circle row and the effective judgment of the same cut.
async fn circle_member(pool: &PgPool, circle: &CircleId, member: &ActorId) -> EffectiveRow {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT circle_member_parent_join_current(realm_id,member_id,value) AS effective, \
         membership,current_commit_id,value FROM circle_member_state_current_results \
         WHERE circle_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(circle.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<EffectiveRow>(&mut conn)
    .await
    .unwrap()
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn circle_stream_commits(pool: &PgPool, stream: &CommitStreamRef) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE stream_ref=$1")
        .bind::<Jsonb, _>(serde_json::to_value(stream).unwrap())
        .get_result::<CountRow>(&mut conn)
        .await
        .unwrap()
        .count
}

async fn circle_scan_authorized(
    store: &PgAuthorityCommitStore,
    stream: &CommitStreamRef,
    member: &ActorId,
) -> bool {
    let request = arkret_wire::StreamScanRequest {
        realm_id: stream.realm_id().clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 16,
    };
    match store
        .scan_stream_for_account(
            &request,
            member.as_account_id().unwrap(),
            &ordinary_realm::station(),
        )
        .await
        .unwrap()
    {
        AccountStreamScan::Page(_) => true,
        AccountStreamScan::NotAuthorized => false,
        other => panic!("unexpected Circle scan answer {other:?}"),
    }
}

fn refusal_code(error: &PersistenceError) -> Option<ConflictCode> {
    error.conflict_code()
}

#[tokio::test]
async fn circle_join_binds_the_exact_parent_join_and_parent_changes_invalidate_it() {
    for history in ["since_join", "all_history_for_current_members"] {
        parent_revision_matrix(history).await;
    }
}

async fn parent_revision_matrix(history: &str) {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let did = device_authorization_history::did_web_station(&ordinary_realm::station());
    let creator = accepted_pcr_account::accepted_pcr_account(&pool, did.clone()).await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &uuid::Uuid::now_v7().to_string(),
        creator.as_account_id().unwrap(),
        &did,
    );
    let at = unit.transactions.last().unwrap().commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm = unit.transactions[0].event.realm_id.clone();
    let alice = remote_member("circle-parent-alice");
    let realm_join = realm_membership(
        unit.transactions.last().unwrap(),
        &alice,
        &alice,
        "join",
        "first join",
    );
    uow.commit_event(realm_join.clone()).await.unwrap();
    let create = sourced(ordinary_realm::next_request_for_actor(
        &realm_join.authority_commit,
        EventKind::CircleCreate,
        creator.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Parent bound","display":{"short_name":"Parent","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":history,
            "state":"active","created_by":creator,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    ));
    uow.commit_event(create.clone()).await.unwrap();
    let circle = CircleId::from_event_id(&create.authority_commit.event.event_id);
    let stream = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let root_event_ref = {
        #[derive(diesel::QueryableByName)]
        struct RootRow {
            #[diesel(sql_type = Text)]
            authority_event_ref: String,
        }
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<RootRow>(&mut conn)
        .await
        .unwrap()
        .authority_event_ref
    };
    let grant = sourced(ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::CapabilityGrant,
        creator.clone(),
        json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":creator,"subject":alice,"actions":["ak.circle.member.add","ak.mls.genesis"],
            "resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
                "authority_event_ref":root_event_ref,"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    ));
    uow.commit_event(grant.clone()).await.unwrap();
    let first_parent = ordinary_realm::parent_membership_revision(&pool, &realm, &alice).await;
    assert_eq!(
        first_parent,
        json!({"commit_id":realm_join.authority_commit.commit.commit_id,
            "stream_position":realm_join.authority_commit.commit.stream_position})
    );

    // Admission: the revision is required on join, forbidden elsewhere, and
    // must be the parent current join exactly.
    let missing = circle_request(
        &grant.authority_commit,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "join", Value::Null, None),
    );
    assert!(matches!(
        uow.commit_event(missing).await.unwrap_err(),
        PersistenceError::SchemaViolation(_)
    ));
    let mut foreign_revision = first_parent.clone();
    foreign_revision["commit_id"] = json!(create.authority_commit.commit.commit_id);
    let foreign = circle_request(
        &grant.authority_commit,
        &circle,
        &alice,
        circle_membership(
            &circle,
            &alice,
            "join",
            Value::Null,
            Some(&foreign_revision),
        ),
    );
    let refused = uow.commit_event(foreign).await.unwrap_err();
    assert_eq!(
        refusal_code(&refused),
        Some(ConflictCode::FailedPrecondition)
    );
    assert!(
        refused
            .to_string()
            .contains("circle_member_must_be_realm_member")
    );
    // The same position number on another Commit is not the parent join.
    let mut shifted = first_parent.clone();
    shifted["stream_position"] = json!(realm_join.authority_commit.commit.stream_position + 1);
    let shifted = circle_request(
        &grant.authority_commit,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "join", Value::Null, Some(&shifted)),
    );
    assert_eq!(
        refusal_code(&uow.commit_event(shifted).await.unwrap_err()),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(circle_stream_commits(&pool, &stream).await, 0);

    let circle_join = circle_request(
        &grant.authority_commit,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "join", Value::Null, Some(&first_parent)),
    );
    uow.commit_event(circle_join.clone()).await.unwrap();
    let joined = circle_member(&pool, &circle, &alice).await;
    assert!(joined.effective);
    assert_eq!(joined.value["parent_membership_revision"], first_parent);
    assert!(circle_scan_authorized(&store, &stream, &alice).await);

    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::circle(
        realm.clone(),
        circle.clone(),
        None,
        0,
        0,
        0,
    )
    .unwrap();
    let payload = json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref":format!("ak:blob:sha256:{}", "3".repeat(64)),
        "ratchet_tree_ref":format!("ak:blob:sha256:{}", "4".repeat(64)),
        "creator_leaf_authority":{
            "leaf_signature_key_b64u":arkret_canonical::base64url_encode([7_u8;32]),
            "endpoint":{"kind":"device","device_id":format!("ak:device:{}",uuid::Uuid::now_v7())},
            "authorization_event_ref":arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[8_u8;32]),
        },
        "governance_binding":binding,
        "created_at":arkret_canonical::format_timestamp_canonical(at),
    });
    let event = ordinary_realm::event_for_actor(
        EventKind::MlsGenesis,
        ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle.clone(),
        },
        alice.clone(),
        payload.clone(),
        at,
    );
    let mut genesis = sourced(ordinary_realm::request_for_event(
        &circle_join.authority_commit,
        event,
        at,
    ));
    genesis.authority_commit.commit.stream_ref = stream.clone();
    genesis.authority_commit.mls_state = Some(soland_storage::MlsStateInstallation {
        effective_scope: ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle.clone(),
        },
        base: None,
        epoch: 0,
        public_state: b"circle-public-state".to_vec(),
        member_principals: Default::default(),
        consumed_proposals: Vec::new(),
        genesis_blobs: Vec::new(),
    });
    let activated = history == "since_join";
    if activated {
        uow.commit_event(genesis.clone()).await.unwrap();
    } else {
        assert_eq!(
            refusal_code(&uow.commit_event(genesis.clone()).await.unwrap_err()),
            Some(ConflictCode::FailedPrecondition)
        );
        assert_eq!(circle_stream_commits(&pool, &stream).await, 1);
    }
    let material_request =
        arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody {
            realm_id: realm.clone(),
            effective_scope: genesis.authority_commit.event.scope_ref.clone(),
            mls_group_id: binding.mls_group_id().unwrap(),
            epoch: Default::default(),
            group_state_event_id: genesis.authority_commit.event.event_id.clone(),
            caller_actor_id: Some(alice.clone()),
            target_commit_event_ref: Some(genesis.authority_commit.event.event_id.clone()),
            target_epoch: Some(0),
            group_info_ref: serde_json::from_value(payload["group_info_ref"].clone()).unwrap(),
            ratchet_tree_ref: serde_json::from_value(payload["ratchet_tree_ref"].clone()).unwrap(),
            max_response_bytes: None,
        };
    let roster_request =
        arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody {
            realm_id: realm.clone(),
            effective_scope: material_request.effective_scope.clone(),
            mls_group_id: material_request.mls_group_id.clone(),
            genesis_event_ref: material_request.group_state_event_id.clone(),
            target_commit_event_ref: material_request.target_commit_event_ref.clone().unwrap(),
            target_epoch: 0,
            caller_actor_id: alice.clone(),
            cursor: None,
        };
    if activated {
        assert!(matches!(
            store
                .mls_member_group_state_material_read(
                    &material_request,
                    &ordinary_realm::station(),
                    None
                )
                .await
                .unwrap(),
            soland_storage::MlsMemberGroupStateMaterialRead::Authorized { genesis: Some(_) }
        ));
        assert!(matches!(
            store
                .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
                .await
                .unwrap(),
            soland_storage::MlsRosterAuthorityRead::Authorized { facts: Some(_) }
        ));
    }
    let circle_head = if activated {
        genesis.authority_commit.clone()
    } else {
        circle_join.authority_commit.clone()
    };

    // A renewed since-join Circle floor hides the old MLS target. The
    // all-history fixture has no accepted MLS target to disclose.
    let same_parent_leave = circle_request(
        &circle_head,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "leave", json!("join"), None),
    );
    uow.commit_event(same_parent_leave.clone()).await.unwrap();
    let same_parent_join = circle_request(
        &same_parent_leave.authority_commit,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "join", json!("leave"), Some(&first_parent)),
    );
    uow.commit_event(same_parent_join.clone()).await.unwrap();
    let answer = store
        .mls_member_group_state_material_read(&material_request, &ordinary_realm::station(), None)
        .await
        .unwrap();
    let roster = store
        .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
        .await
        .unwrap();
    {
        assert!(matches!(
            answer,
            soland_storage::MlsMemberGroupStateMaterialRead::NotFound
        ));
        assert!(matches!(
            roster,
            soland_storage::MlsRosterAuthorityRead::NotFound
        ));
    }
    let joined = circle_member(&pool, &circle, &alice).await;
    let circle_head = same_parent_join.authority_commit.clone();

    // Parent leave: the old Circle join is effective-invalid at once; no
    // Circle Event is synthesized and the canonical row is not rewritten.
    let realm_leave = realm_membership(
        &grant.authority_commit,
        &alice,
        &alice,
        "leave",
        "parent leave",
    );
    uow.commit_event(realm_leave.clone()).await.unwrap();
    let after_leave = circle_member(&pool, &circle, &alice).await;
    assert!(!after_leave.effective);
    assert_eq!(after_leave.membership, "join");
    assert_eq!(after_leave.current_commit_id, joined.current_commit_id);
    assert_eq!(after_leave.value, joined.value);
    assert_eq!(
        circle_stream_commits(&pool, &stream).await,
        if activated { 4 } else { 3 }
    );
    assert!(!circle_scan_authorized(&store, &stream, &alice).await);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(
                &material_request,
                &ordinary_realm::station(),
                None
            )
            .await
            .unwrap(),
        soland_storage::MlsMemberGroupStateMaterialRead::NotFound
    ));
    assert!(matches!(
        store
            .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
            .await
            .unwrap(),
        soland_storage::MlsRosterAuthorityRead::NotFound
    ));

    // Parent rejoin: a new revision never revives the old Circle join.
    let rejoin = realm_membership(
        &realm_leave.authority_commit,
        &alice,
        &alice,
        "join",
        "parent rejoin",
    );
    uow.commit_event(rejoin.clone()).await.unwrap();
    let second_parent = ordinary_realm::parent_membership_revision(&pool, &realm, &alice).await;
    assert_ne!(second_parent, first_parent);
    let after_rejoin = circle_member(&pool, &circle, &alice).await;
    assert!(!after_rejoin.effective);
    assert_eq!(after_rejoin.value, joined.value);
    assert_eq!(
        circle_stream_commits(&pool, &stream).await,
        if activated { 4 } else { 3 }
    );
    assert!(!circle_scan_authorized(&store, &stream, &alice).await);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(
                &material_request,
                &ordinary_realm::station(),
                None
            )
            .await
            .unwrap(),
        soland_storage::MlsMemberGroupStateMaterialRead::NotFound
    ));
    assert!(matches!(
        store
            .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
            .await
            .unwrap(),
        soland_storage::MlsRosterAuthorityRead::NotFound
    ));
    // The old revision is no longer the parent current join.
    let stale = circle_request(
        &circle_head,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "join", json!("leave"), Some(&first_parent)),
    );
    assert_eq!(
        refusal_code(&uow.commit_event(stale).await.unwrap_err()),
        Some(ConflictCode::FailedPrecondition)
    );
    // A leave never carries the revision.
    let misplaced = circle_request(
        &circle_head,
        &circle,
        &alice,
        circle_membership(
            &circle,
            &alice,
            "leave",
            json!("join"),
            Some(&second_parent),
        ),
    );
    assert!(matches!(
        uow.commit_event(misplaced).await.unwrap_err(),
        PersistenceError::SchemaViolation(_)
    ));
    // Only an explicit leave then a new join bound to the new revision
    // restores the Circle.
    let circle_leave = circle_request(
        &circle_head,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "leave", json!("join"), None),
    );
    uow.commit_event(circle_leave.clone()).await.unwrap();
    let circle_rejoin = circle_request(
        &circle_leave.authority_commit,
        &circle,
        &alice,
        circle_membership(
            &circle,
            &alice,
            "join",
            json!("leave"),
            Some(&second_parent),
        ),
    );
    uow.commit_event(circle_rejoin.clone()).await.unwrap();
    let restored = circle_member(&pool, &circle, &alice).await;
    assert!(restored.effective);
    assert_eq!(restored.value["parent_membership_revision"], second_parent);
    // Even all-history policy cannot authorize a historical Circle cut whose
    // join belongs to the previous parent Realm join instance.
    assert!(matches!(
        store
            .mls_member_group_state_material_read(
                &material_request,
                &ordinary_realm::station(),
                None
            )
            .await
            .unwrap(),
        soland_storage::MlsMemberGroupStateMaterialRead::NotFound
    ));
    assert!(matches!(
        store
            .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
            .await
            .unwrap(),
        soland_storage::MlsRosterAuthorityRead::NotFound
    ));
    assert!(circle_scan_authorized(&store, &stream, &alice).await);

    // Parent ban invalidates exactly like leave.
    let ban = realm_membership(
        &rejoin.authority_commit,
        &creator,
        &alice,
        "ban",
        "parent ban",
    );
    uow.commit_event(ban).await.unwrap();
    let after_ban = circle_member(&pool, &circle, &alice).await;
    assert!(!after_ban.effective);
    assert_eq!(after_ban.value, restored.value);
    assert_eq!(
        circle_stream_commits(&pool, &stream).await,
        if activated { 6 } else { 5 }
    );
    assert!(!circle_scan_authorized(&store, &stream, &alice).await);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(
                &material_request,
                &ordinary_realm::station(),
                None
            )
            .await
            .unwrap(),
        soland_storage::MlsMemberGroupStateMaterialRead::NotFound
    ));
    assert!(matches!(
        store
            .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
            .await
            .unwrap(),
        soland_storage::MlsRosterAuthorityRead::NotFound
    ));
}
