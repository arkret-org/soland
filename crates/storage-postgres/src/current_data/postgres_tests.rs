//! These tests exercise the same SQL transaction helper called by Event UoW;
//! signature/admission fixtures belong to the HTTP contract suite.
use arkret_canonical::DigestSuite;
use arkret_wire::{AccountId, ActorId, Event, ScopeRef};
use diesel_async::AsyncConnection;
use serde_json::json;

use super::*;

async fn persist(pool: &crate::PgPool, event: Event) -> PersistenceResult<()> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<(),crate::PgTransactionError,_>(async |conn| {
        let token=event.event_id.token_bytes();
        let bytes=arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,actor_seq,realm_id,kind,schema_id,canonical_bytes,envelope) VALUES($1,1,$2,$3,$4,$5,$6,'fixture',$7,$8)")
            .bind::<Binary,_>(token.to_vec()).bind::<Binary,_>(token[1..].to_vec())
            .bind::<Text,_>(event.actor_id.canonical_key().unwrap()).bind::<diesel::sql_types::BigInt,_>(event.actor_seq as i64)
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.kind.as_str())
            .bind::<Binary,_>(bytes).bind::<Jsonb,_>(serde_json::to_value(&event).unwrap()).execute(&mut *conn).await?;
        commit_sources(conn,&event,DigestSuite::Sha256).await?;
        Ok(())
    }).await.map_err(crate::PgTransactionError::into_persistence)
}

fn source(
    kind: &str,
    realm: &arkret_wire::RealmId,
    actor: &ActorId,
    seq: u64,
    payload: Value,
    bases: &[&Event],
) -> Event {
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-10T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor.clone(),
        seq,
        "000000000001-0000-00000000".parse().unwrap(),
        payload,
        now,
    )
    .unwrap();
    event.causal_refs = bases
        .iter()
        .map(|base| {
            base.event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    event.event_id = event
        .derive_event_id_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    event
}

#[tokio::test]
async fn concurrent_causal_sources_keep_distinct_full_heads_and_failed_patch_is_atomic() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"current MV realm"),
    ));
    let actor = ActorId::account(AccountId::new(
        "ak:did_core:web:current.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let create = source(
        "ak.strand.create",
        &realm,
        &actor,
        1,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"metadata":{"title":"base","summary":"original"},
            "tracks":{"synthesis":{"enabled":true,"is_primary":true}},"created_by":actor,"created_at":"2026-09-10T00:00:00.000Z"
        }}),
        &[],
    );
    persist(&pool, create.clone()).await.unwrap();
    let id = arkret_wire::StrandId::from_event_id(&create.event_id);
    let left = source(
        "ak.strand.update",
        &realm,
        &actor,
        2,
        json!({"target_ref":id,"patch":{"metadata.title":{"$op":"set","value":"left"}}}),
        &[&create],
    );
    let right = source(
        "ak.strand.update",
        &realm,
        &actor,
        3,
        json!({"target_ref":id,"patch":{"metadata.summary":{"$op":"set","value":"right"}}}),
        &[&create],
    );
    let (a, b) = tokio::join!(persist(&pool, left.clone()), persist(&pool, right.clone()));
    a.unwrap();
    b.unwrap();
    #[derive(QueryableByName)]
    struct Payload {
        #[diesel(sql_type=Jsonb)]
        payload: Value,
    }
    let mut conn = pool.get().await.unwrap();
    let current = sql_query("SELECT payload FROM current_result_heads WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Payload>(&mut *conn)
        .await
        .unwrap()
        .payload;
    let heads = current["result"]["heads"].as_array().unwrap();
    assert_eq!(heads.len(), 2);
    assert!(
        heads
            .iter()
            .any(|head| head["value"]["metadata"] == json!({"title":"left","summary":"original"}))
    );
    assert!(
        heads
            .iter()
            .any(|head| head["value"]["metadata"] == json!({"title":"base","summary":"right"}))
    );
    let invalid = source(
        "ak.strand.update",
        &realm,
        &actor,
        4,
        json!({"target_ref":id,"patch":{"metadata.title":{"$op":"set","value":"invalid"}}}),
        &[&left, &right],
    );
    assert_eq!(
        persist(&pool, invalid.clone())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::ReducerProjectionFailed),
    );
    let count = sql_query("SELECT count(*) AS revision FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(invalid.event_id.token_bytes().to_vec())
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .revision;
    assert_eq!(
        count, 0,
        "rejected source must roll back accepted insertion"
    );
    let selected = heads
        .iter()
        .find(|head| head["event_id"] == left.event_id.as_str())
        .unwrap();
    let selected_digest = arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(&selected["value"]).unwrap(),
    );
    let merged = source(
        "ak.strand.update",
        &realm,
        &actor,
        8,
        json!({"target_ref":id,"expected_state_digest":selected_digest,
            "patch":{"metadata.summary":{"$op":"set","value":"right"}}}),
        &[&left, &right],
    );
    persist(&pool, merged.clone()).await.unwrap();
    let merged_current = sql_query("SELECT payload FROM current_result_heads WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Payload>(&mut *conn)
        .await
        .unwrap()
        .payload;
    assert_eq!(
        merged_current["result"]["heads"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        merged_current["result"]["heads"][0]["value"]["metadata"],
        json!({"title":"left","summary":"right"})
    );
    let absent = source(
        "ak.strand.update",
        &realm,
        &actor,
        99,
        json!({"target_ref":id,"patch":{"metadata.title":{"$op":"set","value":"not received"}}}),
        &[&create],
    );
    let waiting = source(
        "ak.strand.update",
        &realm,
        &actor,
        6,
        json!({"target_ref":id,"patch":{"metadata.title":{"$op":"set","value":"waiting"}}}),
        &[&absent],
    );
    assert_eq!(
        persist(&pool, waiting.clone())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::DependencyMissing)
    );
    let count = sql_query("SELECT count(*) AS revision FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(waiting.event_id.token_bytes().to_vec())
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .revision;
    assert_eq!(
        count, 0,
        "missing dependency cannot be acknowledged as accepted"
    );
    let foreign_cell = arkret_wire::StrandId::from_event_id(&absent.event_id);
    let wrong_cell = source(
        "ak.strand.update",
        &realm,
        &actor,
        7,
        json!({"target_ref":foreign_cell,"patch":{"metadata.title":{"$op":"set","value":"wrong cell"}}}),
        &[&create],
    );
    assert_eq!(
        persist(&pool, wrong_cell)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::ReducerProjectionFailed)
    );
    let successor = source(
        "ak.strand.update",
        &realm,
        &actor,
        5,
        json!({"target_ref":id,"patch":{"metadata.title":{"$op":"set","value":"successor"}}}),
        &[&left],
    );
    persist(&pool, successor.clone()).await.unwrap();
    sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(left.event_id.token_bytes().to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    let unavailable = sql_query(
        "SELECT count(*) AS revision FROM current_data_sources WHERE event_id=$1 AND NOT available",
    )
    .bind::<Binary, _>(successor.event_id.token_bytes().to_vec())
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap()
    .revision;
    assert_eq!(
        unavailable, 1,
        "withdrawing a base invalidates its derived post-state"
    );
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type=diesel::sql_types::BigInt)]
    revision: i64,
}

#[tokio::test]
async fn pin_assertions_converge_causally_and_cross_cell_withdrawal_marks_pending() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"pin fold realm"),
    ));
    let actor = ActorId::account(AccountId::new(
        "ak:did_core:web:pin.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let other = ActorId::account(AccountId::new(
        "ak:did_core:web:other.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let payload = json!({"pin_scope":{"kind":"realm","id":realm},"target_ref":realm,"rank":"a"});
    let add = source("ak.pin.add", &realm, &actor, 1, payload.clone(), &[]);
    persist(&pool, add.clone()).await.unwrap();
    let remove = source(
        "ak.pin.remove",
        &realm,
        &other,
        1,
        json!({"pin_scope":payload["pin_scope"],"target_ref":realm}),
        &[],
    );
    persist(&pool, remove.clone()).await.unwrap();
    let cell = format!("ak:cell:ak.component.pin.v1:{realm}");
    async fn read(pool: &crate::PgPool, cell: &str) -> Value {
        #[derive(QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            payload: Value,
        }
        let mut conn = pool.get().await.unwrap();
        sql_query(
            "SELECT payload FROM current_result_heads WHERE payload->'selector'->>'cell_id'=$1",
        )
        .bind::<Text, _>(cell)
        .get_result::<Row>(&mut conn)
        .await
        .unwrap()
        .payload
    }
    let conflict = read(&pool, &cell).await;
    assert_eq!(conflict["result"]["value"]["pins"], json!([]));
    assert_eq!(
        conflict["result"]["value"]["conflicts"][0]["source_event_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let resolve = source(
        "ak.pin.add",
        &realm,
        &actor,
        2,
        payload.clone(),
        &[&add, &remove],
    );
    persist(&pool, resolve.clone()).await.unwrap();
    let bridge_scope = arkret_wire::StrandId::from_event_id(&add.event_id);
    let bridge = source(
        "ak.pin.add",
        &realm,
        &actor,
        3,
        json!({"pin_scope":{"kind":"strand","id":bridge_scope},"target_ref":realm,"rank":"b"}),
        &[&resolve],
    );
    persist(&pool, bridge.clone()).await.unwrap();
    let reorder = source(
        "ak.pin.reorder",
        &realm,
        &actor,
        4,
        json!({"pin_scope":payload["pin_scope"],"target_ref":realm,"rank":"z","expected_rank":"a"}),
        &[&bridge],
    );
    persist(&pool, reorder.clone()).await.unwrap();
    let current = read(&pool, &cell).await;
    assert_eq!(current["result"]["value"]["pins"][0]["pin"]["rank"], "z");
    let bad = source(
        "ak.pin.remove",
        &realm,
        &actor,
        5,
        json!({"pin_scope":payload["pin_scope"],"target_ref":realm,"expected_rank":"wrong"}),
        &[&reorder],
    );
    assert_eq!(
        persist(&pool, bad.clone())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::FailedPrecondition)
    );
    let mut conn = pool.get().await.unwrap();
    sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(bridge.event_id.token_bytes().to_vec())
        .execute(&mut conn)
        .await
        .unwrap();
    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let pending =
        sql_query("SELECT count(*)::bigint AS count FROM current_data_pending WHERE cell_id=$1")
            .bind::<Text, _>(&cell)
            .get_result::<Count>(&mut conn)
            .await
            .unwrap();
    assert_eq!(pending.count, 1);
    let absent = sql_query("SELECT count(*)::bigint AS count FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(bad.event_id.token_bytes().to_vec())
        .get_result::<Count>(&mut conn)
        .await
        .unwrap();
    assert_eq!(absent.count, 0);
}

#[tokio::test]
async fn conditional_space_metadata_is_published_without_a_seal() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"ordinary conditional Space"),
    ));
    let actor = ActorId::account(AccountId::new(
        "ak:did_core:web:current.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let create = source(
        "ak.space.create",
        &realm,
        &actor,
        1,
        json!({"object":{"schema":"ak.schema.space.v1","realm_id":realm,"kind":"folder","title":"before","created_by":actor,"created_at":"2026-09-10T00:00:00.000Z"}}),
        &[],
    );
    persist(&pool, create.clone()).await.unwrap();
    let space_id = arkret_wire::SpaceId::from_event_id(&create.event_id);
    let update = source(
        "ak.space.update",
        &realm,
        &actor,
        2,
        json!({"space_id":space_id,"patch":{"title":{"$op":"set","value":"after"}}}),
        &[&create],
    );
    assert_eq!(
        arkret_schema::classify_event_execution(&update).unwrap(),
        Some(arkret_wire::CbsEffectPlane::Data)
    );
    persist(&pool, update.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let value = sql_query("SELECT source_value FROM current_data_sources WHERE event_digest=$1")
        .bind::<Text, _>(
            update
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .get_result::<SourceRow>(&mut conn)
        .await
        .unwrap()
        .source_value;
    assert_eq!(value["title"], "after");
}

/// Exercise the real composite Seal transaction, including a Data-only member
/// after the command leader. Admission and rejected outcomes cannot leak it.
#[tokio::test]
async fn committed_unit_publishes_nonfirst_data_member_and_rejected_unit_publishes_nothing() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use arkret_state::state::store::{
        AcklessSelfPrincipalIngress, ControlProposalIngress, ControlUnitIngressMember,
    };
    use arkret_wire::{CommandOutcome, Seal, SealCommandOutcome};
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let registry = Arc::new(
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap(),
    );
    let stores = crate::build_state_resolution_stores(Some(pool.clone()), registry);
    let actor = ActorId::account(AccountId::new(
        "ak:did_core:web:current.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    for (index, outcome) in [CommandOutcome::Committed, CommandOutcome::Rejected]
        .into_iter()
        .enumerate()
    {
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(format!("current unit {index}")),
        ));
        let command = source(
            "ak.test.control",
            &realm,
            &actor,
            (index * 2 + 10) as u64,
            json!({}),
            &[],
        );
        let data = source(
            "ak.space.create",
            &realm,
            &actor,
            (index * 2 + 11) as u64,
            json!({"object":{"schema":"ak.schema.space.v1","realm_id":realm,"kind":"folder","title":"sealed","created_by":actor,"created_at":"2026-09-10T00:00:00.000Z"}}),
            &[],
        );
        let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "fixture".into(),
            device_authorize_event_id: "fixture".into(),
            device_generation_ref: 1,
            seal_basis_digest: "fixture".into(),
        });
        let digests = stores
            .control_event_store
            .put_pending_unit_with_ingress(
                &[command.clone(), data.clone()]
                    .into_iter()
                    .map(|event| ControlUnitIngressMember {
                        event,
                        digest_suite: DigestSuite::Sha256,
                        ingress: ingress.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        persist(&pool, command.clone()).await.unwrap();
        persist(&pool, data.clone()).await.unwrap();
        let count_sources = async || {
            let mut conn = pool.get().await.unwrap();
            #[derive(QueryableByName)]
            struct Count {
                #[diesel(sql_type=diesel::sql_types::BigInt)]
                count: i64,
            }
            sql_query(
                "SELECT count(*)::bigint AS count FROM current_data_sources WHERE realm_id=$1",
            )
            .bind::<Text, _>(realm.as_str())
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count
        };
        assert_eq!(
            count_sources().await,
            0,
            "a registered Data member is pending with its whole unit"
        );
        let result = match outcome {
            CommandOutcome::Committed => SealCommandOutcome::committed(
                digests[0].clone(),
                digests.clone(),
                Vec::new(),
                DigestSuite::Sha256,
            )
            .unwrap(),
            CommandOutcome::Rejected => SealCommandOutcome::rejected(
                digests[0].clone(),
                digests.clone(),
                "state_mismatch".parse().unwrap(),
                DigestSuite::Sha256,
            )
            .unwrap(),
        };
        let covered = BTreeSet::new();
        let placeholder = arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let mut seal = Seal {
            id: format!("ak:seal:{placeholder}").parse().unwrap(),
            realm_id: realm.clone(),
            predecessor_ref: None,
            delta: vec![],
            control_event_set_root: arkret_state::state::control_event_set_root(
                &covered,
                DigestSuite::Sha256,
            )
            .unwrap(),
            state_root: arkret_state::state::compute_state_root(
                arkret_state::GovernanceView::new(&BTreeMap::new()),
                DigestSuite::Sha256,
            )
            .unwrap(),
            notary_seq: 0,
            availability_receipt_digests: vec![],
            covered_event_digests: vec![],
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: arkret_wire::MultiSignature {
                kind: arkret_wire::MultiSigKind::MultiSig,
                view: 0,
                signatures: vec![arkret_wire::SealSignature {
                    verification_method: "did:web:station.example#notary".parse().unwrap(),
                    payload_digest: placeholder,
                    jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".into(),
                }],
            },
            sealed_at: chrono::Utc::now(),
            hlc: "019f00000000-0000-00000001".parse().unwrap(),
            configuration_ref: command.event_id.clone(),
            command_results: vec![result],
            authorization_closures: vec![],
            existence_anchors: vec![],
            transaction_records: vec![],
        };
        seal.id = seal.derive_id(DigestSuite::Sha256).unwrap();
        assert!(
            stores
                .event_seal_committer
                .commit_if_head(&seal, DigestSuite::Sha256, None, &[], &covered, &[])
                .await
                .unwrap()
        );
        assert_eq!(
            count_sources().await > 0,
            outcome == CommandOutcome::Committed
        );
        let decided = stores
            .control_event_store
            .control_proposal_snapshot(&digests[1])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decided.command_decisions[0].member_index, 1);
        assert_eq!(decided.command_decisions[0].outcome, outcome);
    }
}
