//! Storage-boundary tests: checkpoints are seeded as already verified inputs.
//! These are not substitutes for Realm/Seal admission tests.

use super::*;

#[tokio::test]
async fn unwritten_realm_singletons_publish_confirmed_empty_baseline() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = pg_conn(&database.pool()).await.unwrap();
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [46; 32],
    ));
    assert!(baseline_missing(&mut conn, realm.as_str()).await.unwrap());
    conn.transaction::<_, EventSealCommitError, _>(async |conn| {
        let revision = crate::current_results::next_revision(conn)
            .await
            .map_err(persistence_to_store)?;
        publish(
            conn,
            realm.as_str(),
            &BTreeMap::new(),
            revision as i64,
            &BTreeMap::new(),
            true,
        )
        .await
    })
    .await
    .unwrap();
    assert!(!baseline_missing(&mut conn, realm.as_str()).await.unwrap());
    let policy = sql_query("SELECT payload AS value FROM current_result_heads WHERE realm_id=$1 AND payload->'selector'->>'cell_id'='ak:cell:ak.component.realm.policy.v1:null'")
        .bind::<Text,_>(realm.as_str()).get_result::<JsonRow>(&mut *conn).await.unwrap().value;
    assert_eq!(
        policy["result"],
        serde_json::json!({"status":"value","value":null})
    );
    // Confirmed absence is not authority: a missing genesis still fails closed.
    let pending = sql_query(
        "SELECT COUNT(*) AS value FROM governance_current_ready WHERE realm_id=$1 AND NOT ready",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    assert_eq!(pending, 1);
}

async fn checkpoint(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    name: u8,
    view: &StoredCheckpointView,
    covered: &[String],
) -> String {
    let seal = format!("ak:seal:sha256:{}", format!("{name:02x}").repeat(32));
    sql_query("INSERT INTO state_seals(id,digest_suite,realm_id,seal_id_preimage_bytes,accepted_seal_bytes,seal_json) VALUES($1,'sha256',$2,$3,$3,'{}')")
        .bind::<Text,_>(&seal).bind::<Text,_>(realm.as_str()).bind::<Binary,_>(vec![name]).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO state_seal_effective_checkpoints(seal_id,realm_id,covered_event_digests,covered_seal_ids,state_json) VALUES($1,$2,$3,$4,$5)")
        .bind::<Text,_>(&seal).bind::<Text,_>(realm.as_str()).bind::<Array<Text>,_>(covered)
        .bind::<Array<Text>,_>(vec![seal.clone()]).bind::<Jsonb,_>(serde_json::to_value(view).unwrap()).execute(conn).await.unwrap();
    seal
}

#[tokio::test]
async fn current_mv_cache_keeps_concurrent_sources_and_rejects_missing_or_stale_basis() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = pg_conn(&database.pool()).await.unwrap();
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [43; 32],
    ));
    let cell = CellRef::new("ak:cell:ak.component.agent.selector_claim.v1:claim").unwrap();
    let context = CheckpointRuleContext::Stable {
        digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
    };
    let mut leaves = Vec::new();
    for byte in [1, 2] {
        let head = CurrentMvHead {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [byte; 32],
            ),
            value: serde_json::json!({"value":byte}),
        };
        let covered = vec![head.event_id.event_digest().to_string()];
        let view = StoredCheckpointView {
            cells: BTreeMap::new(),
            cas_heads: Default::default(),
            rule_context: context.clone(),
            current_mv_heads: BTreeMap::from([(cell.clone(), vec![head])]),
            current_mv_ready: true,
        };
        leaves.push(checkpoint(&mut conn, &realm, byte, &view, &covered).await);
    }
    let (heads, ready) = advance_mv_heads(&mut conn, realm.as_str(), &leaves, &[], &context)
        .await
        .unwrap();
    assert!(ready);
    assert_eq!(heads[&cell].len(), 2);
    let missing = format!("ak:seal:sha256:{}", "33".repeat(32));
    let (_, ready) = advance_mv_heads(&mut conn, realm.as_str(), &[missing], &[], &context)
        .await
        .unwrap();
    assert!(!ready);
    let (_, ready) = advance_mv_heads(
        &mut conn,
        realm.as_str(),
        &leaves,
        &[],
        &CheckpointRuleContext::Unavailable {},
    )
    .await
    .unwrap();
    assert!(!ready);
}

#[tokio::test]
async fn expired_agent_current_result_refreshes_atomically_and_partial_view_stays_unavailable() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pg_conn(&pool).await.unwrap();
    let principal = arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let event = arkret_wire::test_support::raw_event(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        principal.clone(),
        station,
        1,
        arkret_wire::Hlc::new("019f00000000-0001-aabbccdd").unwrap(),
        serde_json::json!({"object":{"purpose":"agent_control"}}),
    )
    .unwrap();
    let realm = event.realm_id.clone();
    sql_query("INSERT INTO state_control_events(event_digest,digest_suite,realm_id,event_json,ingress_class,is_pending) VALUES($1,'sha256',$2,$3,'{}',FALSE)")
        .bind::<Text,_>(event.event_id.event_digest().as_str()).bind::<Text,_>(realm.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&event).unwrap()).execute(&mut *conn).await.unwrap();
    let status = CellRef::new(format!(
        "ak:cell:ak.component.agent.status.v1:{}",
        arkret_wire::composite_subject(&[event.actor_id.canonical_key().unwrap()]).unwrap()
    ))
    .unwrap();
    let key = CellRef::new(format!(
        "ak:cell:ak.component.agent.key.v1:{}",
        arkret_wire::composite_subject(&[principal.as_str(), "runtime-key"]).unwrap()
    ))
    .unwrap();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let scope_key =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&scope).unwrap()).unwrap();
    for cell in [&status, &key] {
        sql_query("INSERT INTO current_selector_origins(realm_id,cell_id,scope_key,selector,target,source_event_id) VALUES($1,$2,$3,$4,$5,$6)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(cell.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Jsonb,_>(serde_json::json!({"scope_ref":scope,"cell_id":cell})).bind::<Jsonb,_>(serde_json::json!({"kind":"realm"}))
            .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await.unwrap();
    }
    let expiry = chrono::Utc::now() - chrono::Duration::seconds(1);
    let raw = serde_json::json!([agent_keys::tests::authorization(
        4,
        &arkret_canonical::format_timestamp_canonical(expiry),
        &["ak.self.account.stream.subscribe.v1"],
        &["https://station.example"]
    )]);
    let cells = BTreeMap::from([
        (status, CellState::Value(Value::String("active".into()))),
        (key.clone(), CellState::Value(raw.clone())),
    ]);
    let registry =
        soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap();
    let context = CheckpointRuleContext::capture(&registry, &realm).unwrap();
    assert!(context.reusable_with(&context));
    let view = StoredCheckpointView {
        cells,
        cas_heads: Default::default(),
        rule_context: context,
        current_mv_heads: Default::default(),
        current_mv_ready: true,
    };
    checkpoint(
        &mut conn,
        &realm,
        9,
        &view,
        &[event.event_id.event_digest().to_string()],
    )
    .await;
    let active = agent_keys::fold(
        &raw,
        &BTreeMap::from([(
            principal.to_string(),
            CellState::Value(Value::String("active".into())),
        )]),
        expiry - chrono::Duration::seconds(1),
    )
    .unwrap()
    .0;
    let selector = serde_json::json!({"scope_ref":scope,"cell_id":key});
    let initial=conn.transaction::<_,EventSealCommitError,_>(async |conn| {
        let revision=crate::current_results::next_revision(conn).await.map_err(persistence_to_store)?;
        let entry=CurrentResultEntry::try_from_json(serde_json::json!({"selector":selector,"target":{"kind":"realm"},"revision":revision,"result":active})).unwrap();
        crate::current_results::publish_entries(conn,&[entry]).await.map_err(persistence_to_store)?;
        sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision,next_expiry) VALUES($1,TRUE,$2,$3)")
            .bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(revision as i64).bind::<Timestamptz,_>(expiry).execute(conn).await?;
        Ok(revision)
    }).await.unwrap();
    conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
        refresh_current_if_expired(conn, realm.as_str(), &registry).await?;
        Ok(())
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
    .unwrap();
    let current = sql_query(
        "SELECT payload AS value FROM current_result_heads WHERE realm_id=$1 AND selector_key=$2",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(
        String::from_utf8(arkret_canonical::canonical_json_bytes(&selector).unwrap()).unwrap(),
    )
    .get_result::<JsonRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    assert_eq!(current["result"]["value"]["reason"], "expired");
    assert!(current["revision"].as_u64().unwrap() > initial);
    let pending=sql_query("SELECT COUNT(*) AS value FROM governance_current_ready WHERE realm_id=$1 AND NOT ready AND next_expiry IS NULL")
        .bind::<Text,_>(realm.as_str()).get_result::<CountRow>(&mut *conn).await.unwrap().value;
    // This intentionally partial storage fixture has no Realm genesis cell;
    // expiry repair must not turn missing current coverage into completion.
    assert_eq!(pending, 1);
}

#[tokio::test]
async fn stale_mv_checkpoint_rebuilds_from_seal_ancestry_not_arrival_order() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pg_conn(&pool).await.unwrap();
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [45; 32],
    ));
    let cell = CellRef::new("ak:cell:ak.component.agent.selector_claim.v1:claim").unwrap();
    let old = CheckpointRuleContext::Stable {
        digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
    };
    let fresh = CheckpointRuleContext::Stable {
        digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
    };
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:principal.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let empty = StoredCheckpointView {
        cells: Default::default(),
        cas_heads: Default::default(),
        rule_context: old,
        current_mv_heads: Default::default(),
        current_mv_ready: false,
    };
    let mut seals = Vec::<String>::new();
    let mut coverage = Vec::<Vec<String>>::new();
    // A -> B and A -> C. D is a successor of B with no write. C arriving last
    // cannot erase B. Both writes in B share one frozen parent view.
    for (index, parent, sources) in [
        (0, None, vec![1u8]),
        (1, Some(0), vec![2, 3]),
        (2, Some(1), vec![]),
        (3, Some(0), vec![4]),
    ] {
        let mut covered = parent.map(|p| coverage[p].clone()).unwrap_or_default();
        covered.extend(
            sources
                .iter()
                .map(|b| format!("sha256:{}", format!("{b:02x}").repeat(32))),
        );
        let seal = format!(
            "ak:seal:sha256:{}",
            format!("{:02x}", index + 11).repeat(32)
        );
        let ancestors = parent
            .map(|p| {
                if p == 1 {
                    vec![seals[0].clone(), seals[1].clone()]
                } else {
                    vec![seals[p].clone()]
                }
            })
            .unwrap_or_default();
        let parents: Vec<String> = parent.map(|p| vec![seals[p].clone()]).unwrap_or_default();
        let closure = ancestors
            .into_iter()
            .chain(std::iter::once(seal.clone()))
            .collect::<Vec<_>>();
        sql_query("INSERT INTO state_seals(id,digest_suite,realm_id,seal_id_preimage_bytes,accepted_seal_bytes,seal_json,predecessor_refs) VALUES($1,'sha256',$2,$3,$3,'{}',$4)")
            .bind::<Text,_>(&seal).bind::<Text,_>(realm.as_str()).bind::<Binary,_>(vec![index as u8+11]).bind::<Jsonb,_>(serde_json::json!(parents)).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO state_seal_effective_checkpoints(seal_id,realm_id,covered_event_digests,covered_seal_ids,state_json) VALUES($1,$2,$3,$4,$5)")
            .bind::<Text,_>(&seal).bind::<Text,_>(realm.as_str()).bind::<Array<Text>,_>(&covered).bind::<Array<Text>,_>(&closure).bind::<Jsonb,_>(serde_json::to_value(&empty).unwrap()).execute(&mut *conn).await.unwrap();
        for (offset, source) in sources.into_iter().enumerate() {
            let digest = format!("sha256:{}", format!("{source:02x}").repeat(32));
            let op = serde_json::json!({"issuer_id":actor,"move_id":digest,"op":{"kind":"set","value":{"source":source}},"supersedes":[]});
            sql_query("INSERT INTO state_cell_ops(realm_id,seal_id,op_index,cell_id,move_id,op_json) VALUES($1,$2,$3,$4,$5,$6)")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&seal).bind::<BigInt,_>(offset as i64).bind::<Text,_>(cell.as_str()).bind::<Text,_>(&digest).bind::<Jsonb,_>(op).execute(&mut *conn).await.unwrap();
        }
        seals.push(seal);
        coverage.push(covered);
    }
    for parents in [
        vec![seals[2].clone(), seals[3].clone()],
        vec![seals[3].clone(), seals[2].clone()],
    ] {
        let (heads, ready) = advance_mv_heads(&mut conn, realm.as_str(), &parents, &[], &fresh)
            .await
            .unwrap();
        assert!(ready);
        assert_eq!(
            heads[&cell]
                .iter()
                .map(|h| h.value["source"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }
    // A missing accepted ancestor cannot be treated as an empty predecessor.
    let mut missing = seals.clone();
    missing.push(format!("ak:seal:sha256:{}", "ff".repeat(32)));
    assert!(
        rebuild_mv_heads(&mut conn, realm.as_str(), &missing, &coverage[2], &fresh)
            .await
            .unwrap()
            .is_none()
    );
}
