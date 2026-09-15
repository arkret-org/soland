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
async fn current_causal_cache_keeps_concurrent_sources_and_rejects_missing_or_stale_basis() {
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
        let head = CurrentCausalWinner {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [byte; 32],
            ),
            depth: 0,
            value: serde_json::json!({"value":byte}),
        };
        let covered = vec![head.event_id.event_digest().to_string()];
        let view = StoredCheckpointView {
            cells: BTreeMap::new(),
            rule_context: context.clone(),
            causal_winners: BTreeMap::from([(cell.clone(), head)]),
            causal_ready: true,
        };
        leaves.push(checkpoint(&mut conn, &realm, byte, &view, &covered).await);
    }
    let (heads, ready) = advance_causal_winners(&mut conn, realm.as_str(), &leaves, &[], &context)
        .await
        .unwrap();
    assert!(ready);
    assert_eq!(heads[&cell].value, serde_json::json!({"value":2}));
    let missing = format!("ak:seal:sha256:{}", "33".repeat(32));
    let (_, ready) = advance_causal_winners(&mut conn, realm.as_str(), &[missing], &[], &context)
        .await
        .unwrap();
    assert!(!ready);
    let (_, ready) = advance_causal_winners(
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
    sql_query("INSERT INTO state_control_events(event_digest,digest_suite,realm_id,event_json,ingress_class,command_unit_event_digests,is_pending) VALUES($1,'sha256',$2,$3,'{}',jsonb_build_array($1),FALSE)")
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
        (
            status,
            ResolvedCellState::Value(Value::String("active".into())),
        ),
        (key.clone(), ResolvedCellState::Value(raw.clone())),
    ]);
    let registry =
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap();
    let context = CheckpointRuleContext::capture(&registry, &realm).unwrap();
    assert!(context.reusable_with(&context));
    let view = StoredCheckpointView {
        cells,
        rule_context: context,
        causal_winners: Default::default(),
        causal_ready: true,
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
            ResolvedCellState::Value(Value::String("active".into())),
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
async fn stale_causal_checkpoint_rebuilds_from_seal_ancestry_not_arrival_order() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pg_conn(&pool).await.unwrap();
    let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [45; 32],
    ));
    let cell = CellRef::new("ak:cell:ak.component.circle.metadata.v1:circle").unwrap();
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
        rule_context: old,
        causal_winners: Default::default(),
        causal_ready: false,
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
        covered.extend(sources.iter().map(|source| {
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [*source; 32])
                .event_digest()
                .to_string()
        }));
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
        let predecessor_ref = parent.map(|p| seals[p].clone());
        let closure = ancestors
            .into_iter()
            .chain(std::iter::once(seal.clone()))
            .collect::<Vec<_>>();
        sql_query("INSERT INTO state_seals(id,digest_suite,realm_id,seal_id_preimage_bytes,accepted_seal_bytes,seal_json,predecessor_ref) VALUES($1,'sha256',$2,$3,$3,'{}',$4)")
            .bind::<Text,_>(&seal).bind::<Text,_>(realm.as_str()).bind::<Binary,_>(vec![index as u8+11]).bind::<Nullable<Text>,_>(predecessor_ref.as_deref()).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO state_seal_effective_checkpoints(seal_id,realm_id,covered_event_digests,covered_seal_ids,state_json) VALUES($1,$2,$3,$4,$5)")
            .bind::<Text,_>(&seal).bind::<Text,_>(realm.as_str()).bind::<Array<Text>,_>(&covered).bind::<Array<Text>,_>(&closure).bind::<Jsonb,_>(serde_json::to_value(&empty).unwrap()).execute(&mut *conn).await.unwrap();
        for (offset, source) in sources.into_iter().enumerate() {
            let event_id =
                EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [source; 32]);
            let op = serde_json::json!({"issuer_id":actor,"event_id":event_id,"op":{"kind":"set","value":{"source":source}},"supersedes":[]});
            sql_query("INSERT INTO state_cell_ops(realm_id,seal_id,op_index,cell_id,event_id,op_json) VALUES($1,$2,$3,$4,$5,$6)")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&seal).bind::<BigInt,_>(offset as i64).bind::<Text,_>(cell.as_str()).bind::<Text,_>(event_id.as_str()).bind::<Jsonb,_>(op).execute(&mut *conn).await.unwrap();
        }
        seals.push(seal);
        coverage.push(covered);
    }
    for parents in [
        vec![seals[2].clone(), seals[3].clone()],
        vec![seals[3].clone(), seals[2].clone()],
    ] {
        let (heads, ready) =
            advance_causal_winners(&mut conn, realm.as_str(), &parents, &[], &fresh)
                .await
                .unwrap();
        assert!(ready);
        assert_eq!(heads[&cell].value["source"].as_u64(), Some(4));
    }
    // A missing accepted ancestor cannot be treated as an empty predecessor.
    let mut missing = seals.clone();
    missing.push(format!("ak:seal:sha256:{}", "ff".repeat(32)));
    assert!(
        rebuild_causal_winners(&mut conn, realm.as_str(), &missing, &coverage[2], &fresh)
            .await
            .unwrap()
            .is_none()
    );
}

/// A Seal delta names Events by digest while `state_cell_ops` names them by
/// their typed EventId. Registration must bridge those two domains: a written
/// singleton that never registers its origin is dropped from publication and
/// permanently holds the Realm below its ready current generation.
#[tokio::test]
async fn written_realm_genesis_registers_its_origin_and_publishes_a_ready_current() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = pg_conn(&database.pool()).await.unwrap();
    let notary = arkret_wire::NotaryValue::new(
        arkret_wire::NotarySignerDescriptor {
            actor_id: ActorId::service(
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:station.example#notary-key".to_owned(),
            )
            .unwrap(),
            key_kind: arkret_wire::NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: arkret_wire::NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: "A".repeat(43),
        },
        0,
    )
    .unwrap();
    let object = serde_json::json!({
        "schema": "ak.schema.realm_genesis.v1",
        "purpose": "collaboration",
        "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "trust_domain": "ak:trust_domain:soland.test",
        "schema_refs": ["ak.schema.realm.v1"],
        "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
        "digest_algorithm": "sha256",
        "security_class": "standard",
        "encryption_profile": "none",
        "notary": notary
    });
    let event = arkret_wire::test_support::raw_event(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        arkret_wire::DidCoreId::new("ak:did_core:web:creator.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        1,
        arkret_wire::Hlc::new("019f00000000-0002-aabbccdd").unwrap(),
        serde_json::json!({ "object": object }),
    )
    .unwrap();
    let realm = event.realm_id.clone();
    let cell = CellRef::new("ak:cell:ak.component.realm.genesis.v1:null").unwrap();
    // The default Strand pointer is the one baseline singleton this Realm has
    // to write, because a causal_register current value cannot be published as
    // a confirmed absence: `account-current-result.schema.json` gives it no
    // null branch and requires its `source`.
    let strand = "ak:strand:Ab37I4k6yBlQvDmm6v80xz-BaUrFUbaPneH1V_h_N2sG";
    let pointer_cell =
        CellRef::new("ak:cell:ak.component.realm.set_default_strand.v1:null").unwrap();
    let pointer = arkret_wire::test_support::raw_event(
        "ak.realm.set_default_strand",
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        arkret_wire::DidCoreId::new("ak:did_core:web:creator.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        2,
        arkret_wire::Hlc::new("019f00000000-0003-aabbccdd").unwrap(),
        serde_json::json!({ "strand_id": strand }),
    )
    .unwrap();
    let seal = format!("ak:seal:sha256:{}", "5a".repeat(32));
    let mut delta = Vec::new();
    for (index, (source, cell_id, value)) in [
        (&event, &cell, object.clone()),
        (&pointer, &pointer_cell, Value::String(strand.to_owned())),
    ]
    .into_iter()
    .enumerate()
    {
        let digest = source.event_id.event_digest().to_string();
        sql_query("INSERT INTO state_control_events(event_digest,digest_suite,realm_id,event_json,ingress_class,command_unit_event_digests,is_pending) VALUES($1,'sha256',$2,$3,'{}',jsonb_build_array($1),FALSE)")
            .bind::<Text,_>(&digest).bind::<Text,_>(realm.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(source).unwrap()).execute(&mut *conn).await.unwrap();
        let op = serde_json::json!({"issuer_id":source.actor_id,"event_id":source.event_id,"op":{"kind":"set","value":value},"supersedes":[]});
        sql_query("INSERT INTO state_cell_ops(realm_id,seal_id,op_index,cell_id,event_id,op_json) VALUES($1,$2,$3,$4,$5,$6)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&seal).bind::<BigInt,_>(index as i64)
            .bind::<Text,_>(cell_id.as_str()).bind::<Text,_>(source.event_id.as_str())
            .bind::<Jsonb,_>(op).execute(&mut *conn).await.unwrap();
        delta.push(digest);
    }
    let cells = BTreeMap::from([
        (cell.clone(), ResolvedCellState::Value(object.clone())),
        (
            pointer_cell.clone(),
            ResolvedCellState::Value(Value::String(strand.to_owned())),
        ),
    ]);
    let winners = CurrentCausalWinners::from([(
        pointer_cell.clone(),
        CurrentCausalWinner {
            event_id: pointer.event_id.clone(),
            depth: 0,
            value: Value::String(strand.to_owned()),
        },
    )]);
    conn.transaction::<_, EventSealCommitError, _>(async |conn| {
        register_delta_origins(conn, realm.as_str(), &delta).await?;
        let revision = crate::current_results::next_revision(conn)
            .await
            .map_err(persistence_to_store)?;
        publish(
            conn,
            realm.as_str(),
            &cells,
            revision as i64,
            &winners,
            true,
        )
        .await
    })
    .await
    .unwrap();
    let origins = sql_query(
        "SELECT COUNT(*) AS value FROM current_selector_origins WHERE realm_id=$1 AND cell_id=ANY($2)",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Array<Text>, _>(vec![cell.as_str().to_owned(), pointer_cell.as_str().to_owned()])
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    assert_eq!(origins, 2);
    let published = sql_query("SELECT payload AS value FROM current_result_heads WHERE realm_id=$1 AND payload->'selector'->>'cell_id'=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(cell.as_str()).get_result::<JsonRow>(&mut *conn).await.unwrap().value;
    assert_eq!(
        published["result"],
        serde_json::json!({"status":"value","value":object})
    );
    assert_eq!(
        published["selector"]["scope_ref"],
        serde_json::json!({"kind":"realm","realm_id":realm})
    );
    assert!(!baseline_missing(&mut conn, realm.as_str()).await.unwrap());
    let ready = sql_query(
        "SELECT COUNT(*) AS value FROM governance_current_ready WHERE realm_id=$1 AND ready",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .value;
    assert_eq!(ready, 1);
}
