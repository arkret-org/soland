use arkret_models_collaboration::sync_frames::current_results::{
    CurrentResultEntry, CurrentTarget,
};

use super::*;

#[test]
fn coverage_uses_decoded_tokens_not_filter_lexical_order() {
    let mut strands = vec![
        "ak:strand:Ab37I4k6yBlQvDmm6v80xz-BaUrFUbaPneH1V_h_N2sG"
            .parse()
            .unwrap(),
        "ak:strand:AbZXl2n7Hn5BHf2TGG5YlOYcXmc3o5Q1bbWSox76uZTB"
            .parse()
            .unwrap(),
    ];
    let mut events = strands
        .iter()
        .map(|strand: &arkret_wire::StrandId| {
            strand
                .to_string()
                .replace("ak:strand:", "ak:event:")
                .parse()
                .unwrap()
        })
        .collect();
    strands.push(strands[0].clone());
    sort_coverage_identifiers(&mut strands, &mut events);
    assert_eq!(strands.len(), 2);
    assert!(strands[0].as_str() > strands[1].as_str());
    CurrentCoverage {
        realm: true,
        strand_ids: strands,
        event_ids: events,
        members: CurrentMemberCoverage::Selected { actor_ids: vec![] },
    }
    .validate()
    .unwrap();
}

#[tokio::test]
async fn baseline_budget_does_not_complete_or_change_snapshot_and_authority_change_restarts() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let registry =
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"current window realm"),
    ));
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:window.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let request = CurrentDetailRequest {
        actor_id: actor.clone(),
        realm_id: realm.clone(),
        strand_ids: Some(vec![]),
        all_members: false,
        event_ids: vec![],
        timeline_limit: 0,
        event_kinds: None,
        not_event_kinds: None,
    };
    let mut conn = pg_conn(&pool).await.unwrap();
    let revision=conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
        let revision=crate::current_results::next_revision(conn).await?;
        let mut entries=vec![];
        for key in priorities(&request)? {
            let selector:CurrentSelector=serde_json::from_str(&key).unwrap();
            entries.push(CurrentResultEntry::try_from_json(serde_json::json!({
                "selector":selector,"target":CurrentTarget::Realm,"revision":revision,
                "result":{"status":"unavailable","reason":"bottom"}
            })).unwrap());
        }
        crate::current_results::publish_entries(conn,&entries).await?;
        sql_query("INSERT INTO account_summary_current(actor_key,realm_id,revision,membership,available) VALUES($1,$2,$3,'join',TRUE)")
            .bind::<Text,_>(actor.canonical_key().unwrap()).bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(revision as i64)
            .execute(&mut *conn).await?;
        sql_query("INSERT INTO governance_current_ready(realm_id,revision,ready) VALUES($1,$2,TRUE)")
            .bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(revision as i64).execute(&mut *conn).await?;
        Ok(revision)
    }).await.map_err(crate::PgTransactionError::into_persistence).unwrap();
    let CurrentDetailOutcome::Page(first) =
        page(&pool, &request, None, 1, &registry).await.unwrap()
    else {
        panic!("frozen page expected")
    };
    assert!(first.entries.is_empty());
    assert!(!first.baseline.as_ref().unwrap().complete);
    let CurrentDetailOutcome::Page(second) = page(
        &pool,
        &request,
        Some(&first.progress),
        1024 * 1024,
        &registry,
    )
    .await
    .unwrap() else {
        panic!("continued page expected")
    };
    assert_eq!(
        first.progress.snapshot_cursor,
        second.progress.snapshot_cursor
    );
    assert_eq!(second.entries.len(), 4);
    assert!(second.baseline.as_ref().unwrap().complete);
    assert_eq!(second.progress.cut_revision, revision as i64);
    // Pending work outside this requested event window cannot stall the Realm.
    sql_query("INSERT INTO current_data_pending(realm_id,scope_key,cell_id,target_kind,target_key) VALUES($1,'test-scope','test-event-cell','event','unrequested-event')")
        .bind::<Text,_>(realm.as_str()).execute(&mut *conn).await.unwrap();
    assert!(matches!(
        page(
            &pool,
            &request,
            Some(&second.progress),
            1024 * 1024,
            &registry
        )
        .await
        .unwrap(),
        CurrentDetailOutcome::Page(_)
    ));
    sql_query("INSERT INTO current_data_pending(realm_id,scope_key,cell_id,target_kind,target_key) VALUES($1,'test-scope','test-realm-cell','realm','')")
        .bind::<Text,_>(realm.as_str()).execute(&mut *conn).await.unwrap();
    assert!(matches!(
        page(
            &pool,
            &request,
            Some(&second.progress),
            1024 * 1024,
            &registry
        )
        .await
        .unwrap(),
        CurrentDetailOutcome::Unavailable
    ));
    sql_query("DELETE FROM current_data_pending WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("UPDATE account_summary_clock SET revision=revision+1 WHERE singleton")
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("UPDATE governance_current_ready SET revision=revision+1 WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(matches!(
        page(
            &pool,
            &request,
            Some(&first.progress),
            1024 * 1024,
            &registry
        )
        .await
        .unwrap(),
        CurrentDetailOutcome::Unavailable
    ));
    // A same-revision member population advances across a bounded page without
    // skipping the last selector, leaving room for roster + worst-case coverage.
    conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
        let revision=crate::current_results::next_revision(conn).await?;
        let mut entries=Vec::new();
        for n in 0..33 {
            let member=arkret_wire::ActorId::account(arkret_wire::AccountId::new(format!("ak:did_core:web:member{n}.example").parse().unwrap(),"ak:did_core:web:station.example".parse().unwrap()));
            let subject=arkret_wire::cell::composite_subject(&[serde_json::json!(member.canonical_key().unwrap())]).unwrap();
            entries.push(CurrentResultEntry::try_from_json(serde_json::json!({"selector":{"scope_ref":{"kind":"realm","realm_id":realm},"cell_id":format!("ak:cell:ak.component.member.state.v1:{subject}")},"target":{"kind":"member","actor_id":member},"revision":revision,"result":{"status":"value","value":"join"}})).unwrap());
        }
        crate::current_results::publish_entries(conn,&entries).await?;Ok(())
    }).await.map_err(crate::PgTransactionError::into_persistence).unwrap();
    let mut all = request.clone();
    all.all_members = true;
    let CurrentDetailOutcome::Page(first) = page(&pool, &all, None, 7 * 1024 * 1024, &registry)
        .await
        .unwrap()
    else {
        panic!("member page")
    };
    let members = |p: &CurrentDetailPage| {
        p.entries
            .iter()
            .filter(|e| matches!(e.target(), CurrentTarget::Member { .. }))
            .count()
    };
    assert_eq!(members(&first), 32);
    assert!(!first.baseline.as_ref().unwrap().complete);
    let CurrentDetailOutcome::Page(last) = page(
        &pool,
        &all,
        Some(&first.progress),
        7 * 1024 * 1024,
        &registry,
    )
    .await
    .unwrap() else {
        panic!("member continuation")
    };
    assert_eq!(members(&last), 1);
    assert!(last.baseline.as_ref().unwrap().complete);
    assert_eq!(
        first.progress.snapshot_cursor,
        last.progress.snapshot_cursor
    );
}

/// The four Realm priority selectors a detail baseline requires, each written
/// with a source. The `set_default_strand` pointer is written here on purpose:
/// an *unwritten* default Strand pointer has no representable current entry
/// yet, which is a spec-side gap, and a server-side test must not paper over it
/// by relaxing the schema.
fn written_priority_entries(
    request: &CurrentDetailRequest,
    revision: u64,
) -> PersistenceResult<Vec<CurrentResultEntry>> {
    let source = serde_json::json!({
        "event_id": arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"current detail priority source"),
        ),
        "depth": 0,
    });
    priorities(request)?
        .into_iter()
        .map(|key| {
            let selector: CurrentSelector = serde_json::from_str(&key).unwrap();
            // Only the causal-register pointer publishes a source; the
            // sequenced-state families forbid one.
            let result = if selector
                .cell_id
                .as_str()
                .starts_with("ak:cell:ak.component.realm.set_default_strand.v1:")
            {
                serde_json::json!({
                    "status": "value",
                    "value": "ak:strand:Ab37I4k6yBlQvDmm6v80xz-BaUrFUbaPneH1V_h_N2sG",
                    "source": source,
                })
            } else {
                serde_json::json!({"status": "value", "value": serde_json::Value::Null})
            };
            Ok(CurrentResultEntry::try_from_json(serde_json::json!({
                "selector": selector,
                "target": CurrentTarget::Realm,
                "revision": revision,
                "result": result,
            }))
            .unwrap())
        })
        .collect()
}

#[tokio::test]
async fn an_invalidated_generation_is_rebuilt_instead_of_reported_unavailable() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let registry =
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"current window rebuild realm"),
    ));
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:rebuild.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let request = CurrentDetailRequest {
        actor_id: actor.clone(),
        realm_id: realm.clone(),
        strand_ids: Some(vec![]),
        all_members: false,
        event_ids: vec![],
        timeline_limit: 20,
        event_kinds: None,
        not_event_kinds: None,
    };
    let mut conn = pg_conn(&pool).await.unwrap();
    conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
        let revision=crate::current_results::next_revision(conn).await?;
        crate::current_results::publish_entries(conn,&written_priority_entries(&request,revision)?).await?;
        sql_query("INSERT INTO account_summary_current(actor_key,realm_id,revision,membership,available) VALUES($1,$2,$3,'join',TRUE)")
            .bind::<Text,_>(actor.canonical_key().unwrap()).bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(revision as i64)
            .execute(&mut *conn).await?;
        sql_query("INSERT INTO governance_current_ready(realm_id,revision,ready) VALUES($1,$2,TRUE)")
            .bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(revision as i64).execute(&mut *conn).await?;
        // Before the first accepted Seal there is no governance frontier to
        // read, and the reader drops the readiness row rather than answering
        // from one. One Seal is what makes this Realm a readable generation.
        sql_query("INSERT INTO state_seals(id,digest_suite,realm_id,seal_id_preimage_bytes,accepted_seal_bytes,seal_json,is_genesis) VALUES($1,'sha256',$2,decode('00','hex'),decode('00','hex'),'{}'::jsonb,TRUE)")
            .bind::<Text,_>(format!("ak:seal:{}",arkret_canonical::sha256_digest(b"current detail rebuild seal").replace("sha256:","")))
            .bind::<Text,_>(realm.as_str()).execute(&mut *conn).await?;
        Ok(())
    }).await.map_err(crate::PgTransactionError::into_persistence).unwrap();

    let outcome = page(&pool, &request, None, 1024 * 1024, &registry)
        .await
        .unwrap();
    let CurrentDetailOutcome::Page(first) = outcome else {
        panic!("frozen page expected, got {outcome:?}")
    };
    // The window ceiling is frozen from the request, not re-derived per turn,
    // which is what makes it a cumulative limit within one generation.
    assert_eq!(first.progress.timeline.window_limit, 20);

    // Eligibility / permission moved under the window. `client-sync.md` 2.3
    // abolishes the affected window and rebuilds it against the current
    // authorization; the rebuilt view must not be relabelled with the old
    // snapshot, and the Realm must not be reported unavailable while it is
    // still deliverable.
    sql_query("UPDATE account_summary_clock SET revision=revision+1 WHERE singleton")
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("UPDATE governance_current_ready SET revision=revision+1 WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    let CurrentDetailOutcome::Page(rebuilt) = page(
        &pool,
        &request,
        Some(&first.progress),
        1024 * 1024,
        &registry,
    )
    .await
    .unwrap() else {
        panic!("an invalidated window rebuilds rather than reporting unavailable")
    };
    assert_ne!(
        rebuilt.progress.snapshot_cursor,
        first.progress.snapshot_cursor
    );
    assert!(
        rebuilt.baseline.is_some(),
        "a rebuilt generation re-declares its baseline"
    );
    assert!(rebuilt.progress.cut_revision > first.progress.cut_revision);
    assert_eq!(
        rebuilt.progress.retained_revision,
        rebuilt.progress.cut_revision
    );

    // Raising the timeline ceiling changes the window range, so 2.3 requires a
    // new generation too. It reaches that outcome through the request digest.
    let mut wider = request.clone();
    wider.timeline_limit = 100;
    let CurrentDetailOutcome::Page(widened) = page(
        &pool,
        &wider,
        Some(&rebuilt.progress),
        1024 * 1024,
        &registry,
    )
    .await
    .unwrap() else {
        panic!("a widened window mints a new generation")
    };
    assert_ne!(
        widened.progress.snapshot_cursor,
        rebuilt.progress.snapshot_cursor
    );
    assert_eq!(widened.progress.timeline.window_limit, 100);
}
