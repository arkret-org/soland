use super::*;

#[tokio::test]
async fn archive_and_freeze_are_reversible_without_reopening_a_terminal_realm() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = unit_with_plaintext_service(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    human_profile::admit(
        &pool,
        &unit.transactions[0].expected_authority.service_id,
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    let strand = source_if_human(&pool, strand).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let actor = creator_account(&unit);
    let mut head = invite_grant_request(
        &pool,
        &strand,
        &unit,
        unit.transactions[0].event.event_id.as_str(),
        &actor,
        &["ak.realm.archive", "ak.realm.freeze"],
    )
    .await;
    uow.commit_event(head.clone()).await.unwrap();
    for (close, reopen, selector, field) in [
        (
            arkret_wire::EventKind::RealmFreeze,
            arkret_wire::EventKind::RealmUnfreeze,
            arkret_wire::CurrentSelector::RealmFreeze,
            "frozen",
        ),
        (
            arkret_wire::EventKind::RealmArchive,
            arkret_wire::EventKind::RealmRestore,
            arkret_wire::CurrentSelector::RealmArchive,
            "archived",
        ),
    ] {
        head = realm_event_request_as(&head, &actor, close, serde_json::json!({}));
        head = source_if_human(&pool, head).await;
        uow.commit_event(head.clone()).await.unwrap();
        let blocked = realm_event_request_as(
            &head,
            &actor,
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"blocked ordinary write"}),
        );
        let blocked = source_if_human(&pool, blocked).await;
        let error = uow.commit_event(blocked.clone()).await.unwrap_err();
        assert!(error.to_string().contains("realm_frozen"), "{error}");
        assert_eq!(
            event_row_count(&pool, blocked.authority_commit.event.event_id.as_str()).await,
            0
        );
        head = realm_event_request_as(&head, &actor, reopen, serde_json::json!({}));
        head = source_if_human(&pool, head).await;
        uow.commit_event(head.clone()).await.unwrap();
        let material = store
            .realm_state_snapshot_material(&head.authority_commit.event.realm_id)
            .await
            .unwrap()
            .unwrap();
        assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
            arkret_wire::TypedCurrentResult::Value { selector: actual, revision, value, .. }
            if actual == &selector && revision.commit_id == head.authority_commit.commit.commit_id
                && value.get(field) == Some(&serde_json::Value::Bool(false))
        )));
        head = realm_event_request_as(
            &head,
            &actor,
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":format!("reopened after {field}")}),
        );
        head = source_if_human(&pool, head).await;
        uow.commit_event(head.clone()).await.unwrap();
    }
}

#[tokio::test]
async fn tombstone_commits_current_and_fences_fresh_writes_without_destroy_bypass() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = unit_with_plaintext_service(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    human_profile::admit(
        &pool,
        &unit.transactions[0].expected_authority.service_id,
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    let strand = source_if_human(&pool, strand).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let actor = creator_account(&unit);
    let grant = invite_grant_request(
        &pool,
        &strand,
        &unit,
        unit.transactions[0].event.event_id.as_str(),
        &actor,
        &["ak.realm.archive", "ak.realm.freeze"],
    )
    .await;
    uow.commit_event(grant.clone()).await.unwrap();
    let strand = grant;
    let realm = strand.authority_commit.event.realm_id.clone();
    let baseline = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    for (kind, payload) in [
        (
            arkret_wire::EventKind::RealmDestroy,
            serde_json::json!({"reason":"close"}),
        ),
        (
            arkret_wire::EventKind::RealmTombstone,
            serde_json::json!({"reason":"migrate"}),
        ),
        (
            arkret_wire::EventKind::RealmTombstone,
            serde_json::json!({"reason":"self", "successor_realm_id":realm}),
        ),
    ] {
        let request = realm_event_request_as(&strand, &actor, kind, payload);
        let request = source_if_human(&pool, request).await;
        assert!(uow.commit_event(request.clone()).await.is_err());
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(
            store
                .realm_state_snapshot_material(&realm)
                .await
                .unwrap()
                .unwrap()
                .current_state_entries,
            baseline.current_state_entries
        );
    }
    let payload = serde_json::json!({
        "reason":"migrate", "successor_realm_id":"ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
    });
    let terminal = realm_event_request_as(
        &strand,
        &actor,
        arkret_wire::EventKind::RealmTombstone,
        payload.clone(),
    );
    let terminal = source_if_human(&pool, terminal).await;
    uow.commit_event(terminal.clone()).await.unwrap();
    let material = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentResult::Value {selector: arkret_wire::CurrentSelector::RealmTombstone, revision, value, ..}
        if revision.commit_id == terminal.authority_commit.commit.commit_id && value == &payload
    )));
    let navigation = store
        .object_projection_lists_for_actor(
            &realm,
            &arkret_wire::ActorId::account(actor.clone()),
            true,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(navigation.0.spaces.is_empty());
    assert!(navigation.1.strands.is_empty());
    assert!(material.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::Strand { .. },
            ..
        }
    )));
    let families = message_families(&pool, &realm).await;
    for (kind, payload) in [
        (
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"reopen"}),
        ),
        (
            arkret_wire::EventKind::RealmTombstone,
            serde_json::json!({"reason":"again", "successor_realm_id":"ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"}),
        ),
        (arkret_wire::EventKind::RealmRestore, serde_json::json!({})),
    ] {
        let request = realm_event_request_as(&terminal, &actor, kind, payload);
        let request = source_if_human(&pool, request).await;
        let error = uow.commit_event(request.clone()).await.unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(message_families(&pool, &realm).await, families);
    }
    assert!(
        !uow.commit_event(terminal.clone())
            .await
            .unwrap()
            .event_inserted
    );
}
