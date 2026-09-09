use super::common::*;

fn envelope(id: &str, actor: &arkret_wire::ActorId, series: &str, seq: u64) -> Value {
    serde_json::json!({
        "backup_id":id, "actor_id":actor, "backup_kind":"secret_storage", "backup_version":"kb_1",
        "created_at":"2026-09-09T00:00:00.000Z", "series_id":series, "series_seq":seq,
        "encryption":{"recipient_method":"secret_storage_key", "recipient_key_ref":"backup-key", "aead":{"name":"xchacha20_poly1305", "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"arkret.secret_storage.v1"},
        "contents":[{"item_kind":"recovery_key_share", "secret_id":"share"}],
        "ciphertext":"AAAA", "ciphertext_digest":"sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"
    })
}

async fn list(state: &AppState, token: &str, cursor: Option<&str>, limit: u32) -> salvo::Response {
    let mut url = url::Url::parse("http://server/_arkret/self/keys/backups").unwrap();
    url.query_pairs_mut()
        .append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        url.query_pairs_mut().append_pair("cursor", cursor);
    }
    TestClient::get(url.as_str())
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
}

#[test]
fn backup_listing_returns_current_pointers_and_rejects_stale_or_foreign_cursors() {
    run_on_deep_stack("backup_listing_current", backup_listing_current_body);
}

async fn backup_listing_current_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let actor = fixture_account_actor(&state, "did:web:alice.example");
    let account = actor.as_account_id().unwrap();
    let series = new_prefixed_uuid7("ak:backup_series:");
    let mut ids = Vec::new();
    for seq in 0..3 {
        let id = new_prefixed_uuid7("ak:backup:");
        state
            .test_persistence()
            .key_backups()
            .put(id.clone(), envelope(&id, &actor, &series, seq))
            .await
            .unwrap();
        ids.push(id);
    }
    let mut response = list(&state, &token, None, 2).await;
    let status = response.status_code;
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "{}",
        response.take_string().await.unwrap_or_default()
    );
    let first: arkret_models_crypto::KeysBackupsList = response.take_json().await.unwrap();
    assert_eq!(first.active_series.account_id, *account);
    assert!(matches!(
        first.active_series.secret_storage,
        arkret_models_crypto::BackupActiveSeriesPointer::Absent {}
    ));
    assert!(matches!(
        first.active_series.mls_history,
        arkret_models_crypto::BackupActiveSeriesPointer::Absent {}
    ));
    assert_eq!(first.backups.len(), 2);
    assert!(first.has_more);
    let cursor = first.next_cursor.unwrap();
    let second: arkret_models_crypto::KeysBackupsList =
        list(&state, &token, Some(cursor.as_str()), 2)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(second.backups.len(), 1);
    assert_eq!(second.backups[0].series_seq, 2);
    assert!(!second.has_more);
    assert!(second.next_cursor.is_none());
    let bob = verified_dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let foreign: Value = list(&state, &bob, Some(cursor.as_str()), 2)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&foreign), "cursor_invalid");
    state
        .test_persistence()
        .key_backups()
        .delete(&ids[2])
        .await
        .unwrap();
    let stale: Value = list(&state, &token, Some(cursor.as_str()), 2)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&stale), "cursor_invalid");
    let bad = list(&state, &token, None, 201).await;
    assert_eq!(bad.status_code, Some(StatusCode::BAD_REQUEST));
}
