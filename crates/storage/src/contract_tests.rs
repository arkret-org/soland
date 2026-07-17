use chrono::{Duration, Utc};

use super::*;

pub async fn assert_idempotency_store_contract(store: &dyn IdempotencyStore, namespace: &str) {
    let now = Utc::now();
    let principal_id = format!("did:web:{namespace}.example");
    let idempotency_key = format!("idempotency:{namespace}");
    let first = IdempotencyRecord {
        principal_id: principal_id.clone(),
        idempotency_key: idempotency_key.clone(),
        service_id: "did:web:soland.example".to_owned(),
        request_hash: "sha256:first".to_owned(),
        response_status: 200,
        response_body: serde_json::json!({"accepted": true}),
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    store.record(&first).await.expect("record first response");
    assert_eq!(
        store
            .get(&principal_id, &idempotency_key)
            .await
            .expect("read first response"),
        Some(first.clone())
    );

    let mut competing = first.clone();
    competing.request_hash = "sha256:competing".to_owned();
    competing.response_status = 409;
    store
        .record(&competing)
        .await
        .expect("record competing response");
    assert_eq!(
        store
            .get(&principal_id, &idempotency_key)
            .await
            .expect("read first-writer response"),
        Some(first),
        "the first response must win a duplicate-key race"
    );
}
