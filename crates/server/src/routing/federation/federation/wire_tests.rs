use super::*;

#[test]
fn federation_idempotency_strict_key_changes_with_key_state_digest() {
    let mut key = FederationIdempotencyKey {
        source_did: "did:web:alice.example".to_owned(),
        dest_did: "did:web:bob.example".to_owned(),
        request_canonical_digest: "sha256:abc".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        origin_key_state_digest: "sha256:state-A".to_owned(),
    };
    let strict_a = key.strict();
    let replay_a = key.canonical_replay();
    key.origin_key_state_digest = "sha256:state-B".to_owned();
    let strict_b = key.strict();
    let replay_b = key.canonical_replay();
    assert_ne!(strict_a, strict_b);
    assert_eq!(replay_a, replay_b);
}

#[test]
fn historical_only_marker_set() {
    let response = mark_response_historical_only(json!({"ok": true}));
    assert_eq!(
        response.get("reason_code").and_then(Value::as_str),
        Some(cokret_sdk::ERROR_CODE_HISTORICAL_ONLY)
    );
    assert_eq!(
        response.get("historical_only").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn delivery_binding_stale_response_carries_new_service_and_frontier() {
    let response = delivery_binding_stale_response(
        &Did::new("did:web:bob.example").unwrap(),
        &[cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap()],
    );
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_str),
        Some(cokret_sdk::ERROR_CODE_DELIVERY_BINDING_STALE)
    );
    assert_eq!(
        response
            .pointer("/error/details/new_recipient_service_did")
            .and_then(Value::as_str),
        Some("did:web:bob.example")
    );
}
