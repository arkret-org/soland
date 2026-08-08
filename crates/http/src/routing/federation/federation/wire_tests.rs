use super::*;

#[test]
fn delivery_binding_stale_response_carries_new_service_and_frontier() {
    let response = delivery_binding_stale_response(
        &Did::new("did:web:bob.example").unwrap(),
        &Did::new("did:web:alice.example").unwrap(),
        &[arkret_identifiers::EventId::new(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        )
        .unwrap()],
        json!({
            "kind": "member_delivery_binding_projection",
            "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }),
    );
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_str),
        Some(arkret_wire::ErrorCode::DELIVERY_BINDING_STALE)
    );
    assert_eq!(
        response
            .pointer("/error/details/new_recipient_service_id")
            .and_then(Value::as_str),
        Some("did:web:bob.example")
    );
    assert_eq!(
        response
            .pointer("/error/details/handover_frontier/0")
            .and_then(Value::as_str),
        Some("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert_eq!(
        response
            .pointer("/error/details/handover_proof/frontier/0")
            .and_then(Value::as_str),
        Some("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert_eq!(
        response
            .pointer("/error/details/handover_proof/recipient_service_id")
            .and_then(Value::as_str),
        Some("did:web:bob.example")
    );
    assert_eq!(
        response
            .pointer("/error/details/handover_proof/actor_id")
            .and_then(Value::as_str),
        Some("did:web:alice.example")
    );
    let details = response
        .pointer("/error/details")
        .cloned()
        .expect("delivery binding details");
    serde_json::from_value::<arkret_models_identity::artifacts_device_identity::DeliveryBindingStale>(details)
        .expect("details must match the SDK delivery-binding-stale DTO");
}

#[test]
fn delivery_binding_handed_over_response_carries_new_service() {
    let response = delivery_binding_handed_over_response(&Did::new("did:web:bob.example").unwrap());
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_str),
        Some(arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER)
    );
    assert_eq!(
        response
            .pointer("/error/details/new_recipient_service_id")
            .and_then(Value::as_str),
        Some("did:web:bob.example")
    );
}
