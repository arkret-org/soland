use super::*;

#[test]
fn delivery_binding_stale_response_carries_new_service_and_frontier() {
    let response = delivery_binding_stale_response(
        &arkret_wire::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        &arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        &arkret_models_identity::ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url:
                "https://bob.example/_arkret/open/services/ak:did_core:web:bob.example/resolution"
                    .to_owned(),
            pinned_record_digest: Some(
                arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
        },
        &[arkret_identifiers::EventId::new(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        )
        .unwrap()],
        json!({
            "kind": "member_delivery_binding_projection",
            "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }),
    );
    let envelope: arkret_wire::problem_details::ErrorEnvelope =
        serde_json::from_value(response).expect("RFC 9457 delivery-binding stale response");
    assert_eq!(
        envelope.code(),
        arkret_wire::ErrorCode::DELIVERY_BINDING_STALE
    );
    let details = Value::Object(envelope.error.details.into_iter().collect());
    assert_eq!(
        details.pointer("/new_recipient_id").and_then(Value::as_str),
        Some("ak:did_core:web:bob.example")
    );
    assert_eq!(
        details
            .pointer("/handover_frontier/0")
            .and_then(Value::as_str),
        Some("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert_eq!(
        details
            .pointer("/handover_proof/frontier/0")
            .and_then(Value::as_str),
        Some("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert_eq!(
        details
            .pointer("/handover_proof/recipient_id")
            .and_then(Value::as_str),
        Some("ak:did_core:web:bob.example")
    );
    assert_eq!(
        details
            .pointer("/handover_proof/actor_id")
            .and_then(Value::as_str),
        Some("ak:did_core:web:alice.example")
    );
    serde_json::from_value::<arkret_models_identity::artifacts_device_identity::DeliveryBindingStale>(details)
        .expect("details must match the SDK delivery-binding-stale DTO");
}

#[test]
fn delivery_binding_handed_over_response_carries_new_service() {
    let response = delivery_binding_handed_over_response(
        &arkret_wire::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
    );
    let envelope: arkret_wire::problem_details::ErrorEnvelope =
        serde_json::from_value(response).expect("RFC 9457 delivery-binding handover response");
    assert_eq!(
        envelope.code(),
        arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER
    );
    assert_eq!(
        envelope
            .error
            .details
            .get("new_recipient_id")
            .and_then(Value::as_str),
        Some("ak:did_core:web:bob.example")
    );
}
