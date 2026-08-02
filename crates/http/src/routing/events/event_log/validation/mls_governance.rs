use super::super::*;

pub(crate) async fn projected_media_plaintext_service_present(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    payload_declares_media_plaintext_service(payload, state.service_id())
        || realm_allows_plaintext_service_for_data_class(
            state,
            realm_id,
            arkret_wire::PlaintextDataClassKind::MediaPlaintext,
        )
        .await
}

pub(crate) fn payload_declares_media_plaintext_service(payload: &Value, service_id: &str) -> bool {
    payload
        .pointer("/plaintext_visible_services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                let Some(object) = service.as_object() else {
                    return false;
                };
                object.get("service_id").and_then(Value::as_str) == Some(service_id)
                    && object
                        .get("data_classes")
                        .and_then(Value::as_array)
                        .is_some_and(|classes| {
                            classes
                                .iter()
                                .any(|class| class.as_str() == Some("media_plaintext"))
                        })
            })
        })
}
