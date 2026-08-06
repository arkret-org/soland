use super::common::*;

/// The served OpenAPI document is generated from the live salvo router via
/// salvo-oapi (`OpenApi::merge_router`), not from any embedded/static
/// artifact. Typed JSON routes are annotated `#[endpoint]`; the remaining
/// transport-specialized handlers are intentionally outside the ordinary
/// generated operation surface.
#[tokio::test]
async fn served_openapi_is_generated_from_the_router() {
    let spec: Value = TestClient::get("http://server/.well-known/arkret/openapi.json")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();

    assert!(
        spec["openapi"]
            .as_str()
            .is_some_and(|version| version.starts_with("3.")),
        "generated document must declare an OpenAPI 3.x version"
    );
    assert_eq!(spec["info"]["title"], "Arkret Service API");
    assert_eq!(
        spec["x-arkret-artifacts"]["openapi_source"],
        "salvo-oapi::OpenApi::merge_router"
    );
    assert_eq!(
        spec["x-arkret-artifacts"]["registered_route_source"],
        "salvo::routing::FilterInfo"
    );
    assert!(
        spec["paths"].is_object(),
        "generated document must expose a paths object"
    );
    assert_required_migrated_operations(&spec);
    assert_operation_ids_are_unique(&spec);
    assert_component_refs_resolve(&spec, &spec);
}

#[tokio::test]
async fn served_openapi_yaml_renders() {
    let response = TestClient::get("http://server/.well-known/arkret/openapi.yaml")
        .send(&app())
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let content_type = response
        .headers()
        .get(salvo::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("application/yaml"),
        "unexpected content type: {content_type}"
    );
}

fn assert_component_refs_resolve(root: &Value, value: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                && let Some(pointer) = reference.strip_prefix('#')
                && pointer.starts_with("/components/")
            {
                assert!(
                    root.pointer(pointer).is_some(),
                    "unresolved OpenAPI component reference: {reference}"
                );
            }
            for child in object.values() {
                assert_component_refs_resolve(root, child);
            }
        }
        Value::Array(array) => {
            for child in array {
                assert_component_refs_resolve(root, child);
            }
        }
        _ => {}
    }
}

fn assert_required_migrated_operations(root: &Value) {
    let operation_ids = operation_ids(root);
    for expected in [
        "org.arkret.soland.system.health",
        "ak.server.query.describe",
        "ak.self.events.read.scan",
        "ak.self.snapshot.query.manifest_head",
        "ak.self.blob.command.presign",
        "mimi_protocol_directory",
        "org.arkret.soland.well_known.arkret",
    ] {
        assert!(
            operation_ids.contains(&expected),
            "migrated operation is absent from generated OpenAPI: {expected}"
        );
    }
}

fn assert_operation_ids_are_unique(root: &Value) {
    let mut seen = std::collections::BTreeSet::new();
    for operation_id in operation_ids(root) {
        assert!(
            seen.insert(operation_id),
            "duplicate generated OpenAPI operationId: {operation_id}"
        );
    }
}

fn operation_ids(root: &Value) -> Vec<&str> {
    const METHODS: &[&str] = &[
        "get", "head", "post", "put", "patch", "delete", "options", "trace",
    ];
    root["paths"]
        .as_object()
        .into_iter()
        .flat_map(|paths| paths.values())
        .filter_map(Value::as_object)
        .flat_map(|path_item| {
            path_item
                .iter()
                .filter(|(method, _)| METHODS.contains(&method.as_str()))
                .filter_map(|(_, operation)| operation["operationId"].as_str())
        })
        .collect()
}

/// A path that exists only in the canonical spec artifact (never registered as
/// a live route) must be treated as unknown by the 404/405 disambiguator,
/// which is now driven by the router walk rather than the OpenAPI document.
#[tokio::test]
async fn artifact_only_path_is_not_treated_as_a_registered_route() {
    let response: Value = TestClient::post("http://server/_arkret/gate/account/session-grants")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["error"]["code"], "unrecognized_endpoint");
}
