use super::common::*;

/// The served OpenAPI document is generated from the live salvo router via
/// salvo-oapi (`OpenApi::merge_router`), not from any embedded/static
/// artifact. Operation-level coverage grows as handlers migrate from
/// `#[handler]` to annotated `#[endpoint]`; this test asserts the generation
/// contract and the soland extension envelope rather than any specific
/// operation, which is intentionally left to the incremental migration.
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
