use super::common::*;

#[tokio::test]
async fn soland_admin_openapi_uses_product_namespace() {
    let spec: Value = TestClient::get("http://server/.well-known/arkret/openapi.json")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    let removed_admin_operation_prefix = format!("{}.{}.", "ak", "admin");
    let rendered = serde_json::to_string(&spec).unwrap();
    assert!(!rendered.contains(&removed_admin_operation_prefix));
    assert_eq!(spec["info"]["title"], "Arkret Service API");
    assert_eq!(
        spec["x-arkret-artifacts"]["protocol_path_policy"],
        "implemented_intersection"
    );
    assert!(
        spec["paths"]["/_arkret/gate/account/session-grants"]["post"].is_null(),
        "artifact-only operations must not be advertised as implemented"
    );

    let server_status = &spec["paths"]["/_soland/admin/server/status"]["get"];
    assert_eq!(
        server_status["operationId"],
        "org.arkret.soland.admin.get_server_status"
    );
    assert_product_admin_tags(server_status);

    let circle_restore = &spec["paths"]["/_arkret/self/circles/{circle_id}/restore"]["post"];
    assert_eq!(
        circle_restore["operationId"],
        "ak.self.circle.command.restore"
    );

    let mut checked_admin_operations = 0;
    let paths = spec["paths"].as_object().expect("paths object");
    for (path, path_item) in paths {
        if !path.starts_with("/_soland/admin") {
            continue;
        }
        for method in ["delete", "get", "head", "patch", "post", "put"] {
            let Some(operation) = path_item.get(method) else {
                continue;
            };
            let Some(operation_id) = operation["operationId"].as_str() else {
                continue;
            };
            checked_admin_operations += 1;
            assert!(!operation_id.starts_with(&removed_admin_operation_prefix));
            assert_no_plain_admin_tag(operation);
            if operation_id.starts_with("org.arkret.soland.admin.") {
                assert_product_admin_tags(operation);
            }
        }
    }
    assert!(checked_admin_operations > 0);
}

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

fn assert_product_admin_tags(operation: &Value) {
    let tags = operation["tags"].as_array().expect("operation tags");
    assert!(tags.iter().any(|tag| tag.as_str() == Some("soland-admin")));
    assert_no_plain_admin_tag(operation);
}

fn assert_no_plain_admin_tag(operation: &Value) {
    assert!(
        operation["tags"]
            .as_array()
            .is_none_or(|tags| !tags.iter().any(|tag| tag.as_str() == Some("admin")))
    );
}
