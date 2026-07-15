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
