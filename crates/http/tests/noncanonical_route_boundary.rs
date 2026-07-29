use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

const OPENAPI: &str = include_str!("../src/product_openapi_appendix.json");
const INVENTORY: &str = include_str!("../../../noncanonical-route-inventory.jsonl");

#[derive(Debug, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum InventoryRecord {
    Metadata {
        schema: String,
        audit_status: String,
        finding: String,
        source: String,
        initial_private_path_count: usize,
    },
    Route {
        methods: BTreeSet<String>,
        path: String,
        classification: String,
        side_effect: String,
        auth_boundary: String,
        caller_refs: Vec<String>,
        canonical_operation: Option<String>,
        decision_ref: String,
        owner: String,
    },
}

#[test]
fn inventory_tracks_every_noncanonical_product_route_once() {
    let document: Value = serde_json::from_str(OPENAPI).expect("product OpenAPI must be JSON");
    let paths = document["paths"]
        .as_object()
        .expect("product OpenAPI paths must be an object");
    let actual = paths
        .iter()
        .filter(|(path, _)| path.starts_with("/_soland/"))
        .map(|(path, item)| {
            let methods = item
                .as_object()
                .expect("OpenAPI path item must be an object")
                .keys()
                .filter(|method| {
                    matches!(
                        method.as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                    )
                })
                .map(|method| method.to_ascii_uppercase())
                .collect::<BTreeSet<_>>();
            (path.clone(), methods)
        })
        .collect::<BTreeMap<_, _>>();

    let records = INVENTORY
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<InventoryRecord>(line).expect("inventory line is JSON"))
        .collect::<Vec<_>>();

    let metadata = records
        .iter()
        .find_map(|record| match record {
            InventoryRecord::Metadata {
                schema,
                audit_status,
                finding,
                source,
                initial_private_path_count,
            } => Some((
                schema,
                audit_status,
                finding,
                source,
                *initial_private_path_count,
            )),
            InventoryRecord::Route { .. } => None,
        })
        .expect("inventory metadata is required");
    assert_eq!(metadata.0, "soland.noncanonical_route_inventory.v1");
    assert_eq!(metadata.1, "provisional_baseline");
    assert_eq!(
        metadata.2,
        "arkret-work/review/spec-done/2026-07-27-12-soland-noncanonical-route-boundary-audit.md"
    );
    assert_eq!(metadata.3, "crates/http/src/product_openapi_appendix.json");
    assert_eq!(metadata.4, 127);

    let mut inventoried = BTreeMap::new();
    for record in records {
        let InventoryRecord::Route {
            methods,
            path,
            classification,
            side_effect,
            auth_boundary,
            caller_refs,
            canonical_operation,
            decision_ref,
            owner,
        } = record
        else {
            continue;
        };
        assert!(
            matches!(
                classification.as_str(),
                "canonical_migration" | "operator_extraction" | "delete"
            ),
            "{path} has an invalid classification"
        );
        assert!(!side_effect.trim().is_empty(), "{path} lacks side_effect");
        assert!(!methods.is_empty(), "{path} lacks HTTP methods");
        assert!(
            !auth_boundary.trim().is_empty(),
            "{path} lacks auth_boundary"
        );
        assert!(!decision_ref.trim().is_empty(), "{path} lacks decision_ref");
        assert!(!owner.trim().is_empty(), "{path} lacks owner");
        let _ = (caller_refs, canonical_operation);
        assert!(
            inventoried.insert(path.clone(), methods).is_none(),
            "{path} is classified more than once"
        );
    }

    assert_eq!(
        actual, inventoried,
        "the committed inventory must exactly match every current /_soland OpenAPI path and method"
    );
}
