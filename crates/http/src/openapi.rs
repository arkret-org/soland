use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::{Context, bail};
use salvo::prelude::*;
use salvo::routing::FilterInfo;
use serde_json::{Map, Value, json};

use crate::openapi_routes::{ArkretOpenApiDoc, populate_known_routes};

static ARKRET_OPENAPI_DOC: OnceLock<Value> = OnceLock::new();
static PRODUCT_OPENAPI_APPENDIX: OnceLock<std::result::Result<Value, String>> = OnceLock::new();

pub fn cached_arkret_openapi_doc(
    router: &Router,
    artifact_registry_summary: serde_json::Value,
) -> Value {
    let doc = ARKRET_OPENAPI_DOC
        .get_or_init(|| {
            arkret_openapi_doc(router, artifact_registry_summary)
                .unwrap_or_else(|error| panic!("failed to build artifact-first OpenAPI: {error:#}"))
        })
        .clone();
    // The same artifact-derived implementation doc is also the source of
    // truth for the 404/405 known-routes table used by `api_not_found`.
    populate_known_routes(&doc);
    doc
}

fn arkret_openapi_doc(
    router: &Router,
    artifact_registry_summary: serde_json::Value,
) -> anyhow::Result<Value> {
    let registered_routes = collect_registered_routes(router)?;
    let appendix = product_openapi_appendix()?;

    let mut artifact: Value = serde_saphyr::from_str(arkret_schema::embedded_openapi_yaml()?)
        .context("failed to parse the embedded canonical OpenAPI artifact")?;
    select_implemented_protocol_paths(&mut artifact, &registered_routes)?;
    append_product_paths(&mut artifact, appendix, &registered_routes)?;
    merge_missing_components(&mut artifact, appendix)?;

    let root = artifact
        .as_object_mut()
        .context("canonical OpenAPI artifact root must be an object")?;
    root.insert(
        "x-operation-aliases".to_owned(),
        json!({
            "events.submit": "ak.self.events.command.submit",
            "events.query": "ak.self.events.query.scan",
            "events.subscribe": "ak.self.events.stream.subscribe",
            "account.subscribe": "ak.self.account.stream.subscribe",
        }),
    );
    root.insert(
        "x-arkret-artifacts".to_owned(),
        json!({
            "registries": artifact_registry_summary,
            "openapi_source": "arkret-schema::embedded_openapi_yaml",
            "canonical_source": "arkret-spec/spec/v1/artifacts/openapi/arkret-service-api.openapi.yaml",
            "protocol_path_policy": "implemented_intersection",
            "registered_route_source": "salvo::routing::FilterInfo",
            "product_appendix_source": "soland-http/product_openapi_appendix.json",
            // The historical entity/view scaffold was removed alongside the
            // entity abstraction. View facets are declared by individual spec
            // event kinds and bound through cell-family registry mappings.
            "authz_constraint_kinds": ["allowed_object_facets"],
        }),
    );
    Ok(artifact)
}

const OPENAPI_METHODS: &[&str] = &[
    "get", "head", "post", "put", "patch", "delete", "options", "trace",
];

type RegisteredRoutes = BTreeMap<String, BTreeSet<String>>;

fn product_openapi_appendix() -> anyhow::Result<&'static Value> {
    match PRODUCT_OPENAPI_APPENDIX.get_or_init(|| {
        serde_json::from_str(include_str!("product_openapi_appendix.json"))
            .map_err(|error| format!("failed to parse product OpenAPI appendix: {error}"))
    }) {
        Ok(appendix) => Ok(appendix),
        Err(error) => bail!("{error}"),
    }
}

fn collect_registered_routes(router: &Router) -> anyhow::Result<RegisteredRoutes> {
    fn walk(
        router: &Router,
        parent_path: &str,
        parent_method: Option<&str>,
        routes: &mut RegisteredRoutes,
    ) -> anyhow::Result<()> {
        let mut path = parent_path.to_owned();
        let mut method = parent_method.map(str::to_owned);
        for filter in router.filters() {
            match filter.info() {
                FilterInfo::Path(fragment) => path = join_route_path(&path, &fragment),
                FilterInfo::Method(candidate) => {
                    let candidate = candidate.as_str().to_ascii_lowercase();
                    if candidate == "options" {
                        return Ok(());
                    }
                    if let Some(existing) = &method
                        && existing != &candidate
                    {
                        bail!(
                            "route `{path}` has conflicting method filters `{existing}` and `{candidate}`"
                        );
                    }
                    method = Some(candidate);
                }
                FilterInfo::Scheme(_)
                | FilterInfo::Host(_)
                | FilterInfo::Port(_)
                | FilterInfo::Other(_) => {}
            }
        }

        if router.goal.is_some()
            && let Some(method) = &method
            && !path.contains("{**")
        {
            routes
                .entry(path.clone())
                .or_default()
                .insert(method.clone());
        }
        for child in router.routers() {
            walk(child, &path, method.as_deref(), routes)?;
        }
        Ok(())
    }

    let mut routes = RegisteredRoutes::new();
    walk(router, "", None, &mut routes)?;
    Ok(routes)
}

fn join_route_path(parent: &str, fragment: &str) -> String {
    let parent = parent.trim_matches('/');
    let fragment = fragment.trim_matches('/');
    match (parent.is_empty(), fragment.is_empty()) {
        (true, true) => "/".to_owned(),
        (true, false) => format!("/{fragment}"),
        (false, true) => format!("/{parent}"),
        (false, false) => format!("/{parent}/{fragment}"),
    }
}

fn select_implemented_protocol_paths(
    artifact: &mut Value,
    registered_routes: &RegisteredRoutes,
) -> anyhow::Result<()> {
    let artifact_paths = artifact
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .context("canonical OpenAPI artifact must contain a paths object")?;
    let canonical_paths = std::mem::take(artifact_paths);
    let mut selected = Map::new();

    for (path, mut canonical_item) in canonical_paths {
        let Some(registered_methods) = registered_routes.get(&path) else {
            continue;
        };
        let canonical_item_object = canonical_item
            .as_object_mut()
            .with_context(|| format!("canonical OpenAPI path `{path}` must be an object"))?;
        let mut implemented = false;
        for method in OPENAPI_METHODS {
            if !registered_methods.contains(*method) {
                canonical_item_object.remove(*method);
                continue;
            }
            let Some(canonical_operation) = canonical_item_object.get(*method) else {
                bail!(
                    "Soland registers {method} {path}, but the canonical OpenAPI artifact does not"
                );
            };
            if canonical_operation
                .get("operationId")
                .and_then(Value::as_str)
                .is_none()
            {
                bail!("canonical OpenAPI operation {method} {path} has no operationId");
            }
            implemented = true;
        }
        if implemented {
            selected.insert(path, canonical_item);
        }
    }

    for (path, registered_methods) in registered_routes {
        if !is_protocol_contract_path(path) {
            continue;
        }
        for method in registered_methods {
            if !selected
                .get(path)
                .and_then(Value::as_object)
                .is_some_and(|item| item.contains_key(method))
            {
                bail!(
                    "registered protocol operation {method} {path} is absent from the canonical OpenAPI artifact"
                );
            }
        }
    }

    *artifact_paths = selected;
    Ok(())
}

fn append_product_paths(
    artifact: &mut Value,
    appendix: &Value,
    registered_routes: &RegisteredRoutes,
) -> anyhow::Result<()> {
    let appendix_paths = appendix
        .get("paths")
        .and_then(Value::as_object)
        .context("product OpenAPI appendix must contain a paths object")?;
    let artifact_paths = artifact
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .context("canonical OpenAPI artifact must contain a paths object")?;
    let mut missing = Vec::new();
    for (path, registered_methods) in registered_routes {
        if is_protocol_contract_path(path) {
            continue;
        }
        let Some(mut item) = appendix_paths.get(path).cloned() else {
            missing.push(format!(
                "{path} [{}]",
                registered_methods
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            continue;
        };
        let item_object = item
            .as_object_mut()
            .with_context(|| format!("product OpenAPI path `{path}` must be an object"))?;
        for method in OPENAPI_METHODS {
            if registered_methods.contains(*method) {
                if !item_object.contains_key(*method) {
                    bail!(
                        "registered product operation {method} {path} is absent from the product OpenAPI appendix"
                    );
                }
            } else {
                item_object.remove(*method);
            }
        }
        artifact_paths.insert(path.clone(), item);
    }
    if !missing.is_empty() {
        bail!(
            "registered product routes are absent from appendix: {}",
            missing.join("; ")
        );
    }
    Ok(())
}

fn is_test_only_protocol_path(path: &str) -> bool {
    path.starts_with("/_arkret/_conformance/")
}

fn is_transport_binding_path(path: &str) -> bool {
    path == "/_arkret/self/blob/resumable" || path.starts_with("/_arkret/self/blob/resumable/")
}

fn is_protocol_contract_path(path: &str) -> bool {
    path.starts_with("/_arkret/")
        && !is_test_only_protocol_path(path)
        && !is_transport_binding_path(path)
}

fn merge_missing_components(artifact: &mut Value, appendix: &Value) -> anyhow::Result<()> {
    let Some(appendix_components) = appendix.get("components").and_then(Value::as_object) else {
        return Ok(());
    };
    let artifact_root = artifact
        .as_object_mut()
        .context("canonical OpenAPI artifact root must be an object")?;
    let artifact_components = artifact_root
        .entry("components")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context("canonical OpenAPI components must be an object")?;

    for (section, appendix_entries) in appendix_components {
        let Some(appendix_entries) = appendix_entries.as_object() else {
            continue;
        };
        let artifact_entries = artifact_components
            .entry(section.clone())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .with_context(|| {
                format!("canonical OpenAPI component section `{section}` is invalid")
            })?;
        for (name, entry) in appendix_entries {
            artifact_entries
                .entry(name.clone())
                .or_insert_with(|| entry.clone());
        }
    }
    Ok(())
}

pub fn soland_extension_operation_ids() -> Vec<String> {
    let appendix = product_openapi_appendix()
        .unwrap_or_else(|error| panic!("failed to load product OpenAPI appendix: {error:#}"));
    appendix
        .get("paths")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|paths| paths.values())
        .filter_map(Value::as_object)
        .flat_map(|path_item| {
            path_item
                .iter()
                .filter(|(method, _)| OPENAPI_METHODS.contains(&method.as_str()))
                .filter_map(|(_, operation)| operation.get("operationId"))
                .filter_map(Value::as_str)
        })
        .filter(|operation_id| operation_id.starts_with("org.arkret.soland."))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "arkret_openapi_json"))]
pub async fn arkret_openapi_json(depot: &mut Depot, res: &mut Response) {
    let doc = depot
        .get_typed::<ArkretOpenApiDoc>()
        .expect("openapi doc injected");
    let spec = serde_json::to_vec_pretty(&doc.0).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render openapi json");
        b"{}\n".to_vec()
    });
    write_openapi_body(res, "application/json; charset=utf-8", spec);
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "arkret_openapi_yaml"))]
pub async fn arkret_openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = depot
        .get_typed::<ArkretOpenApiDoc>()
        .expect("openapi doc injected");
    let spec = serde_saphyr::to_string(&doc.0).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render openapi yaml");
        "{}\n".to_owned()
    });
    write_openapi_body(res, "application/yaml; charset=utf-8", spec.into_bytes());
}

fn write_openapi_body(res: &mut Response, content_type: &'static str, body: Vec<u8>) {
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        content_type.parse().expect("valid OpenAPI content type"),
    );
    res.headers_mut().insert(
        salvo::http::header::CONTENT_LENGTH,
        body.len()
            .to_string()
            .parse()
            .expect("valid OpenAPI content length"),
    );
    res.write_body(body).ok();
}
