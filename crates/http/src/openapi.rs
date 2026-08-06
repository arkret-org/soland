use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::bail;
use salvo::oapi::{OpenApi, OpenApiVersion};
use salvo::prelude::*;
use salvo::routing::FilterInfo;
use serde_json::{Value, json};

use crate::openapi_routes::{ArkretOpenApiDoc, populate_known_routes};

static ARKRET_OPENAPI_DOC: OnceLock<Value> = OnceLock::new();
static PRODUCT_OPENAPI_APPENDIX: OnceLock<std::result::Result<Value, String>> = OnceLock::new();

/// Build (once) and return the served OpenAPI document.
///
/// The document is generated from the live salvo router via salvo-oapi
/// (`OpenApi::merge_router`) rather than from any embedded/static artifact, so
/// every advertised operation comes from a real registered `#[endpoint]`
/// handler. The remaining `#[handler]` routes are deliberately limited to
/// streaming, multipart/binary transfer, protocol middleware, documentation
/// rendering, and framework catchers that cannot be described by the ordinary
/// typed JSON endpoint macro.
///
/// The 404/405 `Allow`-header table (`KNOWN_ROUTES`) is populated separately
/// from a direct router walk (`collect_registered_routes`), so error-envelope
/// correctness never depends on OpenAPI annotation coverage.
pub fn cached_arkret_openapi_doc(router: &Router, artifact_registry_summary: Value) -> Value {
    let registered_routes = collect_registered_routes(router)
        .unwrap_or_else(|error| panic!("failed to walk router for OpenAPI: {error:#}"));
    populate_known_routes(&registered_routes);
    ARKRET_OPENAPI_DOC
        .get_or_init(|| generate_openapi_doc(router, artifact_registry_summary))
        .clone()
}

fn generate_openapi_doc(router: &Router, artifact_registry_summary: Value) -> Value {
    let generated = OpenApi::new("Arkret Service API", env!("CARGO_PKG_VERSION"))
        .openapi_version(OpenApiVersion::Version3_2)
        .merge_router(router);
    let mut doc = serde_json::to_value(&generated)
        .unwrap_or_else(|error| panic!("failed to serialize generated OpenAPI: {error:#}"));
    let root = doc
        .as_object_mut()
        .expect("generated OpenAPI root must be an object");
    // Soland-specific extension metadata carried over from the previous
    // artifact-first document. Operation aliases map spec stream/command kinds
    // onto their canonical operationIds for clients that resolve by alias.
    root.insert(
        "x-operation-aliases".to_owned(),
        json!({
            "events.submit": "ak.self.events.command.submit",
            "events.read": "ak.self.events.read.scan",
            "events.subscribe": "ak.self.events.stream.subscribe",
            "account.subscribe": "ak.self.account.stream.subscribe",
        }),
    );
    root.insert(
        "x-arkret-artifacts".to_owned(),
        json!({
            "registries": artifact_registry_summary,
            "openapi_source": "salvo-oapi::OpenApi::merge_router",
            "registered_route_source": "salvo::routing::FilterInfo",
            // View facets are declared by individual spec event kinds and bound
            // through cell-family registry mappings.
            "authz_constraint_kinds": ["allowed_object_facets"],
        }),
    );
    install_event_read_query_bindings(&mut doc);
    doc
}

const OPENAPI_METHODS: &[&str] = &[
    "get", "head", "post", "put", "patch", "delete", "options", "query", "trace",
];

/// salvo-oapi 0.95.2 can emit an OpenAPI 3.2 document, while its typed
/// `PathItemType` still predates the 3.2 `query` member. Runtime routing comes
/// from Salvo's native `Router::query`; this explicit generation step copies
/// the live typed handler operation into the canonical 3.2 slot and marks the
/// registered GET/POST routes as compatibility bindings without independent
/// operation IDs.
fn install_event_read_query_bindings(doc: &mut Value) {
    let dto_schema = |name: &str| {
        json!({
            "$ref": format!(
                "../schemas/service-operation-dtos.schema.json#/$defs/{name}"
            )
        })
    };
    install_query_binding(
        doc,
        "/_arkret/self/events/describe",
        "/_arkret/self/events/describe",
        "get",
        "ak.self.events.read.describe",
        Some(dto_schema("EventsDescribeRequestBody")),
        &[("/_arkret/self/events/describe", "get")],
    );
    install_query_binding(
        doc,
        "/_arkret/self/events/frontier",
        "/_arkret/self/events/frontier",
        "get",
        "ak.self.events.read.frontier",
        Some(dto_schema("EventsFrontierRequestBody")),
        &[("/_arkret/self/events/frontier", "get")],
    );
    install_query_binding(
        doc,
        "/_arkret/self/events",
        "/_arkret/self/events/query",
        "post",
        "ak.self.events.read.scan",
        Some(dto_schema("EventsQueryPostRequestBody")),
        &[
            ("/_arkret/self/events", "get"),
            ("/_arkret/self/events/query", "post"),
        ],
    );
    install_query_binding(
        doc,
        "/_arkret/self/events/resolve",
        "/_arkret/self/events/resolve",
        "post",
        "ak.self.events.read.resolve",
        Some(dto_schema("EventsResolveRequestBody")),
        &[("/_arkret/self/events/resolve", "post")],
    );
    install_query_binding(
        doc,
        "/_arkret/self/events/mls-governance-proof",
        "/_arkret/self/events/mls-governance-proof",
        "post",
        "ak.self.events.read.mls_governance_proof",
        Some(json!({
            "$ref": "../schemas/mls-governance-proof-bundle.schema.json#/$defs/proof_request"
        })),
        &[("/_arkret/self/events/mls-governance-proof", "post")],
    );
    install_query_binding(
        doc,
        "/_arkret/peer/events/describe",
        "/_arkret/peer/events/describe",
        "get",
        "ak.peer.events.read.describe",
        Some(dto_schema("PeerEventsDescribeRequestBody")),
        &[("/_arkret/peer/events/describe", "get")],
    );
    install_query_binding(
        doc,
        "/_arkret/peer/events/frontier",
        "/_arkret/peer/events/frontier",
        "get",
        "ak.peer.events.read.frontier",
        Some(dto_schema("PeerEventsFrontierRequestBody")),
        &[("/_arkret/peer/events/frontier", "get")],
    );
    install_query_binding(
        doc,
        "/_arkret/peer/events",
        "/_arkret/peer/events/query",
        "post",
        "ak.peer.events.read.scan",
        Some(dto_schema("EventsQueryPostRequestBody")),
        &[
            ("/_arkret/peer/events", "get"),
            ("/_arkret/peer/events/query", "post"),
        ],
    );
    install_query_binding(
        doc,
        "/_arkret/peer/events/resolve",
        "/_arkret/peer/events/resolve",
        "post",
        "ak.peer.events.read.resolve",
        Some(dto_schema("PeerEventsResolveRequestBody")),
        &[("/_arkret/peer/events/resolve", "post")],
    );
}

fn install_query_binding(
    doc: &mut Value,
    canonical_path: &str,
    source_path: &str,
    source_method: &str,
    operation_id: &str,
    request_schema: Option<Value>,
    compatibility_bindings: &[(&str, &str)],
) {
    let mut operation = doc["paths"][source_path][source_method].clone();
    let operation_object = operation.as_object_mut().unwrap_or_else(|| {
        panic!("missing OpenAPI source operation {source_method} {source_path}")
    });
    operation_object.insert("operationId".to_owned(), json!(operation_id));
    operation_object.remove("deprecated");
    operation_object.remove("x-arkret-compatibility-binding-of");
    operation_object.remove("parameters");
    if let Some(schema) = request_schema {
        operation_object.insert(
            "requestBody".to_owned(),
            json!({
                "required": true,
                "content": {"application/json": {"schema": schema}},
            }),
        );
    }
    doc["paths"][canonical_path]["query"] = operation;

    for (path, method) in compatibility_bindings {
        let compatibility = doc["paths"][path][method]
            .as_object_mut()
            .unwrap_or_else(|| panic!("missing compatibility binding {method} {path}"));
        compatibility.remove("operationId");
        compatibility.insert("deprecated".to_owned(), Value::Bool(true));
        compatibility.insert(
            "x-arkret-compatibility-binding-of".to_owned(),
            json!(operation_id),
        );
    }
}

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

/// Walk the live salvo router and collect every registered `path -> methods`
/// pair. This is the single source of truth for the 404/405 known-route table
/// and is independent of OpenAPI generation.
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

/// The soland extension operationIds advertised through `*.describe`.
///
/// Sourced from the product appendix registry (an operation-id catalog, not a
/// served OpenAPI document). This remains deliberately independent of the
/// generated OpenAPI surface because the describe response advertises the
/// complete product contract, including transport-specialized operations.
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
