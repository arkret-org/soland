use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::{Context, bail};
use salvo::oapi::PathItemType;
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
    let mut seen = std::collections::BTreeSet::new();
    SOLAND_EXTENSION_OPERATIONS
        .iter()
        .map(|(_, _, _, operation_id, _)| *operation_id)
        .filter(|operation_id| operation_id.starts_with("org.arkret.soland."))
        .filter(|operation_id| seen.insert((*operation_id).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

const SOLAND_EXTENSION_OPERATIONS: &[(&str, PathItemType, &str, &str, &str)] = &[
    (
        "/health",
        PathItemType::Get,
        "system",
        "org.arkret.soland.system.health",
        "health and liveness",
    ),
    // ② (api-conventions.md §3.3): the local credential issuance endpoint
    // is removed. Clients present the ak.session.grant + DPoP directly to
    // `/_arkret/self/*`, so there is no `POST /_arkret/gate/account/session-grants`
    // issue operation to advertise here.
    (
        "/_arkret/gate/account/logout",
        PathItemType::Post,
        "auth",
        "ak.gate.account.command.logout",
        "device logout: invalidate grant introspection cache + device session record + to-device, trigger Auth-side grant-chain termination",
    ),
    (
        "/_arkret/describe",
        PathItemType::Get,
        "server",
        "ak.server.query.describe",
        "server feature description",
    ),
    (
        "/_arkret/peer/invites",
        PathItemType::Post,
        "peer",
        "ak.peer.invites.command.submit",
        "private invite delivery",
    ),
    (
        "/_arkret/open/invite-locators/resolve",
        PathItemType::Post,
        "open",
        "ak.open.invite_locator.query.resolve",
        "resolve invite locator token",
    ),
    (
        "/_arkret/open/agent-pairing/resolve",
        PathItemType::Post,
        "open",
        "ak.open.agent_pairing.query.resolve",
        "resolve agent pairing token",
    ),
    (
        "/_arkret/open/agent-pairing/runtime-key-requests",
        PathItemType::Post,
        "open",
        "ak.open.agent_pairing.command.submit_runtime_key_request",
        "submit agent runtime key request for controller approval",
    ),
    (
        "/_arkret/open/agent-pairing/runtime-key-requests/status",
        PathItemType::Post,
        "open",
        "ak.open.agent_pairing.query.runtime_key_request_status",
        "poll controller decision for a submitted runtime key request",
    ),
    // Circle admin surface (`ak.self.circle.*`) was promoted to the protocol
    // surface at `/_arkret/self/circles*`; its operation ids are now emitted by
    // the typed `#[endpoint]` handlers in `circles.rs`, so they no longer appear
    // in this soland-extension table.
    (
        "/_arkret/self/events/describe",
        PathItemType::Get,
        "events",
        "ak.self.events.query.describe",
        "describe Event Envelope ingestion profile",
    ),
    (
        "/_arkret/self/events",
        PathItemType::Post,
        "events",
        "ak.self.events.command.submit",
        "submit one Event Envelope",
    ),
    (
        "/_arkret/self/events/{event_id}",
        PathItemType::Get,
        "events",
        "ak.self.events.resource.get",
        "get one Event Envelope",
    ),
    (
        "/_arkret/self/events/resolve",
        PathItemType::Post,
        "events",
        "ak.self.events.query.resolve",
        "resolve Event Envelopes by id",
    ),
    (
        "/_arkret/self/events",
        PathItemType::Get,
        "events",
        "ak.self.events.query.scan",
        "query Event Envelopes (forward / backward)",
    ),
    (
        "/_arkret/self/events/subscribe",
        PathItemType::Get,
        "events",
        "ak.self.events.stream.subscribe",
        "subscribe to Event stream",
    ),
    (
        "/_arkret/self/events/frontier",
        PathItemType::Get,
        "events",
        "ak.self.events.query.frontier",
        "get Event frontier",
    ),
    (
        "/_arkret/self/realms/{realm_id}/spaces",
        PathItemType::Get,
        "realm",
        "ak.self.space.query.list",
        "Space lifecycle projection query",
    ),
    (
        "/_arkret/self/realms/{realm_id}/strands",
        PathItemType::Get,
        "realm",
        "ak.self.strand.query.list",
        "Strand lifecycle projection query",
    ),
    (
        "/_arkret/self/realms/{realm_id}/morphs",
        PathItemType::Get,
        "realm",
        "ak.self.morph.query.list",
        "Morph lifecycle projection query",
    ),
    (
        "/_arkret/self/authz/effective-grants",
        PathItemType::Get,
        "authz",
        "ak.self.authz.grants.query.effective",
        "get effective grants",
    ),
    (
        "/_arkret/self/authz/invites",
        PathItemType::Get,
        "authz",
        "ak.self.authz.invites.query.list",
        "list invites",
    ),
    (
        "/_arkret/peer/events/describe",
        PathItemType::Get,
        "peer",
        "ak.peer.events.query.describe",
        "describe federation peer Events API",
    ),
    (
        "/_arkret/peer/events",
        PathItemType::Post,
        "peer",
        "ak.peer.events.command.submit",
        "submit federation peer Events",
    ),
    (
        "/_arkret/peer/events",
        PathItemType::Get,
        "peer",
        "ak.peer.events.query.scan",
        "query federation peer Events",
    ),
    (
        "/_arkret/peer/events/query",
        PathItemType::Post,
        "peer",
        "ak.peer.events.query.scan_body",
        "query federation peer Events with body parameters",
    ),
    (
        "/_arkret/peer/events/resolve",
        PathItemType::Post,
        "peer",
        "ak.peer.events.query.resolve",
        "resolve federation peer Events",
    ),
    (
        "/_arkret/peer/events/frontier",
        PathItemType::Get,
        "peer",
        "ak.peer.events.query.frontier",
        "read federation peer Event frontier",
    ),
    (
        "/_arkret/peer/snapshot/head",
        PathItemType::Get,
        "peer",
        "ak.peer.snapshot.query.manifest_head",
        "read federation peer snapshot head",
    ),
    (
        "/_arkret/self/account/subscribe",
        PathItemType::Get,
        "account",
        "ak.self.account.stream.subscribe",
        "account-aggregate subscribe",
    ),
    (
        "/_arkret/self/account/describe",
        PathItemType::Get,
        "account",
        "ak.self.account.query.describe",
        "account aggregate describe",
    ),
    (
        "/_arkret/self/snapshot/head",
        PathItemType::Get,
        "snapshot",
        "ak.self.snapshot.query.manifest_head",
        "snapshot head",
    ),
    (
        "/_arkret/find/directory/describe",
        PathItemType::Get,
        "directory",
        "ak.find.directory.query.describe",
        "directory describe",
    ),
    (
        "/_arkret/find/directory/search-realms",
        PathItemType::Post,
        "directory",
        "ak.find.directory.query.search_realms",
        "search realms",
    ),
    (
        "/_arkret/find/directory/resolve-realm",
        PathItemType::Post,
        "directory",
        "ak.find.directory.query.resolve_realm",
        "resolve realm",
    ),
    (
        "/_arkret/find/directory/resolve-agent-selector",
        PathItemType::Post,
        "directory",
        "ak.find.directory.query.resolve_agent_selector",
        "resolve agent selector",
    ),
    (
        "/_arkret/find/directory/list-handles-for-subject",
        PathItemType::Post,
        "directory",
        "ak.find.directory.query.list_handles_for_subject",
        "list handles for subject",
    ),
    (
        "/_soland/admin/actors",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.actors",
        "admin actor snapshot",
    ),
    (
        "/_soland/admin/realms",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.realms",
        "admin realm snapshot",
    ),
    (
        "/_soland/admin/spaces",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.space_containers",
        "admin space container snapshot",
    ),
    (
        "/_soland/admin/devices",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.devices",
        "admin device snapshot",
    ),
    (
        "/_soland/admin/capabilities",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.capabilities",
        "admin capability snapshot",
    ),
    (
        "/_soland/admin/federation",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.federation",
        "admin federation snapshot",
    ),
    (
        "/_soland/admin/applets",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.applets",
        "admin applet snapshot",
    ),
    (
        "/_soland/admin/agents",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.agents",
        "admin agent snapshot",
    ),
    (
        "/_soland/admin/reports",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.reports",
        "admin report snapshot",
    ),
    (
        "/_soland/admin/invite-tokens",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.invite_tokens",
        "admin invite token snapshot",
    ),
    (
        "/_soland/admin/audit",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.audit",
        "admin audit snapshot",
    ),
    (
        "/_soland/admin/policy",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.policy",
        "admin policy snapshot",
    ),
    (
        "/_soland/admin/media",
        PathItemType::Get,
        "soland-admin",
        "org.arkret.soland.admin.media",
        "admin media snapshot",
    ),
    (
        "/_arkret/self/authz/check",
        PathItemType::Post,
        "authz",
        "ak.self.authz.query.check",
        "check authorization",
    ),
    // policy_document CRUD (`ak.self.policy_document.*`) was promoted to the
    // protocol surface at `/_arkret/self/policies*`; its operation ids are now
    // emitted by the typed `#[endpoint]` handlers in `access/policy.rs`. The
    (
        "/_arkret/edge/push/register-device",
        PathItemType::Post,
        "push",
        "ak.edge.push.command.register_device",
        "register push device",
    ),
    (
        "/_soland/edge/push/outbound/bridge/cache/export",
        PathItemType::Get,
        "push",
        "org.arkret.soland.push.outbound_bridge_cache_export",
        "export outbound push bridge cache snapshots",
    ),
    (
        "/_soland/edge/push/outbound/bridge/cache/import",
        PathItemType::Post,
        "push",
        "org.arkret.soland.push.outbound_bridge_cache_import",
        "import outbound push bridge cache snapshots",
    ),
    (
        "/_arkret/self/keys/backups/{backup_id}",
        PathItemType::Put,
        "keys",
        "ak.self.keys.backups.resource.replace",
        "store encrypted key backup",
    ),
    (
        "/_arkret/self/keys/backups/{backup_id}/unlock",
        PathItemType::Post,
        "keys",
        "ak.self.keys.backups.command.unlock",
        "unlock encrypted key backup",
    ),
    (
        "/_arkret/self/keys/backups/{backup_id}",
        PathItemType::Delete,
        "keys",
        "ak.self.keys.backups.resource.delete",
        "delete encrypted key backup",
    ),
    (
        "/_arkret/self/keys/backups",
        PathItemType::Get,
        "keys",
        "ak.self.keys.backups.query.list",
        "list encrypted key backups",
    ),
    (
        "/_arkret/edge/push/unregister-device",
        PathItemType::Post,
        "push",
        "ak.edge.push.command.unregister_device",
        "unregister push device",
    ),
    (
        "/_arkret/edge/push/notify",
        PathItemType::Post,
        "push",
        "ak.edge.push.command.notify",
        "send push notification",
    ),
    (
        "/_arkret/self/blob/upload",
        PathItemType::Post,
        "blob",
        "ak.self.blob.upload.create",
        "upload blob bytes",
    ),
    (
        "/_arkret/self/blob/get",
        PathItemType::Head,
        "blob",
        "ak.self.blob.resource.head",
        "inspect blob metadata",
    ),
    (
        "/_arkret/self/blob/get",
        PathItemType::Get,
        "blob",
        "ak.self.blob.resource.get",
        "download blob bytes",
    ),
    (
        "/_arkret/self/moderation/report",
        PathItemType::Post,
        "moderation",
        "ak.self.moderation.command.report",
        "report moderation issue",
    ),
    (
        "/_arkret/open/mimi/provider-directory",
        PathItemType::Get,
        "mimi",
        "ak.open.mimi.query.provider_directory",
        "MIMI provider directory",
    ),
    (
        "/_arkret/open/mimi/key-material",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.exchange.request_key_material",
        "MIMI key material",
    ),
    (
        "/_arkret/open/mimi/strands/{strand_id}/update",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.update_room",
        "MIMI external room interop update",
    ),
    (
        "/_arkret/open/mimi/strands/{strand_id}/notify",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.notify",
        "MIMI external room interop notify",
    ),
    (
        "/_arkret/open/mimi/strands/{strand_id}/messages",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.submit_message",
        "MIMI external room interop submit message",
    ),
    (
        "/_arkret/open/mimi/strands/{strand_id}/group-info",
        PathItemType::Get,
        "mimi",
        "ak.open.mimi.query.group_info",
        "MIMI external room interop group info",
    ),
    (
        "/_arkret/open/mimi/consent/request",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.request_consent",
        "MIMI request consent",
    ),
    (
        "/_arkret/open/mimi/consent/update",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.update_consent",
        "MIMI update consent",
    ),
    (
        "/_arkret/open/mimi/identifiers/query",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.query.identifiers",
        "MIMI identifier query",
    ),
    (
        "/_arkret/open/mimi/report-abuse",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.report_abuse",
        "MIMI report abuse",
    ),
    (
        "/_arkret/open/mimi/proxy-download",
        PathItemType::Post,
        "mimi",
        "ak.open.mimi.command.proxy_download",
        "MIMI proxy download",
    ),
    // AKP-0008 / AKP-0009 (spec head 37ce729) — Personal Agent + Sidecar
    // operations. Implementation lives at
    // `routing::identity::agents`; the table here makes the operations
    // visible to the OpenAPI snapshot + the 404/405 disambiguator.
    (
        "/_arkret/gate/account/agent-key-pair",
        PathItemType::Post,
        "agents",
        "ak.gate.account.command.pair_agent_key",
        "authorize an agent runtime key pair",
    ),
    (
        "/_arkret/self/agents",
        PathItemType::Post,
        "agents",
        "ak.self.agent.command.provision",
        "provision a personal agent",
    ),
    (
        "/_arkret/self/agents",
        PathItemType::Get,
        "agents",
        "ak.self.agent.query.list",
        "list personal agents",
    ),
    (
        "/_arkret/self/agents/{agent_id}",
        PathItemType::Get,
        "agents",
        "ak.self.agent.resource.get",
        "get a personal agent by id",
    ),
    (
        "/_arkret/self/agents/{agent_id}/pause",
        PathItemType::Post,
        "agents",
        "ak.self.agent.command.pause",
        "pause a personal agent",
    ),
    (
        "/_arkret/self/agents/{agent_id}/resume",
        PathItemType::Post,
        "agents",
        "ak.self.agent.command.resume",
        "resume a personal agent",
    ),
    (
        "/_arkret/self/agents/{agent_id}/deactivate",
        PathItemType::Post,
        "agents",
        "ak.self.agent.command.deactivate",
        "deactivate a personal agent",
    ),
    (
        "/_arkret/self/agents/{agent_id}/grants",
        PathItemType::Post,
        "agents",
        "ak.self.agent.grant.command.attach",
        "attach a capability grant to a personal agent",
    ),
    (
        "/_arkret/self/agents/{agent_id}/grants/{grant_id}",
        PathItemType::Delete,
        "agents",
        "ak.self.agent.grant.resource.delete",
        "detach a capability grant from a personal agent",
    ),
    // AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — media
    // token exchange + signed ICE config. Canonical wire paths now live on
    // the `self` trust segment (`/_arkret/self/rtc/...`); the historical
    // `/arkret/v1/...` and `/api/v1/...` aliases are gone.
    (
        "/_arkret/self/rtc/token",
        PathItemType::Post,
        "media",
        "ak.self.call.media.exchange.issue_token",
        "exchange session-focus for backend media token + participant_binding",
    ),
    (
        "/_arkret/self/rtc/ice-config",
        PathItemType::Post,
        "media",
        "ak.self.media.query.ice_config",
        "issue signed ICE config",
    ),
    // R3 spec-sync — recovery policy read/publish are canonical; history stays
    // on the deployment-local `_soland` surface.
    (
        "/_arkret/root/identity/recovery-policy",
        PathItemType::Get,
        "identity",
        "ak.root.identity.recovery_policy.resource.get",
        "read the active recovery policy",
    ),
    (
        "/_arkret/root/identity/recovery-policy",
        PathItemType::Post,
        "identity",
        "ak.root.identity.recovery_policy.command.publish",
        "submit a ak.schema.recovery_policy.v1 policy",
    ),
    (
        "/_soland/root/identity/recovery-receipt",
        PathItemType::Post,
        "identity",
        "org.arkret.soland.identity.recovery_receipt.put",
        "submit a ak.schema.recovery_receipt.v1 receipt",
    ),
];

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
