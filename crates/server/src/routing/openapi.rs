use std::sync::OnceLock;

use salvo::oapi::{OpenApi, Operation, PathItemType, Response as OapiResponse};
use salvo::prelude::*;
use serde_json::json;

use super::*;

static COKRET_OPENAPI_DOC: OnceLock<OpenApi> = OnceLock::new();

pub(crate) fn cached_cokret_openapi_doc(router: &Router) -> OpenApi {
    let doc = COKRET_OPENAPI_DOC
        .get_or_init(|| cokret_openapi_doc(router))
        .clone();
    // The same cached doc is also the source of truth for the
    // 404/405 known-routes table used by `api_not_found`.
    populate_known_routes(&doc);
    doc
}

fn cokret_openapi_doc(router: &Router) -> OpenApi {
    let mut doc = OpenApi::new("soland", "0.1.0")
        .add_extension(
            "x-operation-aliases",
            json!({
                "events.submit": "ck.self.events.command.submit",
                "events.query": "ck.self.events.query.scan",
                "events.subscribe": "ck.self.events.stream.subscribe",
                "account.subscribe": "ck.self.account.stream.subscribe",
            }),
        )
        .add_extension(
            "x-cokret-artifacts",
            json!({
                "registries": crate::artifacts::registry_summary(),
                "openapi_source": "cokret-spec/spec/v1/artifacts/openapi/cokret-service-api.openapi.yaml",
                // Round-6: the round-4 entity/view scaffold (FacetName /
                // ViewRenderer / AllowedEntityFacetsConstraint /
                // allowed_entity_facets) was removed alongside the entity
                // abstraction. View facets are now declared by individual
                // spec event kinds (`ck.view.*` / `ck.strand.*` / `ck.space.*`)
                // and bound through cell-family registry mappings.
                "authz_constraint_kinds": ["allowed_object_facets"],
            }),
        )
        .merge_router(router);
    register_soland_extension_operations(&mut doc);
    doc
}

fn register_soland_extension_operations(doc: &mut OpenApi) {
    // Stable, namespaced operation IDs for the soland-specific surface. The
    // table covers operations that soland exposes on top of the canonical
    // protocol - auth/account/admin/policy/etc. - until each `#[endpoint]`
    // grows its own typed extractors and operation_id annotation.
    for (path, method, tag, operation_id, summary) in SOLAND_EXTENSION_OPERATIONS {
        add_contract_operation(doc, path, *method, tag, operation_id, summary);
    }
}

pub(crate) fn soland_extension_operation_ids() -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    SOLAND_EXTENSION_OPERATIONS
        .iter()
        .map(|(_, _, _, operation_id, _)| *operation_id)
        .filter(|operation_id| operation_id.starts_with("org.cokret.soland."))
        .filter(|operation_id| seen.insert((*operation_id).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

fn add_contract_operation(
    doc: &mut OpenApi,
    path: &str,
    method: PathItemType,
    tag: &str,
    operation_id: &str,
    summary: &str,
) {
    let operation = Operation::new()
        .tags([tag])
        .summary(summary)
        .operation_id(operation_id)
        .add_response("200", OapiResponse::new("ok"));
    // A table entry whose path is absent from the merged router doc would
    // silently no-op, leaving SOLAND_EXTENSION_OPERATIONS documenting a
    // mount point that does not exist. Fail loudly in debug builds so the
    // table cannot drift away from the actual routes again. Concrete
    // collection entries such as `/_soland/admin/actors` are valid when the
    // merged router exposes the parameterized `/_soland/admin/{resource}`
    // pattern that serves them.
    debug_assert!(
        doc.path_is_served(path),
        "SOLAND_EXTENSION_OPERATIONS path `{path}` (operation `{operation_id}`) is not served by any router"
    );
    if let Some(path_item) = doc.paths.get_mut(path) {
        path_item.operations.insert(method, operation);
    }
}

trait OpenApiRouteExt {
    fn path_is_served(&self, path: &str) -> bool;
}

impl OpenApiRouteExt for OpenApi {
    fn path_is_served(&self, path: &str) -> bool {
        self.paths.contains_key(path)
            || self
                .paths
                .keys()
                .any(|pattern| pattern_matches_path(pattern, path))
    }
}

const SOLAND_EXTENSION_OPERATIONS: &[(&str, PathItemType, &str, &str, &str)] = &[
    (
        "/health",
        PathItemType::Get,
        "system",
        "org.cokret.soland.system.health",
        "health and liveness",
    ),
    // ② (api-conventions.md §3.3): the grant→bearer exchange / issue endpoint
    // is removed. Clients present the ck.session.grant + DPoP directly to
    // `/_cokret/self/*`, so there is no `POST /_cokret/gate/account/session-grants`
    // issue operation to advertise here.
    (
        "/_cokret/gate/account/logout",
        PathItemType::Post,
        "auth",
        "ck.gate.account.command.logout",
        "device logout: invalidate grant introspection cache + device session record + to-device, trigger Auth-side grant-chain termination",
    ),
    (
        "/_cokret/describe",
        PathItemType::Get,
        "server",
        "ck.server.query.describe",
        "server feature description",
    ),
    (
        "/_cokret/peer/invites",
        PathItemType::Post,
        "peer",
        "ck.peer.invites.command.submit",
        "private invite delivery",
    ),
    (
        "/_cokret/open/invite-locators/resolve",
        PathItemType::Post,
        "open",
        "ck.open.invite_locator.query.resolve",
        "resolve invite locator token",
    ),
    // Circle admin surface (`ck.self.circle.*`) was promoted to the protocol
    // surface at `/_cokret/self/circles*`; its operation ids are now emitted by
    // the typed `#[endpoint]` handlers in `circles.rs`, so they no longer appear
    // in this soland-extension table.
    (
        "/_cokret/self/events/describe",
        PathItemType::Get,
        "events",
        "ck.self.events.query.describe",
        "describe Event Envelope ingestion profile",
    ),
    (
        "/_cokret/self/events",
        PathItemType::Post,
        "events",
        "ck.self.events.command.submit",
        "submit one Event Envelope",
    ),
    (
        "/_cokret/self/events/{event_id}",
        PathItemType::Get,
        "events",
        "ck.self.events.resource.get",
        "get one Event Envelope",
    ),
    (
        "/_cokret/self/events/resolve",
        PathItemType::Post,
        "events",
        "ck.self.events.query.resolve",
        "resolve Event Envelopes by id",
    ),
    (
        "/_cokret/self/events",
        PathItemType::Get,
        "events",
        "ck.self.events.query.scan",
        "query Event Envelopes (forward / backward)",
    ),
    (
        "/_cokret/self/events/subscribe",
        PathItemType::Get,
        "events",
        "ck.self.events.stream.subscribe",
        "subscribe to Event stream",
    ),
    (
        "/_cokret/self/events/frontier",
        PathItemType::Get,
        "events",
        "ck.self.events.query.frontier",
        "get Event frontier",
    ),
    (
        "/_cokret/self/projection/spaces",
        PathItemType::Get,
        "projection",
        "ck.self.projection.spaces.query.list",
        "Space lifecycle projection query",
    ),
    (
        "/_cokret/self/projection/strands",
        PathItemType::Get,
        "projection",
        "ck.self.projection.strands.query.list",
        "Strand lifecycle projection query",
    ),
    (
        "/_cokret/self/projection/morphs",
        PathItemType::Get,
        "projection",
        "ck.self.projection.morphs.query.list",
        "Morph lifecycle projection query",
    ),
    (
        "/_cokret/self/authz/effective-grants",
        PathItemType::Get,
        "authz",
        "ck.self.authz.grants.query.effective",
        "get effective grants",
    ),
    (
        "/_cokret/self/authz/invites",
        PathItemType::Get,
        "authz",
        "ck.self.authz.invites.query.list",
        "list invites",
    ),
    (
        "/_cokret/peer/events/describe",
        PathItemType::Get,
        "peer",
        "ck.peer.events.query.describe",
        "describe federation peer Events API",
    ),
    (
        "/_cokret/peer/events",
        PathItemType::Post,
        "peer",
        "ck.peer.events.command.submit",
        "submit federation peer Events",
    ),
    (
        "/_cokret/peer/events",
        PathItemType::Get,
        "peer",
        "ck.peer.events.query.scan",
        "query federation peer Events",
    ),
    (
        "/_cokret/peer/events/query",
        PathItemType::Post,
        "peer",
        "ck.peer.events.query.scan_body",
        "query federation peer Events with body parameters",
    ),
    (
        "/_cokret/peer/events/resolve",
        PathItemType::Post,
        "peer",
        "ck.peer.events.query.resolve",
        "resolve federation peer Events",
    ),
    (
        "/_cokret/peer/events/frontier",
        PathItemType::Get,
        "peer",
        "ck.peer.events.query.frontier",
        "read federation peer Event frontier",
    ),
    (
        "/_cokret/peer/snapshot/head",
        PathItemType::Get,
        "peer",
        "ck.peer.snapshot.query.manifest_head",
        "read federation peer snapshot head",
    ),
    (
        "/_cokret/self/account/subscribe",
        PathItemType::Get,
        "account",
        "ck.self.account.stream.subscribe",
        "account-aggregate subscribe",
    ),
    (
        "/_cokret/self/account/describe",
        PathItemType::Get,
        "account",
        "ck.self.account.query.describe",
        "account aggregate describe",
    ),
    (
        "/_cokret/self/snapshot/head",
        PathItemType::Get,
        "snapshot",
        "ck.self.snapshot.query.manifest_head",
        "snapshot head",
    ),
    (
        "/_cokret/find/directory/describe",
        PathItemType::Get,
        "directory",
        "ck.find.directory.query.describe",
        "directory describe",
    ),
    (
        "/_cokret/find/directory/search-realms",
        PathItemType::Post,
        "directory",
        "ck.find.directory.query.search_realms",
        "search realms",
    ),
    (
        "/_cokret/find/directory/resolve-realm",
        PathItemType::Post,
        "directory",
        "ck.find.directory.query.resolve_realm",
        "resolve realm",
    ),
    (
        "/_cokret/find/directory/resolve-agent-selector",
        PathItemType::Post,
        "directory",
        "ck.find.directory.query.resolve_agent_selector",
        "resolve agent selector",
    ),
    (
        "/_cokret/find/directory/list-handles-for-subject",
        PathItemType::Post,
        "directory",
        "ck.find.directory.query.list_handles_for_subject",
        "list handles for subject",
    ),
    (
        "/_soland/admin/actors",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.actors",
        "admin actor snapshot",
    ),
    (
        "/_soland/admin/realms",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.realms",
        "admin realm snapshot",
    ),
    (
        "/_soland/admin/spaces",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.space_containers",
        "admin space container snapshot",
    ),
    (
        "/_soland/admin/devices",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.devices",
        "admin device snapshot",
    ),
    (
        "/_soland/admin/capabilities",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.capabilities",
        "admin capability snapshot",
    ),
    (
        "/_soland/admin/federation",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.federation",
        "admin federation snapshot",
    ),
    (
        "/_soland/admin/applets",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.applets",
        "admin applet snapshot",
    ),
    (
        "/_soland/admin/agents",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.agents",
        "admin agent snapshot",
    ),
    (
        "/_soland/admin/reports",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.reports",
        "admin report snapshot",
    ),
    (
        "/_soland/admin/invite-tokens",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.invite_tokens",
        "admin invite token snapshot",
    ),
    (
        "/_soland/admin/audit",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.audit",
        "admin audit snapshot",
    ),
    (
        "/_soland/admin/policy",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.policy",
        "admin policy snapshot",
    ),
    (
        "/_soland/admin/media",
        PathItemType::Get,
        "soland-admin",
        "org.cokret.soland.admin.media",
        "admin media snapshot",
    ),
    (
        "/_cokret/self/authz/check",
        PathItemType::Post,
        "authz",
        "ck.self.authz.query.check",
        "check authorization",
    ),
    // policy_document CRUD (`ck.self.policy_document.*`) was promoted to the
    // protocol surface at `/_cokret/self/policies*`; its operation ids are now
    // emitted by the typed `#[endpoint]` handlers in `access/policy.rs`. The
    // soland-local PATCH compatibility route stays on the product surface but is
    // registered via its own `#[endpoint]` annotation, not this table.
    (
        "/_cokret/edge/push/register-device",
        PathItemType::Post,
        "push",
        "ck.edge.push.command.register_device",
        "register push device",
    ),
    (
        "/_soland/edge/push/outbound/bridge/cache/export",
        PathItemType::Get,
        "push",
        "org.cokret.soland.push.outbound_bridge_cache_export",
        "export outbound push bridge cache snapshots",
    ),
    (
        "/_soland/edge/push/outbound/bridge/cache/import",
        PathItemType::Post,
        "push",
        "org.cokret.soland.push.outbound_bridge_cache_import",
        "import outbound push bridge cache snapshots",
    ),
    (
        "/_cokret/self/keys/backups/{backup_id}",
        PathItemType::Put,
        "keys",
        "ck.self.keys.backups.resource.replace",
        "store encrypted key backup",
    ),
    (
        "/_cokret/self/keys/backups/{backup_id}/unlock",
        PathItemType::Post,
        "keys",
        "ck.self.keys.backups.command.unlock",
        "unlock encrypted key backup",
    ),
    (
        "/_cokret/self/keys/backups/{backup_id}",
        PathItemType::Delete,
        "keys",
        "ck.self.keys.backups.resource.delete",
        "delete encrypted key backup",
    ),
    (
        "/_cokret/self/keys/backups",
        PathItemType::Get,
        "keys",
        "ck.self.keys.backups.query.list",
        "list encrypted key backups",
    ),
    (
        "/_cokret/edge/push/unregister-device",
        PathItemType::Post,
        "push",
        "ck.edge.push.command.unregister_device",
        "unregister push device",
    ),
    (
        "/_cokret/edge/push/notify",
        PathItemType::Post,
        "push",
        "ck.edge.push.command.notify",
        "send push notification",
    ),
    (
        "/_cokret/self/blob/upload",
        PathItemType::Post,
        "blob",
        "ck.self.blob.upload.create",
        "upload blob bytes",
    ),
    (
        "/_cokret/self/blob/get",
        PathItemType::Head,
        "blob",
        "ck.self.blob.resource.head",
        "inspect blob metadata",
    ),
    (
        "/_cokret/self/blob/get",
        PathItemType::Get,
        "blob",
        "ck.self.blob.resource.get",
        "download blob bytes",
    ),
    (
        "/_cokret/self/moderation/report",
        PathItemType::Post,
        "moderation",
        "ck.self.moderation.command.report",
        "report moderation issue",
    ),
    (
        "/_cokret/open/mimi/provider-directory",
        PathItemType::Get,
        "mimi",
        "ck.open.mimi.query.provider_directory",
        "MIMI provider directory",
    ),
    (
        "/_cokret/open/mimi/key-material",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.exchange.request_key_material",
        "MIMI key material",
    ),
    (
        "/_cokret/open/mimi/strands/{strand_id}/update",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.update_room",
        "MIMI external room interop update",
    ),
    (
        "/_cokret/open/mimi/strands/{strand_id}/notify",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.notify",
        "MIMI external room interop notify",
    ),
    (
        "/_cokret/open/mimi/strands/{strand_id}/messages",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.submit_message",
        "MIMI external room interop submit message",
    ),
    (
        "/_cokret/open/mimi/strands/{strand_id}/group-info",
        PathItemType::Get,
        "mimi",
        "ck.open.mimi.query.group_info",
        "MIMI external room interop group info",
    ),
    (
        "/_cokret/open/mimi/consent/request",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.request_consent",
        "MIMI request consent",
    ),
    (
        "/_cokret/open/mimi/consent/update",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.update_consent",
        "MIMI update consent",
    ),
    (
        "/_cokret/open/mimi/identifiers/query",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.query.identifiers",
        "MIMI identifier query",
    ),
    (
        "/_cokret/open/mimi/report-abuse",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.report_abuse",
        "MIMI report abuse",
    ),
    (
        "/_cokret/open/mimi/proxy-download",
        PathItemType::Post,
        "mimi",
        "ck.open.mimi.command.proxy_download",
        "MIMI proxy download",
    ),
    // CKP-0008 / CKP-0009 (spec head 37ce729) — Personal Agent + Sidecar
    // operations. Implementation lives at
    // `routing::identity::agents`; the table here makes the operations
    // visible to the OpenAPI snapshot + the 404/405 disambiguator.
    (
        "/_cokret/gate/account/agent-key-pair",
        PathItemType::Post,
        "agents",
        "ck.gate.account.command.pair_agent_key",
        "authorize an agent runtime key pair",
    ),
    (
        "/_cokret/self/agents",
        PathItemType::Post,
        "agents",
        "ck.self.agent.command.provision",
        "provision a personal agent",
    ),
    (
        "/_cokret/self/agents",
        PathItemType::Get,
        "agents",
        "ck.self.agent.query.list",
        "list personal agents",
    ),
    (
        "/_cokret/self/agents/{agent_id}",
        PathItemType::Get,
        "agents",
        "ck.self.agent.resource.get",
        "get a personal agent by id",
    ),
    (
        "/_cokret/self/agents/{agent_id}/pause",
        PathItemType::Post,
        "agents",
        "ck.self.agent.command.pause",
        "pause a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/resume",
        PathItemType::Post,
        "agents",
        "ck.self.agent.command.resume",
        "resume a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/deactivate",
        PathItemType::Post,
        "agents",
        "ck.self.agent.command.deactivate",
        "deactivate a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/rotate-key",
        PathItemType::Post,
        "agents",
        "ck.self.agent.command.rotate_key",
        "rotate a personal agent key",
    ),
    (
        "/_cokret/self/agents/{agent_id}/grants",
        PathItemType::Post,
        "agents",
        "ck.self.agent.grant.command.attach",
        "attach a capability grant to a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/grants/{grant_id}",
        PathItemType::Delete,
        "agents",
        "ck.self.agent.grant.resource.delete",
        "detach a capability grant from a personal agent",
    ),
    // CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — media
    // token exchange + signed ICE config. Canonical wire paths now live on
    // the `self` trust segment (`/_cokret/self/rtc/...`); the historical
    // `/cokret/v1/...` and `/api/v1/...` aliases are gone.
    (
        "/_cokret/self/rtc/token",
        PathItemType::Post,
        "media",
        "ck.self.call.media.exchange.issue_token",
        "exchange session-focus for backend media token + participant_binding",
    ),
    (
        "/_cokret/self/rtc/ice-config",
        PathItemType::Post,
        "media",
        "ck.self.media.query.ice_config",
        "issue signed ICE config",
    ),
    // R3 spec-sync — recovery policy read/publish are canonical; history stays
    // on the deployment-local `_soland` surface.
    (
        "/_cokret/root/identity/recovery-policy",
        PathItemType::Get,
        "identity",
        "ck.root.identity.recovery_policy.resource.get",
        "read the active recovery policy",
    ),
    (
        "/_cokret/root/identity/recovery-policy",
        PathItemType::Post,
        "identity",
        "ck.root.identity.recovery_policy.command.publish",
        "submit a ck.schema.recovery_policy.v1 policy",
    ),
    (
        "/_soland/root/identity/recovery-receipt",
        PathItemType::Post,
        "identity",
        "org.cokret.soland.identity.recovery_receipt.put",
        "submit a ck.schema.recovery_receipt.v1 receipt",
    ),
];

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "cokret_openapi_yaml"))]
pub(crate) async fn cokret_openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = depot
        .obtain::<CokretOpenApiDoc>()
        .expect("openapi doc injected");
    let spec = doc.0.to_yaml().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render openapi yaml");
        "{}\n".to_owned()
    });
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        "application/yaml; charset=utf-8".parse().unwrap(),
    );
    res.headers_mut().insert(
        salvo::http::header::CONTENT_LENGTH,
        spec.len().to_string().parse().unwrap(),
    );
    res.write_body(spec.as_bytes().to_vec()).ok();
}
