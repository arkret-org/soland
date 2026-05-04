pub mod artifacts;
pub mod authz;
pub mod config;
pub mod db;
pub mod handlers;
pub mod hlc;
pub mod ids;
pub mod kinds;
pub mod persistence;
pub mod ratelimit;
pub mod reducer;
pub mod repo;
pub mod schema;
pub mod state;
pub mod wire;

use salvo::affix_state;
use salvo::catcher::Catcher;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::Method;
use salvo::oapi::{
    Array, BasicType, Object, OpenApi, Operation, PathItem, PathItemType, Ref, RefOr,
    Response as OapiResponse, RouterExt, Schema,
};
use salvo::prelude::*;
use serde_json::json;
use std::sync::OnceLock;

use crate::{
    handlers::*,
    ratelimit::{RateLimiter, RateLimiterConfig, RateLimiterMiddleware},
    state::AppState,
};

pub fn service(state: AppState) -> Service {
    Service::new(router(state)).catcher(Catcher::default().hoop(error_catcher))
}

pub fn service_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Service {
    Service::new(router_with_rate_limiter_config(state, rate_limiter_config))
        .catcher(Catcher::default().hoop(error_catcher))
}

pub fn router(state: AppState) -> Router {
    router_with_rate_limiter_config(state, RateLimiterConfig::default())
}

pub fn router_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Router {
    let cors_allow_origin = state.config.cors_allow_origin.clone();
    let rate_limiter = RateLimiter::new(rate_limiter_config);
    let mut router = Router::new()
        .hoop(affix_state::inject(state))
        .hoop(RateLimiterMiddleware::new(rate_limiter));
    if let Some(origin) = cors_allow_origin {
        router = router.hoop(cors_handler_for_origin(origin));
    }
    let router = router
        .push(Router::with_path("health").get(health))
        .push(Router::with_path(".well-known/mimi-protocol-directory").get(mimi_protocol_directory))
        .push(
            Router::with_path("api/v1")
                .oapi_tag("api")
                .hoop(wait_for_sync_token)
                .push(Router::with_path("server/describe").get(server_describe))
                .push(Router::with_path("integration/describe").get(integration_describe))
                .push(Router::with_path("auth/bridge/describe").get(auth_bridge_describe))
                .push(Router::with_path("account/register").post(account_register))
                .push(Router::with_path("account/me").get(account_me))
                .push(Router::with_path("auth/dev-login").post(dev_login))
                .push(
                    Router::with_path("auth/session-grant/exchange")
                        .post(exchange_session_grant),
                )
                .push(Router::with_path("auth/logout").post(logout))
                .push(Router::with_path("contacts/request").post(contact_request))
                .push(Router::with_path("contacts/respond").post(contact_respond))
                .push(Router::with_path("contacts").get(list_contacts))
                .push(Router::with_path("spaces").post(create_space))
                .push(Router::with_path("spaces/{space_id}").delete(delete_space))
                .push(Router::with_path("spaces/{space_id}/export").get(export_space))
                .push(Router::with_path("spaces/{space_id}/members").post(add_space_member))
                .push(
                    Router::with_path("spaces/{space_id}/members/{member_did}")
                        .delete(remove_space_member),
                )
                .push(Router::with_path("messages/send").post(send_message))
                .push(Router::with_path("messages/revise").post(revise_message))
                .push(Router::with_path("messages/redact").post(redact_message))
                .push(
                    Router::with_path("reactions")
                        .post(add_reaction)
                        .delete(remove_reaction),
                )
                .push(
                    Router::with_path("read-markers")
                        .post(set_read_marker)
                        .get(get_read_markers),
                )
                .push(
                    Router::with_path("entities")
                        .post(create_entity)
                        .get(list_entities),
                )
                .push(
                    Router::with_path("entities/{entity_id}")
                        .get(get_entity)
                        .patch(update_entity)
                        .delete(delete_entity),
                )
                .push(
                    Router::with_path("relations")
                        .post(create_relation)
                        .get(list_relations),
                )
                .push(Router::with_path("relations/{relation_id}").delete(delete_relation))
                .push(Router::with_path("views").post(create_view))
                .push(Router::with_path("views/{view_id}").get(get_view))
                .push(
                    Router::with_path("schemas")
                        .get(list_schemas)
                        .post(register_schema),
                )
                .push(
                    Router::with_path("schemas/{schema_id}")
                        .get(get_schema)
                        .delete(delete_schema),
                )
                .push(Router::with_path("identity/describe").get(identity_describe))
                .push(Router::with_path("identity/resolve").post(identity_resolve))
                .push(Router::with_path("identity/document").get(identity_document))
                .push(Router::with_path("identity/log").get(identity_log))
                .push(Router::with_path("identity/submit-did-operation").post(submit_did_operation))
                .push(Router::with_path("identity/receipts").get(identity_receipts))
                .push(Router::with_path("sync/describe").get(sync_describe))
                .push(Router::with_path("sync").post(client_sync))
                .push(Router::with_path("sync/typing").post(set_typing))
                .push(Router::with_path("sync/subscribe").get(sync_subscribe))
                .push(Router::with_path("sync/backfill").get(sync_backfill))
                .push(Router::with_path("sync/backfill/gap").get(sync_gap_backfill))
                .push(Router::with_path("sync/snapshot-head").get(snapshot_head))
                .push(Router::with_path("sync/snapshot-chunk").get(snapshot_chunk))
                .push(Router::with_path("events/describe").get(events_describe))
                .push(
                    Router::with_path("events")
                        .post(submit_event)
                        .get(list_events),
                )
                .push(Router::with_path("events/batch-get").post(batch_get_events))
                .push(Router::with_path("events/frontier").get(events_frontier))
                .push(Router::with_path("events/{event_id}").get(get_event))
                .push(Router::with_path("directory/describe").get(directory_describe))
                .push(Router::with_path("directory/search-spaces").post(search_spaces))
                .push(Router::with_path("directory/resolve-space").post(resolve_space))
                .push(
                    Router::with_path("directory/search-organizations").post(search_organizations),
                )
                .push(
                    Router::with_path("directory/resolve-organization").post(resolve_organization),
                )
                .push(Router::with_path("directory/search-actors").post(search_actors))
                .push(Router::with_path("directory/search-users").get(search_users))
                .push(Router::with_path("directory/resolve-handle").post(resolve_handle))
                .push(Router::with_path("index/describe").get(index_describe))
                .push(Router::with_path("index/debug/reducer").get(index_reducer_debug))
                .push(Router::with_path("index/entity").get(index_entity))
                .push(Router::with_path("index/query").post(index_query))
                .push(Router::with_path("index/thread").get(index_thread))
                .push(Router::with_path("index/notifications").get(index_notifications))
                .push(Router::with_path("index/inbox").get(index_inbox))
                .push(Router::with_path("index/search").post(index_search))
                .push(Router::with_path("index/space-hierarchy").get(index_space_hierarchy))
                .push(Router::with_path("repo/describe").get(repo_describe))
                .push(Router::with_path("repo/commits").get(list_commits))
                .push(Router::with_path("repo/commit").get(get_commit))
                .push(Router::with_path("repo/operations").post(get_operations))
                .push(Router::with_path("repo/sync").post(repo_sync))
                .push(Router::with_path("repo/submit-commit").post(submit_commit))
                .push(Router::with_path("recovery/contract-stack").get(recovery_contract_stack))
                .push(Router::with_path("authz/describe").get(authz_describe))
                .push(Router::with_path("authz/check").post(authz_check))
                .push(Router::with_path("authz/effective-grants").get(effective_grants))
                .push(Router::with_path("authz/grants").post(create_grant))
                .push(Router::with_path("authz/grants/{grant_id}").delete(revoke_grant))
                .push(Router::with_path("authz/invites").get(invites))
                .push(Router::with_path("admin/{resource}").get(admin_collection))
                .push(Router::with_path("audit/events").get(audit_events))
                .push(
                    Router::with_path("policies")
                        .get(list_policy_documents)
                        .post(upsert_policy_document),
                )
                .push(Router::with_path("policies/describe").get(policies_describe))
                .push(
                    Router::with_path("policies/{policy_id}")
                        .get(get_policy_document)
                        .delete(delete_policy_document),
                )
                .push(Router::with_path("profile/presence").get(profile_presence))
                .push(Router::with_path("push/register-device").post(push_register))
                .push(Router::with_path("push/unregister-device").post(push_unregister))
                .push(
                    Router::with_path("push/outbound/bridge/describe")
                        .get(outbound_push_bridge_describe),
                )
                .push(
                    Router::with_path("push/outbound/bridge/resolve")
                        .post(outbound_push_bridge_resolve),
                )
                .push(
                    Router::with_path("push/outbound/bridge/fetch")
                        .post(outbound_push_bridge_fetch),
                )
                .push(
                    Router::with_path("push/outbound/bridge/cache/status")
                        .get(outbound_push_bridge_cache_status),
                )
                .push(
                    Router::with_path("push/outbound/bridge/cache/export")
                        .get(outbound_push_bridge_cache_export),
                )
                .push(
                    Router::with_path("push/outbound/bridge/cache/import")
                        .post(outbound_push_bridge_cache_import),
                )
                .push(
                    Router::with_path("push/outbound/bridge/cache/invalidate")
                        .post(outbound_push_bridge_cache_invalidate),
                )
                .push(
                    Router::with_path("push/rules")
                        .get(push_rules)
                        .post(upsert_push_rule),
                )
                .push(Router::with_path("push/rules/{rule_id}").delete(delete_push_rule))
                .push(Router::with_path("push/notify").post(push_notify))
                .push(Router::with_path("devices/pairing-challenge").post(device_pairing_challenge))
                .push(Router::with_path("devices/authorize-pairing").post(device_authorize_pairing))
                .push(Router::with_path("keys/upload").post(keys_upload))
                .push(Router::with_path("keys/query").post(keys_query))
                .push(Router::with_path("keys/claim").post(keys_claim))
                .push(
                    Router::with_path("keys/backups/describe")
                        .get(key_backups_describe),
                )
                .push(
                    Router::with_path("keys/backups/restore-state/describe")
                        .get(get_key_backup_restore_state_describe),
                )
                .push(
                    Router::with_path("keys/backups/restore-state/export")
                        .get(get_key_backup_restore_state_export),
                )
                .push(
                    Router::with_path("keys/backups/restore-state/import")
                        .post(post_key_backup_restore_state_import),
                )
                .push(
                    Router::with_path("keys/backups/{backup_id}/restore/describe")
                        .get(get_key_backup_restore_describe),
                )
                .push(
                    Router::with_path("keys/backups/{backup_id}/restore/start")
                        .post(post_key_backup_restore_start),
                )
                .push(
                    Router::with_path("keys/backups/restore-tickets/{ticket_id}")
                        .get(get_key_backup_restore_ticket),
                )
                .push(
                    Router::with_path("keys/backups/restore-tickets/{ticket_id}/advance")
                        .post(post_key_backup_restore_ticket_advance),
                )
                .push(
                    Router::with_path("keys/backups/restore-tickets/{ticket_id}/approvals/status")
                        .get(get_key_backup_restore_approval_status),
                )
                .push(
                    Router::with_path("keys/backups/restore-tickets/{ticket_id}/approvals/submit")
                        .post(post_key_backup_restore_approval_submit),
                )
                .push(
                    Router::with_path("keys/backups/restore-tickets/{ticket_id}/executor/status")
                        .get(get_key_backup_restore_executor_status),
                )
                .push(
                    Router::with_path("keys/backups/restore-tickets/{ticket_id}/executor/enqueue")
                        .post(post_key_backup_restore_executor_enqueue),
                )
                .push(
                    Router::with_path("keys/backups/{backup_id}")
                        .put(put_key_backup)
                        .get(get_key_backup)
                        .delete(delete_key_backup),
                )
                .push(Router::with_path("keys/backups").get(list_key_backups))
                .push(Router::with_path("device_messages/describe").get(device_messages_describe))
                .push(Router::with_path("device_messages/{txn_id}").put(put_device_messages))
                .push(Router::with_path("device_messages").get(get_device_messages))
                .push(
                    Router::with_path("federation/transactions/{txn_id}")
                        .put(federation_transaction),
                )
                .push(
                    Router::with_path("federation/push-operations")
                        .post(federation_push_operations),
                )
                .push(
                    Router::with_path("federation/pull-operations").get(federation_pull_operations),
                )
                .push(Router::with_path("federation/space-members").get(federation_space_members))
                .push(Router::with_path("federation/verify-actor").post(federation_verify_actor))
                .push(Router::with_path("webrtc/sessions").post(create_webrtc_session))
                .push(
                    Router::with_path("webrtc/sessions/{session_id}/signals")
                        .post(put_webrtc_signal)
                        .get(get_webrtc_signals),
                )
                .push(
                    Router::with_path("webrtc/sessions/{session_id}").delete(delete_webrtc_session),
                )
                .push(Router::with_path("blob/upload").post(blob_upload))
                .push(Router::with_path("blob/get").get(blob_get).head(blob_get))
                .push(Router::with_path("moderation/report").post(moderation_report))
                .push(Router::with_path("mimi/provider-directory").get(mimi_provider_directory))
                .push(Router::with_path("mimi/key-material").post(mimi_key_material))
                .push(Router::with_path("mimi/rooms/{room_id}/update").put(mimi_room_update))
                .push(Router::with_path("mimi/rooms/{room_id}/notify").post(mimi_room_notify))
                .push(Router::with_path("mimi/rooms/{room_id}/messages").post(mimi_room_message))
                .push(Router::with_path("mimi/rooms/{room_id}/group-info").get(mimi_group_info))
                .push(Router::with_path("mimi/consent/request").post(mimi_consent_request))
                .push(Router::with_path("mimi/consent/update").post(mimi_consent_update))
                .push(Router::with_path("mimi/identifiers/query").post(mimi_identifiers_query))
                .push(Router::with_path("mimi/report-abuse").post(mimi_report_abuse))
                .push(Router::with_path("mimi/proxy-download").post(mimi_proxy_download))
                .push(
                    Router::with_path("{**rest}")
                        .options(cors_preflight)
                        .get(api_not_found),
                ),
        )
        .push(Router::with_path("contrix/v1/check").post(policy_check))
        .push(Router::with_path("contrix/v1/ice-config").post(ice_config));
    let doc = cached_contrix_openapi_doc(&router);
    router
        .unshift(
            Router::with_path(".well-known/contrix/openapi.yaml")
                .hoop(affix_state::inject(ContrixOpenApiDoc(doc.clone())))
                .get(contrix_openapi_yaml),
        )
        .unshift(doc.into_router(".well-known/contrix/openapi.json"))
}

static CONTRIX_OPENAPI_DOC: OnceLock<OpenApi> = OnceLock::new();

fn cached_contrix_openapi_doc(router: &Router) -> OpenApi {
    CONTRIX_OPENAPI_DOC
        .get_or_init(|| contrix_openapi_doc(router))
        .clone()
}

fn contrix_openapi_doc(router: &Router) -> OpenApi {
    let mut doc = OpenApi::new("soland", "0.1.0")
        .add_extension(
            "x-operation-aliases",
            json!({
                "events.submit": "cx.events.submit",
                "index.query": "cx.index.query",
                "repo.submit_commit": "cx.repo.submit_commit",
                "sync.backfill": "cx.sync.backfill",
            }),
        )
        .add_extension(
            "x-contrix-artifacts",
            json!({
                "registries": crate::artifacts::registry_summary(),
                "openapi_source": "contrix-spec/artifacts/openapi/contrix-service-api.openapi.yaml"
            }),
        )
        .merge_router(router);
    register_contract_components(&mut doc);
    register_contract_operations(&mut doc);
    doc
}

fn register_contract_components(doc: &mut OpenApi) {
    let string_schema = Object::with_type(BasicType::String);
    doc.components.schemas.insert(
        "FacetName",
        schema_object(Object::with_type(BasicType::String).enum_values([
            "container",
            "replyable",
            "renderable",
            "stateful",
            "rankable",
        ])),
    );
    doc.components.schemas.insert(
        "ViewRenderer",
        schema_object(Object::with_type(BasicType::String).enum_values([
            "collection",
            "conversation",
            "graph",
            "queue",
            "timeline",
        ])),
    );
    doc.components.schemas.insert(
        "FacetConstraint",
        schema_object(
            Object::with_type(BasicType::Object)
                .required("type")
                .required("facets")
                .property(
                    "type",
                    Object::with_type(BasicType::String).enum_values(["allowed_entity_facets"]),
                )
                .property(
                    "facets",
                    Array::new().items(Ref::from_schema_name("FacetName")),
                ),
        ),
    );
    doc.components.schemas.insert(
        "IndexQueryRequest",
        schema_object(
            Object::with_type(BasicType::Object)
                .property("renderer", Ref::from_schema_name("ViewRenderer"))
                .property(
                    "facets",
                    Array::new().items(Ref::from_schema_name("FacetName")),
                )
                .property("filters", Object::with_type(BasicType::Object))
                .property(
                    "sort",
                    Array::new().items(Object::with_type(BasicType::Object)),
                )
                .property("cursor", string_schema.clone())
                .property("limit", Object::with_type(BasicType::Integer)),
        ),
    );
}

fn schema_object(object: Object) -> RefOr<Schema> {
    RefOr::Type(Schema::object(object))
}

fn register_contract_operations(doc: &mut OpenApi) {
    // TODO(openapi): migrate handlers to Salvo `#[endpoint]` extractors and
    // ToSchema response types, then remove this compatibility contract table.
    for (path, method, tag, operation_id, summary) in CONTRACT_OPERATIONS {
        add_contract_operation(doc, path, *method, tag, operation_id, summary);
    }
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
    doc.paths.insert(path, PathItem::new(method, operation));
}

const CONTRACT_OPERATIONS: &[(&str, PathItemType, &str, &str, &str)] = &[
    (
        "/health",
        PathItemType::Get,
        "system",
        "cx.system.health",
        "health and liveness",
    ),
    (
        "/api/v1/account/register",
        PathItemType::Post,
        "account",
        "cx.account.register",
        "register account",
    ),
    (
        "/api/v1/account/me",
        PathItemType::Get,
        "account",
        "cx.account.me",
        "get current account",
    ),
    (
        "/api/v1/auth/session-grant/exchange",
        PathItemType::Post,
        "auth",
        "cx.auth.exchange_session_grant",
        "exchange coauth session grant for principal bearer session",
    ),
    (
        "/api/v1/auth/logout",
        PathItemType::Post,
        "auth",
        "cx.auth.logout",
        "logout active session",
    ),
    (
        "/api/v1/contacts/request",
        PathItemType::Post,
        "contacts",
        "cx.contacts.request",
        "request contact",
    ),
    (
        "/api/v1/contacts/respond",
        PathItemType::Post,
        "contacts",
        "cx.contacts.respond",
        "respond to contact request",
    ),
    (
        "/api/v1/contacts",
        PathItemType::Get,
        "contacts",
        "cx.contacts.list",
        "list contacts",
    ),
    (
        "/api/v1/spaces",
        PathItemType::Post,
        "spaces",
        "cx.spaces.create",
        "create space",
    ),
    (
        "/api/v1/spaces/{space_id}",
        PathItemType::Delete,
        "spaces",
        "cx.spaces.delete",
        "delete space",
    ),
    (
        "/api/v1/server/describe",
        PathItemType::Get,
        "server",
        "cx.server.describe",
        "server feature description",
    ),
    (
        "/api/v1/spaces/{space_id}/members",
        PathItemType::Post,
        "spaces",
        "cx.spaces.add_member",
        "add space member",
    ),
    (
        "/api/v1/spaces/{space_id}/members/{member_did}",
        PathItemType::Delete,
        "spaces",
        "cx.spaces.remove_member",
        "remove space member",
    ),
    (
        "/api/v1/messages/send",
        PathItemType::Post,
        "messages",
        "cx.messages.send",
        "send message",
    ),
    (
        "/api/v1/events/describe",
        PathItemType::Get,
        "events",
        "cx.events.describe",
        "describe Event Envelope ingestion profile",
    ),
    (
        "/api/v1/events",
        PathItemType::Post,
        "events",
        "cx.events.submit",
        "submit one Event Envelope",
    ),
    (
        "/api/v1/events/{event_id}",
        PathItemType::Get,
        "events",
        "cx.events.get",
        "get one Event Envelope",
    ),
    (
        "/api/v1/events/batch-get",
        PathItemType::Post,
        "events",
        "cx.events.batch_get",
        "get multiple Event Envelopes",
    ),
    (
        "/api/v1/events",
        PathItemType::Get,
        "events",
        "cx.events.list",
        "list Event Envelopes",
    ),
    (
        "/api/v1/events/frontier",
        PathItemType::Get,
        "events",
        "cx.events.frontier",
        "get Event frontier",
    ),
    (
        "/api/v1/repo/describe",
        PathItemType::Get,
        "repo",
        "cx.repo.describe",
        "get repo metadata",
    ),
    (
        "/api/v1/repo/commits",
        PathItemType::Get,
        "repo",
        "cx.repo.list_commits",
        "list commits",
    ),
    (
        "/api/v1/repo/operations",
        PathItemType::Post,
        "repo",
        "cx.repo.get_operations",
        "fetch operations by id",
    ),
    (
        "/api/v1/repo/sync",
        PathItemType::Post,
        "repo",
        "cx.repo.sync",
        "sync repo operations",
    ),
    (
        "/api/v1/index/query",
        PathItemType::Post,
        "index",
        "cx.index.query",
        "run indexed query",
    ),
    (
        "/api/v1/authz/effective-grants",
        PathItemType::Get,
        "authz",
        "cx.authz.get_effective_grants",
        "get effective grants",
    ),
    (
        "/api/v1/authz/invites",
        PathItemType::Get,
        "authz",
        "cx.authz.get_invites",
        "list invites",
    ),
    (
        "/api/v1/repo/submit-commit",
        PathItemType::Post,
        "repo",
        "cx.repo.submit_commit",
        "append commit with canonical operations",
    ),
    (
        "/api/v1/federation/transactions/{txn_id}",
        PathItemType::Put,
        "federation",
        "cx.federation.transaction",
        "submit federation transaction",
    ),
    (
        "/api/v1/federation/push-operations",
        PathItemType::Post,
        "federation",
        "cx.federation.push_operations",
        "push federation operations",
    ),
    (
        "/api/v1/federation/pull-operations",
        PathItemType::Get,
        "federation",
        "cx.federation.pull_operations",
        "pull federation operations",
    ),
    (
        "/api/v1/federation/space-members",
        PathItemType::Get,
        "federation",
        "cx.federation.space_members",
        "list space memberships",
    ),
    (
        "/api/v1/federation/verify-actor",
        PathItemType::Post,
        "federation",
        "cx.federation.verify_actor",
        "verify federation actor",
    ),
    (
        "/api/v1/sync",
        PathItemType::Post,
        "sync",
        "cx.sync.client_sync",
        "client sync",
    ),
    (
        "/api/v1/sync/typing",
        PathItemType::Post,
        "sync",
        "cx.sync.typing",
        "set typing state",
    ),
    (
        "/api/v1/sync/backfill",
        PathItemType::Get,
        "sync",
        "cx.sync.backfill",
        "sync backfill",
    ),
    (
        "/api/v1/sync/backfill/gap",
        PathItemType::Get,
        "sync",
        "cx.sync.backfill_gap",
        "sync gap backfill",
    ),
    (
        "/api/v1/sync/snapshot-head",
        PathItemType::Get,
        "sync",
        "cx.sync.get_snapshot_head",
        "snapshot head",
    ),
    (
        "/api/v1/sync/snapshot-chunk",
        PathItemType::Get,
        "sync",
        "cx.sync.get_snapshot_chunk",
        "snapshot chunk",
    ),
    (
        "/api/v1/directory/describe",
        PathItemType::Get,
        "directory",
        "cx.directory.describe",
        "directory describe",
    ),
    (
        "/api/v1/directory/search-spaces",
        PathItemType::Post,
        "directory",
        "cx.directory.search_spaces",
        "search spaces",
    ),
    (
        "/api/v1/directory/resolve-space",
        PathItemType::Post,
        "directory",
        "cx.directory.resolve_space",
        "resolve space",
    ),
    (
        "/api/v1/index/describe",
        PathItemType::Get,
        "index",
        "cx.index.describe",
        "index describe",
    ),
    (
        "/api/v1/index/debug/reducer",
        PathItemType::Get,
        "index",
        "cx.index.debug_reducer",
        "explain reducer projection frontier",
    ),
    (
        "/api/v1/admin/actors",
        PathItemType::Get,
        "admin",
        "cx.admin.actors",
        "admin actor snapshot",
    ),
    (
        "/api/v1/admin/spaces",
        PathItemType::Get,
        "admin",
        "cx.admin.spaces",
        "admin space snapshot",
    ),
    (
        "/api/v1/admin/devices",
        PathItemType::Get,
        "admin",
        "cx.admin.devices",
        "admin device snapshot",
    ),
    (
        "/api/v1/admin/capabilities",
        PathItemType::Get,
        "admin",
        "cx.admin.capabilities",
        "admin capability snapshot",
    ),
    (
        "/api/v1/admin/federation",
        PathItemType::Get,
        "admin",
        "cx.admin.federation",
        "admin federation snapshot",
    ),
    (
        "/api/v1/admin/applets",
        PathItemType::Get,
        "admin",
        "cx.admin.applets",
        "admin applet snapshot",
    ),
    (
        "/api/v1/admin/agents",
        PathItemType::Get,
        "admin",
        "cx.admin.agents",
        "admin agent snapshot",
    ),
    (
        "/api/v1/admin/reports",
        PathItemType::Get,
        "admin",
        "cx.admin.reports",
        "admin report snapshot",
    ),
    (
        "/api/v1/admin/invite-tokens",
        PathItemType::Get,
        "admin",
        "cx.admin.invite_tokens",
        "admin invite token snapshot",
    ),
    (
        "/api/v1/admin/audit",
        PathItemType::Get,
        "admin",
        "cx.admin.audit",
        "admin audit snapshot",
    ),
    (
        "/api/v1/admin/policy",
        PathItemType::Get,
        "admin",
        "cx.admin.policy",
        "admin policy snapshot",
    ),
    (
        "/api/v1/admin/media",
        PathItemType::Get,
        "admin",
        "cx.admin.media",
        "admin media snapshot",
    ),
    (
        "/api/v1/authz/check",
        PathItemType::Post,
        "authz",
        "cx.authz.check",
        "check authorization",
    ),
    (
        "/api/v1/policies",
        PathItemType::Get,
        "policy",
        "cx.policies.list",
        "list policies",
    ),
    (
        "/api/v1/policies/{policy_id}",
        PathItemType::Get,
        "policy",
        "cx.policies.get",
        "get policy",
    ),
    (
        "/api/v1/policies",
        PathItemType::Post,
        "policy",
        "cx.policies.upsert",
        "upsert policy",
    ),
    (
        "/api/v1/policies/{policy_id}",
        PathItemType::Delete,
        "policy",
        "cx.policies.delete",
        "delete policy",
    ),
    (
        "/api/v1/push/register-device",
        PathItemType::Post,
        "push",
        "cx.push.register_device",
        "register push device",
    ),
    (
        "/api/v1/push/outbound/bridge/cache/export",
        PathItemType::Get,
        "push",
        "cx.push.outbound_bridge_cache_export",
        "export outbound push bridge cache snapshots",
    ),
    (
        "/api/v1/push/outbound/bridge/cache/import",
        PathItemType::Post,
        "push",
        "cx.push.outbound_bridge_cache_import",
        "import outbound push bridge cache snapshots",
    ),
    (
        "/api/v1/keys/backups/restore-state/describe",
        PathItemType::Get,
        "keys",
        "cx.keys.backups.restore_state_describe",
        "describe restore-state snapshot store scaffold",
    ),
    (
        "/api/v1/keys/backups/restore-state/export",
        PathItemType::Get,
        "keys",
        "cx.keys.backups.restore_state_export",
        "export restore-state snapshots",
    ),
    (
        "/api/v1/keys/backups/restore-state/import",
        PathItemType::Post,
        "keys",
        "cx.keys.backups.restore_state_import",
        "import restore-state snapshots",
    ),
    (
        "/api/v1/keys/backups/{backup_id}",
        PathItemType::Put,
        "keys",
        "cx.keys.backups.put",
        "store encrypted key backup",
    ),
    (
        "/api/v1/keys/backups/{backup_id}",
        PathItemType::Get,
        "keys",
        "cx.keys.backups.get",
        "get encrypted key backup",
    ),
    (
        "/api/v1/keys/backups/{backup_id}",
        PathItemType::Delete,
        "keys",
        "cx.keys.backups.delete",
        "delete encrypted key backup",
    ),
    (
        "/api/v1/keys/backups",
        PathItemType::Get,
        "keys",
        "cx.keys.backups.list",
        "list encrypted key backups",
    ),
    (
        "/api/v1/devices/pairing-challenge",
        PathItemType::Post,
        "devices",
        "cx.devices.pairing_challenge",
        "create device pairing challenge",
    ),
    (
        "/api/v1/devices/authorize-pairing",
        PathItemType::Post,
        "devices",
        "cx.devices.authorize_pairing",
        "authorize device pairing",
    ),
    (
        "/api/v1/push/unregister-device",
        PathItemType::Post,
        "push",
        "cx.push.unregister_device",
        "unregister push device",
    ),
    (
        "/api/v1/push/rules",
        PathItemType::Get,
        "push",
        "cx.push.rules",
        "list push rules",
    ),
    (
        "/api/v1/push/notify",
        PathItemType::Post,
        "push",
        "cx.push.notify",
        "send push notification",
    ),
    (
        "/api/v1/webrtc/sessions",
        PathItemType::Post,
        "webrtc",
        "cx.webrtc.create_session",
        "create WebRTC session",
    ),
    (
        "/api/v1/webrtc/sessions/{session_id}/signals",
        PathItemType::Post,
        "webrtc",
        "cx.webrtc.send_signal",
        "send WebRTC signal",
    ),
    (
        "/api/v1/webrtc/sessions/{session_id}",
        PathItemType::Delete,
        "webrtc",
        "cx.webrtc.close_session",
        "close WebRTC session",
    ),
    (
        "/contrix/v1/check",
        PathItemType::Post,
        "policy",
        "cx.policy.check",
        "policy check",
    ),
    (
        "/api/v1/moderation/report",
        PathItemType::Post,
        "moderation",
        "cx.moderation.report",
        "report moderation issue",
    ),
    (
        "/api/v1/mimi/provider-directory",
        PathItemType::Get,
        "mimi",
        "cx.mimi.provider_directory",
        "MIMI provider directory",
    ),
    (
        "/api/v1/mimi/key-material",
        PathItemType::Post,
        "mimi",
        "cx.mimi.key_material",
        "MIMI key material",
    ),
    (
        "/api/v1/mimi/rooms/{room_id}/update",
        PathItemType::Put,
        "mimi",
        "cx.mimi.room_update",
        "MIMI external room interop update",
    ),
    (
        "/api/v1/mimi/rooms/{room_id}/notify",
        PathItemType::Post,
        "mimi",
        "cx.mimi.notify",
        "MIMI external room interop notify",
    ),
    (
        "/api/v1/mimi/rooms/{room_id}/messages",
        PathItemType::Post,
        "mimi",
        "cx.mimi.submit_message",
        "MIMI external room interop submit message",
    ),
    (
        "/api/v1/mimi/rooms/{room_id}/group-info",
        PathItemType::Get,
        "mimi",
        "cx.mimi.group_info",
        "MIMI external room interop group info",
    ),
    (
        "/api/v1/mimi/consent/request",
        PathItemType::Post,
        "mimi",
        "cx.mimi.request_consent",
        "MIMI request consent",
    ),
    (
        "/api/v1/mimi/consent/update",
        PathItemType::Post,
        "mimi",
        "cx.mimi.update_consent",
        "MIMI update consent",
    ),
    (
        "/api/v1/mimi/identifiers/query",
        PathItemType::Post,
        "mimi",
        "cx.mimi.identifier_query",
        "MIMI identifier query",
    ),
    (
        "/api/v1/mimi/report-abuse",
        PathItemType::Post,
        "mimi",
        "cx.mimi.report_abuse",
        "MIMI report abuse",
    ),
    (
        "/api/v1/mimi/proxy-download",
        PathItemType::Post,
        "mimi",
        "cx.mimi.proxy_download",
        "MIMI proxy download",
    ),
];

#[handler]
async fn cors_preflight(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[handler]
async fn api_not_found(res: &mut Response) {
    res.status_code(StatusCode::NOT_FOUND);
}

fn cors_handler_for_origin(origin: String) -> CorsHandler {
    Cors::new()
        .allow_origin(vec![origin.as_str()])
        .allow_credentials(true)
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ])
        .allow_headers(vec![
            "authorization",
            "content-type",
            "x-contrix-wait-for",
            "x-contrix-sha256",
            "range",
        ])
        .expose_headers(vec![
            "retry-after",
            "x-contrix-wait-for-satisfied",
            "content-range",
            "accept-ranges",
        ])
        .max_age(3600)
        .into_handler()
}
