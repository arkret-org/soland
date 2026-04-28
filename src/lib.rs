pub mod authz;
pub mod config;
pub mod db;
pub mod handlers;
pub mod hlc;
pub mod ids;
pub mod persistence;
pub mod ratelimit;
pub mod reducer;
pub mod repo;
pub mod schema;
pub mod state;
pub mod wire;

use salvo::affix_state;
use salvo::catcher::Catcher;
use salvo::prelude::*;

use crate::{
    handlers::*,
    ratelimit::{RateLimiter, RateLimiterConfig, RateLimiterMiddleware},
    state::AppState,
};

pub fn service(state: AppState) -> Service {
    Service::new(router(state)).catcher(Catcher::default().hoop(error_catcher))
}

pub fn router(state: AppState) -> Router {
    let rate_limiter = RateLimiter::new(RateLimiterConfig::default());
    Router::new()
        .hoop(affix_state::inject(state))
        .hoop(RateLimiterMiddleware::new(rate_limiter))
        .push(Router::with_path("health").get(health))
        .push(
            Router::with_path("api/v1")
                .hoop(wait_for_sync_token)
                .push(Router::with_path("server/describe").get(server_describe))
                .push(Router::with_path("account/register").post(account_register))
                .push(Router::with_path("account/me").get(account_me))
                .push(Router::with_path("auth/dev-login").post(dev_login))
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
                .push(Router::with_path("identity/describe").get(identity_describe))
                .push(Router::with_path("identity/resolve").post(identity_resolve))
                .push(Router::with_path("identity/document").get(identity_document))
                .push(Router::with_path("identity/log").get(identity_log))
                .push(Router::with_path("identity/submit-did-operation").post(submit_did_operation))
                .push(Router::with_path("identity/receipts").get(identity_receipts))
                .push(Router::with_path("sync/describe").get(sync_describe))
                .push(Router::with_path("sync").post(client_sync))
                .push(Router::with_path("sync/subscribe").get(sync_subscribe))
                .push(Router::with_path("sync/backfill").get(sync_backfill))
                .push(Router::with_path("sync/snapshot-head").get(snapshot_head))
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
                .push(Router::with_path("authz/check").post(authz_check))
                .push(Router::with_path("authz/effective-grants").get(effective_grants))
                .push(Router::with_path("authz/grants").post(create_grant))
                .push(Router::with_path("authz/grants/{grant_id}").delete(revoke_grant))
                .push(Router::with_path("authz/invites").get(invites))
                .push(Router::with_path("audit/events").get(audit_events))
                .push(Router::with_path("profile/presence").get(profile_presence))
                .push(Router::with_path("push/register-device").post(push_register))
                .push(Router::with_path("push/unregister-device").post(push_unregister))
                .push(Router::with_path("push/notify").post(push_notify))
                .push(Router::with_path("keys/upload").post(keys_upload))
                .push(Router::with_path("keys/query").post(keys_query))
                .push(Router::with_path("keys/claim").post(keys_claim))
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
                .push(Router::with_path("blob/upload").post(blob_upload))
                .push(Router::with_path("blob/get").get(blob_get).head(blob_get))
                .push(Router::with_path("moderation/report").post(moderation_report)),
        )
        .push(Router::with_path("contrix/v1/check").post(policy_check))
        .push(Router::with_path("contrix/v1/ice-config").post(ice_config))
}
