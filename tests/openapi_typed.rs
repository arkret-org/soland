//! Verifies that the typed `#[endpoint]` handlers in
//! `src/routing/describe.rs` actually contribute their request/response
//! schemas to the generated OpenAPI document. The original
//! `cokret_openapi_spec_contains_facet_projection_contracts` test only
//! asserts on operationId presence; this one asserts the typed schema
//! references that prove the conversion is real (not just metadata).

use salvo::test::{ResponseExt, TestClient};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-openapi-typed-blobs"),
        ),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        anchorer_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        compaction_min_anchor_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,

        compaction_prune_walk_interval_seconds: 0,

        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

#[tokio::test]
async fn typed_describe_handlers_publish_response_schemas() {
    let app = service(AppState::new(test_config(), Db { pool: None }));
    let mut response = TestClient::get("http://server/.well-known/cokret/openapi.yaml")
        .send(&app)
        .await;
    let body = response.take_string().await.unwrap();

    // The new typed describe endpoints must:
    // 1. publish their wire response types as components,
    assert!(
        body.contains("AuthBridgeDescribeOutcome"),
        "AuthBridgeDescribeOutcome missing — auth_bridge_describe didn't publish its schema"
    );
    assert!(
        body.contains("IntegrationDescribeOutcome"),
        "IntegrationDescribeOutcome missing — integration_describe didn't publish its schema"
    );
    assert!(
        body.contains("HealthOutcome"),
        "HealthOutcome missing — health didn't publish its schema"
    );

    // 2. publish AppError's standard error envelope on every typed handler,
    assert!(
        body.contains("ErrorEnvelope"),
        "ErrorEnvelope missing — AppError EndpointOutRegister didn't fire"
    );

    // 3. carry generated operation_ids for typed handlers,
    for typed_only in [
        "ck.auth.bridge.describe",
        "ck.authz.describe",
        "ck.extension.soland.policies.describe",
        "ck.device_messages.describe",
        "ck.keys.backups.describe",
        "ck.integration.describe",
    ] {
        assert!(
            body.contains(&format!("operationId: {typed_only}")),
            "missing typed-only operationId {typed_only}"
        );
    }

    // Phase C/D-converted endpoints must publish their request body types so
    // the OpenAPI spec carries the typed schemas (not synthetic placeholders).
    for typed_request_body in [
        "DevLoginRequestBody",
        "SessionGrantExchangeRequestBody",
        "RegisterAccountRequestBody",
        "ContactRequestRequestBody",
        "ContactRespondRequestBody",
        "DirectConversationResolveRequestBody",
        "AddReactionRequestBody",
        "RemoveReactionRequestBody",
        "SetReadMarkerRequestBody",
    ] {
        assert!(
            body.contains(typed_request_body),
            "missing request body schema {typed_request_body}"
        );
    }

    // Phase C/D-converted endpoints must publish typed response shapes too.
    for typed_response in [
        "DevLoginOutcome",
        "LogoutOutcome",
        "SolandAccountRegisterOutcome",
        "ContactRequestOutcome",
        "ContactRespondOutcome",
        "ContactList",
        "DirectConversationResolveOutcome",
        "ReactionOutcome",
        "ReadMarkerOutcome",
        "RealmLifecycleOutcome",
    ] {
        assert!(
            body.contains(typed_response),
            "missing response schema {typed_response}"
        );
    }

    // Round 14c ToSchema audit — federation anchors pull/push and the
    // embedded did:webvh register handler now use typed `#[endpoint]`
    // signatures (`JsonResult<T>` / `body: JsonBody<T>`), so their wire
    // types must appear in the generated YAML. The new
    // `EmbeddedWebvhRegisterOutcome` is asserted alongside the originally
    // forward-compat-only set.
    for typed_now in [
        "FederationAnchorsOutcome",
        "FederationAnchorsPushRequestBody",
        "FederationAnchorsPushOutcome",
        "EmbeddedWebvhRegisterRequestBody",
        "EmbeddedWebvhRegisterOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — handler's typed signature did not publish its schema"
        );
    }

    // Round 15c — projection_query.rs (`GET /_cokret/self/projection/{spaces,flows,morphs}`)
    // uses the SDK canonical response DTOs, so each wrapper + row struct must
    // appear in the generated YAML.
    for typed_now in [
        "ProjectionSpaceList",
        "ProjectionSpaceRow",
        "ProjectionFlowList",
        "ProjectionFlowRow",
        "ProjectionMorphList",
        "ProjectionMorphRow",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — projection_query handler's typed signature did not publish its schema"
        );
    }

    // Round 15g — access/authz.rs invites + effective_grants use the SDK
    // canonical response DTOs.
    for typed_now in ["AuthzInviteList", "GrantList"] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — access/authz typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.self.authz.get_invites",
        "ck.self.authz.get_effective_grants",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15g typed conversion"
        );
    }

    // Round 15j — all 5 federation/federation.rs handlers converted
    // (federation_transaction, federation_push_operations,
    // federation_pull_operations, federation_space_members,
    // federation_verify_actor) plus events/event_log.rs::events_frontier.
    // SDK wire types are already ToSchema (under the `salvo` feature);
    // the conversion attaches the typed operation_id + request/response
    // schemas (and the typed query param schemas where applicable) to
    // the OpenAPI doc.
    for typed_now in [
        "FederationTransactionRequestBody",
        "FederationTransactionOutcome",
        "FederationPushOperationsRequestBody",
        "FederationPushOperationsOutcome",
        "FederationPullOperationsOutcome",
        "FederationRealmMemberList",
        "FederationVerifyActorRequestBody",
        "FederationVerifyActorOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — federation typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.extension.soland.federation.transaction",
        "ck.extension.soland.federation.push_operations",
        "ck.extension.soland.federation.pull_operations",
        "ck.extension.soland.federation.realm_members",
        "ck.extension.soland.federation.verify_actor",
        "ck.self.events.frontier",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15j typed conversion"
        );
    }

    // Round 15k — moderation, push, webrtc handler batch.
    // - moderation/moderation.rs::moderation_report
    // - interop/push.rs::{push_unregister, delete_push_rule, push_notify}
    // - interop/webrtc.rs::{create_webrtc_session, put_webrtc_signal, get_webrtc_signals,
    //   delete_webrtc_session}
    // All wire types already carry `ToSchema`; the conversions attach
    // operation_id + typed request/response/path/query schemas.
    for typed_now in [
        "ModerationReportRequestBody",
        "SolandModerationReportOutcome",
        "PushUnregisterRequestBody",
        "PushNotifyRequestBody",
        "PushNotifyOutcome",
        "CreateWebrtcSessionRequestBody",
        "CreateWebrtcSessionOutcome",
        "WebrtcSignalRequestBody",
        "WebrtcSignalOutcome",
        "WebrtcSignalsOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15k typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.self.moderation.report",
        "ck.edge.push.unregister_device",
        "ck.push.delete_rule",
        "ck.edge.push.notify",
        "ck.extension.soland.webrtc.create_session",
        "ck.extension.soland.webrtc.send_signal",
        "ck.extension.soland.webrtc.get_signals",
        "ck.extension.soland.webrtc.close_session",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15k typed conversion"
        );
    }

    // Round 15l — access/policy.rs + access/authz.rs::authz_check typed batch.
    // - access/policy.rs::{list_policy_documents, get_policy_document, upsert_policy_document,
    //   delete_policy_document, policy_check}
    // - access/authz.rs::authz_check
    // Wire types already carry ToSchema; canonical operation_ids come
    // from the SOLAND_EXTENSION_OPERATIONS registry in routing/mod.rs.
    for typed_now in [
        "UpsertPolicyDocumentRequestBody",
        "PolicyDocumentOutcome",
        "PolicyDocumentsOutcome",
        "SolandPolicyCheckRequestBody",
        "SolandPolicyCheckOutcome",
        "SolandAuthzCheckRequestBody",
        "SolandAuthzCheckOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15l typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.extension.soland.policies.list",
        "ck.extension.soland.policies.get",
        "ck.extension.soland.policies.upsert",
        "ck.extension.soland.policies.delete",
        "ck.self.policy.check",
        "ck.self.authz.check",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15l typed conversion"
        );
    }

    // Round 15m — identity/key_backup.rs + identity/profile.rs typed batch.
    // - identity/key_backup.rs::{put_key_backup, list_key_backups, get_key_backup,
    //   delete_key_backup}
    // - identity/profile.rs::profile_presence
    // Note: profile_presence's response wrapper `ProfilePresenceOutcome`
    // is newly added in profile.rs (no upstream wire type existed).
    for typed_now in [
        "SolandKeysBackupsPutOutcome",
        "SolandKeysBackupsList",
        "SolandKeysBackupsDeleteOutcome",
        "ProfilePresenceOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15m typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.self.keys.backups.put",
        "ck.self.keys.backups.list",
        "ck.self.keys.backups.get",
        "ck.self.keys.backups.delete",
        "ck.profile.presence",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15m typed conversion"
        );
    }

    // Round 15n — identity/device_messages.rs typed batch (2 handlers).
    // Wire types already had ToSchema; operation_ids follow the v1
    // registry's put/get naming.
    for typed_now in [
        "DeviceMessagesPutRequestBody",
        "DeviceMessagesPutOutcome",
        "DeviceMessagesGetOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15n typed signature did not publish its schema"
        );
    }
    for operation_id in ["ck.self.device_messages.put", "ck.self.device_messages.get"] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15n typed conversion"
        );
    }

    // Round 15o — identity/keys.rs typed batch (3 handlers).
    for typed_now in [
        "KeysUploadRequestBody",
        "KeysUploadOutcome",
        "KeysQueryRequestBody",
        "KeysQueryOutcome",
        "KeysClaimRequestBody",
        "KeysClaimOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15o typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.self.keys.upload",
        "ck.self.keys.query",
        "ck.self.keys.claim",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15o typed conversion"
        );
    }

    // Round 15p — identity/did.rs typed batch (4 handlers).
    // identity_resolve, identity_document, identity_log, identity_receipts.
    // embedded_webvh_log is skipped — it streams `application/jsonl` not JSON.
    for typed_now in [
        "IdentityResolveRequestBody",
        "SolandIdentityResolveOutcome",
        "IdentityLogOutcome",
        "IdentityReceiptsOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15p typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.root.identity.resolve",
        "ck.root.identity.get_document",
        "ck.root.identity.get_log",
        "ck.root.identity.submit_did_operation",
        "ck.root.identity.get_receipts",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15p typed conversion"
        );
    }

    // Round 15q-15x — bulk batch covering spaces/{directory,relation,index},
    // events/messages, interop/{push,push_outbound,moderation}, admin/{audit,collection}.
    // Schema assertions: only the brand-new wire types (existing ones were
    // already asserted in earlier rounds, or are publicly stable enough
    // through their handler tags).
    for typed_now in [
        "DirectoryDescription",
        "DirectorySearchRealmsRequestBody",
        "DirectoryRealmSearchOutcome",
        "DirectoryResolveRealmRequestBody",
        "DirectoryRealmResolutionOutcome",
        "RealmPreview",
        "ListRelationsOutcome",
        "TombstoneRelationOutcome",
        "PushRulesOutcome",
        "UpsertPushRuleOutcome",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15q-15x typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.find.directory.search_realms",
        "ck.find.directory.resolve_realm",
        "ck.find.directory.search_organizations",
        "ck.find.directory.resolve_organization",
        "ck.find.directory.search_actors",
        "ck.find.directory.search_users",
        "ck.find.directory.resolve_handle",
        "ck.find.directory.private_contact_discovery",
        "ck.find.directory.announce",
        "ck.find.directory.withdraw",
        "ck.find.directory.push.register",
        "ck.relation.create",
        "ck.relation.tombstone",
        "ck.relation.list",
        "ck.extension.soland.index.object",
        "ck.extension.soland.index.thread",
        "ck.extension.soland.index.notifications",
        "ck.extension.soland.index.search",
        "ck.extension.soland.index.space_hierarchy",
        "ck.extension.soland.index.query",
        "ck.extension.soland.index.debug_reducer",
        "ck.edge.push.register_device",
        "ck.push.rules",
        "ck.push.upsert_rule",
        "ck.extension.soland.push.outbound_bridge_resolve",
        "ck.extension.soland.push.outbound_bridge_fetch",
        "ck.extension.soland.push.outbound_bridge_cache_import",
        "ck.extension.soland.push.outbound_bridge_cache_invalidate",
        "ck.extension.soland.audit.user_action",
        "ck.extension.soland.audit.events",
        "ck.extension.soland.admin.collection",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15q-15x typed conversion"
        );
    }

    // Round 15z — events/sync.rs typed canonical ephemeral send.
    assert!(
        body.contains("operationId: ck.self.ephemeral.send"),
        "missing operationId ck.self.ephemeral.send from canonical ephemeral endpoint"
    );
    assert!(
        body.contains("EphemeralSubmitOutcome"),
        "EphemeralSubmitOutcome missing — canonical ephemeral endpoint did not publish its schema"
    );
    assert!(
        body.contains("operationId: ck.self.events.query_post"),
        "missing operationId ck.self.events.query_post from canonical body-query endpoint"
    );

    // Round 15ab — interop/mimi.rs typed batch. All response shapes are `Value`,
    // so no schema names assert;
    // we lock the operation_ids instead.
    for operation_id in [
        "ck.open.mimi.provider_directory",
        "ck.open.mimi.key_material",
        "ck.open.mimi.room_update",
        "ck.mimi.room_notify",
        "ck.open.mimi.submit_message",
        "ck.open.mimi.group_info",
        "ck.open.mimi.request_consent",
        "ck.open.mimi.update_consent",
        "ck.open.mimi.identifier_query",
        "ck.open.mimi.report_abuse",
        "ck.open.mimi.proxy_download",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15ab typed conversion"
        );
    }

    for operation_id in [
        "ck.self.blob.presign",
        "ck.self.keys.keypackages.consume",
        "ck.self.keys.keypackages.revoke",
        "ck.admin.get_server_status",
        "ck.admin.update_account_status",
        "ck.admin.revoke_device",
        "ck.admin.get_moderation_queue",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from canonical gap-closure batch"
        );
    }

    // Round 15aa — access/authz.rs::{create_grant, revoke_grant} typed.
    // New CreateGrantOutcome + RevokeGrantOutcome wire types.
    for typed_now in ["CreateGrantOutcome", "RevokeGrantOutcome"] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15aa typed signature did not publish its schema"
        );
    }
    for operation_id in ["ck.authz.create_grant", "ck.authz.revoke_grant"] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15aa typed conversion"
        );
    }

    // Round 15ac-15ag — final batch of typed conversions covering
    // event_log read paths + sync.rs core handlers (snapshot, gap
    // backfill, client_sync, events_query, events_query_durable_scope).
    // Most reuse existing wire types already asserted earlier; we lock
    // the new operation_ids here.
    // Note: `events_query_durable_scope` is the typed wrapper around the
    // dispatched `_impl` helper; the original `#[endpoint]` wrapper had
    // no route registered (it's only called from sync.rs::events_query
    // when the selector has no `realms[]`), so OpenAPI doesn't emit it.
    // Skip its operation_id assertion accordingly.
    //
    // Note: snapshot_head / snapshot_chunk get their operation_ids from
    // the SOLAND_EXTENSION_OPERATIONS registry (`ck.self.snapshot.head`
    // / `ck.extension.soland.sync.snapshot_chunk`), not from my handler annotation.
    for operation_id in [
        "ck.self.events.get",
        "ck.self.events.resolve",
        "ck.self.account.subscribe",
        "ck.self.events.query",
        "ck.extension.soland.sync.backfill_gap",
        "ck.self.snapshot.head",
        "ck.extension.soland.sync.snapshot_chunk",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15ac-15ag typed conversion"
        );
    }
}
