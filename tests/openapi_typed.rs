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

        compaction_prune_walk_per_space_limit: 50,
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
        body.contains("AuthBridgeDescribeResponse"),
        "AuthBridgeDescribeResponse missing — auth_bridge_describe didn't publish its schema"
    );
    assert!(
        body.contains("IntegrationDescribeResponse"),
        "IntegrationDescribeResponse missing — integration_describe didn't publish its schema"
    );
    assert!(
        body.contains("HealthResponse"),
        "HealthResponse missing — health didn't publish its schema"
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
        "DevLoginRequest",
        "SessionGrantExchangeRequest",
        "RegisterAccountRequest",
        "ContactRequestRequest",
        "ContactRespondRequest",
        "AddReactionRequest",
        "RemoveReactionRequest",
        "SetReadMarkerRequest",
    ] {
        assert!(
            body.contains(typed_request_body),
            "missing request body schema {typed_request_body}"
        );
    }

    // Phase C/D-converted endpoints must publish typed response shapes too.
    for typed_response in [
        "DevLoginResponse",
        "LogoutResponse",
        "AccountResponse",
        "ContactResponse",
        "ContactsResponse",
        "ReactionResponse",
        "ReadMarkerResponse",
        "SpaceLifecycleResponse",
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
    // `EmbeddedWebvhRegisterResponse` is asserted alongside the originally
    // forward-compat-only set.
    for typed_now in [
        "FederationAnchorsResponse",
        "FederationAnchorsPushRequest",
        "FederationAnchorsPushResponse",
        "EmbeddedWebvhRegisterRequest",
        "EmbeddedWebvhRegisterResponse",
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
        "ProjectionSpacesResBody",
        "ProjectionSpaceRow",
        "ProjectionFlowsResBody",
        "ProjectionFlowRow",
        "ProjectionMorphsResBody",
        "ProjectionMorphRow",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — projection_query handler's typed signature did not publish its schema"
        );
    }

    // Round 15g — access/authz.rs invites + effective_grants converted.
    // Their wire response types are already ToSchema; the conversion
    // adds them to the typed-handler output set.
    for typed_now in ["InvitesResponse", "EffectiveGrantsResBody"] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — access/authz typed signature did not publish its schema"
        );
    }
    for operation_id in ["ck.authz.get_invites", "ck.authz.get_effective_grants"] {
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
        "FederationTransactionReqBody",
        "FederationTransactionResBody",
        "FederationPushOperationsReqBody",
        "FederationPushOperationsResBody",
        "FederationPullOperationsResBody",
        "FederationRealmMembersResBody",
        "FederationVerifyActorReqBody",
        "FederationVerifyActorResBody",
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
        "ck.extension.soland.federation.space_members",
        "ck.extension.soland.federation.verify_actor",
        "ck.events.frontier",
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
        "ModerationReportReqBody",
        "ModerationReportResBody",
        "PushUnregisterRequest",
        "PushNotifyReqBody",
        "PushNotifyResBody",
        "CreateWebrtcSessionRequest",
        "CreateWebrtcSessionResponse",
        "WebrtcSignalRequest",
        "WebrtcSignalResponse",
        "WebrtcSignalsResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15k typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.moderation.report",
        "ck.push.unregister_device",
        "ck.push.delete_rule",
        "ck.push.notify",
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
        "UpsertPolicyDocumentRequest",
        "PolicyDocumentResponse",
        "PolicyDocumentsResponse",
        "PolicyCheckReqBody",
        "PolicyCheckResBody",
        "AuthzCheckReqBody",
        "AuthzCheckResBody",
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
        "ck.policy.check",
        "ck.authz.check",
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
    // Note: profile_presence's response wrapper `ProfilePresenceResponse`
    // is newly added in profile.rs (no upstream wire type existed).
    for typed_now in [
        "KeysBackupsPutResBody",
        "KeysBackupsListResBody",
        "KeysBackupsDeleteResBody",
        "ProfilePresenceResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15m typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.keys.backups.put",
        "ck.keys.backups.list",
        "ck.keys.backups.get",
        "ck.keys.backups.delete",
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
        "DeviceMessagesSendReqBody",
        "DeviceMessagesSendResBody",
        "DeviceMessagesReceiveResBody",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15n typed signature did not publish its schema"
        );
    }
    for operation_id in ["ck.device_messages.put", "ck.device_messages.get"] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15n typed conversion"
        );
    }

    // Round 15o — identity/keys.rs typed batch (3 handlers).
    for typed_now in [
        "KeysUploadReqBody",
        "KeysUploadResBody",
        "KeysQueryReqBody",
        "KeysQueryResBody",
        "KeysClaimReqBody",
        "KeysClaimResBody",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15o typed signature did not publish its schema"
        );
    }
    for operation_id in ["ck.keys.upload", "ck.keys.query", "ck.keys.claim"] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15o typed conversion"
        );
    }

    // Round 15p — identity/did.rs typed batch (4 handlers).
    // identity_resolve, identity_document, identity_log, identity_receipts.
    // embedded_webvh_log is skipped — it streams `application/jsonl` not JSON.
    for typed_now in [
        "IdentityResolveReqBody",
        "IdentityResolveResBody",
        "IdentityLogResBody",
        "IdentityReceiptsResBody",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15p typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.identity.resolve",
        "ck.identity.get_document",
        "ck.identity.get_log",
        "ck.identity.submit_did_operation",
        "ck.identity.get_receipts",
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
        "ListRelationsResponse",
        "DeleteRelationResponse",
        "PushRulesResponse",
        "UpsertPushRuleResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15q-15x typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "ck.directory.search_realms",
        "ck.directory.resolve_realm",
        "ck.directory.search_organizations",
        "ck.directory.resolve_organization",
        "ck.directory.search_actors",
        "ck.directory.search_users",
        "ck.directory.resolve_handle",
        "ck.directory.private_contact_discovery",
        "ck.directory.announce",
        "ck.directory.withdraw",
        "ck.directory.push.register",
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
        "ck.push.register_device",
        "ck.extension.soland.push.rules",
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
        body.contains("operationId: ck.ephemeral.send"),
        "missing operationId ck.ephemeral.send from canonical ephemeral endpoint"
    );
    assert!(
        body.contains("EphemeralSubmitResBody"),
        "EphemeralSubmitResBody missing — canonical ephemeral endpoint did not publish its schema"
    );
    assert!(
        body.contains("operationId: ck.events.query_post"),
        "missing operationId ck.events.query_post from canonical body-query endpoint"
    );

    // Round 15ab — interop/mimi.rs typed batch. All response shapes are `Value`,
    // so no schema names assert;
    // we lock the operation_ids instead.
    for operation_id in [
        "ck.mimi.provider_directory",
        "ck.mimi.key_material",
        "ck.mimi.room_update",
        "ck.mimi.notify",
        "ck.mimi.submit_message",
        "ck.mimi.group_info",
        "ck.mimi.request_consent",
        "ck.mimi.update_consent",
        "ck.mimi.identifier_query",
        "ck.mimi.report_abuse",
        "ck.mimi.proxy_download",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15ab typed conversion"
        );
    }

    for operation_id in [
        "ck.blob.presign",
        "ck.keys.keypackages.consume",
        "ck.keys.keypackages.revoke",
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
    // New CreateGrantResponse + RevokeGrantResponse wire types.
    for typed_now in ["CreateGrantResponse", "RevokeGrantResponse"] {
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
    // when the selector has no `spaces[]`), so OpenAPI doesn't emit it.
    // Skip its operation_id assertion accordingly.
    //
    // Note: snapshot_head / snapshot_chunk get their operation_ids from
    // the SOLAND_EXTENSION_OPERATIONS registry (`ck.snapshot.head`
    // / `ck.extension.soland.sync.get_snapshot_chunk`), not from my handler annotation.
    for operation_id in [
        "ck.events.get",
        "ck.events.resolve",
        "ck.account.subscribe",
        "ck.events.query",
        "ck.extension.soland.sync.backfill_gap",
        "ck.snapshot.head",
        "ck.extension.soland.sync.get_snapshot_chunk",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15ac-15ag typed conversion"
        );
    }
}
