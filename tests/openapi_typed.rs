//! Verifies that the typed `#[endpoint]` handlers in
//! `src/routing/describe.rs` actually contribute their request/response
//! schemas to the generated OpenAPI document. The original
//! `contrix_openapi_spec_contains_facet_projection_contracts` test only
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
    }
}

#[tokio::test]
async fn typed_describe_handlers_publish_response_schemas() {
    let app = service(AppState::new(test_config(), Db { pool: None }));
    let mut response = TestClient::get("http://server/.well-known/contrix/openapi.yaml")
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
        "cx.auth.bridge.describe",
        "cx.authz.describe",
        "cx.policies.describe",
        "cx.device_messages.describe",
        "cx.keys.backups.describe",
        "cx.integration.describe",
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
        "CreateSpaceRequest",
        "AddSpaceMemberRequest",
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

    // Round 15c — projection_query.rs (`GET /api/v1/projection/{places,flows,morphs}`)
    // converted from `&mut Response` + `res.render(Json(json!{...}))` to typed
    // `JsonResult<T>` signatures. Each handler's response wrapper +
    // row struct must now appear in the generated YAML.
    for typed_now in [
        "PlaceProjectionListResponse",
        "PlaceProjectionRow",
        "FlowProjectionListResponse",
        "FlowProjectionRow",
        "MorphProjectionListResponse",
        "MorphProjectionRow",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — projection_query handler's typed signature did not publish its schema"
        );
    }

    // Round 15g — access/authz.rs invites + effective_grants converted.
    // Their wire response types are already ToSchema; the conversion
    // adds them to the typed-handler output set.
    for typed_now in ["InvitesResponse", "EffectiveGrantsResponse"] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — access/authz typed signature did not publish its schema"
        );
    }
    for operation_id in ["cx.authz.get_invites", "cx.authz.get_effective_grants"] {
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
        "FederationTransactionRequest",
        "FederationTransactionResponse",
        "FederationPushOperationsRequest",
        "FederationPushOperationsResponse",
        "FederationPullOperationsResponse",
        "FederationSpaceMembersResponse",
        "FederationVerifyActorRequest",
        "FederationVerifyActorResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — federation typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "cx.federation.transaction",
        "cx.federation.push_operations",
        "cx.federation.pull_operations",
        "cx.federation.space_members",
        "cx.federation.verify_actor",
        "cx.events.frontier",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15j typed conversion"
        );
    }

    // Round 15k — moderation, push, webrtc handler batch.
    // - moderation/moderation.rs::moderation_report
    // - interop/push.rs::{push_unregister, delete_push_rule, push_notify}
    // - interop/webrtc.rs::{create_webrtc_session, put_webrtc_signal,
    //   get_webrtc_signals, delete_webrtc_session}
    // All wire types already carry `ToSchema`; the conversions attach
    // operation_id + typed request/response/path/query schemas.
    for typed_now in [
        "ModerationReportRequest",
        "ModerationReportResponse",
        "PushUnregisterRequest",
        "PushNotifyRequest",
        "PushNotifyResponse",
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
        "cx.moderation.report",
        "cx.push.unregister_device",
        "cx.push.delete_rule",
        "cx.push.notify",
        "cx.webrtc.create_session",
        "cx.webrtc.send_signal",
        "cx.webrtc.get_signals",
        "cx.webrtc.close_session",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15k typed conversion"
        );
    }

    // Round 15l — access/policy.rs + access/authz.rs::authz_check typed batch.
    // - access/policy.rs::{list_policy_documents, get_policy_document,
    //   upsert_policy_document, delete_policy_document, policy_check}
    // - access/authz.rs::authz_check
    // Wire types already carry ToSchema; canonical operation_ids come
    // from the SOLAND_EXTENSION_OPERATIONS registry in routing/mod.rs.
    for typed_now in [
        "UpsertPolicyDocumentRequest",
        "PolicyDocumentResponse",
        "PolicyDocumentsResponse",
        "PolicyCheckRequest",
        "PolicyCheckResponse",
        "AuthzCheckRequest",
        "AuthzCheckResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15l typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "cx.policies.list",
        "cx.policies.get",
        "cx.policies.upsert",
        "cx.policies.delete",
        "cx.policy.check",
        "cx.authz.check",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15l typed conversion"
        );
    }

    // Round 15m — identity/key_backup.rs + identity/profile.rs typed batch.
    // - identity/key_backup.rs::{put_key_backup, list_key_backups,
    //   get_key_backup, delete_key_backup}
    // - identity/profile.rs::profile_presence
    // Note: profile_presence's response wrapper `ProfilePresenceResponse`
    // is newly added in profile.rs (no upstream wire type existed).
    for typed_now in [
        "KeysBackupsPutResponse",
        "KeysBackupsListResponse",
        "KeysBackupsDeleteResponse",
        "ProfilePresenceResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15m typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "cx.keys.backups.put",
        "cx.keys.backups.list",
        "cx.keys.backups.get",
        "cx.keys.backups.delete",
        "cx.profile.presence",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15m typed conversion"
        );
    }

    // Round 15n — identity/device_messages.rs typed batch (2 handlers).
    // - send_device_messages → cx.device_messages.send
    // - get_device_messages → cx.device_messages.receive
    // Wire types already had ToSchema; new operation_ids match the
    // existing `cx.device_messages.describe` family.
    for typed_now in [
        "DeviceMessagesSendRequest",
        "DeviceMessagesSendResponse",
        "DeviceMessagesReceiveResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15n typed signature did not publish its schema"
        );
    }
    for operation_id in ["cx.device_messages.send", "cx.device_messages.receive"] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15n typed conversion"
        );
    }

    // Round 15o — identity/keys.rs typed batch (3 handlers).
    for typed_now in [
        "KeysUploadRequest",
        "KeysUploadResponse",
        "KeysQueryRequest",
        "KeysQueryResponse",
        "KeysClaimRequest",
        "KeysClaimResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15o typed signature did not publish its schema"
        );
    }
    for operation_id in ["cx.keys.upload", "cx.keys.query", "cx.keys.claim"] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15o typed conversion"
        );
    }

    // Round 15p — identity/did.rs typed batch (4 handlers).
    // identity_resolve, identity_document, identity_log, identity_receipts.
    // embedded_webvh_log is skipped — it streams `application/jsonl` not JSON.
    for typed_now in [
        "IdentityResolveRequest",
        "IdentityResolveResponse",
        "IdentityLogResponse",
        "IdentityReceiptsResponse",
    ] {
        assert!(
            body.contains(typed_now),
            "{typed_now} missing — round 15p typed signature did not publish its schema"
        );
    }
    for operation_id in [
        "cx.identity.resolve",
        "cx.identity.document",
        "cx.identity.log",
        "cx.identity.receipts",
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
        "cx.directory.search_spaces",
        "cx.directory.resolve_space",
        "cx.directory.search_organizations",
        "cx.directory.resolve_organization",
        "cx.directory.search_actors",
        "cx.directory.search_users",
        "cx.directory.resolve_handle",
        "cx.relation.create",
        "cx.relation.delete",
        "cx.relation.list",
        "cx.index.object",
        "cx.index.thread",
        "cx.index.notifications",
        "cx.index.search",
        "cx.index.space_hierarchy",
        "cx.index.query",
        "cx.index.debug_reducer",
        "cx.messages.send",
        "cx.push.register_device",
        "cx.push.rules",
        "cx.push.upsert_rule",
        "cx.push.outbound_bridge_resolve",
        "cx.push.outbound_bridge_fetch",
        "cx.push.outbound_bridge_cache_import",
        "cx.push.outbound_bridge_cache_invalidate",
        "cx.audit.user_action",
        "cx.audit.events",
        "cx.admin.collection",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15q-15x typed conversion"
        );
    }

    // Round 15z — events/sync.rs::set_typing (only sync.rs handler converted
    // in this slice; rest of sync.rs is too entangled with cursor/stream
    // helpers to migrate without scope creep).
    assert!(
        body.contains("operationId: cx.sync.typing"),
        "missing operationId cx.sync.typing from round 15z typed conversion"
    );
    assert!(
        body.contains("SetTypingRequest"),
        "SetTypingRequest missing — round 15z typed signature did not publish its schema"
    );
    assert!(
        body.contains("SetTypingResponse"),
        "SetTypingResponse missing — round 15z typed signature did not publish its schema"
    );

    // Round 15ab — interop/mimi.rs typed batch (10 handlers; mimi_protocol_directory
    // + mimi_provider_directory kept as-is — they return a static JSON Value with
    // no error paths). All response shapes are `Value` so no schema names assert;
    // we lock the operation_ids instead.
    for operation_id in [
        "cx.mimi.key_material",
        "cx.mimi.room_update",
        "cx.mimi.notify",
        "cx.mimi.submit_message",
        "cx.mimi.group_info",
        "cx.mimi.request_consent",
        "cx.mimi.update_consent",
        "cx.mimi.identifier_query",
        "cx.mimi.report_abuse",
        "cx.mimi.proxy_download",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15ab typed conversion"
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
    for operation_id in ["cx.authz.create_grant", "cx.authz.revoke_grant"] {
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
    // the SOLAND_EXTENSION_OPERATIONS registry (`cx.sync.get_snapshot_head`
    // / `cx.sync.get_snapshot_chunk`), not from my handler annotation.
    for operation_id in [
        "cx.events.get",
        "cx.events.batch_get",
        "cx.sync.account",
        "cx.events.query",
        "cx.sync.backfill_gap",
        "cx.sync.get_snapshot_head",
        "cx.sync.get_snapshot_chunk",
    ] {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing operationId {operation_id} from round 15ac-15ag typed conversion"
        );
    }
}
