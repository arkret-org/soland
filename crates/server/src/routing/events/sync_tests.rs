use super::*;

#[test]
fn derive_cursor_handle_is_deterministic_and_spec_shaped() {
    let key = b"test-cursor-key-0123456789abcdef";
    let realms = BTreeMap::from([("ck:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ck:realm:a".to_owned(), 11i64)]);
    let binding = stream_cursor_handle_binding(
        "did:web:alice",
        "ck:device:1",
        "did:web:host",
        "fd0",
        &realms,
        &account_realms,
        3,
    );
    let h1 = derive_cursor_handle(key, &binding);
    let h2 = derive_cursor_handle(key, &binding);
    assert_eq!(h1, h2, "same binding -> same handle");
    assert!(
        h1.len() >= cokret_sdk::cursor::CURSOR_HANDLE_MIN_LEN,
        "handle >= 22 base64url chars"
    );
    assert!(
        h1.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "handle is base64url alphabet"
    );
    assert!(
        validate_cursor_handle(&h1).is_ok(),
        "derived handle passes schema validation"
    );
}

#[test]
fn derive_cursor_handle_excludes_devices_timestamp() {
    // The per-mint `devices` timestamp must NOT enter the binding, so two
    // mints at different wall-clock times but identical realm/to_device
    // positions yield the SAME handle (determinism / dedup).
    let key = b"test-cursor-key-0123456789abcdef";
    let realms = BTreeMap::from([("ck:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ck:realm:a".to_owned(), 11i64)]);
    let a = stream_cursor_handle_binding("p", "d", "s", "f", &realms, &account_realms, 3);
    let b = stream_cursor_handle_binding("p", "d", "s", "f", &realms, &account_realms, 3);
    assert_eq!(derive_cursor_handle(key, &a), derive_cursor_handle(key, &b));
}

#[test]
fn derive_cursor_handle_separates_bindings_and_keys() {
    let realms = BTreeMap::from([("ck:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ck:realm:a".to_owned(), 11i64)]);
    let advanced_account_realms = BTreeMap::from([("ck:realm:a".to_owned(), 12i64)]);
    let base = stream_cursor_handle_binding("p", "d", "s", "f", &realms, &account_realms, 3);
    let other_device =
        stream_cursor_handle_binding("p", "d2", "s", "f", &realms, &account_realms, 3);
    let advanced = stream_cursor_handle_binding("p", "d", "s", "f", &realms, &account_realms, 4);
    let advanced_account =
        stream_cursor_handle_binding("p", "d", "s", "f", &realms, &advanced_account_realms, 3);
    let k1 = b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let k2 = b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_ne!(
        derive_cursor_handle(k1, &base),
        derive_cursor_handle(k1, &other_device),
        "different device -> different handle (no cross-device forgery)"
    );
    assert_ne!(
        derive_cursor_handle(k1, &base),
        derive_cursor_handle(k1, &advanced),
        "advanced to_device position -> different handle"
    );
    assert_ne!(
        derive_cursor_handle(k1, &base),
        derive_cursor_handle(k1, &advanced_account),
        "advanced account projection position -> different handle"
    );
    assert_ne!(
        derive_cursor_handle(k1, &base),
        derive_cursor_handle(k2, &base),
        "different server key -> different handle (unguessable without key)"
    );
}

#[test]
fn timeline_position_disambiguates_same_second_events() {
    let created_at = DateTime::parse_from_rfc3339("2026-05-22T16:18:24Z")
        .unwrap()
        .with_timezone(&Utc);
    let realm_create = timestamp_position_with_tie_breaker(
        created_at,
        "ck:event:019e507b-16b2-719a-84fd-a9319ab43a36",
    );
    let welcome_message = timestamp_position_with_tie_breaker(
        created_at,
        "ck:event:019e507b-1857-73b7-9579-a00706bf0af4",
    );

    assert_ne!(realm_create, welcome_message);
    assert!(welcome_message > realm_create);
}

#[test]
fn presence_sync_event_marks_stale_online_offline() {
    let record = PresenceRecord {
        actor: "did:web:alice.example".to_owned(),
        status: "online".to_owned(),
        updated_at: now() - ChronoDuration::seconds(PRESENCE_ONLINE_TTL_SECONDS + 1),
    };

    let event = presence_sync_event_json(record);

    assert_eq!(event["user_id"], "did:web:alice.example");
    assert_eq!(event["presence"], "offline");
    assert_eq!(event["status"], "offline");
    assert!(event.get("last_active").is_some());
}

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-sync-cursor-test-blobs"),
        ),
        ice: crate::config::IceServersConfig::default(),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        notary_signing_key_seed: Some([9u8; 32]),
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: crate::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
        resumable_upload_incomplete_ttl_seconds: 86_400,
        seal_compaction_min_age_seconds: 604_800,
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
        log_format: crate::config::LogFormat::Plain,
    }
}

fn test_state() -> AppState {
    AppState::new(test_config(), crate::db::Db { pool: None })
}

const ROSTER_REALM: &str = "ck:realm:01904100-0000-7000-8000-00000000a001";
const ROSTER_ACTOR: &str = "did:web:alice.example";
const ROSTER_SUBJECT: &str = "did:web:alice-principal.example";
const ROSTER_CALLER: &str = "did:web:bob.example";

fn roster_body(audience: &str) -> SyncRequestBody {
    let mut extra = BTreeMap::new();
    extra.insert("audience".to_owned(), json!(audience));
    SyncRequestBody {
        after: None,
        catchup: None,
        filter: Some(cokret_sdk::SyncFilter {
            realms: Vec::new(),
            timeline_limit: None,
            lazy_load_members: false,
            include_redundant_members: false,
            event_types: Vec::new(),
            not_event_types: Vec::new(),
            extra,
        }),
        set_presence: None,
        subscriptions: None,
        wait_for: None,
    }
}

fn roster_session(state: &AppState, actor: &str) -> SessionRecord {
    SessionRecord {
        token_hash: "token".to_owned(),
        actor: actor.to_owned(),
        device_id: "device-1".to_owned(),
        audience: state.config.service_did.clone(),
        session_public_key: None,
        expires_at: now() + ChronoDuration::hours(1),
        created_at: now(),
        revoked_at: None,
    }
}

fn roster_realm(public: bool, include_caller: bool) -> RealmDirectoryEntry {
    let mut entry = RealmDirectoryEntry::new(
        RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        "Roster evidence",
    );
    entry.public = public;
    entry
        .members
        .insert(cokret_sdk::Did::new(ROSTER_ACTOR.to_owned()).unwrap());
    if include_caller {
        entry
            .members
            .insert(cokret_sdk::Did::new(ROSTER_CALLER.to_owned()).unwrap());
    }
    entry
}

fn insert_member_identity_subject(state: &AppState) {
    use crate::state::{MemberIdentityEventRecord, MemberIdentitySubjectKey};
    let identity_payload = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice" }
        }
    });
    let payload_digest = cokret_sdk::canonical::sha256_digest(
        cokret_sdk::canonical::canonical_json_bytes(&identity_payload).unwrap(),
    );
    state
        .member_identity
        .lock()
        .expect("member_identity lock")
        .insert(MemberIdentityEventRecord {
            event_id: "ck:operation:roster-identity-1".to_owned(),
            subject: MemberIdentitySubjectKey {
                realm_id: ROSTER_REALM.to_owned(),
                actor_id: ROSTER_ACTOR.to_owned(),
                segment: "member_identity".to_owned(),
            },
            payload_digest,
            replaces: Vec::new(),
            raw_event: json!({
                "operation_id": "ck:operation:roster-identity-1",
                "event_kind": crate::kinds::CK_MEMBER_IDENTITY_UPDATE,
                "realm_id": ROSTER_REALM,
                "created_at": now(),
                "payload": {
                    "realm_id": ROSTER_REALM,
                    "actor_id": ROSTER_ACTOR,
                    "segment": "member_identity",
                    "identity_payload": identity_payload,
                }
            }),
        });
}

fn handle_claim(
    state: &AppState,
    issuer: &str,
    audience: &str,
    expires_at: DateTime<Utc>,
    binding_state: &str,
    extra: Option<Value>,
) -> Value {
    let mut claim = json!({
        "schema": "ck.schema.handle_claim.v1",
        "handle": "alice:soland.local",
        "subject": ROSTER_SUBJECT,
        "issuer": issuer,
        "issuer_service_did": issuer,
        "binding_state": binding_state,
        "claim_kind": "handle_binding",
        "visibility": "public",
        "audience": audience,
        "created_at": (now() - ChronoDuration::minutes(1)).to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{issuer}#directory-handle-claim"),
            "payload_digest": "sha256:unsigned-payload",
            "jws": "detached"
        }]
    });
    if let Some(extra) = extra
        && let Some(object) = claim.as_object_mut()
    {
        object.insert("claims".to_owned(), extra);
    }
    // Keep tests honest: use the configured service DID unless a test is
    // intentionally exercising issuer trust rejection.
    if issuer == state.config.service_did {
        claim["issuer_service_did"] = json!(state.config.service_did);
    }
    claim
}

fn cache_claim(state: &AppState, claim: Value) -> String {
    state
        .member_identity
        .lock()
        .expect("member_identity lock")
        .upsert_handle_claim_envelope(claim)
        .expect("claim cached")
}

fn roster_row(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> Value {
    let body = roster_body(&state.config.service_did);
    roster_members_for_realm(state, realm, session, &body)
        .into_iter()
        .find(|row| row["actor_id"] == ROSTER_ACTOR)
        .expect("actor row")
}

fn canonical_value_digest(value: &Value) -> String {
    cokret_sdk::canonical::sha256_digest(
        cokret_sdk::canonical::canonical_json_bytes(value).unwrap(),
    )
}

// SPEC-CR-010 / SOL-05-008 — `project_member_identity_update` MUST store the
// canonical `ck:event:` id (threaded through `payload.event_id`) so the
// effective-set / replaces / R3.2 digests live in the same id space as a
// spec-compliant client, whose `replaces[].event_id` is a `ck:event:` id.
#[test]
fn member_identity_projection_stores_typed_event_id_and_matches_event_replaces() {
    use cokret_sdk::{Operation, OperationId};

    use crate::routing::events::projection::project_member_identity_update;

    let state = test_state();
    let realm = ROSTER_REALM;
    let actor = ROSTER_ACTOR;
    let first_event_id = "ck:event:01904100-0000-7000-8000-0000000000e1";
    let second_event_id = "ck:event:01904100-0000-7000-8000-0000000000e2";

    let first_identity = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice" }
        }
    });
    let first_digest = cokret_sdk::canonical::sha256_digest(
        cokret_sdk::canonical::canonical_json_bytes(&first_identity).unwrap(),
    );

    // First update. Operation carries the canonical `ck:event:` id in
    // `payload.event_id`, exactly as `projection_operation_from_event` threads it.
    let first_op = Operation::create(
        OperationId::new("ck:operation:01904100-0000-7000-8000-0000000000e1".to_owned()).unwrap(),
        RealmId::new(realm.to_owned()).unwrap(),
        crate::kinds::CK_MEMBER_IDENTITY_UPDATE,
        json!({
            "event_id": first_event_id,
            "realm_id": realm,
            "actor_id": actor,
            "segment": "member_identity",
            "identity_payload": first_identity,
        }),
    );
    project_member_identity_update(&state, &first_op);

    {
        let registry = state.member_identity.lock().unwrap();
        let snapshot = registry.snapshot_for_actor(realm, actor).unwrap();
        assert_eq!(snapshot.identity_event_ids, vec![first_event_id.to_owned()]);
    }

    // Second update replaces the first using the spec-compliant `ck:event:`
    // edge. Before the fix this never matched (projection stored `ck:operation:`).
    let second_identity = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice 2" }
        }
    });
    let second_op = Operation::create(
        OperationId::new("ck:operation:01904100-0000-7000-8000-0000000000e2".to_owned()).unwrap(),
        RealmId::new(realm.to_owned()).unwrap(),
        crate::kinds::CK_MEMBER_IDENTITY_UPDATE,
        json!({
            "event_id": second_event_id,
            "realm_id": realm,
            "actor_id": actor,
            "segment": "member_identity",
            "identity_payload": second_identity,
            "replaces": [ { "event_id": first_event_id, "payload_digest": first_digest } ],
        }),
    );
    project_member_identity_update(&state, &second_op);

    let registry = state.member_identity.lock().unwrap();
    let snapshot = registry.snapshot_for_actor(realm, actor).unwrap();
    // The `ck:event:` replaces edge drops the predecessor: only the second
    // event remains effective, and the stored id is the typed event id.
    assert_eq!(
        snapshot.identity_event_ids,
        vec![second_event_id.to_owned()],
        "replaces[].event_id (ck:event:) must match the stored typed event id"
    );
    assert!(
        snapshot
            .effective_entries
            .iter()
            .all(|entry| entry.event_id.starts_with("ck:event:")),
        "effective entries must live in the ck:event: id space"
    );
}

#[test]
fn roster_discloses_handle_claim_for_visible_trusted_issuer() {
    let state = test_state();
    insert_member_identity_subject(&state);
    let claim = handle_claim(
        &state,
        &state.config.service_did,
        &state.config.service_did,
        now() + ChronoDuration::hours(1),
        "verified",
        None,
    );
    let digest = cache_claim(&state, claim);
    let realm = roster_realm(false, true);
    let session = roster_session(&state, ROSTER_CALLER);

    let row = roster_row(&state, &realm, Some(&session));

    assert_eq!(row["subject_id"], ROSTER_SUBJECT);
    assert_eq!(row["handle_claim_digests"], json!([digest]));
    assert_eq!(
        canonical_value_digest(&row["handle_claims"][0]),
        row["handle_claim_digests"][0].as_str().unwrap()
    );
    assert!(row.get("handle_claims_limited").is_none());
}

#[test]
fn roster_hides_handle_claim_from_untrusted_issuer() {
    let state = test_state();
    insert_member_identity_subject(&state);
    cache_claim(
        &state,
        handle_claim(
            &state,
            "did:web:evil.example",
            &state.config.service_did,
            now() + ChronoDuration::hours(1),
            "verified",
            None,
        ),
    );
    let realm = roster_realm(false, true);
    let session = roster_session(&state, ROSTER_CALLER);

    let row = roster_row(&state, &realm, Some(&session));

    assert_eq!(row["subject_id"], ROSTER_SUBJECT);
    assert!(row.get("handle_claim_digests").is_none());
    assert!(row.get("handle_claims").is_none());
}

#[test]
fn roster_hides_expired_handle_claim() {
    let state = test_state();
    insert_member_identity_subject(&state);
    cache_claim(
        &state,
        handle_claim(
            &state,
            &state.config.service_did,
            &state.config.service_did,
            now() - ChronoDuration::seconds(1),
            "verified",
            None,
        ),
    );
    let realm = roster_realm(false, true);
    let session = roster_session(&state, ROSTER_CALLER);

    let row = roster_row(&state, &realm, Some(&session));

    assert_eq!(row["subject_id"], ROSTER_SUBJECT);
    assert!(row.get("handle_claim_digests").is_none());
}

#[test]
fn roster_hides_revoked_handle_claim() {
    let state = test_state();
    insert_member_identity_subject(&state);
    cache_claim(
        &state,
        handle_claim(
            &state,
            &state.config.service_did,
            &state.config.service_did,
            now() + ChronoDuration::hours(1),
            "revoked",
            None,
        ),
    );
    let realm = roster_realm(false, true);
    let session = roster_session(&state, ROSTER_CALLER);

    let row = roster_row(&state, &realm, Some(&session));

    assert_eq!(row["subject_id"], ROSTER_SUBJECT);
    assert!(row.get("handle_claim_digests").is_none());
}

#[test]
fn roster_disclosure_depends_on_realm_policy() {
    let state = test_state();
    insert_member_identity_subject(&state);
    let digest = cache_claim(
        &state,
        handle_claim(
            &state,
            &state.config.service_did,
            &state.config.service_did,
            now() + ChronoDuration::hours(1),
            "verified",
            None,
        ),
    );

    let private_realm = roster_realm(false, false);
    let private_row = roster_row(&state, &private_realm, None);
    assert!(private_row.get("subject_id").is_none());
    assert!(private_row.get("handle_claim_digests").is_none());
    assert!(private_row.get("handle_claims").is_none());

    let public_realm = roster_realm(true, false);
    let public_row = roster_row(&state, &public_realm, None);
    assert_eq!(public_row["subject_id"], ROSTER_SUBJECT);
    assert_eq!(public_row["handle_claim_digests"], json!([digest]));
}

#[test]
fn roster_limits_large_inline_handle_claim_payloads() {
    let state = test_state();
    insert_member_identity_subject(&state);
    let claim = handle_claim(
        &state,
        &state.config.service_did,
        &state.config.service_did,
        now() + ChronoDuration::hours(1),
        "verified",
        Some(json!([{"blob": "x".repeat(HANDLE_CLAIMS_INLINE_MAX_BYTES + 1)}])),
    );
    let digest = cache_claim(&state, claim);
    let realm = roster_realm(false, true);
    let session = roster_session(&state, ROSTER_CALLER);

    let row = roster_row(&state, &realm, Some(&session));

    assert_eq!(row["subject_id"], ROSTER_SUBJECT);
    assert_eq!(row["handle_claim_digests"], json!([digest]));
    assert!(row.get("handle_claims").is_none());
    assert_eq!(row["handle_claims_limited"], true);
}

fn assert_integrity_error(error: SyncCursorError) {
    match error {
        SyncCursorError::Integrity(_) => {}
        other => panic!("expected cursor integrity error, got {other:?}"),
    }
}

#[tokio::test]
async fn inline_cursor_body_is_rejected_by_core_stateful_cursor_parser() {
    let state = test_state();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = encode_sync_cursor_value(json!({
        "v": "1",
        "purpose": "stream",
        "t": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": now_ms + 60_000,
        "issuer_kid": "did:web:soland.local#notary-key",
        "positions": {
            "realms": {},
            "devices": {},
            "to_device": 0
        }
    }));

    let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect_err("inline cursor body must be rejected");

    assert_integrity_error(error);
}

#[tokio::test]
async fn unchanged_frontier_remints_same_handle_and_advance_keeps_old_token_valid() {
    let state = test_state();
    let session = roster_session(&state, "did:web:alice.example");
    let positions = BTreeMap::from([("ck:realm:dedup-test".to_owned(), 7i64)]);
    let now_ms = chrono::Utc::now().timestamp_millis();

    let first = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions.clone(),
        BTreeMap::new(),
        3,
    )
    .await;
    let second = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions.clone(),
        BTreeMap::new(),
        3,
    )
    .await;
    let handle_of = |token: &str| {
        decode_sync_cursor_value(token).expect("decodes")["h"]
            .as_str()
            .expect("handle")
            .to_owned()
    };
    assert_eq!(
        handle_of(&first),
        handle_of(&second),
        "unchanged frontier re-mints the SAME deterministic handle (no churn)"
    );

    // Frontier advances -> a different handle; the OLD token still
    // resolves (rows coexist until forward-progress pruning).
    let advanced =
        sync_token_for_client_sync(&state, Some(&session), None, positions, BTreeMap::new(), 4)
            .await;
    assert_ne!(handle_of(&first), handle_of(&advanced));
    let parsed_old = parse_and_validate_sync_cursor(&first, &state, Some(&session), None, now_ms)
        .await
        .expect("old cursor still parses after a newer mint");
    assert_eq!(parsed_old.to_device_position, 3);
    let parsed_new =
        parse_and_validate_sync_cursor(&advanced, &state, Some(&session), None, now_ms)
            .await
            .expect("advanced cursor parses");
    assert_eq!(parsed_new.to_device_position, 4);
}

#[tokio::test]
async fn presenting_a_cursor_prunes_strictly_older_stream_handles() {
    let state = test_state();
    let session = roster_session(&state, "did:web:alice.example");
    let positions = BTreeMap::from([("ck:realm:prune-test".to_owned(), 1i64)]);
    let now_ms = chrono::Utc::now().timestamp_millis();

    let old_token = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions.clone(),
        BTreeMap::new(),
        1,
    )
    .await;
    // Deterministic issued_at_ms is stamped at first mint; ensure the
    // second mint lands strictly later on the ms clock.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let new_token =
        sync_token_for_client_sync(&state, Some(&session), None, positions, BTreeMap::new(), 2)
            .await;

    let presented =
        parse_and_validate_sync_cursor(&new_token, &state, Some(&session), None, now_ms)
            .await
            .expect("new cursor parses");
    let pruned = state
        .persistence
        .sync_cursors()
        .prune_stream_superseded(
            &session.actor,
            &session.device_id,
            &sync_filter_digest(None),
            presented
                .issued_at_ms
                .expect("stateful cursor carries issued_at_ms"),
        )
        .await
        .expect("prune runs");
    assert_eq!(pruned, 1, "the superseded older handle row is deleted");

    let error = parse_and_validate_sync_cursor(&old_token, &state, Some(&session), None, now_ms)
        .await
        .expect_err("pruned handle no longer resolves");
    assert_integrity_error(error);
    parse_and_validate_sync_cursor(&new_token, &state, Some(&session), None, now_ms)
        .await
        .expect("presented cursor still parses");
}

#[tokio::test]
async fn revoked_cursor_returns_revoked_error() {
    let state = test_state();
    let token = sync_token_for_client_sync(
        &state,
        None,
        None,
        BTreeMap::from([("ck:realm:revoke-test".to_owned(), 3)]),
        BTreeMap::new(),
        5,
    )
    .await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect("freshly issued cursor validates");

    state
        .sync_cursor_revocations
        .lock()
        .unwrap()
        .push(crate::state::CursorRevocation {
            cursor_digest: sha256_hex(token.as_bytes()),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: None,
            scope: "this_cursor".to_owned(),
            reason_code: "compromised".to_owned(),
            revoked_at: now(),
            expires_at: now() + ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS),
        });

    let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect_err("revoked cursor must fail validation");
    assert!(
        matches!(error, SyncCursorError::Revoked),
        "expected Revoked, got {error:?}"
    );
}

#[tokio::test]
async fn expired_revocation_entry_is_pruned_and_does_not_block() {
    let state = test_state();
    let token = sync_token_for_client_sync(
        &state,
        None,
        None,
        BTreeMap::from([("ck:realm:revoke-gc".to_owned(), 1)]),
        BTreeMap::new(),
        0,
    )
    .await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    state
        .sync_cursor_revocations
        .lock()
        .unwrap()
        .push(crate::state::CursorRevocation {
            cursor_digest: sha256_hex(token.as_bytes()),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: None,
            scope: "this_cursor".to_owned(),
            reason_code: "stale".to_owned(),
            revoked_at: now() - ChronoDuration::seconds(2 * CURSOR_MAX_TTL_SECONDS),
            expires_at: now() - ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS),
        });

    parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect("expired revocation entry must be pruned, not block a valid cursor");
    assert!(
        state.sync_cursor_revocations.lock().unwrap().is_empty(),
        "expired revocation entry should have been pruned"
    );
}
