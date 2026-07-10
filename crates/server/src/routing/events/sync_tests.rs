use super::*;

#[test]
fn derive_cursor_handle_is_deterministic_and_spec_shaped() {
    let key = b"test-cursor-key-0123456789abcdef";
    let realms = BTreeMap::from([("ak:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 11i64)]);
    let device_lists = BTreeMap::from([("did:web:alice.example".to_owned(), 13i64)]);
    let binding = stream_cursor_handle_binding(
        "did:web:alice",
        "ak:device:1",
        "did:web:host",
        "fd0",
        &realms,
        &account_realms,
        &device_lists,
        3,
    );
    let h1 = derive_cursor_handle(key, &binding);
    let h2 = derive_cursor_handle(key, &binding);
    assert_eq!(h1, h2, "same binding -> same handle");
    assert!(
        h1.len() >= arkret_sdk::cursor::CURSOR_HANDLE_MIN_LEN,
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
    let realms = BTreeMap::from([("ak:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 11i64)]);
    let device_lists = BTreeMap::from([("did:web:alice.example".to_owned(), 13i64)]);
    let a = stream_cursor_handle_binding(
        "p",
        "d",
        "s",
        "f",
        &realms,
        &account_realms,
        &device_lists,
        3,
    );
    let b = stream_cursor_handle_binding(
        "p",
        "d",
        "s",
        "f",
        &realms,
        &account_realms,
        &device_lists,
        3,
    );
    assert_eq!(derive_cursor_handle(key, &a), derive_cursor_handle(key, &b));
}

#[test]
fn derive_cursor_handle_separates_bindings_and_keys() {
    let realms = BTreeMap::from([("ak:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 11i64)]);
    let advanced_account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 12i64)]);
    let device_lists = BTreeMap::from([("did:web:alice.example".to_owned(), 13i64)]);
    let advanced_device_lists = BTreeMap::from([("did:web:alice.example".to_owned(), 14i64)]);
    let base = stream_cursor_handle_binding(
        "p",
        "d",
        "s",
        "f",
        &realms,
        &account_realms,
        &device_lists,
        3,
    );
    let other_device = stream_cursor_handle_binding(
        "p",
        "d2",
        "s",
        "f",
        &realms,
        &account_realms,
        &device_lists,
        3,
    );
    let advanced = stream_cursor_handle_binding(
        "p",
        "d",
        "s",
        "f",
        &realms,
        &account_realms,
        &device_lists,
        4,
    );
    let advanced_account = stream_cursor_handle_binding(
        "p",
        "d",
        "s",
        "f",
        &realms,
        &advanced_account_realms,
        &device_lists,
        3,
    );
    let advanced_devices = stream_cursor_handle_binding(
        "p",
        "d",
        "s",
        "f",
        &realms,
        &account_realms,
        &advanced_device_lists,
        3,
    );
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
        derive_cursor_handle(k1, &advanced_devices),
        "advanced device-list position -> different handle"
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
        "ak:event:019e507b-16b2-719a-84fd-a9319ab43a36",
    );
    let welcome_message = timestamp_position_with_tie_breaker(
        created_at,
        "ak:event:019e507b-1857-73b7-9579-a00706bf0af4",
    );

    assert_ne!(realm_create, welcome_message);
    assert!(welcome_message > realm_create);
}

fn presence_record(device: &str, status: &str, updated_at: DateTime<Utc>) -> PresenceRecord {
    PresenceRecord {
        actor: "did:web:alice.example".to_owned(),
        device_id: device.to_owned(),
        status: status.to_owned(),
        status_message: None,
        last_active_at: None,
        expires_at: Some(updated_at + ChronoDuration::seconds(60)),
        updated_at,
    }
}

#[test]
fn presence_sync_event_marks_stale_online_offline() {
    let record = presence_record(
        "ak:device:a",
        "online",
        now() - ChronoDuration::seconds(PRESENCE_ONLINE_TTL_SECONDS + 1),
    );

    let aggregated = aggregate_presence_records(&[record], now()).expect("aggregate");
    let event = presence_sync_event_json("did:web:alice.example", &aggregated, true);

    assert_eq!(event["user_id"], "did:web:alice.example");
    assert_eq!(event["presence"], "offline");
    assert_eq!(event["status"], "offline");
    assert!(event.get("last_active").is_none());
    let last_active_at = event["last_active_at"]
        .as_str()
        .expect("stale online presence emits bucketed last_active_at");
    assert!(last_active_at.ends_with("/PT1H"));
}

#[test]
fn presence_sync_event_hides_activity_detail_without_contact_visibility() {
    let mut record = presence_record("ak:device:a", "dnd", now());
    record.status_message = Some("in a meeting".to_owned());
    record.last_active_at = Some("2026-07-03T10:00:00Z/PT1H".to_owned());

    let aggregated = aggregate_presence_records(&[record], now()).expect("aggregate");
    let event = presence_sync_event_json("did:web:alice.example", &aggregated, false);

    assert_eq!(event["presence"], "offline");
    assert_eq!(event["status"], "offline");
    // §3.4 downgrade must not leak the transient message or the
    // activity bucket alongside the degraded state.
    assert!(event.get("status_message").is_none());
    assert!(event.get("last_active_at").is_none());
}

#[test]
fn presence_aggregation_prefers_dnd_then_online_then_idle() {
    let now = now();
    let records = vec![
        presence_record("ak:device:a", "idle", now - ChronoDuration::seconds(1)),
        presence_record("ak:device:b", "online", now),
    ];
    let aggregated = aggregate_presence_records(&records, now).expect("aggregate");
    assert_eq!(aggregated.status, "online");

    let records = vec![
        presence_record("ak:device:a", "online", now),
        presence_record("ak:device:b", "dnd", now - ChronoDuration::seconds(1)),
    ];
    let aggregated = aggregate_presence_records(&records, now).expect("aggregate");
    assert_eq!(aggregated.status, "dnd");
}

#[test]
fn presence_aggregation_all_expired_projects_offline() {
    let now = now();
    let mut record = presence_record("ak:device:a", "idle", now - ChronoDuration::seconds(120));
    record.expires_at = Some(now - ChronoDuration::seconds(30));
    let aggregated = aggregate_presence_records(&[record], now).expect("aggregate");
    assert_eq!(aggregated.status, "offline");
    assert!(aggregated.all_expired);
    assert_eq!(aggregate_presence_records(&[], now).map(|a| a.status), None);
}

#[test]
fn presence_sync_event_carries_status_message_for_authorized_observer() {
    let mut record = presence_record("ak:device:a", "online", now());
    record.status_message = Some("On vacation until May 5".to_owned());
    record.last_active_at = Some("2026-07-03T10:00:00Z/PT1H".to_owned());

    let aggregated = aggregate_presence_records(&[record], now()).expect("aggregate");
    let event = presence_sync_event_json("did:web:alice.example", &aggregated, true);

    assert_eq!(event["status"], "online");
    assert_eq!(event["status_message"], "On vacation until May 5");
    assert_eq!(event["last_active_at"], "2026-07-03T10:00:00Z/PT1H");
}

#[tokio::test]
async fn incremental_sync_includes_presence_only_for_presence_delta() {
    let state = test_state();
    let session = roster_session(&state, ROSTER_ACTOR);
    state.realms.lock().upsert(roster_realm(false, true));
    state
        .persistence
        .presence()
        .put(PresenceRecord {
            actor: ROSTER_ACTOR.to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            status: "dnd".to_owned(),
            status_message: Some("In a meeting".to_owned()),
            last_active_at: None,
            expires_at: Some(now() + ChronoDuration::seconds(60)),
            updated_at: now(),
        })
        .await
        .expect("presence stored");

    let body = roster_body(&state.config.service_did);
    let initial =
        build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default(), false).await;
    assert!(
        initial
            .presence
            .iter()
            .any(|event| event["actor_id"] == ROSTER_ACTOR && event["presence"] == "dnd"),
        "full sync carries visible presence: {:?}",
        initial.presence
    );

    let filter_value = sync_filter_value(body.filter.as_ref());
    let initial_cursor = parse_and_validate_sync_cursor(
        &initial.cursor,
        &state,
        Some(&session),
        filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("initial cursor parses");
    let mut incremental_body = body.clone();
    incremental_body.after = Some(initial.cursor.clone());

    let quiet_incremental = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &initial_cursor,
        false,
    )
    .await;
    assert!(quiet_incremental.presence.is_empty());

    let presence_incremental = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &initial_cursor,
        true,
    )
    .await;
    assert!(
        presence_incremental
            .presence
            .iter()
            .any(|event| event["actor_id"] == ROSTER_ACTOR && event["presence"] == "dnd"),
        "presence-triggered incremental sync carries current presence: {:?}",
        presence_incremental.presence
    );
}

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-sync-cursor-test-blobs"),
        ),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        notary_signing_key_seed: Some([9u8; 32]),
        seed_demo_data: true,
        ..crate::config::AppConfig::test_default()
    }
}

fn test_state() -> AppState {
    AppState::new(test_config(), soland_data::Db { pool: None })
}

const ROSTER_REALM: &str = "ak:realm:01904100-0000-7000-8000-00000000a001";
const ROSTER_ACTOR: &str = "did:web:alice.example";
const ROSTER_SUBJECT: &str = "did:web:alice-principal.example";
const ROSTER_CALLER: &str = "did:web:bob.example";

fn roster_body(audience: &str) -> SyncRequestBody {
    let mut extra = BTreeMap::new();
    extra.insert("audience".to_owned(), json!(audience));
    SyncRequestBody {
        after: None,
        catchup: None,
        filter: Some(arkret_sdk::SyncFilter {
            realms: Vec::new(),
            timeline_limit: None,
            lazy_load_members: false,
            include_redundant_members: false,
            event_types: Vec::new(),
            not_event_types: Vec::new(),
            extra,
        }),
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
        agent_session: None,
        expires_at: now() + ChronoDuration::hours(1),
        created_at: now(),
        revoked_at: None,
    }
}

fn sync_test_operation_at(
    operation_id: &str,
    kind: &str,
    payload: Value,
    created_at: DateTime<Utc>,
) -> arkret_sdk::Operation {
    let mut operation = arkret_sdk::Operation::create(
        arkret_sdk::OperationId::new(operation_id.to_owned()).unwrap(),
        RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        kind,
        payload,
    );
    operation.created_at = created_at;
    operation
}

fn roster_realm(public: bool, include_caller: bool) -> RealmDirectoryEntry {
    let mut entry = RealmDirectoryEntry::new(
        RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        "Roster evidence",
    );
    entry.public = public;
    entry
        .members
        .insert(arkret_sdk::Did::new(ROSTER_ACTOR.to_owned()).unwrap());
    if include_caller {
        entry
            .members
            .insert(arkret_sdk::Did::new(ROSTER_CALLER.to_owned()).unwrap());
    }
    entry
}

fn insert_projected_membership(state: &AppState, actor: &str, membership: &str) {
    let updated_at = now();
    state.projection.lock().members.insert(
        (ROSTER_REALM.to_owned(), actor.to_owned()),
        crate::reducer::SolandMembershipState {
            member: actor.to_owned(),
            realm_id: ROSTER_REALM.to_owned(),
            state: membership.to_owned(),
            role: "member".to_owned(),
            delivery_status: None,
            recipient_service_did: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            invited_at: (membership == "invite").then_some(updated_at),
            joined_at: updated_at,
            updated_at,
        },
    );
}

#[tokio::test]
async fn projection_visibility_uses_received_at_for_joined_history_cutoff() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_data::Db { pool: None });
    state.realms.lock().upsert(roster_realm(false, true));
    let session = roster_session(&state, ROSTER_CALLER);
    let created_at = DateTime::parse_from_rfc3339("2026-06-24T10:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let pre_join_received_at = created_at + ChronoDuration::milliseconds(100);
    let joined_at = created_at + ChronoDuration::milliseconds(200);
    let post_join_received_at = created_at + ChronoDuration::milliseconds(300);

    state
        .persistence
        .realm_meta()
        .put(
            ROSTER_REALM,
            &crate::state::RealmMetaRecord {
                owner: ROSTER_ACTOR.to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .expect("realm meta stored");
    let mut member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000ef",
        arkret_sdk::events::kinds::MEMBER_STATE,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "event_received_at": joined_at.to_rfc3339()
        }),
        created_at,
    );
    member_join.created_at = created_at;
    state.projection.lock().apply(&member_join, &state.hlc);

    let event_at = |event_id: &str, received_at| ProjectionEventRecord {
        event_id: event_id.to_owned(),
        realm_id: ROSTER_REALM.to_owned(),
        event_kind: arkret_sdk::events::kinds::MLS_COMMIT.to_owned(),
        operation_type: "event".to_owned(),
        operation_id: Some(event_id.replace("ak:event:", "ak:operation:")),
        sender: Some(ROSTER_ACTOR.to_owned()),
        payload: json!({
            "realm_id": ROSTER_REALM,
            "mls_group_id": "ak:mls_group:01904100-0000-7000-8000-0000000000e1"
        }),
        created_at,
        received_at,
    };
    let pre_join_event = event_at(
        "ak:event:01904100-0000-7000-8000-0000000000e1",
        pre_join_received_at,
    );
    let post_join_event = event_at(
        "ak:event:01904100-0000-7000-8000-0000000000e2",
        post_join_received_at,
    );

    assert!(
        !projection_record_visible_to_session(&state, &pre_join_event, Some(&session)).await,
        "joined history must crop events received before the member joined even when created_at is the same second"
    );
    assert!(
        projection_record_visible_to_session(&state, &post_join_event, Some(&session)).await,
        "joined history should include events received after the member joined"
    );
}

async fn put_canonical_event_received_at(
    state: &AppState,
    event_id: &str,
    actor_seq: u64,
    kind: &str,
    payload: Value,
    created_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) {
    let envelope = json!({
        "event_id": event_id,
        "actor_id": ROSTER_ACTOR,
        "actor_seq": actor_seq,
        "realm_id": ROSTER_REALM,
        "kind": kind,
        "payload": payload,
        "created_at": created_at,
    });
    let canonical_bytes = serde_json::to_vec(&envelope).expect("canonical event test envelope");
    state
        .persistence
        .events()
        .put(crate::state::CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: ROSTER_ACTOR.to_owned(),
            actor_seq,
            realm_id: Some(ROSTER_REALM.to_owned()),
            kind: kind.to_owned(),
            schema_id: "ak.event.v1".to_owned(),
            canonical_digest: arkret_sdk::canonical::sha256_digest(&canonical_bytes),
            canonical_bytes,
            envelope,
            received_at,
        })
        .await
        .expect("canonical event stored");
}

#[tokio::test]
async fn sync_timeline_visibility_uses_received_at_for_joined_history_cutoff() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_data::Db { pool: None });
    state.realms.lock().upsert(roster_realm(false, true));
    let session = roster_session(&state, ROSTER_CALLER);
    let strand_id = strand_id_from_realm_id(ROSTER_REALM);
    let created_at = DateTime::parse_from_rfc3339("2026-06-24T10:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let pre_join_received_at = created_at + ChronoDuration::milliseconds(100);
    let joined_at = created_at + ChronoDuration::milliseconds(200);
    let post_join_received_at = created_at + ChronoDuration::milliseconds(300);

    state
        .persistence
        .realm_meta()
        .put(
            ROSTER_REALM,
            &crate::state::RealmMetaRecord {
                owner: ROSTER_ACTOR.to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("none".to_owned()),
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .expect("realm meta stored");

    let mut member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000002ef",
        arkret_sdk::events::kinds::MEMBER_STATE,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "event_received_at": joined_at.to_rfc3339()
        }),
        created_at,
    );
    member_join.created_at = created_at;
    state.projection.lock().apply(&member_join, &state.hlc);

    let pre_join_event_id = "ak:event:01904100-0000-7000-8000-0000000002e1";
    let post_join_event_id = "ak:event:01904100-0000-7000-8000-0000000002e2";
    let pre_join_payload = json!({
        "event_id": pre_join_event_id,
        "message_id": "ak:message:01904100-0000-7000-8000-0000000002e1",
        "realm_id": ROSTER_REALM,
        "strand_id": strand_id,
        "thread_id": strand_id,
        "sender": ROSTER_ACTOR,
        "content": {"kind": "ak.content.text", "body": "before join"}
    });
    let post_join_payload = json!({
        "event_id": post_join_event_id,
        "message_id": "ak:message:01904100-0000-7000-8000-0000000002e2",
        "realm_id": ROSTER_REALM,
        "strand_id": strand_id,
        "thread_id": strand_id,
        "sender": ROSTER_ACTOR,
        "content": {"kind": "ak.content.text", "body": "after join"}
    });
    let pre_join_message = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000002e1",
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        pre_join_payload.clone(),
        created_at,
    );
    let post_join_message = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000002e2",
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        post_join_payload.clone(),
        created_at,
    );
    {
        let mut projection = state.projection.lock();
        projection.apply(&pre_join_message, &state.hlc);
        projection.apply(&post_join_message, &state.hlc);
    }
    put_canonical_event_received_at(
        &state,
        pre_join_event_id,
        1,
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        pre_join_payload,
        created_at,
        pre_join_received_at,
    )
    .await;
    put_canonical_event_received_at(
        &state,
        post_join_event_id,
        2,
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        post_join_payload,
        created_at,
        post_join_received_at,
    )
    .await;

    let body = roster_body(&state.config.service_did);
    let snapshot =
        build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default(), false).await;
    let timeline_events = snapshot.realms[ROSTER_REALM]["timeline"]["events"]
        .as_array()
        .expect("timeline events array");
    assert!(
        !timeline_events
            .iter()
            .any(|event| event["event_id"] == pre_join_event_id),
        "joined history must hide messages received before the member joined"
    );
    assert!(
        timeline_events
            .iter()
            .any(|event| event["event_id"] == post_join_event_id),
        "joined history must include messages received after the member joined even when created_at predates joined_at"
    );
}

fn insert_member_identity_subject(state: &AppState) {
    use crate::state::{MemberIdentityEventRecord, MemberIdentitySubjectKey};
    let identity_payload = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice" }
        }
    });
    let payload_digest = arkret_sdk::canonical::sha256_digest(
        arkret_sdk::canonical::canonical_json_bytes(&identity_payload).unwrap(),
    );
    state
        .member_identity
        .lock()
        .insert(MemberIdentityEventRecord {
            event_id: "ak:operation:roster-identity-1".to_owned(),
            subject: MemberIdentitySubjectKey {
                realm_id: ROSTER_REALM.to_owned(),
                actor_id: ROSTER_ACTOR.to_owned(),
                segment: "member_identity".to_owned(),
            },
            payload_digest,
            replaces: Vec::new(),
            raw_event: json!({
                "operation_id": "ak:operation:roster-identity-1",
                "event_kind": arkret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE,
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
        "schema": "ak.schema.handle_claim.v1",
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

fn roster_membership_for_actor<'a>(rows: &'a [Value], actor: &str) -> Option<&'a str> {
    rows.iter()
        .find(|row| row["actor_id"] == actor)
        .and_then(|row| row["membership"].as_str())
}

fn canonical_value_digest(value: &Value) -> String {
    arkret_sdk::canonical::sha256_digest(
        arkret_sdk::canonical::canonical_json_bytes(value).unwrap(),
    )
}

// SPEC-CR-010 / SOL-05-008 — `project_member_identity_update` MUST store the
// canonical `ak:event:` id (threaded through `payload.event_id`) so the
// effective-set / replaces / R3.2 digests live in the same id space as a
// spec-compliant client, whose `replaces[].event_id` is a `ak:event:` id.
#[test]
fn member_identity_projection_stores_typed_event_id_and_matches_event_replaces() {
    use arkret_sdk::{Operation, OperationId};

    use crate::routing::events::projection::project_member_identity_update;

    let state = test_state();
    let realm = ROSTER_REALM;
    let actor = ROSTER_ACTOR;
    let first_event_id = "ak:event:01904100-0000-7000-8000-0000000000e1";
    let second_event_id = "ak:event:01904100-0000-7000-8000-0000000000e2";

    let first_identity = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice" }
        }
    });
    let first_digest = arkret_sdk::canonical::sha256_digest(
        arkret_sdk::canonical::canonical_json_bytes(&first_identity).unwrap(),
    );

    // First update. Operation carries the canonical `ak:event:` id in
    // `payload.event_id`, exactly as `projection_operation_from_event` threads it.
    let first_op = Operation::create(
        OperationId::new("ak:operation:01904100-0000-7000-8000-0000000000e1".to_owned()).unwrap(),
        RealmId::new(realm.to_owned()).unwrap(),
        arkret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE,
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
        let registry = state.member_identity.lock();
        let snapshot = registry.snapshot_for_actor(realm, actor).unwrap();
        assert_eq!(snapshot.identity_event_ids, vec![first_event_id.to_owned()]);
    }

    // Second update replaces the first using the spec-compliant `ak:event:`
    // edge. Before the fix this never matched (projection stored `ak:operation:`).
    let second_identity = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice 2" }
        }
    });
    let second_op = Operation::create(
        OperationId::new("ak:operation:01904100-0000-7000-8000-0000000000e2".to_owned()).unwrap(),
        RealmId::new(realm.to_owned()).unwrap(),
        arkret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE,
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

    let registry = state.member_identity.lock();
    let snapshot = registry.snapshot_for_actor(realm, actor).unwrap();
    // The `ak:event:` replaces edge drops the predecessor: only the second
    // event remains effective, and the stored id is the typed event id.
    assert_eq!(
        snapshot.identity_event_ids,
        vec![second_event_id.to_owned()],
        "replaces[].event_id (ak:event:) must match the stored typed event id"
    );
    assert!(
        snapshot
            .effective_entries
            .iter()
            .all(|entry| entry.event_id.starts_with("ak:event:")),
        "effective entries must live in the ak:event: id space"
    );
}

#[test]
fn roster_includes_projected_members_and_directory_fallback() {
    let state = test_state();
    insert_projected_membership(&state, ROSTER_CALLER, "join");
    insert_projected_membership(&state, "did:web:carol.example", "invite");
    insert_projected_membership(&state, "did:web:dave.example", "knock");
    let realm = roster_realm(false, false);
    let body = roster_body(&state.config.service_did);
    let session = roster_session(&state, ROSTER_ACTOR);

    let rows = roster_members_for_realm(&state, &realm, Some(&session), &body);

    assert_eq!(
        roster_membership_for_actor(&rows, ROSTER_ACTOR),
        Some("join"),
        "directory creator is retained as a joined member fallback"
    );
    assert_eq!(
        roster_membership_for_actor(&rows, ROSTER_CALLER),
        Some("join"),
        "accepted invitee from projected member FSM is emitted"
    );
    assert_eq!(
        roster_membership_for_actor(&rows, "did:web:carol.example"),
        Some("invite")
    );
    assert_eq!(
        roster_membership_for_actor(&rows, "did:web:dave.example"),
        Some("knock")
    );
}

#[test]
fn roster_suppresses_terminal_projected_membership_over_directory_fallback() {
    let state = test_state();
    insert_projected_membership(&state, ROSTER_ACTOR, "leave");
    let realm = roster_realm(false, false);
    let body = roster_body(&state.config.service_did);

    let rows = roster_members_for_realm(&state, &realm, None, &body);

    assert_eq!(roster_membership_for_actor(&rows, ROSTER_ACTOR), None);
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

#[tokio::test]
async fn sync_snapshot_emits_device_list_baseline_changes_and_left_principals() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_data::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    state.realms.lock().upsert(roster_realm(false, true));

    let created_at = DateTime::parse_from_rfc3339("2026-06-18T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let updated_at = created_at + ChronoDuration::seconds(1);
    for (actor, device_id) in [
        (
            ROSTER_ACTOR,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        ),
        (
            ROSTER_CALLER,
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        ),
    ] {
        state
            .persistence
            .devices()
            .put(&DeviceInventoryRecord {
                actor: actor.to_owned(),
                device_id: device_id.to_owned(),
                display_name: None,
                verification_state: "verified".to_owned(),
                payload: json!({"algorithms": ["mls_rfc9420"]}),
                created_at,
                updated_at,
                revoked_at: None,
            })
            .await
            .expect("device inserted");
    }

    let body = roster_body(&state.config.service_did);
    let initial =
        build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default(), false).await;
    assert_eq!(
        initial.device_lists,
        json!({"changed": [ROSTER_ACTOR, ROSTER_CALLER], "left": []})
    );
    let filter_value = sync_filter_value(body.filter.as_ref());
    let initial_cursor = parse_and_validate_sync_cursor(
        &initial.cursor,
        &state,
        Some(&session),
        filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("initial cursor parses");

    let mut revoked = state
        .persistence
        .devices()
        .list_for_actor_including_revoked(ROSTER_ACTOR)
        .await
        .expect("device list")
        .into_iter()
        .next()
        .expect("actor device exists");
    revoked.revoked_at = Some(updated_at + ChronoDuration::seconds(1));
    revoked.updated_at = updated_at + ChronoDuration::seconds(1);
    state
        .persistence
        .devices()
        .put(&revoked)
        .await
        .expect("device revoked");

    let mut incremental_body = body.clone();
    incremental_body.after = Some(initial.cursor.clone());
    let after_revocation = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &initial_cursor,
        false,
    )
    .await;
    assert_eq!(
        after_revocation.device_lists,
        json!({"changed": [ROSTER_ACTOR], "left": []}),
        "device revocation changes the principal device list, not top-level left"
    );
    let incremental_filter_value = sync_filter_value(incremental_body.filter.as_ref());
    let after_revocation_cursor = parse_and_validate_sync_cursor(
        &after_revocation.cursor,
        &state,
        Some(&session),
        incremental_filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("revocation cursor parses");

    state.realms.lock().upsert(roster_realm(false, false));
    let after_scope_loss = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &after_revocation_cursor,
        false,
    )
    .await;
    assert_eq!(
        after_scope_loss.device_lists,
        json!({"changed": [], "left": [ROSTER_ACTOR]}),
        "principals no longer visible through any Realm leave the tracked device list set"
    );
}

#[tokio::test]
async fn sync_snapshot_emits_state_events_without_timeline_messages() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_data::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    state.realms.lock().upsert(roster_realm(false, true));

    let first_created_at = DateTime::parse_from_rfc3339("2026-06-24T10:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let second_created_at = first_created_at + ChronoDuration::seconds(1);
    let meta_created_at = first_created_at - ChronoDuration::seconds(1);
    state
        .persistence
        .realm_meta()
        .put(
            ROSTER_REALM,
            &crate::state::RealmMetaRecord {
                owner: ROSTER_ACTOR.to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "shared".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at: meta_created_at,
                updated_at: meta_created_at,
            },
        )
        .await
        .expect("realm meta stored");
    state
        .persistence
        .projection_events()
        .append(crate::state::ProjectionEventRecord {
            event_id: "ak:event:01904100-0000-7000-8000-0000000000a1".to_owned(),
            realm_id: ROSTER_REALM.to_owned(),
            event_kind: arkret_sdk::events::kinds::STRAND_UPDATE.to_owned(),
            operation_type: "state".to_owned(),
            operation_id: Some("ak:operation:01904100-0000-7000-8000-0000000000a1".to_owned()),
            sender: Some(ROSTER_ACTOR.to_owned()),
            payload: json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-0000000000a2",
                "patch": {"synthesis": {"$op": "set", "value": "first"}}
            }),
            created_at: first_created_at,
            received_at: first_created_at,
        })
        .await
        .expect("first state event appended");

    let body = roster_body(&state.config.service_did);
    let initial =
        build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default(), false).await;
    let initial_events = initial.realms[ROSTER_REALM]["state"]["events"]
        .as_array()
        .expect("state events array");
    assert_eq!(initial_events.len(), 1);
    assert_eq!(initial_events[0]["actor_id"], ROSTER_ACTOR);

    let filter_value = sync_filter_value(body.filter.as_ref());
    let initial_cursor = parse_and_validate_sync_cursor(
        &initial.cursor,
        &state,
        Some(&session),
        filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("initial cursor parses");

    state
        .persistence
        .projection_events()
        .append(crate::state::ProjectionEventRecord {
            event_id: "ak:event:01904100-0000-7000-8000-0000000000b1".to_owned(),
            realm_id: ROSTER_REALM.to_owned(),
            event_kind: arkret_sdk::events::kinds::STRAND_UPDATE.to_owned(),
            operation_type: "state".to_owned(),
            operation_id: Some("ak:operation:01904100-0000-7000-8000-0000000000b1".to_owned()),
            sender: Some(ROSTER_CALLER.to_owned()),
            payload: json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-0000000000a2",
                "patch": {"synthesis": {"$op": "set", "value": "first\n\n---\n\nsecond"}}
            }),
            created_at: second_created_at,
            received_at: second_created_at,
        })
        .await
        .expect("second state event appended");

    let mut incremental_body = body.clone();
    incremental_body.after = Some(initial.cursor.clone());
    let incremental = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &initial_cursor,
        false,
    )
    .await;
    let incremental_events = incremental.realms[ROSTER_REALM]["state"]["events"]
        .as_array()
        .expect("incremental state events array");
    assert_eq!(
        incremental_events.len(),
        1,
        "state-only updates must keep the Realm in incremental sync"
    );
    assert_eq!(incremental_events[0]["actor_id"], ROSTER_CALLER);
    assert_eq!(
        incremental.realms[ROSTER_REALM]["timeline"]["events"]
            .as_array()
            .expect("timeline events")
            .len(),
        0
    );
}

#[tokio::test]
async fn sync_snapshot_includes_shared_pin_events_for_joined_member() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_data::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    let strand_id = strand_id_from_realm_id(ROSTER_REALM);
    let message_event_id = "ak:event:01904100-0000-7000-8000-0000000000d1";
    let message_id = "ak:message:01904100-0000-7000-8000-0000000000d1";
    let base = DateTime::parse_from_rfc3339("2026-06-24T10:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let realm_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c1",
        arkret_sdk::events::kinds::REALM_CREATE,
        json!({
            "object": {
                "id": ROSTER_REALM,
                "title": "Pinned welcome space",
                "created_by": ROSTER_ACTOR,
                "join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "none"
            }
        }),
        base,
    );
    let member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c2",
        arkret_sdk::events::kinds::MEMBER_STATE,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "sender": ROSTER_CALLER
        }),
        base + ChronoDuration::seconds(1),
    );
    let strand_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c3",
        arkret_sdk::events::kinds::STRAND_CREATE,
        json!({
            "object": {
                "id": strand_id,
                "realm_id": ROSTER_REALM,
                "created_by": ROSTER_ACTOR,
                "metadata": {"title": "Discussion"}
            }
        }),
        base + ChronoDuration::seconds(2),
    );
    let message_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c4",
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        json!({
            "event_id": message_event_id,
            "message_id": message_id,
            "realm_id": ROSTER_REALM,
            "strand_id": strand_id,
            "thread_id": strand_id,
            "sender": ROSTER_ACTOR,
            "content": {"kind": "ak.content.text", "body": "Pinned welcome"}
        }),
        base + ChronoDuration::seconds(3),
    );
    crate::routing::events::projection::project_accepted_operations(
        &state,
        ROSTER_ACTOR,
        &[realm_create, member_join, strand_create, message_create],
    )
    .await;

    let body = roster_body(&state.config.service_did);
    let initial =
        build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default(), false).await;
    let filter_value = sync_filter_value(body.filter.as_ref());
    let initial_cursor = parse_and_validate_sync_cursor(
        &initial.cursor,
        &state,
        Some(&session),
        filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("initial cursor parses");

    let pin_add = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c5",
        arkret_sdk::events::kinds::PIN_ADD,
        json!({
            "event_id": "ak:event:01904100-0000-7000-8000-0000000000d5",
            "pin_scope": {"kind": "strand", "id": strand_id},
            "target_ref": message_id,
            "rank": "r1",
            "sender": ROSTER_ACTOR
        }),
        base + ChronoDuration::seconds(4),
    );
    crate::routing::events::projection::project_accepted_operations(
        &state,
        ROSTER_ACTOR,
        &[pin_add],
    )
    .await;

    let mut incremental_body = body.clone();
    incremental_body.after = Some(initial.cursor.clone());
    let incremental = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &initial_cursor,
        false,
    )
    .await;
    let state_events = incremental.realms[ROSTER_REALM]["state"]["events"]
        .as_array()
        .expect("state events array");
    assert!(
        state_events.iter().any(
            |event| event["event_kind"] == arkret_sdk::events::kinds::PIN_ADD
                && event["payload"]["target_ref"] == message_id
        ),
        "joined members must receive shared pin state events through account sync"
    );
}

#[tokio::test]
async fn sync_timeline_dedupes_redacted_revision_by_message_id() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_data::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    let strand_id = strand_id_from_realm_id(ROSTER_REALM);
    let message_event_id = "ak:event:01904100-0000-7000-8000-0000000001d1";
    let revision_event_id = "ak:event:01904100-0000-7000-8000-0000000001d2";
    let redaction_event_id = "ak:event:01904100-0000-7000-8000-0000000001d3";
    let message_id = "ak:message:01904100-0000-7000-8000-0000000001d1";
    let base = DateTime::parse_from_rfc3339("2026-06-24T11:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let realm_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c1",
        arkret_sdk::events::kinds::REALM_CREATE,
        json!({
            "object": {
                "id": ROSTER_REALM,
                "title": "Redacted revision space",
                "created_by": ROSTER_ACTOR,
                "join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "none"
            }
        }),
        base,
    );
    let member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c2",
        arkret_sdk::events::kinds::MEMBER_STATE,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "sender": ROSTER_CALLER
        }),
        base + ChronoDuration::seconds(1),
    );
    let strand_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c3",
        arkret_sdk::events::kinds::STRAND_CREATE,
        json!({
            "object": {
                "id": strand_id,
                "realm_id": ROSTER_REALM,
                "created_by": ROSTER_ACTOR,
                "metadata": {"title": "Discussion"}
            }
        }),
        base + ChronoDuration::seconds(2),
    );
    let message_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c4",
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        json!({
            "event_id": message_event_id,
            "message_id": message_id,
            "realm_id": ROSTER_REALM,
            "strand_id": strand_id,
            "thread_id": strand_id,
            "sender": ROSTER_ACTOR,
            "content": {"kind": "ak.content.text", "body": "original"}
        }),
        base + ChronoDuration::seconds(3),
    );
    let message_revise = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c5",
        arkret_sdk::events::kinds::MESSAGE_REVISE,
        json!({
            "event_id": revision_event_id,
            "target_ref": message_id,
            "realm_id": ROSTER_REALM,
            "strand_id": strand_id,
            "thread_id": strand_id,
            "sender": ROSTER_ACTOR,
            "content": {"kind": "ak.content.text", "body": "edited"}
        }),
        base + ChronoDuration::seconds(4),
    );
    let message_redact = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c6",
        arkret_sdk::events::kinds::MESSAGE_REDACT,
        json!({
            "event_id": redaction_event_id,
            "message_id": message_id,
            "realm_id": ROSTER_REALM,
            "sender": ROSTER_ACTOR,
            "reason": "user requested tombstone"
        }),
        base + ChronoDuration::seconds(5),
    );
    crate::routing::events::projection::project_accepted_operations(
        &state,
        ROSTER_ACTOR,
        &[
            realm_create,
            member_join,
            strand_create,
            message_create,
            message_revise,
            message_redact,
        ],
    )
    .await;

    let body = roster_body(&state.config.service_did);
    let snapshot =
        build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default(), false).await;
    let timeline_events = snapshot.realms[ROSTER_REALM]["timeline"]["events"]
        .as_array()
        .expect("timeline events array");
    let matching = timeline_events
        .iter()
        .filter(|event| event["message_id"] == message_id)
        .collect::<Vec<_>>();

    assert_eq!(
        matching.len(),
        1,
        "timeline must surface one logical tombstone per message_id"
    );
    assert_eq!(matching[0]["event_id"], revision_event_id);
    assert_eq!(matching[0]["redacted"], true);
    assert_eq!(matching[0]["state"], "redacted");
}

#[test]
fn auth_material_present_separates_anonymous_from_bad_credential() {
    // Genuinely anonymous: no Authorization header, no query token → the
    // subscribe handler MAY degrade to an anonymous session.
    assert!(!auth_material_present(None, None));
    assert!(!auth_material_present(
        None,
        Some("catchup=true&set_presence=online")
    ));

    // A presented bearer (even an expired/garbage one) counts as material, so
    // the handler MUST surface the 401 instead of silently degrading to
    // anonymous and stranding the principal-bound cursor (the
    // `cursor principal does not match request actor` loop).
    assert!(auth_material_present(
        Some("Bearer expired.token.value"),
        None
    ));
    assert!(auth_material_present(
        Some("bearer lower.case.scheme"),
        None
    ));

    // A token smuggled into the query string is also material (and separately
    // rejected by the auth layer) — never treat it as anonymous.
    assert!(auth_material_present(None, Some("access_token=x")));
    assert!(auth_material_present(None, Some("foo=1&auth=y")));
    assert!(auth_material_present(None, Some("token=z")));

    // A non-bearer Authorization scheme is not bearer material on its own.
    assert!(!auth_material_present(Some("Basic dXNlcjpwYXNz"), None));
}

fn assert_integrity_error(error: SyncCursorError) {
    match error {
        SyncCursorError::Integrity(_) => {}
        other => panic!("expected cursor integrity error, got {other:?}"),
    }
}

fn insert_cursor_field(cursor: &mut Value, key: &str, value: Value) {
    cursor
        .as_object_mut()
        .expect("cursor test value is object")
        .insert(key.to_owned(), value);
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
async fn inline_filter_digest_pseudo_fields_are_rejected_by_cursor_parsers() {
    let state = test_state();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let handle = "a".repeat(22);

    for field in ["filter_digest", "_filter_digest"] {
        let mut stream_cursor = json!({
            "v": "1",
            "purpose": "stream",
            "t": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "x": now_ms + 60_000,
            "h": handle.clone(),
        });
        insert_cursor_field(&mut stream_cursor, field, json!("client-supplied"));
        let token = encode_sync_cursor_value(stream_cursor);
        let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
            .await
            .expect_err("inline filter digest pseudo-field must be rejected");
        assert_integrity_error(error);

        let mut events_cursor = json!({
            "v": "1",
            "purpose": STREAM_CURSOR_PURPOSE,
            "t": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "x": now_ms + 60_000,
            "h": handle.clone(),
        });
        insert_cursor_field(&mut events_cursor, field, json!("client-supplied"));
        let token = encode_sync_cursor_value(events_cursor);
        let error =
            parse_and_validate_events_query_cursor(&token, &state, None, "digest-a", now_ms)
                .await
                .expect_err("events query inline filter digest pseudo-field must be rejected");
        assert_integrity_error(error);
    }
}

#[tokio::test]
async fn events_query_cursor_rejects_bare_event_id_cursor() {
    let state = test_state();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let error = parse_and_validate_events_query_cursor(
        "ak:event:01904100-0000-7000-8000-0000000000e1",
        &state,
        None,
        "digest-a",
        now_ms,
    )
    .await
    .expect_err("events query must not accept a bare event_id cursor");

    match error {
        SyncCursorError::Invalid(message) => {
            assert!(message.contains("ak:cursor"));
        }
        other => panic!("expected invalid cursor shape, got {other:?}"),
    }
}

#[tokio::test]
async fn events_query_cursor_uses_stream_purpose_and_binds_filter_digest() {
    let state = test_state();
    let session = roster_session(&state, "did:web:alice.example");
    let filter_a = sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.events.query.scan",
        "realms": [ROSTER_REALM],
        "actors": [],
        "filters": {},
        "order": "default",
    })));
    let filter_b = sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.events.query.scan",
        "realms": [ROSTER_REALM],
        "actors": [],
        "filters": {"kind": "ak.message.create"},
        "order": "default",
    })));
    let event_id = "ak:event:01904100-0000-7000-8000-0000000000e1";
    let token = sync_token_for_events_query(&state, Some(&session), &filter_a, event_id).await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token_value = decode_sync_cursor_value(&token).expect("events query cursor decodes");
    assert_eq!(
        token_value.get("purpose").and_then(Value::as_str),
        Some(STREAM_CURSOR_PURPOSE)
    );
    let handle = token_value
        .get("h")
        .and_then(Value::as_str)
        .expect("cursor handle");
    let record = state
        .persistence
        .sync_cursors()
        .get(handle)
        .await
        .unwrap()
        .expect("events query cursor handle persisted");
    assert_eq!(record.purpose, STREAM_CURSOR_PURPOSE);

    let parsed =
        parse_and_validate_events_query_cursor(&token, &state, Some(&session), &filter_a, now_ms)
            .await
            .expect("matching events query cursor parses");
    assert_eq!(parsed.event_id, event_id);

    let error =
        parse_and_validate_events_query_cursor(&token, &state, Some(&session), &filter_b, now_ms)
            .await
            .expect_err("changed query-scope digest must reject cursor replay");
    assert!(matches!(error, SyncCursorError::Mismatch(_)));

    let error = parse_and_validate_sync_cursor(&token, &state, Some(&session), None, now_ms)
        .await
        .expect_err("events query cursor must not parse as account stream cursor");
    assert!(matches!(
        error,
        SyncCursorError::Mismatch(_) | SyncCursorError::Integrity(_)
    ));
}

#[test]
fn sync_filter_digest_normalizes_account_filter_collections() {
    let filter_a = json!({
        "realms": ["ak:realm:b", "ak:realm:a", "ak:realm:a"],
        "event_types": ["ak.reaction.add", "ak.message.create", "ak.message.create"],
        "not_event_types": ["ak.redaction", "ak.audit.accessed"],
        "lazy_load_members": false,
        "include_redundant_members": false
    });
    let filter_b = json!({
        "realms": ["ak:realm:a", "ak:realm:b"],
        "event_types": ["ak.message.create", "ak.reaction.add"],
        "not_event_types": ["ak.audit.accessed", "ak.redaction"]
    });
    assert_eq!(
        sync_filter_digest(Some(&filter_a)),
        sync_filter_digest(Some(&filter_b))
    );

    let narrowed = json!({
        "realms": ["ak:realm:a", "ak:realm:b"],
        "event_types": ["ak.message.create"],
        "not_event_types": ["ak.audit.accessed", "ak.redaction"]
    });
    assert_ne!(
        sync_filter_digest(Some(&filter_a)),
        sync_filter_digest(Some(&narrowed))
    );
}

#[test]
fn sync_filter_digest_normalizes_events_query_scope_collections() {
    let scope_a = json!({
        "operation_id": "ak.self.events.query.scan",
        "realms": ["ak:realm:b", "ak:realm:a", "ak:realm:a"],
        "actors": ["did:web:bob.example", "did:web:alice.example"],
        "filters": {
            "kind": ["ak.reaction.add", "ak.message.create", "ak.message.create"],
            "not_event_types": ["ak.redaction", "ak.audit.accessed"]
        },
        "order": "default"
    });
    let scope_b = json!({
        "operation_id": "ak.self.events.query.scan",
        "realms": ["ak:realm:a", "ak:realm:b"],
        "actors": ["did:web:alice.example", "did:web:bob.example"],
        "filters": {
            "kind": ["ak.message.create", "ak.reaction.add"],
            "not_event_types": ["ak.audit.accessed", "ak.redaction"]
        },
        "order": "default"
    });
    assert_eq!(
        sync_filter_digest(Some(&scope_a)),
        sync_filter_digest(Some(&scope_b))
    );

    let different_order = json!({
        "operation_id": "ak.self.events.query.scan",
        "realms": ["ak:realm:a", "ak:realm:b"],
        "actors": ["did:web:alice.example", "did:web:bob.example"],
        "filters": {
            "kind": ["ak.message.create", "ak.reaction.add"],
            "not_event_types": ["ak.audit.accessed", "ak.redaction"]
        },
        "order": "ascending"
    });
    assert_ne!(
        sync_filter_digest(Some(&scope_a)),
        sync_filter_digest(Some(&different_order))
    );
}

#[tokio::test]
async fn unchanged_frontier_remints_same_handle_and_advance_keeps_old_token_valid() {
    let state = test_state();
    let session = roster_session(&state, "did:web:alice.example");
    let positions = BTreeMap::from([("ak:realm:dedup-test".to_owned(), 7i64)]);
    let now_ms = chrono::Utc::now().timestamp_millis();

    let first = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions.clone(),
        BTreeMap::new(),
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
    let advanced = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions,
        BTreeMap::new(),
        BTreeMap::new(),
        4,
    )
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
    let positions = BTreeMap::from([("ak:realm:prune-test".to_owned(), 1i64)]);
    let now_ms = chrono::Utc::now().timestamp_millis();

    let old_token = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        1,
    )
    .await;
    // Deterministic issued_at_ms is stamped at first mint; ensure the
    // second mint lands strictly later on the ms clock.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let new_token = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        positions,
        BTreeMap::new(),
        BTreeMap::new(),
        2,
    )
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
        BTreeMap::from([("ak:realm:revoke-test".to_owned(), 3)]),
        BTreeMap::new(),
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
        BTreeMap::from([("ak:realm:revoke-gc".to_owned(), 1)]),
        BTreeMap::new(),
        BTreeMap::new(),
        0,
    )
    .await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    state
        .sync_cursor_revocations
        .lock()
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
        state.sync_cursor_revocations.lock().is_empty(),
        "expired revocation entry should have been pruned"
    );
}
