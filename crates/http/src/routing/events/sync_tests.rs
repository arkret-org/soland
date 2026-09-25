use super::*;

fn roster_actor(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal).unwrap(),
        crate::test_event::station_id(),
    ))
}

fn stream_cursor_handle_binding(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    filter_digest: &str,
    realms_positions: &BTreeMap<String, i64>,
    account_realms_positions: &BTreeMap<String, i64>,
    to_device_position: i64,
) -> Vec<u8> {
    let account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal_id.to_owned()).unwrap(),
        arkret_wire::DidCoreId::new(service_id.to_owned()).unwrap(),
    );
    account_cursor_handle_binding(
        Some(&account_id),
        device_id,
        filter_digest,
        realms_positions,
        account_realms_positions,
        to_device_position,
    )
}

#[test]
fn account_cursor_binding_separates_same_core_at_different_stations() {
    let principal_id = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let station_a = arkret_wire::DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
    let station_b = arkret_wire::DidCoreId::new("ak:did_core:web:station-b.example").unwrap();
    let account_a = arkret_wire::AccountId::new(principal_id.clone(), station_a);
    let account_b = arkret_wire::AccountId::new(principal_id, station_b);
    let positions = BTreeMap::new();
    let bind = |account_id| {
        account_cursor_handle_binding(
            Some(account_id),
            "ak:device:01904100-0000-7000-8000-000000000001",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &positions,
            &positions,
            0,
        )
    };
    assert_eq!(bind(&account_a), bind(&account_a));
    assert_ne!(bind(&account_a), bind(&account_b));
}

#[test]
fn derive_cursor_handle_is_deterministic_and_spec_shaped() {
    let key = b"test-cursor-key-0123456789abcdef";
    let realms = BTreeMap::from([("ak:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 11i64)]);
    let binding = stream_cursor_handle_binding(
        "ak:did_core:web:alice.example",
        "ak:device:1",
        "ak:did_core:web:host.example",
        "fd0",
        &realms,
        &account_realms,
        3,
    );
    let h1 = derive_cursor_handle(key, &binding);
    let h2 = derive_cursor_handle(key, &binding);
    assert_eq!(h1, h2, "same binding -> same handle");
    assert!(
        h1.len() >= arkret_hlc::CURSOR_HANDLE_MIN_LEN,
        "handle >= 22 base64url chars"
    );
    assert!(
        h1.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "handle is base64url alphabet"
    );
}

/// Wire-form token whose body carries `handle` as `h`, bypassing the encode-side
/// validation so the decode chain is exercised with out-of-schema handles.
fn cursor_token_with_handle(handle: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(now);
    let expires_at =
        chrono::DateTime::from_timestamp_millis(issued_at.timestamp_millis() + 60 * 60 * 1000)
            .unwrap();
    let cursor = arkret_hlc::Cursor {
        v: "1".to_owned(),
        purpose: arkret_hlc::CursorPurpose::Stream,
        issued_at,
        expires_at,
        h: handle.to_owned(),
    };
    let bytes =
        arkret_canonical::canonical::canonical_json_bytes(&cursor).expect("cursor body serializes");
    format!(
        "ak:cursor:{}",
        arkret_canonical::base64url::base64url_encode(&bytes)
    )
}

/// Migrated from the deleted `soland_http::cursor` local copy: the ≥22-char
/// base64url handle floor (≥128-bit entropy, `encoding.md` §8.3.1) MUST be
/// enforced by the real production parse chain (SDK `Cursor::decode_at`),
/// not by a soland-local validator.
#[test]
fn sync_cursor_decode_rejects_low_entropy_or_padded_handles() {
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    // Positive control: a 22-char base64url handle decodes cleanly.
    assert!(
        arkret_hlc::Cursor::decode_at(&cursor_token_with_handle(&"a".repeat(22), now), now_ms)
            .is_ok(),
        "22-char base64url handle passes the SDK decode chain"
    );
    // 21 chars < 128-bit entropy floor -> reject.
    assert!(
        arkret_hlc::Cursor::decode_at(&cursor_token_with_handle(&"a".repeat(21), now), now_ms)
            .is_err(),
        "21-char handle is below the 128-bit entropy floor"
    );
    // `=` padding is outside the unpadded base64url handle alphabet -> reject.
    assert!(
        arkret_hlc::Cursor::decode_at(
            &cursor_token_with_handle("aaaaaaaaaaaaaaaaaaaaa=", now),
            now_ms
        )
        .is_err(),
        "padded handle is not unpadded base64url"
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
    let a = stream_cursor_handle_binding(
        "ak:did_core:web:principal.example",
        "d",
        "ak:did_core:web:station.example",
        "f",
        &realms,
        &account_realms,
        3,
    );
    let b = stream_cursor_handle_binding(
        "ak:did_core:web:principal.example",
        "d",
        "ak:did_core:web:station.example",
        "f",
        &realms,
        &account_realms,
        3,
    );
    assert_eq!(derive_cursor_handle(key, &a), derive_cursor_handle(key, &b));
}

#[test]
fn derive_cursor_handle_separates_bindings_and_keys() {
    let realms = BTreeMap::from([("ak:realm:a".to_owned(), 7i64)]);
    let account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 11i64)]);
    let advanced_account_realms = BTreeMap::from([("ak:realm:a".to_owned(), 12i64)]);
    let base = stream_cursor_handle_binding(
        "ak:did_core:web:principal.example",
        "d",
        "ak:did_core:web:station.example",
        "f",
        &realms,
        &account_realms,
        3,
    );
    let other_device = stream_cursor_handle_binding(
        "ak:did_core:web:principal.example",
        "d2",
        "ak:did_core:web:station.example",
        "f",
        &realms,
        &account_realms,
        3,
    );
    let advanced = stream_cursor_handle_binding(
        "ak:did_core:web:principal.example",
        "d",
        "ak:did_core:web:station.example",
        "f",
        &realms,
        &account_realms,
        4,
    );
    let advanced_account = stream_cursor_handle_binding(
        "ak:did_core:web:principal.example",
        "d",
        "ak:did_core:web:station.example",
        "f",
        &realms,
        &advanced_account_realms,
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
        derive_cursor_handle(k2, &base),
        "different server key -> different handle (unguessable without key)"
    );
}

// ── Signal rail (`sync/signal.md`) ─────────────────────────────────────
//
// v1 has no presence or typing projection to test. `signal.md` section 1 makes
// `signal_class` the only server-visible classification and puts the presence /
// typing / receipt payload inside the Signal ciphertext, so the server cannot
// aggregate device statuses or re-emit a "presence delta" — it has nothing to
// aggregate. What replaced those projections is the relay delivery contract: a
// per-subscriber-device watermark (deliver-once), the class TTL (section 2)
// after which a record is no longer delivered, and the rule that a device never
// receives its own Signal back. The tests below restate the old presence and
// typing coverage against exactly those rules.

fn signal_envelope(
    realm_id: &str,
    sender_actor: &str,
    sender_device: &str,
    sent_at: DateTime<Utc>,
    ttl_seconds: i64,
) -> arkret_wire::SignalEnvelope {
    let realm = arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap();
    let mut envelope = arkret_wire::SignalEnvelope {
        realm_id: realm.clone(),
        scope_ref: arkret_wire::ScopeRef::Realm { realm_id: realm },
        sender_actor_id: roster_actor(sender_actor),
        sender_device_id: Some(
            arkret_identifiers::DeviceId::new(sender_device.to_owned()).unwrap(),
        ),
        authority_commit_id: arkret_wire::RealmCommitId::from_digest([0xa; 32]),
        signal_class: arkret_wire::SignalClass::Session,
        sent_at,
        expires_at: sent_at + chrono::Duration::seconds(ttl_seconds),
        encrypted_payload: arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: arkret_wire::SignalKeyRef {
                group_state_ref: "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
        },
        proof: arkret_wire::SignalProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{ROSTER_ACTOR_DID}#{sender_device}"
            ))
            .unwrap(),
            envelope_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    envelope
}

fn signal_record(
    envelope: arkret_wire::SignalEnvelope,
    position: u64,
) -> soland_storage::SignalRelayRecord {
    soland_storage::SignalRelayRecord {
        realm_id: envelope.realm_id.as_str().to_owned(),
        scope_ref: envelope.scope_ref.clone(),
        sender_actor_id: envelope.sender_actor_id.to_string(),
        sender_device_id: envelope.sender_device_id.as_ref().map(ToString::to_string),
        signal_class: envelope.signal_class,
        envelope_digest: envelope.envelope_digest().unwrap().as_str().to_owned(),
        sent_at: envelope.sent_at,
        expires_at: envelope.expires_at,
        envelope,
        position,
    }
}

/// Restates `presence_aggregation_all_expired_projects_offline`: the rail TTL is
/// the whole lifetime rule now. A `session`-class Signal — the class that
/// carries presence — is capped at 30 seconds (`signal.md` section 2), so there
/// is no long-lived server-side presence state that could need an
/// "all expired means offline" projection in the first place.
#[test]
fn session_class_signal_ttl_is_capped_at_the_rail_ceiling() {
    let sent_at = now();
    signal_envelope(
        ROSTER_REALM,
        ROSTER_ACTOR,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        sent_at,
        30,
    )
    .validate_structural()
    .expect("a 30s session Signal sits exactly on the class ceiling");
    assert!(
        signal_envelope(
            ROSTER_REALM,
            ROSTER_ACTOR,
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
            sent_at,
            31,
        )
        .validate_structural()
        .is_err(),
        "a session Signal past the 30s ceiling must fail closed"
    );
}

/// Restates `presence_aggregation_prefers_dnd_then_online_then_idle`: two
/// devices of the same principal no longer collapse into one aggregated status.
/// The server keeps each device Signal separate, and the only cross-device rule
/// left is that a sending device is excluded from its own fanout, so two
/// devices produce two independent relay records.
#[tokio::test]
async fn signals_from_two_devices_of_one_principal_stay_independent() {
    let state = test_state();
    let sent_at = now();
    for (device, position) in [
        ("ak:device:01904100-0000-7000-8000-a11ce0000001", 1),
        ("ak:device:01904100-0000-7000-8000-a11ce0000002", 2),
    ] {
        state
            .deliveries()
            .append_signal(signal_record(
                signal_envelope(ROSTER_REALM, ROSTER_ACTOR, device, sent_at, 30),
                position,
            ))
            .await
            .expect("signal relayed");
    }

    let records = state
        .deliveries()
        .signals_for_realm(ROSTER_REALM)
        .await
        .expect("relay readable");
    let devices = records
        .iter()
        .map(|record| record.sender_device_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        devices.len(),
        2,
        "each sending device keeps its own relay record: {devices:?}"
    );
}

/// Restates `typing_state_is_emitted_once_per_cursor_revision` and
/// `incremental_sync_includes_presence_only_for_presence_delta`: deliver-once is
/// now a per-subscriber-device watermark over the monotonic relay `position`,
/// not a per-cursor-revision re-emit of a live projection row. A resumed
/// subscriber at the highest delivered position sees nothing new.
#[tokio::test]
async fn signal_delivery_is_once_per_subscriber_device_watermark() {
    let state = test_state();
    let subscriber = "ak:did_core:web:bob.example";
    let subscriber_device = "ak:device:01904100-0000-7000-8000-b0b0b0000001";
    let sent_at = now();
    state
        .deliveries()
        .append_signal(signal_record(
            signal_envelope(
                ROSTER_REALM,
                ROSTER_ACTOR,
                "ak:device:01904100-0000-7000-8000-a11ce0000001",
                sent_at,
                30,
            ),
            1,
        ))
        .await
        .expect("signal relayed");

    assert_eq!(
        state
            .deliveries()
            .signal_watermark(subscriber, subscriber_device, ROSTER_REALM)
            .await
            .expect("watermark readable"),
        0,
        "a device that has never subscribed starts behind every record"
    );
    state
        .deliveries()
        .advance_signal_watermark(subscriber, subscriber_device, ROSTER_REALM, 1)
        .await
        .expect("watermark advanced");

    let watermark = state
        .deliveries()
        .signal_watermark(subscriber, subscriber_device, ROSTER_REALM)
        .await
        .expect("watermark readable");
    assert_eq!(watermark, 1);
    let undelivered = state
        .deliveries()
        .signals_for_realm(ROSTER_REALM)
        .await
        .expect("relay readable")
        .into_iter()
        .filter(|record| record.position > watermark)
        .count();
    assert_eq!(
        undelivered, 0,
        "a resumed subscriber at the highest delivered position sees nothing new"
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
        notary_signing_key_seed: Some([9u8; 32]),
        seed_demo_data: true,
        ..crate::config::AppConfig::test_default()
    }
}

pub(crate) fn test_state() -> AppState {
    AppState::new(test_config(), soland_storage_postgres::Db { pool: None })
}

pub(crate) const ROSTER_REALM: &str = "ak:realm:AQKdkfI-I4MXIS2hxLXbb_FK57j-jE497FF66I5NPGPE";
const ROSTER_ACTOR_DID: &str = "did:web:alice.example";
pub(crate) const ROSTER_ACTOR: &str = "ak:did_core:web:alice.example";
const ROSTER_SUBJECT: &str = "ak:did_core:web:alice-principal.example";
pub(crate) const ROSTER_CALLER: &str = "ak:did_core:web:bob.example";

fn roster_body(_audience: &str) -> SyncRequestBody {
    SyncRequestBody::default()
}

pub(crate) fn roster_session(state: &AppState, actor: &str) -> SessionIdentityState {
    SessionIdentityState {
        account_pk: None,
        token_hash: "token".to_owned(),
        actor: actor.to_owned(),
        device_id: "device-1".to_owned(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now() + chrono::Duration::hours(1),
        created_at: now(),
        revoked_at: None,
    }
}

pub(crate) fn roster_realm(
    public: bool,
    include_caller: bool,
) -> crate::state::RealmDirectoryEntry {
    let mut entry = crate::state::RealmDirectoryEntry::new(
        RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        "Roster evidence",
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.public = public;
    entry
        .members
        .insert(arkret_identifiers::DidCoreId::new(ROSTER_ACTOR.to_owned()).unwrap());
    if include_caller {
        entry
            .members
            .insert(arkret_identifiers::DidCoreId::new(ROSTER_CALLER.to_owned()).unwrap());
    }
    entry
}

fn insert_projected_membership(state: &AppState, actor: &str, membership: &str) {
    insert_projected_membership_at(state, actor, membership, now());
}

pub(crate) fn insert_projected_membership_at(
    state: &AppState,
    actor: &str,
    membership: &str,
    updated_at: DateTime<Utc>,
) {
    state.test_projection().lock().members.insert(
        (ROSTER_REALM.to_owned(), roster_actor(actor).to_string()),
        soland_domain::reducer::SolandMembershipState {
            member: roster_actor(actor).to_string(),
            realm_id: ROSTER_REALM.to_owned(),
            state: membership.to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: (membership == "invite").then_some(updated_at),
            joined_at: updated_at,
            updated_at,
            reason: None,
        },
    );
}

#[tokio::test]
async fn projection_visibility_uses_received_at_for_joined_history_cutoff() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    state.realm_directory().upsert(roster_realm(false, true));
    let session = roster_session(&state, ROSTER_CALLER);
    let created_at = DateTime::parse_from_rfc3339("2026-06-24T10:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let pre_join_received_at = created_at + chrono::Duration::milliseconds(100);
    let joined_at = created_at + chrono::Duration::milliseconds(200);
    let post_join_received_at = created_at + chrono::Duration::milliseconds(300);

    state
        .realms()
        .store_realm_metadata(
            ROSTER_REALM,
            soland_services::events::RealmMetadata {
                owner: ROSTER_ACTOR.to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_access: "since_join".to_owned(),
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
    insert_projected_membership_at(&state, ROSTER_CALLER, "join", joined_at);

    let event_at = |event_id: &str, received_at| ProjectedEvent {
        event_id: event_id.to_owned(),
        realm_id: ROSTER_REALM.to_owned(),
        event_kind: arkret_wire::EventKind::MlsCommit,
        operation_kind: "event".to_owned(),
        operation_id: Some(event_id.replace("ak:event:", "ak:operation:")),
        sender: Some(ROSTER_ACTOR.to_owned()),
        payload: json!({
            "realm_id": ROSTER_REALM,
            "mls_group_id": "mls-group-01904100-0000-7000-8000-0000000000e1"
        }),
        created_at,
        received_at,
    };
    let pre_join_event = event_at(
        "ak:event:AWLjsk0JkbLdfBfaY2GoxT61q1Ttw6HFu7sU-XGFywHc",
        pre_join_received_at,
    );
    let post_join_event = event_at(
        "ak:event:AS3cyhr0pju5AnMYHRcgMbHHU45oa25NELQwXBDt8smD",
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

/// `account_filter`: an absent `realm_ids` selects no Realm detail, and a
/// selected Realm the caller cannot read is `unavailable.error_code=not_found`
/// whether it is public or was left.
#[tokio::test]
async fn sync_snapshot_excludes_public_realms_without_exact_account_membership() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    state.realm_directory().upsert(roster_realm(true, false));
    insert_projected_membership(&state, ROSTER_ACTOR, "join");
    let detail = |frame| {
        serde_json::to_value(frame).unwrap()["realms"]
            .get(ROSTER_REALM)
            .cloned()
    };

    let unselected = build_sync_snapshot(
        &state,
        Some(&session),
        &roster_body(state.service_id()),
        &SyncCursor::default(),
    )
    .await;
    assert!(detail(unselected).is_none());

    let selected: SyncRequestBody =
        serde_json::from_value(json!({"filter": {"realm_ids": [ROSTER_REALM]}})).unwrap();
    let not_found = json!({"unavailable": {"error_code": "not_found"}});
    let outsider =
        build_sync_snapshot(&state, Some(&session), &selected, &SyncCursor::default()).await;
    assert_eq!(
        detail(outsider),
        Some(not_found.clone()),
        "a public Realm is not readable without exact account membership"
    );
    assert!(!realm_id_accessible(&state, ROSTER_REALM, Some(&session)).await);

    insert_projected_membership(&state, ROSTER_CALLER, "join");
    assert!(realm_id_accessible(&state, ROSTER_REALM, Some(&session)).await);

    insert_projected_membership(&state, ROSTER_CALLER, "leave");
    assert!(!realm_id_accessible(&state, ROSTER_REALM, Some(&session)).await);
    let left = build_sync_snapshot(&state, Some(&session), &selected, &SyncCursor::default()).await;
    assert_eq!(detail(left), Some(not_found));
}

/// One Realm-scope Event by `author` carrying a structural producer proof;
/// the device-list fixtures exercise storage and sync, not signatures.
fn realm_fixture_event(
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    author: &arkret_wire::AccountId,
    payload: serde_json::Value,
    at: DateTime<Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope_ref,
        arkret_wire::ActorId::account(author.clone()),
        payload,
        at,
    )
    .unwrap();
    let principal = author.principal_id.as_str();
    crate::test_event::attach_structural_only_producer_proof(
        &mut event,
        arkret_wire::DidUrl::new(format!(
            "did:{}#key",
            principal.strip_prefix("ak:did_core:").unwrap()
        ))
        .unwrap(),
    );
    event
}

/// An ordinary Realm on this Station, admitted through the bootstrap unit
/// and extended through the Event unit of work, as production commits it.
struct CommittedRealm {
    head: soland_storage::AuthorityCommitTransaction,
}

impl CommittedRealm {
    fn transaction(
        authority: &soland_storage::CurrentRealmAuthority,
        method: &arkret_wire::DidUrl,
        event: arkret_wire::Event,
        previous: Option<&arkret_wire::RealmCommit>,
    ) -> soland_storage::AuthorityCommitTransaction {
        let at = event.created_at;
        let realm_id = authority.realm_id.clone();
        let position = previous.map_or(0, |commit| commit.stream_position + 1);
        soland_storage::AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            commit: arkret_wire::RealmCommit {
                commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    format!("{}:{position}", event.event_id).as_bytes(),
                )),
                realm_id: realm_id.clone(),
                stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id },
                stream_position: position,
                previous_commit_ref: previous.map(|commit| commit.commit_id.clone()),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: authority.authority_ref.clone(),
                committed_at: at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: method.clone(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: at,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
                },
            },
            event,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        }
    }

    async fn bootstrap(
        store: &dyn soland_storage::PersistenceStore,
        founder: &arkret_wire::AccountId,
        method: arkret_wire::DidUrl,
    ) -> Self {
        use arkret_models_collaboration::authority_commit::{
            OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
            SelfAuthoritySubmitRequest,
        };
        use base64::Engine as _;

        let at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let genesis = realm_fixture_event(
            arkret_wire::EventKind::RealmCreate,
            arkret_wire::ScopeRef::RealmGenesis,
            founder,
            json!({"object":{
                "schema":"ak.schema.realm_genesis.v1",
                "purpose":"collaboration",
                "genesis_salt":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                    arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes())),
                "trust_domain":"ak:trust_domain:device-lists.example",
                "security_class":"high_assurance",
                "governance_station_id":founder.station_id,
                "initial_join_rule":"public",
                "initial_history_access":"since_join",
                "initial_discoverability":"invite_only"
            }}),
            at,
        );
        let realm_id = genesis.realm_id.clone();
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let mut events = vec![genesis];
        for (kind, payload) in [
            (
                arkret_wire::EventKind::RealmProfile,
                json!({"schema":"ak.schema.realm_profile.v1","title":"Device lists"}),
            ),
            (
                arkret_wire::EventKind::RealmPolicyBundle,
                json!({"policy_revision":1,"federation_policy":"closed"}),
            ),
            (
                arkret_wire::EventKind::RealmJoinRule,
                json!({"value":"public"}),
            ),
            (
                arkret_wire::EventKind::RealmHistoryAccess,
                json!({"from":null,"to":"since_join"}),
            ),
            (
                arkret_wire::EventKind::RealmDiscovery,
                json!({"value":{"discoverability":"invite_only"}}),
            ),
            (
                arkret_wire::EventKind::MemberState,
                json!({"member_id":arkret_wire::ActorId::account(founder.clone()),"membership":"join"}),
            ),
        ] {
            events.push(realm_fixture_event(
                kind,
                scope.clone(),
                founder,
                payload,
                at,
            ));
        }
        let authority = soland_storage::CurrentRealmAuthority {
            realm_id,
            generation: 0,
            service_id: founder.station_id.clone(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                events[0].event_id.clone(),
            ),
            last_handoff_ref: None,
        };
        let mut transactions: Vec<soland_storage::AuthorityCommitTransaction> = Vec::new();
        for event in &events {
            let previous = transactions.last().map(|transaction| &transaction.commit);
            let transaction = Self::transaction(&authority, &method, event.clone(), previous);
            transactions.push(transaction);
        }
        let submission = OrdinaryRealmBootstrapUnitSubmission {
            unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
            idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
            events: events
                .into_iter()
                .map(arkret_wire::EventAdmissionSubmission::new)
                .collect(),
        };
        let unit = soland_storage::OrdinaryRealmBootstrapCommitUnit {
            exact_request_body: serde_json::to_vec(
                &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone()),
            )
            .unwrap(),
            submission,
            transactions,
        };
        store
            .authority_commits()
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .expect("ordinary Realm bootstrap admitted");
        Self {
            head: unit.transactions.last().unwrap().clone(),
        }
    }

    /// Commit `author`'s `ak.member.state` for `member` at the Realm head.
    async fn member_state(
        &mut self,
        store: &dyn soland_storage::PersistenceStore,
        author: &arkret_wire::AccountId,
        member: &arkret_wire::AccountId,
        membership: &str,
    ) {
        let event = realm_fixture_event(
            arkret_wire::EventKind::MemberState,
            arkret_wire::ScopeRef::Realm {
                realm_id: self.head.event.realm_id.clone(),
            },
            author,
            json!({"member_id":arkret_wire::ActorId::account(member.clone()),"membership":membership}),
            self.head.commit.committed_at,
        );
        let method = self.head.commit.signature.verification_method.clone();
        let transaction = Self::transaction(
            &self.head.expected_authority,
            &method,
            event.clone(),
            Some(&self.head.commit),
        );
        let record = soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(&event).unwrap(),
            received_at: event.created_at,
        };
        store
            .commit_event(soland_storage::EventCommitRequest {
                authority_commit: transaction.clone(),
                self_producer_guard: None,
                forwarded_producer_evidence: None,
                event: record,
                parent_membership_admission: None,
                contact_projection: None,
                agent_draft_pending_intent: None,
                consent_projection: None,
                device_revocation_transition: None,
                device_revocation_gate: None,
                projections: Vec::new(),
                idempotency: None,
                outbox: Vec::new(),
                realm_fanout_source: None,
            })
            .await
            .expect("member state committed");
        self.head = transaction;
    }
}

/// Device-list interest is derived from the account summary the authority
/// transaction writes: both principals are admitted through their PCR
/// genesis, share a committed ordinary Realm, and a committed leave removes
/// the peer from the tracked set.
#[tokio::test]
async fn sync_snapshot_emits_device_list_baseline_changes_and_left_principals() {
    use soland_test_support::pcr_genesis::PcrGenesisFixture;

    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let store = state.test_persistence();
    let caller_genesis = PcrGenesisFixture::new(state.service_did());
    caller_genesis
        .admit_into(store.as_ref())
        .await
        .expect("caller PCR genesis admitted");
    let actor_genesis = PcrGenesisFixture::new(state.service_did());
    actor_genesis
        .admit_into(store.as_ref())
        .await
        .expect("actor PCR genesis admitted");
    let caller = caller_genesis.history.account.clone();
    let actor = actor_genesis.history.account.clone();
    let session = roster_session(&state, caller.principal_id.as_str());

    let mut realm = CommittedRealm::bootstrap(
        store.as_ref(),
        &caller,
        state.service_verification_method("notary-key").unwrap(),
    )
    .await;
    // The public Realm admits the peer by its own join.
    realm
        .member_state(store.as_ref(), &actor, &actor, "join")
        .await;

    let body = roster_body(state.service_id());
    let initial = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
    let mut shared = vec![
        arkret_wire::ActorId::account(actor.clone()),
        arkret_wire::ActorId::account(caller.clone()),
    ];
    shared.sort_by_key(|actor| actor.canonical_key().unwrap());
    assert_eq!(
        serde_json::to_value(&initial.device_lists).unwrap(),
        json!({"changed_ids": shared, "left_ids": []})
    );
    let filter_value = sync_filter_value(body.filter.as_ref());
    let initial_cursor = parse_and_validate_sync_cursor(
        initial.cursor.as_deref().unwrap(),
        &state,
        Some(&session),
        filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("initial cursor parses");

    realm
        .member_state(store.as_ref(), &caller, &caller, "leave")
        .await;
    let mut incremental_body = body.clone();
    incremental_body.after = initial.cursor.clone();
    let after_scope_loss =
        build_sync_snapshot(&state, Some(&session), &incremental_body, &initial_cursor).await;
    assert_eq!(
        serde_json::to_value(&after_scope_loss.device_lists).unwrap(),
        json!({"changed_ids": [], "left_ids": [arkret_wire::ActorId::account(actor)]}),
        "principals no longer visible through any Realm leave the tracked device list set"
    );
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
    assert!(auth_material_present(None, Some("Signature=z")));
    assert!(auth_material_present(None, Some("sign%61ture=z")));
    assert!(!auth_material_present(None, Some("tokenized=true")));

    // A non-bearer Authorization scheme is not bearer material on its own.
    assert!(!auth_material_present(Some("Basic dXNlcjpwYXNz"), None));
}

fn assert_invalid_or_integrity_error(error: SyncCursorError) {
    match error {
        SyncCursorError::Invalid(_) | SyncCursorError::Integrity(_) => {}
        other => panic!("expected cursor structure/integrity error, got {other:?}"),
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
        "t": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "x": now_ms + 60_000,
        "issuer_kid": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#notary-key",
        "positions": {
            "realms": {},
            "devices": {},
            "to_device": 0
        }
    }));

    let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect_err("inline cursor body must be rejected");

    assert_invalid_or_integrity_error(error);
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
            "t": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            "x": now_ms + 60_000,
            "h": handle.clone(),
        });
        insert_cursor_field(&mut stream_cursor, field, json!("client-supplied"));
        let token = encode_sync_cursor_value(stream_cursor);
        let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
            .await
            .expect_err("inline filter digest pseudo-field must be rejected");
        assert_invalid_or_integrity_error(error);

        let mut events_cursor = json!({
            "v": "1",
            "purpose": STREAM_CURSOR_PURPOSE,
            "t": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            "x": now_ms + 60_000,
            "h": handle.clone(),
        });
        insert_cursor_field(&mut events_cursor, field, json!("client-supplied"));
        let token = encode_sync_cursor_value(events_cursor);
        let error =
            parse_and_validate_events_query_cursor(&token, &state, None, "digest-a", now_ms)
                .await
                .expect_err("events query inline filter digest pseudo-field must be rejected");
        assert_invalid_or_integrity_error(error);
    }
}

#[tokio::test]
async fn events_query_cursor_rejects_bare_event_id_cursor() {
    let state = test_state();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let error = parse_and_validate_events_query_cursor(
        "ak:event:AWLjsk0JkbLdfBfaY2GoxT61q1Ttw6HFu7sU-XGFywHc",
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
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let filter_a = sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.committed_event.read.scan.v1",
        "realms": [ROSTER_REALM],
        "actors": [],
        "filters": {},
        "order": "default",
    })));
    let filter_b = sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.committed_event.read.scan.v1",
        "realms": [ROSTER_REALM],
        "actors": [],
        "filters": {"kind": "ak.message.create"},
        "order": "default",
    })));
    let event_id = "ak:event:AWLjsk0JkbLdfBfaY2GoxT61q1Ttw6HFu7sU-XGFywHc";
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
        .sync()
        .cursor(handle)
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
fn account_filter_digest_retains_explicit_empty_and_false() {
    let absent = cursor::account_filter_digest(None);
    assert_eq!(absent, cursor::account_filter_digest(Some(&json!({}))));
    assert_ne!(
        absent,
        cursor::account_filter_digest(Some(&json!({"realm_ids": []})))
    );
    assert_ne!(
        absent,
        cursor::account_filter_digest(Some(&json!({"lazy_load_members": false})))
    );
}

#[test]
fn sync_filter_digest_normalizes_events_query_scope_collections() {
    let scope_a = json!({
        "operation_id": "ak.self.committed_event.read.scan.v1",
        "realms": ["ak:realm:b", "ak:realm:a", "ak:realm:a"],
        "actors": ["did:web:bob.example", "did:web:alice.example"],
        "filters": {
            "kind": ["ak.reaction.add", "ak.message.create", "ak.message.create"],
            "not_event_kinds": ["ak.redaction", "ak.audit.accessed"]
        },
        "order": "default"
    });
    let scope_b = json!({
        "operation_id": "ak.self.committed_event.read.scan.v1",
        "realms": ["ak:realm:a", "ak:realm:b"],
        "actors": ["did:web:alice.example", "did:web:bob.example"],
        "filters": {
            "kind": ["ak.message.create", "ak.reaction.add"],
            "not_event_kinds": ["ak.audit.accessed", "ak.redaction"]
        },
        "order": "default"
    });
    assert_eq!(
        sync_filter_digest(Some(&scope_a)),
        sync_filter_digest(Some(&scope_b))
    );

    let different_order = json!({
        "operation_id": "ak.self.committed_event.read.scan.v1",
        "realms": ["ak:realm:a", "ak:realm:b"],
        "actors": ["did:web:alice.example", "did:web:bob.example"],
        "filters": {
            "kind": ["ak.message.create", "ak.reaction.add"],
            "not_event_kinds": ["ak.audit.accessed", "ak.redaction"]
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
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let positions = BTreeMap::from([("ak:realm:dedup-test".to_owned(), 7i64)]);
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
    // resolves (rows coexist until expiry).
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
async fn account_cursor_roundtrips_station_cas_replay_position() {
    let state = test_state();
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let token = sync_token_for_account_positions(
        &state,
        Some(&session),
        None,
        BTreeMap::new(),
        BTreeMap::new(),
        0,
        0,
        41,
        None,
        BTreeMap::new(),
        false,
        None,
    )
    .await
    .expect("account cursor mints");

    let parsed = parse_and_validate_sync_cursor(
        &token,
        &state,
        Some(&session),
        None,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("account cursor parses");
    assert_eq!(parsed.account_data_change_position, 41);
}

/// 0441: an Account stream cursor, and so every window position it
/// carries, is bound to the Account and filter that minted it; neither
/// another Account nor a changed filter can resume from it.
#[tokio::test]
async fn account_cursor_is_bound_to_its_account_and_filter() {
    let state = test_state();
    let alice = roster_session(&state, "ak:did_core:web:alice.example");
    let bob = roster_session(&state, "ak:did_core:web:bob.example");
    let filter_a = json!({"realm_ids": [ROSTER_REALM]});
    let filter_b = json!({"realm_ids": [ROSTER_REALM], "window_limit": 5});
    let token = sync_token_for_account_positions(
        &state,
        Some(&alice),
        Some(&filter_a),
        BTreeMap::new(),
        BTreeMap::new(),
        0,
        0,
        0,
        None,
        BTreeMap::new(),
        false,
        None,
    )
    .await
    .expect("account cursor mints");
    let now_ms = chrono::Utc::now().timestamp_millis();
    parse_and_validate_sync_cursor(&token, &state, Some(&alice), Some(&filter_a), now_ms)
        .await
        .expect("the minting Account and filter resume");
    for (session, filter) in [(&bob, &filter_a), (&alice, &filter_b)] {
        let error =
            parse_and_validate_sync_cursor(&token, &state, Some(session), Some(filter), now_ms)
                .await
                .expect_err("another Account or filter must not reuse the cursor");
        assert!(matches!(error, SyncCursorError::Mismatch(_)), "{error:?}");
    }
}

#[tokio::test]
async fn presenting_a_newer_cursor_preserves_older_retry_authority() {
    let state = test_state();
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let positions = BTreeMap::from([("ak:realm:prune-test".to_owned(), 1i64)]);
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
    assert_eq!(presented.to_device_position, 2);
    let old = parse_and_validate_sync_cursor(&old_token, &state, Some(&session), None, now_ms)
        .await
        .expect("an older immutable cursor remains resumable until its expiry");
    assert_eq!(old.to_device_position, 1);
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
        5,
    )
    .await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect("freshly issued cursor validates");

    state
        .sync()
        .cache_cursor_revocation(soland_services::sync::CursorRevocationState {
            cursor_digest: sha256_hex(token.as_bytes()),
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                state.service_core_id(),
            ),
            device_id: None,
            scope: "this_cursor".to_owned(),
            reason_code: "compromised".to_owned(),
            revoked_at: now(),
            expires_at: now() + chrono::Duration::seconds(CURSOR_MAX_TTL_SECONDS),
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
        0,
    )
    .await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    state
        .sync()
        .cache_cursor_revocation(soland_services::sync::CursorRevocationState {
            cursor_digest: sha256_hex(token.as_bytes()),
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                state.service_core_id(),
            ),
            device_id: None,
            scope: "this_cursor".to_owned(),
            reason_code: "stale".to_owned(),
            revoked_at: now() - chrono::Duration::seconds(2 * CURSOR_MAX_TTL_SECONDS),
            expires_at: now() - chrono::Duration::seconds(CURSOR_MAX_TTL_SECONDS),
        });

    parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
        .await
        .expect("expired revocation entry must be pruned, not block a valid cursor");
    assert!(
        state.sync().cached_cursor_revocation_count() == 0,
        "expired revocation entry should have been pruned"
    );
}

/// A selected Realm this Account cannot read is an explicit `unavailable`
/// detail with a resumable cursor, never a synthetic window or a resync.
#[tokio::test]
async fn selected_unreadable_realm_is_an_explicit_unavailable_detail() {
    let state = test_state();
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let realm = "ak:realm:AQVZRUJrSSC16EodjmqL6mBFC9TGwv6oxx-sQlJzlvxS";
    let body: SyncRequestBody =
        serde_json::from_value(json!({"filter": {"realm_ids": [realm], "window_limit": 2}}))
            .unwrap();
    let frame = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
    assert_eq!(
        frame.kind,
        arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta
    );
    frame.validate().unwrap();
    assert!(frame.cursor.is_some());
    assert_eq!(
        serde_json::to_value(&frame.realms.unwrap().entries[realm]).unwrap(),
        json!({"unavailable": {"error_code": "not_found"}})
    );
}

#[tokio::test]
async fn account_and_device_queue_cursors_reject_cross_operation_resume() {
    let state = test_state();
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let now = chrono::Utc::now().timestamp_millis();
    let account = sync_token_for_client_sync(
        &state,
        Some(&session),
        None,
        BTreeMap::new(),
        BTreeMap::new(),
        7,
    )
    .await;
    let queue = device_messages_cursor(&state, &session, 7).await.unwrap();
    assert_ne!(account, queue);
    assert!(
        parse_account_cursor(&queue, &state, Some(&session), None, now, false)
            .await
            .is_err()
    );
    assert!(
        parse_account_cursor(&queue, &state, Some(&session), Some(&json!({})), now, true)
            .await
            .is_err()
    );
    assert!(
        parse_device_messages_cursor(&account, &state, &session, now)
            .await
            .is_err()
    );
    assert_eq!(
        parse_device_messages_cursor(&queue, &state, &session, now)
            .await
            .unwrap(),
        7
    );
    parse_account_cursor(&account, &state, Some(&session), None, now, false)
        .await
        .unwrap();
    let other = roster_session(&state, "ak:did_core:web:bob.example");
    assert!(
        parse_device_messages_cursor(&queue, &state, &other, now)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn realm_list_snapshot_identity_is_stable_and_never_renews_its_deadline() {
    let state = test_state();
    let session = roster_session(&state, "ak:did_core:web:alice.example");
    let (watermark, global_watermark) = state.sync().account_sync_watermarks().await.unwrap();
    let mut position = RealmListPosition {
        watermark,
        global_watermark,
        expires_at_ms: chrono::Utc::now().timestamp_millis() + 3_600_000,
        after: None,
    };
    let first = realm_list_token(&state, &session, &position).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let repeated = realm_list_token(&state, &session, &position).await.unwrap();
    assert_eq!(
        first, repeated,
        "later pages must retain the same snapshot identity"
    );
    let parsed = parse_realm_list_cursor(&state, &session, first.as_str())
        .await
        .unwrap();
    assert_eq!(parsed.expires_at_ms, position.expires_at_ms);
    position.expires_at_ms = chrono::Utc::now().timestamp_millis() - 1;
    assert!(matches!(
        realm_list_token(&state, &session, &position).await,
        Err(SyncCursorError::Expired)
    ));
}
