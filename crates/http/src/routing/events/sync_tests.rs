use super::*;

fn ordered_log_message(actor_seq: u64, hlc: &str, body: &str) -> arkret_wire::Event {
    let mut event = crate::test_event::raw_event(
        arkret_wire::EventKind::MessageCreate.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        actor_seq,
        arkret_identifiers::Hlc::new(hlc).unwrap(),
        json!({
            "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
            "body": body,
        }),
    )
    .unwrap();
    let event_digest = arkret_wire::Hash::new(event.event_digest().unwrap()).unwrap();
    event.proofs = vec![arkret_wire::EventProof::Producer(arkret_wire::Proof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(
            "did:webvh:z6mkfixture:alice.example#ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .unwrap(),
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..c2ln".to_owned(),
    })];
    event
}

#[test]
fn timeline_ordered_log_equivocation_is_deterministic_visible_and_non_destructive() {
    let left = ordered_log_message(7, "019041000000-0000-aabbcc01", "left");
    let right = ordered_log_message(7, "019041000001-0000-aabbcc01", "right");
    let normal = ordered_log_message(8, "019041000002-0000-aabbcc01", "normal");
    let left_digest = left.event_digest().unwrap();
    let right_digest = right.event_digest().unwrap();
    let right_wins = matches!(
        arkret_state::lattice::ordered_log::compare_canonical_digests(&right_digest, &left_digest,),
        Some(std::cmp::Ordering::Greater)
    );
    let expected_winner = if right_wins {
        right.event_id.clone()
    } else {
        left.event_id.clone()
    };
    let expected_loser = if right_wins {
        left.event_id.clone()
    } else {
        right.event_id.clone()
    };

    let (visible, conflicts) = collapse_message_ordered_log_equivocations(vec![
        (10, left),
        (11, right),
        (12, normal.clone()),
    ]);

    assert_eq!(visible.len(), 2, "one equivocation loser must be omitted");
    assert!(
        visible
            .iter()
            .any(|(_, event)| event.event_id == expected_winner)
    );
    assert!(
        visible
            .iter()
            .any(|(_, event)| event.event_id == normal.event_id)
    );
    assert!(
        !visible
            .iter()
            .any(|(_, event)| event.event_id == expected_loser)
    );
    assert_eq!(conflicts.len(), 1, "equivocation must be user-visible");
    let diagnostic = &conflicts[0];
    assert_eq!(diagnostic.reason, "issuer_equivocation");
    assert_eq!(diagnostic.issuer_seq, 7);
    assert_eq!(diagnostic.winner_event_id, expected_winner);
    assert_eq!(diagnostic.loser_event_ids, vec![expected_loser]);
}

fn stream_cursor_handle_binding(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    filter_digest: &str,
    realms_positions: &BTreeMap<String, i64>,
    account_realms_positions: &BTreeMap<String, i64>,
    device_list_positions: &BTreeMap<String, i64>,
    to_device_position: i64,
) -> Vec<u8> {
    stream_cursor_handle_binding_with_notification_position(
        principal_id,
        device_id,
        service_id,
        filter_digest,
        realms_positions,
        account_realms_positions,
        device_list_positions,
        to_device_position,
        0,
    )
}

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
        h1.len() >= arkret_hlc::CURSOR_HANDLE_MIN_LEN,
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
fn initial_security_baseline_is_limited_to_current_create_and_policy_facets() {
    assert!(required_security_baseline_kind(
        &arkret_wire::EventKind::RealmCreate
    ));
    assert!(required_security_baseline_kind(
        &arkret_wire::EventKind::RealmPolicyBundle
    ));
    assert!(!required_security_baseline_kind(
        &arkret_wire::EventKind::MessageCreate
    ));
    assert!(!required_security_baseline_kind(
        &arkret_wire::EventKind::RealmHistoryVisibility
    ));
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
    let created_at = DateTime::parse_from_rfc3339("2026-05-22T16:18:24.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let realm_create = timestamp_position_with_tie_breaker(
        created_at,
        "ak:event:AdSEMuROttK4LOqkM58-n9-IoPYt49AdbtfNotnepAVd",
    );
    let welcome_message = timestamp_position_with_tie_breaker(
        created_at,
        "ak:event:AaoIV7frfdMcyZ_DS4-v9rSL4m-ejw11XJ0Vwo5M1f1E",
    );

    assert_ne!(realm_create, welcome_message);
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
        sender_actor_id: arkret_identifiers::DidCoreId::new(sender_actor.to_owned()).unwrap(),
        sender_device_id: arkret_identifiers::DeviceId::new(sender_device.to_owned()).unwrap(),
        seal_ref: arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
            .unwrap(),
        signal_class: arkret_wire::SignalClass::Session,
        sent_at,
        expires_at: sent_at + ChronoDuration::seconds(ttl_seconds),
        encrypted_payload: arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: arkret_wire::SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            aad_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
        },
        proof: arkret_wire::SignalProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{ROSTER_ACTOR_FULL}#{sender_device}"
            ))
            .unwrap(),
            envelope_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: sent_at,
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    envelope
}

fn signal_record(
    envelope: arkret_wire::SignalEnvelope,
    position: u64,
) -> soland_services::delivery::SignalRelayState {
    soland_services::delivery::SignalRelayState {
        realm_id: envelope.realm_id.as_str().to_owned(),
        scope_ref: envelope.scope_ref.clone(),
        sender_actor_id: envelope.sender_actor_id.as_str().to_owned(),
        sender_device_id: envelope.sender_device_id.as_str().to_owned(),
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
        jws_replay_window_per_family: BTreeMap::new(),
        notary_signing_key_seed: Some([9u8; 32]),
        seed_demo_data: true,
        ..crate::config::AppConfig::test_default()
    }
}

fn test_state() -> AppState {
    AppState::new(test_config(), soland_storage_postgres::Db { pool: None })
}

const ROSTER_REALM: &str = "ak:realm:AQKdkfI-I4MXIS2hxLXbb_FK57j-jE497FF66I5NPGPE";
const ROSTER_ACTOR_FULL: &str = "did:web:alice.example";
const ROSTER_ACTOR: &str = "ak:did_core:web:alice.example";
const ROSTER_SUBJECT: &str = "ak:did_core:web:alice-principal.example";
const ROSTER_CALLER: &str = "ak:did_core:web:bob.example";

fn roster_body(audience: &str) -> SyncRequestBody {
    let mut extra = BTreeMap::new();
    extra.insert("audience".to_owned(), json!(audience));
    SyncRequestBody {
        after: None,
        catchup: None,
        filter: Some(
            arkret_models_collaboration::sync_frames::client_sync::SyncFilter {
                realms: Vec::new(),
                timeline_limit: None,
                lazy_load_members: false,
                include_redundant_members: false,
                event_types: Vec::new(),
                not_event_types: Vec::new(),
                extra,
            },
        ),
        subscriptions: None,
    }
}

fn roster_session(state: &AppState, actor: &str) -> SessionRecord {
    SessionRecord {
        token_hash: "token".to_owned(),
        actor: actor.to_owned(),
        device_id: "device-1".to_owned(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now() + ChronoDuration::hours(1),
        created_at: now(),
        revoked_at: None,
    }
}

fn sync_test_operation_at(
    operation_id: &str,
    kind: impl AsRef<str>,
    mut payload: Value,
    created_at: DateTime<Utc>,
) -> arkret_event_draft::ProjectedEventOperation {
    payload
        .as_object_mut()
        .expect("sync fixture payload object")
        .entry("sender")
        .or_insert_with(|| Value::String(ROSTER_ACTOR.to_owned()));
    let mut operation = arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(operation_id.to_owned()).unwrap(),
        RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        kind.as_ref(),
        payload,
    );
    operation.created_at = created_at;
    operation
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture preserves the accepted Event envelope coordinates"
)]
fn accepted_sync_test_operation_at(
    operation_id: &str,
    event_id: &str,
    actor: &str,
    actor_seq: u64,
    kind: impl AsRef<str>,
    payload: Value,
    created_at: DateTime<Utc>,
) -> arkret_event_draft::ProjectedEventOperation {
    let mut event = crate::test_event::raw_event_at(
        kind.as_ref(),
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        },
        crate::test_actor_id_str(actor),
        actor_seq,
        arkret_identifiers::Hlc::new(format!("019041000000-{actor_seq:04x}-00000002")).unwrap(),
        payload,
        created_at,
    )
    .expect("accepted sync fixture Event");
    event.event_id = arkret_identifiers::EventId::new(event_id.to_owned()).unwrap();
    arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        arkret_identifiers::OperationId::new(operation_id.to_owned()).unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        &event,
    )
    .expect("accepted sync fixture operation")
}

fn roster_realm(public: bool, include_caller: bool) -> RealmDirectoryEntry {
    let mut entry = RealmDirectoryEntry::new(
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

fn insert_projected_membership_at(
    state: &AppState,
    actor: &str,
    membership: &str,
    updated_at: DateTime<Utc>,
) {
    state.test_projection().lock().members.insert(
        (ROSTER_REALM.to_owned(), actor.to_owned()),
        soland_domain::reducer::SolandMembershipState {
            member: actor.to_owned(),
            realm_id: ROSTER_REALM.to_owned(),
            state: membership.to_owned(),
            role: "member".to_owned(),
            delivery_status: None,
            recipient_service_id: None,
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
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
    let pre_join_received_at = created_at + ChronoDuration::milliseconds(100);
    let joined_at = created_at + ChronoDuration::milliseconds(200);
    let post_join_received_at = created_at + ChronoDuration::milliseconds(300);

    state
        .realms()
        .store_realm_metadata(
            ROSTER_REALM,
            soland_services::events::RealmMetadata {
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
                aad_visibility_ceiling: Default::default(),
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .expect("realm meta stored");
    insert_projected_membership_at(&state, ROSTER_CALLER, "join", joined_at);

    let event_at = |event_id: &str, received_at| ProjectionEventRecord {
        event_id: event_id.to_owned(),
        realm_id: ROSTER_REALM.to_owned(),
        event_kind: arkret_wire::EventKind::MlsCommit,
        operation_kind: "event".to_owned(),
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

#[tokio::test]
async fn native_sidecar_events_are_visible_only_to_the_controller() {
    const SIDECAR_ID: &str = "ak:sidecar:Aa1Yl71lEGMItLkW6kUVdeM4tRXg6z3J69ELu9xrdCXp";
    const SOURCE_STRAND_ID: &str = "ak:strand:AUUqer3HsddAU4x0pWkmcS8uDu88T4fD7QdPhL5IlxKX";
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    state.realm_directory().upsert(roster_realm(false, true));
    insert_projected_membership(&state, ROSTER_ACTOR, "join");
    insert_projected_membership(&state, ROSTER_CALLER, "join");
    let created_at = DateTime::parse_from_rfc3339("2026-07-29T10:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let apply = |operation_id: &str, kind: arkret_wire::EventKind, payload: Value| {
        state.test_projection().lock().apply(
            &sync_test_operation_at(operation_id, kind, payload, created_at),
            state.hlc(),
        );
    };
    apply(
        "ak:operation:01904100-0000-7000-8000-00000000a001",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": ROSTER_REALM,
                "schema": "ak.schema.realm.v1",
                "title": "Sidecar recovery",
                "created_by": ROSTER_ACTOR,
                "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    apply(
        "ak:operation:01904100-0000-7000-8000-00000000a002",
        arkret_wire::EventKind::SidecarCreate,
        json!({
            "encryption_profile": "mls_rfc9420",
            "event_id": "ak:event:Aa1Yl71lEGMItLkW6kUVdeM4tRXg6z3J69ELu9xrdCXp",
            "sender": ROSTER_ACTOR
        }),
    );
    assert!(
        state
            .projections()
            .snapshot()
            .sidecars
            .contains_key(SIDECAR_ID)
    );

    let structural_event =
        |event_id: &str, kind: arkret_wire::EventKind, payload: Value| ProjectionEventRecord {
            event_id: event_id.to_owned(),
            realm_id: ROSTER_REALM.to_owned(),
            event_kind: kind,
            operation_kind: "event".to_owned(),
            operation_id: Some(event_id.replace("ak:event:", "ak:operation:")),
            sender: Some(ROSTER_ACTOR.to_owned()),
            payload,
            created_at,
            received_at: created_at,
        };
    let attach_event = structural_event(
        "ak:event:AVF6xfk5EJU6x8wIqKL3WPOsSROVxJPxOu8HiqfxQGD7",
        arkret_wire::EventKind::SidecarContextAttach,
        json!({
            "sidecar_id": SIDECAR_ID,
            "source_context_ref": {"kind": "strand", "strand_id": SOURCE_STRAND_ID},
            "version": 1
        }),
    );
    let controller = roster_session(&state, ROSTER_ACTOR);
    let ordinary_realm_member = roster_session(&state, ROSTER_CALLER);
    for event in [&attach_event] {
        assert!(
            projection_record_visible_to_session(&state, event, Some(&controller)).await,
            "the controller must recover its own native Sidecar history"
        );
        assert!(
            !projection_record_visible_to_session(&state, event, Some(&ordinary_realm_member))
                .await,
            "ordinary Realm membership must not disclose native Sidecar history"
        );
        assert!(
            !projection_record_visible_to_session(&state, event, None).await,
            "anonymous query must be indistinguishable from a missing private object"
        );
    }
}

fn canonical_event_record_received_at(
    actor_seq: u64,
    kind: impl AsRef<str>,
    payload: Value,
    actor_id: &str,
    created_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) -> soland_services::events::CanonicalEventRecord {
    let kind = kind.as_ref();
    let event = crate::test_event::raw_event_at(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
        },
        arkret_identifiers::DidCoreId::new(actor_id.to_owned()).unwrap(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!("019041000000-{actor_seq:04x}-00000001")).unwrap(),
        payload,
        created_at,
    )
    .expect("canonical sync fixture Event");
    let envelope = serde_json::to_value(&event).unwrap();
    let canonical_bytes = crate::routing::events::event_log::event_canonical_bytes(&envelope)
        .expect("canonical sync fixture digest payload");
    soland_services::events::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: actor_id.to_owned(),
        actor_seq,
        realm_id: Some(ROSTER_REALM.to_owned()),
        kind: kind.to_owned(),
        schema_id: "ak.event.v1".to_owned(),
        canonical_digest: event.event_digest().unwrap(),
        canonical_bytes,
        envelope,
        received_at,
    }
}

async fn store_canonical_event(
    state: &AppState,
    record: soland_services::events::CanonicalEventRecord,
) {
    state
        .event_queries()
        .store_canonical_event(record)
        .await
        .expect("canonical event stored");
}

#[tokio::test]
async fn sync_timeline_visibility_uses_received_at_for_joined_history_cutoff() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    state.realm_directory().upsert(roster_realm(false, true));
    let session = roster_session(&state, ROSTER_CALLER);
    let strand_id = strand_id_from_realm_id(ROSTER_REALM).expect("canonical fixture RealmId");
    let created_at = DateTime::parse_from_rfc3339("2026-06-24T10:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let pre_join_received_at = created_at + ChronoDuration::milliseconds(100);
    let joined_at = created_at + ChronoDuration::milliseconds(200);
    let post_join_received_at = created_at + ChronoDuration::milliseconds(300);

    state
        .realms()
        .store_realm_metadata(
            ROSTER_REALM,
            soland_services::events::RealmMetadata {
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
                aad_visibility_ceiling: Default::default(),
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .expect("realm meta stored");

    insert_projected_membership_at(&state, ROSTER_CALLER, "join", joined_at);

    let pre_join_record = canonical_event_record_received_at(
        1,
        arkret_wire::EventKind::MessageCreate,
        json!({
            "strand_id": strand_id,
            "thread_id": strand_id,
            "content": {"kind": "ak.content.text", "body": "before join"}
        }),
        ROSTER_ACTOR,
        created_at,
        pre_join_received_at,
    );
    let post_join_record = canonical_event_record_received_at(
        2,
        arkret_wire::EventKind::MessageCreate,
        json!({
            "strand_id": strand_id,
            "thread_id": strand_id,
            "content": {"kind": "ak.content.text", "body": "after join"}
        }),
        ROSTER_ACTOR,
        created_at,
        post_join_received_at,
    );
    let pre_join_event_id = pre_join_record.event_id.clone();
    let post_join_event_id = post_join_record.event_id.clone();
    let pre_join_message_id = arkret_identifiers::MessageId::from_event_id(
        &arkret_identifiers::EventId::new(pre_join_event_id.clone()).unwrap(),
    );
    let post_join_message_id = arkret_identifiers::MessageId::from_event_id(
        &arkret_identifiers::EventId::new(post_join_event_id.clone()).unwrap(),
    );
    let pre_join_payload = json!({
        "event_id": pre_join_event_id,
        "message_id": pre_join_message_id,
        "realm_id": ROSTER_REALM,
        "strand_id": strand_id,
        "thread_id": strand_id,
        "sender": ROSTER_ACTOR,
        "content": {"kind": "ak.content.text", "body": "before join"}
    });
    let post_join_payload = json!({
        "event_id": post_join_event_id,
        "message_id": post_join_message_id,
        "realm_id": ROSTER_REALM,
        "strand_id": strand_id,
        "thread_id": strand_id,
        "sender": ROSTER_ACTOR,
        "content": {"kind": "ak.content.text", "body": "after join"}
    });
    let pre_join_message = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000002e1",
        arkret_wire::EventKind::MessageCreate,
        pre_join_payload.clone(),
        created_at,
    );
    let post_join_message = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000002e2",
        arkret_wire::EventKind::MessageCreate,
        post_join_payload.clone(),
        created_at,
    );
    {
        let mut projection = state.test_projection().lock();
        projection.apply(&pre_join_message, state.hlc());
        projection.apply(&post_join_message, state.hlc());
    }
    store_canonical_event(&state, pre_join_record).await;
    store_canonical_event(&state, post_join_record).await;

    let body = roster_body(state.service_id());
    let snapshot = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
    let timeline_events = &snapshot.realms.as_ref().unwrap().entries[ROSTER_REALM]
        .timeline
        .as_ref()
        .unwrap()
        .events;
    assert!(
        !timeline_events
            .iter()
            .any(|event| event.event_id.as_str() == pre_join_event_id),
        "joined history must hide messages received before the member joined"
    );
    assert!(
        timeline_events
            .iter()
            .any(|event| event.event_id.as_str() == post_join_event_id),
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
    let payload_digest = arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(&identity_payload).unwrap(),
    );
    state.test_insert_member_identity(MemberIdentityEventRecord {
        event_id: "ak:event:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx".to_owned(),
        subject: MemberIdentitySubjectKey {
            realm_id: ROSTER_REALM.to_owned(),
            actor_id: ROSTER_ACTOR.to_owned(),
            segment: "member_identity".to_owned(),
        },
        payload_digest,
        replaces: Vec::new(),
        raw_event: json!({
            "event_id": "ak:event:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx",
            "event_kind": arkret_wire::EventKind::MemberIdentityUpdate,
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
        "issuer_service_id": issuer,
        "binding_state": binding_state,
        "claim_kind": "handle_binding",
        "visibility": "public",
        "audience": audience,
        "created_at": arkret_canonical::format_timestamp_canonical(
            now() - ChronoDuration::minutes(1)
        ),
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "proofs": [{
            "kind": "detached_jws",
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
    if issuer == state.service_id() {
        claim["issuer_service_id"] = json!(state.service_id());
    }
    claim
}

fn cache_claim(state: &AppState, claim: Value) -> String {
    state.test_cache_handle_claim(claim).expect("claim cached")
}

fn roster_row(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> Value {
    let body = roster_body(state.service_id());
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
    arkret_canonical::sha256_digest(arkret_canonical::canonical_json_bytes(value).unwrap())
}

// SPEC-CR-010 / SOL-05-008 — `project_member_identity_update` MUST store the
// canonical `ak:event:` id (threaded through `ProjectionContext`) so the
// effective-set / replaces / R3.2 digests live in the same id space as a
// spec-compliant client, whose `replaces[].event_id` is a `ak:event:` id.
#[test]
fn member_identity_projection_stores_typed_event_id_and_matches_event_replaces() {
    use crate::routing::events::projection::project_member_identity_update;

    let state = test_state();
    let realm = ROSTER_REALM;
    let actor = ROSTER_ACTOR;
    let created_at = now();
    let first_event_id = "ak:event:AWLjsk0JkbLdfBfaY2GoxT61q1Ttw6HFu7sU-XGFywHc";
    let second_event_id = "ak:event:AS3cyhr0pju5AnMYHRcgMbHHU45oa25NELQwXBDt8smD";

    let first_identity = json!({
        "member_identity": {
            "subject_id": ROSTER_SUBJECT,
            "display_profile": { "display_name": "Alice" }
        }
    });
    let first_digest = arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(&first_identity).unwrap(),
    );

    // First update. The canonical `ak:event:` id is envelope metadata in the
    // typed projection context and never part of the signed payload.
    let first_op = accepted_sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000e1",
        first_event_id,
        ROSTER_ACTOR_FULL,
        1,
        arkret_wire::EventKind::MemberIdentityUpdate,
        json!({
            "realm_id": realm,
            "actor_id": actor,
            "segment": "member_identity",
            "identity_payload": first_identity,
        }),
        created_at,
    );
    project_member_identity_update(&state, &first_op);

    {
        let snapshot = state.member_identity_snapshot(realm, actor).unwrap();
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
    let second_op = accepted_sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000e2",
        second_event_id,
        ROSTER_ACTOR_FULL,
        2,
        arkret_wire::EventKind::MemberIdentityUpdate,
        json!({
            "realm_id": realm,
            "actor_id": actor,
            "segment": "member_identity",
            "identity_payload": second_identity,
            "replaces": [ { "event_id": first_event_id, "payload_digest": first_digest } ],
        }),
        created_at + ChronoDuration::milliseconds(1),
    );
    project_member_identity_update(&state, &second_op);

    let snapshot = state.member_identity_snapshot(realm, actor).unwrap();
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
            .all(|entry| entry.event_id.as_str().starts_with("ak:event:")),
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
    let body = roster_body(state.service_id());
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
    let body = roster_body(state.service_id());

    let rows = roster_members_for_realm(&state, &realm, None, &body);

    assert_eq!(roster_membership_for_actor(&rows, ROSTER_ACTOR), None);
}

#[test]
fn roster_discloses_handle_claim_for_visible_trusted_issuer() {
    let state = test_state();
    insert_member_identity_subject(&state);
    let claim = handle_claim(
        &state,
        state.service_id(),
        state.service_id(),
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
            state.service_id(),
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
            state.service_id(),
            state.service_id(),
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
            state.service_id(),
            state.service_id(),
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
            state.service_id(),
            state.service_id(),
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
        state.service_id(),
        state.service_id(),
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
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    state.realm_directory().upsert(roster_realm(false, true));

    let created_at = DateTime::parse_from_rfc3339("2026-06-18T00:00:00.000Z")
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
            .identities()
            .save_device(soland_services::identity::SaveDeviceCommand {
                actor_id: actor.to_owned(),
                device_id: device_id.to_owned(),
                display_name: None,
                device: soland_services::identity::DeviceIdentity {
                    actor_id: actor.to_owned(),
                    device_id: device_id.to_owned(),
                    display_name: None,
                    verification_state: "verified".to_owned(),
                    payload: json!({"algorithms": ["mls_rfc9420"]}),
                    created_at,
                    updated_at,
                    revoked_at: None,
                },
            })
            .await
            .expect("device inserted");
    }

    let body = roster_body(state.service_id());
    let initial = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
    assert_eq!(
        serde_json::to_value(&initial.device_lists).unwrap(),
        json!({"changed": [ROSTER_ACTOR, ROSTER_CALLER], "left": []})
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

    let mut revoked = state
        .identities()
        .devices_for_actor(ROSTER_ACTOR)
        .await
        .expect("device list")
        .into_iter()
        .next()
        .expect("actor device exists");
    revoked.revoked_at = Some(updated_at + ChronoDuration::seconds(1));
    revoked.updated_at = updated_at + ChronoDuration::seconds(1);
    state
        .identities()
        .save_device(soland_services::identity::SaveDeviceCommand {
            actor_id: revoked.actor_id.clone(),
            device_id: revoked.device_id.clone(),
            display_name: revoked.display_name.clone(),
            device: revoked,
        })
        .await
        .expect("device revoked");

    let mut incremental_body = body.clone();
    incremental_body.after = initial.cursor.clone();
    let after_revocation =
        build_sync_snapshot(&state, Some(&session), &incremental_body, &initial_cursor).await;
    assert_eq!(
        serde_json::to_value(&after_revocation.device_lists).unwrap(),
        json!({"changed": [ROSTER_ACTOR], "left": []}),
        "device revocation changes the principal device list, not top-level left"
    );
    let incremental_filter_value = sync_filter_value(incremental_body.filter.as_ref());
    let after_revocation_cursor = parse_and_validate_sync_cursor(
        after_revocation.cursor.as_deref().unwrap(),
        &state,
        Some(&session),
        incremental_filter_value.as_ref(),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("revocation cursor parses");

    state.realm_directory().upsert(roster_realm(false, false));
    let after_scope_loss = build_sync_snapshot(
        &state,
        Some(&session),
        &incremental_body,
        &after_revocation_cursor,
    )
    .await;
    assert_eq!(
        serde_json::to_value(&after_scope_loss.device_lists).unwrap(),
        json!({"changed": [], "left": [ROSTER_ACTOR]}),
        "principals no longer visible through any Realm leave the tracked device list set"
    );
}

#[tokio::test]
async fn sync_snapshot_emits_state_events_without_timeline_messages() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    state.realm_directory().upsert(roster_realm(false, true));

    let first_created_at = DateTime::parse_from_rfc3339("2026-06-24T10:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let second_created_at = first_created_at + ChronoDuration::seconds(1);
    let meta_created_at = first_created_at - ChronoDuration::seconds(1);
    state
        .realms()
        .store_realm_metadata(
            ROSTER_REALM,
            soland_services::events::RealmMetadata {
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
                aad_visibility_ceiling: Default::default(),
                created_at: meta_created_at,
                updated_at: meta_created_at,
            },
        )
        .await
        .expect("realm meta stored");
    let first_payload = json!({
        "strand_id": "ak:strand:Af0cDOgrSK-qWEvQvEo_FnP9vdEMz6mEq0IN2aIOIege",
        "patch": {"synthesis": {"$op": "set", "value": "first"}}
    });
    let first_record = canonical_event_record_received_at(
        1,
        arkret_wire::EventKind::StrandUpdate,
        first_payload.clone(),
        ROSTER_ACTOR,
        first_created_at,
        first_created_at,
    );
    store_canonical_event(&state, first_record.clone()).await;
    crate::routing::events::projection::append_projection_event(
        &state,
        soland_services::events::ProjectedEvent {
            event_id: first_record.event_id.clone(),
            realm_id: ROSTER_REALM.to_owned(),
            event_kind: arkret_wire::EventKind::StrandUpdate,
            operation_kind: "state".to_owned(),
            operation_id: Some("ak:operation:01904100-0000-7000-8000-0000000000a1".to_owned()),
            sender: Some(ROSTER_ACTOR.to_owned()),
            payload: first_payload,
            created_at: first_created_at,
            received_at: first_created_at,
        },
    )
    .await
    .expect("first state event appended");

    let body = roster_body(state.service_id());
    let initial = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
    let initial_value = serde_json::to_value(&initial).unwrap();
    let initial_events = initial_value["realms"][ROSTER_REALM]["state"]["events"]
        .as_array()
        .expect("state events array");
    assert_eq!(initial_events.len(), 1);
    assert_eq!(initial_events[0]["actor_id"], ROSTER_ACTOR);

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

    let second_payload = json!({
        "strand_id": "ak:strand:Af0cDOgrSK-qWEvQvEo_FnP9vdEMz6mEq0IN2aIOIege",
        "patch": {"synthesis": {"$op": "set", "value": "first\n\n---\n\nsecond"}}
    });
    let second_record = canonical_event_record_received_at(
        2,
        arkret_wire::EventKind::StrandUpdate,
        second_payload.clone(),
        ROSTER_CALLER,
        second_created_at,
        second_created_at,
    );
    store_canonical_event(&state, second_record.clone()).await;
    crate::routing::events::projection::append_projection_event(
        &state,
        soland_services::events::ProjectedEvent {
            event_id: second_record.event_id.clone(),
            realm_id: ROSTER_REALM.to_owned(),
            event_kind: arkret_wire::EventKind::StrandUpdate,
            operation_kind: "state".to_owned(),
            operation_id: Some("ak:operation:01904100-0000-7000-8000-0000000000b1".to_owned()),
            sender: Some(ROSTER_CALLER.to_owned()),
            payload: second_payload,
            created_at: second_created_at,
            received_at: second_created_at,
        },
    )
    .await
    .expect("second state event appended");

    let mut incremental_body = body.clone();
    incremental_body.after = initial.cursor.clone();
    let incremental =
        build_sync_snapshot(&state, Some(&session), &incremental_body, &initial_cursor).await;
    let incremental_value = serde_json::to_value(&incremental).unwrap();
    let incremental_events = incremental_value["realms"][ROSTER_REALM]["state"]["events"]
        .as_array()
        .expect("incremental state events array");
    assert_eq!(
        incremental_events.len(),
        1,
        "state-only updates must keep the Realm in incremental sync"
    );
    assert_eq!(incremental_events[0]["actor_id"], ROSTER_CALLER);
    assert_eq!(
        incremental_value["realms"][ROSTER_REALM]["timeline"]["events"]
            .as_array()
            .expect("timeline events")
            .len(),
        0
    );
}

#[tokio::test]
async fn membership_only_projection_advances_incremental_roster() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let session = roster_session(&state, ROSTER_ACTOR);
    state.realm_directory().upsert(roster_realm(false, false));

    let created_at = DateTime::parse_from_rfc3339("2026-06-24T10:30:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    state
        .realms()
        .store_realm_metadata(
            ROSTER_REALM,
            soland_services::events::RealmMetadata {
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
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .expect("realm meta stored");

    let body = roster_body(state.service_id());
    let initial = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
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

    let member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c6",
        arkret_wire::EventKind::MemberState,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "sender": ROSTER_ACTOR
        }),
        created_at + ChronoDuration::seconds(1),
    );
    crate::routing::events::projection::project_accepted_operations(
        &state,
        ROSTER_ACTOR,
        &[member_join],
    )
    .await;

    let mut incremental_body = body;
    incremental_body.after = initial.cursor;
    let incremental =
        build_sync_snapshot(&state, Some(&session), &incremental_body, &initial_cursor).await;
    let value = serde_json::to_value(&incremental).unwrap();
    let members = value["realms"][ROSTER_REALM]["members"]
        .as_array()
        .expect("membership-only delta must include the current roster projection");
    assert_eq!(
        roster_membership_for_actor(members, ROSTER_CALLER),
        Some("join"),
        "ak.member.state(join) must wake account sync and expose the joined member without a timeline message"
    );
    assert_eq!(
        value["realms"][ROSTER_REALM]["members_limited"],
        json!(false)
    );
}

#[tokio::test]
async fn sync_snapshot_includes_shared_pin_events_for_joined_member() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    let strand_id = strand_id_from_realm_id(ROSTER_REALM).expect("canonical fixture RealmId");
    let message_event_id = "ak:event:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";
    let message_id = "ak:message:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";
    let base = DateTime::parse_from_rfc3339("2026-06-24T10:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let realm_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c1",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": ROSTER_REALM,
                "title": "Pinned welcome space",
                "created_by": ROSTER_ACTOR,
                "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                "default_join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "none"
            }
        }),
        base,
    );
    let member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c2",
        arkret_wire::EventKind::MemberState,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "sender": ROSTER_ACTOR
        }),
        base + ChronoDuration::seconds(1),
    );
    let strand_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c3",
        arkret_wire::EventKind::StrandCreate,
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
        arkret_wire::EventKind::MessageCreate,
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

    let body = roster_body(state.service_id());
    let initial = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
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

    let pin_payload = json!({
        "pin_scope": {"kind": "strand", "id": strand_id},
        "target_ref": message_id,
        "rank": "r1"
    });
    let pin_record = canonical_event_record_received_at(
        5,
        arkret_wire::EventKind::PinAdd,
        pin_payload.clone(),
        ROSTER_ACTOR,
        base + ChronoDuration::seconds(4),
        base + ChronoDuration::seconds(4),
    );
    let pin_add = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000000c5",
        arkret_wire::EventKind::PinAdd,
        json!({
            "event_id": pin_record.event_id.clone(),
            "pin_scope": {"kind": "strand", "id": strand_id},
            "target_ref": message_id,
            "rank": "r1",
            "sender": ROSTER_ACTOR
        }),
        base + ChronoDuration::seconds(4),
    );
    store_canonical_event(&state, pin_record).await;
    crate::routing::events::projection::project_accepted_operations(
        &state,
        ROSTER_ACTOR,
        &[pin_add],
    )
    .await;

    let mut incremental_body = body.clone();
    incremental_body.after = initial.cursor.clone();
    let incremental =
        build_sync_snapshot(&state, Some(&session), &incremental_body, &initial_cursor).await;
    let incremental_value = serde_json::to_value(&incremental).unwrap();
    let state_events = incremental_value["realms"][ROSTER_REALM]["state"]["events"]
        .as_array()
        .expect("state events array");
    assert!(
        state_events.iter().any(
            |event| event["kind"] == arkret_wire::EventKind::PinAdd.as_str()
                && event["payload"]["target_ref"] == message_id
        ),
        "joined members must receive shared pin state events through account sync"
    );
}

#[tokio::test]
async fn sync_timeline_dedupes_redacted_revision_by_message_id() {
    let mut config = test_config();
    config.seed_demo_data = false;
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    let session = roster_session(&state, ROSTER_CALLER);
    let strand_id = strand_id_from_realm_id(ROSTER_REALM).expect("canonical fixture RealmId");
    let message_event_id = "ak:event:AQ-IyBN9yVn52Yqaah8H-_0fuHhf3ImJTExtFDnU3ebQ";
    let redaction_event_id = "ak:event:ARd31VEuNctVD_m_3KpeoN5D_TuBpgHos97UPSApGL_6";
    let message_id = "ak:message:AQ-IyBN9yVn52Yqaah8H-_0fuHhf3ImJTExtFDnU3ebQ";
    let base = DateTime::parse_from_rfc3339("2026-06-24T11:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let revision_record = canonical_event_record_received_at(
        5,
        arkret_wire::EventKind::MessageRevise,
        json!({
            "target_ref": message_id,
            "content": {"kind": "ak.content.text", "body": "edited"}
        }),
        ROSTER_ACTOR,
        base + ChronoDuration::seconds(4),
        base + ChronoDuration::seconds(4),
    );
    let revision_event_id = revision_record.event_id.clone();
    let realm_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c1",
        arkret_wire::EventKind::RealmCreate,
        json!({
            "object": {
                "id": ROSTER_REALM,
                "title": "Redacted revision space",
                "created_by": ROSTER_ACTOR,
                "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                "default_join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "none"
            }
        }),
        base,
    );
    let member_join = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c2",
        arkret_wire::EventKind::MemberState,
        json!({
            "realm_id": ROSTER_REALM,
            "actor_id": ROSTER_CALLER,
            "membership": "join",
            "delivery_status": "unroutable",
            "sender": ROSTER_ACTOR
        }),
        base + ChronoDuration::seconds(1),
    );
    let strand_create = sync_test_operation_at(
        "ak:operation:01904100-0000-7000-8000-0000000001c3",
        arkret_wire::EventKind::StrandCreate,
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
        arkret_wire::EventKind::MessageCreate,
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
        arkret_wire::EventKind::MessageRevise,
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
        arkret_wire::EventKind::MessageRedact,
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
    store_canonical_event(&state, revision_record).await;

    let body = roster_body(state.service_id());
    let snapshot = build_sync_snapshot(&state, Some(&session), &body, &SyncCursor::default()).await;
    let snapshot_value = serde_json::to_value(&snapshot).unwrap();
    let timeline_events = snapshot_value["realms"][ROSTER_REALM]["timeline"]["events"]
        .as_array()
        .expect("timeline events array");
    let matching = timeline_events
        .iter()
        .filter(|event| event["payload"]["message_id"] == message_id)
        .collect::<Vec<_>>();

    assert_eq!(
        matching.len(),
        1,
        "timeline must surface one logical tombstone per message_id"
    );
    assert_eq!(matching[0]["event_id"], revision_event_id);
    assert_eq!(matching[0]["payload"]["redacted"], true);
    assert_eq!(matching[0]["payload"]["state"], "redacted");
    assert_eq!(matching[0]["payload"]["message_id"], message_id);
    assert_eq!(matching[0]["payload"]["strand_id"], strand_id);
    assert_eq!(matching[0]["payload"]["thread_id"], strand_id);
    assert_eq!(
        matching[0]["payload"]["content"]["body"], "[redacted]",
        "sync must not fall back to the plaintext canonical revision"
    );
    assert_eq!(matching[0]["unsigned"]["projection_only"], true);
    assert_eq!(matching[0]["proofs"], json!([]));
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

fn assert_integrity_error(error: SyncCursorError) {
    match error {
        SyncCursorError::Integrity(_) => {}
        other => panic!("expected cursor integrity error, got {other:?}"),
    }
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
    let session = roster_session(&state, "did:web:alice.example");
    let filter_a = sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.events.read.scan",
        "realms": [ROSTER_REALM],
        "actors": [],
        "filters": {},
        "order": "default",
    })));
    let filter_b = sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.events.read.scan",
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
        "operation_id": "ak.self.events.read.scan",
        "realms": ["ak:realm:b", "ak:realm:a", "ak:realm:a"],
        "actors": ["did:web:bob.example", "did:web:alice.example"],
        "filters": {
            "kind": ["ak.reaction.add", "ak.message.create", "ak.message.create"],
            "not_event_types": ["ak.redaction", "ak.audit.accessed"]
        },
        "order": "default"
    });
    let scope_b = json!({
        "operation_id": "ak.self.events.read.scan",
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
        "operation_id": "ak.self.events.read.scan",
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
        .sync()
        .prune_superseded_cursors(
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
        .sync()
        .cache_cursor_revocation(soland_services::sync::CursorRevocationState {
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
        .sync()
        .cache_cursor_revocation(soland_services::sync::CursorRevocationState {
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
        state.sync().cached_cursor_revocation_count() == 0,
        "expired revocation entry should have been pruned"
    );
}
