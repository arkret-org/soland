//! Integration tests for the `ak.realm.read_receipt_policy` reducer gates and
//! for `ak.receipt.read` on the Signal Extension rail.
//!
//! `discovery/read-receipts.md` §2.1 is the rail: a read receipt MUST travel as
//! the encrypted plaintext of a [`SignalEnvelope`](../sync/signal.md) with
//! `signal_class=session`, and `ak.receipt.read`, the read target, the Event id,
//! the HLC and the actor all live inside `encrypted_payload`. There is no
//! `POST /_arkret/self/ephemeral` any more, and the server cannot read — and
//! therefore cannot route on — any product field of a receipt.

use arkret_models_collaboration::signal_plaintext::{
    ReadReceipt, SignalPlaintext, open_signal_plaintext, seal_signal_plaintext,
};

use super::common::*;

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const BOB: &str = "did:web:bob.example";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b000000001";
const CAROL: &str = "did:web:carol.example";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-ca0010000001";
const DAVE: &str = "did:web:dave.example";
const DAVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-da0010000001";

async fn set_demo_realm_visibility(
    state: &AppState,
    discoverability: &str,
    history_visibility: &str,
) {
    let now = chrono::Utc::now();
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(DEMO_REALM_ID)
        .await
        .unwrap()
        .unwrap_or_else(|| RealmMetaRecord {
            owner: ALICE.to_owned(),
            deleted: false,
            discoverability: discoverability.to_owned(),
            history_visibility: history_visibility.to_owned(),
            history_sharing_policy: None,
            history_sharing_policy_digest: None,
            preview_policy: None,
            preview_policy_digest: None,
            asset_privacy_policy: None,
            asset_privacy_policy_digest: None,
            encryption_profile: Some("none".to_owned()),
            plaintext_visible_services: std::collections::BTreeSet::from([state
                .service_id()
                .clone()]),
            plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                state.service_id().clone(),
                std::collections::BTreeSet::from([
                    arkret_wire::PlaintextDataClassKind::MessageContent,
                ]),
            )]),
            minimal_metadata_realm: false,
            aad_visibility_ceiling: Default::default(),
            created_at: now,
            updated_at: now,
        });
    meta.discoverability = discoverability.to_owned();
    meta.history_visibility = history_visibility.to_owned();
    meta.encryption_profile = Some("none".to_owned());
    meta.plaintext_visible_services =
        std::collections::BTreeSet::from([state.service_id().clone()]);
    meta.plaintext_visible_service_classes.insert(
        state.service_id().clone(),
        std::collections::BTreeSet::from([arkret_wire::PlaintextDataClassKind::MessageContent]),
    );
    meta.updated_at = now;
    state
        .test_persistence()
        .realm_meta()
        .put(DEMO_REALM_ID, &meta)
        .await
        .unwrap();
}

async fn set_read_receipt_policy(
    state: AppState,
    token: &str,
    visibility: &str,
    allow_public_world_readable: bool,
) {
    let response = submit_read_receipt_policy(
        state,
        token,
        "optional",
        visibility,
        allow_public_world_readable,
        false,
    )
    .await;
    assert!(
        response["status"] == "accepted"
            || response["accepted"]
                .as_array()
                .is_some_and(|events| !events.is_empty()),
        "read receipt policy event: {response}"
    );
}

async fn submit_read_receipt_policy(
    state: AppState,
    token: &str,
    disclosure: &str,
    visibility: &str,
    allow_public_world_readable: bool,
    allow_forced_public_world_readable: bool,
) -> Value {
    submit_actor_private_event(
        state,
        token,
        ALICE,
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ak.realm.read_receipt_policy",
        serde_json::json!({
            "disclosure": disclosure,
            "visibility": visibility,
            "scope_overrides_allowed": true,
            "receipt_compliance_opt_in": {
                "public_receipts_on_world_readable": allow_public_world_readable,
                "forced_public_world_readable_receipts": allow_forced_public_world_readable
            }
        }),
    )
    .await
}

#[tokio::test]
async fn read_receipt_policy_rejects_public_world_readable_without_opt_in() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    set_demo_realm_visibility(&state, "public", "world_readable").await;

    let response = submit_read_receipt_policy(
        state.clone(),
        &alice_token,
        "optional",
        "public",
        false,
        false,
    )
    .await;

    assert_ne!(
        response["status"], "accepted",
        "public world_readable policy must be rejected: {response}"
    );
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(
        encoded.contains("read_receipt_visibility_combination_invalid"),
        "response must include read_receipt_visibility_combination_invalid: {response}"
    );
}

#[tokio::test]
async fn read_receipt_policy_rejects_forced_public_world_readable_without_second_opt_in() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    set_demo_realm_visibility(&state, "public", "world_readable").await;

    let response = submit_read_receipt_policy(
        state.clone(),
        &alice_token,
        "required",
        "public",
        true,
        false,
    )
    .await;

    assert_ne!(
        response["status"], "accepted",
        "forced public world_readable policy must be rejected: {response}"
    );
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(
        encoded.contains("read_receipt_forced_public_world_readable_forbidden"),
        "response must include read_receipt_forced_public_world_readable_forbidden: {response}"
    );
}

/// The Strand the demo Realm's fixture messages are authored into.
const TARGET_STRAND_ID: &str = "ak:strand:0196419b-0000-7000-8000-000000000000";

/// The pre-migration plaintext ephemeral receipt envelope, kept as a negative.
///
/// `read-receipts.md` §2.1 is explicit that this exact shape — receipt target
/// and precise kind on the outer envelope — MUST be rejected with
/// `schema_violation` or `signal_plaintext_forbidden`, so the fixture keeps
/// earning its place as the input the Signal rail refuses to interpret. It is a
/// raw `Value` rather than a strong type on purpose: no SDK type can express it.
fn legacy_plaintext_read_receipt_envelope(actor: &str, device_id: &str, event_id: &str) -> Value {
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let mut envelope = serde_json::json!({
        "kind": "ak.receipt.read",
        "realm_id": DEMO_REALM_ID,
        "actor_id": actor,
        "device_id": device_id,
        "sent_at": arkret_canonical::format_timestamp_canonical(sent_at),
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "payload": {
            "receipt_kind": "read",
            "schema": arkret_wire::SchemaId::READ_RECEIPT_V1,
            "realm_id": DEMO_REALM_ID,
            "actor_id": actor,
            "event_id": event_id,
            "read_scope": {"kind": "realm"},
            "created_at": arkret_canonical::format_timestamp_canonical(sent_at)
        }
    });
    let canonical = arkret_canonical::canonical_json_bytes(&envelope).unwrap();
    let event_digest = arkret_canonical::sha256_digest(&canonical);
    envelope["proof"] = serde_json::json!({
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": format!("{actor}#{device_id}"),
        "event_digest": event_digest,
        "created_at": arkret_canonical::format_timestamp_canonical(sent_at),
        "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
    });
    envelope
}

/// The `ak.schema.read_receipt.v1` Signal plaintext.
///
/// The closed profile carries `kind` + `payload_sequence` plus the reader,
/// target and scope. Realm id and send time are NOT here: §2.1 forbids
/// duplicating what the signed envelope already carries, and the AAD binds the
/// Realm into the ciphertext. `payload_sequence` is the sender-device sequence
/// the receiver dedupe triple needs.
fn read_receipt_plaintext(actor: &str, event_id: &str, payload_sequence: u64) -> String {
    let receipt = ReadReceipt::new(
        payload_sequence,
        Did::new(actor.to_owned()).unwrap(),
        arkret_wire::EventId::new(event_id.to_owned()).unwrap(),
        arkret_wire::ReadReceiptScope::strand(TARGET_STRAND_ID, Some("discussion")),
    )
    .expect("closed read receipt plaintext");
    String::from_utf8(seal_signal_plaintext(&receipt).unwrap()).unwrap()
}

/// Recover the receipt a receiving client would see after decrypting.
///
/// The fixture's `ciphertext` is base64url of the canonical plaintext rather
/// than a real MLS-exporter AEAD output; what this asserts is the placement of
/// the receipt object, not the AEAD construction (which `signal.md` §1 pins and
/// `validate_structural` enforces through `aad_digest`).
fn decrypted_receipt(envelope: &arkret_wire::SignalEnvelope) -> ReadReceipt {
    let plaintext = URL_SAFE_NO_PAD
        .decode(&envelope.encrypted_payload.ciphertext)
        .expect("signal ciphertext is base64url");
    match open_signal_plaintext(&plaintext).expect("registered Signal plaintext kind") {
        SignalPlaintext::ReadReceipt(receipt) => receipt,
        other => panic!("expected ak.receipt.read, got {:?}", other.kind()),
    }
}

/// Everything about the delivered envelope the Sync Service is allowed to read.
fn server_visible_header(envelope: &arkret_wire::SignalEnvelope) -> Value {
    let mut header = serde_json::to_value(envelope).unwrap();
    header["encrypted_payload"]
        .as_object_mut()
        .unwrap()
        .remove("ciphertext");
    header
}

fn realm_scope() -> arkret_wire::ScopeRef {
    arkret_wire::ScopeRef::Realm {
        realm_id: RealmId::new(DEMO_REALM_ID.to_owned()).unwrap(),
    }
}

fn circle_scope(circle_id: &str) -> arkret_wire::ScopeRef {
    arkret_wire::ScopeRef::Circle {
        realm_id: RealmId::new(DEMO_REALM_ID.to_owned()).unwrap(),
        circle_id: arkret_identifiers::CircleId::new(circle_id.to_owned()).unwrap(),
    }
}

/// A receipt Signal from Bob. `signal_class` is fixed to `session` by §2.1.
fn bob_receipt_signal(
    scope_ref: arkret_wire::ScopeRef,
    seal_ref: &arkret_wire::SealId,
    sent_at: chrono::DateTime<chrono::Utc>,
    ttl_seconds: i64,
    plaintext: &str,
    signing_key: &SigningKey,
) -> arkret_wire::SignalEnvelope {
    signed_signal_envelope(
        DEMO_REALM_ID,
        scope_ref,
        BOB,
        BOB_DEVICE,
        seal_ref,
        arkret_wire::SignalClass::Session,
        sent_at,
        ttl_seconds,
        plaintext,
        signing_key,
    )
}

async fn submit_alice_target_message(state: AppState, token: &str, body: &str) -> String {
    let message = submit_message_event(
        state,
        token,
        ALICE,
        DEMO_REALM_ID,
        TARGET_STRAND_ID,
        serde_json::json!({"body": body}),
        false,
    )
    .await;
    message["event_id"].as_str().unwrap().to_owned()
}

/// Restates `private_read_receipt_visible_only_to_target_sender`.
///
/// The old premise was a server-side crop: the service read the receipt's
/// `event_id`, resolved that Event's sender and fanned the receipt out to that
/// actor alone. `read-receipts.md` §2.1 removed the input that crop needed —
/// `ak.receipt.read`, the read target, the Event id, the HLC and the actor are
/// all inside `encrypted_payload`, which the Sync Service may neither see nor
/// route on — and §2.5 rule 1 classifies the policy as a soft compliance
/// declaration rather than a cryptographically enforced, service-side gate. So
/// what survives is asserted here instead:
///
/// 1. the pre-migration plaintext envelope is refused, not reinterpreted (§2.1);
/// 2. the only narrowing the rail can enforce is the signed `scope_ref`, so a Circle-scoped receipt
///    reaches the Circle and not a Realm member outside it;
/// 3. the delivered header names no receipt field at all, and the receipt object is recoverable
///    only from the ciphertext, whose `actor_id` MUST equal the outer `sender_actor_id` (§2.1).
///
/// Per-receipt `visibility=private` fanout is *not* asserted: it is unevaluable
/// on this rail, and the two spec sentences that describe it contradict each
/// other. See the module report rather than inventing a rule here.
#[tokio::test]
async fn private_read_receipt_narrows_by_signed_scope_and_never_exposes_its_target() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, BOB);
    add_test_realm_member(&state, DEMO_REALM_ID, CAROL);
    let (bob_token, bob_key) =
        seed_signal_sender_device(&state, BOB, BOB_DEVICE, "Bob Desktop").await;
    let carol_token =
        verified_dev_token_for_device(state.clone(), CAROL, CAROL_DEVICE, "Carol Desktop").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, ALICE).await;
    set_demo_realm_visibility(&state, "invite_only", "shared").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "private receipt target").await;
    set_read_receipt_policy(state.clone(), &alice_token, "private", false).await;

    // (1) §2.1 — the legacy plaintext ephemeral receipt is refused outright.
    let mut legacy = TestClient::post("http://server/_arkret/self/signal")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&legacy_plaintext_read_receipt_envelope(
            BOB,
            BOB_DEVICE,
            &target_event_id,
        ))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(legacy.status_code, Some(StatusCode::BAD_REQUEST));
    let legacy_body: Value = legacy.take_json().await.unwrap();
    assert_eq!(
        legacy_body["error"]["details"]["reason_code"], "signal_plaintext_forbidden",
        "legacy plaintext receipt body: {legacy_body}"
    );
    assert!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(DEMO_REALM_ID)
            .await
            .unwrap()
            .is_empty(),
        "a plaintext receipt must never reach the live relay"
    );

    // (2) The receipt rides the Signal rail, narrowed to a Circle Alice is in
    // and Carol is not.
    let circle_id = "ak:circle:01904100-0000-7000-8000-c17c1e000003";
    seed_test_circle(&state, DEMO_REALM_ID, circle_id, &[ALICE, BOB]);
    let sent_at = chrono::Utc::now();
    let plaintext = read_receipt_plaintext(BOB, &target_event_id, 1);
    let receipt = bob_receipt_signal(
        circle_scope(circle_id),
        &seal_ref,
        sent_at,
        30,
        &plaintext,
        &bob_key,
    );
    let mut submit = post_signal(state.clone(), &bob_token, &receipt).await;
    assert_eq!(submit.status_code, Some(StatusCode::OK));
    let outcome: arkret_models_collaboration::http_bodies::SignalSubmitOutcome =
        submit.take_json().await.unwrap();
    assert!(outcome.accepted);
    assert_eq!(
        outcome.dispatched_recipient_count,
        Some(1),
        "eligibility is the Circle's membership minus the sender"
    );

    let carol_delivered = signal_subscribe_envelopes(state.clone(), &carol_token, 400).await;
    assert!(
        carol_delivered.is_empty(),
        "a Realm member outside the signed Circle scope receives no receipt"
    );
    let alice_delivered = signal_subscribe_envelopes(state.clone(), &alice_token, 400).await;
    assert_eq!(alice_delivered, vec![receipt.clone()]);

    // (3) Nothing the server may read names the receipt.
    let delivered = &alice_delivered[0];
    let header = server_visible_header(delivered).to_string();
    for forbidden in [
        "ak.receipt.read",
        arkret_wire::SchemaId::READ_RECEIPT_V1,
        "read_scope",
        "receipt_kind",
        target_event_id.as_str(),
    ] {
        assert!(
            !header.contains(forbidden),
            "the server-visible header must not carry '{forbidden}': {header}"
        );
    }
    assert_eq!(delivered.signal_class, arkret_wire::SignalClass::Session);

    let decrypted = decrypted_receipt(delivered);
    assert_eq!(decrypted.payload_sequence, 1);
    assert_eq!(decrypted.event_id.as_str(), target_event_id);
    assert_eq!(
        decrypted.actor_id.as_str(),
        delivered.sender_actor_id.as_str(),
        "§2.1 — the outer sender_actor_id MUST equal the plaintext actor_id"
    );
}

/// Restates `members_and_public_read_receipts_are_cropped`.
///
/// The `members` half survives verbatim in its observable form: a non-member
/// sees nothing. The `public` half inverts. The old test asserted that once the
/// Realm is `world_readable`, the policy is `visibility=public` and the
/// `public_receipts_on_world_readable` opt-in is set, a non-member observer
/// (Dave) receives the receipt — which §2.5.1's fanout-containment clause
/// discourages (the Sync Service SHOULD keep fanout inside the active member
/// set) and, for the forced combination, forbids outright by raising that SHOULD
/// to a MUST NOT. On the Signal rail that containment is
/// structural rather than advisory: `signal/subscribe` only walks Realms the
/// subscriber is a member of, so widening the policy cannot widen the fanout.
#[tokio::test]
async fn read_receipt_fanout_stays_inside_the_realm_member_set_even_when_policy_is_public() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, BOB);
    let (bob_token, bob_key) =
        seed_signal_sender_device(&state, BOB, BOB_DEVICE, "Bob Desktop").await;
    // Dave is deliberately not a member of the demo Realm.
    let dave_token =
        verified_dev_token_for_device(state.clone(), DAVE, DAVE_DEVICE, "Dave Desktop").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, ALICE).await;
    set_demo_realm_visibility(&state, "public", "world_readable").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "members public crop").await;

    set_read_receipt_policy(state.clone(), &alice_token, "members", false).await;
    let members_sent_at = chrono::Utc::now();
    let members_receipt = bob_receipt_signal(
        realm_scope(),
        &seal_ref,
        members_sent_at,
        30,
        &read_receipt_plaintext(BOB, &target_event_id, 1),
        &bob_key,
    );
    let mut members_submit = post_signal(state.clone(), &bob_token, &members_receipt).await;
    assert_eq!(members_submit.status_code, Some(StatusCode::OK));
    let members_outcome: arkret_models_collaboration::http_bodies::SignalSubmitOutcome =
        members_submit.take_json().await.unwrap();
    assert_eq!(
        members_outcome.dispatched_recipient_count,
        Some(1),
        "eligibility is the Realm member set minus the sender; Dave is not in it"
    );

    assert_eq!(
        signal_subscribe_envelopes(state.clone(), &alice_token, 400).await,
        vec![members_receipt]
    );
    assert!(
        signal_subscribe_envelopes(state.clone(), &dave_token, 400)
            .await
            .is_empty(),
        "a non-member receives no receipt under visibility=members"
    );

    // Widen the policy as far as §2.5.1 permits: public receipts on a
    // world_readable Realm, unlocked by the first compliance opt-in.
    set_read_receipt_policy(state.clone(), &alice_token, "public", true).await;
    let public_sent_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    let public_receipt = bob_receipt_signal(
        realm_scope(),
        &seal_ref,
        public_sent_at,
        30,
        &read_receipt_plaintext(BOB, &target_event_id, 2),
        &bob_key,
    );
    assert_eq!(
        post_signal(state.clone(), &bob_token, &public_receipt)
            .await
            .status_code,
        Some(StatusCode::OK)
    );

    assert_eq!(
        signal_subscribe_envelopes(state.clone(), &alice_token, 400).await,
        vec![public_receipt],
        "members still receive the receipt"
    );
    assert!(
        signal_subscribe_envelopes(state.clone(), &dave_token, 400)
            .await
            .is_empty(),
        "§2.5.1 fanout containment — a non-member observer is never pushed a receipt, \
         however permissive the Realm policy is"
    );
}

/// Restates `read_receipt_ttl_expiry_suppresses_sync_and_event_view`.
///
/// The TTL premise is unchanged; both of its old observation points moved.
/// `expires_at` is now a signed member of the envelope, `read-receipts.md` §2.1
/// fixes a receipt's `signal_class` to `session`, and `signal.md` §2 caps that
/// class at 30 seconds — so an over-long receipt fails closed at admission with
/// `signal_ttl_out_of_range`, which the old millisecond-TTL rail had no way to
/// express. The "and event view" half is gone with the rail: §1.1 says a receipt
/// never enters durable Event history, so there is no per-Event receipt view to
/// suppress. That is asserted directly instead.
#[tokio::test]
async fn read_receipt_signal_is_session_ttl_bounded_and_never_durable() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, BOB);
    let (bob_token, bob_key) =
        seed_signal_sender_device(&state, BOB, BOB_DEVICE, "Bob Desktop").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, ALICE).await;
    set_demo_realm_visibility(&state, "invite_only", "shared").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "ttl receipt target").await;
    // The plaintext is invariant across these cases; the TTL rules under test
    // live entirely on the signed envelope.
    let plaintext = |_sent_at| read_receipt_plaintext(BOB, &target_event_id, 1);

    // §2 — one second past the `session` ceiling fails closed at the ingress.
    let over_ceiling_at = chrono::Utc::now();
    let mut over_ceiling = post_signal(
        state.clone(),
        &bob_token,
        &bob_receipt_signal(
            realm_scope(),
            &seal_ref,
            over_ceiling_at,
            31,
            &plaintext(over_ceiling_at),
            &bob_key,
        ),
    )
    .await;
    assert_eq!(over_ceiling.status_code, Some(StatusCode::BAD_REQUEST));
    let over_ceiling_body: Value = over_ceiling.take_json().await.unwrap();
    assert_eq!(
        over_ceiling_body["error"]["code"], "signal_ttl_out_of_range",
        "over-ceiling receipt body: {over_ceiling_body}"
    );

    // §3(4) makes a valid TTL part of what ingress MUST verify, so an envelope
    // whose window has already closed is refused rather than admitted into a
    // rail that could never deliver it. Its declared window is inside the
    // `session` ceiling, so this is a liveness rejection, not a structural one.
    let expired_at = chrono::Utc::now() - chrono::Duration::seconds(40);
    let expired = bob_receipt_signal(
        realm_scope(),
        &seal_ref,
        expired_at,
        30,
        &plaintext(expired_at),
        &bob_key,
    );
    let mut expired_response = post_signal(state.clone(), &bob_token, &expired).await;
    let expired_status = expired_response.status_code;
    let expired_body: Value = expired_response.take_json().await.unwrap();
    assert_eq!(
        expired_status,
        Some(StatusCode::BAD_REQUEST),
        "expired receipt body: {expired_body}"
    );

    let live_at = chrono::Utc::now();
    let live = bob_receipt_signal(
        realm_scope(),
        &seal_ref,
        live_at,
        30,
        &plaintext(live_at),
        &bob_key,
    );
    assert_eq!(
        post_signal(state.clone(), &bob_token, &live)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    // Only the live envelope was admitted, so the relay holds only that one.
    let retained = state
        .test_persistence()
        .signal_relay()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert_eq!(
        retained
            .iter()
            .map(|record| record.envelope_digest.clone())
            .collect::<Vec<_>>(),
        vec![live.envelope_digest().unwrap().as_str().to_owned()],
        "an expired receipt is not retained by the relay"
    );

    let delivered = signal_subscribe_envelopes(state.clone(), &alice_token, 400).await;
    assert_eq!(
        delivered,
        vec![live],
        "an expired read receipt is never delivered"
    );

    // §1.1 — a receipt has no durable Event history to be suppressed from.
    assert!(
        state
            .test_persistence()
            .events()
            .realm_events_newest_first(DEMO_REALM_ID)
            .await
            .unwrap()
            .iter()
            .all(|record| record.kind != "ak.receipt.read"),
        "admitting a read receipt Signal mints no durable Event"
    );
}
