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

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

async fn post_canonical_signal(
    state: AppState,
    token: &str,
    envelope: &arkret_wire::SignalEnvelope,
) -> salvo::http::Response {
    TestClient::post("http://server/_arkret/self/signal")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(envelope))
        .send(&app_from_state(state))
        .await
}

async fn set_demo_realm_visibility(state: &AppState, discoverability: &str, history_access: &str) {
    let now = chrono::Utc::now();
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(demo_realm_id())
        .await
        .unwrap()
        .unwrap_or_else(|| RealmMetaRecord {
            owner: ALICE.to_owned(),
            deleted: false,
            discoverability: discoverability.to_owned(),
            history_access: history_access.to_owned(),
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
            created_at: now,
            updated_at: now,
        });
    meta.discoverability = discoverability.to_owned();
    meta.history_access = history_access.to_owned();
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
        .put(demo_realm_id(), &meta)
        .await
        .unwrap();
}

async fn set_read_receipt_policy(state: AppState, token: &str, visibility: &str) {
    let response = submit_read_receipt_policy(state, token, "optional", visibility).await;
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
) -> Value {
    submit_actor_private_event(
        state,
        token,
        ALICE,
        ALICE_DEVICE,
        demo_realm_id(),
        "ak.realm.read_receipt_policy",
        serde_json::json!({
            "disclosure": disclosure,
            "visibility": visibility,
            "scope_overrides_allowed": true
        }),
    )
    .await
}

/// The Strand the demo Realm's fixture messages are authored into.
const TARGET_STRAND_ID: &str = "ak:strand:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";

fn read_receipt_plaintext(actor: &str, event_id: &str, payload_sequence: u64) -> String {
    let receipt = ReadReceipt::new(
        payload_sequence,
        arkret_wire::project_did_to_core_id(&Did::new(actor.to_owned()).unwrap()).unwrap(),
        arkret_wire::EventId::new(event_id.to_owned()).unwrap(),
        arkret_wire::ReadReceiptScope::strand(TARGET_STRAND_ID, Some("discussion")),
    )
    .expect("closed read receipt plaintext");
    String::from_utf8(seal_signal_plaintext(&receipt).unwrap()).unwrap()
}

fn decrypted_receipt(envelope: &arkret_wire::SignalEnvelope) -> ReadReceipt {
    let plaintext = URL_SAFE_NO_PAD
        .decode(&envelope.encrypted_payload.ciphertext)
        .expect("signal ciphertext is base64url");
    match open_signal_plaintext(&plaintext).expect("registered Signal plaintext kind") {
        SignalPlaintext::ReadReceipt(receipt) => receipt,
        other => panic!("expected ak.receipt.read, got {:?}", other.kind()),
    }
}

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
        realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
    }
}

fn circle_scope(circle_id: &str) -> arkret_wire::ScopeRef {
    arkret_wire::ScopeRef::Circle {
        realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
        circle_id: arkret_identifiers::CircleId::new(circle_id.to_owned()).unwrap(),
    }
}

fn bob_receipt_signal(
    scope_ref: arkret_wire::ScopeRef,
    seal_ref: &arkret_wire::SealId,
    sent_at: chrono::DateTime<chrono::Utc>,
    ttl_seconds: i64,
    plaintext: &str,
    signing_key: &SigningKey,
) -> arkret_wire::SignalEnvelope {
    signed_signal_envelope(
        demo_realm_id(),
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
        demo_realm_id(),
        TARGET_STRAND_ID,
        serde_json::json!({"body": body}),
        false,
    )
    .await;
    message["event_id"].as_str().unwrap().to_owned()
}

#[test]
fn private_read_receipt_narrows_by_signed_scope_and_never_exposes_its_target() {
    run_on_deep_stack(
        "private_read_receipt_narrows_by_signed_scope_and_never_exposes_its_target",
        private_read_receipt_narrows_by_signed_scope_and_never_exposes_its_target_body,
    );
}

async fn private_read_receipt_narrows_by_signed_scope_and_never_exposes_its_target_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, demo_realm_id(), BOB);
    add_test_realm_member(&state, demo_realm_id(), CAROL);
    let (bob_token, bob_key) =
        seed_signal_sender_device(&state, BOB, BOB_DEVICE, "Bob Desktop").await;
    let carol_token =
        verified_dev_token_for_device(state.clone(), CAROL, CAROL_DEVICE, "Carol Desktop").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), ALICE).await;
    set_demo_realm_visibility(&state, "invite_only", "all_history_for_current_members").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "private receipt target").await;
    set_read_receipt_policy(state.clone(), &alice_token, "private").await;

    // The receipt rides the Signal rail, narrowed to a Circle Alice is in
    // and Carol is not.
    let circle_id = "ak:circle:Aa5c9aKm3eqBBuZdfIQ4ORPvt45gtDefEZ3--7YrRKva";
    seed_test_circle(&state, demo_realm_id(), circle_id, &[ALICE, BOB]);
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
    let mut submit = post_canonical_signal(state.clone(), &bob_token, &receipt).await;
    if submit.status_code != Some(StatusCode::OK) {
        let status = submit.status_code;
        let body: Value = submit.take_json().await.unwrap();
        panic!("receipt submit failed with {status:?}: {body}");
    }
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

#[test]
fn read_receipt_signal_is_session_ttl_bounded_and_never_durable() {
    run_on_deep_stack(
        "read_receipt_signal_is_session_ttl_bounded_and_never_durable",
        read_receipt_signal_is_session_ttl_bounded_and_never_durable_body,
    );
}

async fn read_receipt_signal_is_session_ttl_bounded_and_never_durable_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, demo_realm_id(), BOB);
    let (bob_token, bob_key) =
        seed_signal_sender_device(&state, BOB, BOB_DEVICE, "Bob Desktop").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), ALICE).await;
    set_demo_realm_visibility(&state, "invite_only", "all_history_for_current_members").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "ttl receipt target").await;
    // The plaintext is invariant across these cases; the TTL rules under test
    // live entirely on the signed envelope.
    let plaintext = |_sent_at| read_receipt_plaintext(BOB, &target_event_id, 1);

    // §2 — one second past the `session` ceiling fails closed at the ingress.
    let over_ceiling_at = chrono::Utc::now();
    let mut over_ceiling = post_canonical_signal(
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
        problem_code(&over_ceiling_body),
        "signal_ttl_out_of_range",
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
    let mut expired_response = post_canonical_signal(state.clone(), &bob_token, &expired).await;
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
        post_canonical_signal(state.clone(), &bob_token, &live)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    // Only the live envelope was admitted, so the relay holds only that one.
    let retained = state
        .test_persistence()
        .signal_relay()
        .list_for_realm(demo_realm_id())
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
            .realm_events_newest_first(demo_realm_id())
            .await
            .unwrap()
            .iter()
            .all(|record| record.kind != "ak.receipt.read"),
        "admitting a read receipt Signal mints no durable Event"
    );
}
