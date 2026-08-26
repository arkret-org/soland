//! Integration tests — federation peer API.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use soland_domain::reducer::{CircleLifecycleState, CircleProjection};
use soland_storage::RealmMetaRecord;

use super::common::*;

const PEER_SOURCE_DID: &str = "did:web:remote.example";
const PEER_SOURCE_ID: &str = "ak:did_core:web:remote.example";
const PEER_DELIVERY_FRONTIER: &str = "ak:event:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD";

fn publication_signing_key(verification_method: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&arkret_signatures::development_signing_key_seed(
        verification_method,
    ))
}

async fn seed_peer_delivery_binding(state: &AppState) {
    for verification_method in [
        format!("{PEER_SOURCE_DID}#authorization-lease-key"),
        format!("{PEER_SOURCE_DID}#notary-key"),
    ] {
        state.install_federation_peer_verification_method_key(
            None,
            &verification_method,
            publication_signing_key(&verification_method).verifying_key(),
        );
    }
    // The receiving peer has already accepted the Realm's control basis, so a
    // transported DataEvent's `seal_ref` resolves locally. Without it every
    // inbound Event is deferred as `federation_dependencies_pending` before the
    // check under test is ever reached.
    seed_test_realm_basis_seal_for_principal_server(
        state,
        test_realm_id(),
        "did:web:alice.example",
        PEER_SOURCE_ID,
    )
    .await;
    let now = Utc::now();
    let alice = fixture_actor_core_id("did:web:alice.example").to_string();
    state.test_projection().lock().members.insert(
        (test_realm_id().to_owned(), alice.clone()),
        soland_domain::reducer::SolandMembershipState {
            member: alice,
            realm_id: test_realm_id().to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("routable".to_owned()),
            recipient_service_id: Some(PEER_SOURCE_ID.to_owned()),
            recipient_service_resolution: None,
            membership_event_ref: Some(PEER_DELIVERY_FRONTIER.to_owned()),
            delivery_binding_frontier: Some(PEER_DELIVERY_FRONTIER.to_owned()),
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    // The destination binding is a Realm-wide receiver frontier, distinct
    // from Alice's exact origin authority pair. Keep a local routable member
    // on that frontier so the inbound destination is current while Alice is
    // hosted by the authenticated remote Principal Server.
    state.test_projection().lock().members.insert(
        (test_realm_id().to_owned(), "did:web:bob.example".to_owned()),
        soland_domain::reducer::SolandMembershipState {
            member: "did:web:bob.example".to_owned(),
            realm_id: test_realm_id().to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("routable".to_owned()),
            recipient_service_id: Some(service_id().to_owned()),
            recipient_service_resolution: None,
            membership_event_ref: Some(PEER_DELIVERY_FRONTIER.to_owned()),
            delivery_binding_frontier: Some(PEER_DELIVERY_FRONTIER.to_owned()),
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
}

async fn signed_event_after_current_alice_frontier(state: &AppState, fixture_label: &str) -> Value {
    let actor_records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(test_realm_id())
        .await
        .expect("demo Realm actor frontier")
        .into_iter()
        .filter(|record| record.actor_id == fixture_actor_core_id("did:web:alice.example").as_str())
        .collect::<Vec<_>>();
    let actor_seq = actor_records
        .iter()
        .map(|record| record.actor_seq)
        .max()
        .expect("demo Realm has an Alice bootstrap frontier");
    let frontier_event_ids = actor_records
        .iter()
        .filter(|record| record.actor_seq == actor_seq)
        .map(|record| record.event_id.as_str())
        .collect();
    signed_event_envelope(fixture_label, actor_seq + 1, frontier_event_ids)
}
/// Derived, never copied: the destination service id every federated request
/// addresses is this deployment's own resolved identity.
fn service_id() -> &'static str {
    static ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        soland_test_support::app_state(super::common::test_config())
            .service_id()
            .clone()
    });
    &ID
}
const DESTINATION_TRUST_DOMAIN: &str = "ak:trust_domain:soland.local";
fn test_realm_id() -> &'static str {
    demo_realm_id()
}
const TEST_CIRCLE_ID: &str = "ak:circle:ATOTi3sw4NO_6LjlHGedSYTeT3Leu2J3Tb49M1gn9cFN";

fn signed_event_envelope(event_id: &str, actor_seq: u64, prev_refs: Vec<&str>) -> Value {
    resign_federation_event(super::common::signed_event_envelope(
        event_id, actor_seq, prev_refs,
    ))
}

fn resign_federation_event(event: Value) -> Value {
    resign_federation_event_as(event, "did:web:alice.example")
}

fn resign_federation_event_as(event: Value, actor_full_id: &str) -> Value {
    let mut event: arkret_wire::Event =
        serde_json::from_value(event).expect("federation fixture is a typed Event");
    event.principal_server_id = arkret_wire::DidCoreId::new(PEER_SOURCE_ID.to_owned())
        .expect("fixture peer source is a service core ID");
    if event.seal_ref.is_some() {
        event.seal_ref = Some(
            test_realm_basis_for_principal_server(
                &soland_test_support::app_state(super::common::test_config()),
                event.realm_id.as_str(),
                actor_full_id,
                PEER_SOURCE_ID,
            )
            .seal
            .id,
        );
    }
    let verification_method = soland_test_support::signed_event::fixture_verification_method(
        actor_full_id,
        "01904100-0000-7000-8000-a11ce0000001",
    );
    let producer_seed = arkret_signatures::development_signing_key_seed(&verification_method);
    let producer_signing_key = ed25519_dalek::SigningKey::from_bytes(&producer_seed);
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        producer_seed,
        arkret_identity::verification_method_did(verification_method.as_str()).unwrap(),
        verification_method.clone(),
    );
    let created_at = event.created_at;
    event.proofs.clear();
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .expect("federation fixture signs with its development verification method");
    let mut event = event.into_event();
    let producer = event.proofs[0]
        .as_producer()
        .expect("fixture has one producer proof")
        .clone();
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &producer.jws,
            &producer
                .canonical_binding_bytes(&event.actor_id)
                .expect("fixture producer binding canonicalizes"),
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: producer_signing_key.verifying_key().as_bytes().to_vec(),
            },
        )
        .expect("fixture producer signature verifies against its admitted key");
    let admission_verification_method =
        arkret_wire::DidUrl::new(format!("{PEER_SOURCE_DID}#notary-key"))
            .expect("fixture admission verification method is a DID URL");
    let mut admission = arkret_wire::PrincipalServerAdmissionProof {
        kind: arkret_wire::PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
        verification_method: admission_verification_method.clone(),
        event_digest: producer.event_digest.clone(),
        producer_proof_digest: arkret_wire::PrincipalServerAdmissionProof::producer_proof_digest(
            &producer,
        )
        .expect("fixture producer proof digest"),
        producer_verification_method: producer.verification_method.clone(),
        producer_signing_key: arkret_wire::DidKey::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                producer_signing_key.verifying_key().as_bytes()
            )
        ))
        .expect("fixture producer signing key is a did:key"),
        producer_signer_resolution_evidence_ref: None,
        producer_signer_resolution_evidence_digest: None,
        signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:sha256:{}",
            "11".repeat(32)
        ))
        .expect("fixture signer evidence ref"),
        signer_resolution_evidence_digest: arkret_wire::Hash::new(format!(
            "sha256:{}",
            "11".repeat(32)
        ))
        .expect("fixture signer evidence digest"),
        accepted_at: event.created_at,
        jws: String::new(),
    };
    let admission_bytes = admission
        .canonical_binding_bytes()
        .expect("fixture admission binding canonicalizes");
    let admission_signing_key = publication_signing_key(admission_verification_method.as_str());
    admission.jws =
        arkret_signatures::sign_ed25519_detached_jws(&admission_signing_key, &admission_bytes)
            .expect("fixture admission detached JWS signs");
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &admission.jws,
            &admission_bytes,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: admission_signing_key.verifying_key().as_bytes().to_vec(),
            },
        )
        .expect("fixture admission signature verifies against the installed peer key");
    event.proofs.push(admission.into());
    event
        .validate_principal_server_admission_binding(arkret_canonical::DigestSuite::Sha256)
        .expect("fixture admission proof binds the accepted Event");
    serde_json::to_value(event).expect("federation fixture serializes")
}

#[test]
fn peer_events_describe_advertises_formal_surface() {
    run_on_deep_stack(
        "peer_events_describe_advertises_formal_surface",
        peer_events_describe_advertises_formal_surface_body,
    );
}

async fn peer_events_describe_advertises_formal_surface_body() {
    let state = soland_test_support::app_state(test_config());
    let describe: Value = TestClient::query("http://server/_arkret/peer/events/describe")
        .json(&serde_json::json!({}))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["primary_write_path"], "/_arkret/peer/events");
    let operations = describe["supported_operations"].as_array().unwrap();
    assert!(
        operations
            .iter()
            .any(|op| op == "ak.peer.events.command.submit")
    );
    assert!(operations.iter().any(|op| op == "ak.peer.events.read.scan"));
    assert!(
        operations
            .iter()
            .any(|op| op == "ak.peer.events.read.frontier")
    );
    // `ak.peer.snapshot.read.manifest_head` MUST NOT be declared while soland cannot
    // produce a signed ak.schema.snapshot.v1 manifest; the endpoint
    // answers `not_implemented` instead (service-surface.md §5.2).
    assert!(
        !operations
            .iter()
            .any(|op| op == "ak.peer.snapshot.read.manifest_head")
    );
}

#[test]
fn peer_events_query_and_frontier_use_peer_surface() {
    run_on_deep_stack(
        "peer_events_query_and_frontier_use_peer_surface",
        peer_events_query_and_frontier_use_peer_surface_body,
    );
}

async fn peer_events_query_and_frontier_use_peer_surface_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_read_authorization(&state, PEER_SOURCE_ID, "did:web:alice.example").await;
    let mut event = signed_event_envelope(
        "ak:event:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD",
        1,
        Vec::new(),
    );
    let created_at = Utc::now();
    event["created_at"] =
        serde_json::json!(arkret_canonical::format_timestamp_canonical(created_at));
    event = resign_federation_event(event);
    let expected_event_id = authored_event_id(&event).to_owned();
    put_event_record(&state, event, created_at).await;

    let read_body = serde_json::json!({
        "filters": {"kind": "ak.message.create"},
        "realms": [test_realm_id()]
    });
    let query_target = "https://server.test/_arkret/peer/events";
    let mut query = TestClient::query(query_target).json(&read_body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        query_target,
        &read_body,
    ) {
        query = query.add_header(name, value, true);
    }
    let page: Value = query
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        page["events"]
            .as_array()
            .unwrap_or_else(|| panic!("peer query response has no events array: {page:?}"))
            .len(),
        1,
        "{page:?}"
    );
    let returned_event_id = page["events"][0]["event_id"]
        .as_str()
        .or_else(|| page["events"][0]["event"]["event_id"].as_str());
    assert_eq!(
        returned_event_id,
        Some(expected_event_id.as_str()),
        "{page:?}"
    );
    assert!(!page["has_more"].as_bool().unwrap_or(false), "{page:?}");

    let frontier_target = "https://server.test/_arkret/peer/events/frontier";
    let frontier_body = serde_json::json!({"realm_id": test_realm_id()});
    let mut frontier = TestClient::query(frontier_target).json(&frontier_body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        frontier_target,
        &frontier_body,
    ) {
        frontier = frontier.add_header(name, value, true);
    }
    let mut frontier_response = frontier.send(&app_from_state(state)).await;
    let frontier_status = frontier_response.status_code;
    let frontier: Value = frontier_response.take_json().await.unwrap();
    assert_eq!(
        frontier_status,
        Some(StatusCode::OK),
        "peer frontier response: {frontier}"
    );
    assert_eq!(frontier["realm_id"], test_realm_id(), "{frontier}");
    assert!(
        frontier["heads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|head| head == expected_event_id.as_str())
    );
    assert!(
        frontier["frontier_root"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(frontier["issuer"], service_id());
    assert_eq!(frontier["signature"]["scheme"], "ed25519-detached-jws");
    assert_eq!(
        frontier["signature"]["signed_payload"]["frontier_root"],
        frontier["frontier_root"]
    );
}

#[test]
fn peer_events_query_rejects_malformed_cursor_with_invalid_cursor_reason() {
    run_on_deep_stack(
        "peer_events_query_rejects_malformed_cursor_with_invalid_cursor_reason",
        peer_events_query_rejects_malformed_cursor_with_invalid_cursor_reason_body,
    );
}

async fn peer_events_query_rejects_malformed_cursor_with_invalid_cursor_reason_body() {
    // encoding.md §8.3 closed set on the federation read path
    // (`ak.peer.events.read.scan`): an `ak:cursor:`-prefixed token that fails
    // base64url/JSON/schema decoding MUST return top-level `param_invalid`
    // with reason `invalid_cursor`.
    let state = soland_test_support::app_state(test_config());
    seed_peer_read_authorization(&state, PEER_SOURCE_ID, "did:web:alice.example").await;

    let read_body = serde_json::json!({
        "realms": [test_realm_id()],
        "after": "ak:cursor:!!!not-base64url"
    });
    let query_target = "https://server.test/_arkret/peer/events";
    let mut query = TestClient::query(query_target).json(&read_body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        query_target,
        &read_body,
    ) {
        query = query.add_header(name, value, true);
    }
    let mut rejected = query.send(&app_from_state(state)).await;
    assert_eq!(rejected.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = rejected.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "param_invalid", "{body}");
    assert_eq!(
        body["error"]["details"]["reason_code"], "invalid_cursor",
        "{body}"
    );
}

#[test]
fn peer_events_submit_quarantines_actor_seq_sibling_overflow() {
    run_on_deep_stack(
        "peer_events_submit_quarantines_actor_seq_sibling_overflow",
        peer_events_submit_quarantines_actor_seq_sibling_overflow_body,
    );
}

async fn peer_events_submit_quarantines_actor_seq_sibling_overflow_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    let now = Utc::now();
    let predecessor = signed_event_envelope(
        "ak:event:AXx4wC556lXwN4bfK5rMlo6C9Jkdc_q-uTB7ttoKni5M",
        40,
        Vec::new(),
    );
    let predecessor_id = authored_event_id(&predecessor).to_owned();
    put_event_record(&state, predecessor, now - ChronoDuration::seconds(1)).await;
    for idx in 0..16 {
        let event_label = format!("federation-sibling-{idx}");
        let event = signed_event_envelope(&event_label, 41, vec![predecessor_id.as_str()]);
        put_event_record(&state, event, now + ChronoDuration::seconds(idx)).await;
    }

    let overflow = signed_event_envelope(
        "ak:event:AYdYa0NMjToIRBeXdzUM2JL5LmKocV8srALm6U4sos5w",
        41,
        vec![predecessor_id.as_str()],
    );
    let overflow_id = authored_event_id(&overflow).to_owned();
    let body = peer_submit_body(&overflow);
    let target = "https://server.test/_arkret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        target,
        &body,
    ) {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "partial", "{outcome:?}");
    assert_eq!(
        outcome["quarantine"],
        serde_json::json!([overflow_id]),
        "{outcome:?}"
    );
    assert!(outcome["rejected"].as_array().is_none_or(Vec::is_empty));
    assert!(
        state
            .test_persistence()
            .events()
            .get(&overflow_id)
            .await
            .unwrap()
            .is_none(),
        "quarantined sibling must not advance accepted event storage"
    );
}

#[test]
fn peer_events_submit_verifies_digest_against_the_received_wire_body() {
    run_on_deep_stack(
        "peer_events_submit_verifies_digest_against_the_received_wire_body",
        peer_events_submit_verifies_digest_against_the_received_wire_body_body,
    );
}

async fn peer_events_submit_verifies_digest_against_the_received_wire_body_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    let event = signed_event_after_current_alice_frontier(
        &state,
        "ak:event:AaFr4C2IJ5G05kC7Vl1e-d6hWLhI-zf6AZe1lQFN4cvc",
    )
    .await;
    let mut body = peer_submit_body(&event);
    body["events"][0]["event"]["unsigned"] = serde_json::json!({});

    // Event's typed serializer intentionally omits an empty `unsigned` map.
    // The HTTP signature nevertheless binds the exact canonical wire body,
    // so verification must happen before any typed serde normalization.
    let target = "https://server.test/_arkret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        target,
        &body,
    ) {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(outcome["status"], "accepted", "{outcome:?}");
    assert_eq!(outcome["accepted"][0], event["event_id"]);
    assert!(
        outcome.get("error").is_none(),
        "wire digest verification must not produce a top-level error: {outcome:?}"
    );
}

#[test]
fn peer_events_submit_accepts_online_event_without_offline_evidence() {
    run_on_deep_stack(
        "peer_events_submit_accepts_online_event_without_offline_evidence",
        peer_events_submit_accepts_online_event_without_offline_evidence_body,
    );
}

async fn peer_events_submit_accepts_online_event_without_offline_evidence_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    let event = signed_event_after_current_alice_frontier(
        &state,
        "ak:event:AUUkvj_F0wukYtvsEeUOQ7O3tCgjDXllP-2iVm3-4JpR",
    )
    .await;
    let mut body = peer_submit_body(&event);
    body["events"][0]
        .as_object_mut()
        .expect("federation submission")
        .remove("authorization_lease");
    body["events"][0]["ingress_receipts"] = serde_json::json!([]);

    let target = "https://server.test/_arkret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        target,
        &body,
    ) {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(outcome["status"], "accepted", "{outcome:?}");
    assert_eq!(outcome["accepted"][0], event["event_id"]);
}

#[test]
fn peer_events_frontier_exposes_current_sibling_heads() {
    run_on_deep_stack(
        "peer_events_frontier_exposes_current_sibling_heads",
        peer_events_frontier_exposes_current_sibling_heads_body,
    );
}

async fn peer_events_frontier_exposes_current_sibling_heads_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_read_authorization(&state, PEER_SOURCE_ID, "did:web:alice.example").await;
    let now = Utc::now();
    let mut expected_heads = Vec::new();
    for (idx, event_id) in [
        "ak:event:AZTNb6kCXn_8MiH9ew5d3ugUByYbTtI5RHFLWIvmeYK0",
        "ak:event:AXGDvPdO4b3s6WgtLTBVjuLATST_xdBnM02TPZ_YJfhf",
    ]
    .iter()
    .enumerate()
    {
        let event = signed_event_envelope(event_id, 42, Vec::new());
        expected_heads.push(authored_event_id(&event).to_owned());
        put_event_record(&state, event, now + ChronoDuration::seconds(idx as i64)).await;
    }

    let frontier_target = "https://server.test/_arkret/peer/events/frontier";
    let frontier_body = serde_json::json!({"realm_id": test_realm_id()});
    let mut frontier = TestClient::query(frontier_target).json(&frontier_body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        frontier_target,
        &frontier_body,
    ) {
        frontier = frontier.add_header(name, value, true);
    }
    let frontier: Value = frontier
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let heads = frontier["heads"].as_array().unwrap();
    for expected_head in expected_heads {
        assert!(
            heads.iter().any(|head| head == expected_head.as_str()),
            "{frontier:?}"
        );
    }
    assert_eq!(
        frontier["actor_seq_upper_bounds"][fixture_actor_core_id("did:web:alice.example").as_str()],
        42
    );
}

#[test]
fn peer_seal_frontier_returns_typed_frontier_with_service_proof() {
    run_on_deep_stack(
        "peer_seal_frontier_returns_typed_frontier_with_service_proof",
        peer_seal_frontier_returns_typed_frontier_with_service_proof_body,
    );
}

async fn peer_seal_frontier_returns_typed_frontier_with_service_proof_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_read_authorization(&state, PEER_SOURCE_ID, "did:web:alice.example").await;
    seed_test_realm_basis_seal(&state, test_realm_id(), "did:web:alice.example").await;

    let target = "https://server.test/_arkret/peer/seals/frontier";
    let body = serde_json::json!({"realm_id": test_realm_id()});
    let mut request = TestClient::query(target).json(&body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        target,
        &body,
    ) {
        request = request.add_header(name, value, true);
    }
    let mut response = request.send(&app_from_state(state)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let value: Value = response.take_json().await.unwrap();
    let typed: arkret_models_collaboration::event_sync::PeerSealFrontierState =
        serde_json::from_value(value.clone())
            .unwrap_or_else(|error| panic!("typed peer Seal frontier: {error}; {value}"));
    assert_eq!(typed.frontier.realm_id.as_str(), test_realm_id());
    assert!(typed.frontier.sole_leaf().is_ok());
    assert_eq!(
        typed.service_proof.kind,
        arkret_wire::proof_kind::DETACHED_JWS
    );
    assert!(
        typed
            .service_proof
            .payload_digest
            .as_str()
            .starts_with("sha256:")
    );
    typed.service_proof.validate_production().unwrap();
}

/// SOL-02-007 - the federation submit path MUST bind the envelope actor to
/// the authenticated source service authority. An actor hosted elsewhere and
/// not known as a member of the binding Realm is rejected before any session
/// is constructed.
#[test]
fn peer_events_submit_rejects_actor_outside_source_trust_domain() {
    run_on_deep_stack(
        "peer_events_submit_rejects_actor_outside_source_trust_domain",
        peer_events_submit_rejects_actor_outside_source_trust_domain_body,
    );
}

async fn peer_events_submit_rejects_actor_outside_source_trust_domain_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    let mut event = signed_event_envelope(
        "ak:event:AT0-O1Lz_4TR4jP-WqsC73_oH0Y7LB2vuZS-dmyhifFh",
        1,
        Vec::new(),
    );
    // Re-author the envelope as an actor that is neither hosted by the source
    // service authority nor a member of the demo Realm's membership index.
    event["actor_id"] = serde_json::json!(fixture_actor_core_id("did:web:intruder.evil").as_str());
    event = resign_federation_event_as(event, "did:web:intruder.evil");
    let body = peer_submit_body(&event);
    let target = "https://server.test/_arkret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        target,
        &body,
    ) {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "partial");
    assert!(outcome["accepted"].as_array().unwrap().is_empty());
    let rejected = outcome["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["reason_code"], "capability_denied");
    assert!(
        rejected[0]["detail"]
            .as_str()
            .unwrap()
            .contains("source service authority")
    );
}

/// SOL-02-007 — counterpart positive path: a known member of the binding
/// Realm may be relayed by a foreign source domain (identity is still
/// re-verified by the downstream proof chain).
#[test]
fn peer_events_submit_accepts_known_member_relayed_by_foreign_domain() {
    run_on_deep_stack(
        "peer_events_submit_accepts_known_member_relayed_by_foreign_domain",
        peer_events_submit_accepts_known_member_relayed_by_foreign_domain_body,
    );
}

async fn peer_events_submit_accepts_known_member_relayed_by_foreign_domain_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    // encryption-and-audit.md §2: this fixture submits plaintext, so the
    // Realm must explicitly authorize the receiving service to see it. This
    // keeps the assertion focused on foreign-domain member relay acceptance.
    authorize_test_plaintext_message_service(&state, "did:web:alice.example", test_realm_id())
        .await;
    // `did:web:alice.example` is seeded into the demo Realm's membership
    // index; the source domain is `remote.example` (mismatched home), so
    // acceptance exercises the membership-index path.
    let event = signed_event_after_current_alice_frontier(
        &state,
        "ak:event:ASkcnN1egiqz3y15yuMqvitL8ME5emS4-XyB0b7zzseO",
    )
    .await;
    let body = peer_submit_body(&event);
    let target = "https://server.test/_arkret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        target,
        &body,
    ) {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "accepted", "{outcome:?}");
}

#[test]
fn peer_events_submit_preflights_poll_prerequisites_before_durable_acceptance() {
    run_on_deep_stack(
        "peer_events_submit_preflights_poll_prerequisites_before_durable_acceptance",
        peer_events_submit_preflights_poll_prerequisites_before_durable_acceptance_body,
    );
}

async fn peer_events_submit_preflights_poll_prerequisites_before_durable_acceptance_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    authorize_test_plaintext_message_service(&state, "did:web:alice.example", test_realm_id())
        .await;

    let missing_poll_ref = soland_test_support::fixture_content_bound_id("ak:message:");
    let mut out_of_order_response = signed_event_after_current_alice_frontier(
        &state,
        "ak:event:AZfzSfQ4D0yWWnbLzkTmEgHV7LuLoUTQZ4YeVDMIX5Ey",
    )
    .await;
    out_of_order_response["payload"]["content"] = serde_json::json!({
        "kind": "ak.content.poll.response",
        "body": "response before Poll prerequisite",
        "poll_response": {
            "poll_ref": missing_poll_ref,
            "selections": ["now"]
        }
    });
    let out_of_order_response = resign_federation_event(out_of_order_response);
    let rejected_event_id = authored_event_id(&out_of_order_response).to_owned();
    let rejected = submit_peer_event(state.clone(), &out_of_order_response).await;
    assert_eq!(rejected["status"], "partial", "{rejected:?}");
    assert!(
        rejected["accepted"].as_array().is_some_and(Vec::is_empty),
        "out-of-order Poll response was accepted: {rejected:?}"
    );
    assert!(
        rejected.to_string().contains("poll_ref_unknown"),
        "federation Poll prerequisite rejection was not surfaced: {rejected:?}"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .realm_events_newest_first(test_realm_id())
            .await
            .expect("canonical federated Realm Event log")
            .iter()
            .all(|record| record.event_id.as_str() != rejected_event_id.as_str()),
        "out-of-order federated Poll response was durably written"
    );

    let mut poll = signed_event_after_current_alice_frontier(
        &state,
        "ak:event:Ac5IXRYjBUHgxuJBt2sIyfVAJSUF8o2btX3LI3t2pd2s",
    )
    .await;
    poll["payload"]["content"] = serde_json::json!({
        "kind": "ak.content.poll",
        "body": "Which window?",
        "poll": {
            "kind": "disclosed",
            "max_selections": 1,
            "answers": [
                {"id": "now", "text": {"kind": "ak.content.text", "body": "Now"}},
                {"id": "backup", "text": {"kind": "ak.content.text", "body": "After backup"}}
            ]
        }
    });
    let poll = resign_federation_event(poll);
    let poll_event_id = authored_event_id(&poll).to_owned();
    let poll_ref = poll_event_id.replacen("ak:event:", "ak:message:", 1);
    let poll_outcome = submit_peer_event(state.clone(), &poll).await;
    assert_eq!(poll_outcome["status"], "accepted", "{poll_outcome:?}");

    let mut response = signed_event_after_current_alice_frontier(
        &state,
        "ak:event:Ae7kT0W9KeHJdyYZjMC7uxjDEiW_cXdh-oHBqm6RYNnA",
    )
    .await;
    response["payload"]["content"] = serde_json::json!({
        "kind": "ak.content.poll.response",
        "body": "response after Poll prerequisite",
        "poll_response": {
            "poll_ref": poll_ref,
            "selections": ["now"]
        }
    });
    let response = resign_federation_event(response);
    let response_outcome = submit_peer_event(state.clone(), &response).await;
    assert_eq!(
        response_outcome["status"], "accepted",
        "valid Poll successor was rejected after its prerequisite: {response_outcome:?}"
    );
    assert!(
        state
            .test_projection()
            .lock()
            .poll(&poll_ref)
            .is_some_and(|poll_state| {
                poll_state.votes.iter().any(|(actor, vote)| {
                    actor == fixture_actor_core_id("did:web:alice.example").as_str()
                        && vote.selections == BTreeSet::from(["now".to_owned()])
                })
            }),
        "accepted federated Poll successor did not fold into PollState"
    );
}

#[test]
fn peer_events_submit_rejects_mls_welcome_without_peer_profile_declaration() {
    run_on_deep_stack(
        "peer_events_submit_rejects_mls_welcome_without_peer_profile_declaration",
        peer_events_submit_rejects_mls_welcome_without_peer_profile_declaration_body,
    );
}

async fn peer_events_submit_rejects_mls_welcome_without_peer_profile_declaration_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_delivery_binding(&state).await;
    let welcome_event_id = "ak:event:AeKCyaUbw70FHlzkWyBOZi9ZQYsRpG1NIAp9Yjv7Tofa";
    let welcome_event = event_envelope(
        welcome_event_id,
        arkret_wire::EventKind::MlsWelcome.as_str(),
        "did:web:alice.example",
        1,
        mls_welcome_payload(),
    );
    let outcome = submit_peer_event(state.clone(), &welcome_event).await;
    assert_eq!(outcome["status"], "partial", "{outcome:?}");
    assert!(outcome["accepted"].as_array().unwrap().is_empty());
    let rejected = outcome["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["id"], authored_event_id(&welcome_event));
    assert_eq!(rejected[0]["reason_code"], "unsupported_profile");
    assert!(
        rejected[0]["detail"]
            .as_str()
            .unwrap()
            .contains("ak.profile.mls_governance_binding.full.v1"),
        "{outcome:?}"
    );
    assert_eq!(
        state
            .test_persistence()
            .mls_welcomes()
            .snapshot_all()
            .await
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn peer_events_query_clips_circle_event_outside_source_did_member_scope() {
    run_on_deep_stack(
        "peer_events_query_clips_circle_event_outside_source_did_member_scope",
        peer_events_query_clips_circle_event_outside_source_did_member_scope_body,
    );
}

async fn peer_events_query_clips_circle_event_outside_source_did_member_scope_body() {
    let state = soland_test_support::app_state(test_config());
    seed_peer_read_authorization(&state, PEER_SOURCE_ID, "did:web:bob.example").await;
    install_test_circle(&state, TEST_CIRCLE_ID, &["did:web:alice.example"]);
    let now = Utc::now();
    put_event_record(
        &state,
        circle_member_event(
            "ak:event:Ad7f3cOvc0wjqfwCNqjzg1buJv4mBMlocci9EX51zRIJ",
            "did:web:alice.example",
            "did:web:admin.example",
            31,
        ),
        now - ChronoDuration::seconds(20),
    )
    .await;
    let hidden_event_id = "ak:event:ATq9Ua5Klw2I-KCZo-6gt8LNi-Z31nyaZaZVZI1sMp5X";
    let mut event = signed_event_envelope(hidden_event_id, 32, Vec::new());
    event["actor_id"] = serde_json::json!(fixture_actor_core_id("did:web:alice.example").as_str());
    // The Circle security scope of a message is the producer-SIGNED
    // `scope_ref` (`conformance/encoding.md` §6, and the spec's
    // `circle-scope-fixture.json`: message payloads carry no `scope_circle_id`
    // fragment and "still sign Event.scope_ref"). The reducer-managed
    // `effective_scope` this fixture used to stamp on the envelope is not an
    // Event member at all in v1 — it exists only on object read projections.
    event["scope_ref"] = serde_json::json!({
        "kind": "circle",
        "realm_id": test_realm_id(),
        "circle_id": TEST_CIRCLE_ID
    });
    event["created_at"] = serde_json::json!(arkret_canonical::format_timestamp_canonical(
        now - ChronoDuration::seconds(5)
    ));
    event = resign_federation_event(event);
    put_event_record(&state, event, now - ChronoDuration::seconds(10)).await;

    let query_target = "https://server.test/_arkret/peer/events";
    let query_body = serde_json::json!({
        "filters": {"kind": "ak.message.create"},
        "realms": [test_realm_id()]
    });
    let mut query = TestClient::query(query_target).json(&query_body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        query_target,
        &query_body,
    ) {
        query = query.add_header(name, value, true);
    }
    let page: Value = query
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        page["events"].as_array().unwrap().len(),
        0,
        "source service represents Bob only, so Alice's Circle event is outside its read scope: {page:?}"
    );

    let resolve_target = "https://server.test/_arkret/peer/events/resolve";
    // `PeerEventsResolveRequestBody` requires `realm_id`: every selector is
    // scoped to exactly one Realm, so a body without it is not a resolve
    // request at all.
    let resolve_body = serde_json::json!({
        "realm_id": test_realm_id(),
        "event_ids": [hidden_event_id],
        "include_payload": true
    });
    let mut resolve = TestClient::query(resolve_target).json(&resolve_body);
    for (name, value) in signed_federation_query_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        resolve_target,
        &resolve_body,
    ) {
        resolve = resolve.add_header(name, value, true);
    }
    let resolved: Value = resolve
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resolved["events"].as_array().map(Vec::len),
        Some(0),
        "{resolved:?}"
    );
    // `PeerEventsResolveOutcome` keeps typed missing buckets: a nonexistent
    // and an undisclosable selector share `missing_event_ids` so the two stay
    // externally indistinguishable.
    assert_eq!(
        resolved["missing_event_ids"],
        serde_json::json!([hidden_event_id]),
        "{resolved:?}"
    );
}

#[test]
fn self_events_reject_federation_wire() {
    run_on_deep_stack(
        "self_events_reject_federation_wire",
        self_events_reject_federation_wire_body,
    );
}

async fn self_events_reject_federation_wire_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let event = signed_event_envelope(
        "ak:event:AQd34fkc56QClbcsMLcGqGKn_XfLiFA9oRBGKndePHYG",
        1,
        Vec::new(),
    );
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&peer_submit_body(&event))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "schema_violation");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("/_arkret/peer/events"),
        "{body:?}"
    );
}

/// Wrap `event` in the publication evidence a federation submission transports.
///
/// `offline-publication.md` §2.1 — a peer never forwards a bare envelope: the
/// Event travels with the basis-bound `authorization_lease` it was first
/// published under and the `ingress_receipt` the origin service signed for that
/// exact digest inside the lease window. The receiving peer stores that evidence
/// verbatim instead of re-stamping `received_at`, which is what keeps a fixed
/// revocation window from being silently widened.
fn peer_event_submission(event: &Value) -> arkret_wire::EventFederationSubmission {
    let event: arkret_wire::Event =
        serde_json::from_value(event.clone()).expect("federation fixture is a typed Event");
    let event_digest = arkret_identifiers::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .expect("fixture Event digest"),
    )
    .expect("fixture Event digest is a Hash");
    // The lease window has to contain the moment the origin ingress signed its
    // receipt, so both are anchored on one instant here.
    let issued_at = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
        .expect("fixture publication instant");
    let action = event.kind.as_str().to_owned();
    let risk_tier = arkret_schema::capability_action(&action).map_or(
        arkret_wire::RiskTier::High,
        |descriptor| match descriptor.risk_tier {
            arkret_schema::CapabilityRiskTier::Low => arkret_wire::RiskTier::Low,
            arkret_schema::CapabilityRiskTier::Medium => arkret_wire::RiskTier::Medium,
            arkret_schema::CapabilityRiskTier::High => arkret_wire::RiskTier::High,
        },
    );
    let lease_basis = if let Some(seal_ref) = event.seal_ref.clone() {
        arkret_wire::offline_publication::LeaseBasisRef::Seal(seal_ref)
    } else if let Some(seal_basis) = event.seal_basis.clone() {
        arkret_wire::offline_publication::LeaseBasisRef::Joined(seal_basis)
    } else {
        panic!("federation fixture Event has no publication basis")
    };
    let lease_basis_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&lease_basis).expect("fixture lease basis digest"),
    )
    .unwrap();
    let authority_set_policy = arkret_wire::AuthoritySetPolicy {
        schema: arkret_wire::SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: arkret_wire::AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: event.scope_ref.clone(),
        source: arkret_wire::AuthoritySetPolicySource {
            source_kind: arkret_wire::AuthoritySetSourceKind::RealmControl,
            source_ref: test_cited_basis_seal(&event).id.as_str().to_owned(),
            source_digest: lease_basis_digest,
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![arkret_wire::AuthoritySetAuthorizationRule {
            rule_id: "realm_admission".to_owned(),
            issuer_role: arkret_wire::AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec![action.clone()],
            issuers: vec![arkret_wire::AuthoritySetIssuer {
                verification_method: arkret_wire::DidUrl::new(format!(
                    "{PEER_SOURCE_DID}#authorization-lease-key"
                ))
                .unwrap(),
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = arkret_wire::offline_publication::AuthoritySetRef {
        authority_set_id: authority_set_policy.authority_set_id.clone(),
        authority_set_digest: authority_set_policy
            .digest()
            .expect("fixture authority-set policy digest"),
    };
    let mut lease = arkret_wire::offline_publication::AuthorizationLease {
        authorization_lease_id: arkret_identifiers::AuthorizationLeaseId::new(
            "ak:authorization_lease:01904100-0000-7000-8000-fede1ea5e001",
        )
        .unwrap(),
        basis_ref: lease_basis,
        actor_id: event.actor_id.clone(),
        device_id: arkret_identifiers::DeviceId::new(
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .unwrap(),
        scope_ref: event.scope_ref.clone(),
        action,
        authorization_rule_id: "realm_admission".to_owned(),
        risk_tier,
        issued_at,
        expires_at: issued_at
            + if risk_tier == arkret_wire::RiskTier::High {
                ChronoDuration::minutes(30)
            } else {
                ChronoDuration::hours(4)
            },
        authority_set_ref: authority_set_ref.clone(),
        authority_set_policy,
        proofs: Vec::new(),
    };
    lease.proofs = vec![publication_proof(
        &format!("{PEER_SOURCE_DID}#authorization-lease-key"),
        lease.lease_digest().expect("fixture lease digest"),
        issued_at,
    )];
    let lease_binding = lease
        .proof_binding_bytes(&lease.proofs[0])
        .expect("fixture lease proof binding");
    lease.proofs[0].jws = arkret_signatures::jws::sign_jws_ed25519(
        &lease_binding,
        &publication_signing_key(&lease.proofs[0].verification_method),
    )
    .expect("fixture lease proof signature");
    let mut receipt = arkret_wire::offline_publication::IngressReceipt {
        receipt_id: arkret_identifiers::ReceiptId::new(
            "ak:receipt:01904100-0000-7000-8000-fede4ece17e1",
        )
        .unwrap(),
        event_digest: event_digest.clone(),
        authorization_lease_id: lease.authorization_lease_id.clone(),
        qualified_ingress_id: arkret_identifiers::DidFullId::new(PEER_SOURCE_DID.to_owned())
            .unwrap(),
        received_at: issued_at,
        ingress_basis: lease.basis_ref.clone(),
        ingress_frontier: vec![event.event_id.clone()],
        service_id: arkret_wire::project_full_id_to_core_id(
            &arkret_identifiers::DidFullId::new(PEER_SOURCE_DID.to_owned()).unwrap(),
        )
        .unwrap(),
        authority_set_ref: authority_set_ref.clone(),
        proofs: Vec::new(),
    };
    receipt.proofs = vec![publication_proof(
        &format!("{PEER_SOURCE_DID}#authorization-lease-key"),
        receipt.receipt_digest().expect("fixture receipt digest"),
        issued_at,
    )];
    let receipt_binding = receipt
        .proof_binding_bytes(&receipt.proofs[0])
        .expect("fixture ingress receipt proof binding");
    receipt.proofs[0].jws = arkret_signatures::jws::sign_jws_ed25519(
        &receipt_binding,
        &publication_signing_key(&receipt.proofs[0].verification_method),
    )
    .expect("fixture ingress receipt signature");
    let control_proposal_ack = event.seal_basis.as_ref().map(|_| {
        let policy = arkret_wire::ControlProposalDecisionPolicy::default();
        let authority_set_digest = authority_set_ref.authority_set_digest.clone();
        let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
            realm_id: event.realm_id.clone(),
            proposal_digest: event_digest.clone(),
            received_at: issued_at,
            decision_due_at: issued_at + policy.decision_window,
            absolute_due_at: issued_at + policy.absolute_horizon,
            authority_set_ref: authority_set_digest.clone(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new(format!(
                    "{PEER_SOURCE_DID}#notary-key"
                ))
                .unwrap(),
                payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: issued_at,
                jws: "a..b".to_owned(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack
            .authority_ack_digest()
            .expect("fixture proposal authority Ack digest");
        arkret_wire::ControlProposalAck {
            kind: arkret_wire::ControlProposalAckKind::SignedAck,
            realm_id: event.realm_id.clone(),
            proposal_digest: event_digest,
            received_at: issued_at,
            decision_due_at: issued_at + policy.decision_window,
            absolute_due_at: issued_at + policy.absolute_horizon,
            defer_count: 0,
            authority_set_ref: authority_set_digest,
            authority_acks: vec![authority_ack],
        }
    });
    arkret_wire::EventFederationSubmission {
        event,
        authorization_lease: Some(lease),
        ingress_receipts: vec![receipt],
        control_proposal_ack,
        membership_compensation_evidence: None,
    }
}

/// One issuer proof over a lease or receipt digest.
///
/// `payload_digest` is the object with `proofs` removed, and `created_at` MUST
/// equal `issued_at` / `received_at` verbatim — that equality is the revocation
/// boundary, not a formatting detail.
fn publication_proof(
    verification_method: &str,
    payload_digest: arkret_identifiers::Hash,
    created_at: DateTime<Utc>,
) -> arkret_wire::primitives::PayloadProof {
    arkret_wire::primitives::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(verification_method.to_owned()).unwrap(),
        payload_digest,
        created_at,
        domain: None,
        audience: Some(arkret_wire::Audience::Single(PEER_SOURCE_DID.to_owned())),
        proof_purpose: None,
        jws: "a..b".to_owned(),
    }
}

fn peer_submit_body(event: &Value) -> Value {
    let event_id = event["event_id"].as_str().unwrap().to_owned();
    let event_digest = event_canonical_digest(event);
    let typed_event: arkret_wire::Event =
        serde_json::from_value(event.clone()).expect("federation fixture is a typed Event");
    let basis_seal = test_cited_basis_seal(&typed_event);
    let binding_payload = serde_json::json!({
        "domain": "ak.peer.events.command.submit.service_binding.v1",
        "realm_id": test_realm_id(),
        "event_id": &event_id,
        "canonical_digest": &event_digest,
    });
    let body = arkret_models_collaboration::event_sync::EventsSubmitFederationBatchRequestBody {
        service_binding_ref: arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: arkret_identifiers::RealmId::new(test_realm_id().to_owned()).unwrap(),
            realm_policy_digest: arkret_identifiers::Hash::new(sha256_json(&binding_payload))
                .unwrap(),
            membership_frontier: vec![arkret_wire::EventId::new(event_id).unwrap()],
            delivery_binding_frontier: vec![
                arkret_wire::EventId::new(PEER_DELIVERY_FRONTIER.to_owned()).unwrap(),
            ],
            destination_service_kind: "principal_server".to_owned(),
        },
        events: vec![peer_event_submission(event)],
        // The DataEvent's `seal_ref` is a receiver-side prerequisite: a peer
        // that has not accepted that Seal cannot resolve the authorization
        // pre-state. `event-auth-state-resolution.md` §8 disclosure travels in
        // the bundle, reachable from the transported Event's basis, never as a
        // bare `seals[]` rail.
        cba_proof_bundles: vec![arkret_wire::CbaProofBundle {
            target_seal_ref: basis_seal.id.clone(),
            seals: vec![basis_seal],
            control_moves: Vec::new(),
            inclusion_proofs: Vec::new(),
            availability_proofs: Vec::new(),
        }],
    };
    serde_json::to_value(body).expect("federation submit body serializes")
}

async fn submit_peer_event(state: AppState, event: &Value) -> Value {
    let body = peer_submit_body(event);
    let target = format!(
        "{}/_arkret/peer/events",
        state.config().public_base_url.trim_end_matches('/')
    );
    let mut submit = TestClient::post(&target).json(&body);
    for (name, value) in signed_federation_push_headers(
        PEER_SOURCE_DID,
        service_id(),
        DESTINATION_TRUST_DOMAIN,
        &target,
        &body,
    ) {
        submit = submit.add_header(name, value, true);
    }
    submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap()
}

async fn seed_peer_read_authorization(state: &AppState, source_service_id: &str, member_did: &str) {
    let now = Utc::now() - ChronoDuration::seconds(60);
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(test_realm_id())
        .await
        .unwrap()
        .unwrap_or_else(|| RealmMetaRecord {
            owner: "did:web:alice.example".to_owned(),
            deleted: false,
            discoverability: "public".to_owned(),
            history_access: "all_history_for_current_members".to_owned(),
            preview_policy: None,
            preview_policy_digest: None,
            asset_privacy_policy: None,
            asset_privacy_policy_digest: None,
            encryption_profile: None,
            plaintext_visible_services: BTreeSet::new(),
            plaintext_visible_service_classes: Default::default(),
            minimal_metadata_realm: false,
            created_at: now,
            updated_at: now,
        });
    meta.plaintext_visible_services
        .insert(source_service_id.to_owned());
    meta.plaintext_visible_service_classes
        .entry(source_service_id.to_owned())
        .or_default()
        .insert(arkret_wire::PlaintextDataClassKind::MessageContent);
    meta.updated_at = now;
    state
        .test_persistence()
        .realm_meta()
        .put(test_realm_id(), &meta)
        .await
        .unwrap();
    put_event_record(
        state,
        member_binding_event(
            "ak:event:AWOy3SEshibYHuXWgX09nbOW8yvqtRV769ZsokfmH7Ao",
            member_did,
            source_service_id,
            21,
        ),
        now + ChronoDuration::seconds(1),
    )
    .await;
}

fn member_binding_event(
    event_id: &str,
    member_did: &str,
    source_service_id: &str,
    seq: u64,
) -> Value {
    let payload = serde_json::json!({
        "actor_id": member_did,
        "membership": "join",
        "role": "member",
        "delivery_status": "routable",
        "delivery_binding": {
            "recipient_service_id": source_service_id,
            "binding_source": "explicit",
            "delivery_binding_frontier": "ak:frontier:peer-read-test"
        }
    });
    event_envelope(
        event_id,
        "ak.member.state",
        "did:web:admin.example",
        seq,
        payload,
    )
}

fn circle_member_event(event_id: &str, member_did: &str, sender: &str, seq: u64) -> Value {
    let payload = serde_json::json!({
        "circle_id": TEST_CIRCLE_ID,
        "actor": member_did,
        "state": "active",
        "sender": sender,
        "manage_capability_verified": true
    });
    event_envelope(event_id, "ak.circle.member.state", sender, seq, payload)
}

fn mls_welcome_payload() -> Value {
    arkret_schema::embedded_json_artifact("fixtures/keypackage-pairwise-welcome-fixture.json")
        .expect("embedded pairwise Welcome fixture")["schema_validation_cases"][0]["instance"]
        .clone()
}

fn event_envelope(
    event_id: &str,
    kind: &str,
    actor_id: &str,
    actor_seq: u64,
    payload: Value,
) -> Value {
    resign_federation_event(signed_canonical_event(
        event_id,
        kind,
        actor_id,
        "01904100-0000-7000-8000-a11ce0000001",
        test_realm_id(),
        actor_seq,
        Vec::new(),
        payload,
    ))
}

async fn put_event_record(state: &AppState, event: Value, received_at: DateTime<Utc>) {
    // Realm genesis omits `realm_id` on the wire because the resolved Realm id
    // is event-derived; the persistence fixture still needs that resolved key.
    let realm_id = event["realm_id"]
        .as_str()
        .unwrap_or(test_realm_id())
        .to_owned();
    let event: arkret_wire::Event =
        serde_json::from_value(event).expect("federation fixture is a typed Event");
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &event,
            Some(&realm_id),
            received_at,
        ))
        .await
        .unwrap();
}

fn install_test_circle(state: &AppState, circle_id: &str, members: &[&str]) {
    let members = members
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<BTreeSet<_>>();
    state.test_projection().lock().circles.insert(
        circle_id.to_owned(),
        CircleProjection {
            circle_id: circle_id.to_owned(),
            realm_id: test_realm_id().to_owned(),
            profile_ref: None,
            title: "Need to know".to_owned(),
            summary: None,
            display: serde_json::json!({"short_name":"Need","color_token":"slate","symbol":{"glyph":"ring"}}),
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_access: "since_join".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "none".to_owned(),
            content_scheme: None,
            durability_policy: None,
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: "did:web:admin.example".to_owned(),
            created_at: Utc::now() - ChronoDuration::seconds(30),
            updated_by: None,
            updated_at: None,
            members,
        },
    );
}
