//! Integration tests — federation peer API.

#![allow(unused_imports)]
use std::collections::BTreeSet;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use soland::reducer::{CircleLifecycleState, CircleProjection};
use soland::state::{CanonicalEventRecord, RealmMetaRecord};

use super::common::*;

const PEER_SOURCE_DID: &str = "did:web:remote.example";
const SERVICE_DID: &str = "did:web:soland.local";
const TEST_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000000";
const TEST_CIRCLE_ID: &str = "ck:circle:0196419b-0000-7000-8000-0000000000c1";

#[tokio::test]
async fn peer_events_describe_advertises_formal_surface() {
    let state = AppState::new(test_config(), Db { pool: None });
    let describe: Value = TestClient::get("http://server/_cokret/peer/events/describe")
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["primary_write_path"], "/_cokret/peer/events");
    let operations = describe["supported_operations"].as_array().unwrap();
    assert!(
        operations
            .iter()
            .any(|op| op == "ck.peer.events.command.submit")
    );
    assert!(
        operations
            .iter()
            .any(|op| op == "ck.peer.events.query.scan")
    );
    assert!(
        operations
            .iter()
            .any(|op| op == "ck.peer.events.query.frontier")
    );
    // `ck.peer.snapshot.query.manifest_head` MUST NOT be declared while soland cannot
    // produce a signed ck.schema.snapshot.v1 manifest; the endpoint
    // answers `not_implemented` instead (service-surface.md §5.2).
    assert!(
        !operations
            .iter()
            .any(|op| op == "ck.peer.snapshot.query.manifest_head")
    );
}

#[tokio::test]
async fn peer_events_query_and_frontier_use_peer_surface() {
    let state = AppState::new(test_config(), Db { pool: None });
    seed_peer_read_authorization(&state, PEER_SOURCE_DID, "did:web:alice.example").await;
    let mut event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000001",
        1,
        Vec::new(),
    );
    let created_at = Utc::now();
    event["created_at"] = serde_json::json!(created_at.to_rfc3339());
    event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
    put_event_record(&state, event, created_at).await;

    let query_target =
        format!("http://server/_cokret/peer/events?realms={TEST_REALM_ID}&kind=ck.message.create");
    let mut query = TestClient::get(query_target.clone());
    for (name, value) in peer_get_headers(&query_target) {
        query = query.add_header(name, value, true);
    }
    let page: Value = query
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(page["events"].as_array().unwrap().len(), 1, "{page:?}");
    let returned_event_id = page["events"][0]["event_id"]
        .as_str()
        .or_else(|| page["events"][0]["event"]["event_id"].as_str());
    assert_eq!(
        returned_event_id,
        Some("ck:event:01904100-0000-7000-8000-fede00000001"),
        "{page:?}"
    );
    assert!(!page["has_more"].as_bool().unwrap_or(false), "{page:?}");

    let frontier_target =
        format!("http://server/_cokret/peer/events/frontier?realm_id={TEST_REALM_ID}");
    let mut frontier = TestClient::get(frontier_target.clone());
    for (name, value) in peer_get_headers(&frontier_target) {
        frontier = frontier.add_header(name, value, true);
    }
    let frontier: Value = frontier
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(frontier["realm_id"], TEST_REALM_ID);
    assert!(
        frontier["heads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|head| head == "ck:event:01904100-0000-7000-8000-fede00000001")
    );
    assert!(
        frontier["frontier_root"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(frontier["issuer"], SERVICE_DID);
    assert_eq!(frontier["signature"]["alg"], "EdDSA");
    assert_eq!(
        frontier["signature"]["signed_payload"]["frontier_root"],
        frontier["frontier_root"]
    );
}

#[tokio::test]
async fn peer_events_submit_quarantines_actor_seq_sibling_overflow() {
    let state = AppState::new(test_config(), Db { pool: None });
    let now = Utc::now();
    for idx in 0..16 {
        let event_id = format!("ck:event:01904100-0000-7000-8000-fede000001{idx:02x}");
        let mut event = signed_event_envelope(&event_id, 41, Vec::new());
        event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
        put_event_record(&state, event, now + ChronoDuration::seconds(idx)).await;
    }

    let mut overflow = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede000001ff",
        41,
        Vec::new(),
    );
    overflow["canonical_digest"] = serde_json::json!(event_canonical_digest(&overflow));
    let body = peer_submit_body(&overflow);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
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
        serde_json::json!(["ck:event:01904100-0000-7000-8000-fede000001ff"]),
        "{outcome:?}"
    );
    assert!(outcome["rejected"].as_array().is_none_or(Vec::is_empty));
    assert!(
        state
            .persistence
            .events()
            .get("ck:event:01904100-0000-7000-8000-fede000001ff")
            .await
            .unwrap()
            .is_none(),
        "quarantined sibling must not advance accepted event storage"
    );
}

#[tokio::test]
async fn peer_events_frontier_exposes_current_sibling_heads() {
    let state = AppState::new(test_config(), Db { pool: None });
    seed_peer_read_authorization(&state, PEER_SOURCE_DID, "did:web:alice.example").await;
    let now = Utc::now();
    for (idx, event_id) in [
        "ck:event:01904100-0000-7000-8000-fede000002a1",
        "ck:event:01904100-0000-7000-8000-fede000002a2",
    ]
    .iter()
    .enumerate()
    {
        let mut event = signed_event_envelope(event_id, 42, Vec::new());
        event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
        put_event_record(&state, event, now + ChronoDuration::seconds(idx as i64)).await;
    }

    let frontier_target =
        format!("http://server/_cokret/peer/events/frontier?realm_id={TEST_REALM_ID}");
    let mut frontier = TestClient::get(frontier_target.clone());
    for (name, value) in peer_get_headers(&frontier_target) {
        frontier = frontier.add_header(name, value, true);
    }
    let frontier: Value = frontier
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let heads = frontier["heads"].as_array().unwrap();
    assert!(
        heads
            .iter()
            .any(|head| head == "ck:event:01904100-0000-7000-8000-fede000002a1"),
        "{frontier:?}"
    );
    assert!(
        heads
            .iter()
            .any(|head| head == "ck:event:01904100-0000-7000-8000-fede000002a2"),
        "{frontier:?}"
    );
    assert_eq!(
        frontier["actor_seq_upper_bounds"]["did:web:alice.example"],
        42
    );
}

/// SOL-02-007 - the federation submit path MUST bind the envelope actor to
/// the asserted `source-trust-domain`: an actor whose home domain differs
/// from the source domain AND who is not a known member of the binding
/// Realm is rejected before any session is constructed.
#[tokio::test]
async fn peer_events_submit_rejects_actor_outside_source_trust_domain() {
    let state = AppState::new(test_config(), Db { pool: None });
    let mut event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000099",
        1,
        Vec::new(),
    );
    // Re-author the envelope as an actor that is neither homed in the
    // source trust domain (`remote.example`) nor a member of the demo
    // Realm's membership index.
    event["actor_id"] = serde_json::json!("did:web:intruder.evil");
    event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
    let body = peer_submit_body(&event);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
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
            .contains("source-trust-domain")
    );
}

/// SOL-02-007 — counterpart positive path: a known member of the binding
/// Realm may be relayed by a foreign source domain (identity is still
/// re-verified by the downstream proof chain).
#[tokio::test]
async fn peer_events_submit_accepts_known_member_relayed_by_foreign_domain() {
    let state = AppState::new(test_config(), Db { pool: None });
    // `did:web:alice.example` is seeded into the demo Realm's membership
    // index; the source domain is `remote.example` (mismatched home), so
    // acceptance exercises the membership-index path.
    let event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000098",
        1,
        Vec::new(),
    );
    let body = peer_submit_body(&event);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "accepted");
}

#[tokio::test]
async fn peer_events_submit_accepts_bound_mls_welcome_and_rejects_missing_claim_envelope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let welcome_event_id = "ck:event:01904100-0000-7000-8000-fede00000b01";
    let welcome_event = event_envelope(
        welcome_event_id,
        "ck.mls.welcome",
        "ck.schema.event.v1",
        "did:web:alice.example",
        51,
        mls_welcome_payload("claim-peer-01", "opaque-peer-welcome"),
    );
    let outcome = submit_peer_event(state.clone(), &welcome_event).await;
    assert_eq!(outcome["status"], "accepted", "{outcome:?}");
    assert_eq!(outcome["accepted"], serde_json::json!([welcome_event_id]));
    assert_eq!(
        state
            .persistence
            .mls_welcomes()
            .snapshot_all()
            .await
            .unwrap()
            .len(),
        1
    );

    let missing_claim_event_id = "ck:event:01904100-0000-7000-8000-fede00000b02";
    let mut missing_claim_payload =
        mls_welcome_payload("claim-peer-02", "opaque-peer-welcome-missing");
    missing_claim_payload
        .as_object_mut()
        .unwrap()
        .remove("claim_envelope");
    let missing_claim_event = event_envelope(
        missing_claim_event_id,
        "ck.mls.welcome",
        "ck.schema.event.v1",
        "did:web:alice.example",
        52,
        missing_claim_payload,
    );
    let outcome = submit_peer_event(state.clone(), &missing_claim_event).await;
    assert_eq!(outcome["status"], "partial", "{outcome:?}");
    assert!(outcome["accepted"].as_array().unwrap().is_empty());
    let rejected = outcome["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["id"], missing_claim_event_id);
    assert_eq!(rejected[0]["reason_code"], "schema_violation");
    assert!(
        rejected[0]["detail"]
            .as_str()
            .unwrap()
            .contains("claim_envelope"),
        "{outcome:?}"
    );
    assert_eq!(
        state
            .persistence
            .mls_welcomes()
            .snapshot_all()
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn peer_events_query_clips_circle_event_outside_source_did_member_scope() {
    let state = AppState::new(test_config(), Db { pool: None });
    seed_peer_read_authorization(&state, PEER_SOURCE_DID, "did:web:bob.example").await;
    install_test_circle(&state, TEST_CIRCLE_ID, &["did:web:alice.example"]);
    let now = Utc::now();
    put_event_record(
        &state,
        circle_member_event(
            "ck:event:01904100-0000-7000-8000-c1ac1e000001",
            "did:web:alice.example",
            "did:web:admin.example",
            31,
        ),
        now - ChronoDuration::seconds(20),
    )
    .await;
    let hidden_event_id = "ck:event:01904100-0000-7000-8000-c1ac1e000002";
    let mut event = signed_event_envelope(hidden_event_id, 32, Vec::new());
    event["actor_id"] = serde_json::json!("did:web:alice.example");
    event["effective_scope"] = serde_json::json!(TEST_CIRCLE_ID);
    event["created_at"] = serde_json::json!((now - ChronoDuration::seconds(5)).to_rfc3339());
    event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
    put_event_record(&state, event, now - ChronoDuration::seconds(10)).await;

    let query_target =
        format!("http://server/_cokret/peer/events?realms={TEST_REALM_ID}&kind=ck.message.create");
    let mut query = TestClient::get(query_target.clone());
    for (name, value) in peer_get_headers(&query_target) {
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

    let resolve_target = "http://server/_cokret/peer/events/resolve";
    let resolve_body = serde_json::json!({
        "event_ids": [hidden_event_id],
        "include_payload": true
    });
    let mut resolve = TestClient::post(resolve_target).json(&resolve_body);
    for (name, value) in
        signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, resolve_target, &resolve_body)
    {
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
    assert_eq!(
        resolved["missing"],
        serde_json::json!([hidden_event_id]),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn self_events_reject_federation_wire() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000002",
        1,
        Vec::new(),
    );
    let mut response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&peer_submit_body(&event))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "missing_param");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("event_id"),
        "{body:?}"
    );
}

fn peer_submit_body(event: &Value) -> Value {
    let event_id = event["event_id"].as_str().unwrap();
    let event_digest = event["canonical_digest"].as_str().unwrap();
    let binding_payload = serde_json::json!({
        "domain": "ck.peer.events.command.submit.service_binding.v1",
        "realm_id": TEST_REALM_ID,
        "event_id": event_id,
        "canonical_digest": event_digest,
    });
    serde_json::json!({
        "service_binding_ref": {
            "realm_id": TEST_REALM_ID,
            "realm_policy_digest": sha256_json(&binding_payload),
            "membership_frontier": [event_id],
            "delivery_binding_frontier": [event_id],
            "destination_service_type": "principal_server",
            "reducer_profile_digest": cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST,
        },
        "events": [event],
        "idempotency_key": format!("ck:outbox:event:{event_id}"),
    })
}

async fn submit_peer_event(state: AppState, event: &Value) -> Value {
    let body = peer_submit_body(event);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
        submit = submit.add_header(name, value, true);
    }
    submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap()
}

fn peer_get_headers(target_uri: &str) -> Vec<(&'static str, String)> {
    signed_federation_get_headers(PEER_SOURCE_DID, SERVICE_DID, target_uri)
}

async fn seed_peer_read_authorization(
    state: &AppState,
    source_service_did: &str,
    member_did: &str,
) {
    let now = Utc::now() - ChronoDuration::seconds(60);
    let mut meta = state
        .persistence
        .realm_meta()
        .get(TEST_REALM_ID)
        .await
        .unwrap()
        .unwrap_or_else(|| RealmMetaRecord {
            owner: "did:web:alice.example".to_owned(),
            deleted: false,
            discoverability: "public".to_owned(),
            history_visibility: "shared".to_owned(),
            history_sharing_policy: None,
            history_sharing_policy_digest: None,
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
        .insert(source_service_did.to_owned());
    meta.plaintext_visible_service_classes
        .entry(source_service_did.to_owned())
        .or_default()
        .insert(cokret_sdk::PlaintextDataClassKind::MessageContent);
    meta.updated_at = now;
    state
        .persistence
        .realm_meta()
        .put(TEST_REALM_ID, &meta)
        .await
        .unwrap();
    put_event_record(
        state,
        realm_sync_endpoint_event(
            "ck:event:01904100-0000-7000-8000-fede0000a001",
            source_service_did,
            21,
        ),
        now,
    )
    .await;
    put_event_record(
        state,
        member_binding_event(
            "ck:event:01904100-0000-7000-8000-fede0000a002",
            member_did,
            source_service_did,
            22,
        ),
        now + ChronoDuration::seconds(1),
    )
    .await;
}

fn realm_sync_endpoint_event(event_id: &str, source_service_did: &str, seq: u64) -> Value {
    let payload = serde_json::json!({
        "object": {
            "sync_endpoints": [{
                "did": source_service_did,
                "endpoint": "https://remote.example",
                "role": "federation_peer",
                "service_type": "principal_server",
                "plaintext_visible": true,
                "visibility_scope": "plaintext_events"
            }]
        }
    });
    event_envelope(
        event_id,
        "ck.realm.create",
        "ck.schema.realm.v1",
        "did:web:admin.example",
        seq,
        payload,
    )
}

fn member_binding_event(
    event_id: &str,
    member_did: &str,
    source_service_did: &str,
    seq: u64,
) -> Value {
    let payload = serde_json::json!({
        "actor_id": member_did,
        "membership": "join",
        "role": "member",
        "delivery_status": "routable",
        "delivery_binding": {
            "recipient_service_did": source_service_did,
            "binding_source": "explicit",
            "delivery_binding_frontier": "ck:frontier:peer-read-test"
        }
    });
    event_envelope(
        event_id,
        "ck.member.state",
        "ck.schema.member_state.v1",
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
    event_envelope(
        event_id,
        "ck.circle.member.state",
        "ck.schema.circle_member_state.v1",
        sender,
        seq,
        payload,
    )
}

fn mls_welcome_payload(claim_id: &str, ciphertext: &str) -> Value {
    let group_id = "ck:mls_group:peer-dm";
    let keypackage_ref = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    let keypackage_digest =
        "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    serde_json::json!({
        "mls_group_id": group_id,
        "epoch": 1,
        "recipient_principal_id": "did:web:bob.example",
        "recipient_device_id": "ck:device:01904100-0000-7000-8000-b0b0e0000001",
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "claim_id": claim_id,
        "claim_ref": {
            "claim_id": claim_id,
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "capabilities_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "ssk_generation": 1
        },
        "claim_envelope": {
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "intended_realm_id": TEST_REALM_ID,
            "claim_id": claim_id,
            "requester_did": "did:web:alice.example",
            "ssk_generation": 1,
            "nonce": b64(format!("{claim_id}-nonce-128-bit-material").as_bytes()),
            "welcome_digest": cokret_sdk::canonical::sha256_digest(ciphertext.as_bytes()),
            "created_at": "2026-05-25T00:00:02Z",
            "signature": {
                "kid": "did:web:alice.example#self-signing",
                "alg": "EdDSA",
                "sig": b64(format!("{claim_id}-signature").as_bytes())
            }
        },
        "welcome_ref": "ck:blob:sha256:8888888888888888888888888888888888888888888888888888888888888888",
        "ciphertext": ciphertext,
        "expires_at": "2026-05-25T01:00:00Z",
        "commit_ref": "ck:event:01904100-0000-7000-8000-fede00000c01",
        "governance_binding": mls_governance_binding(group_id)
    })
}

fn mls_governance_binding(group_id: &str) -> Value {
    serde_json::json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": TEST_REALM_ID,
        "effective_scope": {
            "kind": "realm",
            "realm_id": TEST_REALM_ID
        },
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "membership_frontier": [
            "ck:event:01904100-0000-7000-8000-fede00000a01"
        ],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "binding_profile": soland::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": soland::kinds::MLS_REDUCER_PROFILE_V1
    })
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn event_envelope(
    event_id: &str,
    kind: &str,
    schema_id: &str,
    actor_id: &str,
    actor_seq: u64,
    payload: Value,
) -> Value {
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": schema_id,
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "realm_id": TEST_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": SERVICE_DID,
        "domain": SERVICE_DID,
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor_id}#01904100-0000-7000-8000-a11ce0000001"),
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": SERVICE_DID,
            "domain": SERVICE_DID,
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
    event
}

async fn put_event_record(state: &AppState, event: Value, received_at: DateTime<Utc>) {
    let event_id = event["event_id"].as_str().unwrap().to_owned();
    let actor_id = event["actor_id"].as_str().unwrap().to_owned();
    let actor_seq = event["actor_seq"].as_u64().unwrap();
    let realm_id = event["realm_id"].as_str().unwrap().to_owned();
    let kind = event["kind"].as_str().unwrap().to_owned();
    let schema_id = event["schema_id"].as_str().unwrap().to_owned();
    let canonical_digest = event["canonical_digest"].as_str().unwrap().to_owned();
    let canonical_bytes = cokret_sdk::canonical::canonical_json_bytes(&event).unwrap();
    state
        .persistence
        .events()
        .put(CanonicalEventRecord {
            event_id,
            actor_id,
            actor_seq,
            realm_id: Some(realm_id),
            kind,
            schema_id,
            canonical_digest,
            canonical_bytes,
            envelope: event,
            received_at,
        })
        .await
        .unwrap();
}

fn install_test_circle(state: &AppState, circle_id: &str, members: &[&str]) {
    let members = members
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<BTreeSet<_>>();
    state.projection.lock().circles.insert(
        circle_id.to_owned(),
        CircleProjection {
            circle_id: circle_id.to_owned(),
            realm_id: TEST_REALM_ID.to_owned(),
            title: "Need to know".to_owned(),
            summary: None,
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_visibility: "joined".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "none".to_owned(),
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
