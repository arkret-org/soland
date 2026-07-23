//! Integration tests for the MIMI facade.

use serde_json::json;

use super::common::*;

const MIMI_SOURCE_SERVICE_ID: &str = "did:web:remote-mimi.example";
const MIMI_DESTINATION_SERVICE_ID: &str =
    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
const MIMI_PROVIDER_ID: &str = "mimi://remote-mimi.example/provider";
const MIMI_TEST_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const MIMI_TEST_STRAND_ID: &str = "ak:strand:01964180-0000-7000-8000-000000000000";
const MIMI_TEST_POLICY_ROOT: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

macro_rules! signed_mimi_post {
    ($url:expr, $body:expr, $room_uri:expr) => {{
        let target_uri: String = ($url).into();
        let request_body = &$body;
        let mut request = TestClient::post(target_uri.clone());
        for (name, value) in signed_mimi_headers("POST", &target_uri, request_body, $room_uri) {
            request = request.add_header(name, value, true);
        }
        request.json(request_body)
    }};
}

fn signed_mimi_headers(
    method: &str,
    target_uri: &str,
    body: &Value,
    room_uri: Option<&str>,
) -> Vec<(&'static str, String)> {
    let body_bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body_bytes)));
    let request_digest = arkret_canonical::sha256_digest(&body_bytes);
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let verification_method = format!("{MIMI_SOURCE_SERVICE_ID}#mimi-provider-test-key");
    let components = if room_uri.is_some() {
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"request-canonical-digest\" \"source-service-id\" \"destination-service-id\" \"provider-id\" \"mimi-room-uri\")"
    } else {
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"request-canonical-digest\" \"source-service-id\" \"destination-service-id\" \"provider-id\")"
    };
    let signature_params = format!(
        "{components};created={created};expires={expires};keyid=\"{verification_method}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_uri(target_uri);
    let room_component = room_uri
        .map(|room_uri| format!("\"mimi-room-uri\": {room_uri}\n"))
        .unwrap_or_default();
    let signature_base = format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"request-canonical-digest\": {request_digest}\n\
         \"source-service-id\": {MIMI_SOURCE_SERVICE_ID}\n\
         \"destination-service-id\": {MIMI_DESTINATION_SERVICE_ID}\n\
         \"provider-id\": {MIMI_PROVIDER_ID}\n\
         {room_component}\
         \"@signature-params\": {signature_params}",
    );
    let signing = mimi_provider_signing_key(&verification_method);
    let signature = signing.sign(signature_base.as_bytes());
    let mut headers = vec![
        ("content-digest", content_digest),
        ("request-canonical-digest", request_digest),
        ("source-service-id", MIMI_SOURCE_SERVICE_ID.to_owned()),
        (
            "destination-service-id",
            MIMI_DESTINATION_SERVICE_ID.to_owned(),
        ),
        ("provider-id", MIMI_PROVIDER_ID.to_owned()),
    ];
    if let Some(room_uri) = room_uri {
        headers.push(("mimi-room-uri", room_uri.to_owned()));
    }
    headers.push(("signature-input", format!("sig1={signature_params}")));
    headers.push((
        "signature",
        format!("sig1=:{}:", STANDARD.encode(signature.to_bytes())),
    ));
    headers
}

fn mimi_provider_signing_key(verification_method: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:mimi-provider-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn mimi_room_uri(room_id: &str) -> String {
    format!("mimi://soland.local/webvh/service/rooms/{room_id}")
}

fn mimi_opaque_payload(value: Value, digest_field: &str) -> Value {
    let bytes = arkret_canonical::canonical_json_bytes(&value).unwrap();
    let mut object = serde_json::Map::new();
    object.insert(
        "content_type".to_owned(),
        json!(if digest_field == "ciphertext_digest" {
            "application/mimi-content"
        } else {
            "application/json"
        }),
    );
    object.insert(
        digest_field.to_owned(),
        json!(arkret_canonical::sha256_digest(&bytes)),
    );
    object.insert("payload".to_owned(), json!(URL_SAFE_NO_PAD.encode(&bytes)));
    Value::Object(object)
}

fn mimi_room_update_body(
    room_id: &str,
    realm_id: &str,
    group_id: &str,
    role: &str,
    status: &str,
) -> Value {
    let binding = json!({
        "kind": "ak.mimi.room_binding",
        "payload": {
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri(room_id),
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": null,
            },
            "hub_provider": "did:web:hub-mimi.example",
            "local_provider_role": role,
            "follower_providers": [],
            "mls_group_id": group_id,
            "content_profile": "application/mimi-content",
            "policy_root": MIMI_TEST_POLICY_ROOT,
            "status": status,
            "created_at": "2026-05-16T00:00:00.000Z",
        }
    });
    json!({
        "mls_group_id": group_id,
        "epoch": 1,
        "sender_actor_id": MIMI_SOURCE_SERVICE_ID,
        "update": {
            "kind": "ak.mimi.room_binding",
            "payload": mimi_opaque_payload(binding, "payload_digest")
        }
    })
}

fn mimi_submit_body(
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    sender: &str,
    mut message: Value,
) -> Value {
    let governance_binding = mimi_governance_binding(realm_id, group_id, epoch);
    let covered_seals_cell = json!({
        "cell_id": format!("ak:cell:ak.component.covered_seals.v1:{group_id}"),
        "seal_refs": ["ak:seal:0196419b-0000-7000-8000-000000000001"],
    });
    if let Value::Object(object) = &mut message {
        object.insert("mls_group_id".to_owned(), json!(group_id));
        object.insert("epoch".to_owned(), json!(epoch));
        object.insert("governance_binding".to_owned(), governance_binding.clone());
        object.insert("covered_seals_cell".to_owned(), covered_seals_cell.clone());
    }
    let associated_data = json!({
        "governance_binding": governance_binding,
        "covered_seals_cell": covered_seals_cell,
    });
    json!({
        "sender_actor_id": sender,
        "device_id": MIMI_TEST_DEVICE_ID,
        "mls_group_id": group_id,
        "epoch": epoch,
        "associated_data": mimi_opaque_payload(associated_data, "payload_digest"),
        "ciphertext": mimi_opaque_payload(message, "ciphertext_digest")
    })
}

fn mimi_governance_binding(realm_id: &str, group_id: &str, epoch: u64) -> Value {
    json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.v1",
        "mls_group_id": group_id,
        "previous_epoch": epoch.saturating_sub(1),
        "next_epoch": epoch,
        "realm_id": realm_id,
        "effective_scope": {
            "kind": "realm",
            "realm_id": realm_id,
        },
        "membership_frontier": ["ak:event:0196419b-0000-7000-8000-000000000001"],
        "policy_root": MIMI_TEST_POLICY_ROOT,
        "capability_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    })
}

fn text_mimi_message(message_id: &str, body: &str) -> Value {
    json!({
        "source_format": "application/mimi-content",
        "mimi_message_id": message_id,
        "original_envelope_hash": arkret_canonical::sha256_digest(message_id.as_bytes()),
        "content": {
            "kind": "ak.content.composite",
            "body": body,
            "parts": [{
                "kind": "ak.content.text",
                "body": body,
            }],
        },
    })
}

fn event_kind(event: &Value) -> Option<&str> {
    event
        .get("event_kind")
        .or_else(|| event.get("kind"))
        .and_then(Value::as_str)
}

fn identifier_commitment(identifier: &str) -> String {
    arkret_canonical::sha256_digest(identifier.as_bytes())
}

#[tokio::test]
async fn mimi_provider_facade_contracts_work() {
    let service = app();

    let well_known: Value = TestClient::get("http://server/.well-known/mimi-protocol-directory")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(well_known["service_type"], "mimi_provider_facade");
    assert_eq!(
        well_known["mimi"]["protocol_draft"],
        "draft-ietf-mimi-protocol-06"
    );
    assert!(
        well_known["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.mimi_interop.v1")
    );

    let directory: Value = TestClient::get("http://server/_arkret/open/mimi/provider-directory")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        directory["mimi"]["content_draft"],
        "draft-ietf-mimi-content-08"
    );
    assert!(
        directory["mimi"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "submit_message")
    );

    let key_material_body = json!({
        "requester": "did:web:alice.example",
        "strand_id": MIMI_TEST_STRAND_ID,
        "device_id": MIMI_TEST_DEVICE_ID,
        "mimi_room_uri": mimi_room_uri("01JSMIMI"),
        "realm_id": DEMO_REALM_ID,
        "mls_group_id": "mimi-group-01JSMIMI",
        "epoch": 1,
    });
    let key_material: Value = signed_mimi_post!(
        "http://server/_arkret/open/mimi/key-material",
        key_material_body,
        None
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        key_material["failures"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        0
    );

    let room_id = "01JSMIMI";
    let group_id = "mimi-group-01JSMIMI";
    let room_uri = mimi_room_uri(room_id);
    let update_body = mimi_room_update_body(room_id, DEMO_REALM_ID, group_id, "hub", "accepted");
    let room_binding: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        update_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        room_binding["accepted"], true,
        "room update: {room_binding}"
    );
    assert!(room_binding["room_state_ref"].as_str().is_some());

    let group_info: Value =
        TestClient::get("http://server/_arkret/open/mimi/strands/01JSMIMI/group-info")
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    let encoded_group_info = group_info["group_info"]["group_info"]
        .as_str()
        .expect("encoded group_info missing");
    let decoded_group_info: Value = serde_json::from_slice(
        &arkret_core::base64url_decode(encoded_group_info).expect("group_info must be base64url"),
    )
    .expect("group_info must contain JSON");
    assert_eq!(
        decoded_group_info["mimi_room_uri"],
        mimi_room_uri("01JSMIMI"),
        "group_info response: {group_info}"
    );
    assert_eq!(
        decoded_group_info["canonical_truth"],
        "arkret_signed_event_reducer"
    );

    let commitment = identifier_commitment("mimi://remote.example/alice");
    let identifier_body = json!({
        "identifiers": [{
            "kind": "mimi_uri",
            "identifier_commitment": commitment.clone(),
        }],
        "requester": "did:web:alice.example",
        "privacy_profile": "private_contact_discovery",
    });
    let identifier: Value = signed_mimi_post!(
        "http://server/_arkret/open/mimi/identifiers/query",
        identifier_body,
        None
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        identifier["matches"][0]["identifier_commitment"],
        commitment.as_str()
    );
    assert_eq!(identifier["matches"][0]["matched"], false);
    assert_eq!(identifier["has_more"], false);

    let message_body = mimi_submit_body(
        DEMO_REALM_ID,
        group_id,
        1,
        "did:web:alice.example",
        text_mimi_message("mimi-msg-contract-001", "hello from MIMI"),
    );
    let mapped: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        message_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert!(mapped["event_ref"].as_str().is_some());
    assert_eq!(mapped["delivery"]["status"], "accepted");
    // mimi-operations.schema.json#mimi_submit_message_outcome: only `delivery`
    // is required; an empty `rejected` is omitted (skip_serializing_if).
    assert!(
        mapped
            .get("rejected")
            .and_then(Value::as_array)
            .is_none_or(|rejected| rejected.is_empty())
    );

    let proxy_body = json!({
        "asset_ref": "ak:blob:sha256:e2e",
        "requester": "did:web:alice.example",
        "strand_id": MIMI_TEST_STRAND_ID,
    });
    let proxy: Value = signed_mimi_post!(
        "http://server/_arkret/open/mimi/proxy-download",
        proxy_body,
        None
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        proxy["download_ref"]
            .as_str()
            .unwrap()
            .contains("/mimi/proxy-download")
    );
    assert!(proxy["expires_at"].as_str().is_some());

    let report_body = json!({
        "strand_id": MIMI_TEST_STRAND_ID,
        "mimi_room_uri": room_uri,
        "realm_id": DEMO_REALM_ID,
        "target_ref": DEMO_REALM_ID,
        "reporter": "did:web:alice.example",
        "abuse_reason_code": "spam",
    });
    let report: Value = signed_mimi_post!(
        "http://server/_arkret/open/mimi/report-abuse",
        report_body,
        None
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(report["status"], "queued");
    assert!(report["report_id"].as_str().is_some());
}

#[tokio::test]
async fn mimi_facade_writes_strand_into_canonical_reducer_chain() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let demo_realm = DEMO_REALM_ID;
    let custom_realm = "ak:realm:0196419b-0000-7000-8000-aaaaaaaaaaaa";
    let room_id = "01JSMIMI-P4-E2E";
    let group_id = "mimi-group-p4-001";
    let room_uri = mimi_room_uri(room_id);

    let update_body = mimi_room_update_body(room_id, demo_realm, group_id, "hub", "accepted");
    let update_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        update_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(update_resp["accepted"], true, "room update: {update_resp}");
    let binding_event_id = update_resp["room_state_ref"]
        .as_str()
        .expect("room_state_ref missing");
    assert!(binding_event_id.starts_with("ak:event:"));

    let msg_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            demo_realm,
            group_id,
            1,
            "did:web:remote.example",
            text_mimi_message("mimi-msg-p4-001", "hello from MIMI P4"),
        ),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let arkret_event_id = msg_resp["event_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("event_ref missing: {msg_resp}"));

    let events: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={demo_realm}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    let binding_event = list
        .iter()
        .find(|event| event["event_id"] == binding_event_id)
        .expect("room_binding event missing from projection log");
    assert_eq!(event_kind(binding_event), Some("ak.mimi.room_binding"));
    assert_eq!(binding_event["payload"]["mimi_room_id"], room_id);
    assert_eq!(
        binding_event["payload"]["binding_scope"]["realm_id"],
        demo_realm
    );

    let message_event = list
        .iter()
        .find(|event| event["event_id"] == arkret_event_id)
        .expect("MIMI-ingressed message missing from projection log");
    assert_eq!(event_kind(message_event), Some("ak.message.create"));
    assert_eq!(message_event["actor_id"], state.service_id().as_str());
    assert_eq!(
        message_event["payload"]["metadata"]["mimi_provenance"]["original_sender"],
        "did:web:remote.example"
    );
    assert_eq!(
        message_event["payload"]["content"]["parts"][0]["body"],
        "hello from MIMI P4"
    );
    assert_eq!(
        message_event["payload"]["metadata"]["mimi_provenance"]["mimi_message_id"],
        "mimi-msg-p4-001"
    );
    assert_eq!(
        message_event["payload"]["metadata"]["mimi_provenance"]["facade"],
        "soland.mimi.v1"
    );

    let report_resp: Value = signed_mimi_post!(
        "http://server/_arkret/open/mimi/report-abuse",
        json!({
            "strand_id": MIMI_TEST_STRAND_ID,
            "mimi_room_uri": room_uri.clone(),
            "realm_id": demo_realm,
            "target_ref": demo_realm,
            // mimi-interop.md §11: attribute a report only after the reporter
            // resolves through a local account or valid consent/holder claim.
            // This reducer-chain test uses the seeded local demo principal;
            // fake consent references are not valid resolution evidence.
            "reporter": "did:web:alice.example",
            "abuse_reason_code": "spam",
        }),
        None
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        report_resp["status"], "queued",
        "report response: {report_resp}"
    );

    let events_again: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={demo_realm}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let report_event = events_again["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| {
            event_kind(event) == Some("ak.self.moderation.report")
                && event["payload"]["target_event_digest"] == demo_realm
        })
        .expect("moderation.report event missing from projection log");
    assert_eq!(report_event["actor_id"], "did:web:alice.example");

    let custom_group_id = "mimi-group-p4-custom";
    let migrating_body = mimi_room_update_body(room_id, demo_realm, group_id, "hub", "migrating");
    let migrating_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        migrating_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(migrating_resp["accepted"], true);

    let rebound_body =
        mimi_room_update_body(room_id, custom_realm, custom_group_id, "hub", "accepted");
    let rebound_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        rebound_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(rebound_resp["accepted"], true);

    let msg_resp_2: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            custom_realm,
            custom_group_id,
            1,
            "did:web:remote.example",
            text_mimi_message("mimi-msg-p4-002", "second message"),
        ),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let second_event_id = msg_resp_2["event_ref"].as_str().expect("event_ref missing");

    let second_record = state
        .test_persistence()
        .events()
        .get(second_event_id)
        .await
        .unwrap()
        .expect("second message must be persisted");
    assert_eq!(
        second_record.realm_id.as_deref(),
        Some(custom_realm),
        "second message must route to the rebound realm_id"
    );

    let revoked_body =
        mimi_room_update_body(room_id, custom_realm, custom_group_id, "hub", "revoked");
    let revoked_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        revoked_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoked_resp["accepted"], true);

    let reopen_body =
        mimi_room_update_body(room_id, custom_realm, custom_group_id, "hub", "accepted");
    let mut reopen_resp = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        reopen_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await;
    assert_eq!(reopen_resp.status_code.unwrap().as_u16(), 400);
    let reopen_error: Value = reopen_resp.take_json().await.unwrap();
    assert_eq!(
        reopen_error["error"]["code"],
        "mimi_room_binding_status_transition_invalid"
    );
}

#[tokio::test]
async fn mimi_facade_enforces_e2ee_boundary_and_quarantines_unknown_content() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let realm_id = DEMO_REALM_ID;
    let room_id = "01JSMIMI-P75-POLICY";
    let group_id = "mimi-group-policy-001";
    let room_uri = mimi_room_uri(room_id);

    let update_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        mimi_room_update_body(room_id, realm_id, group_id, "hub", "accepted"),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(update_resp["accepted"], true, "room update: {update_resp}");

    let mut unmarked = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            "did:web:mimi.example",
            json!({
                "source_format": "application/mimi-content",
                "e2ee": true,
                "mimi_message_id": "mimi-msg-policy-unmarked",
                "content": {
                    "kind": "ak.content.text",
                    "body": "this plaintext must not cross silently",
                },
            }),
        ),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await;
    assert_eq!(unmarked.status_code.unwrap().as_u16(), 400);
    let unmarked_body: Value = unmarked.take_json().await.unwrap();
    assert_eq!(
        unmarked_body["error"]["code"],
        "mimi_e2ee_boundary_unmarked"
    );

    let downgrade_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            "did:web:mimi.example",
            json!({
                "source_format": "application/mimi-content",
                "e2ee": true,
                "e2ee_downgrade": "mimi_bridge",
                "mimi_message_id": "mimi-msg-policy-downgrade",
                "content": {
                    "kind": "ak.content.text",
                    "body": "explicitly downgraded plaintext",
                },
            }),
        ),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let downgrade_event_id = downgrade_resp["event_ref"]
        .as_str()
        .expect("downgrade event id")
        .to_owned();

    let transcript_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            "did:web:mimi.example",
            json!({
                "source_format": "application/mimi-content",
                "encrypted": true,
                "mimi_message_id": "mimi-msg-policy-transcript",
                "transcript_binding": {
                    "profile": "mls-via-ietf-mimi",
                    "transcript_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                },
                "content": {
                    "kind": "ak.content.text",
                    "body": "transcript-bound plaintext",
                },
            }),
        ),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let transcript_event_id = transcript_resp["event_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("transcript event id: {transcript_resp}"))
        .to_owned();

    let quarantine_resp: Value = signed_mimi_post!(
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            "did:web:mimi.example",
            json!({
                "source_format": "application/mimi-content",
                "content_kind": "m.location.share.live",
                "mimi_message_id": "mimi-msg-policy-quarantine",
                "content": {
                    "kind": "m.location.share.live",
                    "geo_uri": "geo:31.2304,121.4737;u=10",
                    "body": "raw live location payload",
                },
            }),
        ),
        Some(room_uri.as_str())
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let quarantine_event_id = quarantine_resp["event_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("quarantine event id: {quarantine_resp}"))
        .to_owned();

    let events: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");
    let find = |event_id: &str| {
        list.iter()
            .find(|event| event["event_id"] == event_id)
            .unwrap_or_else(|| panic!("missing event {event_id}"))
    };
    let downgrade_event = find(&downgrade_event_id);
    assert_eq!(
        downgrade_event["payload"]["content"]["e2ee_downgrade"],
        "mimi_bridge"
    );
    assert_eq!(
        downgrade_event["payload"]["metadata"]["mimi_policy"]["e2ee_boundary"],
        "explicit_downgrade"
    );

    let transcript_event = find(&transcript_event_id);
    assert_eq!(
        transcript_event["payload"]["content"]["transcript_binding"]["transcript_hash"],
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(
        transcript_event["payload"]["metadata"]["mimi_policy"]["e2ee_boundary"],
        "transcript_bound"
    );

    let quarantine_event = find(&quarantine_event_id);
    assert_eq!(
        quarantine_event["payload"]["content"]["kind"],
        "ak.content.text"
    );
    assert_eq!(
        quarantine_event["payload"]["content"]["unknown_content_kind"],
        "m.location.share.live"
    );
    assert_eq!(
        quarantine_event["payload"]["metadata"]["quarantine"]["unknown_content_kind"],
        "m.location.share.live"
    );
}
