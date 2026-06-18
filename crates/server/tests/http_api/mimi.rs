//! Integration tests — `mimi` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

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
            .any(|profile| profile == "ck.profile.mimi_interop.v1")
    );

    let directory: Value = TestClient::get("http://server/_cokret/open/mimi/provider-directory")
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

    let unsupported = TestClient::post("http://server/_cokret/open/mimi/key-material")
        .json(&serde_json::json!({"protocol_draft": "draft-ietf-mimi-protocol-99"}))
        .send(&service)
        .await;
    assert_eq!(unsupported.status_code.unwrap().as_u16(), 400);

    let key_material: Value = TestClient::post("http://server/_cokret/open/mimi/key-material")
        .json(&serde_json::json!({
            "requester": "did:web:alice.example",
            "strand_id": "ck:strand:01964180-0000-7000-8000-000000000000",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "mimi_room_uri": "mimi://soland.local/rooms/01JSMIMI",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(key_material["failures"], serde_json::json!([]));

    let room_binding: Value =
        TestClient::post("http://server/_cokret/open/mimi/strands/01JSMIMI/update")
            .json(&serde_json::json!({
                "mls_group_id": "mimi-group-01JSMIMI",
                "update": {
                    "room_binding": {
                        "mimi_room_uri": "mimi://soland.local/rooms/01JSMIMI",
                        "binding_scope": {
                            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000"
                        }
                    }
                }
            }))
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(room_binding["accepted"], true);
    assert!(room_binding["room_state_ref"].as_str().is_some());

    let group_info: Value =
        TestClient::get("http://server/_cokret/open/mimi/strands/01JSMIMI/group-info")
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        group_info["group_info"]["mimi_room_uri"], "mimi://soland.local/rooms/01JSMIMI",
        "group_info response: {group_info}"
    );
    assert_eq!(
        group_info["group_info"]["canonical_truth"],
        "cokret_signed_event_reducer"
    );

    let identifier: Value = TestClient::post("http://server/_cokret/open/mimi/identifiers/query")
        .json(&serde_json::json!({
            "identifiers": ["mimi://remote.example/alice"],
            "privacy_profile": "private_contact_discovery"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        identifier["matches"][0]["identifier"],
        "mimi://remote.example/alice"
    );
    assert_eq!(identifier["matches"][0]["reachable"], false);
    assert_eq!(
        identifier["matches"][0]["reason_code"],
        "identifier_mapping_not_available"
    );
    assert_eq!(identifier["has_more"], false);

    let mapped: Value =
        TestClient::post("http://server/_cokret/open/mimi/strands/01JSMIMI/messages")
            .json(&serde_json::json!({
                "sender_actor_id": "did:web:alice.example",
                "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
                "ciphertext": {
                    "body": "hello from MIMI"
                },
                "mls_group_id": "mimi-group-01JSMIMI"
            }))
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert!(mapped["event_ref"].as_str().is_some());
    assert_eq!(mapped["delivery"]["status"], "accepted");
    assert!(mapped["rejected"].is_null());

    let proxy: Value = TestClient::post("http://server/_cokret/open/mimi/proxy-download")
        .json(&serde_json::json!({
            "asset_ref": "ck:blob:sha256:e2e",
            "requester": "did:web:alice.example"
        }))
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

    let report = TestClient::post("http://server/_cokret/open/mimi/report-abuse")
        .json(&serde_json::json!({
            "strand_id": "ck:strand:01964180-0000-7000-8000-000000000000",
            "mimi_room_uri": "mimi://soland.local/rooms/01JSMIMI",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "target_ref": "sha256:target",
            "reporter": "did:web:alice.example",
            "abuse_reason_code": "spam",
            "franking_proof": {"scheme": "dev-frank"}
        }))
        .send(&service)
        .await;
    // Round 15ab — mimi handlers converted to typed result signatures;
    // Salvo's typed Writer defaults to 200 OK. Status-code
    // distinction was never load-bearing (no caller branched on 202 vs
    // 200), but the wire body still carries `ok=true` + `status="queued"`.
    assert_eq!(report.status_code.unwrap().as_u16(), 200);
}

#[tokio::test]
async fn mimi_facade_writes_strand_into_canonical_reducer_chain() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let demo_realm = DEMO_REALM_ID;
    let custom_realm = "ck:realm:0196419b-0000-7000-8000-aaaaaaaaaaaa";
    let room_id = "01JSMIMI-P4-E2E";

    // Step 1: post a room_update carrying a room_binding block.
    let update_resp: Value = TestClient::put(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/update"
    ))
    .json(&serde_json::json!({
        "room_binding": {
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
            "binding_scope": {
                "realm_id": demo_realm,
                "strand_id": null,
            },
            "hub_provider": "did:web:test.local",
            "local_provider_role": "hub",
            "follower_providers": [],
            "mls_group_id": "base64url-test",
            "content_profile": "application/mimi-content",
            "policy_component_root": "sha256:test",
            "created_at": "2026-05-16T00:00:00Z",
        },
        "protocol_draft": "draft-ietf-mimi-protocol-06",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(update_resp["ok"], true);
    assert_eq!(
        update_resp["receipt"]["extra"]["binding_emitted"], true,
        "room_update receipt must announce binding emission"
    );
    let binding_event_id = update_resp["binding_event_id"]
        .as_str()
        .expect("binding_event_id missing from response");
    assert!(binding_event_id.starts_with("ck:event:"));

    // Step 2: submit_message into the same room.
    let msg_resp: Value = TestClient::post(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "text/plain;charset=utf-8",
        "content": {
            "kind": "ck.content.composite",
            "body": "hello from MIMI P4",
            "parts": [{"kind": "ck.content.text", "body": "hello from MIMI P4"}],
        },
        "sender_did": "did:web:remote.example",
        "mimi_message_id": "mimi-msg-p4-001",
        "original_envelope_hash": "sha256:p4-orig",
        "protocol_draft": "draft-ietf-mimi-protocol-06",
        "content_draft": "draft-ietf-mimi-content-08",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(msg_resp["ok"], true);
    assert_eq!(
        msg_resp["realm_id"], demo_realm,
        "submit_message must use bound realm_id"
    );
    assert_eq!(
        msg_resp["receipt"]["extra"]["reducer_chain"], "wired",
        "submit_message receipt should announce reducer-chain wire-up"
    );
    let cokret_event_id = msg_resp["cokret_event_id"]
        .as_str()
        .expect("cokret_event_id missing");

    // Step 3: query /_cokret/self/events against the bound Realm and
    // verify both the room_binding event and the message event are
    // present.
    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={demo_realm}"
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
        .find(|e| e["event_id"] == binding_event_id)
        .expect("room_binding event missing from projection log");
    assert_eq!(binding_event["event_kind"], "ck.mimi.room_binding");
    assert_eq!(
        binding_event["payload"]["mimi_room_id"], room_id,
        "room_binding payload must echo room_id for bound-Realm dispatch"
    );
    assert_eq!(
        binding_event["payload"]["binding_scope"]["realm_id"],
        demo_realm
    );

    let message_event = list
        .iter()
        .find(|e| e["event_id"] == cokret_event_id)
        .expect("MIMI-ingressed message missing from projection log");
    assert_eq!(message_event["event_kind"], "ck.message.create");
    assert_eq!(message_event["sender"], "did:web:remote.example");
    assert_eq!(
        message_event["payload"]["content"]["parts"][0]["body"],
        "hello from MIMI P4"
    );
    // mimi_provenance metadata MUST be preserved.
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["mimi_message_id"],
        "mimi-msg-p4-001"
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["original_envelope_hash"],
        "sha256:p4-orig"
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["facade"],
        "soland.mimi.v1"
    );

    // Step 4: report_abuse emits a ck.self.moderation.report event.
    let report_resp: Value = TestClient::post("http://server/_cokret/open/mimi/report-abuse")
        .json(&serde_json::json!({
            "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
            "target_event_digest": "sha256:abuse-target",
            "frank": {"scheme": "dev-frank"},
            "reporter_did": "did:web:reporter.example",
            "realm_id": demo_realm,
            "protocol_draft": "draft-ietf-mimi-protocol-06",
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report_resp["ok"], true);
    let report_event_id = report_resp["report_event_id"]
        .as_str()
        .expect("report_event_id missing");
    assert_eq!(
        report_resp["receipt"]["extra"]["moderation_event_emitted"], true,
        "report_abuse receipt must announce moderation event emission"
    );

    let events_again: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={demo_realm}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let list2 = events_again["events"].as_array().unwrap();
    let report_event = list2
        .iter()
        .find(|e| e["event_id"] == report_event_id)
        .expect("moderation.report event missing from projection log");
    assert_eq!(report_event["event_kind"], "ck.self.moderation.report");
    assert_eq!(report_event["sender"], "did:web:reporter.example");
    assert_eq!(
        report_event["payload"]["mimi_provenance"]["mimi_room_uri"],
        format!("mimi://soland.local/rooms/{room_id}")
    );

    // Step 5: a second room_update with a different binding_scope
    // updates the dispatch lookup. The most-recently-recorded
    // binding wins per `mimi_bound_realm_id` semantics.
    let _: Value = TestClient::put(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/update"
    ))
    .json(&serde_json::json!({
        "room_binding": {
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
            "binding_scope": {
                "realm_id": custom_realm,
                "strand_id": null,
            },
            "hub_provider": "did:web:test.local",
            "local_provider_role": "hub",
            "mls_group_id": "base64url-test-2",
            "policy_component_root": "sha256:test-2",
            "created_at": "2026-05-16T00:00:01Z",
        },
        "protocol_draft": "draft-ietf-mimi-protocol-06",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();

    let msg_resp_2: Value = TestClient::post(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "application/mimi-content",
        "content": {
            "kind": "ck.content.composite",
            "body": "second message",
            "parts": [{"kind": "ck.content.text", "body": "second message"}]
        },
        "protocol_draft": "draft-ietf-mimi-protocol-06",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        msg_resp_2["realm_id"], custom_realm,
        "second message must route to the rebound realm_id"
    );
}

#[tokio::test]
async fn mimi_facade_enforces_e2ee_boundary_and_quarantines_unknown_content() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let realm_id = DEMO_REALM_ID;
    let room_id = "01JSMIMI-P75-POLICY";

    let update_resp: Value = TestClient::put(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/update"
    ))
    .json(&serde_json::json!({
        "room_binding": {
            "profile": "ck.profile.mimi_interop.v1",
            "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": null,
            },
            "content_profile": "application/mimi-content",
        },
        "protocol_draft": "draft-ietf-mimi-protocol-06",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(update_resp["ok"], true);

    let mut unmarked = TestClient::post(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "application/mimi-content",
        "e2ee": true,
        "content": {
            "kind": "ck.content.text",
            "body": "this plaintext must not cross silently"
        },
        "sender_did": "did:web:mimi.example",
        "mimi_message_id": "mimi-msg-policy-unmarked",
        "protocol_draft": "draft-ietf-mimi-protocol-06",
        "content_draft": "draft-ietf-mimi-content-08",
    }))
    .send(&service)
    .await;
    assert_eq!(unmarked.status_code.unwrap().as_u16(), 400);
    let unmarked_body: Value = unmarked.take_json().await.unwrap();
    assert_eq!(
        unmarked_body["error"]["code"],
        "mimi_e2ee_boundary_unmarked"
    );

    let downgrade_resp: Value = TestClient::post(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "application/mimi-content",
        "e2ee": true,
        "e2ee_downgrade": "mimi_bridge",
        "content": {
            "kind": "ck.content.text",
            "body": "explicitly downgraded plaintext"
        },
        "sender_did": "did:web:mimi.example",
        "mimi_message_id": "mimi-msg-policy-downgrade",
        "protocol_draft": "draft-ietf-mimi-protocol-06",
        "content_draft": "draft-ietf-mimi-content-08",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(downgrade_resp["ok"], true);
    assert_eq!(downgrade_resp["status"], "mapped");
    assert_eq!(
        downgrade_resp["receipt"]["extra"]["mimi_policy"]["e2ee_boundary"],
        "explicit_downgrade"
    );
    let downgrade_event_id = downgrade_resp["cokret_event_id"]
        .as_str()
        .expect("downgrade event id")
        .to_owned();

    let transcript_resp: Value = TestClient::post(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "application/mimi-content",
        "encrypted": true,
        "transcript_binding": {
            "profile": "mls-via-ietf-mimi",
            "transcript_hash": "sha256:transcript-bound"
        },
        "content": {
            "kind": "ck.content.text",
            "body": "transcript-bound plaintext"
        },
        "sender_did": "did:web:mimi.example",
        "mimi_message_id": "mimi-msg-policy-transcript",
        "protocol_draft": "draft-ietf-mimi-protocol-06",
        "content_draft": "draft-ietf-mimi-content-08",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(transcript_resp["ok"], true);
    assert_eq!(
        transcript_resp["receipt"]["extra"]["mimi_policy"]["e2ee_boundary"],
        "transcript_bound"
    );
    let transcript_event_id = transcript_resp["cokret_event_id"]
        .as_str()
        .expect("transcript event id")
        .to_owned();

    let quarantine_resp: Value = TestClient::post(format!(
        "http://server/_cokret/open/mimi/strands/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "application/mimi-content",
        "content_kind": "m.location.share.live",
        "content": {
            "kind": "m.location.share.live",
            "geo_uri": "geo:31.2304,121.4737;u=10",
            "body": "raw live location payload"
        },
        "sender_did": "did:web:mimi.example",
        "mimi_message_id": "mimi-msg-policy-quarantine",
        "protocol_draft": "draft-ietf-mimi-protocol-06",
        "content_draft": "draft-ietf-mimi-content-08",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(quarantine_resp["ok"], true);
    assert_eq!(quarantine_resp["status"], "quarantined");
    assert_eq!(
        quarantine_resp["receipt"]["extra"]["quarantine"]["unknown_content_kind"],
        "m.location.share.live"
    );
    let quarantine_event_id = quarantine_resp["cokret_event_id"]
        .as_str()
        .expect("quarantine event id")
        .to_owned();

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={realm_id}"
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
        downgrade_event["payload"]["content"]["ck.morph.e2ee_downgrade"],
        "mimi_bridge"
    );
    assert_eq!(
        downgrade_event["payload"]["mimi_policy"]["e2ee_boundary"],
        "explicit_downgrade"
    );

    let transcript_event = find(&transcript_event_id);
    assert_eq!(
        transcript_event["payload"]["content"]["transcript_binding"]["transcript_hash"],
        "sha256:transcript-bound"
    );
    assert_eq!(
        transcript_event["payload"]["mimi_policy"]["e2ee_boundary"],
        "transcript_bound"
    );

    let quarantine_event = find(&quarantine_event_id);
    assert_eq!(
        quarantine_event["payload"]["content"]["kind"],
        "ck.content.unsupported"
    );
    assert_eq!(
        quarantine_event["payload"]["content"]["body"],
        "unsupported content from MIMI"
    );
    assert_eq!(
        quarantine_event["payload"]["content"]["ck.morph.unknown_content_kind"],
        "m.location.share.live"
    );
}
