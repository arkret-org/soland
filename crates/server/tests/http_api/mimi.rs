//! Integration tests for the MIMI facade.

use serde_json::json;

use super::common::*;

const MIMI_SOURCE_SERVICE_FULL_ID: &str = "did:web:remote-mimi.example";
const MIMI_SOURCE_SERVICE_ID: &str = "ak:did_core:web:remote-mimi.example";
const MIMI_ALICE_ACTOR_ID: &str = "ak:did_core:web:alice.example";
const MIMI_REMOTE_ACTOR_ID: &str = "ak:did_core:web:remote.example";
const MIMI_POLICY_ACTOR_ID: &str = "ak:did_core:web:mimi.example";
const MIMI_PROVIDER_ID: &str = "mimi://remote-mimi.example/provider";
const MIMI_TEST_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const MIMI_TEST_STRAND_ID: &str = "ak:strand:AeR8kl_pHP0Rj8sdg-m7-2iv0BbzptjujMXzwBoelVPt";
const MIMI_TEST_POLICY_ROOT: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const MIMI_TEST_SECURITY_FRONTIER_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

macro_rules! signed_mimi_post {
    ($state:expr, $url:expr, $body:expr, $room_uri:expr) => {{
        let target_uri: String = ($url).into();
        let request_body = &$body;
        let mut request = TestClient::post(target_uri.clone());
        for (name, value) in
            signed_mimi_headers(&$state, "POST", &target_uri, request_body, $room_uri)
        {
            request = request.add_header(name, value, true);
        }
        request.json(request_body)
    }};
}

fn signed_mimi_headers(
    state: &AppState,
    method: &str,
    target_uri: &str,
    body: &Value,
    room_uri: Option<&str>,
) -> Vec<(&'static str, String)> {
    let body_bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body_bytes)));
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let verification_method = format!("{MIMI_SOURCE_SERVICE_FULL_ID}#mimi-provider-test-key");
    let destination_service_id = state.service_id().as_str();
    let mut covered_components = vec![
        arkret_signatures::http_signature::Component::Method,
        arkret_signatures::http_signature::Component::TargetUri,
        arkret_signatures::http_signature::Component::Authority,
        arkret_signatures::http_signature::Component::Header("content-digest".to_owned()),
        arkret_signatures::http_signature::Component::Header("source-service-id".to_owned()),
        arkret_signatures::http_signature::Component::Header("destination-service-id".to_owned()),
        arkret_signatures::http_signature::Component::Header("provider-id".to_owned()),
    ];
    if room_uri.is_some() {
        covered_components.push(arkret_signatures::http_signature::Component::Header(
            "mimi-room-uri".to_owned(),
        ));
    }
    let signature_input = format!(
        "{};created={created};expires={expires};keyid=\"{verification_method}\";alg=\"ed25519\"",
        arkret_signatures::http_signature::format_signature_input_component_list(
            "sig1",
            &covered_components,
        )
        .expect("MIMI signature component profile must be valid")
    );
    let parsed_signature_input =
        arkret_signatures::http_signature::parse_signature_input(&signature_input)
            .expect("generated MIMI Signature-Input must be valid");
    let authority = authority_from_target_uri(target_uri);
    let mut headers = vec![
        ("content-digest", content_digest),
        ("source-service-id", MIMI_SOURCE_SERVICE_ID.to_owned()),
        ("destination-service-id", destination_service_id.to_owned()),
        ("provider-id", MIMI_PROVIDER_ID.to_owned()),
    ];
    if let Some(room_uri) = room_uri {
        headers.push(("mimi-room-uri", room_uri.to_owned()));
    }
    let signed_target_uri = mimi_signature_target_uri(state, target_uri);
    let signature_base = arkret_signatures::http_signature::canonical_message(
        &arkret_signatures::http_signature::SignedRequestParts {
            method: method.to_owned(),
            target_uri: signed_target_uri,
            authority,
            path: String::new(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone()))
                .collect(),
            body_digest: headers
                .iter()
                .find_map(|(name, value)| (*name == "content-digest").then(|| value.clone())),
        },
        &parsed_signature_input,
    )
    .expect("generated MIMI signature components must be present");
    let signature = arkret_signatures::http_signature::sign_message(
        &signature_base,
        &mimi_provider_signing_key(&verification_method),
    );
    headers.push(("signature-input", signature_input));
    headers.push(("signature", format!("sig1=:{signature}:")));
    headers
}

fn mimi_signature_target_uri(state: &AppState, target_uri: &str) -> String {
    let request_url =
        reqwest::Url::parse(target_uri).expect("MIMI test target URI must be absolute");
    let scheme = reqwest::Url::parse(&state.config().public_base_url)
        .ok()
        .map(|url| url.scheme().to_owned())
        .unwrap_or_else(|| request_url.scheme().to_owned());
    let authority = authority_from_target_uri(target_uri);
    let mut path_and_query = request_url.path().to_owned();
    if let Some(query) = request_url.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    format!("{scheme}://{authority}{path_and_query}")
}

fn mimi_provider_signing_key(verification_method: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:mimi-provider-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn mimi_room_uri(state: &AppState, room_id: &str) -> String {
    let service_full_id = state.service_full_id();
    let service_full_id = service_full_id.as_str();
    let provider_id = if let Some(domain) = service_full_id.strip_prefix("did:web:") {
        format!("mimi://{}", canonical_mimi_authority(domain))
    } else if let Some(rest) = service_full_id.strip_prefix("did:webvh:") {
        let (scid, authority_and_path) = rest
            .split_once(':')
            .expect("fixture WebVH service identity must carry an authority");
        assert!(!scid.is_empty());
        assert!(!authority_and_path.is_empty());
        format!("mimi://{}", canonical_mimi_authority(authority_and_path))
    } else {
        format!(
            "mimi://{}",
            service_full_id.replace(':', ".").to_lowercase()
        )
    };
    arkret_wire::MimiRoomUri::new(format!("{provider_id}/rooms/{room_id}"))
        .expect("fixture service identity and room id must form a canonical MIMI room URI")
        .as_str()
        .to_owned()
}

fn canonical_mimi_authority(authority: &str) -> String {
    authority
        .replace(':', "/")
        .replace("%3A", ":")
        .replace("%3a", ":")
        .to_lowercase()
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

async fn mimi_room_update_body(
    state: &AppState,
    token: &str,
    room_id: &str,
    realm_id: &str,
    group_id: &str,
    role: &str,
    status: &str,
) -> Value {
    let binding_payload = json!({
        "profile": "ak.profile.mimi_interop.v1",
        "mimi_room_uri": mimi_room_uri(state, room_id),
        "binding_scope": {
            "realm_id": realm_id,
            "strand_id": MIMI_TEST_STRAND_ID,
        },
        "hub_provider": "ak:did_core:web:hub-mimi.example",
        "local_provider_role": role,
        "follower_providers": [],
        "mls_group_id": group_id,
        "content_profile": "application/mimi-content",
        "policy_root": MIMI_TEST_POLICY_ROOT,
        "status": status,
        "created_at": "2026-05-16T00:00:00.000Z",
    });
    let binding = json!({"kind": "ak.mimi.room_binding", "payload": binding_payload});
    let mut event = signed_canonical_event(
        "mimi-room-binding-event",
        arkret_wire::EventKind::MimiRoomBinding.as_str(),
        MIMI_SOURCE_SERVICE_FULL_ID,
        MIMI_TEST_DEVICE_ID,
        realm_id,
        0,
        vec![],
        binding["payload"].clone(),
    );
    move_event_to_actor_realm_frontier(
        state,
        token,
        MIMI_SOURCE_SERVICE_FULL_ID,
        realm_id,
        &mut event,
    )
    .await;
    let submission = arkret_wire::EventInitialSubmission {
        event: serde_json::from_value(event).unwrap(),
        authorization_lease: None,
        cba_proof_bundles: Vec::new(),
        control_proposal_ack: None,
        membership_compensation_evidence: None,
    };
    json!({
        "mls_group_id": group_id,
        "epoch": 1,
        "sender_actor_id": MIMI_SOURCE_SERVICE_ID,
        "room_binding_event": submission,
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
    if let Value::Object(object) = &mut message {
        object.insert("mls_group_id".to_owned(), json!(group_id));
        object.insert("epoch".to_owned(), json!(epoch));
        object.insert("governance_binding".to_owned(), governance_binding.clone());
    }
    let associated_data = json!({
        "governance_binding": governance_binding,
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
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        arkret_wire::RealmId::new(realm_id.to_owned()).expect("MIMI fixture realm id"),
        group_id,
        epoch.saturating_sub(1),
        epoch,
        arkret_wire::Hash::new(MIMI_TEST_SECURITY_FRONTIER_DIGEST.to_owned())
            .expect("MIMI fixture security frontier digest"),
        arkret_wire::ContentScheme::MlsRfc9420,
        None,
        arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_wire::CORE_REDUCER_PROFILE,
    )
    .expect("MIMI fixture MLS governance binding");
    serde_json::to_value(binding).expect("MIMI fixture MLS governance binding JSON")
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

async fn accepted_canonical_event(state: &AppState, event_id: &str) -> arkret_wire::Event {
    let record = state
        .test_persistence()
        .events()
        .get(event_id)
        .await
        .expect("canonical Event lookup")
        .unwrap_or_else(|| panic!("accepted canonical Event missing: {event_id}"));
    let event: arkret_wire::Event =
        serde_json::from_value(record.envelope).expect("stored canonical Event envelope");
    assert_eq!(event.event_id.as_str(), event_id);
    assert_eq!(event.kind.as_str(), record.kind);
    assert_eq!(event.actor_id.as_str(), record.actor_id);
    assert_eq!(event.realm_id.as_str(), record.realm_id.as_deref().unwrap());
    assert_eq!(
        event
            .event_digest_with_digest_suite(record.digest_suite)
            .expect("stored canonical Event digest"),
        record.canonical_digest
    );
    assert_eq!(
        arkret_canonical::canonical_json_bytes(
            &event
                .digest_payload()
                .expect("stored canonical Event digest payload")
        )
        .expect("stored canonical Event bytes"),
        record.canonical_bytes
    );
    event
}

fn identifier_commitment(identifier: &str) -> String {
    arkret_canonical::sha256_digest(identifier.as_bytes())
}

#[test]
fn mimi_provider_facade_contracts_work() {
    run_on_deep_stack(
        "mimi_provider_facade_contracts_work",
        mimi_provider_facade_contracts_work_body,
    );
}

async fn mimi_provider_facade_contracts_work_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_test_realm_basis_seal(&state, demo_realm_id(), state.service_full_id().as_str()).await;
    add_test_realm_member(&state, demo_realm_id(), MIMI_SOURCE_SERVICE_FULL_ID);
    let service = app_from_state(state.clone());

    let well_known: Value = TestClient::get("http://server/.well-known/mimi-protocol-directory")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(well_known["service_kind"], "mimi_provider_facade");
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
        "requester": MIMI_ALICE_ACTOR_ID,
        "strand_id": MIMI_TEST_STRAND_ID,
        "device_id": MIMI_TEST_DEVICE_ID,
        "mimi_room_uri": mimi_room_uri(&state, "01JSMIMI"),
        "realm_id": demo_realm_id(),
        "mls_group_id": "mimi-group-01JSMIMI",
        "epoch": 1,
    });
    let key_material: Value = signed_mimi_post!(
        state,
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
    let room_uri = mimi_room_uri(&state, room_id);
    project_test_authorized_device(
        &state,
        MIMI_SOURCE_SERVICE_FULL_ID,
        MIMI_TEST_DEVICE_ID,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    let update_body = mimi_room_update_body(
        &state,
        &token,
        room_id,
        demo_realm_id(),
        group_id,
        "hub",
        "accepted",
    )
    .await;
    let mut room_binding_response = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        update_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await;
    let room_binding_status = room_binding_response.status_code;
    let room_binding: Value = room_binding_response.take_json().await.unwrap();
    if room_binding["error"]["code"] == arkret_wire::ErrorCode::UnsupportedFeature.as_str() {
        assert_eq!(room_binding_status, Some(StatusCode::NOT_IMPLEMENTED));
        assert!(
            state
                .test_persistence()
                .events()
                .snapshot_all()
                .await
                .unwrap()
                .iter()
                .all(|record| record.kind != arkret_wire::EventKind::MimiRoomBinding.as_str()),
            "fail-closed optional MIMI profile must write no room-binding Event"
        );
        return;
    }
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
        &arkret_canonical::base64url_decode(encoded_group_info)
            .expect("group_info must be base64url"),
    )
    .expect("group_info must contain JSON");
    assert_eq!(
        decoded_group_info["mimi_room_uri"],
        mimi_room_uri(&state, "01JSMIMI"),
        "group_info response: {group_info}"
    );
    assert_eq!(decoded_group_info["profile"], "ak.profile.mimi_interop.v1");
    assert_eq!(
        decoded_group_info["binding_scope"]["realm_id"],
        demo_realm_id()
    );

    let commitment = identifier_commitment("mimi://remote.example/alice");
    let identifier_body = json!({
        "identifiers": [{
            "kind": "mimi_uri",
            "identifier_commitment": commitment.clone(),
        }],
        "requester": MIMI_ALICE_ACTOR_ID,
        "privacy_profile": "private_contact_discovery",
    });
    let identifier: Value = signed_mimi_post!(
        state,
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
        demo_realm_id(),
        group_id,
        1,
        MIMI_ALICE_ACTOR_ID,
        text_mimi_message("mimi-msg-contract-001", "hello from MIMI"),
    );
    let mapped: Value = signed_mimi_post!(
        state,
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

    let asset_ref = arkret_wire::BlobRef::new(format!("ak:blob:sha256:{}", "e".repeat(64)))
        .expect("MIMI fixture canonical blob ref");
    let proxy_body = json!({
        "asset_ref": asset_ref.as_str(),
        "requester": MIMI_ALICE_ACTOR_ID,
        "strand_id": MIMI_TEST_STRAND_ID,
    });
    let proxy: Value = signed_mimi_post!(
        state,
        "http://server/_arkret/open/mimi/proxy-download",
        proxy_body,
        None
    )
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    let proxy_object = proxy.as_object().expect("proxy outcome object");
    assert_eq!(proxy_object.len(), 2);
    assert!(proxy_object.contains_key("download_ref"));
    assert!(proxy_object.contains_key("expires_at"));
    let proxy: arkret_models_collaboration::http_bodies::MimiProxyDownloadOutcome =
        serde_json::from_value(proxy).expect("closed proxy outcome");
    assert!(proxy.headers.is_empty());
    assert!(proxy.expires_at.is_some());
    let download_ref = reqwest::Url::parse(&proxy.download_ref).expect("proxy download URL");
    assert_eq!(download_ref.path(), "/_arkret/open/mimi/proxy-download");
    assert_eq!(
        download_ref
            .query_pairs()
            .find(|(name, _)| name == "asset_ref")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some(asset_ref.as_str())
    );

    let report_body = json!({
        "strand_id": MIMI_TEST_STRAND_ID,
        "mimi_room_uri": room_uri,
        "realm_id": demo_realm_id(),
        "target_ref": demo_realm_id(),
        "reporter": MIMI_ALICE_ACTOR_ID,
        "abuse_reason_code": "spam",
    });
    let report: Value = signed_mimi_post!(
        state,
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

#[test]
fn mimi_facade_writes_strand_into_canonical_reducer_chain() {
    run_on_deep_stack(
        "mimi_facade_writes_strand_into_canonical_reducer_chain",
        mimi_facade_writes_strand_into_canonical_reducer_chain_body,
    );
}

async fn mimi_facade_writes_strand_into_canonical_reducer_chain_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let demo_realm = demo_realm_id();
    let custom_realm_id = soland_test_support::cba_basis::seed_event_derived_realm_genesis_event(
        &state,
        state.service_full_id().as_str(),
        "MIMI migration target",
    )
    .await;
    let custom_realm = custom_realm_id.as_str();
    seed_test_realm_basis_seal(&state, demo_realm, state.service_full_id().as_str()).await;
    seed_test_realm_basis_seal(&state, custom_realm, state.service_full_id().as_str()).await;
    add_test_realm_member(&state, demo_realm, MIMI_SOURCE_SERVICE_FULL_ID);
    add_test_realm_member(&state, custom_realm, MIMI_SOURCE_SERVICE_FULL_ID);
    let room_id = "01JSMIMI-P4-E2E";
    let group_id = "mimi-group-p4-001";
    let room_uri = mimi_room_uri(&state, room_id);

    project_test_authorized_device(
        &state,
        MIMI_SOURCE_SERVICE_FULL_ID,
        MIMI_TEST_DEVICE_ID,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    let update_body = mimi_room_update_body(
        &state, &token, room_id, demo_realm, group_id, "hub", "accepted",
    )
    .await;
    let mut update_response = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        update_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await;
    let update_status = update_response.status_code;
    let update_resp: Value = update_response.take_json().await.unwrap();
    if update_resp["error"]["code"] == arkret_wire::ErrorCode::UnsupportedFeature.as_str() {
        assert_eq!(update_status, Some(StatusCode::NOT_IMPLEMENTED));
        assert!(
            state
                .test_persistence()
                .events()
                .snapshot_all()
                .await
                .unwrap()
                .iter()
                .all(|record| record.kind != arkret_wire::EventKind::MimiRoomBinding.as_str())
        );
        return;
    }
    assert_eq!(update_resp["accepted"], true, "room update: {update_resp}");
    let binding_event_id = update_resp["room_state_ref"]
        .as_str()
        .expect("room_state_ref missing");
    assert!(binding_event_id.starts_with("ak:event:"));

    let msg_resp: Value = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            demo_realm,
            group_id,
            1,
            MIMI_REMOTE_ACTOR_ID,
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

    let binding_event = accepted_canonical_event(&state, binding_event_id).await;
    assert_eq!(binding_event.kind.as_str(), "ak.mimi.room_binding");
    assert_eq!(binding_event.payload["mimi_room_uri"], room_uri);
    assert_eq!(
        binding_event.payload["binding_scope"]["realm_id"],
        demo_realm
    );

    let message_event = accepted_canonical_event(&state, arkret_event_id).await;
    assert_eq!(message_event.kind.as_str(), "ak.message.create");
    assert_eq!(message_event.actor_id.as_str(), state.service_id().as_str());
    assert_eq!(
        message_event.payload["mimi_provenance"]["attributed_sender_actor_id"],
        MIMI_REMOTE_ACTOR_ID
    );
    assert_eq!(
        message_event.payload["content"]["parts"][0]["body"],
        "hello from MIMI P4"
    );
    assert_eq!(
        message_event.payload["mimi_provenance"]["source_provider"],
        MIMI_SOURCE_SERVICE_ID
    );
    assert_eq!(
        message_event.payload["mimi_provenance"]["provenance"],
        "mimi_facade"
    );
    assert_eq!(
        message_event.payload["mimi_provenance"]["attributed_sender_device_id"],
        MIMI_TEST_DEVICE_ID
    );
    assert_eq!(
        message_event.payload["mimi_provenance"]["room_binding_ref"],
        binding_event_id
    );
    assert!(
        message_event.payload["mimi_provenance"]["source_envelope_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let report_resp: Value = signed_mimi_post!(
        state,
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
            "reporter": MIMI_ALICE_ACTOR_ID,
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

    let report_id = arkret_identifiers::ReportId::new(
        report_resp["report_id"]
            .as_str()
            .expect("MIMI report_id")
            .to_owned(),
    )
    .expect("canonical MIMI report_id");
    let report_event_id = arkret_identifiers::EventIdentityKey::new(
        report_id.digest_suite_code(),
        report_id.digest_bytes(),
    )
    .event_id();
    let report_event = accepted_canonical_event(&state, report_event_id.as_str()).await;
    assert_eq!(report_event.kind.as_str(), "ak.self.moderation.report");
    assert_eq!(report_event.payload["target_ref"], demo_realm);
    // `mimi-interop.md` §11 is about *attribution*: the report must name the
    // principal the facade resolved, not the provider that asserted it. The
    // facade holds no key for that principal, so it authors the envelope under
    // its own service DID and carries the resolved reporter in the payload, as
    // required by `mimi-interop.md` §11.
    assert_eq!(report_event.payload["reporter"], MIMI_ALICE_ACTOR_ID);
    assert_eq!(report_event.actor_id.as_str(), state.service_id().as_str());

    let custom_group_id = "mimi-group-p4-custom";
    let migrating_body = mimi_room_update_body(
        &state,
        &token,
        room_id,
        demo_realm,
        group_id,
        "hub",
        "migrating",
    )
    .await;
    let migrating_resp: Value = signed_mimi_post!(
        state,
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

    let rebound_body = mimi_room_update_body(
        &state,
        &token,
        room_id,
        custom_realm,
        custom_group_id,
        "hub",
        "accepted",
    )
    .await;
    let rebound_resp: Value = signed_mimi_post!(
        state,
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
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            custom_realm,
            custom_group_id,
            1,
            MIMI_REMOTE_ACTOR_ID,
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

    let second_event = accepted_canonical_event(&state, second_event_id).await;
    assert_eq!(
        second_event.realm_id.as_str(),
        custom_realm,
        "second message must route to the rebound realm_id"
    );

    let revoked_body = mimi_room_update_body(
        &state,
        &token,
        room_id,
        custom_realm,
        custom_group_id,
        "hub",
        "revoked",
    )
    .await;
    let revoked_resp: Value = signed_mimi_post!(
        state,
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

    let reopen_body = mimi_room_update_body(
        &state,
        &token,
        room_id,
        custom_realm,
        custom_group_id,
        "hub",
        "accepted",
    )
    .await;
    let mut reopen_resp = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        reopen_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await;
    assert_eq!(reopen_resp.status_code, Some(StatusCode::BAD_REQUEST));
    let reopen_error: Value = reopen_resp.take_json().await.unwrap();
    assert_eq!(
        reopen_error["error"]["code"],
        "mimi_room_binding_status_transition_invalid"
    );
}

#[test]
fn mimi_facade_enforces_e2ee_boundary_and_quarantines_unknown_content() {
    run_on_deep_stack(
        "mimi_facade_enforces_e2ee_boundary_and_quarantines_unknown_content",
        mimi_facade_enforces_e2ee_boundary_and_quarantines_unknown_content_body,
    );
}

async fn mimi_facade_enforces_e2ee_boundary_and_quarantines_unknown_content_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let realm_id = demo_realm_id();
    seed_test_realm_basis_seal(&state, realm_id, state.service_full_id().as_str()).await;
    add_test_realm_member(&state, realm_id, MIMI_SOURCE_SERVICE_FULL_ID);
    let room_id = "01JSMIMI-P75-POLICY";
    let group_id = "mimi-group-policy-001";
    let room_uri = mimi_room_uri(&state, room_id);

    project_test_authorized_device(
        &state,
        MIMI_SOURCE_SERVICE_FULL_ID,
        MIMI_TEST_DEVICE_ID,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    let update_body = mimi_room_update_body(
        &state, &token, room_id, realm_id, group_id, "hub", "accepted",
    )
    .await;
    let mut update_response = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/update"),
        update_body,
        Some(room_uri.as_str())
    )
    .send(&service)
    .await;
    let update_status = update_response.status_code;
    let update_resp: Value = update_response.take_json().await.unwrap();
    if update_resp["error"]["code"] == arkret_wire::ErrorCode::UnsupportedFeature.as_str() {
        assert_eq!(update_status, Some(StatusCode::NOT_IMPLEMENTED));
        assert!(
            state
                .test_persistence()
                .events()
                .snapshot_all()
                .await
                .unwrap()
                .iter()
                .all(|record| record.kind != arkret_wire::EventKind::MimiRoomBinding.as_str())
        );
        return;
    }
    assert_eq!(update_resp["accepted"], true, "room update: {update_resp}");

    let mut unmarked = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            MIMI_POLICY_ACTOR_ID,
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
    assert_eq!(unmarked.status_code, Some(StatusCode::BAD_REQUEST));
    let unmarked_body: Value = unmarked.take_json().await.unwrap();
    assert_eq!(
        unmarked_body["error"]["code"],
        "mimi_e2ee_boundary_unmarked"
    );

    let downgrade_resp: Value = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            MIMI_POLICY_ACTOR_ID,
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
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            MIMI_POLICY_ACTOR_ID,
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
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            MIMI_POLICY_ACTOR_ID,
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

    let downgrade_event = accepted_canonical_event(&state, &downgrade_event_id).await;
    assert_eq!(
        downgrade_event.payload["content"]["e2ee_downgrade"],
        "mimi_bridge"
    );
    assert_eq!(
        downgrade_event.payload["metadata"]["mimi_policy"]["e2ee_boundary"],
        "explicit_downgrade"
    );

    let transcript_event = accepted_canonical_event(&state, &transcript_event_id).await;
    assert_eq!(
        transcript_event.payload["content"]["transcript_binding"]["transcript_hash"],
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(
        transcript_event.payload["metadata"]["mimi_policy"]["e2ee_boundary"],
        "transcript_bound"
    );

    let quarantine_event = accepted_canonical_event(&state, &quarantine_event_id).await;
    assert_eq!(
        quarantine_event.payload["content"]["kind"],
        "ak.content.text"
    );
    assert_eq!(
        quarantine_event.payload["content"]["unknown_content_kind"],
        "m.location.share.live"
    );
    assert_eq!(
        quarantine_event.payload["metadata"]["quarantine"]["unknown_content_kind"],
        "m.location.share.live"
    );
}
