//! Integration tests for the MIMI facade.

use serde_json::json;

use super::common::*;

const MIMI_SOURCE_SERVICE_DID: &str = "did:web:remote-mimi.example";
const MIMI_SOURCE_SERVICE_ID: &str = "ak:did_core:web:remote-mimi.example";
const MIMI_PROVIDER_ID: &str = "mimi://remote-mimi.example/provider";
const MIMI_TEST_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const MIMI_TEST_STRAND_ID: &str = "ak:strand:AeR8kl_pHP0Rj8sdg-m7-2iv0BbzptjujMXzwBoelVPt";
const MIMI_TEST_POLICY_ROOT: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

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
    let verification_method = format!("{MIMI_SOURCE_SERVICE_DID}#mimi-provider-test-key");
    let destination_id = state.service_id().as_str();
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
        ("destination-service-id", destination_id.to_owned()),
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
    let service_did = state.service_did();
    let service_did = service_did.as_str();
    let provider_id = if let Some(domain) = service_did.strip_prefix("did:web:") {
        format!("mimi://{}", canonical_mimi_authority(domain))
    } else if let Some(rest) = service_did.strip_prefix("did:webvh:") {
        let (scid, authority_and_path) = rest
            .split_once(':')
            .expect("fixture WebVH service identity must carry an authority");
        assert!(!scid.is_empty());
        assert!(!authority_and_path.is_empty());
        format!("mimi://{}", canonical_mimi_authority(authority_and_path))
    } else {
        format!("mimi://{}", service_did.replace(':', ".").to_lowercase())
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
        "hub_provider_id": "ak:did_core:web:hub-mimi.example",
        "local_provider_role": role,
        "follower_provider_ids": [],
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
        MIMI_SOURCE_SERVICE_DID,
        MIMI_TEST_DEVICE_ID,
        realm_id,
        0,
        vec![],
        binding["payload"].clone(),
    );
    move_event_to_actor_realm_frontier(state, token, MIMI_SOURCE_SERVICE_DID, realm_id, &mut event)
        .await;
    let submission = arkret_wire::EventInitialSubmission {
        publication_event: None,
        mls_frontier_leaves: None,
        event: serde_json::from_value(event).unwrap(),
        authorization_lease: None,
        cbs_proof_bundles: Vec::new(),
        control_proposal_ack: None,
        membership_compensation_evidence: None,
    };
    json!({
        "mls_group_id": group_id,
        "epoch": 1,
        "sender_actor_id": submission.event.actor_id,
        "room_binding_event": submission,
        "update": {
            "kind": "ak.mimi.room_binding",
            "payload": mimi_opaque_payload(binding, "payload_digest")
        }
    })
}

fn mimi_source_station_account(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id(principal),
        arkret_wire::DidCoreId::new(MIMI_SOURCE_SERVICE_ID).unwrap(),
    ))
}

fn mimi_submit_body(
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    sender: arkret_wire::ActorId,
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
    json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1",
        "mls_group_id": group_id,
        "previous_epoch": epoch.saturating_sub(1),
        "next_epoch": epoch,
        "realm_id": realm_id,
        "effective_scope": {
            "kind": "realm",
            "realm_id": realm_id,
        },
        "security_frontier_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "content_scheme": "mls_rfc9420",
    })
}

fn project_mimi_sender_and_frontier(
    state: &AppState,
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    sender: &arkret_wire::ActorId,
) {
    let now = chrono::Utc::now();
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let scope_key = soland_domain::reducer::mls::effective_scope_key(&effective_scope).unwrap();
    let mut projection = state.test_projections().test_state().lock();
    projection.members.insert(
        (realm_id.to_owned(), sender.to_string()),
        soland_domain::reducer::SolandMembershipState {
            member: sender.to_string(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: Some(
                "ak:event:AZ6wcRvTARthqkHiE-HOofDuOIbhnuXN6XUmeCaLoGhn".to_owned(),
            ),
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    projection.mls_commit_epochs.insert(
        soland_domain::reducer::MlsCommitEpochKey::new(scope_key, group_id),
        soland_domain::reducer::MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope,
            epoch,
            leader_actor_id: sender.to_string(),
            creator_device_id: MIMI_TEST_DEVICE_ID.to_owned(),
            genesis_event_ref: "ak:event:AZ6wcRvTARthqkHiE-HOofDuOIbhnuXN6XUmeCaLoGhn".to_owned(),
            committed_at: now.timestamp(),
            governance_binding: mimi_governance_binding(realm_id, group_id, epoch),
            accepted_commit_digest: Some(format!("sha256:{}", "3".repeat(64))),
            accepted_commit_ref: Some(
                "ak:event:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD".to_owned(),
            ),
        },
    );
}

fn text_mimi_message(message_id: &str, body: &str) -> Value {
    json!({
        "source_format": "application/mimi-content",
        "e2ee_downgrade": "mimi_bridge",
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

fn fixture_event_id(seed: &[u8]) -> arkret_wire::EventId {
    arkret_wire::EventId::from_event_digest(
        &arkret_wire::Hash::new(arkret_canonical::sha256_digest(seed)).unwrap(),
    )
    .unwrap()
}

async fn install_current_mimi_report_binding(
    state: &AppState,
    realm_id: &str,
    room_uri: &str,
    strand_id: &str,
) -> (
    arkret_wire::ActorId,
    arkret_wire::EventId,
    arkret_wire::EventId,
) {
    let reporter_did = "did:web:alice.example";
    add_test_realm_member(state, realm_id, reporter_did);
    let reporter_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id(reporter_did),
        state.service_core_id(),
    ));
    let membership_event_id = fixture_event_id(b"mimi-reporter-membership");
    state
        .test_projection()
        .lock()
        .members
        .get_mut(&(realm_id.to_owned(), reporter_actor.to_string()))
        .expect("fixture joined member")
        .membership_event_ref = Some(membership_event_id.to_string());

    let created_at = chrono::Utc::now();
    let room_event = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::MimiRoomBinding.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).unwrap(),
        },
        arkret_wire::ActorId::service(state.service_core_id()),
        0,
        arkret_wire::Hlc::new("019641370000-0000-00000044".to_owned()).unwrap(),
        json!({
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": room_uri,
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": strand_id,
            },
            "hub_provider_id": MIMI_SOURCE_SERVICE_ID,
            "local_provider_role": "hub",
            "follower_provider_ids": [],
            "content_profile": "application/mimi-content",
            "policy_root": MIMI_TEST_POLICY_ROOT,
            "status": "accepted",
            "created_at": "2026-09-01T00:00:00.000Z",
        }),
        created_at,
    )
    .unwrap();
    let room_binding_event_id = room_event.event_id.clone();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &room_event,
            Some(realm_id),
            created_at,
        ))
        .await
        .unwrap();
    (reporter_actor, membership_event_id, room_binding_event_id)
}

async fn install_revoked_mimi_room_binding_head(
    state: &AppState,
    realm_id: &str,
    room_uri: &str,
    predecessor: arkret_wire::EventId,
) {
    let created_at = chrono::Utc::now();
    let mut revoked = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::MimiRoomBinding.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).unwrap(),
        },
        arkret_wire::ActorId::service(state.service_core_id()),
        1,
        arkret_wire::Hlc::new("019641370001-0000-00000044".to_owned()).unwrap(),
        json!({
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": room_uri,
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": MIMI_TEST_STRAND_ID,
            },
            "hub_provider_id": MIMI_SOURCE_SERVICE_ID,
            "local_provider_role": "hub",
            "follower_provider_ids": [],
            "content_profile": "application/mimi-content",
            "policy_root": MIMI_TEST_POLICY_ROOT,
            "status": "revoked",
            "created_at": "2026-09-01T00:00:01.000Z",
        }),
        created_at,
    )
    .unwrap();
    revoked.prev_refs = vec![predecessor];
    revoked
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &revoked,
            Some(realm_id),
            created_at,
        ))
        .await
        .unwrap();
}

async fn install_parallel_mimi_room_binding_head(state: &AppState, realm_id: &str, room_uri: &str) {
    let created_at = chrono::Utc::now();
    let parallel = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::MimiRoomBinding.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm_id.to_owned()).unwrap(),
        },
        arkret_wire::ActorId::service(state.service_core_id()),
        1,
        arkret_wire::Hlc::new("019641370002-0000-00000044".to_owned()).unwrap(),
        json!({
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": room_uri,
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": MIMI_TEST_STRAND_ID,
            },
            "hub_provider_id": MIMI_SOURCE_SERVICE_ID,
            "local_provider_role": "hub",
            "follower_provider_ids": [],
            "content_profile": "application/mimi-content",
            "policy_root": MIMI_TEST_POLICY_ROOT,
            "status": "accepted",
            "created_at": "2026-09-01T00:00:02.000Z",
        }),
        created_at,
    )
    .unwrap();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &parallel,
            Some(realm_id),
            created_at,
        ))
        .await
        .unwrap();
}

async fn exact_human_mimi_report_body(
    state: &AppState,
    token: &str,
    realm_id: &str,
    room_uri: &str,
) -> arkret_models_collaboration::http_bodies::MimiReportAbuseRequestBody {
    let (reporter_actor, membership_event_id, room_binding_event_id) =
        install_current_mimi_report_binding(state, realm_id, room_uri, MIMI_TEST_STRAND_ID).await;
    let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
    project_test_authorized_device(
        state,
        "did:web:alice.example",
        MIMI_TEST_DEVICE_ID,
        &signing_key,
    )
    .await;
    let mut report_event = signed_canonical_event(
        "mimi-caller-authored-report",
        arkret_wire::EventKind::SelfModerationReport.as_str(),
        "did:web:alice.example",
        MIMI_TEST_DEVICE_ID,
        realm_id,
        0,
        Vec::new(),
        json!({
            "realm_id": realm_id,
            "effective_scope": {"kind": "realm", "realm_id": realm_id},
            "target_ref": realm_id,
            "report_reason_code": "spam",
            "reporter_id": "ak:did_core:web:alice.example",
            "provenance": "mimi_facade",
            "source_provider_id": MIMI_SOURCE_SERVICE_ID,
        }),
    );
    move_event_to_actor_realm_frontier(
        state,
        token,
        "did:web:alice.example",
        realm_id,
        &mut report_event,
    )
    .await;
    let report_event: arkret_wire::Event = serde_json::from_value(report_event).unwrap();
    assert_eq!(report_event.actor_id, reporter_actor);
    let verification_method = report_event
        .producer_proof
        .as_ref()
        .expect("producer proof")
        .verification_method
        .clone();
    let created_at = chrono::Utc::now();
    let mut body = arkret_models_collaboration::http_bodies::MimiReportAbuseRequestBody {
        reporter_authority: arkret_models_collaboration::http_bodies::MimiReporterAuthority {
            actor_id: reporter_actor,
            membership_event_id,
            room_binding_event_id,
            expires_at: created_at + chrono::Duration::minutes(4),
            proof: arkret_wire::PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method,
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at,
                domain: Some(state.config().trust_domain.to_string()),
                audience: Some(arkret_wire::Audience::Single(state.service_id().clone())),
                proof_purpose: None,
                jws: String::new(),
            },
        },
        report_event: arkret_wire::EventInitialSubmission::online(report_event),
        cbs_proof_bundles: Vec::new(),
    };
    body.reporter_authority.proof.payload_digest = body.payload_digest().unwrap();
    body.reporter_authority.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &body
            .unsigned_reporter_authority_binding_bytes(&body.reporter_authority.proof.unsigned())
            .unwrap(),
        &signing_key,
    )
    .unwrap();
    body
}

fn resign_human_mimi_report_authority(
    body: &mut arkret_models_collaboration::http_bodies::MimiReportAbuseRequestBody,
) {
    let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
    body.reporter_authority.proof.payload_digest = body.payload_digest().unwrap();
    body.reporter_authority.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &body
            .unsigned_reporter_authority_binding_bytes(&body.reporter_authority.proof.unsigned())
            .unwrap(),
        &signing_key,
    )
    .unwrap();
}

fn sign_mimi_agent_report_event(
    event: Value,
    verification_method: &arkret_wire::DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Event {
    let signer_did =
        arkret_identity::verification_method_did(verification_method.as_str()).unwrap();
    let mut event: arkret_wire::Event = serde_json::from_value(event).unwrap();
    event.producer_proof = None;
    let created_at = event.created_at;
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key.clone(),
        signer_did,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        verification_method,
        arkret_signatures::SignEventOptions::new(soland_test_support::fixture_signer_evidence_ref()).with_created_at(created_at),
    )
    .unwrap();
    event.into_event()
}

async fn exact_agent_mimi_report_body(
    state: &AppState,
    runtime_key: &SigningKey,
    controller_token: &str,
    realm_id: &str,
    room_uri: &str,
) -> arkret_models_collaboration::http_bodies::MimiReportAbuseRequestBody {
    let (reporter_actor, membership_event_id, room_binding_event_id) =
        install_current_mimi_report_binding(state, realm_id, room_uri, MIMI_TEST_STRAND_ID).await;
    let controller_principal_id = fixture_actor_core_id("did:web:alice.example");
    let records = state
        .test_persistence()
        .agents()
        .list_for_controller(controller_principal_id.as_str())
        .await
        .unwrap();
    let record = records
        .into_iter()
        .next()
        .expect("active Agent runtime fixture");
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(record.id.clone()).unwrap(),
        state.service_core_id(),
    ));
    let verification_method = arkret_wire::DidUrl::new(
        record
            .authorized_verification_method
            .clone()
            .expect("current Agent verification method"),
    )
    .unwrap();
    let authorization_ref = record
        .authorized_event_ref
        .clone()
        .expect("current Agent authorization Event");
    let mut report_event = signed_canonical_event(
        "mimi-agent-caller-authored-report",
        arkret_wire::EventKind::SelfModerationReport.as_str(),
        "did:web:alice.example",
        MIMI_TEST_DEVICE_ID,
        realm_id,
        0,
        Vec::new(),
        json!({
            "realm_id": realm_id,
            "effective_scope": {"kind": "realm", "realm_id": realm_id},
            "target_ref": realm_id,
            "report_reason_code": "spam",
            "reporter_id": "ak:did_core:web:alice.example",
            "provenance": "mimi_facade",
            "source_provider_id": MIMI_SOURCE_SERVICE_ID,
        }),
    );
    move_event_to_actor_realm_frontier(
        state,
        controller_token,
        "did:web:alice.example",
        realm_id,
        &mut report_event,
    )
    .await;
    report_event["executed_by"] = serde_json::to_value(&agent_actor).unwrap();
    report_event["authorization_ref"] = json!(authorization_ref);
    let report_event =
        sign_mimi_agent_report_event(report_event, &verification_method, runtime_key);
    assert_eq!(report_event.actor_id, reporter_actor);

    let created_at = chrono::Utc::now();
    let mut body = arkret_models_collaboration::http_bodies::MimiReportAbuseRequestBody {
        reporter_authority: arkret_models_collaboration::http_bodies::MimiReporterAuthority {
            actor_id: reporter_actor,
            membership_event_id,
            room_binding_event_id,
            expires_at: created_at + chrono::Duration::minutes(4),
            proof: arkret_wire::PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method,
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at,
                domain: Some(state.config().trust_domain.to_string()),
                audience: Some(arkret_wire::Audience::Single(state.service_id().clone())),
                proof_purpose: None,
                jws: String::new(),
            },
        },
        report_event: arkret_wire::EventInitialSubmission::online(report_event),
        cbs_proof_bundles: Vec::new(),
    };
    body.reporter_authority.proof.payload_digest = body.payload_digest().unwrap();
    body.reporter_authority.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &body
            .unsigned_reporter_authority_binding_bytes(&body.reporter_authority.proof.unsigned())
            .unwrap(),
        runtime_key,
    )
    .unwrap();
    body
}

#[test]
fn mimi_report_accepts_exact_human_authority_and_persists_caller_event() {
    run_on_deep_stack(
        "mimi_report_accepts_exact_human_authority_and_persists_caller_event",
        || async {
            let state = soland_test_support::app_state(test_config());
            let token = dev_token(state.clone()).await;
            let realm_id = demo_realm_id();
            let room_uri = "mimi://provider.example/rooms/human-report";
            let body = exact_human_mimi_report_body(&state, &token, realm_id, room_uri).await;
            let event_id = body.report_event.event.event_id.clone();
            let service = app_from_state(state.clone());

            let response: Value = signed_mimi_post!(
                state,
                "http://server/_arkret/open/mimi/report-abuse",
                serde_json::to_value(&body).unwrap(),
                None
            )
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
            assert_eq!(response["status"], "queued", "response: {response}");
            let stored = state
                .test_persistence()
                .events()
                .get(event_id.as_str())
                .await
                .unwrap()
                .expect("caller-authored report Event is durable");
            let stored: arkret_wire::Event = serde_json::from_value(stored.envelope).unwrap();
            assert_eq!(stored.event_id, event_id);
            assert_eq!(stored.actor_id, body.reporter_authority.actor_id);
            assert_eq!(stored.proofs.len(), 1);
        },
    );
}

#[test]
fn mimi_report_accepts_current_agent_proxy_and_freezes_signer_evidence() {
    run_on_deep_stack(
        "mimi_report_accepts_current_agent_proxy_and_freezes_signer_evidence",
        || async {
            let slug = "mimi-agent-reporter";
            let (state, runtime) = super::events::seed_agent_grant_session(
                slug,
                &["ak.self.events.command.submit.v1"],
            )
            .await;
            let controller_token = format!("agent-grant-controller-{slug}");
            let realm_id = demo_realm_id();
            let room_uri = "mimi://provider.example/rooms/agent-report";
            let body = exact_agent_mimi_report_body(
                &state,
                &runtime.holder_key,
                &controller_token,
                realm_id,
                room_uri,
            )
            .await;
            let event_id = body.report_event.event.event_id.clone();
            let service = app_from_state(state.clone());

            let response: Value = signed_mimi_post!(
                state,
                "http://server/_arkret/open/mimi/report-abuse",
                serde_json::to_value(&body).unwrap(),
                None
            )
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
            assert_eq!(response["status"], "queued", "response: {response}");
            let stored = state
                .test_persistence()
                .events()
                .get(event_id.as_str())
                .await
                .unwrap()
                .expect("Agent-proxied caller Event is durable");
            let stored: arkret_wire::Event = serde_json::from_value(stored.envelope).unwrap();
            let producer = &stored.proofs[0];
            let evidence_ref = producer
                .signer_resolution_evidence_ref
                .as_ref()
                .expect("Agent producer retains the frozen signer evidence ref");
            evidence_ref
                .content_digest()
                .expect("the frozen producer evidence ref carries the only digest on the wire");
        },
    );
}

#[test]
fn mimi_report_event_binding_rejection_has_no_event_or_rate_side_effect() {
    run_on_deep_stack(
        "mimi_report_event_binding_rejection_has_no_event_or_rate_side_effect",
        || async {
            let state = soland_test_support::app_state(test_config());
            let token = dev_token(state.clone()).await;
            let realm_id = demo_realm_id();
            let room_uri = "mimi://provider.example/rooms/pre-state-rejection";
            let valid = exact_human_mimi_report_body(&state, &token, realm_id, room_uri).await;
            let event_id = valid.report_event.event.event_id.clone();
            let mut target_swap = valid.clone();
            target_swap.report_event.event.payload.insert(
                "target_ref".to_owned(),
                json!("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            );

            let mut stale_membership = valid.clone();
            stale_membership.reporter_authority.membership_event_id =
                fixture_event_id(b"stale-mimi-membership");
            resign_human_mimi_report_authority(&mut stale_membership);

            let mut stale_room_binding = valid.clone();
            stale_room_binding.reporter_authority.room_binding_event_id =
                fixture_event_id(b"stale-mimi-room-binding");
            resign_human_mimi_report_authority(&mut stale_room_binding);

            let mut provider_swap = valid.clone();
            provider_swap.report_event.event.payload.insert(
                "source_provider_id".to_owned(),
                json!("ak:did_core:web:other-provider.example"),
            );
            resign_human_mimi_report_authority(&mut provider_swap);

            let mut expired = valid.clone();
            expired.reporter_authority.proof.created_at -= chrono::Duration::minutes(10);
            expired.reporter_authority.expires_at =
                expired.reporter_authority.proof.created_at + chrono::Duration::minutes(4);
            resign_human_mimi_report_authority(&mut expired);

            // Encrypted evidence content cannot replace the exact current
            // membership generation even when it is cross-bound into the
            // caller Event and holder transcript.
            let mut opaque_only = stale_membership.clone();
            let target_ref = opaque_only.report_event.event.payload["target_ref"].clone();
            let opaque = json!({
                "target_refs": [target_ref],
                "encryption": "HPKE-Base-X25519-SHA256-AES128GCM",
                "recipient_public_key_ref": "did:web:moderator.example#key-1",
                "encrypted_to_kid": "did:web:moderator.example#key-1",
                "ciphertext": "e30",
                "ciphertext_digest": format!("sha256:{}", "1".repeat(64)),
                "reporter_signature": "c2ln"
            });
            opaque_only
                .report_event
                .event
                .payload
                .insert("evidence_package".to_owned(), opaque);
            resign_human_mimi_report_authority(&mut opaque_only);
            let service = app_from_state(state.clone());

            for (label, forged) in [
                ("target/Event swap", target_swap),
                ("stale membership", stale_membership),
                ("stale room binding", stale_room_binding),
                ("provider swap", provider_swap),
                ("expired authority", expired),
                ("opaque without current membership", opaque_only),
            ] {
                let mut rejected = signed_mimi_post!(
                    state,
                    "http://server/_arkret/open/mimi/report-abuse",
                    serde_json::to_value(&forged).unwrap(),
                    None
                )
                .send(&service)
                .await;
                assert_eq!(rejected.status_code, Some(StatusCode::FORBIDDEN), "{label}");
                let problem: Value = rejected.take_json().await.unwrap();
                assert_eq!(
                    problem_code(&problem),
                    "mimi_reporter_resolution_required",
                    "{label}: {problem}"
                );
            }
            assert!(
                !state
                    .test_persistence()
                    .events()
                    .contains(event_id.as_str())
                    .await
                    .unwrap(),
                "pre-state cross-binding rejection must not persist the caller Event"
            );

            // The valid request has the same complete reporter Actor, source
            // provider, Realm, source IP and target. Its first accepted attempt
            // would be rejected by the one-per-target bucket if the forged
            // request above had consumed moderation capacity.
            let accepted: Value = signed_mimi_post!(
                state,
                "http://server/_arkret/open/mimi/report-abuse",
                serde_json::to_value(&valid).unwrap(),
                None
            )
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
            assert_eq!(accepted["status"], "queued", "response: {accepted}");
            assert!(
                state
                    .test_persistence()
                    .events()
                    .contains(event_id.as_str())
                    .await
                    .unwrap(),
                "the exact caller-authored Event must remain admissible"
            );
        },
    );
}

#[test]
fn mimi_report_rejects_revoked_room_head_without_event_or_rate_side_effect() {
    run_on_deep_stack(
        "mimi_report_rejects_revoked_room_head_without_event_or_rate_side_effect",
        || async {
            let state = soland_test_support::app_state(test_config());
            let token = dev_token(state.clone()).await;
            let realm_id = demo_realm_id();
            let room_uri = "mimi://provider.example/rooms/revoked-report";
            let body = exact_human_mimi_report_body(&state, &token, realm_id, room_uri).await;
            let event_id = body.report_event.event.event_id.clone();
            install_revoked_mimi_room_binding_head(
                &state,
                realm_id,
                room_uri,
                body.reporter_authority.room_binding_event_id.clone(),
            )
            .await;

            let mut rejected = signed_mimi_post!(
                state,
                "http://server/_arkret/open/mimi/report-abuse",
                serde_json::to_value(&body).unwrap(),
                None
            )
            .send(&app_from_state(state.clone()))
            .await;
            assert_eq!(rejected.status_code, Some(StatusCode::FORBIDDEN));
            let problem: Value = rejected.take_json().await.unwrap();
            assert_eq!(problem_code(&problem), "mimi_reporter_resolution_required");
            assert!(
                !state
                    .test_persistence()
                    .events()
                    .contains(event_id.as_str())
                    .await
                    .unwrap()
            );
            let rate_probe = state.record_moderation_report_attempt(
                &body.reporter_authority.actor_id.to_string(),
                Some(MIMI_SOURCE_SERVICE_ID),
                realm_id,
                "post-rejection-probe",
                body.report_payload().unwrap().target_ref.as_str(),
            );
            assert!(
                !rate_probe.rate_limited,
                "revoked room binding must reject before moderation rate state"
            );
        },
    );
}

#[test]
fn mimi_report_rejects_ambiguous_room_heads_without_event_or_rate_side_effect() {
    run_on_deep_stack(
        "mimi_report_rejects_ambiguous_room_heads_without_event_or_rate_side_effect",
        || async {
            let state = soland_test_support::app_state(test_config());
            let token = dev_token(state.clone()).await;
            let realm_id = demo_realm_id();
            let room_uri = "mimi://provider.example/rooms/ambiguous-report";
            let body = exact_human_mimi_report_body(&state, &token, realm_id, room_uri).await;
            let event_id = body.report_event.event.event_id.clone();
            install_parallel_mimi_room_binding_head(&state, realm_id, room_uri).await;

            let mut rejected = signed_mimi_post!(
                state,
                "http://server/_arkret/open/mimi/report-abuse",
                serde_json::to_value(&body).unwrap(),
                None
            )
            .send(&app_from_state(state.clone()))
            .await;
            assert_eq!(rejected.status_code, Some(StatusCode::FORBIDDEN));
            let problem: Value = rejected.take_json().await.unwrap();
            assert_eq!(problem_code(&problem), "mimi_reporter_resolution_required");
            assert!(
                !state
                    .test_persistence()
                    .events()
                    .contains(event_id.as_str())
                    .await
                    .unwrap()
            );
            let rate_probe = state.record_moderation_report_attempt(
                &body.reporter_authority.actor_id.to_string(),
                Some(MIMI_SOURCE_SERVICE_ID),
                realm_id,
                "post-ambiguity-probe",
                body.report_payload().unwrap().target_ref.as_str(),
            );
            assert!(
                !rate_probe.rate_limited,
                "ambiguous room heads must reject before moderation rate state"
            );
        },
    );
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
    seed_test_realm_basis_seal(&state, demo_realm_id(), state.service_did().as_str()).await;
    add_test_realm_member(&state, demo_realm_id(), MIMI_SOURCE_SERVICE_DID);
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
        "requester_id": MIMI_SOURCE_SERVICE_ID,
        "strand_id": MIMI_TEST_STRAND_ID,
        "device_id": MIMI_TEST_DEVICE_ID,
        "mimi_room_uri": mimi_room_uri(&state, "01JSMIMI"),
        "realm_id": demo_realm_id(),
        "mls_group_id": "mimi-group-01JSMIMI",
        "epoch": 1,
    });
    let mut key_material_response = signed_mimi_post!(
        state,
        "http://server/_arkret/open/mimi/key-material",
        key_material_body,
        None
    )
    .send(&service)
    .await;
    assert_eq!(
        key_material_response.status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let key_material: Value = key_material_response.take_json().await.unwrap();
    assert_eq!(problem_code(&key_material), "claim_failed");

    let room_id = "01JSMIMI";
    let group_id = "mimi-group-01JSMIMI";
    let room_uri = mimi_room_uri(&state, room_id);
    project_test_authorized_device(
        &state,
        MIMI_SOURCE_SERVICE_DID,
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
    if room_binding["type"]
        .as_str()
        .and_then(|uri| uri.rsplit('/').next())
        == Some(arkret_wire::ErrorCode::UnsupportedFeature.as_str())
    {
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

    let commitment = identifier_commitment("mimi://remote.example/alice");
    let identifier_body = json!({
        "identifiers": [{
            "kind": "mimi_uri",
            "identifier_commitment": commitment.clone(),
        }],
        "requester_id": MIMI_SOURCE_SERVICE_ID,
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

    let sender = mimi_source_station_account("did:web:alice.example");
    project_mimi_sender_and_frontier(&state, demo_realm_id(), group_id, 1, &sender);
    let message_body = mimi_submit_body(
        demo_realm_id(),
        group_id,
        1,
        sender,
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
    assert!(
        mapped["event_ref"].as_str().is_some(),
        "mapped response: {mapped}"
    );
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
        "asset_ref": format!("ak:blob:sha256:{}", "e".repeat(64)),
        "requester_id": MIMI_SOURCE_SERVICE_ID,
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
    assert!(
        proxy["download_ref"]
            .as_str()
            .unwrap()
            .contains("/mimi/proxy-download")
    );
    assert!(proxy["expires_at"].as_str().is_some());
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
    let custom_realm_value = seed_test_realm(
        &state,
        state.service_did().as_str(),
        "MIMI migration target",
        None,
        "restricted",
        &[],
        &[],
    )
    .await;
    let custom_realm_id = custom_realm_value["realm_id"].as_str().unwrap().to_owned();
    let custom_realm = custom_realm_id.as_str();
    seed_test_realm_basis_seal(&state, demo_realm, state.service_did().as_str()).await;
    seed_test_realm_basis_seal(&state, custom_realm, state.service_did().as_str()).await;
    add_test_realm_member(&state, demo_realm, MIMI_SOURCE_SERVICE_DID);
    add_test_realm_member(&state, custom_realm, MIMI_SOURCE_SERVICE_DID);
    add_test_realm_member(&state, custom_realm, "did:web:alice.example");
    let room_id = "01JSMIMI-P4-E2E";
    let group_id = "mimi-group-p4-001";
    let room_uri = mimi_room_uri(&state, room_id);

    project_test_authorized_device(
        &state,
        MIMI_SOURCE_SERVICE_DID,
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
    if update_resp["type"]
        .as_str()
        .and_then(|uri| uri.rsplit('/').next())
        == Some(arkret_wire::ErrorCode::UnsupportedFeature.as_str())
    {
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

    let sender = mimi_source_station_account("did:web:remote.example");
    project_mimi_sender_and_frontier(&state, demo_realm, group_id, 1, &sender);
    let msg_resp: Value = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            demo_realm,
            group_id,
            1,
            sender.clone(),
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

    let events: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realm_ids": [demo_realm]}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    let list = events["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events array: {events}"));

    let binding_event = list
        .iter()
        .find(|event| event["event_id"] == binding_event_id)
        .expect("room_binding event missing from projection log");
    assert_eq!(event_kind(binding_event), Some("ak.mimi.room_binding"));
    assert_eq!(binding_event["payload"]["mimi_room_uri"], room_uri);
    assert_eq!(
        binding_event["payload"]["binding_scope"]["realm_id"],
        demo_realm
    );

    let message_event = list
        .iter()
        .find(|event| event["event_id"] == arkret_event_id)
        .expect("MIMI-ingressed message missing from projection log");
    assert_eq!(event_kind(message_event), Some("ak.message.create"));
    assert_eq!(
        message_event["actor_id"],
        serde_json::to_value(arkret_wire::ActorId::service(
            state.service_core_id().clone()
        ))
        .unwrap()
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["attributed_sender_actor_id"],
        serde_json::to_value(&sender).unwrap()
    );
    assert_eq!(
        message_event["payload"]["content"]["parts"][0]["body"],
        "hello from MIMI P4"
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["source_provider_id"],
        MIMI_SOURCE_SERVICE_ID
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["provenance"],
        "mimi_facade"
    );

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

    project_mimi_sender_and_frontier(&state, custom_realm, custom_group_id, 1, &sender);
    let msg_resp_2: Value = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            custom_realm,
            custom_group_id,
            1,
            sender,
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
    assert_eq!(reopen_resp.status_code.unwrap().as_u16(), 400);
    let reopen_error: Value = reopen_resp.take_json().await.unwrap();
    assert_eq!(
        problem_code(&reopen_error),
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
    seed_test_realm_basis_seal(&state, realm_id, state.service_did().as_str()).await;
    add_test_realm_member(&state, realm_id, MIMI_SOURCE_SERVICE_DID);
    let room_id = "01JSMIMI-P75-POLICY";
    let group_id = "mimi-group-policy-001";
    let room_uri = mimi_room_uri(&state, room_id);

    project_test_authorized_device(
        &state,
        MIMI_SOURCE_SERVICE_DID,
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
    if update_resp["type"]
        .as_str()
        .and_then(|uri| uri.rsplit('/').next())
        == Some(arkret_wire::ErrorCode::UnsupportedFeature.as_str())
    {
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
    let sender = mimi_source_station_account("did:web:mimi.example");
    project_mimi_sender_and_frontier(&state, realm_id, group_id, 1, &sender);

    let mut unmarked = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            sender.clone(),
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
    assert_eq!(problem_code(&unmarked_body), "mimi_e2ee_boundary_unmarked");

    let downgrade_resp: Value = signed_mimi_post!(
        state,
        format!("http://server/_arkret/open/mimi/strands/{room_id}/messages"),
        mimi_submit_body(
            realm_id,
            group_id,
            1,
            sender.clone(),
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
            sender.clone(),
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
            sender,
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

    let events: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realm_ids": [realm_id]}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    let list = events["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events array: {events}"));
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
