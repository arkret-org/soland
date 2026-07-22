//! Integration tests - personal-agent HTTP surfaces.

use arkret_core::MoveSigner as _;

use super::common::*;

pub(crate) const CONTROLLER_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
pub(crate) const CONTROLLER_DEVICE_SIGNING_SEED: [u8; 32] = [91u8; 32];

fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

pub(crate) async fn seed_controller_session(state: &AppState, token: &str, actor: &str) {
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .sessions()
        .put(&soland_storage::SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            actor: actor.to_owned(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

pub(crate) async fn seed_active_controller_device_generation(state: &AppState, controller: &str) {
    let now = chrono::Utc::now();
    let generation_ref = "1-test-device-generation";
    let signing_key = SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED);
    state
        .test_persistence()
        .webvh()
        .append_log_event(soland_storage::WebvhLogRecord {
            event_digest: format!("sha256:{}", "1".repeat(64)),
            did: controller.to_owned(),
            seq: 1,
            operation: serde_json::json!({
                "versionId": generation_ref,
                "state": {
                    "service": [{
                        "id": format!("{controller}#device-enrollment-authority"),
                        "type": arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
                        "serviceEndpoint": "did:web:device-authority.example"
                    }]
                }
            }),
            created_at: now,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .webvh()
        .put_document(soland_storage::WebvhDocumentRecord {
            did: controller.to_owned(),
            did_document: serde_json::json!({
                "id": controller
            }),
            key_log_head: Some(format!("sha256:{}", "1".repeat(64))),
            seq: 1,
            method_evidence: serde_json::json!({"mode": "test"}),
            fetched_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            updated_at: now,
        })
        .await
        .unwrap();

    let realm_id = soland_test_support::principal_control_realm_for_did(controller);
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(now.timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", created_at.timestamp_millis());
    let realm = arkret_core::RealmId::new(realm_id.clone()).unwrap();
    let actor = arkret_core::Did::new(controller.to_owned()).unwrap();
    let mut bootstrap = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: actor.clone(),
            realm_id: realm.clone(),
            trust_domain: arkret_core::TypedTrustDomainId::new(
                "ak:trust_domain:soland.local".to_owned(),
            )
            .unwrap(),
            did_inception_ref: arkret_core::EventRef::new(
                format!("sha256:{}", "1".repeat(64)),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            event_id: arkret_core::EventId::new(new_prefixed_uuid7("ak:event:")).unwrap(),
            created_at,
            hlc: arkret_core::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e")).unwrap(),
        },
    )
    .unwrap();
    let verification_method = format!("{controller}#{CONTROLLER_DEVICE_ID}");
    let bootstrap_signer = arkret_signatures::Ed25519MoveSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        actor.clone(),
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut bootstrap,
        &bootstrap_signer,
        "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let authorization_ref =
        arkret_core::NonEmptyString::new(format!("{controller}#device-enrollment-authority"))
            .unwrap();
    let authorize_payload = arkret_core::DeviceAuthorizePayload {
        principal_id: actor.clone(),
        device_id: arkret_core::DeviceId::new(CONTROLLER_DEVICE_ID).unwrap(),
        device_public_key: arkret_core::NonEmptyString::new(test_ed25519_multibase_public(
            &signing_key,
        ))
        .unwrap(),
        hpke_key: arkret_core::NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![
            arkret_core::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
        ],
        device_key_algorithm: Some(arkret_core::NonEmptyString::new("EdDSA").unwrap()),
        authorized_by: arkret_core::DeviceOrPrincipalRef::Did(actor.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(arkret_core::DeviceEnrollmentAuthorityBinding {
            kind: arkret_core::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: actor.clone(),
            authorization_ref: authorization_ref.clone(),
        }),
        recovery_session_id: None,
    };
    let mut authorize = arkret_core::Event::new_at(
        arkret_core::events::EventKind::DEVICE_AUTHORIZE,
        realm,
        actor.clone(),
        1,
        arkret_core::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        serde_json::to_value(authorize_payload).unwrap(),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![bootstrap.event_id.clone()];
    authorize.executed_by = Some(actor);
    authorize.authorization_ref = Some(authorization_ref.to_string());
    arkret_signatures::sign_event(
        &mut authorize,
        &bootstrap_signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let bootstrap_seal = arkret_bootstrap::build_self_principal_bootstrap_seal(
        &bootstrap,
        &authorize,
        arkret_core::Hlc::new(format!("{timestamp_hex}-0003-a13f9c2e")).unwrap(),
        &bootstrap_signer,
    )
    .unwrap();
    for (event, kind, actor_seq) in [
        (bootstrap, "ak.realm.create", 0),
        (authorize, "ak.device.authorize", 1),
    ] {
        let event_id = event.event_id.to_string();
        let canonical_digest = event.event_digest().unwrap();
        let envelope = serde_json::to_value(&event).unwrap();
        let canonical_bytes = arkret_core::canonical::canonical_json_bytes(&envelope).unwrap();
        state
            .test_persistence()
            .events()
            .put(soland_storage::CanonicalEventRecord {
                event_id,
                actor_id: controller.to_owned(),
                actor_seq,
                realm_id: Some(realm_id.clone()),
                kind: kind.to_owned(),
                schema_id: "ak.schema.event_envelope.v1".to_owned(),
                canonical_digest,
                canonical_bytes,
                envelope,
                received_at: now,
            })
            .await
            .unwrap();
    }
    state.test_put_seal(&bootstrap_seal).unwrap();

    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: controller.to_owned(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
                "authorized_generation_ref": generation_ref,
                "device_public_key": test_ed25519_multibase_public(&signing_key)
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

pub(crate) async fn seed_agent_provision_prerequisites(state: &AppState, controller: &str) {
    let now = chrono::Utc::now();
    let policy_id = new_prefixed_uuid7("ak:policy:");
    state
        .test_persistence()
        .recovery_policies()
        .insert(soland_storage::RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            principal_id: controller.to_owned(),
            version: 1,
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            allowed_proof_kinds: vec!["principal_signing".to_owned()],
            supersedes: None,
            expires_at: Some(now + chrono::Duration::days(30)),
            issued_at: now,
            raw_payload: serde_json::json!({
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": policy_id,
                "principal_id": controller,
                "version": 1,
                "trust_domain": "ak:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing"],
                "issued_at": now,
                "expires_at": now + chrono::Duration::days(30)
            }),
            accepted_at: now,
            verification_method: format!("{controller}#controller-key"),
        })
        .await
        .unwrap();

    let realm_id = soland_test_support::principal_control_realm_for_did(controller);
    let typed_realm_id = arkret_core::RealmId::new(realm_id.clone()).unwrap();
    let mut entry =
        soland_http::state::RealmDirectoryEntry::new(typed_realm_id, "Principal Control");
    entry
        .members
        .insert(arkret_core::Did::new(controller.to_owned()).unwrap());
    state.test_realms().lock().upsert(entry);
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &soland_storage::RealmMetaRecord {
                owner: controller.to_owned(),
                deleted: false,
                discoverability: "private".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: Default::default(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
}

pub(super) async fn provision_agent_with_sdk_events(
    state: &AppState,
    token: &str,
    controller: &str,
    display_name: &str,
    slug: &str,
    requested_scope: Value,
) -> (StatusCode, Value) {
    let app = app_from_state(state.clone());
    let mut prepared = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "phase": "prepare",
            "display_name": display_name,
            "slug": slug,
            "requested_scope": requested_scope,
        }))
        .send(&app)
        .await;
    let prepare_status = prepared.status_code.expect("prepare status");
    let preparation: Value = prepared.take_json().await.expect("prepare body");
    if prepare_status != StatusCode::OK {
        return (prepare_status, preparation);
    }
    assert_eq!(preparation["status"], "awaiting_controller_events");

    let controller_id = arkret_core::Did::new(controller.to_owned()).unwrap();
    let agent_id =
        serde_json::from_value::<arkret_core::Did>(preparation["agent_id"].clone()).unwrap();
    let controller_realm_id =
        serde_json::from_value::<arkret_core::RealmId>(preparation["controller_realm_id"].clone())
            .unwrap();
    let principal_control_realm_id = preparation["principal_control_realm_id"].clone();
    let scope =
        serde_json::from_value::<arkret_core::AgentKeyScope>(requested_scope.clone()).unwrap();
    let expected_scope_digest =
        arkret_core::agent_requested_scope_digest(&agent_id, &controller_id, &scope).unwrap();
    assert_eq!(
        preparation["requested_scope_digest"],
        expected_scope_digest.as_str()
    );
    let actor_frontier: Value = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?actor_id={controller}&realm_id={controller_realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await
    .take_json()
    .await
    .expect("controller actor frontier");
    let next_actor_seq = actor_frontier["frontier"]["actor_seq"]
        .as_u64()
        .unwrap_or(0)
        + 1;
    let now =
        chrono::DateTime::<chrono::Utc>::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let verification_method = format!("{controller}#{CONTROLLER_DEVICE_ID}");
    let signer = arkret_signatures::Ed25519MoveSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        controller_id,
        verification_method.clone(),
    );
    let mut events = arkret_bootstrap::build_agent_provision_event_drafts(
        signer.signer_did(),
        &controller_realm_id,
        &agent_id,
        slug,
        arkret_bootstrap::AgentProvisionEventDraftOptions {
            created_at: now,
            accountability_actor_seq: next_actor_seq,
            accountability_hlc: arkret_core::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e"))
                .unwrap(),
            selector_actor_seq: next_actor_seq + 1,
            selector_hlc: arkret_core::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        },
        &signer,
    )
    .unwrap();
    events.accountability_grant.prev_refs = actor_frontier["frontier"]["event_id"]
        .as_str()
        .map(|event_id| vec![arkret_core::EventId::new(event_id.to_owned()).unwrap()])
        .unwrap_or_default();
    events.selector_claim.prev_refs = vec![events.accountability_grant.event_id.clone()];
    let mut frontier_response = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?realm_id={controller_realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    if frontier_response.status_code != Some(StatusCode::OK) {
        let body: Value = frontier_response
            .take_json()
            .await
            .expect("frontier error body");
        panic!("controller Realm Seal frontier failed: {body}");
    }
    let frontier: arkret_core::EventsFrontierAccountClientState = frontier_response
        .take_json()
        .await
        .expect("typed controller Realm Seal frontier");
    let arkret_core::EventsFrontierView::RealmSealView(frontier) = frontier.frontier else {
        panic!("controller Realm frontier must materialize a Seal view");
    };
    for event in [&mut events.accountability_grant, &mut events.selector_claim] {
        event.seal_basis = Some(frontier.seal_basis());
        arkret_signatures::sign_event(
            event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
    }
    let commit_body = serde_json::json!({
        "phase": "commit",
        "agent_id": agent_id,
        "principal_control_realm_id": principal_control_realm_id,
        "display_name": display_name,
        "slug": slug,
        "requested_scope": requested_scope,
        "provision_events": events,
    });
    let mut committed = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    let status = committed.status_code.expect("commit status");
    let body = committed.take_json().await.expect("commit body");
    if status == StatusCode::CREATED {
        let mut retried = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        assert_eq!(retried.status_code, Some(StatusCode::CREATED));
        assert_eq!(retried.take_json::<Value>().await.unwrap(), body);
    }
    (status, body)
}

#[tokio::test]
async fn production_agent_provision_admits_controller_signed_sdk_events() {
    let mut config = test_config();
    config.development_mode = false;
    let state = soland_test_support::app_state(config);
    let controller = "did:web:alice.example";
    let token = "prod-agent-provision-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    seed_active_controller_device_generation(&state, controller).await;

    let (status, body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        "Production Agent",
        "production-agent",
        serde_json::json!({
                "actions": [
                    "ak.self.events.stream.subscribe",
                    "ak.self.events.query.scan",
                    "ak.self.events.command.submit",
                    "ak.event.read",
                    "ak.message.create"
                ],
                "resources": [{
                    "kind": "service",
                    "service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service"
                }]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "complete");
    assert_eq!(
        state
            .test_persistence()
            .agents()
            .list_for_controller(controller)
            .await
            .unwrap()
            .len(),
        1
    );

    // Cross-repository closure: SDK producer -> Soland admission/store ->
    // account query replay -> SDK model/digest/proof verifier.
    let app = app_from_state(state.clone());
    let mut replay_response = TestClient::get(format!(
        "http://server/_arkret/self/events?actors={controller}&limit=100"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(replay_response.status_code, Some(StatusCode::OK));
    let replay: Value = replay_response.take_json().await.unwrap();
    let provision_events = replay["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| {
            matches!(
                event["kind"].as_str(),
                Some("ak.identity.accountability_grant" | "ak.agent.selector_claim")
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(provision_events.len(), 2, "{replay}");
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    for replayed in provision_events {
        let event: arkret_core::Event = serde_json::from_value(replayed).unwrap();
        event.validate_proof_bindings().unwrap();
        assert_eq!(event.proofs.len(), 1);
        let canonical_bytes =
            arkret_core::canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        arkret_signatures::verify_eddsa_detached_jws_proof(
            &event.proofs[0],
            &canonical_bytes,
            &event.actor_id,
            &public_key,
        )
        .unwrap();
    }
}

#[tokio::test]
async fn agent_provision_commit_requires_its_server_allocation() {
    let state = soland_test_support::app_state(test_config());
    let controller = "did:web:alice.example";
    let token = "agent-unallocated-commit-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;

    let controller_id = arkret_core::Did::new(controller.to_owned()).unwrap();
    let controller_realm_id = arkret_core::RealmId::new(
        soland_domain::identity::principal_control_realm_for_did(controller),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let hlc =
        arkret_core::Hlc::new(format!("{:012x}-0000-a13f9c2e", now.timestamp_millis())).unwrap();
    let accountability = arkret_core::Event::new(
        arkret_core::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        controller_realm_id.clone(),
        controller_id.clone(),
        1,
        hlc.clone(),
        serde_json::json!({}),
    )
    .unwrap();
    let selector = arkret_core::Event::new(
        arkret_core::events::EventKind::AGENT_SELECTOR_CLAIM,
        controller_realm_id,
        controller_id,
        2,
        hlc,
        serde_json::json!({}),
    )
    .unwrap();
    let app = app_from_state(state.clone());
    let mut response = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "phase": "commit",
            "agent_id": "did:web:unallocated-agent.example",
            "principal_control_realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "slug": "unallocated-agent",
            "requested_scope": {
                "actions": ["ak.self.events.stream.subscribe"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                }],
                "constraints": []
            },
            "provision_events": {
                "accountability_grant": accountability,
                "selector_claim": selector
            }
        }))
        .send(&app)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::PRECONDITION_FAILED));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["error"]["details"]["reason_code"], "agent_provision_allocation_missing",
        "{body}"
    );
    assert!(
        state
            .test_persistence()
            .agents()
            .list_for_controller(controller)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn provisioned_agent_is_listed_and_slug_conflict_is_rejected() {
    let mut config = test_config();
    config.development_mode = true;
    config.session_grant_introspection_bearer = Some("agent-lifecycle-s2s".to_owned());
    let state = soland_test_support::app_state(config);
    let controller = "did:web:alice.example";
    let token = "agent-list-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    seed_active_controller_device_generation(&state, controller).await;

    let requested_scope = serde_json::json!({
        "actions": [
            "ak.self.events.stream.subscribe",
            "ak.self.events.query.scan",
            "ak.self.events.command.submit"
        ],
        "resources": [
            {
                "kind": "operation",
                "operation": "ak.self.events.stream.subscribe"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.query.scan"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.command.submit"
            }
        ],
        "constraints": []
    });

    let app = app_from_state(state.clone());
    let (created_status, created_body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        "Summary Assistant",
        "summary",
        requested_scope,
    )
    .await;

    assert_eq!(created_status, StatusCode::CREATED, "{created_body}");
    let agent_id = created_body["agent_id"]
        .as_str()
        .expect("created agent principal id")
        .to_owned();

    let mut listed = TestClient::get("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;

    assert_eq!(listed.status_code.unwrap(), StatusCode::OK);
    let list_body: Value = listed.take_json().await.unwrap();
    assert_eq!(list_body["has_more"], false, "{list_body}");
    let agents = list_body["agents"].as_array().expect("agents list shape");
    assert_eq!(agents.len(), 1, "{list_body}");
    assert_eq!(agents[0]["agent_id"], agent_id);
    assert_eq!(agents[0]["display_name"], "Summary Assistant");
    assert_eq!(agents[0]["slug"], "summary");
    assert_eq!(agents[0]["status"], "pending_runtime_key");

    let mut service_view = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", "Bearer agent-lifecycle-s2s", true)
        .send(&app)
        .await;
    assert_eq!(service_view.status_code.unwrap(), StatusCode::OK);
    let service_body: Value = service_view.take_json().await.unwrap();
    assert_eq!(service_body["status"], "pending_runtime_key");
    assert_eq!(
        service_body["key_state"]["pairing_request_id"],
        created_body["pairing_request_id"]
    );
    assert!(service_body["key_state"].get("pairing_code").is_none());

    let denied_service_view =
        TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
            .add_header("authorization", "Bearer wrong-s2s-token", true)
            .send(&app)
            .await;
    assert_eq!(
        denied_service_view.status_code.unwrap(),
        StatusCode::UNAUTHORIZED
    );

    let mut duplicate = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "phase": "prepare",
            "display_name": "Duplicate Summary",
            "slug": "summary",
            "requested_scope": {
                "actions": ["ak.self.events.stream.subscribe"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                }],
                "constraints": []
            }
        }))
        .send(&app)
        .await;

    assert_eq!(duplicate.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let duplicate_body: Value = duplicate.take_json().await.unwrap();
    assert_eq!(duplicate_body["error"]["code"], "invalid_param");
    assert!(
        duplicate_body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("slug is already bound"),
        "{duplicate_body}"
    );
}

#[tokio::test]
async fn provisioned_agent_fanout_uses_the_active_controller_device_generation() {
    let mut config = test_config();
    config.development_mode = true;
    let state = soland_test_support::app_state(config);
    let controller = "did:web:alice.example";
    let token = "agent-device-generation-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    seed_active_controller_device_generation(&state, controller).await;

    let (status, body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        "Generation-bound Agent",
        "generation-bound",
        serde_json::json!({
                "actions": ["ak.self.events.stream.subscribe"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                }],
                "constraints": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let accountability_ref = state
        .test_persistence()
        .agents()
        .list_for_controller(controller)
        .await
        .unwrap()[0]
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs["accountability_grant_event_id"].as_str())
        .unwrap()
        .to_owned();
    let accountability = state
        .test_persistence()
        .events()
        .get(&accountability_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accountability.envelope["proofs"][0]["verification_method"],
        format!("{controller}#{CONTROLLER_DEVICE_ID}")
    );
}
