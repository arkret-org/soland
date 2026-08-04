//! Integration tests - personal-agent HTTP surfaces.

use arkret_state::lattice::CellState;
use arkret_wire::PayloadSigner as _;

use super::common::*;

pub(crate) const CONTROLLER_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
pub(crate) const CONTROLLER_DEVICE_SIGNING_SEED: [u8; 32] = [91u8; 32];

/// Genesis-context registry projector: a bootstrap unit has no accepted Realm
/// yet, so there is no digest-suite cell to read and the protocol baseline
/// suite is the only defined one.
pub(crate) fn genesis_projector(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::cba::ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}

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
                        "type": arkret_models_discovery::service_requirements::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
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
    let realm = arkret_identifiers::RealmId::new(realm_id.clone()).unwrap();
    let actor = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let mut bootstrap = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: actor.clone(),
            realm_id: realm.clone(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:soland.local".to_owned(),
            )
            .unwrap(),
            did_inception_ref: arkret_wire::EventRef::new(
                format!("sha256:{}", "1".repeat(64)),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            capability_action_registry_digest:
                arkret_policy::current_capability_action_registry_digest().unwrap(),
            event_id: arkret_wire::EventId::new(new_prefixed_uuid7("ak:event:")).unwrap(),
            created_at,
            hlc: arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e")).unwrap(),
        },
        &genesis_projector,
    )
    .unwrap();
    let verification_method =
        arkret_wire::DidUrl::new(format!("{controller}#{CONTROLLER_DEVICE_ID}"))
            .expect("fixture verification method is a DID URL");
    let bootstrap_signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        actor.clone(),
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut bootstrap,
        &bootstrap_signer,
        &arkret_wire::DidUrl::new(
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        )
        .unwrap(),
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let authorization_ref =
        arkret_wire::NonEmptyString::new(format!("{controller}#device-enrollment-authority"))
            .unwrap();
    let authorize_payload = arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
        principal_id: actor.clone(),
        device_id: arkret_identifiers::DeviceId::new(CONTROLLER_DEVICE_ID).unwrap(),
        device_public_key: arkret_wire::NonEmptyString::new(test_ed25519_multibase_public(
            &signing_key,
        ))
        .unwrap(),
        hpke_key: arkret_wire::NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![
            arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
        ],
        device_key_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(actor.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(arkret_models_identity::DeviceEnrollmentAuthorityBinding {
            kind: arkret_models_identity::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: actor.clone(),
            authorization_ref: authorization_ref.clone(),
        }),
        recovery_session_id: None,
    };
    let mut authorize = arkret_wire::Event::new_at(
        arkret_wire::EventKind::DEVICE_AUTHORIZE,
        arkret_wire::ScopeRef::Realm { realm_id: realm },
        actor.clone(),
        1,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        serde_json::to_value(authorize_payload).unwrap(),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![bootstrap.event_id.clone()];
    authorize.executed_by = Some(actor);
    authorize.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_string()).unwrap());
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
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0003-a13f9c2e")).unwrap(),
        &bootstrap_signer,
        &genesis_projector,
    )
    .unwrap();
    seed_seal_with_direct_event_effects(
        state,
        &bootstrap_seal,
        &[&bootstrap, &authorize],
        &genesis_projector,
    );
    for (event, kind, actor_seq) in [
        (bootstrap, "ak.realm.create", 0),
        (authorize, "ak.device.authorize", 1),
    ] {
        let event_id = event.event_id.to_string();
        let canonical_digest = event.event_digest().unwrap();
        let envelope = serde_json::to_value(&event).unwrap();
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope).unwrap();
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
            acceptance_basis: arkret_wire::LeaseBasisRef::Seal(
                arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64)))
                    .unwrap(),
            ),
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
                "publication_authorization_rules": [{
                    "rule_id": "principal_signing",
                    "proof_kind": "principal_signing",
                    "issuer_role": "identity_recovery",
                    "allowed_actions": ["ak.device.reanchor"],
                    "issuers": [{
                        "verification_method": format!("{controller}#controller-key")
                    }],
                    "threshold": 1
                }],
                "supersedes": null,
                "issued_at": now,
                "expires_at": now + chrono::Duration::days(30),
                "auth_data": {
                    "verification_method": format!("{controller}#controller-key"),
                    "signature_algorithm": "Ed25519",
                    "signature": "c2ln",
                    "signed_fields": [
                        "schema",
                        "policy_id",
                        "principal_id",
                        "version",
                        "supersedes",
                        "trust_domain",
                        "allowed_proof_kinds",
                        "publication_authorization_rules",
                        "issued_at",
                        "expires_at"
                    ]
                }
            }),
            accepted_at: now,
            verification_method: format!("{controller}#controller-key"),
        })
        .await
        .unwrap();

    let realm_id = soland_test_support::principal_control_realm_for_did(controller);
    let typed_realm_id = arkret_identifiers::RealmId::new(realm_id.clone()).unwrap();
    let mut entry =
        soland_http::state::RealmDirectoryEntry::new(typed_realm_id, "Principal Control");
    entry
        .members
        .insert(arkret_identifiers::Did::new(controller.to_owned()).unwrap());
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
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    state
        .test_projection()
        .lock()
        .realm_null_subject_cells
        .insert(
            (
                realm_id,
                format!(
                    "ak:cell:{}:null",
                    arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1
                ),
            ),
            CellState::Value(Value::String(arkret_wire::CORE_REDUCER_PROFILE.to_owned())),
        );
}

pub(super) async fn provision_agent_with_sdk_events(
    state: &AppState,
    token: &str,
    controller: &str,
    slug: &str,
    requested_scope: Value,
) -> (StatusCode, Value) {
    let (status, body, commit_body) =
        provision_agent_sdk_commit_attempt(state, token, controller, slug, requested_scope, None)
            .await;
    if status == StatusCode::CREATED {
        let app = app_from_state(state.clone());
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

async fn provision_agent_sdk_commit_attempt(
    state: &AppState,
    token: &str,
    controller: &str,
    slug: &str,
    requested_scope: Value,
    fault: Option<(
        &soland_storage_memory::FaultInjector,
        soland_storage_memory::FaultPlan,
    )>,
) -> (StatusCode, Value, Value) {
    let app = app_from_state(state.clone());
    let operation_id = arkret_wire::ProtocolOperationId::new(format!(
        "ak:operation:{}",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let idempotency_key =
        arkret_wire::ProtocolOpaqueId::new(uuid::Uuid::now_v7().simple().to_string()).unwrap();
    let scope = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    >(requested_scope.clone())
    .unwrap();
    let prepare_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Prepare {
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            slug: slug.to_owned(),
            requested_scope: scope.clone(),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let mut prepared = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&prepare_body)
        .send(&app)
        .await;
    let prepare_status = prepared.status_code.expect("prepare status");
    let preparation: Value = prepared.take_json().await.expect("prepare body");
    if prepare_status != StatusCode::OK {
        return (prepare_status, preparation, Value::Null);
    }
    let controller_id = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let preparation = serde_json::from_value::<
        arkret_models_collaboration::agent_operations::AgentProvisionOutcome,
    >(preparation)
    .unwrap();
    let arkret_models_collaboration::agent_operations::AgentProvisionOutcome::AwaitingControllerEvent {
        agent_id,
        principal_control_realm_id,
        controller_realm_id,
        allocation_handle,
        controller_authorization_ref,
        requested_scope_digest,
    } = preparation else {
        panic!("prepare must await the controller-authored provision Event");
    };
    let expected_scope_digest =
        arkret_signatures::agent::agent_requested_scope_digest(&agent_id, &controller_id, &scope)
            .unwrap();
    assert_eq!(requested_scope_digest, expected_scope_digest);
    let actor_frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?actor_id={controller}&realm_id={controller_realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await
    .take_json()
    .await
    .expect("controller actor frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(actor_frontier) =
        actor_frontier.frontier
    else {
        panic!("combined Realm+actor selector must return realm_actor frontier");
    };
    assert_eq!(actor_frontier.realm_id, controller_realm_id);
    assert_eq!(actor_frontier.actor_id.as_str(), controller);
    let next_actor_seq = actor_frontier.next_actor_seq;
    let now =
        chrono::DateTime::<chrono::Utc>::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let verification_method =
        arkret_wire::DidUrl::new(format!("{controller}#{CONTROLLER_DEVICE_ID}"))
            .expect("fixture verification method is a DID URL");
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        controller_id,
        verification_method.clone(),
    );
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
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        frontier_response
            .take_json()
            .await
            .expect("typed controller Realm Seal frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
        frontier.frontier
    else {
        panic!("controller Realm frontier must materialize a Seal view");
    };
    let mut event = arkret_bootstrap::build_agent_provision_event_draft(
        signer.signer_did(),
        &controller_realm_id,
        &agent_id,
        &principal_control_realm_id,
        &controller_authorization_ref,
        slug,
        &expected_scope_digest,
        arkret_models_identity::handle::HandleVisibility::Private,
        None,
        arkret_bootstrap::AgentProvisionEventDraftOptions {
            created_at: now,
            actor_seq: next_actor_seq,
            hlc: arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e")).unwrap(),
            prev_refs: actor_frontier.frontier_event_ids,
            seal_basis: Some(frontier.seal_basis()),
        },
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let provision_event = prepare_standard_initial_submissions(state, token, vec![event], &signer)
        .await
        .into_iter()
        .next()
        .expect("single provision submission");
    let commit_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Commit {
            operation_id,
            idempotency_key,
            agent_id,
            principal_control_realm_id,
            allocation_handle,
            slug: slug.to_owned(),
            requested_scope: scope,
            provision_event: Box::new(provision_event),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    if let Some((injector, plan)) = fault {
        injector.arm(plan);
    }
    let mut committed = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    let status = committed.status_code.expect("commit status");
    let body = committed.take_json().await.expect("commit body");
    (status, body, commit_body)
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
        .filter(|event| matches!(event["kind"].as_str(), Some("ak.agent.provision")))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(provision_events.len(), 1, "{replay}");
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    for replayed in provision_events {
        let event: arkret_wire::Event = serde_json::from_value(replayed).unwrap();
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &event,
        )
        .unwrap();
        event.validate_proof_bindings().unwrap();
        assert_eq!(event.proofs.len(), 1);
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        arkret_signatures::verify_ed25519_detached_jws_proof(
            &event.proofs[0],
            &canonical_bytes,
            &event.actor_id,
            &public_key,
        )
        .unwrap();
    }
}

#[tokio::test]
async fn agent_provision_recovers_from_each_durable_commit_boundary() {
    use soland_storage::{
        DeliveryPolicyStoreRegistry, EventProjectionStoreRegistry, MlsAgentStoreRegistry,
    };
    use soland_storage_memory::{FaultPlan, FaultPoint, FaultTiming, SolandMemoryPersistenceStore};

    let plans = [
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::After, 1),
        FaultPlan::new(FaultPoint::WebvhLogCommit, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::WebvhLogCommit, FaultTiming::After, 1),
        FaultPlan::new(FaultPoint::AgentPut, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::AgentPut, FaultTiming::After, 1),
    ];

    for (index, plan) in plans.into_iter().enumerate() {
        let persistence = std::sync::Arc::new(SolandMemoryPersistenceStore::new_with_demo_data());
        let injector = persistence.fault_injector();
        let state =
            soland_test_support::app_state_with_persistence(test_config(), persistence.clone());
        let controller = "did:web:alice.example";
        let token = format!("agent-provision-fault-{index}");
        seed_controller_session(&state, &token, controller).await;
        seed_agent_provision_prerequisites(&state, controller).await;
        seed_active_controller_device_generation(&state, controller).await;

        let requested_scope = serde_json::json!({
            "actions": [
                "ak.self.events.stream.subscribe",
                "ak.self.events.query.scan",
                "ak.self.events.command.submit",
                "ak.event.read",
                "ak.message.create"
            ],
            "resources": [{
                "kind": "service",
                "service_id": state.service_id()
            }]
        });
        let slug = format!("fault-agent-{index}");
        let (failed_status, failed_body, commit_body) = provision_agent_sdk_commit_attempt(
            &state,
            &token,
            controller,
            &slug,
            requested_scope,
            Some((&injector, plan)),
        )
        .await;
        assert_eq!(
            failed_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fault plan {plan:?} did not interrupt the commit: {failed_body}"
        );

        let app = app_from_state(state.clone());
        let mut recovered = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        let recovered_status = recovered.status_code;
        let recovered_body: Value = recovered.take_json().await.unwrap();
        assert_eq!(
            recovered_status,
            Some(StatusCode::CREATED),
            "fault plan {plan:?} did not recover: {recovered_body}"
        );
        assert_eq!(recovered_body["status"], "complete");

        let mut replayed = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        assert_eq!(replayed.status_code, Some(StatusCode::CREATED));
        assert_eq!(replayed.take_json::<Value>().await.unwrap(), recovered_body);

        let agent_id = commit_body["agent_id"].as_str().unwrap();
        let event_ids = [commit_body["provision_event"]["event"]["event_id"]
            .as_str()
            .unwrap()];
        let stored_events = persistence.events().snapshot_all().await.unwrap();
        for event_id in event_ids {
            assert_eq!(
                stored_events
                    .iter()
                    .filter(|event| event.event_id == event_id)
                    .count(),
                1,
                "fault plan {plan:?} duplicated provision event {event_id}"
            );
        }
        let did_history = persistence.webvh().list_log_events(agent_id).await.unwrap();
        assert_eq!(
            did_history.len(),
            1,
            "fault plan {plan:?} duplicated Agent DID inception"
        );
        let did_document = persistence
            .webvh()
            .get_document(agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            did_document.key_log_head.as_deref(),
            Some(did_history[0].event_digest.as_str())
        );
        assert_eq!(
            persistence
                .agents()
                .list_for_controller(controller)
                .await
                .unwrap()
                .len(),
            1,
            "fault plan {plan:?} duplicated the Agent principal"
        );
    }
}

#[tokio::test]
async fn agent_provision_commit_requires_its_server_allocation() {
    let state = soland_test_support::app_state(test_config());
    let controller = "did:web:alice.example";
    let token = "agent-unallocated-commit-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;

    let controller_id = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let controller_realm_id = arkret_identifiers::RealmId::new(
        soland_domain::identity::principal_control_realm_for_did(controller),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let hlc =
        arkret_identifiers::Hlc::new(format!("{:012x}-0000-a13f9c2e", now.timestamp_millis()))
            .unwrap();
    let provision_event = arkret_wire::Event::new(
        arkret_wire::EventKind::AGENT_PROVISION,
        arkret_wire::ScopeRef::Realm {
            realm_id: controller_realm_id.clone(),
        },
        controller_id.clone(),
        1,
        hlc.clone(),
        serde_json::json!({}),
    )
    .unwrap();
    let requested_scope = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    >(serde_json::json!({
        "actions": ["ak.self.events.stream.subscribe"],
        "resources": [{
            "kind": "operation",
            "operation": "ak.self.events.stream.subscribe"
        }],
        "constraints": []
    }))
    .unwrap();
    // This negative vector deliberately uses a schema-valid public SDK request
    // with no matching private server allocation. Admission must fail before
    // interpreting the intentionally incomplete Event payload.
    let commit_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Commit {
            operation_id: arkret_wire::ProtocolOperationId::new(
                "ak:operation:01904100000070008000000000000011",
            )
            .unwrap(),
            idempotency_key: arkret_wire::ProtocolOpaqueId::new("unallocated-commit-001").unwrap(),
            agent_id: arkret_identifiers::Did::new("did:web:unallocated-agent.example").unwrap(),
            principal_control_realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:01904100-0000-7000-8000-000000000001",
            )
            .unwrap(),
            allocation_handle: arkret_wire::ProtocolOpaqueId::new("unallocated.fixture.signature")
                .unwrap(),
            slug: "unallocated-agent".to_owned(),
            requested_scope,
            provision_event: Box::new(arkret_wire::EventInitialSubmission {
                event: provision_event,
                authorization_lease: None,
                cba_proof_bundles: Vec::new(),
                control_proposal_receipt: None,
                membership_compensation_evidence: None,
            }),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let app = app_from_state(state.clone());
    let mut response = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;

    let provision_status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        provision_status,
        Some(StatusCode::PRECONDITION_FAILED),
        "{body}"
    );
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
        "summary",
        requested_scope.clone(),
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
    let list_body: arkret_models_collaboration::agent_operations::AgentList =
        listed.take_json().await.unwrap();
    assert!(!list_body.has_more);
    assert_eq!(list_body.agents.len(), 1);
    let listed_agent = &list_body.agents[0];
    assert_eq!(listed_agent.agent_id.as_str(), agent_id);
    assert_eq!(listed_agent.display_name, None);
    assert_eq!(listed_agent.slug, "summary");
    assert_eq!(
        listed_agent.lifecycle,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    assert_eq!(
        listed_agent.readiness.state,
        arkret_models_collaboration::agent_operations::AgentReadinessState::NotReady
    );
    assert_eq!(
        listed_agent.readiness.blockers,
        vec![
            arkret_models_collaboration::agent_operations::AgentReadinessBlocker::RuntimeKeyMissing,
            arkret_models_collaboration::agent_operations::AgentReadinessBlocker::PairingOpen,
        ]
    );

    let mut service_view = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", "Bearer agent-lifecycle-s2s", true)
        .send(&app)
        .await;
    assert_eq!(service_view.status_code.unwrap(), StatusCode::OK);
    let service_body: arkret_models_collaboration::agent_operations::AgentView =
        service_view.take_json().await.unwrap();
    assert_eq!(
        service_body.agent.lifecycle,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    let key_state = service_body
        .key_state
        .expect("service Agent view key state");
    assert_eq!(
        key_state
            .pairing_request_id
            .as_ref()
            .map(arkret_wire::OpaqueLocalId::as_str),
        created_body["pairing_request_id"].as_str()
    );
    assert_eq!(key_state.pairing_code, None);

    let denied_service_view =
        TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
            .add_header("authorization", "Bearer wrong-s2s-token", true)
            .send(&app)
            .await;
    assert_eq!(
        denied_service_view.status_code.unwrap(),
        StatusCode::UNAUTHORIZED
    );

    let duplicate_scope = serde_json::from_value(requested_scope).unwrap();
    let duplicate_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Prepare {
            operation_id: arkret_wire::ProtocolOperationId::new(format!(
                "ak:operation:{}",
                uuid::Uuid::now_v7().simple()
            ))
            .unwrap(),
            idempotency_key: arkret_wire::ProtocolOpaqueId::new(
                uuid::Uuid::now_v7().simple().to_string(),
            )
            .unwrap(),
            slug: "summary".to_owned(),
            requested_scope: duplicate_scope,
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let mut duplicate = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&duplicate_body)
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

    let provision_ref = state
        .test_persistence()
        .agents()
        .list_for_controller(controller)
        .await
        .unwrap()[0]
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs["provision_event_id"].as_str())
        .unwrap()
        .to_owned();
    let provision = state
        .test_persistence()
        .events()
        .get(&provision_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        provision.envelope["proofs"][0]["verification_method"],
        format!("{controller}#{CONTROLLER_DEVICE_ID}")
    );
}
