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
        device_key_algorithm: Some(arkret_wire::NonEmptyString::new("EdDSA").unwrap()),
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
    display_name: &str,
    slug: &str,
    requested_scope: Value,
) -> (StatusCode, Value) {
    let (status, body, commit_body) = provision_agent_sdk_commit_attempt(
        state,
        token,
        controller,
        display_name,
        slug,
        requested_scope,
        None,
    )
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
    _display_name: &str,
    slug: &str,
    requested_scope: Value,
    fault: Option<(
        &soland_storage_memory::FaultInjector,
        soland_storage_memory::FaultPlan,
    )>,
) -> (StatusCode, Value, Value) {
    let app = app_from_state(state.clone());
    let operation_id = format!("ak:operation:{}", uuid::Uuid::now_v7().simple());
    let idempotency_key = uuid::Uuid::now_v7().simple().to_string();
    let mut prepared = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "phase": "prepare",
            "operation_id": operation_id,
            "idempotency_key": idempotency_key,
            "slug": slug,
            "requested_scope": requested_scope,
        }))
        .send(&app)
        .await;
    let prepare_status = prepared.status_code.expect("prepare status");
    let preparation: Value = prepared.take_json().await.expect("prepare body");
    if prepare_status != StatusCode::OK {
        return (prepare_status, preparation, Value::Null);
    }
    assert_eq!(preparation["status"], "awaiting_controller_event");

    let controller_id = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let agent_id =
        serde_json::from_value::<arkret_identifiers::Did>(preparation["agent_id"].clone()).unwrap();
    let controller_realm_id = serde_json::from_value::<arkret_identifiers::RealmId>(
        preparation["controller_realm_id"].clone(),
    )
    .unwrap();
    let principal_control_realm_id = serde_json::from_value::<arkret_identifiers::RealmId>(
        preparation["principal_control_realm_id"].clone(),
    )
    .unwrap();
    let allocation_handle = serde_json::from_value::<arkret_wire::ProtocolOpaqueId>(
        preparation["allocation_handle"].clone(),
    )
    .unwrap();
    let controller_authorization_ref = serde_json::from_value::<arkret_wire::DidUrl>(
        preparation["controller_authorization_ref"].clone(),
    )
    .unwrap();
    let scope = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    >(requested_scope.clone())
    .unwrap();
    let expected_scope_digest =
        arkret_signatures::agent::agent_requested_scope_digest(&agent_id, &controller_id, &scope)
            .unwrap();
    assert_eq!(
        preparation["requested_scope_digest"],
        expected_scope_digest.as_str()
    );
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
            operation_id: arkret_wire::ProtocolOperationId::new(operation_id).unwrap(),
            idempotency_key: arkret_wire::ProtocolOpaqueId::new(idempotency_key).unwrap(),
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
        let event: arkret_wire::Event = serde_json::from_value(replayed).unwrap();
        event.validate_proof_bindings().unwrap();
        assert_eq!(event.proofs.len(), 1);
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
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
async fn agent_provision_recovers_from_each_durable_commit_boundary() {
    use soland_storage::{
        DeliveryPolicyStoreRegistry, EventProjectionStoreRegistry, MlsAgentStoreRegistry,
    };
    use soland_storage_memory::{FaultPlan, FaultPoint, FaultTiming, SolandMemoryPersistenceStore};

    let plans = [
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::After, 1),
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::Before, 2),
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::After, 2),
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
            "Fault Recovery Agent",
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
        // Each `provision_events` member is an `EventInitialSubmission`, so the
        // Event id sits under its `event`, not at the submission root.
        let event_ids = [
            commit_body["provision_events"]["accountability_grant"]["event"]["event_id"]
                .as_str()
                .unwrap(),
            commit_body["provision_events"]["selector_claim"]["event"]["event_id"]
                .as_str()
                .unwrap(),
        ];
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
    let accountability = arkret_wire::Event::new(
        arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        arkret_wire::ScopeRef::Realm {
            realm_id: controller_realm_id.clone(),
        },
        controller_id.clone(),
        1,
        hlc.clone(),
        serde_json::json!({}),
    )
    .unwrap();
    let selector = arkret_wire::Event::new(
        arkret_wire::EventKind::AGENT_SELECTOR_CLAIM,
        arkret_wire::ScopeRef::Realm {
            realm_id: controller_realm_id,
        },
        controller_id,
        2,
        hlc,
        serde_json::json!({}),
    )
    .unwrap();
    // The commit body only has to be schema-valid to reach the allocation
    // precondition this test is about; the lease is structural evidence, and
    // this Agent has no server allocation to publish against in the first place.
    let authorization_lease = serde_json::json!({
        "authorization_lease_id": "ak:authorization_lease:01904100-0000-7000-8000-a9e07ea5e001",
        "basis_ref": format!("ak:seal:sha256:{}", "0".repeat(64)),
        "actor_id": accountability.actor_id,
        "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "scope_ref": accountability.scope_ref,
        "action": "ak.identity.accountability_grant",
        "authorization_rule_id": "realm_admission",
        "risk_tier": "low",
        "issued_at": arkret_canonical::format_timestamp_canonical(now),
        "expires_at": arkret_canonical::format_timestamp_canonical(
            now + chrono::Duration::hours(4),
        ),
        "authority_set_ref": {
            "authority_set_id": "ak.authority_set.realm_admission.v1",
            "authority_set_digest": format!("sha256:{}", "0".repeat(64))
        },
        "authority_set_policy": {
            "schema": arkret_wire::SchemaId::AUTHORITY_SET_POLICY_V1,
            "authority_set_id": "ak.authority_set.realm_admission.v1",
            "policy_kind": "realm_admission",
            "scope_ref": accountability.scope_ref,
            "source": {
                "source_kind": "realm_control",
                "source_ref": format!("ak:seal:sha256:{}", "0".repeat(64)),
                "source_digest": format!("sha256:{}", "0".repeat(64)),
                "generation_ref": "1"
            },
            "authorization_rules": [{
                "rule_id": "realm_admission",
                "issuer_role": "realm_admission",
                "allowed_actions": ["ak.identity.accountability_grant"],
                "issuers": [{
                    "verification_method": "did:web:alice.example#device-key"
                }],
                "threshold": 1
            }]
        },
        "proofs": []
    });
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
            // `agent_provision_events` carries `EventInitialSubmission`
            // members, not bare Events: the Event is the signed fact and the
            // lease is its separately verified publication evidence.
            "provision_events": {
                "accountability_grant": {
                    "event": accountability,
                    "authorization_lease": authorization_lease.clone()
                },
                "selector_claim": {
                    "event": selector,
                    "authorization_lease": authorization_lease
                }
            }
        }))
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
    // Two orthogonal axes (key-management.md §3.6.1): a freshly provisioned
    // agent's lifecycle intent is active; its derived runtime_state is
    // pending_runtime_key until first pairing completes.
    assert_eq!(agents[0]["status"], "active");
    assert_eq!(agents[0]["runtime_state"], "pending_runtime_key");

    let mut service_view = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", "Bearer agent-lifecycle-s2s", true)
        .send(&app)
        .await;
    assert_eq!(service_view.status_code.unwrap(), StatusCode::OK);
    let service_body: Value = service_view.take_json().await.unwrap();
    assert_eq!(service_body["status"], "active");
    assert_eq!(service_body["runtime_state"], "pending_runtime_key");
    assert_eq!(service_body["key_state"]["status"], "active");
    assert_eq!(
        service_body["key_state"]["runtime_state"],
        "pending_runtime_key"
    );
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
