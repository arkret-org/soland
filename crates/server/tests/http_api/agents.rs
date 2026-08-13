//! Integration tests - personal-agent HTTP surfaces.

use arkret_state::lattice::CellState;

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

fn controller_founding_authorize_payload(
    actor: &arkret_identifiers::DidFullId,
    created_at: chrono::DateTime<chrono::Utc>,
    signing_key: &SigningKey,
) -> arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
    use arkret_models_collaboration::events_payloads::SignatureMaterial;
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    };

    let mut payload = DeviceAuthorizePayload {
        principal_id: arkret_wire::project_full_id_to_core_id(actor).unwrap(),
        device_id: arkret_identifiers::DeviceId::new(CONTROLLER_DEVICE_ID).unwrap(),
        device_public_key: arkret_wire::NonEmptyString::new(format!(
            "did:key:{}",
            test_ed25519_multibase_public(signing_key),
        ))
        .unwrap(),
        hpke_key: arkret_wire::NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![
            arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
        ],
        device_key_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: DeviceOrPrincipalRef::Principal(
            arkret_wire::project_full_id_to_core_id(actor).unwrap(),
        ),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
        device_signature: SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new("pending").unwrap(),
        ),
        recovery_session_id: None,
    };
    let possession_input = payload.device_possession_signature_input().unwrap();
    payload.device_signature = SignatureMaterial::NonEmptyString(
        arkret_wire::NonEmptyString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::Signer::sign(signing_key, &possession_input).to_bytes(),
        ))
        .unwrap(),
    );
    payload
}

fn controller_founding_device_descriptor(
    payload: &arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
) -> arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
    use arkret_models_collaboration::events_payloads::{
        FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm, FoundingDeviceKeyPurpose,
    };

    let payload_value = serde_json::to_value(payload).unwrap();
    arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: payload.device_id.clone(),
        device_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            payload.device_public_key.as_bytes(),
        ))
        .unwrap(),
        device_public_key: payload.device_public_key.clone(),
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            payload.hpke_key.as_bytes(),
        ))
        .unwrap(),
        hpke_key: payload.hpke_key.clone(),
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms: payload.algorithms.clone(),
        founding_authorize_payload_digest: arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
            &payload_value,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    }
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
    let actor_id = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(actor.to_owned()).unwrap(),
    )
    .unwrap()
    .into_string();
    let persistence = state.test_persistence();
    let accounts = persistence.accounts();
    if accounts.get(&actor_id).await.unwrap().is_none() {
        accounts
            .put(&soland_storage::AccountRecord {
                id: format!("ak:account:{}", uuid::Uuid::now_v7()),
                did: actor_id.clone(),
                localpart: "alice".to_owned(),
                display_name: Some("Alice".to_owned()),
                bio: None,
                avatar_blob_ref: None,
                created_at: now,
            })
            .await
            .unwrap();
    }
    state
        .test_persistence()
        .sessions()
        .put(&soland_storage::SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            actor: actor_id.clone(),
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
            actor: actor_id,
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

pub(crate) async fn seed_active_controller_device_generation(
    state: &AppState,
    controller: &str,
) -> arkret_wire::PrincipalAuthorityInstance {
    let now = chrono::Utc::now();
    let generation_ref = "1";
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
                "state": { "id": controller }
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

    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(now.timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", created_at.timestamp_millis());
    let actor = arkret_identifiers::DidFullId::new(controller.to_owned()).unwrap();
    let controller_id = arkret_wire::project_full_id_to_core_id(&actor).unwrap();
    let authorize_payload = controller_founding_authorize_payload(&actor, created_at, &signing_key);
    let founding_device_descriptor = controller_founding_device_descriptor(&authorize_payload);
    let initial_resolution = arkret_models_identity::ResolutionCommitment {
        full_id: actor.clone(),
        method_history_head: format!("sha256:{}", "1".repeat(64)),
        version_id: "1-Qmfixture".to_owned(),
    };
    let mut bootstrap = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: controller_id.clone(),
            principal_full_id: actor.clone(),
            initial_resolution: initial_resolution.clone(),
            genesis_salt: arkret_wire::GenesisSalt::new(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .unwrap(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:soland.local".to_owned(),
            )
            .unwrap(),
            did_inception_ref: arkret_wire::EventRef::new(
                format!("sha256:{}", "1".repeat(64)),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor,
            capability_action_registry_digest:
                arkret_policy::current_capability_action_registry_digest().unwrap(),
            created_at,
            hlc: arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e")).unwrap(),
        },
        &genesis_projector,
    )
    .unwrap();
    let realm = arkret_identifiers::RealmId::from_event_id(&bootstrap.event_id);
    let realm_id = realm.to_string();
    let authority_instance = arkret_wire::PrincipalAuthorityInstance::new(
        bootstrap.actor_id.clone(),
        arkret_wire::DidCoreId::new(state.service_id().to_owned()).unwrap(),
        realm.clone(),
        arkret_wire::Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
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
        &arkret_wire::DidUrl::new(format!(
            "did:key:{0}#{0}",
            test_ed25519_multibase_public(&signing_key)
        ))
        .unwrap(),
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        controller_id.clone(),
        1,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        serde_json::to_value(authorize_payload).unwrap(),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![bootstrap.event_id.clone()];
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
    let authorize_event_id = authorize.event_id.clone();
    for event in [bootstrap.clone(), authorize] {
        state
            .test_persistence()
            .events()
            .put(soland_test_support::signed_event::canonical_event_record(
                &event,
                Some(&realm_id),
                now,
            ))
            .await
            .unwrap();
    }
    let resolution_record = soland_storage::PrincipalResolutionRecord {
        authority_instance: authority_instance.clone(),
        genesis_event: bootstrap.clone(),
        current_event: bootstrap.clone(),
        projection: arkret_models_identity::PrincipalResolutionProjection {
            full_id: initial_resolution.full_id,
            method_history_head: initial_resolution.method_history_head,
            version_id: initial_resolution.version_id,
            resolution_event_ref: bootstrap.event_id.to_string(),
            updated_at: bootstrap.created_at,
        },
    };
    assert!(matches!(
        soland_test_support::AppStateTestExt::test_persistence(state)
            .principal_resolutions()
            .compare_and_set(None, resolution_record)
            .await
            .unwrap(),
        soland_storage::PrincipalResolutionCasResult::Applied(_)
    ));
    soland_test_support::cba_basis::seed_realm_genesis_event(state, &realm_id, controller).await;
    let mut realm_entry = soland_http::state::RealmDirectoryEntry::new(
        realm.clone(),
        "Principal Control",
        soland_services::events::DirectoryProvenance::AcceptedEvent(bootstrap.event_id.to_string()),
    );
    realm_entry.members.insert(bootstrap.actor_id.clone());
    state.test_realms().lock().upsert(realm_entry);
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &soland_storage::RealmMetaRecord {
                owner: controller_id.to_string(),
                deleted: false,
                discoverability: "private".to_owned(),
                history_visibility: "restricted".to_owned(),
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
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .unwrap();

    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: controller_id.to_string(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
                "authorized_generation_ref": generation_ref,
                "device_authorize_event_id": authorize_event_id,
                "device_public_key": format!(
                    "did:key:{}",
                    test_ed25519_multibase_public(&signing_key)
                )
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    authority_instance
}

pub(crate) async fn seed_agent_provision_prerequisites(state: &AppState, controller: &str) {
    let now = chrono::Utc::now();
    let controller_id = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(controller.to_owned()).unwrap(),
    )
    .unwrap();
    let policy_id = new_prefixed_uuid7("ak:policy:");
    state
        .test_persistence()
        .recovery_policies()
        .insert(soland_storage::RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            principal_id: controller_id.to_string(),
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
                "principal_id": controller_id,
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

    let realm_id = soland_test_support::fixture_principal_control_realm(controller);
    let typed_realm_id = arkret_identifiers::RealmId::new(realm_id.clone()).unwrap();
    let mut entry = soland_http::state::RealmDirectoryEntry::new(
        typed_realm_id,
        "Principal Control",
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.members.insert(
        arkret_wire::project_full_id_to_core_id(
            &arkret_identifiers::DidFullId::new(controller.to_owned()).unwrap(),
        )
        .unwrap(),
    );
    state.test_realms().lock().upsert(entry);
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &soland_storage::RealmMetaRecord {
                owner: controller_id.to_string(),
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
    controller_authority_instance: &arkret_wire::PrincipalAuthorityInstance,
    slug: &str,
    requested_scope: Value,
) -> (StatusCode, Value) {
    let (status, body, commit_body, fault_outcome) = provision_agent_sdk_commit_attempt(
        state,
        token,
        controller,
        controller_authority_instance,
        slug,
        requested_scope,
        None,
    )
    .await;
    assert!(fault_outcome.is_none());
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

fn provision_agent_sdk_commit_attempt<'a>(
    state: &'a AppState,
    token: &'a str,
    controller: &'a str,
    controller_authority_instance: &'a arkret_wire::PrincipalAuthorityInstance,
    slug: &'a str,
    requested_scope: Value,
    fault: Option<(
        &'a soland_storage_memory::FaultInjector,
        soland_storage_memory::FaultPlan,
    )>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (StatusCode, Value, Value, Option<(StatusCode, Value)>)>
            + Send
            + 'a,
    >,
> {
    Box::pin(provision_agent_sdk_commit_attempt_inner(
        state,
        token,
        controller,
        controller_authority_instance,
        slug,
        requested_scope,
        fault,
    ))
}

async fn provision_agent_sdk_commit_attempt_inner(
    state: &AppState,
    token: &str,
    controller: &str,
    controller_authority_instance: &arkret_wire::PrincipalAuthorityInstance,
    slug: &str,
    requested_scope: Value,
    fault: Option<(
        &soland_storage_memory::FaultInjector,
        soland_storage_memory::FaultPlan,
    )>,
) -> (StatusCode, Value, Value, Option<(StatusCode, Value)>) {
    let app = app_from_state(state.clone());
    let operation_id = arkret_wire::ProtocolOperationId::new(format!(
        "ak:operation:{}",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let idempotency_key =
        arkret_wire::IdempotencyKey::new(uuid::Uuid::now_v7().simple().to_string()).unwrap();
    let scope = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    >(requested_scope.clone())
    .unwrap();
    let controller_full_id = arkret_identifiers::DidFullId::new(controller.to_owned()).unwrap();
    let controller_id = arkret_wire::project_full_id_to_core_id(&controller_full_id).unwrap();
    let binding_signing_key = SigningKey::from_bytes(&[22_u8; 32]);
    let successor_signing_key = SigningKey::from_bytes(&[23_u8; 32]);
    let agent_inception = arkret_signatures::webvh::prepare_managed_agent_inception(
        &arkret_signatures::webvh::ManagedAgentInceptionInput {
            principal_endpoint: &url::Url::parse("https://soland.local").unwrap(),
            local_id: &format!("agent-{}", uuid::Uuid::now_v7().simple()),
            controller_id: &controller_id,
            version_time: chrono::Utc::now(),
            root_seed: &[21_u8; 32],
            next_root_public_key_multibase: &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                binding_signing_key.verifying_key().as_bytes(),
            ),
        },
    )
    .unwrap();
    let full_id = arkret_identifiers::DidFullId::new(agent_inception.did.clone()).unwrap();
    let mut inception_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&serde_json::to_value(&agent_inception.submit_body).unwrap())
            .send(&app)
            .await;
    let inception_status = inception_response.status_code;
    let inception_body: Value = inception_response.take_json().await.unwrap();
    assert_eq!(inception_status, Some(StatusCode::OK), "{inception_body}");
    assert!(matches!(
        inception_body["status"].as_str(),
        Some("accepted" | "duplicate")
    ));
    let prepare_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Prepare {
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            full_id: full_id.clone(),
            controller_authority_instance: controller_authority_instance.clone(),
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
        return (prepare_status, preparation, Value::Null, None);
    }
    let preparation = serde_json::from_value::<
        arkret_models_collaboration::agent_operations::AgentProvisionOutcome,
    >(preparation)
    .unwrap();
    let arkret_models_collaboration::agent_operations::AgentProvisionOutcome::AwaitingControllerEvent {
        agent_id,
        full_id,
        initial_resolution,
        controller_realm_id,
        allocation_handle,
        controller_authorization_ref,
        requested_scope_digest,
    } = preparation else {
        panic!("prepare must await the controller-authored provision Event");
    };
    assert_eq!(
        arkret_wire::project_full_id_to_core_id(&full_id).unwrap(),
        agent_id
    );
    let expected_scope_digest =
        arkret_signatures::agent::agent_requested_scope_digest(&agent_id, &controller_id, &scope)
            .unwrap();
    assert_eq!(requested_scope_digest, expected_scope_digest);
    let actor_frontier_value: Value =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"actor_id": controller_id, "realm_id": controller_realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app)
            .await
            .take_json()
            .await
            .expect("controller actor frontier response");
    let actor_frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(actor_frontier_value.clone()).unwrap_or_else(|error| {
            panic!("controller actor frontier: {error}; {actor_frontier_value}")
        });
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(actor_frontier) =
        actor_frontier.frontier
    else {
        panic!("combined Realm+actor selector must return realm_actor frontier");
    };
    assert_eq!(actor_frontier.realm_id, controller_realm_id);
    assert_eq!(actor_frontier.actor_id, controller_id);
    let next_actor_seq = actor_frontier.next_actor_seq;
    let now =
        chrono::DateTime::<chrono::Utc>::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let verification_method =
        arkret_wire::DidUrl::new(format!("{controller}#{CONTROLLER_DEVICE_ID}"))
            .expect("fixture verification method is a DID URL");
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        controller_full_id.clone(),
        verification_method.clone(),
    );
    let create_payload = arkret_bootstrap::build_managed_agent_pcr_create_payload(
        arkret_bootstrap::ManagedAgentPcrCreatePayloadInput {
            agent_id: agent_id.clone(),
            initial_resolution: initial_resolution.clone(),
            controller_id: controller_id.clone(),
            genesis_salt: arkret_wire::GenesisSalt::generate().unwrap(),
            trust_domain: state.config().trust_domain.clone(),
            capability_action_registry_digest:
                arkret_policy::current_capability_action_registry_digest().unwrap(),
            created_at: now,
        },
    )
    .unwrap();
    let mut pcr_genesis = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        agent_id.clone(),
        0,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0000-a13f9c2e")).unwrap(),
        serde_json::to_value(create_payload).unwrap(),
    )
    .unwrap();
    pcr_genesis.created_at = now;
    pcr_genesis.requirements.schema_profile_refs =
        vec![arkret_wire::ProfileRef::new(arkret_wire::SchemaId::REALM_V1).unwrap()];
    pcr_genesis.executed_by = Some(controller_id.clone());
    pcr_genesis.authorization_ref = Some(controller_authorization_ref.clone().into());
    pcr_genesis.refs.clear();
    pcr_genesis.refresh_content_bound_identity().unwrap();
    arkret_signatures::sign_event(
        &mut pcr_genesis,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let principal_control_realm_id = pcr_genesis.realm_id.clone();
    let mut frontier_response = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": controller_realm_id}))
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
        &controller_id,
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
    let provision_event = prepare_self_principal_pcr_initial_submissions(state, token, vec![event])
        .await
        .into_iter()
        .next()
        .expect("single provision submission");
    let commit_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Commit {
            operation_id,
            idempotency_key,
            agent_id: agent_id.clone(),
            full_id: full_id.clone(),
            principal_control_realm_id: principal_control_realm_id.clone(),
            allocation_handle,
            slug: slug.to_owned(),
            requested_scope: scope,
            provision_event: Box::new(provision_event),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let fault_expected = fault.is_some();
    if let Some((injector, plan)) = fault {
        injector.arm(plan);
    }
    let mut committed = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    let mut status = committed.status_code.expect("commit status");
    let mut body: serde_json::Value = committed.take_json().await.expect("commit body");
    let mut fault_outcome = None;
    if fault_expected && status.is_server_error() {
        fault_outcome = Some((status, body));
        let mut retried = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        status = retried.status_code.expect("retried commit status");
        body = retried.take_json().await.expect("retried commit body");
    }
    if status != StatusCode::OK || body["status"] != "awaiting_pcr_genesis" {
        return (status, body, commit_body, fault_outcome);
    }

    let predecessor = state
        .test_seal(&frontier.seal_id)
        .unwrap()
        .expect("controller PCR predecessor Seal");
    let mut controller_events = state
        .test_persistence()
        .events()
        .realm_events_newest_first(controller_realm_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .collect::<Vec<_>>();
    controller_events.sort_by(|left, right| {
        left.actor_seq
            .cmp(&right.actor_seq)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let controller_seal = arkret_bootstrap::build_self_principal_event_seal(
        &controller_events,
        &predecessor,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        &signer,
        &genesis_projector,
    )
    .unwrap();
    let controller_seal_body = arkret_canonical::canonical_json_bytes(&controller_seal).unwrap();
    let mut controller_seal_response = TestClient::post("http://server/_arkret/self/events/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(controller_seal_body)
        .send(&app)
        .await;
    let controller_seal_status = controller_seal_response.status_code;
    let controller_seal_response_body = controller_seal_response
        .take_string()
        .await
        .unwrap_or_default();
    assert_eq!(
        controller_seal_status,
        Some(StatusCode::OK),
        "{controller_seal_response_body}"
    );

    let genesis_authority =
        arkret_bootstrap::ManagedAgentPcrGenesisAuthority::from_delegated_create(
            &pcr_genesis,
            &genesis_projector,
        )
        .unwrap();
    let proposal_policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let proposal_member = arkret_wire::ControlProposalAuthorityAck::issue_with_signer(
        pcr_genesis.realm_id.clone(),
        arkret_wire::Hash::new(pcr_genesis.event_digest().unwrap()).unwrap(),
        genesis_authority.authority_set_ref().clone(),
        now,
        proposal_policy,
        &signer,
    )
    .unwrap();
    let mut genesis_submission = arkret_wire::EventInitialSubmission::online(pcr_genesis);
    genesis_submission.control_proposal_ack = Some(
        arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![proposal_member])
            .unwrap(),
    );
    genesis_submission
        .validate_structural_in_context(arkret_wire::EventSubmitContext::AnchorUnit)
        .unwrap();
    let accepted_genesis = genesis_submission.event.clone();
    let genesis_body = arkret_wire::EventsSubmitBatchRequestBody {
        events: vec![genesis_submission],
    };
    let genesis_body = arkret_canonical::canonical_json_bytes(&genesis_body).unwrap();
    let mut genesis_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(genesis_body)
        .send(&app)
        .await;
    let genesis_status = genesis_response.status_code;
    let genesis_response_body = genesis_response.take_string().await.unwrap_or_default();
    assert_eq!(
        genesis_status,
        Some(StatusCode::OK),
        "{genesis_response_body}"
    );
    let genesis_outcome: Value = serde_json::from_str(&genesis_response_body).unwrap();
    assert_eq!(
        genesis_outcome["accepted"],
        serde_json::json!([accepted_genesis.event_id]),
        "{genesis_response_body}"
    );
    let genesis_seal = arkret_bootstrap::build_managed_agent_pcr_event_seal(
        std::slice::from_ref(&accepted_genesis),
        None,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0003-a13f9c2e")).unwrap(),
        &signer,
        &genesis_projector,
    )
    .unwrap();
    let genesis_seal_body = arkret_canonical::canonical_json_bytes(&genesis_seal).unwrap();
    let mut seal_response = TestClient::post("http://server/_arkret/self/events/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(genesis_seal_body)
        .send(&app)
        .await;
    let seal_status = seal_response.status_code;
    let seal_response_body = seal_response.take_string().await.unwrap_or_default();
    assert_eq!(seal_status, Some(StatusCode::OK), "{seal_response_body}");
    let mut awaiting_binding = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    assert_eq!(awaiting_binding.status_code, Some(StatusCode::OK));
    let awaiting_binding_body: Value = awaiting_binding.take_json().await.unwrap();
    assert_eq!(
        awaiting_binding_body["status"], "awaiting_did_binding",
        "{awaiting_binding_body}"
    );
    let hidden_list: Value = TestClient::get("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(hidden_list["agents"], serde_json::json!([]));
    let hidden_get = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(hidden_get.status_code, Some(StatusCode::NOT_FOUND));

    let binding_update = arkret_signatures::webvh::prepare_managed_agent_binding_update(
        &arkret_signatures::webvh::ManagedAgentBindingUpdateInput {
            did: full_id.as_str(),
            local_id: &agent_inception.local_id,
            previous_entries: std::slice::from_ref(&agent_inception.log_entry),
            version_time: now + chrono::Duration::seconds(1),
            current_root_seed: &[22_u8; 32],
            next_root_public_key_multibase: &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                successor_signing_key.verifying_key().as_bytes(),
            ),
            controller_id: &controller_id,
            principal_control_realm_id: &principal_control_realm_id,
            requested_scope_digest: &expected_scope_digest,
        },
    )
    .unwrap();
    let binding_request = serde_json::to_value(&binding_update.submit_body).unwrap();
    let mut binding_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&binding_request)
            .send(&app)
            .await;
    if fault_expected
        && fault_outcome.is_none()
        && binding_response
            .status_code
            .is_some_and(|status| status.is_server_error())
    {
        let failed_status = binding_response.status_code.expect("failed binding status");
        let failed_body = binding_response.take_json().await.unwrap();
        fault_outcome = Some((failed_status, failed_body));
        binding_response =
            TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
                .json(&binding_request)
                .send(&app)
                .await;
    }
    assert_eq!(binding_response.status_code, Some(StatusCode::OK));
    let binding_body: Value = binding_response.take_json().await.unwrap();
    assert!(matches!(
        binding_body["status"].as_str(),
        Some("accepted" | "duplicate")
    ));

    let mut completed = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    let status = completed.status_code.expect("final commit status");
    let body = completed.take_json().await.expect("final commit body");
    (status, body, commit_body, fault_outcome)
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
    let controller_authority_instance =
        seed_active_controller_device_generation(&state, controller).await;

    let (status, body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        &controller_authority_instance,
        "production-agent",
        serde_json::json!({
                "actions": [
                    "ak.self.events.stream.subscribe",
                    "ak.self.events.read.scan",
                    "ak.self.events.command.submit",
                    "ak.event.read",
                    "ak.message.create"
                ],
                "resources": [{
                    "kind": "service",
                    "service_id": state.service_id()
                }]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "complete");
    let controller_id = arkret_wire::project_full_id_to_core_id(
        &arkret_wire::DidFullId::new(controller.to_owned()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state
            .test_persistence()
            .agents()
            .list_for_controller(controller_id.as_str())
            .await
            .unwrap()
            .len(),
        1
    );

    // Cross-repository closure: SDK producer -> Soland admission/store ->
    // account query replay -> SDK model/digest/proof verifier.
    let app = app_from_state(state.clone());
    let mut replay_response = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"actors": [controller_id], "limit": 100}))
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
        let controller_authority_instance =
            seed_active_controller_device_generation(&state, controller).await;

        let requested_scope = serde_json::json!({
            "actions": [
                "ak.self.events.stream.subscribe",
                "ak.self.events.read.scan",
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
        let (status, body, commit_body, fault_outcome) = provision_agent_sdk_commit_attempt(
            &state,
            &token,
            controller,
            &controller_authority_instance,
            &slug,
            requested_scope,
            Some((&injector, plan)),
        )
        .await;
        let (failed_status, failed_body) = fault_outcome
            .unwrap_or_else(|| panic!("fault plan {plan:?} did not interrupt a durable boundary"));
        assert_eq!(
            failed_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fault plan {plan:?} did not interrupt the commit: {failed_body}"
        );
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["status"], "complete");

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
        assert_eq!(recovered_body, body);

        let mut replayed = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        assert_eq!(replayed.status_code, Some(StatusCode::CREATED));
        assert_eq!(replayed.take_json::<Value>().await.unwrap(), recovered_body);

        let agent_id = commit_body["agent_id"].as_str().unwrap();
        let agent_full_id = commit_body["full_id"].as_str().unwrap();
        assert_eq!(
            arkret_wire::project_full_id_to_core_id(
                &arkret_identifiers::DidFullId::new(agent_full_id.to_owned()).unwrap()
            )
            .unwrap()
            .as_str(),
            agent_id
        );
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
        let did_history = persistence
            .webvh()
            .list_log_events(agent_full_id)
            .await
            .unwrap();
        assert_eq!(
            did_history.len(),
            2,
            "fault plan {plan:?} did not preserve exactly entry 0 and its PCR-binding successor"
        );
        let did_document = persistence
            .webvh()
            .get_document(agent_full_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(did_document.did, agent_full_id);
        assert_eq!(did_document.did_document["id"], agent_full_id);
        assert_eq!(
            did_document.key_log_head.as_deref(),
            Some(did_history[1].event_digest.as_str())
        );
        let controller_id = arkret_wire::project_full_id_to_core_id(
            &arkret_wire::DidFullId::new(controller.to_owned()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            persistence
                .agents()
                .list_for_controller(controller_id.as_str())
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

    let controller_full_id = arkret_identifiers::DidFullId::new(controller.to_owned()).unwrap();
    let controller_id = arkret_wire::project_full_id_to_core_id(&controller_full_id).unwrap();
    let controller_realm_id = arkret_identifiers::RealmId::new(
        soland_test_support::fixture_principal_control_realm(controller),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let hlc =
        arkret_identifiers::Hlc::new(format!("{:012x}-0000-a13f9c2e", now.timestamp_millis()))
            .unwrap();
    let provision_event = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::AgentProvision.as_str(),
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
            idempotency_key: arkret_wire::IdempotencyKey::new("unallocated-commit-001").unwrap(),
            agent_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:unallocated-agent.example",
            )
            .unwrap(),
            full_id: arkret_identifiers::DidFullId::new("did:web:unallocated-agent.example")
                .unwrap(),
            principal_control_realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
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
                control_proposal_ack: None,
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
    let controller_authority_instance =
        seed_active_controller_device_generation(&state, controller).await;

    let requested_scope = serde_json::json!({
        "actions": [
            "ak.self.events.stream.subscribe",
            "ak.self.events.read.scan",
            "ak.self.events.command.submit"
        ],
        "resources": [
            {
                "kind": "operation",
                "operation": "ak.self.events.stream.subscribe"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.read.scan"
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
        &controller_authority_instance,
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
    assert_eq!(
        key_state.pairing_code.as_deref(),
        created_body["pairing_code"].as_str(),
        "authorized lifecycle service must receive the still-open pairing code"
    );

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
            idempotency_key: arkret_wire::IdempotencyKey::new(
                uuid::Uuid::now_v7().simple().to_string(),
            )
            .unwrap(),
            full_id: arkret_identifiers::DidFullId::new(
                created_body["full_id"]
                    .as_str()
                    .expect("created Agent full id")
                    .to_owned(),
            )
            .unwrap(),
            controller_authority_instance: controller_authority_instance.clone(),
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
    let controller_authority_instance =
        seed_active_controller_device_generation(&state, controller).await;

    let (status, body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        &controller_authority_instance,
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
