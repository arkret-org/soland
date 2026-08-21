//! Integration tests — the public agent key-pairing ceremony over real HTTP.
//!
//! Walks the open pairing surface end to end with SDK-produced material:
//! provisioning (real ceremony) → `POST /_arkret/open/agent-pairing/
//! runtime-key-requests` → open status poll → `POST /_arkret/gate/account/
//! agent-key-pair` → successor managed-Agent PCR Seal → idempotent retry that
//! activates the runtime. Unlike the storage-port fixture in `events.rs`
//! (which seeds runtime activation directly to test session-grant semantics),
//! every protocol step here goes over the HTTP surface.
//!
//! The one direct-write fixture is the controller-side recovery material the
//! ceremony presupposes but does not itself produce: the Agent PCR MLS group,
//! the `mls_history` key backup binding the Agent to the current sealed
//! frontier, and the controller-signed `ak.key_backup.active_series` pointer
//! selecting that backup's series (`identity/key-management.md` §7.4.1 /
//! §7.6). Its signature is real, so the recovery gate verifies it exactly as
//! it would a client-published pointer.

use super::common::*;

const CEREMONY_SCOPE_ACTIONS: [&str; 3] = [
    "ak.self.events.stream.subscribe",
    "ak.self.events.read.scan",
    "ak.self.events.command.submit",
];

fn ceremony_requested_scope() -> Value {
    serde_json::json!({
        "actions": CEREMONY_SCOPE_ACTIONS,
        "resources": CEREMONY_SCOPE_ACTIONS
            .iter()
            .map(|action| serde_json::json!({"kind": "operation", "operation": action}))
            .collect::<Vec<_>>(),
        "constraints": []
    })
}

/// Seed the controller-side managed-Agent PCR recovery material the pairing
/// commit gate requires: the Agent PCR MLS group, an `mls_history` key backup
/// binding this Agent to `seal`, and the controller-signed active-series
/// pointer that selects the backup's series.
///
/// The active-series record is signed with the controller's accepted device
/// key over the SDK's canonical transcript, so the server-side currency check
/// (`identity/key-management.md` §7.6: accepted signing device, current
/// device generation, matching `device_authorize_event_id`) runs for real.
async fn seed_agent_pcr_recovery_material(
    state: &AppState,
    controller: &str,
    controller_core: &arkret_wire::DidCoreId,
    agent_id: &arkret_wire::DidCoreId,
    agent_pcr_realm: &arkret_identifiers::RealmId,
    authorization_ref: &str,
    seal: &arkret_wire::Seal,
    controller_device_key: &SigningKey,
) {
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let persistence = state.test_persistence();

    // 1/3 — the Agent PCR MLS group. `current_managed_frontier` refuses to
    // report a frontier for a control Realm with no uncontested group.
    let effective_scope = arkret_wire::ScopeRef::Realm {
        realm_id: agent_pcr_realm.clone(),
    };
    let governance_binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        agent_pcr_realm.clone(),
        FIXTURE_MLS_GROUP_ID,
        0,
        0,
        arkret_identifiers::Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
        arkret_models_crypto::MlsContentScheme::MlsRfc9420,
        None,
        arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_wire::CORE_REDUCER_PROFILE,
    )
    .expect("Agent PCR governance binding builds");
    persistence
        .mls_commits()
        .initialize_genesis(soland_storage::MlsCommitGenesis {
            effective_scope: &serde_json::to_value(&effective_scope).unwrap(),
            group_id: FIXTURE_MLS_GROUP_ID,
            leader_actor_id: agent_id.as_str(),
            creator_device_id: super::agents::CONTROLLER_DEVICE_ID,
            genesis_event_ref: seal.id.as_str(),
            governance_binding: &serde_json::to_value(&governance_binding).unwrap(),
            committed_at: now.timestamp_millis(),
        })
        .await
        .unwrap()
        .expect("Agent PCR MLS group initializes");

    // 2/3 — the controller's `mls_history` backup covering this Agent PCR at
    // the current sealed frontier.
    let policy = persistence
        .recovery_policies()
        .get_active_for_principal(controller_core.as_str())
        .await
        .unwrap()
        .expect("seeded controller recovery policy");
    let series_id =
        arkret_identifiers::BackupSeriesId::new(new_prefixed_uuid7("ak:backup_series:")).unwrap();
    let backup_id = arkret_identifiers::BackupId::new(new_prefixed_uuid7("ak:backup:")).unwrap();
    let recipient_key_ref = format!(
        "{controller}#{}",
        super::agents::CONTROLLER_BACKUP_HPKE_FRAGMENT
    );
    let managed_principal_binding = arkret_models_crypto::ManagedPrincipalBinding {
        managed_principal_id: agent_id.clone(),
        controller_id: controller_core.clone(),
        principal_control_realm_id: agent_pcr_realm.clone(),
        authorization_ref: authorization_ref.to_owned(),
        managed_frontier_ref: arkret_models_crypto::ManagedFrontierRef {
            frontier_digest: seal.control_event_set_root.clone(),
            seal_ref: seal.id.as_str().to_owned(),
            mls_epoch: 0,
        },
    };
    let backup = serde_json::json!({
        "backup_id": backup_id,
        "actor_id": controller_core,
        "backup_kind": "mls_history",
        "backup_version": "1",
        "created_at": canonical_timestamp(now),
        "encryption": {
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": recipient_key_ref,
            "aead": {
                "name": "chacha20_poly1305",
                "enc": "QUFB"
            }
        },
        "domain_separation": {
            "hkdf_info": "ak.key_backup.mls_history/v1",
            "subdomain": "mls_history",
            "aead_aad": {
                "schema": arkret_wire::SchemaId::KEY_BACKUP_V1,
                "actor_id": controller_core,
                "device_id": super::agents::CONTROLLER_DEVICE_ID,
                "backup_kind": "mls_history",
                "backup_version": "1",
                "created_at": canonical_timestamp(now),
                "item_kinds": ["mls_group_state"],
                "managed_principal_bindings": [managed_principal_binding],
                "recipient_method": "recovery_public_key",
                "recipient_key_ref": recipient_key_ref
            }
        },
        "contents": [{
            "item_kind": "mls_group_state",
            "realm_id": agent_pcr_realm,
            "managed_principal_binding": managed_principal_binding,
            "mls_group_id": FIXTURE_MLS_GROUP_ID,
            "epoch": 0
        }],
        "ciphertext": "QUFB",
        "ciphertext_digest": format!("sha256:{}", "3".repeat(64)),
        "series_id": series_id,
        "series_seq": 0,
        "recovery_policy_ref": {
            "policy_id": policy.policy_id,
            "policy_version": policy.version
        }
    });
    serde_json::from_value::<arkret_models_crypto::KeyBackup>(backup.clone())
        .expect("fixture backup matches the SDK key-backup envelope");
    persistence
        .key_backups()
        .put(backup_id.as_str().to_owned(), backup)
        .await
        .unwrap();

    // 3/3 — the signed active-series pointer selecting that series.
    let controller_device = persistence
        .devices()
        .get(
            controller_core.as_str(),
            super::agents::CONTROLLER_DEVICE_ID,
        )
        .await
        .unwrap()
        .expect("seeded controller device");
    let device_authorize_event_id = arkret_wire::EventId::new(
        controller_device.payload["device_authorize_event_id"]
            .as_str()
            .expect("seeded controller device authorization")
            .to_owned(),
    )
    .unwrap();
    let unsigned =
        arkret_models_collaboration::events_payloads::UnsignedKeyBackupActiveSeries::new(
            controller_core.clone(),
            arkret_models_crypto::BackupKind::MlsHistory,
            series_id,
            1,
            Vec::new(),
            seal.control_event_set_root.clone(),
            Some(seal.id.clone()),
            now,
            arkret_wire::DidUrl::new(format!(
                "{controller}#{}",
                super::agents::CONTROLLER_DEVICE_ID
            ))
            .unwrap(),
            arkret_models_collaboration::events_payloads::ControllerBackupTrustAnchor {
                authorize_event_id: device_authorize_event_id,
                generation_ref: 1,
            },
        )
        .expect("unsigned active-series record builds");
    let signature = arkret_canonical::base64url_encode(
        controller_device_key
            .sign(&unsigned.signing_payload_bytes().unwrap())
            .to_bytes(),
    );
    let pointer = unsigned
        .attach_signature(arkret_wire::Base64UrlString::new(signature).unwrap())
        .expect("active-series record signs");
    let head =
        arkret_models_collaboration::events_payloads::key_backup_active_series_head(&pointer)
            .expect("active-series head");
    state
        .test_projection()
        .lock()
        .key_backup_active_series
        .insert(
            (
                controller_core.as_str().to_owned(),
                "mls_history".to_owned(),
            ),
            soland_domain::reducer::SolandKeyBackupActiveSeries {
                actor_id: controller_core.as_str().to_owned(),
                backup_kind: "mls_history".to_owned(),
                active_series_id: head.active_series_id.as_str().to_owned(),
                series_pointer_version: head.series_pointer_version,
                previous_series_ids: Vec::new(),
                record_digest: head.record_digest,
                frontier_ref: pointer.frontier_ref.clone(),
                issued_at: pointer.issued_at,
                auth_data: pointer.auth_data.clone(),
                extra: pointer.extra.clone(),
                event_id: format!("ak:event:{}", "A".repeat(44)),
            },
        );
}

#[tokio::test]
async fn public_pairing_ceremony_activates_the_agent_runtime() {
    let state = soland_test_support::app_state(test_config());
    let app = app_from_state(state.clone());
    let controller = "did:web:alice.example";
    let token = "agent-pairing-ceremony-session";
    super::agents::seed_controller_session(&state, token, controller).await;
    super::agents::seed_agent_provision_prerequisites(&state, controller).await;
    let controller_authority =
        super::agents::seed_active_controller_device_generation(&state, controller).await;
    let controller_core = fixture_actor_core_id(controller);
    let service_core = arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap();

    // ── Provisioning: the real prepare/commit ceremony over HTTP. ────────────
    let (status, body) = super::agents::provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        &controller_authority,
        "ceremony",
        ceremony_requested_scope(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let provisioned = serde_json::from_value::<
        arkret_models_collaboration::agent_operations::AgentProvisionOutcome,
    >(body)
    .expect("typed provision outcome");
    let arkret_models_collaboration::agent_operations::AgentProvisionOutcome::Complete { outcome } =
        provisioned
    else {
        panic!("Agent provisioning must complete");
    };
    let pairing_code = outcome
        .pairing_code
        .clone()
        .expect("development provisioning returns the pairing code");

    // ── 1/4 — the runtime submits its key request on the open surface. ───────
    //
    // Before the method-adapter projection fix, this schema-valid SDK request
    // was rejected with 100% certainty: `verification_method` is a full DID
    // URL while `agent_id` is a Core id, and the handler compared the two as
    // bare strings.
    let runtime_seed: [u8; 32] =
        Sha256::digest(b"agent-pairing-ceremony-runtime-key".as_slice()).into();
    let runtime_key = SigningKey::from_bytes(&runtime_seed);
    let endpoint_device_id =
        arkret_identifiers::DeviceId::new(new_prefixed_uuid7("ak:device:")).unwrap();
    let builder = arkret_signatures::agent::RuntimeKeyRequestBuilder::new(
        &runtime_key,
        arkret_models_collaboration::agent_operations::AgentPairingBootstrap {
            arkret_base_url: "http://server".to_owned(),
            service_id: service_core.clone(),
            agent_id: outcome.agent_id.clone(),
            pairing_request_id: outcome.pairing_request_id.clone(),
            pairing_code: pairing_code.clone(),
            pairing_expires_at: outcome.expires_at,
        },
        &outcome.full_id,
        endpoint_device_id.clone(),
    );
    let approval_request = builder
        .build_approval_request()
        .expect("runtime key approval request builds");
    let mut approval_response =
        TestClient::post("http://server/_arkret/open/agent-pairing/runtime-key-requests")
            .json(&serde_json::to_value(&approval_request.body).unwrap())
            .send(&app)
            .await;
    let approval_status = approval_response.status_code;
    let approval_body: Value = approval_response.take_json().await.unwrap();
    assert_eq!(approval_status, Some(StatusCode::OK), "{approval_body}");
    assert_eq!(approval_body["ok"], true, "{approval_body}");
    assert!(
        approval_body["approval_request_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("agent_runtime_approval:")),
        "{approval_body}"
    );

    // ── 2/4 — the runtime polls the open status surface. ─────────────────────
    let status_request = serde_json::json!({
        "pairing_request_id": outcome.pairing_request_id,
        "pairing_code": pairing_code,
        "agent_id": outcome.agent_id,
    });
    let mut status_response =
        TestClient::post("http://server/_arkret/open/agent-pairing/runtime-key-requests/status")
            .json(&status_request)
            .send(&app)
            .await;
    let poll_status = status_response.status_code;
    let poll_body: Value = status_response.take_json().await.unwrap();
    assert_eq!(poll_status, Some(StatusCode::OK), "{poll_body}");
    assert_eq!(
        poll_body["runtime_state"], "pending_runtime_key",
        "{poll_body}"
    );
    assert_eq!(
        poll_body["approval_request_id"], approval_body["approval_request_id"],
        "{poll_body}"
    );

    // ── 3/4 — the controller authors the authorize Event, the signing-key
    // binding, and the requested-scope disclosure, all with real SDK
    // primitives and the seeded controller device key. ───────────────────────
    let record = state
        .test_persistence()
        .agents()
        .get(outcome.agent_id.as_str())
        .await
        .unwrap()
        .expect("provisioned Agent record");
    let agent_pcr_realm =
        arkret_identifiers::RealmId::new(record.principal_control_realm_id.clone()).unwrap();
    let genesis_event_id = state
        .test_persistence()
        .events()
        .realm_events_newest_first(agent_pcr_realm.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .map(|event| arkret_identifiers::EventId::new(event.event_id).unwrap())
        .expect("accepted Agent PCR genesis Event");
    let genesis_seal_id = state
        .test_seal_leaves(&agent_pcr_realm)
        .unwrap()
        .into_iter()
        .next()
        .expect("accepted Agent PCR genesis Seal");
    let genesis_seal = state
        .test_seal(&genesis_seal_id)
        .unwrap()
        .expect("stored Agent PCR genesis Seal");

    let verification_method = approval_request.body.verification_method.clone();
    let validated_runtime_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &approval_request.body.public_key,
        &verification_method,
    )
    .expect("runtime public key validates");
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let agent_key_id =
        arkret_wire::NonEmptyString::new(verification_method.as_str().to_owned()).unwrap();
    let binding_core = arkret_signatures::agent_evidence::prepare_agent_signing_key_binding_core(
        outcome.agent_id.clone(),
        agent_key_id.clone(),
        verification_method.clone(),
        &approval_request.body.public_key,
        created_at,
        None,
        controller_core.clone(),
    )
    .expect("signing key binding core builds");
    let signing_key_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_core_digest(&binding_core)
            .expect("signing key binding core digest");
    let pairing_digest =
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            &controller_core,
            &outcome.agent_id,
            &outcome.pairing_request_id,
            &pairing_code,
            outcome.expires_at,
            &service_core,
            &approval_request
                .body
                .proof_of_possession
                .runtime_key_binding_digest,
            &approval_request.body.proof_of_possession,
        )
        .expect("pairing request binding digest");
    let payload = arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload {
        agent_id: outcome.agent_id.clone(),
        key_id: agent_key_id,
        verification_method: verification_method.clone(),
        public_key_digest: validated_runtime_key.authorization_digest.clone(),
        signing_key_binding_digest,
        accountable_principal_id: controller_core.clone(),
        agent_key_scope: serde_json::from_value(ceremony_requested_scope()).unwrap(),
        audience: vec![state.service_id().clone()],
        issued_at: created_at,
        expires_at: None,
        approval_evidence:
            arkret_models_collaboration::events_payloads::agent::AgentKeyApprovalEvidence {
                kind: arkret_models_collaboration::events_payloads::agent::AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(
                    arkret_identifiers::Hash::new(pairing_digest.as_str().to_owned()).unwrap(),
                ),
                pairing_request_id: Some(outcome.pairing_request_id.clone()),
                approved_by: Some(controller_core.clone()),
            },
        supersedes: Vec::new(),
        revocation_check_ref: None,
        runtime_attestation: None,
    };

    let controller_full_id = arkret_identifiers::DidFullId::new(controller.to_owned()).unwrap();
    let controller_verification_method = arkret_wire::DidUrl::new(format!(
        "{controller}#{}",
        super::agents::CONTROLLER_DEVICE_ID
    ))
    .unwrap();
    let controller_device_key =
        SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED);
    let controller_signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED),
        controller_full_id.clone(),
        controller_verification_method.clone(),
    );
    let timestamp_hex = format!("{:012x}", created_at.timestamp_millis());
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr_realm.clone(),
        },
        outcome.agent_id.clone(),
        soland_test_support::fixture_principal_server_id(),
        1,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0007-a13f9c2e")).unwrap(),
        serde_json::to_value(&payload).unwrap(),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![genesis_event_id];
    authorize.executed_by = Some(controller_core.clone());
    authorize.authorization_ref = Some(record.controller_authorization_ref.clone().into());
    authorize.seal_basis = Some(genesis_seal.seal_basis());
    authorize
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let mut authorize = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        authorize,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("authorize envelope finalizes");
    arkret_signatures::sign_event(
        &mut authorize,
        &controller_signer,
        &controller_verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let authorize = authorize.into_event();

    let binding_to_sign = arkret_signatures::agent_evidence::materialize_agent_signing_key_binding(
        binding_core,
        authorize.event_id.clone(),
        controller_verification_method.clone(),
    )
    .expect("signing key binding materializes");
    let binding_bytes = arkret_signatures::agent_evidence::agent_signing_key_binding_to_sign_bytes(
        &binding_to_sign,
    )
    .expect("signing key binding transcript");
    let controller_jws =
        arkret_signatures::jws::sign_jws_ed25519(&binding_bytes, &controller_device_key)
            .expect("controller proof JWS signs");
    let signing_key_binding = arkret_signatures::agent_evidence::finish_agent_signing_key_binding(
        binding_to_sign.clone(),
        &controller_jws,
    )
    .expect("signing key binding finishes");

    let request_uuid = outcome
        .pairing_request_id
        .as_str()
        .strip_prefix("agent_pairing_request:")
        .expect("typed pairing request id");
    let requested_scope_typed: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
        serde_json::from_value(ceremony_requested_scope()).unwrap();
    let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &outcome.agent_id,
        &controller_core,
        &requested_scope_typed,
    )
    .unwrap();
    let mut disclosure =
        arkret_models_collaboration::agent_operations::AgentRequestedScopeDisclosure {
            schema: arkret_wire::SchemaId::AgentRequestedScopeDisclosureV1,
            request_id: arkret_identifiers::RequestId::new(format!("ak:request:{request_uuid}"))
                .unwrap(),
            agent_id: outcome.agent_id.clone(),
            controller_id: controller_core.clone(),
            requested_scope: requested_scope_typed,
            requested_scope_digest,
            verifier_service_id: service_core.clone(),
            audience: arkret_wire::NonEmptyString::new(
                arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            )
            .unwrap(),
            challenge: arkret_wire::NonEmptyString::new(
                outcome.pairing_request_id.as_str().to_owned(),
            )
            .unwrap(),
            issued_at: created_at,
            expires_at: created_at + chrono::Duration::minutes(5),
            proofs: vec![arkret_wire::Proof {
                kind: "detached_jws".to_owned(),
                verification_method: controller_verification_method.clone(),
                event_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            }],
        };
    disclosure.proofs[0].event_digest = disclosure.payload_digest().unwrap();
    let disclosure_binding = disclosure
        .canonical_proof_binding_bytes(&disclosure.proofs[0])
        .unwrap();
    disclosure.proofs[0].jws =
        arkret_signatures::jws::sign_jws_ed25519(&disclosure_binding, &controller_device_key)
            .unwrap();

    let key_pair_request = builder
        .build_key_pair_request(
            disclosure,
            signing_key_binding,
            arkret_wire::EventInitialSubmission::online(authorize),
        )
        .expect("key pair request builds");
    let key_pair_body = key_pair_request.body;
    let event_id = key_pair_body.authorize_event.event.event_id.clone();

    // ── 4/4a — a forged controller proof is rejected by the real
    // account-authority JWS verification (the pre-fix stub rejected
    // everything, so only the combination of both outcomes below proves the
    // verification is live). ────────────────────────────────────────────────
    let mut forged_body = serde_json::to_value(&key_pair_body).unwrap();
    forged_body["signing_key_binding"]["controller_proof"]["jws"] = Value::String(
        arkret_signatures::jws::sign_jws_ed25519(
            &binding_bytes,
            &SigningKey::from_bytes(&[77u8; 32]),
        )
        .unwrap(),
    );
    let mut forged_response = TestClient::post("http://server/_arkret/gate/account/agent-key-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("idempotency-key", event_id.as_str(), true)
        .json(&forged_body)
        .send(&app)
        .await;
    let forged_status = forged_response.status_code;
    let forged_outcome: Value = forged_response.take_json().await.unwrap();
    assert_eq!(
        forged_status,
        Some(StatusCode::BAD_REQUEST),
        "{forged_outcome}"
    );
    assert_eq!(
        forged_outcome["error"]["code"], "agent_signing_key_mismatch",
        "{forged_outcome}"
    );

    // ── 4/4b — the recovery gate is fail-closed until the controller has a
    // ready managed-Agent PCR recovery backup. Reaching this refusal already
    // proves every wire-verification step in front of it accepted real SDK
    // material. ────────────────────────────────────────────────────────
    let mut not_ready = TestClient::post("http://server/_arkret/gate/account/agent-key-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("idempotency-key", event_id.as_str(), true)
        .json(&serde_json::to_value(&key_pair_body).unwrap())
        .send(&app)
        .await;
    let not_ready_status = not_ready.status_code;
    let not_ready_outcome: Value = not_ready.take_json().await.unwrap();
    assert_eq!(
        not_ready_status,
        Some(StatusCode::PRECONDITION_FAILED),
        "{not_ready_outcome}"
    );
    assert_eq!(
        not_ready_outcome["error"]["code"], "agent_pcr_recovery_not_ready",
        "{not_ready_outcome}"
    );

    seed_agent_pcr_recovery_material(
        &state,
        controller,
        &controller_core,
        &outcome.agent_id,
        &agent_pcr_realm,
        record.controller_authorization_ref.as_str(),
        &genesis_seal,
        &controller_device_key,
    )
    .await;

    // ── 4/4c — with the recovery backup ready the same request commits the
    // controller-signed authorize Event. Durable storage is only the proposal
    // half: activation waits for the successor PCR Seal. ─────────────────
    let mut pair_response = TestClient::post("http://server/_arkret/gate/account/agent-key-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("idempotency-key", event_id.as_str(), true)
        .json(&serde_json::to_value(&key_pair_body).unwrap())
        .send(&app)
        .await;
    let pair_status = pair_response.status_code;
    let pair_outcome: Value = pair_response.take_json().await.unwrap();
    assert_eq!(pair_status, Some(StatusCode::OK), "{pair_outcome}");
    assert_eq!(
        pair_outcome["activation_state"], "awaiting_accepted_frontier",
        "{pair_outcome}"
    );
    assert_eq!(pair_outcome["authorize_event_ref"], event_id.as_str());

    // ── 5/5 — the controller publishes the successor managed-Agent PCR Seal
    // covering the authorize Event, then replays the exact idempotent request.
    // Only accepted Seal application makes the authorization portable, so this
    // is the step that flips the runtime to `active`. ──────────────────
    let mut pcr_events = state
        .test_persistence()
        .events()
        .realm_events_newest_first(agent_pcr_realm.as_str())
        .await
        .unwrap()
        .into_iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .collect::<Vec<_>>();
    pcr_events.sort_by(|left, right| {
        left.actor_seq
            .cmp(&right.actor_seq)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    assert!(
        pcr_events.iter().any(|event| event.event_id == event_id),
        "the committed authorize Event must be durable in the Agent PCR"
    );
    let successor_seal = arkret_bootstrap::build_managed_agent_pcr_event_seal(
        &pcr_events,
        Some(&genesis_seal),
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0009-a13f9c2e")).unwrap(),
        &controller_signer,
        &super::agents::genesis_projector,
    )
    .expect("successor Agent PCR Seal builds");
    let mut seal_response = TestClient::post("http://server/_arkret/self/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&successor_seal).unwrap())
        .send(&app)
        .await;
    let seal_status = seal_response.status_code;
    let seal_body = seal_response.take_string().await.unwrap_or_default();
    assert_eq!(seal_status, Some(StatusCode::OK), "{seal_body}");

    let mut activated = TestClient::post("http://server/_arkret/gate/account/agent-key-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("idempotency-key", event_id.as_str(), true)
        .json(&serde_json::to_value(&key_pair_body).unwrap())
        .send(&app)
        .await;
    let activated_status = activated.status_code;
    let activated_outcome: Value = activated.take_json().await.unwrap();
    assert_eq!(
        activated_status,
        Some(StatusCode::OK),
        "{activated_outcome}"
    );
    assert_eq!(
        activated_outcome["activation_state"], "active",
        "the public pairing ceremony must terminate in an active Agent runtime: \
         {activated_outcome}"
    );
    let activated_record = state
        .test_persistence()
        .agents()
        .get(outcome.agent_id.as_str())
        .await
        .unwrap()
        .expect("activated Agent record");
    assert_eq!(
        activated_record.authorized_event_ref.as_deref(),
        Some(event_id.as_str())
    );
    assert_eq!(
        activated_record.authorized_verification_method.as_deref(),
        Some(verification_method.as_str())
    );
}
