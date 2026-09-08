//! Integration tests — the public agent key-pairing ceremony over real HTTP.
//!
//! Walks the open pairing surface end to end with SDK-produced material:
//! provisioning (real ceremony) → `POST /_arkret/open/agent-pairing/
//! runtime-key-requests` → open status poll → `POST /_arkret/gate/account/
//! agent-key-pair` → successor Agent PCR Seal → idempotent retry that
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

const CEREMONY_SCOPE_ACTIONS: [&str; 5] = [
    "ak.self.events.stream.subscribe.v1",
    "ak.self.events.read.scan.v1",
    "ak.self.events.read.frontier.v1",
    "ak.self.seals.read.frontier.v1",
    "ak.self.events.command.submit.v1",
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

/// Seed the controller-side Agent PCR recovery material the pairing
/// commit gate requires: the Agent PCR MLS group, an `mls_history` key backup
/// The pairing ceremony drives the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn public_pairing_ceremony_activates_the_agent_runtime() {
    run_on_deep_stack(
        "public_pairing_ceremony_activates_the_agent_runtime",
        public_pairing_ceremony_activates_the_agent_runtime_body,
    );
}

async fn public_pairing_ceremony_activates_the_agent_runtime_body() {
    let mut config = test_config();
    let controller_gate = super::events::bind_controller_gate_mock(&mut config).await;
    let state = soland_test_support::app_state(config);
    super::events::spawn_controller_gate_mock(controller_gate, &state);
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

    let pairing_token = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "r": outcome.pairing_request_id,
            "c": pairing_code,
        }))
        .unwrap(),
    );
    let mut resolved = TestClient::post("http://server/_arkret/open/agent-pairing/resolve")
        .json(&serde_json::json!({"pairing_token": pairing_token}))
        .send(&app)
        .await;
    assert_eq!(resolved.status_code, Some(StatusCode::OK));
    let bootstrap: arkret_models_collaboration::agent_operations::AgentPairingBootstrap =
        resolved.take_json().await.unwrap();
    assert_eq!(bootstrap.agent_id, outcome.agent_id);
    let runtime_identity = bootstrap.validated_runtime_identity().unwrap();
    assert_eq!(
        runtime_identity.controller_account_id.principal_id,
        controller_core
    );
    assert_eq!(
        runtime_identity.controller_account_id.station_id,
        service_core
    );
    let runtime_verification_method = runtime_identity.verification_method.clone();

    // ── 1/4 — the runtime submits its key request on the open surface. ───────
    //
    // Before the method-adapter projection fix, this schema-valid SDK request
    // was rejected with 100% certainty: `verification_method` is a DID
    // URL while `agent_id` is a Core id, and the handler compared the two as
    // bare strings.
    let runtime_seed: [u8; 32] =
        Sha256::digest(b"agent-pairing-ceremony-runtime-key".as_slice()).into();
    let runtime_key = SigningKey::from_bytes(&runtime_seed);
    let builder = arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
        &runtime_key,
        bootstrap,
        &runtime_verification_method,
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
    assert_eq!(approval_body["status"], "active", "{approval_body}");
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
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("accepted Agent PCR genesis Seal");
    let genesis_seal = state
        .test_seal(&genesis_seal_id)
        .await
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
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
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

    let controller_did = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let controller_verification_method = arkret_wire::DidUrl::new(format!(
        "{controller}#{}",
        super::agents::CONTROLLER_DEVICE_ID
    ))
    .unwrap();
    let controller_device_key =
        SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED);
    let controller_signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED),
        controller_did.clone(),
        controller_verification_method.clone(),
    );
    let timestamp_hex = format!("{:012x}", created_at.timestamp_millis());
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr_realm.clone(),
        },
        outcome.agent_id.clone(),
        soland_test_support::fixture_station_id(),
        1,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0007-a13f9c2e")).unwrap(),
        serde_json::to_value(&payload).unwrap(),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![genesis_event_id.clone()];
    authorize.executed_by = Some(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        controller_core.clone(),
        service_core.clone(),
    )));
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
    let accepted_genesis = state
        .test_persistence()
        .events()
        .realm_events_newest_first(agent_pcr_realm.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == genesis_event_id.as_str())
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .expect("accepted Agent PCR genesis");
    let agent_pcr_authority = arkret_bootstrap::AgentPcrGenesisAuthority::from_accepted_create(
        &accepted_genesis,
        &super::agents::genesis_projector,
    )
    .unwrap();
    let proposal_member = arkret_wire::ControlProposalAuthorityAck::issue_with_signer(
        agent_pcr_realm.clone(),
        arkret_wire::Hash::new(
            authorize
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
        agent_pcr_authority.authority_set_ref().clone(),
        created_at,
        arkret_wire::ControlProposalDecisionPolicy::default(),
        &controller_signer,
    )
    .unwrap();
    let mut authorize_submission = arkret_wire::EventInitialSubmission::online(authorize);
    authorize_submission.control_proposal_ack = Some(
        arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![proposal_member])
            .unwrap(),
    );

    let binding_to_sign = arkret_signatures::agent_evidence::materialize_agent_signing_key_binding(
        binding_core,
        authorize_submission.event.event_id.clone(),
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
    let mut disclosure =
        arkret_models_collaboration::agent_operations::AgentRequestedScopeDisclosure {
            schema: arkret_wire::SchemaId::AgentRequestedScopeDisclosureV1,
            request_id: arkret_identifiers::RequestId::new(format!("ak:request:{request_uuid}"))
                .unwrap(),
            agent_id: outcome.agent_id.clone(),
            controller_principal_id: controller_core.clone(),
            requested_scope: requested_scope_typed,
            verifier_id: service_core.clone(),
            audience: arkret_wire::NonEmptyString::new(
                arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            )
            .unwrap(),
            challenge: arkret_wire::NonEmptyString::new(
                outcome.pairing_request_id.as_str().to_owned(),
            )
            .unwrap(),
            issued_at: created_at,
            expires_at: created_at + chrono::Duration::minutes(5),
            proofs: vec![arkret_wire::ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: controller_verification_method.clone(),
                event_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                signer_resolution_evidence_ref: None,
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
        .build_key_pair_request(disclosure, signing_key_binding, authorize_submission)
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
        forged_outcome["type"], "https://arkret.org/problems/agent_signing_key_mismatch",
        "{forged_outcome}"
    );

    // ── 4/4b — the same request commits the controller-signed authorize
    // Event. key-management.md 7.5.6: pairing admission verifies current
    // controller/Agent authority, proof-of-possession and the accepted control
    // frontier, never a backup-readiness gate. Durable storage is only the
    // proposal half: activation waits for the successor PCR Seal. ────────
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

    // ── 5/5 — the controller publishes the successor Agent PCR Seal
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
    let predecessor_covered = genesis_seal
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let target = pcr_events
        .iter()
        .map(|event| {
            arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let availability_request =
        arkret_models_collaboration::governance_dependencies::SealAvailabilityReceiptIssueRequest {
            realm_id: agent_pcr_realm.clone(),
            predecessor_refs: vec![genesis_seal.id.clone()],
            event_digests: target.difference(&predecessor_covered).cloned().collect(),
        };
    let mut availability_response =
        TestClient::post("http://server/_arkret/self/seals/availability-receipts")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&availability_request).unwrap())
            .send(&app)
            .await;
    let availability_status = availability_response.status_code;
    let availability_body = availability_response.take_string().await.unwrap();
    assert_eq!(
        availability_status,
        Some(StatusCode::OK),
        "availability receipt issuance failed: {availability_body}"
    );
    let availability = serde_json::from_str::<
        arkret_models_collaboration::governance_dependencies::SealAvailabilityReceiptIssueOutcome,
    >(&availability_body)
    .unwrap();
    let successor_seal = arkret_bootstrap::build_agent_pcr_event_seal(
        &pcr_events,
        Some(&genesis_seal),
        Some(&availability),
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

    // An owned Agent has no human Contact round. Its accepted provision must
    // nevertheless let the controller author the first Direct Conversation.
    let resolve_request = arkret_models_collaboration::direct_conversation_ops::DirectConversationResolveRequestBody {
        peer: arkret_models_collaboration::contact_operations::ContactPeer::Agent {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(outcome.agent_id.clone(), service_core.clone())),
            controller_account_id: controller_authority.clone(),
        },
    };
    let mut direct_response =
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&resolve_request).unwrap())
            .send(&app)
            .await;
    let direct_status = direct_response.status_code;
    let direct_body: Value = direct_response.take_json().await.unwrap();
    assert_eq!(direct_status, Some(StatusCode::OK), "{direct_body}");
    assert_eq!(direct_body["state"], "creation_required", "{direct_body}");
    let evidence = &direct_body["next_founding_input"]["founding_authority_evidence"];
    assert_eq!(evidence["kind"], "controller_agent", "{direct_body}");
    let provision_ref =
        activated_record.provision_event_refs.as_ref().unwrap()["provision_event_id"]
            .as_str()
            .unwrap();
    assert_eq!(evidence["agent_provision_ref"], provision_ref);
    let provision = state
        .test_persistence()
        .events()
        .get(provision_ref)
        .await
        .unwrap()
        .unwrap();
    let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
        serde_json::from_value(provision.envelope["payload"].clone()).unwrap();
    assert_eq!(
        evidence["controller_binding_digest"],
        arkret_canonical::canonical_sha256(&payload).unwrap()
    );
    verify_owned_agent_direct_founding(
        &state,
        token,
        controller,
        &resolve_request,
        evidence.clone(),
    )
    .await;

    // The controller's Principal Control Realm is an ordinary, non-minimal-
    // metadata disclosure context. Add the now-active Agent as a member so
    // the authenticated controller can resolve that Agent's current signer
    // through the public self HTTP surface without any pre-seeded evidence
    // cache.
    let disclosure_realm = soland_test_support::fixture_principal_control_realm(controller);
    let controller_membership = add_test_realm_member(&state, &disclosure_realm, controller);
    assert_eq!(
        controller_membership["ok"], true,
        "controller disclosure membership: {controller_membership}"
    );
    let membership = add_test_realm_member(&state, &disclosure_realm, outcome.did.as_str());
    assert_eq!(
        membership["ok"], true,
        "Agent disclosure membership: {membership}"
    );
    let request =
        arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidenceQueryRequestBody {
            request_id: arkret_wire::RequestId::new(
                "ak:request:019b0000-0000-7000-8000-000000000225",
            )
            .unwrap(),
            realm_id: arkret_wire::RealmId::new(disclosure_realm).unwrap(),
            operation_id: arkret_wire::ServiceOperationId::SelfSignalCommandSendV1,
            request_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                b"cold Agent Signal envelope",
            ))
            .unwrap(),
            recipient_account_id: controller_authority.clone(),
            challenge: arkret_wire::NonEmptyString::new(format!(
                "ak.challenge:{}",
                "A".repeat(32)
            ))
            .unwrap(),
            queries: vec![
                arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidenceSelector::Agent {
                    actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        outcome.agent_id.clone(),
                        service_core.clone(),
                    )),
                    verification_method: verification_method.clone(),
                },
            ],
        };
    let expected_observation_operation = request.agent_observation_operation_id().unwrap();
    let mut evidence_response =
        TestClient::post("http://server/_arkret/self/current-signer-evidence/query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::SELF_CURRENT_SIGNER_EVIDENCE_READ_RESOLVE_V1,
                true,
            )
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&request).unwrap())
            .send(&app)
            .await;
    let evidence_status = evidence_response.status_code;
    let evidence_body = evidence_response.take_string().await.unwrap();
    assert_eq!(evidence_status, Some(StatusCode::OK), "{evidence_body}");
    let outcome = serde_json::from_str::<
        arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidenceQueryOutcome,
    >(&evidence_body)
    .unwrap();
    outcome
        .validate_for_request(&request, chrono::Utc::now())
        .unwrap();
    arkret_signatures::current_signer_evidence::verify_current_signer_evidence_outcome(
        &outcome,
        &state.notary_signing_key().verifying_key(),
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(outcome.response.issuer_id, service_core);
    assert_eq!(outcome.response.verifier_id, state.service_core_id());
    let arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidenceItem::Agent {
        actor,
        verification_method: returned_method,
        authenticated_signer_evidence,
        dependencies,
    } = outcome
        .response
        .evidences
        .first()
        .expect("origin authority omitted current Agent evidence")
    else {
        panic!("origin authority returned the wrong current signer branch")
    };
    assert_eq!(returned_method, &verification_method);
    assert!(!dependencies.is_empty());
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        agent_signer_evidence,
        ..
    } = authenticated_signer_evidence
    else {
        panic!("current Agent item did not contain an authenticated Agent root")
    };
    assert_eq!(signer_id, actor.signing_principal_id());
    let arkret_models_identity::agent_signer_evidence::AgentSignerEvidence::CurrentAdmission {
        admission_evidence,
        current_observation,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        panic!("Signal current evidence unexpectedly contained historical Agent evidence")
    };
    assert_eq!(
        admission_evidence
            .agent_authority_state_evidence
            .state
            .authorization
            .status,
        arkret_models_identity::agent_signer_evidence::AgentAuthorizationStatus::Active
    );
    assert_eq!(
        current_observation.operation_id,
        expected_observation_operation
    );
    assert_eq!(current_observation.request_digest, request.request_digest);
    assert_eq!(current_observation.verifier_id, state.service_core_id());
    assert_eq!(
        current_observation.audience_id,
        controller_authority.principal_id
    );
    assert_eq!(current_observation.challenge, request.challenge);

    let mut wrong_request = request.clone();
    wrong_request.challenge =
        arkret_wire::NonEmptyString::new(format!("ak.challenge:{}", "B".repeat(32))).unwrap();
    assert!(
        outcome
            .validate_for_request(&wrong_request, chrono::Utc::now())
            .is_err(),
        "current Agent evidence must not replay under a different request challenge"
    );
    assert!(
        outcome
            .validate_for_request(&request, outcome.response.expires_at)
            .is_err(),
        "expired current Agent evidence must fail closed"
    );
}

async fn verify_owned_agent_direct_founding(
    state: &AppState,
    token: &str,
    controller: &str,
    resolve_request: &arkret_models_collaboration::direct_conversation_ops::DirectConversationResolveRequestBody,
    evidence: Value,
) {
    use arkret_models_collaboration::direct_conversation_ops::*;
    use arkret_models_collaboration::objects::direct_conversation::*;
    use soland_test_support::signed_event::{
        CallerSignedBasis, CallerSignedEvent, head_eq_precondition, sign_fixture_event,
    };
    let app = app_from_state(state.clone());
    let founder =
        arkret_wire::AccountId::new(fixture_actor_core_id(controller), state.service_core_id());
    let peer = resolve_request.peer.contact_actor_id();
    let created_at = chrono::Utc::now();
    let create_payload = direct_conversation_realm_create_payload(
        arkret_wire::GenesisSalt::generate().unwrap(),
        state.config().trust_domain.clone(),
        arkret_wire::NotaryValue::single_signer(state.service_notary_signer_descriptor().unwrap()),
        created_at,
    )
    .unwrap();
    let sign = |mut event: arkret_wire::Event| {
        event.proofs.clear();
        sign_fixture_event(
            event,
            controller,
            super::agents::CONTROLLER_DEVICE_ID,
            super::agents::CONTROLLER_DEVICE_SIGNING_SEED,
        )
    };
    let create = sign(
        CallerSignedEvent::realm_genesis(
            controller,
            super::agents::CONTROLLER_DEVICE_ID,
            serde_json::to_value(create_payload).unwrap(),
        )
        .with_preconditions(vec![head_eq_precondition(
            &arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_CREATE_V1),
            Value::Null,
        )])
        .build(),
    );
    let realm_id = arkret_wire::RealmId::from_event_id(&create.event_id);
    let peer_account = peer.as_account_id().unwrap();
    let payloads = [
        (
            "ak.member.state",
            serde_json::to_value(
                direct_conversation_peer_membership_bootstrap(
                    realm_id.clone(),
                    &founder,
                    [founder.clone(), peer_account.clone()],
                )
                .unwrap(),
            )
            .unwrap(),
            Some(peer.clone()),
        ),
        (
            "ak.strand.create",
            serde_json::to_value(direct_conversation_main_strand_create_payload(
                realm_id.clone(),
                arkret_wire::ActorId::account(founder.clone()),
                created_at,
            ))
            .unwrap(),
            None,
        ),
        (
            "ak.member.state",
            serde_json::to_value(direct_conversation_member_join_payload(
                realm_id.clone(),
                founder.clone(),
            ))
            .unwrap(),
            Some(arkret_wire::ActorId::account(founder)),
        ),
    ];
    let mut events = vec![create];
    for (index, (kind, payload, member)) in payloads.into_iter().enumerate() {
        let previous = events.last().unwrap().event_id.to_string();
        let mut builder = CallerSignedEvent::new(
            kind,
            controller,
            super::agents::CONTROLLER_DEVICE_ID,
            realm_id.as_str(),
            payload,
        )
        .with_actor_seq((index + 1) as u64)
        .with_prev_refs(vec![&previous])
        .with_basis(CallerSignedBasis::AnchorUnit);
        if let Some(member) = member {
            builder = builder.with_preconditions(vec![head_eq_precondition(
                &format!(
                    "ak:cell:ak.component.member.state.v1:{}",
                    arkret_wire::composite_subject(&[member.canonical_key().unwrap()]).unwrap()
                ),
                Value::Null,
            )]);
        }
        events.push(sign(builder.build()));
    }
    let submission = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: arkret_wire::IdempotencyKey::new(uuid::Uuid::now_v7().to_string())
            .unwrap(),
        events: events
            .into_iter()
            .map(arkret_wire::EventInitialSubmission::online)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        founding_authority_evidence: serde_json::from_value(evidence).unwrap(),
        cbs_proof_bundles: Vec::new(),
    };
    let mut accepted = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&submission).unwrap())
        .send(&app)
        .await;
    let status = accepted.status_code;
    let body: Value = accepted.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    let mut resolved = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(resolve_request).unwrap())
        .send(&app)
        .await;
    let outcome: DirectConversationResolveOutcome = resolved.take_json().await.unwrap();
    assert_eq!(
        outcome
            .coordinates()
            .expect("accepted founding must be openable")
            .realm_id,
        realm_id
    );
}
