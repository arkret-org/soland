//! Integration tests — `events` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

/// Wrap raw Event envelopes into the `events[]` element shape
/// `/_arkret/self/events` accepts: one `EventInitialSubmission` per Event, each
/// carrying its own (here absent) authorization lease outside the signed
/// envelope. The envelopes stay `Value` because these fixtures deliberately
/// mutate and re-sign them before submission.
fn initial_submissions(events: impl IntoIterator<Item = Value>) -> Vec<Value> {
    events
        .into_iter()
        .map(|event| serde_json::json!({"event": event}))
        .collect()
}

/// The cells a v1 receiver derives for this Event envelope.
///
/// v1 deleted the producer `effects[]` array, so a fixture may not restate the
/// writes it expects: it has to go through the same
/// `arkret_schema::project_registered_cell_writes` contract evaluator the server
/// runs (`models/event-and-patch.md` §2.4.2). Mirrors the in-repo reducer test
/// helper `crates/domain/src/reducer/tests/mod.rs::projected_cell_writes`, but
/// takes a wire envelope because the HTTP fixtures are JSON.
fn projected_cell_targets(envelope: &Value) -> std::collections::BTreeSet<String> {
    let event: arkret_wire::Event =
        serde_json::from_value(envelope.clone()).expect("fixture envelope is a canonical Event");
    arkret_schema::project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
        .expect("registered cell contract must be evaluable")
        .into_iter()
        .map(|write| write.cell_id.as_str().to_owned())
        .collect()
}

// ── Agent SessionGrant + DPoP fixture ────────────────────────────────────────
//
// A Agent session is only ever admitted as a typed SessionGrant
// presented together with a DPoP proof (`enforce_agent_session_authority`), so
// a locally seeded bearer SessionRecord can no longer stand in for one. The
// fixture below runs the real prepare/commit provisioning ceremony over HTTP,
// then writes the runtime-key activation through the storage port. That
// shortcut is deliberate: what these tests exercise is session-grant
// semantics, not the pairing ceremony, and skipping the controller-side
// recovery-backup and Seal steps keeps the fixture to the state the grant
// tests actually need. The full public ceremony through to runtime activation
// is covered over real HTTP by `agent_pairing_ceremony.rs`. Every binding
// digest and the controller-proof JWS are still produced by the real SDK
// functions, so the chain under test — introspection, DPoP binding, Agent
// authority enforcement, scope gate — stays fully real.

/// A presented Agent SessionGrant: the bearer JWT plus the holder (DPoP) key
/// the introspected grant's `cnf_jkt` is bound to.
pub(super) struct AgentGrantPresentation {
    pub(super) grant_jwt: String,
    pub(super) holder_key: SigningKey,
}

/// Build the `Authorization`/`DPoP` header pair for one request. `htu` is the
/// configured origin plus the bare path — the query string is excluded, exactly
/// as the server's verifier reconstructs it. The grant rides the RFC 9449
/// `DPoP` authorization scheme; `Bearer` is reserved for local dev sessions.
fn agent_grant_headers(
    state: &AppState,
    presentation: &AgentGrantPresentation,
    method: &str,
    path: &str,
) -> (String, String) {
    let htu = format!(
        "{}{}",
        state.config().public_base_url.trim_end_matches('/'),
        path
    );
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new(method, htu)
            .access_token(presentation.grant_jwt.clone()),
        &presentation.holder_key,
    )
    .expect("DPoP proof builds");
    (
        format!("DPoP {}", presentation.grant_jwt),
        proof.header_value,
    )
}

/// Read one HTTP request (headers + Content-Length body) off a mock
/// introspection connection.
async fn read_introspection_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut request = Vec::new();
    let mut header_end = None;
    let mut content_length = 0;
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.expect("read introspection");
        assert!(read > 0, "introspection request ended early");
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none()
            && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let end = index + 4;
            let headers = String::from_utf8_lossy(&request[..end]);
            content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            header_end = Some(end);
        }
        if header_end.is_some_and(|end| request.len() >= end + content_length) {
            return request;
        }
    }
}

pub(super) async fn bind_controller_gate_mock(config: &mut AppConfig) -> tokio::net::TcpListener {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("controller gate mock binds");
    let authority_address = listener.local_addr().expect("mock address");
    config.account_authority_url = Some(format!("http://{authority_address}"));
    config.account_authority_id = Some(soland_test_support::fixture_station_id().to_string());
    listener
}

pub(super) fn spawn_controller_gate_mock(listener: tokio::net::TcpListener, state: &AppState) {
    use tokio::io::AsyncWriteExt;

    let authority_id = arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap();
    let state = state.clone();
    tokio::spawn(async move {
        let (_, authority_method) = state
            .current_service_receipt_binding()
            .await
            .expect("fixture service receipt binding");
        let authority_signing_key = state.notary_signing_key();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let authority_id = authority_id.clone();
            let authority_method = authority_method.clone();
            let authority_signing_key = authority_signing_key.clone();
            tokio::spawn(async move {
                let request = read_introspection_request(&mut stream).await;
                let body_start = request
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .expect("controller gate request headers");
                let request_body = serde_json::from_slice::<
                    arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestationIssueRequestBody,
                >(&request[body_start..])
                .expect("typed controller gate request");
                let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
                let basis = arkret_models_identity::agent_signer_evidence::ControllerAccountGateBasis::AccountBindingDefault {
                    binding_version: 1,
                    binding_frontier_digest: arkret_wire::Hash::new(
                        arkret_canonical::sha256_digest(b"fixture account binding frontier"),
                    )
                    .unwrap(),
                };
                let mut gate = arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation {
                    schema: arkret_wire::NonEmptyString::new(
                        arkret_wire::SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1,
                    )
                    .unwrap(),
                    principal_id: request_body.principal_id,
                    eligibility: arkret_models_identity::agent_signer_evidence::ControllerAccountEligibility::Active,
                    status: arkret_models_identity::agent_signer_evidence::ControllerAccountStatus::Active,
                    basis,
                    basis_digest: arkret_wire::Hash::new(
                        arkret_canonical::sha256_digest(b"fixture account gate basis"),
                    )
                    .unwrap(),
                    authority_id,
                    verification_method: authority_method,
                    issued_at,
                    expires_at: issued_at + chrono::Duration::minutes(2),
                    proof: arkret_models_identity::agent_signer_evidence::AgentDetachedJws {
                        kind: arkret_wire::NonEmptyString::new("detached_jws").unwrap(),
                        jws: arkret_wire::NonEmptyString::new("pending").unwrap(),
                    },
                };
                arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
                    &mut gate,
                    authority_signing_key.as_ref(),
                )
                .expect("controller gate attestation signs");
                let response_body = serde_json::to_vec(
                    &arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestationIssueOutcome {
                        request_id: request_body.request_id,
                        controller_account_gate_attestation: gate,
                    },
                )
                .expect("serialize controller gate outcome");
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response_body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&response_body).await.unwrap();
            });
        }
    });
}

/// Provision a Agent through the real ceremony, activate its runtime
/// key through the storage port, and stand up a session-grant introspection
/// mock that vouches for a grant scoped to exactly `granted_scopes`.
pub(super) async fn seed_agent_grant_session(
    slug: &str,
    granted_scopes: &[&str],
) -> (AppState, AgentGrantPresentation) {
    use tokio::io::AsyncWriteExt;

    let mut config = test_config();
    let listener = bind_controller_gate_mock(&mut config).await;
    let authority_address = listener.local_addr().expect("mock address");
    config.session_grant_introspection_url = Some(format!(
        "http://{}/_arkret/admin/session-grants/introspect",
        authority_address
    ));
    config.session_grant_introspection_bearer = Some(format!("introspection-bearer-{slug}"));
    let state = soland_test_support::app_state(config);

    let controller = "did:web:alice.example";
    let controller_token = format!("agent-grant-controller-{slug}");
    super::agents::seed_controller_session(&state, &controller_token, controller).await;
    let controller_account_id =
        arkret_wire::AccountId::new(fixture_actor_core_id(controller), state.service_core_id());
    let controller_account = state
        .test_persistence()
        .accounts()
        .get(&controller_account_id)
        .await
        .unwrap()
        .expect("the controller session is bound to this exact Station Account");
    assert_eq!(
        controller_account.principal_id,
        controller_account_id.principal_id
    );
    assert_eq!(
        controller_account.station_id,
        controller_account_id.station_id
    );
    super::agents::seed_agent_provision_prerequisites(&state, controller).await;
    let controller_authority =
        super::agents::seed_active_controller_device_generation(&state, controller).await;
    let (status, body) = super::agents::provision_agent_with_sdk_events(
        &state,
        &controller_token,
        controller,
        &controller_authority,
        slug,
        serde_json::json!({
            "actions": [
                "ak.self.events.stream.subscribe.v1",
                "ak.self.events.read.scan.v1",
                "ak.self.events.command.submit.v1"
            ],
            "resources": [
                {"kind": "operation", "operation": "ak.self.events.stream.subscribe.v1"},
                {"kind": "operation", "operation": "ak.self.events.read.scan.v1"},
                {"kind": "operation", "operation": "ak.self.events.command.submit.v1"}
            ],
            "constraints": []
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Agent provisioning failed: {body}"
    );
    let provisioned = serde_json::from_value::<
        arkret_models_collaboration::agent_operations::AgentProvisionOutcome,
    >(body)
    .expect("typed provision outcome");
    let arkret_models_collaboration::agent_operations::AgentProvisionOutcome::Complete { outcome } =
        provisioned
    else {
        panic!("Agent provisioning must complete");
    };
    let record = state
        .test_persistence()
        .agents()
        .get(outcome.agent_id.as_str())
        .await
        .unwrap()
        .expect("provisioned Agent record");
    assert_eq!(
        record.state,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    let pairing_code = outcome
        .pairing_code
        .clone()
        .expect("development provisioning returns the pairing code");

    // Runtime-key request material, exactly as the runtime would build it from
    // the pairing bootstrap (SDK builder, real proof of possession).
    let runtime_seed: [u8; 32] =
        Sha256::digest(format!("agent-runtime-key-{slug}").as_bytes()).into();
    let runtime_key = SigningKey::from_bytes(&runtime_seed);
    let endpoint_device_id =
        arkret_identifiers::DeviceId::new(new_prefixed_uuid7("ak:device:")).unwrap();
    let request = arkret_signatures::agent::RuntimeKeyRequestBuilder::new(
        &runtime_key,
        arkret_models_collaboration::agent_operations::AgentPairingBootstrap {
            arkret_base_url: "http://server".to_owned(),
            service_id: arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap(),
            agent_id: outcome.agent_id.clone(),
            pairing_request_id: outcome.pairing_request_id.clone(),
            pairing_code: pairing_code.clone(),
            pairing_expires_at: outcome.expires_at,
        },
        &outcome.did,
        endpoint_device_id.clone(),
    )
    .build_approval_request()
    .expect("runtime key approval request builds");
    let verification_method = request.body.verification_method.clone();
    let attestation_digest =
        arkret_signatures::agent::agent_runtime_attestation_digest(None).unwrap();
    let binding_digest = arkret_signatures::agent::agent_runtime_key_binding_digest_from_digests(
        &outcome.agent_id,
        outcome.pairing_request_id.as_str(),
        verification_method.as_str(),
        &request.runtime_request_public_key_digest,
        &attestation_digest,
    )
    .unwrap();
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();

    // 1/3 — the runtime's approval request, as `submit_agent_runtime_key_request`
    // would persist it.
    let approval = soland_storage::AgentRuntimeApprovalWrite {
        agent_id: outcome.agent_id.to_string(),
        pairing_request_id: outcome.pairing_request_id.clone(),
        approval_request_id: arkret_wire::OpaqueLocalId::new(format!(
            "agent_runtime_approval:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        approval_notification_id: new_prefixed_uuid7("ak:notification:"),
        approval_requested_at: now,
        controller_account_pk: controller_account.pk,
        recipient_id: state.service_id().clone(),
        runtime_key_binding_digest: binding_digest.as_str().to_owned(),
        runtime_public_key_digest: request
            .runtime_request_public_key_digest
            .as_str()
            .to_owned(),
        runtime_attestation_digest: attestation_digest.as_str().to_owned(),
        runtime_key_request:
            arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
                pairing_request_id: request.body.pairing_request_id.clone(),
                agent_id: request.body.agent_id.clone(),
                verification_method: verification_method.clone(),
                public_key: request.body.public_key.clone(),
                proof_of_possession: request.body.proof_of_possession.clone(),
                runtime_attestation: request.body.runtime_attestation.clone(),
            },
    };
    assert!(
        state
            .test_persistence()
            .agents()
            .put_runtime_approval_if_compatible(&approval)
            .await
            .unwrap()
            .is_some(),
        "runtime approval write must be compatible with the provisioned record"
    );

    // 2/3 — the controller's signing-key binding, with a real detached JWS over
    // the exact transcript the pairing endpoint would verify.
    let controller_core = fixture_actor_core_id(controller);
    let public_key = arkret_models_identity::agent_signer_evidence::AgentSigningPublicKey {
        kty: arkret_wire::NonEmptyString::new("OKP").unwrap(),
        algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
        key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            runtime_key.verifying_key().to_bytes(),
        ))
        .unwrap(),
    };
    let public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&public_key).unwrap();
    let agent_key_id = arkret_wire::NonEmptyString::new("agent-runtime-key").unwrap();
    let binding_core = arkret_signatures::agent_evidence::prepare_agent_signing_key_binding_core(
        outcome.agent_id.clone(),
        agent_key_id.clone(),
        verification_method.clone(),
        &request.body.public_key,
        now,
        None,
        controller_core.clone(),
    )
    .expect("signing key binding core builds");
    let signing_key_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_core_digest(&binding_core)
            .expect("signing key binding core digest");
    let paired_request_digest =
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            &controller_core,
            &outcome.agent_id,
            &outcome.pairing_request_id,
            &pairing_code,
            outcome.expires_at,
            &arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap(),
            &binding_digest,
            &request.body.proof_of_possession,
        )
        .unwrap();
    let authorize_payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload {
            agent_id: outcome.agent_id.clone(),
            key_id: agent_key_id,
            verification_method: verification_method.clone(),
            public_key_digest: public_key_digest.clone(),
            signing_key_binding_digest,
            accountable_principal_id: controller_core.clone(),
            agent_key_scope: serde_json::from_value(serde_json::json!({
                "actions": [
                    "ak.self.events.stream.subscribe.v1",
                    "ak.self.events.read.scan.v1",
                    "ak.self.events.command.submit.v1"
                ],
                "resources": [
                    {"kind": "operation", "operation": "ak.self.events.stream.subscribe.v1"},
                    {"kind": "operation", "operation": "ak.self.events.read.scan.v1"},
                    {"kind": "operation", "operation": "ak.self.events.command.submit.v1"}
                ],
                "constraints": []
            }))
            .unwrap(),
            audience: vec![state.service_id().clone()],
            issued_at: now,
            expires_at: None,
            approval_evidence:
                arkret_models_collaboration::events_payloads::agent::AgentKeyApprovalEvidence {
                    kind: arkret_models_collaboration::events_payloads::agent::AgentKeyApprovalEvidenceKind::PairingRequest,
                    evidence_ref: None,
                    request_canonical_digest: Some(
                        arkret_identifiers::Hash::new(paired_request_digest.as_str().to_owned())
                            .unwrap(),
                    ),
                    pairing_request_id: Some(outcome.pairing_request_id.clone()),
                    approved_by: Some(controller_core.clone()),
                },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };
    let agent_pcr_realm =
        arkret_wire::RealmId::new(record.principal_control_realm_id.clone()).unwrap();
    let genesis_record = state
        .test_persistence()
        .events()
        .realm_events_newest_first(agent_pcr_realm.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .expect("accepted Agent PCR genesis Event");
    let genesis_event = serde_json::from_value::<arkret_wire::Event>(genesis_record.envelope)
        .expect("typed Agent PCR genesis Event");
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
    let controller_verification_method = arkret_wire::DidUrl::new(format!(
        "{controller}#{}",
        super::agents::CONTROLLER_DEVICE_ID
    ))
    .unwrap();
    let controller_signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED),
        arkret_wire::Did::new(controller.to_owned()).unwrap(),
        controller_verification_method.clone(),
    );
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let mut authorize_event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr_realm.clone(),
        },
        outcome.agent_id.clone(),
        soland_test_support::fixture_station_id(),
        1,
        arkret_wire::Hlc::new(format!("{timestamp_hex}-0007-a13f9c2e")).unwrap(),
        serde_json::to_value(&authorize_payload).unwrap(),
        now,
    )
    .unwrap();
    authorize_event.prev_refs = vec![genesis_event.event_id.clone()];
    authorize_event.executed_by = Some(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        controller_core.clone(),
        state.service_core_id(),
    )));
    authorize_event.authorization_ref = Some(record.controller_authorization_ref.clone().into());
    authorize_event.seal_basis = Some(genesis_seal.seal_basis());
    authorize_event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let mut authorize_event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        authorize_event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("authorize Event finalizes");
    arkret_signatures::sign_event(
        &mut authorize_event,
        &controller_signer,
        &controller_verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let authorize_event = authorize_event.into_event();
    let agent_pcr_authority = arkret_bootstrap::AgentPcrGenesisAuthority::from_accepted_create(
        &genesis_event,
        &super::agents::genesis_projector,
    )
    .unwrap();
    let proposal_member = arkret_wire::ControlProposalAuthorityAck::issue_with_signer(
        agent_pcr_realm.clone(),
        arkret_wire::Hash::new(
            authorize_event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
        agent_pcr_authority.authority_set_ref().clone(),
        now,
        arkret_wire::ControlProposalDecisionPolicy::default(),
        &controller_signer,
    )
    .unwrap();
    let proposal_ack =
        arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![proposal_member])
            .unwrap();
    let authorize_event_id = authorize_event.event_id.clone();
    let binding_to_sign = arkret_signatures::agent_evidence::materialize_agent_signing_key_binding(
        binding_core,
        authorize_event_id.clone(),
        controller_verification_method,
    )
    .expect("signing key binding materializes");
    let controller_proof_bytes =
        arkret_signatures::agent_evidence::agent_signing_key_binding_to_sign_bytes(
            &binding_to_sign,
        )
        .unwrap();
    let controller_jws = arkret_signatures::jws::sign_jws_ed25519(
        &controller_proof_bytes,
        &SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED),
    )
    .expect("controller proof JWS signs");
    let signing_key_binding = arkret_signatures::agent_evidence::finish_agent_signing_key_binding(
        binding_to_sign,
        &controller_jws,
    )
    .expect("signing key binding finishes");
    let intent = soland_storage::AgentPairingCommitIntent {
        agent_id: outcome.agent_id.to_string(),
        approval_request_id: approval.approval_request_id.clone(),
        runtime_key_binding_digest: binding_digest.as_str().to_owned(),
        pairing_request_id: outcome.pairing_request_id.clone(),
        request_digest: paired_request_digest.as_str().to_owned(),
        authorize_event_id: authorize_event_id.as_str().to_owned(),
        signing_key_binding: signing_key_binding.clone(),
    };
    assert!(
        state
            .test_persistence()
            .agents()
            .put_pairing_commit_intent_if_compatible(&intent)
            .await
            .unwrap()
            .is_some(),
        "pairing commit intent must be accepted"
    );

    // 3/3 — activation, mirroring the reconciliation the pairing endpoint
    // performs once the authorize Event is accepted.
    let activation = soland_storage::AgentRuntimeActivation {
        agent_id: outcome.agent_id.to_string(),
        approval_request_id: approval.approval_request_id.clone(),
        runtime_key_binding_digest: binding_digest.as_str().to_owned(),
        pairing_request_id: outcome.pairing_request_id.clone(),
        paired_request_digest: paired_request_digest.as_str().to_owned(),
        authorized_event_ref: authorize_event_id.as_str().to_owned(),
        authorized_verification_method: verification_method.as_str().to_owned(),
        authorized_public_key_digest: public_key_digest.as_str().to_owned(),
        authorized_signing_key_binding: signing_key_binding,
        authorized_at: now,
    };
    assert!(
        state
            .test_persistence()
            .agents()
            .activate_runtime_if_current(&activation)
            .await
            .unwrap(),
        "runtime activation must match the pending intent"
    );
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &authorize_event,
            Some(record.principal_control_realm_id.as_str()),
            now,
        ))
        .await
        .unwrap();
    state
        .test_put_pending_control_event_with_ack(
            &authorize_event,
            &proposal_ack,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

    // Freeze the accepted authorization into the successor Agent-PCR Seal.
    // Current signer evidence is intentionally unavailable until both the
    // key authorization and lifecycle cells have portable Seal witnesses.
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
    let app = app_from_state(state.clone());
    let mut availability_response =
        TestClient::post("http://server/_arkret/self/seals/availability-receipts")
            .add_header("authorization", format!("Bearer {controller_token}"), true)
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
        arkret_wire::Hlc::new(format!("{timestamp_hex}-0009-a13f9c2e")).unwrap(),
        &controller_signer,
        &super::agents::genesis_projector,
    )
    .expect("successor Agent PCR Seal builds");
    let mut seal_response = TestClient::post("http://server/_arkret/self/seals")
        .add_header("authorization", format!("Bearer {controller_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&successor_seal).unwrap())
        .send(&app)
        .await;
    let seal_status = seal_response.status_code;
    let seal_body = seal_response.take_string().await.unwrap_or_default();
    assert_eq!(seal_status, Some(StatusCode::OK), "{seal_body}");

    let effective = state
        .test_effective_state_at(std::slice::from_ref(&successor_seal.id), &agent_pcr_realm)
        .unwrap();
    let key_cell = arkret_wire::CellRef::new(
        arkret_signatures::agent_evidence::agent_authorization_cell_ref(
            &outcome.agent_id,
            &arkret_wire::NonEmptyString::new("agent-runtime-key").unwrap(),
        )
        .unwrap()
        .as_str()
        .to_owned(),
    )
    .unwrap();
    let lifecycle_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        outcome.agent_id.clone(),
        state.service_core_id(),
    ));
    let lifecycle_actor_key = lifecycle_actor.canonical_key().unwrap();
    let lifecycle_subject =
        arkret_wire::composite_subject(&[lifecycle_actor_key.as_str()]).unwrap();
    let lifecycle_cell = arkret_wire::CellRef::new(format!(
        "ak:cell:{}:{lifecycle_subject}",
        arkret_models_identity::agent_signer_evidence::AGENT_STATUS_COMPONENT
    ))
    .unwrap();
    assert!(
        effective.contains_key(&key_cell),
        "missing Agent key witness cell"
    );
    assert!(
        effective.contains_key(&lifecycle_cell),
        "missing Agent lifecycle witness cell"
    );

    state
        .test_projection()
        .lock()
        .agent_authorized_keys
        .entry(outcome.agent_id.to_string())
        .or_default()
        .insert(
            "agent-runtime-key".to_owned(),
            authorize_event_id.to_string(),
        );
    assert_eq!(
        state
            .test_persistence()
            .agents()
            .get(outcome.agent_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .controller_account_pk,
        Some(controller_account.pk),
        "runtime approval must not substitute a demo Account at another Station",
    );

    // The Account Authority introspection mock: vouches for a SessionGrant
    // bound to the runtime key (`cnf.jkt`) and scoped to `granted_scopes`.
    let holder_jwk =
        arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&runtime_key.verifying_key());
    let cnf_jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&holder_jwk).unwrap();
    let session_public_key = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        arkret_canonical::base64url_encode(runtime_key.verifying_key().to_bytes())
    );
    let grant_jwt = {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"Ed25519","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "kind": arkret_models_identity::SESSION_GRANT_CREDENTIAL_KIND,
                "jti": format!("urn:uuid:{}", uuid::Uuid::now_v7()),
            })
            .to_string(),
        );
        let signature = runtime_key.sign(format!("{header}.{payload}").as_bytes());
        format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    };
    let outcome_json = serde_json::json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": {
            "id": arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(format!("agent-session-grant-{slug}").as_bytes()).into(),
            )
            .as_str(),
            "issuer_id": "ak:did_core:web:coauth.local",
            "account_id": {
                "principal_id": outcome.agent_id.as_str(),
                "station_id": state.service_id()
            },
            "audience_id": state.service_id(),
            "scopes": granted_scopes,
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(5))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "revocation_ref": format!("ak:session:{}", uuid::Uuid::now_v7().simple()),
            "session_public_key": session_public_key,
            "cnf_jkt": cnf_jkt,
            "credential_class": "standard",
            "holder_binding": {
                "kind": "agent_runtime",
                "agent_id": outcome.agent_id.as_str(),
                "device_id": endpoint_device_id.as_str(),
                "agent_key_authorization_ref": authorize_event_id.as_str(),
                "verification_method": verification_method.as_str(),
            }
        }
    });
    serde_json::from_value::<
        arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectOutcome,
    >(outcome_json.clone())
    .expect("mock outcome matches the SDK introspection DTO");
    let response_body = serde_json::to_vec(&outcome_json).expect("serialize introspection");
    let authority_id = arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap();
    let (_, authority_method) = state
        .current_service_receipt_binding()
        .await
        .expect("fixture service receipt binding");
    let authority_signing_key = state.notary_signing_key();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let response_body = response_body.clone();
            let authority_id = authority_id.clone();
            let authority_method = authority_method.clone();
            let authority_signing_key = authority_signing_key.clone();
            tokio::spawn(async move {
                let request = read_introspection_request(&mut stream).await;
                let response_body = if request
                    .starts_with(b"POST /_arkret/gate/account/controller-gate-attestations ")
                {
                    let body_start = request
                        .windows(4)
                        .position(|part| part == b"\r\n\r\n")
                        .map(|index| index + 4)
                        .expect("controller gate request headers");
                    let request_body = serde_json::from_slice::<
                        arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestationIssueRequestBody,
                    >(&request[body_start..])
                    .expect("typed controller gate request");
                    let issued_at =
                        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
                    let basis = arkret_models_identity::agent_signer_evidence::ControllerAccountGateBasis::AccountBindingDefault {
                        binding_version: 1,
                        binding_frontier_digest: arkret_wire::Hash::new(
                            arkret_canonical::sha256_digest(b"fixture account binding frontier"),
                        )
                        .unwrap(),
                    };
                    let mut gate = arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation {
                        schema: arkret_wire::NonEmptyString::new(
                            arkret_wire::SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1,
                        )
                        .unwrap(),
                        principal_id: request_body.principal_id,
                        eligibility: arkret_models_identity::agent_signer_evidence::ControllerAccountEligibility::Active,
                        status: arkret_models_identity::agent_signer_evidence::ControllerAccountStatus::Active,
                        basis,
                        basis_digest: arkret_wire::Hash::new(
                            arkret_canonical::sha256_digest(b"fixture account gate basis"),
                        )
                        .unwrap(),
                        authority_id,
                        verification_method: authority_method,
                        issued_at,
                        expires_at: issued_at + chrono::Duration::minutes(2),
                        proof: arkret_models_identity::agent_signer_evidence::AgentDetachedJws {
                            kind: arkret_wire::NonEmptyString::new("detached_jws").unwrap(),
                            jws: arkret_wire::NonEmptyString::new("pending").unwrap(),
                        },
                    };
                    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
                        &mut gate,
                        authority_signing_key.as_ref(),
                    )
                    .expect("controller gate attestation signs");
                    serde_json::to_vec(
                        &arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestationIssueOutcome {
                            request_id: request_body.request_id,
                            controller_account_gate_attestation: gate,
                        },
                    )
                    .expect("serialize controller gate outcome")
                } else {
                    response_body
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response_body.len()
                );
                stream
                    .write_all(headers.as_bytes())
                    .await
                    .expect("write introspection headers");
                stream
                    .write_all(&response_body)
                    .await
                    .expect("write introspection body");
            });
        }
    });

    (
        state,
        AgentGrantPresentation {
            grant_jwt,
            holder_key: runtime_key,
        },
    )
}

fn assert_agent_scope_denied(body: &Value, scope: &str) {
    assert_eq!(problem_code(body), "capability_denied", "{body}");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|message| message.contains(scope)),
        "{body}"
    );
}

async fn optional_pg_app_state() -> Option<AppState> {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .as_ref()?;
    let db = Db::connect(
        std::env::var("DATABASE_URL").ok().as_deref(),
        Default::default(),
    )
    .await
    .expect("postgres migrations should run");
    let state = app_state_for_postgres(test_config(), db);
    state.hydrate().await.expect("postgres state hydrates");
    Some(state)
}

async fn account_subscribe_first_frame_with_status(
    state: AppState,
    token: Option<&str>,
    query: &str,
) -> (StatusCode, Value) {
    let url = if query.is_empty() {
        "http://server/_arkret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_arkret/self/account/subscribe?{query}")
    };
    let mut request = TestClient::get(url);
    if let Some(token) = token {
        request = request.add_header("authorization", format!("Bearer {token}"), true);
    }
    let mut response = request.send(&app_from_state(state)).await;
    let status = response.status_code.expect("response status");
    let body = take_first_response_chunk(&mut response).await;
    let first = body.lines().next().unwrap_or(body.as_str());
    let frame = serde_json::from_str(first).unwrap_or_else(|error| {
        panic!("account subscribe returned non-json frame: {error}: {body}")
    });
    (status, frame)
}

#[test]
fn agent_session_without_stream_scope_cannot_subscribe_events() {
    run_on_deep_stack(
        "agent_session_without_stream_scope_cannot_subscribe_events",
        agent_session_without_stream_scope_cannot_subscribe_events_body,
    );
}

async fn agent_session_without_stream_scope_cannot_subscribe_events_body() {
    let (state, presentation) =
        seed_agent_grant_session("scope-denied-stream", &["ak.self.events.read.scan.v1"]).await;
    let subscribe_url = format!(
        "http://server/_arkret/self/events/subscribe?realm_ids={}&catchup=false&max_duration_ms=100",
        demo_realm_id()
    );

    // A SessionGrant presented without its DPoP proof is not authenticated at
    // all, which keeps the 403 below attributable to the missing scope alone.
    let unauthenticated = TestClient::get(subscribe_url.clone())
        .add_header(
            "authorization",
            format!("Bearer {}", presentation.grant_jwt),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let (authorization, dpop) = agent_grant_headers(
        &state,
        &presentation,
        "GET",
        "/_arkret/self/events/subscribe",
    );
    let mut response = TestClient::get(subscribe_url)
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state))
        .await;

    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "response body: {body}");
    assert_agent_scope_denied(&body, "ak.self.events.stream.subscribe.v1");
}

#[test]
fn agent_session_without_query_scope_cannot_scan_events() {
    run_on_deep_stack(
        "agent_session_without_query_scope_cannot_scan_events",
        agent_session_without_query_scope_cannot_scan_events_body,
    );
}

async fn agent_session_without_query_scope_cannot_scan_events_body() {
    let (state, presentation) = seed_agent_grant_session(
        "scope-denied-query",
        &["ak.self.events.stream.subscribe.v1"],
    )
    .await;

    // Same 401 discriminator as the subscribe test: grant without DPoP.
    let unauthenticated = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realm_ids": [demo_realm_id()]}))
        .add_header(
            "authorization",
            format!("Bearer {}", presentation.grant_jwt),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let (authorization, dpop) =
        agent_grant_headers(&state, &presentation, "QUERY", "/_arkret/self/events");
    let mut response = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realm_ids": [demo_realm_id()]}))
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state))
        .await;

    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "response body: {body}");
    assert_agent_scope_denied(&body, "ak.self.events.read.scan.v1");
}

#[test]
fn agent_session_without_submit_scope_cannot_submit_events() {
    run_on_deep_stack(
        "agent_session_without_submit_scope_cannot_submit_events",
        agent_session_without_submit_scope_cannot_submit_events_body,
    );
}

async fn agent_session_without_submit_scope_cannot_submit_events_body() {
    let (state, presentation) =
        seed_agent_grant_session("scope-denied-submit", &["ak.self.events.read.scan.v1"]).await;
    let event = signed_event_envelope(
        "ak:event:AfepkcDJ52VnnpuZZLL_gaOAp8uRP2_whpmBukWi9roZ",
        0,
        Vec::new(),
    );

    // Same 401 discriminator as the subscribe test: grant without DPoP.
    let unauthenticated = TestClient::post("http://server/_arkret/self/events")
        .add_header(
            "authorization",
            format!("Bearer {}", presentation.grant_jwt),
            true,
        )
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let (authorization, dpop) =
        agent_grant_headers(&state, &presentation, "POST", "/_arkret/self/events");
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .json(&event)
        .send(&app_from_state(state))
        .await;

    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "response body: {body}");
    assert_agent_scope_denied(&body, "ak.self.events.command.submit.v1");
}

#[test]
fn pg_account_subscribe_cursor_handle_survives_app_state_rebuild() {
    run_on_deep_stack(
        "pg_account_subscribe_cursor_handle_survives_app_state_rebuild",
        pg_account_subscribe_cursor_handle_survives_app_state_rebuild_body,
    );
}

async fn pg_account_subscribe_cursor_handle_survives_app_state_rebuild_body() {
    let Some(first_state) = optional_pg_app_state().await else {
        return;
    };
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let actor = format!("did:web:pg-cursor-{suffix}.example");
    let device = new_prefixed_uuid7("ak:device:");
    let token =
        dev_token_for_device(first_state.clone(), &actor, &device, "Pg Cursor Restart").await;

    let baseline = account_subscribe_frame(first_state.clone(), Some(&token), "catchup=true").await;
    let cursor = baseline["cursor"]
        .as_str()
        .expect("baseline cursor")
        .to_owned();
    assert!(cursor.starts_with("ak:cursor:"));

    let Some(restarted_state) = optional_pg_app_state().await else {
        return;
    };
    let (status, resumed) = account_subscribe_first_frame_with_status(
        restarted_state,
        Some(&token),
        &format!("catchup=true&after={cursor}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "resume response: {resumed}");
    assert_eq!(resumed["kind"], "delta");
    assert!(
        resumed.get("error").is_none(),
        "pg restart resume must not fail cursor integrity: {resumed}"
    );
}

#[test]
fn memory_account_subscribe_cursor_handle_does_not_survive_app_state_rebuild() {
    run_on_deep_stack(
        "memory_account_subscribe_cursor_handle_does_not_survive_app_state_rebuild",
        memory_account_subscribe_cursor_handle_does_not_survive_app_state_rebuild_body,
    );
}

async fn memory_account_subscribe_cursor_handle_does_not_survive_app_state_rebuild_body() {
    let first_state = soland_test_support::app_state(test_config());
    let actor = "did:web:memory-cursor-restart.example";
    let device = "ak:device:01904100-0000-7000-8000-0badc0ffee01";
    let first_token =
        dev_token_for_device(first_state.clone(), actor, device, "Memory Cursor Restart").await;
    let baseline = account_subscribe_frame(first_state, Some(&first_token), "catchup=true").await;
    let cursor = baseline["cursor"]
        .as_str()
        .expect("baseline cursor")
        .to_owned();
    assert!(cursor.starts_with("ak:cursor:"));

    let restarted_state = soland_test_support::app_state(test_config());
    let restarted_token = dev_token_for_device(
        restarted_state.clone(),
        actor,
        device,
        "Memory Cursor Restart",
    )
    .await;
    let (status, rejected) = account_subscribe_first_frame_with_status(
        restarted_state,
        Some(&restarted_token),
        &format!("catchup=true&after={cursor}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "memory resume: {rejected}");
    assert_eq!(problem_code(&rejected), "cursor_integrity_invalid");
}

#[test]
fn events_describe_and_single_event_submit_work() {
    run_on_deep_stack(
        "events_describe_and_single_event_submit_work",
        events_describe_and_single_event_submit_work_body,
    );
}

async fn events_describe_and_single_event_submit_work_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    authorize_test_plaintext_message_service(&state, "did:web:alice.example", demo_realm_id())
        .await;
    // `signed_event_envelope` authors a DataEvent whose `seal_ref` is the demo
    // Realm's basis Seal, so the genesis unit that Seal covers has to be
    // accepted before the submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;

    let describe: Value = TestClient::query("http://server/_arkret/self/events/describe")
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert!(advertises_operation(
        &describe,
        "ak.self.events.command.submit.v1"
    ));
    assert_eq!(describe["limits"]["max_event_bytes"], 1024 * 1024);
    assert_eq!(describe["limits"]["max_resolve"], 100);

    let mut first = signed_event_envelope(
        "ak:event:Aa-ZPxu8G6owl48UEXDhLmfA5O0aMtG3N8H7qneE9yth",
        0,
        Vec::new(),
    );
    move_event_to_actor_realm_frontier(
        &state,
        &token,
        "did:web:alice.example",
        demo_realm_id(),
        &mut first,
    )
    .await;
    let first_event_id = authored_event_id(&first).to_owned();
    let submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "single-event-atomic-commit", true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submitted["status"], "accepted", "response: {submitted}");
    assert_eq!(submitted["accepted"][0], first_event_id);
    let committed_idempotency = state
        .test_persistence()
        .idempotency_keys()
        .get(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                fixture_actor_core_id("did:web:alice.example"),
                state.service_core_id(),
            )),
            "ak.self.events.command.submit",
            "single-event-atomic-commit",
        )
        .await
        .unwrap()
        .expect("accepted event commits its idempotent response");
    assert_eq!(committed_idempotency.response_body, submitted);

    let replayed: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "single-event-atomic-commit", true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        replayed, submitted,
        "idempotency replay returns first response"
    );

    let duplicate: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["duplicate"][0], first["event_id"]);

    let fetched: Value = TestClient::get(format!(
        "http://server/_arkret/self/events/{first_event_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(fetched["event"]["event_id"], first_event_id);
    assert_eq!(
        fetched["event"]["proofs"][0]["event_digest"],
        first["proofs"][0]["event_digest"]
    );
    assert_eq!(fetched["visibility"]["realm_id"], demo_realm_id());

    let mut second = signed_event_envelope(
        "ak:event:AanwG47_5YIVZhlCrSwi8avR_TKxfhlP_D8oZhAqjlMe",
        1,
        Vec::new(),
    );
    move_event_to_actor_realm_frontier(
        &state,
        &token,
        "did:web:alice.example",
        demo_realm_id(),
        &mut second,
    )
    .await;
    let second_submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&second)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_submitted["status"], "accepted", "{second_submitted}");

    // Round 13: `ak.strand.create` now has a schema requirement (payload
    // MUST carry `object`) because it's in the canonical-kind registry;
    // prior to round 13 it passed as an opaque envelope. Use a real Strand
    // object payload so this smoke test still exercises the cross-family
    // accept path (kind/schema combo distinct from `ak.message.create`).
    let artifact_kind_payload = serde_json::json!({
        "object": {
            "schema": "ak.schema.strand.v1",
            "realm_id": demo_realm_id(),
            "metadata": { "title": "Onboarding strand" },
            "stage": "draft",
            "tracks": {
                "discussion": {
                    "is_primary": true,
                    "profile": "discussion"
                }
            },
            "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            "created_at": "2026-05-17T00:00:00.000Z"
        }
    });
    let mut artifact_kind_event = signed_canonical_event(
        "ak:event:AW6jkT6LL89S08SrMBvLzD9mXKHw1-NOg02pG7gvqCSG",
        "ak.strand.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        2,
        Vec::new(),
        artifact_kind_payload,
    );
    move_event_to_actor_realm_frontier(
        &state,
        &token,
        "did:web:alice.example",
        demo_realm_id(),
        &mut artifact_kind_event,
    )
    .await;
    let artifact_kind_event_id = authored_event_id(&artifact_kind_event).to_owned();
    let artifact_kind_submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&artifact_kind_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        artifact_kind_submitted["status"], "accepted",
        "response: {artifact_kind_submitted}"
    );

    let mut unknown_schema = signed_event_envelope(
        "ak:event:ATsZ3vasJNhrTVCtZDqkPNZOffJwkjo0lE5CcbfNfpeC",
        3,
        Vec::new(),
    );
    unknown_schema["requirements"] = serde_json::json!({
        "schema": ["ak.schema.not_registered.v1"]
    });
    resign_canonical_event(&mut unknown_schema);
    let mut unknown_schema_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&unknown_schema)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        unknown_schema_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let unknown_schema_body: Value = unknown_schema_response.take_json().await.unwrap();
    assert_eq!(problem_code(&unknown_schema_body), "unknown_schema");

    let missing_event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let batch: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": [&first_event_id, &missing_event_id]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(batch["events"].as_array().unwrap().len(), 1);
    assert_eq!(batch["missing"], serde_json::json!([missing_event_id]));

    // `max_resolve` is one budget across both Event selector kinds.
    let event_ids: Vec<String> = (0..arkret_wire::MAX_EVENT_RESOLVE)
        .map(|_| soland_test_support::fixture_content_bound_id("ak:event:"))
        .collect();
    let mut over_budget = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": event_ids,
            "event_digests": [format!("sha256:{}", "1".repeat(64))]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let over_budget_body: Value = over_budget.take_json().await.unwrap();
    assert_eq!(
        problem_code(&over_budget_body),
        "limit_exceeded",
        "response: {over_budget_body}"
    );

    // The same request without the Seal selector stays inside the budget.
    let at_budget: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"event_ids": event_ids}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        at_budget["missing"].as_array().unwrap().len(),
        arkret_wire::MAX_EVENT_RESOLVE
    );

    let listed: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({
            "actor_ids": [arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                fixture_actor_core_id("did:web:alice.example"), state.service_core_id().clone()))],
            "limit": 20
        }))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // The exact Account selector includes the complete accepted bootstrap as
    // well as the three Events authored here. It must neither drop accepted
    // founding records nor include another Station's same-principal chain.
    let listed_events = listed["events"].as_array().unwrap();
    let actor_key = fixture_account_actor(&state, "did:web:alice.example").to_string();
    let expected_ids = state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.actor_id == actor_key)
        .map(|event| event.event_id)
        .collect::<std::collections::BTreeSet<_>>();
    let listed_ids = listed_events
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(listed_ids, expected_ids, "Account event page: {listed}");
    assert!(!listed["has_more"].as_bool().unwrap_or(false));
    assert!(listed_ids.contains(&artifact_kind_event_id));

    // Actor selector → spec actor frontier `{actor_id, actor_seq, event_id}`.
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({
                "actor_id": fixture_account_actor(&state, "did:web:alice.example")
            }))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let arkret_models_collaboration::event_sync::EventsFrontierView::ActorAggregate(frontier) =
        frontier.frontier
    else {
        panic!("actor-only selector must return non-authoring aggregate");
    };
    assert_eq!(
        frontier.actor_id,
        fixture_account_actor(&state, "did:web:alice.example")
    );
    assert_eq!(frontier.frontiers.len(), 2);
    let demo_frontier = frontier
        .frontiers
        .iter()
        .find(|frontier| frontier.realm_id.as_str() == demo_realm_id())
        .expect("actor aggregate includes demo Realm frontier");
    assert_eq!(
        demo_frontier.next_actor_seq,
        artifact_kind_event["actor_seq"].as_u64().unwrap() + 1
    );
    assert_eq!(
        demo_frontier.frontier_event_ids[0].as_str(),
        artifact_kind_event_id
    );

    // Realm selector exposes only an accepted Seal. A projection-only fixture
    // has no canonical Control Event history, so it must not receive a
    // synthetic Seal.
    let projection_only_realm =
        arkret_identifiers::RealmId::from_event_id(&arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0xf1; 32],
        ));
    let mut projection_only_entry = RealmDirectoryEntry::new(
        projection_only_realm.clone(),
        "Frontier Seal View Realm",
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    projection_only_entry.members.insert(
        arkret_identifiers::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
    );
    state.test_realms().lock().upsert(projection_only_entry);
    assert_eq!(
        add_test_realm_member(
            &state,
            projection_only_realm.as_str(),
            "did:web:alice.example",
        )["ok"],
        true,
        "the projection-only Realm must have an exact Account member",
    );
    let mut seal_view_response = TestClient::query("http://server/_arkret/self/seals/frontier")
        .json(&serde_json::json!({"realm_id": projection_only_realm}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        seal_view_response.status_code,
        Some(StatusCode::NOT_FOUND),
        "a projection-only Realm must not invent an accepted Seal"
    );
    let seal_view: Value = seal_view_response.take_json().await.unwrap();
    assert_eq!(problem_code(&seal_view), "not_found");
    assert_eq!(
        seal_view["detail"],
        "realm has no accepted Seal on this deployment"
    );

    // Inaccessible realm must read as not_found (no existence leak).
    let mut hidden = TestClient::query("http://server/_arkret/self/seals/frontier")
        .json(&serde_json::json!({
            "realm_id": "ak:realm:AeqRpQIZxaoTV-G0Cl9jzAJ6wSak3GJUvizlNJRsvSFY"
        }))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(hidden.status_code.unwrap(), StatusCode::NOT_FOUND);
    let hidden_body: Value = hidden.take_json().await.unwrap();
    assert_eq!(problem_code(&hidden_body), "not_found");
}

#[test]
fn realm_create_genesis_unit_projects_five_cells_without_seal_basis() {
    run_on_deep_stack(
        "realm_create_genesis_unit_projects_five_cells_without_seal_basis",
        realm_create_genesis_unit_projects_five_cells_without_seal_basis_body,
    );
}

async fn realm_create_genesis_unit_projects_five_cells_without_seal_basis_body() {
    let state = soland_test_support::app_state(test_config());
    let actor = test_event_signer_did().to_owned();
    let actor_core = fixture_actor_core_id(&actor);
    let token = verified_dev_token_for_device(
        state.clone(),
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Realm Founder",
    )
    .await;
    let created_at = chrono::Utc::now();
    let payload = soland_test_support::cba_basis::realm_genesis_payload(
        &state,
        &actor,
        "Bootstrap effects realm",
        "ak:trust_domain:soland.local",
        created_at,
    );
    let genesis = soland_test_support::signed_event::CallerSignedEvent::realm_genesis(
        &actor,
        "01904100-0000-7000-8000-a11ce0000001",
        payload.clone(),
    )
    .build();
    let realm_id = RealmId::from_event_id(&genesis.event_id).to_string();
    let bootstrap_unit = soland_test_support::signed_event::complete_realm_bootstrap_unit(
        genesis,
        &actor,
        "01904100-0000-7000-8000-a11ce0000001",
        "Bootstrap effects realm",
    );
    let event = serde_json::to_value(&bootstrap_unit[0]).unwrap();
    // v1 carries no producer `effects[]` and no producer `preconditions` on a
    // genesis anchor: `event-auth-state-resolution.md` §5 makes the
    // `ak.realm.create` unit carry no CBA basis field at all, and
    // `event-and-patch.md` §2.4.2 makes the genesis cell writes a pure
    // function of `kind + payload`. Restate the old hand-written effect array as
    // the receiver's own projection — the identical check
    // `crates/http/.../envelope/envelope_core.rs` runs before admission.
    assert_eq!(
        projected_cell_targets(&event),
        arkret_bootstrap::expected_realm_create_cells(
            &serde_json::from_value(event.clone()).unwrap()
        ),
        "ak.realm.create must derive exactly the canonical registered genesis cells"
    );
    let profile = serde_json::to_value(&bootstrap_unit[1]).unwrap();
    let policy = serde_json::to_value(&bootstrap_unit[2]).unwrap();
    let join_rule = serde_json::to_value(&bootstrap_unit[3]).unwrap();
    let history_access = serde_json::to_value(&bootstrap_unit[4]).unwrap();
    let discovery = serde_json::to_value(&bootstrap_unit[5]).unwrap();
    assert_eq!(
        bootstrap_unit.len(),
        7,
        "ordinary founding unit has one explicit founder join"
    );
    let member_state = serde_json::to_value(&bootstrap_unit[6]).unwrap();
    let actor_key = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor_core.clone(),
        state.service_core_id(),
    ))
    .to_string();

    // The old shape of this case — a signed producer effect disagreeing with its
    // own payload — cannot exist in v1: there is no producer `effects[]` for the
    // two to disagree about. What survives is the atomicity premise, restated
    // against the rule that replaced it. `event-auth-state-resolution.md` §5
    // requires every member of the `ak.realm.create` anchor unit to carry *no*
    // CBA basis field, so a late facet that smuggles a `seal_basis` in is a
    // `plane_cross_write` and MUST reject the whole unit; the subsequent
    // byte-identical retry of the correct unit then proves neither canonical
    // history nor reducer state leaked.
    let mut malformed_member_state = member_state.clone();
    malformed_member_state["seal_basis"] =
        serde_json::to_value(test_realm_basis_seal(&realm_id, &actor).seal_basis())
            .expect("fixture seal basis serializes");
    resign_canonical_event(&mut malformed_member_state);
    let mismatch_submissions = initial_submissions([
        event.clone(),
        profile.clone(),
        policy.clone(),
        join_rule.clone(),
        history_access.clone(),
        discovery.clone(),
        malformed_member_state,
    ]);
    let mut mismatch_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"events": mismatch_submissions}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mismatch_response.status_code, Some(StatusCode::BAD_REQUEST));
    let mismatch_body: Value = mismatch_response.take_json().await.unwrap();
    assert_eq!(problem_code(&mismatch_body), "schema_violation");
    assert!(
        mismatch_body["detail"]
            .as_str()
            .is_some_and(|message| message.contains("plane_cross_write")),
        "an anchor-unit member carrying a CBA basis must fail the §5 plane check \
         with its normative reason: {mismatch_body}"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .all(|record| record.realm_id.as_deref() != Some(realm_id.as_str())),
        "rejected bootstrap must leave no canonical Event"
    );
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, &actor_key)
            .is_none(),
        "rejected bootstrap must leave no creator membership projection"
    );

    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "events": initial_submissions([
                event.clone(),
                profile.clone(),
                policy.clone(),
                join_rule.clone(),
                history_access.clone(),
                discovery.clone(),
                member_state.clone()
            ])
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.expect("submit status");
    let body: Value = response.take_json().await.expect("submit json body");

    assert!(
        matches!(status, StatusCode::OK | StatusCode::CREATED),
        "realm create genesis unit rejected with {status}: {body}"
    );
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["accepted"][0], event["event_id"]);
    assert_eq!(body["accepted"][6], member_state["event_id"]);
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, &actor_key)
            .is_some_and(|member| member.state == "join")
    );
    {
        let projection = state.test_projection().lock();
        let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_core.clone(),
            arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap(),
        ));
        let authority_root = projection
            .realm_authority_root(&realm_id)
            .expect("accepted genesis must register the Realm authority-root cell");
        assert!(
            authority_root.is_genesis_for(&actor_id),
            "the authority root's controller is the Realm creator at epoch/generation 0"
        );
        assert!(
            projection.actor_holds_effective_realm_owner(&realm_id, &actor_id, chrono::Utc::now(),),
            "the authority-root controller holds effective ak.realm.owner"
        );
        assert!(
            !projection.actor_holds_effective_realm_owner(
                &realm_id,
                &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    fixture_actor_core_id("did:web:mallory.example"),
                    arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap(),
                )),
                chrono::Utc::now()
            ),
            "nobody else does"
        );
        // The registered `effect_projection` for each initial facet is
        // `{"kind":"set","value":{"field":"payload"}}`, so the cas-register cell
        // holds the whole signed payload object — not the bare enum the old
        // producer-written effect chose to store.
        for (family, expected) in [
            (
                arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1,
                serde_json::json!({"value": "invite"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
                serde_json::json!({"value": {"discoverability": "invite_only"}}),
            ),
        ] {
            assert_eq!(
                projection.realm_null_subject_cell_value(&realm_id, family),
                Some(&expected)
            );
        }
        assert_eq!(
            projection.realm_null_subject_cell_value(
                &realm_id,
                arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1,
            ),
            Some(&serde_json::json!("since_join")),
        );
    }
    assert!(
        state
            .test_authz()
            .grants_snapshot()
            .iter()
            .all(|grant| { grant.realm_id != realm_id }),
        "genesis issues no capability grant at all: authority is the root cell"
    );

    let sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(
        sync["realms"][&realm_id]["state_at_window_start"]["realm_metadata"]["title"],
        "Bootstrap effects realm",
        "account sync must carry the Realm title in its canonical metadata slot: {sync}"
    );
    assert_eq!(
        sync["realms"][&realm_id]["state_at_window_start"]["realm_metadata"]["summary"],
        Value::Null,
        "the canonical profile fixture leaves its optional summary absent"
    );

    let mut describe_response = TestClient::get("http://server/_arkret/describe")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        describe_response.status_code,
        Some(StatusCode::OK),
        "the local Station must publish its current service resolution before it can be a join candidate"
    );
    let _: Value = describe_response
        .take_json()
        .await
        .expect("service description response");

    let mut resolve_response =
        TestClient::post("http://server/_arkret/find/directory/resolve-realm")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({"realm_id": realm_id}))
            .send(&app_from_state(state.clone()))
            .await;
    let resolve_status = resolve_response.status_code.expect("resolve status");
    let resolve_body: Value = resolve_response
        .take_json()
        .await
        .expect("resolve json body");
    assert_eq!(
        resolve_status,
        StatusCode::OK,
        "Realm resolution failed: {resolve_body}"
    );
    assert!(
        resolve_body.get("join_candidates").is_none(),
        "a bootstrap without an exact routable member account must not be advertised as a join candidate: {resolve_body}"
    );
    assert_eq!(
        resolve_body["realm_preview"]["title"], "Bootstrap effects realm",
        "Directory/sidebar projection must expose the title, not the Realm id: {resolve_body}"
    );

    let restarted = soland_test_support::app_state_with_persistence(
        test_config(),
        state.test_persistence().clone(),
    )
    .await;
    restarted.hydrate().await.expect("restart hydration");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    assert_eq!(
        restarted
            .test_realms()
            .lock()
            .get(&typed_realm_id)
            .map(|entry| entry.title.as_str()),
        Some("Bootstrap effects realm"),
        "restart must rebuild the directory title from canonical create"
    );
    assert!(
        restarted
            .test_projection()
            .lock()
            .member(&realm_id, &actor_key)
            .is_some_and(|member| member.state == "join"),
        "restart must rebuild creator membership from canonical create"
    );
    {
        let restarted_projection = restarted.test_projection().lock();
        assert!(
            restarted_projection
                .realm_authority_root(&realm_id)
                .is_some_and(|root| {
                    root.is_genesis_for(&arkret_wire::ActorId::account(
                        arkret_wire::AccountId::new(
                            actor_core.clone(),
                            arkret_wire::DidCoreId::new(restarted.service_id().clone()).unwrap(),
                        ),
                    ))
                }),
            "restart must rebuild the Realm authority root from canonical create"
        );
        // The registered `effect_projection` for each initial facet is
        // `{"kind":"set","value":{"field":"payload"}}`, so the cas-register cell
        // holds the whole signed payload object — not the bare enum the old
        // producer-written effect chose to store.
        for (family, expected) in [
            (
                arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1,
                serde_json::json!({"value": "invite"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
                serde_json::json!({"value": {"discoverability": "invite_only"}}),
            ),
        ] {
            assert_eq!(
                restarted_projection.realm_null_subject_cell_value(&realm_id, family),
                Some(&expected),
                "restart must rebuild bootstrap cell {family}"
            );
        }
        assert_eq!(
            restarted_projection.realm_null_subject_cell_value(
                &realm_id,
                arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1,
            ),
            Some(&serde_json::json!("since_join")),
        );
    }
}

#[test]
fn invite_create_accepts_locator_evidence_digest_without_local_consent() {
    run_on_deep_stack(
        "invite_create_accepts_locator_evidence_digest_without_local_consent",
        invite_create_accepts_locator_evidence_digest_without_local_consent_body,
    );
}

async fn invite_create_accepts_locator_evidence_digest_without_local_consent_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seeded = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Locator evidence invite",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = seeded["realm_id"].as_str().unwrap().to_owned();
    let payload = serde_json::json!({
        "invitee_account_id": fixture_account_id(&state, "did:web:carol.example"),
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2099-01-01T00:00:00.000Z"
    });
    let mut event = signed_canonical_event(
        "ak:event:AQP6VTZp5qLA0ZHh7k55JiMpQYsOMWXQ_bOl9X_3cVUp",
        "ak.invite.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        0,
        Vec::new(),
        payload.clone(),
    );
    // The producer `effects[]` this fixture used to attach is gone: an
    // `ak.invite.create` write set is projected by the receiver from the
    // registered contract. What the Event still owes is its Control Move
    // `seal_basis`, which is taken below from the Realm's accepted bootstrap
    // Seal (`seed_test_realm`), never from a fabricated zero-hash leaf.
    move_event_to_actor_realm_frontier(
        &state,
        &token,
        "did:web:alice.example",
        &realm_id,
        &mut event,
    )
    .await;
    event["seal_basis"] = seeded["seal_basis"].clone();
    resign_canonical_event(&mut event);
    let invite_id = arkret_identifiers::InviteId::from_event_id(
        &arkret_identifiers::EventId::new(authored_event_id(&event).to_owned()).unwrap(),
    )
    .to_string();

    let submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        submitted["status"], "accepted",
        "submit response: {submitted}"
    );
    let projected = state
        .test_persistence()
        .realm_invites()
        .get(&invite_id)
        .await
        .unwrap()
        .expect("invite projected");
    assert_eq!(projected.status, "pending");
    assert_eq!(
        projected.invitee_id.as_deref(),
        Some(
            fixture_account_id(&state, "did:web:carol.example")
                .canonical_key()
                .unwrap()
                .as_str()
        )
    );
    assert_eq!(
        projected.introduction_evidence_digest.as_deref(),
        payload["introduction_evidence_digest"].as_str()
    );
}

#[test]
fn sync_cursor_rejects_facets_and_renderer_changes() {
    run_on_deep_stack(
        "sync_cursor_rejects_facets_and_renderer_changes",
        sync_cursor_rejects_facets_and_renderer_changes_body,
    );
}

async fn sync_cursor_rejects_facets_and_renderer_changes_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(first["cursor"].as_str().is_some());
    let cursor = first["cursor"].as_str().unwrap();

    // client-sync.md §11 / §12.1: changing the filter scope on a returned cursor
    // MUST trigger a filter_digest mismatch -> cursor_integrity_invalid (HTTP
    // 400). The realm id MUST use the `ak:` prefix (decision 0008 / rebrand); a
    // `ck:` id is rejected by SyncFilter deserialization and silently degrades to
    // an empty filter, which would bypass this case.
    let mut changed_url =
        reqwest::Url::parse("http://server/_arkret/self/account/subscribe").unwrap();
    let changed_filter = serde_json::json!({"realm_ids": [demo_realm_id()]}).to_string();
    changed_url.query_pairs_mut().extend_pairs([
        ("catchup", "true"),
        ("after", cursor),
        ("filter", changed_filter.as_str()),
    ]);
    let filter_changed = TestClient::get(changed_url.as_str())
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_changed.status_code.unwrap().as_u16(), 400);
}

#[test]
fn cursor_syntax_failures_pin_param_invalid_with_invalid_cursor_reason() {
    run_on_deep_stack(
        "cursor_syntax_failures_pin_param_invalid_with_invalid_cursor_reason",
        cursor_syntax_failures_pin_param_invalid_with_invalid_cursor_reason_body,
    );
}

async fn cursor_syntax_failures_pin_param_invalid_with_invalid_cursor_reason_body() {
    // encoding.md §8.3 closed set: a token that carries the `ak:cursor:`
    // prefix but fails base64url/JSON/schema decoding MUST be rejected with
    // top-level `param_invalid` and reason `invalid_cursor` — never
    // `cursor_integrity_invalid` (reserved for handle lookup / binding
    // failures).
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let actor_core = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id("did:web:alice.example"),
        state.service_core_id().clone(),
    ));

    // ak.self.events.read.scan.v1 — `after` in canonical QUERY content.
    let mut rejected = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actor_ids": [actor_core],
            "after": "ak:cursor:!!!not-base64url"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = rejected.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "param_invalid", "{body}");
    assert_eq!(body["reason_code"], "invalid_cursor", "{body}");

    // ak.self.account.stream.subscribe.v1 — `after=` reconnect parameter.
    let frame = account_subscribe_frame(
        state.clone(),
        Some(&token),
        "catchup=true&after=ak:cursor:!!!not-base64url",
    )
    .await;
    assert_eq!(problem_code(&frame), "param_invalid", "{frame}");
    assert_eq!(frame["reason_code"], "invalid_cursor", "{frame}");
}

#[test]
fn account_subscribe_realms_filter_excludes_out_of_scope_realms() {
    run_on_deep_stack(
        "account_subscribe_realms_filter_excludes_out_of_scope_realms",
        account_subscribe_realms_filter_excludes_out_of_scope_realms_body,
    );
}

async fn account_subscribe_realms_filter_excludes_out_of_scope_realms_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let included = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Included Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let excluded = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Excluded Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let included_id = included["realm_id"].as_str().unwrap();
    let excluded_id = excluded["realm_id"].as_str().unwrap();
    let encoded_included_id = included_id.replace(':', "%3A");
    let frame = account_subscribe_frame(
        state,
        Some(&alice),
        &format!("catchup=true&filter=%7B%22realm_ids%22%3A%5B%22{encoded_included_id}%22%5D%7D"),
    )
    .await;

    assert!(
        frame["realms"][included_id].is_object(),
        "requested Realm must be present: {frame}"
    );
    assert!(
        frame["realms"].get(excluded_id).is_none(),
        "out-of-scope Realm must be absent: {frame}"
    );
}

#[test]
fn events_query_exposes_prev_cursor_and_limited_timeline_pages() {
    run_on_deep_stack(
        "events_query_exposes_prev_cursor_and_limited_timeline_pages",
        events_query_exposes_prev_cursor_and_limited_timeline_pages_body,
    );
}

async fn events_query_exposes_prev_cursor_and_limited_timeline_pages_body() {
    let state = soland_test_support::app_state(test_config());
    let actor = test_event_signer_did();
    let actor_core = fixture_actor_core_id(actor);
    let token = verified_dev_token_for_device(
        state.clone(),
        actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Cursor Author",
    )
    .await;
    let realm = seed_test_realm(
        &state,
        actor,
        "Events read pagination Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();

    for body in ["first backfill page", "second backfill page"] {
        let sent = submit_message_event(
            state.clone(),
            &token,
            actor,
            realm_id,
            "ak:strand:backfill-pages",
            serde_json::json!({"body": body}),
            false,
        )
        .await;
        assert!(sent["operation_id"].as_str().is_some());
    }

    let actor_selector = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor_core,
        state.service_core_id().clone(),
    ));
    let read_body = serde_json::json!({"limit": 1, "actor_ids": [actor_selector]});
    let query_page: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&read_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        query_page["next_cursor"].as_str().is_some(),
        "expected newer-edge cursor: {query_page}"
    );
    assert_eq!(
        query_page["events"].as_array().unwrap().len(),
        1,
        "expected one Event in the first read page: {query_page}"
    );
    assert_eq!(query_page["has_more"], true);
    let prev_cursor = query_page["prev_cursor"].as_str().unwrap();
    assert!(prev_cursor.starts_with("ak:cursor:"));

    let second_page: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(
            &serde_json::json!({"limit": 1, "actor_ids": [actor_selector], "before": prev_cursor}),
        )
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);
    assert_ne!(second_page["events"][0], query_page["events"][0]);

    let mut invalid_cursor = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actor_ids": [actor],
            "after": "ak:event:AWNDYdZJJKnSYHxTY2Yye1ERF3ydKwe5EXA6UzTu5DAc"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        invalid_cursor.status_code.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(problem_code(&invalid_cursor_body), "schema_violation");
}

#[test]
fn incremental_sync_waits_30_seconds_then_returns_frontier() {
    run_on_deep_stack_paused(
        "incremental_sync_waits_30_seconds_then_returns_frontier",
        incremental_sync_waits_30_seconds_then_returns_frontier_body,
    );
}

async fn incremental_sync_waits_30_seconds_then_returns_frontier_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap();
    assert!(
        baseline["realms"][demo_realm_id()].is_object(),
        "full sync MUST include the realm baseline: {baseline}"
    );

    let started = tokio::time::Instant::now();
    let quiet = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&after={cursor}"),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(
        elapsed,
        Duration::from_secs(30),
        "quiet incremental subscribe must be a server-side 30s long poll"
    );
    assert_eq!(quiet["kind"], "frontier");
    assert!(
        quiet["realms"].is_null(),
        "frontier must carry no fake delta: {quiet}"
    );
}

#[test]
fn incremental_sync_meta_only_delta_advances_cursor_once() {
    run_on_deep_stack_paused(
        "incremental_sync_meta_only_delta_advances_cursor_once",
        incremental_sync_meta_only_delta_advances_cursor_once_body,
    );
}

async fn incremental_sync_meta_only_delta_advances_cursor_once_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let created = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Meta-only Realm",
        Some("projection-only sync regression"),
        "listed",
        &[],
        &[],
    )
    .await;
    let realm_id = created["realm_id"].as_str().unwrap().to_owned();

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();
    assert!(
        baseline["realms"][&realm_id].is_object(),
        "full sync MUST include the seeded realm baseline: {baseline}"
    );

    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(&realm_id)
        .await
        .unwrap()
        .expect("seeded realm meta");
    meta.updated_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    state
        .test_persistence()
        .realm_meta()
        .put(&realm_id, &meta)
        .await
        .unwrap();

    let meta_delta = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&after={cursor}"),
    )
    .await;
    assert!(
        meta_delta["realms"][&realm_id].is_object(),
        "meta-only change MUST emit the realm once: {meta_delta}"
    );
    assert!(
        meta_delta["realms"][&realm_id]["timeline"]["events"]
            .as_array()
            .is_some_and(|events| events.is_empty()),
        "regression setup must be meta-only, not a timeline event: {meta_delta}"
    );

    let next_cursor = meta_delta["cursor"].as_str().unwrap().to_owned();
    let quiet = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&after={next_cursor}"),
    )
    .await;
    assert_eq!(quiet["kind"], "frontier");
    assert!(
        quiet["realms"].is_null(),
        "same meta-only projection MUST NOT repeat after its cursor: {quiet}"
    );
}

#[test]
fn incremental_sync_emits_realm_with_new_timeline_event() {
    run_on_deep_stack(
        "incremental_sync_emits_realm_with_new_timeline_event",
        incremental_sync_emits_realm_with_new_timeline_event_body,
    );
}

async fn incremental_sync_emits_realm_with_new_timeline_event_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        demo_realm_id(),
        &expected_strand_id_for_scope(demo_realm_id()),
        serde_json::json!({
            "kind": "ak.content.text",
            "body": "incremental wake-up",
            "format": "plain"
        }),
        false,
    )
    .await;
    assert_eq!(message["status"], "accepted", "message submit: {message}");

    let delta = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&after={cursor}"),
    )
    .await;
    let timeline = delta["realms"][demo_realm_id()]["timeline"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("realm should reappear with timeline events: {delta}"));
    assert!(
        timeline
            .iter()
            .any(|event| event["event_id"] == message["event_id"]),
        "delta MUST include the freshly persisted message: {delta}; submit={message}"
    );
}

#[test]
fn account_subscribe_waits_for_broadcast_before_returning_incremental_batch() {
    run_on_deep_stack(
        "account_subscribe_waits_for_broadcast_before_returning_incremental_batch",
        account_subscribe_waits_for_broadcast_before_returning_incremental_batch_body,
    );
}

async fn account_subscribe_waits_for_broadcast_before_returning_incremental_batch_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let waker_state = state.clone();
    let waker_token = alice.clone();
    let waker = tokio::spawn(async move {
        // Give the stream a beat to subscribe before we fire.
        tokio::time::sleep(Duration::from_millis(150)).await;
        submit_message_event(
            waker_state,
            &waker_token,
            "did:web:alice.example",
            demo_realm_id(),
            &expected_strand_id_for_scope(demo_realm_id()),
            serde_json::json!({
                "kind": "ak.content.text",
                "body": "wake up the stream",
                "format": "plain"
            }),
            false,
        )
        .await
    });

    let start = tokio::time::Instant::now();
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?catchup=true&after={cursor}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    let woken: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("woken delta frame");
    assert_eq!(woken["kind"], "delta");
    let catchup: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("catchup-complete frame");
    assert_eq!(catchup["kind"], "catchup_complete");
    let elapsed = start.elapsed();
    let message = waker.await.unwrap();

    assert!(
        elapsed >= Duration::from_millis(150),
        "incremental subscribe returned before its broadcast wake-up: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "broadcast should wake the long poll well before its 30s deadline: {elapsed:?}"
    );
    let timeline = woken["realms"][demo_realm_id()]["timeline"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("woken delta MUST include the realm: {woken}"));
    assert!(
        timeline
            .iter()
            .any(|event| event["event_id"] == message["event_id"]),
        "woken delta MUST include the wake-up event: {woken}"
    );
}

#[test]
fn account_subscribe_preserves_ordered_log_siblings_and_exposes_conflict_diagnostic() {
    run_on_deep_stack(
        "account_subscribe_preserves_ordered_log_siblings_and_exposes_conflict_diagnostic",
        account_subscribe_preserves_ordered_log_siblings_and_exposes_conflict_diagnostic_body,
    );
}

async fn account_subscribe_preserves_ordered_log_siblings_and_exposes_conflict_diagnostic_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    authorize_test_plaintext_message_service(&state, "did:web:alice.example", demo_realm_id())
        .await;
    let content = |body: &str| {
        serde_json::json!({
            "kind": "ak.content.text",
            "body": body,
            "format": "plain"
        })
    };
    let mut left = signed_message_event_envelope(
        "did:web:alice.example",
        demo_realm_id(),
        &expected_strand_id_for_scope(demo_realm_id()),
        content("ordered-log left"),
        false,
    );
    let mut right = signed_message_event_envelope(
        "did:web:alice.example",
        demo_realm_id(),
        &expected_strand_id_for_scope(demo_realm_id()),
        content("ordered-log right"),
        false,
    );
    // Resolve both candidates before submitting either one. They therefore
    // cite the same accepted frontier and are formal actor-sequence siblings.
    move_event_to_actor_realm_frontier(
        &state,
        &alice,
        "did:web:alice.example",
        demo_realm_id(),
        &mut left,
    )
    .await;
    move_event_to_actor_realm_frontier(
        &state,
        &alice,
        "did:web:alice.example",
        demo_realm_id(),
        &mut right,
    )
    .await;
    let actor_seq = left["actor_seq"].as_u64().expect("left actor sequence");
    assert_eq!(right["actor_seq"], actor_seq);
    assert_eq!(right["prev_refs"], left["prev_refs"]);
    let left_event_id = authored_event_id(&left).to_owned();
    let right_event_id = authored_event_id(&right).to_owned();
    for sibling in [&left, &right] {
        let outcome: Value = TestClient::post("http://server/_arkret/self/events")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(sibling)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .expect("sibling submission outcome");
        assert_eq!(outcome["status"], "accepted", "sibling submit: {outcome}");
    }

    let normal = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        demo_realm_id(),
        &expected_strand_id_for_scope(demo_realm_id()),
        content("ordered-log normal"),
        false,
    )
    .await;

    let frame = account_subscribe_frame(state, Some(&alice), "catchup=true").await;
    let timeline = &frame["realms"][demo_realm_id()]["timeline"];
    let event_ids = timeline["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["event_id"].as_str())
        .collect::<Vec<_>>();
    assert!(event_ids.contains(&left_event_id.as_str()), "{frame}");
    assert!(event_ids.contains(&right_event_id.as_str()), "{frame}");
    assert!(
        event_ids.contains(&normal["event_id"].as_str().unwrap()),
        "{frame}"
    );

    let siblings = timeline["ordered_log_siblings"].as_array().unwrap();
    let diagnostic = siblings
        .iter()
        .find(|diagnostic| diagnostic["issuer_seq"] == actor_seq)
        .unwrap_or_else(|| panic!("sibling diagnostic missing: {frame}"));
    let sibling_ids = diagnostic["event_ids"].as_array().unwrap();
    assert!(sibling_ids.contains(&serde_json::json!(left_event_id)));
    assert!(sibling_ids.contains(&serde_json::json!(right_event_id)));
    assert_eq!(diagnostic["reason"], "actor_seq_siblings");
}
