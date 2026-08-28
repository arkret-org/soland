use super::*;

const AGENT_CORE: &str = "ak:did_core:web:agent.example";
const AGENT_DID: &str = "did:web:agent.example";
const CONTROLLER_CORE: &str = "ak:did_core:web:controller.example";
const SERVICE_CORE: &str = "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x";

fn web_did(core_id: &str) -> String {
    core_id
        .strip_prefix("ak:did_core:web:")
        .map(|authority| format!("did:web:{authority}"))
        .expect("fixture uses a did:web Core identifier")
}

fn test_session(actor: &str) -> SessionRecord {
    SessionRecord {
        service_account_id: None,
        token_hash: format!("test-session:{actor}"),
        actor: actor.to_owned(),
        device_id: "test-device".to_owned(),
        audience: "did:web:soland.test".to_owned(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    }
}

fn agent_record(agent_id: &str, controller_id: &str) -> AgentPrincipalRecord {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-06-11T00:00:00.000Z")
        .expect("fixture timestamp")
        .with_timezone(&chrono::Utc);
    let controller_did = web_did(controller_id);
    let mut record = AgentPrincipalRecord::new(
        agent_id.to_owned(),
        controller_id.to_owned(),
        "ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M".to_owned(),
        arkret_wire::DidUrl::new(format!("{controller_did}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        created_at,
    );
    record.display_name = Some("Test Agent".to_owned());
    record.provision_event_refs = Some(json!({ "did_binding_accepted": true }));
    record
}

fn pending_pairing_record(
    agent_id: &str,
    controller_id: &str,
    requested_scope: Value,
    pairing_code: &str,
    pairing_expires_at: &str,
) -> AgentPrincipalRecord {
    let mut record = agent_record(agent_id, controller_id);
    // Lifecycle intent is active from provisioning; the open bootstrap
    // handle drives runtime_state to pending_runtime_key (key-management.md
    // §3.6.1).
    record.state = AgentLifecycleState::Active;
    record.requested_scope = Some(requested_scope);
    record.pairing_request_id = Some(
        arkret_wire::OpaqueLocalId::new(
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
        )
        .unwrap(),
    );
    record.pairing_code = Some(pairing_code.to_owned());
    record.pairing_expires_at = Some(
        chrono::DateTime::parse_from_rfc3339(pairing_expires_at)
            .expect("fixture pairing expiry")
            .with_timezone(&chrono::Utc),
    );
    record
}

fn requested_agent_scope() -> Value {
    json!({
        "actions": [
            "ak.self.events.stream.subscribe.v1",
            "ak.self.events.read.scan.v1",
            "ak.self.events.command.submit.v1",
            "ak.event.read",
            "ak.message.create"
        ],
        "resources": [
            {
                "kind": "realm",
                "realm_id": "ak:realm:AWRn2H80ZSW4qBxlHzdkMQbOwl5Ts8OnQRef8M3BJ93F"
            },
            { "kind": "service", "service_id": SERVICE_CORE }
        ]
    })
}

fn initial_submission(
    event: arkret_wire::Event,
    actor_id: arkret_identifiers::DidCoreId,
) -> arkret_wire::EventInitialSubmission {
    use arkret_wire::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, DeviceId, DidUrl,
        LeaseBasisRef, RiskTier, SchemaId, SealId,
    };

    let policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: event.scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: event.event_id.as_str().to_owned(),
            source_digest: arkret_wire::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "realm_admission".to_owned(),
            issuer_role: AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec![event.kind.as_str().to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new("did:web:controller.example#key-1").unwrap(),
            }],
            threshold: 1,
        }],
    };
    let issued_at = event.created_at;
    arkret_wire::EventInitialSubmission {
        authorization_lease: Some(AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id,
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
            scope_ref: event.scope_ref.clone(),
            action: event.kind.as_str().to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::Low,
            issued_at,
            expires_at: issued_at + chrono::Duration::hours(1),
            authority_set_ref: AuthoritySetRef {
                authority_set_id: policy.authority_set_id.clone(),
                authority_set_digest: policy.digest().unwrap(),
            },
            authority_set_policy: policy,
            proofs: Vec::new(),
        }),
        event,
        cba_proof_bundles: Vec::new(),
        control_proposal_ack: None,
        membership_compensation_evidence: None,
    }
}

fn key_authorize_envelope(
    record: &mut AgentPrincipalRecord,
    controller: &str,
    agent_id: &str,
    verification_method: &str,
    public_key_digest: &str,
    service_id: &str,
    scope: Value,
) -> Value {
    let runtime_request =
        key_pair_request_body(&web_did(agent_id), verification_method, service_id);
    record.runtime_key_binding_digest = Some(
        runtime_request
            .proof_of_possession
            .runtime_key_binding_digest
            .as_str()
            .to_owned(),
    );
    record.runtime_public_key_digest = Some(
        arkret_signatures::agent::agent_runtime_public_key_digest(&runtime_request.public_key)
            .expect("runtime public key digest")
            .as_str()
            .to_owned(),
    );
    record.runtime_attestation_digest = Some(
        arkret_signatures::agent::agent_runtime_attestation_digest(None)
            .expect("runtime attestation digest")
            .as_str()
            .to_owned(),
    );
    record.runtime_key_request = Some(
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
            pairing_request_id: runtime_request.pairing_request_id,
            agent_id: runtime_request.agent_id,
            verification_method: runtime_request.verification_method,
            public_key: runtime_request.public_key,
            proof_of_possession: runtime_request.proof_of_possession,
            runtime_attestation: runtime_request.runtime_attestation,
        },
    );
    let request_canonical_digest = pairing_request_binding_digest(
        record,
        controller,
        agent_id,
        verification_method,
        service_id,
    )
    .expect("pairing binding digest");
    json!({
        "event_id": "ak:event:AaWlxNyGs0FzlOCJpyhjSRcmOcoYvk0qQ4X91NlGuKSZ",
        "kind": "ak.agent.key.authorize",
        "actor_id": agent_id,
        "principal_server_id": service_id,
        "executed_by": controller,
        "authorization_ref": record.controller_authorization_ref.as_str(),
        "realm_id": record.principal_control_realm_id.as_str(),
        "payload": {
            "agent_id": agent_id,
            "key_id": "ak:agent_key:01999999000070008000000000000001",
            "verification_method": verification_method,
            "public_key_digest": public_key_digest,
            "accountable_principal_id": controller,
            "agent_key_scope": scope,
            "audience": [service_id],
            "issued_at": "2026-07-06T00:00:00.000Z",
            "expires_at": "2999-01-01T00:00:00.000Z",
            "approval_evidence": {
                "kind": "pairing_request",
                "request_canonical_digest": request_canonical_digest,
                "pairing_request_id": record.pairing_request_id.as_deref(),
                "approved_by": controller,
            },
        },
    })
}

fn key_pair_request_body(
    agent: &str,
    verification_method: &str,
    service_id: &str,
) -> AgentKeyPairRequestBody {
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let encoded_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().as_bytes());
    let public_key = PublicKey {
        kty: arkret_wire::NonEmptyString::new("OKP").unwrap(),
        kid: arkret_wire::NonEmptyString::new(verification_method).unwrap(),
        algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
        key: arkret_wire::Base64UrlString::new(encoded_public_key).unwrap(),
        key_digest: None,
    };
    let agent_did = Did::new(agent.to_owned()).expect("agent DID");
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let pairing_request_id = arkret_wire::OpaqueLocalId::new(
        "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
    )
    .unwrap();
    let verification_method = arkret_wire::DidUrl::new(verification_method).unwrap();
    let runtime_key_binding_digest =
        arkret_models_collaboration::agent_operations::agent_runtime_key_binding_digest(
            &agent_id,
            &pairing_request_id,
            &verification_method,
            &public_key,
            None,
        )
        .expect("runtime key binding digest");
    let created_at = chrono::Utc::now();
    let expires_at = created_at + chrono::Duration::minutes(5);
    let mut proof_of_possession =
        arkret_models_collaboration::agent_operations::AgentRuntimeKeyPossessionProof {
            kind: arkret_models_collaboration::agent_operations::AgentRuntimeKeyPossessionProofKind::AgentRuntimeKeyPossession,
            verification_method: verification_method.clone(),
            signature_algorithm: arkret_models_collaboration::agent_operations::AgentRuntimeKeyAlgorithm::Ed25519,
            challenge: pairing_request_id.clone(),
            audience_id: arkret_wire::DidCoreId::new(service_id).unwrap(),
            created_at,
            expires_at,
            runtime_key_binding_digest,
            transcript_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
        };
    let transcript = proof_of_possession
        .canonical_transcript_bytes("12345678")
        .unwrap();
    proof_of_possession.transcript_digest =
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(&transcript)).unwrap();
    proof_of_possession.signature = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_key.sign(&transcript).to_bytes()),
    )
    .unwrap();
    let controller_id = DidCoreId::new("ak:did_core:web:controller.example".to_owned()).unwrap();
    let requested_scope: AgentKeyScope = serde_json::from_value(requested_agent_scope()).unwrap();
    let requested_scope_disclosure = serde_json::from_value(json!({
        "schema": "ak.schema.agent_requested_scope_disclosure.v1",
        "request_id": "ak:request:01999999-0000-7000-8000-000000000099",
        "agent_id": agent_id.as_str(),
        "controller_id": controller_id.as_str(),
        "requested_scope": requested_scope,
        "verifier_id": service_id,
        "audience": "ak.gate.account.command.pair_agent_key.v1",
        "challenge": "pairing-challenge-0001",
        "issued_at": "2026-07-06T00:00:00.000Z",
        "expires_at": "2026-07-06T00:05:00.000Z",
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": "did:web:controller.example#key-1",
            "event_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": "2026-07-06T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
        }]
    }))
    .unwrap();
    let authorize_event = crate::test_event::raw_event(
        "ak.agent.key.authorize",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M",
            )
            .unwrap(),
        },
        crate::test_actor_id(&agent_did),
        1,
        arkret_identifiers::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({}),
    )
    .unwrap();
    let authorize_event_id = authorize_event.event_id.clone();
    let authorize_event = initial_submission(authorize_event, agent_id.clone());
    let signing_public_key_digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
        signing_key.verifying_key().as_bytes(),
    ))
    .unwrap();
    let signing_key_binding = serde_json::from_value(json!({
        "schema": "ak.schema.agent_signing_key_binding.v1",
        "agent_id": agent_id,
        "agent_key_id": "ak:agent_key:01999999000070008000000000000001",
        "verification_method": verification_method,
        "public_key": {
            "kty": "OKP",
            "algorithm": "Ed25519",
            "key": public_key.key
        },
        "public_key_digest": signing_public_key_digest,
        "agent_key_authorize_event_id": authorize_event_id,
        "issued_at": "2026-07-06T00:00:00.000Z",
        "controller_id": controller_id,
        "controller_proof": {
            "kind": "detached_jws",
            "verification_method": "did:web:controller.example#key-1",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
        }
    }))
    .unwrap();
    AgentKeyPairRequestBody {
        pairing_request_id,
        agent_id,
        verification_method,
        public_key,
        proof_of_possession,
        requested_scope_disclosure,
        runtime_attestation: None,
        authorize_event,
        signing_key_binding,
    }
}

#[test]
fn agent_id_is_core_did_not_agent_typed_id() {
    validate_agent_id(AGENT_CORE).expect("Core DID-as-id must be accepted");
    assert!(validate_agent_id("ak:agent_principal:01999999-0000-7000-8000-00000000a001").is_err());
}

/// `key-management.md` §7.4.1 — the DID projects onto the Core
/// actor id through its method adapter; a core id concatenated with a
/// fragment is not a DID URL and never matches.
#[test]
fn verification_method_principal_projects_did_to_core_id() {
    assert_eq!(
        verification_method_principal("did:web:agent.example?versionId=1#key-1")
            .as_ref()
            .map(arkret_identifiers::DidCoreId::as_str),
        Some(AGENT_CORE)
    );
    assert_eq!(
        verification_method_principal(&format!("{AGENT_CORE}#key-1")),
        None
    );
}

#[test]
fn verification_method_agent_endpoint_matches_projected_controller() {
    let device_id = "ak:device:01904100-0000-7000-8000-000000000042";
    assert_eq!(
        verification_method_agent_endpoint(&format!("{AGENT_DID}#{device_id}"), AGENT_CORE,)
            .as_ref()
            .map(arkret_identifiers::DeviceId::as_str),
        Some(device_id)
    );
    // The schema-valid DID form must not be compared against the raw
    // core id string, and a core-id controller must never match.
    assert_eq!(
        verification_method_agent_endpoint(&format!("{AGENT_DID}#{device_id}"), AGENT_DID),
        None
    );
    assert_eq!(
        verification_method_agent_endpoint(&format!("{AGENT_CORE}#{device_id}"), AGENT_CORE),
        None
    );
}

fn bind_pairing_request_to_controller_device(
    body: &mut AgentKeyPairRequestBody,
    controller_id: &str,
) {
    let device_id = body
        .authorize_event
        .authorization_lease
        .as_ref()
        .expect("pairing fixture uses a delayed authorization lease")
        .device_id
        .as_str();
    let mut proof = body.requested_scope_disclosure.proofs[0].clone();
    proof.verification_method =
        arkret_wire::DidUrl::new(format!("{}#{device_id}", web_did(controller_id))).unwrap();
    body.authorize_event.event.executed_by =
        Some(crate::test_actor_id_str(&web_did(controller_id)));
    body.authorize_event.event.proofs = vec![proof.into()];
}

#[test]
fn service_pairing_preserves_the_controller_device_bound_by_the_signed_submission() {
    let controller_id = CONTROLLER_CORE;
    let mut body =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-key", SERVICE_CORE);
    bind_pairing_request_to_controller_device(&mut body, controller_id);

    let device_id = service_pairing_controller_device_id(&body, controller_id)
        .expect("signed submission binds the service session device");

    assert_eq!(
        device_id,
        body.authorize_event
            .authorization_lease
            .as_ref()
            .expect("pairing fixture uses a delayed authorization lease")
            .device_id
            .as_str()
    );
}

#[test]
fn service_pairing_rejects_a_proof_from_a_different_controller_device() {
    let controller_id = CONTROLLER_CORE;
    let mut body =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-key", SERVICE_CORE);
    bind_pairing_request_to_controller_device(&mut body, controller_id);
    let arkret_wire::EventProof::Producer(proof) = &mut body.authorize_event.event.proofs[0] else {
        panic!("fixture must carry a producer proof")
    };
    proof.verification_method = arkret_wire::DidUrl::new(format!(
        "{}#ak:device:01904100-0000-7000-8000-000000000099",
        web_did(controller_id)
    ))
    .unwrap();

    assert!(service_pairing_controller_device_id(&body, controller_id).is_err());
}

#[test]
fn service_pairing_rejects_a_non_device_controller_proof() {
    let controller_id = CONTROLLER_CORE;
    let mut body =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-key", SERVICE_CORE);
    bind_pairing_request_to_controller_device(&mut body, controller_id);
    let arkret_wire::EventProof::Producer(proof) = &mut body.authorize_event.event.proofs[0] else {
        panic!("fixture must carry a producer proof")
    };
    proof.verification_method =
        arkret_wire::DidUrl::new(format!("{}#key-1", web_did(controller_id))).unwrap();

    assert!(service_pairing_controller_device_id(&body, controller_id).is_err());
}

#[test]
fn agent_view_projects_spec_shape_dropping_internal_columns() {
    let mut record = agent_record(
        "ak:did_core:web:agent.example",
        "ak:did_core:web:controller.example",
    );
    record.display_name = Some("Summary Assistant".to_owned());
    record.agent_slug = Some("summary".to_owned());
    let view = AgentView {
        agent: agent_projection_from_record(&record, AgentRuntimeState::Ready),
        grants: Vec::new(),
        key_state: None,
    };
    assert_eq!(view.agent.lifecycle, AgentLifecycleState::Active);
    assert_eq!(view.agent.readiness.state, AgentReadinessState::Ready);
    let agent = serde_json::to_value(&view).expect("view serializes");
    assert_eq!(agent["agent"]["slug"], "summary");
    assert_eq!(agent["agent"]["lifecycle"], "active");
    assert_eq!(agent["agent"]["readiness"]["state"], "ready");
    assert_eq!(agent["agent"]["agent_id"], "ak:did_core:web:agent.example");
    // soland-internal columns MUST NOT leak into the protocol projection.
    assert!(agent["agent"].get("controller_id").is_none());
}

#[test]
fn selector_slug_reservation_ignores_expired_and_terminal_agents() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-07T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    // A keyed agent (authorized_event_ref set) reserves its slug for any
    // non-terminal lifecycle intent (key-management.md §3.6.1).
    let mut active = agent_record(AGENT_CORE, CONTROLLER_CORE);
    active.state = AgentLifecycleState::Active;
    active.authorized_event_ref =
        Some("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned());
    assert!(agent_record_reserves_selector_slug(&active, &now));

    let mut paused = active.clone();
    paused.state = AgentLifecycleState::Paused;
    assert!(agent_record_reserves_selector_slug(&paused, &now));

    // A never-keyed agent reserves the slug only while its bootstrap handle
    // is still live.
    let pending_future = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2026-07-08T00:00:00.000Z",
    );
    assert!(agent_record_reserves_selector_slug(&pending_future, &now));

    let pending_expired = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2026-07-06T00:00:00.000Z",
    );
    assert!(!agent_record_reserves_selector_slug(&pending_expired, &now));

    // A never-keyed agent whose bootstrap window lapsed (active intent, no
    // key, no live handle) releases the slug for a fresh provision.
    let mut bootstrap_lapsed = agent_record(AGENT_CORE, CONTROLLER_CORE);
    bootstrap_lapsed.state = AgentLifecycleState::Active;
    assert!(!agent_record_reserves_selector_slug(
        &bootstrap_lapsed,
        &now
    ));

    // Deactivation is terminal.
    let mut deactivated = active;
    deactivated.state = AgentLifecycleState::Deactivated;
    assert!(!agent_record_reserves_selector_slug(&deactivated, &now));
}

#[test]
fn agent_pairing_token_decodes_compact_request_and_code() {
    let token = URL_SAFE_NO_PAD.encode(br#"{"r":"agent_pairing_request:0193","c":"12345678"}"#);

    assert!(is_agent_pairing_token_shape(&token));
    let decoded = decode_agent_pairing_token(&token).expect("decode token");

    assert_eq!(decoded["r"], json!("agent_pairing_request:0193"));
    assert_eq!(decoded["c"], json!("12345678"));
}

#[test]
fn controller_binding_accepts_agent_controller() {
    let session = test_session(CONTROLLER_CORE);
    let record = agent_record(AGENT_CORE, CONTROLLER_CORE);

    ensure_agent_record_controller(&record, AGENT_CORE, &session)
        .expect("controller session must operate its agent");
}

#[test]
fn controller_binding_rejects_non_controller() {
    let session = test_session("ak:did_core:web:mallory.example");
    let record = agent_record(AGENT_CORE, CONTROLLER_CORE);

    let err = ensure_agent_record_controller(&record, AGENT_CORE, &session)
        .expect_err("non-controller session must be rejected");

    assert_eq!(err.wire_code(), "capability_denied");
}

#[test]
fn key_authorize_event_binds_pairing_transcript_and_scope() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );

    ensure_pairing_request_open(&record).expect("pending pairing should be open");
    ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect("matching authorize_event should pass");
}

#[test]
fn key_pair_proof_of_possession_verifies_runtime_key() {
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let body = key_pair_request_body(AGENT_DID, verification_method, service_id);
    let record = pending_pairing_record(
        agent,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );

    verify_runtime_key_pair_proof_of_possession(&body, &record, agent, service_id)
        .expect("runtime PoP must verify");
}

#[test]
fn runtime_approval_request_for_controller_omits_pairing_code() {
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let key_pair = key_pair_request_body(AGENT_DID, verification_method, service_id);
    let request = AgentRuntimeApprovalRequestBody {
        pairing_code: arkret_wire::NonEmptyString::new("12345678").unwrap(),
        pairing_request_id: key_pair.pairing_request_id.clone(),
        agent_id: key_pair.agent_id.clone(),
        verification_method: key_pair.verification_method.clone(),
        public_key: key_pair.public_key.clone(),
        proof_of_possession: key_pair.proof_of_possession.clone(),
        runtime_attestation: None,
    };

    let controller_request = runtime_key_request_for_controller(&request);

    assert_eq!(
        controller_request.pairing_request_id,
        key_pair.pairing_request_id
    );
    assert_eq!(
        controller_request.verification_method.as_str(),
        verification_method,
    );
}

#[test]
fn agent_key_state_projects_pending_runtime_approval() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    record.approval_request_id =
        Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());
    record.approval_requested_at = Some(
        chrono::DateTime::parse_from_rfc3339("2026-07-08T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    let runtime_request = key_pair_request_body(
        AGENT_DID,
        "did:web:agent.example#runtime-key-1",
        SERVICE_CORE,
    );
    record.runtime_key_request = Some(
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
            pairing_request_id: runtime_request.pairing_request_id,
            agent_id: runtime_request.agent_id,
            verification_method: runtime_request.verification_method,
            public_key: runtime_request.public_key,
            proof_of_possession: runtime_request.proof_of_possession,
            runtime_attestation: runtime_request.runtime_attestation,
        },
    );

    let key_state =
        agent_key_state_from_record(&record, Vec::new(), AgentRuntimeState::PendingRuntimeKey)
            .expect("key state projection");

    assert_eq!(
        key_state.approval_request_id.as_deref(),
        Some("agent_runtime_approval:01999999")
    );
    assert_eq!(
        key_state
            .pending_runtime_key_request
            .as_ref()
            .map(|request| request.verification_method.as_str()),
        Some("did:web:agent.example#runtime-key-1")
    );
    assert_eq!(
        key_state.approval_requested_at,
        record.approval_requested_at
    );
    assert_eq!(key_state.pairing_code.as_deref(), Some("12345678"));
}

fn status_request_body(
    pairing_code: &str,
    agent_id: &str,
) -> AgentRuntimeApprovalStatusRequestBody {
    AgentRuntimeApprovalStatusRequestBody {
        pairing_request_id: arkret_wire::OpaqueLocalId::new(
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
        )
        .unwrap(),
        pairing_code: pairing_code.to_owned(),
        agent_id: DidCoreId::new(agent_id.to_owned()).unwrap(),
    }
}

fn status_now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-07-10T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

#[test]
fn runtime_approval_status_reports_pending_request() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    record.approval_request_id =
        Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());

    let outcome = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("12345678", AGENT_CORE),
        status_now(),
    )
    .expect("pending status must resolve");

    assert_eq!(outcome.status, AgentLifecycleState::Active);
    assert_eq!(outcome.runtime_state, AgentRuntimeState::PendingRuntimeKey);
    assert_eq!(
        outcome.approval_request_id.as_deref(),
        Some("agent_runtime_approval:01999999")
    );
    assert!(outcome.authorized_event_ref.is_none());
    assert!(outcome.authorized_public_key_digest.is_none());
}

#[test]
fn runtime_approval_status_reports_authorized_key_binding_after_approval() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    record.state = AgentLifecycleState::Active;
    // Approval consumes the pairing handle (activation stamps
    // paired_pairing_request_id), so runtime_state derives to ready.
    record.paired_pairing_request_id = record.pairing_request_id.clone();
    let signing_key_binding =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-1", SERVICE_CORE)
            .signing_key_binding;
    record.authorized_event_ref =
        Some(signing_key_binding.agent_key_authorize_event_id.to_string());
    record.authorized_verification_method =
        Some(signing_key_binding.verification_method.to_string());
    record.authorized_public_key_digest = Some(signing_key_binding.public_key_digest.to_string());
    record.authorized_signing_key_binding = Some(signing_key_binding.clone());

    let outcome = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("12345678", AGENT_CORE),
        status_now(),
    )
    .expect("approved status must resolve");

    assert_eq!(outcome.status, AgentLifecycleState::Active);
    assert_eq!(outcome.runtime_state, AgentRuntimeState::Ready);
    assert!(outcome.approval_request_id.is_none());
    assert_eq!(
        outcome.authorized_event_ref.as_ref().map(|id| id.as_str()),
        Some(signing_key_binding.agent_key_authorize_event_id.as_str())
    );
    assert_eq!(
        outcome.authorized_verification_method.as_deref(),
        Some("did:web:agent.example#runtime-1")
    );
    assert_eq!(
        outcome.authorized_public_key_digest.as_deref(),
        Some(signing_key_binding.public_key_digest.as_str())
    );
    assert_eq!(
        outcome.authorized_signing_key_binding,
        Some(signing_key_binding)
    );
}

#[test]
fn runtime_approval_status_does_not_report_previous_binding_for_replacement() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    record.state = AgentLifecycleState::Active;
    record.paired_pairing_request_id = Some(
        arkret_wire::OpaqueLocalId::new(
            "agent_pairing_request:01988888-0000-7000-8000-00000000feed",
        )
        .unwrap(),
    );
    let previous_binding =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-1", SERVICE_CORE)
            .signing_key_binding;
    record.authorized_event_ref = Some(previous_binding.agent_key_authorize_event_id.to_string());
    record.authorized_verification_method = Some(previous_binding.verification_method.to_string());
    record.authorized_public_key_digest = Some(previous_binding.public_key_digest.to_string());
    record.authorized_signing_key_binding = Some(previous_binding);

    let outcome = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("12345678", AGENT_CORE),
        status_now(),
    )
    .expect("replacement status must resolve");

    assert_eq!(outcome.status, AgentLifecycleState::Active);
    assert_eq!(outcome.runtime_state, AgentRuntimeState::Replacing);
    assert!(outcome.authorized_event_ref.is_none());
    assert!(outcome.authorized_verification_method.is_none());
    assert!(outcome.authorized_public_key_digest.is_none());
    assert!(outcome.authorized_signing_key_binding.is_none());
}

#[test]
fn runtime_approval_status_lazily_reports_expired_open_pairing() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2026-07-09T00:00:00.000Z",
    );
    record.approval_request_id =
        Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());

    let outcome = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("12345678", AGENT_CORE),
        status_now(),
    )
    .expect("expired status must resolve");

    assert_eq!(outcome.status, AgentLifecycleState::Active);
    assert_eq!(outcome.runtime_state, AgentRuntimeState::PairingExpired);
    assert!(outcome.approval_request_id.is_none());
    assert!(outcome.authorized_event_ref.is_none());
}

#[test]
fn runtime_approval_status_mismatch_is_indistinguishable_from_missing_record() {
    let record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let missing = agent_pairing_not_found();

    let wrong_code = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("00000000", AGENT_CORE),
        status_now(),
    )
    .expect_err("wrong pairing code must fail closed");
    let wrong_principal = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("12345678", "ak:did_core:web:intruder.example"),
        status_now(),
    )
    .expect_err("wrong principal must fail closed");

    assert_eq!(wrong_code.wire_code(), missing.wire_code());
    assert_eq!(wrong_principal.wire_code(), missing.wire_code());
    assert_eq!(wrong_code.to_string(), missing.to_string());
    assert_eq!(wrong_principal.to_string(), missing.to_string());
}

#[test]
fn key_pair_rejects_wrong_pairing_request_id() {
    let record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );

    let err = ensure_pairing_request_id_matches(
        &record,
        "agent_pairing_request:01999999-0000-7000-8000-00000000bad1",
    )
    .expect_err("wrong pairing request must fail closed");

    assert_eq!(err.wire_code(), "failed_precondition");
}

#[test]
fn key_authorize_event_rejects_wrong_pairing_code_digest() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );
    let mut mismatched_record = record.clone();
    mismatched_record.pairing_code = Some("87654321".to_owned());

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &mismatched_record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("wrong pairing code must change the expected digest");

    assert_eq!(err.wire_code(), "param_invalid");
    assert!(err.message.contains("request_canonical_digest"));
}

#[test]
fn key_authorize_event_rejects_wrong_controller_executor() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let envelope = key_authorize_envelope(
        &mut record,
        "ak:did_core:web:mallory.example",
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("authorize_event executor must match authenticated controller");

    assert_eq!(err.wire_code(), "capability_denied");
    assert!(err.message.contains("executed_by"));
}

#[test]
fn key_authorize_event_rejects_wrong_approval_principal() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let mut envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );
    envelope["payload"]["approval_evidence"]["approved_by"] =
        json!("ak:did_core:web:mallory.example");

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("approval evidence must be issued by the authenticated controller");

    assert_eq!(err.wire_code(), "capability_denied");
    assert!(err.message.contains("approved_by"));
}

#[test]
fn key_authorize_event_rejects_expired_pairing() {
    let record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "12345678",
        "2000-01-01T00:00:00.000Z",
    );

    let err =
        ensure_pairing_request_open(&record).expect_err("expired pairing request must fail closed");

    assert_eq!(err.wire_code(), "failed_precondition");
    assert_eq!(
        err.reason_detail.as_deref(),
        Some("pairing request has expired")
    );
}

#[test]
fn key_authorize_event_accepts_narrower_scope_and_rejects_widening() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let expected_scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        expected_scope,
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let weaker_scope = json!({
        "actions": ["ak.self.events.stream.subscribe.v1"],
        "resources": [{ "kind": "service", "service_id": service_id }]
    });
    let envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        weaker_scope,
    );

    ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect("a narrower agent_key_scope must be accepted");

    let widened_scope = json!({
        "actions": ["ak.reaction.add"],
        "resources": [{ "kind": "service", "service_id": service_id }]
    });
    let widened_envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        widened_scope,
    );
    let err = ensure_key_authorize_event_matches_request(
        &widened_envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("agent_key_scope must not exceed provisioned requested_scope");
    assert_eq!(err.wire_code(), "param_invalid");
    assert!(err.message.contains("agent_key_scope"));
}

#[test]
fn key_authorize_event_rejects_wrong_authorization_public_key_digest() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "12345678",
        "2999-01-01T00:00:00.000Z",
    );
    let mut envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );
    envelope["payload"]["public_key_digest"] =
        json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("authorize_event public key digest must bind the raw authorization key");

    assert_eq!(err.wire_code(), "param_invalid");
    assert!(err.message.contains("public_key_digest"));
}
