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

struct ControllerSealSigner {
    did: arkret_identifiers::DidFullId,
    verification_method: arkret_wire::DidUrl,
    signing_key: SigningKey,
}

// v1 has no standalone Move object and therefore no Move signer: a Control Move
// *is* an Event carrying `seal_basis`, and the one signing trait left is
// `PayloadSigner` (`arkret-rust-sdk/crates/wire/src/signer.rs`). Event proposal
// acknowledgements name the controller's device method, while B-model Seals
// name that same device key in canonical `did:key` form; keep those two typed
// signers explicit instead of rewriting either proof after signing.
impl arkret_wire::PayloadSigner for ControllerSealSigner {
    fn signer_did(&self) -> &arkret_identifiers::DidFullId {
        &self.did
    }

    fn verification_method_id(&self) -> &arkret_wire::DidUrl {
        &self.verification_method
    }

    fn sign_payload(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<arkret_wire::PayloadSignature, arkret_wire::WireError> {
        Ok(arkret_wire::PayloadSignature {
            verification_method: self.verification_method.clone(),
            extra: Default::default(),
            payload_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                canonical_bytes,
            ))?,
            created_at: chrono::Utc::now(),
            jws: arkret_signatures::jws::sign_jws_ed25519(canonical_bytes, &self.signing_key)
                .expect("sign managed Agent PCR Seal"),
        })
    }
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
        .map(|write| write.cell.as_str().to_owned())
        .collect()
}

/// Cell projection the SDK bundle verifier needs to recompute the membership
/// frontier claim.
///
/// The verifier no longer trusts a producer effect array to say which cells an
/// Event touched, so it asks the caller for the same registered projection the
/// server used; a fixture that answered anything else would be re-inventing the
/// contract v1 removed.
fn proof_project_cells(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_identifiers::CellRef>, arkret_wire::WireError> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map(|writes| writes.into_iter().map(|write| write.cell).collect())
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
}

async fn fetch_chunked_mls_governance_proof(
    state: &AppState,
    token: &str,
    realm_id: &str,
    mut request_value: Value,
) -> (
    Vec<arkret_models_crypto::MlsGovernanceProofBundle>,
    arkret_models_crypto::MaterializedMlsGovernanceProofBundle,
) {
    let mut frontier_response = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(frontier_response.status_code, Some(StatusCode::OK));
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        frontier_response
            .take_json()
            .await
            .expect("typed Realm Seal frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
        frontier.frontier
    else {
        panic!("Realm frontier must materialize a Seal view");
    };
    let object = request_value
        .as_object_mut()
        .expect("proof request fixture is an object");
    object.insert(
        "trusted_anchor_seal_id".to_owned(),
        Value::String(frontier.seal_id.to_string()),
    );
    object.insert("chunk_index".to_owned(), Value::from(0));
    object.remove("expected_bundle_digest");
    let base_request: arkret_models_crypto::MlsGovernanceProofRequestBody =
        serde_json::from_value(request_value).expect("typed chunk-0 proof request");
    let base_request_body = arkret_canonical::canonical_json_bytes(&base_request)
        .expect("canonical chunk-0 proof request");

    let mut first_response =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(base_request_body)
            .send(&app_from_state(state.clone()))
            .await;
    let first_status = first_response.status_code.expect("proof status");
    let first_body: Value = first_response.take_json().await.expect("proof body");
    assert_eq!(first_status, StatusCode::OK, "proof response: {first_body}");
    let first: arkret_models_crypto::MlsGovernanceProofBundle =
        serde_json::from_value(first_body).expect("typed proof chunk 0");
    let mut chunks = vec![first.clone()];
    for chunk_index in 1..first.chunk_manifest.chunk_count {
        let mut request = base_request.clone();
        request.chunk_index = chunk_index;
        request.expected_bundle_digest = Some(first.bundle_digest.clone());
        let request_body = arkret_canonical::canonical_json_bytes(&request)
            .expect("canonical proof chunk request");
        let mut response =
            TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
                .add_header("authorization", format!("Bearer {token}"), true)
                .add_header("content-type", "application/json", true)
                .body(request_body)
                .send(&app_from_state(state.clone()))
                .await;
        let status = response.status_code.expect("proof chunk status");
        let body: Value = response.take_json().await.expect("proof chunk body");
        assert_eq!(status, StatusCode::OK, "proof chunk response: {body}");
        chunks.push(serde_json::from_value(body).expect("typed proof chunk"));
    }
    let materialized =
        arkret_models_crypto::assemble_mls_governance_proof_chunks(&base_request, &chunks)
            .expect("complete proof chunks assemble");
    (chunks, materialized)
}

// ── Agent SessionGrant + DPoP fixture ────────────────────────────────────────
//
// A managed-Agent session is only ever admitted as a typed SessionGrant
// presented together with a DPoP proof (`enforce_agent_session_authority`), so
// a locally seeded bearer SessionRecord can no longer stand in for one. The
// fixture below runs the real prepare/commit provisioning ceremony over HTTP,
// then writes the runtime-key activation through the storage port: the public
// pairing ceremony is currently not executable end-to-end
// (`verify_principal_authorized_jws_ed25519_async` is an unconditional stub,
// and `submit_agent_runtime_key_request` compares a full DID against a core
// id). Every binding digest and the controller-proof JWS are still produced by
// the real SDK functions, so the chain under test — introspection, DPoP
// binding, Agent authority enforcement, scope gate — stays fully real.

/// A presented Agent SessionGrant: the bearer JWT plus the holder (DPoP) key
/// the introspected grant's `cnf_jkt` is bound to.
struct AgentGrantPresentation {
    grant_jwt: String,
    holder_key: SigningKey,
}

/// Build the `Authorization`/`DPoP` header pair for one request. `htu` is the
/// configured origin plus the bare path — the query string is excluded, exactly
/// as the server's verifier reconstructs it.
fn agent_grant_headers(
    presentation: &AgentGrantPresentation,
    method: &str,
    path: &str,
) -> (String, String) {
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new(method, format!("http://server{path}"))
            .access_token(presentation.grant_jwt.clone()),
        &presentation.holder_key,
    )
    .expect("DPoP proof builds");
    (
        format!("Bearer {}", presentation.grant_jwt),
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

/// Provision a managed Agent through the real ceremony, activate its runtime
/// key through the storage port, and stand up a session-grant introspection
/// mock that vouches for a grant scoped to exactly `granted_scopes`.
async fn seed_agent_grant_session(
    slug: &str,
    granted_scopes: &[&str],
) -> (AppState, AgentGrantPresentation) {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("introspection mock binds");
    let mut config = test_config();
    config.session_grant_introspection_url = Some(format!(
        "http://{}/_arkret/admin/session-grants/introspect",
        listener.local_addr().expect("mock address")
    ));
    config.session_grant_introspection_bearer = Some(format!("introspection-bearer-{slug}"));
    let state = soland_test_support::app_state(config);

    let controller = "did:web:alice.example";
    let controller_token = format!("agent-grant-controller-{slug}");
    super::agents::seed_controller_session(&state, &controller_token, controller).await;
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
                "ak.self.events.stream.subscribe",
                "ak.self.events.read.scan",
                "ak.self.events.command.submit"
            ],
            "resources": [
                {"kind": "operation", "operation": "ak.self.events.stream.subscribe"},
                {"kind": "operation", "operation": "ak.self.events.read.scan"},
                {"kind": "operation", "operation": "ak.self.events.command.submit"}
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
        &outcome.full_id,
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
        controller_account_id: new_prefixed_uuid7("ak:account:"),
        recipient_service_id: state.service_id().clone(),
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
    let authorize_event_id = arkret_identifiers::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        Sha256::digest(format!("agent-key-authorize-{slug}").as_bytes()).into(),
    );
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
    let mut signing_key_binding =
        arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding {
            core: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBindingCore {
                schema: arkret_wire::NonEmptyString::new(
                    arkret_wire::SchemaId::AGENT_SIGNING_KEY_BINDING_V1,
                )
                .unwrap(),
                agent_id: outcome.agent_id.clone(),
                agent_key_id: arkret_wire::NonEmptyString::new("agent-runtime-key").unwrap(),
                verification_method: verification_method.clone(),
                public_key,
                public_key_digest: public_key_digest.clone(),
                issued_at: now,
                expires_at: None,
                controller_id: controller_core.clone(),
            },
            agent_key_authorize_event_id: authorize_event_id.clone(),
            controller_proof: arkret_models_identity::agent_signer_evidence::AgentControllerProof {
                kind: arkret_wire::NonEmptyString::new("detached_jws").unwrap(),
                verification_method: arkret_wire::DidUrl::new(format!(
                    "{controller}#{}",
                    super::agents::CONTROLLER_DEVICE_ID
                ))
                .unwrap(),
                jws: arkret_wire::NonEmptyString::new("pending").unwrap(),
            },
        };
    let controller_proof_bytes =
        arkret_signatures::agent_evidence::agent_signing_key_binding_signing_bytes(
            &signing_key_binding,
        )
        .unwrap();
    signing_key_binding.controller_proof.jws = arkret_wire::NonEmptyString::new(
        arkret_signatures::jws::sign_jws_ed25519(
            &controller_proof_bytes,
            &SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED),
        )
        .expect("controller proof JWS signs"),
    )
    .unwrap();
    let paired_request_digest =
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
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
            "issuer": "ak:did_core:web:coauth.local",
            "subject": outcome.agent_id.as_str(),
            "service_account_id": format!("agent-{slug}"),
            "audience": state.service_id(),
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
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let response_body = response_body.clone();
            tokio::spawn(async move {
                let _ = read_introspection_request(&mut stream).await;
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
    assert_eq!(body["ok"], false, "{body}");
    assert_eq!(body["error"]["code"], "capability_denied", "{body}");
    assert!(
        body["error"]["message"]
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

#[tokio::test]
async fn agent_session_without_stream_scope_cannot_subscribe_events() {
    let (state, presentation) =
        seed_agent_grant_session("scope-denied-stream", &["ak.self.events.read.scan"]).await;
    let subscribe_url = format!(
        "http://server/_arkret/self/events/subscribe?realms={}&catchup=false&max_duration_ms=100",
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

    let (authorization, dpop) =
        agent_grant_headers(&presentation, "GET", "/_arkret/self/events/subscribe");
    let mut response = TestClient::get(subscribe_url)
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.stream.subscribe");
}

#[tokio::test]
async fn agent_session_without_query_scope_cannot_scan_events() {
    let (state, presentation) =
        seed_agent_grant_session("scope-denied-query", &["ak.self.events.stream.subscribe"]).await;

    // Same 401 discriminator as the subscribe test: grant without DPoP.
    let unauthenticated = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realms": [demo_realm_id()]}))
        .add_header(
            "authorization",
            format!("Bearer {}", presentation.grant_jwt),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let (authorization, dpop) = agent_grant_headers(&presentation, "QUERY", "/_arkret/self/events");
    let mut response = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realms": [demo_realm_id()]}))
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.read.scan");
}

#[tokio::test]
async fn agent_session_without_submit_scope_cannot_submit_events() {
    let (state, presentation) =
        seed_agent_grant_session("scope-denied-submit", &["ak.self.events.read.scan"]).await;
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

    let (authorization, dpop) = agent_grant_headers(&presentation, "POST", "/_arkret/self/events");
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .json(&event)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.command.submit");
}

#[tokio::test]
async fn pg_account_subscribe_cursor_handle_survives_app_state_rebuild() {
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

#[tokio::test]
async fn memory_account_subscribe_cursor_handle_does_not_survive_app_state_rebuild() {
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
    assert_eq!(rejected["error"]["code"], "cursor_integrity_invalid");
}

#[tokio::test]
async fn events_describe_and_single_event_submit_work() {
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
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ak.self.events.command.submit")
    );
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
            fixture_actor_core_id("did:web:alice.example").as_str(),
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
            "created_by": fixture_actor_core_id("did:web:alice.example"),
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
    assert_eq!(unknown_schema_body["error"]["code"], "unknown_schema");

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

    // `max_resolve` is one budget across every selector kind: Seal selectors
    // spend from the same 100 as ids and digests rather than riding along free.
    let event_ids: Vec<String> = (0..arkret_wire::MAX_EVENT_RESOLVE)
        .map(|_| soland_test_support::fixture_content_bound_id("ak:event:"))
        .collect();
    let mut over_budget = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": event_ids,
            "seal_refs": [format!("ak:seal:sha256:{}", "1".repeat(64))]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let over_budget_body: Value = over_budget.take_json().await.unwrap();
    assert_eq!(over_budget_body["error"]["code"], "quota_exceeded");

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
            "actors": [fixture_actor_core_id("did:web:alice.example")],
            "limit": 20
        }))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // Alice authored three Events here after the ordinary Realm's eight-Event
    // closed bootstrap unit and the PCR create/authorize pair projected by
    // `dev_token` for strict principal-device proof verification.
    let listed_events = listed["events"].as_array().unwrap();
    assert_eq!(listed_events.len(), 13);
    assert_eq!(listed_events[0]["kind"], "ak.realm.create");
    assert!(!listed["has_more"].as_bool().unwrap_or(false));
    assert_eq!(
        listed_events.last().unwrap()["event_id"],
        artifact_kind_event_id
    );

    // Actor selector → spec actor frontier `{actor_id, actor_seq, event_id}`.
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({
                "actor_id": fixture_actor_core_id("did:web:alice.example")
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
        fixture_actor_core_id("did:web:alice.example")
    );
    assert_eq!(frontier.realms.len(), 2);
    let demo_frontier = frontier
        .realms
        .iter()
        .find(|frontier| frontier.realm_id.as_str() == demo_realm_id())
        .expect("actor aggregate includes demo Realm frontier");
    assert_eq!(demo_frontier.next_actor_seq, 11);
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
    let mut seal_view_response = TestClient::query("http://server/_arkret/self/events/frontier")
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
    assert_eq!(seal_view["error"]["code"], "not_found");
    assert_eq!(
        seal_view["error"]["message"],
        "realm has no accepted Seal on this deployment"
    );

    // Inaccessible realm must read as not_found (no existence leak).
    let mut hidden = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({
            "realm_id": "ak:realm:AeqRpQIZxaoTV-G0Cl9jzAJ6wSak3GJUvizlNJRsvSFY"
        }))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(hidden.status_code.unwrap(), StatusCode::NOT_FOUND);
    let hidden_body: Value = hidden.take_json().await.unwrap();
    assert_eq!(hidden_body["error"]["code"], "not_found");
}

#[tokio::test]
async fn realm_create_genesis_unit_projects_five_cells_without_seal_basis() {
    let state = soland_test_support::app_state(test_config());
    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
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
        &actor,
        state.service_id(),
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
    // A create that cannot establish an authority root is not a Realm anybody
    // could govern, so `realm-and-space.md` §2.5 makes the whole atomic unit
    // roll back rather than materialize an ownerless Realm. The
    // create-locked `capability_action_registry_digest` is the value
    // projection's only non-literal input, so removing it is the minimal way
    // to reach that state.
    let mut rootless_payload = payload.clone();
    rootless_payload["object"]
        .as_object_mut()
        .expect("create payload object")
        .remove("capability_action_registry_digest");
    let rootless_create = soland_test_support::signed_event::CallerSignedEvent::realm_genesis(
        &actor,
        "01904100-0000-7000-8000-a11ce0000001",
        rootless_payload,
    )
    .build();
    let rootless_realm_id = RealmId::from_event_id(&rootless_create.event_id).to_string();
    let mut rootless_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "events": [arkret_wire::EventInitialSubmission::online(rootless_create)]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let rootless_status = rootless_response.status_code.expect("rootless status");
    let rootless_body: Value = rootless_response.take_json().await.expect("rootless body");
    assert_eq!(
        rootless_status,
        StatusCode::PRECONDITION_FAILED,
        "unexpected rootless-create response: {rootless_body}"
    );
    assert_eq!(rootless_body["reason"], "realm_authority_root_missing");
    assert!(
        state
            .test_persistence()
            .events()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .all(|record| record.realm_id.as_deref() != Some(rootless_realm_id.as_str())),
        "a genesis without an authority root must leave no canonical Event"
    );

    let profile = serde_json::to_value(&bootstrap_unit[1]).unwrap();
    let policy = serde_json::to_value(&bootstrap_unit[2]).unwrap();
    let join_rule = serde_json::to_value(&bootstrap_unit[3]).unwrap();
    let history_visibility = serde_json::to_value(&bootstrap_unit[4]).unwrap();
    let discovery = serde_json::to_value(&bootstrap_unit[5]).unwrap();
    let delivery_binding = serde_json::to_value(&bootstrap_unit[6]).unwrap();
    let member_state = serde_json::to_value(&bootstrap_unit[7]).unwrap();

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
        history_visibility.clone(),
        discovery.clone(),
        delivery_binding.clone(),
        malformed_member_state,
    ]);
    let mut mismatch_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"events": mismatch_submissions}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mismatch_response.status_code, Some(StatusCode::BAD_REQUEST));
    let mismatch_body: Value = mismatch_response.take_json().await.unwrap();
    assert_eq!(mismatch_body["error"]["code"], "schema_violation");
    assert!(
        mismatch_body["error"]["message"]
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
            .member(&realm_id, actor_core.as_str())
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
                history_visibility.clone(),
                discovery.clone(),
                delivery_binding.clone(),
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
    assert_eq!(body["accepted"][7], member_state["event_id"]);
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, actor_core.as_str())
            .is_some_and(|member| member.state == "join")
    );
    {
        let projection = state.test_projection().lock();
        let authority_root = projection
            .realm_authority_root(&realm_id)
            .expect("accepted genesis must register the Realm authority-root cell");
        assert!(
            authority_root.is_genesis_for(actor_core.as_str()),
            "the authority root's controller is the Realm creator at epoch/generation 0"
        );
        assert_eq!(
            authority_root.capability_action_registry_digest,
            arkret_policy::current_capability_action_registry_digest().unwrap(),
            "the root copies the signed create payload's registry basis verbatim"
        );
        assert!(
            projection.actor_holds_effective_realm_owner(
                &realm_id,
                actor_core.as_str(),
                actor_core.as_str(),
                chrono::Utc::now(),
            ),
            "the authority-root controller holds effective ak.realm.owner"
        );
        assert!(
            !projection.actor_holds_effective_realm_owner(
                &realm_id,
                fixture_actor_core_id("did:web:mallory.example").as_str(),
                fixture_actor_core_id("did:web:mallory.example").as_str(),
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
                arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1,
                serde_json::json!({"value": "joined"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
                serde_json::json!({"value": "invite_only"}),
            ),
        ] {
            assert_eq!(
                projection.realm_null_subject_cell_value(&realm_id, family),
                Some(&expected)
            );
        }
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
        "the local Principal Server must publish its current service resolution before it can be a join candidate"
    );
    let _: Value = describe_response
        .take_json()
        .await
        .expect("service description response");

    let candidate_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let resolve_body = loop {
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
        if resolve_body["join_candidates"].as_array().map(Vec::len) == Some(1) {
            break resolve_body;
        }
        assert!(
            tokio::time::Instant::now() < candidate_deadline,
            "the configured Realm notary did not finalize a join candidate: {resolve_body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        resolve_body["realm_preview"]["title"], "Bootstrap effects realm",
        "Directory/sidebar projection must expose the title, not the Realm id: {resolve_body}"
    );
    control_seal_coordinator.abort();

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
            .member(&realm_id, actor_core.as_str())
            .is_some_and(|member| member.state == "join"),
        "restart must rebuild creator membership from canonical create"
    );
    {
        let restarted_projection = restarted.test_projection().lock();
        assert!(
            restarted_projection
                .realm_authority_root(&realm_id)
                .is_some_and(|root| root.is_genesis_for(actor_core.as_str())),
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
                arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1,
                serde_json::json!({"value": "joined"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
                serde_json::json!({"value": "invite_only"}),
            ),
        ] {
            assert_eq!(
                restarted_projection.realm_null_subject_cell_value(&realm_id, family),
                Some(&expected),
                "restart must rebuild bootstrap cell {family}"
            );
        }
    }

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1"
    });
    let (_, bundle) =
        fetch_chunked_mls_governance_proof(&state, &token, &realm_id, proof_request).await;
    assert_eq!(bundle.realm_id.as_str(), realm_id);
    assert_eq!(
        bundle
            .frontier_events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        bootstrap_unit
            .iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    arkret_wire::EventKind::RealmCreate | arkret_wire::EventKind::MemberState
                )
            })
            .map(|event| event.event_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        "RealmCreate's derived creator membership and the explicit creator membership Event are both key-access frontier Events"
    );
    let request = arkret_models_crypto::MlsGovernanceProofRequestBody {
        realm_id: arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        effective_scope: arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        },
        mls_group_id: "YXJrcmV0LW1scy1wcm9vZi10ZXN0".to_owned(),
        previous_epoch: 0,
        next_epoch: 1,
        binding_profile: "ak.profile.mls_governance_binding.full.v1".to_owned(),
        reducer_profile: "ak.reducer.core.v1".to_owned(),
        trusted_anchor_seal_id: bundle.trusted_anchor_seal_id.clone(),
        chunk_index: 0,
        expected_bundle_digest: None,
    };
    let leaves = vec![arkret_models_crypto::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        principal_id: arkret_wire::project_full_id_to_core_id(
            &arkret_identifiers::DidFullId::new(actor.clone()).unwrap(),
        )
        .unwrap(),
        credential_ref: arkret_wire::NonEmptyString::new(format!(
            "{actor}#ak:device:01904100-0000-7000-8000-a11ce0000001"
        ))
        .unwrap(),
    }];
    let materialized =
        arkret_state::mls_governance_proof::verify_mls_governance_proof_materialization::<
            arkret_wire::WireError,
            _,
            _,
            _,
        >(
            &bundle,
            &request,
            &bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            proof_project_cells,
            &leaves,
        )
        .expect("a basis-exempt genesis frontier materializes");
    let expected_binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        0,
        1,
        materialized.security_frontier_digest,
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.core.v1",
    )
    .unwrap();

    // A §5 anchor unit verifies as a governance-proof frontier.
    //
    // The only membership-frontier Event of a freshly bootstrapped Realm is its
    // `ak.realm.create`, which `authz/event-auth-state-resolution.md` §5
    // requires to carry no CBA basis field at all.
    // `crypto-media/encryption-and-audit.md` §2.5.1.1 step 6 is the closed list
    // of what a verifier owes each frontier Event — recompute the producer
    // digest, verify the proofs, confirm digest inclusion in the covered set,
    // confirm the control-plane family, confirm Realm and scope — and a
    // `seal_basis` presence test is not among them. What step 6 does require is
    // that the Event is control-plane, which the projected cell family below
    // establishes and a `seal_ref` would disprove.
    arkret_state::mls_governance_proof::verify_mls_governance_proof_bundle::<
        arkret_wire::WireError,
        _,
        _,
        _,
    >(
        &bundle,
        &expected_binding,
        &bundle.trusted_anchor_seal_id,
        |_| Ok(()),
        |_| Ok(()),
        proof_project_cells,
        &leaves,
    )
    .expect("a basis-exempt genesis frontier Event verifies");
}

#[tokio::test]
async fn canonical_control_event_materializes_verifiable_mls_governance_proof() {
    let state = soland_test_support::app_state(test_config());
    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let actor = test_event_signer_did().to_owned();
    let actor_core = fixture_actor_core_id(&actor);
    let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let token =
        verified_dev_token_for_device(state.clone(), &actor, device_id, "Governance Founder").await;
    let (realm_id, bootstrap_unit) =
        authored_ordinary_realm_bootstrap_unit(&state, &actor, device_id, "Governance proof Realm");
    let bootstrap_frontier_event_id = bootstrap_unit
        .last()
        .expect("bootstrap unit has a frontier Event")
        .event_id
        .to_string();
    let mut create_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "events": bootstrap_unit
                .iter()
                .cloned()
                .map(arkret_wire::EventInitialSubmission::online)
                .collect::<Vec<_>>()
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let create_status = create_response.status_code.expect("genesis status");
    let create_body: Value = create_response.take_json().await.expect("genesis body");
    assert!(
        matches!(create_status, StatusCode::OK | StatusCode::CREATED),
        "real Realm genesis failed with {create_status}: {create_body}"
    );

    let genesis_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let genesis_basis = loop {
        let mut response = TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        if response.status_code == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                response.take_json().await.expect("typed genesis frontier");
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                frontier.frontier
            else {
                panic!("Realm-only selector returned the wrong frontier variant");
            };
            break frontier.seal_basis();
        }
        assert!(
            tokio::time::Instant::now() < genesis_deadline,
            "real Realm genesis was not sealed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let mut envelope = signed_canonical_event(
        &event_id,
        arkret_wire::EventKind::MemberState.as_str(),
        &actor,
        device_id,
        &realm_id,
        8,
        vec![&bootstrap_frontier_event_id],
        serde_json::json!({
            "realm_id": realm_id,
            "actor_id": actor_core,
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    );
    envelope["seal_basis"] = serde_json::to_value(&genesis_basis).unwrap();
    resign_canonical_event(&mut envelope);
    assert_eq!(
        projected_cell_targets(&envelope),
        std::collections::BTreeSet::from([format!(
            "ak:cell:ak.component.member.state.v1:{actor_core}"
        )]),
        "ak.member.state must derive exactly the subject's membership cell"
    );
    let mut event_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&envelope)
        .send(&app_from_state(state.clone()))
        .await;
    let event_status = event_response.status_code.expect("Control Move status");
    let event_body: Value = event_response.take_json().await.expect("Control Move body");
    assert!(
        matches!(event_status, StatusCode::OK | StatusCode::CREATED),
        "real Control Move failed with {event_status}: {event_body}"
    );

    let seal_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut response = TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        if response.status_code == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                response.take_json().await.expect("typed Control frontier");
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                frontier.frontier
            else {
                panic!("Realm-only selector returned the wrong frontier variant");
            };
            if frontier.seal_basis().leaves != genesis_basis.leaves {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < seal_deadline,
            "real Control Move was not sealed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1"
    });
    let (proof_chunks, bundle) =
        fetch_chunked_mls_governance_proof(&state, &token, &realm_id, proof_request.clone()).await;
    let mut valid_request_value = proof_request.clone();
    valid_request_value["trusted_anchor_seal_id"] =
        Value::String(bundle.trusted_anchor_seal_id.to_string());
    valid_request_value["chunk_index"] = Value::from(0);
    let valid_request: arkret_models_crypto::MlsGovernanceProofRequestBody =
        serde_json::from_value(valid_request_value).expect("typed proof request");
    let leaves = vec![arkret_models_crypto::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        principal_id: arkret_wire::project_full_id_to_core_id(
            &arkret_identifiers::DidFullId::new(actor.clone()).unwrap(),
        )
        .unwrap(),
        credential_ref: arkret_wire::NonEmptyString::new(format!("{actor}#{device_id}")).unwrap(),
    }];
    let materialized =
        arkret_state::mls_governance_proof::verify_mls_governance_proof_materialization::<
            arkret_wire::WireError,
            _,
            _,
            _,
        >(
            &bundle,
            &valid_request,
            &bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            proof_project_cells,
            &leaves,
        )
        .expect("server proof materializes with SDK");
    let expected_binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        0,
        1,
        materialized.security_frontier_digest,
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.core.v1",
    )
    .unwrap();
    let verified = arkret_state::mls_governance_proof::verify_mls_governance_proof_bundle::<
        arkret_wire::WireError,
        _,
        _,
        _,
    >(
        &bundle,
        &expected_binding,
        &bundle.trusted_anchor_seal_id,
        |_| Ok(()),
        |_| Ok(()),
        proof_project_cells,
        &leaves,
    )
    .expect("server proof verifies with SDK");
    assert_eq!(verified.accepted_seal_id, bundle.accepted_seal_id);

    let mut unreachable_request = valid_request.clone();
    unreachable_request.trusted_anchor_seal_id =
        arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "ff".repeat(32))).unwrap();
    let unreachable_request_bytes =
        arkret_canonical::canonical_json_bytes(&unreachable_request).unwrap();
    let mut unreachable =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(unreachable_request_bytes)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(unreachable.status_code, Some(StatusCode::CONFLICT));
    let unreachable_body: Value = unreachable.take_json().await.expect("anchor error body");
    assert_eq!(
        unreachable_body["error"]["code"],
        "mls_governance_anchor_unreachable"
    );

    let mut stale_manifest_request = valid_request.clone();
    stale_manifest_request.chunk_index = 1;
    stale_manifest_request.expected_bundle_digest =
        Some(arkret_identifiers::Hash::new(format!("sha256:{}", "ee".repeat(32))).unwrap());
    let stale_manifest_request_bytes =
        arkret_canonical::canonical_json_bytes(&stale_manifest_request).unwrap();
    let mut stale_manifest =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(stale_manifest_request_bytes)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        stale_manifest.status_code,
        Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    let stale_body: Value = stale_manifest
        .take_json()
        .await
        .expect("stale manifest error body");
    assert_eq!(stale_body["error"]["code"], "frontier_unavailable");

    let mut out_of_range_request = valid_request;
    out_of_range_request.chunk_index = proof_chunks[0].chunk_manifest.chunk_count;
    out_of_range_request.expected_bundle_digest = Some(bundle.bundle_digest.clone());
    let out_of_range_request_bytes =
        arkret_canonical::canonical_json_bytes(&out_of_range_request).unwrap();
    let mut out_of_range =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(out_of_range_request_bytes)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(out_of_range.status_code, Some(StatusCode::BAD_REQUEST));
    let out_of_range_body: Value = out_of_range
        .take_json()
        .await
        .expect("chunk range error body");
    assert_eq!(out_of_range_body["error"]["code"], "param_invalid");

    let (_, second_bundle) =
        fetch_chunked_mls_governance_proof(&state, &token, &realm_id, proof_request).await;
    assert_eq!(
        second_bundle.accepted_seal_id, bundle.accepted_seal_id,
        "unchanged Event coverage must reuse the accepted Seal"
    );
    control_seal_coordinator.abort();
}

#[tokio::test]
async fn agent_controller_can_use_managed_pcr_frontier_as_governance_anchor() {
    let state = soland_test_support::app_state(test_config());
    let controller_id = "did:web:alice.example";
    let controller_core_id = fixture_actor_core_id(controller_id);
    let token = "managed-agent-governance-session";
    super::agents::seed_controller_session(&state, token, controller_id).await;
    super::agents::seed_agent_provision_prerequisites(&state, controller_id).await;
    let controller_authority =
        super::agents::seed_active_controller_device_generation(&state, controller_id).await;

    // Agent provisioning is the spec-defined prepare/commit transcript. Reuse
    // the SDK-backed fixture instead of maintaining an obsolete one-shot body
    // in this downstream managed-PCR test.
    let (create_status, create_body) = super::agents::provision_agent_with_sdk_events(
        &state,
        token,
        controller_id,
        &controller_authority,
        "governance-recovery",
        serde_json::json!({
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
        }),
    )
    .await;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "managed Agent create failed: {create_body}"
    );
    let agent_id = create_body["agent_id"]
        .as_str()
        .expect("managed Agent id")
        .to_owned();
    let agent_record = state
        .test_persistence()
        .agents()
        .list_for_controller(controller_core_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.id == agent_id)
        .expect("created managed Agent record");
    let realm_id = agent_record.principal_control_realm_id.clone();
    let create = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .expect("completed managed Agent provisioning has an accepted PCR genesis");
    let created_at = create.created_at;
    let signing_key = SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED);
    let signer = ControllerSealSigner {
        did: arkret_identifiers::DidFullId::new(controller_id).unwrap(),
        verification_method: arkret_wire::DidUrl::new(format!(
            "{controller_id}#{}",
            super::agents::CONTROLLER_DEVICE_ID
        ))
        .unwrap(),
        signing_key: signing_key.clone(),
    };
    let event_verification_method = signer.verification_method.clone();
    let records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .unwrap();
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "managed Agent PCR must start at create");
    let mut frontier_response = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    let frontier_status = frontier_response.status_code.expect("frontier status");
    let frontier_body: Value = frontier_response
        .take_json()
        .await
        .expect("managed PCR frontier body");
    assert_eq!(
        frontier_status,
        StatusCode::OK,
        "managed Agent PCR frontier failed: {frontier_body}"
    );
    let returned_head: arkret_wire::Seal =
        serde_json::from_value(frontier_body["receipts"][0]["seal"].clone())
            .expect("managed PCR frontier signed-head receipt");
    let seal = returned_head;

    // Accepted Events may advance before the controller submits the next
    // device-signed Seal. Frontier must keep returning the accepted signed
    // predecessor (including its full receipt) so the controller can author
    // that successor; it must not ask the service notary to synthesize one.
    // The empty payload this fixture used to carry only worked while the SDK
    // read a producer effect array. `ak.mls.genesis` registers three cell
    // writes keyed on `payload.mls_group_id`, so the successor Seal can only be
    // built over a payload the registered contract can actually evaluate.
    let mut pending = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::MlsGenesis.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(realm_id.clone()).unwrap(),
        },
        arkret_identifiers::DidCoreId::new(agent_id.clone()).unwrap(),
        soland_test_support::fixture_principal_server_id(),
        1,
        arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce2").unwrap(),
        serde_json::json!({
            "mls_group_id": "YXJrcmV0LW1scy1tYW5hZ2VkLXNjcg",
            "epoch": 0,
            "creator_principal_id": agent_id,
            "creator_device_id": super::agents::CONTROLLER_DEVICE_ID,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "governance_binding": {
                "binding_version": 1,
                "encoding_profile": "cbor-deterministic-rfc8949-v1",
                "realm_id": realm_id,
                "effective_scope": {"kind": "realm", "realm_id": realm_id},
                "mls_group_id": "YXJrcmV0LW1scy1tYW5hZ2VkLXNjcg",
                "previous_epoch": 0,
                "next_epoch": 0,
                "security_frontier_digest": format!("sha256:{}", "1".repeat(64)),
                "binding_profile": "ak.profile.mls_governance_binding.full.v1",
                "reducer_profile": "ak.reducer.core.v1"
            }
        }),
    )
    .unwrap();
    pending.created_at = created_at;
    pending.prev_refs = vec![create.event_id.clone()];
    pending.executed_by = Some(controller_core_id);
    pending.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(agent_record.controller_authorization_ref.as_str())
            .unwrap(),
    );
    let mut pending = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        pending,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut pending,
        &signer,
        &event_verification_method,
        arkret_signatures::SignEventOptions {
            domain: None,
            audience: None,
            created_at: Some(created_at),
        },
    )
    .unwrap();
    let pending = pending.into_event();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &pending,
            Some(&realm_id),
            chrono::Utc::now(),
        ))
        .await
        .unwrap();

    let mut lagging_frontier = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(lagging_frontier.status_code, Some(StatusCode::OK));
    let lagging_body: Value = lagging_frontier.take_json().await.unwrap();
    assert_eq!(lagging_body["frontier"]["seal_id"], seal.id.as_str());
    let lagging_head: arkret_wire::Seal =
        serde_json::from_value(lagging_body["receipts"][0]["seal"].clone()).unwrap();
    assert_eq!(lagging_head.id, seal.id);
    assert_eq!(
        lagging_head.control_event_set_root,
        seal.control_event_set_root
    );
    assert_eq!(lagging_head.state_root, seal.state_root);
    assert_eq!(
        lagging_head.covered_event_digests,
        seal.covered_event_digests
    );

    let records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .unwrap();
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .collect::<Vec<_>>();
    let successor = arkret_bootstrap::build_managed_agent_pcr_event_seal(
        &events,
        Some(&lagging_head),
        arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce3").unwrap(),
        &signer,
        &super::agents::genesis_projector,
    )
    .unwrap();
    let successor_body_bytes = arkret_canonical::canonical_json_bytes(&successor)
        .expect("canonical managed Agent PCR successor Seal");
    let mut successor_response = TestClient::post("http://server/_arkret/self/events/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(successor_body_bytes)
        .send(&app_from_state(state.clone()))
        .await;
    let successor_status = successor_response.status_code;
    let successor_body: Value = successor_response.take_json().await.unwrap();
    assert_eq!(successor_status, Some(StatusCode::OK), "{successor_body}");
    assert_eq!(successor_body["seal_id"], successor.id.as_str());
    let trusted_anchor_seal_id = successor.id.to_string();

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1tYW5hZ2VkLXNjcg",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1",
        "trusted_anchor_seal_id": trusted_anchor_seal_id,
        "chunk_index": 0
    });
    let (_, bundle) =
        fetch_chunked_mls_governance_proof(&state, token, &realm_id, proof_request.clone()).await;
    assert_eq!(bundle.realm_id.as_str(), realm_id);
    assert_eq!(
        bundle.trusted_anchor_seal_id.as_str(),
        trusted_anchor_seal_id
    );
    let mut denied_request = proof_request;
    denied_request["trusted_anchor_seal_id"] =
        Value::String(bundle.trusted_anchor_seal_id.to_string());
    denied_request["chunk_index"] = Value::from(0);

    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    let mut denied = TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&denied_request)
        .send(&app_from_state(state))
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::NOT_FOUND));
    let denied_body: Value = denied.take_json().await.expect("denied proof body");
    assert_eq!(denied_body["error"]["code"], "not_found");
}

#[tokio::test]
async fn invite_create_accepts_locator_evidence_digest_without_local_consent() {
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
        "invitee": fixture_actor_core_id("did:web:carol.example"),
        "invite_delivery_target": {
            "recipient_service_id": state.service_id(),
            "service_resolution": {
                "current_record_url": format!(
                    "https://soland.local{}",
                    arkret_models_identity::canonical_service_current_record_path(
                        &arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap()
                    )
                )
            },
            "recipient_service_kind": "principal_server"
        },
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
        projected.invitee.as_deref(),
        Some(fixture_actor_core_id("did:web:carol.example").as_str())
    );
    assert_eq!(
        projected.introduction_evidence_digest.as_deref(),
        payload["introduction_evidence_digest"].as_str()
    );
}

#[tokio::test]
async fn sync_cursor_rejects_facets_and_renderer_changes() {
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
    let changed_filter = serde_json::json!({"realms": [demo_realm_id()]}).to_string();
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

#[tokio::test]
async fn account_subscribe_realms_filter_excludes_out_of_scope_realms() {
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
        &format!("catchup=true&filter=%7B%22realms%22%3A%5B%22{encoded_included_id}%22%5D%7D"),
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

#[tokio::test]
async fn events_query_exposes_prev_cursor_and_limited_timeline_pages() {
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

    let read_body = serde_json::json!({"limit": 1, "actors": [actor_core]});
    let query_page: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&read_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query_page["next_cursor"].as_str().is_some());
    assert_eq!(
        query_page["events"].as_array().unwrap().len(),
        1,
        "expected one Event in the first read page: {query_page}"
    );
    assert_eq!(query_page["has_more"], true);
    assert!(query_page["prev_cursor"].is_null());
    let next_cursor = query_page["next_cursor"].as_str().unwrap();
    assert!(next_cursor.starts_with("ak:cursor:"));

    let second_page: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"limit": 1, "actors": [actor_core], "after": next_cursor}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_page["prev_cursor"], next_cursor);
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);

    let mut invalid_cursor = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actors": [actor],
            "after": "ak:event:AWNDYdZJJKnSYHxTY2Yye1ERF3ydKwe5EXA6UzTu5DAc"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        invalid_cursor.status_code.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(invalid_cursor_body["error"]["code"], "schema_violation");
}

#[tokio::test(start_paused = true)]
async fn incremental_sync_waits_30_seconds_then_returns_frontier() {
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

#[tokio::test(start_paused = true)]
async fn incremental_sync_meta_only_delta_advances_cursor_once() {
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

#[tokio::test]
async fn incremental_sync_emits_realm_with_new_timeline_event() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let message = persist_test_message(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        "incremental wake-up",
    )
    .await;

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
            .any(|event| event["event_id"] == message.event_id),
        "delta MUST include the freshly persisted message: {delta}"
    );
}

#[tokio::test]
async fn account_subscribe_waits_for_broadcast_before_returning_incremental_batch() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let waker_state = state.clone();
    let waker = tokio::spawn(async move {
        // Give the stream a beat to subscribe before we fire.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let message = persist_test_message(
            &waker_state,
            demo_realm_id(),
            "did:web:alice.example",
            "wake up the stream",
        )
        .await;
        let _ = waker_state.test_publish_event_notification(EventNotification::event(
            demo_realm_id().to_owned(),
            message.event_id.clone(),
            serde_json::json!({
                "kind": "ak.message.create",
                "event_id": message.event_id,
                "realm_id": demo_realm_id(),
            }),
        ));
        message
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
            .any(|event| event["event_id"] == message.event_id),
        "woken delta MUST include the wake-up event: {woken}"
    );
}

#[tokio::test]
async fn account_subscribe_omits_ordered_log_loser_and_exposes_conflict_diagnostic() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let actor_seq = 900_000;
    let left = persist_test_message_with_actor_seq(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        "ordered-log left",
        actor_seq,
    )
    .await;
    let right = persist_test_message_with_actor_seq(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        "ordered-log right",
        actor_seq,
    )
    .await;
    let normal = persist_test_message_with_actor_seq(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        "ordered-log normal",
        actor_seq + 1,
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
    assert!(event_ids.contains(&left.event_id.as_str()), "{frame}");
    assert!(event_ids.contains(&right.event_id.as_str()), "{frame}");
    assert!(event_ids.contains(&normal.event_id.as_str()), "{frame}");

    let siblings = timeline["ordered_log_siblings"].as_array().unwrap();
    let diagnostic = siblings
        .iter()
        .find(|diagnostic| diagnostic["issuer_seq"] == actor_seq)
        .unwrap_or_else(|| panic!("sibling diagnostic missing: {frame}"));
    let sibling_ids = diagnostic["event_ids"].as_array().unwrap();
    assert!(sibling_ids.contains(&serde_json::json!(left.event_id)));
    assert!(sibling_ids.contains(&serde_json::json!(right.event_id)));
    assert_eq!(diagnostic["reason"], "actor_seq_siblings");
}
