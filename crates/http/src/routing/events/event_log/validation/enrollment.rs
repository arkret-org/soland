use arkret_event_draft::EventPayloadExt as _;

use super::super::*;

/// Enforce the closed device-authorization source model. Root-anchored
/// authorizations exist only inside the exact genesis/re-anchor unit passed by
/// the batch validator. Pairing requires a current, accepted authorizing
/// device; DID service/delegation state is never consulted.
pub(crate) async fn validate_device_authorization_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<(), EventValidationError> {
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    };

    let event = serde_json::from_value::<arkret_wire::Event>(Value::Object(object.clone()))
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid typed ak.device.authorize Event: {error}"),
            )
        })?;
    let payload: DeviceAuthorizePayload = event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid ak.device.authorize payload: {error}"),
            )
        })?;
    if payload.principal_id.as_str() != actor_id {
        return Err(device_authorization_invalid(
            "device authorization principal does not match actor_id",
        ));
    }
    match (&payload.authorization_binding_kind, &payload.authorized_by) {
        (
            DeviceAuthorizationBindingKind::RegistrationAnchor
            | DeviceAuthorizationBindingKind::PcrRecovery,
            DeviceOrPrincipalRef::Principal(root),
        ) => {
            let staged = realm_bootstrap_contexts.iter().any(|context| {
                context.actor_id == actor_id
                    && context.identity_anchor_event_id.is_some()
                    && context
                        .identity_anchor_candidate_device
                        .as_ref()
                        .is_some_and(|candidate| {
                            candidate.principal_id == payload.principal_id
                                && candidate.device_id == payload.device_id
                                && candidate.device_public_key == payload.device_public_key
                                && candidate.hpke_key == payload.hpke_key
                                && candidate.algorithms == payload.algorithms
                                && candidate.authorization_binding_kind
                                    == payload.authorization_binding_kind
                        })
            });
            if root.as_str() != actor_id || !staged {
                return Err(device_authorization_invalid(
                    "root_anchored authorization is outside a closed identity-anchor unit",
                ));
            }
        }
        (
            DeviceAuthorizationBindingKind::AcceptedDevice,
            DeviceOrPrincipalRef::DeviceId(authorizer),
        ) => {
            let expected_method = format!("{actor_id}#{authorizer}");
            let proof_methods = event
                .proofs
                .iter()
                .map(|proof| proof.verification_method.as_str())
                .collect::<Vec<_>>();
            if proof_methods.is_empty()
                || proof_methods
                    .iter()
                    .any(|method| *method != expected_method.as_str())
            {
                return Err(device_authorization_invalid(
                    "accepted_device authorization must be Event-signed by the declared authorizing device",
                ));
            }
            let record = state
                .identities()
                .find_device(soland_services::identity::FindDeviceQuery {
                    actor_id: actor_id.to_owned(),
                    device_id: authorizer.to_string(),
                })
                .await
                .map_err(|error| {
                    event_validation_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "failed_precondition",
                        format!("authorizing device lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    device_authorization_invalid("authorizing device is not accepted")
                })?;
            let current = crate::routing::identity::device_generation::current_device_generation(
                state, actor_id,
            )
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "failed_precondition",
                    format!("device generation state unavailable: {error}"),
                )
            })?
            .ok_or_else(|| device_authorization_invalid("device generation is unavailable"))?;
            if record.verification_state != "verified"
                || record.revoked_at.is_some()
                || record
                    .payload
                    .get("authorized_generation_ref")
                    .and_then(Value::as_str)
                    != Some(current.current_ref.as_str())
            {
                return Err(device_authorization_invalid(
                    "authorizing device is not active at the current generation",
                ));
            }
        }
        _ => {
            return Err(device_authorization_invalid(
                "device authorization binding is not a closed v1 variant",
            ));
        }
    }
    crate::routing::identity::device_signing::validate_device_authorize_binding(state, &payload)
        .map_err(device_authorization_invalid)
}

fn device_authorization_invalid(message: impl Into<String>) -> EventValidationError {
    event_validation_error(StatusCode::FORBIDDEN, "failed_precondition", message)
}

/// Verify the complete portable PCR device-authorization evidence.
///
/// The SDK replay proves the root/device signature chain and derives the
/// current device projection. Soland additionally verifies the service-owned
/// genesis receipt, accepted Seal, and full-range attestation against its
/// configured federation trust before accepting that replay.
pub(crate) async fn validate_federated_device_signing_key_evidence(
    state: &AppState,
    evidence: &arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence,
) -> Result<String, String> {
    evidence
        .validate_shape()
        .map_err(|error| error.to_string())?;
    if evidence.authorization_accepted_at > crate::wire::now() + chrono::Duration::minutes(5) {
        return Err("device authorization accepted_at is in the future".to_owned());
    }

    verify_federated_genesis_receipt(state, &evidence.principal_genesis_receipt).await?;
    verify_federated_accepted_seal(evidence)?;

    let replayed = arkret_signatures::replay_federated_device_authorization(evidence)
        .map_err(|error| format!("PCR device authorization replay failed: {error}"))?;
    if replayed != evidence.current_device_projection {
        return Err("PCR replay changed the current device projection".to_owned());
    }

    for attestation in &evidence.range_completeness_evidence {
        verify_federated_range_attestation(
            state,
            attestation,
            &evidence.principal_genesis_receipt.issuer,
        )
        .await?;
    }

    Ok(replayed
        .generation_state
        .current_device_generation_ref
        .to_string())
}

/// Persist a replay-verified remote device as a derived directory projection.
///
/// Local authoritative rows always win. The portable PCR Event remains the
/// source of key material; Soland stores only the replay result needed by
/// normal device-signature lookup.
pub(crate) async fn project_federated_device_signing_key_evidence(
    state: &AppState,
    evidence: &arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence,
    authorized_generation_ref: &str,
    source_service_id: &str,
) -> Result<(), String> {
    use soland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};

    let authorize_event_id = evidence
        .current_device_projection
        .device_record
        .device_authorize_event_id
        .as_ref()
        .ok_or_else(|| "portable device projection omits authorization Event".to_owned())?;
    let authorize_event = evidence
        .authorization_chain
        .iter()
        .find(|event| &event.event_id == authorize_event_id)
        .ok_or_else(|| "portable device authorization Event is unavailable".to_owned())?;
    let typed: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
        authorize_event
            .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
            .map_err(|error| format!("portable device authorization payload: {error}"))?;
    let principal_id = evidence.actor_id.as_str();
    let device_id = evidence.device_id.as_str();
    let existing = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing) = &existing
        && existing.payload.get("federated_authorization").is_none()
    {
        let local_key = existing
            .payload
            .get("device_public_key")
            .and_then(Value::as_str);
        return if local_key == Some(typed.device_public_key.as_str()) {
            Ok(())
        } else {
            Err("portable device authorization conflicts with local device projection".to_owned())
        };
    }
    if let Some(existing_accepted_at) = existing
        .as_ref()
        .and_then(|record| {
            record
                .payload
                .pointer("/federated_authorization/accepted_at")
        })
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<chrono::DateTime<chrono::Utc>>().ok())
        && existing_accepted_at > evidence.authorization_accepted_at
    {
        return Ok(());
    }

    let now = crate::wire::now();
    let created_at = existing.as_ref().map_or(now, |record| record.created_at);
    let display_name = existing
        .as_ref()
        .and_then(|record| record.display_name.clone());
    let mut payload = existing
        .as_ref()
        .map(|record| record.payload.clone())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    let object = payload
        .as_object_mut()
        .expect("federated device projection payload is an object");
    object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    object.insert(
        "device_public_key".to_owned(),
        Value::String(typed.device_public_key.to_string()),
    );
    object.insert(
        "hpke_key".to_owned(),
        Value::String(typed.hpke_key.to_string()),
    );
    object.insert(
        "algorithms".to_owned(),
        Value::Array(
            typed
                .algorithms
                .iter()
                .map(|algorithm| Value::String(algorithm.to_string()))
                .collect(),
        ),
    );
    object.insert(
        "device_authorize_event_id".to_owned(),
        Value::String(authorize_event_id.to_string()),
    );
    object.insert(
        "authorized_generation_ref".to_owned(),
        Value::String(authorized_generation_ref.to_owned()),
    );
    object.insert(
        "federated_authorization".to_owned(),
        json!({
            "accepted_at": evidence.authorization_accepted_at,
            "source_service_id": source_service_id,
            "verification_method": evidence.verification_method,
        }),
    );

    state
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            display_name: display_name.clone(),
            device: DeviceIdentity {
                actor_id: principal_id.to_owned(),
                device_id: device_id.to_owned(),
                display_name,
                verification_state: "verified".to_owned(),
                payload,
                created_at,
                updated_at: now,
                revoked_at: None,
            },
        })
        .await
        .map_err(|error| error.to_string())
}

async fn verify_federated_genesis_receipt(
    state: &AppState,
    receipt: &arkret_wire::EventBatchReceipt,
) -> Result<(), String> {
    receipt
        .validate()
        .map_err(|error| format!("PCR genesis receipt is invalid: {error}"))?;
    let digest = receipt
        .payload_digest()
        .map_err(|error| format!("PCR genesis receipt digest failed: {error}"))?;
    for proof in &receipt.proofs {
        if proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || proof.payload_digest != digest
            || proof.created_at != receipt.created_at
        {
            return Err("PCR genesis receipt proof binding is invalid".to_owned());
        }
        let signer = arkret_identity::verification_method_did(&proof.verification_method)
            .map_err(|error| format!("PCR genesis receipt signer is invalid: {error}"))?;
        if arkret_wire::project_full_id_to_core_id(&signer)
            .map_or(true, |signer| signer != receipt.issuer)
        {
            return Err("PCR genesis receipt signer does not match issuer".to_owned());
        }
        let binding = receipt
            .proof_binding_bytes(proof)
            .map_err(|error| format!("PCR genesis receipt proof transcript failed: {error}"))?;
        verify_federated_service_jws(
            state,
            &binding,
            &proof.jws,
            proof.verification_method.as_str(),
            receipt.issuer.as_str(),
        )
        .await?;
    }
    Ok(())
}

fn verify_federated_accepted_seal(
    evidence: &arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence,
) -> Result<(), String> {
    let seal = &evidence.accepted_seal;
    seal.validate_structural()
        .map_err(|error| format!("PCR accepted Seal is invalid: {error}"))?;
    seal.validate_id()
        .map_err(|error| format!("PCR accepted Seal id is invalid: {error}"))?;
    let canonical = seal
        .canonical_bytes_for_id()
        .map_err(|error| format!("PCR accepted Seal transcript failed: {error}"))?;
    let digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(&canonical))
        .map_err(|error| format!("PCR accepted Seal digest failed: {error}"))?;
    let arkret_wire::NotarySig::Single(signature) = &seal.notary_signature else {
        return Err("PCR accepted Seal must have one device signature".to_owned());
    };
    let multibase = evidence
        .device_signing_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| "PCR device signing key is not did:key".to_owned())?;
    let expected_principal_id_key_method = format!("{}#{multibase}", evidence.device_signing_key);
    if signature.payload_digest != digest
        || (signature.verification_method != evidence.verification_method
            && signature.verification_method.as_str() != expected_principal_id_key_method)
    {
        return Err("PCR accepted Seal is not signed by the evidenced device".to_owned());
    }
    let key = arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(|error| format!("PCR device signing key is invalid: {error}"))?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &signature.jws,
            &canonical,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_vec(),
            },
        )
        .map_err(|error| format!("PCR accepted Seal signature is invalid: {error}"))
}

async fn verify_federated_range_attestation(
    state: &AppState,
    event: &arkret_wire::Event,
    expected_issuer: &arkret_identifiers::DidCoreId,
) -> Result<(), String> {
    event
        .validate_proof_bindings()
        .map_err(|error| format!("PCR range Event proof binding failed: {error}"))?;
    if event.proofs.is_empty() || &event.actor_id != expected_issuer {
        return Err("PCR range attestation actor does not match receipt issuer".to_owned());
    }
    let digest_payload = event
        .digest_payload()
        .map_err(|error| format!("PCR range Event digest payload failed: {error}"))?;
    let event_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| format!("PCR range Event transcript failed: {error}"))?;
    for proof in &event.proofs {
        let binding = proof
            .canonical_binding_bytes(&event.actor_id)
            .map_err(|error| format!("PCR range Event proof transcript failed: {error}"))?;
        verify_federated_service_jws(
            state,
            &binding,
            &proof.jws,
            proof.verification_method.as_str(),
            expected_issuer.as_str(),
        )
        .await?;
        if proof.event_digest.as_str() != arkret_canonical::sha256_digest(&event_bytes) {
            return Err("PCR range Event proof digest is invalid".to_owned());
        }
    }

    let payload: arkret_models_collaboration::sync_frames::snapshot::RangeCompletenessAttestation =
        event
            .typed_payload::<arkret_wire::event_spec::AttestationRangeCompleteness>()
            .map_err(|error| format!("PCR range attestation payload is invalid: {error}"))?;
    if &payload.issuer != expected_issuer
        || payload.realm_id != event.realm_id
        || payload.schema != arkret_wire::SchemaId::RANGE_COMPLETENESS_ATTESTATION_V1
        || payload.count == 0
        || payload.witness_attestation.witnesses.is_empty()
        || payload
            .witness_attestation
            .witnesses
            .iter()
            .any(|witness| &witness.issuer != expected_issuer)
    {
        return Err("PCR range payload binding is invalid".to_owned());
    }
    let payload_digest = payload
        .payload_digest()
        .map_err(|error| format!("PCR range payload digest failed: {error}"))?;
    if payload.proofs.is_empty() {
        return Err("PCR range payload has no issuer proof".to_owned());
    }
    for proof in &payload.proofs {
        if proof.payload_digest != payload_digest {
            return Err("PCR range payload proof digest is invalid".to_owned());
        }
        let binding = payload
            .proof_binding_bytes(proof)
            .map_err(|error| format!("PCR range payload proof transcript failed: {error}"))?;
        verify_federated_service_jws(
            state,
            &binding,
            &proof.jws,
            proof.verification_method.as_str(),
            expected_issuer.as_str(),
        )
        .await?;
    }
    Ok(())
}

async fn verify_federated_service_jws(
    state: &AppState,
    binding: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
) -> Result<(), String> {
    let controller = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let controller_core =
        arkret_wire::project_full_id_to_core_id(&controller).map_err(|error| error.to_string())?;
    if controller_core.as_str() != issuer {
        return Err("verification method controller does not match issuer core-id".to_owned());
    }
    if let Some(key) = state
        .federation_peer_verification_method_key(verification_method)
        .or_else(|| state.federation_peer_verifying_key(issuer))
    {
        return arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                jws,
                binding,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_bytes().to_vec(),
                },
            )
            .map_err(|error| error.to_string());
    }
    crate::jws_verify::verify_did_controlled_jws_async(
        binding,
        jws,
        verification_method,
        controller.as_str(),
        state,
    )
    .await
}

pub(super) async fn did_document_at(
    state: &AppState,
    did: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, String> {
    let typed_did =
        arkret_identifiers::DidFullId::new(did.to_owned()).map_err(|error| error.to_string())?;
    if typed_did.method() == "key" {
        let document = crate::jws_verify::resolve_did_document_async(state, &typed_did).await?;
        return serde_json::to_value(document)
            .map_err(|error| format!("did:key document encode failed: {error}"));
    }
    let mut history = state
        .dids()
        .log_events(did)
        .await
        .map_err(|error| format!("DID history lookup failed: {error}"))?;
    history.sort_by_key(|entry| (entry.created_at, entry.seq));
    if let Some(document) = history.into_iter().rev().find_map(|entry| {
        (entry.created_at <= accepted_at)
            .then(|| entry.operation.get("state").cloned())
            .flatten()
    }) {
        return Ok(document);
    }
    let current = state
        .dids()
        .document(did)
        .await
        .map_err(|error| format!("DID document lookup failed: {error}"))?;
    if let Some(current) = current
        && current.updated_at <= accepted_at
    {
        return Ok(current.did_document);
    }
    if typed_did.method() == "webvh" {
        return resolve_remote_webvh_document_at(state, &typed_did, accepted_at).await;
    }
    Err("DID document history is unavailable at authorization accepted_at".to_owned())
}

async fn resolve_remote_webvh_document_at(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, String> {
    let verified = resolve_remote_webvh_history(state, did).await?;
    webvh_document_at(&verified, accepted_at).ok_or_else(|| {
        "DID document history is unavailable at authorization accepted_at".to_owned()
    })
}

async fn resolve_remote_webvh_generation_at(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<String, String> {
    let verified = resolve_remote_webvh_history(state, did).await?;
    verified
        .entries
        .iter()
        .rev()
        .find(|entry| entry.version_time <= accepted_at)
        .map(|entry| entry.version_id.clone())
        .ok_or_else(|| {
            "DID generation history is unavailable at authorization accepted_at".to_owned()
        })
}

async fn resolve_remote_webvh_history(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
) -> Result<arkret_identity::VerifiedDidWebvhLog, String> {
    let raw_url = remote_webvh_history_url(state, did)?;
    let mut url = reqwest::Url::parse(&raw_url)
        .map_err(|error| format!("did:webvh history URL is invalid: {error}"))?;
    if state.config().development_mode
        && url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
    {
        url.set_scheme("http")
            .map_err(|()| "did:webvh loopback history URL scheme is invalid".to_owned())?;
    }
    let request_timeout = std::time::Duration::from_secs(10);
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url.as_str(),
        "did:webvh accepted-at history",
        state.config().development_mode,
        request_timeout,
    )?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("did:webvh history fetch failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "did:webvh history fetch returned HTTP {}",
            response.status()
        ));
    }
    let max_bytes = arkret_identity::DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32);
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err("did:webvh history exceeds maximum size".to_owned());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("did:webvh history body read failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err("did:webvh history exceeds maximum size".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    arkret_identity::verify_did_webvh_v1_chain_bytes(did, &body)
        .map_err(|error| format!("did:webvh history verification failed: {error}"))
}

fn remote_webvh_history_url(
    state: &AppState,
    did: &arkret_identifiers::DidFullId,
) -> Result<String, String> {
    if let Ok(url) = arkret_identity::DidWebvhResolver::log_url(did) {
        return Ok(url);
    }
    if state.config().development_mode
        && let Some((_, host, port, path)) = arkret_identity::did_webvh_parts(did)
        && host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    {
        let authority = port.map_or(host.clone(), |port| format!("{host}:{port}"));
        return if path.is_empty() {
            Ok(format!("https://{authority}/.well-known/did.jsonl"))
        } else {
            Ok(format!("https://{authority}/{}/did.jsonl", path.join("/")))
        };
    }
    Err("did:webvh history URL is unavailable".to_owned())
}

fn webvh_document_at(
    history: &arkret_identity::VerifiedDidWebvhLog,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Option<Value> {
    history
        .entries
        .iter()
        .rev()
        .find(|entry| entry.version_time <= accepted_at)
        .map(|entry| entry.state.clone())
}

#[cfg(test)]
mod tests {
    use arkret_identity::{DidWebvhLogEntry, VerifiedDidWebvhLog};
    use serde_json::json;

    use super::webvh_document_at;

    #[test]
    fn webvh_history_selects_latest_state_not_after_accepted_at() {
        let first_time = "2026-07-25T01:00:00Z".parse().unwrap();
        let second_time = "2026-07-25T02:00:00Z".parse().unwrap();
        let history = VerifiedDidWebvhLog {
            raw_entries: Vec::new(),
            entries: vec![
                DidWebvhLogEntry {
                    version_id: "1-first".to_owned(),
                    version_time: first_time,
                    parameters: json!({}),
                    state: json!({"id": "did:webvh:zExample:example.test", "marker": "first"}),
                    proof: Vec::new(),
                },
                DidWebvhLogEntry {
                    version_id: "2-second".to_owned(),
                    version_time: second_time,
                    parameters: json!({}),
                    state: json!({"id": "did:webvh:zExample:example.test", "marker": "second"}),
                    proof: Vec::new(),
                },
            ],
            head_version_id: "2-second".to_owned(),
            head_state: json!({}),
            active_update_keys: Vec::new(),
        };

        let between = "2026-07-25T01:30:00Z".parse().unwrap();
        assert_eq!(
            webvh_document_at(&history, between)
                .and_then(|document| document.get("marker").cloned()),
            Some(json!("first"))
        );
        assert!(webvh_document_at(&history, "2026-07-25T00:59:59Z".parse().unwrap()).is_none());
    }
}
