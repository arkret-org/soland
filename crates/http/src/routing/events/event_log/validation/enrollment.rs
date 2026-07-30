use super::super::*;

/// Device-identity B-model (device-lifecycle.md §5.4 / key-management.md §5.0.6):
/// admit a `service_attested` `ak.device.authorize` whose trust root is the
/// enrollment authority designated by the principal DID document, rather than a
/// client-held SSK (§5.2) or DID inception key (§5.3).
///
/// Only the `enrollment_authority_binding` branch is validated here; payloads
/// carrying `cross_signing_binding` are validated by
/// `cross_signing::validate_device_authorize_binding` and pass through this
/// gate untouched.
///
/// MUST check (device-lifecycle.md §5.4 receiver rules):
/// `executed_by` (== `binding.authority_did`) is the DID that the principal (`actor_id`) DID
/// document designates via its `ArkretDeviceEnrollmentAuthority` service `serviceEndpoint`, and
/// `authorization_ref` matches that service entry id (else
/// `device_enrollment_authority_not_designated`).
///
/// The cryptographic proof (signed by the authority, rooted in `executed_by`)
/// is verified by `validate_event_proofs`; the envelope `executed_by`/`proofs`
/// vm-DID alignment ran earlier in `validate_event_envelope`.
pub(crate) async fn validate_device_enrollment_authority_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> Result<(), EventValidationError> {
    let payload = object.get("payload").and_then(Value::as_object);
    let Some(binding) = payload
        .and_then(|payload| payload.get("enrollment_authority_binding"))
        .and_then(Value::as_object)
    else {
        // Not a service_attested enrollment; cross_signing / bootstrap branch.
        return Ok(());
    };

    let invalid = |code: &'static str, message: &'static str, status: StatusCode| {
        event_validation_error(status, code, message)
    };

    // executed_by must be the DID-document-designated enrollment authority.
    let authority_did = event_string_field(binding, &["authority_did"]).ok_or_else(|| {
        invalid(
            "device_enrollment_authority_not_designated",
            "enrollment_authority_binding requires authority_did",
            StatusCode::FORBIDDEN,
        )
    })?;
    let executed_by = event_string_field(object, &["executed_by"]).ok_or_else(|| {
        invalid(
            "device_enrollment_authority_not_designated",
            "service_attested ak.device.authorize requires envelope executed_by",
            StatusCode::FORBIDDEN,
        )
    })?;
    if executed_by != authority_did {
        return Err(invalid(
            "device_enrollment_authority_not_designated",
            "envelope executed_by must equal enrollment_authority_binding.authority_did",
            StatusCode::FORBIDDEN,
        ));
    }
    let authorization_ref =
        event_string_field(object, &["authorization_ref"]).ok_or_else(|| {
            invalid(
                "device_enrollment_authority_not_designated",
                "service_attested ak.device.authorize requires envelope authorization_ref",
                StatusCode::FORBIDDEN,
            )
        })?;
    // The binding echoes the envelope authorization_ref; reject divergence so the
    // designation evidence is unambiguous.
    if event_string_field(binding, &["authorization_ref"]).as_deref()
        != Some(authorization_ref.as_str())
    {
        return Err(invalid(
            "device_enrollment_authority_not_designated",
            "enrollment_authority_binding.authorization_ref must equal envelope authorization_ref",
            StatusCode::FORBIDDEN,
        ));
    }

    // Resolve the principal DID document and read its one narrow enrollment
    // delegation: an external ArkretDeviceEnrollmentAuthority service (B
    // model), or a principal-owned capabilityDelegation method (A model).
    let designated = resolve_enrollment_authority_designation(state, actor_id)
        .await
        .ok_or_else(|| {
            invalid(
                "device_enrollment_authority_not_designated",
                "principal DID document does not designate a ArkretDeviceEnrollmentAuthority",
                StatusCode::FORBIDDEN,
            )
        })?;
    if designated.service_endpoint != authority_did {
        return Err(invalid(
            "device_enrollment_authority_not_designated",
            "executed_by is not the enrollment authority designated by the principal DID document",
            StatusCode::FORBIDDEN,
        ));
    }
    if designated.service_id != authorization_ref {
        return Err(invalid(
            "device_enrollment_authority_not_designated",
            "authorization_ref does not match the ArkretDeviceEnrollmentAuthority service entry id",
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// Verify the portable trust anchor carried with a federated device key.
///
/// The source Principal Server attests only that this authorization remains
/// active. The destination independently verifies that the original
/// `ak.device.authorize` Event binds the advertised key to the principal and
/// was signed by the DID-designated enrollment authority.
pub(crate) async fn validate_federated_device_signing_key_evidence(
    state: &AppState,
    evidence: &arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence,
) -> Result<String, String> {
    evidence
        .validate_shape()
        .map_err(|error| error.to_string())?;
    evidence
        .device_authorize_event
        .validate_proof_bindings()
        .map_err(|error| format!("device authorization proof binding: {error}"))?;
    if evidence.device_authorize_event.proofs.is_empty() {
        return Err("portable device authorization must contain an authority proof".to_owned());
    }
    if evidence.authorization_accepted_at > crate::wire::now() + chrono::Duration::minutes(5) {
        return Err("device authorization accepted_at is in the future".to_owned());
    }

    let envelope = serde_json::to_value(evidence.device_authorize_event.as_ref())
        .map_err(|error| format!("device authorization Event serialize: {error}"))?;
    let object = envelope
        .as_object()
        .ok_or_else(|| "device authorization Event must be an object".to_owned())?;
    let binding = object
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("enrollment_authority_binding"))
        .and_then(Value::as_object)
        .ok_or_else(|| "device authorization enrollment binding is missing".to_owned())?;
    let historical_designation = resolve_enrollment_authority_designation_at(
        state,
        evidence.actor_id.as_str(),
        evidence.authorization_accepted_at,
    )
    .await
    .map_err(|error| format!("principal DID accepted-at resolution failed: {error}"))?
    .ok_or_else(|| {
        "principal DID enrollment designation is unavailable at authorization accepted_at"
            .to_owned()
    })?;
    if event_string_field(binding, &["authority_did"]).as_deref()
        != Some(historical_designation.service_endpoint.as_str())
        || event_string_field(binding, &["authorization_ref"]).as_deref()
            != Some(historical_designation.service_id.as_str())
    {
        return Err(
            "device authorization does not match the accepted-at DID enrollment designation"
                .to_owned(),
        );
    }

    let executed_by = evidence
        .device_authorize_event
        .executed_by
        .as_ref()
        .ok_or_else(|| "service-attested device authorization requires executed_by".to_owned())?;
    let authorization_ref = evidence
        .device_authorize_event
        .authorization_ref
        .as_ref()
        .ok_or_else(|| {
            "service-attested device authorization requires authorization_ref".to_owned()
        })?;
    if event_string_field(binding, &["authority_did"]).as_deref() != Some(executed_by.as_str())
        || event_string_field(binding, &["authorization_ref"]).as_deref()
            != Some(authorization_ref.as_str())
    {
        return Err("device authorization envelope and enrollment binding do not match".to_owned());
    }
    for proof in &evidence.device_authorize_event.proofs {
        if proof.domain.is_some() || proof.audience.is_some() {
            return Err(
                "portable device authorization proofs must omit service-specific domain and audience"
                    .to_owned(),
            );
        }
        let proof_controller = proof
            .verification_method
            .split_once('#')
            .map_or(proof.verification_method.as_str(), |(did, _)| did);
        if proof_controller != executed_by.as_str() {
            return Err("device authorization proof is not rooted in executed_by".to_owned());
        }
        let signing_bytes = proof
            .canonical_binding_bytes(&evidence.actor_id)
            .map_err(|error| format!("device authorization proof transcript: {error}"))?;
        let authority_document = did_document_at(
            state,
            executed_by.as_str(),
            evidence.authorization_accepted_at,
        )
        .await?;
        crate::jws_verify::verify_jws_ed25519_with_document(
            &signing_bytes,
            &proof.jws,
            &proof.verification_method,
            executed_by.as_str(),
            &authority_document,
        )
        .map_err(|error| format!("device authorization authority proof: {error}"))?;
    }
    device_generation_ref_at(
        state,
        evidence.actor_id.as_str(),
        evidence.authorization_accepted_at,
    )
    .await
}

/// Persist an independently verified portable device authorization as a
/// derived remote directory projection. This does not add the authorization
/// Event to a Realm timeline or alter a transported Event; it only gives local
/// clients the same `(principal, device)` trust anchor that federation ingress
/// already used to verify the canonical Event proof.
pub(crate) async fn project_federated_device_signing_key_evidence(
    state: &AppState,
    evidence: &arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence,
    authorized_generation_ref: &str,
    source_service_id: &str,
) -> Result<(), String> {
    use soland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};

    let typed: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
        serde_json::from_value(Value::Object(
            evidence.device_authorize_event.payload.clone().into_iter().collect(),
        ))
        .map_err(|error| format!("portable device authorization payload: {error}"))?;
    let principal_id = typed.principal_id.as_str();
    let device_id = typed.device_id.as_str();
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
        // A local authoritative projection always wins over derived remote
        // evidence. Matching local rows already expose the same key; a
        // mismatch must never be overwritten by a peer assertion.
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
    let created_at = existing
        .as_ref()
        .map(|record| record.created_at)
        .unwrap_or(now);
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
        "enrollment_authority_binding".to_owned(),
        serde_json::to_value(
            typed
                .enrollment_authority_binding
                .as_ref()
                .ok_or_else(|| "portable enrollment binding is missing".to_owned())?,
        )
        .map_err(|error| format!("portable enrollment binding: {error}"))?,
    );
    object.insert(
        "device_authorize_event_id".to_owned(),
        Value::String(evidence.device_authorize_event.event_id.to_string()),
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
    object.remove("cross_signing_binding");

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

async fn device_generation_ref_at(
    state: &AppState,
    principal_did: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<String, String> {
    let mut history = state
        .dids()
        .log_events(principal_did)
        .await
        .map_err(|error| format!("DID history lookup failed: {error}"))?;
    history.sort_by_key(|entry| (entry.created_at, entry.seq));
    if let Some(version_id) = history.into_iter().rev().find_map(|entry| {
        (entry.created_at <= accepted_at)
            .then(|| {
                entry
                    .operation
                    .get("versionId")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .flatten()
    }) {
        return Ok(version_id);
    }
    if let Some(current) = state
        .dids()
        .document(principal_did)
        .await
        .map_err(|error| format!("DID document lookup failed: {error}"))?
        && current.updated_at <= accepted_at
        && let Some(version_id) = current.key_log_head
    {
        return Ok(version_id);
    }
    let typed_did =
        arkret_identifiers::Did::new(principal_did.to_owned()).map_err(|e| e.to_string())?;
    if typed_did.method() != "webvh" {
        return Err(
            "portable device authorization has no accepted-at device generation".to_owned(),
        );
    }
    resolve_remote_webvh_generation_at(state, &typed_did, accepted_at).await
}

/// The `ArkretDeviceEnrollmentAuthority` designation read from a principal DID
/// document's `service` array: the entry `id` (matched against
/// `authorization_ref`) and its `serviceEndpoint` DID (matched against
/// `executed_by` / `authority_did`).
struct EnrollmentAuthorityDesignation {
    service_id: String,
    service_endpoint: String,
}

/// Read the principal DID document `service` entry of type
/// `ArkretDeviceEnrollmentAuthority` (identity-did.md §3.2). Returns `None` when
/// the document is not ingested or carries no such designation. The persisted
/// raw `did_document` value retains the full `service` array (the SDK
/// `DidDocument` projection only keeps verificationMethod/alsoKnownAs), so the
/// designation is read from the raw record.
async fn resolve_enrollment_authority_designation(
    state: &AppState,
    principal_did: &str,
) -> Option<EnrollmentAuthorityDesignation> {
    let record = state.dids().document(principal_did).await.ok().flatten()?;
    enrollment_authority_designation_from_document(&record.did_document, principal_did)
}

async fn resolve_enrollment_authority_designation_at(
    state: &AppState,
    principal_did: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<EnrollmentAuthorityDesignation>, String> {
    let document = did_document_at(state, principal_did, accepted_at).await?;
    Ok(enrollment_authority_designation_from_document(
        &document,
        principal_did,
    ))
}

pub(super) async fn did_document_at(
    state: &AppState,
    did: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, String> {
    let typed_did =
        arkret_identifiers::Did::new(did.to_owned()).map_err(|error| error.to_string())?;
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
    did: &arkret_identifiers::Did,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, String> {
    let verified = resolve_remote_webvh_history(state, did).await?;
    webvh_document_at(&verified, accepted_at).ok_or_else(|| {
        "DID document history is unavailable at authorization accepted_at".to_owned()
    })
}

async fn resolve_remote_webvh_generation_at(
    state: &AppState,
    did: &arkret_identifiers::Did,
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
    did: &arkret_identifiers::Did,
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
    did: &arkret_identifiers::Did,
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

fn enrollment_authority_designation_from_document(
    did_document: &Value,
    principal_did: &str,
) -> Option<EnrollmentAuthorityDesignation> {
    if let Some(services) = did_document.get("service").and_then(Value::as_array) {
        for service in services {
            let service_kind = service.get("type").and_then(Value::as_str);
            if service_kind
                != Some(
                    arkret_models_discovery::service_requirements::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
                )
            {
                continue;
            }
            let service_id = service.get("id").and_then(Value::as_str)?;
            let service_endpoint = service
                .get("serviceEndpoint")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?;
            return Some(EnrollmentAuthorityDesignation {
                service_id: service_id.to_owned(),
                service_endpoint: service_endpoint.to_owned(),
            });
        }
    }
    let delegated_method = did_document
        .get("capabilityDelegation")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("id").and_then(Value::as_str))
        })?;
    let controller = delegated_method
        .split_once('#')
        .map_or(delegated_method, |(did, _)| did);
    (controller == principal_did).then(|| EnrollmentAuthorityDesignation {
        service_id: delegated_method.to_owned(),
        service_endpoint: principal_did.to_owned(),
    })
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
