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
    evidence: &arkret_core::FederatedDeviceSigningKeyEvidence,
) -> Result<(), String> {
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
    Ok(())
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
    let record = state
        .did_application()
        .document(principal_did)
        .await
        .ok()
        .flatten()?;
    enrollment_authority_designation_from_document(&record.did_document, principal_did)
}

async fn resolve_enrollment_authority_designation_at(
    state: &AppState,
    principal_did: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Option<EnrollmentAuthorityDesignation> {
    let document = did_document_at(state, principal_did, accepted_at)
        .await
        .ok()?;
    enrollment_authority_designation_from_document(&document, principal_did)
}

async fn did_document_at(
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
        .did_application()
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
        .did_application()
        .document(did)
        .await
        .map_err(|error| format!("DID document lookup failed: {error}"))?
        .ok_or_else(|| "DID document history is unavailable".to_owned())?;
    if current.updated_at <= accepted_at {
        return Ok(current.did_document);
    }
    Err("DID document history is unavailable at authorization accepted_at".to_owned())
}

fn enrollment_authority_designation_from_document(
    did_document: &Value,
    principal_did: &str,
) -> Option<EnrollmentAuthorityDesignation> {
    if let Some(services) = did_document.get("service").and_then(Value::as_array) {
        for service in services {
            let service_type = service.get("type").and_then(Value::as_str);
            if service_type
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
