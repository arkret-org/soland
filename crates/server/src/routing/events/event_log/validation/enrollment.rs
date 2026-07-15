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
        .persistence
        .webvh()
        .get_document(principal_did)
        .await
        .ok()
        .flatten()?;
    enrollment_authority_designation_from_document(&record.did_document, principal_did)
}

fn enrollment_authority_designation_from_document(
    did_document: &Value,
    principal_did: &str,
) -> Option<EnrollmentAuthorityDesignation> {
    if let Some(services) = did_document.get("service").and_then(Value::as_array) {
        for service in services {
            let service_type = service.get("type").and_then(Value::as_str);
            if service_type != Some(arkret_sdk::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY) {
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
