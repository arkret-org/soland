use super::super::*;

/// Device-identity B-model (device-lifecycle.md §5.4 / key-management.md §5.0.6):
/// admit a `service_attested` `ck.device.authorize` whose trust root is the
/// enrollment authority designated by the principal DID document, rather than a
/// client-held SSK (§5.2) or DID inception key (§5.3).
///
/// Only the `enrollment_authority_binding` branch is validated here; payloads
/// carrying `cross_signing_binding` or `bootstrap_binding` instead are validated
/// by `cross_signing::validate_device_authorize_binding` (operation policy) and
/// the bootstrap path, and pass through this gate untouched.
///
/// MUST check (device-lifecycle.md §5.4 receiver rules):
/// `executed_by` (== `binding.authority_did`) is the DID that the principal (`actor_id`) DID
/// document designates via its `CokretDeviceEnrollmentAuthority` service `serviceEndpoint`, and
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
            "service_attested ck.device.authorize requires envelope executed_by",
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
                "service_attested ck.device.authorize requires envelope authorization_ref",
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

    // Resolve the principal (actor_id) DID document and read the anchored
    // CokretDeviceEnrollmentAuthority service entry. If the binding carries a
    // versionTime provenance anchor, replay the DID log at that time instead
    // of accepting a current-policy-only designation.
    let designated = resolve_enrollment_authority_designation(state, actor_id, binding)
        .await
        .ok_or_else(|| {
            invalid(
                "device_enrollment_authority_not_designated",
                "principal DID document does not designate a CokretDeviceEnrollmentAuthority",
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
            "authorization_ref does not match the CokretDeviceEnrollmentAuthority service entry id",
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// The `CokretDeviceEnrollmentAuthority` designation read from a principal DID
/// document's `service` array: the entry `id` (matched against
/// `authorization_ref`) and its `serviceEndpoint` DID (matched against
/// `executed_by` / `authority_did`).
struct EnrollmentAuthorityDesignation {
    service_id: String,
    service_endpoint: String,
}

/// Read the principal DID document `service` entry of type
/// `CokretDeviceEnrollmentAuthority` (identity-did.md §3.2). Returns `None` when
/// the document is not ingested or carries no such designation. The persisted
/// raw `did_document` value retains the full `service` array (the SDK
/// `DidDocument` projection only keeps verificationMethod/alsoKnownAs), so the
/// designation is read from the raw record.
async fn resolve_enrollment_authority_designation(
    state: &AppState,
    principal_did: &str,
    binding: &serde_json::Map<String, Value>,
) -> Option<EnrollmentAuthorityDesignation> {
    if let Some(version_time) = enrollment_authority_version_time(binding) {
        let document =
            historical_enrollment_authority_document(state, principal_did, version_time).await?;
        return enrollment_authority_designation_from_document(&document);
    }
    let record = state
        .persistence
        .webvh()
        .get_document(principal_did)
        .await
        .ok()
        .flatten()?;
    enrollment_authority_designation_from_document(&record.did_document)
}

fn enrollment_authority_version_time(
    binding: &serde_json::Map<String, Value>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    for field in ["authority_version_time", "version_time", "versionTime"] {
        let Some(raw) = binding.get(field).and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let parsed = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
        return Some(parsed.with_timezone(&chrono::Utc));
    }
    None
}

async fn historical_enrollment_authority_document(
    state: &AppState,
    principal_did: &str,
    version_time: chrono::DateTime<chrono::Utc>,
) -> Option<Value> {
    let mut events = state
        .persistence
        .webvh()
        .list_log_events(principal_did)
        .await
        .ok()?;
    events.sort_by_key(|event| event.seq);
    events
        .into_iter()
        .rfind(|event| {
            let entry_time = event
                .operation
                .get("versionTime")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&chrono::Utc))
                .unwrap_or(event.created_at);
            entry_time <= version_time
        })
        .and_then(|event| {
            event
                .operation
                .get("state")
                .cloned()
                .or_else(|| event.operation.get("did_document").cloned())
        })
}

fn enrollment_authority_designation_from_document(
    did_document: &Value,
) -> Option<EnrollmentAuthorityDesignation> {
    let services = did_document.get("service")?.as_array()?;
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
    None
}
