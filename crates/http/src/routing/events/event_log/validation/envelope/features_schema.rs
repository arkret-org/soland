use super::*;

pub(crate) fn validate_event_critical_features(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let supported_features = service_declared_event_requirement_features(state);
    for key in ["crit", "critical", "critical_features"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let features = match value {
            Value::Array(values) => values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>(),
            Value::String(value) => Some(vec![value.clone()]),
            _ => None,
        }
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "critical features must be strings",
            )
        })?;
        for feature in features {
            if !LOCAL_EVENT_CRITICAL_FEATURES.contains(&feature.as_str()) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_critical_feature",
                    "unknown critical Event feature is not supported",
                ));
            }
        }
    }
    if let Some(features) = object
        .get("requirements")
        .and_then(|requirements| requirements.get("features"))
    {
        let Some(features) = features.as_array() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "requirements.features must be an array",
            ));
        };
        for feature in features {
            let Some(feature) = feature.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "requirements.features entries must be strings",
                ));
            };
            if !supported_features.contains(feature) {
                return Err(event_validation_error(
                    StatusCode::NOT_IMPLEMENTED,
                    "unsupported_feature",
                    "unknown requirements.features entry is not supported",
                ));
            }
        }
    }
    let Some(critical_extensions) = object
        .get("requirements")
        .and_then(|requirements| requirements.get("critical_extensions"))
    else {
        return Ok(());
    };
    let Some(critical_extensions) = critical_extensions.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "requirements.critical_extensions must be an array",
        ));
    };
    for extension in critical_extensions {
        let (id, fail_closed) = match extension {
            Value::String(id) => (id.as_str(), true),
            Value::Object(object) => {
                let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "requirements.critical_extensions[].id is required",
                    )
                })?;
                let fail_closed = object
                    .get("fail_closed")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                (id, fail_closed)
            }
            _ => {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "requirements.critical_extensions entries must be strings or objects",
                ));
            }
        };
        if fail_closed
            && !LOCAL_EVENT_CRITICAL_FEATURES.contains(&id)
            && !supported_features.contains(id)
        {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "unknown requirements.critical_extensions entry is not supported",
            ));
        }
    }
    Ok(())
}

pub(super) fn service_declared_event_requirement_features(
    state: &AppState,
) -> std::collections::BTreeSet<String> {
    let mut declared = std::collections::BTreeSet::new();
    declared.extend(
        LOCAL_EVENT_CRITICAL_FEATURES
            .iter()
            .map(|feature| (*feature).to_owned()),
    );
    let mut description = crate::wire::describe(
        state.service_resolution_commitment().as_ref(),
        state.jobs().storage_mode(),
        state.config(),
    );
    crate::routing::system::describe::apply_claim_level_partition(
        &mut description,
        state.verified_profiles(),
        state.config().sovereign_enclave_enabled,
    );
    declared.extend(description.supported_features);
    declared
}

pub(crate) fn validate_event_time_fields(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let created_at_value = object.get("created_at");
    if created_at_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "created_at must be a string",
        ));
    }
    match created_at_value.and_then(Value::as_str) {
        Some(value) => canonical::validate_timestamp_canonical(value).map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "created_at must use canonical RFC3339 UTC millisecond form",
            )
        })?,
        None if !state.config().development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_missing",
                "created_at is required in production mode",
            ));
        }
        None => {}
    }

    let hlc_value = object.get("hlc");
    if hlc_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "hlc must be a string",
        ));
    }
    match hlc_value.and_then(Value::as_str) {
        Some(value) => {
            Hlc::new(value).map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
                    "hlc must use canonical lower-hex HLC form",
                )
            })?;
        }
        None if !state.config().development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_missing",
                "hlc is required in production mode",
            ));
        }
        None => {}
    }

    Ok(())
}

pub(crate) fn validate_event_schema_and_payload(
    _state: &AppState,
    kind: &str,
    _schema_id: &str,
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("event envelope violates its typed wire contract: {error}"),
        )
    })?;

    let payload = object.get("payload").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "event payload is required",
        )
    })?;
    // Wire-shape validators that must run before the registered payload
    // schema validator to surface their precise reason codes.
    validate_pre_schema_wire_shape(kind, payload)?;
    if matches!(
        kind,
        arkret_wire::event_kind_str::SPACE_ARCHIVE
            | arkret_wire::event_kind_str::SPACE_RESTORE
            | arkret_wire::event_kind_str::SPACE_TOMBSTONE
    ) {
        return validate_space_container_lifecycle_payload(payload);
    }
    let typed_kind = arkret_wire::EventKind::from(kind);
    arkret_event_draft::validate_event_payload(&typed_kind, payload).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("event payload violates its typed SDK contract: {error}"),
        )
    })?;
    if kind == arkret_wire::EventKind::SchemaDefine.as_str() {
        arkret_schema::validate_schema_definition_payload(payload).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("event payload violates its registered validator profile: {error}"),
            )
        })?;
    }
    Ok(())
}

pub(crate) async fn validate_member_identity_proof(
    state: &AppState,
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(identity_payload) = payload.get("identity_payload") else {
        return Ok(());
    };
    let Some(member_identity_value) = identity_payload.get("member_identity") else {
        if identity_payload.get("encrypted_payload").is_some() {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "encrypted MemberIdentity proof verification is not wired; refusing fail-closed",
            ));
        }
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "identity_payload must carry member_identity or encrypted_payload",
        ));
    };
    let identity: arkret_models_identity::member_identity::MemberIdentity =
        serde_json::from_value(member_identity_value.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("MemberIdentity payload shape is invalid: {error}"),
            )
        })?;
    let payload_realm = payload.get("realm_id").and_then(Value::as_str);
    let payload_actor = payload
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok());
    if payload_realm != Some(identity.realm_id.as_str())
        || payload_actor.as_ref() != Some(&identity.actor_id)
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "MemberIdentity realm_id/actor_id must match the update payload subject",
        ));
    }
    let canonical_bytes = identity.canonical_payload_bytes().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity canonical payload failed: {error}"),
        )
    })?;
    let payload_digest = identity.canonical_payload_sha256().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity payload digest failed: {error}"),
        )
    })?;
    if identity.proof.payload_digest.as_str() != payload_digest {
        crate::metrics::record_digest_mismatch("member_identity_carrier_digest");
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "proof_event_digest_mismatch",
            "MemberIdentityProof.payload_digest does not match the canonical payload",
        ));
    }
    if !matches!(
        identity.proof.signature_algorithm,
        arkret_models_identity::member_identity::MemberIdentitySignatureAlgorithm::Ed25519
    ) {
        let code = soland_http::error::ErrorCode::UnsupportedSignatureAlg;
        return Err(event_validation_error(
            soland_http::error::error_http_status(code),
            code.as_str(),
            "only Ed25519 MemberIdentityProof.signature_algorithm is supported",
        ));
    }
    crate::jws_verify::validate_verification_method_controller(
        identity.actor_id.signing_principal_id().as_str(),
        &identity.proof.verification_method,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "proof_invalid",
            format!("MemberIdentity proof controller mismatch: {error}"),
        )
    })?;
    let public_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, &identity.proof.verification_method)
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    "proof_invalid",
                    format!("MemberIdentity proof verification key resolution failed: {error}"),
                )
            })?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(identity.proof.signature.as_bytes())
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_invalid",
                format!("MemberIdentity proof signature is not base64url: {error}"),
            )
        })?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "proof_invalid",
            "MemberIdentity proof signature must be 64 bytes",
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    public_key
        .verify(&canonical_bytes, &signature)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "proof_invalid",
                format!("MemberIdentity proof signature verification failed: {error}"),
            )
        })
}

pub(crate) fn event_requirements_schema_id(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let canonical_schema_id = object
        .get("requirements")
        .and_then(|requirements| requirements.get("schema"))
        .and_then(Value::as_array)
        .and_then(|schemas| schemas.first())
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if !state.config().development_mode && canonical_schema_id.is_none() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "requirements.schema[] is required in production mode",
        ));
    }
    let schema_id = canonical_schema_id
        .or_else(|| {
            object
                .get("schema_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| arkret_wire::SchemaId::EVENT_V1.to_owned());
    if !schema_id.starts_with("ak.schema.") || !artifacts::schema_ids().contains(&schema_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_schema",
            "event schema_id is not in the arkret-spec schema registry",
        ));
    }
    Ok(schema_id)
}
