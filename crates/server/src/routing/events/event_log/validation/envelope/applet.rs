use super::*;

pub(super) async fn validate_applet_delegated_authorization_chain(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    kind: &str,
    actor_id: &str,
    realm_id: &str,
) -> Result<(), EventValidationError> {
    let Some(applet_id) = event_string_field(object, &["applet_id"]) else {
        return Ok(());
    };
    let executed_by = event_string_field(object, &["executed_by"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            crate::error::reasons::EXECUTED_BY_MISSING,
            "applet-originated delegated Event requires executed_by",
        )
    })?;
    let authorization_ref =
        event_string_field(object, &["authorization_ref"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "authorization_ref_missing",
                "applet-originated Event requires authorization_ref",
            )
        })?;
    if !authorization_ref.starts_with("ak:grant:") {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_invalid",
            "applet-originated Event authorization_ref must reference an accepted capability grant",
        ));
    }

    let record_value = state
        .persistence
        .applets()
        .get(&applet_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet record for delegated event");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "applet authorization store unavailable",
            )
        })?
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_unauthorized",
                "applet_id does not identify an active installed applet",
            )
        })?;
    let record: crate::routing::extensions::applet_bridge::AppletRecord =
        serde_json::from_value(record_value).map_err(|error| {
            tracing::error!(%error, %applet_id, "stored applet record is invalid");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "stored applet record is invalid",
            )
        })?;
    if record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_revoked",
            "applet install has been revoked",
        ));
    }
    if record.portal_realm_id != realm_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_effective_scope_mismatch",
            "applet Event realm_id is outside the installed effective scope",
        ));
    }
    let package = record.package.as_ref().ok_or_else(|| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_install_required",
            "applet delegated Event requires a package install",
        )
    })?;
    if !applet_executor_in_subject_set(&record, package.service_did.as_str(), &executed_by) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_namespace_mismatch",
            "executed_by is outside the installed applet subject set",
        ));
    }
    let actor_is_managed = applet_actor_is_managed(&record, actor_id);
    if !actor_is_managed && !applet_actor_matches_exact_namespace(&record, actor_id) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_namespace_mismatch",
            "actor_id is outside the installed applet actor namespace",
        ));
    }

    let grants = state.authz.grants_for_subject(&executed_by, realm_id);
    let grant = grants
        .iter()
        .find(|grant| grant.grant_id.as_str() == authorization_ref.as_str())
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_inactive",
                "authorization_ref does not identify an active grant for executed_by",
            )
        })?;
    if !grant.actions.iter().any(|action| action == kind) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "authorization_ref grant does not cover this Event kind",
        ));
    }
    let event_id = event_string_field(object, &["event_id"]).unwrap_or_default();
    let resources =
        delegated_applet_resource_candidates(state, object, realm_id, actor_id, &event_id);
    if !resources
        .iter()
        .any(|resource| crate::authz::resource_matches(&grant.resource, resource))
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "authorization_ref grant does not cover this Event resource",
        ));
    }
    if !actor_is_managed && grant.issuer.as_str() != actor_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "native-principal applet delegation must be issued by the acted-for actor_id",
        ));
    }
    validate_applet_registration_epoch_binding(
        state,
        object,
        package,
        grant,
        &applet_id,
        &executed_by,
    )
    .await?;
    Ok(())
}

pub(super) async fn validate_applet_registration_epoch_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    package: &cokret_sdk::AppletPackage,
    grant: &crate::authz::Grant,
    applet_id: &str,
    executed_by: &str,
) -> Result<(), EventValidationError> {
    crate::authz::validate_applet_delegation_binding(
        grant,
        applet_id,
        executed_by,
        package.registration_epoch.as_str(),
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            applet_delegation_binding_reason(error),
            "authorization_ref grant is not bound to the installed applet registration epoch",
        )
    })?;

    let evidence = package
        .registration_epoch_evidence
        .as_ref()
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_epoch_evidence_missing",
                "installed applet package is missing registration_epoch evidence",
            )
        })?;
    let document =
        crate::jws_verify::resolve_did_document(state, &package.service_did).map_err(|reason| {
            tracing::debug!(%reason, %applet_id, "applet registration_epoch DID resolution failed");
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_epoch_evidence_mismatch",
                "installed applet service DID document could not be resolved",
            )
        })?;
    evidence
        .validate_against_did_document(&document)
        .map_err(|reason| {
            tracing::debug!(%reason, %applet_id, "applet registration_epoch evidence mismatch");
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_epoch_evidence_mismatch",
                "installed applet registration_epoch evidence does not match the current service DID document",
            )
        })?;

    if executed_by == package.service_did.as_str()
        && let Some(verification_method) = first_event_proof_verification_method(object)
        && !evidence.contains_signing_key(&verification_method)
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_registration_epoch_signing_key_mismatch",
            "event proof signing key is outside the applet registration_epoch evidence",
        ));
    }
    Ok(())
}

pub(super) fn applet_delegation_binding_reason(
    error: crate::authz::AppletDelegationBindingError,
) -> &'static str {
    match error {
        crate::authz::AppletDelegationBindingError::Missing => {
            "applet_registration_epoch_binding_missing"
        }
        crate::authz::AppletDelegationBindingError::AppletIdMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        crate::authz::AppletDelegationBindingError::ExecutedByMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        crate::authz::AppletDelegationBindingError::RegistrationEpochMismatch => {
            "applet_registration_epoch_mismatch"
        }
    }
}

pub(super) fn applet_executor_in_subject_set(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    service_did: &str,
    executed_by: &str,
) -> bool {
    executed_by == service_did
        || executed_by == record.bot_actor_id
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id == executed_by && ghost.revoked_at.is_none())
        || applet_actor_matches_exact_namespace(record, executed_by)
}

pub(super) fn applet_actor_is_managed(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    actor_id == record.bot_actor_id
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id == actor_id && ghost.revoked_at.is_none())
}

pub(super) fn applet_actor_matches_exact_namespace(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    record.namespaces.as_ref().is_some_and(|namespaces| {
        namespaces.actors.iter().any(|entry| {
            !applet_namespace_pattern_is_wildcard(&entry.pattern)
                && cokret_sdk::namespace_pattern_matches(
                    cokret_sdk::AppletNamespaceDomain::Actors,
                    &entry.pattern,
                    actor_id,
                )
        })
    })
}

pub(super) fn applet_namespace_pattern_is_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.ends_with(':') || pattern.ends_with('/')
}

pub(super) fn delegated_applet_resource_candidates(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    realm_id: &str,
    actor_id: &str,
    event_id: &str,
) -> Vec<String> {
    let mut resources = Vec::new();
    let projection = state.projection.lock();
    append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, actor_id);
    append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, event_id);
    if let Some(redacts) = event_string_field(object, &["redacts"]) {
        append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, &redacts);
    }
    if let Some(payload) = object.get("payload").and_then(Value::as_object) {
        for field in [
            "strand_id",
            "thread_id",
            "message_id",
            "object_id",
            "target_ref",
        ] {
            if let Some(value) = event_string_field(payload, &[field]) {
                append_authz_resource_candidates(
                    &mut resources,
                    Some(&*projection),
                    realm_id,
                    &value,
                );
            }
        }
    }
    resources.sort();
    resources.dedup();
    resources
}

pub(super) fn first_event_proof_verification_method(
    object: &serde_json::Map<String, Value>,
) -> Option<String> {
    object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(Value::as_object)
        .and_then(|proof| event_string_field(proof, &["verification_method"]))
}
