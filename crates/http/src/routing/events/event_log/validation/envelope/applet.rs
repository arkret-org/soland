use super::*;

/// The registration gate every `applet_id`-carrying Event has to clear.
async fn validate_applet_registration_is_live(
    state: &AppState,
    applet_id: &str,
    realm_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<(), EventValidationError> {
    let record = load_installed_applet_record(state, applet_id, effective_scope).await?;
    if record.portal_realm_id.as_str() != realm_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_effective_scope_mismatch",
            "applet_id is not installed in the Event Realm",
        ));
    }
    Ok(())
}

async fn load_installed_applet_record(
    state: &AppState,
    applet_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<crate::routing::extensions::applet_bridge::AppletRecord, EventValidationError> {
    let effective_scope_key =
        soland_storage::applet_effective_scope_key(effective_scope).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("Event effective scope is invalid: {error}"),
            )
        })?;
    let record_value = state
        .event_queries()
        .applet(applet_id, &effective_scope_key)
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
    record.validate_stored_bindings().map_err(|error| {
        tracing::error!(%error, %applet_id, "stored applet record bindings are invalid");
        event_validation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "stored applet record bindings are invalid",
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
    Ok(record)
}

/// `is_delegated` is `applet-integration.md` §11's own trigger: the envelope
/// signature is an applet / delegated agent key while `actor_id` names a
/// different DID. Only §11's field triple (`executed_by` / `authorization_ref`
/// / the grant behind them) is scoped that way — an applet signing as itself
/// still has to be a live, unrevoked registration bound to this Realm, so the
/// registration gate below runs for every Event carrying `applet_id`.
pub(super) async fn validate_applet_delegated_authorization_chain(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    kind: &str,
    actor_id: &str,
    realm_id: &str,
    is_delegated: bool,
) -> Result<(), EventValidationError> {
    let Some(applet_id) = event_string_field(object, &["applet_id"]) else {
        return Ok(());
    };
    let effective_scope: arkret_wire::ScopeRef =
        serde_json::from_value(object.get("scope_ref").cloned().ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "applet Event requires scope_ref",
            )
        })?)
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("applet Event scope_ref is invalid: {error}"),
            )
        })?;
    if !is_delegated {
        return validate_applet_registration_is_live(state, &applet_id, realm_id, &effective_scope)
            .await;
    }
    let executed_by = event_string_field(object, &["executed_by"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ReasonCode::EXECUTED_BY_MISSING,
            "applet-originated delegated Event requires executed_by",
        )
    })?;
    let principal_server_id =
        event_string_field(object, &["principal_server_id"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "applet-originated Event requires principal_server_id",
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

    let record = load_installed_applet_record(state, &applet_id, &effective_scope).await?;
    if record.portal_realm_id.as_str() != realm_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_effective_scope_mismatch",
            "applet Event realm_id is outside the installed effective scope",
        ));
    }
    let package = &record.package;
    if !applet_executor_in_subject_set(&record, package.service_id.as_str(), &executed_by) {
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

    let grants = state.authorization().grants_for_subject(
        &executed_by,
        Some(&principal_server_id),
        realm_id,
    );
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
    if !actor_is_managed && grant.issuer_id.as_str() != actor_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "native-principal applet delegation must be issued by the acted-for actor_id",
        ));
    }
    validate_applet_registration_epoch_binding(
        state,
        object,
        &record,
        package,
        grant,
        &applet_id,
        &executed_by,
    )
    .await?;
    Ok(())
}

/// Fence every write authored by an Applet-managed Bot/Ghost, including a
/// self-signed Event that did not enter through the Applet HTTP adapter.  The
/// immutable provision/PCR anchors identify the authority pair; runtime
/// liveness is derived from the current durable registration and grant.
pub(super) async fn validate_applet_managed_actor_liveness(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    kind: &str,
    realm_id: &str,
) -> Result<bool, EventValidationError> {
    let principal_server_id =
        event_string_field(object, &["principal_server_id"]).unwrap_or_default();
    let applet_id = event_string_field(object, &["applet_id"]);
    let authorization_ref = event_string_field(object, &["authorization_ref"]);
    let records = state.event_queries().applets().await.map_err(|error| {
        tracing::error!(%error, %actor_id, "failed to enumerate managed Applet actors");
        event_validation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "applet authorization store unavailable",
        )
    })?;
    let mut actor_core_seen = false;
    for value in records {
        let record: crate::routing::extensions::applet_bridge::AppletRecord =
            serde_json::from_value(value).map_err(|error| {
                tracing::error!(%error, "stored applet record is invalid");
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "stored applet record is invalid",
                )
            })?;
        record.validate_stored_bindings().map_err(|error| {
            tracing::error!(%error, "stored applet record bindings are invalid");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "stored applet record bindings are invalid",
            )
        })?;
        let bot_match = record.bot_actor_id.as_str() == actor_id;
        let ghost_match = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id.as_str() == actor_id);
        if !bot_match && ghost_match.is_none() {
            continue;
        }
        actor_core_seen = true;
        let (expected_server, expected_authorization, expected_pcr_realm) = if bot_match {
            let provision: arkret_models_integration::AppletManagedActorProvisionPayload =
                serde_json::from_value(
                    serde_json::to_value(&record.bot_actor_provision_event.payload).map_err(
                        |_| {
                            event_validation_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal_error",
                                "stored Bot provision payload is invalid",
                            )
                        },
                    )?,
                )
                .map_err(|_| {
                    event_validation_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "stored Bot provision payload is invalid",
                    )
                })?;
            (
                record.bot_actor_principal_server_id.to_string(),
                provision.applet_authority_ref.to_string(),
                record.bot_principal_control_realm_id.to_string(),
            )
        } else {
            let ghost = ghost_match.expect("checked above");
            let provision = ghost.provision_payload().map_err(|error| {
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("stored Ghost provision bindings are invalid: {error}"),
                )
            })?;
            (
                ghost.actor_principal_server_id.to_string(),
                provision.applet_authority_ref.to_string(),
                ghost.principal_control_realm_id().to_string(),
            )
        };
        if expected_server != principal_server_id {
            continue;
        }
        if record.revoked_at.is_some()
            || !matches!(record.status.as_str(), "installed" | "partially_installed")
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_revoked",
                "Applet-managed actor registration has been revoked",
            ));
        }
        if applet_id.as_deref() != Some(record.applet_id.as_str()) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_inactive",
                "Applet-managed actor write must carry its exact live Applet registration and grant",
            ));
        }
        let grants = state.authorization().grants_for_subject(
            record.package.service_id.as_str(),
            Some(&expected_server),
            record.portal_realm_id.as_str(),
        );
        let active_authority = grants
            .iter()
            .any(|grant| grant.grant_id.as_str() == expected_authorization);
        if !active_authority {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_inactive",
                "Applet-managed actor creation authority grant is no longer active",
            ));
        }
        let is_rotation = kind == "ak.identity.resolution.update";
        if is_rotation {
            if realm_id != expected_pcr_realm {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "principal_control_realm_mismatch",
                    "Applet-managed actor rotation must target its exact PCR",
                ));
            }
        } else if realm_id != record.portal_realm_id.as_str() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_effective_scope_mismatch",
                "Applet-managed actor write is outside its portal Realm",
            ));
        }
        {
            let event_id = event_string_field(object, &["event_id"]).unwrap_or_default();
            let resources =
                delegated_applet_resource_candidates(state, object, realm_id, actor_id, &event_id);
            let grant = grants.iter().find(|grant| {
                authorization_ref.as_deref() == Some(grant.grant_id.as_str())
                    && grant.actions.iter().any(|action| action == kind)
                    && resources
                        .iter()
                        .any(|resource| crate::authz::resource_matches(&grant.resource, resource))
            });
            let Some(grant) = grant else {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "authorization_ref_scope",
                    "Applet-managed actor write requires an active exact grant covering its Event kind and resource",
                ));
            };
            crate::authz::validate_applet_authority_binding(
                grant,
                record.applet_id.as_str(),
                record.package.service_id.as_str(),
                record.package.registration_epoch.as_str(),
            )
            .map_err(|error| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    applet_delegation_binding_reason(error),
                    "Applet-managed actor grant is not bound to the current registration epoch",
                )
            })?;
        }
        return Ok(true);
    }
    if actor_core_seen {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "principal_authority_mismatch",
            "Applet-managed actor Event targets a different Principal Server authority",
        ));
    }
    Ok(false)
}

pub(super) async fn validate_applet_registration_epoch_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    package: &arkret_models_integration::AppletPackage,
    grant: &crate::authz::Grant,
    applet_id: &str,
    executed_by: &str,
) -> Result<(), EventValidationError> {
    crate::authz::validate_applet_authority_binding(
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

    let evidence =
        crate::routing::extensions::applet_bridge::registration_epoch_evidence_from_record(record)
            .map_err(|reason| {
                tracing::error!(%reason, %applet_id, "stored Applet registration Event is invalid");
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "stored Applet registration Event is invalid",
                )
            })?;
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
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

    if executed_by == package.service_id.as_str()
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
    error: crate::authz::AppletAuthorityBindingError,
) -> &'static str {
    match error {
        crate::authz::AppletAuthorityBindingError::Missing => {
            "applet_registration_epoch_binding_missing"
        }
        crate::authz::AppletAuthorityBindingError::AppletIdMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        crate::authz::AppletAuthorityBindingError::ExecutedByMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        crate::authz::AppletAuthorityBindingError::RegistrationEpochMismatch => {
            "applet_registration_epoch_mismatch"
        }
    }
}

pub(super) fn applet_executor_in_subject_set(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    service_id: &str,
    executed_by: &str,
) -> bool {
    executed_by == service_id
        || executed_by == record.bot_actor_id.as_str()
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id.as_str() == executed_by)
        || applet_actor_matches_exact_namespace(record, executed_by)
}

pub(super) fn applet_actor_is_managed(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    actor_id == record.bot_actor_id.as_str()
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id.as_str() == actor_id)
}

pub(super) fn applet_actor_matches_exact_namespace(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    record
        .package
        .namespaces
        .actor_namespace_entries
        .iter()
        .any(|entry| {
        !applet_namespace_pattern_is_wildcard(&entry.pattern)
            && arkret_models_integration::namespace_pattern_matches(
                arkret_models_integration::AppletNamespaceDomain::Actors,
                &entry.pattern,
                actor_id,
            )
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
    let projection = state.projections().snapshot();
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, actor_id);
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, event_id);
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
                    Some(&projection),
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
