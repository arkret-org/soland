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
    let record = crate::routing::extensions::applet_bridge::record::applet_record(
        state,
        applet_id,
        effective_scope,
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, %applet_id, "failed to read applet record for delegated event");
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
    let is_rotation = kind == arkret_wire::event_kind_str::IDENTITY_RESOLUTION_UPDATE;
    let event_scope = if is_rotation {
        None
    } else {
        Some(
            serde_json::from_value::<arkret_wire::ScopeRef>(
                object.get("scope_ref").cloned().ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "Applet-managed actor Event requires scope_ref",
                    )
                })?,
            )
            .map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("Applet-managed actor Event scope_ref is invalid: {error}"),
                )
            })?,
        )
    };
    let records = crate::routing::extensions::applet_bridge::record::applet_records(state)
        .await
        .map_err(|error| {
            tracing::error!(?error, %actor_id, "failed to enumerate managed Applet actors");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "applet authorization store unavailable",
            )
        })?;
    let mut actor_core_seen = false;
    let mut selected_scope_seen = false;
    let mut selected_scope_revoked = false;
    let mut selected_scope_live = false;
    for record in records {
        let bot_match = record.bot_actor_id.as_str() == actor_id;
        let ghost_match = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id.as_str() == actor_id);
        if !bot_match && ghost_match.is_none() {
            continue;
        }
        actor_core_seen = true;
        if record.identity.globally_fenced_at.is_some() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_revoked",
                "Applet-managed actor identity is globally fenced",
            ));
        }
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
        if applet_id.as_deref() != Some(record.applet_id.as_str()) {
            continue;
        }
        if !managed_actor_installation_selects_event(
            &record.effective_scope,
            record.portal_realm_id.as_str(),
            event_scope.as_ref(),
            realm_id,
            is_rotation,
            &expected_pcr_realm,
        ) {
            continue;
        }
        selected_scope_seen = true;
        if record.revoked_at.is_some()
            || !matches!(record.status.as_str(), "installed" | "partially_installed")
        {
            selected_scope_revoked = true;
            continue;
        }
        selected_scope_live = true;
        let grants = state.authorization().grants_for_subject(
            record.package.service_id.as_str(),
            Some(&expected_server),
            record.portal_realm_id.as_str(),
        );
        if !bot_match
            && !grants
                .iter()
                .any(|grant| grant.grant_id.as_str() == expected_authorization)
        {
            continue;
        }
        if is_rotation {
            debug_assert_eq!(realm_id, expected_pcr_realm);
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
                continue;
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
        if selected_scope_revoked && !selected_scope_live {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_revoked",
                "Applet-managed actor registration has been revoked",
            ));
        }
        if selected_scope_seen {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_scope",
                "Applet-managed actor write requires an active exact grant covering its selected scope",
            ));
        }
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            if is_rotation {
                "principal_control_realm_mismatch"
            } else {
                "applet_effective_scope_mismatch"
            },
            "Applet-managed actor Event does not select a live installation scope",
        ));
    }
    Ok(false)
}

fn managed_actor_installation_selects_event(
    installation_scope: &arkret_wire::ScopeRef,
    installation_realm_id: &str,
    event_scope: Option<&arkret_wire::ScopeRef>,
    event_realm_id: &str,
    is_pcr_rotation: bool,
    actor_pcr_realm_id: &str,
) -> bool {
    if is_pcr_rotation {
        event_realm_id == actor_pcr_realm_id
    } else {
        event_scope == Some(installation_scope) && event_realm_id == installation_realm_id
    }
}

#[cfg(test)]
mod managed_actor_scope_selection_tests {
    use super::managed_actor_installation_selects_event;

    #[test]
    fn non_pcr_write_selects_exact_scope_before_liveness() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
        )
        .unwrap();
        let realm = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let circle = arkret_wire::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
            )
            .unwrap(),
        };
        assert!(!managed_actor_installation_selects_event(
            &realm,
            realm_id.as_str(),
            Some(&circle),
            realm_id.as_str(),
            false,
            "ak:realm:pcr"
        ));
        assert!(managed_actor_installation_selects_event(
            &circle,
            realm_id.as_str(),
            Some(&circle),
            realm_id.as_str(),
            false,
            "ak:realm:pcr"
        ));
    }

    #[test]
    fn pcr_rotation_selects_any_scope_only_through_shared_pcr() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
        )
        .unwrap();
        let scope = arkret_wire::ScopeRef::Realm { realm_id };
        assert!(managed_actor_installation_selects_event(
            &scope,
            "ak:realm:portal",
            None,
            "ak:realm:pcr",
            true,
            "ak:realm:pcr"
        ));
        assert!(!managed_actor_installation_selects_event(
            &scope,
            "ak:realm:portal",
            None,
            "ak:realm:other",
            true,
            "ak:realm:pcr"
        ));
    }
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
    record.package.namespaces.actors.iter().any(|entry| {
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
