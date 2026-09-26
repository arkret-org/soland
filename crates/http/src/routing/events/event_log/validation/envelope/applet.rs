use super::*;

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

/// Validate the exact live installation and grant for every ordinary Applet
/// service or native-delegated write. Managed actors have a separate provision
/// and current-authority gate, including when they use their own producer key.
pub(super) async fn validate_applet_delegated_authorization_chain(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    kind: &str,
    actor_id: &str,
    realm_id: &str,
    _is_delegated: bool,
) -> Result<(), EventValidationError> {
    let Some(applet_id) = event_string_field(object, &["applet_id"]) else {
        return Ok(());
    };
    let effective_scope: arkret_wire::ScopeRef =
        serde_json::from_value(object.get("scope_ref").cloned().ok_or_else(|| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "applet Event requires scope_ref",
            )
        })?)
        .map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("applet Event scope_ref is invalid: {error}"),
            )
        })?;
    let executed_by = object
        .get("executed_by")
        .or_else(|| object.get("actor_id"))
        .cloned()
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "Applet Event requires a complete producer ActorId",
            )
        })?;
    let executed_by_actor =
        serde_json::from_value::<arkret_wire::ActorId>(executed_by).map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("applet executed_by is invalid: {error}"),
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
    if !applet_executor_in_subject_set(&record, package.service_id.as_str(), &executed_by_actor) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_namespace_mismatch",
            "executed_by is outside the installed applet subject set",
        ));
    }
    let actor_is_managed = applet_actor_is_managed(&record, actor_id);
    let actor_is_service = object
        .get("actor_id")
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        == Some(arkret_wire::ActorId::service(package.service_id.clone()));
    if !actor_is_managed
        && !actor_is_service
        && !applet_actor_matches_exact_namespace(&record, actor_id)
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_namespace_mismatch",
            "actor_id is outside the installed applet actor namespace",
        ));
    }

    let authorization =
        applet_grant_holder_authorization(state, realm_id, &executed_by_actor).await?;
    let grant = authorization
        .grants
        .iter()
        .map(|effective| &effective.grant)
        .find(|grant| grant.id.as_str() == authorization_ref.as_str())
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
        delegated_applet_resource_candidates(&authorization.realm_id, object, &event_id);
    if !resources
        .iter()
        .any(|resource| soland_storage::grant_names_target(grant, &[kind], resource))
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "authorization_ref grant does not cover this Event resource",
        ));
    }
    if !actor_is_managed
        && !actor_is_service
        && object.get("actor_id") != serde_json::to_value(&grant.issuer_id).ok().as_ref()
    {
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
        &executed_by_actor,
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
    let event_actor = serde_json::from_value::<arkret_wire::ActorId>(
        object.get("actor_id").cloned().ok_or_else(|| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "Applet-managed actor Event requires actor_id",
            )
        })?,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("Applet-managed actor Event actor_id is invalid: {error}"),
        )
    })?;
    let station_id = event_actor.route_service_id().as_str();
    let applet_id = event_string_field(object, &["applet_id"]);
    let authorization_ref = event_string_field(object, &["authorization_ref"]);
    // `device-lifecycle.md` 5.2.3 / 15: the Applet-managed delegated device
    // authorization is an ordinary successor Event inside the principal's own
    // `applet_managed_control` PCR, authorized by that principal's controller
    // method. It is not an Applet-delegated write: the Approved Capability Set
    // has no action for it, and the install grants the Applet no say in which
    // devices the principal it provisioned holds. Matching it here would
    // therefore demand a grant that MUST NOT exist. Its own preconditions --
    // self-anchor, exact `applet_id`, accepted provision and genesis, and the
    // install revoke fence -- run in `validate_device_authorization_binding`,
    // which also rejects the envelope authority fields whose absence selects
    // this branch.
    if kind == arkret_wire::event_kind_str::DEVICE_AUTHORIZE
        && applet_id.is_none()
        && authorization_ref.is_none()
        && object
            .get("payload")
            .and_then(Value::as_object)
            .and_then(|payload| payload.get("authorization_binding_kind"))
            .and_then(Value::as_str)
            == Some("applet_managed_delegation")
    {
        return Ok(true);
    }
    let is_rotation = kind == arkret_wire::event_kind_str::IDENTITY_RESOLUTION_UPDATE;
    let event_scope = if is_rotation {
        None
    } else {
        Some(
            serde_json::from_value::<arkret_wire::ScopeRef>(
                object.get("scope_ref").cloned().ok_or_else(|| {
                    event_validation_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "schema_violation",
                        "Applet-managed actor Event requires scope_ref",
                    )
                })?,
            )
            .map_err(|error| {
                event_validation_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
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
        let bot_match = record.bot_actor_id == event_actor;
        let ghost_match = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id == event_actor);
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
                record.bot_actor_id.route_service_id().to_string(),
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
                ghost.ghost_actor_id.route_service_id().to_string(),
                provision.applet_authority_ref.to_string(),
                ghost.principal_control_realm_id().to_string(),
            )
        };
        if expected_server != station_id {
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
        if !bot_match
            && !applet_grant_holder_authorization(
                state,
                record.portal_realm_id.as_str(),
                &arkret_wire::ActorId::service(record.package.service_id.clone()),
            )
            .await?
            .grants
            .iter()
            .any(|effective| effective.grant.id.as_str() == expected_authorization)
        {
            continue;
        }
        if is_rotation {
            debug_assert_eq!(realm_id, expected_pcr_realm);
        }
        {
            let producer: arkret_wire::ActorId = serde_json::from_value(
                object
                    .get("executed_by")
                    .or_else(|| object.get("actor_id"))
                    .cloned()
                    .ok_or_else(|| {
                        event_validation_error(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "schema_violation",
                            "Applet-managed write requires a producer ActorId",
                        )
                    })?,
            )
            .map_err(|error| {
                event_validation_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "schema_violation",
                    format!("invalid Applet producer ActorId: {error}"),
                )
            })?;
            let authorization = applet_grant_holder_authorization(
                state,
                record.portal_realm_id.as_str(),
                &producer,
            )
            .await?;
            let event_id = event_string_field(object, &["event_id"]).unwrap_or_default();
            let resources =
                delegated_applet_resource_candidates(&authorization.realm_id, object, &event_id);
            let grant = authorization
                .grants
                .iter()
                .map(|effective| &effective.grant)
                .find(|grant| {
                    authorization_ref.as_deref() == Some(grant.id.as_str())
                        && resources.iter().any(|resource| {
                            soland_storage::grant_names_target(grant, &[kind], resource)
                        })
                });
            let Some(grant) = grant else {
                continue;
            };
            validate_applet_authority_binding(
                grant,
                record.applet_id.as_str(),
                &producer,
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
#[allow(
    clippy::items_after_test_module,
    reason = "the focused regression tests stay adjacent to their private scope-selection helper"
)]
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
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    applet_id: &str,
    executed_by: &arkret_wire::ActorId,
) -> Result<(), EventValidationError> {
    validate_applet_authority_binding(
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

    if executed_by == &arkret_wire::ActorId::service(package.service_id.clone())
        && let Some(verification_method) = event_proof_verification_method(object)
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

pub(super) fn applet_delegation_binding_reason(error: AppletAuthorityBindingError) -> &'static str {
    match error {
        AppletAuthorityBindingError::Missing => "applet_registration_epoch_binding_missing",
        AppletAuthorityBindingError::AppletIdMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        AppletAuthorityBindingError::ExecutedByMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        AppletAuthorityBindingError::RegistrationEpochMismatch => {
            "applet_registration_epoch_mismatch"
        }
    }
}

/// Why an Applet-delegated grant does not bind the executing Applet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AppletAuthorityBindingError {
    Missing,
    AppletIdMismatch,
    ExecutedByMismatch,
    RegistrationEpochMismatch,
}

/// `constraint-schema.md` §7.3: an Applet install grant carries exactly one
/// `authority_control`/`applet_authority` binding naming the Applet, its
/// executing actor and the registration epoch it was issued under.
pub(super) fn validate_applet_authority_binding(
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    applet_id: &str,
    executed_by: &arkret_wire::ActorId,
    registration_epoch: &str,
) -> Result<(), AppletAuthorityBindingError> {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintKind, GrantConstraintSubkind,
    };
    let binding = grant
        .constraints
        .iter()
        .find(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                && constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
        })
        .ok_or(AppletAuthorityBindingError::Missing)?;
    let (Some(binding_applet_id), Some(binding_executed_by), Some(binding_epoch)) = (
        binding.applet_id.as_ref(),
        binding.executed_by.as_ref(),
        binding.registration_epoch.as_ref(),
    ) else {
        return Err(AppletAuthorityBindingError::Missing);
    };
    if binding_applet_id.as_str() != applet_id {
        return Err(AppletAuthorityBindingError::AppletIdMismatch);
    }
    if binding_executed_by != executed_by {
        return Err(AppletAuthorityBindingError::ExecutedByMismatch);
    }
    if binding_epoch.as_str() != registration_epoch {
        return Err(AppletAuthorityBindingError::RegistrationEpochMismatch);
    }
    Ok(())
}

pub(super) fn applet_executor_in_subject_set(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    service_id: &str,
    executed_by: &arkret_wire::ActorId,
) -> bool {
    matches!(executed_by, arkret_wire::ActorId::Service { service_id: executor } if executor.as_str() == service_id)
        || executed_by == &record.bot_actor_id
        || record
            .ghosts
            .iter()
            .any(|ghost| &ghost.ghost_actor_id == executed_by)
        || (executed_by.route_service_id().as_str() == service_id
            && applet_actor_matches_exact_namespace(
                record,
                executed_by.signing_principal_id().as_str(),
            ))
}

pub(super) fn applet_actor_is_managed(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    actor_id == record.bot_actor_id.signing_principal_id().as_str()
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id.signing_principal_id().as_str() == actor_id)
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

/// The resources an Applet-delegated Event acts on inside `realm_id`: the
/// Realm, the Event itself, and every Realm object its payload targets.
pub(super) fn delegated_applet_resource_candidates(
    realm_id: &arkret_wire::RealmId,
    object: &serde_json::Map<String, Value>,
    event_id: &str,
) -> Vec<arkret_wire::WireResourceSelector> {
    let mut resources = vec![arkret_wire::WireResourceSelector::realm(realm_id.clone())];
    resources.extend(crate::authz::resource_selector(realm_id, event_id));
    if let Some(payload) = object.get("payload").and_then(Value::as_object) {
        for field in ["strand_id", "message_id", "object_id", "target_ref"] {
            if let Some(value) = event_string_field(payload, &[field]) {
                resources.extend(crate::authz::resource_selector(realm_id, &value));
            }
        }
    }
    resources
}

/// The durable authorization of an Applet grant holder in `realm_id`, read at
/// this instant.
async fn applet_grant_holder_authorization(
    state: &AppState,
    realm_id: &str,
    holder: &arkret_wire::ActorId,
) -> Result<soland_storage::ActorRealmAuthorization, EventValidationError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "Applet Event realm_id is invalid",
        )
    })?;
    crate::authz::actor_realm_authorization(state, &realm_id, holder, chrono::Utc::now())
        .await
        .map_err(|error| {
            tracing::error!(?error, %realm_id, "applet grant read failed");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "applet authorization store unavailable",
            )
        })
}

pub(super) fn event_proof_verification_method(
    object: &serde_json::Map<String, Value>,
) -> Option<String> {
    object
        .get("producer_proof")
        .and_then(Value::as_object)
        .and_then(|proof| event_string_field(proof, &["verification_method"]))
}
