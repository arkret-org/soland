//! Ghost / bot actor provisioning, revocation, and caller-signed proof checks.

use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use arkret_models_integration::{
    AppletManagedActorProvisionPayload, AppletManagedActorRole, AppletNamespaceDomain,
    GhostActorProvisionRequestBody, namespace_pattern_matches,
};
use arkret_wire::{CapabilityActionId, Event};
use serde_json::{Value, json};
use soland_http::error::AppError;

use super::install::registration_epoch_evidence_from_event;
use super::record::{applet_record, persist_applet_record};
use super::types::AppletRecord;
use crate::state::AppState;

pub(super) async fn revoke_applet_record_after_admin_gate(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    revoke_applet_record_inner(state, actor, applet_id).await
}

async fn revoke_applet_record_inner(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    let mut attempts = 0_u8;
    let record = loop {
        let current = applet_record(state, applet_id)
            .await?
            .ok_or_else(|| AppError::not_found("applet is not registered"))?;
        if current.status == "revoked" {
            break current;
        }
        let mut replacement = current.clone();
        replacement.status = "revoked".to_owned();
        replacement.revoked_at = Some(chrono::Utc::now());
        // Ghost principals follow the Applet lifecycle; the Applet
        // registration fence is the sole durable write-admission state.
        if persist_applet_record(state, &current, &replacement).await? {
            break replacement;
        }
        attempts += 1;
        if attempts >= 8 {
            return Err(
                AppError::conflict("Applet record changed repeatedly during revoke")
                    .with_wire_code("cas_conflict"),
            );
        }
    };
    let now = record
        .revoked_at
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::internal("revoked Applet has no revoked_at"))?;
    crate::routing::append_audit_log(
        state,
        Some(actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id.clone(),
            "bot_actor_id": record.bot_actor_id,
            "ghost_count": record.ghosts.len(),
        }),
        "accepted",
    )
    .await;
    Ok(super::types::AppletRevokeRecordOutcome {
        applet_id: record.applet_id.clone(),
        status: "revoked".to_owned(),
        revoked_at: now,
        bot_actor_id: record.bot_actor_id.to_string(),
        ghost_actor_ids: record
            .ghosts
            .iter()
            .map(|ghost| ghost.ghost_actor_id.to_string())
            .collect(),
    })
}

pub(super) fn validate_ghost_actor_provision_request(
    path_applet_id: &str,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    if provision.schema != GhostActorProvisionRequestBody::SCHEMA {
        return Err(AppError::param_invalid(
            "schema must be ak.applet.ghost_actor.provision_request.v1",
        ));
    }
    if provision.applet_id.as_str() != path_applet_id {
        return Err(AppError::param_invalid(
            "body applet_id must match applet_id path segment",
        ));
    }
    for (field, value) in [
        (
            "external_ref.protocol",
            provision.external_ref.protocol.as_str(),
        ),
        (
            "external_ref.instance_id",
            provision.external_ref.instance_id.as_str(),
        ),
        (
            "external_ref.external_id",
            provision.external_ref.external_id.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(AppError::param_missing(format!("{field} is required")));
        }
    }
    if let Some(display_name) = provision.display_name.as_deref()
        && display_name.trim().is_empty()
    {
        return Err(AppError::param_invalid(
            "display_name must be omitted or non-empty",
        ));
    }
    Ok(())
}

pub(super) fn ensure_formal_ghost_provision_allowed(
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    let package = &record.package;
    if package.service_id != provision.service_id {
        return Err(AppError::capability_denied(
            "service_id does not match installed applet package",
        ));
    }
    if record.portal_realm_id != provision.realm_id {
        return Err(
            AppError::conflict("realm_id does not match installed applet effective scope")
                .with_wire_code("applet_effective_scope_mismatch"),
        );
    }
    if !record.ghost_actors_allowed {
        return Err(AppError::capability_denied(
            "applet install does not grant ghost actor provisioning",
        ));
    }
    Ok(())
}

pub(super) fn ghost_provision_authorization_ref(record: &AppletRecord) -> Result<String, AppError> {
    if !record
        .capabilities
        .iter()
        .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
    {
        return Err(AppError::capability_denied(
            "applet install does not grant ak.applet.ghost.provision",
        ));
    }
    for event in &record.capability_grant_events {
        let payload = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::CapabilityGrantPayload,
        >(serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!(
                "stored Applet capability grant payload cannot be encoded: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::internal(format!(
                "stored Applet capability grant payload is invalid: {error}"
            ))
        })?;
        if payload
            .grant
            .actions
            .iter()
            .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
        {
            return Ok(arkret_identifiers::GrantId::from_event_id(&event.event_id).to_string());
        }
    }
    Err(
        AppError::conflict("applet ghost provisioning grant projection is incomplete")
            .with_wire_code("applet_install_projection_incomplete"),
    )
}

pub(super) async fn validate_signed_ghost_provision_events(
    state: &AppState,
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(String, AppletManagedActorProvisionPayload), AppError> {
    let accountability = &provision.accountability_grant_event;
    let profile = &provision.profile_event;
    let service_actor_id = provision.service_id.clone();
    let ghost_actor_id = provision.ghost_actor_id.clone();
    let authorization_ref = ghost_provision_authorization_ref(record)?;
    let managed_provision =
        validate_ghost_managed_actor_unit(state, record, provision, authorization_ref.as_str())
            .await?;
    let registration_verification_method =
        super::signature::applet_registration_verification_method(
            record,
            provision.service_id.as_str(),
        )?;
    let applet_matches = |event: &Event| {
        event.applet_id.as_ref() == Some(&provision.applet_id)
            && event.authorization_ref.as_deref() == Some(authorization_ref.as_str())
    };
    if accountability.kind != arkret_wire::EventKind::IdentityAccountabilityGrant
        || accountability.realm_id != provision.realm_id
        || accountability.actor_id != service_actor_id
        || accountability.executed_by.is_some()
        || !applet_matches(accountability)
    {
        return Err(AppError::param_invalid(
            "accountability_grant_event envelope does not match the Applet provision binding",
        ));
    }
    if profile.kind != arkret_wire::EventKind::ProfileCreate
        || profile.realm_id != provision.realm_id
        || profile.actor_id != ghost_actor_id
        || profile.executed_by.as_ref() != Some(&service_actor_id)
        || !applet_matches(profile)
    {
        return Err(AppError::param_invalid(
            "profile_event envelope does not match the delegated Ghost provision binding",
        ));
    }
    let accountability_refs = profile
        .refs
        .iter()
        .filter(|event_ref| event_ref.role == "accountability")
        .collect::<Vec<_>>();
    if accountability_refs.len() != 1
        || accountability_refs[0].id != accountability.event_id.as_str()
        || !accountability_refs[0].critical
    {
        return Err(AppError::param_invalid(
            "profile_event must critically reference accountability_grant_event",
        ));
    }
    if accountability
        .proofs
        .iter()
        .chain(profile.proofs.iter())
        .any(|proof| {
            proof
                .as_producer()
                .is_none_or(|proof| proof.verification_method != registration_verification_method)
        })
    {
        return Err(AppError::capability_denied(
            "Ghost provisioning Event proofs must use the installed registration-epoch key",
        )
        .with_wire_code("invalid_proof"));
    }

    let grant: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&accountability.payload).map_err(|error| {
            AppError::param_invalid(format!(
                "accountability_grant_event payload invalid: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        AppError::param_invalid(format!(
            "accountability_grant_event payload invalid: {error}"
        ))
    })?;
    if grant.issuer != provision.service_id
        || grant.subject != provision.ghost_actor_id
        || grant.accountability_scope
            != AccountabilityScope::Single(AccountabilityScopeKind::ContractedService)
        || !matches!(
            grant.grant_status,
            arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active
        )
    {
        return Err(AppError::param_invalid(
            "accountability_grant_event payload does not bind the service to the Ghost",
        ));
    }
    grant
        .validate_lifecycle_at(chrono::Utc::now())
        .map_err(|error| {
            AppError::param_invalid(format!(
                "accountability_grant_event payload invalid: {error}"
            ))
        })?;
    if grant.proof.verification_method != registration_verification_method {
        return Err(AppError::capability_denied(
            "accountability payload proof must use the installed registration-epoch key",
        )
        .with_wire_code("invalid_proof"));
    }
    let proof_binding = grant.canonical_proof_binding_bytes().map_err(|error| {
        AppError::param_invalid(format!(
            "accountability payload proof binding is invalid: {error}"
        ))
    })?;
    verify_registration_epoch_payload_jws(
        state,
        record,
        &proof_binding,
        &grant.proof.jws,
        grant.proof.verification_method.as_str(),
    )
    .map_err(|error| {
        AppError::param_invalid(format!(
            "accountability payload proof JWS verification failed: {error}"
        ))
        .with_wire_code("invalid_proof")
    })?;

    let profile_payload: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(serde_json::to_value(&profile.payload).map_err(|error| {
            AppError::param_invalid(format!("profile_event payload invalid: {error}"))
        })?)
        .map_err(|error| {
            AppError::param_invalid(format!("profile_event payload invalid: {error}"))
        })?;
    let actor_profile = profile_payload.object;
    let expected_display_name = provision
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(provision.external_ref.external_id.as_str());
    let expected_external_ref = serde_json::to_value(&provision.external_ref).map_err(|error| {
        AppError::internal(format!("external_ref serialization failed: {error}"))
    })?;
    let has_exact_accountable_principal = actor_profile.accountable_principal_ids.len() == 1
        && actor_profile.accountable_principal_ids[0].as_str() == service_actor_id.as_str();
    if actor_profile.principal_id.as_str() != ghost_actor_id.as_str()
        || actor_profile.realm_id.as_ref() != Some(&provision.realm_id)
        || actor_profile.actor_kind != arkret_wire::ActorKind::Integration
        || actor_profile.display_name != expected_display_name
        || actor_profile
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(provision.applet_id.as_str())
        || actor_profile.profile_fields.get("external_ref") != Some(&expected_external_ref)
        || !has_exact_accountable_principal
    {
        return Err(AppError::param_invalid(
            "profile_event payload does not exactly match the Ghost provision request",
        ));
    }
    Ok((authorization_ref, managed_provision))
}

async fn validate_ghost_managed_actor_unit(
    state: &AppState,
    record: &AppletRecord,
    request: &GhostActorProvisionRequestBody,
    authorization_ref: &str,
) -> Result<AppletManagedActorProvisionPayload, AppError> {
    let event = &request.managed_actor_provision_event;
    if event.kind.as_str() != "ak.applet.managed_actor.provision"
        || event.actor_id != request.service_id
        || event.applet_id.as_ref() != Some(&request.applet_id)
        || event.realm_id != request.realm_id
        || event.proofs.is_empty()
    {
        return Err(AppError::param_invalid(
            "managed_actor_provision_event does not match the installed Applet service",
        )
        .with_wire_code("applet_managed_actor_provision_invalid"));
    }
    let payload: AppletManagedActorProvisionPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!(
                "managed actor provision serialization failed: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::param_invalid(format!("managed actor provision payload invalid: {error}"))
                .with_wire_code("applet_managed_actor_provision_invalid")
        })?;
    payload.validate().map_err(|error| {
        AppError::param_invalid(format!("managed actor provision payload invalid: {error}"))
            .with_wire_code("applet_managed_actor_provision_invalid")
    })?;
    if payload.actor_role != AppletManagedActorRole::Ghost
        || payload.applet_id != request.applet_id
        || payload.service_id != request.service_id
        || payload.actor_id != request.ghost_actor_id
        || payload.actor_id == record.package.controller_id
        || payload.actor_id == record.package.bot_actor_id
        || payload.actor_principal_server_id != request.actor_principal_server_id
        || payload.actor_principal_server_id.as_str() != state.service_id()
        || record.registration_event.event_id != payload.registration_ref
        || payload.applet_authority_ref.as_str() != authorization_ref
        || payload.external_ref.as_ref() != Some(&request.external_ref)
    {
        return Err(AppError::param_invalid(
            "Ghost provision authority does not bind the exact authority pair, registration, grant, or external principal",
        )
        .with_wire_code("applet_managed_actor_provision_invalid"));
    }
    super::install::validate_managed_actor_method_evidence(&payload)?;
    super::install::validate_managed_actor_current_method_evidence(state, &payload).await?;
    if !record.package.namespaces.actors.is_empty()
        && !record.package.namespaces.actors.iter().any(|entry| {
            namespace_pattern_matches(
                AppletNamespaceDomain::Actors,
                &entry.pattern,
                payload.initial_resolution.full_id.as_str(),
            )
        })
    {
        return Err(AppError::capability_denied(
            "Ghost full_id is outside the installed Applet actor namespace",
        )
        .with_wire_code("applet_namespace_mismatch"));
    }

    let genesis = &request.pcr_genesis_event;
    let expected_realm_id = arkret_wire::RealmId::from_event_id(&genesis.event_id);
    let genesis_object: arkret_models_collaboration::events_payloads::RealmGenesis =
        serde_json::from_value(
            genesis
                .payload
                .get("object")
                .cloned()
                .ok_or_else(|| AppError::param_missing("Ghost PCR genesis object is required"))?,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("Ghost PCR genesis object is invalid: {error}"))
                .with_wire_code("applet_managed_pcr_genesis_invalid")
        })?;
    let expected_host_notary = arkret_wire::NotaryValue::single_signer(
        state
            .service_notary_signer_descriptor()
            .map_err(AppError::internal)?,
    );
    super::install::validate_hosted_applet_pcr_notary(
        &genesis_object.notary,
        &expected_host_notary,
    )?;
    let provision_ref_count = genesis
        .refs
        .iter()
        .filter(|reference| {
            reference.role == "applet_managed_actor_provision"
                && reference.critical
                && reference.id == event.event_id.as_str()
        })
        .count();
    let provision_role_count = genesis
        .refs
        .iter()
        .filter(|reference| reference.role == "applet_managed_actor_provision")
        .count();
    if genesis.kind != arkret_wire::EventKind::RealmCreate
        || genesis.actor_id != request.ghost_actor_id
        || genesis.executed_by.as_ref() != Some(&request.service_id)
        || genesis.principal_server_id != payload.actor_principal_server_id
        || genesis.applet_id.as_ref() != Some(&request.applet_id)
        || genesis.realm_id != expected_realm_id
        || genesis.authorization_ref.as_deref() != Some(authorization_ref)
        || provision_role_count != 1
        || provision_ref_count != 1
        || genesis_object.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
        || genesis_object.initial_resolution.as_ref() != Some(&payload.initial_resolution)
    {
        return Err(AppError::param_invalid(
            "Ghost PCR genesis does not exactly cross-bind its immutable provision authority",
        )
        .with_wire_code("applet_managed_pcr_genesis_invalid"));
    }
    Ok(payload)
}

fn verify_registration_epoch_payload_jws(
    state: &AppState,
    record: &AppletRecord,
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
) -> Result<(), String> {
    let evidence = registration_epoch_evidence_from_event(&record.registration_event)
        .map_err(|error| error.to_string())?;
    if !evidence.contains_signing_key(verification_method) {
        return Err("payload proof key is outside the installed registration epoch".to_owned());
    }
    let document = crate::jws_verify::resolve_did_document(state, &evidence.full_id)?;
    evidence
        .validate_against_did_document(&document)
        .map_err(|error| format!("registration-epoch DID evidence mismatch: {error}"))?;
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| format!("payload proof verification method is invalid: {error}"))?;
    arkret_identity::verify_jws_with_document(
        canonical_bytes,
        jws,
        &verification_method,
        &evidence.full_id,
        &document,
    )
    .map_err(|error| error.to_string())
}
