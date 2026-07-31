//! Ghost / bot actor provisioning, revocation, and caller-signed proof checks.

use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use arkret_models_integration::{
    AppletNamespaceDomain, GhostActorProvisionRequestBody, namespace_pattern_matches,
};
use arkret_wire::{CapabilityActionId, Event};
use serde_json::{Value, json};
use soland_http::error::AppError;

use super::record::{
    applet_record, applet_records, ensure_not_revoked, extension_actor_id_document,
    ghost_actor_id_for, persist_applet_record,
};
use super::types::{AppletGhostIngressRequestBody, AppletRecord, GhostActorRecord};
use crate::state::AppState;

pub(super) async fn revoke_applet_record(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    revoke_applet_record_inner(state, actor, applet_id, true).await
}

pub(super) async fn revoke_applet_record_after_admin_gate(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    revoke_applet_record_inner(state, actor, applet_id, false).await
}

async fn revoke_applet_record_inner(
    state: &AppState,
    actor: &str,
    applet_id: &str,
    require_owner: bool,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    let now = chrono::Utc::now();
    let mut record = applet_record(state, applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    if require_owner && record.owner_actor_id != actor {
        return Err(AppError::capability_denied(
            "only the registering actor can revoke this applet",
        ));
    }
    record.status = "revoked".to_owned();
    record.revoked_at = Some(now);
    for ghost in &mut record.ghosts {
        ghost.revoked_at.get_or_insert(now);
    }
    // SOL-HYG-01: the applet record persisted above carries the durable
    // revocation state (`status` / `revoked_at` on the applet and on each
    // ghost); the prior in-memory `bot_actor::revoke_bot` shadow was redundant
    // and not durable across restart / replicas.
    persist_applet_record(state, &record).await?;
    crate::routing::append_audit_log(
        state,
        Some(actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id,
            "bot_actor_id": record.bot_actor_id,
            "ghost_count": record.ghosts.len(),
        }),
        "accepted",
    )
    .await;
    Ok(super::types::AppletRevokeRecordOutcome {
        applet_id: record.applet_id,
        status: "revoked".to_owned(),
        revoked_at: now,
        bot_actor_id: record.bot_actor_id,
        ghost_actor_ids: record
            .ghosts
            .iter()
            .map(|ghost| ghost.ghost_actor_id.clone())
            .collect(),
    })
}

pub async fn did_document_for_extension_actor(
    state: &AppState,
    did: &str,
) -> Result<Option<Value>, AppError> {
    for record in applet_records(state).await? {
        if record.bot_actor_id == did {
            let status = if record.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            return Ok(Some(extension_actor_id_document(
                did,
                "bot_actor",
                status,
                &record.owner_actor_id,
                &record,
                None,
            )));
        }
        if let Some(ghost) = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id == did)
        {
            let status = if record.revoked_at.is_some() || ghost.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            return Ok(Some(extension_actor_id_document(
                did,
                "ghost_actor",
                status,
                &record.bot_actor_id,
                &record,
                Some(ghost),
            )));
        }
    }
    Ok(None)
}

pub(super) fn validate_ghost_actor_provision_request(
    path_applet_id: &str,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    if provision.schema != arkret_wire::GHOST_ACTOR_PROVISION_REQUEST_SCHEMA {
        return Err(AppError::invalid_param(format!(
            "schema must be {}",
            arkret_wire::GHOST_ACTOR_PROVISION_REQUEST_SCHEMA
        )));
    }
    if provision.applet_id.as_str() != path_applet_id {
        return Err(AppError::invalid_param(
            "body applet_id must match applet_id path segment",
        ));
    }
    for (field, value) in [
        ("protocol", provision.protocol.as_str()),
        ("tenant", provision.tenant.as_str()),
        ("external_user_id", provision.external_user_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(AppError::missing_param(format!("{field} is required")));
        }
    }
    if let Some(display_name) = provision.display_name.as_deref()
        && display_name.trim().is_empty()
    {
        return Err(AppError::invalid_param(
            "display_name must be omitted or non-empty",
        ));
    }
    Ok(())
}

pub(super) fn ensure_formal_ghost_provision_allowed(
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    let package = record.package.as_ref().ok_or_else(|| {
        AppError::conflict("formal ghost provisioning requires package install")
            .with_wire_code("applet_install_required")
    })?;
    if package.service_id != provision.service_id {
        return Err(AppError::capability_denied(
            "service_id does not match installed applet package",
        ));
    }
    if record.portal_realm_id != provision.realm_id.as_str() {
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
    if let Some(namespaces) = record.namespaces.as_ref()
        && !namespaces.actors.is_empty()
        && !namespaces.actors.iter().any(|entry| {
            namespace_pattern_matches(
                AppletNamespaceDomain::Actors,
                &entry.pattern,
                provision.ghost_actor_id.as_str(),
            )
        })
    {
        return Err(AppError::capability_denied(
            "ghost_actor_id is outside the installed applet actor namespace",
        )
        .with_wire_code("applet_namespace_mismatch"));
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
        if payload.grant.as_ref().is_some_and(|grant| {
            grant
                .actions
                .iter()
                .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION)
        }) {
            return Ok(payload.grant_id.to_string());
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
) -> Result<String, AppError> {
    let accountability = &provision.accountability_grant_event;
    let profile = &provision.profile_event;
    let authorization_ref = ghost_provision_authorization_ref(record)?;
    let registration_verification_method =
        super::signature::applet_registration_verification_method(
            record,
            provision.service_id.as_str(),
        )?;
    let applet_matches = |event: &Event| {
        event.applet_id.as_ref() == Some(&provision.applet_id)
            && event.authorization_ref.as_deref() == Some(authorization_ref.as_str())
    };
    if accountability.kind.as_str() != arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT
        || accountability.realm_id != provision.realm_id
        || accountability.actor_id != provision.service_id
        || accountability.executed_by.is_some()
        || !applet_matches(accountability)
    {
        return Err(AppError::invalid_param(
            "accountability_grant_event envelope does not match the Applet provision binding",
        ));
    }
    if profile.kind.as_str() != arkret_wire::EventKind::PROFILE_CREATE
        || profile.realm_id != provision.realm_id
        || profile.actor_id != provision.ghost_actor_id
        || profile.executed_by.as_ref() != Some(&provision.service_id)
        || !applet_matches(profile)
    {
        return Err(AppError::invalid_param(
            "profile_event envelope does not match the delegated Ghost provision binding",
        ));
    }
    if !profile.refs.iter().any(|event_ref| {
        event_ref.id == accountability.event_id.as_str()
            && event_ref.role == "accountability"
            && event_ref.critical
    }) {
        return Err(AppError::invalid_param(
            "profile_event must critically reference accountability_grant_event",
        ));
    }
    if accountability
        .proofs
        .iter()
        .chain(profile.proofs.iter())
        .any(|proof| proof.verification_method != registration_verification_method)
    {
        return Err(AppError::capability_denied(
            "Ghost provisioning Event proofs must use the installed registration-epoch key",
        )
        .with_wire_code("invalid_proof"));
    }

    let grant: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&accountability.payload).map_err(|error| {
            AppError::invalid_param(format!(
                "accountability_grant_event payload invalid: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        AppError::invalid_param(format!(
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
        return Err(AppError::invalid_param(
            "accountability_grant_event payload does not bind the service to the Ghost",
        ));
    }
    grant
        .validate_lifecycle_at(chrono::Utc::now())
        .map_err(|error| {
            AppError::invalid_param(format!(
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
        AppError::invalid_param(format!(
            "accountability payload proof binding is invalid: {error}"
        ))
    })?;
    crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
        &proof_binding,
        &grant.proof.jws,
        &grant.proof.verification_method,
        provision.service_id.as_str(),
        state,
    )
    .await
    .map_err(|error| {
        AppError::invalid_param(format!(
            "accountability payload proof JWS verification failed: {error}"
        ))
        .with_wire_code("invalid_proof")
    })?;

    let profile_payload: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(serde_json::to_value(&profile.payload).map_err(|error| {
            AppError::invalid_param(format!("profile_event payload invalid: {error}"))
        })?)
        .map_err(|error| {
            AppError::invalid_param(format!("profile_event payload invalid: {error}"))
        })?;
    let actor_profile = profile_payload.object;
    let expected_display_name = provision
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(provision.external_user_id.as_str());
    let expected_external_ref = json!({
        "schema": "ak.applet.ghost_actor.external_ref.v1",
        "protocol": provision.protocol,
        "tenant": provision.tenant,
        "external_user_id": provision.external_user_id,
        "realm_id": provision.realm_id,
        "external_ref": provision.external_ref,
    });
    let has_exact_accountable_principal = actor_profile.accountable_principal_ids.len() == 1
        && actor_profile.accountable_principal_ids[0] == provision.service_id;
    if actor_profile.principal_id != provision.ghost_actor_id
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
        return Err(AppError::invalid_param(
            "profile_event payload does not exactly match the Ghost provision request",
        ));
    }
    Ok(authorization_ref)
}

pub(super) async fn provision_ghost(
    state: &AppState,
    applet_id: &str,
    external_id: &str,
    display_name: Option<String>,
) -> Result<(AppletRecord, GhostActorRecord), AppError> {
    let now = chrono::Utc::now();
    let mut record = applet_record(state, applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    ensure_not_revoked(&record)?;
    if !record.ghost_actors_allowed {
        return Err(AppError::capability_denied(
            "applet install does not grant ghost actor provisioning",
        ));
    }
    if let Some(existing) = record
        .ghosts
        .iter()
        .find(|ghost| ghost.external_id == external_id)
        .cloned()
    {
        return Ok((record, existing));
    }
    let ghost = GhostActorRecord {
        ghost_actor_id: ghost_actor_id_for(&record.namespace, applet_id, external_id),
        external_id: external_id.to_owned(),
        display_name,
        request_digest: None,
        profile_event_ref: None,
        accountability_grant_ref: None,
        authorization_ref: None,
        created_at: now,
        revoked_at: None,
    };
    record.ghosts.push(ghost.clone());
    // SOL-HYG-01: persisting the applet record (with the freshly pushed ghost)
    // is the durable source of truth for ghost liveness; no separate in-memory
    // registry write is needed.
    persist_applet_record(state, &record).await?;
    Ok((record, ghost))
}

pub(super) fn external_user_from_ghost_request(
    body: &AppletGhostIngressRequestBody,
) -> Result<(String, Option<String>), AppError> {
    if let Some(external_user) = &body.external_user {
        let external_id = external_user
            .id
            .as_deref()
            .or(external_user.external_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::missing_param("external_user.id is required"))?;
        let display_name = external_user.display_name.clone();
        return Ok((external_id.to_owned(), display_name));
    }
    let external_id = body
        .external_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("external_id is required"))?;
    let display_name = body.display_name.clone();
    Ok((external_id.to_owned(), display_name))
}
