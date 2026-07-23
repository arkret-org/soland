//! Canonical applet install: package validation, plan building, registration
//! projection, portal message ingress, and the realm-admin governance gate.

use std::collections::BTreeSet;

use arkret_core::{
    AppletApprovalRequest, AppletGhostActorMode, AppletId, AppletInstallAppletId,
    AppletInstallEffectiveStatus, AppletInstallOutcome, AppletInstallPlan,
    AppletInstallRequestBody, AppletPackage, AppletRejectedItem, AppletWireNamespaces,
    CapabilityConstraint, DeniedScope, Did, E2eeEffect, E2eePolicy, EffectiveScope, EventId,
    EventSubmission, GrantId, NamespaceConflict, RealmId, ScopeGrant, WidgetEffect,
};
use arkret_identity::DidDocument;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_application::events::{MessageState, ProjectedEvent as ProjectionEventRecord};
use soland_http::error::AppError;

use super::super::applet_manifest::{AppletManifest, VerifiedAppletManifest};
use super::record::{
    applet_record, applet_records, bot_actor_id_for, manifest_namespace, persist_applet_record,
    portal_realm_id_for, safe_token,
};
use super::types::{
    AppletManifestRegisterRequestBody, AppletPortalMessageOutcome, AppletRecord, AppletView,
    GhostActorRecord,
};
use crate::ids;
use crate::routing::events::strand::strand_id_from_realm_id;
use crate::state::AppState;

pub(super) const GHOST_PROVISION_ACTION: &str = "ak.applet.ghost.provision";

pub(super) async fn register_package_install(
    state: &AppState,
    owner_actor_id: &str,
    commit: AppletInstallRequestBody,
    idempotency_key: String,
    body_digest: String,
    res: &mut Response,
) -> Result<AppletInstallOutcome, AppError> {
    let submitted_plan_digest = commit.plan_digest.to_string();
    let package = commit.applet_package;
    let applet_id = package.applet_id.clone();
    let namespace = package_namespace(&package);
    let realm_id = effective_scope_realm_id(&commit.effective_scope);
    let approved_actions = actions_from_approved_scopes(&commit.approved_scopes);
    let allow_ghost_actors =
        allow_ghost_actors_for_install(&package, &approved_actions, commit.actor_policy.as_ref());

    if let Some(existing) = applet_record(state, &applet_id).await? {
        if existing.idempotency_key.as_deref() == Some(idempotency_key.as_str()) {
            if existing.install_body_digest.as_deref() == Some(body_digest.as_str())
                && let Some(response) = &existing.install_response
            {
                let mut recovered = existing.clone();
                if recovered.install_execution.is_none() {
                    recovered.install_execution = Some(build_install_execution_record(
                        state.service_id(),
                        owner_actor_id,
                        &idempotency_key,
                        &body_digest,
                        &submitted_plan_digest,
                        &recovered,
                        response,
                        false,
                    )?);
                    persist_applet_record(state, &recovered).await?;
                }
                recover_applet_install_fanout(state, &mut recovered, response).await?;
                res.status_code(StatusCode::OK);
                return Ok(response.clone());
            }
            return Err(AppError::conflict(
                "Idempotency-Key was already used with a different applet install body",
            )
            .with_wire_code("duplicate_conflict"));
        }
        return Err(AppError::conflict("applet package id is already installed")
            .with_wire_code("applet_already_registered"));
    }

    let namespace_conflicts =
        namespace_conflicts_for(state, &applet_id, &package.namespaces).await?;
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }

    let now = chrono::Utc::now();
    let registration_event_ref = EventId::new(ids::generate_event_id())
        .map_err(|error| AppError::internal(format!("generated event id is invalid: {error}")))?;
    let capability_grant_refs = approved_actions
        .iter()
        .map(|_| {
            GrantId::new(ids::generate_grant_id()).map_err(|error| {
                AppError::internal(format!("generated capability grant id is invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let e2ee_authorization_refs =
        e2ee_authorization_refs_for_install(&package, commit.e2ee_policy.as_ref())?;
    let effective_status = if approved_actions.is_empty() {
        AppletInstallEffectiveStatus::Rejected
    } else if approved_actions.len() < package.requested_scopes.len() {
        AppletInstallEffectiveStatus::PartiallyInstalled
    } else {
        AppletInstallEffectiveStatus::Installed
    };
    let effective_status_wire = match effective_status {
        AppletInstallEffectiveStatus::Installed => "installed",
        AppletInstallEffectiveStatus::PartiallyInstalled => "partially_installed",
        AppletInstallEffectiveStatus::Rejected => "rejected",
    };
    // G3.S9 — bot actor DID recorded against the applet MUST be a
    // well-formed bare DID scalar (no DID URL fragment).
    crate::routing::extensions::bot_actor::validate_extension_actor_did(
        package.bot_actor_id.as_str(),
    )?;
    let install_id = ids::generate_install_id();
    let response = AppletInstallOutcome {
        ok: effective_status != AppletInstallEffectiveStatus::Rejected,
        install_id,
        applet_id: applet_id.clone(),
        registration_event_ref: Some(registration_event_ref.clone()),
        registration_epoch: package.registration_epoch.clone(),
        bot_actor_id: package.bot_actor_id.clone(),
        capability_grant_refs,
        membership_event_refs: Vec::new(),
        e2ee_authorization_refs,
        widget_policy_ref: None,
        effective_status,
        rejected: denied_scope_values(&package, &approved_actions)
            .into_iter()
            .map(|scope| AppletRejectedItem {
                requested_scope: Some(scope.requested_scope),
                reason_code: scope.reason_code,
            })
            .collect(),
    };
    let mut record = AppletRecord {
        applet_id: package.applet_id.clone(),
        namespace,
        owner_actor_id: owner_actor_id.to_owned(),
        registry_did: package.controller_id.to_string(),
        bot_actor_id: package.bot_actor_id.to_string(),
        portal_realm_id: realm_id,
        capabilities: approved_actions,
        manifest: manifest_from_package(&package),
        package: Some(package.clone()),
        registration_epoch_evidence: package.registration_epoch_evidence.clone(),
        namespaces: Some(package.namespaces.clone()),
        allow_ghost_actors,
        status: effective_status_wire.to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key: Some(idempotency_key),
        install_body_digest: Some(body_digest),
        install_id: Some(response.install_id.clone()),
        install_response: Some(response.clone()),
        install_execution: None,
        ghosts: Vec::new(),
    };
    record.install_execution = Some(build_install_execution_record(
        state.service_id(),
        owner_actor_id,
        record.idempotency_key.as_deref().unwrap_or_default(),
        record.install_body_digest.as_deref().unwrap_or_default(),
        &submitted_plan_digest,
        &record,
        &response,
        false,
    )?);
    persist_applet_record(state, &record).await?;
    recover_applet_install_fanout(state, &mut record, &response).await?;
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_id),
        "applet.install",
        json!({
            "applet_id": record.applet_id,
            "namespace": record.namespace,
            "service_id": package.service_id,
            "bot_actor_id": record.bot_actor_id,
            "registration_event_ref": registration_event_ref,
            "registration_epoch": package.registration_epoch,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    Ok(response)
}

async fn recover_applet_install_fanout(
    state: &AppState,
    record: &mut AppletRecord,
    response: &AppletInstallOutcome,
) -> Result<(), AppError> {
    update_applet_projection(state, record);
    if let Some(event_id) = response.registration_event_ref.as_ref() {
        ensure_applet_registration_projection(state, record, event_id.as_str()).await?;
    }
    project_applet_install_grants(state, record, &response.capability_grant_refs);
    ensure_applet_e2ee_authorization_projections(state, record, &response.e2ee_authorization_refs)
        .await?;
    if record
        .install_execution
        .as_ref()
        .and_then(|execution| execution.get("status"))
        .and_then(Value::as_str)
        != Some("completed")
    {
        let submitted_plan_digest = record
            .install_execution
            .as_ref()
            .and_then(|execution| execution.get("submitted_plan_digest"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        record.install_execution = Some(build_install_execution_record(
            state.service_id(),
            &record.owner_actor_id,
            record.idempotency_key.as_deref().unwrap_or_default(),
            record.install_body_digest.as_deref().unwrap_or_default(),
            &submitted_plan_digest,
            record,
            response,
            true,
        )?);
        persist_applet_record(state, record).await?;
    }
    Ok(())
}

async fn ensure_applet_e2ee_authorization_projections(
    state: &AppState,
    record: &AppletRecord,
    event_ids: &[EventId],
) -> Result<(), AppError> {
    if event_ids.is_empty() {
        return Ok(());
    }
    let existing = state
        .event_query_application()
        .projected_events()
        .await
        .map_err(|error| {
            tracing::error!(%error, "applet install: failed to inspect e2ee authorization projection recovery");
            AppError::internal("failed to inspect applet e2ee authorization projection")
        })?
        .into_iter()
        .map(|event| event.event_id)
        .collect::<BTreeSet<_>>();
    for event_id in event_ids {
        if !existing.contains(event_id.as_str()) {
            append_applet_e2ee_authorization_projection(state, record, event_id.as_str()).await?;
        }
    }
    Ok(())
}

async fn ensure_applet_registration_projection(
    state: &AppState,
    record: &AppletRecord,
    event_id: &str,
) -> Result<(), AppError> {
    let exists = state
        .event_query_application()
        .projected_events()
        .await
        .map_err(|error| {
            tracing::error!(%error, %event_id, "applet install: failed to inspect registration projection recovery");
            AppError::internal("failed to inspect applet registration projection")
        })?
        .into_iter()
        .any(|event| event.event_id == event_id);
    if exists {
        return Ok(());
    }
    append_applet_registration_projection(state, record, event_id).await
}

fn project_applet_install_grants(state: &AppState, record: &AppletRecord, grant_ids: &[GrantId]) {
    if record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
    {
        return;
    }
    let Some(package) = record.package.as_ref() else {
        return;
    };
    for (grant_id, action) in grant_ids.iter().zip(record.capabilities.iter()) {
        state
            .authorization_application()
            .upsert_projected_grant(applet_install_grant(
                record,
                package,
                grant_id.as_str(),
                action,
            ));
    }
}

fn applet_install_grant(
    record: &AppletRecord,
    package: &AppletPackage,
    grant_id: &str,
    action: &str,
) -> crate::authz::Grant {
    crate::authz::Grant {
        grant_id: grant_id.to_owned(),
        realm_id: record.portal_realm_id.clone(),
        issuer: record.owner_actor_id.clone(),
        subject: package.service_id.to_string(),
        resource: record.portal_realm_id.clone(),
        actions: vec![action.to_owned()],
        capability_action_registry_digest: None,
        constraints: applet_delegation_constraints(record, package),
        revoked: false,
        created_at: record.registered_at,
        delegated_from: None,
        expires_at: None,
    }
}

fn applet_delegation_constraints(
    record: &AppletRecord,
    package: &AppletPackage,
) -> Vec<crate::authz::Constraint> {
    vec![crate::authz::Constraint::AppletDelegationBinding {
        applet_id: record.applet_id.clone(),
        executed_by: package.service_id.to_string(),
        registration_epoch: package.registration_epoch.to_string(),
    }]
}

fn build_install_execution_record(
    principal_service_id: &str,
    admin_actor_id: &str,
    idempotency_key: &str,
    body_digest: &str,
    submitted_plan_digest: &str,
    record: &AppletRecord,
    response: &AppletInstallOutcome,
    accepted: bool,
) -> Result<Value, AppError> {
    let status = if accepted { "completed" } else { "pending" };
    let produced_event_refs = if accepted {
        install_produced_event_refs(response)
    } else {
        Vec::new()
    };
    Ok(json!({
        "principal_service_id": principal_service_id,
        "admin_actor_id": admin_actor_id,
        "idempotency_key": idempotency_key,
        "body_hash": body_digest,
        "submitted_plan_digest": submitted_plan_digest,
        "status": status,
        "effective_status": record.status.as_str(),
        "produced_event_refs": produced_event_refs,
        "steps": install_execution_steps(record, response, accepted)?,
    }))
}

fn install_produced_event_refs(response: &AppletInstallOutcome) -> Vec<String> {
    let mut refs = Vec::with_capacity(
        1 + response.capability_grant_refs.len()
            + response.membership_event_refs.len()
            + response.e2ee_authorization_refs.len()
            + usize::from(response.widget_policy_ref.is_some()),
    );
    refs.extend(
        response
            .registration_event_ref
            .iter()
            .map(ToString::to_string),
    );
    refs.extend(
        response
            .capability_grant_refs
            .iter()
            .map(ToString::to_string),
    );
    refs.extend(
        response
            .membership_event_refs
            .iter()
            .map(ToString::to_string),
    );
    refs.extend(
        response
            .e2ee_authorization_refs
            .iter()
            .map(ToString::to_string),
    );
    if let Some(widget_policy_ref) = &response.widget_policy_ref {
        refs.push(widget_policy_ref.to_string());
    }
    refs
}

fn install_execution_steps(
    record: &AppletRecord,
    response: &AppletInstallOutcome,
    accepted: bool,
) -> Result<Vec<Value>, AppError> {
    let Some(package) = record.package.as_ref() else {
        return Ok(Vec::new());
    };
    let mut steps = Vec::with_capacity(
        1 + response.capability_grant_refs.len() + response.e2ee_authorization_refs.len(),
    );
    let registration_body = json!({
        "event_kind": arkret_wire::events::EventKind::APPLET_REGISTRATION,
        "payload": registration_payload_from_package(package)?,
    });
    if let Some(event_ref) = response.registration_event_ref.as_ref() {
        steps.push(install_execution_step(
            0,
            arkret_wire::events::EventKind::APPLET_REGISTRATION,
            event_ref.as_str(),
            canonical_digest(&registration_body)?,
            accepted,
            None,
        ));
    }
    for (offset, (grant_id, action)) in response
        .capability_grant_refs
        .iter()
        .zip(record.capabilities.iter())
        .enumerate()
    {
        let grant = applet_install_grant(record, package, grant_id.as_str(), action);
        let grant_body = json!({
            "event_kind": arkret_wire::events::EventKind::CAPABILITY_GRANT,
            "payload": {
                "grant_id": grant_id,
                "grant": grant,
            },
        });
        steps.push(install_execution_step(
            offset + 1,
            arkret_wire::events::EventKind::CAPABILITY_GRANT,
            grant_id.as_str(),
            canonical_digest(&grant_body)?,
            accepted,
            Some(json!({
                "applet_id": record.applet_id.as_str(),
                "executed_by": package.service_id.to_string(),
                "registration_epoch": package.registration_epoch.to_string(),
            })),
        ));
    }
    let e2ee_start = 1 + response.capability_grant_refs.len();
    for (offset, event_ref) in response.e2ee_authorization_refs.iter().enumerate() {
        let body = json!({
            "event_kind": "ak.member.state",
            "payload": applet_e2ee_authorization_payload(record, package),
        });
        steps.push(install_execution_step(
            e2ee_start + offset,
            "ak.member.state",
            event_ref.as_str(),
            canonical_digest(&body)?,
            accepted,
            Some(json!({
                "applet_id": record.applet_id.as_str(),
                "authorization_gate": "applet_e2ee_join",
                "reason_code": "applet_e2ee_join_unauthorized",
            })),
        ));
    }
    Ok(steps)
}

fn install_execution_step(
    step_index: usize,
    target_event_kind: &str,
    planned_event_ref: &str,
    canonical_event_body_hash: String,
    accepted: bool,
    grant_binding: Option<Value>,
) -> Value {
    let status = if accepted { "accepted" } else { "pending" };
    let event_ref = if accepted {
        Value::String(planned_event_ref.to_owned())
    } else {
        Value::Null
    };
    let mut step = json!({
        "step_index": step_index,
        "target_event_kind": target_event_kind,
        "canonical_event_body_hash": canonical_event_body_hash,
        "status": status,
        "planned_event_ref": planned_event_ref,
        "event_ref": event_ref,
    });
    if let Some(grant_binding) = grant_binding
        && let Some(object) = step.as_object_mut()
    {
        object.insert("grant_binding".to_owned(), grant_binding);
    }
    step
}

pub(super) async fn append_applet_registration_projection(
    state: &AppState,
    record: &AppletRecord,
    event_id: &str,
) -> Result<(), AppError> {
    let Some(package) = record.package.as_ref() else {
        return Ok(());
    };
    let realm_id = record.portal_realm_id.clone();
    let projection_record = ProjectionEventRecord {
        event_id: event_id.to_owned(),
        realm_id,
        event_kind: arkret_wire::events::EventKind::APPLET_REGISTRATION.to_owned(),
        operation_type: "applet_install_registration".to_owned(),
        operation_id: None,
        sender: Some(record.owner_actor_id.clone()),
        payload: registration_payload_from_package(package)?,
        created_at: chrono::Utc::now(),
        received_at: chrono::Utc::now(),
    };
    if let Err(error) = crate::routing::events::projection::persist_and_publish_projection_event(
        state,
        projection_record,
    )
    .await
    {
        tracing::error!(%error, "applet install: failed to append registration projection");
        return Err(AppError::internal(
            "failed to persist applet registration projection",
        ));
    }
    Ok(())
}

pub(super) fn update_applet_projection(state: &AppState, record: &AppletRecord) {
    let Some(package) = record.package.as_ref() else {
        return;
    };
    let now = chrono::Utc::now();
    state.projection_application().cache_applet(
        package.service_id.to_string(),
        record.applet_id.clone(),
        record.namespace.clone(),
        Some(json!(package.manifest_snapshot())),
        Some(json!(record.capabilities)),
        now,
        now,
    );
}

pub(super) async fn register_verified_applet(
    state: &AppState,
    owner_actor_id: &str,
    manifest: AppletManifest,
    verified: VerifiedAppletManifest,
    idempotency_key: Option<String>,
    res: &mut Response,
) -> Result<AppletView, AppError> {
    let applet_id = verified.id.clone();
    let namespace = manifest_namespace(&manifest).unwrap_or_else(|| safe_token(&applet_id));
    if let Some(existing) = applet_record(state, &applet_id).await? {
        if idempotency_key.is_some()
            && existing.idempotency_key.as_deref() == idempotency_key.as_deref()
        {
            res.status_code(StatusCode::OK);
            return Ok(applet_response(&existing));
        }
        return Err(
            AppError::conflict("applet manifest id is already registered")
                .with_wire_code("applet_already_registered"),
        );
    }
    if applet_records(state).await?.into_iter().any(|record| {
        record.namespace == namespace
            && record.applet_id != applet_id
            && record.revoked_at.is_none()
    }) {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }

    let now = chrono::Utc::now();
    let bot_actor_id = bot_actor_id_for(&namespace, &applet_id);
    // G3.S9 — the minted bot actor DID MUST be a well-formed bare DID
    // scalar before it is persisted on the applet record.
    crate::routing::extensions::bot_actor::validate_extension_actor_did(&bot_actor_id)?;
    let portal_realm_id = portal_realm_id_for(&namespace, &applet_id);
    let record = AppletRecord {
        applet_id,
        namespace,
        owner_actor_id: owner_actor_id.to_owned(),
        registry_did: verified.signer_did,
        bot_actor_id,
        portal_realm_id,
        capabilities: verified.capabilities,
        manifest,
        package: None,
        registration_epoch_evidence: None,
        namespaces: None,
        allow_ghost_actors: false,
        status: "registered".to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key,
        install_body_digest: None,
        install_id: None,
        install_response: None,
        install_execution: None,
        ghosts: Vec::new(),
    };
    // SOL-HYG-01: the bot actor's liveness/revocation state is captured durably
    // by the applet record persisted here (`bot_actor_id` + `revoked_at`); the
    // prior in-memory registry write was a redundant, non-durable shadow.
    persist_applet_record(state, &record).await?;
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_id),
        "extensions.applet.register",
        json!({
            "applet_id": record.applet_id,
            "namespace": record.namespace,
            "registry_did": record.registry_did,
            "bot_actor_id": record.bot_actor_id,
            "portal_realm_id": record.portal_realm_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    Ok(applet_response(&record))
}

pub(super) async fn append_portal_message(
    state: &AppState,
    applet: &AppletRecord,
    ghost: &GhostActorRecord,
    realm_id: &str,
    content: Value,
) -> Result<AppletPortalMessageOutcome, AppError> {
    if !applet
        .capabilities
        .iter()
        .any(|capability| capability_allows_message_create(capability))
    {
        return Err(AppError::capability_denied(
            "applet install does not grant ak.message.create",
        ));
    }
    let operation_id = ids::generate_operation_id();
    let event_id = ids::generate_event_id();
    let thread_id = strand_id_from_realm_id(realm_id);
    let created_at = chrono::Utc::now();
    let content_with_portal = enrich_content_with_portal_metadata(content, applet, ghost);
    let message_record = MessageState {
        event_id: event_id.clone(),
        message_id: crate::routing::events::strand::message_id_from_event_id(&event_id),
        realm_id: realm_id.to_owned(),
        sender: ghost.ghost_actor_id.clone(),
        thread_id: thread_id.clone(),
        content: content_with_portal.clone(),
        encrypted: false,
        created_at,
    };
    if let Err(error) = state
        .event_query_application()
        .store_message(message_record.clone())
        .await
    {
        tracing::error!(%error, "applet bridge: failed to persist portal MessageRecord");
        return Err(AppError::internal("failed to persist portal message"));
    }
    let projection_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.to_owned(),
        event_kind: arkret_wire::events::EventKind::MESSAGE_CREATE.to_owned(),
        operation_type: "applet_portal_ingress".to_owned(),
        operation_id: Some(operation_id.clone()),
        sender: Some(ghost.ghost_actor_id.clone()),
        payload: json!({
            "thread_id": thread_id,
            "content": content_with_portal,
            "encrypted": false,
            "portal_realm_id": applet.portal_realm_id,
            "applet_id": applet.applet_id,
            "bot_actor_id": applet.bot_actor_id,
            "ghost_actor_id": ghost.ghost_actor_id,
            "external_id": ghost.external_id,
        }),
        created_at,
        received_at: chrono::Utc::now(),
    };
    if let Err(error) = crate::routing::events::projection::persist_and_publish_projection_event(
        state,
        projection_record,
    )
    .await
    {
        tracing::error!(%error, "applet bridge: failed to append projection event");
        return Err(AppError::internal("failed to persist portal projection"));
    }
    Ok(AppletPortalMessageOutcome {
        message_id: message_record.message_id.clone(),
        event_id,
        operation_id,
        realm_id: realm_id.to_owned(),
        portal_realm_id: applet.portal_realm_id.clone(),
    })
}

pub(super) fn parse_manifest(
    body: &AppletManifestRegisterRequestBody,
) -> Result<AppletManifest, AppError> {
    let mut manifest_value = body
        .manifest
        .as_ref()
        .or(body.manifest_json.as_ref())
        .cloned()
        .ok_or_else(|| AppError::missing_param("manifest is required"))?;
    if let Some(signature) = body
        .signature
        .as_deref()
        .or(body.manifest_signature.as_deref())
        && manifest_value
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        && let Some(object) = manifest_value.as_object_mut()
    {
        object.insert("signature".to_owned(), Value::String(signature.to_owned()));
    }
    serde_json::from_value(manifest_value)
        .map_err(|err| AppError::bad_json(format!("manifest parse: {err}")))
}

pub(super) fn portal_message_payload(payload: &Value) -> Result<Option<Value>, AppError> {
    if payload.is_null() {
        return Ok(None);
    }
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("message");
    if kind != "message" && kind != "ak.content.text" {
        return Ok(None);
    }
    let text = payload
        .get("text")
        .or_else(|| payload.get("body"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid_param("payload.text is required"))?;
    Ok(Some(json!({
        "kind": "ak.content.text",
        "body": text,
    })))
}

pub(super) fn enrich_content_with_portal_metadata(
    mut content: Value,
    applet: &AppletRecord,
    ghost: &GhostActorRecord,
) -> Value {
    if let Some(object) = content.as_object_mut() {
        object.insert(
            "portal".to_owned(),
            json!({
                "applet_id": applet.applet_id,
                "portal_realm_id": applet.portal_realm_id,
                "bot_actor_id": applet.bot_actor_id,
                "ghost_actor_id": ghost.ghost_actor_id,
                "external_id": ghost.external_id,
                "display_name": ghost.display_name,
            }),
        );
    }
    content
}

pub(super) fn applet_response(record: &AppletRecord) -> AppletView {
    AppletView {
        applet_id: record.applet_id.clone(),
        namespace: record.namespace.clone(),
        owner_actor_id: record.owner_actor_id.clone(),
        registry_did: record.registry_did.clone(),
        bot_actor_id: record.bot_actor_id.clone(),
        portal_realm_id: record.portal_realm_id.clone(),
        capabilities: record.capabilities.clone(),
        status: record.status.clone(),
        registered_at: record.registered_at,
        revoked_at: record.revoked_at,
        ghost_actor_ids: record
            .ghosts
            .iter()
            .map(|ghost| ghost.ghost_actor_id.clone())
            .collect(),
        manifest: record.manifest.clone(),
    }
}

pub(super) fn validate_applet_package(
    state: &AppState,
    package: &mut AppletPackage,
) -> Result<(), AppError> {
    let evidence = validated_registration_epoch_evidence(state, package)?;
    package.registration_epoch_evidence = Some(evidence);
    package.validate().map_err(|error| {
        AppError::invalid_param(format!("applet package invalid: {error}"))
            .with_wire_code("schema_violation")
    })?;
    if let Some(expires_at) = package.expires_at
        && expires_at <= chrono::Utc::now()
    {
        return Err(AppError::conflict("applet package has expired")
            .with_wire_code("applet_package_expired"));
    }
    let expected_digest = package
        .compute_package_digest()
        .map_err(|error| AppError::internal(format!("package digest failed: {error}")))?;
    if package.package_digest.as_ref() != Some(&expected_digest) {
        return Err(
            AppError::invalid_param("applet package_digest does not match package body")
                .with_wire_code("schema_violation"),
        );
    }
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::invalid_param("applet package proof is required"))?;
    proof.validate().map_err(|error| {
        AppError::invalid_param(format!("applet package proof invalid: {error}"))
    })?;
    let mut unsigned = package.clone();
    unsigned.proof = None;
    let unsigned_canonical_bytes = arkret_core::canonical::canonical_json_bytes(&unsigned)
        .map_err(|error| {
            AppError::internal(format!("package proof canonical bytes failed: {error}"))
        })?;
    let expected_payload_digest = arkret_core::Hash::new(arkret_core::canonical::sha256_digest(
        &unsigned_canonical_bytes,
    ))
    .map_err(|error| AppError::internal(format!("package proof digest invalid: {error}")))?;
    if proof.event_digest != expected_payload_digest {
        return Err(
            AppError::invalid_param("applet package proof payload_digest mismatch")
                .with_wire_code("proof_invalid"),
        );
    }
    // applet-integration.md §4.1 line 193/199 + §4b line 229: the controller
    // detached proof MUST be a real signature by `controller_id` covering the
    // canonical package body. Digest equality alone is forgeable — anyone can
    // recompute `event_digest` over `unsigned` and sign it with an arbitrary
    // key. Anchor the proof's verification_method to `controller_id` and run
    // the same detached-JWS verifier every other soland proof path uses
    // (dev: shape-only; production: DID-resolved Ed25519). Preview/commit MUST
    // fail closed (`proof_invalid`) when the controller proof is invalid or its
    // key cannot be resolved.
    validate_controller_proof(state, package, &unsigned_canonical_bytes)?;
    Ok(())
}

/// Cryptographically verify the controller detached proof on an Applet package.
///
/// Reuses the shared soland detached-JWS verifier boundary
/// (`crate::jws_verify`), dispatching on `development_mode` exactly like
/// [`crate::routing::federation::move_seal::select_jws_verifier`]: dev mode runs
/// the RFC 7515 shape-only check (no live DID document required, but the
/// all-zero sentinel signature is still rejected), production resolves the
/// controller DID document and runs the Ed25519 verify against the
/// verification method's public key.
///
/// `controller_id` is anchored two ways: the proof's `verification_method`
/// MUST be a DID URL under `controller_id`, and the resolved public key MUST
/// come from `controller_id`'s DID document (production). A proof signed by any
/// other key — even with a correctly recomputed `event_digest` — fails here.
fn validate_controller_proof(
    state: &AppState,
    package: &AppletPackage,
    unsigned_canonical_bytes: &[u8],
) -> Result<(), AppError> {
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::invalid_param("applet package proof is required"))?;
    let controller_id = package.controller_id.as_str();
    crate::jws_verify::validate_verification_method_controller(
        controller_id,
        &proof.verification_method,
    )
    .map_err(|reason| {
        AppError::invalid_param("applet package proof is not anchored to controller_id")
            .with_wire_code("proof_invalid")
            .with_reason_detail(reason)
    })?;
    let verify_result = if state.config().development_mode {
        crate::jws_verify::verify_jws_shape(
            unsigned_canonical_bytes,
            &proof.jws,
            &proof.verification_method,
            controller_id,
        )
    } else {
        crate::jws_verify::verify_jws_ed25519(
            unsigned_canonical_bytes,
            &proof.jws,
            &proof.verification_method,
            controller_id,
            state,
        )
    };
    verify_result.map_err(|reason| {
        AppError::invalid_param("applet package controller proof signature is invalid")
            .with_wire_code("proof_invalid")
            .with_reason_detail(reason)
    })
}

fn validated_registration_epoch_evidence(
    state: &AppState,
    package: &AppletPackage,
) -> Result<arkret_core::AppletRegistrationEpochEvidence, AppError> {
    let document =
        crate::jws_verify::resolve_did_document(state, &package.service_id).map_err(|reason| {
            AppError::invalid_param("applet service DID document could not be resolved")
                .with_wire_code("applet_registration_epoch_evidence_mismatch")
                .with_reason_detail(reason)
        })?;
    validate_registration_epoch_evidence_for_document(package, &document)
}

fn validate_registration_epoch_evidence_for_document(
    package: &AppletPackage,
    document: &DidDocument,
) -> Result<arkret_core::AppletRegistrationEpochEvidence, AppError> {
    let evidence = package.registration_epoch_evidence.clone().ok_or_else(|| {
        AppError::invalid_param("applet package registration_epoch evidence is required")
            .with_wire_code("applet_registration_epoch_evidence_mismatch")
    })?;
    evidence
        .validate_against_did_document(document)
        .map_err(|reason| {
            AppError::invalid_param(
                "applet registration_epoch evidence does not match service DID document",
            )
            .with_wire_code("applet_registration_epoch_evidence_mismatch")
            .with_reason_detail(reason.to_string())
        })?;
    if !evidence.contains_signing_key(&package.webhook_auth.key_ref) {
        return Err(AppError::invalid_param(
            "applet webhook_auth key_ref is outside registration_epoch evidence",
        )
        .with_wire_code("applet_registration_epoch_signing_key_mismatch"));
    }
    Ok(evidence)
}

pub(super) fn approved_scopes_from_approval_request(
    package: &AppletPackage,
    scope: &EffectiveScope,
    approval: &AppletApprovalRequest,
) -> Result<Vec<ScopeGrant>, AppError> {
    let approve_actions = approval_actions_for_install(approval);
    let requested = package
        .requested_scopes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let approved = approve_actions
        .iter()
        .filter(|action| requested.contains(*action))
        .cloned()
        .collect::<BTreeSet<_>>();
    if approved.is_empty() {
        return Ok(Vec::new());
    }
    let (realm_id, circle_ids) = match scope {
        EffectiveScope::Realm { realm_id } => (realm_id.clone(), None),
        EffectiveScope::Circle {
            realm_id,
            circle_id,
        } => (realm_id.clone(), Some(vec![circle_id.clone()])),
        _ => {
            return Err(AppError::invalid_param(
                "unsupported applet effective scope",
            ));
        }
    };
    Ok(vec![ScopeGrant {
        actions: approved.into_iter().collect(),
        realm_ids: vec![realm_id],
        circle_ids,
        constraints: Vec::new(),
    }])
}

pub(super) fn approval_actions_for_install(approval: &AppletApprovalRequest) -> Vec<String> {
    approval
        .approve_actions
        .iter()
        .filter(|action| approval.allow_ghost_actors || action.as_str() != GHOST_PROVISION_ACTION)
        .cloned()
        .collect()
}

pub(super) async fn build_install_plan(
    state: &AppState,
    package: &AppletPackage,
    scope: &EffectiveScope,
    approved_scopes: Vec<ScopeGrant>,
) -> Result<AppletInstallPlan, AppError> {
    let namespace_conflicts =
        namespace_conflicts_for(state, &package.applet_id, &package.namespaces).await?;
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }
    let approved_actions = actions_from_approved_scopes(&approved_scopes);
    let denied_scopes = denied_scope_values(package, &approved_actions);
    let registration_payload = registration_payload_from_package(package)?;
    let package_digest = package
        .package_digest
        .clone()
        .ok_or_else(|| AppError::missing_param("applet_package.package_digest is required"))?;
    let seed = json!({
        "schema": "ak.schema.applet_install_plan.v1",
        "applet_id": package.applet_id,
        "package_digest": package_digest,
        "registration_epoch": package.registration_epoch,
        "effective_scope": scope,
        "requested_scopes": package.requested_scopes,
        "approved_scopes": approved_scopes,
        "denied_scopes": denied_scopes,
        "events_to_submit": [{
            "event_kind": arkret_wire::events::EventKind::APPLET_REGISTRATION,
            "payload": registration_payload,
        }],
        "capability_constraints": capability_constraints_for_scope(scope),
        "namespace_conflicts": [],
        "e2ee_effect": e2ee_effect_for_package(package),
        "widget_effect": widget_effect_for_package(package),
        "warnings": [],
    });
    let plan_id = deterministic_plan_id(&seed)?;
    let event_payload = serde_json::from_value(registration_payload).map_err(|error| {
        AppError::internal(format!(
            "applet registration payload is not an object: {error}"
        ))
    })?;
    let mut plan = AppletInstallPlan {
        schema: "ak.schema.applet_install_plan.v1".to_owned(),
        plan_id,
        applet_id: applet_install_plan_applet_id(&package.applet_id)?,
        package_digest: package_digest.clone(),
        registration_epoch: package.registration_epoch.clone(),
        effective_scope: scope.clone(),
        requested_scopes: package.requested_scopes.clone(),
        approved_scopes,
        denied_scopes,
        events_to_submit: vec![EventSubmission {
            event_kind: arkret_wire::events::EventKind::APPLET_REGISTRATION.to_owned(),
            payload: event_payload,
            refs: None,
        }],
        capability_constraints: capability_constraints_for_scope(scope),
        namespace_conflicts: Vec::<NamespaceConflict>::new(),
        e2ee_effect: e2ee_effect_for_package(package),
        widget_effect: widget_effect_for_package(package),
        warnings: Vec::new(),
        plan_digest: package_digest.clone(),
    };
    plan.seal()
        .map_err(|error| AppError::internal(format!("install plan digest failed: {error}")))?;
    Ok(plan)
}

fn applet_install_plan_applet_id(value: &str) -> Result<AppletInstallAppletId, AppError> {
    if let Ok(did) = Did::new(value.to_owned()) {
        return Ok(AppletInstallAppletId::Did(did));
    }
    AppletId::new(value.to_owned())
        .map(AppletInstallAppletId::AppletId)
        .map_err(|error| AppError::invalid_param(format!("invalid applet_id: {error}")))
}

pub(super) fn registration_payload_from_package(
    package: &AppletPackage,
) -> Result<Value, AppError> {
    Ok(json!({
        "applet_id": package.applet_id,
        "service_id": package.service_id,
        "controller_id": package.controller_id,
        "base_url": package.base_url,
        "bot_actor_id": package.bot_actor_id,
        "protocols": package.protocols,
        "namespaces": package.namespaces,
        "receive_events": package.receive_events,
        "receive_ephemeral": package.receive_ephemeral,
        "rate_limited": package.rate_limited,
        "requested_scopes": package.requested_scopes,
        "registration_epoch": package.registration_epoch,
        "webhook_auth": package.webhook_auth,
        "manifest": package.manifest_snapshot(),
        "proof": package.proof,
        "created_at": package.created_at,
    }))
}

pub(super) fn capability_constraints_for_scope(
    scope: &EffectiveScope,
) -> Vec<CapabilityConstraint> {
    let mut params = std::collections::BTreeMap::from([(
        "realm_id".to_owned(),
        Value::String(effective_scope_realm_id(scope)),
    )]);
    if let EffectiveScope::Circle { circle_id, .. } = scope {
        params.insert("circle_id".to_owned(), Value::String(circle_id.to_string()));
    }
    vec![CapabilityConstraint {
        constraint_type: "effective_scope".to_owned(),
        params: Some(params),
    }]
}

pub(super) fn e2ee_effect_for_package(package: &AppletPackage) -> E2eeEffect {
    E2eeEffect {
        requires_mls_join: package.e2ee_policy.mls_join_requested.unwrap_or(false),
        plaintext_access: "policy_declared".to_owned(),
        authorization_refs: None,
    }
}

fn package_requests_mls_join(package: &AppletPackage) -> bool {
    package.e2ee_policy.mls_join_requested.unwrap_or(false)
}

fn e2ee_authorization_refs_for_install(
    package: &AppletPackage,
    e2ee_policy: Option<&E2eePolicy>,
) -> Result<Vec<EventId>, AppError> {
    if !package_requests_mls_join(package) {
        return Ok(Vec::new());
    }
    if !e2ee_policy.is_some_and(|policy| policy.allow_mls_join.unwrap_or(false)) {
        return Err(AppError::capability_denied(
            "applet E2EE MLS join requires independent authorization",
        )
        .with_wire_code("applet_e2ee_join_unauthorized"));
    }
    Ok(vec![EventId::new(ids::generate_event_id()).map_err(
        |error| AppError::internal(format!("generated event id is invalid: {error}")),
    )?])
}

fn applet_e2ee_authorization_payload(record: &AppletRecord, package: &AppletPackage) -> Value {
    json!({
        "membership": "join",
        "realm_id": record.portal_realm_id.as_str(),
        "actor_id": package.bot_actor_id.to_string(),
        "applet_id": record.applet_id.as_str(),
        "managed_by_applet": true,
        "e2ee_join_authorization": {
            "profile": "ak.profile.applet_e2ee_join.v1",
            "authorization_gate": "applet_e2ee_join",
            "authorized_by": record.owner_actor_id.as_str(),
            "registration_epoch": package.registration_epoch.to_string(),
            "service_id": package.service_id.to_string(),
            "reason_code": "applet_e2ee_join_unauthorized",
        },
        "created_at": record.registered_at,
    })
}

async fn append_applet_e2ee_authorization_projection(
    state: &AppState,
    record: &AppletRecord,
    event_id: &str,
) -> Result<(), AppError> {
    let Some(package) = record.package.as_ref() else {
        return Ok(());
    };
    let payload = applet_e2ee_authorization_payload(record, package);
    let projection_record = ProjectionEventRecord {
        event_id: event_id.to_owned(),
        realm_id: record.portal_realm_id.clone(),
        event_kind: "ak.member.state".to_owned(),
        operation_type: "applet_e2ee_join_authorization".to_owned(),
        operation_id: None,
        sender: Some(record.owner_actor_id.clone()),
        payload,
        created_at: record.registered_at,
        received_at: chrono::Utc::now(),
    };
    crate::routing::events::projection::persist_and_publish_projection_event(
        state,
        projection_record,
    )
        .await
        .map(|_| ())
        .map_err(|error| {
            tracing::error!(%error, %event_id, "applet install: failed to append e2ee authorization projection");
            AppError::internal("failed to append applet e2ee authorization projection")
        })
}

pub(super) fn widget_effect_for_package(package: &AppletPackage) -> WidgetEffect {
    WidgetEffect {
        allow_widget: package.widget.is_some(),
        policy_event_ref: None,
    }
}

pub(super) fn deterministic_plan_id(plan_seed: &Value) -> Result<String, AppError> {
    let digest = canonical_digest(plan_seed)?;
    Ok(format!("ak:plan:{}", digest.trim_start_matches("sha256:")))
}

pub(super) fn canonical_digest(value: &Value) -> Result<String, AppError> {
    arkret_core::canonical::canonical_sha256(value)
        .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))
}

pub(super) fn actions_from_approved_scopes(scopes: &[ScopeGrant]) -> Vec<String> {
    scopes
        .iter()
        .flat_map(|scope| scope.actions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn denied_scope_values(
    package: &AppletPackage,
    approved_actions: &[String],
) -> Vec<DeniedScope> {
    let approved = approved_actions.iter().collect::<BTreeSet<_>>();
    package
        .requested_scopes
        .iter()
        .filter(|scope| !approved.contains(scope))
        .map(|scope| DeniedScope {
            requested_scope: scope.clone(),
            reason_code: "not_approved".to_owned(),
        })
        .collect()
}

pub(super) async fn namespace_conflicts_for(
    state: &AppState,
    applet_id: &str,
    namespaces: &AppletWireNamespaces,
) -> Result<Vec<Value>, AppError> {
    let mut conflicts = Vec::new();
    for record in applet_records(state)
        .await?
        .into_iter()
        .filter(|record| record.revoked_at.is_none() && record.applet_id != applet_id)
    {
        let Some(existing) = record.namespaces.as_ref() else {
            continue;
        };
        for conflict in namespaces.conflicts_with(existing) {
            conflicts.push(json!({
                "namespace": conflict.pattern,
                "existing_owner": record.applet_id,
                "resolution": "deny",
            }));
        }
    }
    Ok(conflicts)
}

pub(super) fn effective_scope_realm_id(scope: &EffectiveScope) -> String {
    match scope {
        EffectiveScope::Realm { realm_id } | EffectiveScope::Circle { realm_id, .. } => {
            realm_id.to_string()
        }
        _ => unreachable!("unsupported canonical applet effective scope"),
    }
}

/// Governance gate for canonical applet install/revoke.
///
/// An authenticated session is not enough to register or revoke a realm-scoped
/// applet install: the actor MUST hold `ak.realm.admin` over the install's
/// effective_scope realm. P1 projected capability grants into the authz index,
/// so [`SolandAuthzEngine::check`] is authoritative here. Mirrors the ban gate
/// in `routing/events/operations/policy.rs::validate_member_state_policy`.
/// fail-closed: anything other than an explicit allow is rejected with
/// `applet_registration_unauthorized`.
pub(super) async fn require_realm_admin(
    state: &AppState,
    actor: &str,
    scope: &EffectiveScope,
) -> Result<(), AppError> {
    let realm_id = effective_scope_realm_id(scope);
    let (owner, members) = realm_owner_and_members(state, &realm_id).await;
    if state
        .authorization_application()
        .check(soland_application::authorization::AuthorizationCheck {
            actor,
            action: "ak.realm.admin",
            resource: &realm_id,
            realm_id: &realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        return Ok(());
    }
    Err(
        AppError::capability_denied("actor lacks ak.realm.admin over the applet install realm")
            .with_wire_code("applet_registration_unauthorized"),
    )
}

/// Resolve the realm owner and member set, matching
/// `routing/events/operations.rs::realm_owner_and_members` (which is module
/// private). Both feed the authz check's owner/member implicit-grant logic.
async fn realm_owner_and_members(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let owner = state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = {
        let realms = state.realm_directory_application().snapshot();
        RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|id| realms.get(&id))
            .map(|realm| realm.members.iter().map(ToString::to_string).collect())
            .unwrap_or_default()
    };
    (owner, members)
}

pub(super) fn manifest_from_package(package: &AppletPackage) -> AppletManifest {
    AppletManifest {
        id: package.applet_id.clone(),
        version: "1.0.0".to_owned(),
        signer_did: package.controller_id.to_string(),
        signature: package
            .proof
            .as_ref()
            .map(|proof| proof.jws.clone())
            .unwrap_or_default(),
        signer_public_key: String::new(),
        requested_capabilities: package.requested_scopes.clone(),
        schema_hash: package
            .package_digest
            .as_ref()
            .map(|hash| hash.to_string())
            .unwrap_or_default(),
        metadata: json!({
            "namespace": package_namespace(package),
            "display_name": package.package_id,
            "bridge_url": package.base_url,
            "claimed_profiles": package.claimed_profiles,
            "protocols": package.protocols,
        }),
    }
}

pub(super) fn package_namespace(package: &AppletPackage) -> String {
    package
        .namespaces
        .handles
        .first()
        .or_else(|| package.namespaces.realms.first())
        .or_else(|| package.namespaces.actors.first())
        .map(|entry| safe_token(&entry.pattern))
        .unwrap_or_else(|| safe_token(&package.applet_id))
}

pub(super) fn allow_ghost_actors_for_install(
    package: &AppletPackage,
    approved_actions: &[String],
    actor_policy: Option<&arkret_core::AppletActorPolicy>,
) -> bool {
    let package_allows = package.ghost_policy.enabled;
    let scope_approved = approved_actions
        .iter()
        .any(|action| action == GHOST_PROVISION_ACTION);
    let actor_policy_allows = actor_policy.is_some_and(|policy| {
        matches!(
            policy.ghost_actor_mode,
            Some(AppletGhostActorMode::ControllerApproved | AppletGhostActorMode::PolicyDeclared)
        )
    });
    package_allows && scope_approved && actor_policy_allows
}

pub(super) fn capability_allows_message_create(capability: &str) -> bool {
    capability == "ak.message.create"
}

#[cfg(test)]
mod tests {
    use arkret_core::{
        AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod, AppletNamespaceEntry, Did,
        Hash,
    };
    use arkret_signatures::Ed25519MoveSigner;

    use super::*;

    /// Minimal production-mode (`development_mode == false`) AppState for
    /// exercising the controller-proof verifier against the built-in
    /// `did:key` resolver. Mirrors `routing/events/operations/policy_tests.rs`
    /// but with real-crypto verification enabled.
    fn production_test_state() -> AppState {
        let config = crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-applet-proof-test-blobs"),
            ),
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: Some([9u8; 32]),
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, soland_storage_postgres::Db { pool: None })
    }

    /// Derive a `did:key` DID + its `#`-fragment verification method for an
    /// Ed25519 seed, using the SDK's canonical multibase encoder so the
    /// built-in `DidKeyResolver` resolves the embedded public key.
    fn did_key_for_seed(seed: [u8; 32]) -> (Did, String) {
        let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let multibase = arkret_core::ed25519_pubkey_to_did_key_multibase(&verifying.to_bytes());
        let did_str = format!("did:key:{multibase}");
        let vm = format!("{did_str}#{multibase}");
        (Did::new(did_str).unwrap(), vm)
    }

    /// Build a sealed package whose `controller_id` is a `did:key` and whose
    /// `registration_epoch_evidence` is consistent with a non-empty service
    /// DID document, then sign it with the signer/verification_method chosen
    /// by the caller. When the signer key differs from `controller_id`'s key
    /// the resulting controller proof MUST fail verification.
    fn signed_did_key_package(
        controller_seed: [u8; 32],
        signer_seed: [u8; 32],
        verification_method: &str,
    ) -> AppletPackage {
        let (controller_id, _) = did_key_for_seed(controller_seed);
        let mut package = AppletPackage::new(
            "package:ak:applet:test".to_owned(),
            "ak:applet:01974100-0000-7000-8000-000000000001".to_owned(),
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            controller_id.clone(),
            "https://test-applet.example".to_owned(),
            Did::new("did:web:bot-test-applet.soland.local".to_owned()).unwrap(),
            vec!["arkret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
        );
        package.requested_scopes = vec!["ak.message.create".to_owned()];
        package.endpoint_policy.endpoints = vec![AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/events".to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        }];
        package
            .seal_registration_epoch(
                arkret_models_integration::applet::AppletRegistrationEpochEvidence::new(
                    package.service_id.clone(),
                    Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
                    arkret_models_integration::applet::AppletDidMethodVersionEvidence::unversioned(
                        "did:web",
                    )
                    .unwrap(),
                    vec![
                        arkret_models_integration::applet::AppletAcceptedSigningKeyEvidence {
                            key_ref: package.webhook_auth.key_ref.clone(),
                            public_key_digest: Hash::new(format!("sha256:{}", "33".repeat(32)))
                                .unwrap(),
                        },
                    ],
                ),
            )
            .unwrap();
        package.seal().unwrap();
        let signer = Ed25519MoveSigner::from_did_key_seed(
            signer_seed,
            controller_id,
            verification_method.to_owned(),
        );
        package.sign(&signer, verification_method).unwrap();
        package
    }

    #[test]
    fn validate_controller_proof_rejects_wrong_key_signature() {
        let state = production_test_state();
        // controller_id is keyed by `controller_seed`, but the proof is signed
        // with `signer_seed` while still naming controller_id's verification
        // method. The forged proof recomputes the correct payload digest yet
        // the Ed25519 signature is made by the wrong key — verification MUST
        // fail closed with `proof_invalid`.
        let controller_seed = [1u8; 32];
        let signer_seed = [2u8; 32];
        let (_, controller_vm) = did_key_for_seed(controller_seed);
        let package = signed_did_key_package(controller_seed, signer_seed, &controller_vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_core::canonical::canonical_json_bytes(&unsigned).unwrap();
        let error = validate_controller_proof(&state, &package, &bytes)
            .expect_err("wrong-key controller proof must be rejected");
        assert_eq!(error.wire_code(), "proof_invalid");
    }

    #[test]
    fn validate_controller_proof_rejects_unanchored_verification_method() {
        let state = production_test_state();
        // Sign with a verification_method belonging to a *different* DID than
        // controller_id. The anchoring gate MUST reject before any crypto,
        // because the proof is not attributable to controller_id.
        let controller_seed = [1u8; 32];
        let other_seed = [2u8; 32];
        let (_, other_vm) = did_key_for_seed(other_seed);
        let package = signed_did_key_package(controller_seed, other_seed, &other_vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_core::canonical::canonical_json_bytes(&unsigned).unwrap();
        let error = validate_controller_proof(&state, &package, &bytes)
            .expect_err("controller proof not anchored to controller_id must be rejected");
        assert_eq!(error.wire_code(), "proof_invalid");
    }

    #[test]
    fn validate_controller_proof_accepts_correct_controller_signature() {
        let state = production_test_state();
        // Same key for controller_id and signer: a genuine controller proof
        // verifies against the resolved did:key public key.
        let seed = [1u8; 32];
        let (_, vm) = did_key_for_seed(seed);
        let package = signed_did_key_package(seed, seed, &vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_core::canonical::canonical_json_bytes(&unsigned).unwrap();
        validate_controller_proof(&state, &package, &bytes)
            .expect("genuine controller proof must verify");
    }

    fn sample_package() -> AppletPackage {
        AppletPackage::new(
            "package:ak:applet:test".to_owned(),
            "ak:applet:01974100-0000-7000-8000-000000000001".to_owned(),
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            Did::new("did:web:test-registry.example".to_owned()).unwrap(),
            "https://test-applet.example".to_owned(),
            Did::new("did:web:bot-test-applet.soland.local".to_owned()).unwrap(),
            vec!["arkret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
        )
    }

    fn sample_response(package: &AppletPackage) -> AppletInstallOutcome {
        AppletInstallOutcome {
            ok: true,
            install_id: "ak:install:01974100-0000-7000-8000-000000000001".to_owned(),
            applet_id: package.applet_id.clone(),
            registration_event_ref: Some(
                arkret_core::EventId::new(
                    "ak:event:01974100-0000-7000-8000-000000000010".to_owned(),
                )
                .unwrap(),
            ),
            registration_epoch: package.registration_epoch.clone(),
            bot_actor_id: package.bot_actor_id.clone(),
            capability_grant_refs: vec![
                arkret_core::GrantId::new(
                    "ak:grant:01974100-0000-7000-8000-000000000020".to_owned(),
                )
                .unwrap(),
                arkret_core::GrantId::new(
                    "ak:grant:01974100-0000-7000-8000-000000000021".to_owned(),
                )
                .unwrap(),
            ],
            membership_event_refs: Vec::new(),
            e2ee_authorization_refs: Vec::new(),
            widget_policy_ref: None,
            effective_status: arkret_core::AppletInstallEffectiveStatus::Installed,
            rejected: Vec::new(),
        }
    }

    #[test]
    fn allow_ghost_actors_uses_package_ghost_policy_enabled() {
        let mut package = sample_package();
        package.ghost_policy = arkret_models_integration::applet::AppletGhostPolicy {
            enabled: true,
            accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
            ..Default::default()
        };
        let actor_policy = arkret_core::AppletActorPolicy {
            bot_membership: Some(arkret_core::AppletBotMembership::Join),
            ghost_actor_mode: Some(arkret_core::AppletGhostActorMode::PolicyDeclared),
        };
        assert!(allow_ghost_actors_for_install(
            &package,
            &[GHOST_PROVISION_ACTION.to_owned()],
            Some(&actor_policy)
        ));

        package.ghost_policy = arkret_models_integration::applet::AppletGhostPolicy {
            enabled: false,
            accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
            ..Default::default()
        };
        assert!(!allow_ghost_actors_for_install(
            &package,
            &[GHOST_PROVISION_ACTION.to_owned()],
            Some(&actor_policy)
        ));
    }

    fn sample_record(package: &AppletPackage, response: &AppletInstallOutcome) -> AppletRecord {
        AppletRecord {
            applet_id: package.applet_id.clone(),
            namespace: "bridge.test".to_owned(),
            owner_actor_id: "did:web:alice.example".to_owned(),
            registry_did: package.controller_id.to_string(),
            bot_actor_id: package.bot_actor_id.to_string(),
            portal_realm_id: "ak:realm:01974100-0000-7000-8000-000000000001".to_owned(),
            capabilities: vec![
                "ak.message.create".to_owned(),
                GHOST_PROVISION_ACTION.to_owned(),
            ],
            manifest: manifest_from_package(package),
            package: Some(package.clone()),
            registration_epoch_evidence: package.registration_epoch_evidence.clone(),
            namespaces: Some(package.namespaces.clone()),
            allow_ghost_actors: true,
            status: "installed".to_owned(),
            registered_at: chrono::DateTime::parse_from_rfc3339("2026-06-22T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            revoked_at: None,
            idempotency_key: Some("install-idem-1".to_owned()),
            install_body_digest: Some(format!("sha256:{}", "22".repeat(32))),
            install_id: Some(response.install_id.clone()),
            install_response: Some(response.clone()),
            install_execution: None,
            ghosts: Vec::new(),
        }
    }

    #[test]
    fn applet_record_round_trip_preserves_registration_epoch_evidence() {
        let mut package = sample_package();
        package.registration_epoch_evidence = Some(
            arkret_models_integration::applet::AppletRegistrationEpochEvidence::new(
                package.service_id.clone(),
                Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
                arkret_models_integration::applet::AppletDidMethodVersionEvidence::unversioned(
                    "did:web",
                )
                .unwrap(),
                vec![
                    arkret_models_integration::applet::AppletAcceptedSigningKeyEvidence {
                        key_ref: package.webhook_auth.key_ref.clone(),
                        public_key_digest: Hash::new(format!("sha256:{}", "33".repeat(32)))
                            .unwrap(),
                    },
                ],
            ),
        );
        let response = sample_response(&package);
        let record = sample_record(&package, &response);

        let stored = serde_json::to_value(&record).unwrap();
        assert!(stored.get("registration_epoch_evidence").is_some());
        let restored: AppletRecord = serde_json::from_value(stored).unwrap();
        assert_eq!(
            restored.registration_epoch_evidence,
            package.registration_epoch_evidence
        );
    }

    #[test]
    fn registration_epoch_validation_preserves_supplied_version_evidence() {
        let mut package = sample_package();
        let document = DidDocument::new(
            package.service_id.clone(),
            package.webhook_auth.key_ref.clone(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let version_time = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let evidence = arkret_core::AppletRegistrationEpochEvidence::from_did_document(
            &document,
            arkret_core::AppletDidMethodVersionEvidence::versioned(
                "did:web",
                None,
                Some(version_time),
            )
            .unwrap(),
        )
        .unwrap();
        package.registration_epoch_evidence = Some(evidence.clone());

        let validated =
            validate_registration_epoch_evidence_for_document(&package, &document).unwrap();
        assert_eq!(validated, evidence);
    }

    #[test]
    fn registration_epoch_validation_rejects_missing_supplied_evidence() {
        let package = sample_package();
        let document = DidDocument::new(
            package.service_id.clone(),
            package.webhook_auth.key_ref.clone(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );

        assert!(validate_registration_epoch_evidence_for_document(&package, &document).is_err());
    }

    #[test]
    fn install_execution_record_tracks_pending_and_accepted_steps() {
        let package = sample_package();
        let response = sample_response(&package);
        let record = sample_record(&package, &response);
        let body_digest = record.install_body_digest.as_deref().unwrap();
        let submitted_plan_digest = format!("sha256:{}", "33".repeat(32));

        let pending = build_install_execution_record(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            &record.owner_actor_id,
            record.idempotency_key.as_deref().unwrap(),
            body_digest,
            &submitted_plan_digest,
            &record,
            &response,
            false,
        )
        .unwrap();
        assert_eq!(pending["status"], json!("pending"));
        assert_eq!(pending["body_hash"], json!(body_digest));
        assert_eq!(
            pending["submitted_plan_digest"],
            json!(submitted_plan_digest.as_str())
        );
        assert!(
            pending["produced_event_refs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let pending_steps = pending["steps"].as_array().unwrap();
        assert_eq!(pending_steps.len(), 3);
        assert_eq!(
            pending_steps[0]["target_event_kind"],
            json!(arkret_wire::events::EventKind::APPLET_REGISTRATION)
        );
        assert_eq!(pending_steps[0]["status"], json!("pending"));
        assert_eq!(pending_steps[0]["event_ref"], Value::Null);
        assert!(
            pending_steps[0]["canonical_event_body_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            pending_steps[1]["grant_binding"]["registration_epoch"],
            json!(package.registration_epoch.to_string())
        );

        let accepted = build_install_execution_record(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            &record.owner_actor_id,
            record.idempotency_key.as_deref().unwrap(),
            body_digest,
            &submitted_plan_digest,
            &record,
            &response,
            true,
        )
        .unwrap();
        assert_eq!(accepted["status"], json!("completed"));
        let produced_refs = accepted["produced_event_refs"].as_array().unwrap();
        assert_eq!(produced_refs.len(), 3);
        assert!(produced_refs.contains(&json!(
            response.registration_event_ref.as_ref().unwrap().as_str()
        )));
        assert!(produced_refs.contains(&json!(response.capability_grant_refs[0].as_str())));
        let accepted_steps = accepted["steps"].as_array().unwrap();
        assert!(
            accepted_steps
                .iter()
                .all(|step| step["status"] == json!("accepted"))
        );
        assert_eq!(
            accepted_steps[0]["event_ref"],
            json!(response.registration_event_ref.as_ref().unwrap().as_str())
        );
        assert_eq!(
            accepted_steps[1]["event_ref"],
            json!(response.capability_grant_refs[0].as_str())
        );
        assert_eq!(
            accepted,
            build_install_execution_record(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
                &record.owner_actor_id,
                record.idempotency_key.as_deref().unwrap(),
                body_digest,
                &submitted_plan_digest,
                &record,
                &response,
                true,
            )
            .unwrap()
        );
    }
}
