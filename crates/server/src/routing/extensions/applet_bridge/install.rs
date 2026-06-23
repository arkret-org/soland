//! Canonical applet install: package validation, plan building, registration
//! projection, portal message ingress, and the realm-admin governance gate.

use std::collections::BTreeSet;

use cokret_sdk::{
    AppletPackage, AppletWireNamespaces, ApprovalRequest, ApprovedScope, EffectiveScope,
    InstallCapabilityConstraint, InstallCommitOutcome, InstallCommitRequestBody,
    InstallDeniedScope, InstallE2eeEffect, InstallE2eePolicy, InstallEventSubmission,
    InstallNamespaceConflict, InstallPlan, InstallWidgetEffect, RealmId,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::super::applet_manifest::{AppletManifest, VerifiedAppletManifest};
use super::super::bot_actor::{self, BotActor, KIND_BOT};
use super::record::{
    applet_display_name, applet_record, applet_records, bot_actor_id_for, manifest_namespace,
    persist_applet_record, portal_realm_id_for, safe_token,
};
use super::types::{
    AppletManifestRegisterRequestBody, AppletPortalMessageOutcome, AppletRecord, AppletView,
    GhostActorRecord,
};
use crate::error::AppError;
use crate::ids;
use crate::reducer::AppletProjection;
use crate::routing::events::projection::projection_event_json;
use crate::routing::events::strand::strand_id_from_realm_id;
use crate::state::{AppState, EventNotification, MessageRecord, ProjectionEventRecord};

pub(super) const GHOST_PROVISION_ACTION: &str = "ck.applet.ghost.provision";

pub(super) async fn register_package_install(
    state: &AppState,
    owner_actor_id: &str,
    commit: InstallCommitRequestBody,
    idempotency_key: String,
    body_digest: String,
    res: &mut Response,
) -> Result<InstallCommitOutcome, AppError> {
    let submitted_plan_digest = commit.plan_digest.to_string();
    let package = commit.applet_package;
    let applet_id = package.applet_id.clone();
    let namespace = package_namespace(&package);
    let realm_id = effective_scope_realm_id(&commit.effective_scope);
    let approved_actions = actions_from_approved_scopes(&commit.approved_scopes);
    let allow_ghost_actors =
        allow_ghost_actors_for_install(&package, &approved_actions, &commit.actor_policy);

    if let Some(existing) = applet_record(state, &applet_id).await? {
        if existing.idempotency_key.as_deref() == Some(idempotency_key.as_str()) {
            if existing.install_body_digest.as_deref() == Some(body_digest.as_str())
                && let Some(response) = &existing.install_response
            {
                let mut recovered = existing.clone();
                if recovered.install_execution.is_none() {
                    recovered.install_execution = Some(build_install_execution_record(
                        &state.config.service_did,
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
    let registration_event_ref = ids::generate_event_id();
    let capability_grant_refs = approved_actions
        .iter()
        .map(|_| ids::generate_grant_id())
        .collect::<Vec<_>>();
    let e2ee_authorization_refs =
        e2ee_authorization_refs_for_install(&package, &commit.e2ee_policy)?;
    let effective_status = if approved_actions.is_empty() {
        "rejected"
    } else if approved_actions.len() < package.requested_scopes.len() {
        "partially_installed"
    } else {
        "installed"
    };
    let install_id = ids::generate_install_id();
    let response = InstallCommitOutcome {
        ok: effective_status != "rejected",
        install_id,
        applet_id: applet_id.clone(),
        registration_event_ref: registration_event_ref.clone(),
        registration_epoch: package.registration_epoch.clone(),
        bot_actor_id: package.bot_actor_id.clone(),
        capability_grant_refs,
        membership_event_refs: Vec::new(),
        e2ee_authorization_refs,
        widget_policy_ref: None,
        effective_status: effective_status.to_owned(),
        rejected: denied_scope_values(&package, &approved_actions)
            .into_iter()
            .map(|scope| {
                serde_json::to_value(scope)
                    .map_err(|error| AppError::internal(format!("denied scope serialize: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut record = AppletRecord {
        applet_id: package.applet_id.clone(),
        namespace,
        owner_actor_id: owner_actor_id.to_owned(),
        registry_did: package.controller_did.to_string(),
        bot_actor_id: package.bot_actor_id.to_string(),
        portal_realm_id: realm_id,
        capabilities: approved_actions,
        manifest: manifest_from_package(&package),
        package: Some(package.clone()),
        namespaces: Some(package.namespaces.clone()),
        allow_ghost_actors,
        status: effective_status.to_owned(),
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
        &state.config.service_did,
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
            "service_did": package.service_did,
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
    response: &InstallCommitOutcome,
) -> Result<(), AppError> {
    register_applet_install_bot(record);
    update_applet_projection(state, record);
    ensure_applet_registration_projection(state, record, &response.registration_event_ref).await?;
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
            &state.config.service_did,
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
    event_ids: &[String],
) -> Result<(), AppError> {
    if event_ids.is_empty() {
        return Ok(());
    }
    let existing = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .map_err(|error| {
            tracing::error!(%error, "applet install: failed to inspect e2ee authorization projection recovery");
            AppError::internal("failed to inspect applet e2ee authorization projection")
        })?
        .into_iter()
        .map(|event| event.event_id)
        .collect::<BTreeSet<_>>();
    for event_id in event_ids {
        if !existing.contains(event_id) {
            append_applet_e2ee_authorization_projection(state, record, event_id).await?;
        }
    }
    Ok(())
}

fn register_applet_install_bot(record: &AppletRecord) {
    bot_actor::register_bot(BotActor {
        did: record.bot_actor_id.clone(),
        name: applet_display_name(&record.manifest).unwrap_or_else(|| record.namespace.clone()),
        kind: KIND_BOT.to_owned(),
        owner_actor_id: record.owner_actor_id.clone(),
        created_at: record.registered_at,
        revoked_at: None,
    });
}

async fn ensure_applet_registration_projection(
    state: &AppState,
    record: &AppletRecord,
    event_id: &str,
) -> Result<(), AppError> {
    let exists = state
        .persistence
        .projection_events()
        .snapshot_all()
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

fn project_applet_install_grants(state: &AppState, record: &AppletRecord, grant_ids: &[String]) {
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
            .authz
            .upsert_projected_grant(applet_install_grant(record, package, grant_id, action));
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
        subject: package.service_did.to_string(),
        resource: record.portal_realm_id.clone(),
        actions: vec![action.to_owned()],
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
        executed_by: package.service_did.to_string(),
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
    response: &InstallCommitOutcome,
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

fn install_produced_event_refs(response: &InstallCommitOutcome) -> Vec<String> {
    let mut refs = Vec::with_capacity(
        1 + response.capability_grant_refs.len()
            + response.membership_event_refs.len()
            + response.e2ee_authorization_refs.len()
            + usize::from(response.widget_policy_ref.is_some()),
    );
    refs.push(response.registration_event_ref.clone());
    refs.extend(response.capability_grant_refs.iter().cloned());
    refs.extend(response.membership_event_refs.iter().cloned());
    refs.extend(response.e2ee_authorization_refs.iter().cloned());
    if let Some(widget_policy_ref) = &response.widget_policy_ref {
        refs.push(widget_policy_ref.clone());
    }
    refs
}

fn install_execution_steps(
    record: &AppletRecord,
    response: &InstallCommitOutcome,
    accepted: bool,
) -> Result<Vec<Value>, AppError> {
    let Some(package) = record.package.as_ref() else {
        return Ok(Vec::new());
    };
    let mut steps = Vec::with_capacity(
        1 + response.capability_grant_refs.len() + response.e2ee_authorization_refs.len(),
    );
    let registration_body = json!({
        "event_kind": cokret_sdk::events::kinds::APPLET_REGISTRATION,
        "payload": registration_payload_from_package(package)?,
    });
    steps.push(install_execution_step(
        0,
        cokret_sdk::events::kinds::APPLET_REGISTRATION,
        &response.registration_event_ref,
        canonical_digest(&registration_body)?,
        accepted,
        None,
    ));
    for (offset, (grant_id, action)) in response
        .capability_grant_refs
        .iter()
        .zip(record.capabilities.iter())
        .enumerate()
    {
        let grant = applet_install_grant(record, package, grant_id, action);
        let grant_body = json!({
            "event_kind": cokret_sdk::events::kinds::CAPABILITY_GRANT,
            "payload": {
                "grant_id": grant_id,
                "grant": grant,
            },
        });
        steps.push(install_execution_step(
            offset + 1,
            cokret_sdk::events::kinds::CAPABILITY_GRANT,
            grant_id,
            canonical_digest(&grant_body)?,
            accepted,
            Some(json!({
                "applet_id": record.applet_id.as_str(),
                "executed_by": package.service_did.to_string(),
                "registration_epoch": package.registration_epoch.to_string(),
            })),
        ));
    }
    let e2ee_start = 1 + response.capability_grant_refs.len();
    for (offset, event_ref) in response.e2ee_authorization_refs.iter().enumerate() {
        let body = json!({
            "event_kind": "ck.member.state",
            "payload": applet_e2ee_authorization_payload(record, package),
        });
        steps.push(install_execution_step(
            e2ee_start + offset,
            "ck.member.state",
            event_ref,
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
        event_kind: cokret_sdk::events::kinds::APPLET_REGISTRATION.to_owned(),
        operation_type: "applet_install_registration".to_owned(),
        operation_id: None,
        sender: Some(record.owner_actor_id.clone()),
        payload: registration_payload_from_package(package)?,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        projection_event_json(&projection_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(projection_record)
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
    let projection = AppletProjection {
        service_did: package.service_did.to_string(),
        namespace: record.namespace.clone(),
        manifest: Some(package.manifest_snapshot()),
        capabilities: Some(json!(record.capabilities)),
        registered_at: now,
        updated_at: now,
    };
    let mut guard = state.projection.lock().expect("projection lock");
    guard
        .applets
        .insert(package.service_did.to_string(), projection.clone());
    guard.applets.insert(record.applet_id.clone(), projection);
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
    let portal_realm_id = portal_realm_id_for(&namespace, &applet_id);
    let record = AppletRecord {
        applet_id,
        namespace,
        owner_actor_id: owner_actor_id.to_owned(),
        registry_did: verified.signer_did,
        bot_actor_id: bot_actor_id.clone(),
        portal_realm_id,
        capabilities: verified.capabilities,
        manifest,
        package: None,
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
    persist_applet_record(state, &record).await?;
    bot_actor::register_bot(BotActor {
        did: bot_actor_id,
        name: applet_display_name(&record.manifest).unwrap_or_else(|| record.namespace.clone()),
        kind: KIND_BOT.to_owned(),
        owner_actor_id: owner_actor_id.to_owned(),
        created_at: now,
        revoked_at: None,
    });
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
            "applet install does not grant ck.message.create",
        ));
    }
    let operation_id = ids::generate_operation_id();
    let event_id = ids::generate_event_id();
    let thread_id = strand_id_from_realm_id(realm_id);
    let created_at = chrono::Utc::now();
    let content_with_portal = enrich_content_with_portal_metadata(content, applet, ghost);
    let message_record = MessageRecord {
        event_id: event_id.clone(),
        message_id: crate::routing::events::strand::message_id_from_event_id(&event_id),
        realm_id: realm_id.to_owned(),
        sender: ghost.ghost_actor_id.clone(),
        thread_id: thread_id.clone(),
        content: content_with_portal.clone(),
        encrypted: false,
        created_at,
    };
    if let Err(error) = state.persistence.messages().put(&message_record).await {
        tracing::error!(%error, "applet bridge: failed to persist portal MessageRecord");
        return Err(AppError::internal("failed to persist portal message"));
    }
    let projection_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.to_owned(),
        event_kind: cokret_sdk::events::kinds::MESSAGE_CREATE.to_owned(),
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
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        projection_event_json(&projection_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(projection_record)
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
    if kind != "message" && kind != "ck.content.text" {
        return Ok(None);
    }
    let text = payload
        .get("text")
        .or_else(|| payload.get("body"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid_param("payload.text is required"))?;
    Ok(Some(json!({
        "kind": "ck.content.text",
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
    package: &AppletPackage,
) -> Result<(), AppError> {
    package
        .validate()
        .map_err(|error| AppError::invalid_param(format!("applet package invalid: {error}")))?;
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
    let expected_payload_digest = cokret_sdk::Hash::new(
        cokret_sdk::canonical::canonical_sha256(&unsigned)
            .map_err(|error| AppError::internal(format!("package proof digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("package proof digest invalid: {error}")))?;
    if proof.event_digest != expected_payload_digest {
        return Err(
            AppError::invalid_param("applet package proof payload_digest mismatch")
                .with_wire_code("proof_invalid"),
        );
    }
    validate_registration_epoch_evidence(state, package)?;
    Ok(())
}

fn validate_registration_epoch_evidence(
    state: &AppState,
    package: &AppletPackage,
) -> Result<(), AppError> {
    let evidence = package
        .registration_epoch_evidence
        .as_ref()
        .ok_or_else(|| {
            AppError::invalid_param("applet package registration_epoch_evidence is required")
                .with_wire_code("applet_registration_epoch_evidence_missing")
        })?;
    let document =
        crate::jws_verify::resolve_did_document(state, &package.service_did).map_err(|reason| {
            AppError::invalid_param("applet service DID document could not be resolved")
                .with_wire_code("applet_registration_epoch_evidence_mismatch")
                .with_reason_detail(reason)
        })?;
    evidence
        .validate_against_did_document(&document)
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
    Ok(())
}

pub(super) fn approved_scopes_from_approval_request(
    package: &AppletPackage,
    scope: &EffectiveScope,
    approval: &ApprovalRequest,
) -> Result<Vec<ApprovedScope>, AppError> {
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
        EffectiveScope::Realm { realm_id } => (realm_id.clone(), Vec::new()),
        EffectiveScope::Circle {
            realm_id,
            circle_id,
        } => (realm_id.clone(), vec![circle_id.clone()]),
    };
    Ok(vec![ApprovedScope {
        actions: approved.into_iter().collect(),
        realm_ids: vec![realm_id],
        circle_ids,
        constraints: Vec::new(),
    }])
}

pub(super) fn approval_actions_for_install(approval: &ApprovalRequest) -> Vec<String> {
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
    approved_scopes: Vec<ApprovedScope>,
) -> Result<InstallPlan, AppError> {
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
        "schema": "ck.schema.applet_install_plan.v1",
        "applet_id": package.applet_id,
        "package_digest": package_digest,
        "registration_epoch": package.registration_epoch,
        "effective_scope": scope,
        "requested_scopes": package.requested_scopes,
        "approved_scopes": approved_scopes,
        "denied_scopes": denied_scopes,
        "events_to_submit": [{
            "event_kind": cokret_sdk::events::kinds::APPLET_REGISTRATION,
            "payload": registration_payload,
        }],
        "capability_constraints": capability_constraints_for_scope(scope),
        "namespace_conflicts": [],
        "e2ee_effect": e2ee_effect_for_package(package),
        "widget_effect": widget_effect_for_package(package),
        "warnings": [],
    });
    let plan_id = deterministic_plan_id(&seed)?;
    let mut plan = InstallPlan {
        schema: "ck.schema.applet_install_plan.v1".to_owned(),
        plan_id,
        applet_id: package.applet_id.clone(),
        package_digest,
        registration_epoch: package.registration_epoch.clone(),
        effective_scope: scope.clone(),
        requested_scopes: package.requested_scopes.clone(),
        approved_scopes,
        denied_scopes,
        events_to_submit: vec![InstallEventSubmission {
            event_kind: cokret_sdk::events::kinds::APPLET_REGISTRATION.to_owned(),
            payload: registration_payload,
            refs: Vec::new(),
        }],
        capability_constraints: capability_constraints_for_scope(scope),
        namespace_conflicts: Vec::<InstallNamespaceConflict>::new(),
        e2ee_effect: e2ee_effect_for_package(package),
        widget_effect: widget_effect_for_package(package),
        warnings: Vec::new(),
        plan_digest: None,
    };
    let plan_digest = plan
        .compute_plan_digest()
        .map_err(|error| AppError::internal(format!("install plan digest failed: {error}")))?;
    plan.plan_digest = Some(plan_digest);
    Ok(plan)
}

pub(super) fn registration_payload_from_package(
    package: &AppletPackage,
) -> Result<Value, AppError> {
    Ok(json!({
        "applet_id": package.applet_id,
        "service_did": package.service_did,
        "controller_did": package.controller_did,
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
) -> Vec<InstallCapabilityConstraint> {
    let mut params = json!({
        "realm_id": effective_scope_realm_id(scope),
    });
    if let EffectiveScope::Circle { circle_id, .. } = scope
        && let Some(params) = params.as_object_mut()
    {
        params.insert("circle_id".to_owned(), Value::String(circle_id.to_string()));
    }
    vec![InstallCapabilityConstraint {
        constraint_type: "effective_scope".to_owned(),
        params: Some(params),
    }]
}

pub(super) fn e2ee_effect_for_package(package: &AppletPackage) -> InstallE2eeEffect {
    InstallE2eeEffect {
        requires_mls_join: package
            .e2ee_policy
            .get("allow_mls_join")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        plaintext_access: "policy_declared".to_owned(),
        authorization_refs: Vec::new(),
    }
}

fn package_requests_mls_join(package: &AppletPackage) -> bool {
    package
        .e2ee_policy
        .get("allow_mls_join")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn e2ee_authorization_refs_for_install(
    package: &AppletPackage,
    e2ee_policy: &InstallE2eePolicy,
) -> Result<Vec<String>, AppError> {
    if !package_requests_mls_join(package) {
        return Ok(Vec::new());
    }
    if !e2ee_policy.allow_mls_join {
        return Err(AppError::capability_denied(
            "applet E2EE MLS join requires independent authorization",
        )
        .with_wire_code("applet_e2ee_join_unauthorized"));
    }
    Ok(vec![ids::generate_event_id()])
}

fn applet_e2ee_authorization_payload(record: &AppletRecord, package: &AppletPackage) -> Value {
    json!({
        "membership": "join",
        "realm_id": record.portal_realm_id.as_str(),
        "actor_id": package.bot_actor_id.to_string(),
        "applet_id": record.applet_id.as_str(),
        "managed_by_applet": true,
        "e2ee_join_authorization": {
            "profile": "ck.profile.applet_e2ee_join.v1",
            "authorization_gate": "applet_e2ee_join",
            "authorized_by": record.owner_actor_id.as_str(),
            "registration_epoch": package.registration_epoch.to_string(),
            "service_did": package.service_did.to_string(),
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
        event_kind: "ck.member.state".to_owned(),
        operation_type: "applet_e2ee_join_authorization".to_owned(),
        operation_id: None,
        sender: Some(record.owner_actor_id.clone()),
        payload,
        created_at: record.registered_at,
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        projection_event_json(&projection_record),
    ));
    state
        .persistence
        .projection_events()
        .append(projection_record)
        .await
        .map_err(|error| {
            tracing::error!(%error, %event_id, "applet install: failed to append e2ee authorization projection");
            AppError::internal("failed to append applet e2ee authorization projection")
        })
}

pub(super) fn widget_effect_for_package(package: &AppletPackage) -> InstallWidgetEffect {
    InstallWidgetEffect {
        allow_widget: package.widget.is_some(),
        policy_event_ref: None,
    }
}

pub(super) fn deterministic_plan_id(plan_seed: &Value) -> Result<String, AppError> {
    let digest = canonical_digest(plan_seed)?;
    Ok(format!("ck:plan:{}", digest.trim_start_matches("sha256:")))
}

pub(super) fn canonical_digest(value: &Value) -> Result<String, AppError> {
    cokret_sdk::canonical::canonical_sha256(value)
        .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))
}

pub(super) fn actions_from_approved_scopes(scopes: &[ApprovedScope]) -> Vec<String> {
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
) -> Vec<InstallDeniedScope> {
    let approved = approved_actions.iter().collect::<BTreeSet<_>>();
    package
        .requested_scopes
        .iter()
        .filter(|scope| !approved.contains(scope))
        .map(|scope| InstallDeniedScope {
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
    }
}

/// Governance gate for canonical applet install/revoke.
///
/// An authenticated session is not enough to register or revoke a realm-scoped
/// applet install: the actor MUST hold `ck.realm.admin` over the install's
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
        .authz
        .check(
            actor,
            "ck.realm.admin",
            &realm_id,
            &realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err(
        AppError::capability_denied("actor lacks ck.realm.admin over the applet install realm")
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
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = state
        .realms
        .lock()
        .ok()
        .map(|realms| {
            if let Some(realm) = RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id))
            {
                return realm.members.iter().map(ToString::to_string).collect();
            }
            Vec::new()
        })
        .unwrap_or_default();
    (owner, members)
}

pub(super) fn manifest_from_package(package: &AppletPackage) -> AppletManifest {
    AppletManifest {
        id: package.applet_id.clone(),
        version: "1.0.0".to_owned(),
        signer_did: package.controller_did.to_string(),
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
    actor_policy: &cokret_sdk::ActorPolicy,
) -> bool {
    let package_allows = package
        .ghost_policy
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let scope_approved = approved_actions
        .iter()
        .any(|action| action == GHOST_PROVISION_ACTION);
    package_allows && scope_approved && actor_policy.ghost_actor_mode != "disallowed"
}

pub(super) fn capability_allows_message_create(capability: &str) -> bool {
    capability == "ck.message.create"
}

#[cfg(test)]
mod tests {
    use cokret_sdk::{AppletNamespaceEntry, Did, Hash};

    use super::*;

    fn sample_package() -> AppletPackage {
        let registration_epoch = Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        AppletPackage::new(
            "package:ck:applet:test".to_owned(),
            "ck:applet:01974100-0000-7000-8000-000000000001".to_owned(),
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            Did::new("did:web:test-registry.example".to_owned()).unwrap(),
            "https://test-applet.example".to_owned(),
            Did::new("did:web:bot-test-applet.soland.local".to_owned()).unwrap(),
            vec!["cokret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
            registration_epoch,
        )
    }

    fn sample_response(package: &AppletPackage) -> InstallCommitOutcome {
        InstallCommitOutcome {
            ok: true,
            install_id: "ck:install:01974100-0000-7000-8000-000000000001".to_owned(),
            applet_id: package.applet_id.clone(),
            registration_event_ref: "ck:event:01974100-0000-7000-8000-000000000010".to_owned(),
            registration_epoch: package.registration_epoch.clone(),
            bot_actor_id: package.bot_actor_id.clone(),
            capability_grant_refs: vec![
                "ck:grant:01974100-0000-7000-8000-000000000020".to_owned(),
                "ck:grant:01974100-0000-7000-8000-000000000021".to_owned(),
            ],
            membership_event_refs: Vec::new(),
            e2ee_authorization_refs: Vec::new(),
            widget_policy_ref: None,
            effective_status: "installed".to_owned(),
            rejected: Vec::new(),
        }
    }

    #[test]
    fn allow_ghost_actors_uses_package_ghost_policy_enabled() {
        let mut package = sample_package();
        package.ghost_policy = json!({
            "enabled": true,
            "accountability_template": "bot_actor_and_applet_registry"
        });
        let actor_policy = cokret_sdk::ActorPolicy {
            bot_membership: "join".to_owned(),
            ghost_actor_mode: "policy_declared".to_owned(),
        };
        assert!(allow_ghost_actors_for_install(
            &package,
            &[GHOST_PROVISION_ACTION.to_owned()],
            &actor_policy
        ));

        package.ghost_policy = json!({
            "enabled": false,
            "accountability_template": "bot_actor_and_applet_registry"
        });
        assert!(!allow_ghost_actors_for_install(
            &package,
            &[GHOST_PROVISION_ACTION.to_owned()],
            &actor_policy
        ));
    }

    fn sample_record(package: &AppletPackage, response: &InstallCommitOutcome) -> AppletRecord {
        AppletRecord {
            applet_id: package.applet_id.clone(),
            namespace: "bridge.test".to_owned(),
            owner_actor_id: "did:web:alice.example".to_owned(),
            registry_did: package.controller_did.to_string(),
            bot_actor_id: package.bot_actor_id.to_string(),
            portal_realm_id: "ck:realm:01974100-0000-7000-8000-000000000001".to_owned(),
            capabilities: vec![
                "ck.message.create".to_owned(),
                GHOST_PROVISION_ACTION.to_owned(),
            ],
            manifest: manifest_from_package(package),
            package: Some(package.clone()),
            namespaces: Some(package.namespaces.clone()),
            allow_ghost_actors: true,
            status: "installed".to_owned(),
            registered_at: chrono::DateTime::parse_from_rfc3339("2026-06-22T00:00:00Z")
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
    fn install_execution_record_tracks_pending_and_accepted_steps() {
        let package = sample_package();
        let response = sample_response(&package);
        let record = sample_record(&package, &response);
        let body_digest = record.install_body_digest.as_deref().unwrap();
        let submitted_plan_digest = format!("sha256:{}", "33".repeat(32));

        let pending = build_install_execution_record(
            "did:web:soland.local",
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
            json!(cokret_sdk::events::kinds::APPLET_REGISTRATION)
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
            "did:web:soland.local",
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
        assert!(produced_refs.contains(&json!(response.registration_event_ref.as_str())));
        assert!(produced_refs.contains(&json!(response.capability_grant_refs[0].as_str())));
        let accepted_steps = accepted["steps"].as_array().unwrap();
        assert!(
            accepted_steps
                .iter()
                .all(|step| step["status"] == json!("accepted"))
        );
        assert_eq!(
            accepted_steps[0]["event_ref"],
            json!(response.registration_event_ref.as_str())
        );
        assert_eq!(
            accepted_steps[1]["event_ref"],
            json!(response.capability_grant_refs[0].as_str())
        );
        assert_eq!(
            accepted,
            build_install_execution_record(
                "did:web:soland.local",
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
