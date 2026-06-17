//! Ghost / bot actor provisioning, revocation, and the formal applet event
//! build + persistence path.

use cokret_sdk::{
    AccountabilityGrantPayload, AccountabilityScope, ActorProfileId,
    AppletDelegatedEventAuthorization, AppletId, Did, Event, EventRef, GhostActorProfileRequest,
    GhostActorProvisionRequestBody, Hash, Hlc, Proof, RealmId, canonical,
};
use serde_json::{Value, json};

use super::super::bot_actor::{self, BotActor, KIND_GHOST};
use super::record::{
    applet_record, applet_records, ensure_not_revoked, extension_actor_id_document,
    ghost_actor_id_for, persist_applet_record,
};
use super::types::{
    AppletGhostIngressRequestBody, AppletRecord, EVENT_SCHEMA_ID, FormalAppletEvent,
    GhostActorRecord,
};
use crate::error::AppError;
use crate::ids;
use crate::routing::events::projection::projection_event_json;
use crate::state::{AppState, CanonicalEventRecord, EventNotification, ProjectionEventRecord};

pub(super) async fn revoke_applet_record(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<super::types::AppletRevokeRecordOutcome, AppError> {
    let now = chrono::Utc::now();
    let mut record = applet_record(state, applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    if record.owner_actor_id != actor {
        return Err(AppError::capability_denied(
            "only the registering actor can revoke this applet",
        ));
    }
    record.status = "revoked".to_owned();
    record.revoked_at = Some(now);
    for ghost in &mut record.ghosts {
        ghost.revoked_at.get_or_insert(now);
    }
    persist_applet_record(state, &record).await?;
    bot_actor::revoke_bot(&record.bot_actor_id);
    for ghost in &record.ghosts {
        bot_actor::revoke_bot(&ghost.ghost_actor_id);
    }
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

pub(super) async fn build_ghost_accountability_grant_event(
    state: &AppState,
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
    service_did: &Did,
    ghost_actor_id: &Did,
    realm_id: &RealmId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<FormalAppletEvent, AppError> {
    let proof = production_payload_proof(
        state,
        service_did,
        "applet-accountability-grant",
        &json!({
            "issuer": service_did,
            "subject": ghost_actor_id,
            "applet_id": provision.applet_id,
            "realm_id": realm_id,
            "protocol": provision.protocol,
            "tenant": provision.tenant,
            "external_user_id": provision.external_user_id,
            "external_ref": provision.external_ref,
        }),
        now,
    )?;
    let grant = AccountabilityGrantPayload::new(
        service_did.clone(),
        ghost_actor_id.clone(),
        AccountabilityScope::Multiple(vec![
            "applet_ghost_actor".to_owned(),
            format!("applet:{}", provision.applet_id),
            format!("protocol:{}", provision.protocol),
            format!("tenant:{}", provision.tenant),
        ]),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::days(365),
        proof,
    );
    grant.validate_lifecycle_at(now).map_err(|error| {
        AppError::invalid_param(format!("accountability_grant invalid: {error}"))
    })?;
    let event = grant
        .to_event(
            realm_id.clone(),
            next_actor_seq(state, service_did.as_str()).await?,
            next_hlc(state)?,
            None,
        )
        .map_err(|error| {
            AppError::internal(format!("accountability grant event build failed: {error}"))
        })?;
    formal_event_from_sdk_event(
        state,
        event,
        service_did,
        "applet_ghost_accountability_grant",
        Some(service_did.as_str()),
        json!({
            "applet_id": record.applet_id,
            "service_did": service_did,
            "ghost_actor_id": ghost_actor_id,
            "protocol": provision.protocol,
            "tenant": provision.tenant,
            "external_user_id": provision.external_user_id,
            "external_ref": provision.external_ref,
        }),
    )
}

pub(super) async fn build_ghost_profile_create_event(
    state: &AppState,
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
    applet_id: AppletId,
    service_did: &Did,
    ghost_actor_id: &Did,
    realm_id: &RealmId,
    authorization_ref: &str,
) -> Result<FormalAppletEvent, AppError> {
    let display_name = provision
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(provision.external_user_id.as_str());
    let profile_id = ActorProfileId::new(cokret_sdk::new_prefixed_uuid7("ck:actor_profile:"))
        .map_err(|error| AppError::internal(format!("profile id generation failed: {error}")))?;
    let external_ref = json!({
        "schema": "ck.applet.ghost_actor.external_ref.v1",
        "protocol": provision.protocol,
        "tenant": provision.tenant,
        "external_user_id": provision.external_user_id,
        "realm_id": realm_id,
        "external_ref": provision.external_ref,
    });
    let mut accountable_principal_ids = vec![service_did.clone()];
    if let Ok(controller) = Did::new(record.registry_did.clone())
        && !accountable_principal_ids
            .iter()
            .any(|did| did == &controller)
    {
        accountable_principal_ids.push(controller);
    }
    let request = GhostActorProfileRequest::new(
        profile_id,
        ghost_actor_id.clone(),
        display_name,
        applet_id.clone(),
    )
    .with_realm_id(realm_id.clone())
    .with_accountable_principal_ids(accountable_principal_ids)
    .with_external_ref(external_ref);
    let authorization = AppletDelegatedEventAuthorization::new(
        service_did.clone(),
        authorization_ref.to_owned(),
        applet_id,
    );
    let mut event = request
        .profile_create_event(
            realm_id.clone(),
            next_actor_seq(state, ghost_actor_id.as_str()).await?,
            next_hlc(state)?,
            Some(&authorization),
        )
        .map_err(|error| {
            AppError::internal(format!("profile create event build failed: {error}"))
        })?;
    event
        .refs
        .push(EventRef::new(authorization_ref, "authorized_by"));
    formal_event_from_sdk_event(
        state,
        event,
        service_did,
        "applet_ghost_profile_create",
        Some(ghost_actor_id.as_str()),
        json!({
            "applet_id": record.applet_id,
            "service_did": service_did,
            "ghost_actor_id": ghost_actor_id,
            "authorization_ref": authorization_ref,
            "protocol": provision.protocol,
            "tenant": provision.tenant,
            "external_user_id": provision.external_user_id,
            "display_name": provision.display_name,
            "external_ref": provision.external_ref,
        }),
    )
}

pub(super) async fn persist_formal_applet_event(
    state: &AppState,
    event: FormalAppletEvent,
) -> Result<(), AppError> {
    if let Err(error) = state.persistence.events().put(event.canonical).await {
        tracing::error!(%error, event_id = %event.event_id, "applet ghost provisioning: failed to persist canonical event");
        return Err(AppError::internal(
            "failed to persist ghost actor provisioning event",
        ));
    }
    let _ = state.event_broadcast.send(EventNotification::event(
        event.projection.realm_id.clone(),
        event.projection.event_id.clone(),
        projection_event_json(&event.projection),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(event.projection)
        .await
    {
        tracing::error!(%error, event_id = %event.event_id, "applet ghost provisioning: failed to persist projection event");
        return Err(AppError::internal(
            "failed to persist ghost actor provisioning projection",
        ));
    }
    Ok(())
}

pub(super) fn formal_event_from_sdk_event(
    state: &AppState,
    event: Event,
    signing_did: &Did,
    operation_type: &str,
    sender: Option<&str>,
    projection_payload: Value,
) -> Result<FormalAppletEvent, AppError> {
    let event_id = event.event_id.to_string();
    let actor_id = event.actor_id.to_string();
    let actor_seq = event.actor_seq;
    let realm_id = event.realm_id.to_string();
    let kind = event.kind.clone();
    let mut envelope = serde_json::to_value(&event)
        .map_err(|error| AppError::internal(format!("event serialize failed: {error}")))?;
    let canonical_source = event_canonical_source(&envelope);
    let canonical_bytes = canonical::canonical_json_bytes(&canonical_source)
        .map_err(|error| AppError::internal(format!("event canonicalization failed: {error}")))?;
    let canonical_digest = canonical::sha256_digest(&canonical_bytes);
    let proof = event_proof(state, signing_did, &actor_id, &canonical_digest)?;
    envelope
        .as_object_mut()
        .ok_or_else(|| AppError::internal("event envelope is not an object"))?
        .insert("proofs".to_owned(), json!([proof]));

    let received_at = chrono::Utc::now();
    let canonical = CanonicalEventRecord {
        event_id: event_id.clone(),
        actor_id,
        actor_seq,
        realm_id: Some(realm_id.clone()),
        kind: kind.as_str().to_owned(),
        schema_id: EVENT_SCHEMA_ID.to_owned(),
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at,
    };
    let projection = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id,
        event_kind: kind.as_str().to_owned(),
        operation_type: operation_type.to_owned(),
        operation_id: Some(ids::generate_operation_id()),
        sender: sender.map(ToOwned::to_owned),
        payload: projection_payload,
        created_at: received_at,
    };
    Ok(FormalAppletEvent {
        event_id,
        canonical,
        projection,
    })
}

pub(super) fn event_canonical_source(envelope: &Value) -> Value {
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
}

pub(super) fn event_proof(
    state: &AppState,
    signing_did: &Did,
    actor_id: &str,
    event_digest: &str,
) -> Result<Proof, AppError> {
    let created_at = chrono::Utc::now();
    let verification_method = format!("{signing_did}#applet-service-key");
    let binding = json!({
        "event_digest": event_digest,
        "actor_id": actor_id,
        "verification_method": verification_method,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!("proof binding canonicalization failed: {error}"))
    })?;
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| AppError::internal(format!("event proof signing failed: {error}")))?;
    Ok(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(event_digest.to_owned())
            .map_err(|error| AppError::internal(format!("event digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        jws,
    })
}

pub(super) fn production_payload_proof(
    state: &AppState,
    signing_did: &Did,
    label: &str,
    payload: &Value,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Proof, AppError> {
    let binding = json!({
        "label": label,
        "payload": payload,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!(
            "accountability proof canonicalization failed: {error}"
        ))
    })?;
    let digest = canonical::sha256_digest(&binding_bytes);
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| {
                AppError::internal(format!("accountability proof signing failed: {error}"))
            })?;
    Ok(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{signing_did}#applet-service-key"),
        event_digest: Hash::new(digest)
            .map_err(|error| AppError::internal(format!("proof digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        jws,
    })
}

pub(super) async fn next_actor_seq(state: &AppState, actor_id: &str) -> Result<u64, AppError> {
    state
        .persistence
        .events()
        .max_actor_seq(actor_id)
        .await
        .map(|seq| seq.unwrap_or(0) + 1)
        .map_err(|error| AppError::internal(format!("event sequence lookup failed: {error}")))
}

pub(super) fn next_hlc(state: &AppState) -> Result<Hlc, AppError> {
    Hlc::new(state.hlc.now()).map_err(|error| AppError::internal(format!("HLC invalid: {error}")))
}

pub(super) fn validate_ghost_actor_provision_request(
    path_applet_id: &str,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    if provision.schema != GhostActorProvisionRequestBody::SCHEMA {
        return Err(AppError::invalid_param(format!(
            "schema must be {}",
            GhostActorProvisionRequestBody::SCHEMA
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
    if provision.external_ref.is_null() {
        return Err(AppError::missing_param("external_ref is required"));
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
    if package.service_did != provision.service_did {
        return Err(AppError::capability_denied(
            "service_did does not match installed applet package",
        ));
    }
    if record.portal_realm_id != provision.realm_id.as_str() {
        return Err(
            AppError::conflict("realm_id does not match installed applet effective scope")
                .with_wire_code("applet_effective_scope_mismatch"),
        );
    }
    if !record.allow_ghost_actors {
        return Err(AppError::capability_denied(
            "applet install does not grant ghost actor provisioning",
        ));
    }
    Ok(())
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
    if !record.allow_ghost_actors {
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
        created_at: now,
        revoked_at: None,
    };
    record.ghosts.push(ghost.clone());
    persist_applet_record(state, &record).await?;
    bot_actor::register_bot(BotActor {
        did: ghost.ghost_actor_id.clone(),
        name: ghost
            .display_name
            .clone()
            .unwrap_or_else(|| ghost.external_id.clone()),
        kind: KIND_GHOST.to_owned(),
        owner_actor_id: record.owner_actor_id.clone(),
        created_at: now,
        revoked_at: None,
    });
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
