//! Ghost / bot actor provisioning, revocation, and the formal applet event
//! build + persistence path.

use arkret_core::{
    ActorProfileId, AppletDelegatedEventAuthorization, AppletId, AppletNamespaceDomain, Did, Event,
    EventRef, GhostActorProfileRequest, GhostActorProvisionRequestBody, Hash, Hlc, PayloadProof,
    RealmId, canonical, namespace_pattern_matches,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_storage::SessionRecord;

use super::record::{
    applet_record, applet_records, ensure_not_revoked, extension_actor_id_document,
    ghost_actor_id_for, persist_applet_record,
};
use super::types::{
    AppletGhostIngressRequestBody, AppletRecord, FormalAppletEvent, GhostActorRecord,
};
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

pub(super) async fn build_ghost_accountability_grant_event(
    state: &AppState,
    provision: &GhostActorProvisionRequestBody,
    service_id: &Did,
    ghost_actor_id: &Did,
    realm_id: &RealmId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<FormalAppletEvent, AppError> {
    let proof = production_payload_proof(
        state,
        service_id,
        "applet-accountability-grant",
        &json!({
            "issuer": service_id,
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
        service_id.clone(),
        ghost_actor_id.clone(),
        AccountabilityScope::Single(AccountabilityScopeKind::ContractedService),
        now - chrono::Duration::seconds(1),
        // Longevity-safe default: no expiry cliff; the grant is governed by
        // grant_status revocation and Applet registration lifecycle
        // (actor.md §3.3.1).
        None,
        proof,
    );
    grant.validate_lifecycle_at(now).map_err(|error| {
        AppError::invalid_param(format!("accountability_grant invalid: {error}"))
    })?;
    let (actor_seq, prev_refs) = next_actor_frontier(state, service_id.as_str(), realm_id).await?;
    let mut event = arkret_event_draft::accountability_grant_event(
        &grant,
        realm_id.clone(),
        actor_seq,
        next_hlc(state)?,
        None,
    )
    .map_err(|error| {
        AppError::internal(format!("accountability grant event build failed: {error}"))
    })?;
    event.prev_refs = prev_refs;
    formal_event_from_sdk_event(state, event, service_id)
}

pub(super) async fn build_ghost_profile_create_event(
    state: &AppState,
    provision: &GhostActorProvisionRequestBody,
    applet_id: AppletId,
    service_id: &Did,
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
    let profile_id = ActorProfileId::new(arkret_core::new_prefixed_uuid7("ak:actor_profile:"))
        .map_err(|error| AppError::internal(format!("profile id generation failed: {error}")))?;
    let external_ref = json!({
        "schema": "ak.applet.ghost_actor.external_ref.v1",
        "protocol": provision.protocol,
        "tenant": provision.tenant,
        "external_user_id": provision.external_user_id,
        "realm_id": realm_id,
        "external_ref": provision.external_ref,
    });
    let request = GhostActorProfileRequest::new(
        profile_id,
        ghost_actor_id.clone(),
        display_name,
        applet_id.clone(),
    )
    .with_realm_id(realm_id.clone())
    .with_accountable_principal_ids(vec![service_id.clone()])
    .with_external_ref(
        serde_json::from_value(external_ref)
            .map_err(|error| AppError::internal(format!("external_ref encode failed: {error}")))?,
    );
    let authorization = AppletDelegatedEventAuthorization::new(
        service_id.clone(),
        authorization_ref.to_owned(),
        applet_id,
    );
    let (actor_seq, prev_refs) =
        next_actor_frontier(state, ghost_actor_id.as_str(), realm_id).await?;
    let mut event = request
        .profile_create_event(
            realm_id.clone(),
            actor_seq,
            next_hlc(state)?,
            Some(&authorization),
        )
        .map_err(|error| {
            AppError::internal(format!("profile create event build failed: {error}"))
        })?;
    event.prev_refs = prev_refs;
    event
        .refs
        .push(EventRef::new(authorization_ref, "authorized_by"));
    formal_event_from_sdk_event(state, event, service_id)
}

pub(super) async fn persist_formal_applet_event(
    state: &AppState,
    event: FormalAppletEvent,
) -> Result<(), AppError> {
    let now = chrono::Utc::now();
    let realm_id = event.event.realm_id.to_string();
    let kind = event.event.kind.to_string();
    let event_id = event.event.event_id.to_string();
    let session = SessionRecord {
        token_hash: "applet-formal-event".to_owned(),
        actor: event.event.actor_id.to_string(),
        device_id: "applet-service".to_owned(),
        audience: state.service_id.clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: now + chrono::Duration::minutes(5),
        created_at: now,
        revoked_at: None,
    };
    let envelope = serde_json::to_value(event.event)
        .map_err(|error| AppError::internal(format!("event serialize failed: {error}")))?;
    crate::routing::events::event_log::submit_applet_event_value(
        state, &session, envelope, &realm_id, &kind, &event_id,
    )
    .await
    .map_err(|error| {
        AppError::new(
            soland_http::error::ErrorCode::InvalidParam,
            format!("applet formal Event admission failed: {}", error.message),
        )
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    Ok(())
}

pub(super) fn formal_event_from_sdk_event(
    state: &AppState,
    mut event: Event,
    signing_did: &Did,
) -> Result<FormalAppletEvent, AppError> {
    let event_id = event.event_id.to_string();
    let verification_method = format!("{signing_did}#notary-key");
    let signer = arkret_signatures::Ed25519MoveSigner::new(
        state.notary_signing_key().as_ref().clone(),
        signing_did.clone(),
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new(),
    )
    .map_err(|error| AppError::internal(format!("event proof signing failed: {error}")))?;
    Ok(FormalAppletEvent { event_id, event })
}

pub(super) fn production_payload_proof(
    state: &AppState,
    signing_did: &Did,
    label: &str,
    payload: &Value,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<PayloadProof, AppError> {
    let binding = json!({
        "label": label,
        "payload": payload,
        "created_at": arkret_core::canonical::format_timestamp_canonical(created_at),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!(
            "accountability proof canonicalization failed: {error}"
        ))
    })?;
    let digest = canonical::sha256_digest(&binding_bytes);
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &binding_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("accountability proof signing failed: {error}")))?;
    Ok(PayloadProof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{signing_did}#applet-service-key"),
        payload_digest: Hash::new(digest)
            .map_err(|error| AppError::internal(format!("proof digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws,
    })
}

pub(super) async fn next_actor_frontier(
    state: &AppState,
    actor_id: &str,
    realm_id: &RealmId,
) -> Result<(u64, Vec<arkret_core::EventId>), AppError> {
    let records = state
        .events_store()
        .list_for_actor(actor_id)
        .await
        .map_err(|error| AppError::internal(format!("event frontier lookup failed: {error}")))?;
    let scoped = records
        .into_iter()
        .filter(|record| record.realm_id.as_deref() == Some(realm_id.as_str()))
        .collect::<Vec<_>>();
    let max_seq = scoped
        .iter()
        .map(|record| record.actor_seq)
        .max()
        .unwrap_or(0);
    let prev_refs = scoped
        .into_iter()
        .filter(|record| record.actor_seq == max_seq && max_seq > 0)
        .map(|record| {
            arkret_core::EventId::new(record.event_id)
                .map_err(|error| AppError::internal(format!("stored Event id invalid: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((max_seq + 1, prev_refs))
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
    if !record.allow_ghost_actors {
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
