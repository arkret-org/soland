use base64::Engine as _;

use super::*;

const CONTACT_MESSAGE_STUB: &str = "[message withheld until contact is accepted]";
const CONTACT_CONSENT_ACTION_SCOPES: &[&str] = &[
    "invite",
    "direct_message",
    "voice_call",
    "video_call",
    "presence",
];
const CONTACT_REQUEST_PENDING_TTL_DAYS: i64 = 14;
const DIRECT_CONVERSATION_PAIRWISE_DID_METHOD_PREFIXES: &[&str] = &["did:peer:", "did:key:"];
const DIRECT_BINDING_PENDING_POLL_ATTEMPTS: usize = 100;
const DIRECT_BINDING_PENDING_POLL_DELAY_MS: u64 = 25;

mod direct;

#[cfg(test)]
use direct::*;
pub(crate) use direct::{
    active_direct_binding, complete_remote_direct_binding_with_realm,
    create_direct_binding_with_realm, direct_authorization_basis_from_contact,
    direct_binding_matches_projection, direct_pair_key, ensure_direct_peer_resolvable,
    pending_direct_materialization, prepare_remote_direct_keypackage_claim,
    project_canonical_direct_binding, retire_direct_bindings_for_operation,
    validate_direct_binding_operation,
};

#[endpoint(
    operation_id = "ak.self.contact.command.request",
    tags("contacts"),
    summary = "Open a pending contact relationship",
    status_codes(200, 201, 400, 401, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.request"))]
pub(crate) async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ContactRequestRequestBody>,
) -> JsonResult<ContactRequestOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.target.as_str() == session.actor {
        return Err(AppError::invalid_param("invalid contact target"));
    }
    let target = body.target.as_str().to_owned();
    // Spec contact-and-direct-conversation.md §4.1 — cross-PS addressing.
    // When `recipient_service_id` names a different Principal Server, the
    // target holder is remote: skip the local-account precondition and
    // federate the signed `ak.contact.requested` fact to the target's home PS.
    let recipient_service_id = body
        .recipient_service_id
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty());
    let is_remote_target = recipient_service_id
        .as_deref()
        .is_some_and(|did| did != state.service_id());
    if !is_remote_target {
        let target_account = state
            .identity_application()
            .find_account_by_actor(soland_application::identity::FindAccountByActorQuery {
                actor_id: target.clone(),
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        if target_account.is_none() {
            return Err(AppError::not_found("not found"));
        }
    }
    // Spec 0015 §3.4 — optional free-text greeting. NFC-normalize and
    // bound to 1..2000 chars before it enters the requested fact/record.
    let message = normalize_contact_message(body.message.as_deref())?;
    let scope = contact_request_scope(&body)?;
    let introduction_evidence = body
        .introduction_evidence
        .clone()
        .unwrap_or(ContactIntroductionEvidence::ExplicitAddress);
    // Spec contact-and-direct-conversation.md §3 — the requester-side
    // contact-managed grant is a real `ak.consent.grant`; its event ref is
    // referenced from the `ak.contact.requested` fact's
    // `requester_consent_refs[]`.
    let requester_previous = consent_cell_snapshot(state, &session.actor, &target, &scope);
    let (requester_consent_ref, requester_consent_cell) =
        grant_contact_managed_consent(state, &session.actor, &target, &scope, now());
    persist_consent_cell(state, &requester_consent_cell, requester_previous).await?;
    let requester_consent_refs = EventId::new(requester_consent_ref)
        .ok()
        .into_iter()
        .collect::<Vec<_>>();
    let contact_status = "pending";
    if !is_remote_target {
        let pending_previous = consent_cell_snapshot(state, &target, &session.actor, &scope);
        let pending = record_pending_request(state, &target, &session.actor, &scope, now());
        persist_consent_cell(state, &pending, pending_previous).await?;
    }
    let stub_message = message.is_some()
        && should_stub_local_contact_message(
            state,
            &session.actor,
            &target,
            contact_status,
            is_remote_target,
        )
        .await?;
    let record_message = if stub_message {
        Some(CONTACT_MESSAGE_STUB.to_owned())
    } else {
        message.clone()
    };
    let contacts = state.contact_application();
    if let Some(mut existing) = contacts
        .contact(&session.actor, &target, &scope)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if existing.status == "rejected" {
            return json_ok(contact_request_outcome(
                &existing,
                &session.actor,
                Vec::new(),
            )?);
        }
        // A re-sent request MAY refresh the greeting; keep the prior one
        // when the new request omits a message.
        let message_changed = existing.status == "pending"
            && record_message.is_some()
            && existing.message != record_message;
        if message_changed {
            if record_message.is_some() {
                existing.message = record_message.clone();
            }
            existing.updated_at = now();
            contacts
                .save_contact(existing.clone())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if stub_message && message_changed {
                append_local_stubbed_contact_message_audit(
                    state,
                    &target,
                    &session.actor,
                    &scope,
                    message.as_deref().unwrap_or_default(),
                    existing.request_event_ref.as_deref().unwrap_or_default(),
                )
                .await;
            }
        }
        return json_ok(contact_request_outcome(
            &existing,
            &session.actor,
            requester_consent_refs,
        )?);
    }
    if contacts
        .contact(&target, &session.actor, &scope)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return Err(AppError::new(
            soland_http::error::ErrorCode::DuplicateConflict,
            "contact relationship already exists",
        ));
    }
    let request_event_ref = synthetic_contact_event_ref();
    let contact = ContactRecord {
        requester: session.actor,
        target,
        scope,
        status: contact_status.to_owned(),
        request_event_ref: Some(request_event_ref.to_string()),
        response_event_ref: None,
        tombstone_event_ref: None,
        message: record_message,
        // Local (same-Principal-Server) request: peer's home server is this
        // service, so there is nothing cross-PS to address.
        peer_service_id: None,
        created_at: now(),
        updated_at: now(),
    };
    let request_fact_payload = json!({
        "request_id": request_event_ref.as_str(),
        "requester": contact.requester.clone(),
        "target": contact.target.clone(),
        "requested_scopes": [contact.scope.clone()],
        "requester_consent_refs": requester_consent_refs.clone(),
        "message": contact.message.clone(),
    });
    append_contact_fact_projection_event(
        state,
        &request_event_ref,
        "ak.contact.requested",
        &contact.requester,
        request_fact_payload.clone(),
        contact.created_at,
    )
    .await;
    append_audit_log(
        state,
        Some(&contact.requester),
        "ak.contact.requested",
        request_fact_payload,
        "accepted",
    )
    .await;
    contacts
        .save_contact(contact.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if stub_message {
        append_local_stubbed_contact_message_audit(
            state,
            &contact.target,
            &contact.requester,
            &contact.scope,
            message.as_deref().unwrap_or_default(),
            request_event_ref.as_str(),
        )
        .await;
    }
    // Spec §4.1 — federate the signed `ak.contact.requested` fact to the
    // target holder's home Principal Server when the target is remote.
    if let Some(recipient_service_id) = recipient_service_id.as_deref()
        && is_remote_target
    {
        let introduction_evidence_digest =
            contact_introduction_evidence_digest(&introduction_evidence)?;
        super::super::contact_federation::federate_contact_fact(
            state,
            "ak.contact.requested",
            &contact.requester,
            &contact.target,
            recipient_service_id,
            Some(introduction_evidence),
            json!({
                "request_id": request_event_ref.as_str(),
                "requester": contact.requester.clone(),
                "target": contact.target.clone(),
                "requested_scopes": [contact.scope.clone()],
                "requester_consent_refs": requester_consent_refs.clone(),
                "message": contact.message.clone(),
                "introduction_evidence_digest": introduction_evidence_digest,
            }),
            request_event_ref.as_str(),
        )
        .await?;
    }
    res.status_code(StatusCode::CREATED);
    json_ok(contact_request_outcome(
        &contact,
        &contact.requester,
        requester_consent_refs,
    )?)
}

/// Spec 0015 §3.4 — normalize a contact-request greeting: trim, NFC, and
/// enforce the 1..2000 char bound. Empty/whitespace-only input is treated
/// as "no message" (`None`).
fn normalize_contact_message(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = arkret_core::canonical::to_nfc(trimmed);
    let len = normalized.chars().count();
    if len > 2000 {
        return Err(AppError::invalid_param(
            "contact request message must be at most 2000 characters",
        ));
    }
    Ok(Some(normalized))
}

async fn should_stub_local_contact_message(
    state: &AppState,
    requester: &str,
    target: &str,
    contact_status: &str,
    is_remote_target: bool,
) -> Result<bool, AppError> {
    if is_remote_target || contact_status != "pending" {
        return Ok(false);
    }
    if actor_has_active_consent_for_peer(state, target, requester) {
        return Ok(false);
    }
    Ok(!has_accepted_contact_for_peer_any_scope(state, target, requester).await?)
}

fn actor_has_active_consent_for_peer(state: &AppState, holder: &str, peer: &str) -> bool {
    CONTACT_CONSENT_ACTION_SCOPES
        .iter()
        .copied()
        .any(|scope| has_active_consent_for_scope(state, holder, peer, scope, now()))
}

async fn has_accepted_contact_for_peer_any_scope(
    state: &AppState,
    actor: &str,
    peer: &str,
) -> Result<bool, AppError> {
    let contacts = state
        .contact_application()
        .contacts_for_actor(actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(contacts.iter().any(|record| {
        record.status == "accepted"
            && ((record.requester == actor && record.target == peer)
                || (record.requester == peer && record.target == actor))
    }))
}

async fn append_local_stubbed_contact_message_audit(
    state: &AppState,
    target: &str,
    requester: &str,
    scope: &str,
    message: &str,
    contact_event_id: &str,
) {
    append_audit_log(
        state,
        Some(target),
        "contacts.message_stubbed",
        json!({
            "requester": requester,
            "target": target,
            "scope": scope,
            "contact_event_id": contact_event_id,
            "message_chars": message.chars().count(),
            "message_digest": arkret_core::canonical::sha256_digest(message.as_bytes()),
        }),
        "accepted",
    )
    .await;
}

fn contact_introduction_evidence_digest(
    evidence: &ContactIntroductionEvidence,
) -> Result<String, AppError> {
    let value = serde_json::to_value(evidence).map_err(|error| {
        AppError::internal(format!("contact introduction evidence serialize: {error}"))
    })?;
    arkret_core::canonical::canonical_sha256(&value).map_err(|error| {
        AppError::internal(format!("contact introduction evidence digest: {error}"))
    })
}

async fn append_contact_fact_projection_event(
    state: &AppState,
    event_ref: &EventId,
    event_kind: &str,
    issuer: &str,
    mut payload: Value,
    created_at: chrono::DateTime<chrono::Utc>,
) {
    if let Value::Object(object) = &mut payload {
        object
            .entry("event_id".to_owned())
            .or_insert_with(|| Value::String(event_ref.to_string()));
    }
    let _ = crate::routing::events::projection::append_projection_event(
        state,
        ProjectionEventRecord {
            event_id: event_ref.to_string(),
            realm_id: soland_application::identity::principal_control_realm_for_did(issuer),
            event_kind: event_kind.to_owned(),
            operation_type: "contact_fact".to_owned(),
            operation_id: None,
            sender: Some(issuer.to_owned()),
            payload,
            created_at,
            received_at: chrono::Utc::now(),
        },
    )
    .await;
}

#[endpoint(
    operation_id = "ak.self.contact.command.respond",
    tags("contacts"),
    summary = "Accept or reject a pending contact request"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.respond"))]
pub(crate) async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRespondRequestBody>,
) -> JsonResult<ContactRespondOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if !matches!(body.action.as_str(), "accept" | "reject") {
        return Err(AppError::invalid_param("action must be accept or reject"));
    }
    let contacts = state.contact_application();
    let Some(mut contact) = contacts
        .contact_any(body.requester.as_str(), &session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::not_found("not found"));
    };
    if contact.status != "pending" {
        let requested_status = if body.action == "accept" {
            "accepted"
        } else {
            "rejected"
        };
        if contact.status == requested_status {
            if contact.response_event_ref.is_none() {
                return Err(contact_failed_precondition(
                    arkret_wire::ErrorCode::CONTACT_REQUEST_NOT_PENDING,
                    "contact request is no longer pending",
                ));
            }
            if requested_status == "rejected" {
                auto_revoke_requester_side_contact_consent(
                    state,
                    &contact.requester,
                    &contact.target,
                    &[contact.scope.clone()],
                    now(),
                    "contact_rejected",
                    contact.response_event_ref.as_deref(),
                )
                .await?;
            }
            return json_ok(contact_respond_outcome(&contact, Vec::new())?);
        }
        return Err(AppError::new(
            soland_http::error::ErrorCode::DuplicateConflict,
            "contact request is no longer pending",
        ));
    }
    let request_event_ref = contact_event_ref(&contact.request_event_ref, "request_event_ref")?;
    if request_event_ref != body.request_id {
        return Err(contact_failed_precondition(
            arkret_wire::ErrorCode::CONTACT_REQUEST_NOT_PENDING,
            "contact request_id does not match the pending request",
        ));
    }
    let observed_at = now();
    if contact_request_is_expired(&contact, observed_at) {
        auto_revoke_requester_side_contact_consent(
            state,
            &contact.requester,
            &contact.target,
            &[contact.scope.clone()],
            observed_at,
            "contact_request_pending_ttl",
            contact.request_event_ref.as_deref(),
        )
        .await?;
        return Err(contact_failed_precondition(
            arkret_wire::ErrorCode::CONTACT_REQUEST_EXPIRED,
            "contact request expired",
        ));
    }
    let mut consent_grant_refs = Vec::new();
    let mut granted_scope_wire = Vec::new();
    let response_event_ref = synthetic_contact_event_ref();
    contact.status = if body.action == "accept" {
        let scopes = contact_respond_scopes(&body, &contact.scope)?;
        for scope in scopes {
            // Spec contact-and-direct-conversation.md §3 — each granted scope
            // writes a target-controlled `ak.consent.grant`; its event ref is
            // referenced from the `ak.contact.accepted` `consent_grant_refs[]`.
            let previous = consent_cell_snapshot(state, &session.actor, &contact.requester, &scope);
            let (grant_ref, grant_cell) = grant_contact_managed_consent(
                state,
                &session.actor,
                &contact.requester,
                &scope,
                now(),
            );
            persist_consent_cell(state, &grant_cell, previous).await?;
            if let Ok(event_ref) = EventId::new(grant_ref) {
                consent_grant_refs.push(event_ref);
            }
            granted_scope_wire.push(contact_scope_wire(&scope));
        }
        "accepted".to_owned()
    } else {
        "rejected".to_owned()
    };
    contact.response_event_ref = Some(response_event_ref.to_string());
    contact.updated_at = now();
    contacts
        .save_contact(contact.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if body.action == "reject" {
        auto_revoke_requester_side_contact_consent(
            state,
            &contact.requester,
            &contact.target,
            &[contact.scope.clone()],
            now(),
            "contact_rejected",
            Some(response_event_ref.as_str()),
        )
        .await?;
    }
    let response_fact_kind = if contact.status == "accepted" {
        "ak.contact.accepted"
    } else {
        "ak.contact.rejected"
    };
    let response_fact_payload = json!({
        "request_id": request_event_ref.as_str(),
        "requester": contact.requester.clone(),
        "target": session.actor.clone(),
        "scope": contact.scope.clone(),
        "granted_scopes": granted_scope_wire.clone(),
        "consent_grant_refs": consent_grant_refs.clone(),
    });
    append_contact_fact_projection_event(
        state,
        &response_event_ref,
        response_fact_kind,
        &session.actor,
        response_fact_payload.clone(),
        contact.updated_at,
    )
    .await;

    // Spec §4.1 — federate the accept / reject fact back to the original
    // requester's home Principal Server when the requester is remote. The
    // requester DID does not embed its home PS, so the responder supplies it
    // via `requester_service_id` (cross-PS addressing).
    if let Some(requester_service_id) = body
        .requester_service_id
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty() && did != state.service_id())
    {
        super::super::contact_federation::federate_contact_fact(
            state,
            response_fact_kind,
            &session.actor,
            &contact.requester,
            &requester_service_id,
            None,
            response_fact_payload,
            response_event_ref.as_str(),
        )
        .await?;
    }
    json_ok(contact_respond_outcome(&contact, consent_grant_refs)?)
}

#[endpoint(
    operation_id = "ak.self.contact.command.tombstone",
    tags("contacts"),
    summary = "Tombstone a contact and revoke contact-managed consent",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.tombstone"))]
pub(crate) async fn contact_tombstone(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactTombstoneRequestBody>,
) -> JsonResult<ContactTombstone> {
    // Spec contact-and-direct-conversation.md §3/§4 — the holder writes a
    // `ak.contact.tombstoned` fact, enumerates and revokes its
    // contact-managed active consent dots toward `peer` (default =
    // every scope, or the explicit `revoke_scopes[]`), and — when
    // `block_peer` — adds the peer DID to the holder's private
    // `invite_receive_policy.blocked_subjects` (hard block).
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let holder = session.actor.clone();
    let peer = body.contact.as_str().to_owned();
    if peer == holder {
        return Err(AppError::invalid_param("invalid contact"));
    }

    let now = now();
    // Revoke contact-managed consent dots holder→peer. `complete=false`
    // means the dot enumeration was partial; we MUST then report a partial
    // tombstone rather than a full one.
    let (revoked_dots, complete, revoked_cells) =
        revoke_contact_managed_consent(state, &holder, &peer, &body.revoke_scopes, now);
    for mutation in &revoked_cells {
        persist_consent_cell(state, &mutation.updated, mutation.previous.clone()).await?;
    }
    if !revoked_cells.is_empty() {
        let invalidation_scope = if body.revoke_scopes.len() == 1 {
            normalize_scope(Some(&body.revoke_scopes[0])).unwrap_or_else(|_| "any".to_owned())
        } else {
            "any".to_owned()
        };
        emit_consent_revoke_invalidation(
            state,
            &holder,
            &peer,
            &invalidation_scope,
            now,
            &revoked_cells,
        )
        .await;
    }

    // Flip every holder↔peer contact row this holder controls to
    // `tombstoned`. The holder's own outgoing rows are the authoritative
    // tombstone target.
    let contacts = state.contact_application();
    let mut tombstoned_any = false;
    let tombstone_event_ref = synthetic_contact_event_ref();
    let mut requester_side_revoke_scopes = Vec::new();
    // Peer's home Principal Server learned from a stored holder↔peer row (set
    // on cross-PS contact deliveries). Used as the federation fallback when the
    // request body omits `peer_service_id`.
    let mut row_peer_service_id: Option<String> = None;
    let rows = contacts
        .contacts_for_actor(&holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    for mut row in rows {
        let touches_peer = (row.requester == holder && row.target == peer)
            || (row.requester == peer && row.target == holder);
        if !touches_peer {
            continue;
        }
        if row_peer_service_id.is_none()
            && let Some(service_id) = row
                .peer_service_id
                .as_ref()
                .map(|did| did.trim().to_owned())
                .filter(|did| !did.is_empty())
        {
            row_peer_service_id = Some(service_id);
        }
        if row.requester == peer
            && row.target == holder
            && !requester_side_revoke_scopes.contains(&row.scope)
        {
            requester_side_revoke_scopes.push(row.scope.clone());
        }
        if row.status == "tombstoned" {
            continue;
        }
        row.status = "tombstoned".to_owned();
        row.tombstone_event_ref = Some(tombstone_event_ref.to_string());
        row.updated_at = now;
        contacts
            .save_contact(row)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        tombstoned_any = true;
    }
    for scope in requester_side_revoke_scopes {
        auto_revoke_requester_side_contact_consent(
            state,
            &peer,
            &holder,
            &[scope],
            now,
            "contact_tombstoned",
            Some(tombstone_event_ref.as_str()),
        )
        .await?;
    }
    if !tombstoned_any && revoked_dots.is_empty() && !body.block_peer {
        return Err(AppError::not_found("not found"));
    }

    if body.block_peer
        && let Some(policy) = blocked_invite_policy_update(state, &holder, &peer)
    {
        state
                .contact_application()
                .save_invite_policy(policy.clone())
                .await
                .map_err(|error| {
                    tracing::error!(%error, holder = %holder, "failed to persist invite_receive_policy block");
                    AppError::internal(format!(
                        "failed to persist invite_receive_policy block: {error}"
                    ))
                })?;
    }

    let tombstone_fact_payload = json!({
        "holder": holder.clone(),
        "peer": peer.clone(),
        "revoke_scopes": body.revoke_scopes.clone(),
        "consent_revoke_refs": revoked_dots.clone(),
        "full_peer_revoke": body.full_peer_revoke,
        "block_peer": body.block_peer,
        "partial_revoke": !complete,
    });
    append_contact_fact_projection_event(
        state,
        &tombstone_event_ref,
        "ak.contact.tombstoned",
        &holder,
        tombstone_fact_payload.clone(),
        now,
    )
    .await;
    append_audit_log(
        state,
        Some(&holder),
        "ak.contact.tombstoned",
        tombstone_fact_payload.clone(),
        "accepted",
    )
    .await;

    // Spec contact-and-direct-conversation.md §2/§4.1 — federate the
    // `ak.contact.tombstoned` fact to the peer's home Principal Server when the
    // peer is remote. The addressing service DID comes from the request body
    // first, then falls back to the `peer_service_id` recorded on the stored
    // holder↔peer contact row. The receiver
    // (`contact_federation::peer_contacts_submit`) downgrades the mirrored row.
    if let Some(peer_service_id) = body
        .peer_service_id
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty())
        .or(row_peer_service_id)
        .filter(|did| did != state.service_id())
    {
        super::super::contact_federation::federate_contact_fact(
            state,
            "ak.contact.tombstoned",
            &holder,
            &peer,
            &peer_service_id,
            None,
            tombstone_fact_payload,
            tombstone_event_ref.as_str(),
        )
        .await?;
    }

    let consent_revoke_refs = revoked_dots
        .iter()
        .filter_map(|dot| EventId::new(format!("ak:event:{}", sha256_hex(dot.as_bytes()))).ok())
        .collect::<Vec<_>>();
    json_ok(ContactTombstone {
        tombstone_event_ref,
        consent_revoke_refs,
        state: ContactState::Tombstoned,
        partial_revoke: (!complete).then_some(true),
    })
}

/// Add `peer` to the holder's private `invite_receive_policy.blocked_subjects`
/// (spec invite-addressing.md §5 / 0015 §3.4). Materializes the holder's
/// recommended default policy first if no override exists yet, so the hard
/// block is the only durable mutation a tombstone needs to make.
/// Returns the mutated policy clone so the async caller can write it through
/// to durable storage before publishing it into the in-memory projection.
/// `None` when the peer DID is malformed or already blocked.
fn blocked_invite_policy_update(
    state: &AppState,
    holder: &str,
    peer: &str,
) -> Option<arkret_core::InviteReceivePolicy> {
    let peer_did = Did::new(peer.to_owned()).ok()?;
    let mut policy = state
        .contact_application()
        .invite_policy(holder)
        .unwrap_or_else(|| crate::routing::invites::default_invite_receive_policy(holder));
    if policy.blocked_subjects.iter().any(|did| did == &peer_did) {
        return None;
    }
    policy.blocked_subjects.push(peer_did);
    Some(policy)
}

#[endpoint(
    operation_id = "ak.self.invite_receive_policy.resource.get",
    tags("contacts"),
    summary = "Get the authenticated subject's invite-receive policy",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.invite_receive_policy.resource.get"))]
pub(crate) async fn get_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — return the subject's private override
    // from the shared in-memory store (the same store
    // `ak.self.contact.command.tombstone(block_peer)` writes `blocked_subjects` to),
    // falling back to the recommended default when none is set.
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy = state
        .contact_application()
        .invite_policy(&session.actor)
        .unwrap_or_else(|| crate::routing::invites::default_invite_receive_policy(&session.actor));
    json_ok(policy)
}

#[endpoint(
    operation_id = "ak.self.invite_receive_policy.resource.replace",
    tags("contacts"),
    summary = "Replace the authenticated subject's invite-receive policy",
    status_codes(200, 400, 401, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.invite_receive_policy.resource.replace")
)]
pub(crate) async fn set_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<InviteReceivePolicy>,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — the subject may only set its own
    // policy: `subject_id` MUST equal the session actor. The override lands
    // in the same store as the tombstone `blocked_subjects` writes, so the
    // two stay consistent.
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy = body.into_inner();
    if policy.subject_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "invite_receive_policy.subject_id must equal the session actor",
        ));
    }
    // Write through to durable storage so the override survives restarts
    // (hydrated back into the in-memory map by `AppState::hydrate`).
    state
        .contact_application()
        .save_invite_policy(policy.clone())
        .await
        .map_err(|error| {
            tracing::error!(%error, actor = %session.actor, "failed to persist invite_receive_policy");
            AppError::internal(format!("failed to persist invite_receive_policy: {error}"))
        })?;
    json_ok(policy)
}

#[endpoint(
    operation_id = "ak.self.contact.query.list",
    tags("contacts"),
    summary = "List contacts visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.query.list"))]
pub(crate) async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .contact_application()
        .contacts_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let records =
        auto_revoke_expired_pending_outgoing_contact_consents(state, &session.actor, records)
            .await?;
    let contacts = contact_list_rows(state, &session.actor, records).await?;
    json_ok(ContactList {
        contacts,
        has_more: false,
        next_cursor: None,
    })
}

async fn auto_revoke_expired_pending_outgoing_contact_consents(
    state: &AppState,
    actor: &str,
    records: Vec<ContactRecord>,
) -> Result<Vec<ContactRecord>, AppError> {
    let observed_at = now();
    for record in &records {
        if record.requester != actor || record.status != "pending" {
            continue;
        }
        if !contact_request_is_expired(record, observed_at) {
            continue;
        }
        auto_revoke_requester_side_contact_consent(
            state,
            actor,
            &record.target,
            std::slice::from_ref(&record.scope),
            observed_at,
            "contact_request_pending_ttl",
            record.request_event_ref.as_deref(),
        )
        .await?;
    }
    Ok(records)
}

fn contact_request_is_expired(
    contact: &ContactRecord,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    contact.created_at + chrono::Duration::days(CONTACT_REQUEST_PENDING_TTL_DAYS) <= observed_at
}

fn contact_request_scope(body: &ContactRequestRequestBody) -> Result<String, AppError> {
    let candidate = body
        .requested_scopes
        .first()
        .map(String::as_str)
        .unwrap_or("direct_message");
    normalize_scope(Some(candidate))
}

fn contact_respond_scopes(
    body: &ContactRespondRequestBody,
    fallback_scope: &str,
) -> Result<Vec<String>, AppError> {
    if body.granted_scopes.is_empty() {
        return Ok(vec![normalize_scope(Some(fallback_scope))?]);
    }
    let mut scopes = Vec::new();
    for scope in &body.granted_scopes {
        let normalized = normalize_scope(Some(scope))?;
        if !scopes.contains(&normalized) {
            scopes.push(normalized);
        }
    }
    Ok(scopes)
}

fn contact_request_outcome(
    contact: &ContactRecord,
    actor: &str,
    requester_consent_refs: Vec<EventId>,
) -> Result<ContactRequestOutcome, AppError> {
    let request_event_ref = contact_event_ref(&contact.request_event_ref, "request_event_ref")?;
    Ok(ContactRequestOutcome {
        request_event_ref,
        requester_consent_refs,
        state: directional_contact_state(actor, contact).ok_or_else(|| {
            AppError::internal(format!(
                "unrecognized stored contact state: {}",
                contact.status
            ))
        })?,
    })
}

fn contact_respond_outcome(
    contact: &ContactRecord,
    consent_grant_refs: Vec<EventId>,
) -> Result<ContactRespondOutcome, AppError> {
    let response_event_ref = contact_event_ref(&contact.response_event_ref, "response_event_ref")?;
    Ok(ContactRespondOutcome {
        response_event_ref,
        consent_grant_refs,
        state: directional_contact_state(&contact.target, contact).ok_or_else(|| {
            AppError::internal(format!(
                "unrecognized stored contact state: {}",
                contact.status
            ))
        })?,
    })
}

fn synthetic_contact_event_ref() -> EventId {
    EventId::new(crate::ids::generate_event_id()).expect("generated contact event id is valid")
}

fn contact_event_ref(value: &Option<String>, field: &str) -> Result<EventId, AppError> {
    value
        .as_deref()
        .ok_or_else(|| AppError::internal(format!("contact projection missing {field}")))
        .and_then(|event_ref| {
            EventId::new(event_ref.to_owned()).map_err(|error| {
                AppError::internal(format!("contact projection invalid {field}: {error}"))
            })
        })
}

fn optional_contact_event_ref(value: &Option<String>) -> Option<EventId> {
    value
        .as_deref()
        .and_then(|event_ref| EventId::new(event_ref.to_owned()).ok())
}

async fn contact_list_rows(
    state: &AppState,
    actor: &str,
    records: Vec<ContactRecord>,
) -> Result<Vec<ContactListRow>, AppError> {
    let mut rows: BTreeMap<String, ContactListRow> = BTreeMap::new();
    let mut records = records;
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.scope.cmp(&right.scope))
    });
    for record in records {
        let peer = if record.requester == actor {
            record.target.clone()
        } else {
            record.requester.clone()
        };
        let row_state = match directional_contact_state(actor, &record) {
            Some(state) => state,
            None => continue,
        };
        let entry = rows.entry(peer.clone()).or_insert_with(|| ContactListRow {
            peer: Did::new(peer.clone()).expect("contact peer DID is validated"),
            state: row_state,
            request_event_ref: None,
            response_event_ref: None,
            tombstone_event_ref: None,
            granted_by_me: Vec::new(),
            granted_to_me: Vec::new(),
            bidirectional_scopes: Vec::new(),
            effective_scopes: Vec::new(),
            invite_consent_grant_ref: None,
            peer_service_id: None,
            direct_conversation: None,
            agents: Vec::new(),
        });
        if contact_state_rank(&row_state) > contact_state_rank(&entry.state) {
            entry.state = row_state;
        }
        if entry.request_event_ref.is_none() {
            entry.request_event_ref = optional_contact_event_ref(&record.request_event_ref);
        }
        if entry.response_event_ref.is_none() {
            entry.response_event_ref = optional_contact_event_ref(&record.response_event_ref);
        }
        if entry.tombstone_event_ref.is_none() {
            entry.tombstone_event_ref = optional_contact_event_ref(&record.tombstone_event_ref);
        }
        // Surface the peer's home Principal Server when learned from a cross-PS
        // delivery (None for same-PS contacts). Multiple scoped records can
        // collapse into one peer row; keep the first known service DID.
        if entry.peer_service_id.is_none() {
            entry.peer_service_id = record
                .peer_service_id
                .as_deref()
                .and_then(|did| Did::new(did.to_owned()).ok());
        }
    }
    let mut out = rows
        .into_values()
        .map(|mut row| {
            row.granted_by_me = active_scopes(state, actor, row.peer.as_str());
            row.granted_to_me = active_scopes(state, row.peer.as_str(), actor);
            row.bidirectional_scopes = intersection(&row.granted_by_me, &row.granted_to_me);
            row.effective_scopes = row.bidirectional_scopes.clone();
            // contact-operations.schema.json — when `peer` (acting as
            // consent-cell holder) gave the authenticated actor an active
            // `invite`/`any` grant, surface that grant's event ref so the
            // actor can invite `peer` into a Realm using `consent_grant`
            // introduction evidence (no locator URL). The cell direction is
            // holder=peer / peer=actor — exactly the cell
            // `has_active_consent_grant_evidence(subject=peer, inviter=actor)`
            // verifies on the receiving (peer's) server, so the ref is
            // self-consistent in both directions.
            row.invite_consent_grant_ref =
                active_invite_consent_grant_ref(state, row.peer.as_str(), actor, now())
                    .and_then(|event_ref| EventId::new(event_ref).ok());
            row.direct_conversation = direct_pair_key(state, actor, row.peer.as_str())
                .ok()
                .and_then(|pair_key| active_direct_binding(state, &pair_key))
                .map(direct_summary);
            row
        })
        .collect::<Vec<_>>();
    let mut agent_peers = BTreeSet::new();
    let mut agents_by_controller = BTreeMap::<String, Vec<ContactAgentProjection>>::new();
    for row in &out {
        let can_receive_direct_messages = row.state == ContactState::Accepted
            && row
                .effective_scopes
                .iter()
                .any(|scope| scope == "direct_message");
        if !can_receive_direct_messages {
            continue;
        }
        let Some(record) = state
            .agent_pairing_application()
            .agent(row.peer.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        else {
            continue;
        };
        if record.state != "active" {
            continue;
        }
        if record.controller_id == actor {
            continue;
        }
        let Some(controller) = Did::new(record.controller_id.clone()).ok() else {
            continue;
        };
        let display_name = record
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let agent_slug = record
            .agent_slug
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let avatar_blob_ref = record
            .avatar_blob_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| BlobRef::new(value.to_owned()).ok());
        agent_peers.insert(row.peer.to_string());
        agents_by_controller
            .entry(controller.to_string())
            .or_default()
            .push(ContactAgentProjection {
                agent_id: row.peer.clone(),
                controller_id: controller,
                display_name,
                agent_slug,
                avatar_blob_ref,
                direct_conversation: row.direct_conversation.clone(),
            });
    }
    out.retain(|row| !agent_peers.contains(row.peer.as_str()));
    for row in &mut out {
        row.agents = agents_by_controller
            .remove(row.peer.as_str())
            .unwrap_or_default();
        row.agents.sort_by(|left, right| {
            left.display_name
                .as_deref()
                .unwrap_or(left.agent_id.as_str())
                .cmp(
                    right
                        .display_name
                        .as_deref()
                        .unwrap_or(right.agent_id.as_str()),
                )
        });
    }
    out.sort_by(|left, right| left.peer.cmp(&right.peer));
    Ok(out)
}

/// Map a stored contact FSM status to its actor-relative [`ContactState`].
///
/// Returns `None` for an unrecognized stored status. `status` is written
/// by the server-side contact FSM (never request-controlled), so an
/// unknown value implies a migration / partial-write / writer bug; read
/// paths fail soft (skip the row) and write outcomes surface an internal
/// error rather than panicking and taking down the whole endpoint.
fn directional_contact_state(actor: &str, record: &ContactRecord) -> Option<ContactState> {
    Some(match record.status.as_str() {
        "pending" if record.requester == actor => ContactState::PendingOutgoing,
        "pending" => ContactState::PendingIncoming,
        "accepted" => ContactState::Accepted,
        "rejected" => ContactState::Rejected,
        "tombstoned" => ContactState::Tombstoned,
        other => {
            tracing::warn!(
                stored_status = %other,
                "skipping contact row with unrecognized stored state"
            );
            return None;
        }
    })
}

fn contact_state_rank(state: &ContactState) -> u8 {
    match state {
        ContactState::Accepted => 5,
        ContactState::PendingIncoming => 4,
        ContactState::PendingOutgoing => 3,
        ContactState::Rejected => 2,
        ContactState::Tombstoned => 1,
    }
}

fn active_scopes(state: &AppState, holder: &str, peer: &str) -> Vec<String> {
    [
        "direct_message",
        "invite",
        "voice_call",
        "video_call",
        "presence",
        "any",
    ]
    .into_iter()
    .filter(|scope| has_active_consent_for_scope(state, holder, peer, scope, now()))
    .map(contact_scope_wire)
    .collect()
}

fn contact_scope_wire(scope: &str) -> String {
    match scope {
        "message" => "direct_message",
        "call" => "voice_call",
        other => other,
    }
    .to_owned()
}

fn intersection(left: &[String], right: &[String]) -> Vec<String> {
    let right = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|scope| right.contains(scope))
        .cloned()
        .collect()
}

pub(crate) async fn accepted_contact_for_pair(
    state: &AppState,
    actor: &str,
    peer: &str,
    scope: &str,
) -> Result<Option<ContactRecord>, AppError> {
    for (requester, target) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = state
            .contact_application()
            .contact(requester, target, scope)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            && contact.status == "accepted"
            && accepted_contact_has_fact_refs(&contact)
        {
            return Ok(Some(contact));
        }
    }
    Ok(None)
}

fn accepted_contact_has_fact_refs(contact: &ContactRecord) -> bool {
    contact
        .request_event_ref
        .as_deref()
        .is_some_and(valid_contact_event_ref)
        && contact
            .response_event_ref
            .as_deref()
            .is_some_and(valid_contact_event_ref)
        && contact.tombstone_event_ref.is_none()
}

fn contact_fact_refs(contact: &ContactRecord) -> Vec<String> {
    [
        contact.request_event_ref.as_ref(),
        contact.response_event_ref.as_ref(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect()
}

fn valid_contact_event_ref(event_ref: &str) -> bool {
    EventId::new(event_ref.to_owned()).is_ok()
}

pub(crate) fn direct_resolve_precondition(reason: &'static str, message: &'static str) -> AppError {
    contact_failed_precondition(reason, message)
}

fn contact_failed_precondition(reason: &'static str, message: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

fn direct_summary(binding: DirectConversationBindingRecord) -> DirectConversationSummary {
    DirectConversationSummary {
        realm_id: RealmId::new(binding.realm_id).expect("direct conversation realm id is valid"),
        main_strand_id: StrandId::new(binding.main_strand_id)
            .expect("direct conversation strand id is valid"),
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref).expect("direct conversation event id is valid"),
        ),
        state: direct_conversation_binding_state(&binding.state),
    }
}

fn direct_conversation_binding_state(state: &str) -> DirectConversationBindingState {
    match state {
        "active" => DirectConversationBindingState::Active,
        "retired" => DirectConversationBindingState::Retired,
        "duplicate" => DirectConversationBindingState::Duplicate,
        "non_canonical" => DirectConversationBindingState::NonCanonical,
        other => panic!("invalid stored direct conversation binding state: {other}"),
    }
}

pub(crate) fn direct_resolve_response(
    binding: DirectConversationBindingRecord,
    created: bool,
    state: DirectConversationResolveState,
    materialization_draft: Option<arkret_core::DirectConversationMaterializationDraft>,
) -> DirectConversationResolveOutcome {
    DirectConversationResolveOutcome {
        state,
        realm_id: Some(
            RealmId::new(binding.realm_id).expect("direct conversation realm id is valid"),
        ),
        main_strand_id: Some(
            StrandId::new(binding.main_strand_id).expect("direct conversation strand id is valid"),
        ),
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref).expect("direct conversation event id is valid"),
        ),
        created: Some(created),
        authoring_kind: (state == DirectConversationResolveState::AuthoringRequired).then_some(
            arkret_core::DirectConversationAuthoringKind::DirectConversationMaterialization,
        ),
        claim_authorization_draft: None,
        materialization_draft,
    }
}

#[cfg(test)]
mod tests;
