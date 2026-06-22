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

#[endpoint(
    operation_id = "ck.self.contact.command.request",
    tags("contacts"),
    summary = "Open a pending contact relationship",
    status_codes(200, 201, 400, 401, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.command.request"))]
pub(crate) async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ContactRequestRequestBody>,
) -> JsonResult<ContactRequestOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.target.as_str() == session.actor {
        return Err(AppError::invalid_param("invalid contact target"));
    }
    let target = body.target.as_str().to_owned();
    // Spec contact-and-direct-conversation.md §4.1 — cross-PS addressing.
    // When `recipient_service_did` names a different Principal Server, the
    // target holder is remote: skip the local-account precondition and
    // federate the signed `ck.contact.requested` fact to the target's home PS.
    let recipient_service_did = body
        .recipient_service_did
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty());
    let is_remote_target = recipient_service_did
        .as_deref()
        .is_some_and(|did| did != state.config.service_did);
    if !is_remote_target {
        let target_account = state
            .persistence
            .accounts()
            .get(&target)
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
    // contact-managed grant is a real `ck.consent.grant`; its event ref is
    // referenced from the `ck.contact.requested` fact's
    // `requester_consent_refs[]`.
    let requester_previous = consent_cell_snapshot(state, &session.actor, &target, &scope);
    let (requester_consent_ref, requester_consent_cell) =
        grant_contact_managed_consent(state, &session.actor, &target, &scope, now());
    persist_consent_cell(state, &requester_consent_cell, requester_previous).await?;
    let requester_consent_refs = EventId::new(requester_consent_ref)
        .ok()
        .into_iter()
        .collect::<Vec<_>>();
    let contact_status = if is_remote_target {
        // Remote target: the requester only forms `pending_outgoing` locally.
        // `pending_incoming` (and any accept) is projected on the target's PS
        // once the federated fact lands there.
        "pending"
    } else if has_active_consent_for_scope(state, &target, &session.actor, &scope, now()) {
        "accepted"
    } else {
        let pending_previous = consent_cell_snapshot(state, &target, &session.actor, &scope);
        let pending = record_pending_request(state, &target, &session.actor, &scope, now());
        persist_consent_cell(state, &pending, pending_previous).await?;
        "pending"
    };
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
    let store = state.persistence.contacts();
    if let Some(mut existing) = store
        .get_scoped(&session.actor, &target, &scope)
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
        let status_changed = existing.status != contact_status;
        // A re-sent request MAY refresh the greeting; keep the prior one
        // when the new request omits a message.
        let message_changed = record_message.is_some() && existing.message != record_message;
        if status_changed || message_changed {
            existing.status = contact_status.to_owned();
            if record_message.is_some() {
                existing.message = record_message.clone();
            }
            existing.updated_at = now();
            store
                .put(&existing)
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
    if store
        .get_scoped(&target, &session.actor, &scope)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
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
        peer_service_did: None,
        created_at: now(),
        updated_at: now(),
    };
    append_audit_log(
        state,
        Some(&contact.requester),
        "ck.contact.requested",
        json!({
            "requester": contact.requester,
            "target": contact.target,
            "requested_scopes": [contact.scope.clone()],
            "message": contact.message,
        }),
        "accepted",
    )
    .await;
    store
        .put(&contact)
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
    // Spec §4.1 — federate the signed `ck.contact.requested` fact to the
    // target holder's home Principal Server when the target is remote.
    if let Some(recipient_service_did) = recipient_service_did.as_deref()
        && is_remote_target
    {
        let introduction_evidence_digest =
            contact_introduction_evidence_digest(&introduction_evidence)?;
        super::super::contact_federation::federate_contact_fact(
            state,
            "ck.contact.requested",
            &contact.requester,
            &contact.target,
            recipient_service_did,
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
    let normalized = cokret_sdk::canonical::to_nfc(trimmed);
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
        .persistence
        .contacts()
        .list_for_actor(actor)
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
            "message_digest": cokret_sdk::canonical::sha256_digest(message.as_bytes()),
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
    cokret_sdk::canonical::canonical_sha256(&value).map_err(|error| {
        AppError::internal(format!("contact introduction evidence digest: {error}"))
    })
}

#[endpoint(
    operation_id = "ck.self.contact.command.respond",
    tags("contacts"),
    summary = "Accept or reject a pending contact request"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.command.respond"))]
pub(crate) async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRespondRequestBody>,
) -> JsonResult<ContactRespondOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if !matches!(body.action.as_str(), "accept" | "reject") {
        return Err(AppError::invalid_param("action must be accept or reject"));
    }
    let store = state.persistence.contacts();
    let Some(mut contact) = store
        .get(body.requester.as_str(), &session.actor)
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
                    cokret_sdk::ERROR_CODE_CONTACT_REQUEST_NOT_PENDING,
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
            crate::error::ErrorCode::DuplicateConflict,
            "contact request is no longer pending",
        ));
    }
    let request_event_ref = contact_event_ref(&contact.request_event_ref, "request_event_ref")?;
    if request_event_ref != body.request_id {
        return Err(contact_failed_precondition(
            cokret_sdk::ERROR_CODE_CONTACT_REQUEST_NOT_PENDING,
            "contact request_id does not match the pending request",
        ));
    }
    let mut consent_grant_refs = Vec::new();
    let mut granted_scope_wire = Vec::new();
    let response_event_ref = synthetic_contact_event_ref();
    contact.status = if body.action == "accept" {
        let scopes = contact_respond_scopes(&body, &contact.scope)?;
        for scope in scopes {
            // Spec contact-and-direct-conversation.md §3 — each granted scope
            // writes a target-controlled `ck.consent.grant`; its event ref is
            // referenced from the `ck.contact.accepted` `consent_grant_refs[]`.
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
    store
        .put(&contact)
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

    // Spec §4.1 — federate the accept / reject fact back to the original
    // requester's home Principal Server when the requester is remote. The
    // requester DID does not embed its home PS, so the responder supplies it
    // via `requester_service_did` (cross-PS addressing).
    if let Some(requester_service_did) = body
        .requester_service_did
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty() && did != &state.config.service_did)
    {
        let fact_kind = if contact.status == "accepted" {
            "ck.contact.accepted"
        } else {
            "ck.contact.rejected"
        };
        super::super::contact_federation::federate_contact_fact(
            state,
            fact_kind,
            &session.actor,
            &contact.requester,
            &requester_service_did,
            None,
            json!({
                "request_id": request_event_ref.as_str(),
                "requester": contact.requester.clone(),
                "target": session.actor.clone(),
                "scope": contact.scope.clone(),
                "granted_scopes": granted_scope_wire,
                "consent_grant_refs": consent_grant_refs.clone(),
            }),
            response_event_ref.as_str(),
        )
        .await?;
    }
    json_ok(contact_respond_outcome(&contact, consent_grant_refs)?)
}

#[endpoint(
    operation_id = "ck.self.contact.command.tombstone",
    tags("contacts"),
    summary = "Tombstone a contact and revoke contact-managed consent",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.command.tombstone"))]
pub(crate) async fn contact_tombstone(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactTombstoneRequestBody>,
) -> JsonResult<ContactTombstone> {
    // Spec contact-and-direct-conversation.md §3/§4 — the holder writes a
    // `ck.contact.tombstoned` fact, enumerates and revokes its
    // contact-managed active consent dots toward `peer` (default =
    // every scope, or the explicit `revoke_scopes[]`), and — when
    // `block_peer` — adds the peer DID to the holder's private
    // `invite_receive_policy.blocked_subjects` (hard block).
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let store = state.persistence.contacts();
    let mut tombstoned_any = false;
    let tombstone_event_ref = synthetic_contact_event_ref();
    let mut requester_side_revoke_scopes = Vec::new();
    // Peer's home Principal Server learned from a stored holder↔peer row (set
    // on cross-PS contact deliveries). Used as the federation fallback when the
    // request body omits `peer_service_did`.
    let mut row_peer_service_did: Option<String> = None;
    let rows = store
        .list_for_actor(&holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    for mut row in rows {
        let touches_peer = (row.requester == holder && row.target == peer)
            || (row.requester == peer && row.target == holder);
        if !touches_peer {
            continue;
        }
        if row_peer_service_did.is_none() {
            if let Some(service_did) = row
                .peer_service_did
                .as_ref()
                .map(|did| did.trim().to_owned())
                .filter(|did| !did.is_empty())
            {
                row_peer_service_did = Some(service_did);
            }
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
        store
            .put(&row)
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

    if body.block_peer {
        if let Some(policy) = blocked_invite_policy_update(state, &holder, &peer) {
            state
                .persistence
                .invite_receive_policies()
                .put(&policy)
                .await
                .map_err(|error| {
                    tracing::error!(%error, holder = %holder, "failed to persist invite_receive_policy block");
                    AppError::internal(format!(
                        "failed to persist invite_receive_policy block: {error}"
                    ))
                })?;
            state
                .invite_receive_policies
                .lock()
                .expect("invite_receive_policies lock")
                .insert(holder.clone(), policy);
        }
    }

    append_audit_log(
        state,
        Some(&holder),
        "ck.contact.tombstoned",
        json!({
            "holder": holder,
            "peer": peer,
            "revoke_scopes": body.revoke_scopes,
            "consent_revoke_refs": revoked_dots,
            "full_peer_revoke": body.full_peer_revoke,
            "block_peer": body.block_peer,
            "partial_revoke": !complete,
        }),
        "accepted",
    )
    .await;

    // Spec contact-and-direct-conversation.md §2/§4.1 — federate the
    // `ck.contact.tombstoned` fact to the peer's home Principal Server when the
    // peer is remote. The addressing service DID comes from the request body
    // first, then falls back to the `peer_service_did` recorded on the stored
    // holder↔peer contact row. The receiver
    // (`contact_federation::peer_contacts_submit`) downgrades the mirrored row.
    if let Some(peer_service_did) = body
        .peer_service_did
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty())
        .or(row_peer_service_did)
        .filter(|did| did != &state.config.service_did)
    {
        super::super::contact_federation::federate_contact_fact(
            state,
            "ck.contact.tombstoned",
            &holder,
            &peer,
            &peer_service_did,
            None,
            json!({
                "holder": holder,
                "peer": peer,
                "revoke_scopes": body.revoke_scopes,
                "full_peer_revoke": body.full_peer_revoke,
                "block_peer": body.block_peer,
            }),
            tombstone_event_ref.as_str(),
        )
        .await?;
    }

    let consent_revoke_refs = revoked_dots
        .iter()
        .filter_map(|dot| EventId::new(format!("ck:event:{}", sha256_hex(dot.as_bytes()))).ok())
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
) -> Option<cokret_sdk::InviteReceivePolicy> {
    let peer_did = Did::new(peer.to_owned()).ok()?;
    let policies = state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock");
    let mut policy = policies
        .get(holder)
        .cloned()
        .unwrap_or_else(|| crate::routing::invites::default_invite_receive_policy(holder));
    if policy.blocked_subjects.iter().any(|did| did == &peer_did) {
        return None;
    }
    policy.blocked_subjects.push(peer_did);
    Some(policy)
}

#[endpoint(
    operation_id = "ck.self.invite_receive_policy.resource.get",
    tags("contacts"),
    summary = "Get the authenticated subject's invite-receive policy",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.invite_receive_policy.resource.get"))]
pub(crate) async fn get_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — return the subject's private override
    // from the shared in-memory store (the same store
    // `ck.self.contact.command.tombstone(block_peer)` writes `blocked_subjects` to),
    // falling back to the recommended default when none is set.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy = state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock")
        .get(&session.actor)
        .cloned()
        .unwrap_or_else(|| crate::routing::invites::default_invite_receive_policy(&session.actor));
    json_ok(policy)
}

#[endpoint(
    operation_id = "ck.self.invite_receive_policy.resource.replace",
    tags("contacts"),
    summary = "Replace the authenticated subject's invite-receive policy",
    status_codes(200, 400, 401, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.self.invite_receive_policy.resource.replace")
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
        .persistence
        .invite_receive_policies()
        .put(&policy)
        .await
        .map_err(|error| {
            tracing::error!(%error, actor = %session.actor, "failed to persist invite_receive_policy");
            AppError::internal(format!("failed to persist invite_receive_policy: {error}"))
        })?;
    state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock")
        .insert(session.actor.clone(), policy.clone());
    json_ok(policy)
}

#[endpoint(
    operation_id = "ck.self.contact.query.list",
    tags("contacts"),
    summary = "List contacts visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.query.list"))]
pub(crate) async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .persistence
        .contacts()
        .list_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let records =
        auto_revoke_expired_pending_outgoing_contact_consents(state, &session.actor, records)
            .await?;
    let contacts = contact_list_rows(state, &session.actor, records);
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
        if record.created_at + chrono::Duration::days(CONTACT_REQUEST_PENDING_TTL_DAYS)
            > observed_at
        {
            continue;
        }
        auto_revoke_requester_side_contact_consent(
            state,
            actor,
            &record.target,
            &[record.scope.clone()],
            observed_at,
            "contact_request_pending_ttl",
            record.request_event_ref.as_deref(),
        )
        .await?;
    }
    Ok(records)
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
        state: directional_contact_state(actor, contact),
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
        state: directional_contact_state(&contact.target, contact),
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

fn contact_list_rows(
    state: &AppState,
    actor: &str,
    records: Vec<ContactRecord>,
) -> Vec<ContactListRow> {
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
        let row_state = directional_contact_state(actor, &record);
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
            peer_service_did: None,
            direct_conversation: None,
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
        if entry.peer_service_did.is_none() {
            entry.peer_service_did = record
                .peer_service_did
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
            row.direct_conversation =
                active_direct_binding(state, &direct_pair_key(actor, row.peer.as_str()))
                    .map(direct_summary);
            row
        })
        .collect::<Vec<_>>();
    out.sort_by(|left, right| left.peer.cmp(&right.peer));
    out
}

fn directional_contact_state(actor: &str, record: &ContactRecord) -> ContactState {
    match record.status.as_str() {
        "pending" if record.requester == actor => ContactState::PendingOutgoing,
        "pending" => ContactState::PendingIncoming,
        "accepted" => ContactState::Accepted,
        "rejected" => ContactState::Rejected,
        "tombstoned" => ContactState::Tombstoned,
        other => panic!("invalid stored contact state: {other}"),
    }
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
    let store = state.persistence.contacts();
    for (requester, target) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = store
            .get_scoped(requester, target, scope)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            && contact.status == "accepted"
        {
            return Ok(Some(contact));
        }
    }
    Ok(None)
}

pub(crate) fn direct_resolve_precondition(reason: &'static str, message: &'static str) -> AppError {
    contact_failed_precondition(reason, message)
}

fn contact_failed_precondition(reason: &'static str, message: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

pub(crate) fn direct_pair_key(left: &str, right: &str) -> String {
    let mut participants = [left.to_owned(), right.to_owned()];
    participants.sort();
    participants.join("\0")
}

pub(crate) fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    state
        .direct_conversation_bindings
        .lock()
        .expect("direct_conversation_bindings lock")
        .get(pair_key)
        .filter(|binding| binding.state == "active")
        .cloned()
}

/// Spec contact-and-direct-conversation.md §6 step5 / §7 / §8 — resolve(create=true)
/// stands up a *real event-log* DM Realm: it submits `ck.realm.create`
/// (DM well-known shape), both participants' `ck.member.state{join}`, and
/// the main `ck.strand.create`, then writes the direct conversation binding
/// fact. The realm becomes a true event Realm both sides can submit
/// `ck.message.create` into (accepted, peer-readable) — not just a
/// directory entry. Reuses soland's existing local operation acceptance +
/// projection path (`accept_local_operations`); it does NOT build a parallel
/// realm-materialization path.
pub(crate) async fn create_direct_binding_with_realm(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    peer: &str,
) -> Result<(DirectConversationBindingRecord, bool), AppError> {
    // Reserve the canonical binding under lock so concurrent resolves for the
    // same pair collapse onto a single realm. The reservation holds the
    // generated realm/strand ids; we release the lock before the (async) event
    // submission so projection writes don't deadlock against the guard.
    let (realm_id, main_strand_id, binding_event_ref, reserved) = {
        let mut guard = state
            .direct_conversation_bindings
            .lock()
            .expect("direct_conversation_bindings lock");
        if let Some(existing) = guard
            .get(pair_key)
            .filter(|binding| binding.state == "active")
        {
            return Ok((existing.clone(), false));
        }
        let realm_id = crate::ids::generate_realm_id();
        let main_strand_id = crate::ids::generate("strand");
        let binding_event_ref = crate::ids::generate_event_id();
        let binding = DirectConversationBindingRecord {
            participants_unordered: sorted_participants(actor, peer),
            realm_id: realm_id.clone(),
            main_strand_id: main_strand_id.clone(),
            binding_event_ref: binding_event_ref.clone(),
            state: "active".to_owned(),
            created_at: now(),
            updated_at: now(),
        };
        guard.insert(pair_key.to_owned(), binding.clone());
        (realm_id, main_strand_id, binding_event_ref, binding)
    };

    // Submit the genesis events that turn the reserved ids into a real
    // event-log Realm. The realm creator (`actor`) bootstraps the Realm +
    // its own membership in one event; the peer is added with an explicit
    // join; the main Strand is created last. If any step is rejected we must
    // not leave a dangling "active" binding pointing at an orphan realm, so
    // we roll back the reservation and surface the failure.
    if let Err(error) =
        submit_direct_realm_genesis(state, &realm_id, &main_strand_id, actor, peer).await
    {
        let removed = {
            let mut guard = state
                .direct_conversation_bindings
                .lock()
                .expect("direct_conversation_bindings lock");
            let removed = guard
                .get(pair_key)
                .is_some_and(|binding| binding.binding_event_ref == reserved.binding_event_ref);
            if removed {
                guard.remove(pair_key);
            }
            removed
        };
        // Mirror the in-memory rollback into durable storage so a restart
        // mid-failure doesn't resurrect a binding pointing at an orphan realm.
        if removed
            && let Err(error) = state
                .persistence
                .direct_conversation_bindings()
                .delete(pair_key)
                .await
        {
            tracing::warn!(%error, pair_key, "failed to delete rolled-back direct binding");
        }
        return Err(AppError::internal(format!(
            "direct conversation realm genesis failed: {error}"
        )));
    }

    // Genesis succeeded — write the binding through to durable storage so the
    // canonical pair → (realm_id, main_strand_id) projection survives restart.
    if let Err(error) = state
        .persistence
        .direct_conversation_bindings()
        .put(pair_key, &reserved)
        .await
    {
        let removed = {
            let mut guard = state
                .direct_conversation_bindings
                .lock()
                .expect("direct_conversation_bindings lock");
            let removed = guard
                .get(pair_key)
                .is_some_and(|binding| binding.binding_event_ref == reserved.binding_event_ref);
            if removed {
                guard.remove(pair_key);
            }
            removed
        };
        tracing::error!(
            %error,
            pair_key,
            removed,
            "failed to persist direct binding to durable storage"
        );
        return Err(AppError::internal(format!(
            "failed to persist direct binding: {error}"
        )));
    }

    // Binding fact (spec §6) — the canonical pair → (realm_id, main_strand_id)
    // signed fact / projection. Recorded after the realm + membership + main
    // Strand are all live so it only ever references a verifiable realm.
    append_audit_log(
        state,
        Some(actor),
        "ck.direct_conversation.bound",
        json!({
            "participants_unordered": reserved.participants_unordered,
            "realm_id": realm_id,
            "main_strand_id": main_strand_id,
            "binding_event_ref": binding_event_ref,
            "created_at": reserved.created_at.to_rfc3339(),
        }),
        "accepted",
    )
    .await;

    Ok((reserved, true))
}

fn sorted_participants(actor: &str, peer: &str) -> Vec<String> {
    let mut participants = vec![actor.to_owned(), peer.to_owned()];
    participants.sort();
    participants
}

/// Build + accept the DM Realm genesis operations through the canonical
/// local-operation path. Order matters: realm.create (creator becomes the
/// first member), peer member.state{join}, then the main strand.create.
async fn submit_direct_realm_genesis(
    state: &AppState,
    realm_id: &str,
    main_strand_id: &str,
    actor: &str,
    peer: &str,
) -> Result<(), &'static str> {
    let realm_scope = cokret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|_| "generated invalid direct conversation realm id")?;

    // ck.realm.create — DM Realm well-known shape (spec §7): mls_rfc9420
    // encryption profile, fail-closed join rule, direct-conversation
    // discriminator in `fields`. The creator is treated as a member by the
    // genesis bootstrap.
    let realm_op = direct_realm_create_operation(state, realm_scope.clone(), realm_id, actor)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&realm_op)).await?;

    // ck.member.state{join} — add the peer so both participants are active
    // members (active member count == 2, spec §7).
    let member_op = direct_member_join_operation(realm_scope.clone(), peer)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&member_op)).await?;

    // ck.strand.create — main discussion Strand (spec §8): discussion track is
    // primary; no Circle scope.
    let strand_op = direct_strand_create_operation(realm_scope, main_strand_id)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&strand_op)).await?;

    Ok(())
}

fn direct_operation_id() -> Result<cokret_sdk::OperationId, &'static str> {
    cokret_sdk::OperationId::new(crate::ids::generate_operation_id())
        .map_err(|_| "generated invalid operation id")
}

fn direct_realm_create_operation(
    state: &AppState,
    realm_scope: cokret_sdk::RealmId,
    realm_id: &str,
    creator: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "ck.schema.realm.v1",
            "title": "Direct conversation",
            "trust_domain": "ck:trust_domain:soland.local",
            "created_by": creator,
            "schema_refs": ["ck.schema.realm.v1"],
            "default_discoverability": "invite",
            // DM Realms are fail-closed: third-party invite / member_add MUST
            // be refused (spec §7).
            "default_join_rule": "closed",
            // Both participants share the full 1:1 history (the canonical DM
            // is a symmetric two-party conversation, not a join-gated room):
            // `shared` lets each active member read every message the other
            // sent, which is what a direct conversation means. spec §7 leaves
            // history_visibility to the DM profile; it only pins the
            // encryption profile / join rule / member-count invariants.
            "history_visibility": "shared",
            // DM Realms use the MLS RFC 9420 profile (spec §7).
            "encryption_profile": "mls_rfc9420",
            "security_class": "standard",
            "federation_policy": "restricted",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
                "type": "single_did",
                "did": creator,
            },
            // Registered direct-conversation discriminator (spec §7) — NOT
            // `fields.purpose`, which Principal Control Realm semantics own.
            "fields": {
                "conversation_kind": "direct_message",
            },
            "created_at": now().to_rfc3339_opts(SecondsFormat::Secs, true),
        },
        // The hosting Principal Server must be able to route plaintext
        // direct-message content for its own members (spec §7 minimal
        // `is_direct_message` projection without decrypting user content).
        // Both participants live on this PS, so it is the sole entry. This is
        // read at the payload root by `ensure_projected_realm` (the local
        // operation acceptance path), mirroring the realm.create wire shape
        // soland's submit bootstrap also accepts at the root.
        "plaintext_visible_services": [state.config.service_did.clone()],
    });
    Ok(cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        crate::kinds::CK_REALM_CREATE,
        payload,
    ))
}

fn direct_member_join_operation(
    realm_scope: cokret_sdk::RealmId,
    member: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let payload = json!({
        "actor_id": member,
        "membership": "join",
    });
    Ok(cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        crate::kinds::CK_MEMBER_STATE,
        payload,
    ))
}

fn direct_strand_create_operation(
    realm_scope: cokret_sdk::RealmId,
    main_strand_id: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let payload = json!({
        "object": {
            "id": main_strand_id,
            "kind": "discussion",
            "title": "Direct conversation",
        }
    });
    Ok(cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        crate::kinds::CK_STRAND_CREATE,
        payload,
    ))
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
    }
}
