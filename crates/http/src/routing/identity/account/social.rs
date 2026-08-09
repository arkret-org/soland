use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use salvo::oapi::endpoint;

use super::*;

const DIRECT_CONVERSATION_PAIRWISE_DID_METHOD_PREFIXES: &[&str] = &["did:peer:", "did:key:"];

pub(crate) mod direct;

pub(crate) use direct::{
    active_direct_binding, direct_binding_conflict, direct_binding_matches_projection,
    direct_pair_key, project_canonical_direct_binding, validate_direct_binding_operation,
};

mod contact_write;

pub(crate) use contact_write::{
    canonical_contact_digest, validate_request_receipt_cryptography,
    verify_contact_service_signature, verify_contact_service_signature_bytes,
};

#[endpoint(
    operation_id = "ak.self.contact.command.request",
    summary = "Prepare or commit a holder-signed Contact request",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.request"))]
pub(crate) async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactOperationRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    contact_write::request(state, &session, body.into_inner()).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.respond",
    summary = "Prepare or commit a normal Contact acceptance",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.respond"))]
pub(crate) async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactAcceptRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    contact_write::respond(state, &session, body.into_inner()).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.reject",
    summary = "Prepare or commit a terminal Contact request rejection",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.reject"))]
pub(crate) async fn contact_reject(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRejectRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    contact_write::reject(state, &session, body.into_inner()).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.scope_update",
    summary = "Prepare or commit a directional Contact scope replacement",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.scope_update"))]
pub(crate) async fn contact_scope_update(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactScopeUpdateRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    contact_write::scope_update(state, &session, body.into_inner()).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.tombstone",
    summary = "Prepare or commit a terminal Contact tombstone",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.tombstone"))]
pub(crate) async fn contact_tombstone(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactTombstoneRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    contact_write::tombstone(state, &session, body.into_inner()).await
}
#[endpoint(
    operation_id = "ak.self.invite_receive_policy.resource.get",
    summary = "Get the invite receive policy",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.invite_receive_policy.resource.get"))]
pub(crate) async fn get_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — return the subject's private override,
    // falling back to the recommended default when none is set. Contact
    // tombstones and invite receive policy are independent state machines.
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = Did::new(session.actor.clone())
        .map_err(|error| AppError::invalid_param(format!("invalid session principal: {error}")))?;
    let policy = state
        .contacts()
        .invite_policy(&session.actor)
        .unwrap_or_else(|| InviteReceivePolicy::spec_default(actor_id));
    json_ok(policy)
}

#[endpoint(
    operation_id = "ak.self.invite_receive_policy.resource.replace",
    summary = "Replace the invite receive policy",
    tags("contacts")
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
    // policy: `subject_id` MUST equal the session actor.
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
        .contacts()
        .save_invite_policy(policy.clone())
        .await
        .map_err(|error| {
            tracing::error!(%error, actor = %session.actor, "failed to persist invite_receive_policy");
            AppError::internal(format!("failed to persist invite_receive_policy: {error}"))
        })?;
    json_ok(policy)
}

#[endpoint(
    operation_id = "ak.self.contact.read.list",
    summary = "List contacts",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.read.list"))]
pub(crate) async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .contacts()
        .contacts_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let contacts = contact_list_rows(state, &session.actor, records).await?;
    json_ok(ContactList {
        contacts,
        has_more: false,
        next_cursor: None,
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
            .then_with(|| left.basis_id.cmp(&right.basis_id))
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
        let peer_model = if let Some(agent) = state
            .agent_pairings()
            .agent(&peer)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            ContactPeer::Agent {
                agent_id: Did::new(peer.clone()).expect("contact peer DID is validated"),
                controller_id: Did::new(agent.controller_id)
                    .expect("stored Agent controller DID is validated"),
            }
        } else {
            ContactPeer::Human {
                principal_id: Did::new(peer.clone()).expect("contact peer DID is validated"),
            }
        };
        let entry = rows.entry(peer.clone()).or_insert_with(|| ContactListRow {
            peer: peer_model,
            state: row_state,
            request_event_ref: None,
            response_event_ref: None,
            tombstone_event_ref: None,
            granted_to_peer_scopes: Vec::new(),
            granted_by_peer_scopes: Vec::new(),
            bidirectional_scopes: Vec::new(),
            effective_scopes: None,
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
        if record.requester == actor {
            entry.granted_to_peer_scopes = record
                .granted_to_target_scopes
                .iter()
                .filter_map(|scope| contact_scope_model(scope))
                .collect();
            entry.granted_by_peer_scopes = record
                .granted_to_requester_scopes
                .iter()
                .filter_map(|scope| contact_scope_model(scope))
                .collect();
        } else {
            entry.granted_to_peer_scopes = record
                .granted_to_requester_scopes
                .iter()
                .filter_map(|scope| contact_scope_model(scope))
                .collect();
            entry.granted_by_peer_scopes = record
                .granted_to_target_scopes
                .iter()
                .filter_map(|scope| contact_scope_model(scope))
                .collect();
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
            row.bidirectional_scopes =
                intersection(&row.granted_to_peer_scopes, &row.granted_by_peer_scopes);
            row.effective_scopes = Some(row.bidirectional_scopes.clone());
            row.direct_conversation = direct_pair_key(state, actor, row.peer.subject_id().as_str())
                .ok()
                .and_then(|pair_key| {
                    // §5.7 — a pair holding two distinct endorsements is frozen,
                    // and neither side may be presented as the conversation.
                    if direct_binding_conflict(state, &pair_key) {
                        return state
                            .contacts()
                            .direct_bindings_for_pair(&pair_key)
                            .and_then(|bindings| bindings.any_endorsed())
                            .map(|binding| {
                                direct_summary(binding, DirectConversationSummaryState::Suspended)
                            });
                    }
                    active_direct_binding(state, &pair_key).map(|binding| {
                        direct_summary(binding, DirectConversationSummaryState::Found)
                    })
                });
            row
        })
        .collect::<Vec<_>>();
    let mut agent_peers = BTreeSet::new();
    let mut agents_by_controller = BTreeMap::<String, Vec<ContactAgentProjection>>::new();
    for row in &out {
        let can_receive_direct_messages = row.state == ContactState::Accepted
            && row.effective_scopes.as_ref().is_some_and(|scopes| {
                scopes.contains(
                    &arkret_models_collaboration::contact_operations::ContactScope::DirectMessage,
                )
            });
        if !can_receive_direct_messages {
            continue;
        }
        let Some(record) = state
            .agent_pairings()
            .agent(row.peer.subject_id().as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        else {
            continue;
        };
        if record.state != AgentLifecycleState::Active {
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
        agent_peers.insert(row.peer.subject_id().to_string());
        agents_by_controller
            .entry(controller.to_string())
            .or_default()
            .push(ContactAgentProjection {
                agent_id: row.peer.subject_id().clone(),
                controller_id: controller,
                display_name,
                agent_slug,
                avatar_blob_ref,
                direct_conversation: row.direct_conversation.clone(),
            });
    }
    out.retain(|row| !agent_peers.contains(row.peer.subject_id().as_str()));
    for row in &mut out {
        row.agents = agents_by_controller
            .remove(row.peer.subject_id().as_str())
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
    out.sort_by(|left, right| left.peer.subject_id().cmp(right.peer.subject_id()));
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
        ContactState::Expired => 2,
        ContactState::Tombstoned => 1,
    }
}

fn contact_scope_wire(scope: &str) -> String {
    scope.to_owned()
}

fn contact_scope_model(
    scope: &str,
) -> Option<arkret_models_collaboration::contact_operations::ContactScope> {
    serde_json::from_value(Value::String(scope.to_owned())).ok()
}

fn intersection(
    left: &[arkret_models_collaboration::contact_operations::ContactScope],
    right: &[arkret_models_collaboration::contact_operations::ContactScope],
) -> Vec<arkret_models_collaboration::contact_operations::ContactScope> {
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
            .contacts()
            .contact_any(requester, target)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            && contact.status == "accepted"
            && contact_has_scope_for_both(&contact, scope)
            && accepted_contact_has_fact_refs(&contact)
        {
            return Ok(Some(contact));
        }
    }
    Ok(None)
}

fn contact_has_scope_for_both(contact: &ContactRecord, scope: &str) -> bool {
    let scope = contact_scope_wire(scope);
    contact
        .granted_to_target_scopes
        .iter()
        .any(|candidate| contact_scope_wire(candidate) == scope)
        && contact
            .granted_to_requester_scopes
            .iter()
            .any(|candidate| contact_scope_wire(candidate) == scope)
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

fn direct_summary(
    binding: DirectConversationBindingRecord,
    state: DirectConversationSummaryState,
) -> DirectConversationSummary {
    DirectConversationSummary {
        realm_id: RealmId::new(binding.realm_id).expect("direct conversation realm id is valid"),
        main_strand_id: StrandId::new(binding.main_strand_id)
            .expect("direct conversation strand id is valid"),
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref).expect("direct conversation event id is valid"),
        ),
        state,
    }
}
