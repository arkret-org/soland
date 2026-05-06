//! Message create / revise / redact handlers.
//!
//! Surfaces:
//! - `POST /api/v1/messages/send`   — create a message + commit
//! - `POST /api/v1/messages/revise` — append a revision pointing back to the
//!   original event
//! - `POST /api/v1/messages/redact` — emit a redaction event tombstoning the
//!   target. Spec B-09 (`actor_seq` preservation in stripped stubs) is tracked
//!   in `_todos.md` Stream-A19.
//!
//! All three commit through `state.repo` and re-project via
//! `project_accepted_operations` (which lives in `mod.rs` because it is the
//! shared write-fan-out). Plaintext-vs-encrypted policy is enforced via
//! `space_allows_plaintext_service` + the encrypted-envelope validators.

use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    ids, json_ok, kinds,
    state::{AppState, MessageRecord},
    wire::{
        RedactMessageRequest, RedactMessageResponse, ReviseMessageRequest, ReviseMessageResponse,
        SendMessageRequest, SendMessageResponse, sync_token,
    },
};

use super::{
    AuthArgs, DevProofVerifier, ProofVerifier, append_audit_log, append_projection_event,
    dev_proof, is_device_revoked, next_author_seq, now, project_accepted_operations,
    projection_event_from_operation, space_allows_plaintext_service, space_has_member,
    validate_canonical_json_value, validate_content_blocks, validate_encrypted_payload_envelope,
    validate_mentions, validate_space_id,
};

#[endpoint(
    operation_id = "cx.messages.send",
    tags("messages"),
    summary = "Send a message into a Space",
    status_codes(201, 400, 401, 403, 409, 500),
)]
pub async fn send_message(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<SendMessageRequest>,
) -> JsonResult<SendMessageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if validate_space_id(&body.space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "sender is not a joined member of the space",
        ));
    }
    if !body.content.is_object() {
        return Err(AppError::invalid_param("content must be a JSON object"));
    }
    if body.encrypted && is_device_revoked(state, &session.actor, &session.device_id) {
        return Err(AppError::unauthenticated("device revoked"));
    }
    if let Err(message) = validate_canonical_json_value(&body.content) {
        return Err(AppError::invalid_param(message));
    }
    if !body.encrypted && !space_allows_plaintext_service(state, &body.space_id) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "private plaintext messages require this service in plaintext_visible_services",
        ));
    }
    if body.encrypted
        && let Err(message) = validate_encrypted_payload_envelope(&body.content)
    {
        return Err(AppError::invalid_param(message));
    }
    if !body.encrypted
        && let Err(message) = validate_content_blocks(&body.content)
    {
        return Err(AppError::invalid_param(message));
    }
    if !body.encrypted
        && let Err(message) = validate_mentions(&body.content)
    {
        return Err(AppError::invalid_param(message));
    }

    let event_id = ids::generate_event_id();
    let thread_id = body.thread_id.unwrap_or_else(|| body.space_id.clone());
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "event_id": event_id,
        "sender": session.actor.clone(),
        "thread_id": thread_id.clone(),
        "content": body.content,
        "encrypted": body.encrypted,
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).expect("generated valid operation id"),
        SpaceId::new(body.space_id.clone()).expect("validated space id"),
        kinds::CX_MESSAGE_CREATE,
        payload.clone(),
    );
    let operation_digest = operation
        .operation_digest()
        .map_err(|error| AppError::internal(error.to_string()))
        .and_then(|digest| Hash::new(digest).map_err(|error| AppError::internal(error.to_string())))?;
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).expect("generated valid commit id"),
        session.actor.clone(),
        Did::new(session.actor.clone()).expect("session actor is valid"),
        next_author_seq(state, &session.actor),
    );
    commit.prev_commit = match state
        .repo
        .head(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(head) => Some(Hash::new(head).map_err(|error| AppError::internal(error.to_string()))?),
        None => None,
    };
    commit.operations.push(operation_digest);
    commit.proofs.push(dev_proof(&session.actor));

    let projection_event = projection_event_from_operation(&operation, Some(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    let head_commit = state
        .repo
        .submit_commit(
            &session.actor,
            expected_head.as_deref(),
            vec![operation.clone()],
            commit,
            &ProofVerifier::for_state(state),
        )
        .map_err(|error| {
            AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
        })?;
    if let Ok(mut proj) = state.projection.lock() {
        proj.apply(&operation, &state.hlc);
    }
    append_projection_event(state, projection_event);

    let audit_actor = session.actor.clone();
    let audit_space_id = body.space_id.clone();
    state
        .messages
        .lock()
        .expect("messages lock")
        .push(MessageRecord {
            event_id: event_id.clone(),
            space_id: body.space_id,
            sender: session.actor,
            thread_id,
            content: payload["content"].clone(),
            encrypted: body.encrypted,
            created_at: now(),
        });
    append_audit_log(
        state,
        Some(&audit_actor),
        "message.send",
        json!({
            "space_id": audit_space_id,
            "operation_id": operation_id.clone(),
            "commit_id": commit_id.clone(),
            "event_id": event_id.clone()
        }),
        "accepted",
    );

    res.status_code(StatusCode::CREATED);
    json_ok(SendMessageResponse {
        event_id,
        operation_id,
        commit_id,
        head_commit,
        sync_token: sync_token(),
    })
}

#[endpoint(
    operation_id = "cx.messages.revise",
    tags("messages"),
    summary = "Append a revision pointing back to the original event",
)]
pub async fn revise_message(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ReviseMessageRequest>,
) -> JsonResult<ReviseMessageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let original = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .find(|m| m.event_id == body.event_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("original message not found"))?;
    if original.sender != session.actor {
        return Err(AppError::capability_denied(
            "only the sender can revise a message",
        ));
    }
    let new_event_id = ids::generate_event_id();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "target_event_id": body.event_id,
        "new_event_id": new_event_id,
        "sender": session.actor,
        "content": body.content,
        "thread_id": original.thread_id,
        "encrypted": original.encrypted
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(original.space_id.clone()).unwrap(),
        kinds::CX_MESSAGE_REVISE,
        payload,
    );
    let operation_digest = operation
        .operation_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = state.repo.head(&session.actor).ok().flatten();
    if let Some(head) = expected_head.as_ref()
        && let Ok(head) = Hash::new(head.clone())
    {
        commit.prev_commit = Some(head);
    }
    state
        .repo
        .submit_commit(
            &session.actor,
            expected_head.as_deref(),
            vec![operation.clone()],
            commit,
            &DevProofVerifier,
        )
        .map_err(|error| {
            AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
        })?;
    project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
    {
        let mut messages = state.messages.lock().expect("messages lock");
        messages.push(MessageRecord {
            event_id: new_event_id.clone(),
            space_id: original.space_id.clone(),
            sender: session.actor.clone(),
            thread_id: original.thread_id.clone(),
            content: body.content,
            encrypted: original.encrypted,
            created_at: now(),
        });
    }
    json_ok(ReviseMessageResponse {
        event_id: new_event_id,
        revision_of: body.event_id,
        operation_id,
        commit_id,
    })
}

#[endpoint(
    operation_id = "cx.messages.redact",
    tags("messages"),
    summary = "Emit a redaction event tombstoning the target message",
)]
pub async fn redact_message(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RedactMessageRequest>,
) -> JsonResult<RedactMessageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let space_id = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .find(|m| m.event_id == body.event_id)
        .map(|m| m.space_id.clone())
        .ok_or_else(|| AppError::not_found("message not found"))?;
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "target_event_id": body.event_id
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(space_id.clone()).unwrap(),
        kinds::CX_MESSAGE_REDACT,
        payload,
    );
    let operation_digest = operation
        .operation_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = state.repo.head(&session.actor).ok().flatten();
    if let Some(head) = expected_head.as_ref()
        && let Ok(head) = Hash::new(head.clone())
    {
        commit.prev_commit = Some(head);
    }
    state
        .repo
        .submit_commit(
            &session.actor,
            expected_head.as_deref(),
            vec![operation.clone()],
            commit,
            &DevProofVerifier,
        )
        .map_err(|error| {
            AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
        })?;
    project_accepted_operations(state, &session.actor, &[operation]);
    let _ = space_id;
    json_ok(RedactMessageResponse {
        redacted: true,
        event_id: body.event_id,
    })
}
