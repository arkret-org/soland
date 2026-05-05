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
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids, kinds,
    state::{AppState, MessageRecord},
    wire::{
        RedactMessageRequest, RedactMessageResponse, ReviseMessageRequest, ReviseMessageResponse,
        SendMessageRequest, SendMessageResponse, sync_token,
    },
};

use super::{
    DevProofVerifier, ProofVerifier, append_audit_log, append_projection_event, auth_or_render,
    dev_proof, is_device_revoked, next_author_seq, now, project_accepted_operations,
    projection_event_from_operation, render_error, space_allows_plaintext_service, space_has_member,
    validate_canonical_json_value, validate_content_blocks, validate_encrypted_payload_envelope,
    validate_mentions, validate_space_id,
};

#[handler]
pub async fn send_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<SendMessageRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid send message request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "sender is not a joined member of the space",
        );
        return;
    }
    if !body.content.is_object() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "content must be a JSON object",
        );
        return;
    }
    if body.encrypted && is_device_revoked(state, &session.actor, &session.device_id) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "device revoked",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&body.content) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.encrypted && !space_allows_plaintext_service(state, &body.space_id) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "policy_denied",
            "private plaintext messages require this service in plaintext_visible_services",
        );
        return;
    }
    if body.encrypted
        && let Err(message) = validate_encrypted_payload_envelope(&body.content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.encrypted
        && let Err(message) = validate_content_blocks(&body.content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.encrypted
        && let Err(message) = validate_mentions(&body.content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
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
    let operation_digest = match operation.operation_digest() {
        Ok(digest) => match Hash::new(digest) {
            Ok(digest) => digest,
            Err(error) => {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "repo_error",
                    &error.to_string(),
                );
                return;
            }
        },
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).expect("generated valid commit id"),
        session.actor.clone(),
        Did::new(session.actor.clone()).expect("session actor is valid"),
        next_author_seq(state, &session.actor),
    );
    commit.prev_commit = match state.repo.head(&session.actor) {
        Ok(Some(head)) => match Hash::new(head) {
            Ok(head) => Some(head),
            Err(error) => {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "repo_error",
                    &error.to_string(),
                );
                return;
            }
        },
        Ok(None) => None,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    commit.operations.push(operation_digest);
    commit.proofs.push(dev_proof(&session.actor));

    let projection_event = projection_event_from_operation(&operation, Some(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    let head_commit = match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &ProofVerifier::for_state(state),
    ) {
        Ok(head_commit) => head_commit,
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
            return;
        }
    };
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
    res.render(Json(SendMessageResponse {
        event_id,
        operation_id,
        commit_id,
        head_commit,
        sync_token: sync_token(),
    }));
}

#[handler]
pub async fn revise_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<ReviseMessageRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid revise request",
            );
            return;
        }
    };
    let Some(original) = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .find(|m| m.event_id == body.event_id)
        .cloned()
    else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "original message not found",
        );
        return;
    };
    if original.sender != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the sender can revise a message",
        );
        return;
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
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
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
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
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
            res.render(Json(ReviseMessageResponse {
                event_id: new_event_id,
                revision_of: body.event_id,
                operation_id,
                commit_id,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn redact_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<RedactMessageRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid redact request",
            );
            return;
        }
    };
    let found = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .any(|m| m.event_id == body.event_id);
    if !found {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "message not found");
        return;
    }
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "target_event_id": body.event_id
    });
    let space_id = state
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .find(|m| m.event_id == body.event_id)
        .map(|m| m.space_id.clone())
        .unwrap_or_default();
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(space_id.clone()).unwrap(),
        kinds::CX_MESSAGE_REDACT,
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
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
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(RedactMessageResponse {
                redacted: true,
                event_id: body.event_id,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}
