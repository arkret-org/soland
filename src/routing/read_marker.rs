//! Read marker + read receipt handlers.
//!
//! Surfaces:
//! - `POST /api/v1/read-markers` — set the actor's read marker (durable
//!   persistent state per-actor; spec discovery/read-receipts.md §6).
//! - `GET  /api/v1/read-markers` — list the actor's read markers,
//!   optionally filtered by `?space_id=...`.
//! - `POST /api/v1/receipts/read` — ephemeral `cx.receipt.read` fanout
//!   request (spec discovery/read-receipts.md §2.4-2.5). The handler
//!   applies the effective Space `read_receipt_policy`:
//!   - `disclosure="disabled"` → drop with HTTP 403 + `policy_violation`
//!     (`retry_after_ms=null`; retry will not change the outcome).
//!   - `visibility="private"` → fanout only to the original sender of
//!     `event_id`; non-sender callers see `fanout="private"`.
//!   - `disclosure="required"` / `visibility="public"|"members"` →
//!     normal fanout (`fanout="members"`).

use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    ids, json_ok, kinds,
    state::AppState,
    wire::{
        ReadMarkerResponse, SendReadReceiptRequest, SendReadReceiptResponse, SetReadMarkerRequest,
    },
};

use super::{
    AuthArgs, DevProofVerifier, dev_proof, next_author_seq, now, project_accepted_operations,
};

#[endpoint(
    operation_id = "cx.read_markers.set",
    tags("read_markers"),
    summary = "Set the authenticated actor's read marker for a Space",
)]
pub async fn set_read_marker(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SetReadMarkerRequest>,
) -> JsonResult<ReadMarkerResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let scope_id = body
        .scope_id
        .clone()
        .unwrap_or_else(|| "_default".to_owned());
    let payload = json!({
        "event_id": body.event_id,
        "sender": session.actor,
        "scope_id": scope_id
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(body.space_id.clone()).unwrap(),
        kinds::CX_READ_MARKER,
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
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
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
    json_ok(ReadMarkerResponse {
        space_id: body.space_id,
        actor: session.actor.clone(),
        scope_id,
        event_id: body.event_id,
        read_at: now().to_rfc3339(),
    })
}

#[endpoint(
    operation_id = "cx.read_markers.list",
    tags("read_markers"),
    summary = "List the authenticated actor's read markers, optionally filtered by space",
)]
pub async fn get_read_markers(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: QueryParam<String, false>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let space_id = space_id.unwrap_or_default();
    let markers = {
        let proj = state.projection.lock().expect("projection lock");
        proj.read_markers
            .values()
            .filter(|m| m.actor == session.actor && (space_id.is_empty() || m.space_id == space_id))
            .map(|m| ReadMarkerResponse {
                space_id: m.space_id.clone(),
                actor: m.actor.clone(),
                scope_id: m.scope_id.clone(),
                event_id: m.event_id.clone(),
                read_at: m.read_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    json_ok(json!({ "markers": markers }))
}

/// C14 / read-receipts §2.4-2.5: ephemeral `cx.receipt.read` fanout
/// endpoint. Applies the effective Space `read_receipt_policy` before
/// fanout — `disclosure="disabled"` returns 403 `policy_violation`;
/// `visibility="private"` returns `fanout="private"` so the client knows
/// only the sender of the referenced event will see the receipt.
#[endpoint(
    operation_id = "cx.receipt.read",
    tags("receipts"),
    summary = "Send an ephemeral read receipt for an event in a Space",
)]
pub async fn send_read_receipt(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SendReadReceiptRequest>,
) -> JsonResult<SendReadReceiptResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();

    // Look up effective Space policy. If no policy event has been written,
    // treat as `Optional` / `Members` / `scope_overrides_allowed=true` per
    // spec default.
    let (disclosure, visibility, _scope_overrides_allowed) =
        super::effective_read_receipt_policy_for_space(state, &body.space_id)
            .unwrap_or_else(|| ("optional".to_owned(), "members".to_owned(), true));

    if disclosure == "disabled" {
        // Spec read-receipts §2.5: hard refusal. retry_after_ms=null because
        // retry will not change the outcome.
        return Err(AppError::new(
            ErrorCode::PolicyViolation,
            format!(
                "Space '{}' read_receipt_policy.disclosure=disabled; cx.receipt.read dropped",
                body.space_id
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    // Determine fanout scope. `private` means we only echo to the sender of
    // the referenced event_id; for now we surface the policy outcome and
    // let the client/server decide on the actual broadcast list.
    let fanout = if visibility == "private" {
        "private".to_owned()
    } else {
        // public / members both broadcast to space members; track + flow_id
        // scoping is informational — the projection layer decides who
        // actually receives the event.
        if body.flow_id.is_some() || body.track.is_some() {
            "track_scoped".to_owned()
        } else {
            "members".to_owned()
        }
    };

    json_ok(SendReadReceiptResponse {
        space_id: body.space_id,
        actor: session.actor.clone(),
        event_id: body.event_id,
        fanout,
        received_at: now().to_rfc3339(),
    })
}
