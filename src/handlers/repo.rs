//! Repo (per-actor commit log) HTTP surface.
//!
//! Surfaces:
//! - `GET  /api/v1/repo/describe`        — repo head + supported signature suites
//! - `GET  /api/v1/repo/commits`         — paginated commit list
//! - `GET  /api/v1/repo/commit`          — single commit with optional operation expansion
//! - `POST /api/v1/repo/operations`      — fetch operations by id
//! - `POST /api/v1/repo/sync`            — pull operations since a cursor
//! - `POST /api/v1/repo/submit-commit`   — append a signed commit (CAS via `expected_head`)
//!
//! The repo HTTP layer is intentionally thin — it delegates to `state.repo`
//! (the local Diesel-backed adapter in `src/repo.rs`). Operation-level
//! validation (`validate_operation_semantics`, `validate_operation_policy`)
//! still lives in `mod.rs` because it is also called from the federation
//! ingest path; if/when those validators move, this module will pull them in
//! via `super::`.

use contrix_sdk::CommitId;
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::AppState,
    wire::{
        GetOperationsRequest, GetOperationsResponse, ListCommitsResponse, RepoDescribeResponse,
        RepoSyncRequest, RepoSyncResponse, SubmitCommitRequest, SubmitCommitResponse, sync_token,
    },
};

use super::{
    ProofVerifier, append_audit_log, operation_kind_records, project_accepted_operations,
    query_flag, query_param, render_error, validate_operation_policy, validate_operation_semantics,
};

#[handler]
pub async fn repo_describe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let repo_id = query_param(req, "repo_id").unwrap_or_else(|| state.config.service_did.clone());
    let head_commit = match state.repo.head(&repo_id) {
        Ok(head) => head,
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
    res.render(Json(RepoDescribeResponse {
        repo_did: repo_id,
        head_commit,
        supported_signatures: vec![
            "detached_jws".to_owned(),
            "http_message_signature".to_owned(),
        ],
        limits: json!({"max_commits": 100, "max_operations": 500}),
    }));
}

#[handler]
pub async fn list_commits(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let repo_id = query_param(req, "repo_id").unwrap_or_else(|| state.config.service_did.clone());
    match state
        .repo
        .list_commits(&repo_id, query_param(req, "cursor").as_deref(), limit)
    {
        Ok(page) => res.render(Json(ListCommitsResponse {
            commits: page.items,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
        })),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn get_commit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(commit_id) = query_param(req, "commit_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "commit_id is required",
        );
        return;
    };
    let Ok(commit_id) = CommitId::new(commit_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid commit_id",
        );
        return;
    };
    match state.repo.get_commit(&commit_id) {
        Ok(Some(commit)) => {
            let include_operations =
                query_flag(req, "include_operations") || query_flag(req, "expand_operations");
            let operations = if include_operations {
                match state.repo.get_operations_by_digests(
                    &commit
                        .operations
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                ) {
                    Ok(operations) => operations,
                    Err(error) => {
                        render_error(
                            res,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "repo_error",
                            &error.to_string(),
                        );
                        return;
                    }
                }
            } else {
                Vec::new()
            };
            let proofs = commit.proofs.clone();
            res.render(Json(
                json!({"commit": commit, "operations": operations, "proofs": proofs}),
            ))
        }
        Ok(None) => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn get_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<GetOperationsRequest>()
        .await
        .unwrap_or(GetOperationsRequest {
            operation_ids: Vec::new(),
            include_payload: true,
        });
    match state.repo.get_operations(&body.operation_ids, 500) {
        Ok((operations, missing)) => res.render(Json(GetOperationsResponse {
            operations,
            missing,
            unauthorized: Vec::new(),
        })),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn repo_sync(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<RepoSyncRequest>()
        .await
        .unwrap_or(RepoSyncRequest {
            repo_id: state.config.service_did.clone(),
            since: None,
            limit: Some(100),
            filters: None,
        });
    let limit = body.limit.unwrap_or(100).min(500);
    match state
        .repo
        .sync_operations(&body.repo_id, body.since.as_deref(), limit)
    {
        Ok(page) => res.render(Json(RepoSyncResponse {
            operations: page.items,
            next_cursor: page.next_cursor.or_else(|| Some(sync_token())),
            has_more: page.has_more,
        })),
        Err(error) => render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "repo_error",
            &error.to_string(),
        ),
    }
}

#[handler]
pub async fn submit_commit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<SubmitCommitRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid submit commit request",
            );
            return;
        }
    };

    let commit_id = body.commit.commit_id.to_string();
    let commit_already_exists = state
        .repo
        .get_commit(&body.commit.commit_id)
        .is_ok_and(|commit| commit.is_some());
    if let Err(message) = validate_operation_semantics(state, &body.operations) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !commit_already_exists
        && let Err(message) = validate_operation_policy(state, &body.operations)
    {
        append_audit_log(
            state,
            Some(&body.repo_id),
            "repo.submit_commit",
            json!({
                "commit_id": commit_id.clone(),
                "operation_kinds": operation_kind_records(&body.operations),
                "reason": "policy_denied",
                "message": message,
            }),
            "policy_denied",
        );
        render_error(res, StatusCode::FORBIDDEN, "policy_denied", message);
        return;
    }

    let operations_for_projection = body.operations.clone();
    let repo_id = body.repo_id.clone();
    match state.repo.submit_commit(
        &body.repo_id,
        body.expected_head.as_deref(),
        body.operations,
        body.commit,
        &ProofVerifier::for_state(state),
    ) {
        Ok(head_commit) => {
            project_accepted_operations(state, &repo_id, &operations_for_projection);
            append_audit_log(
                state,
                Some(&repo_id),
                "repo.submit_commit",
                json!({
                    "commit_id": commit_id.clone(),
                    "operation_kinds": operation_kind_records(&operations_for_projection),
                }),
                "accepted",
            );
            res.render(Json(SubmitCommitResponse {
                status: "accepted".to_owned(),
                commit_id,
                head_commit,
                sync_token: sync_token(),
            }));
        }
        Err(error) => {
            let message = error.to_string();
            let code = if message.contains("expected_head mismatch") {
                "cas_conflict"
            } else if message.contains("operation idempotency conflict")
                || message.contains("conflicting bytes for idempotent object cx:operation:")
            {
                "quarantine"
            } else {
                "duplicate_conflict"
            };
            append_audit_log(
                state,
                Some(&repo_id),
                "repo.submit_commit",
                json!({
                    "commit_id": commit_id,
                    "operation_kinds": operation_kind_records(&operations_for_projection),
                    "conflict": code,
                }),
                code,
            );
            render_error(res, StatusCode::CONFLICT, code, &message);
        }
    }
}
