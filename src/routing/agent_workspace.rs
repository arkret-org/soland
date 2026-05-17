//! `cx.profile.agent_workspace.v1` HTTP service operations.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §11`
//! OpenAPI: `contrix-spec/spec/v1/artifacts/openapi/contrix-service-api.openapi.yaml`
//!
//! Two endpoints:
//!
//! - `GET /api/v1/agent_workspace/mirror_flow?source_flow_id=...`
//!   → controller-only resolve. Returns mapping only when reservation +
//!     create both completed. Unauthenticated MUST return 401/403, not 404
//!     (workspace existence is not enumerable).
//!
//! - `GET /api/v1/agent_workspace/pending_tasks`
//!   → controller-only list of in-flight agent_task objects awaiting
//!     reconcile (execution_state ∈ {pending_source_stub, active}).
//!
//! **Stub note** (2026-05-17 AW-2 round): this module wires the HTTP
//! surface + OpenAPI schemas so yougen can develop against soland. The
//! underlying mirror Space resolution + agent_task pending-list query are
//! placeholders; full reducer integration is tracked in
//! `contrix-spec/_todos.md` AW-2.2 / AW-2.4.

use salvo::http::StatusCode;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

/// Mount agent_workspace routes under `/api/v1/agent_workspace`.
pub fn router() -> Router {
    Router::new()
        .push(Router::with_path("agent_workspace/mirror_flow").get(resolve_mirror_flow))
        .push(Router::with_path("agent_workspace/pending_tasks").get(list_pending_tasks))
}

// ── Request / response shapes ──────────────────────────────────────────

/// Response payload for `GET /api/v1/agent_workspace/mirror_flow` on 200.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ResolveMirrorFlowResponse {
    pub mirror_flow_id: String,
    pub mirror_space_id: String,
}

/// Response payload for `GET /api/v1/agent_workspace/pending_tasks`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PendingTasksResponse {
    pub tasks: Vec<PendingTaskSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PendingTaskSummary {
    pub agent_task_id: String,
    pub execution_state: String,
    pub transparency: Option<String>,
    pub source_authority: Option<String>,
    /// Mirror Flow ID hosting the task.
    pub mirror_flow_id: String,
    /// Optional source Flow ID if context_anchor is set.
    pub source_flow_id: Option<String>,
}

// ── Handlers ───────────────────────────────────────────────────────────

/// `GET /api/v1/agent_workspace/mirror_flow?source_flow_id=...`
///
/// Privacy invariant: unauthenticated / non-owner MUST receive 401/403
/// (NOT 404). 404 is reserved for the authenticated workspace owner with
/// `not_provisioned` reason.
#[endpoint(
    operation_id = "cx.agent_workspace.resolve_mirror_flow",
    tags("agent_workspace"),
    summary = "Resolve mirror Flow ID for a given source Flow"
)]
async fn resolve_mirror_flow(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    source_flow_id: QueryParam<String, true>,
) -> JsonResult<ResolveMirrorFlowResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let _src = source_flow_id.into_inner();

    // Stub: full reducer integration pending (AW-2.2 / AW-2.4).
    // Returning 404 not_provisioned for the authenticated owner is the
    // correct privacy-preserving default until real provisioning lands.
    Err(AppError::new(ErrorCode::NotFound, "not_provisioned").with_status(StatusCode::NOT_FOUND))
}

/// `GET /api/v1/agent_workspace/pending_tasks`
///
/// Controller-only list. Returns agent_task objects whose execution_state
/// is `pending_source_stub` or `active` for client reconcile after offline.
#[endpoint(
    operation_id = "cx.agent_workspace.list_pending_tasks",
    tags("agent_workspace"),
    summary = "List in-flight agent_task objects awaiting client reconcile"
)]
async fn list_pending_tasks(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PendingTasksResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;

    // Stub: empty list. Real implementation queries the projection view
    // for cx.schema.agent_task.v1 objects whose execution_state cell head
    // is in {pending_source_stub, active}.
    json_ok(PendingTasksResponse { tasks: Vec::new() })
}
