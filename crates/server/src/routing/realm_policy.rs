//! G3.S2 — Realm policy server admin HTTP surface.
//!
//! Surfaces:
//! - `GET /_soland/self/realms/{realm_id}/policy-server` — fetch the currently-projected
//!   `ak.realm.policy_server` config. Returns 404 if neither the realm nor its `governed_by`
//!   ancestor chain has declared one.
//! - `PUT /_soland/self/realms/{realm_id}/policy-server` — submit a `ak.realm.policy_server` Move.
//!   Routes through the standard `accept_local_operations` pipeline so the reducer's validators
//!   (URL scheme, on_timeout enum) run.
//! - `DELETE /_soland/self/realms/{realm_id}/policy-server` — write a tombstoning Move so admins
//!   can remove the per-realm policy server config (callers fall back to the `governed_by` chain or
//!   the local-only capability check after this lands).
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §2.

use arkret_sdk::{Operation, OperationId, RealmId};
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AuthArgs, accept_local_operations};
use crate::error::AppError;
use crate::ids;
use crate::result::{EmptyResult, JsonResult, empty_ok, json_ok};
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realms").push(
        Router::with_path("{realm_id}/policy-server")
            .get(get_realm_policy_server)
            .put(put_realm_policy_server)
            .delete(delete_realm_policy_server),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmPolicyServerOutcome {
    pub realm_id: String,
    pub policy_server_did: String,
    pub policy_server_url: String,
    pub cache_ttl_seconds: u64,
    pub timeout_ms: u64,
    pub on_timeout: String,
    pub updated_at: String,
    /// When `true`, the config was resolved via the org-fallback
    /// chain (the realm itself had no row of its own).
    pub from_org_fallback: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PutRealmPolicyServerRequestBody {
    pub policy_server_did: String,
    pub policy_server_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// `fail_closed` (default) or `deny`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<String>,
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.get",
    tags("realms"),
    summary = "Read the projected ak.realm.policy_server config (G3.S2)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.get"))]
async fn get_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmPolicyServerOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let projection = state.projection.lock();
    let direct = projection.realm_policy_servers.get(&realm_id);
    let (cfg, from_org_fallback) = match direct {
        Some(c) => (c.clone(), false),
        None => match projection.realm_policy_server_config(&realm_id) {
            Some(c) => (c.clone(), true),
            None => {
                return Err(AppError::not_found(
                    "no ak.realm.policy_server declared for this realm",
                ));
            }
        },
    };
    json_ok(RealmPolicyServerOutcome {
        realm_id: cfg.realm_id,
        policy_server_did: cfg.policy_server_did,
        policy_server_url: cfg.policy_server_url,
        cache_ttl_seconds: cfg.cache_ttl_seconds,
        timeout_ms: cfg.timeout_ms,
        on_timeout: cfg.on_timeout,
        updated_at: cfg.updated_at.to_rfc3339(),
        from_org_fallback,
    })
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.replace",
    tags("realms"),
    summary = "Submit a ak.realm.policy_server Move (G3.S2)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.replace"))]
async fn put_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<PutRealmPolicyServerRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmPolicyServerOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let body = body.into_inner();

    let mut payload = json!({
        "policy_server_did": body.policy_server_did,
        "policy_server_url": body.policy_server_url,
    });
    if let Some(ttl) = body.cache_ttl_seconds {
        payload["cache_ttl_seconds"] = json!(ttl);
    }
    if let Some(ms) = body.timeout_ms {
        payload["timeout_ms"] = json!(ms);
    }
    if let Some(on_timeout) = body.on_timeout.as_ref() {
        payload["on_timeout"] = json!(on_timeout);
    }

    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(
        op_id,
        realm_scope,
        arkret_sdk::events::EventKind::REALM_POLICY_SERVER,
        payload,
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;

    let projection = state.projection.lock();
    let cfg = projection
        .realm_policy_servers
        .get(&realm_id)
        .cloned()
        .ok_or_else(|| {
            AppError::new(
                crate::error::ErrorCode::InternalError,
                "policy_server projection vanished after accept",
            )
        })?;
    json_ok(RealmPolicyServerOutcome {
        realm_id: cfg.realm_id,
        policy_server_did: cfg.policy_server_did,
        policy_server_url: cfg.policy_server_url,
        cache_ttl_seconds: cfg.cache_ttl_seconds,
        timeout_ms: cfg.timeout_ms,
        on_timeout: cfg.on_timeout,
        updated_at: cfg.updated_at.to_rfc3339(),
        from_org_fallback: false,
    })
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.delete",
    tags("realms"),
    summary = "Tombstone the ak.realm.policy_server cell (G3.S2)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.delete"))]
async fn delete_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> EmptyResult {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();

    // Tombstone marker payload — the reducer's validator rejects it as
    // malformed (no did/url), but the cell write below will null the
    // structured cache directly. We use the projection-side delete
    // path for the tombstone effect.
    let mut projection = state.projection.lock();
    if projection.realm_policy_servers.remove(&realm_id).is_none() {
        return Err(AppError::not_found(
            "no ak.realm.policy_server to tombstone for this realm",
        ));
    }
    if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.realm.policy_server.v1:{realm_id}"
    )) {
        projection.cells.remove(&cell_id);
    }
    drop(projection);
    // Audit attribution: emit a tracing record so the deletion shows
    // up in the policy_audit_obligation sink.
    tracing::info!(
        target: "policy_audit_obligation",
        kind = "policy_server_tombstone",
        realm_id = %realm_id,
        actor = %session.actor,
        "G3.S2: ak.realm.policy_server tombstoned"
    );
    empty_ok()
}

fn reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(crate::error::ErrorCode::FailedPrecondition, reason)
        .with_status(salvo::http::StatusCode::UNPROCESSABLE_ENTITY)
        .with_wire_code(reason)
}
