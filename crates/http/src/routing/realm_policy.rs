//! G3.S2 — Realm policy server admin HTTP surface.
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/policy-server` — fetch the currently-projected
//!   `ak.realm.policy_server` config. Returns 404 if neither the realm nor its `governed_by`
//!   ancestor chain has declared one.
//! - `PUT /_arkret/self/realms/{realm_id}/policy-server` — submit a `ak.realm.policy_server`
//!   declaration. Routes through the standard `accept_local_operations` pipeline so the reducer's
//!   validators (URL scheme, on_timeout enum) run.
//! - `DELETE /_arkret/self/realms/{realm_id}/policy-server` — submit the durable
//!   `{"tombstone":true}` value to the same CAS-register cell.
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §2.

use arkret_event_draft::Operation;
use arkret_identifiers::{Did, OperationId, RealmId};
use arkret_models_collaboration::governance::realm_governance::{
    RealmPolicyServerOnTimeout, RealmPolicyServerPayload, RealmPolicyServerReplaceRequestBody,
    RealmPolicyServerTombstonePayload, RealmPolicyServerView,
};
use arkret_state::lattice::CellState;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{EmptyResult, JsonResult, empty_ok, json_ok};

use super::{AuthArgs, accept_local_operations_with_policy_actor};
use crate::ids;
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realms").push(
        Router::with_path("{realm_id}/policy-server")
            .get(get_realm_policy_server)
            .put(put_realm_policy_server)
            .delete(delete_realm_policy_server),
    )
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.get",
    summary = "Get a realm's policy server config",
    tags("realm_policy_server")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.get"))]
async fn get_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmPolicyServerView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let view = state
        .projections()
        .realm_policy_server_config(&realm_id)
        .map_err(policy_server_resolution_error)?
        .ok_or_else(|| AppError::not_found("no ak.realm.policy_server declared for this realm"))?;
    json_ok(policy_server_view(view)?)
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.replace",
    summary = "Replace a realm's policy server config",
    tags("realm_policy_server")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_policy_server.resource.replace"))]
async fn put_realm_policy_server(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<RealmPolicyServerReplaceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmPolicyServerView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let body = body.into_inner();

    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    require_policy_manage(state, &session.actor, realm_scope.as_str()).await?;
    validate_https_policy_server_url(&body.policy_server_url)?;
    if body.timeout_ms == Some(0) {
        return Err(AppError::invalid_param(
            "policy server timeout_ms must be greater than zero",
        ));
    }
    let mut payload = serde_json::to_value(&body)
        .map_err(|error| AppError::internal(format!("policy server payload: {error}")))?;
    let cell_key = policy_server_cell_key(&realm_id);
    if let Some(prior) = direct_policy_server_cell_value(state, &cell_key)? {
        attach_head_eq_precondition(&mut payload, prior)?;
    }
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(
        op_id,
        realm_scope,
        arkret_wire::events::EventKind::REALM_POLICY_SERVER,
        payload,
    );
    accept_local_operations_with_policy_actor(
        state,
        &session.actor,
        std::slice::from_ref(&operation),
    )
    .await
    .map_err(reducer_reject_to_app_error)?;

    let view = state
        .projections()
        .realm_policy_server_config(&realm_id)
        .map_err(policy_server_resolution_error)?
        .ok_or_else(|| {
            AppError::new(
                soland_http::error::ErrorCode::InternalError,
                "policy_server projection vanished after accept",
            )
        })?;
    json_ok(policy_server_view(view)?)
}

#[endpoint(
    operation_id = "ak.self.realm_policy_server.resource.delete",
    summary = "Delete a realm's policy server config",
    tags("realm_policy_server")
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
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    require_policy_manage(state, &session.actor, realm_scope.as_str()).await?;

    let cell_key = policy_server_cell_key(&realm_id);
    let prior = match direct_policy_server_cell_value(state, &cell_key)? {
        Some(value) if is_policy_server_tombstone(&value) => {
            return empty_ok();
        }
        Some(value) => value,
        None => {
            return Err(AppError::not_found(
                "no direct ak.realm.policy_server declaration to tombstone for this realm",
            ));
        }
    };

    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let mut payload = serde_json::to_value(RealmPolicyServerTombstonePayload::VALUE)
        .map_err(|error| AppError::internal(format!("policy server tombstone payload: {error}")))?;
    attach_head_eq_precondition(&mut payload, prior)?;
    let operation = Operation::create(
        op_id,
        realm_scope,
        arkret_wire::events::EventKind::REALM_POLICY_SERVER,
        payload,
    );
    accept_local_operations_with_policy_actor(
        state,
        &session.actor,
        std::slice::from_ref(&operation),
    )
    .await
    .map_err(reducer_reject_to_app_error)?;

    match state
        .projections()
        .snapshot()
        .realm_null_subject_cells
        .get(&cell_key)
    {
        Some(CellState::Value(value)) if is_policy_server_tombstone(value) => empty_ok(),
        Some(CellState::Bottom(_)) => Err(policy_server_resolution_error("cell_bottom_state")),
        _ => Err(AppError::internal(
            "policy server tombstone projection vanished after accept",
        )),
    }
}

fn policy_server_view(
    view: soland_services::authorization::RealmPolicyServerConfigView,
) -> Result<RealmPolicyServerView, AppError> {
    let cfg = view.config;
    Ok(RealmPolicyServerView {
        realm_id: RealmId::new(cfg.realm_id)
            .map_err(|error| AppError::internal(format!("stored realm_id is invalid: {error}")))?,
        policy_server_did: Did::new(cfg.policy_server_did).map_err(|error| {
            AppError::internal(format!("stored policy_server_did is invalid: {error}"))
        })?,
        policy_server_url: cfg.policy_server_url,
        cache_ttl_seconds: cfg.cache_ttl_seconds,
        timeout_ms: cfg.timeout_ms,
        on_timeout: match cfg.on_timeout.as_str() {
            "fail_closed" => RealmPolicyServerOnTimeout::FailClosed,
            "deny" => RealmPolicyServerOnTimeout::Deny,
            _ => {
                return Err(AppError::internal(
                    "stored policy server timeout mode is invalid",
                ));
            }
        },
        updated_at: cfg.updated_at,
        from_org_fallback: view.inherited_from_organization,
    })
}

fn validate_https_policy_server_url(raw_url: &str) -> Result<(), AppError> {
    let url = url::Url::parse(raw_url)
        .map_err(|error| AppError::invalid_param(format!("policy_server_url: {error}")))?;
    if url.scheme() != "https" {
        return Err(AppError::invalid_param("policy_server_url must use https"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::invalid_param(
            "policy_server_url must not contain credentials, query, or fragment",
        ));
    }
    if url.host_str().is_none() || url.path() != "/_arkret/self/policy/check" {
        return Err(AppError::invalid_param(
            "policy_server_url must target /_arkret/self/policy/check",
        ));
    }
    Ok(())
}

fn policy_server_cell_key(realm_id: &str) -> (String, String) {
    (
        realm_id.to_owned(),
        "ak:cell:ak.component.realm.policy_server.v1:null".to_owned(),
    )
}

fn direct_policy_server_cell_value(
    state: &AppState,
    cell_key: &(String, String),
) -> Result<Option<serde_json::Value>, AppError> {
    let snapshot = state.projections().snapshot();
    match snapshot.realm_null_subject_cells.get(cell_key) {
        Some(CellState::Bottom(_)) => Err(policy_server_resolution_error("cell_bottom_state")),
        Some(CellState::Value(value)) if is_policy_server_tombstone(value) => {
            Ok(Some(value.clone()))
        }
        Some(CellState::Value(value))
            if matches!(
                serde_json::from_value::<RealmPolicyServerPayload>(value.clone()),
                Ok(RealmPolicyServerPayload::Declaration(_))
            ) && snapshot.realm_policy_servers.contains_key(&cell_key.0) =>
        {
            Ok(Some(value.clone()))
        }
        Some(CellState::Value(_)) => Err(policy_server_resolution_error(
            "realm_policy_server_projection_missing",
        )),
        None if snapshot.realm_policy_servers.contains_key(&cell_key.0) => Err(
            policy_server_resolution_error("realm_policy_server_projection_missing"),
        ),
        None => Ok(None),
    }
}

fn is_policy_server_tombstone(value: &serde_json::Value) -> bool {
    matches!(
        serde_json::from_value::<RealmPolicyServerPayload>(value.clone()),
        Ok(RealmPolicyServerPayload::Tombstone(tombstone)) if tombstone.validate().is_ok()
    )
}

fn attach_head_eq_precondition(
    payload: &mut serde_json::Value,
    expected: serde_json::Value,
) -> Result<(), AppError> {
    let object = payload
        .as_object_mut()
        .ok_or_else(|| AppError::internal("policy server payload must be an object"))?;
    object.insert(
        "preconditions".to_owned(),
        serde_json::json!([{
            "cell": "ak:cell:ak.component.realm.policy_server.v1:null",
            "predicate": {
                "op": "head_eq",
                "value": expected,
            }
        }]),
    );
    Ok(())
}

async fn require_policy_manage(
    state: &AppState,
    actor: &str,
    realm_id: &str,
) -> Result<(), AppError> {
    let (owner, members) =
        crate::routing::events::operations::realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action: arkret_wire::CapabilityActionId::POLICY_MANAGE,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        Ok(())
    } else {
        Err(AppError::capability_denied("missing_capability"))
    }
}

fn reducer_reject_to_app_error(reason: &'static str) -> AppError {
    if reason == "projection_event_persistence_failed" {
        return AppError::internal(reason).with_wire_code("internal_error");
    }
    if reason == "failed_precondition" {
        return AppError::new(soland_http::error::ErrorCode::FailedPrecondition, reason)
            .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
            .with_wire_code("failed_precondition");
    }
    AppError::new(soland_http::error::ErrorCode::FailedPrecondition, reason)
        .with_status(salvo::http::StatusCode::UNPROCESSABLE_ENTITY)
        .with_wire_code(reason)
}

fn policy_server_resolution_error(reason: &'static str) -> AppError {
    if reason == "cell_bottom_state" {
        return AppError::new(
            soland_http::error::ErrorCode::FailedPrecondition,
            "realm policy-server cell is in Bottom",
        )
        .with_status(salvo::http::StatusCode::CONFLICT)
        .with_wire_code("failed_bottom");
    }
    AppError::new(
        soland_http::error::ErrorCode::FailedPrecondition,
        format!("realm policy-server resolution failed closed: {reason}"),
    )
    .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
    .with_wire_code("failed_precondition")
}
