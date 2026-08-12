use arkret_models_collaboration::direct_conversation_ops::{
    AcceptedAtServiceBinding, PrincipalServiceBindingCommitOutcome,
    PrincipalServiceBindingCommitRequestBody, PrincipalServiceBindingPrepareOutcome,
    PrincipalServiceBindingPrepareRequestBody,
};
use arkret_wire::PrincipalAuthorityInstance;
use chrono::{DateTime, Utc};
use salvo::Writer as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::{Depot, Request};
use serde::{Deserialize, Serialize};
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::{AccountDataCasOutcome, AccountDataState};

use super::super::AuthArgs;
use crate::JsonResult;
use crate::state::AppState;

const BINDING_STATE_KEY: &str = "ak.internal.principal_service_binding.v1";
const MAX_CAS_ATTEMPTS: usize = 8;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalServiceBindingState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_binding: Option<AcceptedAtServiceBinding>,
}

fn canonical_now() -> Result<DateTime<Utc>, AppError> {
    DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("current timestamp is out of range"))
}

fn decode_state(
    entry: Option<&AccountDataState>,
) -> Result<PrincipalServiceBindingState, AppError> {
    entry
        .map(|entry| {
            serde_json::from_value(entry.payload.clone()).map_err(|error| {
                AppError::internal(format!(
                    "stored principal service binding state is invalid: {error}"
                ))
            })
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

async fn load_state(
    state: &AppState,
    principal_id: &str,
) -> Result<(Option<AccountDataState>, PrincipalServiceBindingState), AppError> {
    let entry = state
        .account_data()
        .entry(principal_id, BINDING_STATE_KEY)
        .await
        .map_err(|error| {
            AppError::internal(format!("principal service binding lookup failed: {error}"))
        })?;
    let decoded = decode_state(entry.as_ref())?;
    Ok((entry, decoded))
}

async fn compare_and_set_state(
    state: &AppState,
    principal_id: &str,
    previous: Option<&AccountDataState>,
    payload: &PrincipalServiceBindingState,
    updated_at: DateTime<Utc>,
) -> Result<bool, AppError> {
    let expected_revision = previous.map_or(0, |entry| entry.revision);
    let record = AccountDataState {
        actor_id: principal_id.to_owned(),
        account_data_key: BINDING_STATE_KEY.to_owned(),
        revision: expected_revision + 1,
        payload: serde_json::to_value(payload).map_err(|error| {
            AppError::internal(format!(
                "principal service binding state encoding failed: {error}"
            ))
        })?,
        tombstone: false,
        updated_at,
    };
    let result = state
        .account_data()
        .compare_and_set(record, expected_revision)
        .await
        .map_err(|error| {
            AppError::internal(format!("principal service binding persist failed: {error}"))
        })?;
    Ok(matches!(result, AccountDataCasOutcome::Applied(_)))
}

/// Development-only fixture seam. The supplied accepted binding already
/// carries the exact authority instance and is validated before persistence.
pub(crate) async fn install_conformance_binding(
    state: &AppState,
    binding: AcceptedAtServiceBinding,
) -> Result<(), AppError> {
    if !state.config().development_mode {
        return Err(AppError::new(
            ErrorCode::NotFound,
            "conformance principal binding installation requires development mode",
        ));
    }
    binding
        .validate_shape()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    for _ in 0..MAX_CAS_ATTEMPTS {
        let (previous, mut stored) = load_state(state, binding.principal_id.as_str()).await?;
        stored.current_binding = Some(binding.clone());
        if compare_and_set_state(
            state,
            binding.principal_id.as_str(),
            previous.as_ref(),
            &stored,
            canonical_now()?,
        )
        .await?
        {
            return Ok(());
        }
    }
    Err(AppError::conflict(
        "principal service binding fixture changed concurrently",
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.principal_service_binding.command.prepare",
    tags("identity")
)]
pub(super) async fn prepare(
    aa: AuthArgs,
    _body: JsonBody<PrincipalServiceBindingPrepareRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalServiceBindingPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    Err(AppError::new(
        ErrorCode::FailedPrecondition,
        "principal service binding request does not select an exact authority_instance",
    )
    .with_status(StatusCode::PRECONDITION_FAILED))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.principal_service_binding.command.commit",
    tags("identity")
)]
pub(super) async fn commit(
    aa: AuthArgs,
    _body: JsonBody<PrincipalServiceBindingCommitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalServiceBindingCommitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    Err(AppError::new(
        ErrorCode::FailedPrecondition,
        "principal service binding request does not select an exact authority_instance",
    )
    .with_status(StatusCode::PRECONDITION_FAILED))
}

/// The stored accepted-at binding for exactly this authority instance.
///
/// Deliberately unused today, and deliberately not deleted: it is the only
/// selector shape `contact-and-direct-conversation.md` §9.1.2 permits, and the
/// alternative — selecting a binding by principal core — is the same-core PCR
/// substitution AUTH-RELAY-003 forbids. The resolver cannot call it until the
/// `creation_required` branch carries the founder's exact authority instance,
/// and `prepare`/`commit` above cannot produce a binding until the same carrier
/// lands, so the only writer today is the conformance fixture. Tracked in
/// `arkret-work/work/active/2026-08-08-1108-soland-unwired-spec-capabilities.md`:
/// wire it or delete it together with the fixture field, never widen it.
#[allow(dead_code)]
pub(crate) async fn binding_for_authority(
    state: &AppState,
    authority: &PrincipalAuthorityInstance,
) -> Result<Option<AcceptedAtServiceBinding>, AppError> {
    authority
        .validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let (_, binding_state) = load_state(state, authority.principal_id.as_str()).await?;
    Ok(binding_state
        .current_binding
        .filter(|binding| binding.authority_instance == *authority))
}
