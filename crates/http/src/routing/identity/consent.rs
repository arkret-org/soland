//! Holder-private Consent routes.
//!
//! The retired Cell/Seal consent projection cannot establish a typed current
//! revision. Keep every authority-bearing edge closed until the PCR
//! RealmCommit reducer and durable current-result reader are available.

use arkret_event_draft::ProjectedEventOperation;
use arkret_models_collaboration::consent_operations::{
    ConsentGrantRequestBody, ConsentList, ConsentRequestOutcome, ConsentRequestRequestBody,
    ConsentRevokeRequestBody, ConsentView,
};
use arkret_wire::{AccountDataKey, Event, EventKind};
use chrono::{DateTime, Utc};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_services::events::CommitConsentProjection;
use soland_storage::{ConsentRequestQuarantineInput, ConsentRequestQuarantineOutcome};

use super::AuthArgs;
use super::device_messages::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
    fanout_actor_private_update, station_device_message_sender,
};
use crate::error::AppError;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("results").get(list_consents))
        .push(Router::with_path("result").get(get_consent))
        .push(Router::with_path("results/grant").post(grant_consent))
        .push(Router::with_path("results/revoke").post(revoke_consent))
        .push(Router::with_path("request").post(request_consent))
}

fn current_unavailable() -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        "Consent current result and RealmCommit admission provider are unavailable"
    )
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.read.list.v1"))]
async fn list_consents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    Err(current_unavailable())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.resource.get.v1"))]
async fn get_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    Err(current_unavailable())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.grant.v1"))]
async fn grant_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentGrantRequestBody>,
) -> JsonResult<ConsentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    body.into_inner()
        .validate()
        .map_err(|error| AppError::param_invalid(format!("grant_event: {error}")))?;
    Err(current_unavailable())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.revoke.v1"))]
async fn revoke_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRevokeRequestBody>,
) -> JsonResult<ConsentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    body.into_inner()
        .validate()
        .map_err(|error| AppError::param_invalid(format!("revoke_event: {error}")))?;
    Err(current_unavailable())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.request.v1"))]
async fn request_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRequestRequestBody>,
) -> JsonResult<ConsentRequestOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(format!("consent request: {error}")))?;
    let requester =
        super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if actor.as_account_id() != Some(&requester) {
        return Err(AppError::unauthenticated(
            "Consent requester differs from its authenticated Account",
        ));
    }
    // The self route is Station-local. Remote or unknown holders receive the
    // same opaque result as quota, policy and successful queue admission.
    if body.holder_account_id.station_id != state.service_core_id() {
        return json_ok(ConsentRequestOutcome::accepted());
    }
    let quota_constraints = state
        .config()
        .receive_policy_constraints
        .as_ref()
        .and_then(|constraints| constraints.new_source_quota.clone())
        .unwrap_or_default();
    let received_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let source_digest = crate::routing::invites::new_source_ledger_digest(
        state,
        &body.holder_account_id,
        requester.principal_id.as_str(),
    );
    let admitted = state
        .persistence()
        .admit_consent_request_quarantine(ConsentRequestQuarantineInput {
            holder: body.holder_account_id.clone(),
            requester,
            consent_scope: body.consent_scope,
            source_digest,
            received_at,
            quota_constraints,
        })
        .await;
    if let Ok(ConsentRequestQuarantineOutcome::Queued(record)) = admitted {
        // Only the committed CAS winner is delivered, and its complete row is
        // the content every active holder device can read independently.
        fanout_actor_private_update(
            state,
            body.holder_account_id.principal_id.as_str(),
            ActorPrivateDeviceUpdate::AccountData {
                sender: station_device_message_sender(state),
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
                    revision: record.revision,
                    content: Some(record.payload),
                    updated_at: record.updated_at,
                },
                created_at: record.updated_at,
            },
        )
        .await;
    } else if let Err(error) = admitted {
        // A storage refusal must not reveal holder presence or policy through
        // the requester's response. The transaction has already rolled back.
        tracing::warn!(%error, "Consent request quarantine admission failed closed");
    }
    json_ok(ConsentRequestOutcome::accepted())
}

/// Legacy event_log integration carrier. No instance is constructed until
/// admission and current projection execute in one RealmCommit transaction.
#[derive(Clone, Debug)]
pub(crate) struct ConsentAdmission {
    commit: CommitConsentProjection,
}

impl ConsentAdmission {
    pub(crate) fn commit(&self) -> CommitConsentProjection {
        self.commit.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConsentRejection {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

/// Consent Event admission cannot use the retired Cell/Seal OR-set reducer.
/// Reject before Event/RealmCommit writes while letting unrelated Events pass.
pub(crate) async fn preflight_consent_admission(
    _state: &AppState,
    _operation: &ProjectedEventOperation,
    event: &Event,
) -> Result<Option<ConsentAdmission>, ConsentRejection> {
    if matches!(
        event.kind,
        EventKind::ConsentGrant | EventKind::ConsentRevoke
    ) {
        return Err(ConsentRejection {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "temporarily_unavailable",
            message: "Consent RealmCommit current admission provider is unavailable".to_owned(),
        });
    }
    Ok(None)
}

pub(crate) async fn apply_committed_consent_admission(
    _state: &AppState,
    _admission: &ConsentAdmission,
) {
    // No caller can create a ConsentAdmission until the formal reducer exists.
}

/// Introduction evidence must be checked against the holder's current
/// authority. A local legacy grant-dot cache is never proof of freshness.
pub(crate) fn has_active_consent_grant_evidence(
    _state: &AppState,
    _subject: &str,
    _holder_station_id: &str,
    _inviter_actor_id: &arkret_wire::ActorId,
    _consent_grant_ref: &str,
    _consent_id: Option<&str>,
    _at: DateTime<Utc>,
) -> bool {
    false
}
