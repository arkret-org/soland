//! Invite-token admin write surface.
//!
//! The collection snapshot already reads `RealmInviteRecord`; this module adds
//! the operator create/revoke endpoints without physically deleting invite rows.

use arkret_identifiers::RealmId;
use chrono::{DateTime, NaiveDateTime, Utc};
use salvo::prelude::*;
use serde_json::json;
use soland_services::events::RealmInviteState as RealmInviteRecord;
use soland_contracts::admin::invite_tokens::{AdminInviteTokenItem, CreateInviteTokenRequest};
use soland_http::error::AppError;

use super::{AuthArgs, append_audit_log, require_admin_principal};
use salvo::oapi::extract::{JsonBody, PathParam};
use crate::state::AppState;
use crate::{JsonResult, ids, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("invite-tokens")
        .post(create_invite_token)
        .push(Router::with_path("{invite_id}").delete(revoke_invite_token))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.invite_tokens.create"))]
async fn create_invite_token(
    aa: AuthArgs,
    body: JsonBody<CreateInviteTokenRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminInviteTokenItem> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let body = body.into_inner();
    if body
        .uses_allowed
        .is_some_and(|uses_allowed| uses_allowed != 1)
    {
        return Err(AppError::invalid_param(
            "uses_allowed must be omitted or 1 for single-use Realm invite tokens",
        ));
    }

    let realm_id = match body.realm_id {
        Some(realm_id) if !realm_id.trim().is_empty() => realm_id,
        _ => default_invite_realm_id(state)
            .ok_or_else(|| AppError::invalid_param("realm_id is required"))?,
    };
    let realm_id = RealmId::new(realm_id)
        .map_err(|error| AppError::invalid_param(format!("realm_id: {error}")))?
        .to_string();
    ensure_realm_exists(state, &realm_id)?;

    let invite = RealmInviteRecord {
        invite_id: ids::generate_invite_id(),
        realm_id,
        inviter: session.actor.clone(),
        invitee: body.invitee.filter(|value| !value.trim().is_empty()),
        invite_delivery_target: body.invite_delivery_target,
        introduction_evidence_digest: body
            .introduction_evidence_digest
            .filter(|value| !value.trim().is_empty()),
        third_party_id: None,
        join_rule_snapshot: None,
        invite_token: ids::generate("invite-token"),
        status: "pending".to_owned(),
        claim_nonces: std::collections::BTreeMap::new(),
        expires_at: parse_expires_at(body.expires_at.as_deref())?,
        created_at: Utc::now(),
        updated_at: None,
    };
    state
        .realm_invites()
        .put(invite.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.invite_tokens.create",
        json!({
            "invite_id": invite.invite_id,
            "realm_id": invite.realm_id,
            "invitee": invite.invitee,
        }),
        "accepted",
    )
    .await;

    json_ok(super::collection::admin_invite_item(&invite))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.invite_tokens.revoke"))]
async fn revoke_invite_token(
    aa: AuthArgs,
    invite_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminInviteTokenItem> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let invite_id = invite_id.into_inner();
    let mut invite = state
        .realm_invites()
        .get(&invite_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("invite token not found"))?;
    invite.status = "revoked".to_owned();
    state
        .realm_invites()
        .put(invite.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.invite_tokens.revoke",
        json!({
            "invite_id": invite.invite_id,
            "realm_id": invite.realm_id,
        }),
        "accepted",
    )
    .await;

    json_ok(super::collection::admin_invite_item(&invite))
}

fn default_invite_realm_id(state: &AppState) -> Option<String> {
    let realms = state.realm_directory().snapshot();
    realms
        .search(Default::default())
        .first()
        .map(|realm| realm.realm_id.as_str().to_owned())
}

fn ensure_realm_exists(state: &AppState, realm_id: &str) -> Result<(), AppError> {
    let realm_id = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::invalid_param(format!("realm_id: {error}")))?;
    let exists = state
        .realm_directory()
        .snapshot()
        .get(&realm_id)
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(AppError::not_found("realm not found"))
    }
}

fn parse_expires_at(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        return Ok(Some(parsed.with_timezone(&Utc)));
    }
    for format in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(raw, format) {
            return Ok(Some(DateTime::<Utc>::from_naive_utc_and_offset(
                parsed, Utc,
            )));
        }
    }
    Err(AppError::invalid_param(
        "expires_at must be RFC3339 or datetime-local format",
    ))
}

