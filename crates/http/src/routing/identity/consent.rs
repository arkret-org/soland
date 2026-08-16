//! Holder-private consent cell routes.
//!
//! This is the G3.S4 minimal reducer surface for
//! `ak.component.consent.grant.v1`: accepted Consent Events project into
//! holder-private OR-set cells. Contact and Personal DM authority are separate
//! and never consult this projection.
//!
//! `grant` and `revoke` take the holder-signed `ak.consent.grant` /
//! `ak.consent.revoke` Control Move and submit those exact bytes through ordinary
//! Event admission. The or_set dot is `ak:event:<event_id>:<write_index>` and the
//! cell subject is the caller-minted `consent_id`, so the service chooses neither
//! (spec `zh/identity/consent-model.md` sections 3.1 and 3.2). A dot no Event
//! produced would be an element in replicated state that nothing in the log
//! explains, and revoke targets dots by value.

use std::collections::BTreeSet;

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{ConsentId, DidCoreId};
use arkret_models_collaboration::account_lifecycle::{
    ConsentCellList, ConsentCellView, ConsentGrantRequestBody, ConsentRequestOutcome,
    ConsentRequestRequestBody, ConsentRevokeRequestBody, ConsentState,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
};
use arkret_wire::{AccountDataKey, Event};
use chrono::{DateTime, Utc};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::{
    AccountDataCasOutcome, AccountDataState, ConsentCellRecord,
    SessionIdentityState as SessionRecord,
};

use super::{AuthArgs, append_audit_log, now, query_param};
use crate::routing::identity::device_messages::fanout_actor_private_update;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const INVITE_QUARANTINE_ORIGIN_DEVICE: &str = "server:consent_revoke";

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("cells").get(list_consent_cells))
        .push(Router::with_path("cells/{holder_principal_id}").get(get_consent_cell))
        .push(Router::with_path("cells/{holder_principal_id}/grant").post(grant_consent_cell))
        .push(Router::with_path("cells/{holder_principal_id}/revoke").post(revoke_consent_cell))
        .push(Router::with_path("request").post(request_consent_cell))
}

pub(crate) async fn project_consent_operation(state: &AppState, operation: &Operation) {
    let kind = soland_services::operation_semantics::canonical_kind(operation);
    let projected = match kind {
        arkret_wire::EventKind::ConsentGrant => {
            project_consent_grant_operation(state, operation).await
        }
        arkret_wire::EventKind::ConsentRevoke => {
            project_consent_revoke_operation(state, operation).await
        }
        _ => return,
    };
    if let Err(error) = projected {
        tracing::warn!(
            %error,
            operation_id = %operation.operation_id,
            kind = %kind,
            "accepted consent event could not be projected into consent cells"
        );
    }
}

async fn project_consent_grant_operation(
    state: &AppState,
    operation: &Operation,
) -> Result<(), AppError> {
    let holder = consent_holder(operation)?;
    let peer = consent_peer(&operation.payload)?;
    validate_holder_update(&holder, &holder, &peer)?;
    let scope = consent_scope(&operation.payload)?;
    let consent_id = consent_id(&operation.payload)?;
    let expires_at = consent_expires_at(&operation.payload)?;
    let dot = consent_grant_dot(operation)?;
    let previous = consent_cell_snapshot(state, &holder, &peer, &scope);
    let updated = grant_cell_with_dot(
        state,
        &holder,
        &peer,
        &scope,
        dot,
        consent_cell_id_for_consent_id(&consent_id),
        expires_at,
        operation.created_at,
    );
    persist_consent_cell(state, &updated, previous).await
}

async fn project_consent_revoke_operation(
    state: &AppState,
    operation: &Operation,
) -> Result<(), AppError> {
    let holder = consent_holder(operation)?;
    let consent_id = consent_id(&operation.payload)?;
    let (peer, scope) = consent_revoke_target(state, &holder, &operation.payload, &consent_id)?;
    validate_holder_update(&holder, &holder, &peer)?;
    let observed_dots = observed_dots(&operation.payload)?;
    let revoked_at = consent_revoked_at(&operation.payload)?.unwrap_or(operation.created_at);
    let mutations = revoke_cells_with_observed_dots(
        state,
        &holder,
        &peer,
        &scope,
        &consent_id,
        &observed_dots,
        revoked_at,
    );
    for mutation in &mutations {
        persist_consent_cell(state, &mutation.updated, mutation.previous.clone()).await?;
    }
    emit_consent_revoke_invalidation(state, &holder, &peer, &scope, revoked_at, &mutations).await;
    Ok(())
}

#[endpoint(
    operation_id = "ak.self.consent.read.list",
    summary = "List consent cells",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.read.list"))]
async fn list_consent_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCellList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let now = now();
    let mut cells = state
        .consents()
        .visible_cells(&session.actor)
        .iter()
        .map(|cell| consent_response(cell, now))
        .collect::<Result<Vec<_>, _>>()?;
    cells.sort_by(|a, b| {
        a.holder_principal_id
            .cmp(&b.holder_principal_id)
            .then_with(|| a.peer_principal_id.cmp(&b.peer_principal_id))
            .then_with(|| a.consent_scope.cmp(&b.consent_scope))
    });
    json_ok(ConsentCellList { ok: true, cells })
}

#[endpoint(
    operation_id = "ak.self.consent.resource.get",
    summary = "Get one consent cell",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.resource.get"))]
async fn get_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_principal_id: PathParam<String>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_principal_id.into_inner();
    if DidCoreId::new(holder.clone()).is_err() {
        return Err(AppError::param_invalid("invalid holder principal id"));
    }
    let peer =
        query_param(req, "peer").ok_or_else(|| AppError::param_missing("peer is required"))?;
    if DidCoreId::new(peer.clone()).is_err() {
        return Err(AppError::param_invalid("invalid peer principal id"));
    }
    authorize_reader(&session.actor, &holder, &peer)?;
    // Accept both `consent_scope` (canonical) and the shorter `scope` alias so
    // holder-private reads stay addressable from either query convention.
    let scope_param = query_param(req, "consent_scope").or_else(|| query_param(req, "scope"));
    let scope = normalize_scope(scope_param.as_deref())?;
    let cell = state
        .consents()
        .cell(&holder, &peer, &scope)
        .ok_or_else(|| AppError::not_found("consent cell not found"))?;
    json_ok(consent_response(&cell, now())?)
}

#[endpoint(
    operation_id = "ak.self.consent.command.grant",
    summary = "Grant a consent cell",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.grant"))]
async fn grant_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_principal_id: PathParam<String>,
    body: JsonBody<ConsentGrantRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_principal_id.into_inner();
    let submission = body.into_inner().grant_event;
    let target = caller_signed_consent_target(
        &session.actor,
        &holder,
        &submission.event,
        arkret_wire::EventKind::ConsentGrant.as_str(),
    )?;
    submit_caller_signed_consent_event(state, &session, submission).await?;
    // Admission projected the or_set add through
    // `project_consent_grant_operation`, which derives the cell subject from the
    // Event's own `payload.consent_id` and the dot from its `event_id`.
    let cell = state
        .consents()
        .cell(&holder, &target.peer, &target.scope)
        .ok_or_else(|| {
            AppError::internal("consent grant accepted but the cell was not projected")
        })?;
    append_audit_log(
        state,
        Some(&holder),
        "consent.grant",
        json!({
            "holder_principal_id": holder,
            "peer_principal_id": target.peer,
            "consent_scope": target.scope,
            "consent_id": target.consent_id,
            "grant_event_id": target.event_id,
        }),
        "accepted",
    )
    .await;
    json_ok(consent_response(&cell, now())?)
}

#[endpoint(
    operation_id = "ak.self.consent.command.revoke",
    summary = "Revoke a consent cell",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.revoke"))]
async fn revoke_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_principal_id: PathParam<String>,
    body: JsonBody<ConsentRevokeRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_principal_id.into_inner();
    let submission = body.into_inner().revoke_event;
    let target = caller_signed_consent_target(
        &session.actor,
        &holder,
        &submission.event,
        arkret_wire::EventKind::ConsentRevoke.as_str(),
    )?;
    // The dots being removed come from the Event the holder signed, never from a
    // server-side enumeration: an observe-remove OR-Set revoke is only correct
    // when the revoker named the dots it observed.
    let observed_dots = observed_dots(&event_payload_value(&submission.event))?;
    submit_caller_signed_consent_event(state, &session, submission).await?;
    let cell = state
        .consents()
        .cell(&holder, &target.peer, &target.scope)
        .ok_or_else(|| {
            AppError::internal("consent revoke accepted but the cell was not projected")
        })?;
    append_audit_log(
        state,
        Some(&holder),
        "consent.revoke",
        json!({
            "holder_principal_id": holder,
            "peer_principal_id": target.peer,
            "consent_scope": target.scope,
            "consent_id": target.consent_id,
            "revoke_event_id": target.event_id,
            "observed_dots": observed_dots,
        }),
        "accepted",
    )
    .await;
    json_ok(consent_response(&cell, now())?)
}

/// What a caller-signed consent Event says it is acting on.
#[derive(Debug)]
struct ConsentTarget {
    event_id: String,
    consent_id: String,
    peer: String,
    scope: String,
}

/// Check what the request wrapper alone can decide about a caller-signed consent
/// Control Move, and report the cell it names.
///
/// The signature, envelope shape and the holder's consent-write authorization are
/// the ordinary Event admission path's job. This covers only the bindings between
/// the authenticated session, the path holder and the Event that was submitted.
fn caller_signed_consent_target(
    actor: &str,
    holder: &str,
    event: &Event,
    expected_kind: &str,
) -> Result<ConsentTarget, AppError> {
    if event.kind.as_str() != expected_kind {
        return Err(AppError::param_invalid(format!(
            "submitted Event kind must be {expected_kind}"
        )));
    }
    if event.actor_id.as_str() != holder {
        return Err(AppError::param_invalid(
            "the submitted Event must be authored by the path holder",
        ));
    }
    // The payload accessors are shared with the projection path, which reads a
    // whole-value payload; an envelope carries the same object as a map.
    let payload = event_payload_value(event);
    let peer = consent_peer(&payload)?;
    validate_holder_update(actor, holder, peer.as_str())?;
    Ok(ConsentTarget {
        event_id: event.event_id.to_string(),
        consent_id: consent_id(&payload)?,
        peer,
        scope: consent_scope(&payload)?,
    })
}

/// Restate a typed envelope's payload as the whole `Value` the shared payload
/// accessors expect.
fn event_payload_value(event: &Event) -> Value {
    Value::Object(event.payload.clone().into_iter().collect())
}

/// Submit the holder's exact Event bytes through ordinary Event admission.
async fn submit_caller_signed_consent_event(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<(), AppError> {
    let kind = submission.event.kind.as_str().to_owned();
    crate::routing::events::event_log::submit_initial_event_submission(state, session, submission)
        .await
        .map(|_| ())
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                &format!("{kind} submit failed"),
                error.status,
                error.code,
                &error.message,
            )
        })
}

#[endpoint(
    operation_id = "ak.self.consent.command.request",
    summary = "Request consent from a peer",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.request"))]
async fn request_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRequestRequestBody>,
) -> JsonResult<ConsentRequestOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let peer = match body.peer_principal_id {
        Some(peer) => peer,
        None => arkret_identifiers::DidCoreId::new(session.actor.clone())
            .map_err(|e| AppError::param_invalid(format!("peer_principal_id: {e}")))?,
    };
    if peer.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "consent request peer must match authenticated actor",
        ));
    }
    // Syntactic validation is safe, but holder existence, policy, rate-limit,
    // silent drop and quarantine admission are intentionally indistinguishable.
    // This operation never creates a consent cell or a pending consent state.
    let _ = normalize_scope(body.consent_scope.as_deref())?;
    let _ = body.holder_principal_id;
    json_ok(ConsentRequestOutcome {
        ok: true,
        accepted_for_processing: true,
    })
}

pub(super) fn normalize_scope(input: Option<&str>) -> Result<String, AppError> {
    let raw = input.unwrap_or("direct_message").trim();
    if raw.is_empty() {
        return Ok("direct_message".to_owned());
    }
    let normalized = raw.to_ascii_lowercase();
    match normalized.as_str() {
        "invite" => Ok("invite".to_owned()),
        "message" | "direct_message" | "messaging" | "dm" => Ok("direct_message".to_owned()),
        "call" | "voice_call" => Ok("voice_call".to_owned()),
        "video_call" => Ok("video_call".to_owned()),
        "presence" => Ok("presence".to_owned()),
        "any" => Ok("any".to_owned()),
        _ => Err(AppError::param_invalid(
            "scope must be invite, direct_message, voice_call, video_call, presence, or any",
        )),
    }
}

pub(super) fn consent_cell_snapshot(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
) -> Option<ConsentCellRecord> {
    state.consents().cell(holder, peer, scope)
}

/// Write-through a single mutated consent cell to durable storage.
///
/// Callers update the in-memory working projection before reaching this async
/// boundary. On durable write failure, this helper rolls back the matching
/// in-memory mutation before surfacing the request failure.
pub(super) async fn persist_consent_cell(
    state: &AppState,
    record: &ConsentCellRecord,
    previous: Option<ConsentCellRecord>,
) -> Result<(), AppError> {
    if let Err(error) = state.consents().save_cell(record.clone()).await {
        let restored = restore_consent_cell_after_persist_failure(state, record, previous);
        tracing::error!(
            %error,
            holder = %record.holder,
            peer = %record.peer,
            scope = %record.scope,
            restored,
            "failed to persist consent cell to durable storage"
        );
        return Err(AppError::internal(format!(
            "failed to persist consent cell: {error}"
        )));
    }
    Ok(())
}

fn restore_consent_cell_after_persist_failure(
    state: &AppState,
    record: &ConsentCellRecord,
    previous: Option<ConsentCellRecord>,
) -> bool {
    state.consents().restore_cell_if_current(record, previous)
}

pub(crate) fn has_active_consent_for_scope(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    at: DateTime<Utc>,
) -> bool {
    let scope = normalize_scope(Some(scope)).unwrap_or_else(|_| scope.to_owned());
    [&scope, "any"].iter().any(|scope| {
        state
            .consents()
            .cell(holder, peer, scope)
            .is_some_and(|cell| effective_state(&cell, at) == "granted")
    })
}

/// Spec `sync/invite-addressing.md` §2 — verify a `consent_grant`
/// introduction evidence. The `consent_grant_ref` (and optional
/// `consent_id`) MUST resolve to an **active** grant dot in `subject`'s
/// (the invitee's) consent cell with `peer == inviter` and
/// `consent_scope ∈ {invite, any}`, unrevoked and unexpired. Returns
/// `true` only when such a dot exists. On any mismatch the caller MUST
/// downgrade the delivery to the low-trust `explicit_address` path.
pub(crate) fn has_active_consent_grant_evidence(
    state: &AppState,
    subject: &str,
    inviter: &str,
    consent_grant_ref: &str,
    consent_id: Option<&str>,
    at: DateTime<Utc>,
) -> bool {
    let grant_ref = consent_grant_ref.trim();
    if grant_ref.is_empty() {
        return false;
    }
    let expected_cell_id = consent_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(consent_cell_id_for_consent_id);
    state
        .consents()
        .cells_for_pair(subject, inviter)
        .iter()
        .any(|cell| {
            if cell.holder != subject || cell.peer != inviter {
                return false;
            }
            if !matches!(cell.scope.as_str(), "invite" | "any") {
                return false;
            }
            if let Some(expected) = &expected_cell_id
                && &cell.cell_id != expected
            {
                return false;
            }
            active_grant_dots(cell, at)
                .iter()
                .any(|dot| grant_dot_matches_ref(dot, grant_ref))
        })
}

/// A consent grant dot is `{event_id}:{write_index}`. The
/// `consent_grant_ref` carried in introduction evidence is the originating
/// Event id; match it against the dot's event-id segment as well as the whole
/// dot string.
fn grant_dot_matches_ref(dot: &str, grant_ref: &str) -> bool {
    if dot == grant_ref {
        return true;
    }
    event_ref_for_dot(dot).is_some_and(|event_ref| event_ref == grant_ref)
}

/// Extract the canonical Event id encoded in a grant
/// dot, if any. Only the `{event_id}:{write_index}` form (and a bare Event id)
/// carries a real Event id.
///
/// `EventId` values may themselves be `:`-delimited, so we
/// strip only the trailing `:<write_index>` segment rather than splitting on
/// the first `:`. The result is validated through `EventId::new` so callers
/// can rely on it being a well-formed event ref.
pub(crate) fn event_ref_for_dot(dot: &str) -> Option<&str> {
    if dot.contains('#') {
        // `{actor}#{seq}` / `{consent_id}#{op}` — head is not an event id.
        return None;
    }
    // A bare Event-id dot, or the `{event_id}:{write_index}` mint form.
    let candidate = match dot.rsplit_once(':') {
        // Trailing segment is the numeric write index; the prefix is the id.
        Some((prefix, seq)) if seq.chars().all(|c| c.is_ascii_digit()) && !seq.is_empty() => prefix,
        _ => dot,
    };
    arkret_identifiers::EventId::new(candidate)
        .ok()
        .map(|_| candidate)
}

pub(crate) struct ConsentCellMutation {
    pub previous: Option<ConsentCellRecord>,
    pub updated: ConsentCellRecord,
}

#[allow(clippy::too_many_arguments)]
fn grant_cell_with_dot(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    dot: String,
    cell_id: String,
    expires_at: Option<DateTime<Utc>>,
    granted_at: DateTime<Utc>,
) -> ConsentCellRecord {
    state.consents().grant_cell(
        holder,
        peer,
        scope,
        cell_id.clone(),
        dot,
        Some(cell_id),
        expires_at,
        granted_at,
    )
}

fn revoke_cells_with_observed_dots(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    consent_id: &str,
    observed_dots: &[String],
    revoked_at: DateTime<Utc>,
) -> Vec<ConsentCellMutation> {
    revoke_cells_inner(
        state,
        holder,
        peer,
        scope,
        consent_id,
        Some(observed_dots),
        revoked_at,
    )
}

fn revoke_cells_inner(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    consent_id: &str,
    observed_dots: Option<&[String]>,
    revoked_at: DateTime<Utc>,
) -> Vec<ConsentCellMutation> {
    revoke_target_scopes(scope)
        .into_iter()
        .map(|target_scope| {
            let previous = consent_cell_snapshot(state, holder, peer, &target_scope);
            let dots = if scope == "any" && target_scope != "any" {
                grant_dots_for_cell(state, holder, peer, &target_scope)
            } else {
                observed_dots
                    .map(|dots| dots.to_vec())
                    .unwrap_or_else(|| grant_dots_for_cell(state, holder, peer, &target_scope))
            };
            let cell_id = consent_cell_id_for_consent_id(consent_id);
            let mut updated = revoke_cell_with_dots(
                state,
                holder,
                peer,
                &target_scope,
                &cell_id,
                &dots,
                revoked_at,
            );
            if scope == "any" && target_scope != "any" {
                updated = mark_cell_superseded_by_any_revoke(
                    state,
                    holder,
                    peer,
                    &target_scope,
                    &cell_id,
                    revoked_at,
                );
            }
            ConsentCellMutation { previous, updated }
        })
        .collect()
}

fn revoke_target_scopes(scope: &str) -> Vec<String> {
    if scope == "any" {
        std::iter::once("any")
            .chain(CONSENT_ACTION_SCOPE_CASCADE.iter().copied())
            .map(ToOwned::to_owned)
            .collect()
    } else {
        vec![scope.to_owned()]
    }
}

fn grant_dots_for_cell(state: &AppState, holder: &str, peer: &str, scope: &str) -> Vec<String> {
    state.consents().grant_dots(holder, peer, scope)
}

fn mark_cell_superseded_by_any_revoke(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    cell_id: &str,
    revoked_at: DateTime<Utc>,
) -> ConsentCellRecord {
    state.consents().mark_superseded_by_any_revoke(
        holder,
        peer,
        scope,
        cell_id.to_owned(),
        SUPERSEDED_BY_ANY_REVOKE,
        revoked_at,
    )
}

fn revoke_cell_with_dots(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    cell_id: &str,
    observed_dots: &[String],
    revoked_at: DateTime<Utc>,
) -> ConsentCellRecord {
    state.consents().revoke_cell(
        holder,
        peer,
        scope,
        cell_id.to_owned(),
        observed_dots,
        revoked_at,
    )
}

fn validate_holder_update(session_actor: &str, holder: &str, peer: &str) -> Result<(), AppError> {
    if DidCoreId::new(holder.to_owned()).is_err() {
        return Err(AppError::param_invalid("invalid holder principal id"));
    }
    if DidCoreId::new(peer.to_owned()).is_err() {
        return Err(AppError::param_invalid("invalid peer principal id"));
    }
    if session_actor != holder {
        return Err(AppError::capability_denied(
            "only the holder DID may update a consent cell",
        ));
    }
    if peer == holder {
        return Err(AppError::param_invalid(
            "peer DID must differ from holder DID",
        ));
    }
    Ok(())
}

fn authorize_reader(session_actor: &str, holder: &str, _peer: &str) -> Result<(), AppError> {
    if session_actor == holder {
        Ok(())
    } else {
        Err(AppError::capability_denied(
            "consent cell is visible only to its holder or an explicitly authorized controller",
        ))
    }
}

fn consent_cell_id_for_consent_id(consent_id: &str) -> String {
    let consent_id = ConsentId::new(consent_id.to_owned())
        .expect("consent IDs are validated before cell projection");
    arkret_state::consent::consent_cell_id(&consent_id)
        .expect("typed consent IDs always produce valid cell references")
        .into_string()
}

fn consent_id(payload: &Value) -> Result<String, AppError> {
    let consent_id = payload
        .get("consent_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_missing("consent_id is required"))?;
    ConsentId::new(consent_id.to_owned())
        .map(ConsentId::into_string)
        .map_err(|_| {
            AppError::param_invalid("consent_id must be an ak:consent:<UUIDv7> identifier")
        })
}

fn consent_holder(operation: &Operation) -> Result<String, AppError> {
    let sender = operation.context.sender.as_str();
    let holder = first_payload_string(
        &operation.payload,
        &["holder_principal_id", "holder", "consenter", "issuer"],
    )
    .unwrap_or_else(|| sender.to_owned());
    if holder != sender {
        return Err(AppError::capability_denied(
            "consent holder must match event sender",
        ));
    }
    Ok(holder)
}

fn consent_peer(payload: &Value) -> Result<String, AppError> {
    first_payload_string(
        payload,
        &[
            "peer",
            "peer_principal_id",
            "grantee_did",
            "target_did",
            "target",
        ],
    )
    .or_else(|| {
        payload
            .get("tag")
            .and_then(Value::as_object)
            .and_then(|tag| {
                tag.get("peer")
                    .or_else(|| tag.get("peer_principal_id"))
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
    })
    .ok_or_else(|| AppError::param_missing("peer is required"))
}

fn consent_scope(payload: &Value) -> Result<String, AppError> {
    let scope = first_payload_string(payload, &["consent_scope", "scope"]).or_else(|| {
        payload
            .get("tag")
            .and_then(Value::as_object)
            .and_then(|tag| {
                tag.get("scope")
                    .or_else(|| tag.get("consent_scope"))
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
    });
    normalize_scope(scope.as_deref())
}

fn consent_revoke_target(
    state: &AppState,
    holder: &str,
    payload: &Value,
    consent_id: &str,
) -> Result<(String, String), AppError> {
    if let (Ok(peer), Ok(scope)) = (consent_peer(payload), consent_scope(payload)) {
        return Ok((peer, scope));
    }
    let cell_id = consent_cell_id_for_consent_id(consent_id);
    state
        .consents()
        .holder_cell_by_id(holder, &cell_id)
        .as_ref()
        .map(|cell| (cell.peer.clone(), cell.scope.clone()))
        .ok_or_else(|| {
            AppError::param_missing("revoke requires peer/scope or an existing consent_id cell")
        })
}

fn consent_expires_at(payload: &Value) -> Result<Option<DateTime<Utc>>, AppError> {
    optional_timestamp(payload, &["expires_at"])
}

fn consent_revoked_at(payload: &Value) -> Result<Option<DateTime<Utc>>, AppError> {
    optional_timestamp(payload, &["revoked_at"])
}

fn optional_timestamp(payload: &Value, keys: &[&str]) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(value) = keys
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
    else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|value| Some(value.with_timezone(&Utc)))
        .map_err(|_| AppError::param_invalid("timestamp must be RFC3339"))
}

fn first_payload_string(payload: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn consent_grant_dot(operation: &Operation) -> Result<String, AppError> {
    let event_id = operation.context.event_id.as_str();
    Ok(format!("{event_id}:0"))
}

fn observed_dots(payload: &Value) -> Result<Vec<String>, AppError> {
    let observed = payload
        .get("observed_dots")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::param_missing("observed_dots is required"))?;
    let dots = observed
        .iter()
        .map(|value| {
            let dot = value
                .as_str()
                .ok_or_else(|| AppError::param_invalid("observed_dots entries must be strings"))?;
            if !is_event_derived_consent_dot(dot) {
                return Err(AppError::param_invalid(
                    "observed_dots entries must be Event-derived consent dots",
                ));
            }
            Ok(dot.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if dots.is_empty() {
        return Err(AppError::param_invalid("observed_dots must not be empty"));
    }
    Ok(dots)
}

fn is_event_derived_consent_dot(dot: &str) -> bool {
    let Some((event_id, write_index)) = dot.rsplit_once(':') else {
        return false;
    };
    !write_index.is_empty()
        && write_index
            .chars()
            .all(|character| character.is_ascii_digit())
        && arkret_identifiers::EventId::new(event_id.to_owned()).is_ok()
}

fn consent_response(
    cell: &ConsentCellRecord,
    at: DateTime<Utc>,
) -> Result<ConsentCellView, AppError> {
    let active_grant_dots = active_grant_dots(cell, at);
    Ok(ConsentCellView {
        ok: true,
        cell_id: cell.cell_id.clone(),
        holder_principal_id: arkret_identifiers::DidCoreId::new(cell.holder.clone())
            .map_err(|e| AppError::internal(format!("stored consent holder_principal_id: {e}")))?,
        peer_principal_id: arkret_identifiers::DidCoreId::new(cell.peer.clone())
            .map_err(|e| AppError::internal(format!("stored consent peer_principal_id: {e}")))?,
        consent_scope: normalize_scope(Some(&cell.scope))?,
        state: consent_response_state(cell, at),
        expires_at: response_expires_at(cell),
        requested_at: cell.requested_at,
        updated_at: cell.updated_at,
        active_grant_dots,
        grant_dots: cell
            .grant_dots
            .values()
            .map(|grant| grant.dot.clone())
            .collect(),
        revoked_dots: cell.revoked_dots.iter().cloned().collect(),
    })
}

fn consent_response_state(cell: &ConsentCellRecord, at: DateTime<Utc>) -> ConsentState {
    if effective_state(cell, at) == "granted" {
        ConsentState::Active
    } else {
        ConsentState::NoConsent
    }
}

fn active_grant_dots(cell: &ConsentCellRecord, at: DateTime<Utc>) -> Vec<String> {
    cell.grant_dots
        .iter()
        .filter(|(dot, grant)| {
            !cell.revoked_dots.contains(*dot)
                && grant.expires_at.is_none_or(|expires_at| expires_at > at)
        })
        .map(|(_, grant)| grant.dot.clone())
        .collect()
}

fn response_expires_at(cell: &ConsentCellRecord) -> Option<DateTime<Utc>> {
    cell.grant_dots
        .values()
        .max_by_key(|grant| grant.granted_at)
        .and_then(|grant| grant.expires_at)
}

fn effective_state(cell: &ConsentCellRecord, at: DateTime<Utc>) -> &'static str {
    let mut has_unrevoked = false;
    let mut has_expired_unrevoked = false;
    for (dot, grant) in &cell.grant_dots {
        if cell.revoked_dots.contains(dot) {
            continue;
        }
        has_unrevoked = true;
        if grant.expires_at.is_some_and(|expires_at| expires_at <= at) {
            has_expired_unrevoked = true;
        } else {
            return "granted";
        }
    }
    if has_unrevoked && has_expired_unrevoked {
        return "expired";
    }
    if let Some(revoked_at) = cell.revoked_at {
        let request_reopened_after_revoke = cell
            .requested_at
            .is_some_and(|requested_at| requested_at > revoked_at);
        if !request_reopened_after_revoke {
            return "revoked";
        }
    }
    "pending"
}

pub(super) async fn emit_consent_revoke_invalidation(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
    mutations: &[ConsentCellMutation],
) {
    let invalidated_action_scopes = revoke_target_scopes(scope);
    let target_peer_service_ids = consent_invalidation_peer_service_ids(state, holder, peer).await;
    let invalidated_quarantine_entries =
        match invalidate_quarantined_invites_for_revoke(state, holder, peer, scope, revoked_at)
            .await
        {
            Ok(count) => count,
            Err(error) => {
                tracing::warn!(
                    %error,
                    holder,
                    peer,
                    scope,
                    "failed to invalidate invite quarantine entries for consent revoke"
                );
                0
            }
        };
    let invalidated_channels = ConsentRevokeInvalidationChannel::ALL
        .iter()
        .map(|channel| channel.as_str())
        .collect::<Vec<_>>();
    let mutated_cells = mutations
        .iter()
        .map(|mutation| {
            json!({
                "cell_id": &mutation.updated.cell_id,
                "consent_scope": &mutation.updated.scope,
                "revoked_dots": mutation.updated.revoked_dots.iter().cloned().collect::<Vec<_>>(),
                "revoked_at": mutation.updated.revoked_at.map(
                    arkret_canonical::format_timestamp_canonical
                ),
            })
        })
        .collect::<Vec<_>>();
    let payload = json!({
        "schema": "ak.vector.consent.cache_invalidation.v1",
        "holder_principal_id": holder,
        "peer_principal_id": peer,
        "consent_scope": scope,
        "invalidated_action_scopes": invalidated_action_scopes,
        "invalidated_cache_scopes": CONSENT_SCOPE_CASCADE,
        "invalidated_channels": invalidated_channels,
        "target_peer_service_ids": target_peer_service_ids,
        "local_quarantine_entries_invalidated": invalidated_quarantine_entries,
        "eager_invalidation": true,
        "scope_cascade_marker": if scope == "any" {
            Some(SUPERSEDED_BY_ANY_REVOKE)
        } else {
            None
        },
        "mutated_cells": mutated_cells,
        "revoked_at": arkret_canonical::format_timestamp_canonical(revoked_at),
    });
    append_audit_log(
        state,
        Some(holder),
        "consent.revoke.cache_invalidation",
        payload,
        "accepted",
    )
    .await;
}

// ────────────────────────────────────────────────────────────────────────
// scope=any cascade.
// ────────────────────────────────────────────────────────────────────────

async fn consent_invalidation_peer_service_ids(
    state: &AppState,
    holder: &str,
    peer: &str,
) -> Vec<String> {
    let mut services = BTreeSet::new();
    for actor in [holder, peer] {
        let records = match state.contacts().contacts_for_actor(actor).await {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(
                    %error,
                    actor,
                    holder,
                    peer,
                    "failed to list contacts for consent invalidation target discovery"
                );
                continue;
            }
        };
        for record in records {
            let same_pair = (record.requester == holder && record.target == peer)
                || (record.requester == peer && record.target == holder);
            if !same_pair {
                continue;
            }
            if let Some(service_id) = record
                .peer_service_id
                .as_deref()
                .filter(|value| *value != state.service_id())
            {
                services.insert(service_id.to_owned());
            }
        }
    }
    services.into_iter().collect()
}

async fn invalidate_quarantined_invites_for_revoke(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
) -> Result<usize, AppError> {
    if !matches!(scope, "invite" | "any") {
        return Ok(0);
    }
    let Some(existing) = state
        .account_data()
        .entry(holder, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(0);
    };
    let Some(entries) = existing.payload.get("entries").and_then(Value::as_array) else {
        return Ok(0);
    };
    let mut removed = 0usize;
    let retained = entries
        .iter()
        .filter(|entry| {
            let should_remove = quarantine_entry_matches_consent_revoke(entry, peer);
            if should_remove {
                removed += 1;
            }
            !should_remove
        })
        .cloned()
        .collect::<Vec<_>>();
    if removed == 0 {
        return Ok(0);
    }

    let mut object = existing.payload.as_object().cloned().unwrap_or_default();
    object.insert(
        "schema".to_owned(),
        Value::String(arkret_wire::AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned()),
    );
    object.insert("entries".to_owned(), Value::Array(retained));
    object.insert("updated_at".to_owned(), json!(revoked_at));
    object.insert(
        "last_invalidation".to_owned(),
        json!({
            "reason": "consent_revoke",
            "peer_principal_id": peer,
            "consent_scope": scope,
            "revoked_at": revoked_at,
            "removed_entries": removed,
        }),
    );
    let record = AccountDataState {
        actor_id: holder.to_owned(),
        account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
        revision: existing.revision + 1,
        payload: Value::Object(object),
        tombstone: false,
        updated_at: revoked_at,
    };
    let expected_revision = existing.revision;
    let applied = state
        .account_data()
        .compare_and_set(record.clone(), expected_revision)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let AccountDataCasOutcome::Applied(record) = applied else {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "invite quarantine account data changed concurrently",
        ));
    };
    fanout_actor_private_update(
        state,
        holder,
        ActorPrivateDeviceUpdate::AccountData {
            sender_device_id: INVITE_QUARANTINE_ORIGIN_DEVICE.to_owned(),
            content: ActorPrivateAccountDataUpdate {
                operation: ActorPrivateAccountDataOperation::Put,
                account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
                revision: record.revision,
                content: Some(record.payload.clone()),
                updated_at: record.updated_at,
            },
            created_at: record.updated_at,
        },
    )
    .await;
    append_audit_log(
        state,
        Some(holder),
        "consent.revoke.invite_quarantine_invalidation",
        json!({
            "holder_principal_id": holder,
            "peer_principal_id": peer,
            "consent_scope": scope,
            "removed_entries": removed,
            "revoked_at": revoked_at,
        }),
        "accepted",
    )
    .await;
    Ok(removed)
}

fn quarantine_entry_matches_consent_revoke(entry: &Value, peer: &str) -> bool {
    let pending = entry
        .get("status")
        .and_then(Value::as_str)
        .is_none_or(|status| status == "pending_review");
    let invite_scope = entry
        .get("consent_scope")
        .and_then(Value::as_str)
        .is_none_or(|scope| scope == "invite");
    let peer_matches = entry
        .get("source_peer_principal_id")
        .or_else(|| entry.get("inviter"))
        .and_then(Value::as_str)
        == Some(peer);
    pending && invite_scope && peer_matches
}

/// Concrete action scopes covered by `consent_scope=any`.
pub const CONSENT_ACTION_SCOPE_CASCADE: &[&str] = &[
    "invite",
    "direct_message",
    "voice_call",
    "video_call",
    "presence",
];

/// Spec T17 — downstream cache scopes that a `scope=any` revoke MUST invalidate.
/// The full list is open-ended in spec; soland tracks the five that gate
/// cross-service routing today.
pub const CONSENT_SCOPE_CASCADE: &[&str] = &[
    "directory_reachability",
    "mimi_consent",
    "push_contact_psi",
    "invite_gate",
    "in_flight_invite",
];

/// Spec T17 — when a consent revoke is issued with `scope=any`, the
/// projection MUST mark every cascaded child scope with this marker so
/// consumers can distinguish "explicitly revoked" from "swept by an
/// any-revoke".
pub const SUPERSEDED_BY_ANY_REVOKE: &str = "superseded_by_any_revoke";

/// Spec T17 — five cache-invalidation channels that an `any`-revoke MUST
/// broadcast to cross-service consumers (teabay / floria / coauth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentRevokeInvalidationChannel {
    DirectoryReachability,
    MimiConsent,
    PushContactPsi,
    InviteGate,
    InFlightInvite,
}

impl ConsentRevokeInvalidationChannel {
    pub const ALL: &'static [Self] = &[
        Self::DirectoryReachability,
        Self::MimiConsent,
        Self::PushContactPsi,
        Self::InviteGate,
        Self::InFlightInvite,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryReachability => "directory_reachability",
            Self::MimiConsent => "mimi_consent",
            Self::PushContactPsi => "push_contact_psi",
            Self::InviteGate => "invite_gate",
            Self::InFlightInvite => "in_flight_invite",
        }
    }
}

#[cfg(test)]
mod tests {
    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    #[test]
    fn complete_consent_cell_is_holder_private() {
        let holder = "ak:did_core:web:holder.example";
        let peer = "ak:did_core:web:peer.example";
        assert!(authorize_reader(holder, holder, peer).is_ok());
        assert!(authorize_reader(peer, holder, peer).is_err());
        assert!(authorize_reader("ak:did_core:web:other.example", holder, peer).is_err());
    }

    #[test]
    fn consent_revoke_cascade_table_stable() {
        // Sanity — 5 channels, 5 cascade scopes.
        assert_eq!(ConsentRevokeInvalidationChannel::ALL.len(), 5);
        assert_eq!(CONSENT_SCOPE_CASCADE.len(), 5);
    }

    const HOLDER: &str = "ak:did_core:web:holder.example";
    const PEER: &str = "ak:did_core:web:peer.example";
    const CONSENT_ID: &str = "ak:consent:01964137-0000-7000-8000-000000000041";
    const GRANT_EVENT: &str = "ak:event:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV";
    const HOLDER_PCR: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";

    #[test]
    fn revoke_before_grant_keeps_the_payload_consent_id_as_cell_subject() {
        let state = AppState::new(test_config(), Db { pool: None });
        let mutations = revoke_cells_with_observed_dots(
            &state,
            HOLDER,
            PEER,
            "invite",
            CONSENT_ID,
            &[],
            Utc::now(),
        );
        assert_eq!(mutations.len(), 1);
        assert_eq!(
            mutations[0].updated.cell_id,
            format!("ak:cell:ak.component.consent.grant.v1:{CONSENT_ID}")
        );
    }

    fn consent_event(kind: &str, actor: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": GRANT_EVENT,
            "kind": kind,
            "realm_id": HOLDER_PCR,
            "scope_ref": { "kind": "realm", "realm_id": HOLDER_PCR },
            "actor_id": actor,
            "principal_server_id": "ak:did_core:web:soland.test",
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": payload,
            "proofs": [],
        }))
        .expect("consent envelope")
    }

    fn grant_payload() -> Value {
        json!({
            "consent_id": CONSENT_ID,
            "peer": PEER,
            "consent_scope": "invite",
        })
    }

    #[test]
    fn a_grant_event_reports_the_cell_it_names() {
        let event = consent_event(
            arkret_wire::EventKind::ConsentGrant.as_str(),
            HOLDER,
            grant_payload(),
        );
        let target = caller_signed_consent_target(
            HOLDER,
            HOLDER,
            &event,
            arkret_wire::EventKind::ConsentGrant.as_str(),
        )
        .unwrap();

        assert_eq!(target.consent_id, CONSENT_ID);
        assert_eq!(target.peer, PEER);
        assert_eq!(target.scope, "invite");
        // The cell subject is the caller's consent_id, so the service never picks
        // it: `consent_cell_id_for_consent_id` is a pure function of the payload.
        assert_eq!(
            consent_cell_id_for_consent_id(&target.consent_id),
            format!("ak:cell:ak.component.consent.grant.v1:{CONSENT_ID}")
        );
    }

    #[test]
    fn a_consent_event_authored_by_someone_else_is_rejected() {
        let event = consent_event(
            arkret_wire::EventKind::ConsentGrant.as_str(),
            "ak:did_core:web:attacker.example",
            grant_payload(),
        );
        caller_signed_consent_target(
            HOLDER,
            HOLDER,
            &event,
            arkret_wire::EventKind::ConsentGrant.as_str(),
        )
        .expect_err("only the holder may author a write to the holder's consent cell");
    }

    #[test]
    fn a_revoke_endpoint_refuses_a_grant_event() {
        let event = consent_event(
            arkret_wire::EventKind::ConsentGrant.as_str(),
            HOLDER,
            grant_payload(),
        );
        caller_signed_consent_target(
            HOLDER,
            HOLDER,
            &event,
            arkret_wire::EventKind::ConsentRevoke.as_str(),
        )
        .expect_err("the revoke surface must not accept a grant Event");
    }

    #[test]
    fn a_revoke_event_must_name_the_dots_it_observed() {
        // An observe-remove OR-Set revoke with no observed dots is the
        // concurrent-revoke race the dot model exists to close.
        let mut payload = grant_payload();
        payload["revoked_at"] = json!("2026-07-06T00:00:00.000Z");
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            HOLDER,
            payload,
        );
        observed_dots(&event_payload_value(&event))
            .expect_err("observed_dots is required on ak.consent.revoke");

        let mut with_dots = grant_payload();
        with_dots["observed_dots"] = json!([format!("{GRANT_EVENT}:0")]);
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            HOLDER,
            with_dots,
        );
        assert_eq!(
            observed_dots(&event_payload_value(&event)).unwrap(),
            vec![format!("{GRANT_EVENT}:0")]
        );

        let mut legacy_object = grant_payload();
        legacy_object["observed_dots"] = json!([{
            "event_id": GRANT_EVENT,
            "actor_seq": 0
        }]);
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            HOLDER,
            legacy_object,
        );
        observed_dots(&event_payload_value(&event))
            .expect_err("legacy object-shaped dots must fail closed");
    }

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            seal_compaction_min_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            ..AppConfig::test_default()
        }
    }
}
