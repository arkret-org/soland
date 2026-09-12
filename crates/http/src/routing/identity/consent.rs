//! Holder-private consent routes and admission planning.
//!
//! The consent family is a security cell whose active tagged set is executed
//! in confirmed Seal command order. `consent_id` is its subject; the holder and
//! frozen peer/scope intent identify the local read mirror. Retained grant and
//! revocation records are local audit material, not a second protocol OR-Set.
//!
//! Admission validates the holder-signed command and stages its intent. Pending
//! and rejected commands publish no consent authority or quarantine invalidation.
//! The exact committed decision replays the signed grant/revoke against the
//! transaction's current mirror and cache. Runtime readers reload that durable
//! result after the complete Seal transaction succeeds.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{CellRef, ConsentId, DidCoreId};
use arkret_models_collaboration::account_lifecycle::{
    ConsentCellList, ConsentCellView, ConsentCounterparty, ConsentGrantRequestBody, ConsentPeer,
    ConsentRequestOutcome, ConsentRequestRequestBody, ConsentRevokeRequestBody, ConsentState,
};
use arkret_models_collaboration::governance::invite_addressing::{
    HolderQuarantine, HolderQuarantineEntry, HolderQuarantineInvalidation,
    HolderQuarantineInvalidationReason, HolderQuarantineInvalidationScope, HolderQuarantineSurface,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
};
use arkret_wire::{AccountDataKey, AccountId, ConsentRequestScope, ConsentScope, Event, SealId};
use chrono::{DateTime, Utc};
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_services::events::{CommitAccountDataCas, CommitConsentProjection};
use soland_services::identity::{
    AccountDataState, ConsentCellRecord, ConsentGrantDot, SessionIdentityState as SessionRecord,
};

use super::{AuthArgs, append_audit_log, now, query_param};
use crate::routing::identity::device_messages::{
    fanout_actor_private_update, station_device_message_sender,
};
use crate::routing::invites::{
    HOLDER_QUARANTINE_TTL_DAYS, admit_quarantine_new_source, resolve_core_invite_receive_policy,
    write_holder_quarantine_entry,
};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("cells").get(list_consent_cells))
        .push(Router::with_path("cell").get(get_consent_cell))
        .push(Router::with_path("cells/grant").post(grant_consent_cell))
        .push(Router::with_path("cells/revoke").post(revoke_consent_cell))
        .push(Router::with_path("request").post(request_consent_cell))
}

// ────────────────────────────────────────────────────────────────────────
// Event admission.
// ────────────────────────────────────────────────────────────────────────

/// A consent Control Move that admission refuses before acceptance.
#[derive(Clone, Debug)]
pub(crate) struct ConsentRejection {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ConsentRejection {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn schema(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            message,
        )
    }

    fn precondition(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::PRECONDITION_FAILED, code, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
}

/// Everything one accepted consent Control Move changes, resolved before the
/// Event is accepted.
#[derive(Clone, Debug)]
pub(crate) struct ConsentAdmission {
    holder_account_id: AccountId,
    event_id: String,
    consent_id: String,
    commit: CommitConsentProjection,
    effect: ConsentAdmissionEffect,
}

#[derive(Clone, Debug)]
enum ConsentAdmissionEffect {
    Grant {
        dot: String,
    },
    Revoke {
        observed_dot_ids: Vec<String>,
        revoked_at: DateTime<Utc>,
        quarantine_entries_invalidated: usize,
    },
}

impl ConsentAdmission {
    pub(crate) fn commit(&self) -> CommitConsentProjection {
        self.commit.clone()
    }
}

/// Resolve the durable effects of a consent Control Move, or refuse it.
///
/// Returns `None` for every other Event kind. Nothing here mutates state: the
/// caller commits [`ConsentAdmission::commit`] with the canonical Event and
/// only then publishes the runtime projection through
/// [`apply_committed_consent_admission`].
pub(crate) async fn preflight_consent_admission(
    state: &AppState,
    operation: &Operation,
    event: &Event,
) -> Result<Option<ConsentAdmission>, ConsentRejection> {
    match soland_services::operation_semantics::canonical_kind(operation) {
        arkret_wire::EventKind::ConsentGrant => {
            plan_consent_grant(state, operation).await.map(Some)
        }
        arkret_wire::EventKind::ConsentRevoke => {
            plan_consent_revoke(state, operation, event).await.map(Some)
        }
        _ => Ok(None),
    }
}

/// Publish a committed consent Control Move's read-model and notification
/// effects. The durable write must already have succeeded inside the Seal transaction.
pub(crate) async fn apply_committed_consent_admission(
    state: &AppState,
    admission: &ConsentAdmission,
) {
    state
        .consents()
        .install_committed_cell(admission.commit.cell.clone());
    match &admission.effect {
        ConsentAdmissionEffect::Grant { dot } => {
            append_audit_log(
                state,
                Some(admission.holder_account_id.principal_id.as_str()),
                "consent.grant",
                json!({
                    "holder_account_id": admission.holder_account_id,
                    "peer": admission.commit.cell.peer,
                    "consent_scope": admission.commit.cell.consent_scope,
                    "consent_id": admission.consent_id,
                    "grant_event_id": admission.event_id,
                    "grant_dot": dot,
                }),
                "accepted",
            )
            .await;
        }
        ConsentAdmissionEffect::Revoke {
            observed_dot_ids,
            revoked_at,
            quarantine_entries_invalidated,
        } => {
            append_audit_log(
                state,
                Some(admission.holder_account_id.principal_id.as_str()),
                "consent.revoke",
                json!({
                    "holder_account_id": admission.holder_account_id,
                    "peer": admission.commit.cell.peer,
                    "consent_scope": admission.commit.cell.consent_scope,
                    "consent_id": admission.consent_id,
                    "revoke_event_id": admission.event_id,
                    "observed_dot_ids": observed_dot_ids,
                }),
                "accepted",
            )
            .await;
            if let Some(cas) = admission.commit.holder_quarantine.as_ref() {
                fanout_actor_private_update(
                    state,
                    admission.holder_account_id.principal_id.as_str(),
                    ActorPrivateDeviceUpdate::AccountData {
                        sender: station_device_message_sender(state),
                        content: ActorPrivateAccountDataUpdate {
                            operation: ActorPrivateAccountDataOperation::Put,
                            account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
                            revision: cas.record.revision,
                            content: Some(cas.record.payload.clone()),
                            updated_at: cas.record.updated_at,
                        },
                        created_at: cas.record.updated_at,
                    },
                )
                .await;
                append_audit_log(
                    state,
                    Some(admission.holder_account_id.principal_id.as_str()),
                    "consent.revoke.holder_quarantine_invalidation",
                    json!({
                        "holder_account_id": admission.holder_account_id,
                        "peer": admission.commit.cell.peer,
                        "consent_scope": admission.commit.cell.consent_scope,
                        "removed_entries": quarantine_entries_invalidated,
                        "revoked_at": arkret_canonical::format_timestamp_canonical(*revoked_at),
                    }),
                    "accepted",
                )
                .await;
            }
            emit_consent_revoke_invalidation(
                state,
                &admission.commit.cell,
                observed_dot_ids,
                *revoked_at,
                *quarantine_entries_invalidated,
            )
            .await;
        }
    }
}

/// Spec §3.1/§3.2 — a `consent_id` is one holder's cell subject, and the first
/// accepted grant freezes the exact `(peer, consent_scope)` intent every later
/// dot on that cell carries. A regrant adds a new Event-derived dot; a grant
/// that names the same `consent_id` with a different peer or scope is refused
/// before acceptance.
async fn plan_consent_grant(
    state: &AppState,
    operation: &Operation,
) -> Result<ConsentAdmission, ConsentRejection> {
    let holder_account_id = consent_event_holder(operation)?;
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::ConsentGrant>()
        .map_err(|error| {
            ConsentRejection::schema(format!("ak.consent.grant payload is invalid: {error}"))
        })?;
    let peer = payload.peer;
    let consent_scope = payload.consent_scope.as_str().to_owned();
    validate_consent_intent(&holder_account_id, &peer)?;
    let consent_id = payload.consent_id.to_string();
    let cell_id = consent_cell_id_for_consent_id(&consent_id)?;
    let dot = consent_grant_dot(operation);
    let granted_at = operation.created_at;

    let mut cell = match state.consents().holder_cell(&holder_account_id, &cell_id) {
        Some(existing) => {
            if existing.peer != peer || existing.consent_scope != consent_scope {
                return Err(ConsentRejection::precondition(
                    "consent_intent_rebind",
                    "consent_id is already bound to a different peer or consent_scope",
                ));
            }
            existing
        }
        None => ConsentCellRecord {
            cell_id: cell_id.clone(),
            holder_account_id: holder_account_id.clone(),
            peer: peer.clone(),
            consent_scope: consent_scope.clone(),
            active_grants: BTreeMap::new(),
            revoked_grants: BTreeMap::new(),
            updated_at: granted_at,
        },
    };
    if cell.active_grants.contains_key(&dot) || cell.revoked_grants.contains_key(&dot) {
        return Err(ConsentRejection::precondition(
            "consent_dot_replay",
            "this grant dot is already an element of the consent cell",
        ));
    }
    cell.active_grants.insert(
        dot.clone(),
        ConsentGrantDot {
            dot: dot.clone(),
            not_before: payload.not_before,
            expires_at: payload.expires_at,
            granted_at,
        },
    );
    cell.updated_at = granted_at;

    Ok(ConsentAdmission {
        holder_account_id,
        event_id: operation.context.event_id.to_string(),
        consent_id,
        commit: CommitConsentProjection {
            cell,
            holder_quarantine: None,
        },
        effect: ConsentAdmissionEffect::Grant { dot },
    })
}

/// Spec §3.3/§4.1.1 — every `observed_dot_ids[]` entry MUST resolve, under this
/// Move's own frozen `seal_basis` view, to an active add dot of the holder's
/// `consent_id` cell. Unknown, already-removed, foreign and not-yet-observable
/// dots all fail closed, and `consent_scope=any` removes exactly the dots the
/// payload names: the service never enumerates child scopes or synthesises a
/// cascade the caller did not sign.
async fn plan_consent_revoke(
    state: &AppState,
    operation: &Operation,
    event: &Event,
) -> Result<ConsentAdmission, ConsentRejection> {
    let holder_account_id = consent_event_holder(operation)?;
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::ConsentRevoke>()
        .map_err(|error| {
            ConsentRejection::schema(format!("ak.consent.revoke payload is invalid: {error}"))
        })?;
    payload.validate_minimal().map_err(|error| {
        ConsentRejection::schema(format!("ak.consent.revoke payload is invalid: {error}"))
    })?;
    let consent_id = payload.consent_id.to_string();
    let cell_id = consent_cell_id_for_consent_id(&consent_id)?;
    let observed_dot_ids = payload
        .observed_dot_ids
        .iter()
        .map(|dot| dot.as_str().to_owned())
        .collect::<Vec<_>>();
    let revoked_at = payload.revoked_at.unwrap_or(operation.created_at);

    let mut cell = state
        .consents()
        .holder_cell(&holder_account_id, &cell_id)
        .ok_or_else(|| {
            ConsentRejection::precondition(
                "consent_cell_unknown",
                "revoke consent_id does not identify a holder consent cell",
            )
        })?;
    validate_consent_intent(&holder_account_id, &cell.peer)?;

    // The reducer's removal set and the signed payload MUST be the same set
    // (§3.3): schema validation, audit projection and the state model reducer all
    // see one revocation set or none of them can be trusted.
    let projected = projected_consent_remove_dots(state, event, cell_id.as_str())?;
    let payload_set = observed_dot_ids.iter().cloned().collect::<BTreeSet<_>>();
    if payload_set.len() != observed_dot_ids.len() {
        return Err(ConsentRejection::schema(
            "ak.consent.revoke observed_dot_ids must be unique",
        ));
    }
    if projected != payload_set {
        return Err(ConsentRejection::new(
            StatusCode::BAD_REQUEST,
            "reducer_projection_failed",
            "reducer observed_dot_ids do not equal the signed payload observed_dot_ids",
        ));
    }

    // Membership first: a dot that is not an active add of this very cell is
    // refused before the Seal walk, so a foreign or replayed dot reports what
    // is wrong with it rather than what is wrong with the basis.
    for dot in &observed_dot_ids {
        let Some(grant) = cell.active_grants.get(dot) else {
            return Err(ConsentRejection::precondition(
                if cell.revoked_grants.contains_key(dot) {
                    "consent_observed_dot_removed"
                } else {
                    "consent_observed_dot_unknown"
                },
                "observed dot is not a current active grant of this consent cell",
            ));
        };
        if grant
            .expires_at
            .is_some_and(|expires_at| expires_at < revoked_at)
        {
            return Err(ConsentRejection::precondition(
                "consent_observed_dot_expired",
                "observed dot is outside its validity window",
            ));
        }
    }
    let basis_view = seal_basis_event_view(state, event).await?;
    for dot in &observed_dot_ids {
        basis_view.require_covers(state, dot).await?;
    }

    cell.revoke_grants(observed_dot_ids.iter().cloned());
    cell.updated_at = revoked_at;

    let quarantine = plan_holder_quarantine_invalidation(
        state,
        event.actor_id.as_account_id().ok_or_else(|| {
            ConsentRejection::schema("consent quarantine holder must be an Account Actor")
        })?,
        &cell.peer,
        &cell.consent_scope,
        revoked_at,
    )
    .await?;
    let quarantine_entries_invalidated = quarantine
        .as_ref()
        .map(|(_, removed)| *removed)
        .unwrap_or(0);

    Ok(ConsentAdmission {
        holder_account_id,
        event_id: operation.context.event_id.to_string(),
        consent_id,
        commit: CommitConsentProjection {
            cell,
            holder_quarantine: quarantine.map(|(cas, _)| cas),
        },
        effect: ConsentAdmissionEffect::Revoke {
            observed_dot_ids,
            revoked_at,
            quarantine_entries_invalidated,
        },
    })
}

/// Maximum Seals walked while closing one Control Move's `seal_basis`.
const MAX_CONSENT_BASIS_SEALS: usize = arkret_wire::cbs_proof_bundle::MAX_BUNDLE_SEALS;

/// The Event digests a Control Move's frozen `seal_basis` observes.
///
/// Only committed command results in the basis predecessor chain establish
/// grant observability. Rejected results and material availability do not. A dot minted by an Event
/// outside that set is one the revoker could not have observed at its own basis (§3.3).
#[derive(Clone, Debug, Default)]
struct SealBasisEventView {
    covered_event_digests: BTreeSet<String>,
}

impl SealBasisEventView {
    async fn require_covers(&self, state: &AppState, dot: &str) -> Result<(), ConsentRejection> {
        let event_ref = event_ref_for_dot(dot).ok_or_else(|| {
            ConsentRejection::schema("observed dot does not carry a canonical Event ref")
        })?;
        let record = state
            .event_queries()
            .canonical_event(event_ref)
            .await
            .map_err(|error| {
                ConsentRejection::internal(format!("observed dot Event lookup failed: {error}"))
            })?
            .ok_or_else(|| {
                ConsentRejection::precondition(
                    "consent_observed_dot_unknown",
                    "observed dot names an Event this service never accepted",
                )
            })?;
        if !self
            .covered_event_digests
            .contains(&record.canonical_digest)
        {
            return Err(ConsentRejection::precondition(
                "consent_observed_dot_not_in_basis",
                "observed dot is not visible under this Move's seal_basis",
            ));
        }
        Ok(())
    }
}

async fn seal_basis_event_view(
    state: &AppState,
    event: &Event,
) -> Result<SealBasisEventView, ConsentRejection> {
    let basis = event
        .seal_basis
        .as_ref()
        .ok_or_else(|| ConsentRejection::schema("ak.consent.revoke requires seal_basis.leaves"))?;
    if basis.leaves.is_empty() {
        return Err(ConsentRejection::schema(
            "ak.consent.revoke seal_basis.leaves must be non-empty",
        ));
    }
    let mut covered_event_digests = BTreeSet::new();
    let mut visited = BTreeSet::<String>::new();
    let mut pending: Vec<SealId> = basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.to_string()) {
            continue;
        }
        if visited.len() > MAX_CONSENT_BASIS_SEALS {
            return Err(ConsentRejection::precondition(
                "consent_seal_basis_too_large",
                "seal_basis predecessor closure exceeds the v1 limit",
            ));
        }
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .await
            .map_err(|error| {
                ConsentRejection::internal(format!("seal_basis is unavailable: {error}"))
            })?
            .ok_or_else(|| {
                ConsentRejection::precondition(
                    "consent_seal_basis_unknown",
                    "seal_basis names a Seal this service has not accepted",
                )
            })?;
        for result in &seal.command_results {
            if result.outcome == arkret_wire::CommandOutcome::Committed {
                covered_event_digests.extend(
                    result
                        .unit_event_digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned()),
                );
            }
        }
        pending.extend(seal.predecessor_ref.iter().cloned());
    }
    Ok(SealBasisEventView {
        covered_event_digests,
    })
}

/// The registered reducer's own removal set for this revoke Event.
fn projected_consent_remove_dots(
    state: &AppState,
    event: &Event,
    cell_id: &str,
) -> Result<BTreeSet<String>, ConsentRejection> {
    let writes = state
        .projections()
        .project_cell_writes(event)
        .map_err(|error| {
            ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                format!("ak.consent.revoke does not project its registered cell writes: {error}"),
            )
        })?;
    let mut dots = BTreeSet::new();
    for write in writes {
        if write.cell_id.as_str() != cell_id {
            return Err(ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke projects a write outside its own consent cell",
            ));
        }
        let arkret_wire::cbs::ProjectedOp::Direct(op) = &write.op else {
            return Err(ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke must project direct active-set remove ops",
            ));
        };
        if op.op_type != arkret_wire::cbs::LatticeOpType::Remove {
            return Err(ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke must project only active-set remove ops",
            ));
        }
        let tag = op.tag.clone().ok_or_else(|| {
            ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke remove op carries no dot",
            )
        })?;
        if !dots.insert(tag) {
            return Err(ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke projects a duplicate remove dot",
            ));
        }
    }
    Ok(dots)
}

// ────────────────────────────────────────────────────────────────────────
// Holder-private routes.
// ────────────────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ak.self.consent.read.list",
    summary = "List consent cells",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.read.list.v1"))]
async fn list_consent_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCellList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder_account_id = authenticated_holder_account_id(state, &session.actor)?;
    let now = now();
    // Consent is holder-private (spec section 8): only the holder's own cells
    // are listed, never the cells a peer appears in.
    let mut cells = state
        .consents()
        .holder_cells(&holder_account_id)
        .iter()
        .map(|cell| consent_response(cell, now))
        .collect::<Result<Vec<_>, _>>()?;
    cells.sort_by(|a, b| a.cell_id.cmp(&b.cell_id));
    json_ok(ConsentCellList {
        consent_cell_views: cells,
    })
}

#[endpoint(
    operation_id = "ak.self.consent.resource.get",
    summary = "Get one consent cell",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.resource.get.v1"))]
async fn get_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder_account_id = authenticated_holder_account_id(state, &session.actor)?;
    let peer =
        query_param(req, "peer").ok_or_else(|| AppError::param_missing("peer is required"))?;
    let peer: ConsentPeer = serde_json::from_str(&peer)
        .map_err(|error| AppError::param_invalid(format!("invalid consent peer: {error}")))?;
    let consent_scope = normalize_scope(query_param(req, "consent_scope").as_deref())?;
    let matches = state
        .consents()
        .cells_for_intent(&holder_account_id, &peer, &consent_scope);
    match matches.as_slice() {
        [cell] => json_ok(consent_response(cell, now())?),
        [] => Err(AppError::not_found("consent cell not found")),
        // The binding addresses one cell per (holder, peer, consent_scope).
        // Two consent_ids on the same intent make this address ambiguous, and
        // answering with either one would report a partial view as the whole.
        _ => Err(crate::app_error!(
            Conflict,
            "more than one consent cell carries this intent",
        )),
    }
}

#[endpoint(
    operation_id = "ak.self.consent.command.grant",
    summary = "Grant a consent cell",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.grant.v1"))]
async fn grant_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentGrantRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder_account_id = authenticated_holder_account_id(state, &session.actor)?;
    let submission = body.into_inner().grant_event;
    let consent_id = caller_signed_consent_event_identity(
        &session.actor,
        &holder_account_id,
        &submission.event,
        arkret_wire::EventKind::ConsentGrant.as_str(),
    )?;
    submit_caller_signed_consent_event(state, &session, submission).await?;
    read_back_consent_cell(state, &holder_account_id, &consent_id)
}

#[endpoint(
    operation_id = "ak.self.consent.command.revoke",
    summary = "Revoke a consent cell",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.revoke.v1"))]
async fn revoke_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRevokeRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder_account_id = authenticated_holder_account_id(state, &session.actor)?;
    let submission = body.into_inner().revoke_event;
    // The dots being removed come from the Event the holder signed, never from
    // a server-side enumeration: a confirmed active-set revoke is only
    // correct when the revoker named the dots it observed.
    let consent_id = caller_signed_consent_event_identity(
        &session.actor,
        &holder_account_id,
        &submission.event,
        arkret_wire::EventKind::ConsentRevoke.as_str(),
    )?;
    submit_caller_signed_consent_event(state, &session, submission).await?;
    read_back_consent_cell(state, &holder_account_id, &consent_id)
}

#[endpoint(
    operation_id = "ak.self.consent.command.request",
    summary = "Request consent from a peer",
    tags("consent")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.request.v1"))]
async fn request_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRequestRequestBody>,
) -> JsonResult<ConsentRequestOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let requester_principal_id = DidCoreId::new(session.actor.clone())
        .map_err(|e| AppError::internal(format!("authenticated actor is invalid: {e}")))?;
    // The scope enum is already the section 4 vocabulary without `invite`:
    // `ConsentRequestScope` has no invite variant, so an invite-scope request is
    // refused by body deserialization rather than being stored as a branch the
    // schema forbids. Caller-shape rejection is not a holder signal.
    let consent_scope = body.consent_scope.unwrap_or(ConsentRequestScope::DEFAULT);
    body.holder_account_id.validate().map_err(|error| {
        AppError::param_invalid(format!("holder_account_id is invalid: {error}"))
    })?;
    // Everything past this point is holder-dependent, so it never changes the
    // response. `consent-model.md` section 6.1.1 keeps five outcomes -- admitted
    // to quarantine, anti-abuse drop, TTL discard, unknown holder, holder policy
    // deny -- byte-identical, and section 6.1.2 adds this operation to that class.
    admit_consent_request_quarantine_entry(
        state,
        &body.holder_account_id,
        &requester_principal_id,
        consent_scope,
    )
    .await?;
    json_ok(ConsentRequestOutcome {
        accepted_for_processing: true,
    })
}

/// Run `ak.self.consent.command.request.v1` through the section 6.1.1
/// chokepoint the invite delivery surface already uses.
///
/// Ordering is normative: live-entry deduplication first, because section
/// 6.1.1.4 makes a repeat request while an entry is still live a no-op that
/// MUST NOT bill the quota; then the shared new-source ledger; then the shared
/// CAS write. Every refusal returns `Ok(())` and leaves the opaque outcome
/// untouched -- only an infrastructure failure is an error, and even that is
/// mapped by the caller into the same response.
async fn admit_consent_request_quarantine_entry(
    state: &AppState,
    holder_account_id: &AccountId,
    requester_principal_id: &DidCoreId,
    consent_scope: ConsentRequestScope,
) -> Result<(), AppError> {
    if holder_account_id.station_id != state.service_core_id()
        || holder_account_id.principal_id == *requester_principal_id
    {
        return Ok(());
    }
    let holder_exists = state
        .identities()
        .account(holder_account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    if !holder_exists {
        return Ok(());
    }

    let policy = resolve_core_invite_receive_policy(state, holder_account_id);
    let requester_actor = arkret_wire::ActorId::account(AccountId::new(
        requester_principal_id.clone(),
        state.service_core_id(),
    ));
    // A consent request carries no introduction evidence at all, so under the
    // `require_explicit_consent` profile it can never be the `consent_grant`
    // evidence that profile admits: it is always a silent drop there.
    if policy
        .denied_actor_ids
        .iter()
        .any(|actor| actor == &requester_actor)
        || policy.consent_profile.requires_explicit_consent()
    {
        return Ok(());
    }

    let received_at = now();
    let holder = arkret_wire::ActorId::account(holder_account_id.clone()).to_string();
    let existing = state
        .account_data()
        .entry(&holder, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
        .await
        .map_err(|error| {
            AppError::internal(format!("holder quarantine cell is unavailable: {error}"))
        })?;
    if let Some(existing) = existing.as_ref() {
        let cell: HolderQuarantine =
            serde_json::from_value(existing.payload.clone()).map_err(|error| {
                AppError::internal(format!("invalid holder quarantine cell: {error}"))
            })?;
        if cell
            .live_consent_request(requester_principal_id, consent_scope)
            .is_some()
        {
            // Section 6.1.1.4, consent_request branch: while one entry for
            // `(account_id, source_peer_principal_id, consent_scope)` is live the
            // repeat is a no-op. No second entry, no ledger charge, no new TTL.
            return Ok(());
        }
    }

    if !admit_quarantine_new_source(
        state,
        holder_account_id,
        requester_principal_id.as_str(),
        received_at,
    )
    .await?
    {
        return Ok(());
    }

    // `entry_digest` is required on both branches, but it is not a second
    // deduplication rule here: it is the live key itself, hashed. Deriving it
    // from anything else would let two entries share the live key while carrying
    // different digests, which is exactly the two-rule split the ruling refused.
    let entry_digest = crate::util::canonical_digest(&json!({
        "account_id": holder_account_id,
        "source_peer_principal_id": requester_principal_id,
        "surface_kind": "consent_request",
        "consent_scope": consent_scope,
    }))?;
    let entry = HolderQuarantineEntry {
        entry_digest: arkret_wire::Hash::new(entry_digest)
            .map_err(|error| AppError::internal(format!("holder quarantine digest: {error}")))?,
        account_id: holder_account_id.clone(),
        source_peer_principal_id: requester_principal_id.clone(),
        // The authenticated transport source of a self operation is this
        // Station: the requester reached the holder without a peer hop.
        source_id: state.service_core_id(),
        surface: HolderQuarantineSurface::ConsentRequest { consent_scope },
        received_at,
        expires_at: received_at + chrono::Duration::days(HOLDER_QUARANTINE_TTL_DAYS),
    };
    let written = write_holder_quarantine_entry(
        state,
        holder_account_id,
        holder_account_id.principal_id.as_str(),
        entry,
        received_at,
    )
    .await?;
    append_audit_log(
        state,
        Some(holder_account_id.principal_id.as_str()),
        "self.consent.request.quarantine",
        json!({
            "holder_id": holder_account_id.principal_id,
            "source_peer_principal_id": requester_principal_id,
            "consent_scope": consent_scope,
        }),
        if written { "accepted" } else { "skipped" },
    )
    .await;
    Ok(())
}

fn read_back_consent_cell(
    state: &AppState,
    holder_account_id: &AccountId,
    consent_id: &str,
) -> JsonResult<ConsentCellView> {
    let cell_id = consent_cell_id_for_consent_id(consent_id)
        .map_err(|rejection| AppError::param_invalid(rejection.message))?;
    let cell = state
        .consents()
        .holder_cell(holder_account_id, &cell_id)
        .ok_or_else(|| {
            AppError::internal("consent event accepted but the cell was not projected")
        })?;
    json_ok(consent_response(&cell, now())?)
}

/// Check what the request wrapper alone can decide about a caller-signed
/// consent Control Move, and report the consent_id it names.
///
/// The signature, envelope shape, the holder authority-root authorization and
/// the security-cell command contract are shared Event validation's job. This covers
/// only the bindings between the authenticated session, the path holder and the
/// Event that was submitted.
fn caller_signed_consent_event_identity(
    actor: &str,
    holder_account_id: &AccountId,
    event: &Event,
    expected_kind: &str,
) -> Result<String, AppError> {
    if event.kind.as_str() != expected_kind {
        return Err(AppError::param_invalid(format!(
            "submitted Event kind must be {expected_kind}"
        )));
    }
    if event.actor_id.as_account_id() != Some(holder_account_id) {
        return Err(AppError::param_invalid(
            "the submitted Event must be authored by the exact holder account",
        ));
    }
    if actor != holder_account_id.principal_id.as_str() {
        return Err(AppError::capability_denied(
            "only the holder account may update a consent cell",
        ));
    }
    let consent_id = event
        .payload
        .get("consent_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_missing("consent_id is required"))?;
    ConsentId::new(consent_id.to_owned())
        .map(ConsentId::into_string)
        .map_err(|_| {
            AppError::param_invalid("consent_id must be an ak:consent:<UUIDv7> identifier")
        })
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
                error.status(),
                error.code(),
                &error.message(),
            )
        })
}

// ────────────────────────────────────────────────────────────────────────
// Shared consent vocabulary.
// ────────────────────────────────────────────────────────────────────────

/// Concrete action scopes a `consent_scope=any` grant can satisfy.
pub const CONSENT_ACTION_SCOPE_CASCADE: &[&str] = &[
    "invite",
    "direct_message",
    "voice_call",
    "video_call",
    "presence",
];

/// Spec section 4.1.2 — downstream cache scopes a consent revoke MUST eagerly
/// invalidate.
pub const CONSENT_SCOPE_CASCADE: &[&str] = &[
    "directory_reachability",
    "mimi_consent",
    "push_contact_psi",
    "invite_gate",
    "in_flight_invite",
];

/// Spec section 4.1.2 — the cache-invalidation channels a consent revoke MUST
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

/// Read-surface `consent_scope` query parameter. The enum is closed, so an
/// unlisted value is rejected rather than coerced.
pub(super) fn normalize_scope(input: Option<&str>) -> Result<String, AppError> {
    let raw = input.unwrap_or("direct_message").trim();
    if raw.is_empty() {
        return Ok("direct_message".to_owned());
    }
    raw.parse::<ConsentScope>()
        .map(|scope| scope.as_str().to_owned())
        .map_err(|_| {
            AppError::param_invalid(
                "consent_scope must be invite, direct_message, voice_call, video_call, presence, or any",
            )
        })
}

fn consent_cell_id_for_consent_id(consent_id: &str) -> Result<CellRef, ConsentRejection> {
    let consent_id = ConsentId::new(consent_id.to_owned()).map_err(|_| {
        ConsentRejection::schema("consent_id must be an ak:consent:<UUIDv7> identifier")
    })?;
    arkret_state::consent::consent_cell_id(&consent_id)
        .map_err(|error| ConsentRejection::internal(format!("consent cell id: {error}")))
}

/// Spec section 2.1 — the Event actor and the authenticated holder are the same
/// principal, and consent state is written only into that holder's own cell.
fn consent_event_holder(operation: &Operation) -> Result<AccountId, ConsentRejection> {
    operation
        .context
        .sender
        .as_account_id()
        .cloned()
        .ok_or_else(|| ConsentRejection::schema("consent holder must be an Account Actor"))
}

fn authenticated_holder_account_id(state: &AppState, actor: &str) -> Result<AccountId, AppError> {
    let principal_id = DidCoreId::new(actor.to_owned())
        .map_err(|error| AppError::internal(format!("authenticated actor is invalid: {error}")))?;
    Ok(AccountId::new(
        principal_id,
        state.service_core_id().clone(),
    ))
}

/// Spec section 3.2 Event admission: closed shape, `ak:did_core:key:` form for
/// the pairwise branch, and peer principal != holder principal. No foreign
/// Realm is queried here — "only an accepted binding counts" is a match-time
/// condition (section 6.1 query step 1), so an unaccepted, cross-Realm or
/// invented pairwise value simply yields an entry that never matches.
fn validate_consent_intent(
    holder_account_id: &AccountId,
    peer: &ConsentPeer,
) -> Result<(), ConsentRejection> {
    peer.validate_admission_form(&holder_account_id.principal_id)
        .map_err(|error| ConsentRejection::schema(error.to_string()))
}

fn consent_grant_dot(operation: &Operation) -> String {
    format!("{}:0", operation.context.event_id)
}

// ────────────────────────────────────────────────────────────────────────
// Effective consent (spec section 5).
// ────────────────────────────────────────────────────────────────────────

/// Active dots of one cell: added, not observed-removed, and inside their
/// validity window.
fn active_grant_dots(cell: &ConsentCellRecord, at: DateTime<Utc>) -> Vec<String> {
    cell.active_grants
        .iter()
        .filter(|(_, grant)| grant.is_active_at(at))
        .map(|(_, grant)| grant.dot.clone())
        .collect()
}

/// Spec `sync/invite-addressing.md` section 2 — verify a `consent_grant`
/// introduction evidence. The `consent_grant_ref` (and optional `consent_id`)
/// MUST resolve to an **active** grant dot in `subject`'s (the invitee_id's)
/// consent cell whose peer matches the authenticated inviter and whose
/// `consent_scope` is in `{invite, any}`, unrevoked and unexpired. Returns
/// `true` only when such a dot exists. On any mismatch the caller MUST
/// downgrade the delivery to the low-trust `explicit_address` path.
///
/// `inviter_actor_id` is the **complete** ActorId that signed the durable
/// `ak.invite.create` Event, and consent-model.md section 6.1 query step 1
/// matches it as such: Station and actor role are part of the identity, so an
/// invite authored from another Station or in another actor role by the same
/// principal core is a different peer and finds no grant. An invite is always
/// authored by an Account or service Actor, never by a Realm-local ephemeral
/// pairwise actor, so this gate only ever resolves the `{kind:"actor"}` lane
/// and `{kind:"pairwise_principal"}` entries are structurally unreachable
/// from here.
pub(crate) fn has_active_consent_grant_evidence(
    state: &AppState,
    subject: &str,
    holder_station_id: &str,
    inviter_actor_id: &arkret_wire::ActorId,
    consent_grant_ref: &str,
    consent_id: Option<&str>,
    at: DateTime<Utc>,
) -> bool {
    let grant_ref = consent_grant_ref.trim();
    if grant_ref.is_empty() {
        return false;
    }
    let expected_cell_id = match consent_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(consent_id) => match consent_cell_id_for_consent_id(consent_id) {
            Ok(cell_id) => Some(cell_id),
            Err(_) => return false,
        },
        None => None,
    };
    let (Ok(holder_principal_id), Ok(holder_station_id)) = (
        DidCoreId::new(subject.to_owned()),
        DidCoreId::new(holder_station_id.to_owned()),
    ) else {
        return false;
    };
    let holder_account_id = arkret_wire::AccountId::new(holder_principal_id, holder_station_id);
    let inviter = ConsentCounterparty::actor(inviter_actor_id.clone());
    state
        .consents()
        .cells_for_counterparty(&holder_account_id, &inviter)
        .iter()
        .any(|cell| {
            if !matches!(cell.consent_scope.as_str(), "invite" | "any") {
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

/// A consent grant dot is `{event_id}:{write_index}`. The `consent_grant_ref`
/// carried in introduction evidence is the originating Event id; match it
/// against the dot's event-id segment as well as the whole dot string.
fn grant_dot_matches_ref(dot: &str, grant_ref: &str) -> bool {
    if dot == grant_ref {
        return true;
    }
    event_ref_for_dot(dot).is_some_and(|event_ref| event_ref == grant_ref)
}

/// Extract the canonical Event id encoded in a grant dot, if any.
///
/// `EventId` values may themselves be `:`-delimited, so we strip only the
/// trailing `:<write_index>` segment rather than splitting on the first `:`.
/// The result is validated through `EventId::new` so callers can rely on it
/// being a well-formed event ref.
pub(crate) fn event_ref_for_dot(dot: &str) -> Option<&str> {
    if dot.contains('#') {
        return None;
    }
    let candidate = match dot.rsplit_once(':') {
        Some((prefix, seq)) if seq.chars().all(|c| c.is_ascii_digit()) && !seq.is_empty() => prefix,
        _ => dot,
    };
    arkret_identifiers::EventId::new(candidate)
        .ok()
        .map(|_| candidate)
}

fn consent_response(
    cell: &ConsentCellRecord,
    at: DateTime<Utc>,
) -> Result<ConsentCellView, AppError> {
    let active_grant_dots = active_grant_dots(cell, at);
    Ok(ConsentCellView {
        cell_id: cell.cell_id.to_string(),
        peer: cell.peer.clone(),
        consent_scope: cell
            .consent_scope
            .parse()
            .map_err(|e| AppError::internal(format!("stored consent_scope: {e}")))?,
        state: if active_grant_dots.is_empty() {
            ConsentState::NoConsent
        } else {
            ConsentState::Active
        },
        expires_at: cell
            .active_grants
            .values()
            .max_by_key(|grant| grant.granted_at)
            .and_then(|grant| grant.expires_at),
        requested_at: None,
        updated_at: cell.updated_at,
        active_grant_dots,
        grant_dots: cell
            .active_grants
            .keys()
            .chain(cell.revoked_grants.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        revoked_dots: cell.revoked_grants.keys().cloned().collect(),
    })
}

// ────────────────────────────────────────────────────────────────────────
// Eager cache invalidation (spec section 4.1.2).
// ────────────────────────────────────────────────────────────────────────

/// Resolve the holder-quarantine mutation a revoke owes, without writing it.
///
/// Returns the staged CAS and how many `pending_review` entries it drops. The
/// write itself happens inside the Event commit transaction, so a revoke that
/// cannot invalidate is never accepted.
///
/// The quarantine ledger keys new sources on the section 6.1.1.2 quota
/// identity, whose peer component is the principal part of the **complete**
/// inviter ActorId. Only the `{kind:"actor"}` branch can therefore address an
/// entry: a Realm-local ephemeral pairwise actor exists solely inside its own
/// minimal-metadata Realm and never authors an invite delivery into a holder
/// Principal Control Realm, so a pairwise revoke invalidates nothing here
/// rather than reaching entries by a bare principal core.
async fn plan_holder_quarantine_invalidation(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    peer: &ConsentPeer,
    consent_scope: &str,
    revoked_at: DateTime<Utc>,
) -> Result<Option<(CommitAccountDataCas, usize)>, ConsentRejection> {
    if !matches!(consent_scope, "invite" | "any") {
        return Ok(None);
    }
    let ConsentPeer::Actor { actor_id: peer } = peer else {
        return Ok(None);
    };
    let peer = peer.signing_principal_id().as_str();
    if account_id.station_id != state.service_core_id() {
        return Err(ConsentRejection::schema(
            "consent quarantine holder must belong to this Station",
        ));
    }
    let holder = arkret_wire::ActorId::account(account_id.clone()).to_string();
    let existing = state
        .account_data()
        .entry(&holder, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
        .await
        .map_err(|error| {
            ConsentRejection::internal(format!("holder quarantine cell is unavailable: {error}"))
        })?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let mut quarantine: HolderQuarantine = serde_json::from_value(existing.payload.clone())
        .map_err(|error| {
            ConsentRejection::internal(format!("invalid holder quarantine cell: {error}"))
        })?;
    quarantine.validate_holder(account_id).map_err(|error| {
        ConsentRejection::internal(format!("holder quarantine binding: {error}"))
    })?;
    let mut removed = 0usize;
    quarantine.quarantine_entries.retain(|entry| {
        let matches_peer = entry.source_peer_principal_id.as_str() == peer;
        if matches_peer {
            removed += 1;
        }
        !matches_peer && entry.expires_at > revoked_at
    });
    if removed == 0 {
        return Ok(None);
    }
    quarantine.updated_at = revoked_at;
    quarantine.last_invalidation = Some(HolderQuarantineInvalidation {
        reason: HolderQuarantineInvalidationReason::ConsentRevoke,
        peer_principal_id: DidCoreId::new(peer.to_owned()).map_err(|error| {
            ConsentRejection::internal(format!("invalid revoked peer: {error}"))
        })?,
        consent_scope: if consent_scope == "any" {
            HolderQuarantineInvalidationScope::Any
        } else {
            HolderQuarantineInvalidationScope::Invite
        },
        revoked_at,
        removed_entries: removed as u64,
    });
    quarantine.validate_holder(account_id).map_err(|error| {
        ConsentRejection::internal(format!("holder quarantine binding: {error}"))
    })?;
    let record = AccountDataState {
        actor_id: holder.to_owned(),
        account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
        revision: existing.revision + 1,
        payload: serde_json::to_value(quarantine).map_err(|error| {
            ConsentRejection::internal(format!("holder quarantine encode: {error}"))
        })?,
        tombstone: false,
        updated_at: revoked_at,
    };
    Ok(Some((
        CommitAccountDataCas {
            record,
            expected_revision: existing.revision,
            conflict_code: "cas_conflict".to_owned(),
        },
        removed,
    )))
}

/// Record the eager invalidation a committed revoke performed.
///
/// A `consent_scope=any` revoke invalidates every concrete scope's cache
/// entries; that is a cache rule, not a state model rule, so it never adds or
/// removes a dot the payload did not name.
async fn emit_consent_revoke_invalidation(
    state: &AppState,
    cell: &ConsentCellRecord,
    observed_dot_ids: &[String],
    revoked_at: DateTime<Utc>,
    quarantine_entries_invalidated: usize,
) {
    let invalidated_action_scopes = if cell.consent_scope == "any" {
        std::iter::once("any")
            .chain(CONSENT_ACTION_SCOPE_CASCADE.iter().copied())
            .collect::<Vec<_>>()
    } else {
        vec![cell.consent_scope.as_str()]
    };
    let target_peer_ids =
        consent_invalidation_peer_ids(state, &cell.holder_account_id, &cell.peer).await;
    let payload = json!({
        "schema": "ak.vector.consent.cache_invalidation.v1",
        "holder_account_id": cell.holder_account_id,
        "peer": cell.peer,
        "consent_scope": cell.consent_scope,
        "cell_id": cell.cell_id,
        "invalidated_action_scopes": invalidated_action_scopes,
        "invalidated_cache_scopes": CONSENT_SCOPE_CASCADE,
        "invalidated_channels": ConsentRevokeInvalidationChannel::ALL
            .iter()
            .map(|channel| channel.as_str())
            .collect::<Vec<_>>(),
        "target_peer_ids": target_peer_ids,
        "local_quarantine_entries_invalidated": quarantine_entries_invalidated,
        "eager_invalidation": true,
        "removed_dots": observed_dot_ids,
        "revoked_dots": cell.revoked_grants.keys().cloned().collect::<Vec<_>>(),
        "revoked_at": arkret_canonical::format_timestamp_canonical(revoked_at),
    });
    append_audit_log(
        state,
        Some(cell.holder_account_id.principal_id.as_str()),
        "consent.revoke.cache_invalidation",
        payload,
        "accepted",
    )
    .await;
}

/// Downstream services that hold a cached view of this `(holder, peer)` pair.
///
/// Contact records address both sides by complete ActorId, so the lookup does
/// too. A Realm-local ephemeral pairwise peer has no Contact record and no
/// hosting Station of its own to notify, so it resolves to no target rather
/// than to whatever Contact happens to share its principal core.
async fn consent_invalidation_peer_ids(
    state: &AppState,
    holder_account_id: &AccountId,
    peer: &ConsentPeer,
) -> Vec<String> {
    let ConsentPeer::Actor { actor_id: peer } = peer else {
        return Vec::new();
    };
    let mut services = BTreeSet::new();
    let holder_actor = arkret_wire::ActorId::account(holder_account_id.clone());
    let records = match state.contacts().contacts_for_actor(&holder_actor).await {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(
                %error,
                actor = %holder_actor,
                holder = %holder_account_id.principal_id,
                peer = %peer,
                "failed to list contacts for consent invalidation target discovery"
            );
            return Vec::new();
        }
    };
    for record in records {
        let same_pair = (record.requester_id == holder_actor && record.target_id == *peer)
            || (record.requester_id == *peer && record.target_id == holder_actor);
        if !same_pair {
            continue;
        }
        if let Some(service_id) = record
            .peer_host_id
            .as_ref()
            .filter(|value| value.as_str() != state.service_id())
        {
            services.insert(service_id.to_string());
        }
    }
    services.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use soland_services::identity::{DeviceIdentity, SaveDeviceCommand};
    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};
    use crate::routing::events::event_log::projection_operation_from_envelope;

    const HOLDER: &str = "ak:did_core:web:holder.example";
    const HOLDER_STATION: &str = "ak:did_core:web:soland.test";
    const PEER: &str = "ak:did_core:web:peer.example";
    const OTHER_PEER: &str = "ak:did_core:web:second-peer.example";
    const CONSENT_ID: &str = "ak:consent:01964137-0000-7000-8000-000000000041";
    const OTHER_CONSENT_ID: &str = "ak:consent:01964137-0000-7000-8000-000000000042";
    const GRANT_EVENT: &str = "ak:event:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV";
    const REVOKE_EVENT: &str = "ak:event:AdOBf6fvL9Q7FrkkRwDrquZ52Nky2-aShGC7r3Pl6WsP";
    const HOLDER_PCR: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
    const BASIS_SEAL: &str =
        "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            ..AppConfig::test_default()
        }
    }

    fn production_test_config() -> AppConfig {
        AppConfig {
            development_mode: false,
            seed_demo_data: false,
            ..test_config()
        }
    }

    fn consent_envelope(kind: &str, event_id: &str, actor: &str, payload: Value) -> Value {
        json!({
            "event_id": event_id,
            "kind": kind,
            "realm_id": HOLDER_PCR,
            "scope_ref": { "kind": "realm", "realm_id": HOLDER_PCR },
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": actor, "station_id": HOLDER_STATION
            }},
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "seal_basis": { "leaves": [BASIS_SEAL] },
            "payload": payload,
            "proofs": [],
        })
    }

    fn consent_event(kind: &str, event_id: &str, actor: &str, payload: Value) -> Event {
        serde_json::from_value(consent_envelope(kind, event_id, actor, payload))
            .expect("consent envelope")
    }

    fn consent_operation(kind: &str, event_id: &str, actor: &str, payload: Value) -> Operation {
        projection_operation_from_envelope(&consent_envelope(kind, event_id, actor, payload))
            .expect("consent operation")
    }

    fn holder_account_id() -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new(HOLDER.to_owned()).unwrap(),
            DidCoreId::new(HOLDER_STATION.to_owned()).unwrap(),
        )
    }

    fn grant_payload(peer: &str, consent_scope: &str) -> Value {
        json!({
            "consent_id": CONSENT_ID,
            "peer": {"kind": "actor", "actor_id": {"kind": "account", "account_id": {
                "principal_id": peer,
                "station_id": crate::test_event::station_id().to_string()
            }}},
            "consent_scope": consent_scope,
        })
    }

    fn revoke_payload(dots: Value) -> Value {
        json!({
            "consent_id": CONSENT_ID,
            "observed_dot_ids": dots,
            "revoked_at": "2026-07-06T00:00:00.000Z",
        })
    }

    fn granted_cell(
        consent_id: &str,
        peer: &str,
        consent_scope: &str,
        dot: &str,
    ) -> ConsentCellRecord {
        ConsentCellRecord {
            cell_id: consent_cell_id_for_consent_id(consent_id).expect("cell id"),
            holder_account_id: holder_account_id(),
            peer: ConsentPeer::Actor {
                actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(peer.to_owned()).unwrap(),
                    crate::test_event::station_id(),
                )),
            },
            consent_scope: consent_scope.to_owned(),
            active_grants: BTreeMap::from([(
                dot.to_owned(),
                ConsentGrantDot {
                    dot: dot.to_owned(),
                    not_before: None,
                    expires_at: None,
                    granted_at: Utc::now(),
                },
            )]),
            revoked_grants: BTreeMap::new(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn consent_revoke_cache_invalidation_table_is_closed() {
        assert_eq!(ConsentRevokeInvalidationChannel::ALL.len(), 5);
        assert_eq!(CONSENT_SCOPE_CASCADE.len(), 5);
        assert_eq!(CONSENT_ACTION_SCOPE_CASCADE.len(), 5);
        assert_eq!(ConsentScope::ALL.len(), 6);
    }

    #[test]
    fn only_the_closed_consent_scope_enum_is_accepted() {
        assert_eq!(normalize_scope(None).unwrap(), "direct_message");
        assert_eq!(normalize_scope(Some("any")).unwrap(), "any");
        // Unregistered values fail at both query and signed-payload boundaries.
        normalize_scope(Some("dm")).expect_err("dm is not a consent_scope");
        serde_json::from_value::<
            arkret_models_collaboration::events_payloads::ConsentGrantPayload,
        >(grant_payload(PEER, "messaging"))
        .expect_err("messaging is not a consent_scope");
    }

    #[tokio::test]
    async fn a_first_grant_freezes_the_consent_id_intent() {
        let state = AppState::new(test_config(), Db { pool: None });
        let operation = consent_operation(
            arkret_wire::EventKind::ConsentGrant.as_str(),
            GRANT_EVENT,
            HOLDER,
            grant_payload(PEER, "invite"),
        );
        let admission = plan_consent_grant(&state, &operation)
            .await
            .expect("first grant is admissible");
        let cell = &admission.commit.cell;
        assert_eq!(
            cell.cell_id.as_str(),
            format!("ak:cell:ak.component.consent.grant.v1:{CONSENT_ID}")
        );
        assert_eq!(
            cell.peer,
            ConsentPeer::Actor {
                actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(PEER.to_owned()).unwrap(),
                    crate::test_event::station_id(),
                )),
            }
        );
        assert_eq!(cell.consent_scope, "invite");
        assert_eq!(
            cell.active_grants.keys().cloned().collect::<Vec<_>>(),
            vec![format!("{GRANT_EVENT}:0")]
        );
        // Nothing is written before the Event commits.
        assert!(
            state
                .consents()
                .holder_cells(&holder_account_id())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_grant_may_not_rebind_a_consent_id_to_another_peer_or_scope() {
        let state = AppState::new(test_config(), Db { pool: None });
        state
            .consents()
            .install_committed_cell(granted_cell(CONSENT_ID, PEER, "invite", "seed:0"));
        for payload in [
            grant_payload(OTHER_PEER, "invite"),
            grant_payload(PEER, "direct_message"),
        ] {
            let operation = consent_operation(
                arkret_wire::EventKind::ConsentGrant.as_str(),
                GRANT_EVENT,
                HOLDER,
                payload,
            );
            let rejection = plan_consent_grant(&state, &operation)
                .await
                .expect_err("a consent_id binds exactly one intent");
            assert_eq!(rejection.code, "consent_intent_rebind");
        }
    }

    #[tokio::test]
    async fn a_regrant_adds_a_new_dot_on_the_same_intent() {
        let state = AppState::new(test_config(), Db { pool: None });
        state.consents().install_committed_cell(granted_cell(
            CONSENT_ID,
            PEER,
            "invite",
            "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA:0",
        ));
        let operation = consent_operation(
            arkret_wire::EventKind::ConsentGrant.as_str(),
            GRANT_EVENT,
            HOLDER,
            grant_payload(PEER, "invite"),
        );
        let admission = plan_consent_grant(&state, &operation)
            .await
            .expect("regrant on the same intent is normative");
        assert_eq!(admission.commit.cell.active_grants.len(), 2);
    }

    #[tokio::test]
    async fn a_revoke_without_its_cell_fails_closed() {
        let state = AppState::new(test_config(), Db { pool: None });
        let operation = consent_operation(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            revoke_payload(json!([format!("{GRANT_EVENT}:0")])),
        );
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            revoke_payload(json!([format!("{GRANT_EVENT}:0")])),
        );
        let rejection = plan_consent_revoke(&state, &operation, &event)
            .await
            .expect_err("an unknown consent_id must fail closed");
        assert_eq!(rejection.code, "consent_cell_unknown");
    }

    #[tokio::test]
    async fn a_revoke_naming_a_foreign_or_removed_dot_fails_closed() {
        let state = AppState::new(test_config(), Db { pool: None });
        let mut cell = granted_cell(CONSENT_ID, PEER, "invite", &format!("{GRANT_EVENT}:0"));
        state.consents().install_committed_cell(granted_cell(
            OTHER_CONSENT_ID,
            PEER,
            "presence",
            "other:0",
        ));

        // A dot that belongs to no add op of this cell.
        state.consents().install_committed_cell(cell.clone());
        let unknown_dot = format!("{REVOKE_EVENT}:0");
        let payload = revoke_payload(json!([unknown_dot]));
        let operation = consent_operation(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            payload.clone(),
        );
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            payload,
        );
        assert_eq!(
            plan_consent_revoke(&state, &operation, &event)
                .await
                .expect_err("unknown dots fail closed")
                .code,
            "consent_observed_dot_unknown"
        );

        // A dot this cell already observed as removed.
        cell.revoke_grants([format!("{GRANT_EVENT}:0")]);
        state.consents().install_committed_cell(cell);
        let payload = revoke_payload(json!([format!("{GRANT_EVENT}:0")]));
        let operation = consent_operation(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            payload.clone(),
        );
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            payload,
        );
        assert_eq!(
            plan_consent_revoke(&state, &operation, &event)
                .await
                .expect_err("already-removed dots fail closed")
                .code,
            "consent_observed_dot_removed"
        );
    }

    #[tokio::test]
    async fn a_revoke_whose_basis_is_unknown_fails_closed() {
        let state = AppState::new(test_config(), Db { pool: None });
        state.consents().install_committed_cell(granted_cell(
            CONSENT_ID,
            PEER,
            "any",
            &format!("{GRANT_EVENT}:0"),
        ));
        let payload = revoke_payload(json!([format!("{GRANT_EVENT}:0")]));
        let operation = consent_operation(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            payload.clone(),
        );
        let event = consent_event(
            arkret_wire::EventKind::ConsentRevoke.as_str(),
            REVOKE_EVENT,
            HOLDER,
            payload,
        );
        let rejection = plan_consent_revoke(&state, &operation, &event)
            .await
            .expect_err("a basis this service never accepted cannot resolve dots");
        assert_eq!(rejection.code, "consent_seal_basis_unknown");
        // A scope=any revoke never enumerates the concrete-scope cells.
        assert_eq!(state.consents().holder_cells(&holder_account_id()).len(), 1);
    }

    #[test]
    fn a_dot_outside_its_validity_window_is_not_active() {
        let now = Utc::now();
        let mut cell = granted_cell(CONSENT_ID, PEER, "invite", "dot:0");
        cell.active_grants.get_mut("dot:0").unwrap().not_before =
            Some(now + chrono::Duration::hours(1));
        assert!(active_grant_dots(&cell, now).is_empty());
        cell.active_grants.get_mut("dot:0").unwrap().not_before = None;
        cell.active_grants.get_mut("dot:0").unwrap().expires_at =
            Some(now - chrono::Duration::hours(1));
        assert!(active_grant_dots(&cell, now).is_empty());
        cell.active_grants.get_mut("dot:0").unwrap().expires_at = None;
        assert_eq!(active_grant_dots(&cell, now), vec!["dot:0".to_owned()]);
    }

    #[tokio::test]
    async fn quarantine_invalidation_is_planned_before_acceptance_and_fanned_out_after() {
        let state = AppState::new(production_test_config(), Db { pool: None });
        let holder_account =
            arkret_wire::AccountId::new(DidCoreId::new(HOLDER).unwrap(), state.service_core_id());
        let holder_actor = arkret_wire::ActorId::account(holder_account.clone()).to_string();
        let device_id = "ak:device:01904100-0000-7000-8000-0000000000f1";
        let updated_at = arkret_canonical::canonical::normalize_timestamp_canonical(now());
        state
            .identities()
            .save_device(SaveDeviceCommand {
                actor_id: HOLDER.to_owned(),
                device_id: device_id.to_owned(),
                display_name: None,
                device: DeviceIdentity {
                    actor_id: HOLDER.to_owned(),
                    device_id: device_id.to_owned(),
                    display_name: None,
                    verification_state: "verified".to_owned(),
                    payload: json!({"device_id": device_id}),
                    created_at: updated_at,
                    updated_at,
                    revoked_at: None,
                },
            })
            .await
            .expect("holder device");
        let initial = AccountDataState {
            actor_id: holder_actor.clone(),
            account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
            revision: 1,
            payload: json!({
                "schema": "ak.schema.holder_quarantine.v1",
                "quarantine_entries": [{
                    "entry_digest": format!("sha256:{}", "a".repeat(64)),
                    "account_id": { "principal_id": HOLDER, "station_id": state.service_id() },
                    "source_peer_principal_id": PEER,
                    "source_id": state.service_id(),
                    "surface_kind": "invite_delivery",
                    "consent_scope": "invite",
                    "introduction_kind": "explicit_address",
                    "effective_kind": "explicit_address",
                    "trust_tier": "low",
                    "invite_event_id": arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x42; 32]),
                    "request_digest": format!("sha256:{}", "c".repeat(64)),
                    "idempotency_key_digest": format!("sha256:{}", "d".repeat(64)),
                    "received_at": arkret_canonical::format_timestamp_canonical(updated_at),
                    "expires_at": arkret_canonical::format_timestamp_canonical(updated_at + chrono::Duration::days(1)),
                }],
                "updated_at": arkret_canonical::format_timestamp_canonical(updated_at),
            }),
            tombstone: false,
            updated_at,
        };
        assert!(matches!(
            state
                .account_data()
                .compare_and_set(initial, 0)
                .await
                .expect("seed quarantine cell"),
            soland_services::identity::AccountDataCasOutcome::Applied(_)
        ));

        let revoked_at = updated_at + chrono::Duration::seconds(1);
        let foreign_holder = arkret_wire::AccountId::new(
            holder_account.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        // The seeded entry names PEER as its source principal, so the peer this
        // plan matches on is that principal hosted by this Station.
        let peer = ConsentPeer::Actor {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new(PEER.to_owned()).unwrap(),
                state.service_core_id(),
            )),
        };
        plan_holder_quarantine_invalidation(&state, &foreign_holder, &peer, "invite", revoked_at)
            .await
            .expect_err("the same principal at another Station cannot revoke this quarantine");
        let (cas, removed) = plan_holder_quarantine_invalidation(
            &state,
            &holder_account,
            &peer,
            "invite",
            revoked_at,
        )
        .await
        .expect("quarantine invalidation plan")
        .expect("one pending entry matches the revoked peer");
        assert_eq!(removed, 1);
        assert_eq!(cas.expected_revision, 1);
        assert_eq!(cas.record.revision, 2);
        assert_eq!(cas.record.payload["quarantine_entries"], json!([]));
        assert!(cas.record.payload.get("entries").is_none());
        // Planning is read-only: the durable cell only changes with the Event.
        assert_eq!(
            state
                .account_data()
                .entry(&holder_actor, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
                .await
                .expect("quarantine cell")
                .expect("seeded cell")
                .revision,
            1
        );

        let mut cell = granted_cell(CONSENT_ID, PEER, "invite", &format!("{GRANT_EVENT}:0"));
        cell.revoke_grants([format!("{GRANT_EVENT}:0")]);
        let admission = ConsentAdmission {
            holder_account_id: arkret_wire::AccountId::new(
                DidCoreId::new(HOLDER.to_owned()).unwrap(),
                crate::test_event::station_id(),
            ),
            event_id: REVOKE_EVENT.to_owned(),
            consent_id: CONSENT_ID.to_owned(),
            commit: CommitConsentProjection {
                cell,
                holder_quarantine: Some(cas),
            },
            effect: ConsentAdmissionEffect::Revoke {
                observed_dot_ids: vec![format!("{GRANT_EVENT}:0")],
                revoked_at,
                quarantine_entries_invalidated: removed,
            },
        };
        apply_committed_consent_admission(&state, &admission).await;

        let queued = state
            .deliveries()
            .device_messages_after(HOLDER, device_id, 0, 101)
            .await
            .expect("holder to-device queue");
        assert_eq!(queued.len(), 1);
        let envelopes = crate::routing::identity::device_messages::device_message_envelopes_after(
            &state, &queued,
        );
        assert_eq!(envelopes.len(), 1, "service envelope parses without repair");
        let envelope = &envelopes[0];
        assert_eq!(envelope.recipient_account_id.principal_id.as_str(), HOLDER);
        assert_eq!(
            envelope.recipient_account_id.station_id.as_str(),
            state.service_id()
        );
        assert!(matches!(
            &envelope.sender,
            crate::wire::DeviceMessageSender::Service { sender_id }
                if sender_id.as_str() == state.service_id()
        ));
        let content = serde_json::to_value(&envelope.content).unwrap();
        assert_eq!(content.get("revision"), Some(&json!(2)));
        assert_eq!(
            state
                .consents()
                .holder_cell(
                    &holder_account_id(),
                    consent_cell_id_for_consent_id(CONSENT_ID).unwrap(),
                )
                .expect("committed cell is published to the runtime projection")
                .revoked_grants
                .len(),
            1
        );
    }
}

/// `ak.self.consent.command.request.v1` admission.
///
/// Section 6.1.2 makes this operation write one `surface_kind="consent_request"`
/// entry through the section 6.1.1 chokepoint, and section 6.1.1.4 deduplicates
/// that branch by holder-local live-entry uniqueness rather than by a digest the
/// request has no source for.
#[cfg(test)]
mod consent_request_admission_tests {
    use arkret_models_collaboration::governance::invite_addressing::HolderQuarantineSurfaceKind;
    use soland_services::identity::AccountProfileState;
    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    const HOLDER: &str = "ak:did_core:web:request-holder.example";
    const REQUESTER: &str = "ak:did_core:web:request-peer.example";
    const OTHER_REQUESTER: &str = "ak:did_core:web:request-peer-two.example";

    fn request_test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: false,
            seed_demo_data: false,
            ..AppConfig::test_default()
        }
    }

    async fn holder_state(config: AppConfig) -> AppState {
        let state = AppState::new(config, Db { pool: None });
        state
            .identities()
            .save_account(AccountProfileState {
                pk: soland_storage::AccountPk(0),
                account_id: holder_account(&state),
                principal_id: DidCoreId::new(HOLDER.to_owned()).unwrap(),
                localpart: "request-holder".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: now(),
            })
            .await
            .expect("holder account");
        state
    }

    fn holder_account(state: &AppState) -> AccountId {
        AccountId::new(
            DidCoreId::new(HOLDER.to_owned()).unwrap(),
            state.service_core_id(),
        )
    }

    async fn quarantine_cell(state: &AppState) -> Option<HolderQuarantine> {
        let holder = arkret_wire::ActorId::account(holder_account(state)).to_string();
        state
            .account_data()
            .entry(&holder, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
            .await
            .expect("holder quarantine cell")
            .map(|record| {
                serde_json::from_value(record.payload).expect("cell decodes as the closed shape")
            })
    }

    #[tokio::test]
    async fn a_non_invite_scope_request_lands_in_the_consent_request_branch() {
        let state = holder_state(request_test_config()).await;
        let requester = DidCoreId::new(REQUESTER.to_owned()).unwrap();
        admit_consent_request_quarantine_entry(
            &state,
            &holder_account(&state),
            &requester,
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("consent request admission");

        let cell = quarantine_cell(&state)
            .await
            .expect("one entry was written");
        cell.validate_holder(&holder_account(&state))
            .expect("the written cell binds its holder");
        assert_eq!(cell.quarantine_entries.len(), 1);
        let entry = &cell.quarantine_entries[0];
        assert_eq!(
            entry.surface_kind(),
            HolderQuarantineSurfaceKind::ConsentRequest
        );
        assert_eq!(entry.consent_scope(), ConsentScope::DirectMessage);
        assert_eq!(entry.source_peer_principal_id, requester);
        // The branch carries no Event reference and neither digest: the type has
        // no place to put one, and the wire form must not grow one either.
        let encoded = serde_json::to_value(entry).unwrap();
        for absent in [
            "invite_event_id",
            "request_digest",
            "idempotency_key_digest",
            "introduction_kind",
            "effective_kind",
            "trust_tier",
            "status",
        ] {
            assert!(encoded.get(absent).is_none(), "{absent} leaked");
        }
    }

    #[tokio::test]
    async fn a_repeat_request_while_the_entry_is_live_is_a_no_op() {
        let state = holder_state(request_test_config()).await;
        let requester = DidCoreId::new(REQUESTER.to_owned()).unwrap();
        for _ in 0..3 {
            admit_consent_request_quarantine_entry(
                &state,
                &holder_account(&state),
                &requester,
                ConsentRequestScope::DirectMessage,
            )
            .await
            .expect("consent request admission");
        }
        let cell = quarantine_cell(&state)
            .await
            .expect("one entry was written");
        assert_eq!(
            cell.quarantine_entries.len(),
            1,
            "live-entry uniqueness, not a digest, is the deduplication rule"
        );

        // A different scope for the same requester is a different live key, so
        // it is a second pending item rather than a replay.
        admit_consent_request_quarantine_entry(
            &state,
            &holder_account(&state),
            &requester,
            ConsentRequestScope::VoiceCall,
        )
        .await
        .expect("consent request admission");
        let cell = quarantine_cell(&state).await.expect("two entries");
        assert_eq!(cell.quarantine_entries.len(), 2);
        cell.validate_holder(&holder_account(&state))
            .expect("two distinct live keys are legal");
    }

    #[tokio::test]
    async fn an_unknown_holder_and_a_self_addressed_request_write_nothing() {
        let state = holder_state(request_test_config()).await;
        let requester = DidCoreId::new(REQUESTER.to_owned()).unwrap();
        let unknown = AccountId::new(
            DidCoreId::new("ak:did_core:web:absent-holder.example".to_owned()).unwrap(),
            state.service_core_id(),
        );
        admit_consent_request_quarantine_entry(
            &state,
            &unknown,
            &requester,
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("an unknown holder is not an error the requester can see");

        let foreign = AccountId::new(
            DidCoreId::new(HOLDER.to_owned()).unwrap(),
            DidCoreId::new("ak:did_core:web:other-station.example".to_owned()).unwrap(),
        );
        admit_consent_request_quarantine_entry(
            &state,
            &foreign,
            &requester,
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("a holder hosted elsewhere is not this Station's cell");

        let holder_principal = DidCoreId::new(HOLDER.to_owned()).unwrap();
        admit_consent_request_quarantine_entry(
            &state,
            &holder_account(&state),
            &holder_principal,
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("a self-addressed request needs no consent");
        assert!(quarantine_cell(&state).await.is_none());
    }

    #[tokio::test]
    async fn the_require_explicit_consent_profile_drops_silently() {
        let state = holder_state(request_test_config()).await;
        let holder = holder_account(&state);
        let mut policy = arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::spec_default(holder.clone());
        policy.consent_profile = arkret_wire::ConsentProfile::RequireExplicitConsent;
        state
            .contacts()
            .apply_committed_invite_policy(holder.clone(), policy);
        admit_consent_request_quarantine_entry(
            &state,
            &holder,
            &DidCoreId::new(REQUESTER.to_owned()).unwrap(),
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("a policy deny is not visible to the requester");
        assert!(
            quarantine_cell(&state).await.is_none(),
            "a consent request carries no introduction evidence, so it can never \
             be the consent_grant evidence this profile admits"
        );
    }

    #[tokio::test]
    async fn the_new_source_quota_is_shared_with_invite_delivery() {
        let mut config = request_test_config();
        config.receive_policy_constraints = Some(arkret_wire::ReceivePolicyConstraints {
            policy_version: None,
            applies_to: None,
            deployment_allowed_introduction_kinds: None,
            deployment_denied_introduction_kinds: Vec::new(),
            handle_claim_max_behavior: None,
            explicit_address_max_behavior: None,
            unknown_invites_max_behavior: None,
            new_source_quota: Some(arkret_wire::receive_policy::NewSourceQuotaConstraints {
                window_seconds: Some(3_600),
                default_new_sources_per_window: Some(1),
                max_new_sources_per_window: Some(10),
                retention_seconds: Some(7_200),
                default_new_sources_per_retention: Some(30),
                max_new_sources_per_retention: Some(200),
            }),
            disclosure_max: None,
            allowed_handle_domains: None,
            trusted_handle_issuer_ids: None,
            trusted_directory_ids: None,
            trusted_source_ids: None,
            denied_source_ids: None,
            accepted_subject_did_methods: None,
        });
        let state = holder_state(config).await;
        let holder = holder_account(&state);
        admit_consent_request_quarantine_entry(
            &state,
            &holder,
            &DidCoreId::new(REQUESTER.to_owned()).unwrap(),
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("first source fits the ceiling");
        admit_consent_request_quarantine_entry(
            &state,
            &holder,
            &DidCoreId::new(OTHER_REQUESTER.to_owned()).unwrap(),
            ConsentRequestScope::DirectMessage,
        )
        .await
        .expect("the second source is dropped, not rejected");
        let cell = quarantine_cell(&state)
            .await
            .expect("one entry was written");
        assert_eq!(
            cell.quarantine_entries.len(),
            1,
            "the second distinct source is over the shared ceiling"
        );
        assert_eq!(
            cell.quarantine_entries[0].source_peer_principal_id.as_str(),
            REQUESTER
        );
    }
}

/// Spec `zh/identity/consent-model.md` section 6.1 query step 1 — the peer of a
/// consent entry is matched by kind, exactly, and never across kinds.
///
/// Every case here used to be a *hit* while `consent_peer_principal` folded
/// both branches down to a bare `DidCoreId`, so each one is a closed
/// escalation path rather than a hypothetical.
#[cfg(test)]
mod consent_peer_exact_matching_tests {
    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::AppConfig;

    const HOLDER: &str = "ak:did_core:web:holder-matching.example";
    const HOLDER_STATION: &str = "ak:did_core:web:soland.test";
    const PEER_CORE: &str = "ak:did_core:web:peer-matching.example";
    const PEER_STATION: &str = "ak:did_core:web:station-one.example";
    const OTHER_STATION: &str = "ak:did_core:web:station-two.example";
    const PAIRWISE_KEY: &str = "ak:did_core:key:z6MkfixturePairwiseMatching";
    const REALM: &str = "ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    const OTHER_REALM: &str = "ak:realm:Abqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    const MATCHING_CONSENT_ID: &str = "ak:consent:01964137-0000-7000-8000-000000000051";
    const MATCHING_GRANT_EVENT: &str = "ak:event:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV";

    fn state() -> AppState {
        AppState::new(
            AppConfig {
                development_mode: true,
                ..AppConfig::test_default()
            },
            Db { pool: None },
        )
    }

    fn core(value: &str) -> DidCoreId {
        DidCoreId::new(value.to_owned()).expect("did core id")
    }

    fn realm(value: &str) -> arkret_wire::RealmId {
        arkret_wire::RealmId::new(value.to_owned()).expect("realm id")
    }

    fn account_actor(principal: &str, station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(core(principal), core(station)))
    }

    fn holder() -> AccountId {
        arkret_wire::AccountId::new(core(HOLDER), core(HOLDER_STATION))
    }

    /// A committed `invite` cell whose frozen intent is `peer`, carrying one
    /// active dot minted by [`MATCHING_GRANT_EVENT`].
    fn install_invite_cell(state: &AppState, peer: ConsentPeer) {
        state.consents().install_committed_cell(ConsentCellRecord {
            cell_id: consent_cell_id_for_consent_id(MATCHING_CONSENT_ID).expect("cell id"),
            holder_account_id: holder(),
            peer,
            consent_scope: "invite".to_owned(),
            active_grants: BTreeMap::from([(
                format!("{MATCHING_GRANT_EVENT}:0"),
                ConsentGrantDot {
                    dot: format!("{MATCHING_GRANT_EVENT}:0"),
                    not_before: None,
                    expires_at: None,
                    granted_at: Utc::now(),
                },
            )]),
            revoked_grants: BTreeMap::new(),
            updated_at: Utc::now(),
        });
    }

    /// The invite gate verdict for one authenticated inviter ActorId.
    fn invite_gate_admits(state: &AppState, inviter: &arkret_wire::ActorId) -> bool {
        has_active_consent_grant_evidence(
            state,
            HOLDER,
            HOLDER_STATION,
            inviter,
            MATCHING_GRANT_EVENT,
            Some(MATCHING_CONSENT_ID),
            Utc::now(),
        )
    }

    #[tokio::test]
    async fn the_exact_granted_actor_still_matches() {
        let state = state();
        install_invite_cell(
            &state,
            ConsentPeer::Actor {
                actor_id: account_actor(PEER_CORE, PEER_STATION),
            },
        );
        assert!(invite_gate_admits(
            &state,
            &account_actor(PEER_CORE, PEER_STATION)
        ));
    }

    /// Negative 1 — same principal core, different Station.
    #[tokio::test]
    async fn a_different_station_with_the_same_core_is_a_different_peer() {
        let state = state();
        install_invite_cell(
            &state,
            ConsentPeer::Actor {
                actor_id: account_actor(PEER_CORE, PEER_STATION),
            },
        );
        assert!(!invite_gate_admits(
            &state,
            &account_actor(PEER_CORE, OTHER_STATION)
        ));
    }

    /// Negative 2 — same principal core, different actor role.
    #[tokio::test]
    async fn a_different_actor_role_with_the_same_core_is_a_different_peer() {
        let state = state();
        install_invite_cell(
            &state,
            ConsentPeer::Actor {
                actor_id: account_actor(PEER_CORE, PEER_STATION),
            },
        );
        assert!(!invite_gate_admits(
            &state,
            &arkret_wire::ActorId::service(core(PEER_CORE))
        ));
    }

    /// Negative 3 — the same pairwise key bound in another Realm.
    #[tokio::test]
    async fn the_same_pairwise_key_in_another_realm_is_a_different_peer() {
        let state = state();
        install_invite_cell(
            &state,
            ConsentPeer::PairwisePrincipal {
                realm_id: realm(REALM),
                principal_id: core(PAIRWISE_KEY),
            },
        );
        let granted_realm =
            ConsentCounterparty::realm_local_pairwise(realm(REALM), core(PAIRWISE_KEY))
                .expect("verified pairwise counterparty");
        let other_realm =
            ConsentCounterparty::realm_local_pairwise(realm(OTHER_REALM), core(PAIRWISE_KEY))
                .expect("verified pairwise counterparty");
        assert_eq!(
            state
                .consents()
                .cells_for_counterparty(&holder(), &granted_realm)
                .len(),
            1
        );
        assert!(
            state
                .consents()
                .cells_for_counterparty(&holder(), &other_realm)
                .is_empty(),
            "(realm_id, principal_id) is the isolation key and MUST NOT aggregate across Realms"
        );
    }

    /// Negative 4 — a pairwise value impersonating an ordinary Account, and the
    /// mirror image of it. Neither kind may reach the entry of the other.
    #[tokio::test]
    async fn the_two_peer_kinds_never_reach_each_other() {
        let pairwise_entry = state();
        install_invite_cell(
            &pairwise_entry,
            ConsentPeer::PairwisePrincipal {
                realm_id: realm(REALM),
                principal_id: core(PAIRWISE_KEY),
            },
        );
        // An ordinary Account whose principal core is the pairwise key.
        assert!(!invite_gate_admits(
            &pairwise_entry,
            &account_actor(PAIRWISE_KEY, PEER_STATION)
        ));
        assert!(!invite_gate_admits(
            &pairwise_entry,
            &arkret_wire::ActorId::service(core(PAIRWISE_KEY))
        ));

        let actor_entry = state();
        install_invite_cell(
            &actor_entry,
            ConsentPeer::Actor {
                actor_id: account_actor(PAIRWISE_KEY, PEER_STATION),
            },
        );
        let pairwise = ConsentCounterparty::realm_local_pairwise(realm(REALM), core(PAIRWISE_KEY))
            .expect("verified pairwise counterparty");
        assert!(
            actor_entry
                .consents()
                .cells_for_counterparty(&holder(), &pairwise)
                .is_empty(),
            "an Account entry MUST NOT be reachable through the pairwise lane"
        );
    }

    /// Negative 5 — the counterparty is not the actor projected by the target
    /// Realm current active LeafNode.
    ///
    /// Admission never queries a foreign Realm (section 3.2), so a holder can
    /// write a pairwise entry for a Realm it has no accepted binding in. The
    /// entry is inert: a counterparty only enters the pairwise lane once its
    /// caller has verified the active-leaf binding, and every gate that cannot
    /// verify one presents an ordinary Actor counterparty instead, which the
    /// pairwise entry refuses. Equivalent to no-consent, fail closed.
    #[tokio::test]
    async fn an_unbound_pairwise_entry_is_inert() {
        let state = state();
        let peer = ConsentPeer::PairwisePrincipal {
            realm_id: realm(OTHER_REALM),
            principal_id: core(PAIRWISE_KEY),
        };
        // Admission accepts the form without reaching into OTHER_REALM.
        peer.validate_admission_form(&core(HOLDER))
            .expect("admission validates form only");
        install_invite_cell(&state, peer);

        // No gate in this deployment can authenticate a Realm-local pairwise
        // actor, so nothing ever reaches the entry.
        assert!(!invite_gate_admits(
            &state,
            &account_actor(PAIRWISE_KEY, HOLDER_STATION)
        ));
        assert!(
            state
                .consents()
                .cells_for_counterparty(
                    &holder(),
                    &ConsentCounterparty::actor(account_actor(PAIRWISE_KEY, HOLDER_STATION)),
                )
                .is_empty()
        );
        // A verified binding in the Realm the holder actually named is the only
        // thing that reaches it.
        assert_eq!(
            state
                .consents()
                .cells_for_counterparty(
                    &holder(),
                    &ConsentCounterparty::realm_local_pairwise(
                        realm(OTHER_REALM),
                        core(PAIRWISE_KEY)
                    )
                    .expect("verified pairwise counterparty"),
                )
                .len(),
            1
        );
    }

    /// An ordinary account principal MUST NOT be smuggled into the pairwise
    /// branch: the `ak:did_core:key:` form is an admission-time check.
    #[test]
    fn the_pairwise_branch_admits_only_did_key_projections() {
        let peer = ConsentPeer::PairwisePrincipal {
            realm_id: realm(REALM),
            principal_id: core(PEER_CORE),
        };
        assert!(peer.validate_admission_form(&core(HOLDER)).is_err());
        assert!(
            ConsentCounterparty::realm_local_pairwise(realm(REALM), core(PEER_CORE)).is_err(),
            "an ordinary account principal is not a Realm-local pairwise actor"
        );
    }
}
