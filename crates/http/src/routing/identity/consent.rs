//! Holder-private consent cell routes and Event admission.
//!
//! `ak.component.consent.grant.v1` is an observe-remove OR-Set whose subject is
//! the caller-minted `consent_id` (spec `zh/identity/consent-model.md` §3.1), so
//! a cell is addressed by `(holder, cell_id)` and carries the `(peer,
//! consent_scope)` intent its first accepted grant froze. Contact and Personal
//! DM authority are separate and never consult this projection.
//!
//! `grant` and `revoke` take the holder-signed `ak.consent.grant` /
//! `ak.consent.revoke` Control Move and submit those exact bytes through
//! ordinary Event admission. The or_set dot is `ak:event:<event_id>:<write_index>`
//! and the cell subject is the caller's `consent_id`, so the service chooses
//! neither (§3.1, §3.2). A dot no Event produced would be an element in
//! replicated state that nothing in the log explains, and revoke targets dots by
//! value.
//!
//! Admission is the only writer. [`preflight_consent_admission`] resolves the
//! whole cell mutation and its eager cache invalidation *before* the Event is
//! accepted and hands them to the Event commit unit of work; a rejected Move
//! leaves no accepted Event, no cell mutation and no invalidation behind
//! (spec section 4.1.2 puts them inside one transaction boundary).

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{CellRef, ConsentId, DidCoreId};
use arkret_models_collaboration::account_lifecycle::{
    ConsentCellList, ConsentCellView, ConsentGrantRequestBody, ConsentRequestOutcome,
    ConsentRequestRequestBody, ConsentRevokeRequestBody, ConsentState,
};
use arkret_models_collaboration::governance::invite_addressing::{
    InviteQuarantine, InviteQuarantineInvalidation, InviteQuarantineInvalidationReason,
    InviteQuarantineInvalidationScope,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
};
use arkret_wire::{AccountDataKey, ConsentScope, Event, SealId};
use chrono::{DateTime, Utc};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_services::events::{CommitAccountDataCas, CommitConsentProjection};
use soland_services::identity::{
    AccountDataState, ConsentCellRecord, ConsentGrantDot, SessionIdentityState as SessionRecord,
};

use super::{AuthArgs, append_audit_log, now, query_param};
use crate::routing::identity::device_messages::{
    fanout_actor_private_update, station_device_message_sender,
};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("cells").get(list_consent_cells))
        .push(Router::with_path("cells/{holder_principal_id}").get(get_consent_cell))
        .push(Router::with_path("cells/{holder_principal_id}/grant").post(grant_consent_cell))
        .push(Router::with_path("cells/{holder_principal_id}/revoke").post(revoke_consent_cell))
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
    holder: DidCoreId,
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
/// effects. The durable write already succeeded inside the Event transaction.
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
                Some(admission.holder.as_str()),
                "consent.grant",
                json!({
                    "holder_principal_id": admission.holder,
                    "peer_principal_id": admission.commit.cell.peer_principal_id,
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
                Some(admission.holder.as_str()),
                "consent.revoke",
                json!({
                    "holder_principal_id": admission.holder,
                    "peer_principal_id": admission.commit.cell.peer_principal_id,
                    "consent_scope": admission.commit.cell.consent_scope,
                    "consent_id": admission.consent_id,
                    "revoke_event_id": admission.event_id,
                    "observed_dot_ids": observed_dot_ids,
                }),
                "accepted",
            )
            .await;
            if let Some(cas) = admission.commit.invite_quarantine.as_ref() {
                fanout_actor_private_update(
                    state,
                    admission.holder.as_str(),
                    ActorPrivateDeviceUpdate::AccountData {
                        sender: station_device_message_sender(state),
                        content: ActorPrivateAccountDataUpdate {
                            operation: ActorPrivateAccountDataOperation::Put,
                            account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
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
                    Some(admission.holder.as_str()),
                    "consent.revoke.invite_quarantine_invalidation",
                    json!({
                        "holder_principal_id": admission.holder,
                        "peer_principal_id": admission.commit.cell.peer_principal_id,
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
    let holder = consent_event_holder(operation)?;
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::ConsentGrant>()
        .map_err(|error| {
            ConsentRejection::schema(format!("ak.consent.grant payload is invalid: {error}"))
        })?;
    let peer = payload.peer_id;
    let consent_scope = payload.consent_scope.as_str().to_owned();
    validate_consent_intent(&holder, &peer)?;
    let consent_id = payload.consent_id.to_string();
    let cell_id = consent_cell_id_for_consent_id(&consent_id)?;
    let dot = consent_grant_dot(operation);
    let granted_at = operation.created_at;

    let mut cell = match state.consents().holder_cell(&holder, &cell_id) {
        Some(existing) => {
            if existing.peer_principal_id != peer || existing.consent_scope != consent_scope {
                return Err(ConsentRejection::precondition(
                    "consent_intent_rebind",
                    "consent_id is already bound to a different peer or consent_scope",
                ));
            }
            existing
        }
        None => ConsentCellRecord {
            cell_id: cell_id.clone(),
            holder_principal_id: holder.clone(),
            peer_principal_id: peer.clone(),
            consent_scope: consent_scope.clone(),
            grant_dots: BTreeMap::new(),
            revoked_dots: BTreeSet::new(),
            updated_at: granted_at,
        },
    };
    if cell.grant_dots.contains_key(&dot) || cell.revoked_dots.contains(&dot) {
        return Err(ConsentRejection::precondition(
            "consent_dot_replay",
            "this grant dot is already an element of the consent cell",
        ));
    }
    cell.grant_dots.insert(
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
        holder,
        event_id: operation.context.event_id.to_string(),
        consent_id,
        commit: CommitConsentProjection {
            cell,
            invite_quarantine: None,
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
    let holder = consent_event_holder(operation)?;
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
        .holder_cell(&holder, &cell_id)
        .ok_or_else(|| {
            ConsentRejection::precondition(
                "consent_cell_unknown",
                "revoke consent_id does not identify a holder consent cell",
            )
        })?;
    validate_consent_intent(&holder, &cell.peer_principal_id)?;

    // The reducer's removal set and the signed payload MUST be the same set
    // (§3.3): schema validation, audit projection and the lattice reducer all
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
        let Some(grant) = cell.grant_dots.get(dot) else {
            return Err(ConsentRejection::precondition(
                "consent_observed_dot_unknown",
                "observed dot is not an add dot of this consent cell",
            ));
        };
        if cell.revoked_dots.contains(dot) {
            return Err(ConsentRejection::precondition(
                "consent_observed_dot_removed",
                "observed dot was already removed from this consent cell",
            ));
        }
        if grant
            .expires_at
            .is_some_and(|expires_at| expires_at <= revoked_at)
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

    cell.revoked_dots.extend(observed_dot_ids.iter().cloned());
    cell.updated_at = revoked_at;

    let quarantine = plan_invite_quarantine_invalidation(
        state,
        holder.as_str(),
        cell.peer_principal_id.as_str(),
        &cell.consent_scope,
        revoked_at,
    )
    .await?;
    let quarantine_entries_invalidated = quarantine
        .as_ref()
        .map(|(_, removed)| *removed)
        .unwrap_or(0);

    Ok(ConsentAdmission {
        holder,
        event_id: operation.context.event_id.to_string(),
        consent_id,
        commit: CommitConsentProjection {
            cell,
            invite_quarantine: quarantine.map(|(cas, _)| cas),
        },
        effect: ConsentAdmissionEffect::Revoke {
            observed_dot_ids,
            revoked_at,
            quarantine_entries_invalidated,
        },
    })
}

/// Maximum Seals walked while closing one Control Move's `seal_basis`.
const MAX_CONSENT_BASIS_SEALS: usize = arkret_wire::cba_proof_bundle::MAX_BUNDLE_SEALS;

/// The Event digests a Control Move's frozen `seal_basis` observes.
///
/// Cumulative coverage of a Seal is `delta` plus everything its predecessors
/// covered, so the view is the union over the basis leaves' predecessor
/// closure. A dot minted by an Event outside that set is one the revoker could
/// not have observed at its own basis (§3.3).
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
            .map_err(|error| {
                ConsentRejection::internal(format!("seal_basis is unavailable: {error}"))
            })?
            .ok_or_else(|| {
                ConsentRejection::precondition(
                    "consent_seal_basis_unknown",
                    "seal_basis names a Seal this service has not accepted",
                )
            })?;
        for digest in seal.delta.iter().chain(seal.covered_event_digests.iter()) {
            covered_event_digests.insert(digest.as_str().to_owned());
        }
        pending.extend(seal.predecessor_refs.iter().cloned());
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
        let arkret_wire::cba::ProjectedOp::Direct(op) = &write.op else {
            return Err(ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke must project direct or_set remove ops",
            ));
        };
        if op.op_type != arkret_wire::cba::LatticeOpType::Remove {
            return Err(ConsentRejection::new(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "ak.consent.revoke must project only or_set remove ops",
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
    let now = now();
    // Consent is holder-private (spec section 8): only the holder's own cells
    // are listed, never the cells a peer appears in.
    let mut cells = state
        .consents()
        .holder_cells(&session.actor)
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
    authorize_reader(&session.actor, &holder)?;
    let consent_scope = normalize_scope(query_param(req, "consent_scope").as_deref())?;
    let matches = state
        .consents()
        .cells_for_intent(&holder, &peer, &consent_scope);
    match matches.as_slice() {
        [cell] => json_ok(consent_response(cell, now())?),
        [] => Err(AppError::not_found("consent cell not found")),
        // The binding addresses one cell per (holder, peer, consent_scope).
        // Two consent_ids on the same intent make this address ambiguous, and
        // answering with either one would report a partial view as the whole.
        _ => Err(AppError::new(
            ErrorCode::Conflict,
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
    holder_principal_id: PathParam<String>,
    body: JsonBody<ConsentGrantRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_principal_id.into_inner();
    let submission = body.into_inner().grant_event;
    let consent_id = caller_signed_consent_event_identity(
        &session.actor,
        &holder,
        &submission.event,
        arkret_wire::EventKind::ConsentGrant.as_str(),
    )?;
    submit_caller_signed_consent_event(state, &session, submission).await?;
    read_back_consent_cell(state, &holder, &consent_id)
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
    holder_principal_id: PathParam<String>,
    body: JsonBody<ConsentRevokeRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_principal_id.into_inner();
    let submission = body.into_inner().revoke_event;
    // The dots being removed come from the Event the holder signed, never from
    // a server-side enumeration: an observe-remove OR-Set revoke is only
    // correct when the revoker named the dots it observed.
    let consent_id = caller_signed_consent_event_identity(
        &session.actor,
        &holder,
        &submission.event,
        arkret_wire::EventKind::ConsentRevoke.as_str(),
    )?;
    submit_caller_signed_consent_event(state, &session, submission).await?;
    read_back_consent_cell(state, &holder, &consent_id)
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
    let _peer = arkret_identifiers::DidCoreId::new(session.actor.clone())
        .map_err(|e| AppError::internal(format!("authenticated actor is invalid: {e}")))?;
    // Syntactic validation is safe, but holder existence, policy, rate-limit,
    // silent drop and quarantine admission are intentionally indistinguishable.
    // This operation never creates a consent cell or a pending consent state.
    let _ = normalize_scope(body.consent_scope.as_ref().map(|scope| scope.as_str()))?;
    let _ = body.holder_principal_id;
    json_ok(ConsentRequestOutcome {
        accepted_for_processing: true,
    })
}

fn read_back_consent_cell(
    state: &AppState,
    holder: &str,
    consent_id: &str,
) -> JsonResult<ConsentCellView> {
    let cell_id = consent_cell_id_for_consent_id(consent_id)
        .map_err(|rejection| AppError::param_invalid(rejection.message))?;
    let holder = DidCoreId::new(holder.to_owned())
        .map_err(|_| AppError::param_invalid("invalid holder principal id"))?;
    let cell = state
        .consents()
        .holder_cell(&holder, &cell_id)
        .ok_or_else(|| {
            AppError::internal("consent event accepted but the cell was not projected")
        })?;
    json_ok(consent_response(&cell, now())?)
}

/// Check what the request wrapper alone can decide about a caller-signed
/// consent Control Move, and report the consent_id it names.
///
/// The signature, envelope shape, the holder authority-root authorization and
/// the whole OR-Set contract are ordinary Event admission's job. This covers
/// only the bindings between the authenticated session, the path holder and the
/// Event that was submitted.
fn caller_signed_consent_event_identity(
    actor: &str,
    holder: &str,
    event: &Event,
    expected_kind: &str,
) -> Result<String, AppError> {
    if event.kind.as_str() != expected_kind {
        return Err(AppError::param_invalid(format!(
            "submitted Event kind must be {expected_kind}"
        )));
    }
    if DidCoreId::new(holder.to_owned()).is_err() {
        return Err(AppError::param_invalid("invalid holder principal id"));
    }
    if event.actor_id.signing_principal_id().as_str() != holder {
        return Err(AppError::param_invalid(
            "the submitted Event must be authored by the path holder",
        ));
    }
    if actor != holder {
        return Err(AppError::capability_denied(
            "only the holder DID may update a consent cell",
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
                error.status,
                error.code,
                &error.message,
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
fn consent_event_holder(operation: &Operation) -> Result<DidCoreId, ConsentRejection> {
    Ok(operation.context.sender.signing_principal_id().clone())
}

fn validate_consent_intent(holder: &DidCoreId, peer: &DidCoreId) -> Result<(), ConsentRejection> {
    if peer == holder {
        return Err(ConsentRejection::schema(
            "peer DID must differ from holder DID",
        ));
    }
    Ok(())
}

fn consent_grant_dot(operation: &Operation) -> String {
    format!("{}:0", operation.context.event_id)
}

fn authorize_reader(session_actor: &str, holder: &str) -> Result<(), AppError> {
    if session_actor == holder {
        Ok(())
    } else {
        Err(AppError::capability_denied(
            "consent cell is visible only to its holder or an explicitly authorized controller",
        ))
    }
}

// ────────────────────────────────────────────────────────────────────────
// Effective consent (spec section 5).
// ────────────────────────────────────────────────────────────────────────

/// Active dots of one cell: added, not observed-removed, and inside their
/// validity window.
fn active_grant_dots(cell: &ConsentCellRecord, at: DateTime<Utc>) -> Vec<String> {
    cell.grant_dots
        .iter()
        .filter(|(dot, grant)| {
            !cell.revoked_dots.contains(*dot)
                && grant.not_before.is_none_or(|not_before| not_before <= at)
                && grant.expires_at.is_none_or(|expires_at| expires_at > at)
        })
        .map(|(_, grant)| grant.dot.clone())
        .collect()
}

/// Spec `sync/invite-addressing.md` section 2 — verify a `consent_grant`
/// introduction evidence. The `consent_grant_ref` (and optional `consent_id`)
/// MUST resolve to an **active** grant dot in `subject`'s (the invitee_id's)
/// consent cell with `peer == inviter_id` and `consent_scope` in
/// `{invite, any}`, unrevoked and unexpired. Returns `true` only when such a
/// dot exists. On any mismatch the caller MUST downgrade the delivery to the
/// low-trust `explicit_address` path.
pub(crate) fn has_active_consent_grant_evidence(
    state: &AppState,
    subject: &str,
    inviter_id: &str,
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
    state
        .consents()
        .cells_for_pair(subject, inviter_id)
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
        holder_principal_id: cell.holder_principal_id.clone(),
        peer_principal_id: cell.peer_principal_id.clone(),
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
            .grant_dots
            .values()
            .max_by_key(|grant| grant.granted_at)
            .and_then(|grant| grant.expires_at),
        requested_at: None,
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

// ────────────────────────────────────────────────────────────────────────
// Eager cache invalidation (spec section 4.1.2).
// ────────────────────────────────────────────────────────────────────────

/// Resolve the invite-quarantine mutation a revoke owes, without writing it.
///
/// Returns the staged CAS and how many `pending_review` entries it drops. The
/// write itself happens inside the Event commit transaction, so a revoke that
/// cannot invalidate is never accepted.
async fn plan_invite_quarantine_invalidation(
    state: &AppState,
    holder: &str,
    peer: &str,
    consent_scope: &str,
    revoked_at: DateTime<Utc>,
) -> Result<Option<(CommitAccountDataCas, usize)>, ConsentRejection> {
    if !matches!(consent_scope, "invite" | "any") {
        return Ok(None);
    }
    let existing = state
        .account_data()
        .entry(holder, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
        .await
        .map_err(|error| {
            ConsentRejection::internal(format!("invite quarantine cell is unavailable: {error}"))
        })?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let account_id = arkret_wire::AccountId::new(
        DidCoreId::new(holder.to_owned()).map_err(|error| {
            ConsentRejection::internal(format!("invalid quarantine holder: {error}"))
        })?,
        state.service_core_id().clone(),
    );
    let mut quarantine: InviteQuarantine = serde_json::from_value(existing.payload.clone())
        .map_err(|error| {
            ConsentRejection::internal(format!("invalid invite quarantine cell: {error}"))
        })?;
    quarantine.validate_holder(&account_id).map_err(|error| {
        ConsentRejection::internal(format!("invite quarantine binding: {error}"))
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
    quarantine.last_invalidation = Some(InviteQuarantineInvalidation {
        reason: InviteQuarantineInvalidationReason::ConsentRevoke,
        peer_principal_id: DidCoreId::new(peer.to_owned()).map_err(|error| {
            ConsentRejection::internal(format!("invalid revoked peer: {error}"))
        })?,
        consent_scope: if consent_scope == "any" {
            InviteQuarantineInvalidationScope::Any
        } else {
            InviteQuarantineInvalidationScope::Invite
        },
        revoked_at,
        removed_entries: removed as u64,
    });
    quarantine.validate_holder(&account_id).map_err(|error| {
        ConsentRejection::internal(format!("invite quarantine binding: {error}"))
    })?;
    let record = AccountDataState {
        actor_id: holder.to_owned(),
        account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
        revision: existing.revision + 1,
        payload: serde_json::to_value(quarantine).map_err(|error| {
            ConsentRejection::internal(format!("invite quarantine encode: {error}"))
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
/// entries; that is a cache rule, not a lattice rule, so it never adds or
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
        consent_invalidation_peer_ids(state, &cell.holder_principal_id, &cell.peer_principal_id)
            .await;
    let payload = json!({
        "schema": "ak.vector.consent.cache_invalidation.v1",
        "holder_principal_id": cell.holder_principal_id,
        "peer_principal_id": cell.peer_principal_id,
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
        "revoked_dots": cell.revoked_dots.iter().cloned().collect::<Vec<_>>(),
        "revoked_at": arkret_canonical::format_timestamp_canonical(revoked_at),
    });
    append_audit_log(
        state,
        Some(cell.holder_principal_id.as_str()),
        "consent.revoke.cache_invalidation",
        payload,
        "accepted",
    )
    .await;
}

async fn consent_invalidation_peer_ids(
    state: &AppState,
    holder: &DidCoreId,
    peer: &DidCoreId,
) -> Vec<String> {
    let mut services = BTreeSet::new();
    let holder_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        holder.clone(),
        state.service_core_id().clone(),
    ));
    let records = match state.contacts().contacts_for_actor(&holder_actor).await {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(
                %error,
                actor = %holder,
                holder = %holder.as_str(),
                peer = %peer.as_str(),
                "failed to list contacts for consent invalidation target discovery"
            );
            return Vec::new();
        }
    };
    for record in records {
        let same_pair = (record.requester_id.signing_principal_id() == holder
            && record.target_id.signing_principal_id() == peer)
            || (record.requester_id.signing_principal_id() == peer
                && record.target_id.signing_principal_id() == holder);
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
                "principal_id": actor, "station_id": "ak:did_core:web:soland.test"
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

    fn grant_payload(peer: &str, consent_scope: &str) -> Value {
        json!({
            "consent_id": CONSENT_ID,
            "peer_id": peer,
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
            holder_principal_id: DidCoreId::new(HOLDER.to_owned()).unwrap(),
            peer_principal_id: DidCoreId::new(peer.to_owned()).unwrap(),
            consent_scope: consent_scope.to_owned(),
            grant_dots: BTreeMap::from([(
                dot.to_owned(),
                ConsentGrantDot {
                    dot: dot.to_owned(),
                    not_before: None,
                    expires_at: None,
                    granted_at: Utc::now(),
                },
            )]),
            revoked_dots: BTreeSet::new(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn a_consent_cell_is_holder_private() {
        assert!(authorize_reader(HOLDER, HOLDER).is_ok());
        assert!(authorize_reader(PEER, HOLDER).is_err());
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
        assert_eq!(cell.peer_principal_id.as_str(), PEER);
        assert_eq!(cell.consent_scope, "invite");
        assert_eq!(
            cell.grant_dots.keys().cloned().collect::<Vec<_>>(),
            vec![format!("{GRANT_EVENT}:0")]
        );
        // Nothing is written before the Event commits.
        assert!(
            state
                .consents()
                .holder_cells(DidCoreId::new(HOLDER.to_owned()).unwrap())
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
        assert_eq!(admission.commit.cell.grant_dots.len(), 2);
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
        cell.revoked_dots.insert(format!("{GRANT_EVENT}:0"));
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
        assert_eq!(
            state
                .consents()
                .holder_cells(DidCoreId::new(HOLDER.to_owned()).unwrap())
                .len(),
            1
        );
    }

    #[test]
    fn a_dot_outside_its_validity_window_is_not_active() {
        let now = Utc::now();
        let mut cell = granted_cell(CONSENT_ID, PEER, "invite", "dot:0");
        cell.grant_dots.get_mut("dot:0").unwrap().not_before =
            Some(now + chrono::Duration::hours(1));
        assert!(active_grant_dots(&cell, now).is_empty());
        cell.grant_dots.get_mut("dot:0").unwrap().not_before = None;
        cell.grant_dots.get_mut("dot:0").unwrap().expires_at =
            Some(now - chrono::Duration::hours(1));
        assert!(active_grant_dots(&cell, now).is_empty());
        cell.grant_dots.get_mut("dot:0").unwrap().expires_at = None;
        assert_eq!(active_grant_dots(&cell, now), vec!["dot:0".to_owned()]);
    }

    #[tokio::test]
    async fn quarantine_invalidation_is_planned_before_acceptance_and_fanned_out_after() {
        let state = AppState::new(production_test_config(), Db { pool: None });
        let device_id = "ak:device:01904100-0000-7000-8000-0000000000f1";
        let updated_at = now();
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
            actor_id: HOLDER.to_owned(),
            account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
            revision: 1,
            payload: json!({
                "schema": "ak.schema.invite_quarantine.v1",
                "quarantine_entries": [{
                    "entry_digest": format!("sha256:{}", "a".repeat(64)),
                    "status": "pending_review",
                    "account_id": { "principal_id": HOLDER, "station_id": state.service_id() },
                    "source_id": state.service_id(),
                    "consent_scope": "invite",
                    "source_peer_principal_id": PEER,
                    "introduction_kind": "explicit_address",
                    "effective_kind": "explicit_address",
                    "trust_tier": "low",
                    "invite_event_digest": format!("sha256:{}", "b".repeat(64)),
                    "request_digest": format!("sha256:{}", "c".repeat(64)),
                    "idempotency_key_digest": format!("sha256:{}", "d".repeat(64)),
                    "received_at": updated_at,
                    "expires_at": updated_at + chrono::Duration::days(1),
                }],
                "updated_at": updated_at,
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
        let (cas, removed) =
            plan_invite_quarantine_invalidation(&state, HOLDER, PEER, "invite", revoked_at)
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
                .entry(HOLDER, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
                .await
                .expect("quarantine cell")
                .expect("seeded cell")
                .revision,
            1
        );

        let mut cell = granted_cell(CONSENT_ID, PEER, "invite", &format!("{GRANT_EVENT}:0"));
        cell.revoked_dots.insert(format!("{GRANT_EVENT}:0"));
        let admission = ConsentAdmission {
            holder: DidCoreId::new(HOLDER.to_owned()).unwrap(),
            event_id: REVOKE_EVENT.to_owned(),
            consent_id: CONSENT_ID.to_owned(),
            commit: CommitConsentProjection {
                cell,
                invite_quarantine: Some(cas),
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
            .device_messages_after(HOLDER, device_id, 0)
            .await
            .expect("holder to-device queue");
        assert_eq!(queued.len(), 1);
        let envelopes = crate::routing::identity::device_messages::device_message_envelopes_after(
            &state, &queued,
        );
        assert_eq!(envelopes.len(), 1, "service envelope parses without repair");
        let envelope = &envelopes[0];
        assert_eq!(envelope.sender_principal_id.as_str(), HOLDER);
        assert_eq!(envelope.recipient_principal_id.as_str(), HOLDER);
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
                    DidCoreId::new(HOLDER.to_owned()).unwrap(),
                    consent_cell_id_for_consent_id(CONSENT_ID).unwrap(),
                )
                .expect("committed cell is published to the runtime projection")
                .revoked_dots
                .len(),
            1
        );
    }
}
