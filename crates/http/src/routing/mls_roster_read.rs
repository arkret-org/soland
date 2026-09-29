//! Member-authorized signed MLS roster reads through Account and governance Stations.

use arkret_models_collaboration::mls_roster_authority::{
    MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody,
};
use arkret_wire::{DidCoreId, ErrorCode};
use soland_services::authority_commit::{
    MlsRosterAuthorityApplicationRead as Read, MlsRosterAuthorityPreflight as Preflight,
};

use super::*;

const MAX_PEER_PAGE_BYTES: usize = 2 * 1024 * 1024;

fn not_found() -> AppError {
    AppError::not_found("MLS roster authority not found")
}

fn unavailable() -> AppError {
    AppError::new(
        ErrorCode::RevisionUnavailable,
        "authorized MLS roster history is unavailable",
    )
}

fn cursor_invalid() -> AppError {
    AppError::new(ErrorCode::CursorInvalid, "invalid MLS roster cursor")
}

fn validate_request(request: &MlsRosterAuthorityReadRequestBody) -> Result<(), AppError> {
    request.validate().map_err(|_| {
        if request.cursor.is_some() {
            cursor_invalid()
        } else {
            AppError::new(ErrorCode::SchemaViolation, "invalid MLS roster selector")
        }
    })
}

fn internal_read_error(_: soland_services::ServiceError) -> AppError {
    AppError::internal("MLS roster authority read unavailable")
}

fn read_page(outcome: Read) -> Result<MlsRosterAuthorityReadOutcome, AppError> {
    match outcome {
        Read::NotFound => Err(not_found()),
        Read::CursorInvalid => Err(cursor_invalid()),
        Read::RevisionUnavailable | Read::ForwardRequired => Err(unavailable()),
        Read::Page(page) => Ok(page),
    }
}

async fn governance_page(
    state: &AppState,
    request: &MlsRosterAuthorityReadRequestBody,
    source_peer: Option<&DidCoreId>,
) -> Result<MlsRosterAuthorityReadOutcome, AppError> {
    let issuer = state.service_core_id();
    let head = match state
        .authority_commits()
        .mls_roster_authority_attestors(request, &issuer, source_peer)
        .await
        .map_err(internal_read_error)?
    {
        Preflight::NotFound => return Err(not_found()),
        Preflight::RevisionUnavailable | Preflight::ForwardRequired => return Err(unavailable()),
        Preflight::Authorized {
            authority_head_commit_event_ref,
        } => authority_head_commit_event_ref,
    };
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|_| unavailable())?;
    let key = state.notary_signing_key();
    let outcome = state
        .authority_commits()
        .mls_roster_authority_read(
            request,
            &issuer,
            source_peer,
            &head,
            &verification_method,
            key.as_ref(),
            chrono::Utc::now(),
        )
        .await
        .map_err(internal_read_error)?;
    read_page(outcome)
}

fn json_page(page: MlsRosterAuthorityReadOutcome) -> JsonResult<serde_json::Value> {
    let value = serde_json::to_value(page)
        .map_err(|_| AppError::internal("MLS roster page serialization unavailable"))?;
    json_ok(value)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.mls.read.roster_authority",
    request_body = serde_json::Value,
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.mls.read.roster_authority.v1"))]
pub(super) async fn resolve_self_mls_roster_authority(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let request = req
        .parse_json::<MlsRosterAuthorityReadRequestBody>()
        .await
        .map_err(|_| AppError::new(ErrorCode::SchemaViolation, "invalid MLS roster request"))?;
    validate_request(&request)?;
    if request.caller_actor_id != caller || caller.route_service_id() != &state.service_core_id() {
        return Err(not_found());
    }
    let local = state.service_core_id();
    let authorized = state
        .authority_commits()
        .mls_roster_authority_attestors(&request, &local, None)
        .await
        .map_err(internal_read_error)?;
    match authorized {
        Preflight::NotFound => return Err(not_found()),
        Preflight::RevisionUnavailable => return Err(unavailable()),
        Preflight::Authorized { .. } | Preflight::ForwardRequired => {}
    }
    let authority = state
        .authority_commits()
        .current_authority(&request.realm_id)
        .await
        .map_err(internal_read_error)?
        .ok_or_else(not_found)?;
    if authority.service_id == local {
        return json_page(governance_page(state, &request, None).await?);
    }
    if !matches!(authorized, Preflight::ForwardRequired) {
        return Err(unavailable());
    }
    crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &request.realm_id,
        &authority.service_id,
    )
    .await
    .map_err(|_| unavailable())?;
    let body = arkret_canonical::canonical_json_bytes(&request).map_err(|_| unavailable())?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        authority.service_id.as_str(),
        arkret_wire::PATH_PEER_MLS_ROSTER_AUTHORITY,
        &body,
        MAX_PEER_PAGE_BYTES,
    )
    .await
    .map_err(|_| unavailable())?;
    match response.status {
        404 => return Err(not_found()),
        400 => return Err(cursor_invalid()),
        503 => return Err(unavailable()),
        200 => {}
        _ => return Err(unavailable()),
    }
    let page: MlsRosterAuthorityReadOutcome =
        serde_json::from_slice(&response.body).map_err(|_| unavailable())?;
    let resolution = crate::routing::identity::agents::evidence::fetch_service_resolution(
        state,
        &authority.service_id,
        None,
    )
    .await
    .map_err(|_| unavailable())?;
    arkret::verify_mls_roster_authority_manifest_signature(
        &page.manifest,
        &request,
        &authority.service_id,
        &page.manifest.authority_head_commit_event_ref,
        &resolution,
    )
    .map_err(|_| unavailable())?;
    if page.records.is_empty()
        || page.records.len() > 8
        || page.page_index >= page.manifest.page_count
        || page.next_cursor.is_some() != (page.page_index + 1 < page.manifest.page_count)
    {
        return Err(unavailable());
    }
    json_page(page)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.mls.read.roster_authority",
    request_body = serde_json::Value,
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.mls.read.roster_authority.v1"))]
pub(super) async fn resolve_peer_mls_roster_authority(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = crate::routing::events::peer::authenticated_peer_context(state, req, true).await?;
    let request = req
        .parse_json::<MlsRosterAuthorityReadRequestBody>()
        .await
        .map_err(|_| AppError::new(ErrorCode::SchemaViolation, "invalid MLS roster request"))?;
    validate_request(&request)?;
    if request.caller_actor_id.route_service_id() != &peer.source_service_id {
        return Err(not_found());
    }
    json_page(governance_page(state, &request, Some(&peer.source_service_id)).await?)
}
