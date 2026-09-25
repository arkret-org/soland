//! Realm join preparation and post-admission bootstrap on the current v1 carriers.

use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody, SelfRealmJoinPrepareOutcome,
    SelfRealmJoinPrepareRequestBody,
};
use arkret_wire::{ActorId, AuthorityBundleRequest, Base64UrlString, CommitStreamRef, EventKind};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
mod authority;
mod preview;

pub(in crate::routing) use authority::resolve_verified_authority;
pub(crate) use authority::{
    LocatedRealmAuthority, insert_method_key, resolve_verified_authority_of_service,
};

pub(super) fn self_router() -> Router {
    Router::new()
        .push(Router::with_path("realm-joins/preview").post(preview::self_preview))
        .push(Router::with_path("realm-joins/prepare").post(prepare))
}

pub(super) fn peer_router() -> Router {
    Router::new()
        .push(Router::with_path("realm-joins/preview").post(preview::peer_preview))
        .push(Router::with_path("realm-joins/bootstrap").post(peer_bootstrap))
}

fn invalid_request(error: impl std::fmt::Display) -> AppError {
    AppError::param_invalid(error.to_string())
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("Realm authority evidence unavailable: {error}"))
}

fn nonce_for_request(request_id: &arkret_wire::RequestId) -> Result<Base64UrlString, AppError> {
    Base64UrlString::new(request_id.as_str().trim_start_matches("ak:request:"))
        .map_err(invalid_request)
}

/// This Station's own nonce-bound bundle for a Realm it currently governs.
/// A Realm governed elsewhere fails here, so the result is never a claim of
/// authority this Station does not hold.
async fn local_authority_bundle(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    nonce: &Base64UrlString,
) -> Result<arkret_wire::RealmAuthorityBundle, AppError> {
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
    let route = serde_json::to_value(route).map_err(unavailable)?;
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(unavailable)?;
    state
        .authority_commits()
        .authority_bundle(
            &AuthorityBundleRequest {
                realm_id: realm_id.clone(),
                nonce: nonce.clone(),
            },
            &state.service_core_id(),
            route,
            verification_method,
            state.notary_signing_key().as_ref(),
            crate::wire::now(),
        )
        .await
        .map_err(unavailable)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.command.prepare.v1"))]
async fn prepare(depot: &mut Depot, req: &mut Request) -> JsonResult<SelfRealmJoinPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = AuthArgs::default()
        .authenticated_session(state, req)
        .await?;
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id != state.service_core_id() {
        return Err(AppError::not_found("Realm join preparation not found"));
    }
    let body = req
        .parse_json::<SelfRealmJoinPrepareRequestBody>()
        .await
        .map_err(invalid_request)?;
    body.validate().map_err(invalid_request)?;
    let located =
        authority::resolve_join_target_authority(state, &body.target, &body.request_id).await?;
    // The verified current authority is the join intake state this Station
    // keeps: the applicant's exact signed Event is then forwarded to that
    // Station and nowhere else (join-policy.md §6).
    if located.authority.current_service_id() != &state.service_core_id() {
        state
            .authority_commits()
            .record_remote_authority(&located.current_authority(), &state.service_core_id())
            .await
            .map_err(unavailable)?;
    }
    let bundle = located.bundle;
    let outcome = SelfRealmJoinPrepareOutcome {
        request_id: body.request_id,
        realm_stream_head: bundle.realm_stream_head.clone(),
        authority_bundle: bundle,
    };
    json_ok(outcome)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.peer.realm_join.read.bootstrap.v1"))]
async fn peer_bootstrap(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerRealmJoinBootstrapOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = crate::routing::events::peer::source_id_from_request(req)?;
    let body = req
        .parse_json::<PeerRealmJoinBootstrapRequestBody>()
        .await
        .map_err(invalid_request)?;
    if body.member_account_id.station_id.as_str() != source_id {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let accepted = state
        .authority_commits()
        .committed_event_by_commit_id(&body.membership_commit_id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| AppError::not_found("Realm join bootstrap not found"))?;
    let event = &accepted.event;
    let expected_stream = CommitStreamRef::Realm {
        realm_id: body.realm_id.clone(),
    };
    if event.realm_id != body.realm_id || accepted.commit.stream_ref != expected_stream {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let member = ActorId::account(body.member_account_id.clone());
    // The membership Commit is the member's own join: its `ak.member.state{join}`
    // or, for a directed Invite, its `ak.invite.accept`.
    let joins_member = match event.kind {
        EventKind::MemberState => serde_json::to_value(&event.payload)
            .ok()
            .and_then(|payload| serde_json::from_value::<MembershipPayload>(payload).ok())
            .is_some_and(|payload| {
                payload.member_id == member && payload.membership == MembershipPayloadState::Join
            }),
        EventKind::InviteAccept => event.actor_id == member,
        _ => false,
    };
    if !joins_member {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let bundle =
        local_authority_bundle(state, &body.realm_id, &nonce_for_request(&body.request_id)?)
            .await?;
    let mut material = state
        .authority_commits()
        .realm_state_snapshot_material(&body.realm_id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| AppError::not_found("Realm join bootstrap not found"))?;
    // A Realm membership Commit grants the Realm stream. Circle and Sidecar
    // streams require separate scope-specific membership evidence.
    material
        .visible_stream_heads
        .retain(|head| head.stream_ref == expected_stream);
    material
        .retention_and_history_floor
        .stream_floors
        .retain(|floor| floor.stream_ref == expected_stream);
    if material.visible_stream_heads.is_empty() {
        return Err(unavailable("Realm stream head is unavailable"));
    }
    let snapshot = soland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        state
            .service_verification_method("notary-key")
            .map_err(unavailable)?,
        state.notary_signing_key().as_ref(),
        crate::wire::now(),
    )
    .map_err(unavailable)?;
    json_ok(PeerRealmJoinBootstrapOutcome {
        request_id: body.request_id,
        authority_bundle: bundle,
        snapshot,
        visible_stream_heads: material.visible_stream_heads,
    })
}
