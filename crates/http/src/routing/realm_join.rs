//! Realm join preparation and post-admission bootstrap on the current v1 carriers.

use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody, RealmJoinIntent,
    SelfRealmJoinPrepareOutcome, SelfRealmJoinPrepareRequestBody,
};
use arkret_wire::{ActorId, AuthorityBundleRequest, Base64UrlString, CommitStreamRef, EventKind};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
mod authority;

pub(super) fn self_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/prepare").post(prepare))
}

pub(super) fn peer_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/bootstrap").post(peer_bootstrap))
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

async fn local_authority_bundle(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    request_id: &arkret_wire::RequestId,
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
                nonce: nonce_for_request(request_id)?,
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
    body.target.validate().map_err(invalid_request)?;
    let target = &body.target;
    match &body.intent {
        RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } if target.invite_id.as_ref() == Some(invite_id)
            && target.invite_token.as_ref() == Some(invite_token) => {}
        RealmJoinIntent::InviteAccept { .. } => {
            return Err(invalid_request(
                "invite intent does not bind the target invite",
            ));
        }
        RealmJoinIntent::MemberJoin | RealmJoinIntent::Knock => {}
    }
    let bundle = authority::resolve_authority_bundle(state, target, &body.request_id).await?;
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
    if event.kind != EventKind::MemberState
        || event.realm_id != body.realm_id
        || accepted.commit.stream_ref != expected_stream
    {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let payload = serde_json::from_value::<MembershipPayload>(
        serde_json::to_value(&event.payload).map_err(unavailable)?,
    )
    .map_err(|_| AppError::not_found("Realm join bootstrap not found"))?;
    if payload.member_id != ActorId::account(body.member_account_id.clone())
        || payload.membership != MembershipPayloadState::Join
    {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let bundle = local_authority_bundle(state, &body.realm_id, &body.request_id).await?;
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
