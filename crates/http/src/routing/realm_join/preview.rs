//! Pre-join Realm preview (`invite-addressing.md` section 7.1).
//!
//! The preview has one source, the same as join preparation: the Realm's
//! current governance Station. The caller's own Station verifies that Station
//! through the locator hints with a nonce it generates itself, then asks it
//! for the preview over service-to-service authentication, or answers on the
//! equivalent local path when it is that Station. Inviter Stations, Directory
//! entries and member Stations are never a preview source.

use std::time::Duration;

use arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValue;
use arkret_models_collaboration::events_payloads::realm::RealmProfile;
use arkret_models_collaboration::governance::membership_invite::InviteCreatePayload;
use arkret_models_collaboration::governance::realm_join_intake::{
    PUBLIC_PREVIEW_DISPLAY_NAME_MAX_CHARS, PeerRealmJoinPreviewOutcome,
    PeerRealmJoinPreviewRequestBody, RealmPublicPreview, SelfRealmJoinPreviewOutcome,
    SelfRealmJoinPreviewRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CurrentSelector, DidCoreId, EventId, EventKind,
    HistoryAccess, InviteId, JoinRule, RealmId, TypedCurrentResult,
};
use base64::Engine as _;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{AuthArgs, invalid_request};
use crate::state::AppState;

/// Every peer preview answer, disclosed or not, is held to at least this
/// duration so that unknown, hidden, non-governed and mismatched targets fall
/// into one timing bucket with the successful path.
const PEER_PREVIEW_TIMING_FLOOR: Duration = Duration::from_millis(150);

/// Registered `max_canonical_body_bytes` of the peer preview operation, also
/// the bound applied to its response.
const PEER_PREVIEW_MAX_BYTES: usize = 64 * 1024;

const PEER_PREVIEW_PATH: &str = "/_arkret/peer/realm-joins/preview";

/// The single non-enumerating failure for every target the governance
/// Station does not disclose.
fn preview_not_found() -> AppError {
    AppError::not_found("Realm preview not found")
}

/// The current governance Station could not be reached or answered outside
/// the closed outcome. The caller may retry; no other source is substituted.
fn governance_unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        ServiceUnavailable,
        "Realm governance Station preview unavailable: {error}",
    )
}

fn fresh_nonce() -> Result<Base64UrlString, AppError> {
    Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
    )
    .map_err(|error| AppError::internal(error.to_string()))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.read.preview.v1"))]
pub(super) async fn self_preview(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SelfRealmJoinPreviewOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = AuthArgs::default()
        .authenticated_session(state, req)
        .await?;
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id != state.service_core_id() {
        return Err(preview_not_found());
    }
    let body = req
        .parse_json::<SelfRealmJoinPreviewRequestBody>()
        .await
        .map_err(invalid_request)?;
    body.validate().map_err(invalid_request)?;
    // The hint set was validated above, so a failure here means no locator
    // led to a verified, converging current governance Station: the target
    // is unresolvable and shares the non-enumerating `not_found`.
    let located = super::resolve_verified_authority(
        state,
        &body.target.realm_id,
        &body.target.authority_locator_hints,
        &fresh_nonce()?,
    )
    .await
    .map_err(|_| preview_not_found())?;
    let peer_request = PeerRealmJoinPreviewRequestBody {
        request_id: body.request_id.clone(),
        realm_id: body.target.realm_id.clone(),
        requester_account_id: account_id,
        invite_id: body.target.invite_id.clone(),
    };
    let governance = located.authority.current_service_id();
    let preview = if *governance == state.service_core_id() {
        governance_preview(state, &peer_request).await?
    } else {
        request_peer_preview(state, governance, &peer_request)
            .await?
            .preview
    };
    let outcome = SelfRealmJoinPreviewOutcome {
        request_id: body.request_id.clone(),
        authority_bundle: located.bundle,
        preview,
    };
    // A preview answered under a different governance tenure than the bundle
    // this Station verified raced a handoff; the caller retries.
    outcome
        .validate_for_request(&body)
        .map_err(governance_unavailable)?;
    json_ok(outcome)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.peer.realm_join.read.preview.v1"))]
pub(super) async fn peer_preview(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerRealmJoinPreviewOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = crate::routing::events::peer::source_id_from_request(req)?;
    let body = req
        .parse_json::<PeerRealmJoinPreviewRequestBody>()
        .await
        .map_err(invalid_request)?;
    body.validate().map_err(invalid_request)?;
    json_ok(answer_peer_preview(state, &source_id, body).await?)
}

/// Answer one authenticated peer preview. The requester Account must belong
/// to the calling Station; every answer, disclosed or not, is held to the
/// same timing floor.
async fn answer_peer_preview(
    state: &AppState,
    source_id: &str,
    body: PeerRealmJoinPreviewRequestBody,
) -> Result<PeerRealmJoinPreviewOutcome, AppError> {
    let started = tokio::time::Instant::now();
    let answer = if body.requester_account_id.station_id.as_str() == source_id {
        governance_preview(state, &body).await
    } else {
        Err(preview_not_found())
    };
    tokio::time::sleep_until(started + PEER_PREVIEW_TIMING_FLOOR).await;
    Ok(PeerRealmJoinPreviewOutcome {
        request_id: body.request_id,
        preview: answer?,
    })
}

/// The governance Station's own answer. Every non-disclosing branch returns
/// the same `not_found`; only a storage fault surfaces as an internal error.
pub(super) async fn governance_preview(
    state: &AppState,
    request: &PeerRealmJoinPreviewRequestBody,
) -> Result<RealmPublicPreview, AppError> {
    let authorities = state.authority_commits();
    let Some(authority) = authorities
        .current_authority(&request.realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(preview_not_found());
    };
    if authority.service_id != state.service_core_id() {
        return Err(preview_not_found());
    }
    let invited = match &request.invite_id {
        Some(invite_id) => {
            if !invite_binds_requester(
                state,
                &request.realm_id,
                invite_id,
                &request.requester_account_id,
            )
            .await?
            {
                return Err(preview_not_found());
            }
            true
        }
        None => false,
    };
    let Some(policy) = effective_preview_policy(state, &request.realm_id).await? else {
        return Err(preview_not_found());
    };
    let member = authorities
        .local_current_member_joined(
            &request.realm_id,
            &ActorId::account(request.requester_account_id.clone()),
            &authority.service_id,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(material) = authorities
        .realm_state_snapshot_material(&request.realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(preview_not_found());
    };
    if material.governance_generation != authority.generation {
        return Err(governance_unavailable(
            "the governing tenure changed while the preview was read",
        ));
    }
    disclose(
        &policy,
        PreviewAudience { invited, member },
        &request.realm_id,
        material.governance_generation,
        &material.current_state_entries,
    )
    .ok_or_else(preview_not_found)
}

/// An `invite_id` counts only when this Station committed the directed
/// `ak.invite.create` for this Realm, its payload names the exact complete
/// requester AccountId, it has not expired, and its lifecycle has not moved to
/// a terminal state.
async fn invite_binds_requester(
    state: &AppState,
    realm_id: &RealmId,
    invite_id: &InviteId,
    requester: &AccountId,
) -> Result<bool, AppError> {
    let Ok(event_id) = EventId::from_token_bytes(invite_id.token_bytes()) else {
        return Ok(false);
    };
    let Some(committed) = state
        .authority_commits()
        .committed_event(&event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(false);
    };
    let event = &committed.event;
    if event.kind != EventKind::InviteCreate
        || event.realm_id != *realm_id
        || committed.commit.realm_id != *realm_id
        || committed.commit.event_ref != event.event_id
    {
        return Ok(false);
    }
    let Ok(payload) = serde_json::to_value(&event.payload)
        .and_then(serde_json::from_value::<InviteCreatePayload>)
    else {
        return Ok(false);
    };
    if payload.invitee_account_id != *requester || payload.expires_at <= crate::wire::now() {
        return Ok(false);
    }
    let lifecycle = state
        .realm_invites()
        .get(invite_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(lifecycle
        .is_some_and(|invite| invite.realm_id == realm_id.as_str() && invite.status == "pending"))
}

/// The accepted `ak.realm.preview_policy` value of this Realm, as the
/// governing Station projected it from its committed Events. A missing or
/// undecodable policy is "no effective preview policy".
async fn effective_preview_policy(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Option<PreviewPolicyPayloadValue>, AppError> {
    let meta = state
        .realms()
        .realm_metadata(realm_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(meta
        .and_then(|meta| meta.preview_policy)
        .and_then(|policy| serde_json::from_value::<PreviewPolicyPayloadValue>(policy).ok()))
}

#[derive(Clone, Copy, Debug)]
struct PreviewAudience {
    invited: bool,
    member: bool,
}

impl PreviewAudience {
    /// A peer requester is always an authenticated Account; the invited and
    /// member classes are added only from this Station's accepted state.
    /// Knock applicant, restricted claim and link-token audiences have no
    /// accepted source on this path and are never assumed.
    fn admitted_by(self, audiences: &[String]) -> bool {
        audiences.iter().any(|audience| match audience.as_str() {
            "anonymous" | "authenticated" => true,
            "invited" => self.invited,
            "realm_member" => self.member,
            _ => false,
        })
    }
}

fn singleton_value<'a>(
    entries: &'a [TypedCurrentResult],
    wanted: &CurrentSelector,
) -> Option<&'a serde_json::Value> {
    entries.iter().find_map(|entry| match entry {
        TypedCurrentResult::Value {
            selector, value, ..
        } if selector == wanted => Some(value),
        _ => None,
    })
}

/// Build the disclosed preview from one governing cut. The required members
/// always come from the committed `realm_join_rule` and `realm_history_access`
/// results; `display_name` is disclosed only when the policy lists `title` and
/// the committed profile carries a valid one. `None` means nothing may be
/// disclosed to this audience.
fn disclose(
    policy: &PreviewPolicyPayloadValue,
    audience: PreviewAudience,
    realm_id: &RealmId,
    governance_generation: u64,
    entries: &[TypedCurrentResult],
) -> Option<RealmPublicPreview> {
    if policy.mode == "none" || !audience.admitted_by(&policy.audiences) {
        return None;
    }
    let join_rule = singleton_value(entries, &CurrentSelector::RealmJoinRule)
        .and_then(|value| serde_json::from_value::<JoinRule>(value.clone()).ok())?;
    let history_access = singleton_value(entries, &CurrentSelector::RealmHistoryAccess)
        .and_then(|value| serde_json::from_value::<HistoryAccess>(value.clone()).ok())?;
    let display_name = policy
        .fields
        .iter()
        .any(|field| field == "title")
        .then(|| singleton_value(entries, &CurrentSelector::RealmProfile))
        .flatten()
        .and_then(|value| serde_json::from_value::<RealmProfile>(value.clone()).ok())
        .map(|profile| profile.title)
        .filter(|title| {
            !title.is_empty() && title.chars().count() <= PUBLIC_PREVIEW_DISPLAY_NAME_MAX_CHARS
        });
    let preview = RealmPublicPreview {
        realm_id: realm_id.clone(),
        join_rule,
        history_access,
        governance_generation,
        display_name,
    };
    preview.validate().ok()?;
    Some(preview)
}

/// Ask the verified current governance Station over service-to-service
/// authentication. The requester's own bearer or session credential is never
/// forwarded: the request names the complete requester Account, which the
/// governance Station binds to this Station's `Source-Service-ID`.
async fn request_peer_preview(
    state: &AppState,
    governance: &DidCoreId,
    request: &PeerRealmJoinPreviewRequestBody,
) -> Result<PeerRealmJoinPreviewOutcome, AppError> {
    use crate::routing::federation::outbox::{
        content_digest_header_value, insert_header_if_valid, rfc9421_sign,
    };

    let peer_target = crate::routing::federation::resolved_peer_target(
        state,
        governance.as_str(),
        "station",
        false,
    )
    .await
    .map_err(governance_unavailable)?;
    let target = format!("{}{PEER_PREVIEW_PATH}", peer_target.base_url);
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Realm join preview",
        state.config().development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    )
    .map_err(governance_unavailable)?;
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    insert_header_if_valid(
        &mut headers,
        "content-digest",
        &content_digest_header_value(&body),
    );
    insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    insert_header_if_valid(&mut headers, "destination-service-id", governance.as_str());
    insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &peer_target.trust_domain,
    );
    let headers = rfc9421_sign(state, headers, "POST", &target);
    let mut response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(governance_unavailable)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(preview_not_found());
    }
    if !response.status().is_success() {
        return Err(governance_unavailable(format!(
            "HTTP {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(governance_unavailable)? {
        if bytes.len() + chunk.len() > PEER_PREVIEW_MAX_BYTES {
            return Err(governance_unavailable(
                "response exceeds the operation limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome = serde_json::from_slice::<PeerRealmJoinPreviewOutcome>(&bytes)
        .map_err(governance_unavailable)?;
    outcome
        .validate_for_request(request)
        .map_err(governance_unavailable)?;
    Ok(outcome)
}

#[cfg(test)]
#[path = "preview_tests.rs"]
mod tests;
