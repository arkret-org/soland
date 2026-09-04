//! Invite addressing protocol surface.
//!
//! Implements the v1 private invite delivery endpoint and the body-only
//! online locator resolver from `sync/invite-addressing.md`.

use arkret_canonical as canonical;
use arkret_identifiers::{DidCoreId, Hash, InviteLocatorId};
use arkret_models_collaboration::governance::invite_addressing::{
    DisclosedOutcome, DisclosureLevel, IntroductionEvidence, InviteDelivery, InviteDeliveryEntry,
    InviteDeliveryOutcome, InviteDeliveryOutcomeStatus, InviteDeliveryRequestBody,
    InviteLocatorIssueOutcome, InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody,
    InviteLocatorRevokeOutcome, InviteLocatorRevokeRequestBody, InviteLocatorRotateRequestBody,
    InviteLocatorStatus, InviteQuarantine, InviteQuarantineEntry, InviteQuarantineScope,
    InviteQuarantineStatus, InviteReceivePolicy, InviteTrustTier, PrincipalLocator,
    PrincipalLocatorProof, PrincipalLocatorProofPurpose, SelfInviteDispatchRequestBody,
};
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
};
use arkret_models_discovery::DirectoryIntent;
use arkret_models_identity::handle::Handle;
use arkret_models_identity::proof::DetachedPayloadProof;
use arkret_models_identity::{HandleClaim, HandleClaimStatus, ServiceResolutionCarrier};
use arkret_wire::receive_policy::EffectiveNewSourceQuota;
use arkret_wire::{
    AccountDataKey, InviteReceiveAction, ReceivePolicyConstraints, ReceivePolicySurface,
    UnknownInviteAction,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use salvo::http::HeaderValue;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_http::util::sha256_hex;
use soland_services::events::{
    AcceptedEvent, InviteLocatorInsertResult as InviteLocatorInsertOutcome,
    InviteLocatorRotateCommand as InviteLocatorRotateMutation,
    InviteLocatorState as InviteLocatorRecord, RealmInviteState as RealmInviteRecord,
};
use soland_services::federation::{EnqueueFederationDeliveryCommand, FederationDeliveryRecord};
use soland_services::identity::{
    AccountDataCasOutcome, AccountDataState, SessionIdentityState as SessionRecord,
};
use soland_storage::NewSourceAdmission;

use crate::routing::identity::device_messages::{
    fanout_actor_private_update, station_device_message_sender,
};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
/// HTTP binding of `ak.peer.invites.command.submit.v1` — the only endpoint a
/// remote private invite delivery is ever addressed to.
const PEER_INVITES_ENDPOINT: &str = "/_arkret/peer/invites";
const ACTIVE_LOCATOR_LIMIT: usize = 16;
const INVITE_LOCATOR_CACHE_CONTROL: &str = "private, no-store";
const INVITE_QUARANTINE_TTL_DAYS: i64 = 30;
const MAX_INVITE_QUARANTINE_ENTRIES: usize = 200;
const INVITE_DELIVERY_CAS_ATTEMPTS: usize = 3;
const INVITE_QUARANTINE_CAS_ATTEMPTS: usize = 8;

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("invites").post(peer_invites_submit))
}

pub(crate) fn open_router() -> Router {
    Router::new().push(Router::with_path("invite-locators/resolve").post(resolve_invite_locator))
}

pub(crate) fn self_router() -> Router {
    Router::new()
        .push(Router::with_path("invite-locators").post(issue_invite_locator))
        .push(Router::with_path("invite-locators/rotate").post(rotate_invite_locator))
        .push(Router::with_path("invite-locators/revoke").post(revoke_invite_locator))
        .push(Router::with_path("invites/dispatch").post(self_invites_dispatch))
}

fn new_invite_locator(
    subject_id: &str,
    recipient_id: &str,
    options: InviteLocatorIssueRequestBody,
) -> Result<(InviteLocatorRecord, String), AppError> {
    options
        .validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(i64::from(options.effective_ttl_seconds()));
    let (token, token_digest) = new_invite_locator_secret();
    let record = InviteLocatorRecord {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest,
        subject_id: subject_id.to_owned(),
        recipient_id: recipient_id.to_owned(),
        issued_at,
        expires_at,
        one_time_use: options.one_time_use.unwrap_or(false),
        display_hint: options.display_hint,
        revoked_at: None,
        consumed_at: None,
    };
    Ok((record, token))
}

fn new_invite_locator_secret() -> (String, String) {
    let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
    let token_digest = format!("sha256:{}", sha256_hex(token.as_bytes()));
    (token, token_digest)
}

fn set_invite_locator_secret_response_headers(res: &mut Response) {
    res.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static(INVITE_LOCATOR_CACHE_CONTROL),
    );
}

fn locator_issue_outcome(
    record: &InviteLocatorRecord,
    locator_token: String,
) -> Result<InviteLocatorIssueOutcome, AppError> {
    Ok(InviteLocatorIssueOutcome {
        locator_id: InviteLocatorId::new(record.locator_id.clone())
            .map_err(|error| AppError::internal(format!("stored invite locator id: {error}")))?,
        locator_token,
        expires_at: record.expires_at,
        one_time_use: record.one_time_use,
    })
}

#[endpoint(summary = "Issue an invite locator", tags("invites"))]
async fn issue_invite_locator(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<InviteLocatorIssueRequestBody>,
) -> JsonResult<InviteLocatorIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let (record, token) =
        new_invite_locator(&session.actor, state.service_id(), body.into_inner())?;
    match state
        .realm_invites()
        .insert_locator(&record, ACTIVE_LOCATOR_LIMIT, now())
        .await
        .map_err(|error| AppError::internal(format!("invite locator insert: {error}")))?
    {
        InviteLocatorInsertOutcome::Inserted => {
            set_invite_locator_secret_response_headers(res);
            json_ok(locator_issue_outcome(&record, token)?)
        }
        InviteLocatorInsertOutcome::ActiveLimitReached => Err(crate::app_error!(
            FailedPrecondition,
            "active invite locator limit reached",
        )
        .with_wire_code("failed_precondition")),
    }
}

#[endpoint(summary = "Rotate an invite locator", tags("invites"))]
async fn rotate_invite_locator(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<InviteLocatorRotateRequestBody>,
) -> JsonResult<InviteLocatorIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let (token, token_digest) = new_invite_locator_secret();
    let mutation = InviteLocatorRotateMutation {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest,
        issued_at: now(),
        ttl_seconds: body.ttl_seconds,
        one_time_use: body.one_time_use,
        display_hint: body.display_hint,
    };
    let Some(record) = state
        .realm_invites()
        .rotate_locator(&session.actor, body.locator_id.as_str(), &mutation, now())
        .await
        .map_err(|error| AppError::internal(format!("invite locator rotate: {error}")))?
    else {
        return Err(invite_locator_not_found());
    };
    set_invite_locator_secret_response_headers(res);
    json_ok(locator_issue_outcome(&record, token)?)
}

#[endpoint(summary = "Revoke an invite locator", tags("invites"))]
async fn revoke_invite_locator(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<InviteLocatorRevokeRequestBody>,
) -> JsonResult<InviteLocatorRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let revoked_at = now();
    let Some(record) = state
        .realm_invites()
        .revoke_locator(&session.actor, body.locator_id.as_str(), revoked_at)
        .await
        .map_err(|error| AppError::internal(format!("invite locator revoke: {error}")))?
    else {
        return Err(invite_locator_not_found());
    };
    json_ok(InviteLocatorRevokeOutcome {
        locator_id: InviteLocatorId::new(record.locator_id)
            .map_err(|error| AppError::internal(format!("stored invite locator id: {error}")))?,
        status: InviteLocatorStatus::Revoked,
        revoked_at: record.revoked_at.unwrap_or(revoked_at),
    })
}

#[endpoint(
    operation_id = "ak.peer.invites.command.submit",
    summary = "Submit a peer invite delivery",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.invites.command.submit.v1"))]
async fn peer_invites_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteDeliveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::events::peer::validate_peer_request(state, req, true).await?;
    let delivery = req
        .parse_json::<InviteDeliveryRequestBody>()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.peer.invites.command.submit.v1 request body")
        })?;
    let body = serde_json::to_value(&delivery).map_err(|error| {
        AppError::internal(format!("invite delivery request serialize: {error}"))
    })?;

    delivery.validate_minimal().map_err(|error| {
        super::events::peer::schema_violation(format!("invalid invite delivery request: {error}"))
    })?;

    let destination_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if destination_id != delivery.invite_address.account_id.station_id.as_str() {
        return Err(super::events::peer::cross_domain_replay(
            "Destination-Service-ID must equal invite_address.account_id.station_id",
        ));
    }
    let source_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;

    // Steps 1-3 are the service-to-service binding: the peer session below
    // exists only so the delivered envelope can be verified against a
    // trust-domain-bound identity. It is never a principal session and MUST NOT
    // be reused by the authenticated self dispatch surface.
    let trust_headers = crate::routing::federation::FederationTrustHeaders::from_salvo_request(req)
        .map_err(|violation| {
            super::events::peer::schema_violation(violation.message())
                .with_wire_code(violation.error_code())
        })?;
    let request_hash = crate::util::canonical_digest(&body)?;
    let session = SessionRecord {
        token_hash: format!(
            "peer-invite:{}:{request_hash}",
            trust_headers.source_trust_domain
        ),
        account_pk: None,
        actor: delivery
            .invite_event
            .actor_id
            .signing_principal_id()
            .as_str()
            .to_owned(),
        device_id: format!("peer-invite:{source_id}"),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now() + Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    };

    json_ok(
        receive_private_invite_delivery(
            state,
            &delivery,
            &body,
            &source_id,
            "peer.invites.submit",
            InvitePrivateProjection::FromDeliveredEvent { session: &session },
        )
        .await?,
    )
}

/// How the notify branch of a private invite delivery materializes the
/// holder-private invite row (spec invite-addressing.md §7 steps 4 / 8 / 9).
enum InvitePrivateProjection<'a> {
    /// Peer ingress. This service holds no shared-Realm copy of the delivered
    /// `ak.invite.create`, so the envelope is verified here under the
    /// service-to-service session and projected into the holder's private
    /// invite row.
    FromDeliveredEvent { session: &'a SessionRecord },
    /// Local self dispatch. This service already accepted the Event — which is
    /// exactly what the two accepted-event preconditions proved — so its
    /// registered reducer contract already owns the holder-visible invite row
    /// and the notify branch owes no second write of it.
    AlreadyAcceptedLocally { record: &'a AcceptedEvent },
}

/// Spec invite-addressing.md §7 steps 4-9 — the receive half of a private
/// invite delivery, shared by the peer service-to-service ingress and the local
/// `ak.self.invites.command.dispatch.v1` branch.
///
/// Steps 1-3 are the service-to-service binding and stay with the caller. The
/// local branch substitutes "authenticated self session + the two
/// accepted-event preconditions" for them, and MUST NOT synthesize federation
/// trust headers or a peer session to reach this path.
async fn receive_private_invite_delivery(
    state: &AppState,
    delivery: &InviteDeliveryRequestBody,
    body: &Value,
    source_id: &str,
    audit_operation: &'static str,
    projection: InvitePrivateProjection<'_>,
) -> Result<InviteDeliveryOutcome, AppError> {
    validate_invite_delivery_consistency(body, delivery, state)?;

    // The inviter is the actor that signed the durable `ak.invite.create`
    // event; it is the exact peer we test `denied_actor_ids` and the
    // `consent_grant` evidence against (spec invite-addressing.md §2 / §5).
    let inviter_id = delivery
        .invite_event
        .actor_id
        .signing_principal_id()
        .as_str()
        .to_owned();
    let inviter_actor_id = &delivery.invite_event.actor_id;
    let subject_id = delivery.invite_address.account_id.principal_id.clone();
    let subject = subject_id.as_str().to_owned();
    let same_station = delivery
        .invite_event
        .actor_id
        .as_account_id()
        .is_some_and(|inviter| inviter.station_id == delivery.invite_address.account_id.station_id);

    // Spec invite-addressing.md §5..§8 — resolve the subject's private
    // receive policy, derive the effective trust tier (downgrading
    // `consent_grant` to `explicit_address` when the grant cannot be
    // verified), then apply blocklist + allowlist + behavior to pick a
    // receive action and a graded-disclosure outcome.
    let policy = resolve_core_invite_receive_policy(state, &delivery.invite_address.account_id);
    let decision = evaluate_invite_receive(
        state,
        &policy,
        &delivery.introduction_evidence,
        inviter_actor_id,
        &inviter_id,
        &subject,
        delivery.invite_address.account_id.station_id.as_str(),
        source_id,
        same_station,
    );

    if decision.action != InviteReceiveAction::Notify {
        let quarantine_persisted = if decision.action == InviteReceiveAction::Quarantine {
            persist_invite_quarantine_entry(
                state,
                &subject,
                source_id,
                &inviter_id,
                delivery,
                body,
                &decision,
            )
            .await?
        } else {
            false
        };
        super::append_audit_log(
            state,
            None,
            audit_operation,
            json!({
                "idempotency_key": delivery.idempotency_key,
                "invitee_id": delivery.invite_address.account_id.principal_id,
                "recipient_id": delivery.invite_address.account_id.station_id,
                "introduction_kind": delivery.introduction_evidence.kind(),
                "effective_kind": decision.effective_kind,
                "trust_tier": decision.trust_tier.as_str(),
                "receive_action": receive_action_str(&decision.action),
                "quarantine_persisted": quarantine_persisted,
            }),
            "deferred",
        )
        .await;
        // §5.1 — quarantine and drop share one wire class: `deferred` without
        // `disclosed_outcome` unless the graded disclosure explicitly permits
        // the `blocked` answer.
        return Ok(InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Deferred,
            disclosed_outcome: decision.disclosed_outcome,
            received_at: Some(now()),
            retry_after_ms: None,
        });
    }

    let (event_id, event_canonical_digest, duplicate, realm_id) = match projection {
        InvitePrivateProjection::FromDeliveredEvent { session } => {
            let validated = super::events::event_log::validate_private_invite_envelope(
                state,
                session,
                &body["invite_event"],
            )
            .await
            .map_err(|error| {
                crate::app_error!(SchemaViolation, error.message).with_wire_code(error.code)
            })?;
            let duplicate = persist_private_invite_projection(
                state,
                &delivery.invite_address.account_id,
                body,
                &validated,
            )
            .await?;
            (
                validated.event_id.to_string(),
                validated.canonical_digest,
                duplicate,
                validated.realm_id.to_string(),
            )
        }
        InvitePrivateProjection::AlreadyAcceptedLocally { record } => (
            record.event_id.clone(),
            record.canonical_digest.clone(),
            false,
            record.realm_id.clone().ok_or_else(|| {
                AppError::internal("accepted ak.invite.create carries no realm_id")
            })?,
        ),
    };

    // §7 — the notify branch owes the invitee_id's devices the private delivery
    // material itself: the invite token is transport material, never an Invite
    // read-model field (governance-objects.md §5.3), so it travels on the
    // actor-private account-data carrier instead.
    let inviter_account_id = delivery
        .invite_event
        .actor_id
        .as_account_id()
        .ok_or_else(|| super::events::peer::schema_violation("invite author must be an account"))?;
    let credential_delivered = deliver_invite_credential(
        state,
        &delivery.invite_address.account_id,
        inviter_account_id,
        body,
        &realm_id,
    )
    .await?;

    let status = if duplicate { "duplicate" } else { "accepted" };
    super::append_audit_log(
        state,
        None,
        audit_operation,
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": event_id,
            "invitee_id": delivery.invite_address.account_id.principal_id,
            "recipient_id": delivery.invite_address.account_id.station_id,
            "introduction_kind": delivery.introduction_evidence.kind(),
            "effective_kind": decision.effective_kind,
            "trust_tier": decision.trust_tier.as_str(),
            "request_canonical_digest": crate::util::canonical_digest(body)?,
            "event_canonical_digest": event_canonical_digest,
            "projection": "holder_private_invite",
            "credential_delivered": credential_delivered,
        }),
        status,
    )
    .await;
    Ok(InviteDeliveryOutcome {
        status: if duplicate {
            InviteDeliveryOutcomeStatus::Duplicate
        } else {
            InviteDeliveryOutcomeStatus::Accepted
        },
        disclosed_outcome: decision.disclosed_outcome,
        received_at: Some(now()),
        retry_after_ms: None,
    })
}

#[endpoint(
    operation_id = "ak.self.invites.command.dispatch",
    summary = "Dispatch a private invite delivery",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.invites.command.dispatch.v1"))]
async fn self_invites_dispatch(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteDeliveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let raw_body = req
        .payload()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.self.invites.command.dispatch.v1 request body")
        })?
        .to_vec();
    let body: Value = serde_json::from_slice(&raw_body).map_err(|_| {
        AppError::json_invalid("invalid ak.self.invites.command.dispatch.v1 request body")
    })?;
    let dispatch: SelfInviteDispatchRequestBody =
        serde_json::from_value(body.clone()).map_err(|error| {
            AppError::param_invalid(format!("invalid invite dispatch request: {error}"))
        })?;
    dispatch
        .validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;

    let accepted = require_dispatchable_invite_event(state, &session, &dispatch).await?;
    // `canonical_bytes` is the Event digest preimage and deliberately omits
    // identity/proof fields such as `event_id`.  Private delivery carries the
    // complete accepted Event, which is stored separately as the envelope.
    let invite_event = serde_json::from_value(accepted.envelope.clone())
        .map_err(|error| AppError::internal(format!("stored invite Event is invalid: {error}")))?;
    let delivery = InviteDeliveryRequestBody {
        schema: dispatch.schema,
        invite_event,
        invite_address: dispatch.invite_address,
        introduction_evidence: dispatch.introduction_evidence,
        idempotency_key: dispatch.idempotency_key,
    };
    let delivery_body = serde_json::to_value(&delivery)
        .map_err(|error| AppError::internal(format!("invite delivery encoding failed: {error}")))?;

    if delivery.invite_address.account_id.station_id.as_str() == state.service_id() {
        // §7 — the local target runs the same steps 4-9 the peer ingress runs.
        return json_ok(
            receive_private_invite_delivery(
                state,
                &delivery,
                &delivery_body,
                state.service_id(),
                "self.invites.dispatch",
                InvitePrivateProjection::AlreadyAcceptedLocally { record: &accepted },
            )
            .await?,
        );
    }
    json_ok(enqueue_remote_invite_delivery(state, &delivery, &delivery_body, &accepted).await?)
}

/// Spec invite-addressing.md §7 — the accepted Event preconditions
/// of `ak.self.invites.command.dispatch.v1`.
///
/// The order is closed: resolve the accepted Event by `event_id` first, then
/// compare its stored signing actor.
/// Each failure is `failed_precondition` carrying its own reason code, and none
/// of them may produce a delivery, an outbox enqueue or a holder-private write,
/// so they are evaluated before either dispatch branch does anything at all.
///
/// This operation MUST NOT re-verify the signature of an Event this service
/// already admitted. Delivery uses the accepted, validated Event envelope stored at admission;
/// `canonical_bytes` is only the digest preimage and is never a wire Event carrier.
async fn require_dispatchable_invite_event(
    state: &AppState,
    session: &SessionRecord,
    dispatch: &SelfInviteDispatchRequestBody,
) -> Result<AcceptedEvent, AppError> {
    let Some(accepted) = state
        .event_queries()
        .canonical_event(dispatch.invite_event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("invite event lookup: {error}")))?
    else {
        return Err(invite_event_precondition(
            arkret_wire::ReasonCode::INVITE_EVENT_UNACCEPTED,
            "invite_event has not been accepted by this Station",
        ));
    };
    let session_principal = DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    let session_station = DidCoreId::new(session.audience.clone())
        .map_err(|error| AppError::internal(format!("session audience is invalid: {error}")))?;
    let session_actor = if session.agent_session.is_some() {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            session_principal,
            session_station,
        ))
    } else {
        let account_pk = session
            .account_pk
            .ok_or_else(|| AppError::unauthenticated("session account binding is missing"))?;
        let account = state
            .identities()
            .account_by_id(account_pk)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
        if account.account_id.principal_id != session_principal
            || account.account_id.station_id != session_station
        {
            return Err(AppError::unauthenticated(
                "session does not bind the stored account",
            ));
        }
        arkret_wire::ActorId::account(account.account_id)
    };
    let accepted_actor: arkret_wire::ActorId = serde_json::from_str(&accepted.actor_id)
        .map_err(|error| AppError::internal(format!("stored Event actor is invalid: {error}")))?;
    let event: arkret_wire::Event =
        serde_json::from_value(accepted.envelope.clone()).map_err(|error| {
            AppError::internal(format!("stored Event envelope is invalid: {error}"))
        })?;
    if event.actor_id != accepted_actor {
        return Err(AppError::internal(
            "stored Event actor does not match its canonical envelope",
        ));
    }
    if event.executed_by.as_ref().unwrap_or(&accepted_actor) != &session_actor {
        return Err(invite_event_precondition(
            arkret_wire::ReasonCode::INVITE_EVENT_ACTOR_MISMATCH,
            "invite_event was not signed by the authenticated session actor",
        ));
    }
    Ok(accepted)
}

fn invite_event_precondition(reason_code: &'static str, message: &'static str) -> AppError {
    crate::app_error!(FailedPrecondition, message)
        .with_wire_code("failed_precondition")
        .with_reason_code(reason_code)
}

/// Spec invite-addressing.md §7 — hand the exact canonical request body to the
/// durable service-to-service outbox bound for `ak.peer.invites.command.submit.v1`.
///
/// The payload is the JCS form of the bytes the caller sent, never a
/// re-encoding of the typed model, so every retry under the same
/// `idempotency_key` reproduces byte-identical wire bytes and the receiver
/// computes the same request digest. Deduplication is the outbox's own
/// `(peer_id, idempotency_key)` uniqueness.
async fn enqueue_remote_invite_delivery(
    state: &AppState,
    delivery: &InviteDeliveryRequestBody,
    body: &Value,
    accepted: &AcceptedEvent,
) -> Result<InviteDeliveryOutcome, AppError> {
    validate_invite_delivery_event_binding(body, delivery)?;
    let recipient_id = &delivery.invite_address.account_id.station_id;
    let resolver = state
        .service_route_resolver()
        .map_err(|error| AppError::internal(error.to_owned()))?;
    let entry = resolver
        .resolve_carrier(
            &delivery.invite_address.service_resolution,
            recipient_id,
            "station",
            now(),
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                FailedPrecondition,
                format!("recipient service has no verified route: {error}"),
            )
        })?;
    let payload_json =
        String::from_utf8(canonical::canonical_json_bytes(body).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "ak.self.invites.command.dispatch.v1 body is not canonicalizable: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::internal(format!("invite delivery body is not utf8: {error}"))
        })?;
    let enqueued_id = uuid::Uuid::new_v4().to_string();
    let enqueued = state
        .federation()
        .enqueue_delivery(EnqueueFederationDeliveryCommand {
            delivery: FederationDeliveryRecord {
                id: enqueued_id.clone(),
                peer_id: recipient_id.clone(),
                peer_url: Some(entry.base_url.trim_end_matches('/').to_owned()),
                endpoint: PEER_INVITES_ENDPOINT.to_owned(),
                idempotency_key: delivery.idempotency_key.clone(),
                payload_json,
                coalescing_key: None,
                coalescing_position: None,
                realm_fanout: None,
                created_at: now().timestamp(),
            },
        })
        .await
        .map_err(|error| AppError::internal(format!("invite delivery enqueue: {error}")))?;
    let duplicate = enqueued.id != enqueued_id;
    super::append_audit_log(
        state,
        None,
        "self.invites.dispatch",
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": accepted.event_id,
            "invitee_id": delivery.invite_address.account_id.principal_id,
            "recipient_id": delivery.invite_address.account_id.station_id,
            "introduction_kind": delivery.introduction_evidence.kind(),
            "outbox_id": enqueued.id,
            "endpoint": PEER_INVITES_ENDPOINT,
        }),
        if duplicate { "duplicate" } else { "accepted" },
    )
    .await;
    Ok(InviteDeliveryOutcome {
        status: if duplicate {
            InviteDeliveryOutcomeStatus::Duplicate
        } else {
            InviteDeliveryOutcomeStatus::Accepted
        },
        // The recipient's receive decision is not knowable here, and §5.1
        // forbids inventing one, so the sender never echoes a disclosed
        // outcome for a remote target.
        disclosed_outcome: None,
        received_at: Some(now()),
        retry_after_ms: None,
    })
}

async fn persist_private_invite_projection(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    body: &Value,
    validated: &super::events::event_log::ValidatedEventEnvelope,
) -> Result<bool, AppError> {
    if account_id.station_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "private invite holder belongs to another Station",
        ));
    }
    let event = body
        .get("invite_event")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event must be an object"))?;
    let payload = event
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    let invite_id = arkret_wire::InviteId::from_event_id(&validated.event_id).to_string();
    let created_at = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            super::events::peer::schema_violation(
                "invite_event.created_at must be an RFC 3339 timestamp",
            )
        })?;
    let expires_at = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .map(|parsed| parsed.with_timezone(&chrono::Utc))
                .map_err(|_| {
                    super::events::peer::schema_violation(
                        "invite_event.payload.expires_at must be an RFC 3339 timestamp",
                    )
                })
        })
        .transpose()?
        .or_else(|| Some(created_at + Duration::days(7)));
    let introduction_evidence_digest = payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: validated.realm_id.to_string(),
        inviter_id: validated
            .actor
            .as_account_id()
            .ok_or_else(|| {
                super::events::peer::schema_violation("invite author must be an account")
            })?
            .to_string(),
        invitee_id: Some(account_id.to_string()),
        introduction_evidence_digest,
        third_party_invite: None,
        invite_token: crate::routing::generate_invite_token(
            &invite_id,
            validated.realm_id.as_str(),
            &account_id.to_string(),
        ),
        status: "pending".to_owned(),
        claim_nonces: std::collections::BTreeMap::new(),
        expires_at,
        created_at,
        updated_at: None,
    };

    let invites = state.realm_invites();
    if let Some(existing) = invites
        .get(&invite_id)
        .await
        .map_err(|error| AppError::internal(format!("private invite lookup: {error}")))?
    {
        let exact_replay = existing.realm_id == record.realm_id
            && existing.inviter_id == record.inviter_id
            && existing.invitee_id == record.invitee_id
            && existing.introduction_evidence_digest == record.introduction_evidence_digest
            && existing.expires_at == record.expires_at
            && existing.created_at == record.created_at;
        if exact_replay {
            return Ok(true);
        }
        return Err(crate::app_error!(
            DuplicateConflict,
            "invite_id is already bound to a different private invite delivery",
        )
        .with_wire_code("duplicate_conflict"));
    }
    invites
        .put(record)
        .await
        .map_err(|error| AppError::internal(format!("private invite projection: {error}")))?;
    Ok(false)
}

/// Spec invite-addressing.md §7 — hand a notified invite's private delivery
/// material to the invitee_id's devices.
///
/// The invite token is transport material: `governance-objects.md` §5.3
/// forbids materializing it on the Invite object, so the authz Invite read
/// model never carries it. The holder-private carrier is the actor-private
/// account-data cell `ak.account.invite_delivery` — the same carrier family
/// `consent-model.md` §6.1.1 defines for the quarantine inbox — persisted as a
/// bounded CAS register so late devices can read it back, and fanned out to
/// every device as an `ak.account_data.update`.
///
/// The token itself is derived with the same inputs the invite projection
/// used, so this never has to read the invite row back: the local dispatch
/// branch runs before the reducer projection is guaranteed visible, and a
/// deterministic derivation cannot race it.
async fn deliver_invite_credential(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    inviter_account_id: &arkret_wire::AccountId,
    body: &Value,
    realm_id: &str,
) -> Result<bool, AppError> {
    if account_id.station_id != state.service_core_id() {
        return Err(AppError::param_invalid(
            "invite subject belongs to another Station",
        ));
    }
    let subject_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
    let subject_exists = state
        .identities()
        .account(account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    if !subject_exists {
        // No local account means no devices to reach; the invite row itself is
        // already persisted, so this delivery stays `accepted`.
        return Ok(false);
    }
    let event = body
        .get("invite_event")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event must be an object"))?;
    let payload = event
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    // event-payload.schema.json `invite_create_payload`: the Invite id is
    // derived from the create Event's id and MUST NOT be carried in the
    // genesis payload, so derive it here instead of reading
    // `payload.invite_id`.
    let invite_id = event
        .get("event_id")
        .and_then(Value::as_str)
        .and_then(|value| arkret_identifiers::EventId::new(value.to_owned()).ok())
        .map(|event_id| arkret_identifiers::InviteId::from_event_id(&event_id))
        .ok_or_else(|| {
            super::events::peer::schema_violation("invite_event.event_id must be an Event id")
        })?;
    let created_at = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            super::events::peer::schema_violation(
                "invite_event.created_at must be an RFC 3339 timestamp",
            )
        })?;
    let expires_at = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .map(|parsed| parsed.with_timezone(&chrono::Utc))
                .map_err(|_| {
                    super::events::peer::schema_violation(
                        "invite_event.payload.expires_at must be an RFC 3339 timestamp",
                    )
                })
        })
        .transpose()?
        .unwrap_or_else(|| created_at + Duration::days(7));
    let invite_token = crate::routing::generate_invite_token(
        invite_id.as_str(),
        realm_id,
        &account_id.to_string(),
    );

    let received_at = now();
    let new_entry = InviteDeliveryEntry {
        invite_id,
        realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("invite realm id is invalid: {error}")))?,
        inviter_account_id: inviter_account_id.clone(),
        invite_token,
        received_at,
        expires_at,
    };
    let account_data = state.account_data();
    let mut attempt = 0;
    let record = loop {
        let existing = account_data
            .entry(&subject_actor, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let existing_cell = existing
            .as_ref()
            .map(|record| serde_json::from_value::<InviteDelivery>(record.payload.clone()))
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("invite delivery cell does not parse: {error}"))
            })?;
        let cell = merge_invite_delivery_cell(existing_cell, new_entry.clone(), received_at)?;
        let payload = serde_json::to_value(&cell).map_err(|error| {
            AppError::internal(format!("invite delivery cell serialize: {error}"))
        })?;
        let record = AccountDataState {
            actor_id: subject_actor.clone(),
            account_data_key: AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
            revision: existing.as_ref().map_or(1, |record| record.revision + 1),
            payload,
            tombstone: false,
            updated_at: received_at,
        };
        let expected_revision = existing.as_ref().map_or(0, |record| record.revision);
        #[cfg(test)]
        tokio::task::yield_now().await;
        match account_data
            .compare_and_set(record, expected_revision)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            AccountDataCasOutcome::Applied(record) => break record,
            AccountDataCasOutcome::Conflict(_) => {
                attempt += 1;
                if attempt >= INVITE_DELIVERY_CAS_ATTEMPTS {
                    return Err(crate::app_error!(
                        CasConflict,
                        "invite delivery account data changed concurrently",
                    ));
                }
            }
        }
    };
    fanout_actor_private_update(
        state,
        account_id.principal_id.as_str(),
        ActorPrivateDeviceUpdate::AccountData {
            sender: station_device_message_sender(state),
            content: ActorPrivateAccountDataUpdate {
                operation: ActorPrivateAccountDataOperation::Put,
                account_data_key: AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
                revision: record.revision,
                content: Some(record.payload.clone()),
                updated_at: record.updated_at,
            },
            created_at: record.updated_at,
        },
    )
    .await;
    Ok(true)
}

/// Merge one accepted delivery into the current `ak.account.invite_delivery`
/// cell (spec invite-addressing.md §7 write semantics): purge entries expired
/// at `received_at`, replace any prior entry for the same invite, append the
/// new entry, then evict the oldest entries beyond
/// [`InviteDelivery::MAX_ENTRIES`]. The result is validated against the SDK
/// cell contract before it is offered to the CAS write.
fn merge_invite_delivery_cell(
    existing: Option<InviteDelivery>,
    new_entry: InviteDeliveryEntry,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<InviteDelivery, AppError> {
    let mut cell = existing.unwrap_or_else(|| InviteDelivery::new(received_at, Vec::new()));
    cell.delivery_entries.retain(|candidate| {
        invite_delivery_entry_active(candidate, received_at)
            && candidate.invite_id != new_entry.invite_id
    });
    cell.delivery_entries.push(new_entry);
    if cell.delivery_entries.len() > InviteDelivery::MAX_ENTRIES {
        let excess = cell.delivery_entries.len() - InviteDelivery::MAX_ENTRIES;
        cell.delivery_entries.drain(0..excess);
    }
    cell.updated_at = received_at;
    cell.validate()
        .map_err(|error| AppError::internal(format!("invite delivery cell is invalid: {error}")))?;
    Ok(cell)
}

fn invite_delivery_entry_active(
    entry: &InviteDeliveryEntry,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    entry.expires_at > at
}

#[endpoint(
    operation_id = "ak.open.invite_locator.read.resolve",
    summary = "Resolve an invite locator",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.invite_locator.read.resolve.v1"))]
async fn resolve_invite_locator(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalLocator> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if locator_token_appears_in_url(req) {
        return Err(AppError::param_invalid(
            "locator_token must be sent in the JSON body, never in URL path or query",
        )
        .with_wire_code("schema_violation"));
    }
    let body = req
        .parse_json::<InviteLocatorResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid invite locator resolve request body"))?;
    body.validate_minimal()
        .map_err(|_| invite_locator_not_found())?;
    let locator_token = body.locator_token.trim();
    let token_digest = format!("sha256:{}", sha256_hex(locator_token.as_bytes()));
    let locator_ref = state
        .realm_invites()
        .resolve_and_consume_locator(&token_digest, now())
        .await
        .map_err(|error| AppError::internal(format!("invite locator resolve: {error}")))?
        .ok_or_else(invite_locator_not_found)?;
    let subject_id =
        DidCoreId::new(locator_ref.subject_id.clone()).map_err(|_| invite_locator_not_found())?;
    let issued_at = locator_ref.issued_at;
    let expires_at = locator_ref.expires_at;
    let locator_ref_digest = Hash::new(locator_ref.token_digest.clone())
        .map_err(|error| AppError::internal(format!("locator_ref_digest invalid: {error}")))?;
    let display_hint = locator_ref.display_hint;
    let recipient_id = DidCoreId::new(locator_ref.recipient_id).map_err(|error| {
        AppError::internal(format!(
            "configured service DID invalid for principal locator: {error}"
        ))
    })?;
    let mut locator = PrincipalLocator {
        schema: arkret_wire::SchemaId::PRINCIPAL_LOCATOR_V1.to_owned(),
        account_id: arkret_wire::AccountId::new(subject_id, recipient_id.clone()),
        service_resolution: ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: format!(
                "{}{}",
                state.config().public_base_url.trim_end_matches('/'),
                arkret_models_identity::canonical_service_current_record_path(&recipient_id)
            ),
            pinned_record_digest: None,
        },
        route_assistance: None,
        issued_at,
        expires_at,
        locator_ref_digest,
        display_hint,
        proofs: Vec::new(),
    };
    let mut proof =
        DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: state.service_verification_method("notary-key").map_err(
                |error| AppError::internal(format!("principal locator signing method: {error}")),
            )?,
            payload_digest: locator.payload_digest().map_err(|error| {
                AppError::internal(format!("principal locator digest: {error}"))
            })?,
            created_at: now(),
            domain: None,
            audience: None,
            jws: String::new(),
        };
    let signing_bytes = locator
        .proof_signing_bytes(&proof)
        .map_err(|error| AppError::internal(format!("principal locator transcript: {error}")))?;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &signing_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("principal locator sign: {error}")))?;
    locator.proofs = vec![PrincipalLocatorProof {
        proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
        proof,
    }];
    locator.validate_minimal().map_err(|error| {
        AppError::internal(format!("principal locator validation failed: {error}"))
    })?;
    json_ok(locator)
}

/// Spec invite-addressing.md §2 — introduction-evidence trust tiers.
/// High = `{locator_ref, consent_grant, shared_realm}`; Low =
/// `{same_station, explicit_address, missing/invalid evidence}`. The tier
/// drives both the receive action and the §5.1 graded disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustTier {
    High,
    Discovery,
    Low,
}

impl TrustTier {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Discovery => "discovery",
            Self::Low => "low",
        }
    }
}

fn receive_action_str(action: &InviteReceiveAction) -> &'static str {
    match action {
        InviteReceiveAction::Drop => "drop",
        InviteReceiveAction::Quarantine => "quarantine",
        InviteReceiveAction::Notify => "notify",
    }
}

async fn persist_invite_quarantine_entry(
    state: &AppState,
    subject: &str,
    source_id: &str,
    inviter_id: &str,
    delivery: &InviteDeliveryRequestBody,
    body: &Value,
    decision: &ReceiveDecision,
) -> Result<bool, AppError> {
    let account_id = &delivery.invite_address.account_id;
    if account_id.principal_id.as_str() != subject
        || account_id.station_id != state.service_core_id()
    {
        return Err(AppError::capability_denied(
            "invite quarantine holder mismatch",
        ));
    }
    let subject_exists = state
        .identities()
        .account(account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    if !subject_exists {
        super::append_audit_log(
            state,
            None,
            "peer.invites.quarantine",
            json!({
                "invitee_id": subject,
                "source_id": source_id,
                "receive_action": receive_action_str(&decision.action),
                "reason": "unknown_subject",
            }),
            "skipped",
        )
        .await;
        return Ok(false);
    }

    let received_at = now();

    // `consent-model.md` section 6.1.1.3 -- the per-holder new-source quota is
    // evaluated here, at the single admission chokepoint, exactly once and
    // strictly before the CAS write. Deciding inside the retry loop below would
    // charge one delivery several times.
    if !admit_quarantine_new_source(state, account_id, inviter_id, received_at).await? {
        super::append_audit_log(
            state,
            Some(subject),
            "peer.invites.quarantine",
            json!({
                "invitee_id": subject,
                "source_id": source_id,
                "receive_action": receive_action_str(&decision.action),
                "reason": "new_source_quota_exhausted",
            }),
            "skipped",
        )
        .await;
        return Ok(false);
    }

    let expires_at = received_at + Duration::days(INVITE_QUARANTINE_TTL_DAYS);
    let invite_event_id = body
        .pointer("/invite_event/event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| arkret_wire::EventId::new(value.to_owned()))
        .transpose()
        .map_err(|error| AppError::param_invalid(format!("invalid invite event id: {error}")))?
        .ok_or_else(|| AppError::param_invalid("invite Event id is required for quarantine"))?;
    let request_digest = crate::util::canonical_digest(body)?;
    let idempotency_key_digest =
        format!("sha256:{}", sha256_hex(delivery.idempotency_key.as_bytes()));
    let entry_digest = crate::util::canonical_digest(&json!({
        "account_id": account_id,
        "source_id": source_id,
        "idempotency_key": delivery.idempotency_key,
        "invite_event_id": invite_event_id,
    }))?;
    let parse_digest = |value: String| {
        Hash::new(value)
            .map_err(|error| AppError::internal(format!("invite quarantine digest: {error}")))
    };
    let entry = InviteQuarantineEntry {
        entry_digest: parse_digest(entry_digest)?,
        status: InviteQuarantineStatus::PendingReview,
        account_id: account_id.clone(),
        source_peer_principal_id: DidCoreId::new(inviter_id.to_owned())
            .map_err(|error| AppError::param_invalid(format!("invalid inviter: {error}")))?,
        source_id: DidCoreId::new(source_id.to_owned())
            .map_err(|error| AppError::param_invalid(format!("invalid source: {error}")))?,
        consent_scope: InviteQuarantineScope::Invite,
        introduction_kind: serde_json::from_value(json!(delivery.introduction_evidence.kind()))
            .map_err(|error| AppError::internal(format!("invalid introduction kind: {error}")))?,
        effective_kind: serde_json::from_value(json!(decision.effective_kind))
            .map_err(|error| AppError::internal(format!("invalid effective kind: {error}")))?,
        trust_tier: match decision.trust_tier {
            TrustTier::High => InviteTrustTier::High,
            TrustTier::Discovery => InviteTrustTier::Discovery,
            TrustTier::Low => InviteTrustTier::Low,
        },
        invite_event_id: invite_event_id.clone(),
        request_digest: parse_digest(request_digest)?,
        idempotency_key_digest: parse_digest(idempotency_key_digest)?,
        received_at,
        expires_at,
    };

    let account_data = state.account_data();
    let subject_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
    let mut attempt = 0;
    let record = loop {
        let existing = account_data
            .entry(&subject_actor, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let existing_cell = existing
            .as_ref()
            .map(|record| serde_json::from_value::<InviteQuarantine>(record.payload.clone()))
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("invalid invite quarantine cell: {error}"))
            })?;
        let quarantine =
            merge_invite_quarantine_cell(existing_cell, entry.clone(), received_at, account_id)?;
        let cell_updated_at = quarantine.updated_at;
        let payload = serde_json::to_value(&quarantine)
            .map_err(|error| AppError::internal(format!("invite quarantine encode: {error}")))?;
        let record = AccountDataState {
            actor_id: subject_actor.clone(),
            account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
            revision: existing.as_ref().map_or(1, |record| record.revision + 1),
            payload,
            tombstone: false,
            updated_at: cell_updated_at,
        };
        let expected_revision = existing.as_ref().map_or(0, |record| record.revision);
        match account_data
            .compare_and_set(record, expected_revision)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            AccountDataCasOutcome::Applied(record) => break record,
            AccountDataCasOutcome::Conflict(_) => {
                attempt += 1;
                if attempt >= INVITE_QUARANTINE_CAS_ATTEMPTS {
                    // Quarantine, policy drop, unknown holder and anti-abuse
                    // drop are one opaque wire class. A hot CAS cell therefore
                    // degrades to a silent local drop instead of exposing a
                    // sender-visible `cas_conflict` discriminator.
                    super::append_audit_log(
                        state,
                        Some(subject),
                        "peer.invites.quarantine",
                        json!({
                            "invitee_id": subject,
                            "source_id": source_id,
                            "inviter_id": inviter_id,
                            "invite_event_id": invite_event_id,
                            "reason": "concurrent_write_saturation",
                        }),
                        "skipped",
                    )
                    .await;
                    return Ok(false);
                }
            }
        }
    };
    fanout_actor_private_update(
        state,
        subject,
        ActorPrivateDeviceUpdate::AccountData {
            sender: station_device_message_sender(state),
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
    super::append_audit_log(
        state,
        Some(subject),
        "peer.invites.quarantine",
        json!({
            "invitee_id": subject,
            "source_id": source_id,
            "inviter_id": inviter_id,
            "invite_event_id": invite_event_id,
            "expires_at": expires_at,
        }),
        "accepted",
    )
    .await;
    Ok(true)
}

/// Run the quarantine admission chokepoint for one first contact.
///
/// Returns `true` when the caller may proceed to the quarantine cell write --
/// either because this source was already admitted inside the retention window,
/// or because it fit under both sliding ceilings and was just charged. `false`
/// means the delivery is silently dropped: no ledger write, no cell write, and
/// the same opaque `deferred` the requester sees for every other member of the
/// `consent-model.md` section 6.1.1 equivalence class.
async fn admit_quarantine_new_source(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    inviter_id: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, AppError> {
    let quota = effective_new_source_quota(state, account_id)?;
    let source_digest = new_source_ledger_digest(state, account_id, inviter_id);
    let admission = state
        .persistence()
        .invite_new_source_ledger_store()
        .admit_new_source(account_id, &source_digest, received_at, &quota)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(admission != NewSourceAdmission::Denied)
}

/// Intersect the deployment ceiling with the holder override.
///
/// An absent deployment object is not "quota off": section 6.1.1.1 makes the
/// quota a MUST, so the specification defaults apply and the empty constraints
/// object produces exactly those.
fn effective_new_source_quota(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> Result<EffectiveNewSourceQuota, AppError> {
    let constraints = constraints_for_surface(state, ReceivePolicySurface::InviteDelivery)
        .and_then(|constraints| constraints.new_source_quota.clone())
        .unwrap_or_default();
    let policy = resolve_core_invite_receive_policy(state, account_id);
    constraints
        .effective(policy.new_source_quota.as_ref())
        .map_err(|error| AppError::internal(error.to_string()))
}

/// Keyed digest of `(holder, source peer principal)`.
///
/// Section 6.1.1.4 only needs equality for membership testing, so the ledger
/// stores a digest keyed by this Station's private notary key rather than a
/// readable list of every stranger who has contacted a holder. The holder is
/// bound into the transcript as well, so one holder's rows cannot be correlated
/// with another's.
fn new_source_ledger_digest(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    inviter_id: &str,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let secret = state.notary_signing_key().to_bytes();
    let material = format!(
        "soland-invite-new-source-ledger-v1\0{}\0{}\0{inviter_id}",
        account_id.principal_id.as_str(),
        account_id.station_id.as_str()
    );
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&secret)
        .expect("HMAC accepts keys of any length");
    mac.update(material.as_bytes());
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    hex::encode(tag)
}

fn merge_invite_quarantine_cell(
    existing: Option<InviteQuarantine>,
    new_entry: InviteQuarantineEntry,
    received_at: chrono::DateTime<chrono::Utc>,
    account_id: &arkret_wire::AccountId,
) -> Result<InviteQuarantine, AppError> {
    let mut quarantine = existing.unwrap_or_else(|| InviteQuarantine::new(received_at));
    quarantine
        .validate_holder(account_id)
        .map_err(|error| AppError::internal(format!("invite quarantine binding: {error}")))?;
    let updated_at = quarantine.updated_at.max(received_at);
    quarantine.quarantine_entries.retain(|candidate| {
        candidate.expires_at > updated_at && candidate.entry_digest != new_entry.entry_digest
    });
    quarantine.quarantine_entries.push(new_entry);
    quarantine.quarantine_entries.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.entry_digest.as_str().cmp(right.entry_digest.as_str()))
    });
    if quarantine.quarantine_entries.len() > MAX_INVITE_QUARANTINE_ENTRIES {
        let excess = quarantine.quarantine_entries.len() - MAX_INVITE_QUARANTINE_ENTRIES;
        quarantine.quarantine_entries.drain(0..excess);
    }
    quarantine.updated_at = updated_at;
    quarantine
        .validate_holder(account_id)
        .map_err(|error| AppError::internal(format!("invite quarantine binding: {error}")))?;
    Ok(quarantine)
}

/// Effective trust tier of an introduction evidence kind, *after* any
/// `consent_grant` verification downgrade has been resolved by the caller.
fn trust_tier_for_kind(kind: &str) -> TrustTier {
    match kind {
        "locator_ref" | "consent_grant" | "shared_realm" => TrustTier::High,
        "handle_claim" => TrustTier::Discovery,
        // same_station / explicit_address / unknown → low
        _ => TrustTier::Low,
    }
}

/// Outcome of applying the subject's `invite_receive_policy` to one
/// delivery: the receive action, the effective (post-downgrade) evidence
/// kind, its trust tier, and the graded-disclosure value to echo back.
pub(crate) struct ReceiveDecision {
    pub(crate) action: InviteReceiveAction,
    pub(crate) effective_kind: &'static str,
    pub(crate) trust_tier: TrustTier,
    pub(crate) disclosed_outcome: Option<DisclosedOutcome>,
}

/// Read the subject's private `invite_receive_policy`, falling back to the
/// conservative protocol default when the subject has never published one.
///
/// `invite-addressing.md` section 5 makes that default normative: a subject
/// without a published policy accepts only the high-trust introduction kinds
/// and quarantines or drops everything else. Erroring out instead would both
/// break that default and leak, through a distinguishable status, whether the
/// subject has ever published a policy — which section 5.1 requires to stay
/// indistinguishable from an ordinary quarantine.
fn resolve_core_invite_receive_policy(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> InviteReceivePolicy {
    state
        .contacts()
        .invite_policy(account_id)
        .unwrap_or_else(|| InviteReceivePolicy::spec_default(account_id.clone()))
}

/// Spec invite-addressing.md §2/§5/§5.1/§7-8 — the full receive decision.
pub(crate) fn directory_handle_claim_resolve_allowed(
    state: &AppState,
    intent: Option<DirectoryIntent>,
    requester_id: Option<&DidCoreId>,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
    handle_claim: &HandleClaim,
    resolved_by: Option<DidCoreId>,
) -> bool {
    if !matches!(
        intent,
        Some(
            DirectoryIntent::ContactRequest | DirectoryIntent::Invite | DirectoryIntent::MemberAdd
        )
    ) {
        return true;
    }
    let Some(requester_id) = requester_id else {
        return false;
    };
    let handle = handle_claim.claim.handle.clone();
    let Ok(subject_id) = DidCoreId::new(subject.to_owned()) else {
        return false;
    };
    let Ok(station_id) = DidCoreId::new(recipient_id.to_owned()) else {
        return false;
    };
    let policy = resolve_core_invite_receive_policy(
        state,
        &arkret_wire::AccountId::new(subject_id, station_id),
    );
    let Ok(requester_station_id) = DidCoreId::new(source_id.to_owned()) else {
        return false;
    };
    let requester_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        requester_id.clone(),
        requester_station_id,
    ));
    let decision = match intent {
        Some(DirectoryIntent::ContactRequest) => {
            let evidence = ContactIntroductionEvidence::HandleClaim {
                handle,
                handle_claim: Box::new(handle_claim.clone()),
                resolved_by,
                resolved_at: Some(chrono::Utc::now()),
            };
            evaluate_contact_receive(
                state,
                &policy,
                &evidence,
                requester_id.as_str(),
                subject,
                recipient_id,
                source_id,
            )
        }
        Some(DirectoryIntent::Invite | DirectoryIntent::MemberAdd) => {
            let evidence = IntroductionEvidence::HandleClaim {
                handle,
                handle_claim: Box::new(handle_claim.clone()),
                resolved_by,
                resolved_at: Some(chrono::Utc::now()),
            };
            evaluate_invite_receive(
                state,
                &policy,
                &evidence,
                &requester_actor_id,
                requester_id.as_str(),
                subject,
                recipient_id,
                source_id,
                false,
            )
        }
        _ => return true,
    };
    decision.effective_kind == "handle_claim" && decision.action != InviteReceiveAction::Drop
}

fn evaluate_invite_receive(
    state: &AppState,
    policy: &InviteReceivePolicy,
    evidence: &IntroductionEvidence,
    inviter_actor_id: &arkret_wire::ActorId,
    inviter_id: &str,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
    same_station: bool,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::InviteDelivery);

    // §5 — exact `denied_actor_ids` hit: MUST drop and force opaque disclosure so
    // the blocklist cannot leak through the response side channel.
    if policy
        .denied_actor_ids
        .iter()
        .any(|actor| actor == inviter_actor_id)
    {
        return ReceiveDecision {
            action: InviteReceiveAction::Drop,
            effective_kind: if same_station && evidence.kind() == "explicit_address" {
                "same_station"
            } else {
                evidence.kind()
            },
            trust_tier: TrustTier::Low,
            disclosed_outcome: None,
        };
    }

    // §2 — `consent_grant` evidence: verify the referenced grant is an
    // active `invite`/`any` dot the subject gave the inviter_id. On failure
    // MUST downgrade to low-trust `explicit_address`.
    if principal_service_blocked(policy, constraints, source_id)
        || !principal_service_trusted(policy, constraints, source_id)
        || !subject_did_method_accepted(constraints, subject)
    {
        return opaque_drop(evidence.kind());
    }

    let verified_kind: &'static str = match evidence {
        IntroductionEvidence::LocatorRef { principal_locator } => {
            if verified_locator_for_recipient(state, principal_locator, subject, recipient_id, now)
            {
                "locator_ref"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::ConsentGrant {
            consent_grant_ref,
            consent_id,
        } => {
            if crate::routing::identity::consent::has_active_consent_grant_evidence(
                state,
                subject,
                recipient_id,
                inviter_id,
                consent_grant_ref.as_str(),
                consent_id.as_deref(),
                now,
            ) {
                "consent_grant"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::SharedRealm { realm_id, .. } => {
            if policy.trusted_realm_ids.is_empty()
                || policy
                    .trusted_realm_ids
                    .iter()
                    .any(|trusted| trusted == realm_id)
            {
                "shared_realm"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::HandleClaim {
            handle,
            handle_claim,
            resolved_by,
            ..
        } => {
            if handle_claim_evidence_valid(
                policy,
                constraints,
                handle,
                handle_claim,
                resolved_by.as_ref(),
                subject,
                recipient_id,
                now,
            ) {
                "handle_claim"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::ExplicitAddress => "explicit_address",
    };
    let effective_kind = if verified_kind == "explicit_address" && same_station {
        "same_station"
    } else {
        verified_kind
    };

    if kind_forbidden_by_constraints(constraints, effective_kind)
        || !kind_permitted_by_constraints(constraints, effective_kind)
    {
        return opaque_drop(effective_kind);
    }

    // consent-model.md §6.1 step 2 — `require_explicit_consent` profile: only
    // verified `consent_grant` evidence may notify. Everything else is silently
    // dropped on the holder Station inside the opaque `deferred` class: no
    // quarantine, no quota charge, no holder-private write, and graded
    // disclosure is forced opaque so the profile itself is not observable.
    if policy.consent_profile.requires_explicit_consent() && effective_kind != "consent_grant" {
        return opaque_drop(effective_kind);
    }

    let trust_tier = trust_tier_for_kind(effective_kind);
    let action = receive_action_for_kind(policy, constraints, effective_kind);

    // §5.1 — graded disclosure. High-trust + `outcome` echoes the real
    // result; everything else stays opaque (`disclosed_outcome = None`).
    let disclosure_level = match trust_tier {
        TrustTier::High => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.high_trust.clone())
            .unwrap_or(DisclosureLevel::Outcome),
        TrustTier::Discovery => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.discovery_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
        TrustTier::Low => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.low_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
    };
    let disclosed_outcome = disclosed_outcome_for_action(disclosure_level, &action);

    ReceiveDecision {
        action,
        effective_kind,
        trust_tier,
        disclosed_outcome,
    }
}

fn verified_locator_for_recipient(
    state: &AppState,
    locator: &PrincipalLocator,
    subject: &str,
    recipient_id: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    if locator.validate_minimal().is_err()
        || locator.account_id.principal_id.as_str() != subject
        || locator.account_id.station_id.as_str() != recipient_id
        || locator.issued_at > at
        || locator.expires_at <= at
    {
        return false;
    }
    locator.proofs.iter().any(|entry| {
        let proof = &entry.proof;
        if entry.proof_purpose != PrincipalLocatorProofPurpose::RecipientServiceAcceptance
            || proof.kind != "detached_jws"
            || proof.created_at < locator.issued_at
            || proof.created_at > at
            || proof.created_at >= locator.expires_at
        {
            return false;
        }
        let Ok(transcript) = locator.proof_signing_bytes(proof) else {
            return false;
        };
        crate::jws_verify::verify_did_controlled_jws(
            &transcript,
            &proof.jws,
            proof.verification_method.as_str(),
            recipient_id,
            state,
        )
        .is_ok()
    })
}

pub(crate) fn evaluate_contact_receive(
    state: &AppState,
    policy: &InviteReceivePolicy,
    evidence: &ContactIntroductionEvidence,
    requester_id: &str,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::ContactRequest);
    let effective_kind: &'static str = match evidence {
        ContactIntroductionEvidence::LocatorRef { principal_locator } => {
            if verified_locator_for_recipient(state, principal_locator, subject, recipient_id, now)
            {
                "locator_ref"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::SharedRealm { realm_id, .. } => {
            if policy.trusted_realm_ids.is_empty()
                || policy
                    .trusted_realm_ids
                    .iter()
                    .any(|trusted| trusted == realm_id)
            {
                "shared_realm"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::HandleClaim {
            handle,
            handle_claim,
            resolved_by,
            ..
        } => {
            if handle_claim_evidence_valid(
                policy,
                constraints,
                handle,
                handle_claim,
                resolved_by.as_ref(),
                subject,
                recipient_id,
                now,
            ) {
                "handle_claim"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::SameStation => "same_station",
        ContactIntroductionEvidence::ExplicitAddress => "explicit_address",
    };

    let requester_actor = DidCoreId::new(requester_id.to_owned())
        .ok()
        .zip(DidCoreId::new(source_id.to_owned()).ok())
        .map(|(principal_id, station_id)| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id))
        });
    if requester_actor.as_ref().is_some_and(|requester| {
        policy
            .denied_actor_ids
            .iter()
            .any(|actor| actor == requester)
    }) || principal_service_blocked(policy, constraints, source_id)
        || !principal_service_trusted(policy, constraints, source_id)
        || !subject_did_method_accepted(constraints, subject)
        || kind_forbidden_by_constraints(constraints, effective_kind)
        || !kind_permitted_by_constraints(constraints, effective_kind)
    {
        return opaque_drop(effective_kind);
    }

    // consent-model.md §6.1 step 2 — the holder's `require_explicit_consent`
    // profile applies to first-contact delivery exactly as to invites.
    if policy.consent_profile.requires_explicit_consent() && effective_kind != "consent_grant" {
        return opaque_drop(effective_kind);
    }

    let trust_tier = trust_tier_for_kind(effective_kind);
    let action = receive_action_for_kind(policy, constraints, effective_kind);
    let disclosure_level = match trust_tier {
        TrustTier::High => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.high_trust.clone())
            .unwrap_or(DisclosureLevel::Outcome),
        TrustTier::Discovery => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.discovery_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
        TrustTier::Low => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.low_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
    };
    let disclosed_outcome = disclosed_outcome_for_action(disclosure_level, &action);
    ReceiveDecision {
        action,
        effective_kind,
        trust_tier,
        disclosed_outcome,
    }
}

fn constraints_for_surface(
    state: &AppState,
    surface: ReceivePolicySurface,
) -> Option<&ReceivePolicyConstraints> {
    state
        .config()
        .receive_policy_constraints
        .as_ref()
        .filter(|constraints| {
            constraints
                .applies_to
                .as_ref()
                .is_none_or(|surfaces| surfaces.contains(&surface))
        })
}

fn opaque_drop(effective_kind: &'static str) -> ReceiveDecision {
    ReceiveDecision {
        action: InviteReceiveAction::Drop,
        effective_kind,
        trust_tier: TrustTier::Low,
        disclosed_outcome: None,
    }
}

fn disclosed_outcome_for_action(
    disclosure_level: DisclosureLevel,
    action: &InviteReceiveAction,
) -> Option<DisclosedOutcome> {
    match (disclosure_level, action) {
        (DisclosureLevel::Outcome, InviteReceiveAction::Notify) => {
            Some(DisclosedOutcome::Delivered)
        }
        (DisclosureLevel::Outcome, InviteReceiveAction::Drop) => Some(DisclosedOutcome::Blocked),
        // Quarantine is holder-private consent state. It is always represented
        // externally by status=deferred without a disclosed_outcome, including
        // on high-trust/outcome routes.
        (DisclosureLevel::Outcome, InviteReceiveAction::Quarantine)
        | (DisclosureLevel::Opaque, _) => None,
    }
}

fn unknown_action_to_receive(action: &UnknownInviteAction) -> InviteReceiveAction {
    match action {
        UnknownInviteAction::Drop => InviteReceiveAction::Drop,
        UnknownInviteAction::Quarantine => InviteReceiveAction::Quarantine,
    }
}

fn receive_action_rank(action: &InviteReceiveAction) -> u8 {
    match action {
        InviteReceiveAction::Drop => 0,
        InviteReceiveAction::Quarantine => 1,
        InviteReceiveAction::Notify => 2,
    }
}

fn cap_receive_action(
    action: InviteReceiveAction,
    cap: Option<&InviteReceiveAction>,
) -> InviteReceiveAction {
    let Some(cap) = cap else {
        return action;
    };
    if receive_action_rank(&action) <= receive_action_rank(cap) {
        action
    } else {
        cap.clone()
    }
}

/// `invite-addressing.md` §5 / §5.2 — the holder's effective receive action for
/// one already-verified evidence kind.
///
/// The per-kind behavior fields do not carry two of the section's constraints
/// on their own:
///
/// - `holder_allowed_introduction_kinds` is an allowlist, and §5 states that an evidence kind
///   outside it MUST NOT reach a user notification. A holder who sets `handle_claim_behavior` /
///   `explicit_address_behavior` to `notify` without also allowlisting the kind therefore lands on
///   the next strictest behavior instead of notifying.
/// - `unknown_invites` governs deliveries with no evidence or non-conforming evidence.
///   `same_station` is receiver-derived but conforming, so it stays on the low-trust
///   `explicit_address_behavior` even when it is not allowlisted.
fn receive_action_for_kind(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
) -> InviteReceiveAction {
    let allowlisted = policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|kind| kind == effective_kind);
    let unknown_path = !allowlisted
        && !matches!(
            effective_kind,
            "handle_claim" | "same_station" | "explicit_address"
        );
    let mut action = match effective_kind {
        "handle_claim" => policy
            .handle_claim_behavior
            .clone()
            .unwrap_or(InviteReceiveAction::Quarantine),
        "same_station" | "explicit_address" => policy.explicit_address_behavior.clone(),
        _ if allowlisted => InviteReceiveAction::Notify,
        _ => unknown_action_to_receive(&policy.unknown_invites),
    };
    if !allowlisted {
        action = cap_receive_action(action, Some(&InviteReceiveAction::Quarantine));
    }
    apply_behavior_caps(constraints, effective_kind, unknown_path, action)
}

fn apply_behavior_caps(
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
    unknown_path: bool,
    action: InviteReceiveAction,
) -> InviteReceiveAction {
    let Some(constraints) = constraints else {
        return action;
    };
    let capped = match effective_kind {
        "handle_claim" => {
            cap_receive_action(action, constraints.handle_claim_max_behavior.as_ref())
        }
        // §2 puts `same_station` in the same low-trust tier as
        // `explicit_address`, and `receive_policy_constraints` carries no
        // separate `same_station_max_behavior`, so the two share one deployment
        // ceiling. Matching it by kind name alone let an allowlisted
        // `same_station` escape `explicit_address_max_behavior`, which §5.2
        // forbids: a deployment constraint may only make the subject harder to
        // reach, never easier.
        "same_station" | "explicit_address" => {
            cap_receive_action(action, constraints.explicit_address_max_behavior.as_ref())
        }
        _ => action,
    };
    if unknown_path {
        match constraints.unknown_invites_max_behavior.as_ref() {
            Some(UnknownInviteAction::Drop) => InviteReceiveAction::Drop,
            Some(UnknownInviteAction::Quarantine) => {
                cap_receive_action(capped, Some(&InviteReceiveAction::Quarantine))
            }
            None => capped,
        }
    } else {
        capped
    }
}

fn kind_forbidden_by_constraints(
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
) -> bool {
    constraints.is_some_and(|constraints| {
        constraints
            .deployment_denied_introduction_kinds
            .iter()
            .any(|kind| kind == effective_kind)
    })
}

fn kind_permitted_by_constraints(
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
) -> bool {
    constraints
        .and_then(|constraints| constraints.deployment_allowed_introduction_kinds.as_ref())
        .is_none_or(|kinds| kinds.iter().any(|kind| kind == effective_kind))
}

fn did_in_list(value: &str, list: &[DidCoreId]) -> bool {
    list.iter().any(|did| did.as_str() == value)
}

fn principal_service_blocked(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_id: &str,
) -> bool {
    policy
        .denied_source_ids
        .iter()
        .any(|did| did.as_str() == source_id)
        || constraints
            .and_then(|constraints| constraints.denied_source_ids.as_ref())
            .is_some_and(|blocked| did_in_list(source_id, blocked))
}

fn principal_service_trusted(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_id: &str,
) -> bool {
    if !policy.trusted_source_ids.is_empty() && !did_in_list(source_id, &policy.trusted_source_ids)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_source_ids.as_ref())
        .is_none_or(|trusted| did_in_list(source_id, trusted))
}

fn subject_did_method_accepted(
    constraints: Option<&ReceivePolicyConstraints>,
    subject: &str,
) -> bool {
    let Some(methods) =
        constraints.and_then(|constraints| constraints.accepted_subject_did_methods.as_ref())
    else {
        return true;
    };
    let Some(method) = did_method(subject) else {
        return false;
    };
    methods.iter().any(|accepted| accepted == &method)
}

fn did_method(did: &str) -> Option<String> {
    let mut parts = did.splitn(3, ':');
    match (parts.next(), parts.next()) {
        (Some("did"), Some(method)) if !method.is_empty() => Some(format!("did:{method}")),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_claim_evidence_valid(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    handle: &Handle,
    handle_claim: &HandleClaim,
    resolved_by: Option<&DidCoreId>,
    subject: &str,
    recipient_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if handle_claim.validate().is_err() {
        return false;
    }
    if &handle_claim.claim.handle != handle {
        return false;
    }
    if handle_claim.claim.subject_account_id.principal_id.as_str() != subject
        || handle_claim.claim.subject_account_id.station_id.as_str() != recipient_id
    {
        return false;
    }
    if handle_claim.status != HandleClaimStatus::Verified
        || now < handle_claim.as_of
        || now >= handle_claim.fresh_until
        || resolved_by.is_some_and(|resolver| resolver != &handle_claim.verifier_id)
    {
        return false;
    }
    if handle_claim
        .claim
        .expires_at
        .is_none_or(|expires_at| expires_at <= now)
    {
        return false;
    }
    if !handle_domain_allowed(policy, constraints, handle.domain()) {
        return false;
    }
    if !handle_claim_issuer_allowed(policy, constraints, handle_claim) {
        return false;
    }
    if !resolved_by_allowed(policy, constraints, resolved_by) {
        return false;
    }
    true
}

fn handle_domain_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    domain: &str,
) -> bool {
    let domain = domain.to_ascii_lowercase();
    if policy
        .denied_handle_domains
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(&domain))
    {
        return false;
    }
    if !policy.allowed_handle_domains.is_empty()
        && !policy
            .allowed_handle_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&domain))
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.allowed_handle_domains.as_ref())
        .is_none_or(|allowed| {
            allowed
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&domain))
        })
}

fn handle_claim_issuer_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    handle_claim: &HandleClaim,
) -> bool {
    if !policy.trusted_handle_issuer_ids.is_empty()
        && !handle_claim_matches_did_list(handle_claim, &policy.trusted_handle_issuer_ids)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_handle_issuer_ids.as_ref())
        .is_none_or(|trusted| handle_claim_matches_did_list(handle_claim, trusted))
}

fn handle_claim_matches_did_list(handle_claim: &HandleClaim, trusted: &[DidCoreId]) -> bool {
    if trusted.is_empty() {
        return false;
    }
    trusted
        .iter()
        .any(|did| did == &handle_claim.claim.issuer_id)
}

fn resolved_by_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    resolved_by: Option<&DidCoreId>,
) -> bool {
    if !policy.trusted_directory_ids.is_empty()
        && !resolved_by.is_some_and(|did| policy.trusted_directory_ids.iter().any(|v| v == did))
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_directory_ids.as_ref())
        .is_none_or(|trusted| {
            !trusted.is_empty()
                && resolved_by.is_some_and(|did| trusted.iter().any(|candidate| candidate == did))
        })
}

fn validate_invite_delivery_consistency(
    body: &Value,
    delivery: &InviteDeliveryRequestBody,
    state: &AppState,
) -> Result<(), AppError> {
    if delivery.invite_address.account_id.station_id.as_str() != state.service_id() {
        return Err(super::events::peer::cross_domain_replay(
            "invite_address.account_id.station_id does not match this service",
        ));
    }
    validate_invite_delivery_event_binding(body, delivery)
}

/// Spec invite-addressing.md §7 steps 4-7 — the target-independent bindings
/// between `invite_event` and the delivery envelope. The receiving service and
/// the dispatching service both owe these; only the recipient-service identity
/// check above is local to the receiver.
fn validate_invite_delivery_event_binding(
    body: &Value,
    delivery: &InviteDeliveryRequestBody,
) -> Result<(), AppError> {
    if body.pointer("/invite_event/kind").and_then(Value::as_str)
        != Some(arkret_wire::EventKind::InviteCreate.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.kind must be ak.invite.create",
        ));
    }
    let payload = body
        .pointer("/invite_event/payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    let invitee = payload
        .get("invitee_account_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok());
    let expected = arkret_wire::AccountId::new(
        delivery.invite_address.account_id.principal_id.clone(),
        delivery.invite_address.account_id.station_id.clone(),
    );
    if invitee.as_ref() != Some(&expected) {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invitee_account_id must bind invite_address subject and recipient Station",
        ));
    }
    let evidence_digest =
        canonical::canonical_sha256(&body["introduction_evidence"]).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "introduction_evidence is not canonical-hashable: {error}"
            ))
        })?;
    if payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        != Some(evidence_digest.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.introduction_evidence_digest must equal digest(canonical_json(introduction_evidence))",
        ));
    }
    Ok(())
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            super::events::peer::schema_violation(format!(
                "required federation header {name} missing"
            ))
        })
}

fn locator_token_appears_in_url(req: &Request) -> bool {
    req.uri().query().is_some()
}

fn invite_locator_not_found() -> AppError {
    AppError::not_found("invite locator not found")
}

#[cfg(test)]
mod invite_locator_security_tests {
    use soland_services::identity::{AccountProfileState, DeviceIdentity, SaveDeviceCommand};

    use super::*;

    const PRODUCTION_HOLDER: &str = "ak:did_core:web:holder.example";
    const PRODUCTION_INVITER: &str = "ak:did_core:web:inviter_id.example";
    const PRODUCTION_DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-0000000000e1";
    const PRODUCTION_DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-0000000000e2";
    const PRODUCTION_REALM: &str = "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W";
    const PRODUCTION_INVITE_EVENT: &str = "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E2";

    #[tokio::test]
    async fn locator_trust_requires_the_account_bound_recipient_signature() {
        let state = production_holder_state().await;
        let at = now();
        let mut locator = PrincipalLocator {
            schema: arkret_wire::SchemaId::PRINCIPAL_LOCATOR_V1.to_owned(),
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                state.service_core_id().clone(),
            ),
            service_resolution: ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url: "https://soland.test/_arkret/open/services/resolution"
                    .to_owned(),
                pinned_record_digest: None,
            },
            route_assistance: None,
            issued_at: at,
            expires_at: at + Duration::minutes(5),
            locator_ref_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            display_hint: None,
            proofs: Vec::new(),
        };
        let mut proof = DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: state.service_verification_method("notary-key").unwrap(),
            payload_digest: locator.payload_digest().unwrap(),
            created_at: at,
            domain: None,
            audience: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &locator.proof_signing_bytes(&proof).unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        locator.proofs.push(PrincipalLocatorProof {
            proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
            proof,
        });
        assert!(verified_locator_for_recipient(
            &state,
            &locator,
            PRODUCTION_HOLDER,
            state.service_id(),
            at
        ));

        let mut forged = locator.clone();
        forged.account_id.principal_id = DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap();
        forged.proofs[0].proof.payload_digest = forged.payload_digest().unwrap();
        assert!(!verified_locator_for_recipient(
            &state,
            &forged,
            PRODUCTION_INVITER,
            state.service_id(),
            at
        ));

        let mut raw_payload_signature = locator.clone();
        let mut payload = serde_json::to_value(&raw_payload_signature).unwrap();
        payload.as_object_mut().unwrap().remove("proofs");
        raw_payload_signature.proofs[0].proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &canonical::canonical_json_bytes(&payload).unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        assert!(!verified_locator_for_recipient(
            &state,
            &raw_payload_signature,
            PRODUCTION_HOLDER,
            state.service_id(),
            at
        ));
        assert!(!verified_locator_for_recipient(
            &state,
            &locator,
            PRODUCTION_HOLDER,
            state.service_id(),
            locator.expires_at
        ));
    }

    async fn production_holder_state() -> AppState {
        production_holder_state_with_config(crate::config::AppConfig {
            development_mode: false,
            seed_demo_data: false,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-invite-service-fanout-test-blobs"),
            ),
            ..crate::config::AppConfig::test_default()
        })
        .await
    }

    async fn production_holder_state_with_config(config: crate::config::AppConfig) -> AppState {
        let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
        let created_at = now();
        state
            .identities()
            .save_account(AccountProfileState {
                pk: soland_storage::AccountPk(0),
                account_id: arkret_wire::AccountId::new(
                    DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                    state.service_core_id().clone(),
                ),
                principal_id: DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                localpart: "holder".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at,
            })
            .await
            .expect("holder account");
        for device_id in [PRODUCTION_DEVICE_A, PRODUCTION_DEVICE_B] {
            state
                .identities()
                .save_device(SaveDeviceCommand {
                    actor_id: PRODUCTION_HOLDER.to_owned(),
                    device_id: device_id.to_owned(),
                    display_name: None,
                    device: DeviceIdentity {
                        actor_id: PRODUCTION_HOLDER.to_owned(),
                        device_id: device_id.to_owned(),
                        display_name: None,
                        verification_state: "verified".to_owned(),
                        payload: json!({"device_id": device_id}),
                        created_at,
                        updated_at: created_at,
                        revoked_at: None,
                    },
                })
                .await
                .expect("holder device");
        }
        state
    }

    async fn assert_service_account_data_fanout(
        state: &AppState,
        account_data_key: &str,
        expected_revision: u64,
        expected_payload: &Value,
    ) {
        for device_id in [PRODUCTION_DEVICE_A, PRODUCTION_DEVICE_B] {
            let queued = state
                .deliveries()
                .device_messages_after(PRODUCTION_HOLDER, device_id, 0)
                .await
                .expect("holder to-device queue");
            assert_eq!(
                queued.len(),
                1,
                "all active holder devices receive service fanout"
            );
            let envelopes =
                crate::routing::identity::device_messages::device_message_envelopes_after(
                    state, &queued,
                );
            assert_eq!(envelopes.len(), 1, "queued service envelope is readable");
            let envelope = &envelopes[0];
            assert_eq!(
                envelope.recipient_account_id.principal_id.as_str(),
                PRODUCTION_HOLDER
            );
            assert_eq!(
                envelope.recipient_account_id.station_id.as_str(),
                state.service_id()
            );
            assert_eq!(envelope.recipient_device_id.as_str(), device_id);
            assert!(matches!(
                &envelope.sender,
                crate::wire::DeviceMessageSender::Service { sender_id }
                    if sender_id.as_str() == state.service_id()
            ));
            let content = serde_json::to_value(&envelope.content).unwrap();
            assert_eq!(
                content.get("account_data_key"),
                Some(&json!(account_data_key))
            );
            assert_eq!(content.get("revision"), Some(&json!(expected_revision)));
            assert_eq!(content.get("content"), Some(expected_payload));
        }
    }

    fn production_invite_delivery(state: &AppState) -> InviteDeliveryRequestBody {
        let event: arkret_wire::Event = serde_json::from_value(json!({
            "event_id": PRODUCTION_INVITE_EVENT,
            "kind": arkret_wire::EventKind::InviteCreate.as_str(),
            "realm_id": PRODUCTION_REALM,
            "scope_ref": { "kind": "realm", "realm_id": PRODUCTION_REALM },
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": PRODUCTION_INVITER, "station_id": state.service_id()
            }},
            "actor_seq": 0,
            "created_at": "2026-08-21T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "invitee_account_id": {"principal_id": PRODUCTION_HOLDER, "station_id": state.service_id()},
                "introduction_evidence_digest": canonical::canonical_sha256(&IntroductionEvidence::ExplicitAddress).unwrap(),
                "expires_at": "2099-01-01T00:00:00.000Z"
            },
            "proofs": []
        }))
        .expect("invite Event");
        let service_id = DidCoreId::new(state.service_id().to_owned()).unwrap();
        let address =
            arkret_models_collaboration::governance::invite_addressing::InviteAddress::station(
                DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                service_id,
                ServiceResolutionCarrier::CurrentRecordUrl {
                    current_record_url: "https://soland.test/.well-known/arkret/current".to_owned(),
                    pinned_record_digest: None,
                },
            );
        InviteDeliveryRequestBody::new(
            event,
            address,
            IntroductionEvidence::ExplicitAddress,
            "ak:idempotency:production-service-fanout",
        )
    }

    #[test]
    fn issued_secret_is_192_bit_opaque_and_never_enters_the_durable_record() {
        let (record, token) = new_invite_locator(
            "did:webvh:z6mkfixture:alice.example",
            "did:webvh:z6mkfixture:ps.example",
            InviteLocatorIssueRequestBody::default(),
        )
        .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 24);
        assert!(serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(&token).unwrap()).is_err());
        let durable = format!("{record:?}");
        assert!(!durable.contains(&token));
        assert_eq!(
            record.token_digest,
            format!("sha256:{}", sha256_hex(token.as_bytes()))
        );
    }

    /// `consent-model.md` section 6.1 step 2 -- under the holder's
    /// `require_explicit_consent` profile every delivery without verified
    /// `consent_grant` evidence is an opaque drop, even when the evidence kind
    /// is allowlisted, configured to notify and disclosed with `outcome`. The
    /// drop is what upstream maps to the same opaque `deferred` as a
    /// quarantine, so the profile itself is not observable by the requester.
    #[tokio::test]
    async fn require_explicit_consent_profile_drops_every_non_consent_grant_delivery() {
        let state = production_holder_state().await;
        let holder_account = arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );
        let mut policy = InviteReceivePolicy::spec_default(holder_account);
        policy
            .holder_allowed_introduction_kinds
            .extend(["explicit_address".to_owned(), "same_station".to_owned()]);
        policy.explicit_address_behavior = InviteReceiveAction::Notify;
        policy.disclosure = Some(
            arkret_models_collaboration::governance::invite_addressing::DisclosurePolicy {
                high_trust: Some(DisclosureLevel::Outcome),
                discovery_trust: Some(DisclosureLevel::Outcome),
                low_trust: Some(DisclosureLevel::Outcome),
            },
        );
        let inviter_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        ));
        let evaluate_invite = |policy: &InviteReceivePolicy| {
            evaluate_invite_receive(
                &state,
                policy,
                &IntroductionEvidence::ExplicitAddress,
                &inviter_actor,
                PRODUCTION_INVITER,
                PRODUCTION_HOLDER,
                state.service_id(),
                state.service_id(),
                true,
            )
        };
        let evaluate_contact = |policy: &InviteReceivePolicy| {
            evaluate_contact_receive(
                &state,
                policy,
                &ContactIntroductionEvidence::ExplicitAddress,
                PRODUCTION_INVITER,
                PRODUCTION_HOLDER,
                state.service_id(),
                state.service_id(),
            )
        };

        // Default profile: the holder's own notify choice stands.
        assert_eq!(policy.consent_profile, arkret_wire::ConsentProfile::Default);
        assert_eq!(evaluate_invite(&policy).action, InviteReceiveAction::Notify);
        assert_eq!(
            evaluate_contact(&policy).action,
            InviteReceiveAction::Notify
        );

        policy.consent_profile = arkret_wire::ConsentProfile::RequireExplicitConsent;
        let invite = evaluate_invite(&policy);
        assert_eq!(invite.action, InviteReceiveAction::Drop);
        assert!(
            invite.disclosed_outcome.is_none(),
            "the profile drop must stay inside the opaque deferred class"
        );
        let contact = evaluate_contact(&policy);
        assert_eq!(contact.action, InviteReceiveAction::Drop);
        assert!(contact.disclosed_outcome.is_none());
    }

    /// `invite-addressing.md` §5 — `holder_allowed_introduction_kinds` is an
    /// allowlist and an evidence kind outside it MUST NOT reach a user
    /// notification, however the holder configured that kind's own behavior.
    /// The behavior field alone used to decide the outcome, so a holder who set
    /// `explicit_address_behavior = notify` without allowlisting the kind was
    /// notified anyway.
    #[tokio::test]
    async fn a_kind_outside_the_allowlist_never_notifies() {
        let state = production_holder_state().await;
        let holder_account = arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );
        let mut policy = InviteReceivePolicy::spec_default(holder_account);
        policy.explicit_address_behavior = InviteReceiveAction::Notify;
        policy.handle_claim_behavior = Some(InviteReceiveAction::Notify);
        let inviter_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        ));

        // `spec_default` allowlists only the high-trust kinds, so the delivery
        // downgrades to the low-trust tier and must stay out of the inbox.
        let invite = evaluate_invite_receive(
            &state,
            &policy,
            &IntroductionEvidence::ExplicitAddress,
            &inviter_actor,
            PRODUCTION_INVITER,
            PRODUCTION_HOLDER,
            state.service_id(),
            state.service_id(),
            true,
        );
        assert_eq!(invite.effective_kind, "same_station");
        assert_eq!(invite.action, InviteReceiveAction::Quarantine);

        let contact = evaluate_contact_receive(
            &state,
            &policy,
            &ContactIntroductionEvidence::ExplicitAddress,
            PRODUCTION_INVITER,
            PRODUCTION_HOLDER,
            state.service_id(),
            state.service_id(),
        );
        assert_eq!(contact.effective_kind, "explicit_address");
        assert_eq!(contact.action, InviteReceiveAction::Quarantine);

        // Allowlisting the kind is what makes the holder's own `notify` choice
        // effective.
        policy
            .holder_allowed_introduction_kinds
            .push("same_station".to_owned());
        let invite = evaluate_invite_receive(
            &state,
            &policy,
            &IntroductionEvidence::ExplicitAddress,
            &inviter_actor,
            PRODUCTION_INVITER,
            PRODUCTION_HOLDER,
            state.service_id(),
            state.service_id(),
            true,
        );
        assert_eq!(invite.action, InviteReceiveAction::Notify);
    }

    #[tokio::test]
    async fn invite_delivery_binding_rejects_same_principal_at_another_station() {
        let state = production_holder_state().await;
        let delivery = production_invite_delivery(&state);
        let body = serde_json::to_value(&delivery).unwrap();
        validate_invite_delivery_event_binding(&body, &delivery).unwrap();
        let mut wrong_station = body.clone();
        wrong_station["invite_event"]["payload"]["invitee_account_id"]["station_id"] =
            json!("ak:did_core:web:another-station.example");
        assert!(validate_invite_delivery_event_binding(&wrong_station, &delivery).is_err());
        let mut bare_principal = body;
        bare_principal["invite_event"]["payload"]["invitee_account_id"] = json!(PRODUCTION_HOLDER);
        assert!(validate_invite_delivery_event_binding(&bare_principal, &delivery).is_err());
    }

    #[test]
    fn quarantine_is_never_disclosed_even_on_outcome_routes() {
        assert_eq!(
            disclosed_outcome_for_action(
                DisclosureLevel::Outcome,
                &InviteReceiveAction::Quarantine
            ),
            None
        );
        assert_eq!(
            disclosed_outcome_for_action(DisclosureLevel::Outcome, &InviteReceiveAction::Notify),
            Some(DisclosedOutcome::Delivered)
        );
        assert_eq!(
            disclosed_outcome_for_action(DisclosureLevel::Outcome, &InviteReceiveAction::Drop),
            Some(DisclosedOutcome::Blocked)
        );
    }

    #[test]
    fn invite_delivery_entry_activity_follows_expiry() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entry_with_expiry = |expires_at: &str| InviteDeliveryEntry {
            invite_id: arkret_identifiers::InviteId::new(
                "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K".to_owned(),
            )
            .unwrap(),
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W".to_owned(),
            )
            .unwrap(),
            inviter_account_id: arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            ),
            invite_token: "opaque-token".to_owned(),
            received_at: at,
            expires_at: chrono::DateTime::parse_from_rfc3339(expires_at)
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        assert!(invite_delivery_entry_active(
            &entry_with_expiry("2026-08-05T10:00:00.000Z"),
            at
        ));
        assert!(!invite_delivery_entry_active(
            &entry_with_expiry("2026-07-05T10:00:00.000Z"),
            at
        ));
        assert!(!invite_delivery_entry_active(
            &entry_with_expiry("2026-08-01T00:00:00.000Z"),
            at
        ));
    }

    #[test]
    fn invite_delivery_cell_merge_matches_the_spec_write_semantics() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entry = |invite_token: &str, expires_at: &str| InviteDeliveryEntry {
            invite_id: arkret_identifiers::InviteId::new(
                "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K".to_owned(),
            )
            .unwrap(),
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W".to_owned(),
            )
            .unwrap(),
            inviter_account_id: arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            ),
            invite_token: invite_token.to_owned(),
            received_at: at,
            expires_at: chrono::DateTime::parse_from_rfc3339(expires_at)
                .unwrap()
                .with_timezone(&chrono::Utc),
        };

        // A redelivery of the same invite replaces the previous entry instead
        // of taking a second slot, and an expired prior entry is purged.
        let prior = InviteDelivery::new(at, vec![entry("stale-token", "2026-07-05T10:00:00.000Z")]);
        let merged = merge_invite_delivery_cell(
            Some(prior),
            entry("fresh-token", "2026-08-05T10:00:00.000Z"),
            at,
        )
        .expect("merge into a cell holding only a stale entry");
        assert_eq!(merged.delivery_entries.len(), 1);
        assert_eq!(merged.delivery_entries[0].invite_token, "fresh-token");
        assert_eq!(merged.updated_at, at);
        assert_eq!(merged.schema, InviteDelivery::SCHEMA);
        merged.validate().expect("merged cell validates");

        // Overflow evicts from the front (oldest first) down to the cap.
        let invite_id_for = |seed: u8| {
            arkret_identifiers::InviteId::from_event_id(&arkret_identifiers::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [seed; 32],
            ))
        };
        let full = InviteDelivery::new(
            at,
            (0..InviteDelivery::MAX_ENTRIES)
                .map(|index| {
                    let mut held = entry("held-token", "2026-08-05T10:00:00.000Z");
                    held.invite_id = invite_id_for(index as u8);
                    held
                })
                .collect(),
        );
        let mut new_entry = entry("fresh-token", "2026-08-05T10:00:00.000Z");
        new_entry.invite_id = invite_id_for(u8::MAX);
        let merged =
            merge_invite_delivery_cell(Some(full), new_entry, at).expect("merge into a full cell");
        assert_eq!(merged.delivery_entries.len(), InviteDelivery::MAX_ENTRIES);
        assert_eq!(
            merged
                .delivery_entries
                .last()
                .map(|entry| entry.invite_token.as_str()),
            Some("fresh-token")
        );
    }

    #[tokio::test]
    async fn production_invite_delivery_fanout_uses_a_readable_service_sender() {
        let state = production_holder_state().await;
        let delivery = production_invite_delivery(&state);
        let body = serde_json::to_value(&delivery).unwrap();
        let inviter_account_id = arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );

        assert!(
            deliver_invite_credential(
                &state,
                &delivery.invite_address.account_id,
                &inviter_account_id,
                &body,
                PRODUCTION_REALM,
            )
            .await
            .expect("invite credential delivery")
        );
        let cell = state
            .account_data()
            .entry(
                &arkret_wire::ActorId::account(delivery.invite_address.account_id.clone())
                    .to_string(),
                AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            )
            .await
            .expect("invite delivery cell")
            .expect("invite delivery write");
        assert_service_account_data_fanout(
            &state,
            AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            cell.revision,
            &cell.payload,
        )
        .await;
        assert!(
            state
                .account_data()
                .entry(PRODUCTION_HOLDER, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
                .await
                .unwrap()
                .is_none()
        );
        let foreign = arkret_wire::AccountId::new(
            delivery.invite_address.account_id.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        assert!(
            deliver_invite_credential(
                &state,
                &foreign,
                &inviter_account_id,
                &body,
                PRODUCTION_REALM
            )
            .await
            .is_err()
        );
        assert!(
            state
                .account_data()
                .entry(
                    &arkret_wire::ActorId::account(foreign).to_string(),
                    AccountDataKey::ACCOUNT_INVITE_DELIVERY
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    /// One quarantine delivery from `inviter_id`, so a test can drive several
    /// distinct sources at the same holder.
    fn production_invite_delivery_from(
        state: &AppState,
        inviter_id: &str,
        invite_event_id: &str,
        idempotency_key: &str,
    ) -> InviteDeliveryRequestBody {
        let mut delivery = production_invite_delivery(state);
        let account = arkret_wire::AccountId::new(
            DidCoreId::new(inviter_id.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );
        delivery.invite_event.actor_id = arkret_wire::ActorId::account(account);
        delivery.invite_event.event_id =
            arkret_identifiers::EventId::new(invite_event_id.to_owned()).unwrap();
        delivery.idempotency_key = idempotency_key.to_owned();
        delivery
    }

    /// `consent-model.md` section 6.1.1.3 -- the third distinct new source is
    /// over a `default_new_sources_per_window = 2` deployment ceiling, so it
    /// must be dropped before the cell write while the two under the ceiling
    /// are admitted. The caller only ever learns `false`, which upstream maps
    /// to the same opaque `deferred` as an ordinary quarantine.
    #[tokio::test]
    async fn new_source_quota_denies_the_source_over_the_window_ceiling() {
        let mut config = crate::config::AppConfig {
            development_mode: false,
            seed_demo_data: false,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-invite-new-source-quota-test-blobs"),
            ),
            ..crate::config::AppConfig::test_default()
        };
        config.receive_policy_constraints = Some(ReceivePolicyConstraints {
            policy_version: None,
            applies_to: None,
            deployment_allowed_introduction_kinds: None,
            deployment_denied_introduction_kinds: Vec::new(),
            handle_claim_max_behavior: None,
            explicit_address_max_behavior: None,
            unknown_invites_max_behavior: None,
            new_source_quota: Some(arkret_wire::receive_policy::NewSourceQuotaConstraints {
                window_seconds: Some(3_600),
                default_new_sources_per_window: Some(2),
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
        let state = production_holder_state_with_config(config).await;
        let decision = ReceiveDecision {
            action: InviteReceiveAction::Quarantine,
            effective_kind: "explicit_address",
            trust_tier: TrustTier::Low,
            disclosed_outcome: None,
        };

        let sources = [
            (
                "ak:did_core:web:quota-one.example",
                "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E1",
                "ak:idempotency:quota-one",
            ),
            (
                "ak:did_core:web:quota-two.example",
                "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E2",
                "ak:idempotency:quota-two",
            ),
            (
                "ak:did_core:web:quota-three.example",
                "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E3",
                "ak:idempotency:quota-three",
            ),
        ];
        let mut admitted = Vec::new();
        for (inviter_id, event_id, idempotency_key) in sources {
            let delivery =
                production_invite_delivery_from(&state, inviter_id, event_id, idempotency_key);
            let body = serde_json::to_value(&delivery).unwrap();
            admitted.push(
                persist_invite_quarantine_entry(
                    &state,
                    PRODUCTION_HOLDER,
                    state.service_id(),
                    inviter_id,
                    &delivery,
                    &body,
                    &decision,
                )
                .await
                .expect("invite quarantine write"),
            );
        }
        assert_eq!(
            admitted,
            vec![true, true, false],
            "the deployment ceiling of two new sources per window was not enforced"
        );

        let cell = state
            .account_data()
            .entry(
                &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                    state.service_core_id().clone(),
                ))
                .to_string(),
                AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
            )
            .await
            .expect("invite quarantine cell")
            .expect("invite quarantine write");
        let entries = cell.payload["quarantine_entries"]
            .as_array()
            .expect("quarantine entries");
        assert_eq!(
            entries.len(),
            2,
            "the over-quota source reached the holder cell: {:?}",
            cell.payload
        );

        // A repeat contact from an already-charged source is seen, not new, so
        // it is admitted even though the window is full.
        let repeat = production_invite_delivery_from(
            &state,
            "ak:did_core:web:quota-one.example",
            "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E4",
            "ak:idempotency:quota-one-repeat",
        );
        let repeat_body = serde_json::to_value(&repeat).unwrap();
        assert!(
            persist_invite_quarantine_entry(
                &state,
                PRODUCTION_HOLDER,
                state.service_id(),
                "ak:did_core:web:quota-one.example",
                &repeat,
                &repeat_body,
                &decision,
            )
            .await
            .expect("repeat quarantine write"),
            "a repeat contact from an admitted source must not be charged again"
        );
    }

    #[tokio::test]
    async fn production_invite_quarantine_fanout_uses_a_readable_service_sender() {
        let state = production_holder_state().await;
        let delivery = production_invite_delivery(&state);
        let body = serde_json::to_value(&delivery).unwrap();
        let decision = ReceiveDecision {
            action: InviteReceiveAction::Quarantine,
            effective_kind: "explicit_address",
            trust_tier: TrustTier::Low,
            disclosed_outcome: None,
        };

        assert!(
            persist_invite_quarantine_entry(
                &state,
                PRODUCTION_HOLDER,
                state.service_id(),
                PRODUCTION_INVITER,
                &delivery,
                &body,
                &decision,
            )
            .await
            .expect("invite quarantine write")
        );
        let cell = state
            .account_data()
            .entry(
                &arkret_wire::ActorId::account(delivery.invite_address.account_id.clone())
                    .to_string(),
                AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
            )
            .await
            .expect("invite quarantine cell")
            .expect("invite quarantine write");
        assert_eq!(cell.payload["schema"], "ak.schema.invite_quarantine.v1");
        assert!(cell.payload.get("entries").is_none());
        let typed: InviteQuarantine = serde_json::from_value(cell.payload.clone()).unwrap();
        typed
            .validate_holder(&delivery.invite_address.account_id)
            .unwrap();
        let entry = &cell.payload["quarantine_entries"][0];
        assert!(
            entry["entry_digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
        );
        assert_eq!(entry["source_peer_principal_id"], PRODUCTION_INVITER);
        assert!(entry.get("quarantine_id").is_none());
        assert!(entry.get("source_peer_id").is_none());
        assert!(entry.get("inviter_id").is_none());
        assert!(entry.get("subject_id").is_none());
        assert!(entry.get("recipient_id").is_none());
        assert!(!entry.get("invite_event_id").is_some_and(Value::is_null));
        assert_service_account_data_fanout(
            &state,
            AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
            cell.revision,
            &cell.payload,
        )
        .await;
        assert!(
            state
                .account_data()
                .entry(PRODUCTION_HOLDER, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
                .await
                .unwrap()
                .is_none()
        );
        let mut foreign_delivery = delivery.clone();
        foreign_delivery.invite_address.account_id.station_id =
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert!(
            persist_invite_quarantine_entry(
                &state,
                PRODUCTION_HOLDER,
                state.service_id(),
                PRODUCTION_INVITER,
                &foreign_delivery,
                &body,
                &decision
            )
            .await
            .is_err()
        );
        assert!(
            state
                .account_data()
                .entry(
                    &arkret_wire::ActorId::account(foreign_delivery.invite_address.account_id)
                        .to_string(),
                    AccountDataKey::ACCOUNT_INVITE_QUARANTINE
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_invite_quarantine_writes_merge_without_exposing_cas_conflict() {
        let state = production_holder_state().await;
        let delivery_a = production_invite_delivery(&state);
        let body_a = serde_json::to_value(&delivery_a).unwrap();
        let mut delivery_b = delivery_a.clone();
        delivery_b.invite_event.event_id = arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x42; 32],
        );
        delivery_b.idempotency_key = "ak:idempotency:concurrent-quarantine-b".to_owned();
        let body_b = serde_json::to_value(&delivery_b).unwrap();
        let decision = ReceiveDecision {
            action: InviteReceiveAction::Quarantine,
            effective_kind: "explicit_address",
            trust_tier: TrustTier::Low,
            disclosed_outcome: None,
        };

        let (first, second) = tokio::join!(
            persist_invite_quarantine_entry(
                &state,
                PRODUCTION_HOLDER,
                state.service_id(),
                PRODUCTION_INVITER,
                &delivery_a,
                &body_a,
                &decision,
            ),
            persist_invite_quarantine_entry(
                &state,
                PRODUCTION_HOLDER,
                state.service_id(),
                "ak:did_core:web:second-inviter.example",
                &delivery_b,
                &body_b,
                &decision,
            ),
        );
        assert!(first.expect("first quarantine outcome"));
        assert!(second.expect("second quarantine outcome"));

        let cell = state
            .account_data()
            .entry(
                &arkret_wire::ActorId::account(delivery_a.invite_address.account_id.clone())
                    .to_string(),
                AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
            )
            .await
            .expect("invite quarantine cell")
            .expect("concurrent quarantine writes");
        let quarantine: InviteQuarantine = serde_json::from_value(cell.payload).unwrap();
        quarantine
            .validate_holder(&delivery_a.invite_address.account_id)
            .unwrap();
        assert_eq!(quarantine.quarantine_entries.len(), 2);
        assert!(
            quarantine
                .quarantine_entries
                .iter()
                .any(|entry| { entry.source_peer_principal_id.as_str() == PRODUCTION_INVITER })
        );
        assert!(quarantine.quarantine_entries.iter().any(|entry| {
            entry.source_peer_principal_id.as_str() == "ak:did_core:web:second-inviter.example"
        }));
    }

    #[tokio::test]
    async fn invite_credential_delivery_skips_a_subject_without_local_account() {
        let state = AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );
        let body = json!({
            "invite_event": {
                "created_at": "2026-07-29T10:00:00.000Z",
                "payload": {
                    "invite_id": "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K",
                    "expires_at": "2026-08-05T10:00:00.000Z"
                }
            }
        });
        let account_id = arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:carol.example").unwrap(),
            state.service_core_id().clone(),
        );
        let inviter_account_id = arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            state.service_core_id().clone(),
        );
        assert!(
            !deliver_invite_credential(
                &state,
                &account_id,
                &inviter_account_id,
                &body,
                "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W",
            )
            .await
            .expect("unknown subject skips the credential write")
        );
        assert!(
            state
                .account_data()
                .entry(
                    &arkret_wire::ActorId::account(account_id).to_string(),
                    AccountDataKey::ACCOUNT_INVITE_DELIVERY
                )
                .await
                .expect("account data lookup")
                .is_none(),
            "no credential cell may be written for an unknown subject"
        );
    }

    #[tokio::test]
    async fn private_invite_projection_is_idempotent_and_never_writes_shared_event_state() {
        let state = AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W";
        let subject = "ak:did_core:web:bob.example";
        let account_id =
            arkret_wire::AccountId::new(DidCoreId::new(subject).unwrap(), state.service_core_id());
        let body = json!({
            "invite_event": {
                "created_at": "2026-07-29T10:00:00.000Z",
                "payload": {
                    "introduction_evidence_digest":
                        format!("sha256:{}", "a".repeat(64)),
                    "expires_at": "2026-08-05T10:00:00.000Z"
                }
            }
        });
        let validated = crate::routing::events::event_log::ValidatedEventEnvelope {
            event_id: arkret_identifiers::EventId::new(
                "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E2".to_owned(),
            )
            .unwrap(),
            // `ValidatedEventEnvelope::actor_id` is a `DidCoreId`, whose wire
            // form is `ak:did_core:<method>:<rest>`; a bare `did:web:` string
            // is a DID and belongs only where a complete DID is required
            // (verification methods, proof controllers).
            actor_id: DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                state.service_core_id().clone(),
            )),
            device_id: Some(
                arkret_wire::DeviceId::new(
                    "ak:device:01904100-0000-7000-8000-000000000404".to_owned(),
                )
                .unwrap(),
            ),
            actor_seq: 7,
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            kind: arkret_wire::EventKind::InviteCreate.as_str().to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            prev_refs: Vec::new(),
            canonical_digest: format!("sha256:{}", "b".repeat(64)),
            canonical_bytes: Vec::new(),
            producer_signing_key: None,
        };
        let invite_id = arkret_wire::InviteId::from_event_id(&validated.event_id).to_string();

        assert!(
            !persist_private_invite_projection(&state, &account_id, &body, &validated)
                .await
                .expect("first private projection")
        );
        assert!(
            persist_private_invite_projection(&state, &account_id, &body, &validated)
                .await
                .expect("exact replay")
        );
        let invite = state
            .realm_invites()
            .get(&invite_id)
            .await
            .unwrap()
            .expect("private invite lookup");
        assert_eq!(
            invite.invitee_id.as_deref(),
            Some(account_id.to_string().as_str())
        );
        assert_eq!(
            invite.invite_token,
            crate::routing::generate_invite_token(&invite_id, realm_id, &account_id.to_string())
        );
        let foreign_account = arkret_wire::AccountId::new(
            account_id.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        assert!(
            persist_private_invite_projection(&state, &foreign_account, &body, &validated)
                .await
                .is_err()
        );
        assert!(
            state
                .event_queries()
                .realm_events_newest_first(realm_id)
                .await
                .expect("shared Event query")
                .is_empty()
        );
        assert!(
            state
                .projections()
                .snapshot()
                .members_in_state(realm_id, "invite")
                .is_empty()
        );
    }
}
