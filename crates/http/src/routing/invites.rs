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
    InviteLocatorStatus, InviteReceivePolicy, PrincipalLocator, PrincipalLocatorProof,
    PrincipalLocatorProofPurpose, SelfInviteDispatchRequestBody,
};
use arkret_models_collaboration::governance::member_delivery_binding_candidate::{
    CandidateIntent, CandidateValidationContext, MemberDeliveryBindingCandidate,
};
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
};
use arkret_models_discovery::DirectoryIntent;
use arkret_models_identity::handle::{Handle, HandleBindingState};
use arkret_models_identity::proof::DetachedPayloadProof;
use arkret_models_identity::{HandleClaim, ServiceResolutionCarrier};
use arkret_wire::{
    AccountDataKey, InviteReceiveAction, ReceivePolicyConstraints, ReceivePolicySurface,
    UnknownInviteAction,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use salvo::http::{HeaderValue, StatusCode};
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
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

use crate::routing::identity::device_messages::{
    fanout_actor_private_update, principal_server_device_message_sender,
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
pub(crate) const INVITE_QUARANTINE_SCHEMA: &str = "ak.schema.invite_quarantine.v1";
const INVITE_DELIVERY_CAS_ATTEMPTS: usize = 3;

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
        InviteLocatorInsertOutcome::ActiveLimitReached => Err(AppError::new(
            ErrorCode::FailedPrecondition,
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
    if destination_id != delivery.invite_address.recipient_id.as_str() {
        return Err(super::events::peer::cross_domain_replay(
            "Destination-Service-ID must equal invite_address.recipient_id",
        ));
    }
    let source_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;

    // Steps 1-3 are the service-to-service binding: the peer session below
    // exists only so the delivered envelope can be verified against a
    // trust-domain-bound identity. It is never a principal session and MUST NOT
    // be reused by the authenticated self dispatch surface.
    let trust_headers =
        crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
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
        actor: delivery.invite_event.actor_id.as_str().to_owned(),
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

    // The inviter_id is the actor that signed the durable `ak.invite.create`
    // event; it is the `peer` we test `denied_subjects` and the
    // `consent_grant` evidence against (spec invite-addressing.md §2 / §5).
    let inviter_id = delivery.invite_event.actor_id.as_str().to_owned();
    let subject_id = delivery.invite_address.subject_id.clone();
    let subject = subject_id.as_str().to_owned();

    // Spec invite-addressing.md §5..§8 — resolve the subject's private
    // receive policy, derive the effective trust tier (downgrading
    // `consent_grant` to `explicit_address` when the grant cannot be
    // verified), then apply blocklist + allowlist + behavior to pick a
    // receive action and a graded-disclosure outcome.
    let policy = resolve_core_invite_receive_policy(state, &subject_id);
    let decision = evaluate_invite_receive(
        state,
        &policy,
        &delivery.introduction_evidence,
        &inviter_id,
        &subject,
        delivery.invite_address.recipient_id.as_str(),
        source_id,
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
                "invitee_id": delivery.invite_address.subject_id,
                "recipient_id": delivery.invite_address.recipient_id,
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
                AppError::new(ErrorCode::SchemaViolation, error.message)
                    .with_status(error.status)
                    .with_wire_code(error.code)
            })?;
            let duplicate = persist_private_invite_projection(
                state,
                delivery.invite_address.subject_id.as_str(),
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
    let credential_delivered =
        deliver_invite_credential(state, &subject, &inviter_id, body, &realm_id).await?;

    let status = if duplicate { "duplicate" } else { "accepted" };
    super::append_audit_log(
        state,
        None,
        audit_operation,
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": event_id,
            "invitee_id": delivery.invite_address.subject_id,
            "recipient_id": delivery.invite_address.recipient_id,
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

    if delivery.invite_address.recipient_id.as_str() == state.service_id() {
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
            "invite_event has not been accepted by this Principal Server",
        ));
    };
    let session_actor = DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    let accepted_actor = DidCoreId::new(accepted.actor_id.clone())
        .map_err(|error| AppError::internal(format!("stored Event actor is invalid: {error}")))?;
    if accepted_actor != session_actor {
        return Err(invite_event_precondition(
            arkret_wire::ReasonCode::INVITE_EVENT_ACTOR_MISMATCH,
            "invite_event was not signed by the authenticated session actor",
        ));
    }
    Ok(accepted)
}

fn invite_event_precondition(reason_code: &'static str, message: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
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
    let recipient_id = &delivery.invite_address.recipient_id;
    let resolver = state
        .service_route_resolver()
        .map_err(|error| AppError::internal(error.to_owned()))?;
    let entry = resolver
        .resolve_carrier(
            &delivery.invite_address.service_resolution,
            recipient_id,
            "principal_server",
            now(),
        )
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FailedPrecondition,
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
                peer_url: Some(entry.base_uri.trim_end_matches('/').to_owned()),
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
            "invitee_id": delivery.invite_address.subject_id,
            "recipient_id": delivery.invite_address.recipient_id,
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
    subject: &str,
    body: &Value,
    validated: &super::events::event_log::ValidatedEventEnvelope,
) -> Result<bool, AppError> {
    let event = body
        .get("invite_event")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event must be an object"))?;
    let payload = event
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    let invite_id = payload
        .get("invite_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            super::events::peer::schema_violation("invite_event.payload.invite_id is required")
        })?
        .to_owned();
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
    let invite_delivery_target = payload.get("invite_delivery_target").cloned();
    let introduction_evidence_digest = payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: validated.realm_id.to_string(),
        inviter_id: validated.actor_id.to_string(),
        invitee_id: Some(subject.to_owned()),
        invite_delivery_target,
        introduction_evidence_digest,
        third_party_invite: None,
        invite_token: crate::routing::generate_invite_token(
            &invite_id,
            validated.realm_id.as_str(),
            subject,
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
            && existing.invite_delivery_target == record.invite_delivery_target
            && existing.introduction_evidence_digest == record.introduction_evidence_digest
            && existing.expires_at == record.expires_at
            && existing.created_at == record.created_at;
        if exact_replay {
            return Ok(true);
        }
        return Err(AppError::new(
            ErrorCode::DuplicateConflict,
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
    subject: &str,
    inviter_id: &str,
    body: &Value,
    realm_id: &str,
) -> Result<bool, AppError> {
    let subject_exists = state
        .identities()
        .account(subject)
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
    let invite_token = crate::routing::generate_invite_token(invite_id.as_str(), realm_id, subject);

    let received_at = now();
    let new_entry = InviteDeliveryEntry {
        invite_id,
        realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
            .map_err(|error| AppError::internal(format!("invite realm id is invalid: {error}")))?,
        inviter_id: DidCoreId::new(inviter_id.to_owned())
            .map_err(|error| AppError::internal(format!("inviter_id id is invalid: {error}")))?,
        invite_token,
        received_at,
        expires_at,
    };
    let account_data = state.account_data();
    let mut attempt = 0;
    let record = loop {
        let existing = account_data
            .entry(subject, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
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
            actor_id: subject.to_owned(),
            account_data_key: AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
            revision: existing.as_ref().map_or(1, |record| record.revision + 1),
            payload,
            tombstone: false,
            updated_at: received_at,
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
                if attempt >= INVITE_DELIVERY_CAS_ATTEMPTS {
                    return Err(AppError::new(
                        ErrorCode::CasConflict,
                        "invite delivery account data changed concurrently",
                    ));
                }
            }
        }
    };
    fanout_actor_private_update(
        state,
        subject,
        ActorPrivateDeviceUpdate::AccountData {
            sender: principal_server_device_message_sender(state),
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
        .with_status(StatusCode::BAD_REQUEST)
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
        subject_id,
        service_resolution: ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: format!(
                "{}/_arkret/open/services/{recipient_id}/resolution",
                state.config().public_base_url.trim_end_matches('/')
            ),
            pinned_record_digest: None,
        },
        route_assistance: None,
        recipient_id,
        recipient_kind: None,
        issued_at,
        expires_at,
        locator_ref_digest,
        delivery_modes: Vec::new(),
        display_hint,
        proofs: Vec::new(),
    };
    let mut unsigned_locator = serde_json::to_value(&locator).map_err(|error| {
        AppError::internal(format!("principal locator unsigned serialize: {error}"))
    })?;
    if let Value::Object(object) = &mut unsigned_locator {
        object.remove("proofs");
    }
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned_locator)
        .map_err(|error| AppError::internal(format!("principal locator canonicalize: {error}")))?;
    let payload_digest =
        Hash::new(canonical::sha256_digest(&canonical_bytes)).map_err(|error| {
            AppError::internal(format!("principal locator digest invalid: {error}"))
        })?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &canonical_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("principal locator sign: {error}")))?;
    locator.proofs = vec![PrincipalLocatorProof {
        proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
        proof: DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#notary-key",
                state.service_resolution_commitment().did
            ))
            .map_err(|error| {
                AppError::internal(format!(
                    "service notary verification method is invalid: {error}"
                ))
            })?,
            payload_digest,
            created_at: now(),
            domain: None,
            audience: None,
            jws,
        },
    }];
    locator.validate_minimal().map_err(|error| {
        AppError::internal(format!("principal locator validation failed: {error}"))
    })?;
    json_ok(locator)
}

/// Spec invite-addressing.md §2 — introduction-evidence trust tiers.
/// High = `{locator_ref, consent_grant, shared_realm}`; Low =
/// `{same_principal_server, explicit_address, missing/invalid evidence}`. The tier
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
    let subject_exists = state
        .identities()
        .account(subject)
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
    let expires_at = received_at + Duration::days(INVITE_QUARANTINE_TTL_DAYS);
    let invite_event_id = body
        .pointer("/invite_event/event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    let invite_event_digest =
        crate::util::canonical_digest(body.get("invite_event").unwrap_or(&Value::Null))?;
    let request_digest = crate::util::canonical_digest(body)?;
    let idempotency_key_digest =
        format!("sha256:{}", sha256_hex(delivery.idempotency_key.as_bytes()));
    let entry_digest = format!(
        "sha256:{}",
        sha256_hex(
            format!(
                "{subject}|{source_id}|{}|{invite_event_digest}",
                delivery.idempotency_key
            )
            .as_bytes()
        )
    );
    let entry = json!({
        "entry_digest": entry_digest.clone(),
        "status": "pending_review",
        "subject_id": subject,
        "source_peer_principal_id": inviter_id,
        "source_id": source_id,
        "recipient_id": delivery.invite_address.recipient_id.as_str(),
        "consent_scope": "invite",
        "introduction_kind": delivery.introduction_evidence.kind(),
        "effective_kind": decision.effective_kind,
        "trust_tier": decision.trust_tier.as_str(),
        "invite_event_id": invite_event_id.clone(),
        "invite_event_digest": invite_event_digest.clone(),
        "request_digest": request_digest,
        "idempotency_key_digest": idempotency_key_digest,
        "received_at": received_at,
        "expires_at": expires_at,
    });

    let account_data = state.account_data();
    let existing = account_data
        .entry(subject, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut entries = existing
        .as_ref()
        .and_then(|record| record.payload.get("entries"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    entries.retain(|candidate| {
        invite_quarantine_entry_active(candidate, received_at)
            && candidate
                .get("entry_digest")
                .and_then(Value::as_str)
                .is_none_or(|existing_digest| existing_digest != entry_digest.as_str())
    });
    entries.push(entry);
    if entries.len() > MAX_INVITE_QUARANTINE_ENTRIES {
        let excess = entries.len() - MAX_INVITE_QUARANTINE_ENTRIES;
        entries.drain(0..excess);
    }

    let payload = json!({
        "schema": INVITE_QUARANTINE_SCHEMA,
        "entries": entries,
        "updated_at": received_at,
    });
    let record = AccountDataState {
        actor_id: subject.to_owned(),
        account_data_key: AccountDataKey::ACCOUNT_INVITE_QUARANTINE.to_owned(),
        revision: existing.as_ref().map_or(1, |record| record.revision + 1),
        payload,
        tombstone: false,
        updated_at: received_at,
    };
    let expected_revision = existing.as_ref().map_or(0, |record| record.revision);
    let applied = account_data
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
        subject,
        ActorPrivateDeviceUpdate::AccountData {
            sender: principal_server_device_message_sender(state),
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
            "invite_event_digest": invite_event_digest,
            "expires_at": expires_at,
        }),
        "accepted",
    )
    .await;
    Ok(true)
}

fn invite_quarantine_entry_active(entry: &Value, at: chrono::DateTime<chrono::Utc>) -> bool {
    entry
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc) > at)
        .unwrap_or(false)
}

/// Effective trust tier of an introduction evidence kind, *after* any
/// `consent_grant` verification downgrade has been resolved by the caller.
fn trust_tier_for_kind(kind: &str) -> TrustTier {
    match kind {
        "locator_ref" | "consent_grant" | "shared_realm" => TrustTier::High,
        "handle_claim" => TrustTier::Discovery,
        // same_principal_server / explicit_address / unknown → low
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
    subject: &DidCoreId,
) -> InviteReceivePolicy {
    state
        .contacts()
        .invite_policy(subject.as_str())
        .unwrap_or_else(|| InviteReceivePolicy::spec_default(subject.clone()))
}

/// Spec invite-addressing.md §2/§5/§5.1/§7-8 — the full receive decision.
pub(crate) fn directory_handle_claim_resolve_allowed(
    state: &AppState,
    intent: Option<DirectoryIntent>,
    requester: Option<&DidCoreId>,
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
    let Some(requester) = requester else {
        return false;
    };
    let Some(handle) = handle_claim.handle.clone() else {
        return false;
    };
    let Ok(subject_id) = DidCoreId::new(subject.to_owned()) else {
        return false;
    };
    let policy = resolve_core_invite_receive_policy(state, &subject_id);
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
                requester.as_str(),
                subject,
                recipient_id,
                source_id,
            )
        }
        Some(DirectoryIntent::Invite | DirectoryIntent::MemberAdd) => {
            let evidence = IntroductionEvidence::HandleClaim {
                handle,
                handle_claim: Box::new(handle_claim.clone()),
                member_delivery_binding_candidate: None,
                resolved_by,
                resolved_at: Some(chrono::Utc::now()),
            };
            evaluate_invite_receive(
                state,
                &policy,
                &evidence,
                requester.as_str(),
                subject,
                recipient_id,
                source_id,
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
    inviter_id: &str,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::InviteDelivery);

    // §5 — `denied_subjects` hit: MUST drop and force opaque disclosure so
    // the blocklist cannot leak through the response side channel.
    if policy
        .denied_subject_ids
        .iter()
        .any(|did| did.as_str() == inviter_id)
    {
        return ReceiveDecision {
            action: InviteReceiveAction::Drop,
            effective_kind: evidence.kind(),
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

    let effective_kind: &'static str = match evidence {
        IntroductionEvidence::LocatorRef { principal_locator } => {
            if principal_locator.validate_minimal().is_ok()
                && principal_locator.subject_id.as_str() == subject
                && principal_locator.recipient_id.as_str() == recipient_id
                && principal_locator.expires_at > now
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
            member_delivery_binding_candidate,
            resolved_by,
            ..
        } => {
            if handle_claim_evidence_valid(
                policy,
                constraints,
                handle,
                handle_claim,
                member_delivery_binding_candidate.as_deref(),
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
        other => other.kind(),
    };

    if kind_forbidden_by_constraints(constraints, effective_kind)
        || !kind_permitted_by_constraints(constraints, effective_kind)
    {
        return opaque_drop(effective_kind);
    }

    let trust_tier = trust_tier_for_kind(effective_kind);

    // §5 — allowlist gate. Evidence kinds not in `holder_allowed_introduction_kinds`
    // MUST NOT notify; they fall through to the explicit/unknown behavior.
    let allowlisted = policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|kind| kind == effective_kind);

    let unknown_path =
        !allowlisted && !matches!(effective_kind, "handle_claim" | "explicit_address");

    let mut action = if allowlisted {
        match effective_kind {
            "handle_claim" => policy
                .handle_claim_behavior
                .clone()
                .unwrap_or(InviteReceiveAction::Quarantine),
            "explicit_address" => policy.explicit_address_behavior.clone(),
            _ => InviteReceiveAction::Notify,
        }
    } else if effective_kind == "handle_claim" {
        policy
            .handle_claim_behavior
            .clone()
            .unwrap_or(InviteReceiveAction::Quarantine)
    } else if effective_kind == "explicit_address" {
        policy.explicit_address_behavior.clone()
    } else {
        unknown_action_to_receive(&policy.unknown_invites)
    };
    action = apply_behavior_caps(constraints, effective_kind, unknown_path, action);

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

pub(crate) fn evaluate_contact_receive(
    state: &AppState,
    policy: &InviteReceivePolicy,
    evidence: &ContactIntroductionEvidence,
    requester: &str,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::ContactRequest);
    let effective_kind: &'static str = match evidence {
        ContactIntroductionEvidence::LocatorRef { principal_locator } => {
            if principal_locator.validate_minimal().is_ok()
                && principal_locator.subject_id.as_str() == subject
                && principal_locator.recipient_id.as_str() == recipient_id
                && principal_locator.expires_at > now
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
                None,
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
        ContactIntroductionEvidence::SamePrincipalServer => "same_principal_server",
        ContactIntroductionEvidence::ExplicitAddress => "explicit_address",
    };

    if policy
        .denied_subject_ids
        .iter()
        .any(|did| did.as_str() == requester)
        || principal_service_blocked(policy, constraints, source_id)
        || !principal_service_trusted(policy, constraints, source_id)
        || !subject_did_method_accepted(constraints, subject)
        || kind_forbidden_by_constraints(constraints, effective_kind)
        || !kind_permitted_by_constraints(constraints, effective_kind)
    {
        return opaque_drop(effective_kind);
    }

    let trust_tier = trust_tier_for_kind(effective_kind);
    let allowlisted = policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|kind| kind == effective_kind);
    let unknown_path =
        !allowlisted && !matches!(effective_kind, "handle_claim" | "explicit_address");
    let mut action = if allowlisted {
        match effective_kind {
            "handle_claim" => policy
                .handle_claim_behavior
                .clone()
                .unwrap_or(InviteReceiveAction::Quarantine),
            "explicit_address" => policy.explicit_address_behavior.clone(),
            _ => InviteReceiveAction::Notify,
        }
    } else if effective_kind == "handle_claim" {
        policy
            .handle_claim_behavior
            .clone()
            .unwrap_or(InviteReceiveAction::Quarantine)
    } else if effective_kind == "explicit_address" {
        policy.explicit_address_behavior.clone()
    } else {
        unknown_action_to_receive(&policy.unknown_invites)
    };
    action = apply_behavior_caps(constraints, effective_kind, unknown_path, action);
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
        "explicit_address" => {
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
        .denied_principal_ids
        .iter()
        .any(|did| did.as_str() == source_id)
        || constraints
            .and_then(|constraints| constraints.denied_principal_ids.as_ref())
            .is_some_and(|blocked| did_in_list(source_id, blocked))
}

fn principal_service_trusted(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_id: &str,
) -> bool {
    if !policy.trusted_principal_ids.is_empty()
        && !did_in_list(source_id, &policy.trusted_principal_ids)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_principal_ids.as_ref())
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
    candidate: Option<&MemberDeliveryBindingCandidate>,
    resolved_by: Option<&DidCoreId>,
    subject: &str,
    recipient_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if handle_claim.validate().is_err() {
        return false;
    }
    if handle_claim.handle.as_ref() != Some(handle) {
        return false;
    }
    if handle_claim.subject_id.as_ref().map(DidCoreId::as_str) != Some(subject) {
        return false;
    }
    if handle_claim.binding_state != Some(HandleBindingState::Verified) {
        return false;
    }
    if handle_claim
        .expires_at
        .is_none_or(|expires_at| expires_at <= now)
    {
        return false;
    }
    if handle_claim.proofs.is_empty() {
        return false;
    }
    if let Some(binding) = &handle_claim.member_delivery_binding
        && binding.recipient_id.as_str() != recipient_id
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
    if let Some(candidate) = candidate
        && !member_delivery_candidate_valid(candidate, handle, subject, recipient_id, now)
    {
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
    handle_claim
        .issuer_id
        .as_ref()
        .is_some_and(|issuer| trusted.iter().any(|did| did == issuer))
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

fn member_delivery_candidate_valid(
    candidate: &MemberDeliveryBindingCandidate,
    handle: &Handle,
    subject: &str,
    recipient_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if candidate.intent != CandidateIntent::Invite {
        return false;
    }
    if &candidate.handle != handle {
        return false;
    }
    if candidate.subject_id.as_str() != subject {
        return false;
    }
    if candidate.member_delivery_binding.recipient_id.as_str() != recipient_id {
        return false;
    }
    let Ok(subject_id) = DidCoreId::new(subject.to_owned()) else {
        return false;
    };
    let context = CandidateValidationContext::new(candidate.audience.clone())
        .with_now(now)
        .with_expected_subject(subject_id);
    candidate.validate(&context).is_ok()
}

fn validate_invite_delivery_consistency(
    body: &Value,
    delivery: &InviteDeliveryRequestBody,
    state: &AppState,
) -> Result<(), AppError> {
    if delivery.invite_address.recipient_id.as_str() != state.service_id() {
        return Err(super::events::peer::cross_domain_replay(
            "invite_address.recipient_id does not match this service",
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
    if payload.get("invitee_id").and_then(Value::as_str)
        != Some(delivery.invite_address.subject_id.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invitee_id must equal invite_address.subject_id",
        ));
    }
    if payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_id"))
        .and_then(Value::as_str)
        != Some(delivery.invite_address.recipient_id.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invite_delivery_target.recipient_id must equal invite_address.recipient_id",
        ));
    }
    if let Some(service_kind) = payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_kind"))
        .and_then(Value::as_str)
        && service_kind != "principal_server"
    {
        return Err(super::events::peer::schema_violation(
            "invite_delivery_target.recipient_kind must be principal_server",
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

    async fn production_holder_state() -> AppState {
        let state = AppState::new(
            crate::config::AppConfig {
                development_mode: false,
                seed_demo_data: false,
                object_storage: crate::config::ObjectStorageConfig::local(
                    std::env::temp_dir().join("soland-invite-service-fanout-test-blobs"),
                ),
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );
        let created_at = now();
        state
            .identities()
            .save_account(AccountProfileState {
                id: PRODUCTION_HOLDER.to_owned(),
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
            assert_eq!(envelope.sender_principal_id.as_str(), PRODUCTION_HOLDER);
            assert_eq!(envelope.recipient_principal_id.as_str(), PRODUCTION_HOLDER);
            assert_eq!(envelope.recipient_device_id.as_str(), device_id);
            assert!(matches!(
                &envelope.sender,
                crate::wire::DeviceMessageSender::Service { sender_id }
                    if sender_id.as_str() == state.service_id()
            ));
            assert_eq!(
                envelope.content.get("account_data_key"),
                Some(&json!(account_data_key))
            );
            assert_eq!(
                envelope.content.get("revision"),
                Some(&json!(expected_revision))
            );
            assert_eq!(envelope.content.get("content"), Some(expected_payload));
        }
    }

    fn production_invite_delivery(state: &AppState) -> InviteDeliveryRequestBody {
        let event: arkret_wire::Event = serde_json::from_value(json!({
            "event_id": PRODUCTION_INVITE_EVENT,
            "kind": arkret_wire::EventKind::InviteCreate.as_str(),
            "realm_id": PRODUCTION_REALM,
            "scope_ref": { "kind": "realm", "realm_id": PRODUCTION_REALM },
            "actor_id": PRODUCTION_INVITER,
            "principal_server_id": state.service_id(),
            "actor_seq": 0,
            "created_at": "2026-08-21T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "invitee_id": PRODUCTION_HOLDER,
                "expires_at": "2099-01-01T00:00:00.000Z"
            },
            "proofs": []
        }))
        .expect("invite Event");
        let service_id = DidCoreId::new(state.service_id().to_owned()).unwrap();
        let address = arkret_models_collaboration::governance::invite_addressing::InviteAddress::principal_server(
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
            inviter_id: DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
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
            inviter_id: DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
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

        assert!(
            deliver_invite_credential(
                &state,
                PRODUCTION_HOLDER,
                PRODUCTION_INVITER,
                &body,
                PRODUCTION_REALM,
            )
            .await
            .expect("invite credential delivery")
        );
        let cell = state
            .account_data()
            .entry(PRODUCTION_HOLDER, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
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
            .entry(PRODUCTION_HOLDER, AccountDataKey::ACCOUNT_INVITE_QUARANTINE)
            .await
            .expect("invite quarantine cell")
            .expect("invite quarantine write");
        assert_eq!(cell.payload["schema"], INVITE_QUARANTINE_SCHEMA);
        let entry = &cell.payload["entries"][0];
        assert!(
            entry["entry_digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
        );
        assert_eq!(entry["source_peer_principal_id"], PRODUCTION_INVITER);
        assert!(entry.get("quarantine_id").is_none());
        assert!(entry.get("source_peer_id").is_none());
        assert!(entry.get("inviter_id").is_none());
        assert_service_account_data_fanout(
            &state,
            AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
            cell.revision,
            &cell.payload,
        )
        .await;
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
        assert!(
            !deliver_invite_credential(
                &state,
                "did:web:carol.example",
                "ak:did_core:web:alice.example",
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
                    "did:web:carol.example",
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
        let invite_id = "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K";
        let subject = "did:web:bob.example";
        let body = json!({
            "invite_event": {
                "created_at": "2026-07-29T10:00:00.000Z",
                "payload": {
                    "invite_id": invite_id,
                    "invite_delivery_target": {
                        "recipient_id": state.service_id(),
                        "recipient_kind": "principal_server"
                    },
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

        assert!(
            !persist_private_invite_projection(&state, subject, &body, &validated)
                .await
                .expect("first private projection")
        );
        assert!(
            persist_private_invite_projection(&state, subject, &body, &validated)
                .await
                .expect("exact replay")
        );
        assert!(
            state
                .realm_invites()
                .get(invite_id)
                .await
                .expect("private invite lookup")
                .is_some()
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
