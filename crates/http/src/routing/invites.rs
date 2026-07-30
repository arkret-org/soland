//! Invite addressing protocol surface.
//!
//! Implements the v1 private invite delivery endpoint and the body-only
//! online locator resolver from `sync/invite-addressing.md`.

// NOTE: `arkret_models_collaboration::governance::invite_addressing::DisclosurePolicy` at the crate
// root resolves to the auth/DID-proof type (re-exported explicitly), which shadows the
// invite-addressing one from the `model::*` glob. Import the
// invite-addressing variant via its `model` module path to disambiguate.
use arkret_canonical as canonical;
use arkret_identifiers::{Did, Hash, InviteLocatorId};
use arkret_models_collaboration::governance::invite_addressing::{
    DisclosedOutcome, DisclosureLevel, DisclosurePolicy, IntroductionEvidence,
    InviteDeliveryOutcome, InviteDeliveryOutcomeStatus, InviteDeliveryRequestBodyBody,
    InviteLocatorIssueOutcome, InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody,
    InviteLocatorRevokeOutcome, InviteLocatorRevokeRequestBody, InviteLocatorRotateRequestBody,
    InviteLocatorStatus, InviteReceivePolicy, PrincipalLocator, PrincipalLocatorProof,
    PrincipalLocatorProofPurpose,
};
use arkret_models_collaboration::governance::member_delivery_binding_candidate::{
    CandidateIntent, CandidateValidationContext, MemberDeliveryBindingCandidate,
};
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_discovery::DirectoryIntent;
use arkret_models_identity::HandleClaim;
use arkret_models_identity::handle::{Handle, HandleBindingState};
use arkret_models_identity::proof::DetachedPayloadProof;
use arkret_wire::{
    InviteReceiveAction, ReceivePolicyConstraints, ReceivePolicySurface, UnknownInviteAction,
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
    InviteLocatorInsertResult as InviteLocatorInsertOutcome,
    InviteLocatorRotateCommand as InviteLocatorRotateMutation,
    InviteLocatorState as InviteLocatorRecord, RealmInviteState as RealmInviteRecord,
};
use soland_services::identity::{
    AccountDataCasOutcome, AccountDataState, SessionIdentityState as SessionRecord,
};

use crate::routing::identity::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, fanout_actor_private_update,
};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
const ACCOUNT_DATA_KEY_INVITE_QUARANTINE: &str = "ak.account.invite_quarantine";
const ACTIVE_LOCATOR_LIMIT: usize = 16;
const INVITE_LOCATOR_CACHE_CONTROL: &str = "private, no-store";
const INVITE_QUARANTINE_TTL_DAYS: i64 = 30;
const MAX_INVITE_QUARANTINE_ENTRIES: usize = 200;
const INVITE_QUARANTINE_ORIGIN_DEVICE: &str = "server:invite_quarantine";

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
}

fn new_invite_locator(
    subject_id: &str,
    recipient_service_id: &str,
    options: InviteLocatorIssueRequestBody,
) -> Result<(InviteLocatorRecord, String), AppError> {
    options
        .validate_minimal()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(i64::from(options.effective_ttl_seconds()));
    let (token, token_digest) = new_invite_locator_secret();
    let record = InviteLocatorRecord {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest,
        subject_id: subject_id.to_owned(),
        recipient_service_id: recipient_service_id.to_owned(),
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
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
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
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
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
#[tracing::instrument(skip_all, fields(op = "ak.peer.invites.command.submit"))]
async fn peer_invites_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteDeliveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::events::peer::validate_peer_request(state, req, true).await?;
    let delivery = req
        .parse_json::<InviteDeliveryRequestBodyBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid ak.peer.invites.command.submit request body"))?;
    let body = serde_json::to_value(&delivery).map_err(|error| {
        AppError::internal(format!("invite delivery request serialize: {error}"))
    })?;

    delivery.validate_minimal().map_err(|error| {
        super::events::peer::schema_violation(format!("invalid invite delivery request: {error}"))
    })?;

    let destination_service_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if destination_service_id != delivery.invite_address.recipient_service_id.as_str() {
        return Err(super::events::peer::cross_domain_replay(
            "Destination-Service-ID must equal invite_address.recipient_service_id",
        ));
    }

    validate_invite_delivery_consistency(&body, &delivery, state)?;

    // The inviter is the actor that signed the durable `ak.invite.create`
    // event; it is the `peer` we test `denied_subjects` and the
    // `consent_grant` evidence against (spec invite-addressing.md §2 / §5).
    let actor = body
        .pointer("/invite_event/actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.actor_id is required"))?
        .to_owned();
    let inviter = actor.clone();
    let subject = delivery.invite_address.subject_id.as_str().to_owned();
    let source_service_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;

    // Spec invite-addressing.md §5..§8 — resolve the subject's private
    // receive policy, derive the effective trust tier (downgrading
    // `consent_grant` to `explicit_address` when the grant cannot be
    // verified), then apply blocklist + allowlist + behavior to pick a
    // receive action and a graded-disclosure outcome.
    let policy = resolve_invite_receive_policy(state, &subject);
    let decision = evaluate_invite_receive(
        state,
        &policy,
        &delivery.introduction_evidence,
        &inviter,
        &subject,
        delivery.invite_address.recipient_service_id.as_str(),
        &source_service_id,
    );

    if decision.action != InviteReceiveAction::Notify {
        let quarantine_persisted = if decision.action == InviteReceiveAction::Quarantine {
            persist_invite_quarantine_entry(
                state,
                &subject,
                &source_service_id,
                &inviter,
                &delivery,
                &body,
                &decision,
            )
            .await?
        } else {
            false
        };
        super::append_audit_log(
            state,
            None,
            "peer.invites.submit",
            json!({
                "idempotency_key": delivery.idempotency_key,
                "invitee": delivery.invite_address.subject_id,
                "recipient_service_id": delivery.invite_address.recipient_service_id,
                "introduction_kind": delivery.introduction_evidence.kind(),
                "effective_kind": decision.effective_kind,
                "trust_tier": decision.trust_tier.as_str(),
                "receive_action": receive_action_str(&decision.action),
                "quarantine_persisted": quarantine_persisted,
            }),
            "deferred",
        )
        .await;
        let outcome = InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Deferred,
            disclosed_outcome: decision.disclosed_outcome,
            received_at: Some(now()),
            retry_after_ms: None,
        };
        return json_ok(outcome);
    }

    let trust_headers =
        crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
            .map_err(|violation| {
                super::events::peer::schema_violation(violation.message())
                    .with_wire_code(violation.error_code())
            })?;
    let request_hash = canonical::canonical_sha256(&body).map_err(|error| {
        super::events::peer::schema_violation(format!(
            "ak.peer.invites.command.submit body is not canonical-hashable: {error}"
        ))
    })?;
    let session = SessionRecord {
        token_hash: format!(
            "peer-invite:{}:{request_hash}",
            trust_headers.source_trust_domain
        ),
        actor,
        device_id: format!("peer-invite:{source_service_id}"),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: now() + Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    };

    let validated = super::events::event_log::validate_private_invite_envelope(
        state,
        &session,
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
        &body,
        &validated,
    )
    .await?;

    let status = if duplicate { "duplicate" } else { "accepted" };
    super::append_audit_log(
        state,
        None,
        "peer.invites.submit",
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": validated.event_id,
            "invitee": delivery.invite_address.subject_id,
            "recipient_service_id": delivery.invite_address.recipient_service_id,
            "introduction_kind": delivery.introduction_evidence.kind(),
            "effective_kind": decision.effective_kind,
            "trust_tier": decision.trust_tier.as_str(),
            "request_canonical_digest": request_hash,
            "event_canonical_digest": validated.canonical_digest,
            "projection": "holder_private_invite",
        }),
        status,
    )
    .await;
    let outcome = InviteDeliveryOutcome {
        status: if duplicate {
            InviteDeliveryOutcomeStatus::Duplicate
        } else {
            InviteDeliveryOutcomeStatus::Accepted
        },
        disclosed_outcome: decision.disclosed_outcome,
        received_at: Some(now()),
        retry_after_ms: None,
    };
    json_ok(outcome)
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
        realm_id: validated.realm_id.clone(),
        inviter: validated.actor_id.clone(),
        invitee: Some(subject.to_owned()),
        invite_delivery_target,
        introduction_evidence_digest,
        third_party_id: None,
        join_rule_snapshot: payload.get("join_rule_snapshot").cloned(),
        invite_token: crate::routing::generate_invite_token(
            &invite_id,
            &validated.realm_id,
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
            && existing.inviter == record.inviter
            && existing.invitee == record.invitee
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

#[endpoint(
    operation_id = "ak.open.invite_locator.query.resolve",
    summary = "Resolve an invite locator",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.invite_locator.query.resolve"))]
async fn resolve_invite_locator(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalLocator> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if locator_token_appears_in_url(req) {
        return Err(AppError::invalid_param(
            "locator_token must be sent in the JSON body, never in URL path or query",
        )
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation"));
    }
    let body = req
        .parse_json::<InviteLocatorResolveRequestBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid invite locator resolve request body"))?;
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
        Did::new(locator_ref.subject_id.clone()).map_err(|_| invite_locator_not_found())?;
    let issued_at = locator_ref.issued_at;
    let expires_at = locator_ref.expires_at;
    let locator_ref_digest = Hash::new(locator_ref.token_digest.clone())
        .map_err(|error| AppError::internal(format!("locator_ref_digest invalid: {error}")))?;
    let display_hint = locator_ref.display_hint;
    let recipient_service_id = Did::new(locator_ref.recipient_service_id).map_err(|error| {
        AppError::internal(format!(
            "configured service DID invalid for principal locator: {error}"
        ))
    })?;
    let mut locator = PrincipalLocator {
        schema: arkret_wire::constants::PRINCIPAL_LOCATOR_SCHEMA.to_owned(),
        subject_id,
        recipient_service_id,
        recipient_service_kind: None,
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
            verification_method: format!("{}#notary-key", state.service_id()),
            alg: "EdDSA".to_owned(),
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
    source_service_id: &str,
    inviter: &str,
    delivery: &InviteDeliveryRequestBodyBody,
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
                "invitee": subject,
                "source_service_id": source_service_id,
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
    let invite_event_digest = canonical_digest(body.get("invite_event").unwrap_or(&Value::Null))?;
    let request_digest = canonical_digest(body)?;
    let idempotency_key_digest =
        format!("sha256:{}", sha256_hex(delivery.idempotency_key.as_bytes()));
    let quarantine_id = format!(
        "ak:invite_quarantine:{}",
        sha256_hex(
            format!(
                "{subject}|{source_service_id}|{}|{invite_event_digest}",
                delivery.idempotency_key
            )
            .as_bytes()
        )
    );
    let entry = json!({
        "quarantine_id": quarantine_id.clone(),
        "status": "pending_review",
        "subject_id": subject,
        "inviter": inviter,
        "source_peer_did": inviter,
        "source_service_id": source_service_id,
        "recipient_service_id": delivery.invite_address.recipient_service_id.as_str(),
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
        .entry(subject, ACCOUNT_DATA_KEY_INVITE_QUARANTINE)
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
                .get("quarantine_id")
                .and_then(Value::as_str)
                .is_none_or(|existing_id| existing_id != quarantine_id.as_str())
    });
    entries.push(entry);
    if entries.len() > MAX_INVITE_QUARANTINE_ENTRIES {
        let excess = entries.len() - MAX_INVITE_QUARANTINE_ENTRIES;
        entries.drain(0..excess);
    }

    let payload = json!({
        "schema": "ak.account.invite_quarantine.v1",
        "status": "pending_review",
        "entries": entries,
        "updated_at": received_at,
    });
    let record = AccountDataState {
        actor_id: subject.to_owned(),
        account_data_key: ACCOUNT_DATA_KEY_INVITE_QUARANTINE.to_owned(),
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
        INVITE_QUARANTINE_ORIGIN_DEVICE,
        ACCOUNT_DATA_UPDATE_TYPE,
        json!({
            "operation": "put",
            "account_data_key": ACCOUNT_DATA_KEY_INVITE_QUARANTINE,
            "revision": record.revision,
            "content": record.payload.clone(),
            "updated_at": record.updated_at,
        }),
    )
    .await;
    super::append_audit_log(
        state,
        Some(subject),
        "peer.invites.quarantine",
        json!({
            "invitee": subject,
            "source_service_id": source_service_id,
            "inviter": inviter,
            "invite_event_id": invite_event_id,
            "invite_event_digest": invite_event_digest,
            "expires_at": expires_at,
        }),
        "accepted",
    )
    .await;
    Ok(true)
}

fn canonical_digest(value: &Value) -> Result<String, AppError> {
    canonical::canonical_sha256(value)
        .map_err(|error| AppError::internal(format!("canonical invite digest failed: {error}")))
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

/// Spec invite-addressing.md §5 — the recommended default
/// `invite_receive_policy` applied to subjects without an explicit
/// override: `consent_grant` is allowlisted (so already-consented
/// contacts can invite without a locator URL), explicit addresses are
/// quarantined, unknown invites dropped, and disclosure is
/// `high_trust=outcome / low_trust=opaque`.
pub(crate) fn default_invite_receive_policy(subject: &str) -> InviteReceivePolicy {
    InviteReceivePolicy {
        schema: arkret_wire::constants::INVITE_RECEIVE_POLICY_SCHEMA.to_owned(),
        subject_id: Did::new(subject.to_owned()).unwrap_or_else(|_| {
            // did:webvh-only red line: placeholder is never a did:web literal.
            Did::new("did:webvh:invalid.invalid".to_owned()).expect("placeholder did")
        }),
        holder_allowed_introduction_kinds: vec![
            "locator_ref".to_owned(),
            "consent_grant".to_owned(),
            "shared_realm".to_owned(),
        ],
        explicit_address_behavior: InviteReceiveAction::Quarantine,
        handle_claim_behavior: Some(InviteReceiveAction::Quarantine),
        unknown_invites: UnknownInviteAction::Drop,
        allowed_handle_domains: Vec::new(),
        denied_handle_domains: Vec::new(),
        trusted_handle_issuers: Vec::new(),
        trusted_directory_services: Vec::new(),
        trusted_realm_ids: Vec::new(),
        trusted_principal_services: Vec::new(),
        denied_principal_services: Vec::new(),
        denied_subjects: Vec::new(),
        disclosure: Some(DisclosurePolicy {
            high_trust: Some(DisclosureLevel::Outcome),
            discovery_trust: Some(DisclosureLevel::Opaque),
            low_trust: Some(DisclosureLevel::Opaque),
        }),
    }
}

/// Read the subject's private `invite_receive_policy`, falling back to the
/// recommended default. `denied_subjects` written by
/// `ak.self.contact.command.tombstone(block_peer)` are merged from the in-memory
/// override store.
pub(crate) fn resolve_invite_receive_policy(
    state: &AppState,
    subject: &str,
) -> InviteReceivePolicy {
    state
        .contacts()
        .invite_policy(subject)
        .unwrap_or_else(|| default_invite_receive_policy(subject))
}

/// Spec invite-addressing.md §2/§5/§5.1/§7-8 — the full receive decision.
pub(crate) fn directory_handle_claim_resolve_allowed(
    state: &AppState,
    intent: Option<DirectoryIntent>,
    requester: Option<&Did>,
    subject: &str,
    recipient_service_id: &str,
    source_service_id: &str,
    handle_claim: &HandleClaim,
    resolved_by: Option<Did>,
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
    let policy = resolve_invite_receive_policy(state, subject);
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
                recipient_service_id,
                source_service_id,
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
                recipient_service_id,
                source_service_id,
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
    inviter: &str,
    subject: &str,
    recipient_service_id: &str,
    source_service_id: &str,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::InviteDelivery);

    // §5 — `denied_subjects` hit: MUST drop and force opaque disclosure so
    // the blocklist cannot leak through the response side channel.
    if policy
        .denied_subjects
        .iter()
        .any(|did| did.as_str() == inviter)
    {
        return ReceiveDecision {
            action: InviteReceiveAction::Drop,
            effective_kind: evidence.kind(),
            trust_tier: TrustTier::Low,
            disclosed_outcome: None,
        };
    }

    // §2 — `consent_grant` evidence: verify the referenced grant is an
    // active `invite`/`any` dot the subject gave the inviter. On failure
    // MUST downgrade to low-trust `explicit_address`.
    if principal_service_blocked(policy, constraints, source_service_id)
        || !principal_service_trusted(policy, constraints, source_service_id)
        || !subject_did_method_accepted(constraints, subject)
    {
        return opaque_drop(evidence.kind());
    }

    let effective_kind: &'static str = match evidence {
        IntroductionEvidence::LocatorRef { principal_locator } => {
            if principal_locator.validate_minimal().is_ok()
                && principal_locator.subject_id.as_str() == subject
                && principal_locator.recipient_service_id.as_str() == recipient_service_id
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
                inviter,
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
                recipient_service_id,
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
    recipient_service_id: &str,
    source_service_id: &str,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::ContactRequest);
    let effective_kind: &'static str = match evidence {
        ContactIntroductionEvidence::LocatorRef { principal_locator } => {
            if principal_locator.validate_minimal().is_ok()
                && principal_locator.subject_id.as_str() == subject
                && principal_locator.recipient_service_id.as_str() == recipient_service_id
                && principal_locator.expires_at > now
            {
                "locator_ref"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::ConsentGrant {
            consent_grant_ref,
            consent_id,
        } => {
            if crate::routing::identity::consent::has_active_consent_grant_evidence(
                state,
                subject,
                requester,
                consent_grant_ref.as_str(),
                consent_id.as_deref(),
                now,
            ) {
                "consent_grant"
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
                recipient_service_id,
                now,
            ) {
                "handle_claim"
            } else {
                "explicit_address"
            }
        }
        other => other.kind(),
    };

    if policy
        .denied_subjects
        .iter()
        .any(|did| did.as_str() == requester)
        || principal_service_blocked(policy, constraints, source_service_id)
        || !principal_service_trusted(policy, constraints, source_service_id)
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

fn did_in_list(value: &str, list: &[Did]) -> bool {
    list.iter().any(|did| did.as_str() == value)
}

fn principal_service_blocked(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_service_id: &str,
) -> bool {
    policy
        .denied_principal_services
        .iter()
        .any(|did| did.as_str() == source_service_id)
        || constraints
            .and_then(|constraints| constraints.denied_principal_services.as_ref())
            .is_some_and(|blocked| did_in_list(source_service_id, blocked))
}

fn principal_service_trusted(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_service_id: &str,
) -> bool {
    if !policy.trusted_principal_services.is_empty()
        && !did_in_list(source_service_id, &policy.trusted_principal_services)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_principal_services.as_ref())
        .is_none_or(|trusted| did_in_list(source_service_id, trusted))
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
    resolved_by: Option<&Did>,
    subject: &str,
    recipient_service_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if handle_claim.validate().is_err() {
        return false;
    }
    if handle_claim.handle.as_ref() != Some(handle) {
        return false;
    }
    if handle_claim.subject.as_ref().map(Did::as_str) != Some(subject) {
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
        && binding.recipient_service_id.as_str() != recipient_service_id
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
        && !member_delivery_candidate_valid(candidate, handle, subject, recipient_service_id, now)
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
    if !policy.trusted_handle_issuers.is_empty()
        && !handle_claim_matches_did_list(handle_claim, &policy.trusted_handle_issuers)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_handle_issuers.as_ref())
        .is_none_or(|trusted| handle_claim_matches_did_list(handle_claim, trusted))
}

fn handle_claim_matches_did_list(handle_claim: &HandleClaim, trusted: &[Did]) -> bool {
    if trusted.is_empty() {
        return false;
    }
    if handle_claim
        .issuer_service_id
        .as_ref()
        .is_some_and(|issuer| trusted.iter().any(|did| did == issuer))
    {
        return true;
    }
    handle_claim
        .issuer
        .as_deref()
        .and_then(|issuer| Did::new(issuer.to_owned()).ok())
        .is_some_and(|issuer| trusted.iter().any(|did| did == &issuer))
}

fn resolved_by_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    resolved_by: Option<&Did>,
) -> bool {
    if !policy.trusted_directory_services.is_empty()
        && !resolved_by
            .is_some_and(|did| policy.trusted_directory_services.iter().any(|v| v == did))
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_directory_services.as_ref())
        .is_none_or(|trusted| {
            !trusted.is_empty()
                && resolved_by.is_some_and(|did| trusted.iter().any(|candidate| candidate == did))
        })
}

fn member_delivery_candidate_valid(
    candidate: &MemberDeliveryBindingCandidate,
    handle: &Handle,
    subject: &str,
    recipient_service_id: &str,
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
    if candidate
        .member_delivery_binding
        .recipient_service_id
        .as_str()
        != recipient_service_id
    {
        return false;
    }
    let Ok(subject_did) = Did::new(subject.to_owned()) else {
        return false;
    };
    let context = CandidateValidationContext::new(candidate.audience.clone())
        .with_now(now)
        .with_expected_subject(subject_did);
    candidate.validate(&context).is_ok()
}

fn validate_invite_delivery_consistency(
    body: &Value,
    delivery: &InviteDeliveryRequestBodyBody,
    state: &AppState,
) -> Result<(), AppError> {
    if delivery.invite_address.recipient_service_id.as_str() != state.service_id() {
        return Err(super::events::peer::cross_domain_replay(
            "invite_address.recipient_service_id does not match this service",
        ));
    }
    if body.pointer("/invite_event/kind").and_then(Value::as_str)
        != Some(arkret_wire::events::EventKind::INVITE_CREATE)
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.kind must be ak.invite.create",
        ));
    }
    let payload = body
        .pointer("/invite_event/payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    if payload.get("invitee").and_then(Value::as_str)
        != Some(delivery.invite_address.subject_id.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invitee must equal invite_address.subject_id",
        ));
    }
    if payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_service_id"))
        .and_then(Value::as_str)
        != Some(delivery.invite_address.recipient_service_id.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invite_delivery_target.recipient_service_id must equal invite_address.recipient_service_id",
        ));
    }
    if let Some(service_kind) = payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_service_kind"))
        .and_then(Value::as_str)
        && service_kind != "principal_server"
    {
        return Err(super::events::peer::schema_violation(
            "invite_delivery_target.recipient_service_kind must be principal_server",
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
    use super::*;

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

    #[tokio::test]
    async fn private_invite_projection_is_idempotent_and_never_writes_shared_event_state() {
        let state = AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000401";
        let invite_id = "ak:invite:01904100-0000-7000-8000-000000000402";
        let subject = "did:web:bob.example";
        let body = json!({
            "invite_event": {
                "created_at": "2026-07-29T10:00:00.000Z",
                "payload": {
                    "invite_id": invite_id,
                    "invite_delivery_target": {
                        "recipient_service_id": state.service_id(),
                        "recipient_service_kind": "principal_server"
                    },
                    "introduction_evidence_digest":
                        format!("sha256:{}", "a".repeat(64)),
                    "expires_at": "2026-08-05T10:00:00.000Z"
                }
            }
        });
        let validated = crate::routing::events::event_log::ValidatedEventEnvelope {
            event_id: "ak:event:01904100-0000-7000-8000-000000000403".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000404".to_owned(),
            actor_seq: 7,
            realm_id: realm_id.to_owned(),
            kind: arkret_wire::events::EventKind::INVITE_CREATE.to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            prev_refs: Vec::new(),
            authorized_refs: Vec::new(),
            canonical_digest: format!("sha256:{}", "b".repeat(64)),
            canonical_bytes: Vec::new(),
            data_event_query_grade:
                crate::routing::events::event_log::DataEventQueryGrade::Observed,
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
