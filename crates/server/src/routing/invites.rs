//! Invite addressing protocol surface.
//!
//! Implements the v1 private invite delivery endpoint and the body-only
//! online locator resolver from `sync/invite-addressing.md`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Duration;
// NOTE: `cokret_sdk::DisclosurePolicy` at the crate root resolves to the
// auth/DID-proof type (re-exported explicitly), which shadows the
// invite-addressing one from the `model::*` glob. Import the
// invite-addressing variant via its `model` module path to disambiguate.
use cokret_sdk::model::DisclosurePolicy;
use cokret_sdk::{
    DetachedPayloadProof, Did, DisclosedOutcome, DisclosureLevel, Hash, IntroductionEvidence,
    InviteDeliveryOutcome, InviteDeliveryOutcomeStatus, InviteDeliveryRequest,
    InviteLocatorResolveRequestBody, InviteReceiveAction, InviteReceivePolicy, PrincipalLocator,
    PrincipalLocatorDisplayHint, PrincipalLocatorProof, PrincipalLocatorProofPurpose,
    UnknownInviteAction, canonical,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, SessionRecord};
use crate::wire::now;

const HEADER_CONTENT_DIGEST: &str = "content-digest";
const HEADER_SOURCE_SERVICE_DID: &str = "source-service-did";
const HEADER_DESTINATION_SERVICE_DID: &str = "destination-service-did";
const DEFAULT_LOCATOR_TTL_MINUTES: i64 = 15;

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("invites").post(peer_invites_submit))
}

pub(crate) fn open_router() -> Router {
    Router::new().push(Router::with_path("invite-locators/resolve").post(resolve_invite_locator))
}

#[endpoint(
    operation_id = "ck.peer.invites.command.submit",
    tags("peer"),
    summary = "Private Principal Server invite delivery"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.invites.command.submit"))]
async fn peer_invites_submit(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<Value>()
        .await
        .map_err(|_| AppError::bad_json("invalid ck.peer.invites.command.submit request body"))?;
    super::events::peer::validate_peer_request(state, req, Some(&body))?;
    validate_content_digest(req, &body)?;

    let delivery: InviteDeliveryRequest =
        serde_json::from_value(body.clone()).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "invalid ck.peer.invites.command.submit shape: {error}"
            ))
        })?;
    delivery.validate_minimal().map_err(|error| {
        super::events::peer::schema_violation(format!("invalid invite delivery request: {error}"))
    })?;

    let destination_service_did = required_header(req, HEADER_DESTINATION_SERVICE_DID)?;
    if destination_service_did != delivery.invite_address.recipient_service_did.as_str() {
        return Err(super::events::peer::cross_domain_replay(
            "Destination-Service-DID must equal invite_address.recipient_service_did",
        ));
    }

    validate_invite_delivery_consistency(&body, &delivery, state)?;

    // The inviter is the actor that signed the durable `ck.invite.create`
    // event; it is the `peer` we test `blocked_subjects` and the
    // `consent_grant` evidence against (spec invite-addressing.md §2 / §5).
    let actor = body
        .pointer("/invite_event/actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.actor_id is required"))?
        .to_owned();
    let inviter = actor.clone();
    let subject = delivery.invite_address.subject_id.as_str().to_owned();

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
    );

    if decision.action != InviteReceiveAction::Notify {
        super::append_audit_log(
            state,
            None,
            "peer.invites.submit",
            json!({
                "idempotency_key": delivery.idempotency_key,
                "invitee": delivery.invite_address.subject_id,
                "recipient_service_did": delivery.invite_address.recipient_service_did,
                "introduction_kind": delivery.introduction_evidence.kind(),
                "effective_kind": decision.effective_kind,
                "trust_tier": decision.trust_tier.as_str(),
                "receive_action": receive_action_str(&decision.action),
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
        return json_ok(serde_json::to_value(outcome).map_err(|error| {
            AppError::internal(format!("invite delivery outcome serialize: {error}"))
        })?);
    }

    let source_service_did = required_header(req, HEADER_SOURCE_SERVICE_DID)?;
    let trust_headers =
        crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
            .map_err(|violation| {
                super::events::peer::schema_violation(violation.message())
                    .with_wire_code(violation.error_code())
            })?;
    let request_hash = canonical::canonical_sha256(&body).map_err(|error| {
        super::events::peer::schema_violation(format!(
            "ck.peer.invites.command.submit body is not canonical-hashable: {error}"
        ))
    })?;
    let session = SessionRecord {
        token_hash: format!(
            "peer-invite:{}:{request_hash}",
            trust_headers.source_trust_domain
        ),
        actor,
        device_id: format!("peer-invite:{source_service_did}"),
        audience: state.config.service_did.clone(),
        expires_at: now() + Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    };

    let response =
        super::events::event_log::submit_event_value(state, &session, body["invite_event"].clone())
            .await
            .map_err(|error| {
                AppError::new(ErrorCode::SchemaViolation, error.message)
                    .with_status(error.status)
                    .with_wire_code(error.code)
            })?;

    let status = if response.duplicate {
        "duplicate"
    } else {
        "accepted"
    };
    super::append_audit_log(
        state,
        None,
        "peer.invites.submit",
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": response.event_id,
            "invitee": delivery.invite_address.subject_id,
            "recipient_service_did": delivery.invite_address.recipient_service_did,
            "introduction_kind": delivery.introduction_evidence.kind(),
            "effective_kind": decision.effective_kind,
            "trust_tier": decision.trust_tier.as_str(),
            "request_canonical_digest": request_hash,
        }),
        status,
    )
    .await;
    let outcome = InviteDeliveryOutcome {
        status: if response.duplicate {
            InviteDeliveryOutcomeStatus::Duplicate
        } else {
            InviteDeliveryOutcomeStatus::Accepted
        },
        disclosed_outcome: decision.disclosed_outcome,
        received_at: Some(now()),
        retry_after_ms: None,
    };
    json_ok(serde_json::to_value(outcome).map_err(|error| {
        AppError::internal(format!("invite delivery outcome serialize: {error}"))
    })?)
}

#[endpoint(
    operation_id = "ck.open.invite_locator.query.resolve",
    tags("open"),
    summary = "Resolve an online invite locator token"
)]
#[tracing::instrument(skip_all, fields(op = "ck.open.invite_locator.query.resolve"))]
async fn resolve_invite_locator(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    if locator_token_appears_in_url(req) {
        return Err(AppError::invalid_param(
            "locator_token must be sent in the JSON body, never in URL path or query",
        )
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation"));
    }
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<InviteLocatorResolveRequestBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid invite locator resolve request body"))?;
    body.validate_minimal()
        .map_err(|_| invite_locator_not_found())?;
    let locator_token = body.locator_token.trim();
    let locator_ref = decode_locator_token(locator_token).ok_or_else(invite_locator_not_found)?;
    let subject_id = locator_ref
        .get("subject_id")
        .and_then(Value::as_str)
        .filter(|value| Did::new((*value).to_owned()).is_ok())
        .ok_or_else(invite_locator_not_found)?;
    let subject_id = Did::new(subject_id.to_owned()).map_err(|_| invite_locator_not_found())?;
    if locator_ref
        .get("nonce")
        .and_then(Value::as_str)
        .filter(|value| is_locator_token_shape(value))
        .is_none()
    {
        return Err(invite_locator_not_found());
    }
    if let Some(expires_at) = locator_ref
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        && expires_at <= now()
    {
        return Err(invite_locator_not_found());
    }

    let issued_at = now();
    let expires_at = locator_ref
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| issued_at + Duration::minutes(DEFAULT_LOCATOR_TTL_MINUTES));
    let locator_ref_digest = Hash::new(canonical::sha256_digest(locator_token.as_bytes()))
        .map_err(|error| AppError::internal(format!("locator_ref_digest invalid: {error}")))?;
    let display_hint = locator_ref
        .get("display_hint")
        .cloned()
        .map(serde_json::from_value::<PrincipalLocatorDisplayHint>)
        .transpose()
        .map_err(|_| invite_locator_not_found())?;
    let recipient_service_did = Did::new(state.config.service_did.clone()).map_err(|error| {
        AppError::internal(format!(
            "configured service DID invalid for principal locator: {error}"
        ))
    })?;
    let mut locator = PrincipalLocator {
        schema: cokret_sdk::PRINCIPAL_LOCATOR_SCHEMA.to_owned(),
        subject_id,
        recipient_service_did,
        recipient_service_type: None,
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
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&canonical_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| AppError::internal(format!("principal locator sign: {error}")))?;
    locator.proofs = vec![PrincipalLocatorProof {
        proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
        proof: DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: format!("{}#server-key-1", state.config.service_did),
            alg: "EdDSA".to_owned(),
            payload_digest,
            created_at: issued_at,
            domain: None,
            audience: None,
            jws,
        },
    }];
    locator.validate_minimal().map_err(|error| {
        AppError::internal(format!("principal locator validation failed: {error}"))
    })?;
    json_ok(
        serde_json::to_value(locator)
            .map_err(|error| AppError::internal(format!("principal locator serialize: {error}")))?,
    )
}

/// Spec invite-addressing.md §2 — introduction-evidence trust tiers.
/// High = `{locator_ref, consent_grant, shared_realm}`; Low =
/// `{same_principal_server, explicit_address, missing/invalid evidence}`. The tier
/// drives both the receive action and the §5.1 graded disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrustTier {
    High,
    Low,
}

impl TrustTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
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

/// Effective trust tier of an introduction evidence kind, *after* any
/// `consent_grant` verification downgrade has been resolved by the caller.
fn trust_tier_for_kind(kind: &str) -> TrustTier {
    match kind {
        "locator_ref" | "consent_grant" | "shared_realm" => TrustTier::High,
        // same_principal_server / explicit_address / unknown → low
        _ => TrustTier::Low,
    }
}

/// Outcome of applying the subject's `invite_receive_policy` to one
/// delivery: the receive action, the effective (post-downgrade) evidence
/// kind, its trust tier, and the graded-disclosure value to echo back.
struct ReceiveDecision {
    action: InviteReceiveAction,
    effective_kind: &'static str,
    trust_tier: TrustTier,
    disclosed_outcome: Option<DisclosedOutcome>,
}

/// Spec invite-addressing.md §5 — the recommended default
/// `invite_receive_policy` applied to subjects without an explicit
/// override: `consent_grant` is allowlisted (so already-consented
/// contacts can invite without a locator URL), explicit addresses are
/// quarantined, unknown invites dropped, and disclosure is
/// `high_trust=outcome / low_trust=opaque`.
pub(crate) fn default_invite_receive_policy(subject: &str) -> InviteReceivePolicy {
    InviteReceivePolicy {
        schema: cokret_sdk::INVITE_RECEIVE_POLICY_SCHEMA.to_owned(),
        subject_id: Did::new(subject.to_owned()).unwrap_or_else(|_| {
            Did::new("did:web:invalid.invalid".to_owned()).expect("placeholder did")
        }),
        allowed_introduction_kinds: vec![
            "locator_ref".to_owned(),
            "consent_grant".to_owned(),
            "shared_realm".to_owned(),
            "same_principal_server".to_owned(),
        ],
        explicit_address_behavior: InviteReceiveAction::Quarantine,
        unknown_invites: UnknownInviteAction::Drop,
        trusted_realm_ids: Vec::new(),
        trusted_principal_services: Vec::new(),
        blocked_principal_services: Vec::new(),
        blocked_subjects: Vec::new(),
        disclosure: Some(DisclosurePolicy {
            high_trust: Some(DisclosureLevel::Outcome),
            low_trust: Some(DisclosureLevel::Opaque),
        }),
    }
}

/// Read the subject's private `invite_receive_policy`, falling back to the
/// recommended default. `blocked_subjects` written by
/// `ck.self.contact.command.tombstone(block_peer)` are merged from the in-memory
/// override store.
fn resolve_invite_receive_policy(state: &AppState, subject: &str) -> InviteReceivePolicy {
    state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock")
        .get(subject)
        .cloned()
        .unwrap_or_else(|| default_invite_receive_policy(subject))
}

/// Spec invite-addressing.md §2/§5/§5.1/§7-8 — the full receive decision.
fn evaluate_invite_receive(
    state: &AppState,
    policy: &InviteReceivePolicy,
    evidence: &IntroductionEvidence,
    inviter: &str,
    subject: &str,
) -> ReceiveDecision {
    let now = now();

    // §5 — `blocked_subjects` hit: MUST drop and force opaque disclosure so
    // the blocklist cannot leak through the response side channel.
    if policy
        .blocked_subjects
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
    let effective_kind: &'static str = match evidence {
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
        other => other.kind(),
    };

    let trust_tier = trust_tier_for_kind(effective_kind);

    // §5 — allowlist gate. Evidence kinds not in `allowed_introduction_kinds`
    // MUST NOT notify; they fall through to the explicit/unknown behavior.
    let allowlisted = policy
        .allowed_introduction_kinds
        .iter()
        .any(|kind| kind == effective_kind);

    let action = if allowlisted {
        InviteReceiveAction::Notify
    } else if effective_kind == "explicit_address" {
        policy.explicit_address_behavior.clone()
    } else {
        match policy.unknown_invites {
            UnknownInviteAction::Drop => InviteReceiveAction::Drop,
            UnknownInviteAction::Quarantine => InviteReceiveAction::Quarantine,
        }
    };

    // §5.1 — graded disclosure. High-trust + `outcome` echoes the real
    // result; everything else stays opaque (`disclosed_outcome = None`).
    let disclosure_level = match trust_tier {
        TrustTier::High => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.high_trust.clone())
            .unwrap_or(DisclosureLevel::Outcome),
        TrustTier::Low => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.low_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
    };
    let disclosed_outcome = match disclosure_level {
        DisclosureLevel::Outcome => Some(match &action {
            InviteReceiveAction::Notify => DisclosedOutcome::Delivered,
            InviteReceiveAction::Quarantine => DisclosedOutcome::Quarantined,
            InviteReceiveAction::Drop => DisclosedOutcome::Blocked,
        }),
        DisclosureLevel::Opaque => None,
    };

    ReceiveDecision {
        action,
        effective_kind,
        trust_tier,
        disclosed_outcome,
    }
}

fn validate_invite_delivery_consistency(
    body: &Value,
    delivery: &InviteDeliveryRequest,
    state: &AppState,
) -> Result<(), AppError> {
    if delivery.invite_address.recipient_service_did.as_str() != state.config.service_did {
        return Err(super::events::peer::cross_domain_replay(
            "invite_address.recipient_service_did does not match this service",
        ));
    }
    if body.pointer("/invite_event/kind").and_then(Value::as_str)
        != Some(crate::kinds::CK_INVITE_CREATE)
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.kind must be ck.invite.create",
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
        .and_then(|target| target.get("recipient_service_did"))
        .and_then(Value::as_str)
        != Some(delivery.invite_address.recipient_service_did.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invite_delivery_target.recipient_service_did must equal invite_address.recipient_service_did",
        ));
    }
    if let Some(service_type) = payload
        .get("invite_delivery_target")
        .and_then(|target| target.get("recipient_service_type"))
        .and_then(Value::as_str)
        && service_type != "principal_server"
    {
        return Err(super::events::peer::schema_violation(
            "invite_delivery_target.recipient_service_type must be principal_server",
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

fn validate_content_digest(req: &Request, body: &Value) -> Result<(), AppError> {
    let header = required_header(req, HEADER_CONTENT_DIGEST)?;
    let canonical_bytes = canonical::canonical_json_bytes(body).map_err(|error| {
        super::events::peer::schema_violation(format!(
            "request body is not canonical-hashable: {error}"
        ))
    })?;
    // RFC 9530 Content-Digest is the base64 of the SHA-256 *digest* of the
    // canonical body bytes, matching the `peer/events` federation surface
    // (`federation::content_digest_header`) and the signing base every peer
    // builds. Earlier this hashed nothing and base64'd the raw canonical
    // bytes, so well-formed `peer/invites` deliveries were rejected.
    let expected = format!(
        "sha-256=:{}:",
        STANDARD.encode(Sha256::digest(&canonical_bytes))
    );
    if header != expected {
        crate::metrics::record_digest_mismatch("peer_invites_content_digest");
        return Err(super::events::peer::cross_domain_replay(
            "Content-Digest does not match the canonical request body",
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
    req.uri()
        .query()
        .is_some_and(|query| query.contains("locator_token=") || query.contains("token="))
}

fn is_locator_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_locator_token(locator_token: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(locator_token.as_bytes()).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

fn invite_locator_not_found() -> AppError {
    AppError::not_found("invite locator not found")
}
