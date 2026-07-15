//! Cross-Principal-Server contact fact delivery (spec
//! `contact-and-direct-conversation.md` §2 / §4.1).
//!
//! Contact facts (`ak.contact.requested` / `accepted` / `rejected` /
//! `tombstoned`) are principal-scoped and cross-Realm. When the issuer and the
//! target holder live on different Principal Servers, the issuer-side server
//! federates the signed fact to the target holder's server via
//! `ak.peer.contacts.command.submit` (`POST /_arkret/peer/contacts`); the recipient
//! projects the original signed envelope into the target holder's contact
//! projection without re-signing it.
//!
//! Surfaces:
//! - sender: [`federate_contact_fact`] — enqueue a durable outbound delivery when the addressed
//!   holder is hosted on a configured federation peer.
//! - receiver: [`peer_contacts_submit`] — accept a delivered fact and project it into the local
//!   target holder's contact projection.

use arkret_sdk::{
    ContactIntroductionEvidence, Did, DisclosedOutcome, Event, EventId, Hash, Hlc,
    InviteReceiveAction, PeerContactAddress, PeerContactDeliveryRequest, PeerContactFactKind,
    Proof, RealmId, canonical, proof_kind,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::SecondsFormat;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::consent::{
    auto_revoke_requester_side_contact_consent, consent_cell_snapshot,
    has_active_consent_for_scope, normalize_scope, persist_consent_cell,
    project_contact_managed_consent_ref,
};
use super::now;
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, ContactRecord, ProjectionEventRecord};

const HEADER_CONTENT_DIGEST: &str = "content-digest";
const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const CONTACT_MESSAGE_STUB: &str = "[message withheld until contact is accepted]";

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("contacts").post(peer_contacts_submit))
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct PeerContactDeliveryOutcome {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosed_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    received_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

/// Issuer-side: federate a signed contact fact to `subject_id`'s home
/// Principal Server (`recipient_service_id`). Returns `Ok(false)` (no-op)
/// when `recipient_service_id` is this service (same-server request handled
/// locally) or when the deployment does not list the peer; `Ok(true)` when a
/// durable outbound delivery was enqueued.
///
/// `fact_kind` is one of the `ak.contact.*` kinds. `fact_payload` carries the
/// projection fields the recipient needs (requester/target/scope/message/
/// granted_scopes/consent grant refs). The fact is wrapped in a dev-proof
/// EventEnvelope scoped to the issuer's Principal Control Realm so it is a
/// real signed contact fact the recipient can project as the original
/// envelope (spec §2).
pub(crate) async fn federate_contact_fact(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    recipient_service_id: &str,
    introduction_evidence: Option<ContactIntroductionEvidence>,
    fact_payload: Value,
    contact_event_id: &str,
) -> Result<bool, AppError> {
    let recipient_service_id = recipient_service_id.trim();
    if recipient_service_id.is_empty() || recipient_service_id == state.config.service_id {
        // Same Principal Server: nothing to federate, the local operation
        // already projected the fact for both holders.
        return Ok(false);
    }
    let Some(peer_url) = crate::routing::federation::federation::peer_url_for_service_id(
        state,
        recipient_service_id,
    ) else {
        tracing::warn!(
            recipient_service_id,
            issuer,
            fact_kind,
            "contact fact federation: recipient service DID is not a configured federation peer; \
             fact stays local"
        );
        return Ok(false);
    };

    let fact_kind = PeerContactFactKind::from_wire(fact_kind)
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let issuer_pcr = super::recovery::principal_control_realm_for_did(issuer);
    let contact_event = build_contact_envelope(
        state,
        fact_kind,
        issuer,
        &issuer_pcr,
        fact_payload,
        contact_event_id,
    )?;
    let idempotency_key = contact_delivery_idempotency_key(
        &state.config.service_id,
        recipient_service_id,
        fact_kind.as_str(),
        issuer,
        subject_id,
        &contact_event,
    );
    let delivery = PeerContactDeliveryRequest::new(
        contact_event,
        PeerContactAddress {
            subject_id: Did::new(subject_id.to_owned())
                .map_err(|error| AppError::invalid_param(format!("invalid subject_id: {error}")))?,
            recipient_service_id: Did::new(recipient_service_id.to_owned()).map_err(|error| {
                AppError::invalid_param(format!("invalid recipient_service_id: {error}"))
            })?,
            recipient_service_type: Some("principal_server".to_owned()),
        },
        fact_kind,
        introduction_evidence,
        idempotency_key,
    );
    let payload_bytes = canonical::canonical_json_bytes(&delivery)
        .map_err(|error| AppError::internal(format!("contact delivery canonicalize: {error}")))?;
    let payload_json = String::from_utf8(payload_bytes)
        .map_err(|error| AppError::internal(format!("contact delivery utf8: {error}")))?;
    let idempotency_key = delivery.idempotency_key.clone();

    crate::routing::federation::outbox::enqueue_outbound(
        state,
        &peer_url,
        recipient_service_id,
        "/_arkret/peer/contacts",
        &idempotency_key,
        &payload_json,
    )
    .await
    .map_err(|error| AppError::internal(format!("contact delivery enqueue: {error}")))?;
    tracing::info!(
        fact_kind = fact_kind.as_str(),
        issuer,
        subject_id,
        recipient_service_id,
        "enqueued cross-PS contact fact delivery"
    );
    Ok(true)
}

/// Build a dev-proof contact-fact EventEnvelope scoped to the issuer's
/// Principal Control Realm. The recipient validates + projects this as the
/// original signed envelope; it never re-signs it as a local fact (spec §2).
fn build_contact_envelope(
    state: &AppState,
    fact_kind: PeerContactFactKind,
    issuer: &str,
    issuer_pcr: &str,
    fact_payload: Value,
    contact_event_id: &str,
) -> Result<Event, AppError> {
    let realm_id = RealmId::new(issuer_pcr.to_owned())
        .map_err(|error| AppError::internal(format!("issuer PCR realm_id invalid: {error}")))?;
    let actor_id = Did::new(issuer.to_owned())
        .map_err(|error| AppError::invalid_param(format!("invalid contact issuer DID: {error}")))?;
    let hlc = Hlc::new(state.hlc.now())
        .map_err(|error| AppError::internal(format!("contact event HLC invalid: {error}")))?;
    let mut event = Event::new(fact_kind.as_str(), realm_id, actor_id, 0, hlc, fact_payload)
        .map_err(|error| AppError::internal(format!("contact event build failed: {error}")))?;
    event.event_id = EventId::new(contact_event_id.to_owned())
        .map_err(|error| AppError::internal(format!("contact event_id invalid: {error}")))?;
    let event_digest = event
        .event_digest()
        .map_err(|error| AppError::internal(format!("contact event digest failed: {error}")))?;
    let event_digest = Hash::new(event_digest)
        .map_err(|error| AppError::internal(format!("contact event digest invalid: {error}")))?;
    event.proofs.push(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{issuer}#device"),
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        jws: "dev-contact-fact".to_owned(),
    });
    Ok(event)
}

fn contact_delivery_idempotency_key(
    origin_service_id: &str,
    recipient_service_id: &str,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    contact_event: &Event,
) -> String {
    let event_id = contact_event.event_id.as_str();
    let mut hasher = Sha256::new();
    for part in [
        origin_service_id,
        recipient_service_id,
        fact_kind,
        issuer,
        subject_id,
        event_id,
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"|");
    }
    format!("ak:contact-outbox:{}", hex::encode(hasher.finalize()))
}

#[endpoint(
    operation_id = "ak.peer.contacts.command.submit",
    tags("peer"),
    summary = "Private Principal Server contact fact delivery"
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.contacts.command.submit"))]
async fn peer_contacts_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerContactDeliveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let delivery = req
        .parse_json::<PeerContactDeliveryRequest>()
        .await
        .map_err(|_| AppError::bad_json("invalid ak.peer.contacts.command.submit request body"))?;
    let body = serde_json::to_value(&delivery).map_err(|error| {
        AppError::internal(format!("contact delivery request serialize: {error}"))
    })?;
    super::super::events::peer::validate_peer_request(state, req, Some(&body)).await?;
    validate_content_digest(req, &body)?;

    delivery.validate_minimal().map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "invalid contact delivery request: {error}"
        ))
    })?;
    let fact_kind = delivery.fact_kind.as_str();
    let issuer = delivery.contact_event.actor_id.as_str().to_owned();
    let subject_id = delivery.contact_address.subject_id.as_str().to_owned();
    let recipient_service_id = delivery.contact_address.recipient_service_id.as_str();
    if recipient_service_id != state.config.service_id {
        return Err(super::super::events::peer::cross_domain_replay(
            "contact_address.recipient_service_id does not match this service",
        ));
    }
    let payload = delivery.contact_event.payload.clone();

    // Originating Principal Server of this delivery: the peer end of the
    // projected contact row (the issuer) is hosted there. `validate_peer_request`
    // above already verified this header is a present, well-formed DID, so we
    // record it on the projection as the contact's `peer_service_id` — that is
    // the requester's/accepter's home server, NOT this service. inkson reads it
    // off a pending_incoming row as the `requester_service_id` to address the
    // reverse `respond` delivery back to the originator.
    let source_service_id = req
        .headers()
        .get(HEADER_SOURCE_SERVICE_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    // §2 hard boundary: project the issuer's original signed envelope into the
    // local target holder's contact projection. We do NOT re-sign it as a
    // local fact. soland's contact projection is the ContactRecord store +
    // contact-managed consent cells, so projection means upserting the
    // holder-scoped row (and, for accept, the target-controlled consent grant
    // refs the original issuer already wrote on its own PCR).
    if delivery.fact_kind == PeerContactFactKind::Requested {
        let Some(evidence) = delivery.introduction_evidence.as_ref() else {
            return Err(super::super::events::peer::schema_violation(
                "introduction_evidence is required for ak.contact.requested",
            ));
        };
        let payload_value = serde_json::to_value(&payload).map_err(|error| {
            AppError::internal(format!("contact payload encode failed: {error}"))
        })?;
        validate_contact_introduction_evidence_digest(&payload_value, evidence)?;
        let policy = crate::routing::invites::resolve_invite_receive_policy(state, &subject_id);
        let decision = crate::routing::invites::evaluate_contact_receive(
            state,
            &policy,
            evidence,
            &issuer,
            &subject_id,
            recipient_service_id,
            source_service_id.as_deref().unwrap_or_default(),
        );
        if decision.action != InviteReceiveAction::Notify {
            super::append_audit_log(
                state,
                Some(&subject_id),
                "peer.contacts.submit",
                json!({
                    "fact_kind": fact_kind,
                    "issuer": issuer,
                    "subject_id": subject_id,
                    "introduction_kind": evidence.kind(),
                    "effective_kind": decision.effective_kind,
                    "trust_tier": decision.trust_tier.as_str(),
                    "receive_action": receive_action_str(&decision.action),
                }),
                "deferred",
            )
            .await;
            return json_ok(PeerContactDeliveryOutcome {
                status: "deferred".to_owned(),
                disclosed_outcome: decision.disclosed_outcome.map(disclosed_outcome_str),
                received_at: Some(now().to_rfc3339_opts(SecondsFormat::Secs, true)),
                retry_after_ms: None,
            });
        }
    }

    let outcome = project_delivered_contact_fact(
        state,
        fact_kind,
        &issuer,
        &subject_id,
        &serde_json::to_value(&payload).map_err(|error| {
            AppError::internal(format!("contact payload encode failed: {error}"))
        })?,
        delivery.contact_event.event_id.as_str(),
        source_service_id.as_deref(),
    )
    .await?;

    super::append_audit_log(
        state,
        Some(&subject_id),
        "peer.contacts.submit",
        json!({
            "fact_kind": fact_kind,
            "issuer": issuer,
            "subject_id": subject_id,
            "status": outcome,
        }),
        outcome,
    )
    .await;
    json_ok(PeerContactDeliveryOutcome {
        status: outcome.to_owned(),
        disclosed_outcome: None,
        received_at: Some(now().to_rfc3339_opts(SecondsFormat::Secs, true)),
        retry_after_ms: None,
    })
}

fn validate_contact_introduction_evidence_digest(
    payload: &Value,
    evidence: &ContactIntroductionEvidence,
) -> Result<(), AppError> {
    let expected = payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "contact_requested_payload.introduction_evidence_digest is required",
            )
        })?;
    let evidence_value = serde_json::to_value(evidence).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "contact introduction_evidence is not serializable: {error}"
        ))
    })?;
    let actual = canonical::canonical_sha256(&evidence_value).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "contact introduction_evidence is not canonical-hashable: {error}"
        ))
    })?;
    if expected != actual {
        return Err(super::super::events::peer::schema_violation(
            "contact_requested_payload.introduction_evidence_digest mismatch",
        ));
    }
    Ok(())
}

fn receive_action_str(action: &InviteReceiveAction) -> &'static str {
    match action {
        InviteReceiveAction::Drop => "drop",
        InviteReceiveAction::Quarantine => "quarantine",
        InviteReceiveAction::Notify => "notify",
    }
}

fn disclosed_outcome_str(outcome: DisclosedOutcome) -> String {
    match outcome {
        DisclosedOutcome::Delivered => "delivered",
        DisclosedOutcome::Blocked => "blocked",
        DisclosedOutcome::Quarantined => "quarantined",
    }
    .to_owned()
}

async fn should_stub_incoming_contact_message(
    state: &AppState,
    requester: &str,
    target: &str,
    _scope: &str,
) -> Result<bool, AppError> {
    if target_has_active_consent_for_requester(state, target, requester) {
        return Ok(false);
    }
    let contacts = state
        .persistence
        .contacts()
        .list_for_actor(target)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let accepted_contact = contacts.iter().any(|record| {
        record.status == "accepted"
            && ((record.requester == requester && record.target == target)
                || (record.requester == target && record.target == requester))
    });
    Ok(!accepted_contact)
}

fn target_has_active_consent_for_requester(
    state: &AppState,
    target: &str,
    requester: &str,
) -> bool {
    [
        "invite",
        "direct_message",
        "voice_call",
        "video_call",
        "presence",
    ]
    .into_iter()
    .any(|scope| has_active_consent_for_scope(state, target, requester, scope, now()))
}

async fn append_stubbed_contact_message_audit(
    state: &AppState,
    target: &str,
    requester: &str,
    scope: &str,
    message: &str,
    contact_event_id: &str,
) {
    super::append_audit_log(
        state,
        Some(target),
        "peer.contacts.message_stubbed",
        json!({
            "requester": requester,
            "target": target,
            "scope": scope,
            "contact_event_id": contact_event_id,
            "message_chars": message.chars().count(),
            "message_digest": canonical::sha256_digest(message.as_bytes()),
        }),
        "accepted",
    )
    .await;
}

async fn append_delivered_contact_fact_projection_event(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    payload: &Value,
    contact_event_id: &str,
) {
    let mut payload = payload.clone();
    if let Value::Object(object) = &mut payload {
        object
            .entry("event_id".to_owned())
            .or_insert_with(|| Value::String(contact_event_id.to_owned()));
        object.insert(
            "original_issuer".to_owned(),
            Value::String(issuer.to_owned()),
        );
    }
    let _ = crate::routing::events::projection::append_projection_event(
        state,
        ProjectionEventRecord {
            event_id: contact_event_id.to_owned(),
            realm_id: super::recovery::principal_control_realm_for_did(issuer),
            event_kind: fact_kind.to_owned(),
            operation_type: "delivered_contact_fact".to_owned(),
            operation_id: None,
            sender: Some(issuer.to_owned()),
            payload,
            created_at: now(),
            received_at: now(),
        },
    )
    .await;
}

/// Project a delivered contact fact into the local `subject_id`'s contact
/// projection. Returns the receive status (`accepted` / `duplicate`).
async fn project_delivered_contact_fact(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    payload: &Value,
    contact_event_id: &str,
    source_service_id: Option<&str>,
) -> Result<&'static str, AppError> {
    let scope = normalize_scope(
        payload
            .get("requested_scopes")
            .and_then(Value::as_array)
            .and_then(|scopes| scopes.first())
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .get("granted_scopes")
                    .and_then(Value::as_array)
                    .and_then(|scopes| scopes.first())
                    .and_then(Value::as_str)
            })
            .or_else(|| payload.get("scope").and_then(Value::as_str)),
    )?;
    let store = state.persistence.contacts();
    match fact_kind {
        "ak.contact.requested" => {
            // requester = issuer, target = subject_id (this holder). Form a
            // pending_incoming row on the target side.
            let raw_message = payload
                .get("message")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let stub_message = raw_message.is_some()
                && should_stub_incoming_contact_message(state, issuer, subject_id, &scope).await?;
            let message = if stub_message {
                Some(CONTACT_MESSAGE_STUB.to_owned())
            } else {
                raw_message.clone()
            };
            if let Some(existing) = store
                .get_scoped(issuer, subject_id, &scope)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                && existing.status == "pending"
            {
                return Ok("duplicate");
            }
            let contact = ContactRecord {
                requester: issuer.to_owned(),
                target: subject_id.to_owned(),
                scope: scope.clone(),
                status: "pending".to_owned(),
                request_event_ref: Some(contact_event_id.to_owned()),
                response_event_ref: None,
                tombstone_event_ref: None,
                message,
                // Peer end of this pending_incoming row is the remote requester
                // (`issuer`), hosted on the delivering source server. The local
                // holder later uses this as the reverse-delivery target when it
                // responds (inkson's `requester_service_id`).
                peer_service_id: source_service_id.map(ToOwned::to_owned),
                created_at: now(),
                updated_at: now(),
            };
            store
                .put(&contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if stub_message {
                append_stubbed_contact_message_audit(
                    state,
                    subject_id,
                    issuer,
                    &scope,
                    raw_message.as_deref().unwrap_or_default(),
                    contact_event_id,
                )
                .await;
            }
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        "ak.contact.accepted" => {
            // Travelling back to the original requester (subject_id). The
            // target (issuer) accepted: flip the requester-side row to accepted
            // and project the issuer -> requester consent grants by their
            // original event refs, so the requester's row surfaces
            // invite_consent_grant_ref / bidirectional scopes without
            // re-minting target-controlled grant facts locally.
            let Some(mut contact) = store
                .get_scoped(subject_id, issuer, &scope)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted references no local pending request",
                ));
            };
            if contact.status == "accepted" {
                return Ok("duplicate");
            }
            if contact.status != "pending" || contact.request_event_ref.is_none() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted references a non-pending or unverifiable request",
                ));
            }
            if payload.get("request_id").and_then(Value::as_str)
                != contact.request_event_ref.as_deref()
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted request_id does not match the pending request",
                ));
            }
            let granted_scopes = granted_scopes(payload);
            let consent_grant_refs = event_ref_strings(payload, "consent_grant_refs");
            if !granted_scopes.is_empty() && consent_grant_refs.len() < granted_scopes.len() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted requires one consent_grant_ref per granted scope",
                ));
            }
            for (granted, grant_ref) in granted_scopes.iter().zip(consent_grant_refs.iter()) {
                let previous = consent_cell_snapshot(state, issuer, subject_id, granted);
                let grant_cell = project_contact_managed_consent_ref(
                    state,
                    issuer,
                    subject_id,
                    granted,
                    grant_ref,
                    now(),
                )?;
                persist_consent_cell(state, &grant_cell, previous).await?;
            }
            contact.status = "accepted".to_owned();
            contact.response_event_ref = Some(contact_event_id.to_owned());
            contact.updated_at = now();
            // Peer end is the remote accepter (`issuer`), hosted on the
            // delivering source server. Record/backfill it so the requester's
            // row can address future invites/responses to the peer's home PS.
            if let Some(source) = source_service_id {
                contact.peer_service_id = Some(source.to_owned());
            }
            store
                .put(&contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        "ak.contact.rejected" => {
            let Some(mut contact) = store
                .get_scoped(subject_id, issuer, &scope)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected references no local pending request",
                ));
            };
            if contact.status == "rejected" {
                auto_revoke_requester_side_contact_consent(
                    state,
                    subject_id,
                    issuer,
                    std::slice::from_ref(&scope),
                    now(),
                    "contact_rejected",
                    Some(contact_event_id),
                )
                .await?;
                return Ok("duplicate");
            }
            if contact.status != "pending" || contact.request_event_ref.is_none() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected references a non-pending or unverifiable request",
                ));
            }
            if payload.get("request_id").and_then(Value::as_str)
                != contact.request_event_ref.as_deref()
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected request_id does not match the pending request",
                ));
            }
            contact.status = "rejected".to_owned();
            contact.response_event_ref = Some(contact_event_id.to_owned());
            contact.updated_at = now();
            store
                .put(&contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            auto_revoke_requester_side_contact_consent(
                state,
                subject_id,
                issuer,
                std::slice::from_ref(&scope),
                now(),
                "contact_rejected",
                Some(contact_event_id),
            )
            .await?;
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        "ak.contact.tombstoned" => {
            // Downgrade every local row this holder shares with the issuer.
            let rows = store
                .list_for_actor(subject_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let mut requester_side_revoke_scopes = Vec::new();
            for mut row in rows {
                let touches_issuer = (row.requester == subject_id && row.target == issuer)
                    || (row.requester == issuer && row.target == subject_id);
                if touches_issuer
                    && row.requester == subject_id
                    && row.target == issuer
                    && !requester_side_revoke_scopes.contains(&row.scope)
                {
                    requester_side_revoke_scopes.push(row.scope.clone());
                }
                if !touches_issuer || row.status == "tombstoned" {
                    continue;
                }
                row.status = "tombstoned".to_owned();
                row.tombstone_event_ref = Some(contact_event_id.to_owned());
                row.updated_at = now();
                store
                    .put(&row)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
            }
            for scope in requester_side_revoke_scopes {
                auto_revoke_requester_side_contact_consent(
                    state,
                    subject_id,
                    issuer,
                    &[scope],
                    now(),
                    "contact_tombstoned",
                    Some(contact_event_id),
                )
                .await?;
            }
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        other => Err(super::super::events::peer::schema_violation(format!(
            "unsupported contact fact_kind {other}"
        ))),
    }
}

fn granted_scopes(payload: &Value) -> Vec<String> {
    payload
        .get("granted_scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|scope| normalize_scope(Some(scope)).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn event_ref_strings(payload: &Value, field: &str) -> Vec<String> {
    payload
        .get(field)
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(|value| {
                    value
                        .as_str()
                        .filter(|event_ref| EventId::new((*event_ref).to_owned()).is_ok())
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// RFC 9530 `Content-Digest` check, matching `peer/invites` (the federation
/// outbox dispatcher emits `sha-256=:<base64(sha256(canonical_body))>:`).
fn validate_content_digest(req: &Request, body: &Value) -> Result<(), AppError> {
    let header = req
        .headers()
        .get(HEADER_CONTENT_DIGEST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation("required header content-digest missing")
        })?;
    let canonical_bytes = arkret_sdk::canonical::canonical_json_bytes(body).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "request body is not canonical-hashable: {error}"
        ))
    })?;
    let expected = format!(
        "sha-256=:{}:",
        STANDARD.encode(Sha256::digest(&canonical_bytes))
    );
    if header != expected {
        crate::metrics::record_digest_mismatch("peer_contacts_content_digest");
        return Err(super::super::events::peer::cross_domain_replay(
            "Content-Digest does not match the canonical request body",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use soland_data::Db;

    use super::*;
    use crate::config::{
        AppConfig, IceServersConfig, LiveKitConfig, LogFormat, ObjectStorageConfig,
    };

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            service_id: "did:web:recipient.local".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            seal_compaction_min_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            trust_domain: "ak:trust_domain:recipient.local".to_owned(),
            ..AppConfig::test_default()
        }
    }

    /// Cross-PS `ak.contact.requested` delivery: the projected pending_incoming
    /// row on the recipient (target holder) MUST record the *originating*
    /// requester's home Principal Server as `peer_service_id` — the
    /// `source-service-id` of the delivery, NOT the recipient's own service
    /// DID. This is exactly the address inkson reads back as
    /// `requester_service_id` to federate the reverse `respond` delivery.
    #[tokio::test]
    async fn delivered_request_records_originating_peer_service_id() {
        let state = AppState::new(test_config(), Db { pool: None });
        let requester = "did:web:remote-alice.example"; // issuer, on source PS
        let target = "did:web:local-bob.example"; // subject_id, this holder
        let source_service_id = "did:web:remote.local"; // requester's home PS

        let payload = json!({
            "requested_scopes": ["message"],
            "message": "hi from across the federation",
        });

        let outcome = project_delivered_contact_fact(
            &state,
            "ak.contact.requested",
            requester,
            target,
            &payload,
            "ak:event:0196419b-0000-7000-8000-000000000001",
            Some(source_service_id),
        )
        .await
        .expect("delivered request projects");
        assert_eq!(outcome, "accepted");

        let record = state
            .persistence
            .contacts()
            .get_scoped(requester, target, "direct_message")
            .await
            .expect("contact store lookup")
            .expect("pending_incoming row was projected");

        assert_eq!(
            record.peer_service_id.as_deref(),
            Some(source_service_id),
            "peer_service_id must be the originating requester's PS, not the recipient's own \
             service_id ({})",
            state.config.service_id,
        );
        assert_eq!(
            record.request_event_ref.as_deref(),
            Some("ak:event:0196419b-0000-7000-8000-000000000001"),
        );
        assert_ne!(
            record.peer_service_id.as_deref(),
            Some(state.config.service_id.as_str()),
            "peer_service_id must not point at this recipient service",
        );
    }
}
