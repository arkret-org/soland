//! Ephemeral signal admission (`ck.self.ephemeral.command.send`): typing /
//! presence / read-receipt validation + persistence. Split out of `sync.rs`
//! (SOL-07-002) as a self-contained unit — no cross-module callers other than
//! the parent router, which references `ephemeral::submit_ephemeral`.

use cokret_sdk::EphemeralSubmitOutcome;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::Value;

use crate::routing::spaces::space::{
    PresenceVisibilityPolicy, presence_visibility_for_actor, realm_has_member,
    realm_history_visibility_for_id, typing_scope_allows_actor,
};
use crate::state::{AppState, EventNotification, PresenceRecord, SessionRecord, TypingRecord};

#[endpoint(
    operation_id = "ck.self.ephemeral.command.send",
    tags("sync"),
    summary = "Send a broadcast ephemeral signal"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.ephemeral.command.send"))]
pub(super) async fn submit_ephemeral(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<cokret_sdk::EphemeralEnvelope>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EphemeralSubmitOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let envelope = body.into_inner();

    validate_ephemeral_envelope(&envelope)?;

    let realm_id = envelope.realm_id.clone();
    let realm_id_str = realm_id.as_str();
    let actor_id = envelope.actor_id.to_string();
    if actor_id != session.actor {
        return Err(crate::error::AppError::capability_denied(
            "ephemeral actor_id must match the bearer session actor",
        ));
    }
    if !realm_has_member(state, realm_id_str, &session.actor).await {
        return Err(crate::error::AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let mut dispatched_to: Option<u64> = None;
    let should_wake_account_sync = match envelope.kind.as_str() {
        "ck.typing" => {
            persist_ephemeral_typing(state, &session.actor, realm_id_str, &envelope).await?;
            true
        }
        "ck.presence" => {
            persist_ephemeral_presence(state, &session, &envelope).await?;
            true
        }
        "ck.receipt.read" => {
            admit_ephemeral_read_receipt(state, &session, realm_id_str, &envelope).await?;
            false
        }
        "ck.realm_key.request" => {
            // realm-and-space.md history-sharing — a late-joining member device
            // asks a provider device to seal retained history keys. The request
            // is relayed to the provider's to-device queue (no realm broadcast),
            // so this does NOT wake account sync.
            crate::routing::events::realm_key_request::relay_ephemeral_realm_key_request(
                state,
                &session,
                realm_id_str,
                &envelope,
            )
            .await?;
            dispatched_to = Some(1);
            false
        }
        "ck.call.signal" => {
            // `service-http-binding.md` §162 — sending a `ck.call.signal`
            // envelope on `/_cokret/self/ephemeral` requires the realm-scoped
            // `ck.call.signal.send` capability (registered in
            // `capability-action-registry.json`). Realm membership stays a
            // precondition (checked above); signal-send authority is an
            // explicit capability so a member without it cannot relay call
            // signals. §162 defines no dedicated error code, so we surface the
            // generic `capability_denied` (403).
            if !crate::routing::interop::webrtc::actor_has_call_capability(
                state,
                realm_id_str,
                &session.actor,
                cokret_sdk::CAP_CALL_SIGNAL_SEND,
            )
            .await
            {
                return Err(crate::error::AppError::capability_denied(
                    "actor does not hold the ck.call.signal.send capability for this realm",
                ));
            }
            let payload = admit_ephemeral_call_signal(&envelope)?;
            let recipients =
                relay_ephemeral_call_signal(state, &session, realm_id_str, &payload, &envelope)
                    .await?;
            dispatched_to = Some(recipients);
            true
        }
        _ => {
            return Err(crate::error::AppError::invalid_param(
                "unsupported ephemeral kind",
            ));
        }
    };

    if should_wake_account_sync {
        let _ = state.event_broadcast.send(EventNotification::ephemeral(
            realm_id_str.to_owned(),
            envelope.kind.clone(),
        ));
    }

    crate::result::json_ok(EphemeralSubmitOutcome {
        accepted: true,
        kind: envelope.kind,
        realm_id,
        dispatched_to,
        server_received_at: Some(chrono::Utc::now()),
    })
}

/// `webrtc-signaling.md` §5 — persist the verbatim signed `ck.call.signal`
/// envelope into the realm-broadcast relay so subscribers in the Realm pick it
/// up off `ephemeral.call_signals` and verify the carried `proof`. The
/// envelope is stored unmodified (proof intact) and pruned at its TTL.
async fn relay_ephemeral_call_signal(
    state: &AppState,
    session: &crate::state::SessionRecord,
    realm_id: &str,
    payload: &cokret_sdk::CallSignalPayload,
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<u64, crate::error::AppError> {
    let envelope_value = serde_json::to_value(envelope).map_err(|error| {
        crate::error::AppError::invalid_param(format!(
            "ck.call.signal envelope is not serialisable: {error}"
        ))
    })?;
    let record = crate::state::CallSignalRelayRecord {
        realm_id: realm_id.to_owned(),
        sender_actor: session.actor.clone(),
        sender_device: session.device_id.clone(),
        call_id: payload.call_id.to_string(),
        expires_at: envelope.expires_at,
        envelope: envelope_value,
        // `append` assigns the monotonic per-Realm position.
        position: 0,
    };
    if let Err(error) = state.persistence.call_signal_relay().append(record).await {
        tracing::error!(%error, "failed to relay ephemeral ck.call.signal");
        return Err(crate::error::AppError::internal(
            "failed to relay ck.call.signal for realm broadcast",
        ));
    }
    // Broadcast breadth = Realm members other than the sender; the precise
    // per-device recipient set is resolved lazily on each subscribe.
    Ok(crate::routing::spaces::space::realm_member_count_excluding(
        state,
        realm_id,
        &session.actor,
    ))
}

fn validate_ephemeral_envelope(
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if !matches!(
        envelope.kind.as_str(),
        "ck.call.signal" | "ck.presence" | "ck.typing" | "ck.receipt.read" | "ck.realm_key.request"
    ) {
        return Err(crate::error::AppError::invalid_param(
            "unsupported ephemeral kind",
        ));
    }
    let window_ms = envelope
        .expires_at
        .signed_duration_since(envelope.sent_at)
        .num_milliseconds();
    if window_ms <= 0 || (window_ms as u64) > cokret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
    {
        return Err(crate::error::AppError::invalid_param(
            "ephemeral expires_at must be after sent_at and within the hard TTL ceiling",
        ));
    }
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(crate::error::AppError::invalid_param(
            "ephemeral signal is already expired",
        ));
    }
    // ephemeral-envelope.schema.json: every broadcast ephemeral kind MUST
    // carry `device_id` and a detached-JWS `proof` whose verification_method
    // is `{actor_id}#{device_id}` and whose event_digest covers the canonical
    // envelope bytes without `proof`. (`ck.realm_key.request` is a targeted
    // to-device relay, not one of the four broadcast kinds, and keeps its own
    // admission rules in realm_key_request.rs.)
    if matches!(
        envelope.kind.as_str(),
        "ck.call.signal" | "ck.presence" | "ck.typing" | "ck.receipt.read"
    ) {
        validate_ephemeral_broadcast_proof_shape(envelope)?;
    }
    Ok(())
}

async fn persist_ephemeral_typing(
    state: &AppState,
    actor: &str,
    realm_id: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    // ephemeral-envelope.schema.json ck.typing branch: `track_name` is optional
    // but const "discussion" in v1 (mirrors message.schema.json); when omitted
    // receivers resolve it to "discussion".
    if let Some(track_name) = envelope.payload.get("track_name") {
        if track_name.as_str() != Some("discussion") {
            return Err(crate::routing::events::peer::schema_violation(
                "ck.typing payload.track_name must be \"discussion\" in v1",
            ));
        }
    }
    let typing = envelope
        .payload
        .get("typing")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if typing {
        if presence_visibility_for_actor(state, actor).await == PresenceVisibilityPolicy::Nobody {
            let _ = state.persistence.typing().remove(actor, realm_id).await;
            return Ok(());
        }
        let strand_id = envelope
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                crate::error::AppError::invalid_param("ck.typing payload requires strand_id")
            })?;
        typing_scope_allows_actor(state, realm_id, actor, Some(strand_id.as_str())).await?;
        if let Err(error) = state
            .persistence
            .typing()
            .put(TypingRecord {
                actor: actor.to_owned(),
                realm_id: realm_id.to_owned(),
                scope_id: Some(strand_id),
                expires_at: envelope.expires_at,
                updated_at: chrono::Utc::now(),
            })
            .await
        {
            tracing::error!(%error, "failed to persist ephemeral typing");
        }
    } else {
        let _ = state.persistence.typing().remove(actor, realm_id).await;
    }
    Ok(())
}

async fn persist_ephemeral_presence(
    state: &AppState,
    session: &SessionRecord,
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    let actor = session.actor.as_str();
    // Fail-closed field admission (profiles-presence.md §3.2/§3.3):
    // validate the payload before consulting the visibility policy so a
    // malformed broadcast is rejected identically for every sender.
    let status = presence_state_from_payload(&envelope.payload)?;
    let status_message = match envelope.payload.get("status_message") {
        None | Some(Value::Null) => None,
        Some(Value::String(message)) => {
            cokret_sdk::validate_status_message(message).map_err(|error| {
                crate::error::AppError::new(
                    crate::error::ErrorCode::SchemaViolation,
                    format!("ck.presence status_message rejected: {error}"),
                )
            })?;
            Some(message.clone())
        }
        Some(_) => {
            return Err(crate::error::AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                "ck.presence status_message must be a string",
            ));
        }
    };
    let last_active_at = match envelope.payload.get("last_active_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            cokret_sdk::validate_last_active_at(value).map_err(|error| {
                crate::error::AppError::new(
                    crate::error::ErrorCode::SchemaViolation,
                    format!("ck.presence last_active_at rejected: {error}"),
                )
            })?;
            // §3.3: without a policy explicitly allowing precise
            // disclosure only the bucketed form is admitted; a valid
            // second-precision timestamp is a policy violation, not a
            // schema one.
            if !value.contains('/') {
                return Err(crate::error::AppError::new(
                    crate::error::ErrorCode::PolicyViolation,
                    "ck.presence last_active_at must be bucketed; precise timestamps require an explicit disclosure policy",
                )
                .with_status(StatusCode::FORBIDDEN));
            }
            Some(value.clone())
        }
        Some(_) => {
            return Err(crate::error::AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                "ck.presence last_active_at must be a string",
            ));
        }
    };
    if presence_visibility_for_actor(state, actor).await == PresenceVisibilityPolicy::Nobody {
        if let Err(error) = state.persistence.presence().delete(actor).await {
            tracing::error!(%error, "failed to clear hidden ephemeral presence");
        }
        return Ok(());
    }
    // `validate_ephemeral_broadcast_proof_shape` already guaranteed the
    // proof-bound device_id is present.
    let device_id = envelope
        .device_id
        .as_ref()
        .map(|device| device.as_str().to_owned())
        .unwrap_or_else(|| session.device_id.clone());
    if let Err(error) = state
        .persistence
        .presence()
        .put(PresenceRecord {
            actor: actor.to_owned(),
            device_id,
            status: status.as_wire().to_owned(),
            status_message,
            last_active_at,
            expires_at: Some(envelope.expires_at),
            updated_at: chrono::Utc::now(),
        })
        .await
    {
        tracing::error!(%error, "failed to persist ephemeral presence");
    }
    Ok(())
}

/// Strict closed-set `state` admission (profiles-presence.md §3.2):
/// unknown or missing values are a `schema_violation`, never guessed
/// into a nearby state (`unavailable` / `busy` are not v1 wire values).
fn presence_state_from_payload(
    payload: &Value,
) -> Result<cokret_sdk::PresenceStatus, crate::error::AppError> {
    let state = payload
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            crate::error::AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                "ck.presence payload requires state",
            )
        })?;
    cokret_sdk::PresenceStatus::parse_wire(state).ok_or_else(|| {
        crate::error::AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            "ck.presence state is not in the closed v1 set {online, idle, dnd, offline}",
        )
    })
}

async fn admit_ephemeral_read_receipt(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if envelope
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Err(crate::error::AppError::invalid_param(
            "ck.receipt.read payload requires event_id",
        ));
    }

    let policy =
        crate::routing::events::event_log::effective_read_receipt_policy_for_realm(state, realm_id)
            .await
            .unwrap_or_default();
    if policy.disclosure == cokret_sdk::ReadReceiptDisclosure::Disabled {
        return Err(crate::error::AppError::new(
            crate::error::ErrorCode::PolicyViolation,
            format!(
                "Realm '{realm_id}' read_receipt_policy.disclosure=disabled; ck.receipt.read dropped"
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    match policy.visibility {
        cokret_sdk::ReadReceiptVisibility::Private | cokret_sdk::ReadReceiptVisibility::Members => {
        }
        cokret_sdk::ReadReceiptVisibility::Public => {
            let history_visibility = realm_history_visibility_for_id(state, realm_id).await;
            if history_visibility == "world_readable"
                && !policy.allow_public_receipts_on_world_readable
            {
                return Err(crate::error::AppError::new(
                    crate::error::ErrorCode::PolicyViolation,
                    "read_receipt_policy.visibility=public is rejected for world_readable history unless allow_public_receipts_on_world_readable=true",
                )
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("read_receipt_visibility_combination_invalid"));
            }
            if history_visibility == "world_readable"
                && policy.disclosure == cokret_sdk::ReadReceiptDisclosure::Required
                && !policy.allow_forced_public_world_readable_receipts
            {
                return Err(crate::error::AppError::new(
                    crate::error::ErrorCode::PolicyViolation,
                    "read_receipt_policy.disclosure=required with visibility=public is rejected for world_readable history unless allow_forced_public_world_readable_receipts=true",
                )
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("read_receipt_forced_public_world_readable_forbidden"));
            }
        }
    }
    let visibility = match policy.visibility {
        cokret_sdk::ReadReceiptVisibility::Public => "public",
        cokret_sdk::ReadReceiptVisibility::Members => "members",
        cokret_sdk::ReadReceiptVisibility::Private => "private",
    };
    crate::routing::events::read_receipts::relay_ephemeral_read_receipt(
        state, session, realm_id, visibility, envelope,
    )
    .await?;
    Ok(())
}

/// `webrtc-signaling.md` §5 — structural admission for `ck.call.signal`
/// envelopes arriving on the canonical `/ephemeral` channel (the path the
/// canonical client takes). We reuse the SDK
/// [`cokret_sdk::validate_call_signal_envelope`] as the single truth source
/// for the required shape: `device_id` present, `proof` present, and
/// `payload` deserialises into `{call_id, signal_type, seq}` with a
/// `signal_type` drawn from the canonical [`cokret_sdk::CALL_SIGNAL_TYPES`]
/// set (which includes `moderation`).
///
/// Boundary (FIN-F task 5 decision, unchanged): the relay does NOT perform
/// cryptographic `proof` verification — §5 assigns signature verification to
/// the *receiver* over the canonical envelope bytes excluding `proof`. The
/// relay only enforces the structural contract (existence + type + seq shape)
/// so malformed call signals never enter the ephemeral fan-out.
fn admit_ephemeral_call_signal(
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<cokret_sdk::CallSignalPayload, crate::error::AppError> {
    let payload = cokret_sdk::validate_call_signal_envelope(envelope).map_err(|error| {
        crate::error::AppError::invalid_param(format!(
            "ck.call.signal envelope failed structural validation: {error}"
        ))
    })?;
    Ok(payload)
}

/// Structural proof admission shared by all four broadcast ephemeral kinds
/// (`ephemeral-envelope.schema.json`): `device_id` present, detached-JWS
/// `proof` present, `verification_method == {actor_id}#{device_id}`, and
/// `event_digest` covering the canonical envelope bytes without `proof`.
///
/// Boundary (unchanged from the call.signal-only era): the relay does NOT
/// perform cryptographic `proof` verification — the spec assigns signature
/// verification to the *receiver*. The relay enforces the structural contract
/// so malformed signals never enter the ephemeral fan-out.
fn validate_ephemeral_broadcast_proof_shape(
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    let kind = envelope.kind.as_str();
    let device_id = envelope.device_id.as_ref().ok_or_else(|| {
        crate::error::AppError::invalid_param(format!(
            "{kind} device_id is required for broadcast ephemeral signals"
        ))
    })?;
    let proof_value = envelope.proof.as_ref().ok_or_else(|| {
        crate::error::AppError::invalid_param(format!("{kind} proof is required"))
    })?;
    let proof: cokret_sdk::Proof =
        serde_json::from_value(proof_value.clone()).map_err(|error| {
            crate::error::AppError::invalid_param(format!("{kind} proof is malformed: {error}"))
        })?;
    proof.validate_production().map_err(|error| {
        crate::error::AppError::invalid_param(format!(
            "{kind} proof is not production-grade: {error}"
        ))
    })?;
    let expected_vm = format!("{}#{}", envelope.actor_id, device_id.as_str());
    if proof.verification_method != expected_vm {
        return Err(crate::error::AppError::invalid_param(format!(
            "{kind} proof.verification_method must be {{actor_id}}#{{device_id}}"
        )));
    }
    let parts = proof.jws.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(crate::error::AppError::invalid_param(format!(
            "{kind} proof.jws must be detached header..signature"
        )));
    }
    // The digest covers the canonical envelope without `proof`; the typed
    // clone with `proof = None` serializes to exactly those bytes.
    let without_proof = cokret_sdk::EphemeralEnvelope {
        proof: None,
        ..envelope.clone()
    };
    let without_proof = serde_json::to_value(&without_proof).map_err(|error| {
        crate::error::AppError::invalid_param(format!(
            "{kind} envelope is not serialisable: {error}"
        ))
    })?;
    let canonical =
        cokret_sdk::canonical::canonical_json_bytes(&without_proof).map_err(|error| {
            crate::error::AppError::invalid_param(format!(
                "{kind} envelope canonicalization failed: {error}"
            ))
        })?;
    let expected = cokret_sdk::canonical::sha256_digest(&canonical);
    if proof.event_digest.as_str() != expected {
        return Err(crate::error::AppError::invalid_param(format!(
            "{kind} proof.event_digest does not match the envelope without proof"
        )));
    }
    Ok(())
}
