//! Ephemeral signal admission (`ck.self.ephemeral.command.send`): typing /
//! presence / read-receipt validation + persistence. Split out of `sync.rs`
//! (SOL-07-002) as a self-contained unit — no cross-module callers other than
//! the parent router, which references `ephemeral::submit_ephemeral`.

use cokret_sdk::EphemeralSubmitOutcome;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::Value;

use crate::routing::spaces::space::realm_has_member;
use crate::state::{AppState, PresenceRecord, TypingRecord};

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

    match envelope.kind.as_str() {
        "ck.typing" => {
            persist_ephemeral_typing(state, &session.actor, realm_id_str, &envelope).await
        }
        "ck.presence" => persist_ephemeral_presence(state, &session.actor, &envelope).await,
        "ck.receipt.read" => admit_ephemeral_read_receipt(state, realm_id_str, &envelope).await?,
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
            admit_ephemeral_call_signal(&envelope)?
        }
        _ => {
            return Err(crate::error::AppError::invalid_param(
                "unsupported ephemeral kind",
            ));
        }
    }

    crate::result::json_ok(EphemeralSubmitOutcome {
        accepted: true,
        kind: envelope.kind,
        realm_id,
        dispatched_to: None,
        server_received_at: Some(chrono::Utc::now()),
    })
}

fn validate_ephemeral_envelope(
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if !matches!(
        envelope.kind.as_str(),
        "ck.call.signal" | "ck.presence" | "ck.typing" | "ck.receipt.read"
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
    Ok(())
}

async fn persist_ephemeral_typing(
    state: &AppState,
    actor: &str,
    realm_id: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) {
    let typing = envelope
        .payload
        .get("typing")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if typing {
        let scope_id = envelope
            .payload
            .get("scope_id")
            .or_else(|| envelope.payload.get("strand_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned);
        if let Err(error) = state
            .persistence
            .typing()
            .put(TypingRecord {
                actor: actor.to_owned(),
                realm_id: realm_id.to_owned(),
                scope_id,
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
}

async fn persist_ephemeral_presence(
    state: &AppState,
    actor: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) {
    let status = envelope
        .payload
        .get("status")
        .or_else(|| envelope.payload.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("online")
        .to_owned();
    if let Err(error) = state
        .persistence
        .presence()
        .put(PresenceRecord {
            actor: actor.to_owned(),
            status,
            updated_at: chrono::Utc::now(),
        })
        .await
    {
        tracing::error!(%error, "failed to persist ephemeral presence");
    }
}

async fn admit_ephemeral_read_receipt(
    state: &AppState,
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

    let (disclosure, _visibility, _scope_overrides_allowed) =
        crate::routing::events::event_log::effective_read_receipt_policy_for_realm(state, realm_id)
            .await
            .unwrap_or_else(|| ("optional".to_owned(), "members".to_owned(), true));
    if disclosure == "disabled" {
        return Err(crate::error::AppError::new(
            crate::error::ErrorCode::PolicyViolation,
            format!(
                "Realm '{realm_id}' read_receipt_policy.disclosure=disabled; ck.receipt.read dropped"
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
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
) -> Result<(), crate::error::AppError> {
    cokret_sdk::validate_call_signal_envelope(envelope).map_err(|error| {
        crate::error::AppError::invalid_param(format!(
            "ck.call.signal envelope failed structural validation: {error}"
        ))
    })?;
    Ok(())
}
