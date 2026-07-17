//! Ephemeral signal admission (`ak.self.ephemeral.command.send`): typing /
//! presence / read-receipt validation + persistence. Split out of `sync.rs`
//! (SOL-07-002) as a self-contained unit â€” no cross-module callers other than
//! the parent router, which references `ephemeral::submit_ephemeral`.

use std::collections::BTreeMap;

use arkret_sdk::EphemeralSubmitOutcome;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::Value;
use soland_storage::{PresenceRecord, SessionRecord, TypingRecord};

use crate::routing::spaces::space::{
    PresenceVisibilityPolicy, presence_visibility_for_actor, realm_has_member,
    realm_history_visibility_for_id, typing_scope_allows_actor,
};
use crate::state::{AppState, EventNotification};

#[endpoint(
    operation_id = "ak.self.ephemeral.command.send",
    tags("sync"),
    summary = "Send a broadcast ephemeral signal"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.ephemeral.command.send"))]
pub(super) async fn submit_ephemeral(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<arkret_sdk::EphemeralEnvelope>,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<EphemeralSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let envelope = body.into_inner();

    validate_ephemeral_envelope(&envelope)?;

    let realm_id = envelope.realm_id.clone();
    let realm_id_str = realm_id.as_str();
    let actor_id = envelope.actor_id.to_string();
    if actor_id != session.actor {
        return Err(soland_http::error::AppError::capability_denied(
            "ephemeral actor_id must match the bearer session actor",
        ));
    }
    if !realm_has_member(state, realm_id_str, &session.actor).await {
        return Err(soland_http::error::AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }
    if matches!(envelope.kind.as_str(), "ak.presence" | "ak.typing") {
        verify_ephemeral_device_proof(state, &envelope).await?;
    }

    let mut dispatched_to: Option<u64> = None;
    let should_wake_account_sync = match envelope.kind.as_str() {
        "ak.typing" => {
            persist_ephemeral_typing(state, &session.actor, realm_id_str, &envelope).await?;
            true
        }
        "ak.presence" => {
            persist_ephemeral_presence(state, &session, &envelope).await?;
            true
        }
        "ak.receipt.read" => {
            admit_ephemeral_read_receipt(state, &session, realm_id_str, &envelope).await?;
            false
        }
        "ak.call.signal" => {
            // `service-http-binding.md` Â§162 â€” sending a `ak.call.signal`
            // envelope on `/_arkret/self/ephemeral` requires the realm-scoped
            // `ak.call.signal.send` capability (registered in
            // `capability-action-registry.json`). Realm membership stays a
            // precondition (checked above); signal-send authority is an
            // explicit capability so a member without it cannot relay call
            // signals. Â§162 defines no dedicated error code, so we surface the
            // generic `capability_denied` (403).
            if !crate::routing::interop::webrtc::actor_has_call_capability(
                state,
                realm_id_str,
                &session.actor,
                arkret_sdk::CapabilityActionId::CALL_SIGNAL_SEND,
            )
            .await
            {
                return Err(soland_http::error::AppError::capability_denied(
                    "actor does not hold the ak.call.signal.send capability for this realm",
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
            return Err(soland_http::error::AppError::invalid_param(
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

    soland_http::result::json_ok(EphemeralSubmitOutcome {
        accepted: true,
        kind: envelope.kind,
        realm_id,
        dispatched_to,
        server_received_at: Some(chrono::Utc::now()),
    })
}

/// `webrtc-signaling.md` Â§5 â€” persist the verbatim signed `ak.call.signal`
/// envelope into the realm-broadcast relay so subscribers in the Realm pick it
/// up from `ephemeral.events` and verify the carried `proof`. The
/// envelope is stored unmodified (proof intact) and pruned at its TTL.
async fn relay_ephemeral_call_signal(
    state: &AppState,
    session: &soland_storage::SessionRecord,
    realm_id: &str,
    payload: &arkret_sdk::CallSignalPayload,
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<u64, soland_http::error::AppError> {
    let record = soland_storage::CallSignalRelayRecord {
        realm_id: realm_id.to_owned(),
        sender_actor: session.actor.clone(),
        sender_device: session.device_id.clone(),
        call_id: payload.call_id.to_string(),
        expires_at: envelope.expires_at,
        envelope: envelope.clone(),
        // `append` assigns the monotonic per-Realm position.
        position: 0,
    };
    if let Err(error) = state.persistence.call_signal_relay().append(record).await {
        tracing::error!(%error, "failed to relay ephemeral ak.call.signal");
        return Err(soland_http::error::AppError::internal(
            "failed to relay ak.call.signal for realm broadcast",
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
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<(), soland_http::error::AppError> {
    if !matches!(
        envelope.kind.as_str(),
        "ak.call.signal" | "ak.presence" | "ak.typing" | "ak.receipt.read" | "ak.realm_key.request"
    ) {
        return Err(soland_http::error::AppError::invalid_param(
            "unsupported ephemeral kind",
        ));
    }
    let window_ms = envelope
        .expires_at
        .signed_duration_since(envelope.sent_at)
        .num_milliseconds();
    if window_ms <= 0 || (window_ms as u64) > arkret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
    {
        return Err(soland_http::error::AppError::invalid_param(
            "ephemeral expires_at must be after sent_at and within the hard TTL ceiling",
        ));
    }
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(soland_http::error::AppError::invalid_param(
            "ephemeral signal is already expired",
        ));
    }
    // ephemeral-envelope.schema.json: every broadcast ephemeral kind MUST
    // carry `device_id` and a detached-JWS `proof` whose verification_method
    // is `{actor_id}#{device_id}` and whose event_digest covers the canonical
    // envelope bytes without `proof`. `ak.realm_key.request` is a targeted
    // to-device relay, not one of the four broadcast kinds, so it is outside
    // this broadcast-only proof-shape gate.
    if matches!(
        envelope.kind.as_str(),
        "ak.call.signal" | "ak.presence" | "ak.typing" | "ak.receipt.read"
    ) {
        validate_ephemeral_broadcast_proof_shape(envelope)?;
    }
    Ok(())
}

async fn persist_ephemeral_typing(
    state: &AppState,
    actor: &str,
    realm_id: &str,
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<(), soland_http::error::AppError> {
    // ephemeral-envelope.schema.json ak.typing branch: `track_name` is optional
    // but const "discussion" in v1 (mirrors message.schema.json); when omitted
    // receivers resolve it to "discussion".
    if let Some(track_name) = envelope.payload.get("track_name") {
        if track_name.as_str() != Some("discussion") {
            return Err(crate::routing::events::peer::schema_violation(
                "ak.typing payload.track_name must be \"discussion\" in v1",
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
            state
                .persistence
                .typing()
                .remove(actor, realm_id)
                .await
                .map_err(|error| {
                    tracing::error!(%error, "failed to clear hidden ephemeral typing");
                    ephemeral_channel_unavailable("clear hidden typing state")
                })?;
            return Ok(());
        }
        let strand_id = envelope
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                soland_http::error::AppError::invalid_param("ak.typing payload requires strand_id")
            })?;
        typing_scope_allows_actor(state, realm_id, actor, Some(strand_id.as_str())).await?;
        state
            .persistence
            .typing()
            .put(TypingRecord {
                actor: actor.to_owned(),
                realm_id: realm_id.to_owned(),
                scope_id: Some(strand_id),
                expires_at: envelope.expires_at,
                updated_at: chrono::Utc::now(),
                envelope: envelope.clone(),
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to persist ephemeral typing");
                ephemeral_channel_unavailable("persist typing state")
            })?;
    } else {
        state
            .persistence
            .typing()
            .remove(actor, realm_id)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to clear ephemeral typing");
                ephemeral_channel_unavailable("clear typing state")
            })?;
    }
    Ok(())
}

async fn persist_ephemeral_presence(
    state: &AppState,
    session: &SessionRecord,
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<(), soland_http::error::AppError> {
    let actor = session.actor.as_str();
    // Fail-closed field admission (profiles-presence.md Â§3.2/Â§3.3):
    // validate the payload before consulting the visibility policy so a
    // malformed broadcast is rejected identically for every sender.
    let status = presence_state_from_payload(&envelope.payload)?;
    let status_message = match envelope.payload.get("status_message") {
        None | Some(Value::Null) => None,
        Some(Value::String(message)) => {
            arkret_sdk::validate_status_message(message).map_err(|error| {
                soland_http::error::AppError::new(
                    soland_http::error::ErrorCode::SchemaViolation,
                    format!("ak.presence status_message rejected: {error}"),
                )
            })?;
            Some(message.clone())
        }
        Some(_) => {
            return Err(soland_http::error::AppError::new(
                soland_http::error::ErrorCode::SchemaViolation,
                "ak.presence status_message must be a string",
            ));
        }
    };
    let last_active_at = match envelope.payload.get("last_active_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            arkret_sdk::validate_last_active_at(value).map_err(|error| {
                soland_http::error::AppError::new(
                    soland_http::error::ErrorCode::SchemaViolation,
                    format!("ak.presence last_active_at rejected: {error}"),
                )
            })?;
            // Â§3.3: without a policy explicitly allowing precise
            // disclosure only the bucketed form is admitted; a valid
            // second-precision timestamp is a policy violation, not a
            // schema one.
            if !value.contains('/') {
                return Err(soland_http::error::AppError::new(
                    soland_http::error::ErrorCode::PolicyViolation,
                    "ak.presence last_active_at must be bucketed; precise timestamps require an explicit disclosure policy",
                )
                .with_status(StatusCode::FORBIDDEN));
            }
            Some(value.clone())
        }
        Some(_) => {
            return Err(soland_http::error::AppError::new(
                soland_http::error::ErrorCode::SchemaViolation,
                "ak.presence last_active_at must be a string",
            ));
        }
    };
    if presence_visibility_for_actor(state, actor).await == PresenceVisibilityPolicy::Nobody {
        state
            .persistence
            .presence()
            .delete(actor)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to clear hidden ephemeral presence");
                ephemeral_channel_unavailable("clear hidden presence state")
            })?;
        return Ok(());
    }
    // `validate_ephemeral_broadcast_proof_shape` already guaranteed the
    // proof-bound device_id is present.
    let device_id = envelope.device_id.as_str().to_owned();
    state
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
            envelope: envelope.clone(),
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to persist ephemeral presence");
            ephemeral_channel_unavailable("persist presence state")
        })?;
    Ok(())
}

fn ephemeral_channel_unavailable(action: &str) -> soland_http::error::AppError {
    soland_http::error::AppError::new(
        soland_http::error::ErrorCode::EphemeralChannelUnavailable,
        format!("ephemeral channel unavailable while attempting to {action}"),
    )
}

/// Strict closed-set `state` admission (profiles-presence.md Â§3.2):
/// unknown or missing values are a `schema_violation`, never guessed
/// into a nearby state (`unavailable` / `busy` are not v1 wire values).
fn presence_state_from_payload(
    payload: &BTreeMap<String, Value>,
) -> Result<arkret_sdk::PresenceStatus, soland_http::error::AppError> {
    let state = payload
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            soland_http::error::AppError::new(
                soland_http::error::ErrorCode::SchemaViolation,
                "ak.presence payload requires state",
            )
        })?;
    arkret_sdk::PresenceStatus::parse_wire(state).ok_or_else(|| {
        soland_http::error::AppError::new(
            soland_http::error::ErrorCode::SchemaViolation,
            "ak.presence state is not in the closed v1 set {online, idle, dnd, offline}",
        )
    })
}

async fn admit_ephemeral_read_receipt(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<(), soland_http::error::AppError> {
    if envelope
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Err(soland_http::error::AppError::invalid_param(
            "ak.receipt.read payload requires event_id",
        ));
    }

    let policy =
        crate::routing::events::event_log::effective_read_receipt_policy_for_realm(state, realm_id)
            .await
            .unwrap_or_default();
    if policy.disclosure == arkret_sdk::ReadReceiptDisclosure::Disabled {
        return Err(soland_http::error::AppError::new(
            soland_http::error::ErrorCode::PolicyViolation,
            format!(
                "Realm '{realm_id}' read_receipt_policy.disclosure=disabled; ak.receipt.read dropped"
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    match policy.visibility {
        arkret_sdk::ReadReceiptVisibility::Private | arkret_sdk::ReadReceiptVisibility::Members => {
        }
        arkret_sdk::ReadReceiptVisibility::Public => {
            let history_visibility = realm_history_visibility_for_id(state, realm_id).await;
            if history_visibility == "world_readable"
                && !policy.allow_public_receipts_on_world_readable
            {
                return Err(soland_http::error::AppError::new(
                    soland_http::error::ErrorCode::PolicyViolation,
                    "read_receipt_policy.visibility=public is rejected for world_readable history unless allow_public_receipts_on_world_readable=true",
                )
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("read_receipt_visibility_combination_invalid"));
            }
            if history_visibility == "world_readable"
                && policy.disclosure == arkret_sdk::ReadReceiptDisclosure::Required
                && !policy.allow_forced_public_world_readable_receipts
            {
                return Err(soland_http::error::AppError::new(
                    soland_http::error::ErrorCode::PolicyViolation,
                    "read_receipt_policy.disclosure=required with visibility=public is rejected for world_readable history unless allow_forced_public_world_readable_receipts=true",
                )
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("read_receipt_forced_public_world_readable_forbidden"));
            }
        }
    }
    let visibility = match policy.visibility {
        arkret_sdk::ReadReceiptVisibility::Public => "public",
        arkret_sdk::ReadReceiptVisibility::Members => "members",
        arkret_sdk::ReadReceiptVisibility::Private => "private",
    };
    crate::routing::events::read_receipts::relay_ephemeral_read_receipt(
        state, session, realm_id, visibility, envelope,
    )
    .await?;
    Ok(())
}

/// `webrtc-signaling.md` Â§5 â€” structural admission for `ak.call.signal`
/// envelopes arriving on the canonical `/ephemeral` channel (the path the
/// canonical client takes). We reuse the SDK
/// [`arkret_sdk::validate_call_signal_envelope`] as the single truth source
/// for the required shape: `device_id` present, `proof` present, and
/// `payload` deserialises into `{call_id, signal_type, seq}` with a
/// `signal_type` drawn from the canonical [`arkret_sdk::CALL_SIGNAL_TYPES`]
/// set (which includes `moderation`).
///
/// Boundary (FIN-F task 5 decision, unchanged): the relay does NOT perform
/// cryptographic `proof` verification â€” Â§5 assigns signature verification to
/// the *receiver* over the canonical envelope bytes excluding `proof`. The
/// relay only enforces the structural contract (existence + type + seq shape)
/// so malformed call signals never enter the ephemeral fan-out.
fn admit_ephemeral_call_signal(
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<arkret_sdk::CallSignalPayload, soland_http::error::AppError> {
    let payload = arkret_sdk::validate_call_signal_envelope(envelope).map_err(|error| {
        soland_http::error::AppError::invalid_param(format!(
            "ak.call.signal envelope failed structural validation: {error}"
        ))
    })?;
    Ok(payload)
}

/// Structural proof admission shared by all four broadcast ephemeral kinds
/// (`ephemeral-envelope.schema.json`): `device_id` present, detached-JWS
/// `proof` present, `verification_method == {actor_id}#{device_id}`, and
/// `event_digest` covering the canonical envelope bytes without `proof`.
///
/// Presence / typing receive an additional cryptographic check against the
/// authoritative device directory in [`verify_ephemeral_device_proof`]. Call
/// signals and read receipts retain their profile-specific receiver-side
/// verification rules after this shared structural gate.
fn validate_ephemeral_broadcast_proof_shape(
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<(), soland_http::error::AppError> {
    let kind = envelope.kind.as_str();
    let device_id = &envelope.device_id;
    let proof = &envelope.proof;
    proof.validate_production().map_err(|error| {
        soland_http::error::AppError::invalid_param(format!(
            "{kind} proof is not production-grade: {error}"
        ))
    })?;
    let expected_vm = format!("{}#{}", envelope.actor_id, device_id.as_str());
    if proof.verification_method != expected_vm {
        return Err(soland_http::error::AppError::invalid_param(format!(
            "{kind} proof.verification_method must be {{actor_id}}#{{device_id}}"
        )));
    }
    let parts = proof.jws.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(soland_http::error::AppError::invalid_param(format!(
            "{kind} proof.jws must be detached header..signature"
        )));
    }
    // The digest covers the canonical envelope without `proof`.
    let mut without_proof = serde_json::to_value(envelope).map_err(|error| {
        soland_http::error::AppError::invalid_param(format!(
            "{kind} envelope is not serialisable: {error}"
        ))
    })?;
    without_proof
        .as_object_mut()
        .expect("EphemeralEnvelope serializes as an object")
        .remove("proof");
    let canonical =
        arkret_sdk::canonical::canonical_json_bytes(&without_proof).map_err(|error| {
            soland_http::error::AppError::invalid_param(format!(
                "{kind} envelope canonicalization failed: {error}"
            ))
        })?;
    let expected = arkret_sdk::canonical::sha256_digest(&canonical);
    if proof.event_digest.as_str() != expected {
        return Err(soland_http::error::AppError::invalid_param(format!(
            "{kind} proof.event_digest does not match the envelope without proof"
        )));
    }
    Ok(())
}

/// `profiles-presence.md` §3.4 requires the Sync Service to authenticate every
/// presence / typing source before persistence or fan-out. The authoritative
/// key is the active, non-revoked device signing key projected by the device
/// lifecycle directory; the detached JWS signs the SDK-defined canonical proof
/// binding object and binds the canonical proof-less envelope through its
/// `event_digest`.
async fn verify_ephemeral_device_proof(
    state: &AppState,
    envelope: &arkret_sdk::EphemeralEnvelope,
) -> Result<(), soland_http::error::AppError> {
    let device_id = &envelope.device_id;
    let facet =
        crate::routing::identity::cross_signing::try_resolve_device_signing_directory_facet(
            state,
            envelope.actor_id.as_str(),
            device_id.as_str(),
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, actor = %envelope.actor_id, device = %device_id, "failed to resolve ephemeral device signing key");
            ephemeral_channel_unavailable("resolve the device signing directory")
        })?;
    if !matches!(facet.status, arkret_sdk::DeviceStatus::Active) {
        return Err(ephemeral_proof_invalid(
            "ephemeral proof device is not active and authorized",
        ));
    }
    let multibase = facet
        .signing_key_did
        .as_deref()
        .and_then(|value| value.strip_prefix("did:key:"))
        .ok_or_else(|| {
            ephemeral_proof_invalid("ephemeral proof device signing key is unavailable")
        })?;
    let public_key = arkret_sdk::signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    arkret_sdk::signatures::verify_eddsa_detached_jws_ephemeral_proof(envelope, &public_key)
    .map_err(|error| {
        tracing::warn!(%error, actor = %envelope.actor_id, device = %device_id, "ephemeral device proof verification failed");
        ephemeral_proof_invalid("ephemeral device proof verification failed")
    })
}

fn ephemeral_proof_invalid(message: impl Into<String>) -> soland_http::error::AppError {
    soland_http::error::AppError::invalid_param(message)
        .with_reason_code(arkret_sdk::ReasonCode::PROOF_INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_failure_maps_to_retriable_ephemeral_channel_error() {
        let error = ephemeral_channel_unavailable("persist presence state");
        assert_eq!(
            error.code,
            soland_http::error::ErrorCode::EphemeralChannelUnavailable
        );
        assert_eq!(error.http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
