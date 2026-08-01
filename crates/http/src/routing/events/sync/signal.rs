//! Signal Extension rail (`zh/sync/signal.md`).
//!
//! Two local client surfaces:
//! - `POST /_arkret/self/signal`           — `ak.self.signal.command.send`
//! - `GET  /_arkret/self/signal/subscribe` — `ak.self.signal.stream.subscribe`
//!
//! Cross-service recipients are reached through the separate authenticated
//! single-hop `POST /_arkret/peer/signal` federation binding.
//!
//! A Signal is not a durable Event: admitting one mints no Event id, advances
//! no `actor_seq`, enters no Seal coverage and produces no reducer state. The
//! only server-visible product classification is `signal_class`; the payload
//! type, the Strand / Message / Call / receipt target and the sender sequence
//! all live inside the ciphertext and are never reconstructible here.
//!
//! There is no plaintext branch (§3). A legacy plaintext ephemeral envelope is
//! rejected with `signal_plaintext_forbidden` rather than being interpreted.

use std::collections::BTreeSet;

use arkret_models_collaboration::http_bodies::SignalSubmitOutcome;
use arkret_wire::{SignalClass, SignalEnvelope, SignalRelayRequest, SignalStreamFrame};
use futures_util::stream::StreamExt;
use salvo::prelude::*;
use serde_json::Value;
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::SessionIdentityState as SessionRecord;

use super::events_query::ndjson_line;
use super::subscribe::account_subscribe_session_or_render;
use crate::routing::spaces::space::realm_has_member;
use crate::state::{AppState, EventNotification};

/// Default lifetime of one `signal/subscribe` connection. A Signal TTL never
/// exceeds 120s (§2), so a client that reconnects inside this window loses
/// nothing: the relay still holds every unexpired envelope and the
/// per-`(actor, device, realm)` watermark keeps redelivery at-most-once.
const SIGNAL_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 30_000;
/// Idle keepalive so an intermediary does not reap a quiet connection.
const SIGNAL_SUBSCRIBE_DEFAULT_HEARTBEAT_MS: u64 = 15_000;
/// How often the stream re-polls the relay. Signals are short-lived and are
/// not carried on the durable event broadcast, so the live rail polls.
const SIGNAL_SUBSCRIBE_POLL_MS: u64 = 250;

/// `ak.self.signal.command.send`.
///
/// The body is an `ak.schema.signal_envelope.v1` [`SignalEnvelope`]. It is
/// parsed twice on purpose: once as raw JSON so a legacy plaintext ephemeral
/// envelope can be rejected with the §3 `signal_plaintext_forbidden` reason
/// instead of an anonymous parse failure, then into the strong SDK type that
/// owns every structural rule.
#[endpoint(operation_id = "ak.self.signal.command.send")]
#[tracing::instrument(skip_all, fields(op = "ak.self.signal.command.send"))]
pub(super) async fn submit_signal(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<SignalSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SIGNAL_COMMAND_SEND,
    )?;

    let raw: Value = req.parse_json().await.map_err(|error| {
        AppError::bad_json(format!("signal envelope is not valid JSON: {error}"))
    })?;
    let envelope = parse_signal_envelope(raw)?;

    admit_signal(state, &session, &envelope).await?;

    let envelope_digest = envelope
        .envelope_digest()
        .map_err(|error| signal_invalid(format!("signal envelope digest: {error}")))?
        .as_str()
        .to_owned();
    let realm_id = envelope.realm_id.clone();

    // §2 — the server does short-term replay suppression on the complete
    // envelope digest only. A repeat inside the retention window is answered
    // as accepted without a second relay append: a Signal has no durable
    // receipt to reissue, so the only observable difference must be that it is
    // not delivered twice.
    let duplicate = state
        .deliveries()
        .signal_digest_seen(realm_id.as_str(), &envelope_digest)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to check signal replay suppression");
            signal_rail_unavailable("check signal replay suppression")
        })?;

    let mut dispatched_recipient_count = None;
    if !duplicate {
        let record = soland_services::delivery::SignalRelayState {
            realm_id: realm_id.as_str().to_owned(),
            scope_ref: envelope.scope_ref.clone(),
            sender_actor_id: envelope.sender_actor_id.as_str().to_owned(),
            sender_device_id: envelope.sender_device_id.as_str().to_owned(),
            signal_class: envelope.signal_class,
            envelope_digest: envelope_digest.clone(),
            sent_at: envelope.sent_at,
            expires_at: envelope.expires_at,
            envelope: envelope.clone(),
            position: 0,
        };
        state
            .deliveries()
            .append_signal(record)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to append signal to the live relay");
                signal_rail_unavailable("append the signal to the live relay")
            })?;
        dispatched_recipient_count = Some(eligible_recipient_count(state, &envelope));
        let _ = state.publish_event_notification(EventNotification::signal(
            realm_id.as_str().to_owned(),
            envelope.signal_class,
        ));
        relay_signal_to_remote_services(state, &envelope);
    }

    soland_http::result::json_ok(SignalSubmitOutcome {
        accepted: true,
        realm_id,
        envelope_digest: arkret_wire::Hash::new(envelope_digest)
            .map_err(|error| signal_invalid(format!("signal envelope digest: {error}")))?,
        dispatched_recipient_count,
        server_received_at: Some(chrono::Utc::now()),
    })
}

/// Fan one admitted local Signal out to each eligible remote recipient service.
///
/// The protocol deliberately gives this path no durable outbox, retry, or
/// acknowledgement semantics. Each destination is attempted once in a
/// detached task; failure is diagnostic-only and never changes the sender's
/// opaque accepted outcome.
fn relay_signal_to_remote_services(state: &AppState, envelope: &SignalEnvelope) {
    for destination_service_id in remote_recipient_services(state, envelope) {
        let Some(peer_url) = crate::routing::federation::federation::peer_url_for_service_id(
            state,
            &destination_service_id,
        ) else {
            tracing::debug!(
                %destination_service_id,
                realm = %envelope.realm_id,
                "Signal recipient service has no configured peer target"
            );
            continue;
        };
        let state = state.clone();
        let request = SignalRelayRequest {
            realm_id: envelope.realm_id.clone(),
            signals: vec![envelope.clone()],
        };
        tokio::spawn(async move {
            if let Err(error) = crate::routing::federation::outbox::relay_signal_once(
                &state,
                &peer_url,
                &destination_service_id,
                &request,
            )
            .await
            {
                tracing::debug!(
                    %error,
                    %destination_service_id,
                    realm = %request.realm_id,
                    "single-attempt Signal peer relay failed"
                );
            }
        });
    }
}

fn remote_recipient_services(state: &AppState, envelope: &SignalEnvelope) -> BTreeSet<String> {
    let local_service_id = state.service_id().as_str();
    let projection = state.projections().snapshot();
    projection
        .members
        .values()
        .filter(|membership| {
            membership.realm_id == envelope.realm_id.as_str()
                && membership.state == "join"
                && membership.member != envelope.sender_actor_id.as_str()
                && membership
                    .recipient_service_id
                    .as_deref()
                    .is_some_and(|service_id| service_id != local_service_id)
                && envelope.scope_ref.circle_id().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor(circle_id.as_str(), &membership.member)
                })
        })
        .filter_map(|membership| membership.recipient_service_id.clone())
        .collect()
}

/// Reject a legacy plaintext ephemeral input before it can be mistaken for a
/// malformed Signal (§3: "不存在 plaintext branch").
fn parse_signal_envelope(raw: Value) -> Result<SignalEnvelope, AppError> {
    let Some(object) = raw.as_object() else {
        return Err(AppError::bad_json("signal envelope must be a JSON object"));
    };
    if !object.contains_key("encrypted_payload") {
        return Err(AppError::new(
            ErrorCode::InvalidParam,
            "signal envelopes are encrypted-only; there is no plaintext branch",
        )
        .with_reason_code(arkret_wire::ReasonCode::SIGNAL_PLAINTEXT_FORBIDDEN));
    }
    serde_json::from_value::<SignalEnvelope>(raw).map_err(|error| {
        AppError::bad_json(format!(
            "signal envelope does not match ak.schema.signal_envelope.v1: {error}"
        ))
    })
}

/// The §3 admission set, in order: scope/realm coherence and every structural
/// rule the SDK owns, then the sender binding, then the checks that need
/// accepted state (Seal basis, live send eligibility, moderation action), then
/// the device proof.
async fn admit_signal(
    state: &AppState,
    session: &SessionRecord,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    // (1) + (4, partly) — `scope_ref.realm_id == realm_id`, the E2EE profile
    // constants, the AAD binding, `proof.created_at == sent_at`, the envelope
    // digest and the per-class TTL ceilings.
    envelope.validate_structural().map_err(structural_error)?;
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(signal_invalid("signal envelope is already expired"));
    }

    // The sending device is the authenticated one. A Signal proof names the
    // device, so a session may not relay another device's envelope.
    if envelope.sender_actor_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "signal sender_actor_id must match the bearer session actor",
        ));
    }
    if envelope.sender_device_id.as_str() != session.device_id {
        return Err(AppError::capability_denied(
            "signal sender_device_id must match the bearer session device",
        ));
    }

    // (4) — `aead_profile` MUST name an ACTIVE row of the MLS ciphersuite
    // registry. The stronger rule (equality with the ciphersuite the group at
    // `key_ref.group_state_ref` actually negotiated) needs accepted MLS group
    // state that this service does not retain; with exactly one active v1
    // suite the two coincide today, and a reserved or unregistered suite fails
    // closed here either way.
    if !mls_ciphersuite_is_active(&envelope.encrypted_payload.aead_profile) {
        return Err(signal_invalid(format!(
            "signal aead_profile '{}' is not an active MLS ciphersuite",
            envelope.encrypted_payload.aead_profile
        )));
    }

    let realm_id = envelope.realm_id.as_str();
    if !realm_has_member(state, realm_id, &session.actor).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    // (2) — the Seal basis must be verifiable and must belong to this Realm. A
    // Signal carries no `seal_basis` of its own: `seal_ref` IS the basis the
    // sender claims its send eligibility under, so an unknown or foreign Seal
    // leaves nothing to evaluate eligibility against.
    let seal = state
        .projections()
        .seal_by_id(&envelope.seal_ref)
        .map_err(|error| {
            tracing::error!(%error, "failed to resolve the signal seal_ref");
            signal_rail_unavailable("resolve the signal seal basis")
        })?
        .ok_or_else(|| signal_invalid("signal seal_ref does not resolve to a known Seal"))?;
    if seal.realm_id != envelope.realm_id {
        return Err(signal_invalid(
            "signal seal_ref belongs to a different Realm",
        ));
    }

    // (2, continued) — live send eligibility for the target scope. A
    // Circle-scoped Signal requires a joined membership in that Circle, not
    // merely Realm membership, because the relay fans a Circle Signal out to
    // that Circle's devices.
    signal_scope_send_eligible(state, session, envelope)?;

    // (3) — `moderation` additionally requires the moderation action.
    if envelope.signal_class == SignalClass::Moderation
        && !crate::routing::interop::webrtc::actor_has_call_capability(
            state,
            realm_id,
            &session.actor,
            arkret_wire::CapabilityActionId::MODERATION_DECISION,
        )
        .await
    {
        return Err(AppError::new(
            ErrorCode::SignalClassNotPermitted,
            "signal_class=moderation requires the ak.moderation.decision capability",
        ));
    }

    // (4) — the device proof, against the key the accepted device directory
    // authorizes for `sender_device_id` under `sender_actor_id`. The
    // verification-method fragment is never accepted as a stand-in.
    verify_signal_device_proof(state, envelope).await
}

/// `signal.md` §3(2) — live send eligibility for the envelope's scope.
fn signal_scope_send_eligible(
    state: &AppState,
    session: &SessionRecord,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    let Some(circle_id) = envelope.scope_ref.circle_id() else {
        // Realm scope: Realm membership, already established by the caller.
        return Ok(());
    };
    let projection = state.projections().snapshot();
    let joined = projection
        .circle_membership(circle_id.as_str(), &session.actor)
        .is_some_and(|membership| membership.state == "join")
        && projection.circle_scope_visible_to_actor(circle_id.as_str(), &session.actor);
    if !joined {
        return Err(AppError::capability_denied(
            "actor may not send signals into this Circle scope",
        ));
    }
    Ok(())
}

async fn verify_signal_device_proof(
    state: &AppState,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    let facet =
        crate::routing::identity::cross_signing::try_resolve_device_signing_directory_facet(
            state,
            envelope.sender_actor_id.as_str(),
            envelope.sender_device_id.as_str(),
        )
        .await
        .map_err(|error| {
            tracing::error!(
                %error,
                actor = %envelope.sender_actor_id,
                device = %envelope.sender_device_id,
                "failed to resolve the signal sender device signing key"
            );
            signal_rail_unavailable("resolve the device signing directory")
        })?;
    if !matches!(
        facet.status,
        arkret_models_crypto::keys::DeviceStatus::Active
    ) {
        return Err(signal_proof_invalid(
            "signal sender device is not active and authorized",
        ));
    }
    // §1 — `verification_method` is the directory lookup key and the SDK's
    // shared structural contract has already required it to equal
    // `{sender_actor_id}#{sender_device_id}` verbatim. That equality is never
    // the authorization: the key material verified against comes from the
    // accepted device directory row (`signing_key_did`), not from anything the
    // envelope carries.
    let multibase = facet
        .signing_key_did
        .as_deref()
        .and_then(|value| value.strip_prefix("did:key:"))
        .ok_or_else(|| signal_proof_invalid("signal sender device signing key is unavailable"))?;
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    // `signal.md` §3 — the Signal transcript is the SDK's, not this crate's: it
    // commits to `envelope_digest` (the envelope with `proof` removed) and names
    // the sending device, so a signature can never be replayed across the Event
    // rail. The state-dependent admission checks §3 also requires — that the
    // method resolves to this device's active signing key, and that the device
    // may send into this scope — ran above.
    arkret_signatures::verify_eddsa_signal_proof(envelope, &public_key).map_err(|error| {
        tracing::warn!(
            %error,
            actor = %envelope.sender_actor_id,
            device = %envelope.sender_device_id,
            "signal device proof verification failed"
        );
        signal_proof_invalid("signal device proof verification failed")
    })
}

/// Admit one item from an authenticated single-hop peer relay.
///
/// Every item-level failure is returned only to the caller for audit logging;
/// the HTTP handler deliberately converts it to the same opaque accepted
/// outcome. Request authentication and request-shape failures are handled
/// before this function is entered.
pub(in crate::routing::events) async fn accept_peer_signal(
    state: &AppState,
    source_service_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    envelope.validate_structural().map_err(structural_error)?;
    if !mls_ciphersuite_is_active(&envelope.encrypted_payload.aead_profile) {
        return Err(signal_invalid("signal aead_profile is not active"));
    }

    let projection = state.projections().snapshot();
    let membership_key = (
        envelope.realm_id.as_str().to_owned(),
        envelope.sender_actor_id.as_str().to_owned(),
    );
    let sender = projection
        .members
        .get(&membership_key)
        .filter(|membership| membership.state == "join")
        .ok_or_else(|| signal_invalid("signal sender is not a current member"))?;
    if sender.recipient_service_id.as_deref() != Some(source_service_id) {
        return Err(signal_invalid(
            "source service is not the sender current delivery binding",
        ));
    }

    let seal = state
        .projections()
        .seal_by_id(&envelope.seal_ref)
        .map_err(|_| signal_rail_unavailable("resolve the signal seal basis"))?
        .ok_or_else(|| signal_invalid("signal seal_ref does not resolve"))?;
    if seal.realm_id != envelope.realm_id {
        return Err(signal_invalid(
            "signal seal_ref belongs to a different Realm",
        ));
    }
    if let Some(circle_id) = envelope.scope_ref.circle_id()
        && (!projection
            .circle_membership(circle_id.as_str(), envelope.sender_actor_id.as_str())
            .is_some_and(|membership| membership.state == "join")
            || !projection.circle_scope_visible_to_actor(
                circle_id.as_str(),
                envelope.sender_actor_id.as_str(),
            ))
    {
        return Err(signal_invalid(
            "signal sender is not eligible for the Circle scope",
        ));
    }
    if envelope.signal_class == SignalClass::Moderation
        && !crate::routing::interop::webrtc::actor_has_call_capability(
            state,
            envelope.realm_id.as_str(),
            envelope.sender_actor_id.as_str(),
            arkret_wire::CapabilityActionId::MODERATION_DECISION,
        )
        .await
    {
        return Err(signal_invalid("signal sender lacks the moderation action"));
    }
    verify_signal_device_proof(state, envelope).await?;

    let local_service_id = state.service_id().as_str();
    let has_local_recipient = projection.members.values().any(|membership| {
        membership.realm_id == envelope.realm_id.as_str()
            && membership.state == "join"
            && membership.member != envelope.sender_actor_id.as_str()
            && membership.recipient_service_id.as_deref() == Some(local_service_id)
            && envelope.scope_ref.circle_id().is_none_or(|circle_id| {
                projection.circle_scope_visible_to_actor(circle_id.as_str(), &membership.member)
            })
    });
    if !has_local_recipient {
        return Ok(());
    }

    let envelope_digest = envelope
        .envelope_digest()
        .map_err(|error| signal_invalid(format!("signal envelope digest: {error}")))?
        .as_str()
        .to_owned();
    if state
        .deliveries()
        .signal_digest_seen(envelope.realm_id.as_str(), &envelope_digest)
        .await
        .map_err(|_| signal_rail_unavailable("check signal replay suppression"))?
    {
        return Ok(());
    }
    state
        .deliveries()
        .append_signal(soland_services::delivery::SignalRelayState {
            realm_id: envelope.realm_id.as_str().to_owned(),
            scope_ref: envelope.scope_ref.clone(),
            sender_actor_id: envelope.sender_actor_id.as_str().to_owned(),
            sender_device_id: envelope.sender_device_id.as_str().to_owned(),
            signal_class: envelope.signal_class,
            envelope_digest,
            sent_at: envelope.sent_at,
            expires_at: envelope.expires_at,
            envelope: envelope.clone(),
            position: 0,
        })
        .await
        .map_err(|_| signal_rail_unavailable("append peer signal to the live relay"))?;
    let _ = state.publish_event_notification(EventNotification::signal(
        envelope.realm_id.as_str().to_owned(),
        envelope.signal_class,
    ));
    Ok(())
}

/// How many Realm members other than the sender could observe this Signal.
///
/// Reported as `dispatched_recipient_count`. It is an eligibility count, not a
/// delivery guarantee: §4 is explicit that the rail has none.
fn eligible_recipient_count(state: &AppState, envelope: &SignalEnvelope) -> u64 {
    let sender = envelope.sender_actor_id.as_str();
    match envelope.scope_ref.circle_id() {
        Some(circle_id) => state
            .projections()
            .snapshot()
            .circles
            .get(circle_id.as_str())
            .map(|circle| {
                circle
                    .members
                    .iter()
                    .filter(|member| member.as_str() != sender)
                    .count() as u64
            })
            .unwrap_or(0),
        None => state
            .realm_directory()
            .snapshot()
            .get(&envelope.realm_id)
            .map(|realm| {
                realm
                    .members
                    .iter()
                    .filter(|member| member.as_str() != sender)
                    .count() as u64
            })
            .unwrap_or(0),
    }
}

fn mls_ciphersuite_is_active(canonical_id: &str) -> bool {
    arkret_wire::MLS_CIPHERSUITES
        .iter()
        .any(|suite| suite.canonical_id == canonical_id && suite.status == "active")
}

/// Map the SDK's structural rejection onto the registered wire code. The TTL
/// ceiling has its own code (`signal_ttl_out_of_range`); everything else is a
/// malformed envelope.
fn structural_error(error: arkret_wire::Error) -> AppError {
    let message = error.to_string();
    if message.contains(arkret_wire::ErrorCode::SIGNAL_TTL_OUT_OF_RANGE) {
        return AppError::new(ErrorCode::SignalTtlOutOfRange, message);
    }
    signal_invalid(message)
}

fn signal_invalid(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidParam, message)
}

fn signal_proof_invalid(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidParam, message)
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn signal_rail_unavailable(what: &str) -> AppError {
    AppError::new(
        ErrorCode::SignalRailUnavailable,
        format!("the signal rail could not {what}"),
    )
}

/// `ak.self.signal.stream.subscribe` at `GET /_arkret/self/signal/subscribe`.
///
/// NDJSON of the verbatim admitted [`SignalEnvelope`], so a receiver verifies
/// `proof` over the exact canonical bytes the sender signed. §4 forbids a new
/// stream frame kind or server-visible selector per payload type, and the
/// binding table gives this operation no request body and no durable cursor:
/// the stream therefore takes no scope selector and no `after` token. It emits
/// envelope lines plus bounded transport control frames only.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.signal.stream.subscribe"))]
pub(super) async fn signal_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let session = match account_subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
    if let Err(error) = super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE,
    ) {
        soland_http::error::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
        return;
    }

    let max_duration_ms = super::query_param(req, "max_duration_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SIGNAL_SUBSCRIBE_DEFAULT_WAIT_MS)
        .min(600_000);
    let heartbeat_ms = super::query_param(req, "heartbeat_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SIGNAL_SUBSCRIBE_DEFAULT_HEARTBEAT_MS)
        .max(100);

    let body_stream = async_stream::stream! {
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(max_duration_ms);
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(heartbeat_ms));
        heartbeat.tick().await;
        let mut poll = tokio::time::interval(std::time::Duration::from_millis(
            SIGNAL_SUBSCRIBE_POLL_MS,
        ));
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let frame = SignalStreamFrame::Drain {
                        reconnect_after_ms: Some(super::SUBSCRIBE_RECONNECT_AFTER_MS),
                        reason: None,
                    };
                    yield Ok::<bytes::Bytes, std::io::Error>(ndjson_line(&frame));
                    break;
                }
                _ = poll.tick() => {
                    for envelope in pending_signals_for_subscriber(&state, &session).await {
                        yield Ok(ndjson_line(&SignalStreamFrame::signal(envelope)));
                    }
                }
                _ = heartbeat.tick() => {
                    yield Ok(ndjson_line(&SignalStreamFrame::HEARTBEAT));
                }
            }
        }
    };

    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

/// Every unexpired Signal this device is eligible for and has not already been
/// handed, ascending by relay position. The watermark is advanced as the batch
/// is taken, so the same envelope is not re-emitted on the next poll or on a
/// reconnect inside the TTL window.
pub(crate) async fn pending_signals_for_subscriber(
    state: &AppState,
    session: &SessionRecord,
) -> Vec<SignalEnvelope> {
    let now = chrono::Utc::now();
    let mut delivered = Vec::new();
    let member_realms: Vec<String> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .filter(|realm| {
                realm
                    .members
                    .iter()
                    .any(|member| member.as_str() == session.actor)
            })
            .map(|realm| realm.realm_id.as_str().to_owned())
            .collect()
    };
    for realm_id in member_realms {
        let watermark = state
            .deliveries()
            .signal_watermark(&session.actor, &session.device_id, &realm_id)
            .await
            .unwrap_or(0);
        let records = state
            .deliveries()
            .signals_for_realm(&realm_id)
            .await
            .unwrap_or_default();
        let mut highest = watermark;
        for record in records {
            highest = highest.max(record.position);
            if record.position <= watermark || record.expires_at <= now {
                continue;
            }
            // A device never receives its own Signal back.
            if record.sender_actor_id == session.actor
                && record.sender_device_id == session.device_id
            {
                continue;
            }
            if !signal_visible_to_subscriber(state, &record, &session.actor) {
                continue;
            }
            delivered.push(record.envelope);
        }
        if highest > watermark {
            let _ = state
                .deliveries()
                .advance_signal_watermark(&session.actor, &session.device_id, &realm_id, highest)
                .await;
        }
    }
    delivered
}

/// Receiver-side scope check (§3 applies to the receiver too): a Circle-scoped
/// Signal reaches only that Circle's members.
fn signal_visible_to_subscriber(
    state: &AppState,
    record: &soland_services::delivery::SignalRelayState,
    actor: &str,
) -> bool {
    match record.scope_ref.circle_id() {
        None => true,
        Some(circle_id) => state
            .projections()
            .snapshot()
            .circle_scope_visible_to_actor(circle_id.as_str(), actor),
    }
}

#[cfg(test)]
mod tests {
    use salvo::http::StatusCode;

    use super::*;

    #[test]
    fn plaintext_ephemeral_input_is_rejected_with_the_registered_reason() {
        let error = parse_signal_envelope(serde_json::json!({
            "realm_id": "ak:realm:01904100-0000-7000-8000-65c7feb295d7",
            "kind": "ak.typing",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "content": {"typing": true}
        }))
        .expect_err("a plaintext ephemeral envelope must not be admitted");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::SIGNAL_PLAINTEXT_FORBIDDEN)
        );
    }

    #[test]
    fn only_active_registry_ciphersuites_are_accepted() {
        assert!(mls_ciphersuite_is_active(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        ));
        // Reserved rows fail closed until their profile is activated.
        assert!(!mls_ciphersuite_is_active(
            "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"
        ));
        assert!(!mls_ciphersuite_is_active("AES128GCM"));
    }

    #[test]
    fn ttl_overrun_surfaces_the_registered_wire_code() {
        let error = structural_error(arkret_wire::Error::Protocol(format!(
            "{}: signal TTL 90s exceeds the Session class ceiling of 30s",
            arkret_wire::ErrorCode::SIGNAL_TTL_OUT_OF_RANGE
        )));
        assert_eq!(error.wire_code(), "signal_ttl_out_of_range");
        assert_eq!(error.http_status(), StatusCode::BAD_REQUEST);
    }
}
