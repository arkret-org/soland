//! Signal Extension rail (`zh/sync/signal.md`).
//!
//! Two local client surfaces:
//! - `POST /_arkret/self/signal`           — `ak.self.signal.command.send.v1`
//! - `GET  /_arkret/self/signal/subscribe` — `ak.self.signal.stream.subscribe.v1`
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
//! There is no plaintext branch (§3).

use std::collections::BTreeSet;

use arkret_models_collaboration::http_bodies::SignalSubmitOutcome;
use arkret_wire::{SignalClass, SignalEnvelope, SignalRelayRequest, SignalStreamFrame};
use futures_util::stream::StreamExt;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_services::identity::SessionIdentityState;

use super::events_query::ndjson_line;
use super::subscribe::account_subscribe_session_or_render;
use crate::routing::spaces::space::realm_has_member;
use crate::state::{AppState, EventNotification};

/// Default lifetime of one cursorless Signal connection. Reconnection may lose frames;
/// the relay never promises catch-up or delivery.
const SIGNAL_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 30_000;
/// Idle keepalive so an intermediary does not reap a quiet connection.
const SIGNAL_SUBSCRIBE_DEFAULT_HEARTBEAT_MS: u64 = 15_000;
/// A cursorless Signal rail cannot catch up across a reconnect gap. Keep the
/// normal bounded-response rollover below the product's five-second live
/// presence recovery target instead of inheriting the durable subscribe
/// surfaces' ten-second cooldown.
const SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 250;
/// How often the stream re-polls the relay. Signals are short-lived and are
/// not carried on the durable event broadcast, so the live rail polls.
const SIGNAL_SUBSCRIBE_POLL_MS: u64 = 250;

/// `ak.self.signal.command.send.v1`.
///
/// The body is an `ak.schema.signal_envelope.v1` [`SignalEnvelope`].
#[endpoint(operation_id = "ak.self.signal.command.send")]
#[tracing::instrument(skip_all, fields(op = "ak.self.signal.command.send.v1"))]
pub(super) async fn submit_signal(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<SignalSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SIGNAL_COMMAND_SEND_V1,
    )?;

    let envelope: SignalEnvelope = req.parse_json().await.map_err(|error| {
        AppError::json_invalid(format!(
            "signal envelope does not match ak.schema.signal_envelope.v1: {error}"
        ))
    })?;

    admit_signal(state, &session, &envelope).await?;
    let sender_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;

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
        let record = soland_storage::SignalRelayRecord {
            realm_id: realm_id.as_str().to_owned(),
            scope_ref: envelope.scope_ref.clone(),
            sender_actor_id: sender_actor.to_string(),
            sender_device_id: envelope.sender_device_id.as_ref().map(ToString::to_string),
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
        dispatched_recipient_count =
            Some(eligible_recipient_count(state, &envelope, &sender_actor));
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
    for destination_id in remote_recipient_services(state, envelope) {
        let state = state.clone();
        let request = SignalRelayRequest {
            realm_id: envelope.realm_id.clone(),
            signals: vec![envelope.clone()],
        };
        tokio::spawn(async move {
            if let Err(error) = crate::routing::federation::outbox::relay_signal_once(
                &state,
                &destination_id,
                &request,
            )
            .await
            {
                tracing::debug!(
                    %error,
                    %destination_id,
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
                && serde_json::from_str::<arkret_wire::ActorId>(&membership.member)
                    .is_ok_and(|actor| actor.route_service_id().as_str() != local_service_id)
                && envelope.scope_ref.circle_id().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor(circle_id.as_str(), &membership.member)
                })
        })
        .filter_map(|membership| {
            serde_json::from_str::<arkret_wire::ActorId>(&membership.member)
                .ok()
                .map(|actor| actor.route_service_id().to_string())
        })
        .collect()
}

/// The §3 admission set, in order: scope/realm coherence and every structural
/// rule the SDK owns, then the sender binding, then the checks that need
/// accepted state (Seal basis, live send eligibility, moderation action), then
/// the device proof.
async fn admit_signal(
    state: &AppState,
    session: &SessionIdentityState,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    // (1) + (4, partly) — `scope_ref.realm_id == realm_id`, the E2EE profile
    // constants, the AAD binding, the signed outer `sent_at`, the envelope
    // digest and the per-class TTL ceilings.
    envelope.validate_structural().map_err(structural_error)?;
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(signal_invalid("signal envelope is already expired"));
    }

    // The complete sender actor is always the authenticated one. Endpoint
    // authority is checked by the selected closed branch below.
    let authenticated_actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    if envelope.sender_actor_id != authenticated_actor {
        return Err(AppError::capability_denied(
            "signal sender_actor_id must match the bearer session actor",
        ));
    }

    verify_signal_mls_basis(state, envelope).await?;

    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;

    // (2) — the Seal basis must be verifiable and must belong to this Realm. A
    // Signal carries no `seal_basis` of its own: `seal_ref` IS the basis the
    // sender claims its send eligibility under, so an unknown or foreign Seal
    // leaves nothing to evaluate eligibility against.
    let seal = state
        .projections()
        .seal_by_id(&envelope.seal_ref)
        .await
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

    // (2, continued) + (3) — evaluate membership/scope and class action from
    // signed Seal state at both the declared historical basis and the complete
    // current accepted antichain. A current projection row or pending-removal
    // flag is not a substitute for either signed view.
    verify_signal_scope_authority(state, envelope, &actor).await?;

    match (&envelope.sender_device_id, &session.agent_session) {
        (Some(device_id), None) if device_id.as_str() == session.device_id => {
            verify_signal_device_proof(state, envelope, &actor).await
        }
        (None, Some(_)) => verify_signal_agent_proof(state, session, envelope, &actor).await,
        (Some(_), Some(_)) => Err(signal_proof_invalid(
            "Agent Signal sender must omit sender_device_id",
        )),
        (None, None) => Err(signal_proof_invalid(
            "ordinary Signal sender must carry sender_device_id",
        )),
        (Some(_), None) => Err(AppError::capability_denied(
            "signal sender_device_id must match the bearer session device",
        )),
    }
}

/// `signal.md` §3(2) — live send eligibility for the envelope's scope.
async fn verify_signal_scope_authority(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    let realm = &envelope.realm_id;
    let current_leaves = state
        .projections()
        .realm_seal_leaves(realm)
        .await
        .map_err(|error| {
            signal_rail_unavailable(&format!("resolve current Signal Seal basis: {error}"))
        })?;
    if current_leaves.is_empty() {
        return Err(signal_invalid(
            "signal Realm has no current signed Seal basis",
        ));
    }
    let historical = arkret_wire::SealBasis {
        leaves: vec![envelope.seal_ref.clone()],
    };
    let current = arkret_wire::SealBasis {
        leaves: current_leaves,
    };
    for (label, basis) in [("declared", historical), ("current", current)] {
        let view = state
            .projections()
            .effective_state_at(&basis.leaves, realm)
            .await
            .map_err(|error| {
                signal_rail_unavailable(&format!(
                    "resolve {label} Signal governance basis: {error}"
                ))
            })?;
        if !signal_actor_joined_in_view(&view, &envelope.scope_ref, actor)? {
            return Err(AppError::capability_denied(format!(
                "signal sender is not joined in the {label} signed Seal basis"
            )));
        }
        if envelope.signal_class == SignalClass::Moderation
            && !signal_actor_has_realm_action_in_view(
                &view,
                realm,
                actor,
                arkret_wire::CapabilityActionId::CALL_MODERATE,
            )
        {
            return Err(crate::app_error!(
                SignalClassDenied,
                format!("signal sender lacks ak.call.moderate in the {label} signed Seal basis"),
            ));
        }
    }
    Ok(())
}

fn signal_actor_joined_in_view(
    view: &std::collections::BTreeMap<
        arkret_wire::CellRef,
        arkret_state::state_model::ResolvedCellState,
    >,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
) -> Result<bool, AppError> {
    let actor = actor
        .canonical_key()
        .map_err(|error| signal_invalid(format!("signal sender ActorId: {error}")))?;
    let member_subject =
        arkret_wire::cell::composite_subject(&[serde_json::Value::String(actor.clone())])
            .map_err(|error| signal_invalid(format!("signal Realm membership subject: {error}")))?;
    let realm_cell = arkret_wire::CellRef::new(arkret_wire::cell::subject_cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        &member_subject,
    ))
    .map_err(|error| signal_invalid(format!("signal Realm membership cell: {error}")))?;
    if !matches!(view.get(&realm_cell), Some(arkret_state::state_model::ResolvedCellState::Value(value)) if value.as_str() == Some("join"))
    {
        return Ok(false);
    }
    let arkret_wire::ScopeRef::Circle { circle_id, .. } = scope else {
        return Ok(true);
    };
    let circle_subject = arkret_wire::cell::composite_subject(&[
        serde_json::Value::String(circle_id.to_string()),
        serde_json::Value::String(actor),
    ])
    .map_err(|error| signal_invalid(format!("signal Circle membership subject: {error}")))?;
    let circle_cell = arkret_wire::CellRef::new(arkret_wire::cell::subject_cell(
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
        &circle_subject,
    ))
    .map_err(|error| signal_invalid(format!("signal Circle membership cell: {error}")))?;
    Ok(
        matches!(view.get(&circle_cell), Some(arkret_state::state_model::ResolvedCellState::Value(value)) if value.as_str() == Some("join")),
    )
}

fn signal_actor_has_realm_action_in_view(
    view: &std::collections::BTreeMap<
        arkret_wire::CellRef,
        arkret_state::state_model::ResolvedCellState,
    >,
    realm: &arkret_wire::RealmId,
    actor: &arkret_wire::ActorId,
    action: &str,
) -> bool {
    let root_cell =
        arkret_wire::CellRef::new(arkret_wire::cell::REALM_AUTHORITY_ROOT_CELL.to_owned()).ok();
    let root_controller = root_cell
        .as_ref()
        .and_then(|cell| view.get(cell))
        .and_then(arkret_state::state_model::ResolvedCellState::settled_value)
        .and_then(|value| {
            serde_json::from_value::<arkret_policy::realm_bootstrap::RealmAuthorityRootValue>(
                value.clone(),
            )
            .ok()
        })
        .map(|root| root.controller_actor_id);
    if root_controller.as_ref() == Some(actor)
        && arkret_schema::capability_action(arkret_wire::CapabilityActionId::REALM_OWNER)
            .is_some_and(|descriptor| descriptor.grant_authority_actions.contains(&action))
    {
        return true;
    }

    let engine = crate::authz::SolandAuthzEngine::new();
    for (cell, cell_state) in view {
        let Ok(cell_id) = arkret_wire::cell::CellId::from_ref(cell) else {
            continue;
        };
        if cell_id.component() != arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1 {
            continue;
        }
        let scoped_state = signal_capability_cell_state_for_realm(cell_state, realm);
        if let Some(grant) = soland_services::projection::engine_grant_from_capability_cell_state(
            cell_id.subject(),
            &scoped_state,
        ) {
            engine.upsert_projected_grant(grant);
        }
    }
    let root_controller_key = root_controller.as_ref().map(ToString::to_string);
    engine
        .check_for_authority(
            actor,
            action,
            realm.as_str(),
            realm.as_str(),
            root_controller_key.as_deref(),
            &[],
            &[],
        )
        .allowed
}

fn signal_capability_cell_state_for_realm(
    cell_state: &arkret_state::state_model::ResolvedCellState,
    realm: &arkret_wire::RealmId,
) -> arkret_state::state_model::ResolvedCellState {
    let mut scoped = cell_state.clone();
    let arkret_state::state_model::ResolvedCellState::Value(serde_json::Value::Array(items)) =
        &mut scoped
    else {
        return scoped;
    };
    for item in items {
        let value = if item.get("value").is_some() {
            item.get_mut("value").expect("value existence was checked")
        } else {
            item
        };
        let body = if value.get("grant").is_some() {
            value.get_mut("grant").expect("grant existence was checked")
        } else {
            value
        };
        if let Some(body) = body.as_object_mut() {
            // `grant.realm_id` is optional on the canonical producer payload:
            // the accepted Event envelope supplies the scope. Preserve an
            // explicit value so a mismatch still fails the engine realm pin.
            body.entry("realm_id".to_owned())
                .or_insert_with(|| serde_json::Value::String(realm.to_string()));
        }
    }
    scoped
}

async fn verify_signal_device_proof(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    let sender_device_id = envelope.sender_device_id.as_ref().ok_or_else(|| {
        signal_proof_invalid("ordinary Signal sender must carry sender_device_id")
    })?;
    // This identity adapter owns only this Station's account device directory.
    // A peer's account must not borrow a local same-principal device record.
    require_local_signal_device_account(actor, state.service_id())?;
    // Account shape alone does not distinguish an Agent. Accepted local
    // provisioning must never be downgraded into an ordinary device lookup.
    if state
        .projections()
        .snapshot()
        .agent_membership_binding(envelope.realm_id.as_str(), &actor.to_string())
        .is_some()
        || crate::routing::identity::agent_pcr::agent_record_for_actor(state, actor)
            .await
            .map_err(|_| signal_rail_unavailable("resolve the Signal sender provisioning"))?
            .is_some()
    {
        return Err(signal_proof_invalid(
            "Signal has no registered Agent sender carrier",
        ));
    }
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            envelope.sender_actor_id.signing_principal_id().as_str(),
            sender_device_id.as_str(),
        )
        .await
        .map_err(|error| {
            tracing::error!(
                %error,
                actor = %envelope.sender_actor_id,
                device = %sender_device_id,
                "failed to resolve the signal sender device signing key"
            );
            signal_rail_unavailable("resolve the device signing directory")
        })?;
    if !matches!(
        facet.status,
        arkret_models_crypto::keys::DeviceStatus::Active
    ) || facet.device_authorize_event_id.is_none()
        || !facet
            .authorized_generation_ref
            .is_some_and(|generation| generation >= 1)
    {
        return Err(signal_proof_invalid(
            "signal sender device is not active and authorized",
        ));
    }
    // Current authorization includes the exact accepted Event/generation,
    // pending revocation, and the original authorization's time window.
    if crate::routing::identity::device_signing::current_device_authorization(
        state,
        actor,
        sender_device_id,
        &facet,
    )
    .await
    .map_err(|_| signal_rail_unavailable("resolve current device authorization"))?
    .is_none()
    {
        return Err(signal_proof_invalid(
            "signal device authorization is not currently effective",
        ));
    }
    // §1 — `verification_method` is the directory lookup key and the SDK's
    // shared structural contract already binds its principal and device.
    // That structural binding is never
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
    arkret_signatures::verify_ed25519_signal_proof(envelope, &public_key).map_err(|error| {
        tracing::warn!(
            %error,
            actor = %envelope.sender_actor_id,
            device = %sender_device_id,
            "signal device proof verification failed"
        );
        signal_proof_invalid("signal device proof verification failed")
    })
}

async fn verify_signal_agent_proof(
    state: &AppState,
    session: &SessionIdentityState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    let agent_session = session
        .agent_session
        .as_ref()
        .filter(|agent| agent.freshness_state == arkret_wire::FreshnessState::Fresh)
        .ok_or_else(|| signal_proof_invalid("Agent Signal requires a fresh Agent session"))?;
    let _ = agent_session;
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        signal_proof_invalid("Agent Signal requires a typed session-grant authority binding")
    })?;
    let arkret_models_identity::session_credential::SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        device_id,
        agent_key_authorization_ref,
        verification_method,
    } = &grant.holder_binding
    else {
        return Err(signal_proof_invalid(
            "Agent Signal cannot use a human-device session grant",
        ));
    };
    if agent_id != actor.signing_principal_id()
        || device_id.as_str() != session.device_id
        || verification_method != &envelope.proof.verification_method
    {
        return Err(signal_proof_invalid(
            "Agent Signal does not match its typed session-grant key binding",
        ));
    }

    verify_signal_agent_current_authority(
        state,
        envelope,
        actor,
        Some((agent_key_authorization_ref, verification_method)),
    )
    .await
}

async fn verify_signal_agent_current_authority(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
    session_binding: Option<(&arkret_wire::EventId, &arkret_wire::DidUrl)>,
) -> Result<(), AppError> {
    let agent_id = actor.signing_principal_id();
    let agent_record = crate::routing::identity::agent_pcr::agent_record_for_actor(state, actor)
        .await
        .map_err(|_| signal_rail_unavailable("resolve the Signal Agent provisioning"))?
        .ok_or_else(|| signal_proof_invalid("Signal sender is not an accepted Agent"))?;
    if agent_record.state
        != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    {
        return Err(signal_proof_invalid("Signal Agent is not active"));
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &agent_record,
        chrono::Utc::now(),
    )
    .await?;
    let controller_account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &agent_record).await?;
    let controller_actor = arkret_wire::ActorId::account(controller_account);
    if !realm_has_member(
        state,
        envelope.realm_id.as_str(),
        &controller_actor.to_string(),
    )
    .await
    {
        return Err(signal_proof_invalid(
            "Signal Agent controller is not a current Realm member",
        ));
    }
    let runtime = agent_record
        .runtime_bindings()
        .map_err(|_| signal_proof_invalid("Signal Agent runtime binding is inconsistent"))?
        .active_binding
        .ok_or_else(|| signal_proof_invalid("Signal Agent has no active runtime binding"))?;
    if runtime.verification_method != envelope.proof.verification_method {
        return Err(signal_proof_invalid(
            "Signal Agent proof method differs from the active runtime binding",
        ));
    }
    if let Some((agent_key_authorization_ref, verification_method)) = &session_binding
        && (runtime.authorized_event_ref != **agent_key_authorization_ref
            || runtime.verification_method != **verification_method)
    {
        return Err(signal_proof_invalid(
            "Signal Agent session names a stale runtime authorization",
        ));
    }

    let active_authorizations =
        crate::routing::identity::agents::accepted_active_agent_key_authorizations(
            state,
            &agent_record,
        )
        .await
        .map_err(|_| signal_rail_unavailable("resolve accepted Agent key state"))?;
    if active_authorizations.is_empty() {
        return Err(signal_proof_invalid(
            "Signal Agent has no current accepted key authorization",
        ));
    }
    for (key_id, authorization_ref) in active_authorizations {
        let authorization = state
            .event_queries()
            .canonical_event(&authorization_ref)
            .await
            .map_err(|_| signal_rail_unavailable("resolve Agent key authorization"))?
            .ok_or_else(|| signal_proof_invalid("Agent key authorization is unavailable"))?;
        let event: arkret_wire::Event = serde_json::from_value(authorization.envelope)
            .map_err(|_| signal_proof_invalid("Agent authorization Event is invalid"))?;
        let key =
            arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
                &event,
            )
            .map_err(|_| signal_proof_invalid("Agent authorization key is invalid"))?;
        if key.agent_id != *agent_id
            || key.agent_key_id.as_str() != key_id
            || key.verification_method != runtime.verification_method
            || key.public_key_digest != runtime.public_key_digest
        {
            return Err(signal_proof_invalid(
                "Agent has conflicting current runtime key authorizations",
            ));
        }
    }

    // The authenticated grant binds the runtime authorization, while its
    // session public key authenticates HTTP DPoP only. Signal producers sign
    // with the independently accepted Agent runtime key (signal.md section 1).
    let authorized_key =
        arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
            &runtime.key_authorization_event,
        )
        .map_err(|_| signal_proof_invalid("Agent authorization Event key is invalid"))?;
    let public_key =
        agent_runtime_signal_public_key(&authorized_key.public_key, &runtime.public_key_digest)?;
    arkret_signatures::verify_ed25519_signal_proof(envelope, &public_key).map_err(|error| {
        tracing::warn!(
            %error,
            actor = %envelope.sender_actor_id,
            "signal Agent proof verification failed"
        );
        signal_proof_invalid("signal Agent proof verification failed")
    })
}

fn agent_runtime_signal_public_key(
    key: &arkret_models_identity::agent_signer_evidence::AgentSigningPublicKey,
    expected_digest: &arkret_wire::Hash,
) -> Result<arkret_signatures::PublicKeyMaterial, AppError> {
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(key.key.as_str())
            .map_err(|_| signal_proof_invalid("Agent runtime public key is invalid"))?,
    };
    if public_key
        .raw_ed25519_digest()
        .map_err(|_| signal_proof_invalid("Agent runtime public key is invalid"))?
        != *expected_digest
    {
        return Err(signal_proof_invalid(
            "Agent runtime public key differs from its accepted binding",
        ));
    }
    Ok(public_key)
}

fn require_local_signal_device_account(
    actor: &arkret_wire::ActorId,
    station_id: &str,
) -> Result<(), AppError> {
    if actor
        .as_account_id()
        .is_some_and(|account| account.station_id.as_str() == station_id)
    {
        Ok(())
    } else {
        Err(signal_proof_invalid(
            "the exact Signal account has no accepted device directory here",
        ))
    }
}

/// Admit one item from an authenticated single-hop peer relay.
///
/// Every item-level failure is returned only to the caller for audit logging;
/// the HTTP handler deliberately converts it to the same opaque accepted
/// outcome. Request authentication and request-shape failures are handled
/// before this function is entered.
pub(in crate::routing::events) async fn accept_peer_signal(
    state: &AppState,
    source_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    admit_signal_outer(state, source_id, envelope).await?;
    // The authenticated source Station owns current ordinary-device admission.
    // Destination transport admission cannot authenticate a foreign producer
    // using a local same-principal directory or an MLS public-tree lookup.
    // Recipients still authenticate the original proof before consuming it.
    let projection = state.projections().snapshot();
    let sender_actor = &envelope.sender_actor_id;
    let local_service_id = state.service_id().as_str();
    let has_local_recipient = projection.members.values().any(|membership| {
        membership.realm_id == envelope.realm_id.as_str()
            && membership.state == "join"
            && membership.member != sender_actor.to_string()
            && serde_json::from_str::<arkret_wire::ActorId>(&membership.member)
                .is_ok_and(|actor| actor.route_service_id().as_str() == local_service_id)
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
        .append_signal(soland_storage::SignalRelayRecord {
            realm_id: envelope.realm_id.as_str().to_owned(),
            scope_ref: envelope.scope_ref.clone(),
            sender_actor_id: sender_actor.to_string(),
            sender_device_id: envelope.sender_device_id.as_ref().map(ToString::to_string),
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

/// Revalidate current source authority immediately before signing a peer request.
pub(crate) async fn admit_outbound_signal(
    state: &AppState,
    destination_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    let actor = &envelope.sender_actor_id;
    admit_signal_outer(state, state.service_id(), envelope).await?;
    if !remote_recipient_services(state, envelope).contains(destination_id) {
        return Err(signal_invalid(
            "Signal destination has no current eligible member",
        ));
    }
    match envelope.sender_device_id.as_ref() {
        Some(_) => verify_signal_device_proof(state, envelope, actor).await,
        None => verify_signal_agent_current_authority(state, envelope, actor, None).await,
    }
}

#[cfg(feature = "test-support")]
impl AppState {
    #[doc(hidden)]
    pub async fn test_admit_outbound_signal(
        &self,
        destination_id: &str,
        envelope: &SignalEnvelope,
    ) -> Result<(), AppError> {
        admit_outbound_signal(self, destination_id, envelope).await
    }
}

/// Server-visible checks shared by source dispatch and destination admission.
async fn admit_signal_outer(
    state: &AppState,
    source_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    envelope.validate_structural().map_err(structural_error)?;
    if envelope.sender_actor_id.as_account_id().is_none() {
        return Err(signal_proof_invalid(
            "Signal requires an account-backed ordinary or Agent sender",
        ));
    }
    arkret_signatures::proof::validate_ed25519_detached_jws_shape(&envelope.proof.jws)
        .map_err(|_| signal_proof_invalid("signal producer proof encoding is invalid"))?;
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(signal_invalid("signal envelope is already expired"));
    }
    verify_signal_mls_basis(state, envelope).await?;

    let sender_actor = envelope.sender_actor_id.clone();
    if sender_actor.route_service_id().as_str() != source_id {
        return Err(signal_invalid(
            "Signal sender route does not match the authenticated source Station",
        ));
    }
    let seal = state
        .projections()
        .seal_by_id(&envelope.seal_ref)
        .await
        .map_err(|_| signal_rail_unavailable("resolve the signal seal basis"))?
        .ok_or_else(|| signal_invalid("signal seal_ref does not resolve"))?;
    if seal.realm_id != envelope.realm_id {
        return Err(signal_invalid(
            "signal seal_ref belongs to a different Realm",
        ));
    }
    verify_signal_scope_authority(state, envelope, &sender_actor).await?;
    Ok(())
}

/// How many Realm members other than the sender could observe this Signal.
///
/// Reported as `dispatched_recipient_count`. It is an eligibility count, not a
/// delivery guarantee: §4 is explicit that the rail has none.
fn eligible_recipient_count(
    state: &AppState,
    envelope: &SignalEnvelope,
    sender: &arkret_wire::ActorId,
) -> u64 {
    let projection = state.projections().snapshot();
    let sender = sender.to_string();
    projection
        .members_of_realm(envelope.realm_id.as_str())
        .into_iter()
        .filter(|member| {
            member.member != sender
                && envelope.scope_ref.circle_id().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor(circle_id.as_str(), &member.member)
                })
        })
        .count() as u64
}

fn mls_ciphersuite_is_active(canonical_id: &str) -> bool {
    arkret_wire::MLS_CIPHERSUITES
        .iter()
        .any(|suite| suite.canonical_id == canonical_id && suite.status == "active")
}

/// Check the accepted outer MLS basis, without a public tree or device lookup.
async fn verify_signal_mls_basis(
    state: &AppState,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    if !mls_ciphersuite_is_active(&envelope.encrypted_payload.aead_profile) {
        return Err(signal_invalid("signal aead_profile is not active"));
    }
    let group_id = envelope
        .scope_ref
        .canonical_mls_group_id()
        .map_err(|error| signal_invalid(format!("signal MLS scope: {error}")))?;
    let current = state
        .mls_commits()
        .commit(&envelope.scope_ref, &group_id)
        .await
        .map_err(|_| signal_rail_unavailable("resolve the signal MLS basis"))?
        .ok_or_else(|| signal_invalid("signal scope has no accepted MLS state"))?;
    let current_ref = current
        .accepted_commit_ref
        .as_deref()
        .unwrap_or(&current.genesis_event_ref);
    if current.frontier_contested
        || current.effective_scope != envelope.scope_ref
        || current.epoch != envelope.encrypted_payload.epoch
        || current_ref != envelope.encrypted_payload.key_ref.group_state_ref
        || current.governance_binding.effective_scope() != &envelope.scope_ref
        || current.governance_binding.mls_group_id() != group_id
        || current.governance_binding.next_epoch() != current.epoch
    {
        return Err(signal_invalid(
            "signal MLS basis is stale, mismatched, or contested",
        ));
    }
    if state
        .projections()
        .snapshot()
        .pending_mls_removals
        .iter()
        .any(|removal| {
            removal.realm_id == envelope.realm_id.as_str()
                && removal.circle_id.as_deref()
                    == envelope.scope_ref.circle_id().map(|id| id.as_str())
        })
    {
        return Err(signal_invalid(
            "signal MLS basis has pending removal obligations",
        ));
    }
    let genesis = state
        .event_queries()
        .canonical_event(&current.genesis_event_ref)
        .await
        .map_err(|_| signal_rail_unavailable("resolve the signal MLS genesis"))?
        .ok_or_else(|| signal_invalid("signal MLS genesis is unavailable"))?;
    let payload = genesis
        .envelope
        .get("payload")
        .ok_or_else(|| signal_invalid("signal MLS genesis payload is unavailable"))?;
    if genesis.kind != arkret_wire::EventKind::MlsGenesis.as_str()
        || genesis.realm_id.as_deref() != Some(envelope.realm_id.as_str())
        || crate::routing::mls::payload_fields::mls_group_id(payload) != Some(group_id.as_str())
        || payload
            .get("cipher_suite")
            .and_then(serde_json::Value::as_str)
            != Some(envelope.encrypted_payload.aead_profile.as_str())
        || crate::routing::mls::payload_fields::group_state_effective_scope(payload)
            .and_then(|value| serde_json::from_value::<arkret_wire::ScopeRef>(value).ok())
            .as_ref()
            != Some(&envelope.scope_ref)
    {
        return Err(signal_invalid(
            "signal MLS genesis does not bind the scope and cipher suite",
        ));
    }
    Ok(())
}

/// Map the SDK's structural rejection onto the registered wire code. The TTL
/// and byte ceilings retain their registered codes; other violations are
/// malformed envelopes.
fn structural_error(error: arkret_wire::WireError) -> AppError {
    let error_code = error.error_code();
    let message = error.to_string();
    if error_code == Some(arkret_wire::ErrorCode::SignalTtlOutOfRange) {
        return crate::app_error!(SignalTtlOutOfRange, message);
    }
    if error_code == Some(arkret_wire::ErrorCode::PayloadTooLarge) {
        return crate::app_error!(PayloadTooLarge, message);
    }
    signal_invalid(message)
}

fn signal_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(ParamInvalid, message)
}

fn signal_proof_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(ParamInvalid, message)
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn signal_rail_unavailable(what: &str) -> AppError {
    crate::app_error!(
        SignalRailUnavailable,
        format!("the signal rail could not {what}"),
    )
}

/// `ak.self.signal.stream.subscribe.v1` at `GET /_arkret/self/signal/subscribe`.
///
/// NDJSON of the verbatim admitted [`SignalEnvelope`], so a receiver verifies
/// `proof` over the exact canonical bytes the sender signed. §4 forbids a new
/// stream frame kind or server-visible selector per payload type, and the
/// binding table gives this operation no request body and no durable cursor:
/// the stream therefore takes no scope selector and no `after` token. It emits
/// envelope lines plus bounded transport control frames only.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.signal.stream.subscribe.v1"))]
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
        arkret_wire::ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE_V1,
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
                        reconnect_after_ms: Some(SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS),
                        reason: None,
                    };
                    yield Ok::<bytes::Bytes, std::io::Error>(ndjson_line(&frame));
                    break;
                }
                _ = poll.tick() => {
                    for envelope in pending_signals_for_subscriber(&state, &session).await {
                        if let Ok(frame) = admitted_signal_frame(&state, &session, envelope).await {
                            yield Ok(ndjson_line(&frame));
                        }
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

/// Fresh current admission belongs to the recipient authenticated self boundary,
/// separately from peer relay. Never return a frame if current authority is unknown.
pub(crate) async fn admitted_signal_frame(
    state: &AppState,
    session: &SessionIdentityState,
    envelope: SignalEnvelope,
) -> Result<SignalStreamFrame, AppError> {
    use arkret_models_identity::{
        AccountDeviceSenderKind, AgentSenderKind, CurrentAccountDeviceSelector,
        CurrentAdmissionMode, CurrentAgentSelector, SignerKeyQueryOutcome, SignerKeyQuerySelector,
        SignerKeysQueryRequestBody,
    };
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let recipient = actor
        .as_account_id()
        .cloned()
        .ok_or_else(|| signal_invalid("recipient is not an account"))?;
    admit_signal_outer(
        state,
        envelope.sender_actor_id.route_service_id().as_str(),
        &envelope,
    )
    .await?;
    let selector = match envelope.sender_device_id.as_ref() {
        Some(device_id) => {
            SignerKeyQuerySelector::CurrentAccountDevice(CurrentAccountDeviceSelector {
                verification_mode: CurrentAdmissionMode::CurrentAdmission,
                sender_kind: AccountDeviceSenderKind::AccountDevice,
                actor: envelope.sender_actor_id.clone(),
                device_id: device_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
            })
        }
        None => SignerKeyQuerySelector::CurrentAgent(CurrentAgentSelector {
            verification_mode: CurrentAdmissionMode::CurrentAdmission,
            sender_kind: AgentSenderKind::Agent,
            actor: envelope.sender_actor_id.clone(),
            verification_method: envelope.proof.verification_method.clone(),
        }),
    };
    let request = SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64),
        realm_id: envelope.realm_id.clone(),
        recipient_account_id: recipient.clone(),
        queries: vec![selector],
    };
    let outcome = crate::routing::identity::current_signer_evidence::resolve_self_signer_keys(
        state, session, &request,
    )
    .await?;
    let Some(SignerKeyQueryOutcome::Current(result)) = outcome.results.into_iter().next() else {
        return Err(signal_rail_unavailable("verify current sender authority"));
    };
    // Re-check time/scope after a possible remote round trip and before emitting this frame.
    admit_signal_outer(
        state,
        envelope.sender_actor_id.route_service_id().as_str(),
        &envelope,
    )
    .await?;
    crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let recipient_actor = arkret_wire::ActorId::account(recipient.clone()).to_string();
    if !realm_has_member(state, envelope.realm_id.as_str(), &recipient_actor).await
        || envelope.scope_ref.circle_id().is_some_and(|circle_id| {
            !state
                .projections()
                .snapshot()
                .circle_scope_visible_to_actor(circle_id.as_str(), &recipient_actor)
        })
    {
        return Err(signal_rail_unavailable("verify current recipient scope"));
    }
    let authority = arkret_wire::SignalDeliveryAuthority {
        recipient_account_id: recipient,
        key: result.key,
    };
    authority
        .validate_for_envelope(&envelope)
        .map_err(structural_error)?;
    Ok(SignalStreamFrame::signal(envelope, authority))
}

/// Every unexpired Signal this device is eligible for and has not already been
/// handed, ascending by relay position. The watermark is advanced as the batch
/// is taken, so the same envelope is not re-emitted on the next poll or on a
/// reconnect inside the TTL window.
pub(crate) async fn pending_signals_for_subscriber(
    state: &AppState,
    session: &SessionIdentityState,
) -> Vec<SignalEnvelope> {
    let now = chrono::Utc::now();
    let mut delivered = Vec::new();
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return delivered;
    };
    let actor_key = actor.to_string();
    let member_realms: Vec<String> = {
        let projection = state.projections().snapshot();
        projection
            .members
            .iter()
            .filter(|((_, member), state)| member == &actor_key && state.state == "join")
            .map(|((realm, _), _)| realm.clone())
            .collect()
    };
    for realm_id in member_realms {
        if !realm_has_member(state, &realm_id, &actor_key).await {
            continue;
        }
        let watermark = state
            .deliveries()
            .signal_watermark(&actor_key, &session.device_id, &realm_id)
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
            if record.sender_actor_id == actor_key
                && record.sender_device_id.as_deref() == Some(session.device_id.as_str())
            {
                continue;
            }
            if !signal_visible_to_subscriber(state, &record, &actor_key) {
                continue;
            }
            delivered.push(record.envelope);
        }
        if highest > watermark {
            let _ = state
                .deliveries()
                .advance_signal_watermark(&actor_key, &session.device_id, &realm_id, highest)
                .await;
        }
    }
    delivered
}

/// Receiver-side scope check (§3 applies to the receiver too): a Circle-scoped
/// Signal reaches only that Circle's members.
fn signal_visible_to_subscriber(
    state: &AppState,
    record: &soland_storage::SignalRelayRecord,
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
    use serde_json::json;

    use super::*;

    #[test]
    fn agent_signal_key_comes_from_runtime_authorization_independently_of_session_key() {
        use arkret_signatures::PublicKeyMaterial;
        let runtime_bytes = [0x73; 32];
        let session_bytes = [0x74; 32];
        let runtime_digest = PublicKeyMaterial::Ed25519Raw {
            bytes: runtime_bytes.to_vec(),
        }
        .raw_ed25519_digest()
        .unwrap();
        let session_digest = PublicKeyMaterial::Ed25519Raw {
            bytes: session_bytes.to_vec(),
        }
        .raw_ed25519_digest()
        .unwrap();
        assert_ne!(runtime_digest, session_digest);
        let runtime_key = serde_json::from_value(serde_json::json!({
            "kty": "OKP", "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(runtime_bytes),
        }))
        .unwrap();
        let selected = agent_runtime_signal_public_key(&runtime_key, &runtime_digest).unwrap();
        assert_eq!(selected.raw_ed25519_digest().unwrap(), runtime_digest);
        assert!(agent_runtime_signal_public_key(&runtime_key, &session_digest).is_err());
    }

    #[test]
    fn signal_device_directory_never_substitutes_a_same_principal_local_account() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        let service = arkret_wire::ActorId::service(principal);
        assert!(require_local_signal_device_account(&local, station.as_str()).is_ok());
        assert!(require_local_signal_device_account(&foreign, station.as_str()).is_err());
        assert!(require_local_signal_device_account(&service, station.as_str()).is_err());
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
        let error = structural_error(arkret_wire::WireError::ProtocolCode {
            code: arkret_wire::ErrorCode::SignalTtlOutOfRange,
            message: "signal TTL 90s exceeds the Session class ceiling of 30s".to_owned(),
        });
        assert_eq!(error.wire_code(), "signal_ttl_out_of_range");
        assert_eq!(error.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn other_structural_rejections_stay_on_the_generic_param_code() {
        let error = structural_error(arkret_wire::WireError::Protocol(
            "signal expires_at must be strictly after sent_at".to_owned(),
        ));
        assert_eq!(error.wire_code(), "param_invalid");
    }

    #[test]
    fn signal_byte_overflow_retains_the_registered_wire_code() {
        let error = structural_error(arkret_wire::WireError::ProtocolCode {
            code: arkret_wire::ErrorCode::PayloadTooLarge,
            message: "signal envelope exceeds 65536 canonical bytes".to_owned(),
        });
        assert_eq!(error.wire_code(), "payload_too_large");
        assert_eq!(error.http_status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn cursorless_signal_rollover_does_not_inherit_durable_stream_cooldown() {
        assert_eq!(
            SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS,
            SIGNAL_SUBSCRIBE_POLL_MS
        );
        const {
            assert!(
                SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS < super::super::SUBSCRIBE_RECONNECT_AFTER_MS
            );
        }
    }

    fn governance_test_actor(name: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn governance_test_realm() -> arkret_wire::RealmId {
        arkret_wire::RealmId::new("ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy").unwrap()
    }

    #[test]
    fn signed_view_membership_uses_registry_subjects_for_realm_and_circle() {
        let actor = governance_test_actor("alice");
        let realm = governance_test_realm();
        let circle =
            arkret_wire::CircleId::new("ak:circle:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy")
                .unwrap();
        let actor_key = actor.canonical_key().unwrap();
        let realm_subject = arkret_wire::cell::composite_subject(&[json!(actor_key)]).unwrap();
        let circle_subject = arkret_wire::cell::composite_subject(&[
            json!(circle.to_string()),
            json!(actor.canonical_key().unwrap()),
        ])
        .unwrap();
        let mut view = std::collections::BTreeMap::new();
        for (family, subject) in [
            (arkret_wire::CellFamilyId::MEMBER_STATE_V1, realm_subject),
            (arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1, circle_subject),
        ] {
            view.insert(
                arkret_wire::CellRef::new(arkret_wire::cell::subject_cell(family, &subject))
                    .unwrap(),
                arkret_state::state_model::ResolvedCellState::Value(json!("join")),
            );
        }
        assert!(
            signal_actor_joined_in_view(
                &view,
                &arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                &actor,
            )
            .unwrap()
        );
        assert!(
            signal_actor_joined_in_view(
                &view,
                &arkret_wire::ScopeRef::Circle {
                    realm_id: realm,
                    circle_id: circle,
                },
                &actor,
            )
            .unwrap()
        );
    }

    #[test]
    fn signed_view_moderation_requires_an_active_exact_actor_grant() {
        let realm = governance_test_realm();
        let actor = governance_test_actor("moderator");
        let other = governance_test_actor("other");
        let grant_id = "ak:grant:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM";
        let cell = arkret_wire::CellRef::new(arkret_wire::cell::subject_cell(
            arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1,
            grant_id,
        ))
        .unwrap();
        let mut view = std::collections::BTreeMap::new();
        view.insert(
            cell,
            arkret_state::state_model::ResolvedCellState::Value(json!([{
                "tag": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM:0",
                "value": {"grant": {
                    "issuer_id": actor.clone(),
                    "subject": actor.clone(),
                    "actions": [arkret_wire::CapabilityActionId::CALL_MODERATE],
                    "resources": [{"kind": "realm"}],
                    "constraints": [],
                    "issued_at": "2026-08-31T00:00:00.000Z",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm.clone(),
                        "cell_ref": arkret_wire::cell::REALM_AUTHORITY_ROOT_CELL,
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }]
                }}
            }])),
        );
        assert!(signal_actor_has_realm_action_in_view(
            &view,
            &realm,
            &actor,
            arkret_wire::CapabilityActionId::CALL_MODERATE,
        ));
        assert!(!signal_actor_has_realm_action_in_view(
            &view,
            &realm,
            &other,
            arkret_wire::CapabilityActionId::CALL_MODERATE,
        ));
    }
}
