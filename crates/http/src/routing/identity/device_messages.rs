//! To-device message transport.
//!
//! Surfaces:
//! - `POST /_arkret/self/device_messages` — send to-device messages, idempotent on `(actor,
//!   idempotency_key)` so duplicate retries return 200 without re-queueing. The idempotency key is
//!   supplied via the `Idempotency-Key` request header.
//! - `GET /_arkret/self/device_messages` — pull pending to-device messages for the bound
//!   session/device. A `from` cursor is read-only pagination state; it never prunes the queue.
//! - `POST /_arkret/self/device_messages/ack` — consume a bearer ack token and prune the messages
//!   covered by that delivery batch.

use std::collections::BTreeMap;

#[cfg(test)]
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateDeviceUpdate, DeviceMessageContent,
};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::delivery::{
    DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection, DeviceMessageBatchItemRecord,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageState,
};
use soland_services::identity::DeviceIdentity;

use super::{SyncCursorError, now, parse_and_validate_sync_cursor, sync_token_for_client_sync};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    DeviceMessageEnvelope, DeviceMessageSender, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
    DeviceMessagesSendRequestBody,
};

pub(crate) const TO_DEVICE_PAGE_LIMIT: usize = 1000;

/// Build the only service sender accepted by the internal actor-private
/// materializer. Keeping this constructor beside the fanout prevents CAS
/// producers from accepting or copying a caller-supplied service identity.
pub(crate) fn station_device_message_sender(state: &AppState) -> DeviceMessageSender {
    DeviceMessageSender::Service {
        sender_id: arkret_identifiers::DidCoreId::new(state.service_id().to_owned())
            .expect("the loaded Station identity is a core DID"),
    }
}

struct PreparedDeviceMessageTarget {
    recipient: String,
    device_id: String,
    target: arkret_models_collaboration::sync_frames::account_sync::DeviceMessageTarget,
    message_key: String,
    intent_digest: String,
}

/// Canonical preimage of one to-device message intent, digested for
/// idempotent-send conflict detection. The shape is typed so `kind` and
/// `content` cannot be paired by hand-authored JSON; `content` stays the
/// spec-open object declared by `device-message.schema.json` and arrives
/// already validated through [`DeviceMessageTarget`].
#[derive(serde::Serialize)]
struct DeviceMessageIntentPreimage<'a> {
    device_message_id: &'a arkret_wire::DeviceMessageId,
    kind: &'a arkret_wire::ProtocolKind,
    sender_account_id: &'a arkret_wire::AccountId,
    sender_device_id: &'a str,
    recipient_account_id: &'a arkret_wire::AccountId,
    recipient_device_id: &'a arkret_wire::DeviceId,
    expires_at: chrono::DateTime<chrono::Utc>,
    content: &'a BTreeMap<String, Value>,
}

pub(crate) async fn prune_device_messages_for_limits(
    state: &AppState,
) -> soland_services::ServiceResult<()> {
    state
        .deliveries()
        .prune_device_messages(state.config().to_device_queue_capacity, now())
        .await
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("device_messages")
                .post(send_device_messages)
                .get(get_device_messages),
        )
        .push(Router::with_path("device_messages/ack").post(ack_device_messages))
}

#[endpoint(
    operation_id = "ak.self.device_messages.command.send",
    summary = "Send device-to-device messages",
    tags("device_messages")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.command.send.v1"))]
async fn send_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesSendRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesSendOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let sender_account_id =
        super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    let body = body.into_inner();
    let restricted_fresh_device_verification = state.config().development_mode
        && session.session_grant.is_none()
        && body.messages.iter().all(|(principal_id, targets)| {
            principal_id.as_str() == session.actor
                && targets
                    .values()
                    .all(|target| target.kind.as_str().starts_with("ak.key.verification."))
        });
    let sender_revocation_gate =
        match super::device_generation::active_device_revocation_gate_selector(
            state,
            &session.actor,
            &session.device_id,
        )
        .await
        {
            Ok(selector) => Some(selector),
            Err(_) if restricted_fresh_device_verification => None,
            Err(error) if error.is_not_found() => {
                return Err(
                    AppError::capability_denied("device authorization is not active")
                        .with_wire_code("device_unauthorized"),
                );
            }
            Err(error) => {
                return Err(AppError::internal(format!(
                    "current device revocation selector unavailable: {error}"
                )));
            }
        };
    let idempotency_key = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?
        .trim();
    if idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key must contain 1 to 128 characters",
        ));
    }
    let idempotency_key = idempotency_key.to_owned();
    let request_digest = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let request_key = arkret_canonical::canonical_sha256(&json!([session.actor, idempotency_key,]))
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut prepared_targets = Vec::new();
    let mut idempotency_expires_at = now();
    for (recipient, devices) in body.messages {
        for (device_id, target) in devices {
            idempotency_expires_at = idempotency_expires_at.max(target.expires_at);
            let message_key = arkret_canonical::canonical_sha256(&json!({
                "sender_account_id": sender_account_id,
                "sender_device_id": session.device_id,
                "device_message_id": target.device_message_id,
            }))
            .map_err(|error| AppError::internal(error.to_string()))?;
            let recipient_account_id =
                arkret_wire::AccountId::new(recipient.clone(), state.service_core_id().clone());
            let intent_digest = arkret_canonical::canonical_sha256(&DeviceMessageIntentPreimage {
                device_message_id: &target.device_message_id,
                kind: &target.kind,
                sender_account_id: &sender_account_id,
                sender_device_id: &session.device_id,
                recipient_account_id: &recipient_account_id,
                recipient_device_id: &device_id,
                expires_at: target.expires_at,
                content: &target.content,
            })
            .map_err(|error| AppError::internal(error.to_string()))?;
            prepared_targets.push(PreparedDeviceMessageTarget {
                recipient: recipient.to_string(),
                device_id: device_id.to_string(),
                target,
                message_key,
                intent_digest,
            });
        }
    }
    let intents = prepared_targets
        .iter()
        .map(|target| DeviceMessageIntentRecord {
            message_key: target.message_key.clone(),
            intent_digest: target.intent_digest.clone(),
        })
        .collect::<Vec<_>>();
    let inspection = state
        .deliveries()
        .inspect_device_message_batch(&request_key, &request_digest, &intents)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let existing_message_outcomes = match inspection {
        DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        } => existing_message_outcomes,
        DeviceMessageBatchInspection::Duplicate(outcomes) => {
            return json_ok(device_message_send_outcome(&prepared_targets, &outcomes)?);
        }
        DeviceMessageBatchInspection::RequestConflict => {
            return Err(device_message_request_conflict());
        }
        DeviceMessageBatchInspection::MessageConflict { .. } => {
            return Err(device_message_intent_conflict());
        }
    };
    let has_fresh_targets = prepared_targets
        .iter()
        .any(|target| !existing_message_outcomes.contains_key(&target.message_key));
    let sender_verified = if has_fresh_targets {
        let sender_device = state
            .identities()
            .find_device(soland_services::identity::FindDeviceQuery {
                actor_id: session.actor.clone(),
                device_id: session.device_id.clone(),
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        device_is_active_verified(sender_device.as_ref())
    } else {
        false
    };
    // A restricted fresh-device session (development-mode, grant-less,
    // same-principal, `ak.key.verification.*` only — device-lifecycle.md §7)
    // may bootstrap without an accepted sender device; every other fresh send
    // requires one.
    if has_fresh_targets && !sender_verified && !restricted_fresh_device_verification {
        return Err(AppError::capability_denied(
            "to-device send requires an accepted current sender device",
        )
        .with_wire_code("device_unauthorized"));
    }

    let mut batch_items = Vec::with_capacity(prepared_targets.len());
    for prepared in &prepared_targets {
        let message = if existing_message_outcomes.contains_key(&prepared.message_key) {
            None
        } else {
            let secret_message = prepared.target.kind.starts_with("ak.secret.");
            let target_record = state
                .identities()
                .find_device(soland_services::identity::FindDeviceQuery {
                    actor_id: prepared.recipient.clone(),
                    device_id: prepared.device_id.clone(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let target_agent_endpoint = if !device_is_active_verified(target_record.as_ref()) {
                active_agent_keypackage_endpoint(state, &prepared.recipient, &prepared.device_id)
                    .await?
            } else {
                false
            };
            let target_active = device_is_active(target_record.as_ref()) || target_agent_endpoint;
            let target_verified =
                device_is_active_verified(target_record.as_ref()) || target_agent_endpoint;
            // The fresh-device bootstrap exemption reaches only authorized
            // same-principal devices (the kind/principal restriction is pinned
            // by `restricted_fresh_device_verification` above).
            if !sender_verified && !target_verified {
                return Err(AppError::capability_denied(
                    "fresh device sessions may only send verification bootstrap to authorized same-principal devices",
                )
                .with_wire_code("fresh_device_scope_violation"));
            }
            if secret_message && !target_verified {
                return Err(AppError::capability_denied(
                    "secret to-device messages require authorized sender and recipient devices",
                )
                .with_wire_code("device_unauthorized"));
            }
            let deliverable = target_active;
            if deliverable {
                let created_at = now();
                let mut content = serde_json::to_value(&prepared.target)
                    .map_err(|error| AppError::internal(error.to_string()))?;
                if let Some(object) = content.as_object_mut() {
                    // The send surface is device-authenticated, so the queued
                    // body records the `device` branch of the §8.2.1 sender XOR.
                    object.insert("sender_account_id".to_owned(), json!(sender_account_id));
                    object.insert("sender_device_id".to_owned(), json!(session.device_id));
                }
                Some(DeviceMessageState {
                    idempotency_key: idempotency_key.clone(),
                    sender: session.actor.clone(),
                    recipient: prepared.recipient.clone(),
                    device_id: prepared.device_id.clone(),
                    position: state.next_to_device_position(),
                    content,
                    created_at,
                })
            } else {
                None
            }
        };
        batch_items.push(DeviceMessageBatchItemRecord {
            message_key: prepared.message_key.clone(),
            intent_digest: prepared.intent_digest.clone(),
            idempotency_expires_at: prepared.target.expires_at + chrono::Duration::hours(1),
            message,
        });
    }
    let batch_outcome = state
        .deliveries()
        .commit_device_message_batch(DeviceMessageBatchRecord {
            request_key,
            request_digest,
            idempotency_expires_at: idempotency_expires_at + chrono::Duration::hours(1),
            device_revocation_gate: sender_revocation_gate,
            target_snapshot_guard: None,
            items: batch_items,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let message_outcomes = match batch_outcome {
        DeviceMessageBatchCommitOutcome::Stored(outcomes)
        | DeviceMessageBatchCommitOutcome::Duplicate(outcomes) => outcomes,
        DeviceMessageBatchCommitOutcome::RequestConflict => {
            return Err(device_message_request_conflict());
        }
        DeviceMessageBatchCommitOutcome::MessageConflict { .. } => {
            return Err(device_message_intent_conflict());
        }
        DeviceMessageBatchCommitOutcome::SnapshotConflict => {
            return Err(AppError::conflict("recipient device snapshot changed"));
        }
        DeviceMessageBatchCommitOutcome::DeviceRevocationPending => {
            return Err(AppError::conflict("device revocation is pending")
                .with_wire_code("device_revocation_pending"));
        }
        DeviceMessageBatchCommitOutcome::DeviceRevoked => {
            return Err(
                AppError::conflict("device generation is revoked").with_wire_code("device_revoked")
            );
        }
    };
    let outcome = device_message_send_outcome(&prepared_targets, &message_outcomes)?;
    if let Err(error) = prune_device_messages_for_limits(state).await {
        tracing::error!(%error, "failed to prune to-device messages after send");
    }
    json_ok(outcome)
}

fn device_message_send_outcome(
    targets: &[PreparedDeviceMessageTarget],
    outcomes: &BTreeMap<String, bool>,
) -> Result<DeviceMessagesSendOutcome, AppError> {
    let mut delivered_by_recipient: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unknown_devices = BTreeMap::new();
    for target in targets {
        let delivered = outcomes
            .get(&target.message_key)
            .copied()
            .ok_or_else(|| AppError::internal("stored device-message outcome omitted a target"))?;
        if delivered {
            delivered_by_recipient
                .entry(target.recipient.clone())
                .or_default()
                .push(target.device_id.clone());
        } else {
            note_unknown_device(&mut unknown_devices, &target.recipient, &target.device_id);
        }
    }
    let delivered = delivered_by_recipient
        .into_iter()
        .map(|(recipient, devices)| (recipient, json!(devices)))
        .collect();
    Ok(DeviceMessagesSendOutcome {
        delivered,
        unknown_devices,
    })
}

fn device_message_request_conflict() -> AppError {
    AppError::conflict("Idempotency-Key was already used for a different request body")
        .with_wire_code("duplicate_conflict")
}

fn device_message_intent_conflict() -> AppError {
    AppError::conflict("device_message_id was already used for a different canonical target")
        .with_wire_code("duplicate_conflict")
        .with_reason_code("device_message_id_conflict")
}

/// Fan an actor-private update (account-data / blocklist / read-cursor
/// deltas, plaintext `content`) out to the holder's active devices. A real
/// device sender excludes its origin device; the local Station
/// materializer has no origin device and therefore reaches every active one.
///
/// Sidecar isolation note (zh/models/sidecar.md §7 / private-objects.md
/// §4.2): controller-private account-data plaintext travels over this surface,
/// and the target set is exactly `devices_for_actor(actor)` — the device
/// directory rows registered under the controller principal itself. Agent
/// runtime endpoints are NOT in that set: agent pairing never writes a
/// `DeviceIdentity` row under the controller (there is no `save_device` call
/// anywhere in the pairing flow), agent sessions authenticate as the agent's
/// own DID with `ak.agent.key.authorize`, and their to-device endpoints are
/// MLS key-package rows keyed by the *agent* principal
/// (`active_agent_keypackage_endpoint` resolves `row.actor_id ==
/// agent principal`). Controller-actor device rows can only be created by the
/// controller's own device flows (registration placeholder, login/device
/// pair, and the `ak.device.authorize` projection for the controller
/// principal), so this fanout is naturally isolated from agent-bound devices;
/// `fanout_skips_devices_registered_under_other_principals` pins that fact.
/// After at least one durable queue write, the materializer also publishes an
/// account-context wakeup. The wakeup carries no private body and is only a
/// latency hint; account subscribe always rebuilds its delta from durable
/// queue positions.
pub(crate) async fn fanout_actor_private_update(
    state: &AppState,
    actor: &str,
    update: ActorPrivateDeviceUpdate,
) -> usize {
    let event_type = update.kind();
    let created_at = update.created_at();
    let sender = match &update {
        ActorPrivateDeviceUpdate::AccountData { sender, .. }
        | ActorPrivateDeviceUpdate::Blocklist { sender, .. }
        | ActorPrivateDeviceUpdate::ReadCursor { sender, .. } => sender,
    };
    let (origin_device_id, sender_endpoint_id, sender_revocation_gate) = match sender {
        DeviceMessageSender::Device {
            sender_account_id,
            sender_device_id,
        } => {
            if sender_account_id.principal_id.as_str() != actor
                || sender_account_id.station_id != state.service_core_id()
            {
                tracing::warn!(
                    actor,
                    "actor-private fanout rejected because sender AccountId differs from holder"
                );
                return 0;
            }
            let sender_revocation_gate =
                match super::device_generation::active_device_revocation_gate_selector(
                    state,
                    actor,
                    sender_device_id.as_str(),
                )
                .await
                {
                    Ok(selector) => Some(selector),
                    Err(_) if state.config().development_mode => None,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            actor,
                            origin_device_id = sender_device_id.as_str(),
                            "actor-private fanout rejected because the sender device authority is not active"
                        );
                        return 0;
                    }
                };
            (
                Some(sender_device_id.as_str()),
                sender_device_id.as_str(),
                sender_revocation_gate,
            )
        }
        DeviceMessageSender::Service { sender_id } => {
            if sender_id.as_str() != state.service_id() {
                tracing::warn!(
                    actor,
                    sender_id = sender_id.as_str(),
                    local_service_id = state.service_id(),
                    "actor-private fanout rejected because the service sender is not local"
                );
                return 0;
            }
            // This internal materializer always writes `sender == recipient ==
            // actor` below. A Station update is therefore scoped to
            // the holder whose cell changed, does not borrow a holder device's
            // authority, and has neither a device-revocation gate nor an
            // origin device to exclude.
            (None, sender_id.as_str(), None)
        }
        DeviceMessageSender::Agent { .. } => {
            tracing::warn!(
                actor,
                "actor-private fanout rejected because Agent senders are not cell materializers"
            );
            return 0;
        }
    };
    let content = match &update {
        ActorPrivateDeviceUpdate::AccountData { content, .. } => {
            DeviceMessageContent::AccountDataUpdate(content.clone())
        }
        ActorPrivateDeviceUpdate::Blocklist { content, .. } => {
            DeviceMessageContent::BlocklistUpdate(content.clone())
        }
        ActorPrivateDeviceUpdate::ReadCursor { content, .. } => {
            DeviceMessageContent::ReadCursorUpdate(content.clone())
        }
    };
    let devices = state
        .identities()
        .devices_for_actor(actor)
        .await
        .unwrap_or_default();
    let mut delivered = 0;
    for device in devices {
        if device.revoked_at.is_some()
            || origin_device_id.is_some_and(|origin| device.device_id == origin)
        {
            continue;
        }
        let position = state.next_to_device_position();
        let envelope = DeviceMessageEnvelope {
            device_message_id: arkret_identifiers::DeviceMessageId::new(crate::ids::generate(
                "device_message",
            ))
            .expect("the server device-message generator returns a typed UUIDv7 id"),
            kind: arkret_wire::wire_strings::ProtocolKind::new(event_type)
                .expect("actor-private update kinds are registered protocol kinds"),
            sender: sender.clone(),
            recipient_account_id: arkret_wire::AccountId::new(
                arkret_identifiers::DidCoreId::new(actor.to_owned())
                    .expect("authenticated actor-private holder is a core DID"),
                state.service_core_id().clone(),
            ),
            recipient_device_id: arkret_identifiers::DeviceId::new(device.device_id.clone())
                .expect("persisted active device has a typed device id"),
            sent_at: created_at,
            expires_at: created_at + chrono::Duration::hours(1),
            content: content.clone(),
            unsigned: None,
        };
        let envelope = match serde_json::to_value(envelope) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::error!(%error, actor, "failed to serialize actor-private envelope");
                continue;
            }
        };
        let idempotency_key = format!("{event_type}:{actor}:{sender_endpoint_id}:{position}");
        match state
            .deliveries()
            .append_device_message(
                sender_revocation_gate.as_ref(),
                DeviceMessageState {
                    idempotency_key,
                    sender: actor.to_owned(),
                    recipient: actor.to_owned(),
                    device_id: device.device_id,
                    position,
                    content: envelope.clone(),
                    created_at,
                },
            )
            .await
        {
            Ok(()) => delivered += 1,
            Err(error) => tracing::error!(%error, actor, "failed to fan out actor-private update"),
        }
    }
    if let Err(error) = prune_device_messages_for_limits(state).await {
        tracing::error!(%error, actor, "failed to prune to-device messages after actor-private fanout");
    }
    if delivered > 0 {
        let Ok(principal_id) = arkret_wire::DidCoreId::new(actor.to_owned()) else {
            tracing::warn!(actor, "actor-private fanout actor is invalid");
            return delivered;
        };
        let account_id = arkret_wire::AccountId::new(principal_id, state.service_core_id().clone());
        match state.identities().account(&account_id).await {
            Ok(Some(account)) => {
                let _ = state.publish_event_notification(crate::state::EventNotification::account(
                    account.account_id,
                    state.service_core_id().clone(),
                ));
            }
            Ok(None) => {
                tracing::warn!(
                    actor,
                    "actor-private fanout queued messages without a local account wakeup target"
                );
            }
            Err(error) => {
                // The queue rows are durable and the bounded account long poll
                // re-reads them at timeout. A failed lookup can delay delivery,
                // but it must not turn an accepted private update into a
                // failed or duplicated write.
                tracing::warn!(
                    %error,
                    actor,
                    "actor-private fanout could not publish an account-stream wakeup"
                );
            }
        }
    }
    delivered
}

#[endpoint(
    operation_id = "ak.self.device_messages.read.list",
    summary = "List pending device messages",
    tags("device_messages")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.read.list.v1"))]
async fn get_device_messages(
    aa: AuthArgs,
    after: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesGetOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let cursor = after.into_inner();
    let cursor_position = match cursor {
        Some(cursor) => match parse_and_validate_sync_cursor(
            &cursor,
            state,
            Some(&session),
            None,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            Ok(cursor) => {
                // Presenting a valid cursor proves the client persisted it;
                // strictly-older handle rows for this stream are superseded.
                // Best-effort.
                if let Some(presented_issued_at_ms) = cursor.issued_at_ms {
                    let _ = state
                        .sync()
                        .prune_superseded_cursors(
                            &session.actor,
                            &session.device_id,
                            &crate::routing::events::sync::sync_filter_digest(None),
                            presented_issued_at_ms,
                        )
                        .await;
                }
                cursor.to_device_position
            }
            Err(SyncCursorError::Expired) => {
                return Err(AppError::new(
                    ErrorCode::CursorExpired,
                    "cursor has expired",
                ));
            }
            Err(SyncCursorError::Invalid(message)) => {
                return Err(AppError::param_invalid(message));
            }
            Err(SyncCursorError::Mismatch(message)) => {
                return Err(AppError::new(ErrorCode::CursorIntegrityInvalid, message));
            }
            Err(SyncCursorError::Integrity(message)) => {
                return Err(AppError::new(ErrorCode::CursorIntegrityInvalid, message));
            }
            Err(SyncCursorError::Revoked) => {
                return Err(AppError::new(
                    ErrorCode::CursorRevoked,
                    "cursor authority has been revoked",
                ));
            }
        },
        None => 0,
    };
    let page_limit = match limit.into_inner() {
        Some(0) => return Err(AppError::param_invalid("limit must be greater than zero")),
        Some(limit) => (limit as usize).min(TO_DEVICE_PAGE_LIMIT),
        None => TO_DEVICE_PAGE_LIMIT,
    };
    prune_device_messages_for_limits(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let lost_watermark = state
        .deliveries()
        .device_message_lost_watermark(&session.actor, &session.device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let lost = lost_watermark.is_some_and(|position| position > cursor_position);
    let queued = state
        .deliveries()
        .device_messages_after(&session.actor, &session.device_id, cursor_position)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let has_more = queued.len() > page_limit;
    let page = queued.into_iter().take(page_limit).collect::<Vec<_>>();
    let messages = device_message_envelopes_after(state, &page);
    let delivered_position = page
        .iter()
        .map(|message| message.position)
        .max()
        .unwrap_or(cursor_position);
    let mut to_device_position = delivered_position;
    if lost && let Some(lost_watermark) = lost_watermark {
        to_device_position = to_device_position.max(lost_watermark);
    }
    let ack_token = if page.is_empty() {
        None
    } else {
        state
            .deliveries()
            .issue_device_message_ack_token(&session.actor, &session.device_id, delivered_position)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    };
    let next_cursor = if page.is_empty() && !lost {
        None
    } else {
        Some(
            sync_token_for_client_sync(
                state,
                Some(&session),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                to_device_position,
            )
            .await,
        )
    };
    json_ok(DeviceMessagesGetOutcome {
        messages,
        ack_token,
        next_cursor,
        has_more,
        limited: has_more,
        lost,
    })
}

#[endpoint(
    operation_id = "ak.self.device_messages.command.ack",
    summary = "Acknowledge received device messages",
    tags("device_messages")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.command.ack.v1"))]
async fn ack_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesAckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesAckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let ack_token = body.ack_token.trim();
    if ack_token.is_empty() {
        return Err(AppError::param_invalid("invalid_ack_token"));
    }
    let Some(pruned_count) = state
        .deliveries()
        .acknowledge_device_messages(&session.actor, &session.device_id, ack_token)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::param_invalid("invalid_ack_token"));
    };
    json_ok(DeviceMessagesAckOutcome {
        pruned_count: pruned_count as u64,
    })
}

pub(crate) fn device_message_envelopes_after(
    state: &AppState,
    messages: &[DeviceMessageState],
) -> Vec<DeviceMessageEnvelope> {
    messages
        .iter()
        .filter_map(|message| device_message_envelope_from_record(state, message))
        .collect()
}

fn device_is_active(record: Option<&DeviceIdentity>) -> bool {
    record.is_some_and(|record| record.revoked_at.is_none())
}

fn device_is_active_verified(record: Option<&DeviceIdentity>) -> bool {
    record.is_some_and(|record| {
        record.revoked_at.is_none() && record.verification_state == "verified"
    })
}

async fn active_agent_keypackage_endpoint(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<bool, AppError> {
    let now_unix = now().timestamp();
    let rows = state
        .mls_key_packages()
        .key_packages()
        .await
        .map_err(|error| AppError::internal(format!("mls keypackage snapshot failed: {error}")))?;
    let principal = arkret_identifiers::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("invalid Agent principal: {error}")))?;
    for row in &rows {
        let lifecycle = row.lifecycle().map_err(|error| {
            AppError::internal(format!(
                "invalid persisted MLS KeyPackage lifecycle for `{}`: {error}",
                row.id
            ))
        })?;
        let Some(authorize_event_id) = row.agent_key_authorize_event_id.as_deref() else {
            continue;
        };
        if row.actor_id == principal_id
            && row.device_id.as_deref() == Some(device_id)
            && matches!(
                lifecycle.claim_state,
                soland_services::events::PersistedKeyPackageClaimState::Available
                    | soland_services::events::PersistedKeyPackageClaimState::Claimed { .. }
            )
            && row.lifetime_not_after > now_unix
            && crate::routing::mls::current_agent_key_authorization_matches(
                state,
                &principal,
                authorize_event_id,
            )
            .await
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn note_unknown_device(
    unknown_devices: &mut BTreeMap<String, Value>,
    recipient: &str,
    device_id: &str,
) {
    let entry = unknown_devices
        .entry(recipient.to_owned())
        .or_insert_with(|| json!([]));
    if let Some(devices) = entry.as_array_mut() {
        devices.push(json!(device_id));
    } else {
        *entry = json!([device_id]);
    }
}

fn device_message_envelope_from_record(
    state: &AppState,
    message: &DeviceMessageState,
) -> Option<DeviceMessageEnvelope> {
    let kind = arkret_wire::wire_strings::ProtocolKind::new(
        message.content.get("kind").and_then(Value::as_str)?,
    )
    .ok()?;
    let content_value = message
        .content
        .get("content")
        .and_then(Value::as_object)?
        .clone();
    let content =
        arkret_models_collaboration::sync_frames::account_sync::decode_device_message_content(
            &kind,
            Value::Object(content_value),
        )
        .ok()?;
    let expires_at = message
        .content
        .get("expires_at")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(|| message.created_at + chrono::Duration::hours(1));
    let unsigned = match message.content.get("unsigned") {
        Some(Value::Object(object)) => Some(object.clone().into_iter().collect()),
        Some(_) => return None,
        None => None,
    };
    // `contact-and-direct-conversation.md` §8.2.1 — the queued body carries the
    // closed sender endpoint XOR verbatim. A body that does not resolve to
    // exactly one complete branch is dropped rather than repaired: repairing it
    // would mean choosing a sender identity the producer never wrote down.
    let sender = <DeviceMessageSender as serde::Deserialize>::deserialize(&message.content).ok()?;
    if let DeviceMessageSender::Service { sender_id } = &sender
        && sender_id.as_str() != state.service_id()
    {
        // Fail closed on persisted rows that do not carry the exact local
        // service/holder binding the internal materializer wrote.
        return None;
    }
    Some(DeviceMessageEnvelope {
        device_message_id: arkret_identifiers::DeviceMessageId::new(
            message
                .content
                .get("device_message_id")?
                .as_str()?
                .to_owned(),
        )
        .ok()?,
        kind,
        sender,
        recipient_account_id: arkret_wire::AccountId::new(
            arkret_identifiers::DidCoreId::new(message.recipient.clone()).ok()?,
            state.service_core_id().clone(),
        ),
        recipient_device_id: arkret_identifiers::DeviceId::new(message.device_id.clone()).ok()?,
        sent_at: message.created_at,
        expires_at,
        content,
        unsigned,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use soland_services::identity::{AccountProfileState, DeviceIdentity, SaveDeviceCommand};

    use super::*;

    fn test_state() -> AppState {
        let config = crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-device-messages-test-blobs"),
            ),
            development_mode: true,
            seed_demo_data: false,
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, soland_storage_postgres::Db { pool: None })
    }

    fn production_test_state() -> AppState {
        let config = crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-device-messages-production-test-blobs"),
            ),
            development_mode: false,
            seed_demo_data: false,
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, soland_storage_postgres::Db { pool: None })
    }

    async fn save_active_device(state: &AppState, actor: &str, device_id: &str) {
        let registered_at = now();
        state
            .identities()
            .save_device(SaveDeviceCommand {
                actor_id: actor.to_owned(),
                device_id: device_id.to_owned(),
                display_name: None,
                device: DeviceIdentity {
                    actor_id: actor.to_owned(),
                    device_id: device_id.to_owned(),
                    display_name: None,
                    verification_state: "verified".to_owned(),
                    payload: json!({"device_id": device_id}),
                    created_at: registered_at,
                    updated_at: registered_at,
                    revoked_at: None,
                },
            })
            .await
            .expect("device saved");
    }

    /// S-3 (spec review): controller-private account-data plaintext fanned out
    /// by `fanout_actor_private_update` only reaches device rows registered
    /// under the controller principal itself. Agent runtime devices live under
    /// the agent's own actor id (agent pairing registers no controller-actor
    /// device row), so the fanout surface is naturally isolated from agents —
    /// this test pins that fact by registering an agent-actor device and
    /// asserting the controller fanout never enqueues anything for it.
    #[tokio::test]
    async fn fanout_skips_devices_registered_under_other_principals() {
        let state = test_state();
        let controller = "ak:did_core:web:alice.example";
        let agent = "ak:did_core:web:agent.alice.example";
        let origin_device = "ak:device:01904100-0000-7000-8000-0000000000c0";
        let other_controller_device = "ak:device:01904100-0000-7000-8000-0000000000c1";
        let agent_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        save_active_device(&state, controller, origin_device).await;
        save_active_device(&state, controller, other_controller_device).await;
        // The agent runtime's device row belongs to the agent actor, mirroring
        // how agent endpoints are keyed in production.
        save_active_device(&state, agent, agent_device).await;

        let delivered = fanout_actor_private_update(
            &state,
            controller,
            ActorPrivateDeviceUpdate::AccountData {
                sender: DeviceMessageSender::Device {
                    sender_account_id: arkret_wire::AccountId::new(
                        arkret_wire::DidCoreId::new(controller.to_owned()).unwrap(),
                        state.service_core_id(),
                    ),
                    sender_device_id: arkret_identifiers::DeviceId::new(origin_device.to_owned())
                        .unwrap(),
                },
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: "ak.account.blocklist".to_owned(),
                    revision: 1,
                    content: Some(json!({"private": true})),
                    updated_at: now(),
                },
                created_at: now(),
            },
        )
        .await;

        assert_eq!(
            delivered, 1,
            "only the controller's other device receives the fanout"
        );
        let controller_queue = state
            .deliveries()
            .device_messages_after(controller, other_controller_device, 0)
            .await
            .expect("controller queue");
        assert_eq!(controller_queue.len(), 1);
        let agent_queue = state
            .deliveries()
            .device_messages_after(agent, agent_device, 0)
            .await
            .expect("agent queue");
        assert!(
            agent_queue.is_empty(),
            "agent-actor devices must never receive controller-private fanout"
        );
        let cross_queue = state
            .deliveries()
            .device_messages_after(controller, agent_device, 0)
            .await
            .expect("cross queue");
        assert!(
            cross_queue.is_empty(),
            "the agent device id is not addressable under the controller actor"
        );
    }

    #[tokio::test]
    async fn production_service_fanout_reaches_every_active_holder_device_and_is_readable() {
        let state = production_test_state();
        let holder = "ak:did_core:web:holder.example";
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(holder.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );
        let first_device = "ak:device:01904100-0000-7000-8000-0000000000d1";
        let second_device = "ak:device:01904100-0000-7000-8000-0000000000d2";
        state
            .identities()
            .save_account(AccountProfileState {
                pk: soland_storage::AccountPk(1),
                account_id: account_id.clone(),
                principal_id: arkret_wire::DidCoreId::new(holder.to_owned()).unwrap(),
                localpart: "holder".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: now(),
            })
            .await
            .expect("holder account saved");
        save_active_device(&state, holder, first_device).await;
        save_active_device(&state, holder, second_device).await;
        let updated_at = now();
        let cell = json!({"entries": [{"invite_id": "one"}]});
        let mut account_wakeups = state.test_subscribe_event_notifications();

        let delivered = fanout_actor_private_update(
            &state,
            holder,
            ActorPrivateDeviceUpdate::AccountData {
                sender: station_device_message_sender(&state),
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: "ak.account.invite_delivery".to_owned(),
                    revision: 7,
                    content: Some(cell.clone()),
                    updated_at,
                },
                created_at: updated_at,
            },
        )
        .await;

        assert_eq!(
            delivered, 2,
            "service fanout has no origin device to exclude"
        );
        let wakeup =
            tokio::time::timeout(std::time::Duration::from_secs(1), account_wakeups.recv())
                .await
                .expect("account stream wakeup timeout")
                .expect("account stream wakeup channel");
        assert!(matches!(
            wakeup.kind,
            crate::state::EventNotificationKind::Account {
                account_id: ref received_account_id,
                recipient_id: ref received_recipient_id,
            } if received_account_id == &account_id
                && received_recipient_id.as_str() == state.service_id()
        ));
        for device_id in [first_device, second_device] {
            let queued = state
                .deliveries()
                .device_messages_after(holder, device_id, 0)
                .await
                .expect("holder device queue");
            assert_eq!(queued.len(), 1);
            let envelopes = device_message_envelopes_after(&state, &queued);
            assert_eq!(
                envelopes.len(),
                1,
                "service sender must parse without repair"
            );
            let envelope = &envelopes[0];
            assert_eq!(&envelope.recipient_account_id, &account_id);
            assert_eq!(envelope.recipient_device_id.as_str(), device_id);
            assert!(matches!(
                &envelope.sender,
                DeviceMessageSender::Service { sender_id }
                    if sender_id.as_str() == state.service_id()
            ));
            let content = serde_json::to_value(&envelope.content).unwrap();
            assert_eq!(content.get("revision"), Some(&json!(7)));
            assert_eq!(content.get("content"), Some(&cell));
        }
    }
}
