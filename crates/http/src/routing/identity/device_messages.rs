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

use arkret_models_collaboration::sync_frames::account_sync::ActorPrivateDeviceUpdate;
#[cfg(test)]
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate,
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
    DeviceMessageEnvelope, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome, DeviceMessagesSendRequestBody,
};

pub(crate) const TO_DEVICE_PAGE_LIMIT: usize = 1000;

struct PreparedDeviceMessageTarget {
    recipient: String,
    device_id: String,
    target: arkret_models_collaboration::sync_frames::account_sync::DeviceMessageTarget,
    message_key: String,
    intent_digest: String,
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
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.command.send"))]
async fn send_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesSendRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesSendOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?
        .trim();
    if idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key must contain 1 to 128 characters",
        ));
    }
    let idempotency_key = idempotency_key.to_owned();
    let body = body.into_inner();
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
                "sender_principal_id": session.actor,
                "sender_device_id": session.device_id,
                "message_id": target.message_id,
            }))
            .map_err(|error| AppError::internal(error.to_string()))?;
            let intent_digest = arkret_canonical::canonical_sha256(&json!({
                "message_id": target.message_id,
                "kind": target.kind,
                "sender_principal_id": session.actor,
                "sender_device_id": session.device_id,
                "recipient_principal_id": recipient,
                "recipient_device_id": device_id,
                "expires_at": target.expires_at,
                "content": target.content,
            }))
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

    let mut batch_items = Vec::with_capacity(prepared_targets.len());
    for prepared in &prepared_targets {
        let message = if existing_message_outcomes.contains_key(&prepared.message_key) {
            None
        } else {
            let same_principal = prepared.recipient == session.actor;
            let verification_bootstrap = prepared.target.kind.starts_with("ak.key.verification.");
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
            if !(sender_verified || same_principal && target_verified && verification_bootstrap) {
                return Err(AppError::capability_denied(
                    "fresh device sessions may only send verification bootstrap to authorized same-principal devices",
                )
                .with_wire_code("fresh_device_scope_violation"));
            }
            if secret_message && !(sender_verified && target_verified) {
                return Err(AppError::capability_denied(
                    "secret to-device messages require authorized sender and recipient devices",
                )
                .with_wire_code("device_not_authorized"));
            }
            let deliverable = target_active
                && (target_verified || sender_verified && same_principal && verification_bootstrap);
            if deliverable {
                let created_at = now();
                let mut content = serde_json::to_value(&prepared.target)
                    .map_err(|error| AppError::internal(error.to_string()))?;
                if let Some(object) = content.as_object_mut() {
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
        ok: true,
        delivered,
        unknown_devices,
    })
}

fn device_message_request_conflict() -> AppError {
    AppError::conflict("Idempotency-Key was already used for a different request body")
        .with_wire_code("duplicate_conflict")
}

fn device_message_intent_conflict() -> AppError {
    AppError::conflict("message_id was already used for a different canonical target")
        .with_wire_code("duplicate_conflict")
        .with_reason_code("message_id_conflict")
}

/// Fan an actor-private update (account-data / blocklist / read-cursor
/// deltas, plaintext `content`) out to the actor's *other* devices.
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
pub(crate) async fn fanout_actor_private_update(
    state: &AppState,
    actor: &str,
    update: ActorPrivateDeviceUpdate,
) -> usize {
    let event_type = update.kind();
    let origin_device_id = update.sender_device_id();
    let created_at = update.created_at();
    let envelope = match serde_json::to_value(&update) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::error!(%error, actor, "failed to serialize actor-private update");
            return 0;
        }
    };
    let devices = state
        .identities()
        .devices_for_actor(actor)
        .await
        .unwrap_or_default();
    let mut delivered = 0;
    for device in devices {
        if device.revoked_at.is_some() || device.device_id == origin_device_id {
            continue;
        }
        let position = state.next_to_device_position();
        let idempotency_key = format!("{event_type}:{actor}:{origin_device_id}:{position}");
        match state
            .deliveries()
            .append_device_message(DeviceMessageState {
                idempotency_key,
                sender: actor.to_owned(),
                recipient: actor.to_owned(),
                device_id: device.device_id,
                position,
                content: envelope.clone(),
                created_at,
            })
            .await
        {
            Ok(()) => delivered += 1,
            Err(error) => tracing::error!(%error, actor, "failed to fan out actor-private update"),
        }
    }
    if let Err(error) = prune_device_messages_for_limits(state).await {
        tracing::error!(%error, actor, "failed to prune to-device messages after actor-private fanout");
    }
    delivered
}

#[endpoint(
    operation_id = "ak.self.device_messages.read.list",
    summary = "List pending device messages",
    tags("device_messages")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.read.list"))]
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
                return Err(AppError::invalid_param(message));
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
        Some(0) => return Err(AppError::invalid_param("limit must be greater than zero")),
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
    let messages = device_message_envelopes_after(&page);
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
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.command.ack"))]
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
        return Err(AppError::invalid_param("invalid_ack_token"));
    }
    let Some(pruned_count) = state
        .deliveries()
        .acknowledge_device_messages(&session.actor, &session.device_id, ack_token)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::invalid_param("invalid_ack_token"));
    };
    json_ok(DeviceMessagesAckOutcome {
        ok: true,
        pruned_count: Some(pruned_count as u64),
    })
}

pub(crate) fn device_message_envelopes_after(
    messages: &[DeviceMessageState],
) -> Vec<DeviceMessageEnvelope> {
    messages
        .iter()
        .filter_map(device_message_envelope_from_record)
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
    let principal = arkret_identifiers::Did::new(principal_id.to_owned())
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
            && row.device_id == device_id
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
    message: &DeviceMessageState,
) -> Option<DeviceMessageEnvelope> {
    let kind = arkret_wire::wire_strings::ProtocolKind::new(
        message
            .content
            .get("kind")
            .or_else(|| message.content.get("type"))
            .and_then(Value::as_str)?,
    )
    .ok()?;
    let content = message
        .content
        .get("content")
        .and_then(Value::as_object)?
        .clone()
        .into_iter()
        .collect();
    let expires_at = message
        .content
        .get("expires_at")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(|| message.created_at + chrono::Duration::hours(1));
    let device_proof = match message.content.get("device_proof") {
        Some(Value::Object(object)) => Some(object.clone().into_iter().collect()),
        Some(_) => return None,
        None => None,
    };
    let unsigned = match message.content.get("unsigned") {
        Some(Value::Object(object)) => Some(object.clone().into_iter().collect()),
        Some(_) => return None,
        None => None,
    };
    Some(DeviceMessageEnvelope {
        message_id: arkret_identifiers::DeviceMessageId::new(
            message.content.get("message_id")?.as_str()?.to_owned(),
        )
        .ok()?,
        kind,
        sender_principal_id: arkret_identifiers::Did::new(message.sender.clone()).ok()?,
        sender_device_id: arkret_identifiers::DeviceId::new(
            message
                .content
                .get("sender_device_id")
                .and_then(Value::as_str)?
                .to_owned(),
        )
        .ok()?,
        recipient_principal_id: arkret_identifiers::Did::new(message.recipient.clone()).ok()?,
        recipient_device_id: arkret_identifiers::DeviceId::new(message.device_id.clone()).ok()?,
        sent_at: message.created_at,
        expires_at,
        content,
        device_proof,
        unsigned,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use soland_services::identity::{DeviceIdentity, SaveDeviceCommand};

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
        let controller = "did:web:alice.example";
        let agent = "did:web:agent.alice.example";
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
                sender_device_id: origin_device.to_owned(),
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
}
