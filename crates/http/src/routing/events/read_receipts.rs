use std::collections::BTreeMap;

use arkret_models_collaboration::objects::read_receipts::ReadReceipt;
use arkret_wire::ReadScopeKind;
use chrono::{DateTime, Utc};
use serde_json::Value;
use soland_services::delivery::ReadReceiptState;
use soland_services::events::CanonicalEventRecord;
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_http::error::AppError;

use crate::routing::events::event_log::{
    canonical_realm_id_for_record, effective_scope_for_envelope, event_visible_to_session,
};
use crate::routing::spaces::space::{realm_event_visible_to_session, realm_has_member};
use crate::state::{AppState, EventNotification};

struct NormalizedReadReceipt {
    event_id: String,
    read_scope: Value,
    receipt: Value,
    created_at: DateTime<Utc>,
}

pub(crate) async fn relay_ephemeral_read_receipt(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    visibility: &str,
    envelope: &arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
) -> Result<(), AppError> {
    let normalized = normalize_read_receipt_payload(realm_id, envelope)?;
    let target = state
        .event_queries()
        .canonical_event(&normalized.event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::invalid_param("ak.receipt.read target event not found"))?;
    if canonical_realm_id_for_record(&target).as_deref() != Some(realm_id) {
        return Err(AppError::invalid_param(
            "ak.receipt.read target event belongs to another realm",
        ));
    }
    if !target_event_visible_to_session(state, &target, Some(session)).await {
        return Err(AppError::capability_denied(
            "ak.receipt.read target event is not visible to the actor",
        ));
    }
    state
        .projections()
        .observe_message_read_for_expiry(
            &session.actor,
            &normalized.event_id,
            &arkret_canonical::format_timestamp_canonical(normalized.created_at),
            normalized.created_at,
        );

    let record = ReadReceiptState {
        realm_id: realm_id.to_owned(),
        actor_id: session.actor.clone(),
        sender_device: Some(envelope.device_id.to_string()),
        event_id: normalized.event_id,
        read_scope: normalized.read_scope,
        target_actor: Some(target.actor_id.clone()),
        visibility: visibility.to_owned(),
        receipt: normalized.receipt,
        envelope: envelope.clone(),
        created_at: normalized.created_at,
        expires_at: envelope.expires_at,
        position: 0,
    };
    if let Err(error) = state
        .deliveries()
        .store_read_receipt(record)
        .await
    {
        tracing::error!(%error, "failed to relay ephemeral ak.receipt.read");
        return Err(AppError::internal(
            "failed to relay ak.receipt.read for realm sync",
        ));
    }
    let _ = state.publish_event_notification(EventNotification::ephemeral(
        realm_id.to_owned(),
        "ak.receipt.read",
    ));
    Ok(())
}

fn normalize_read_receipt_payload(
    realm_id: &str,
    envelope: &arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
) -> Result<NormalizedReadReceipt, AppError> {
    let payload = envelope.payload.clone();
    let event_id = {
        let object = &payload;

        require_string_field(
            object,
            "receipt_type",
            arkret_wire::constants::READ_RECEIPT_TYPE,
        )?;
        require_string_field(
            object,
            "schema",
            arkret_wire::constants::READ_RECEIPT_SCHEMA,
        )?;
        require_string_field(object, "realm_id", realm_id)?;
        require_string_field(object, "actor_id", envelope.actor_id.as_str())?;
        object
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AppError::invalid_param("ak.receipt.read payload requires event_id"))?
            .to_owned()
    };

    let receipt: ReadReceipt = serde_json::from_value(Value::Object(
        payload.clone().into_iter().collect(),
    ))
    .map_err(|error| {
        AppError::invalid_param(format!("ak.receipt.read payload is malformed: {error}"))
    })?;
    if !receipt.read_scope.kind.valid_for_read_receipt() {
        return Err(AppError::invalid_param(
            "ak.receipt.read read_scope.kind is not valid for read receipts",
        ));
    }
    receipt.read_scope.validate().map_err(|error| {
        AppError::invalid_param(format!("ak.receipt.read read_scope is malformed: {error}"))
    })?;

    Ok(NormalizedReadReceipt {
        event_id,
        read_scope: serde_json::to_value(&receipt.read_scope).map_err(|error| {
            AppError::internal(format!("read_scope serialization failed: {error}"))
        })?,
        receipt: Value::Object(payload.into_iter().collect()),
        created_at: receipt.created_at,
    })
}

fn require_string_field(
    object: &BTreeMap<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), AppError> {
    let Some(value) = object.get(field).and_then(Value::as_str) else {
        return Err(AppError::invalid_param(format!(
            "ak.receipt.read payload.{field} must be a string"
        )));
    };
    if value != expected {
        return Err(AppError::invalid_param(format!(
            "ak.receipt.read payload.{field} does not match envelope"
        )));
    }
    Ok(())
}

pub(crate) async fn deliver_read_receipt_envelopes_for_subscriber(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
    full_sync: bool,
) -> Vec<arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope> {
    let records =
        pending_read_receipt_records_for_subscriber(state, realm_id, session, full_sync).await;
    if let (Some(session), Some(max_position)) =
        (session, records.iter().map(|record| record.position).max())
    {
        let _ = state
            .deliveries()
            .advance_read_receipt_watermark(
                &session.actor,
                &session.device_id,
                realm_id,
                max_position,
            )
            .await;
    }
    records.into_iter().map(|record| record.envelope).collect()
}

async fn pending_read_receipt_records_for_subscriber(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
    full_sync: bool,
) -> Vec<ReadReceiptState> {
    let now = Utc::now();
    let watermark = if full_sync {
        0
    } else if let Some(session) = session {
        state
            .deliveries()
            .read_receipt_watermark(&session.actor, &session.device_id, realm_id)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let mut visible = Vec::new();
    for record in state
        .deliveries()
        .read_receipts_for_realm(realm_id)
        .await
        .unwrap_or_default()
    {
        if record.expires_at <= now || record.position <= watermark {
            continue;
        }
        if read_receipt_relay_visible_to_session(state, &record, session, None).await {
            visible.push(record);
        }
    }
    visible
}

pub(crate) async fn visible_read_receipts_for_event(
    state: &AppState,
    target: &CanonicalEventRecord,
    session: &SessionRecord,
) -> Vec<Value> {
    let now = Utc::now();
    let mut visible = Vec::new();
    for record in state
        .deliveries()
        .read_receipts_for_event(&target.event_id)
        .await
        .unwrap_or_default()
    {
        if record.expires_at <= now {
            continue;
        }
        if read_receipt_relay_visible_to_session(state, &record, Some(session), Some(target)).await
        {
            visible.push(record.receipt);
        }
    }
    visible
}

async fn read_receipt_relay_visible_to_session(
    state: &AppState,
    record: &ReadReceiptState,
    session: Option<&SessionRecord>,
    target_hint: Option<&CanonicalEventRecord>,
) -> bool {
    if record.expires_at <= Utc::now() {
        return false;
    }
    match record.visibility.as_str() {
        "private" => session
            .is_some_and(|session| record.target_actor.as_deref() == Some(session.actor.as_str())),
        "members" => {
            let Some(session) = session else {
                return false;
            };
            if !active_realm_member(state, &record.realm_id, &session.actor).await {
                return false;
            }
            if !read_scope_visible_to_session(state, &record.read_scope, session, record.created_at)
            {
                return false;
            }
            target_record_visible_to_session(state, record, Some(session), target_hint).await
        }
        "public" => {
            if let Some(session) = session {
                if !read_scope_visible_to_session(
                    state,
                    &record.read_scope,
                    session,
                    record.created_at,
                ) {
                    return false;
                }
            } else if read_scope_circle_id(state, &record.read_scope).is_some() {
                return false;
            }
            target_record_visible_to_session(state, record, session, target_hint).await
        }
        _ => false,
    }
}

async fn target_record_visible_to_session(
    state: &AppState,
    record: &ReadReceiptState,
    session: Option<&SessionRecord>,
    target_hint: Option<&CanonicalEventRecord>,
) -> bool {
    let target = if let Some(target) = target_hint {
        target.clone()
    } else {
        let Some(target) = state
            .event_queries()
            .canonical_event(&record.event_id)
            .await
            .ok()
            .flatten()
        else {
            return false;
        };
        target
    };
    target_event_visible_to_session(state, &target, session).await
}

async fn target_event_visible_to_session(
    state: &AppState,
    target: &CanonicalEventRecord,
    session: Option<&SessionRecord>,
) -> bool {
    if let Some(session) = session {
        if event_visible_to_session(state, target, session).await {
            return true;
        }
        return false;
    }
    let Some(realm_id) = canonical_realm_id_for_record(target) else {
        return false;
    };
    if effective_scope_for_envelope(&target.envelope)
        .is_some_and(|scope| scope.starts_with("ak:circle:"))
    {
        return false;
    }
    realm_event_visible_to_session(
        state,
        &realm_id,
        target.received_at,
        Some(&target.actor_id),
        None,
    )
    .await
}

async fn active_realm_member(state: &AppState, realm_id: &str, actor: &str) -> bool {
    let projected_state = state
        .projections()
        .snapshot()
        .member(realm_id, actor)
        .map(|member| member.state.clone());
    if let Some(projected_state) = projected_state {
        return projected_state == "join";
    }
    realm_has_member(state, realm_id, actor).await
}

fn read_scope_visible_to_session(
    state: &AppState,
    read_scope: &Value,
    session: &SessionRecord,
    created_at: DateTime<Utc>,
) -> bool {
    let Some(circle_id) = read_scope_circle_id(state, read_scope) else {
        return true;
    };
    state
        .projections()
        .snapshot()
        .circle_scope_visible_to_actor_at(&circle_id, &session.actor, created_at)
}

fn read_scope_circle_id(state: &AppState, read_scope: &Value) -> Option<String> {
    if read_scope.get("kind").and_then(Value::as_str) != Some(ReadScopeKind::Strand.as_str()) {
        return None;
    }
    let strand_id = read_scope.get("object_ref").and_then(Value::as_str)?;
    state
        .projections()
        .snapshot()
        .strand_scope_circle_id(strand_id)
}

