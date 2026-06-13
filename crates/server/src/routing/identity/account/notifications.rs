use super::*;

#[endpoint(
    operation_id = "org.cokret.soland.notifications.list",
    tags("notifications"),
    summary = "List notifications visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.notifications.list"))]
pub(crate) async fn list_notifications(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_handle = state
        .persistence
        .accounts()
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|account| account.handle())
        .unwrap_or_else(|| handle_for_did(&session.actor));
    let last_read_at = state
        .notification_read_cursors
        .lock()
        .expect("notification_read_cursors lock")
        .get(&session.actor)
        .copied();
    // Snapshot the candidate messages off the projection lock first; the
    // visibility checks below are async and must not run while the (non-Send)
    // guard is held.
    let candidate_messages: Vec<_> = {
        let projection = state.projection.lock().expect("projection lock");
        projection
            .messages
            .values()
            .filter(|message| message.sender != session.actor)
            .cloned()
            .collect()
    };
    let mut items = Vec::new();
    for message in &candidate_messages {
        let mentions_actor = content_mentions_actor(
            &message.content,
            &message.realm_id,
            &session.actor,
            &actor_handle,
        ) || content_audience_mentions_actor(state, message, &session.actor);
        let mentioned = !content_has_explicit_mention(&message.content) || mentions_actor;
        if mentioned
            && realm_has_member(state, &message.realm_id, &session.actor).await
            && !personal_blocklist_blocks_sender(state, &session.actor, &message.sender).await
        {
            items.push(notification_from_message(
                message,
                last_read_at.as_ref(),
                mentions_actor,
            ));
        }
    }
    items.sort_by(|left, right| {
        right
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .cmp(&left.get("timestamp").and_then(serde_json::Value::as_str))
    });
    let unread_count = items
        .iter()
        .filter(|item| {
            !item
                .get("read")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    json_ok(json!({
        "items": items,
        "unread_count": unread_count,
        "last_read_at": last_read_at.map(|dt| dt.to_rfc3339()),
    }))
}

async fn personal_blocklist_blocks_sender(state: &AppState, actor: &str, sender: &str) -> bool {
    for data_type in PERSONAL_BLOCKLIST_DATA_TYPES.iter() {
        let blocked = state
            .persistence
            .account_data()
            .get(actor, data_type)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| blocklist_payload_blocks_sender(&record.payload, sender));
        if blocked {
            return true;
        }
    }
    false
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    if let Some(entries) = payload.get("blocked").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    blocklist_entry_blocks_sender(payload, sender)
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    match entry {
        Value::String(_) => blocklist_value_is_sender(entry, sender),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return false;
            }
            object
                .get("target")
                .or_else(|| object.get("did"))
                .or_else(|| object.get("actor"))
                .is_some_and(|target| blocklist_entry_target_matches_sender(target, sender))
        }
        _ => false,
    }
}

fn blocklist_entry_target_matches_sender(target: &Value, sender: &str) -> bool {
    match target {
        Value::String(_) => blocklist_value_is_sender(target, sender),
        Value::Object(object) => object
            .get("did")
            .or_else(|| object.get("actor"))
            .or_else(|| object.get("id"))
            .is_some_and(|value| blocklist_value_is_sender(value, sender)),
        _ => false,
    }
}

fn blocklist_value_is_sender(value: &Value, sender: &str) -> bool {
    value.as_str().is_some_and(|value| value == sender)
}

fn notification_from_message(
    message: &crate::reducer::MessageState,
    last_read_at: Option<&chrono::DateTime<chrono::Utc>>,
    mentions_actor: bool,
) -> serde_json::Value {
    let priority = notification_priority(&message.content);
    let notification_kind = if mentions_actor { "mention" } else { "message" };
    let read = last_read_at.is_some_and(|marker| message.created_at <= *marker);
    if message.encrypted {
        return encrypted_notification_from_message(message, notification_kind, read);
    }
    json!({
        "id": format!("ck:notification:{}", message.event_id),
        "notification_id": format!("ck:notification:{}", message.event_id),
        "event_id": message.event_id,
        "event_kind": "ck.message.create",
        "notification_type": notification_kind,
        "notification_kind": notification_kind,
        "kind": notification_kind,
        "title": if mentions_actor { "You were mentioned" } else { "New message" },
        "body": notification_body(&message.content),
        "realm_id": message.realm_id,
        "sender": message.sender,
        "sender_did": message.sender,
        "thread_id": message.thread_id,
        "timestamp": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "created_at": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "read": read,
        "mentions_actor": mentions_actor,
        "priority": priority,
        "priority_override": priority.as_deref().is_some_and(notification_priority_overrides),
        "encrypted": message.encrypted,
    })
}

fn encrypted_notification_from_message(
    message: &crate::reducer::MessageState,
    notification_kind: &str,
    read: bool,
) -> serde_json::Value {
    let mut item = json!({
        "id": format!("ck:notification:{}", message.event_id),
        "notification_id": format!("ck:notification:{}", message.event_id),
        "event_id": message.event_id,
        "event_kind": "ck.message.create",
        "notification_type": "blind_wakeup",
        "notification_kind": notification_kind,
        "kind": "blind_wakeup",
        "realm_id": message.realm_id,
        "sender_did": message.sender,
        "thread_id": message.thread_id,
        "timestamp": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "created_at": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "read": read,
        "encrypted": true,
        "privacy_mode": "blind_wakeup",
        "wakeup_kind": "encrypted_message",
        "local_decrypted": false,
    });
    if let Some(sidecar) = message.content.get("mention_sidecar_hash")
        && let Some(object) = item.as_object_mut()
    {
        object.insert("mention_sidecar_hash".to_owned(), sidecar.clone());
    }
    item
}

fn notification_body(content: &serde_json::Value) -> String {
    content
        .as_str()
        .or_else(|| {
            content
                .get("body")
                .or_else(|| content.get("text"))
                .or_else(|| content.get("summary"))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "New message".to_owned())
}

fn notification_priority(content: &serde_json::Value) -> Option<String> {
    content
        .get("priority")
        .or_else(|| content.get("notification_priority"))
        .or_else(|| {
            content
                .get("notification")
                .and_then(|notification| notification.get("priority"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn notification_priority_overrides(priority: &str) -> bool {
    matches!(priority, "critical" | "high" | "urgent" | "priority")
}

fn content_mentions_actor(
    content: &serde_json::Value,
    realm_id: &str,
    actor: &str,
    actor_handle: &str,
) -> bool {
    if content
        .get("mention_sidecar_hash")
        .is_some_and(|sidecar| mention_sidecar_targets_actor(sidecar, realm_id, actor))
    {
        return true;
    }
    let handle = actor_handle.trim();
    let handle_without_at = handle.trim_start_matches('@');
    if content
        .get("mentions")
        .is_some_and(|mentions| mention_value_targets_actor(mentions, actor, handle))
    {
        return true;
    }
    notification_body(content)
        .to_ascii_lowercase()
        .split(|ch: char| {
            !(ch.is_ascii_alphanumeric()
                || ch == ':'
                || ch == '@'
                || ch == '-'
                || ch == '_'
                || ch == '.')
        })
        .any(|token| {
            token == actor.to_ascii_lowercase()
                || (!handle.is_empty() && token == handle.to_ascii_lowercase())
                || (!handle_without_at.is_empty()
                    && token == format!("@{}", handle_without_at.to_ascii_lowercase()))
                || (!handle_without_at.is_empty()
                    && token == handle_without_at.to_ascii_lowercase())
        })
}

fn content_audience_mentions_actor(
    state: &AppState,
    message: &crate::reducer::MessageState,
    actor: &str,
) -> bool {
    let audiences = content_audience_mentions(&message.content);
    if audiences.is_empty() {
        return false;
    }
    audiences
        .iter()
        .any(|audience| audience_targets_actor(state, message, audience.as_str(), actor))
}

fn audience_targets_actor(
    state: &AppState,
    message: &crate::reducer::MessageState,
    audience: &str,
    actor: &str,
) -> bool {
    match audience {
        "effective_scope_members" => true,
        "flow_participants" => flow_participants_include_actor(state, &message.thread_id, actor),
        "flow_watchers" => flow_watchers_include_actor(state, &message.thread_id, actor),
        "flow_engaged" => {
            flow_participants_include_actor(state, &message.thread_id, actor)
                || flow_watchers_include_actor(state, &message.thread_id, actor)
        }
        "assigned_actors" => flow_assignees_include_actor(state, &message.thread_id, actor),
        _ => false,
    }
}

fn flow_participants_include_actor(state: &AppState, flow_id: &str, actor: &str) -> bool {
    state.projection.lock().ok().is_some_and(|projection| {
        projection
            .messages_for_thread(flow_id)
            .into_iter()
            .any(|message| message.sender == actor)
    })
}

fn flow_watchers_include_actor(state: &AppState, flow_id: &str, actor: &str) -> bool {
    let cell_id = format!("ck:cell:ck.component.flow.watch.v1:{flow_id}:{actor}");
    state
        .projection
        .lock()
        .ok()
        .and_then(|projection| {
            cokret_sdk::CellRef::new(cell_id)
                .ok()
                .and_then(|cell| projection.cell_value(&cell).cloned())
        })
        .is_some_and(|value| {
            if value.is_null() {
                return false;
            }
            value
                .get("level")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|level| level != "muted")
        })
}

fn flow_assignees_include_actor(state: &AppState, flow_id: &str, actor: &str) -> bool {
    state.projection.lock().ok().is_some_and(|projection| {
        projection.relations.values().any(|relation| {
            relation.relation_kind == "assigned_to"
                && relation.from_ref.as_deref() == Some(flow_id)
                && relation.to_ref.as_deref() == Some(actor)
                && relation.is_active()
        })
    })
}

fn content_audience_mentions(content: &serde_json::Value) -> Vec<String> {
    let mut audiences = Vec::new();
    collect_content_audience_mentions(content, &mut audiences);
    audiences
}

fn collect_content_audience_mentions(content: &serde_json::Value, out: &mut Vec<String>) {
    match content {
        serde_json::Value::Object(object) => {
            if object.get("kind").and_then(serde_json::Value::as_str) == Some("audience_mention") {
                if let Some(audience) = object.get("audience").and_then(serde_json::Value::as_str) {
                    out.push(audience.to_owned());
                }
                return;
            }
            for value in object.values() {
                collect_content_audience_mentions(value, out);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_content_audience_mentions(value, out);
            }
        }
        _ => {}
    }
}

fn content_has_explicit_mention(content: &serde_json::Value) -> bool {
    if content
        .get("mention_sidecar_hash")
        .is_some_and(|sidecar| !sidecar.as_array().is_some_and(Vec::is_empty))
    {
        return true;
    }
    if content
        .get("mentions")
        .is_some_and(|mentions| !mentions.as_array().is_some_and(Vec::is_empty))
    {
        return true;
    }
    if !content_audience_mentions(content).is_empty() {
        return true;
    }
    notification_body(content)
        .to_ascii_lowercase()
        .split(|ch: char| {
            !(ch.is_ascii_alphanumeric()
                || ch == ':'
                || ch == '@'
                || ch == '-'
                || ch == '_'
                || ch == '.')
        })
        .any(|token| token.starts_with('@') && token.len() > 1)
}

fn mention_sidecar_targets_actor(sidecar: &serde_json::Value, realm_id: &str, actor: &str) -> bool {
    let expected = mention_sidecar_hash(realm_id, actor);
    match sidecar {
        serde_json::Value::String(value) => value == &expected,
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|value| value == expected),
        _ => false,
    }
}

fn mention_sidecar_hash(realm_id: &str, actor: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(realm_id.as_bytes());
    hasher.update(b"|");
    hasher.update(actor.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn mention_value_targets_actor(value: &serde_json::Value, actor: &str, actor_handle: &str) -> bool {
    match value {
        serde_json::Value::String(text) => mention_token_matches(text, actor, actor_handle),
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| mention_value_targets_actor(item, actor, actor_handle)),
        serde_json::Value::Object(object) => [
            "target",
            "target_did",
            "did",
            "actor",
            "actor_id",
            "user_id",
            "handle",
        ]
        .iter()
        .any(|key| {
            object
                .get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| mention_token_matches(text, actor, actor_handle))
        }),
        _ => false,
    }
}

fn mention_token_matches(text: &str, actor: &str, actor_handle: &str) -> bool {
    let token = text.trim().to_ascii_lowercase();
    let actor = actor.to_ascii_lowercase();
    let handle = actor_handle.trim().to_ascii_lowercase();
    let handle_without_at = handle.trim_start_matches('@');
    token == actor
        || (!handle.is_empty() && token == handle)
        || (!handle_without_at.is_empty() && token == handle_without_at)
        || (!handle_without_at.is_empty() && token == format!("@{handle_without_at}"))
}

#[endpoint(
    operation_id = "org.cokret.soland.notifications.mark_all_read",
    tags("notifications"),
    summary = "Stamp the authenticated actor's `last_read_at` marker to Utc::now()"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.notifications.mark_all_read"))]
pub(crate) async fn notifications_mark_all_read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let marked_at = chrono::Utc::now();
    state
        .notification_read_cursors
        .lock()
        .expect("notification_read_cursors lock")
        .insert(session.actor.clone(), marked_at);
    append_audit_log(
        state,
        Some(&session.actor),
        "notifications.mark_all_read",
        json!({"marked_at": marked_at.to_rfc3339()}),
        "accepted",
    )
    .await;
    fanout_actor_private_update(
        state,
        &session.actor,
        &session.device_id,
        NOTIFICATION_READ_MARKER_UPDATE_TYPE,
        json!({
            "actor_id": session.actor,
            "device_id": session.device_id,
            "marked_at": marked_at,
        }),
    )
    .await;
    json_ok(json!({
        "marked_at": marked_at.to_rfc3339(),
        "actor": session.actor,
    }))
}
