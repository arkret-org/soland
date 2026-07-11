use super::*;

/// Build one snapshot of the account-aggregate sync response for the next
/// `ak.self.account.stream.subscribe` delta frame.
pub(crate) async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
    include_presence_delta: bool,
) -> arkret_sdk::models::SyncOutcome {
    let filter_value = sync_filter_value(body.filter.as_ref());
    // SYNC-MEM-1 + ROST-SOL-1..3 (arkret-spec @ b56cab1) — `members[]` is
    // the per-Realm roster v2 projection from
    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
    // row carries `{actor_id, membership, subject_id?, identity_event_ids?,
    // member_display_state_digest?, identity_events?, handle_claim_digests?,
    // handle_claims?, handle_claims_limited?}` — `handle` / display name MUST
    // NOT appear here. Identity is resolved by following
    // `identity_event_ids[]` into the separately delivered
    // `ak.member.identity.update` event log; servers that lack the events for
    // the client SHOULD inline them via `identity_events[]` (gated on
    // `subject_id` disclosure).
    let candidate_realms: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut visible_realms: Vec<(String, String, Option<String>, _, Option<String>, _)> =
        Vec::new();
    for realm_entry in &candidate_realms {
        if realm_visible_to(state, realm_entry, session).await {
            let members = roster_members_for_realm(state, realm_entry, session, body);
            visible_realms.push((
                realm_entry.realm_id.to_string(),
                realm_entry.title.clone(),
                realm_entry.description.clone(),
                realm_entry.tags.clone(),
                realm_entry.category.clone(),
                members,
            ));
        }
    }
    // Compute "left after last cursor" so incremental syncs can prune
    // client-side caches without forcing a full account baseline.
    // On full sync (no `after` cursor -> empty `after_cursor.positions`)
    // there is nothing to compare against; the client already treats
    // omission from `realms` as authoritative there.
    let visible_realm_ids: BTreeSet<&str> =
        visible_realms.iter().map(|(id, ..)| id.as_str()).collect();
    let left_realms: Vec<String> = if body.after.is_some() {
        after_cursor
            .positions
            .keys()
            .filter(|id| !visible_realm_ids.contains(id.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    drop(visible_realm_ids);

    let mut visible_actors = BTreeSet::new();
    for (_, _, _, _, _, members) in &visible_realms {
        for member in members {
            if let Some(actor) = roster_member_actor_id(member) {
                visible_actors.insert(actor);
            }
        }
    }
    if let Some(session) = session {
        visible_actors.insert(session.actor.clone());
    }
    let presence = if body.after.is_none() || include_presence_delta {
        presence_events_for_actors(state, visible_actors.clone(), session).await
    } else {
        Vec::new()
    };
    let (device_lists, device_list_positions) = device_lists_for_actors(
        state,
        session,
        &visible_actors,
        after_cursor,
        body.after.is_some(),
    )
    .await;

    // Clone the projection so the per-Realm loop below can `.await` async
    // visibility/timeline helpers without holding the (non-Send) lock guard
    // across a suspension point.
    let projection = state.projection.lock().clone();
    let mut sync_realms = std::collections::BTreeMap::new();
    let mut timeline_positions = BTreeMap::new();
    let mut account_positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    let (invite_notifications, invite_positions) =
        pending_invite_notification_delta(state, session, after_cursor, is_incremental).await;
    let (mut account_notifications, notification_positions) =
        persisted_notification_delta(state, session, after_cursor, is_incremental, &projection)
            .await;
    account_notifications.extend(invite_notifications);
    account_notifications.sort_by(|left, right| {
        let left_timestamp = left
            .get("timestamp")
            .or_else(|| left.get("created_at"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let right_timestamp = right
            .get("timestamp")
            .or_else(|| right.get("created_at"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        left_timestamp.cmp(right_timestamp).then_with(|| {
            left.get("notification_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(
                    right
                        .get("notification_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
        })
    });
    for (realm_id, title, summary, tags, category, members) in visible_realms {
        let strand =
            strand_projection_for_realm(state, &realm_id, &title, summary.as_deref()).await;
        let strand_state_after = strand.clone();
        let strand_list_item = strand.clone();
        let summary_members = members.clone();
        let meta = state
            .persistence
            .realm_meta()
            .get(&realm_id)
            .await
            .ok()
            .flatten();
        let history_visibility = meta
            .as_ref()
            .map(|record| record.history_visibility.clone())
            .unwrap_or_else(|| "shared".to_owned());
        let encryption_profile = meta
            .as_ref()
            .and_then(|record| record.encryption_profile.clone())
            .unwrap_or_else(|| "none".to_owned());
        // §2.10 content scheme (capability axis) — projected from the
        // `ak.component.realm.policy_components.v1` cell. Surfaced top-level so
        // the client encrypt path can read the realm's declared scheme and
        // author content as `mls-exporter-aead-v1` (history-shareable) vs the
        // forward-secret `mls-rfc9420`. `None` ⇒ field is null ⇒ client treats
        // it as the `mls-rfc9420` default (legacy realms predate the field).
        let content_scheme = projection.realm_content_scheme(&realm_id);
        let known_timeline_to_cursor = after_cursor.positions.contains_key(&realm_id);
        let known_account_to_cursor = after_cursor.account_positions.contains_key(&realm_id);
        let after_timeline_position = after_cursor
            .positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let after_account_position = after_cursor
            .account_positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, timeline_position) = timeline_events_for_realm(
            state,
            &projection,
            &realm_id,
            after_timeline_position,
            session,
        )
        .await;
        let (state_events, state_position) =
            state_events_for_realm(state, &realm_id, after_account_position, session).await;
        let account_position =
            account_realm_projection_position(meta.as_ref(), &realm_id).max(state_position);
        timeline_positions.insert(realm_id.clone(), timeline_position);
        account_positions.insert(realm_id.clone(), account_position);
        let account_projection_changed = if known_account_to_cursor {
            account_position != after_account_position
        } else {
            account_position > after_timeline_position
        };
        // Incremental sync skips realms whose visible account-aggregate
        // projection is unchanged. This drops the always-full
        // `summary`/`strands`/`state_after`/`members` baseline from idle polls
        // while still minting a cursor that advances internal frontiers.
        //
        // Timeline and account projection positions are separate cursor
        // vectors. Visible timeline events drive `positions.realms`; Realm /
        // Strand metadata drives `positions.account_realms`. Keeping them
        // separate prevents a metadata-only position from masking a later
        // visible timeline event, and lets hidden timeline advancement move
        // the cursor without emitting an empty Realm projection.
        //
        // Caveats: membership changes that don't bump a projection position
        // (e.g. raw `ak.realm.member.update` events) will not propagate through
        // an incremental sync until either (a) a new timeline event arrives,
        // or (b) the client issues a full sync (no `after`). This is a known
        // limitation — see follow-up TODO to add per-realm activity tracking
        // off `event_broadcast`.
        if is_incremental
            && known_timeline_to_cursor
            && timeline_events.is_empty()
            && state_events.is_empty()
            && !account_projection_changed
            && !has_pending_call_signals_for_subscriber(state, &realm_id, session, !is_incremental)
                .await
            && !has_pending_typing_for_subscriber(state, &realm_id, session).await
            && !has_pending_read_receipts_for_subscriber(state, &realm_id, session, !is_incremental)
                .await
        {
            continue;
        }
        let bottom_cells = bottom_cells_for_realm(&projection, &realm_id);
        let seal_view = seal_view_for_realm(&bottom_cells);
        let mut ephemeral =
            typing_ephemeral_for_realm(state, &realm_id, session, !is_incremental).await;
        ephemeral.extend(
            read_receipt_ephemeral_for_realm(state, &realm_id, session, !is_incremental).await,
        );
        sync_realms.insert(
            realm_id.clone(),
            json!({
                "summary": {
                    "strand": strand,
                    "title": title,
                    "summary": summary,
                    "tags": tags,
                    "category": category,
                    "members": summary_members,
                    // SYNC-MEM-2/4 — mirror `members_limited` so the two
                    // `members` views stay byte-equal.
                    "members_limited": false,
                    "history_visibility": history_visibility.clone(),
                    "encryption_profile": encryption_profile.clone(),
                    "content_scheme": content_scheme.clone(),
                },
                "history_visibility": history_visibility,
                "encryption_profile": encryption_profile,
                "content_scheme": content_scheme,
                "members": members,
                // SYNC-MEM-2 (arkret-spec @ 7157ee8) — `members_limited`
                // is always `false` until lazy-load truncation lands; the
                // spec requires the flag to be present so clients can tell
                // a small roster from a truncated one.
                "members_limited": false,
                "strands": [strand_list_item],
                "timeline": {"events": timeline_events, "limited": false},
                "state": {"events": state_events, "limited": false},
                "state_after": {"events": [strand_state_after]},
                "bottom_cells": bottom_cells,
                "seal_view": seal_view,
                "ephemeral": ephemeral,
                "unread": {"notification_count": 0, "highlight_count": 0}
            }),
        );
    }
    drop(projection);
    merge_account_position_max(&mut account_positions, invite_positions);
    merge_account_position_max(&mut account_positions, notification_positions);

    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let mut to_device_lost = None;
    let to_device = if let Some(session) = session {
        let device_messages = state.persistence.device_messages();
        if let Err(error) = prune_device_messages_for_limits(state).await {
            tracing::error!(%error, "failed to prune to-device messages during sync snapshot");
        }
        let lost_watermark = match device_messages
            .lost_watermark(&session.actor, &session.device_id)
            .await
        {
            Ok(watermark) => watermark,
            Err(error) => {
                tracing::error!(%error, "failed to read to-device lost watermark during sync snapshot");
                None
            }
        };
        if lost_watermark.is_some_and(|position| position > after_cursor.to_device_position) {
            to_device_lost = Some(true);
            if let Some(lost_watermark) = lost_watermark {
                to_device_position = to_device_position.max(lost_watermark);
            }
        }
        let queued = device_messages
            .list_after(&session.actor, &session.device_id, 0)
            .await
            .unwrap_or_default();
        to_device_limited = queued.len() > TO_DEVICE_PAGE_LIMIT;
        let page = queued
            .into_iter()
            .take(TO_DEVICE_PAGE_LIMIT)
            .collect::<Vec<_>>();
        let events = device_message_envelopes_after(&page)
            .into_iter()
            .filter_map(|message| serde_json::to_value(message).ok())
            .collect::<Vec<_>>();
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = to_device_position.max(max_position);
            to_device_ack_token = state
                .persistence
                .device_messages()
                .issue_ack_token(&session.actor, &session.device_id, max_position)
                .await
                .ok()
                .flatten();
            if to_device_limited {
                to_device_next_cursor = Some(
                    sync_token_for_client_sync(
                        state,
                        Some(session),
                        filter_value.as_ref(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        to_device_position,
                    )
                    .await,
                );
            }
        }
        events
    } else {
        Vec::new()
    };

    // Actor-private account data: hydrate every `(actor, data_type)` row
    // owned by the authenticated session so the client can join e.g.
    // `ak.contacts.realm.<realm_id>` Realm remarks against the public
    // Realm title during render. Spec: discovery/client-preferences.md
    // §2 (storage model) / §3.7 (Realm remarks).
    let account_data = if let Some(session) = session {
        state
            .persistence
            .account_data()
            .list_for_actor(&session.actor)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|record| {
                json!({
                    "data_type": record.data_type,
                    "content": record.payload,
                    "updated_at": record.updated_at,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    arkret_sdk::models::SyncOutcome {
        cursor: sync_token_for_client_sync(
            state,
            session,
            filter_value.as_ref(),
            timeline_positions,
            account_positions,
            device_list_positions,
            to_device_position,
        )
        .await,
        realms: sync_realms,
        left_realms,
        to_device,
        to_device_ack_token,
        to_device_limited,
        to_device_next_cursor,
        to_device_lost,
        device_lists,
        account_data,
        presence,
        notifications: notifications_delta_value(account_notifications),
        partial: false,
    }
}

fn merge_account_position_max(
    account_positions: &mut BTreeMap<String, i64>,
    incoming: BTreeMap<String, i64>,
) {
    for (realm_id, position) in incoming {
        account_positions
            .entry(realm_id)
            .and_modify(|current| *current = (*current).max(position))
            .or_insert(position);
    }
}

fn notifications_delta_value(events: Vec<Value>) -> Value {
    if events.is_empty() {
        Value::Null
    } else {
        json!({ "events": events })
    }
}

async fn persisted_notification_delta(
    state: &AppState,
    session: Option<&SessionRecord>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
    projection: &ProjectionState,
) -> (Vec<Value>, BTreeMap<String, i64>) {
    let Some(session) = session else {
        return (Vec::new(), BTreeMap::new());
    };
    let mut positions: BTreeMap<String, i64> = BTreeMap::new();
    let mut notifications = Vec::new();
    let rows = state
        .persistence
        .notifications()
        .list_for_recipient(&session.actor)
        .await
        .unwrap_or_default();
    for row in rows {
        let Some(realm_id) = row.get("realm_id").and_then(Value::as_str) else {
            continue;
        };
        if !realm_id_accessible(state, realm_id, Some(session)).await {
            continue;
        }
        let position = notification_projection_position(&row);
        positions
            .entry(realm_id.to_owned())
            .and_modify(|current| *current = (*current).max(position))
            .or_insert(position);
        if is_incremental
            && after_cursor
                .account_positions
                .get(realm_id)
                .is_some_and(|after| position <= *after)
        {
            continue;
        }
        let Some(source) =
            notification_source_value(state, projection, realm_id, &row, session).await
        else {
            continue;
        };
        if let Some(notification) = notification_value_from_row(&row, &source) {
            notifications.push(notification);
        }
    }
    (notifications, positions)
}

fn notification_projection_position(notification: &Value) -> i64 {
    let notification_id = notification
        .get("notification_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let created_at = notification
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
        .unwrap_or_else(now);
    timestamp_position_with_tie_breaker(created_at, notification_id)
}

async fn notification_source_message_value(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    source_event_id: &str,
    session: &SessionRecord,
) -> Option<Value> {
    if let Some(message) = projection.messages.get(source_event_id) {
        if message.realm_id != realm_id {
            return None;
        }
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            Some(session),
        )
        .await
        {
            return None;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            Some(session),
            Some(&message.sender),
        ) {
            return None;
        }
        let mut event = sync_timeline_message_json_with_projection(message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
        }
        return Some(event);
    }

    let message = state
        .persistence
        .messages()
        .get(source_event_id)
        .await
        .ok()
        .flatten()?;
    if message.realm_id != realm_id {
        return None;
    }
    let event_received_at =
        timeline_event_received_at(state, &message.event_id, message.created_at).await;
    if !realm_event_visible_to_session_with_projection(
        state,
        projection,
        realm_id,
        event_received_at,
        Some(&message.sender),
        Some(session),
    )
    .await
    {
        return None;
    }
    if !circle_scope_visible_to_session(
        projection,
        message_scope_circle_id(&message.content),
        event_received_at,
        Some(session),
        Some(&message.sender),
    ) {
        return None;
    }
    let mut event = sync_timeline_message_record_json_with_projection(&message, projection);
    if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
        tombstone_timeline_event_for_retention(&mut event, &tombstone);
    }
    Some(event)
}

async fn notification_source_value(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    notification: &Value,
    session: &SessionRecord,
) -> Option<Value> {
    let notification_type = notification
        .get("notification_type")
        .and_then(Value::as_str)
        .unwrap_or("message");
    let Some(source_event_id) = notification.get("source_event_id").and_then(Value::as_str) else {
        return None;
    };
    if matches!(
        notification_type,
        "message" | "mention" | "reply" | "reaction"
    ) {
        return notification_source_message_value(
            state,
            projection,
            realm_id,
            source_event_id,
            session,
        )
        .await;
    }
    notification_source_projection_value(state, projection, realm_id, notification, session).await
}

async fn notification_source_projection_value(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    notification: &Value,
    session: &SessionRecord,
) -> Option<Value> {
    let source_event_id = notification.get("source_event_id")?.as_str()?;
    let strand_id = notification.get("strand_id").and_then(Value::as_str);
    if let Some(strand_id) = strand_id {
        let strand = projection.strands.get(strand_id)?;
        if strand.realm_id != realm_id {
            return None;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            strand.created_at,
            Some(&strand.created_by),
            Some(session),
        )
        .await
        {
            return None;
        }
        if !circle_scope_visible_to_session(
            projection,
            strand.scope_circle_id.as_deref(),
            strand.created_at,
            Some(session),
            Some(&strand.created_by),
        ) {
            return None;
        }
    }
    let mut source = json!({
        "event_id": source_event_id,
        "realm_id": realm_id,
        "event_kind": notification
            .get("event_kind")
            .and_then(Value::as_str)
            .unwrap_or("ak.notification"),
        "created_at": notification
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "encrypted": false,
    });
    if let Some(strand_id) = strand_id {
        source["strand_id"] = json!(strand_id);
    }
    if let Some(track_name) = notification.get("track_name").and_then(Value::as_str) {
        source["track_name"] = json!(track_name);
    }
    if let Some(actor_id) = notification.get("source_actor_id").and_then(Value::as_str) {
        source["sender"] = json!(actor_id);
    }
    Some(source)
}

fn notification_value_from_row(notification: &Value, source: &Value) -> Option<Value> {
    let notification_id = notification.get("notification_id")?.as_str()?;
    let source_event_id = notification.get("source_event_id")?.as_str()?;
    let notification_type = notification
        .get("notification_type")
        .and_then(Value::as_str)
        .unwrap_or("message");
    let realm_id = notification
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| source.get("realm_id").and_then(Value::as_str))
        .unwrap_or_default();
    let strand_id = notification
        .get("strand_id")
        .and_then(Value::as_str)
        .or_else(|| source.get("strand_id").and_then(Value::as_str));
    let track_name = notification
        .get("track_name")
        .and_then(Value::as_str)
        .or_else(|| source.get("track_name").and_then(Value::as_str));
    let actor_id = notification
        .get("source_actor_id")
        .and_then(Value::as_str)
        .or_else(|| source.get("sender").and_then(Value::as_str));
    let encrypted = source
        .get("encrypted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let timestamp = notification
        .get("created_at")
        .and_then(Value::as_str)
        .or_else(|| source.get("created_at").and_then(Value::as_str))
        .unwrap_or_default();
    let mut value = json!({
        "notification_id": notification_id,
        "notification_kind": notification_type,
        "notification_type": notification_type,
        "kind": notification_type,
        "event_kind": notification
            .get("event_kind")
            .and_then(Value::as_str)
            .or_else(|| source.get("event_kind").and_then(Value::as_str))
            .unwrap_or("ak.message.create"),
        "realm_id": realm_id,
        "source_event_id": source_event_id,
        "timestamp": timestamp,
        "created_at": timestamp,
        "read": false,
        "state": "unread",
        "encrypted": encrypted,
        "local_decrypted": !encrypted,
    });
    if notification_type == "mention" {
        value["title"] = json!("You were mentioned");
        value["mentions_actor"] = json!(true);
    } else if notification_type == "assignment" {
        value["title"] = json!("You were assigned");
        value["body"] = json!("You were assigned to a Strand.");
        value["assigned_to_actor"] = json!(true);
    } else if notification_type == "schedule" {
        value["title"] = json!("Schedule updated");
        value["body"] = json!("A due date or calendar schedule changed.");
        value["schedule_target"] = json!(true);
    }
    if let Some(strand_id) = strand_id {
        value["strand_id"] = json!(strand_id);
    }
    if let Some(track_name) = track_name {
        value["track_name"] = json!(track_name);
    }
    if let Some(actor_id) = actor_id {
        value["actor_id"] = json!(actor_id);
    }
    if !encrypted
        && let Some(body) = source
            .get("content")
            .and_then(|content| content.get("body"))
            .and_then(Value::as_str)
            .filter(|body| !body.trim().is_empty())
    {
        value["body"] = json!(body);
        value["preview"] = json!(body);
    }
    Some(value)
}

pub(crate) async fn pending_invite_notification_delta(
    state: &AppState,
    session: Option<&SessionRecord>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
) -> (Vec<Value>, BTreeMap<String, i64>) {
    let Some(session) = session else {
        return (Vec::new(), BTreeMap::new());
    };
    let now = now();
    let mut positions: BTreeMap<String, i64> = BTreeMap::new();
    let mut notifications = Vec::new();
    for invite in state
        .persistence
        .realm_invites()
        .snapshot_all()
        .await
        .unwrap_or_default()
    {
        if !matches!(invite.status.as_str(), "pending" | "claimed")
            || invite.invitee.as_deref() != Some(session.actor.as_str())
            || invite
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
        {
            continue;
        }
        if crate::routing::spaces::space::realm_has_member_by_id(
            state,
            &invite.realm_id,
            &session.actor,
        )
        .await
        {
            continue;
        }
        let position = invite_projection_position(&invite);
        positions
            .entry(invite.realm_id.clone())
            .and_modify(|current| *current = (*current).max(position))
            .or_insert(position);
        if is_incremental
            && after_cursor
                .account_positions
                .get(&invite.realm_id)
                .is_some_and(|after| position <= *after)
        {
            continue;
        }
        notifications.push(invite_notification_value(&invite));
    }
    notifications.sort_by(|left, right| {
        let left_timestamp = left
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let right_timestamp = right
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default();
        left_timestamp.cmp(right_timestamp).then_with(|| {
            left.get("invite_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(
                    right
                        .get("invite_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
        })
    });
    (notifications, positions)
}

#[cfg(test)]
mod notification_projection_tests {
    use serde_json::json;

    use super::notification_value_from_row;

    #[test]
    fn assignment_notification_projects_without_message_source() {
        let row = json!({
            "notification_id": "ak:notification:01904100-0000-7000-8000-000000000001",
            "recipient_id": "did:web:bob.example",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "source_event_id": "ak:event:01904100-0000-7000-8000-000000000003",
            "source_ref": "ak:relation:01904100-0000-7000-8000-000000000004",
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000005",
            "notification_type": "assignment",
            "event_kind": "ak.relation.create",
            "source_actor_id": "did:web:alice.example",
            "created_at": "2026-07-05T00:00:00Z"
        });
        let source = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000003",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "event_kind": "ak.relation.create"
        });

        let projected = notification_value_from_row(&row, &source).unwrap();

        assert_eq!(projected["notification_type"], "assignment");
        assert_eq!(projected["event_kind"], "ak.relation.create");
        assert_eq!(projected["assigned_to_actor"], true);
        assert_eq!(projected["actor_id"], "did:web:alice.example");
    }

    #[test]
    fn schedule_notification_projects_without_message_source() {
        let row = json!({
            "notification_id": "ak:notification:01904100-0000-7000-8000-000000000006",
            "recipient_id": "did:web:bob.example",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "source_event_id": "ak:event:01904100-0000-7000-8000-000000000007",
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000005",
            "notification_type": "schedule",
            "event_kind": "ak.strand.update",
            "source_actor_id": "did:web:alice.example",
            "created_at": "2026-07-05T00:00:00Z"
        });
        let source = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000007",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "event_kind": "ak.strand.update"
        });

        let projected = notification_value_from_row(&row, &source).unwrap();

        assert_eq!(projected["notification_type"], "schedule");
        assert_eq!(projected["event_kind"], "ak.strand.update");
        assert_eq!(projected["schedule_target"], true);
        assert_eq!(
            projected["body"],
            "A due date or calendar schedule changed."
        );
    }
}

fn invite_projection_position(invite: &crate::state::RealmInviteRecord) -> i64 {
    timestamp_position_with_tie_breaker(
        invite.updated_at.unwrap_or(invite.created_at),
        &invite.invite_id,
    )
}

fn invite_notification_value(invite: &crate::state::RealmInviteRecord) -> Value {
    let timestamp = invite
        .updated_at
        .unwrap_or(invite.created_at)
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    json!({
        "notification_id": format!("invite:{}", invite.invite_id),
        "invite_id": invite.invite_id,
        "notification_kind": "invite",
        "notification_type": "invite",
        "kind": "invite",
        "title": "Realm invite",
        "body": "You were invited to join a Realm.",
        "realm_id": invite.realm_id,
        "inviter": invite.inviter,
        "timestamp": timestamp,
        "created_at": invite.created_at,
        "read": false,
    })
}

/// SYNC-MEM-1..4 + ROST-SOL-1..3 (arkret-spec @ b56cab1) — build the
/// per-Realm `members[]` roster v2 projection from the structured membership
/// FSM, the legacy in-memory `RealmDirectoryEntry`, and the MemberIdentity
/// registry.
///
/// Schema source:
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
/// row carries `{actor_id, membership, subject_id?, identity_event_ids?,
/// member_display_state_digest?, identity_events?, handle_claim_digests?,
/// handle_claims?, handle_claims_limited?}`. The retired R3 shape
/// `{did, handle_uri?}` is gone and the R3.1 roster digest field is renamed
/// to `member_display_state_digest` (R3.2). `handle` / display
/// name MUST NOT appear here; handle strings may only ride inside signed
/// `handle_claims[]`.
///
/// R3.2 dependentRequired (ROST-SOL-2): the disclosure-gated fields
/// (`subject_id` plus its companions `identity_events` / `handle_claim_digests`
/// / `handle_claims` / `handle_claims_limited`) MUST be omitted together
/// unless `subject_id` is disclosed by Realm policy. Clients resolve
/// identity by following `identity_event_ids[]` into the separately
/// delivered `ak.member.identity.update` event log; SYNC-MEM-3 inlines the
/// original envelopes only when `subject_id` is disclosed.
///
/// MIU-SOL-4: the effective set is multi-valued (no last-writer-wins); ALL
/// effective `identity_event_ids[]` are listed.
pub(super) fn roster_members_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> Vec<Value> {
    let membership_states = roster_membership_states_for_realm(state, realm_entry);
    let registry = state.member_identity_registry();
    let context =
        RosterDisclosureContext::new(state, realm_entry, session, body, &membership_states);
    membership_states
        .into_iter()
        .map(|(actor_id, membership)| {
            let actor_id = actor_id.as_str();
            let mut entry = serde_json::Map::new();
            entry.insert("actor_id".to_owned(), json!(actor_id));
            entry.insert("membership".to_owned(), json!(membership));
            if let Some(snapshot) =
                registry.snapshot_for_actor(realm_entry.realm_id.as_str(), actor_id)
            {
                if !snapshot.identity_event_ids.is_empty() {
                    entry.insert(
                        "identity_event_ids".to_owned(),
                        json!(snapshot.identity_event_ids),
                    );
                }
                // ROST-SOL-1 — roster digest field rename to
                // `member_display_state_digest`. NOT disclosure-gated.
                if let Some(digest) = snapshot.member_display_state_digest {
                    entry.insert("member_display_state_digest".to_owned(), json!(digest));
                }
                // ROST-SOL-2 — `subject_id` is disclosed only when Realm
                // policy authorizes the caller to learn the principal /
                // holder DID. When disclosed, the gated companion fields MAY
                // be populated; otherwise they MUST all be omitted (the SDK
                // `MemberRosterEntry::validate` dependentRequired rule).
                if subject_disclosed_to_caller(&context, actor_id)
                    && let Some(subject_id) = snapshot.subject_id.as_deref()
                {
                    entry.insert("subject_id".to_owned(), json!(subject_id));
                    // SYNC-MEM-3 — inline original Event envelopes (gated on
                    // subject disclosure per ROST-SOL-2). The reducer stores
                    // the events as received; we do NOT rewrite projection
                    // on egress.
                    if !snapshot.identity_events.is_empty() {
                        entry.insert(
                            "identity_events".to_owned(),
                            json!(snapshot.identity_events),
                        );
                    }
                    let visible_claims: Vec<HandleClaimEvidenceRecord> = registry
                        .handle_claims_for_subject(subject_id)
                        .into_iter()
                        .filter(|claim| handle_claim_visible_to_caller(&context, claim))
                        .collect();
                    if !visible_claims.is_empty() {
                        let digest_inputs: Vec<HandleClaimDigestInput> = visible_claims
                            .iter()
                            .map(|claim| HandleClaimDigestInput {
                                claim_digest: claim.digest.clone(),
                                binding_state: claim.binding_state.clone(),
                                expires_at: claim.expires_at.map(|expires_at| {
                                    expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)
                                }),
                            })
                            .collect();
                        if let Some(digest) = crate::state::display_state_digest(
                            realm_entry.realm_id.as_str(),
                            actor_id,
                            &snapshot.effective_entries,
                            &digest_inputs,
                        ) {
                            entry.insert("member_display_state_digest".to_owned(), json!(digest));
                        }
                        entry.insert(
                            "handle_claim_digests".to_owned(),
                            json!(
                                visible_claims
                                    .iter()
                                    .map(|claim| claim.digest.clone())
                                    .collect::<Vec<_>>()
                            ),
                        );
                        let (claims, limited) = inline_handle_claims(&visible_claims);
                        if !claims.is_empty() {
                            entry.insert("handle_claims".to_owned(), json!(claims));
                        }
                        if limited {
                            entry.insert("handle_claims_limited".to_owned(), json!(true));
                        }
                    }
                }
            }
            Value::Object(entry)
        })
        .collect()
}

fn roster_membership_states_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
) -> BTreeMap<String, String> {
    let projected_states = {
        let projection = state.projection.lock();
        projection
            .members
            .iter()
            .filter_map(|((realm_id, actor_id), membership)| {
                if realm_id == realm_entry.realm_id.as_str() {
                    Some((actor_id.clone(), membership.state.clone()))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<_, _>>()
    };
    let mut roster_states = projected_states
        .iter()
        .filter(|(_, membership)| roster_membership_is_visible(membership))
        .map(|(actor_id, membership)| (actor_id.clone(), membership.clone()))
        .collect::<BTreeMap<_, _>>();

    for did in &realm_entry.members {
        let actor_id = did.as_str().to_owned();
        if !projected_states.contains_key(&actor_id) {
            roster_states
                .entry(actor_id)
                .or_insert_with(|| "join".to_owned());
        }
    }

    roster_states
}

fn roster_membership_is_visible(membership: &str) -> bool {
    matches!(membership, "join" | "invite" | "knock")
}

struct RosterDisclosureContext<'a> {
    service_id: &'a str,
    realm_public: bool,
    caller: Option<&'a str>,
    caller_is_realm_member: bool,
    audience: String,
    now: DateTime<Utc>,
}

impl<'a> RosterDisclosureContext<'a> {
    fn new(
        state: &'a AppState,
        realm_entry: &'a RealmDirectoryEntry,
        session: Option<&'a SessionRecord>,
        body: &SyncRequestBody,
        membership_states: &BTreeMap<String, String>,
    ) -> Self {
        let caller = session.map(|session| session.actor.as_str());
        Self {
            service_id: &state.config.service_id,
            realm_public: realm_entry.public,
            caller,
            caller_is_realm_member: caller.is_some_and(|actor_id| {
                membership_states
                    .get(actor_id)
                    .is_some_and(|membership| membership == "join")
            }),
            audience: roster_handle_claim_audience(state, session, body),
            now: now(),
        }
    }

    fn caller_is_realm_member(&self) -> bool {
        self.caller_is_realm_member
    }
}

fn roster_handle_claim_audience(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> String {
    let filter_value = sync_filter_value(body.filter.as_ref());
    filter_value
        .as_ref()
        .and_then(|filter| filter.get("handle_claim_audience"))
        .or_else(|| {
            filter_value
                .as_ref()
                .and_then(|filter| filter.get("audience"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| session.map(|session| session.audience.clone()))
        .unwrap_or_else(|| state.config.service_id.clone())
}

/// ROST-SOL-2/3 — subject and companion fields disclose only when the Realm
/// policy admits the caller. Public Realms can reveal public evidence; private
/// Realms require the caller to be a member. A caller may always see their own
/// subject binding.
fn subject_disclosed_to_caller(context: &RosterDisclosureContext<'_>, actor_id: &str) -> bool {
    context.caller == Some(actor_id) || context.realm_public || context.caller_is_realm_member()
}

fn handle_claim_visible_to_caller(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    if !trusted_handle_claim_issuer(context, claim) {
        return false;
    }
    if claim.revoked || claim.binding_state != "verified" {
        return false;
    }
    if claim
        .expires_at
        .is_some_and(|expires_at| expires_at <= context.now)
    {
        return false;
    }
    if claim
        .audience
        .as_deref()
        .is_some_and(|audience| audience != context.audience)
    {
        return false;
    }
    match claim.visibility.as_deref().unwrap_or("restricted") {
        "public" => subject_disclosed_to_caller(context, &claim.subject_id),
        "members" | "restricted" => {
            context.caller == Some(claim.subject_id.as_str()) || context.caller_is_realm_member()
        }
        _ => false,
    }
}

fn trusted_handle_claim_issuer(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    claim.issuer == context.service_id
        || claim.issuer_service_id.as_deref() == Some(context.service_id)
}

fn inline_handle_claims(claims: &[HandleClaimEvidenceRecord]) -> (Vec<Value>, bool) {
    let mut used = 0usize;
    let mut out = Vec::new();
    let mut limited = false;
    for claim in claims {
        let Ok(bytes) = serde_json::to_vec(&claim.envelope) else {
            limited = true;
            continue;
        };
        if used + bytes.len() > HANDLE_CLAIMS_INLINE_MAX_BYTES {
            limited = true;
            continue;
        }
        used += bytes.len();
        out.push(claim.envelope.clone());
    }
    (out, limited)
}

async fn timeline_events_for_realm(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionRecord>,
) -> (Vec<serde_json::Value>, i64) {
    let mut seen = BTreeSet::new();
    let mut seen_message_ids = BTreeSet::new();
    let mut newest_position = after_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_realm_including_redacted(realm_id) {
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        let position = timestamp_position_with_tie_breaker(event_received_at, &message.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !seen.insert(message.event_id.clone())
            || !seen_message_ids.insert(message.message_id.clone())
        {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        let mut event = sync_timeline_message_json_with_projection(message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
        }
        timeline_entries.push((position, event));
    }

    for message in state
        .persistence
        .messages()
        .list_for_realm(realm_id, 100)
        .await
        .unwrap_or_default()
    {
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        let position = timestamp_position_with_tie_breaker(event_received_at, &message.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !seen.insert(message.event_id.clone())
            || !seen_message_ids.insert(message.message_id.clone())
        {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        let mut event = sync_timeline_message_record_json_with_projection(&message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
        }
        timeline_entries.push((position, event));
    }

    timeline_entries.sort_by_key(|left| left.0);
    (
        timeline_entries
            .into_iter()
            .map(|(_, event)| event)
            .collect(),
        newest_position,
    )
}

async fn state_events_for_realm(
    state: &AppState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionRecord>,
) -> (Vec<serde_json::Value>, i64) {
    let mut events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.realm_id == realm_id)
        .collect::<Vec<_>>();
    if events.is_empty() {
        events = crate::routing::events::projection::load_projected_events_from_pg(state, realm_id)
            .await
            .unwrap_or_default();
    }

    let mut seen = BTreeSet::new();
    let mut newest_position = after_position;
    let mut state_entries = Vec::new();
    for event in events {
        if event.event_kind == arkret_sdk::events::kinds::MESSAGE_CREATE {
            continue;
        }
        let position = projection_event_position(&event);
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(event.event_id.clone()) {
            continue;
        }
        if !projection_record_visible_to_session(state, &event, session).await {
            continue;
        }
        state_entries.push((position, projection_event_json(&event)));
    }
    state_entries.sort_by_key(|left| left.0);
    (
        state_entries.into_iter().map(|(_, event)| event).collect(),
        newest_position,
    )
}

fn projection_event_position(event: &crate::state::ProjectionEventRecord) -> i64 {
    timestamp_position_with_tie_breaker(event.received_at, &event.event_id)
}

fn account_realm_projection_position(meta: Option<&RealmMetaRecord>, realm_id: &str) -> i64 {
    meta.map(|record| timestamp_position_with_tie_breaker(record.updated_at, realm_id))
        .unwrap_or_default()
}

async fn device_lists_for_actors(
    state: &AppState,
    session: Option<&SessionRecord>,
    visible_actors: &BTreeSet<String>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
) -> (Value, BTreeMap<String, i64>) {
    if session.is_none() {
        return (json!({"changed": [], "left": []}), BTreeMap::new());
    }

    let mut positions = BTreeMap::new();
    let mut changed = BTreeSet::new();
    let mut left = BTreeSet::new();
    let devices = state.persistence.devices();

    for actor in visible_actors {
        let records = match devices.list_for_actor_including_revoked(actor).await {
            Ok(records) => records,
            Err(error) => {
                tracing::error!(%error, actor, "failed to load device list for sync snapshot");
                changed.insert(actor.clone());
                continue;
            }
        };
        let position = records
            .iter()
            .map(device_inventory_position)
            .max()
            .unwrap_or_default();
        positions.insert(actor.clone(), position);

        if !is_incremental {
            changed.insert(actor.clone());
            continue;
        }

        match after_cursor.device_list_positions.get(actor).copied() {
            Some(previous_position) if position <= previous_position => {}
            _ => {
                changed.insert(actor.clone());
            }
        }
    }

    if is_incremental {
        for actor in after_cursor.device_list_positions.keys() {
            if !visible_actors.contains(actor) {
                left.insert(actor.clone());
            }
        }
    }

    (
        json!({
            "changed": changed.into_iter().collect::<Vec<_>>(),
            "left": left.into_iter().collect::<Vec<_>>(),
        }),
        positions,
    )
}

fn device_inventory_position(record: &DeviceInventoryRecord) -> i64 {
    let key = format!("{}\0{}", record.actor, record.device_id);
    record
        .updated_at
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(stable_position_tie_breaker(&key))
}

fn stable_position_tie_breaker(key: &str) -> i64 {
    let digest = sha256_hex(key.as_bytes());
    i64::from_str_radix(&digest[..3], 16).unwrap_or_default() & 0x03ff
}

async fn timeline_event_received_at(
    state: &AppState,
    event_id: &str,
    created_at: DateTime<Utc>,
) -> DateTime<Utc> {
    state
        .persistence
        .events()
        .get(event_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.received_at)
        .unwrap_or(created_at)
}

pub(super) fn timestamp_position_with_tie_breaker(timestamp: DateTime<Utc>, event_id: &str) -> i64 {
    timestamp
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(timeline_event_tie_breaker(event_id))
}

fn timeline_event_tie_breaker(event_id: &str) -> i64 {
    ids::typed_uuid_part(event_id)
        .map(|uuid| ((uuid.as_u128() >> 64) & 0x03ff) as i64)
        .unwrap_or_default()
}

async fn realm_event_visible_to_session_with_projection(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    if personal_blocklist_blocks_sender_for_session(state, session, sender).await {
        return false;
    }
    match realm_history_visibility(state, realm_id).await.as_str() {
        "world_readable" => true,
        "shared" => {
            if realm_discoverability(state, realm_id).await == "public" {
                return true;
            }
            match session {
                Some(session) => realm_has_member(state, realm_id, &session.actor).await,
                None => false,
            }
        }
        "joined" | "invited" => {
            let Some(session) = session else {
                return false;
            };
            let mut joined_at = projection
                .member(realm_id, &session.actor)
                .filter(|member| member.state == "join")
                .map(|member| member.joined_at);
            if joined_at.is_none() {
                let meta = state
                    .persistence
                    .realm_meta()
                    .get(realm_id)
                    .await
                    .ok()
                    .flatten();
                if let Some(meta) = meta
                    && meta.owner == session.actor
                {
                    joined_at = Some(meta.created_at);
                }
            }
            joined_at.is_some_and(|joined_at| event_created_at >= joined_at)
        }
        _ => false,
    }
}

fn bottom_cells_for_realm(projection: &ProjectionState, realm_id: &str) -> Vec<Value> {
    projection
        .cells
        .iter()
        .filter_map(|(cell, state)| {
            let CellState::Bottom(bottom) = state else {
                return None;
            };
            let cell_id = cell.as_str();
            if !cell_id.contains(realm_id) {
                return None;
            }
            Some(json!({
                "realm_id": realm_id,
                "cell_id": cell_id,
                "state": "bottom",
                "bottom": bottom,
            }))
        })
        .collect()
}

fn seal_view_for_realm(bottom_cells: &[Value]) -> Value {
    let cells = bottom_cells
        .iter()
        .filter_map(|entry| {
            let cell_id = entry.get("cell_id").and_then(Value::as_str)?;
            let bottom = entry.get("bottom")?;
            let status = match bottom.get("kind").and_then(Value::as_str) {
                Some("Conflict") | Some("conflict") => "expose",
                _ => "reject",
            };
            let heads = bottom_heads_for_sync(bottom);
            Some((
                cell_id.to_owned(),
                json!({
                    "bottom": status,
                    "heads": heads,
                    "diagnostic": bottom,
                }),
            ))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "frontier": [],
        "leaves": [],
        "state_root": Value::Null,
        "cells": cells,
    })
}

fn bottom_heads_for_sync(bottom: &Value) -> Vec<Value> {
    if let Some(heads) = bottom.get("heads").and_then(Value::as_array)
        && !heads.is_empty()
    {
        return heads
            .iter()
            .filter_map(|head| {
                if let Some(object) = head.as_object() {
                    let move_id = object
                        .get("move_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if move_id.is_empty() {
                        return None;
                    }
                    return Some(json!({
                        "move_id": move_id,
                        "value": object.get("value").cloned().unwrap_or(Value::Null),
                    }));
                }
                let move_id = head.as_str()?;
                Some(json!({"move_id": move_id, "value": Value::Null}))
            })
            .collect();
    }
    bottom
        .get("move_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|move_id| move_id.as_str())
        .map(|move_id| json!({"move_id": move_id, "value": Value::Null}))
        .collect()
}

pub(crate) async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectionEventRecord,
    session: Option<&SessionRecord>,
) -> bool {
    if !realm_event_visible_to_session(
        state,
        &event.realm_id,
        event.received_at,
        event.sender.as_deref(),
        session,
    )
    .await
    {
        return false;
    }
    if personal_blocklist_blocks_sender_for_session(state, session, event.sender.as_deref()).await {
        return false;
    }
    let projection = state.projection.lock();
    let scope_circle_id = projection_event_scope_circle_id(&projection, event);
    circle_scope_visible_to_session(
        &projection,
        scope_circle_id.as_deref(),
        event.received_at,
        session,
        event.sender.as_deref(),
    )
}

pub(crate) async fn projection_event_value_visible_to_session(
    state: &AppState,
    event: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(realm_id) = event.get("realm_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(created_at) = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    else {
        return false;
    };
    let sender = event.get("sender").and_then(Value::as_str);
    realm_event_visible_to_session(state, realm_id, created_at, sender, session).await
        && !personal_blocklist_blocks_sender_for_session(state, session, sender).await
}

pub(crate) async fn canonical_event_visible_to_personal_blocklist(
    state: &AppState,
    record: &crate::state::CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    !personal_blocklist_blocks_sender_for_session(state, Some(session), Some(&record.actor_id))
        .await
}

async fn personal_blocklist_blocks_sender_for_session(
    state: &AppState,
    session: Option<&SessionRecord>,
    sender: Option<&str>,
) -> bool {
    let (Some(session), Some(sender)) = (session, sender) else {
        return false;
    };
    if sender == session.actor {
        return false;
    }
    for data_type in PERSONAL_BLOCKLIST_DATA_TYPES.iter() {
        match state
            .persistence
            .account_data()
            .get(&session.actor, data_type)
            .await
        {
            Ok(None) => {}
            Ok(Some(record)) => {
                return blocklist_payload_blocks_sender(&record.payload, sender);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    actor = %session.actor,
                    "failed to read personal blocklist policy"
                );
                return true;
            }
        }
    }
    false
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if payload
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let Some(entries) = payload.get("entries").and_then(Value::as_array) else {
        return false;
    };
    entries
        .iter()
        .any(|entry| blocklist_entry_blocks_sender(entry, sender))
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    let mode = entry
        .get("mode")
        .or_else(|| entry.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("block");
    if mode != "block" {
        return false;
    }
    if entry.get("expires_at").is_some_and(|expires_at| {
        expires_at.as_str().is_some_and(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .is_ok_and(|expires| expires <= chrono::Utc::now())
        })
    }) {
        return false;
    }
    let Some(target) = entry.get("target") else {
        return ["did", "actor", "id"]
            .iter()
            .any(|field| entry.get(*field).and_then(Value::as_str) == Some(sender));
    };
    if let Some(value) = target.as_str() {
        return value == sender;
    }
    let Some(object) = target.as_object() else {
        return false;
    };
    if object.get("kind").and_then(Value::as_str) != Some("actor") {
        return false;
    }
    ["did", "actor", "id"]
        .iter()
        .any(|field| object.get(*field).and_then(Value::as_str) == Some(sender))
}

fn message_scope_circle_id(content: &Value) -> Option<&str> {
    content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:circle:"))
}

fn projection_event_scope_circle_id(
    projection: &ProjectionState,
    event: &ProjectionEventRecord,
) -> Option<String> {
    if event.event_kind == arkret_sdk::events::kinds::MESSAGE_CREATE {
        return event
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .payload
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .filter(|value| value.starts_with("ak:strand:"))
            })
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id));
    }
    event
        .payload
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .payload
                .get("relation")
                .and_then(Value::as_object)
                .and_then(|relation| relation.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

fn circle_scope_visible_to_session(
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
    event_created_at: chrono::DateTime<chrono::Utc>,
    session: Option<&SessionRecord>,
    sender: Option<&str>,
) -> bool {
    let Some(scope_circle_id) = scope_circle_id else {
        return true;
    };
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    let Some(session) = session else {
        return false;
    };
    projection.circle_scope_visible_to_actor_at(scope_circle_id, &session.actor, event_created_at)
}

fn add_scope_circle_metadata(event: &mut serde_json::Value, content: &serde_json::Value) {
    let Some(scope_circle_id) = message_scope_circle_id(content) else {
        return;
    };
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert(
        "scope_circle_id".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
    object.insert(
        "effective_scope".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
}

fn sync_timeline_message_record_json(message: &crate::state::MessageRecord) -> serde_json::Value {
    // strand_id is always derived from realm_id (one strand per Realm for
    // the message timeline) — thread_id is the discussion *track* within
    // that strand, NOT the strand itself. The removed top-level `branch` object
    // was replaced by the concrete v1 `track_name` wire field.
    let strand_id = strand_id_from_realm_id(&message.realm_id);
    let track_id = message.thread_id.clone();
    let mut event = json!({
        "kind": "ak.message.create",
        "event_id": message.event_id,
        "message_id": message.message_id,
        "strand_id": strand_id,
        "realm_id": message.realm_id,
        "track_name": default_discussion_track(&strand_id, &track_id),
        "thread_id": message.thread_id,
        "actor_id": message.sender,
        "sender_actor_id": message.sender,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "plaintext" },
        "created_at": message.created_at,
    });
    add_scope_circle_metadata(&mut event, &message.content);
    event
}

fn sync_timeline_message_record_json_with_projection(
    message: &crate::state::MessageRecord,
    projection: &ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_record_json(message);
    if actor_erased_in_realm(projection, &message.sender, &message.realm_id) {
        tombstone_timeline_event_value(&mut event);
    }
    if apply_message_redaction_timeline_projection(&mut event, &message.event_id, projection) {
        return event;
    }
    augment_timeline_message_json(event, &message.event_id, &message.content, projection)
}
