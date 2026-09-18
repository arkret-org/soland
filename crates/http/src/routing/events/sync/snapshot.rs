use super::*;

fn session_actor(state: &AppState, session: &SessionIdentityState) -> Option<arkret_wire::ActorId> {
    crate::routing::identity::session_actor::session_actor_from_credential(state, session).ok()
}

/// Build one snapshot of the account-aggregate sync response for the next
/// `ak.self.account.stream.subscribe.v1` delta frame.
pub(crate) async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    if after_cursor.detail_turn {
        if let Some(frame) = current_details::frame(state, session, body, after_cursor).await {
            return frame;
        }
    }
    let filter_value = sync_filter_value(body.filter.as_ref());
    let summary_delta = if let Some(session) = session {
        match demand_list::read(state, session, body, after_cursor).await {
            Ok(delta) => Some(delta),
            Err(error) => {
                tracing::warn!(%error, "account summary snapshot unavailable");
                return serde_json::from_value(json!({"kind": "resync_required"}))
                    .expect("closed resync control frame");
            }
        }
    } else {
        None
    };

    let timeline_positions = after_cursor.positions.clone();
    let account_positions = after_cursor.account_positions.clone();
    let global = if let Some(session) = session {
        match global_channels::read(
            state,
            session,
            after_cursor,
            summary_delta
                .as_ref()
                .and_then(|delta| delta.initial_global_snapshot),
        )
        .await
        {
            Ok(delta) => delta,
            Err(error) => {
                tracing::error!(%error, "account global slice unavailable");
                return serde_json::from_value(json!({"kind":"resync_required"}))
                    .expect("resync frame");
            }
        }
    } else {
        return serde_json::from_value(json!({"kind":"unauthorized"})).expect("unauthorized frame");
    };
    let sync_realms = BTreeMap::new();
    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let mut to_device_lost = None;
    let to_device = if let Some(session) = session {
        if let Err(error) = prune_device_messages_for_limits(state).await {
            tracing::error!(%error, "failed to prune to-device messages during sync snapshot");
        }
        let lost_watermark = match state
            .deliveries()
            .device_message_lost_watermark(&session.actor, &session.device_id)
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
        let queued = state
            .deliveries()
            .device_messages_after(&session.actor, &session.device_id, 0, 101)
            .await
            .unwrap_or_default();
        let queued_count = queued.len();
        let mut page = Vec::new();
        let mut page_bytes = 0usize;
        for message in queued.into_iter().take(100) {
            let bytes = arkret_canonical::canonical_json_bytes(&message.content)
                .map_or(usize::MAX, |value| value.len());
            if page_bytes.saturating_add(bytes) > 512 * 1024 {
                break;
            }
            page_bytes += bytes;
            page.push(message);
        }
        to_device_limited = page.len() < queued_count;
        let events = device_message_envelopes_after(state, &page);
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = to_device_position.max(max_position);
            to_device_ack_token = state
                .deliveries()
                .issue_device_message_ack_token(&session.actor, &session.device_id, max_position)
                .await
                .ok()
                .flatten();
            if to_device_limited {
                to_device_next_cursor = Some(
                    cursor::device_messages_cursor(state, session, to_device_position)
                        .await
                        .unwrap_or_else(|error| {
                            tracing::error!(?error, "device queue continuation unavailable");
                            String::new()
                        }),
                );
            }
        }
        if to_device_limited && to_device_next_cursor.is_none() {
            to_device_next_cursor = Some(
                cursor::device_messages_cursor(state, session, to_device_position)
                    .await
                    .unwrap_or_else(|error| {
                        tracing::error!(?error, "device queue continuation unavailable");
                        String::new()
                    }),
            );
        }
        events
    } else {
        Vec::new()
    };

    if to_device_next_cursor.as_ref().is_some_and(String::is_empty) {
        return serde_json::from_value(json!({"kind":"resync_required"})).expect("resync frame");
    }

    let cursor = cursor::sync_token_for_account_positions(
        state,
        session,
        filter_value.as_ref(),
        timeline_positions,
        account_positions,
        to_device_position,
        summary_delta
            .as_ref()
            .map_or(after_cursor.account_summary_position, |delta| {
                delta.position
            }),
        Some(global.context),
        after_cursor.detail_positions.clone(),
        true,
        after_cursor.detail_next_realm.clone(),
    )
    .await;
    let cursor = match cursor {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::error!(?error, "account continuation unavailable");
            return serde_json::from_value(json!({"kind":"resync_required"}))
                .expect("resync frame");
        }
    };
    let summary_advanced = summary_delta
        .as_ref()
        .is_some_and(|delta| delta.position > after_cursor.account_summary_position);
    let response=arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        realm_list: summary_delta.as_ref().and_then(|delta| delta.page.clone()),
        realm_list_changes: summary_delta.as_ref().and_then(|delta| delta.changes.clone()),
        realm_invalidations: summary_delta.and_then(|delta| delta.invalidations),
        baseline: global.baseline,
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta,
        cursor: Some(cursor),
        realms: Some(arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeRealms {
            entries: sync_realms,
        }),
        to_device: Some(arkret_models_collaboration::sync_frames::account_subscribe::DeviceMessageContainer {
            messages: to_device,
            ack_token: to_device_ack_token,
            lost: to_device_lost,
            limited: to_device_limited.then_some(true),
            next_cursor: to_device_next_cursor,
            extra: BTreeMap::new(),
        }),
        device_lists: Some(global.device_lists),
        account_data: Some(global.account_data),
        notifications: Some(global.notifications),
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    };
    if (summary_advanced
        || (!after_cursor.detail_turn
            && body
                .filter
                .as_ref()
                .and_then(|filter| filter.realm_ids.as_ref())
                .is_some_and(|realms| !realms.is_empty())))
        && subscribe::delta_is_empty(&response)
    {
        serde_json::from_value(json!({"kind":"frontier","cursor":response.cursor}))
            .expect("detail scheduling frontier")
    } else {
        response
    }
}

pub(crate) async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectedEvent,
    session: Option<&SessionIdentityState>,
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
    let projection = state.projections().snapshot();
    let sidecar_id = match &event.event_kind {
        arkret_wire::EventKind::SidecarCreate => event
            .event_id
            .strip_prefix("ak:event:")
            .map(|event_token| format!("ak:sidecar:{event_token}")),
        arkret_wire::EventKind::SidecarContextAttach
        | arkret_wire::EventKind::AgentSidecarExchangeControl => event
            .payload
            .get("sidecar_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        // Remaining sidecar-bearing kinds are the MLS events, whose payloads
        // name the binding `governance_binding` (`mls_governance_binding` is a
        // profile / reason-code prefix, never a payload field).
        _ => crate::routing::mls::payload_fields::governance_binding(&event.payload)
            .and_then(|binding| binding.get("sidecar_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    };
    if let Some(sidecar_id) = sidecar_id {
        return session.is_some_and(|session| {
            projection.sidecars.get(&sidecar_id).is_some_and(|sidecar| {
                session_actor(state, session).is_some_and(|actor| {
                    actor.as_account_id() == Some(&sidecar.controller_account_id)
                })
            })
        });
    }
    let scope_circle_id = projection_event_scope_circle_id(&projection, event);
    circle_scope_visible_to_session(
        state,
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
    session: Option<&SessionIdentityState>,
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
}

fn projection_event_scope_circle_id(
    projection: &ProjectionState,
    event: &ProjectedEvent,
) -> Option<String> {
    if event.event_kind == arkret_wire::EventKind::MessageCreate {
        return event
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id));
    }
    let explicit_scope = event
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
        .map(ToOwned::to_owned);
    if explicit_scope.is_some() {
        return explicit_scope;
    }
    if event.event_kind == arkret_wire::EventKind::RelationCreate {
        let relation = event.payload.get("relation").and_then(Value::as_object);
        return relation
            .and_then(|value| value.get("from_ref"))
            .and_then(Value::as_str)
            .or_else(|| {
                relation
                    .and_then(|value| value.get("to_ref"))
                    .and_then(Value::as_str)
            })
            .and_then(|object_ref| {
                projection
                    .strand_scope_circle_id(object_ref)
                    .or_else(|| projection.relation_scope_circle_id(object_ref))
                    .or_else(|| projection.morph_scope_circle_id(object_ref))
                    .or_else(|| projection.space_container_scope_circle_id(object_ref))
            });
    }
    None
}

pub(super) fn circle_scope_visible_to_session(
    state: &AppState,
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
    event_created_at: chrono::DateTime<chrono::Utc>,
    session: Option<&SessionIdentityState>,
    sender: Option<&str>,
) -> bool {
    let Some(scope_circle_id) = scope_circle_id else {
        return true;
    };
    let Some(actor) = session.and_then(|session| session_actor(state, session)) else {
        return false;
    };
    let actor_key = actor.to_string();
    if sender == Some(actor_key.as_str()) {
        return true;
    }
    projection.circle_scope_visible_to_actor_at(scope_circle_id, &actor_key, event_created_at)
}

#[cfg(test)]
mod account_notification_tests {
    use super::*;

    #[test]
    fn typed_agent_approval_uses_discriminator_free_notification_delta() {
        let delta =
            arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta::try_new(
                arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                    arkret_wire::NotificationId::new(
                        "ak:notification:019fa1ef-00ee-77e0-9f06-2f2d36bf2475".to_owned(),
                    )
                    .expect("test notification id"),
                ),
                arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Upsert,
                Some(
                    arkret_models_collaboration::sync_frames::account_subscribe::NotificationData::AgentRuntimeApproval(
                        arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalNotificationData {
                            approval_request_id: arkret_wire::OpaqueLocalId::new(
                                "agent_runtime_approval:019fa1ef-00ee-77e0-9f06-2f1d9ed5e3fa",
                            )
                            .unwrap(),
                            agent_id: arkret_wire::DidCoreId::new(
                                "ak:did_core:web:agent.example".to_owned(),
                            )
                            .expect("test Agent core id"),
                            requested_at: "2026-07-27T04:57:02.959Z"
                                .parse()
                                .expect("test requested_at"),
                            expires_at: "2026-07-27T05:07:02.959Z"
                                .parse()
                                .expect("test expires_at"),
                        },
                    ),
                ),
            )
            .expect("typed Agent approval must be valid");
        let wire = serde_json::to_value(delta).expect("NotificationDelta must serialize");

        assert!(wire.get("notification_kind").is_none());
        assert!(wire["data"].get("kind").is_none());
        assert_eq!(wire.get("action").and_then(Value::as_str), Some("upsert"));
    }
}
