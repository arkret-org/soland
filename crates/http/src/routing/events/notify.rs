//! Notification fanout for message mentions, assignment targets, and schedule
//! changes.
//!
//! Message mention fanout keeps the AKP-0016 third-party agent gate: a native
//! personal agent is only notified of a third-party mention (author != its
//! controller) when its effective `accept_third_party_mention` bit (selection
//! ∩ ceiling) is true for the message scope; otherwise the mention is dropped
//! for that agent. Assignment and schedule fanout use the same per-recipient
//! notification projection store and access gates.

use std::collections::BTreeSet;

use arkret_models_collaboration::objects::read_receipts::{
    Notification, NotificationEventSource, NotificationSchema, NotificationSource,
    NotificationSourceRef,
};
use arkret_wire::events::EventKind;
use arkret_wire::{
    DidCoreId, EventId, NotificationId, NotificationKind, NotificationPriority, NotificationState,
    RealmId, StrandId,
};
use serde_json::Value;

use crate::routing::agent_participation::{
    resolve_agent_participation_for_scope_keys, scope_keys_for_message,
};
use crate::state::AppState;

fn value_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn relation_value_string<'a>(payload: &'a Value, keys: &[&str]) -> Option<&'a str> {
    value_string(payload, keys).or_else(|| {
        payload
            .get("relation")
            .and_then(|relation| value_string(relation, keys))
    })
}

fn operation_source_event_id(operation: &arkret_event_draft::ProjectedEventOperation) -> String {
    operation.context.event_id.to_string()
}

fn operation_source_actor_id(
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Option<String> {
    Some(operation.context.sender.to_string())
}

fn explicit_watch_level(state: &AppState, strand_id: &str, actor_id: &str) -> Option<String> {
    state
        .projections()
        .snapshot()
        .strand_watches
        .get(&(strand_id.to_owned(), actor_id.to_owned()))
        .and_then(|watch| watch.level.clone())
}

fn all_watch_recipients(state: &AppState, strand_id: &str) -> BTreeSet<String> {
    state
        .projections()
        .snapshot()
        .strand_watches
        .values()
        .filter(|watch| watch.strand_id == strand_id && watch.level.as_deref() == Some("all"))
        .map(|watch| watch.actor_id.clone())
        .collect()
}

fn actor_has_realm_access(state: &AppState, realm_id: &str, actor_id: &str) -> bool {
    realm_joined_members(state, realm_id).contains(actor_id)
}

fn actor_can_see_strand(state: &AppState, realm_id: &str, strand_id: &str, actor_id: &str) -> bool {
    if !actor_has_realm_access(state, realm_id, actor_id) {
        return false;
    }
    let projection = state.projections().snapshot();
    let Some(strand) = projection.strands.get(strand_id) else {
        return false;
    };
    if strand.realm_id != realm_id {
        return false;
    }
    if let Some(circle_id) = strand.scope_circle_id.as_deref() {
        return projection.circle_scope_visible_to_actor(circle_id, actor_id);
    }
    true
}

fn actor_can_receive_watched_message(
    state: &AppState,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
) -> bool {
    if !actor_has_realm_access(state, realm_id, actor_id) {
        return false;
    }
    let projection = state.projections().snapshot();
    let Some(strand) = projection.strands.get(strand_id) else {
        return true;
    };
    if strand.realm_id != realm_id {
        return false;
    }
    if let Some(circle_id) = strand.scope_circle_id.as_deref() {
        return projection.circle_scope_visible_to_actor(circle_id, actor_id);
    }
    true
}

/// Direct-mention subject DIDs of a message payload's Content Block.
///
/// Only the canonical `mention_node.subject_id` is authoritative for routing
/// (strand-and-message.md §9.4.2); a payload that fails canonical mention
/// admission routes to nobody.
fn mention_subjects(payload: &Value) -> Vec<String> {
    payload
        .get("content")
        .or_else(|| payload.get("payload").and_then(|p| p.get("content")))
        .and_then(|content| crate::routing::events::operations::mention_subject_ids(content).ok())
        .unwrap_or_default()
        .into_iter()
        .map(arkret_identifiers::DidCoreId::into_string)
        .collect()
}

fn realm_joined_members(state: &AppState, realm_id: &str) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    if let Ok(parsed_realm_id) = arkret_identifiers::RealmId::new(realm_id.to_owned()) {
        let realms = state.realm_directory().snapshot();
        if let Some(entry) = realms.get(&parsed_realm_id) {
            members.extend(entry.members.iter().map(|did| did.as_str().to_owned()));
        }
    }
    {
        let projection = state.projections().snapshot();
        members.extend(
            projection
                .members_of_realm(realm_id)
                .into_iter()
                .map(|member| member.member.clone()),
        );
        members.retain(|member| {
            projection
                .agent_membership_binding(realm_id, member)
                .is_none()
                || projection.effective_agent_membership_base(realm_id, member)
        });
    }
    members
}

/// Effective `accept_third_party_mention` for an agent in the message
/// scope = most-specific selection (strand over circle over realm) intersected with ceiling.
async fn agent_accepts_third_party_mention(
    state: &AppState,
    agent: &str,
    realm_id: &str,
    strand_id: Option<&str>,
) -> bool {
    let Some(scope_keys) = scope_keys_for_message(state, realm_id, strand_id) else {
        return false;
    };
    resolve_agent_participation_for_scope_keys(state, agent, &scope_keys)
        .await
        .is_some_and(|resolved| resolved.effective.accept_third_party_mention)
}

async fn put_notification(
    state: &AppState,
    recipient_id: &str,
    realm_id: &str,
    source_event_id: &str,
    notification_kind: NotificationKind,
    event_kind: EventKind,
    source_ref: Option<&str>,
    strand_id: Option<&str>,
    track_name: Option<&str>,
    source_actor_id: Option<&str>,
    preview: Option<Value>,
) {
    let created_at = crate::routing::events::now();
    let record = (|| {
        let preview = preview
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("notification preview is invalid: {error}"))?;
        let notification = Notification {
            id: NotificationId::new(crate::ids::generate_notification_id())
                .map_err(|error| format!("notification id is invalid: {error}"))?,
            schema: NotificationSchema::V1,
            actor_id: arkret_identifiers::DidCoreId::new(recipient_id.to_owned())
                .map_err(|error| format!("notification recipient is invalid: {error}"))?,
            source: NotificationSource::Event(NotificationEventSource {
                source_event_id: EventId::new(source_event_id.to_owned())
                    .map_err(|error| format!("notification source Event is invalid: {error}"))?,
                realm_id: Some(
                    RealmId::new(realm_id.to_owned())
                        .map_err(|error| format!("notification Realm is invalid: {error}"))?,
                ),
                source_ref: source_ref
                    .map(|value| NotificationSourceRef::new(value.to_owned()))
                    .transpose()
                    .map_err(|error| {
                        format!("notification source reference is invalid: {error}")
                    })?,
                strand_id: strand_id
                    .map(|value| StrandId::new(value.to_owned()))
                    .transpose()
                    .map_err(|error| format!("notification Strand is invalid: {error}"))?,
                track_name: track_name.map(ToOwned::to_owned),
            }),
            notification_kind,
            priority: NotificationPriority::Normal,
            state: NotificationState::Unread,
            preview,
            created_at,
            updated_at: Some(created_at),
        };
        notification
            .validate()
            .map_err(|error| format!("notification is invalid: {error}"))?;
        let source_actor_id = source_actor_id
            .map(|value| DidCoreId::new(value.to_owned()))
            .transpose()
            .map_err(|error| format!("notification source actor is invalid: {error}"))?;
        Ok::<_, String>(soland_services::delivery::RecipientNotificationRecord {
            notification,
            event_kind,
            source_actor_id,
        })
    })();
    let record = match record {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(%error, "failed to materialize typed notification");
            return;
        }
    };
    if let Err(error) = state
        .deliveries()
        .store_notification(soland_services::delivery::StoreNotificationCommand { record })
        .await
    {
        tracing::warn!(%error, "failed to persist notification");
    }
}

async fn put_message_notification(
    state: &AppState,
    recipient_id: &str,
    realm_id: &str,
    source_event_id: &str,
    notification_kind: NotificationKind,
    strand_id: Option<&str>,
    source_actor_id: Option<&str>,
    source_ref: Option<&str>,
    track_name: Option<&str>,
    preview: Option<Value>,
) {
    put_notification(
        state,
        recipient_id,
        realm_id,
        source_event_id,
        notification_kind,
        EventKind::MessageCreate,
        source_ref,
        strand_id,
        track_name,
        source_actor_id,
        preview,
    )
    .await;
}

/// Fan out message notifications for an accepted `ak.message.create`.
pub(crate) async fn dispatch_message_notifications(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) {
    let payload = &operation.payload;
    let sender = operation.context.sender.to_string();
    let realm_id = operation.realm_id.as_str().to_owned();
    let source_event_id = operation_source_event_id(operation);
    let strand_id = payload
        .get("strand_id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("thread_id").and_then(Value::as_str))
        .map(ToOwned::to_owned);
    let source_ref = payload
        .get("message_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let track_name = payload
        .get("track_name")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let preview = payload
        .pointer("/content/body")
        .and_then(Value::as_str)
        .map(|body| serde_json::json!({ "body": body }));
    // SOL-SEC-06 — if the message is scoped to a Circle, a mention notification
    // MUST NOT be delivered to a subject who cannot see that Circle; otherwise
    // the notification leaks the metadata "a message in this Circle mentions
    // you" to a non-member.
    let scope_circle_id = payload
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    let mentioned_subjects = mention_subjects(payload)
        .into_iter()
        .filter(|subject| !subject.trim().is_empty())
        .collect::<BTreeSet<_>>();
    // SPI-SOL-004 — mention-routing sidecar gate (push-notifications.md
    // §4.5). Opaque `mention_sidecar_digest` tags on an encrypted message may
    // only ever be consulted under an effective `recipient_registered_token`
    // policy; the effective hint is resolved BEFORE any sidecar consumption.
    // Hardened Realms (minimal-metadata + both audited E2EE profiles) and
    // undeclared / unknown hints force `disabled`: the tags are dropped here,
    // unregistered / uncompared / unpersisted, and mention wakeup rides the
    // blind / batch path. soland has no recipient token registry yet, so even
    // an opted-in ordinary E2EE Realm falls back to blind delivery — a future
    // registry MUST be driven through
    // `mention_routing::drive_mention_routing_sidecar`, never directly.
    let sidecar_tag_count = payload
        .get("mention_sidecar_digest")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if sidecar_tag_count > 0 {
        let effective_hint =
            super::mention_routing::effective_realm_mention_routing_hint(state, &realm_id, None)
                .await;
        tracing::debug!(
            %realm_id,
            sidecar_tag_count,
            effective_hint = effective_hint.as_str(),
            "mention sidecar tags dropped; blind/batch fallback"
        );
    }
    if let Some(strand_id) = strand_id.as_deref() {
        for recipient in all_watch_recipients(state, strand_id) {
            if recipient == sender || mentioned_subjects.contains(&recipient) {
                continue;
            }
            if !actor_can_receive_watched_message(state, &realm_id, strand_id, &recipient) {
                continue;
            }
            put_message_notification(
                state,
                &recipient,
                &realm_id,
                &source_event_id,
                NotificationKind::Message,
                Some(strand_id),
                Some(&sender),
                source_ref.as_deref(),
                track_name.as_deref(),
                preview.clone(),
            )
            .await;
        }
    }
    for subject in mentioned_subjects {
        if subject == sender {
            continue;
        }
        if let Some(circle_id) = scope_circle_id.as_deref() {
            let visible = state
                .projections()
                .snapshot()
                .circle_scope_visible_to_actor(circle_id, &subject);
            if !visible {
                continue;
            }
        }
        // AKP-0016 §9.4.5 — agent third-party mention gate.
        if let Ok(Some(agent_record)) = state
            .identities()
            .find_agent_controller(soland_services::identity::FindAgentControllerQuery {
                agent_id: subject.clone(),
            })
            .await
        {
            let controller = agent_record.controller_id.as_str();
            if sender != controller
                && !agent_accepts_third_party_mention(
                    state,
                    &subject,
                    &realm_id,
                    strand_id.as_deref(),
                )
                .await
            {
                continue;
            }
        }
        put_message_notification(
            state,
            &subject,
            &realm_id,
            &source_event_id,
            NotificationKind::Mention,
            strand_id.as_deref(),
            Some(&sender),
            source_ref.as_deref(),
            track_name.as_deref(),
            preview.clone(),
        )
        .await;
    }
}

/// Fan out assignment notifications for an accepted `ak.relation.create`.
pub(crate) async fn dispatch_assignment_notifications(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) {
    let payload = &operation.payload;
    if relation_value_string(payload, &["relation_kind", "kind"]) != Some("assigned_to") {
        return;
    }
    let Some(strand_id) = relation_value_string(payload, &["from_ref", "from"])
        .filter(|value| value.starts_with("ak:strand:"))
    else {
        return;
    };
    let Some(assignee) = relation_value_string(payload, &["to_ref", "to"])
        .filter(|value| value.starts_with("ak:did_core:"))
    else {
        return;
    };
    let source_actor_id = operation_source_actor_id(operation);
    if source_actor_id.as_deref() == Some(assignee) {
        return;
    }
    let realm_id = operation.realm_id.as_str();
    if explicit_watch_level(state, strand_id, assignee).as_deref() == Some("muted") {
        return;
    }
    if !actor_can_see_strand(state, realm_id, strand_id, assignee) {
        return;
    }
    let source_event_id = operation_source_event_id(operation);
    let relation_id = relation_value_string(payload, &["relation_id", "id"]);
    put_notification(
        state,
        assignee,
        realm_id,
        &source_event_id,
        NotificationKind::Assignment,
        EventKind::RelationCreate,
        relation_id,
        Some(strand_id),
        None,
        source_actor_id.as_deref(),
        None,
    )
    .await;
}

fn patch_touches_calendar(payload: &Value) -> bool {
    let Some(patch) = payload.get("patch").and_then(Value::as_object) else {
        return false;
    };
    patch.iter().any(|(path, value)| {
        if path == "metadata.fields.calendar"
            || path.starts_with("metadata.fields.calendar.")
        {
            return true;
        }
        if path == "metadata.fields" {
            return value
                .get("value")
                .or_else(|| value.get("$value"))
                .or_else(|| value.get("fields"))
                .or(Some(value))
                .and_then(Value::as_object)
                .is_some_and(|fields| {
                    fields.contains_key(
                        arkret_models_collaboration::objects::productivity::CALENDAR_METADATA_FIELDS_NAMESPACE,
                    )
                });
        }
        if path == "metadata" {
            return value
                .get("value")
                .or_else(|| value.get("$value"))
                .and_then(|metadata| metadata.get("fields"))
                .and_then(Value::as_object)
                .is_some_and(|fields| {
                    fields.contains_key(
                        arkret_models_collaboration::objects::productivity::CALENDAR_METADATA_FIELDS_NAMESPACE,
                    )
                });
        }
        false
    })
}

fn patch_touches_due_schedule(payload: &Value) -> bool {
    let Some(patch) = payload.get("patch").and_then(Value::as_object) else {
        return false;
    };
    patch.iter().any(|(path, value)| {
        if path == "metadata.fields.due_at" {
            return true;
        }
        if path == "metadata.fields" {
            return value
                .get("value")
                .or_else(|| value.get("$value"))
                .or_else(|| value.get("fields"))
                .or(Some(value))
                .and_then(Value::as_object)
                .is_some_and(|fields| fields.contains_key("due_at"));
        }
        if path == "metadata" {
            return value
                .get("value")
                .or_else(|| value.get("$value"))
                .and_then(|metadata| metadata.get("fields"))
                .and_then(Value::as_object)
                .is_some_and(|fields| fields.contains_key("due_at"));
        }
        false
    })
}

fn relation_schedule_recipients(state: &AppState, strand_id: &str) -> BTreeSet<String> {
    let projection = state.projections().snapshot();
    let mut recipients = projection
        .relations
        .values()
        .filter(|relation| {
            relation.relation_kind == "assigned_to"
                && relation.state == "active"
                && relation.from_ref.as_deref() == Some(strand_id)
        })
        .filter_map(|relation| relation.to_ref.clone())
        .filter(|actor| actor.starts_with("ak:did_core:"))
        .collect::<BTreeSet<_>>();
    recipients.extend(
        projection
            .strand_watches
            .values()
            .filter(|watch| watch.strand_id == strand_id && watch.level.as_deref() == Some("all"))
            .map(|watch| watch.actor_id.clone()),
    );
    recipients
}

/// Fan out due-date notifications for an accepted `ak.strand.update`.
/// Calendar updates are recognized separately and fail closed below until the
/// receiver-private policy projection required by their optional server
/// profile exists.
pub(crate) async fn dispatch_schedule_notifications(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) {
    let due_schedule = patch_touches_due_schedule(&operation.payload);
    let calendar_schedule = patch_touches_calendar(&operation.payload);
    if !due_schedule && !calendar_schedule {
        return;
    }
    let Some(strand_id) = operation
        .payload
        .get("target_ref")
        .or_else(|| operation.payload.get("strand_id"))
        .and_then(Value::as_str)
    else {
        return;
    };
    let realm_id = operation.realm_id.as_str();
    let source_actor_id = operation_source_actor_id(operation);
    let source_event_id = operation_source_event_id(operation);
    if due_schedule {
        for recipient in relation_schedule_recipients(state, strand_id) {
            if source_actor_id.as_deref() == Some(recipient.as_str()) {
                continue;
            }
            if explicit_watch_level(state, strand_id, &recipient).as_deref() == Some("muted") {
                continue;
            }
            if !actor_can_see_strand(state, realm_id, strand_id, &recipient) {
                continue;
            }
            put_notification(
                state,
                &recipient,
                realm_id,
                &source_event_id,
                NotificationKind::Schedule,
                EventKind::StrandUpdate,
                Some(strand_id),
                Some(strand_id),
                None,
                source_actor_id.as_deref(),
                None,
            )
            .await;
        }
    }
    // Calendar fanout additionally requires receiver-private blocklist, DND
    // and push-rule gates before a Notification row or wakeup is generated.
    // Soland stores those standard account-data cells as holder-encrypted
    // values and has no holder-authorized readable policy projection. The
    // conformant behavior is therefore fail-closed; do not infer a verified
    // schedule notification or blind wakeup from Calendar metadata.
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::RealmId;
    use serde_json::{Value, json};
    use soland_storage_postgres::Db;

    use super::*;

    fn test_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-agent-notify-test-blobs"),
            ),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: Some([9u8; 32]),
            seed_demo_data: true,
            ..crate::config::AppConfig::test_default()
        }
    }

    fn test_state() -> AppState {
        AppState::new(test_config(), Db { pool: None })
    }

    async fn notifications_for(state: &AppState, recipient_id: &str) -> Vec<Value> {
        state
            .deliveries()
            .list_recipient_notifications(
                soland_services::delivery::ListRecipientNotificationsQuery {
                    recipient_id: recipient_id.to_owned(),
                },
            )
            .await
            .expect("notification query")
            .into_iter()
            .map(|record| {
                serde_json::to_value(record.notification).expect("encode typed notification")
            })
            .collect()
    }

    fn seed_realm_members(state: &AppState, realm_id: &str, members: &[&str]) {
        let realm_id_typed = RealmId::new(realm_id.to_owned()).expect("valid realm id");
        let mut entry = crate::state::RealmDirectoryEntry::new(
            realm_id_typed,
            "Notify test",
            soland_services::events::DirectoryProvenance::LocalOnly,
        );
        for member in members {
            entry.members.insert(
                arkret_identifiers::DidCoreId::new((*member).to_owned()).expect("valid member id"),
            );
        }
        state.realm_directory().upsert(entry);
    }

    async fn put_agent(state: &AppState, agent: &str, controller: &str, verification_method: &str) {
        let mut record = soland_services::identity::AgentPairingState::new(
            agent.to_owned(),
            controller.to_owned(),
            "ak:realm:ATWQEEyC8UZTZ3u0Vp5MrgAI7TdaZ7A8gEomiO5_Q9Vy".to_owned(),
            arkret_wire::DidUrl::new(verification_method.to_owned()).unwrap(),
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            chrono::Utc::now(),
        );
        record.agent_slug = Some("summary".to_owned());
        record.display_name = Some("Summary".to_owned());
        state
            .agent_pairings()
            .save_agent(record)
            .await
            .expect("agent record");
    }

    async fn set_realm_selection(
        state: &AppState,
        realm_id: &str,
        agent: &str,
        accept_third_party_mention: bool,
        expected_version: u64,
    ) {
        assert!(
            state
                .agent_participations()
                .compare_and_swap_selection(
                    json!({
                        "agent_id": agent,
                        "scope_kind": "realm",
                        "scope_key": crate::routing::agent_participation::realm_scope_key(realm_id),
                        "realm_id": realm_id,
                        "scope": { "kind": "realm", "realm_id": realm_id },
                        "version": expected_version + 1,
                        "reply_message": true,
                        "reaction_add": false,
                        "reaction_remove": false,
                        "accept_third_party_mention": accept_third_party_mention,
                        "act_on_behalf": false,
                    }),
                    expected_version
                )
                .await
                .expect("agent participation selection")
        );
    }

    async fn set_circle_selection(
        state: &AppState,
        realm_id: &str,
        circle_id: &str,
        agent: &str,
        accept_third_party_mention: bool,
    ) {
        assert!(
            state
                .agent_participations()
                .compare_and_swap_selection(
                    json!({
                        "agent_id": agent,
                        "scope_kind": "circle",
                        "scope_key": crate::routing::agent_participation::circle_scope_key(
                            realm_id,
                            circle_id,
                        ),
                        "realm_id": realm_id,
                        "scope": { "kind": "circle", "realm_id": realm_id, "circle_id": circle_id },
                        "version": 1,
                        "reply_message": true,
                        "reaction_add": false,
                        "reaction_remove": false,
                        "accept_third_party_mention": accept_third_party_mention,
                        "act_on_behalf": false,
                    }),
                    0
                )
                .await
                .expect("agent participation circle selection")
        );
    }

    async fn put_circle_ceiling(
        state: &AppState,
        realm_id: &str,
        circle_id: &str,
        accept_third_party_mention: bool,
    ) {
        state
            .agent_participations()
            .store_ceiling(json!({
                "scope_kind": "circle",
                "scope_key": crate::routing::agent_participation::circle_scope_key(
                    realm_id,
                    circle_id,
                ),
                "realm_id": realm_id,
                "reply_message": true,
                "reaction_add": false,
                "reaction_remove": false,
                "accept_third_party_mention": accept_third_party_mention,
                "act_on_behalf": false,
            }))
            .await
            .expect("agent participation circle ceiling");
    }

    fn plain_message(
        realm_id: &str,
        seed: &str,
        sender: &str,
    ) -> arkret_event_draft::ProjectedEventOperation {
        plain_message_with_strand(realm_id, seed, sender, None)
    }

    fn fixture_event_id(seed: &str) -> arkret_identifiers::EventId {
        let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(seed))
            .expect("fixture digest is typed");
        arkret_identifiers::EventId::from_event_digest(&digest)
            .expect("SHA-256 is a registered Event digest suite")
    }

    fn plain_message_with_strand(
        realm_id: &str,
        seed: &str,
        sender: &str,
        strand_id: Option<&str>,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event_id = fixture_event_id(seed);
        let mut payload = json!({
            "sender": sender,
            "event_id": event_id,
            "content": {
                "body": "hello"
            }
        });
        if let Some(strand_id) = strand_id {
            payload
                .as_object_mut()
                .expect("message payload object")
                .insert("strand_id".to_owned(), json!(strand_id));
        }
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::MessageCreate.as_str(),
            payload,
        )
    }

    fn seed_strand_watch(state: &AppState, strand_id: &str, actor_id: &str, level: &str) {
        state.test_projection().lock().strand_watches.insert(
            (strand_id.to_owned(), actor_id.to_owned()),
            soland_domain::reducer::StrandWatchProjection {
                strand_id: strand_id.to_owned(),
                actor_id: actor_id.to_owned(),
                level: Some(level.to_owned()),
                level_public: false,
                updated_at: chrono::Utc::now(),
            },
        );
    }

    fn seed_strand_scope(state: &AppState, realm_id: &str, strand_id: &str, circle_id: &str) {
        state.test_projection().lock().strands.insert(
            strand_id.to_owned(),
            soland_domain::reducer::StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: realm_id.to_owned(),
                tracks: Default::default(),
                title: "Scoped".to_owned(),
                summary: None,
                fields: Default::default(),
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "ak:did_core:web:alice.example".to_owned(),
                created_at: chrono::Utc::now(),
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                schema_refs: Vec::new(),
                schedule_revision_heads: Vec::new(),
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
    }

    fn seed_strand(state: &AppState, realm_id: &str, strand_id: &str) {
        state.test_projection().lock().strands.insert(
            strand_id.to_owned(),
            soland_domain::reducer::StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: realm_id.to_owned(),
                tracks: Default::default(),
                title: "Task".to_owned(),
                summary: None,
                fields: Default::default(),
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "ak:did_core:web:alice.example".to_owned(),
                created_at: chrono::Utc::now(),
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                schema_refs: Vec::new(),
                schedule_revision_heads: Vec::new(),
                scope_circle_id: None,
            },
        );
    }

    fn relation_create(
        realm_id: &str,
        seed: &str,
        sender: &str,
        strand_id: &str,
        assignee: &str,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event_id = fixture_event_id(seed);
        let relation_id = arkret_identifiers::RelationId::from_event_id(&event_id);
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationCreate.as_str(),
            json!({
                "sender": sender,
                "event_id": event_id,
                "relation_id": relation_id,
                "relation_kind": "assigned_to",
                "from_ref": strand_id,
                "to_ref": assignee,
            }),
        )
    }

    fn schedule_update(
        realm_id: &str,
        seed: &str,
        sender: &str,
        strand_id: &str,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event_id = fixture_event_id(seed);
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::StrandUpdate.as_str(),
            json!({
                "sender": sender,
                "event_id": event_id,
                "target_ref": strand_id,
                "patch": {
                    "metadata.fields.due_at": {
                        "$op": "set",
                        "value": "2026-07-06T00:00:00.000Z"
                    }
                }
            }),
        )
    }

    fn rsvp_update(
        realm_id: &str,
        seed: &str,
        sender: &str,
        strand_id: &str,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event_id = fixture_event_id(seed);
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::RsvpSet.as_str(),
            json!({
                "sender": sender,
                "event_id": event_id,
                "event_ref": strand_id,
                "occurrence": null,
                "entry": {
                    "schedule_basis_refs": [
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    ],
                    "response": {"status": "accepted"}
                }
            }),
        )
    }

    fn mention_message(
        realm_id: &str,
        seed: &str,
        sender: &str,
        agent: &str,
    ) -> arkret_event_draft::ProjectedEventOperation {
        mention_message_with_strand(realm_id, seed, sender, agent, None)
    }

    fn mention_message_with_strand(
        realm_id: &str,
        seed: &str,
        sender: &str,
        agent: &str,
        strand_id: Option<&str>,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event_id = fixture_event_id(seed);
        let mut payload = json!({
            "sender": sender,
            "event_id": event_id,
            "content": {
                "body": "ping",
                "mentions": [{
                    "kind": "mention",
                    "subject_id": agent,
                    "mention_text_original": "@agent"
                }]
            }
        });
        if let Some(strand_id) = strand_id {
            payload
                .as_object_mut()
                .expect("message payload object")
                .insert("strand_id".to_owned(), json!(strand_id));
        }
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::MessageCreate.as_str(),
            payload,
        )
    }

    fn encrypted_unregistered_sidecar_message(
        realm_id: &str,
        seed: &str,
        sender: &str,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event_id = fixture_event_id(seed);
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::MessageCreate.as_str(),
            json!({
                "sender": sender,
                "event_id": event_id,
                "mention_sidecar_digest": ["unregistered-opaque-tag"],
                "encrypted": true,
                "encrypted_content": {
                    "content_type": "ak.message.v1",
                    "ciphertext": "opaque-ciphertext"
                }
            }),
        )
    }

    #[tokio::test]
    async fn plain_message_does_not_notify_unmentioned_members_by_default() {
        let state = test_state();
        let realm_id = "ak:realm:AauAoPMR2z4BNQITCfoc7MFdCoZUkuRA2F1Ar8_Y5wGi";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let carol = "ak:did_core:web:carol.example";
        seed_realm_members(&state, realm_id, &[alice, bob, carol]);

        let delivered = plain_message(realm_id, "000000009971", alice);
        dispatch_message_notifications(&state, &delivered).await;

        assert!(notifications_for(&state, alice).await.is_empty());
        for recipient in [bob, carol] {
            assert!(notifications_for(&state, recipient).await.is_empty());
        }
    }

    #[tokio::test]
    async fn plain_message_notifies_all_watchers_only() {
        let state = test_state();
        let realm_id = "ak:realm:AS1XvoEwEve7yjNY6nVsquBYDGIKDIrmFJeSCVjzcASh";
        let strand_id = "ak:strand:AYzqeQ1hbLexQxBuFmhDzV2R1jsnUEvB0ELJR10hOgtK";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let carol = "ak:did_core:web:carol.example";
        seed_realm_members(&state, realm_id, &[alice, bob, carol]);
        seed_strand(&state, realm_id, strand_id);
        seed_strand_watch(&state, strand_id, bob, "all");
        seed_strand_watch(&state, strand_id, carol, "participating");

        let delivered = plain_message_with_strand(realm_id, "000000009953", alice, Some(strand_id));
        dispatch_message_notifications(&state, &delivered).await;

        let bob_notifications = notifications_for(&state, bob).await;
        assert_eq!(bob_notifications.len(), 1);
        assert_eq!(
            bob_notifications[0]
                .get("notification_kind")
                .and_then(Value::as_str),
            Some("message")
        );
        assert_eq!(
            bob_notifications[0]
                .get("strand_id")
                .and_then(Value::as_str),
            Some(strand_id)
        );
        assert!(notifications_for(&state, carol).await.is_empty());
        assert!(notifications_for(&state, alice).await.is_empty());
    }

    #[tokio::test]
    async fn plain_message_all_watcher_falls_back_to_realm_access_when_strand_missing() {
        let state = test_state();
        let realm_id = "ak:realm:Adyav4arFL7WanivBY0R2rPKamnwP3Ufm3id4lK6RvLC";
        let strand_id = "ak:strand:ATzedkQcDEQSoizsKm0tLBqVS7MdSmwECSr83UPmfDCv";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let mallory = "ak:did_core:web:mallory.example";
        seed_realm_members(&state, realm_id, &[alice, bob]);
        seed_strand_watch(&state, strand_id, bob, "all");
        seed_strand_watch(&state, strand_id, mallory, "all");

        let delivered = plain_message_with_strand(realm_id, "000000009956", alice, Some(strand_id));
        dispatch_message_notifications(&state, &delivered).await;

        assert_eq!(notifications_for(&state, bob).await.len(), 1);
        assert!(notifications_for(&state, mallory).await.is_empty());
    }

    #[tokio::test]
    async fn member_mention_is_single_mention_notification() {
        let state = test_state();
        let realm_id = "ak:realm:AQXbZyLQDsJ3HgYeoGi2pg7v2-EAb87QmzHIKinXcPx7";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        seed_realm_members(&state, realm_id, &[alice, bob]);

        let delivered = mention_message(realm_id, "000000009973", alice, bob);
        dispatch_message_notifications(&state, &delivered).await;

        let notifications = notifications_for(&state, bob).await;
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]
                .get("notification_kind")
                .and_then(Value::as_str),
            Some("mention")
        );
    }

    #[tokio::test]
    async fn assignment_relation_create_notifies_new_assignee() {
        let state = test_state();
        let realm_id = "ak:realm:AfiUdT1FiCuG9vrwdBoVapciBl_9lj1WXVvcQiqjwjL1";
        let strand_id = "ak:strand:ATOuTJ1jIr62GMxyz9DvXbMreJu0R34jc4VIYM4ArDuj";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        seed_realm_members(&state, realm_id, &[alice, bob]);
        seed_strand(&state, realm_id, strand_id);

        let operation = relation_create(realm_id, "000000009994", alice, strand_id, bob);
        state.projections().apply(&operation, state.hlc());
        dispatch_assignment_notifications(&state, &operation).await;

        let notifications = notifications_for(&state, bob).await;
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]
                .get("notification_kind")
                .and_then(Value::as_str),
            Some("assignment")
        );
        assert_eq!(
            notifications[0].get("strand_id").and_then(Value::as_str),
            Some(strand_id)
        );
    }

    #[tokio::test]
    async fn schedule_update_notifies_assignees_and_all_watchers() {
        let state = test_state();
        let realm_id = "ak:realm:Ae_gn71jX8JjmWkvGzHGOxtSJGQ6O5zlLx95wejUyP2q";
        let strand_id = "ak:strand:AYXsQsNFlX2cPilpTg9wFxq8ZR7FMXe2x3oUUPW1lKze";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let carol = "ak:did_core:web:carol.example";
        seed_realm_members(&state, realm_id, &[alice, bob, carol]);
        seed_strand(&state, realm_id, strand_id);
        let assignment = relation_create(realm_id, "000000009997", alice, strand_id, bob);
        state.projections().apply(&assignment, state.hlc());
        seed_strand_watch(&state, strand_id, carol, "all");

        let operation = schedule_update(realm_id, "000000009998", alice, strand_id);
        dispatch_schedule_notifications(&state, &operation).await;

        for recipient in [bob, carol] {
            let notifications = notifications_for(&state, recipient).await;
            assert_eq!(
                notifications.len(),
                1,
                "{recipient} should receive schedule"
            );
            assert_eq!(
                notifications[0]
                    .get("notification_kind")
                    .and_then(Value::as_str),
                Some("schedule")
            );
        }
        assert!(notifications_for(&state, alice).await.is_empty());
    }

    #[tokio::test]
    async fn calendar_schedule_fanout_fails_closed_without_private_policy_projection() {
        let state = test_state();
        let realm_id = "ak:realm:ARj7PZkho4xcjXfMvde5k0hNB7YBVc6TGbS_IQvAuKxh";
        let strand_id = "ak:strand:AVYkqAhEtUpBukcTx8idL_KiAIF0h1LWipAY-VigqJZZ";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        seed_realm_members(&state, realm_id, &[alice, bob]);
        seed_strand(&state, realm_id, strand_id);
        let assignment = relation_create(realm_id, "000000009932", alice, strand_id, bob);
        state.projections().apply(&assignment, state.hlc());
        let operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000009933".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::StrandUpdate.as_str(),
            json!({
                "sender": alice,
                "event_id": "ak:event:Aa_qcpHgRDcZFoRX6jMUFjWIJktoe_GppP1Pl1zg0pGs",
                "target_ref": strand_id,
                "patch": {
                    "metadata.fields.calendar": {
                        "$op": "set",
                        "value": {
                            "start": "2026-07-06T09:00:00",
                            "end": "2026-07-06T10:00:00",
                            "timezone": "Etc/UTC",
                            "tzdb_version": "2025b",
                            "all_day": false,
                            "status": "confirmed"
                        }
                    }
                }
            }),
        );

        dispatch_schedule_notifications(&state, &operation).await;

        assert!(notifications_for(&state, bob).await.is_empty());
    }

    #[tokio::test]
    async fn rsvp_change_never_emits_a_schedule_notification() {
        let state = test_state();
        let realm_id = "ak:realm:AaQmWDnuj2L95eyMHnDSAuVVh6dlrGqPknIPvBibhOmJ";
        let strand_id = "ak:strand:AWpZLCspUVLBed5WbRkPgTNizbqjIiZrgmHKrcZ1dLGp";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        seed_realm_members(&state, realm_id, &[alice, bob]);
        seed_strand(&state, realm_id, strand_id);
        let operation = rsvp_update(realm_id, "000000009948", alice, strand_id);

        dispatch_schedule_notifications(&state, &operation).await;

        assert!(notifications_for(&state, bob).await.is_empty());
    }

    #[tokio::test]
    async fn unregistered_mention_sidecar_is_never_compared_to_member_ids() {
        let state = test_state();
        let realm_id = "ak:realm:AZfY2N95Y0T6RkbZInh0TK2U52OiArWMoi24g5SjFjSe";
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let carol = "ak:did_core:web:carol.example";
        seed_realm_members(&state, realm_id, &[alice, bob, carol]);

        let delivered = encrypted_unregistered_sidecar_message(realm_id, "000000009975", alice);
        dispatch_message_notifications(&state, &delivered).await;

        let bob_notifications = notifications_for(&state, bob).await;
        assert!(bob_notifications.is_empty());
        assert!(notifications_for(&state, carol).await.is_empty());
    }

    #[tokio::test]
    async fn agent_third_party_mention_gate_is_non_retroactive() {
        let state = test_state();
        let realm_id = "ak:realm:Ae34nQKc2ovP6XDJ1VP9lVATdzZ-6obodata7oQp4ucY";
        let controller = "ak:did_core:web:alice.example";
        let third_party = "ak:did_core:web:bob.example";
        let agent = "ak:did_core:web:agents.example:alice-summary";
        put_agent(
            &state,
            agent,
            controller,
            "did:web:agents.example:alice-summary#managed-controller",
        )
        .await;
        set_realm_selection(&state, realm_id, agent, false, 0).await;

        let suppressed_event_id = fixture_event_id("000000009982").to_string();
        let suppressed = mention_message(realm_id, "000000009982", third_party, agent);
        dispatch_message_notifications(&state, &suppressed).await;
        assert!(notifications_for(&state, agent).await.is_empty());

        let controller_event_id = fixture_event_id("000000009983").to_string();
        let controller_mention = mention_message(realm_id, "000000009983", controller, agent);
        dispatch_message_notifications(&state, &controller_mention).await;
        assert_eq!(notifications_for(&state, agent).await.len(), 1);

        set_realm_selection(&state, realm_id, agent, true, 1).await;
        let after_flip = notifications_for(&state, agent).await;
        assert_eq!(after_flip.len(), 1);
        assert!(after_flip.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str) == Some(controller_event_id.as_str())
        }));

        let unknown_strand = mention_message_with_strand(
            realm_id,
            "000000009985",
            third_party,
            agent,
            Some("ak:strand:AYw7orP7RhgsjMax3dy_Y7I4L3nP34aEH-nMPH-flI1k"),
        );
        dispatch_message_notifications(&state, &unknown_strand).await;
        assert_eq!(notifications_for(&state, agent).await.len(), 1);

        let delivered_event_id = fixture_event_id("000000009984").to_string();
        let delivered = mention_message(realm_id, "000000009984", third_party, agent);
        dispatch_message_notifications(&state, &delivered).await;
        let notifications = notifications_for(&state, agent).await;
        assert_eq!(notifications.len(), 2);
        assert!(notifications.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str) == Some(delivered_event_id.as_str())
        }));
        assert!(!notifications.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str) == Some(suppressed_event_id.as_str())
        }));
    }

    #[tokio::test]
    async fn strand_mention_uses_circle_effective_participation() {
        let state = test_state();
        let realm_id = "ak:realm:AakPvoRAhodng9IHc5ZdoFQD-VzTa8ev2gXDgp_ivtfK";
        let circle_id = "ak:circle:Aecu1rM_o2niy2h_rtK9KBChw8L-QoAsngbVoP1bpNrl";
        let strand_id = "ak:strand:AWfDaIWeo-OwLmokFm6boWYM7iYeSPeyw_TUiOku1wdZ";
        let controller = "ak:did_core:web:alice.example";
        let third_party = "ak:did_core:web:bob.example";
        let agent = "ak:did_core:web:agents.example:alice-summary";
        put_agent(
            &state,
            agent,
            controller,
            "did:web:agents.example:alice-summary#managed-controller",
        )
        .await;
        seed_strand_scope(&state, realm_id, strand_id, circle_id);
        set_realm_selection(&state, realm_id, agent, false, 0).await;
        set_circle_selection(&state, realm_id, circle_id, agent, true).await;

        let delivered = mention_message_with_strand(
            realm_id,
            "000000009990",
            third_party,
            agent,
            Some(strand_id),
        );
        dispatch_message_notifications(&state, &delivered).await;
        assert_eq!(notifications_for(&state, agent).await.len(), 1);

        put_circle_ceiling(&state, realm_id, circle_id, false).await;
        let capped = mention_message_with_strand(
            realm_id,
            "000000009991",
            third_party,
            agent,
            Some(strand_id),
        );
        dispatch_message_notifications(&state, &capped).await;
        let notifications = notifications_for(&state, agent).await;
        assert_eq!(notifications.len(), 1);
        assert!(!notifications.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str)
                == Some("ak:event:ARB0T1mvrpz_J_FsI1hgDyYCX14jycSPEv8_lITFehi_")
        }));
    }
}
