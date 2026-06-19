use std::collections::BTreeMap;

use cokret_sdk::Operation;
use serde_json::json;

use super::*;
use crate::kinds;
use crate::state::ProjectionEventRecord;

pub fn sync_timeline_message_json(message: &crate::reducer::MessageState) -> serde_json::Value {
    // strand_id is always derived from realm_id; thread_id is a discussion
    // track within the strand, not the strand itself. See
    // `sync_timeline_message_record_json` for the matching MessageRecord
    // path. The removed top-level `branch` object was replaced by the v1
    // `track` field.
    let strand_id = strand_id_from_realm_id(&message.realm_id);
    let track_id = message.thread_id.clone();
    let mut event = json!({
        "kind": "ck.message.create",
        "event_id": message.event_id,
        "message_id": message_id_from_event_id(&message.event_id),
        "strand_id": strand_id,
        "realm_id": message.realm_id,
        "track_name": default_discussion_track(&strand_id, &track_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "plaintext" },
        "created_at": message.created_at,
    });
    add_scope_circle_metadata(&mut event, &message.content);
    event
}

pub fn sync_timeline_message_json_with_projection(
    message: &crate::reducer::MessageState,
    projection: &crate::reducer::ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_json(message);
    if actor_erased_in_realm(projection, &message.sender, &message.realm_id) {
        tombstone_timeline_event_value(&mut event);
    }
    if apply_message_expiry_timeline_projection(&mut event, message, chrono::Utc::now()) {
        return event;
    }
    augment_timeline_message_json(event, &message.event_id, &message.content, projection)
}

pub fn augment_timeline_message_json(
    mut event: serde_json::Value,
    event_id: &str,
    content: &serde_json::Value,
    projection: &crate::reducer::ProjectionState,
) -> serde_json::Value {
    let Some(object) = event.as_object_mut() else {
        return event;
    };

    let mut reactions = projection.reactions_for_event(event_id);
    reactions.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.actor.cmp(&right.actor))
    });
    object.insert(
        "reactions".to_owned(),
        serde_json::Value::Array(
            reactions
                .iter()
                .map(|reaction| {
                    json!({
                        "actor": reaction.actor.clone(),
                        "key": reaction.key.clone(),
                        "active": reaction.active,
                        "created_at": reaction.created_at.clone(),
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "reaction_summary".to_owned(),
        reaction_summary_json(&reactions),
    );

    if let Some(reply_to) = reply_to_from_content(content) {
        object.insert(
            "reply_to".to_owned(),
            serde_json::Value::String(reply_to.clone()),
        );
        object.insert(
            "relations".to_owned(),
            json!([{
                "kind": "reply_to",
                "target_ref": reply_to,
            }]),
        );
    }
    if let Some(mentions) = content.get("mentions").cloned() {
        object.insert("mentions".to_owned(), mentions.clone());
        if !object.contains_key("mention_routing_hint")
            && let Some(hint) = mention_routing_hint_from_mentions(&mentions)
        {
            object.insert("mention_routing_hint".to_owned(), hint);
        }
    }
    if let Some(hint) = mention_routing_hint_from_content(content) {
        object.insert("mention_routing_hint".to_owned(), hint);
    }
    if let Some(poll) = poll_projection_json(content, event_id, projection) {
        object.insert("poll".to_owned(), poll);
    }
    event
}

fn reaction_summary_json(reactions: &[&crate::reducer::ReactionState]) -> serde_json::Value {
    let mut summary: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for reaction in reactions {
        summary
            .entry(reaction.key.clone())
            .or_default()
            .push(reaction.actor.clone());
    }
    json!(summary)
}

fn reply_to_from_content(content: &serde_json::Value) -> Option<String> {
    content
        .get("reply_to")
        .or_else(|| content.get("in_reply_to"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn mention_routing_hint_from_content(content: &serde_json::Value) -> Option<serde_json::Value> {
    content.get("mention_routing_hint").cloned().or_else(|| {
        content.get("mention_sidecar_hash").map(|hash| {
            json!({
                "mention_sidecar_hash": hash,
            })
        })
    })
}

fn mention_routing_hint_from_mentions(mentions: &serde_json::Value) -> Option<serde_json::Value> {
    let mentioned: Vec<String> = mentions
        .as_array()?
        .iter()
        .filter_map(|mention| {
            mention
                .get("did")
                .or_else(|| mention.get("subject_id"))
                .or_else(|| mention.get("actor_id"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect();
    if mentioned.is_empty() {
        None
    } else {
        Some(json!({
            "mentioned": mentioned,
            "source": "content.mentions",
        }))
    }
}

fn poll_projection_json(
    content: &serde_json::Value,
    event_id: &str,
    projection: &crate::reducer::ProjectionState,
) -> Option<serde_json::Value> {
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("ck.content.poll") {
        return None;
    }
    let poll_id = content
        .get("poll_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| event_id.replacen("ck:event:", "ck:message:", 1));
    let Some(poll) = projection.poll(&poll_id) else {
        return Some(json!({
            "poll_id": poll_id,
            "state": "open",
            "results": [],
        }));
    };
    let results = poll
        .options
        .iter()
        .map(|option| {
            let voters = poll
                .votes
                .iter()
                .filter_map(|(actor, choices)| {
                    if choices.contains(&option.id) {
                        Some(actor.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            json!({
                "id": option.id.clone(),
                "label": option.label.clone(),
                "count": voters.len(),
                "voters": voters,
            })
        })
        .collect::<Vec<_>>();
    Some(json!({
        "poll_id": poll.poll_id.clone(),
        "message_event_id": poll.message_event_id.clone(),
        "question": poll.question.clone(),
        "state": if poll.closed { "closed" } else { "open" },
        "closed": poll.closed,
        "max_selections": poll.max_selections,
        "results": results,
        "updated_at": poll.updated_at.clone(),
    }))
}

pub fn projection_event_from_operation(
    operation: &Operation,
    sender_fallback: Option<&str>,
) -> ProjectionEventRecord {
    let event_id = operation_event_id(operation);
    ProjectionEventRecord {
        event_id,
        realm_id: operation.realm_id.to_string(),
        event_kind: kinds::canonical_kind_string(operation),
        operation_type: operation_type_string(operation),
        operation_id: Some(operation.operation_id.to_string()),
        sender: operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .or(sender_fallback)
            .map(ToOwned::to_owned),
        payload: operation.payload.clone(),
        created_at: operation.created_at,
    }
}
