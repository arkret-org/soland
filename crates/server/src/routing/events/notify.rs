//! CKP-0016 §9.4.5 — message mention notification fanout + agent
//! third-party mention gate.
//!
//! Derives per-recipient `notification` rows from an accepted
//! `ck.message.create`. A native personal agent is only notified of a
//! third-party mention (author != its controller) when its effective
//! `accept_third_party_mention` bit (selection ∩ ceiling) is true for the
//! message scope; otherwise the mention is dropped for that agent. Human
//! recipients are notified unconditionally (mute / blocklist / DND / push
//! rules are layered on top by the push pipeline — TODO floria push).

use serde_json::Value;

use crate::state::AppState;

fn uuid_tail(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

fn nbool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Mention subject DIDs from a message payload's `content.mentions[]`
/// (string DID, `{subject_id}`, or `{did}` forms).
fn mention_subjects(payload: &Value) -> Vec<String> {
    let content = payload
        .get("content")
        .or_else(|| payload.get("payload").and_then(|p| p.get("content")));
    let Some(mentions) = content
        .and_then(|c| c.get("mentions"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for mention in mentions {
        if let Some(did) = mention.as_str() {
            out.push(did.to_owned());
        } else if let Some(subject) = mention.get("subject_id").and_then(Value::as_str) {
            out.push(subject.to_owned());
        } else if let Some(did) = mention.get("did").and_then(Value::as_str) {
            out.push(did.to_owned());
        }
    }
    out
}

/// Effective `accept_third_party_mention` for an agent in the message
/// scope = most-specific selection (strand over realm) ∩ ceiling.
async fn agent_accepts_third_party_mention(
    state: &AppState,
    agent: &str,
    realm_uuid: &str,
    strand_id: Option<&str>,
) -> bool {
    let realm_key = format!("realm:{realm_uuid}");
    let strand_key = strand_id.map(|f| format!("strand:{realm_uuid}:{}", uuid_tail(f)));
    let selections = state
        .persistence
        .agent_participation()
        .list_selections(agent)
        .await
        .unwrap_or_default();
    let mut selection = None;
    if let Some(fk) = strand_key.as_deref() {
        selection = selections
            .iter()
            .find(|r| r.get("scope_key").and_then(Value::as_str) == Some(fk))
            .cloned();
    }
    if selection.is_none() {
        selection = selections
            .iter()
            .find(|r| r.get("scope_key").and_then(Value::as_str) == Some(realm_key.as_str()))
            .cloned();
    }
    let Some(selection) = selection else {
        return false;
    };
    if !nbool(&selection, "accept_third_party_mention") {
        return false;
    }
    let scope_key = selection
        .get("scope_key")
        .and_then(Value::as_str)
        .unwrap_or(realm_key.as_str())
        .to_owned();
    let rows = state
        .persistence
        .agent_participation()
        .ceilings_for_scope_keys(&[realm_key.clone(), scope_key])
        .await
        .unwrap_or_default();
    for row in &rows {
        if !nbool(row, "accept_third_party_mention") {
            return false;
        }
    }
    true
}

/// Fan out mention notifications for an accepted `ck.message.create`.
pub(crate) async fn dispatch_message_notifications(
    state: &AppState,
    operation: &cokret_sdk::Operation,
) {
    let payload = &operation.payload;
    let sender = payload
        .get("sender")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let realm_id = operation.realm_id.as_str().to_owned();
    let realm_uuid = uuid_tail(&realm_id).to_owned();
    let source_event_id = payload
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let strand_id = payload
        .get("strand_id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("thread_id").and_then(Value::as_str))
        .map(ToOwned::to_owned);
    for subject in mention_subjects(payload) {
        if subject == sender {
            continue;
        }
        // CKP-0016 §9.4.5 — agent third-party mention gate.
        if let Ok(Some(agent_record)) = state.persistence.agents().get(&subject).await {
            let controller = agent_record
                .get("controller_did")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if sender != controller
                && !agent_accepts_third_party_mention(
                    state,
                    &subject,
                    &realm_uuid,
                    strand_id.as_deref(),
                )
                .await
            {
                continue;
            }
        }
        let record = serde_json::json!({
            "notification_id": format!("ck:notification:{}", uuid::Uuid::now_v7()),
            "recipient_id": subject,
            "realm_id": realm_id,
            "source_event_id": source_event_id,
            "notification_type": "mention",
        });
        if let Err(error) = state.persistence.notifications().put(record).await {
            tracing::warn!(%error, "failed to persist mention notification");
        }
    }
}
