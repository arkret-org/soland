//! Preflight helpers retained while the legacy post-commit Seal path is retired.
//!
//! Accepted Event/RealmCommit, current results and outbox writes now belong
//! to one authority unit of work. These helpers do not publish accepted state.

use super::*;
pub(super) fn operation_with_unsigned_agent_context(
    operation: &Operation,
    envelope: &Value,
) -> Operation {
    let mut operation = operation.clone();
    if let Some(object) = operation.payload.as_object_mut()
        && !object.contains_key("agent_context")
        && let Some(agent_context) = envelope
            .get("unsigned")
            .and_then(|unsigned| unsigned.get("agent_context"))
            .filter(|value| value.is_object())
    {
        object.insert("agent_context".to_owned(), agent_context.clone());
    }
    operation
}

pub(super) async fn record_rejected_invite_claim_effect(
    state: &AppState,
    operation: &Operation,
) -> Result<(), String> {
    if !kinds::operation_is_invite_claim(operation) {
        return Ok(());
    }
    let Some(payload) = operation.payload.as_object() else {
        return Ok(());
    };
    let Some(invite_id) = rejected_invite_claim_string_field(payload, "invite_id") else {
        return Ok(());
    };
    let Some(claim_nonce) = rejected_invite_claim_string_field(payload, "claim_nonce") else {
        return Ok(());
    };

    let invites = state.realm_invites();
    let Some(mut record) = invites
        .get(&invite_id)
        .await
        .map_err(|error| format!("load invite {invite_id}: {error}"))?
    else {
        return Ok(());
    };

    let mut changed = false;
    match record.claim_nonces.get(&claim_nonce) {
        Some(existing_operation_id) if existing_operation_id != operation.operation_id.as_str() => {
            return Ok(());
        }
        Some(_) => {}
        None => {
            record
                .claim_nonces
                .insert(claim_nonce.clone(), operation.operation_id.to_string());
            changed = true;
        }
    }

    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        record.status = "expired".to_owned();
        record.invite_token.clear();
        remove_rejected_claim_active_material(&mut record.third_party_invite, true);
        changed = true;
    }

    if !changed {
        return Ok(());
    }
    record.updated_at = Some(operation.created_at);
    invites
        .put(record)
        .await
        .map_err(|error| format!("store invite rejected claim effect: {error}"))
}

pub(super) fn rejected_invite_claim_string_field(
    payload: &serde_json::Map<String, Value>,
    field: &str,
) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn remove_rejected_claim_active_material(
    third_party_invite: &mut Option<
        arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite,
    >,
    remove_commitment: bool,
) {
    let Some(value) = third_party_invite.as_mut() else {
        return;
    };
    // The closed `ThirdPartyInvite` schema never admits `token_salt` /
    // `pepper` members; only the registered handles can be present.
    value.token_salt_id = None;
    value.lookup_table_ref = None;
    value.pepper_id = None;
    if remove_commitment {
        value.token_commitment = None;
    }
}
