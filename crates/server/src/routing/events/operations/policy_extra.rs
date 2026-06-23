use cokret_sdk::{Operation, ReadReceiptPolicy, ReadReceiptPolicyChildViolation};
use serde_json::Value;

use super::*;

pub(crate) async fn validate_history_visibility_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(cokret_sdk::events::kinds::REALM_HISTORY_VISIBILITY)
    {
        return Ok(());
    }
    if operation.payload.get("value").and_then(Value::as_str) != Some("restricted") {
        return Ok(());
    }
    let Some(meta) = state
        .persistence
        .realm_meta()
        .get(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Err("history_sharing_policy_missing");
    };
    let Some(policy_digest) = meta.history_sharing_policy_digest.as_deref() else {
        return Err("history_sharing_policy_missing");
    };
    let requested_digest = operation
        .payload
        .get("restricted_policy_digest")
        .and_then(Value::as_str);
    if requested_digest == Some(policy_digest) {
        Ok(())
    } else {
        Err("history_sharing_policy_missing")
    }
}

const READ_RECEIPT_VISIBILITY_COMBINATION_INVALID: &str =
    "read_receipt_visibility_combination_invalid";
const READ_RECEIPT_FORCED_PUBLIC_WORLD_READABLE_FORBIDDEN: &str =
    "read_receipt_forced_public_world_readable_forbidden";
const READ_RECEIPT_POLICY_RULE: &str = "ck.realm.read_receipt_policy";

pub(crate) async fn validate_read_receipt_policy_combination_write(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(cokret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY) => {
            let policy = read_receipt_policy_projection_from_payload(&operation.payload)?;
            let history_visibility = intended_history_visibility_for_realm(
                state,
                operations,
                operation.realm_id.as_str(),
            )
            .await;
            validate_read_receipt_policy_against_history(&policy, &history_visibility)?;
            validate_read_receipt_child_policy_write(state, operations, operation, &policy).await
        }
        Some(cokret_sdk::events::kinds::REALM_HISTORY_VISIBILITY) => {
            if operation.payload.get("value").and_then(Value::as_str) != Some("world_readable") {
                return Ok(());
            }
            let policy = intended_read_receipt_policy_for_realm(
                state,
                operations,
                operation.realm_id.as_str(),
            )
            .await?;
            validate_read_receipt_policy_against_history(&policy, "world_readable")
        }
        _ => Ok(()),
    }
}

fn read_receipt_policy_projection_from_payload(
    payload: &Value,
) -> Result<ReadReceiptPolicy, &'static str> {
    serde_json::from_value(projection_context_stripped_payload(payload))
        .map_err(|_| "ck.realm.read_receipt_policy payload is invalid")
}

async fn intended_history_visibility_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> String {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            == Some(cokret_sdk::events::kinds::REALM_HISTORY_VISIBILITY)
            && operation.realm_id.as_str() == realm_id
            && let Some(value) = operation.payload.get("value").and_then(Value::as_str)
        {
            return value.to_owned();
        }
    }
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.history_visibility)
        .unwrap_or_else(|| "joined".to_owned())
}

async fn intended_read_receipt_policy_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> Result<ReadReceiptPolicy, &'static str> {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            == Some(cokret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY)
            && operation.realm_id.as_str() == realm_id
        {
            return read_receipt_policy_projection_from_payload(&operation.payload);
        }
    }
    let policy =
        crate::routing::events::event_log::effective_read_receipt_policy_for_realm(state, realm_id)
            .await
            .unwrap_or_default();
    Ok(policy)
}

fn validate_read_receipt_policy_against_history(
    policy: &ReadReceiptPolicy,
    history_visibility: &str,
) -> Result<(), &'static str> {
    if history_visibility != "world_readable"
        || policy.visibility != cokret_sdk::ReadReceiptVisibility::Public
    {
        return Ok(());
    }
    if !policy.allow_public_receipts_on_world_readable {
        return Err(READ_RECEIPT_VISIBILITY_COMBINATION_INVALID);
    }
    if policy.disclosure == cokret_sdk::ReadReceiptDisclosure::Required
        && !policy.allow_forced_public_world_readable_receipts
    {
        return Err(READ_RECEIPT_FORCED_PUBLIC_WORLD_READABLE_FORBIDDEN);
    }
    Ok(())
}

async fn validate_read_receipt_child_policy_write(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
    child_policy: &ReadReceiptPolicy,
) -> Result<(), &'static str> {
    let realm_id = operation.realm_id.as_str();
    let Some(parent_realm_id) = read_receipt_policy_parent_realm_id(state, operations, realm_id)
    else {
        return Ok(());
    };
    let parent_policy =
        intended_read_receipt_policy_for_realm(state, operations, &parent_realm_id).await?;
    parent_policy
        .validate_child_policy(child_policy)
        .map_err(read_receipt_child_violation_reason)
}

fn read_receipt_child_violation_reason(violation: ReadReceiptPolicyChildViolation) -> &'static str {
    match violation {
        ReadReceiptPolicyChildViolation::ComplianceFloorViolated => {
            cokret_sdk::ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
        }
        ReadReceiptPolicyChildViolation::ScopeOverridesDisabled
        | ReadReceiptPolicyChildViolation::DisclosurePrivacyLoosened
        | ReadReceiptPolicyChildViolation::VisibilityLoosened => "policy_denied",
    }
}

fn read_receipt_policy_parent_realm_id(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> Option<String> {
    if let Some(pending) = pending_read_receipt_policy_source_realm(operations, realm_id) {
        return pending.and_then(|source_realm_id| {
            active_read_receipt_parent_link(state, operations, realm_id, &source_realm_id)
                .then_some(source_realm_id)
        });
    }
    let policy = state
        .projection
        .lock()
        .ok()
        .and_then(|projection| projection.realm_inheritance_policy(realm_id).cloned())?;
    if !policy
        .allowed_policies
        .iter()
        .any(|policy| policy == READ_RECEIPT_POLICY_RULE)
    {
        return None;
    }
    active_read_receipt_parent_link(state, operations, realm_id, &policy.source_realm_id)
        .then_some(policy.source_realm_id)
}

fn pending_read_receipt_policy_source_realm(
    operations: &[Operation],
    realm_id: &str,
) -> Option<Option<String>> {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            != Some(cokret_sdk::events::kinds::REALM_INHERITANCE_POLICY)
            || operation.realm_id.as_str() != realm_id
        {
            continue;
        }
        let policies = crate::reducer::inheritance_allowed_policies(&operation.payload);
        if !policies
            .iter()
            .any(|policy| policy == READ_RECEIPT_POLICY_RULE)
        {
            return Some(None);
        }
        return Some(
            operation
                .payload
                .get("source_realm_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        );
    }
    None
}

fn active_read_receipt_parent_link(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
    source_realm_id: &str,
) -> bool {
    if realm_id == source_realm_id {
        return false;
    }
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            != Some(cokret_sdk::events::kinds::REALM_LINK)
            || operation.realm_id.as_str() != realm_id
            || operation
                .payload
                .get("target_realm_id")
                .and_then(Value::as_str)
                != Some(source_realm_id)
        {
            continue;
        }
        return operation
            .payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("active")
            == "active"
            && operation
                .payload
                .get("link_kind")
                .and_then(Value::as_str)
                .is_some_and(read_receipt_parent_link_kind);
    }
    state
        .projection
        .lock()
        .ok()
        .and_then(|projection| projection.realm_links.get(realm_id).cloned())
        .is_some_and(|links| {
            links.iter().any(|link| {
                link.target_realm_id == source_realm_id
                    && link.status == "active"
                    && read_receipt_parent_link_kind(&link.link_kind)
            })
        })
}

fn read_receipt_parent_link_kind(link_kind: &str) -> bool {
    matches!(link_kind, "governed_by" | "inherits_policy_from")
}

pub(crate) async fn validate_realm_key_share_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(cokret_sdk::events::kinds::REALM_KEY_SHARE)
    {
        return Ok(());
    }
    let Some(meta) = state
        .persistence
        .realm_meta()
        .get(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Err("history_sharing_policy_missing");
    };
    let Some(policy_value) = meta.history_sharing_policy.as_ref() else {
        return Err("history_sharing_policy_missing");
    };
    let share =
        serde_json::from_value::<cokret_sdk::RealmKeySharePayload>(operation.payload.clone())
            .map_err(|_| "policy_denied")?;
    if !realm_key_share_receiver_is_current_member(
        state,
        operation.realm_id.as_str(),
        share.recipient_principal_id.as_str(),
    )
    .await
    {
        return Err("not_member");
    }
    if crate::routing::identity::auth::is_device_revoked(
        state,
        share.recipient_principal_id.as_str(),
        &share.recipient_device_id,
    )
    .await
    {
        return Err("device_revoked");
    }
    let device = state
        .persistence
        .devices()
        .get(
            share.recipient_principal_id.as_str(),
            &share.recipient_device_id,
        )
        .await
        .map_err(|_| "policy_denied")?
        .ok_or("policy_denied")?;
    let policy = serde_json::from_value::<cokret_sdk::HistorySharingPolicyPayloadValue>(
        policy_value.clone(),
    )
    .map_err(|_| "policy_denied")?;
    cokret_sdk::validate_history_sharing_policy(&policy).map_err(|_| "policy_denied")?;
    let visibility = share.key_scope.history_visibility.unwrap_or_else(|| {
        meta.history_visibility
            .parse()
            .unwrap_or(cokret_sdk::HistoryVisibility::Restricted)
    });
    let receiver_state = realm_key_share_receiver_event_state(
        state,
        operation.realm_id.as_str(),
        share.recipient_principal_id.as_str(),
    );
    let input = cokret_sdk::HistoryKeyShareGateInput {
        visibility,
        reader: cokret_sdk::HistoryReaderContext {
            current_active_member: true,
            event_state: receiver_state,
            has_discoverability: true,
            has_preview_token: false,
        },
        range: cokret_sdk::HistoryRangeContext {
            since_invite: true,
            since_join: receiver_state == cokret_sdk::HistoryReaderEventState::Joined,
            epoch_span: realm_key_share_epoch_span(
                share.key_scope.from_epoch,
                share.key_scope.to_epoch,
            ),
        },
        policy: Some(&policy),
        key_source: realm_key_share_source(&share),
        scope: None,
        device: cokret_sdk::HistoryDeviceGate {
            revoked: device.revoked_at.is_some(),
            verified: device.verification_state == "verified",
        },
        safety_policy_allows: true,
        audit: cokret_sdk::HistoryAuditGate {
            required: policy.audit.share_audit_event_required,
            satisfied: !policy.audit.share_audit_event_required,
        },
    };
    let decision = cokret_sdk::evaluate_history_key_share_gates(input);
    if decision.allowed {
        Ok(())
    } else {
        Err(match decision.withheld_reason_code {
            Some(cokret_sdk::RealmKeyWithheldReasonCode::NotMember) => "not_member",
            Some(cokret_sdk::RealmKeyWithheldReasonCode::HistoryNotVisible) => {
                "history_not_visible"
            }
            Some(cokret_sdk::RealmKeyWithheldReasonCode::PolicyDenied) => "policy_denied",
            Some(cokret_sdk::RealmKeyWithheldReasonCode::BlacklistedDevice) => "device_revoked",
            Some(cokret_sdk::RealmKeyWithheldReasonCode::UnverifiedDevice) => "policy_denied",
            Some(cokret_sdk::RealmKeyWithheldReasonCode::UnknownSession) => "policy_denied",
            None => "policy_denied",
        })
    }
}

async fn realm_key_share_receiver_is_current_member(
    state: &AppState,
    realm_id: &str,
    receiver: &str,
) -> bool {
    if let Ok(projection) = state.projection.lock()
        && let Some(member) = projection.member(realm_id, receiver)
    {
        return member.state == "join";
    }
    crate::routing::spaces::space::realm_has_member_by_id(state, realm_id, receiver).await
}

fn realm_key_share_receiver_event_state(
    state: &AppState,
    realm_id: &str,
    receiver: &str,
) -> cokret_sdk::HistoryReaderEventState {
    if let Ok(projection) = state.projection.lock()
        && let Some(member) = projection.member(realm_id, receiver)
    {
        return match member.state.as_str() {
            "join" => cokret_sdk::HistoryReaderEventState::Joined,
            "invite" => cokret_sdk::HistoryReaderEventState::Invited,
            "leave" | "ban" => cokret_sdk::HistoryReaderEventState::Removed,
            _ => cokret_sdk::HistoryReaderEventState::None,
        };
    }
    cokret_sdk::HistoryReaderEventState::None
}

fn realm_key_share_source(
    share: &cokret_sdk::RealmKeySharePayload,
) -> cokret_sdk::HistoryKeySource {
    if share.sender_device_id == share.recipient_device_id {
        cokret_sdk::HistoryKeySource::OwnDevice
    } else if share.encrypted_key_ref.is_some() {
        cokret_sdk::HistoryKeySource::KeyBackup
    } else {
        cokret_sdk::HistoryKeySource::VerifiedMemberDevice
    }
}

fn realm_key_share_epoch_span(from_epoch: Option<u64>, to_epoch: Option<u64>) -> Option<u64> {
    Some(to_epoch?.saturating_sub(from_epoch?).saturating_add(1))
}

pub(crate) fn membership_target(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("actor_id")
        .or_else(|| operation.payload.get("member"))
        .or_else(|| operation.payload.get("actor"))
        .or_else(|| operation.payload.get("sender"))
        .and_then(Value::as_str)
}

pub(crate) async fn validate_realm_moderation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(cokret_sdk::events::kinds::REALM_MODERATION_POLICY)
    {
        return Ok(());
    }
    let realm_id = operation.realm_id.as_str();
    let requires_approval = crate::routing::organizations::realm_policy_override_requires_approval(
        state,
        realm_id,
        &operation.payload,
    )
    .await;
    let has_approval = crate::routing::organizations::realm_policy_override_has_approval(
        state,
        realm_id,
        &operation.payload,
    )
    .await;
    if requires_approval && !has_approval {
        return Err("requires_organization_approval");
    }
    Ok(())
}

pub(crate) async fn realm_owner_matches(state: &AppState, realm_id: &str, actor: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|meta| meta.owner == actor)
}

pub(crate) fn validate_poll_operation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::operation_is_message_create(operation) {
        return Ok(());
    }
    let Some(content) = operation.payload.get("content") else {
        return Ok(());
    };
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("ck.content.poll.response") {
        return Ok(());
    }
    let Some(poll_id) = content.get("poll_id").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let Ok(projection) = state.projection.lock() else {
        return Ok(());
    };
    if projection.poll(poll_id).is_some_and(|poll| poll.closed) {
        Err("poll_closed")
    } else {
        Ok(())
    }
}

pub(crate) async fn validate_audience_mention_operation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(cokret_sdk::events::kinds::MESSAGE_CREATE | cokret_sdk::events::kinds::MESSAGE_REVISE)
    ) {
        return Ok(());
    }
    let mentions = operation_audience_mentions(operation)?;
    if mentions.is_empty() {
        return Ok(());
    }
    let actor = operation_actor(operation).ok_or("audience_mention_actor_missing")?;
    let realm_id = operation.realm_id.as_str();
    let resource = operation
        .payload
        .get("strand_id")
        .or_else(|| operation.payload.get("target_ref"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id);
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    let authz = state.authz.check(
        actor,
        CAP_ACTION_MESSAGE_MENTION_BROADCAST,
        resource,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
    if !authz.allowed {
        return Err("ck.message.mention.broadcast required for audience_mention");
    }
    if !authz
        .grants
        .iter()
        .any(grant_has_broadcast_safety_constraints)
    {
        return Err(
            "ck.message.mention.broadcast grant requires temporal and rate_limiting constraints",
        );
    }

    let Some(policy) = effective_audience_mention_policy_for_realm(state, realm_id).await else {
        return Err("audience_mention_policy_missing");
    };
    for mention in mentions {
        let count =
            estimate_audience_recipient_count(mention.audience(), &members, operation, state);
        audience_mention_policy_allows(&policy, mention.audience(), count)?;
    }
    Ok(())
}

pub(crate) fn operation_actor(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("actor_id"))
        .or_else(|| operation.payload.get("created_by"))
        .and_then(Value::as_str)
}

pub(crate) async fn realm_owner_and_members(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten();
    let owner = meta.map(|meta| meta.owner);
    let members = state
        .realms
        .lock()
        .ok()
        .map(|realms| {
            if let Some(realm) = cokret_sdk::RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id))
            {
                return realm.members.iter().map(ToString::to_string).collect();
            }
            Vec::new()
        })
        .unwrap_or_default();
    (owner, members)
}

pub(crate) fn grant_has_broadcast_safety_constraints(grant: &crate::authz::Grant) -> bool {
    let has_temporal = grant.expires_at.is_some()
        || grant.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                crate::authz::Constraint::Temporal {
                    expires_at: Some(_),
                    ..
                }
            )
        });
    let has_rate_limit = grant.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            crate::authz::Constraint::RateLimiting { max_operations, period }
                if *max_operations > 0 && !period.trim().is_empty()
        )
    });
    has_temporal && has_rate_limit
}

pub(crate) async fn effective_audience_mention_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<Value> {
    let events = state
        .persistence
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .ok()?;
    events.into_iter().find_map(|record| {
        record
            .envelope
            .pointer("/payload/object/audience_mention_policy")
            .or_else(|| record.envelope.pointer("/payload/audience_mention_policy"))
            .or_else(|| {
                record
                    .envelope
                    .pointer("/payload/object/notification_policy/audience_mentions")
            })
            .or_else(|| {
                record
                    .envelope
                    .pointer("/payload/notification_policy/audience_mentions")
            })
            .cloned()
    })
}

pub(crate) fn estimate_audience_recipient_count(
    audience: &str,
    members: &[String],
    operation: &Operation,
    state: &AppState,
) -> usize {
    match audience {
        "strand_participants" => operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .map(|strand_id| {
                state
                    .projection
                    .lock()
                    .ok()
                    .map(|projection| {
                        projection
                            .messages_for_thread(strand_id)
                            .into_iter()
                            .map(|message| message.sender.as_str())
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                    })
                    .unwrap_or(members.len())
            })
            .unwrap_or(members.len()),
        // Conservative upper bound: when the dispatcher cannot cheaply derive
        // watchers / assigned actors at policy time, use the readable member
        // set size so max_recipients never underestimates fanout.
        _ => members.len(),
    }
}

pub(crate) fn audience_mention_policy_allows(
    policy: &Value,
    audience: &str,
    recipient_count: usize,
) -> Result<(), &'static str> {
    if policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Err("audience_mention_policy_disabled");
    }
    let audience_policy = policy
        .get("audiences")
        .and_then(|audiences| audiences.get(audience));
    let listed = policy
        .get("allowed_audiences")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item == audience)
        });
    if audience_policy.is_none() && !listed {
        return Err("audience_mention_audience_not_allowed");
    }
    if audience_policy
        .and_then(|entry| entry.get("enabled"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Err("audience_mention_audience_not_allowed");
    }
    let max_recipients = audience_policy
        .and_then(|entry| entry.get("max_recipients"))
        .or_else(|| policy.get("max_recipients"))
        .and_then(Value::as_u64)
        .ok_or("audience_mention_max_recipients_missing")?;
    if recipient_count as u64 > max_recipients {
        return Err("audience_mention_recipient_count_exceeds_limit");
    }
    if !policy_declares_audience_quota(policy, audience_policy) {
        return Err("audience_mention_policy_quota_missing");
    }
    Ok(())
}

fn policy_declares_audience_quota(policy: &Value, audience_policy: Option<&Value>) -> bool {
    [audience_policy, Some(policy)]
        .into_iter()
        .flatten()
        .any(|entry| {
            let quota = entry.get("quota").unwrap_or(entry);
            quota
                .get("max_operations")
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 0)
                && quota
                    .get("period")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
        })
}

pub(crate) fn validate_morph_schema_migrate_capability(
    operation: &Operation,
) -> Result<(), &'static str> {
    if operation
        .payload
        .get("authorization_ref")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("ck:event:"))
        .is_none()
    {
        return Err("ck.morph.schema_migrate requires authorization_ref");
    }
    let action = operation
        .payload
        .get("capability_action")
        .or_else(|| operation.payload.get("action"))
        .and_then(serde_json::Value::as_str);
    if action != Some("ck.morph.schema.migrate") {
        return Err("ck.morph.schema_migrate requires ck.morph.schema.migrate capability");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn read_receipt_policy_projection_ignores_projection_context() {
        let policy = read_receipt_policy_projection_from_payload(&json!({
            "disclosure": "required",
            "event_id": "ck:event:01904100-0000-7000-8000-000000000702",
            "sender": "did:web:alice.example",
            "hlc": "2026-06-14T10:00:00Z/node/1",
            "seal_ref": "ck:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }))
        .unwrap();

        assert_eq!(
            policy.disclosure,
            cokret_sdk::ReadReceiptDisclosure::Required
        );
    }
}
