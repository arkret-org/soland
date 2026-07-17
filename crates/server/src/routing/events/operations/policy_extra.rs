use arkret_sdk::{Operation, ReadReceiptPolicy, ReadReceiptPolicyChildViolation};
use serde_json::Value;
use soland_domain::reducer::poll_id_from_content;

use super::*;

pub(crate) async fn validate_history_visibility_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_sdk::events::EventKind::REALM_HISTORY_VISIBILITY)
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

pub(crate) async fn validate_history_visibility_content_scheme_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_sdk::events::EventKind::REALM_CREATE)
        | Some(arkret_sdk::events::EventKind::REALM_HISTORY_VISIBILITY)
        | Some(arkret_sdk::events::EventKind::REALM_POLICY_COMPONENTS) => {}
        _ => return Ok(()),
    }
    let realm_id = operation.realm_id.as_str();
    let encryption_profile =
        intended_encryption_profile_for_realm(state, operations, realm_id).await;
    if encryption_profile.as_deref() != Some("mls_rfc9420") {
        return Ok(());
    }
    let history_visibility =
        intended_history_visibility_for_realm(state, operations, realm_id).await;
    let content_scheme = intended_content_scheme_for_realm(state, operations, realm_id).await;
    arkret_sdk::validate_history_visibility_content_scheme_values(
        &history_visibility,
        content_scheme.as_deref(),
    )
}

const READ_RECEIPT_VISIBILITY_COMBINATION_INVALID: &str =
    "read_receipt_visibility_combination_invalid";
const READ_RECEIPT_FORCED_PUBLIC_WORLD_READABLE_FORBIDDEN: &str =
    "read_receipt_forced_public_world_readable_forbidden";
const READ_RECEIPT_POLICY_RULE: &str = "ak.realm.read_receipt_policy";

pub(crate) async fn validate_read_receipt_policy_combination_write(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_sdk::events::EventKind::REALM_READ_RECEIPT_POLICY) => {
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
        Some(arkret_sdk::events::EventKind::REALM_HISTORY_VISIBILITY) => {
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
        .map_err(|_| "ak.realm.read_receipt_policy payload is invalid")
}

async fn intended_history_visibility_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> String {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_sdk::events::EventKind::REALM_HISTORY_VISIBILITY)
            && operation.realm_id.as_str() == realm_id
            && let Some(value) = operation.payload.get("value").and_then(Value::as_str)
        {
            return value.to_owned();
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_sdk::events::EventKind::REALM_CREATE)
            && operation.realm_id.as_str() == realm_id
            && let Some(value) = operation
                .payload
                .get("object")
                .and_then(|object| object.get("history_visibility"))
                .and_then(Value::as_str)
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

async fn intended_content_scheme_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> Option<String> {
    for operation in operations.iter().rev() {
        if operation.realm_id.as_str() != realm_id {
            continue;
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_sdk::events::EventKind::REALM_POLICY_COMPONENTS)
            && let Some(value) = policy_components_content_scheme(&operation.payload)
        {
            return Some(value);
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_sdk::events::EventKind::REALM_CREATE)
            && let Some(value) = operation
                .payload
                .get("object")
                .and_then(|object| object.get("content_scheme"))
                .and_then(Value::as_str)
        {
            return Some(value.to_owned());
        }
    }
    {
        let projection = state.projection.lock();
        projection.realm_content_scheme(realm_id)
    }
}

async fn intended_encryption_profile_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> Option<String> {
    for operation in operations.iter().rev() {
        if operation.realm_id.as_str() == realm_id
            && kinds::canonical_kind_for_operation(operation)
                == Some(arkret_sdk::events::EventKind::REALM_CREATE)
            && let Some(value) = operation
                .payload
                .get("object")
                .and_then(|object| object.get("encryption_profile"))
                .and_then(Value::as_str)
        {
            return Some(value.to_owned());
        }
    }
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .and_then(|meta| meta.encryption_profile)
}

fn policy_components_content_scheme(payload: &Value) -> Option<String> {
    let value = projection_context_stripped_payload(payload);
    let value = value.get("value").unwrap_or(&value);
    value
        .get("content_scheme")
        .or_else(|| value.pointer("/components/content_scheme"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

async fn intended_read_receipt_policy_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> Result<ReadReceiptPolicy, &'static str> {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_sdk::events::EventKind::REALM_READ_RECEIPT_POLICY)
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
        || policy.visibility != arkret_sdk::ReadReceiptVisibility::Public
    {
        return Ok(());
    }
    if !policy.allow_public_receipts_on_world_readable {
        return Err(READ_RECEIPT_VISIBILITY_COMBINATION_INVALID);
    }
    if policy.disclosure == arkret_sdk::ReadReceiptDisclosure::Required
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
            arkret_sdk::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
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
    let policy = {
        let projection = state.projection.lock();
        projection.realm_inheritance_policy(realm_id).cloned()
    }?;
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
            != Some(arkret_sdk::events::EventKind::REALM_INHERITANCE_POLICY)
            || operation.realm_id.as_str() != realm_id
        {
            continue;
        }
        let policies = soland_domain::reducer::inheritance_allowed_policies(&operation.payload);
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
            != Some(arkret_sdk::events::EventKind::REALM_LINK)
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
    {
        let projection = state.projection.lock();
        projection.realm_links.get(realm_id).cloned()
    }
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
        != Some(arkret_sdk::events::EventKind::REALM_KEY_SHARE)
    {
        return Ok(());
    }
    let share = serde_json::from_value::<arkret_sdk::RealmKeySharePayload>(
        projection_context_stripped_payload(&operation.payload),
    )
    .map_err(|_| "policy_denied")?;
    // encryption-and-audit.md §2.10.8 — a `ak.realm_key.share` with
    // `share_class=realm_recovery_key` is the Realm Recovery Key (RRK) eager-
    // sealing path: provider-initiated, the recipient is an OFFLINE recovery org
    // (NOT an MLS member, not in the ratchet tree). It MUST NOT be forced through
    // the member history-share gate (it would reject `not_member`). The canonical
    // discriminator is the `share_class` field (event-payload.schema.json); an
    // RRK-class share MUST validate as a declared `durability_policy`
    // recovery recipient or it is rejected.
    if matches!(
        share.share_class,
        arkret_sdk::RealmKeyShareClass::RealmRecoveryKey
    ) {
        return validate_rrk_targeted_realm_key_share(state, operation.realm_id.as_str(), &share)
            .unwrap_or(Err("durability_recovery_recipient_unverified"));
    }
    // share_class=member_device from here: recipient_device_id is required.
    let recipient_device_id = share
        .recipient_device_id
        .as_ref()
        .map(arkret_sdk::DeviceId::as_str)
        .ok_or("policy_denied")?;
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
        recipient_device_id,
    )
    .await
    {
        return Err("device_revoked");
    }
    let device = state
        .persistence
        .devices()
        .get(share.recipient_principal_id.as_str(), recipient_device_id)
        .await
        .map_err(|_| "policy_denied")?
        .ok_or("policy_denied")?;
    let policy = serde_json::from_value::<arkret_sdk::HistorySharingPolicyPayloadValue>(
        policy_value.clone(),
    )
    .map_err(|_| "policy_denied")?;
    arkret_sdk::validate_history_sharing_policy(&policy).map_err(|_| "policy_denied")?;
    let visibility = share.key_scope.history_visibility.unwrap_or_else(|| {
        meta.history_visibility
            .parse()
            .unwrap_or(arkret_sdk::HistoryVisibility::Restricted)
    });
    let receiver_state = realm_key_share_receiver_event_state(
        state,
        operation.realm_id.as_str(),
        share.recipient_principal_id.as_str(),
    );
    let input = arkret_sdk::HistoryKeyShareGateInput {
        visibility,
        reader: arkret_sdk::HistoryReaderContext {
            current_active_member: true,
            event_state: receiver_state,
            has_discoverability: true,
            has_preview_token: false,
        },
        range: arkret_sdk::HistoryRangeContext {
            since_invite: true,
            since_join: receiver_state == arkret_sdk::HistoryReaderEventState::Joined,
            epoch_span: realm_key_share_epoch_span(
                share.key_scope.from_epoch,
                share.key_scope.to_epoch,
            ),
        },
        policy: Some(&policy),
        key_source: realm_key_share_source(&share),
        scope: None,
        device: arkret_sdk::HistoryDeviceGate {
            revoked: device.revoked_at.is_some(),
            verified: device.verification_state == "verified",
        },
        safety_policy_allows: true,
        audit: arkret_sdk::HistoryAuditGate {
            required: policy.audit.share_audit_event_required,
            satisfied: !policy.audit.share_audit_event_required,
        },
    };
    let decision = arkret_sdk::evaluate_history_key_share_gates(input);
    if decision.allowed {
        Ok(())
    } else {
        Err(match decision.withheld_reason_code {
            Some(arkret_sdk::RealmKeyWithheldReasonCode::NotMember) => "not_member",
            Some(arkret_sdk::RealmKeyWithheldReasonCode::HistoryNotVisible) => {
                "history_not_visible"
            }
            Some(arkret_sdk::RealmKeyWithheldReasonCode::PolicyDenied) => "policy_denied",
            Some(arkret_sdk::RealmKeyWithheldReasonCode::BlacklistedDevice) => "device_revoked",
            Some(arkret_sdk::RealmKeyWithheldReasonCode::UnverifiedDevice) => "policy_denied",
            Some(arkret_sdk::RealmKeyWithheldReasonCode::UnknownSession) => "policy_denied",
            None => "policy_denied",
        })
    }
}

/// encryption-and-audit.md §2.10.8 — RRK eager-seal acceptance gate.
///
/// ## RRK design decision (recipient targeting without a wire field)
///
/// The spec `realm_key_share_payload` schema is `additionalProperties:false` and
/// carries no recovery-recipient discriminator. Rather than widen the wire (the
/// spec is authoritative and frozen), soland recognises an RRK-targeted share
/// structurally: a `ak.realm_key.share` whose `recipient_principal_id` equals a
/// `principal_id` listed in the Realm's current
/// `durability_policy.recovery_recipients[]` is treated as the provider-initiated
/// RRK seal for that recipient. This is unambiguous because recovery recipients
/// are offline orgs, NOT realm members — the member history-share path and the
/// RRK path never collide on the same `(recipient_principal_id, realm)`.
///
/// Returns:
/// - `None` — not RRK-targeted; the caller falls through to the member history-share gate.
/// - `Some(Ok(()))` — a valid RRK seal: the recipient is a current recovery recipient, the share
///   carries ciphertext / key material, and `key_scope` references this Realm with a valid epoch
///   range. Membership is NOT required.
/// - `Some(Err(reason))` — RRK-shaped but invalid (recipient no longer a recovery recipient,
///   missing material, or scope mismatch).
///
/// The ciphertext is opaque to soland (HPKE-sealed to the recipient's RRK public
/// key); the server stores it as a durable Event and never decrypts it.
fn validate_rrk_targeted_realm_key_share(
    state: &AppState,
    realm_id: &str,
    share: &arkret_sdk::RealmKeySharePayload,
) -> Option<Result<(), &'static str>> {
    use arkret_sdk::models::DurabilityMode;
    // Snapshot the durability policy off the projection without holding the lock
    // across any await (this function is sync).
    let durability = {
        let projection = state.projection.lock();
        projection.realm_durability_policy(realm_id)?
    };
    if matches!(durability.mode, DurabilityMode::None) {
        // A realm_recovery_key-class share on a Realm without an active
        // durability policy is unverifiable.
        return Some(Err("durability_recovery_recipient_unverified"));
    }
    let recipient = share.recipient_principal_id.as_str();
    let matched = durability
        .recovery_recipients
        .iter()
        .find(|recovery_recipient| recovery_recipient.principal_id.as_str() == recipient);
    let Some(matched) = matched else {
        // realm_recovery_key class but recipient is not a declared recovery
        // recipient — reject (do NOT fall through to the member gate).
        return Some(Err("durability_recovery_recipient_unverified"));
    };
    // The RRK addressing fields MUST match the declared recovery recipient
    // (verification_method + recipient_id), not just the principal.
    if share.recovery_recipient_id.as_deref() != Some(matched.recipient_id.as_str())
        || share.recipient_verification_method.as_deref()
            != Some(matched.verification_method.as_str())
    {
        return Some(Err("durability_recovery_recipient_unverified"));
    }
    // RRK-targeted: validate material presence and that the key_scope references
    // this Realm with a sane epoch range. Membership / history-visibility gates
    // do NOT apply (the recipient is an offline org, not a member).
    let has_material = share
        .ciphertext
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || share.encrypted_key_ref.is_some();
    if !has_material {
        return Some(Err("realm_key_share_material_missing"));
    }
    if share.key_scope.effective_scope.realm_id().as_str() != realm_id {
        return Some(Err("realm_key_share_scope_mismatch"));
    }
    if share
        .key_scope
        .from_epoch
        .zip(share.key_scope.to_epoch)
        .is_some_and(|(from_epoch, to_epoch)| from_epoch > to_epoch)
    {
        return Some(Err("realm_key_share_epoch_range_invalid"));
    }
    Some(Ok(()))
}

async fn realm_key_share_receiver_is_current_member(
    state: &AppState,
    realm_id: &str,
    receiver: &str,
) -> bool {
    {
        let projection = state.projection.lock();
        if let Some(member) = projection.member(realm_id, receiver) {
            return member.state == "join";
        }
    }
    crate::routing::spaces::space::realm_has_member_by_id(state, realm_id, receiver).await
}

fn realm_key_share_receiver_event_state(
    state: &AppState,
    realm_id: &str,
    receiver: &str,
) -> arkret_sdk::HistoryReaderEventState {
    {
        let projection = state.projection.lock();
        if let Some(member) = projection.member(realm_id, receiver) {
            return match member.state.as_str() {
                "join" => arkret_sdk::HistoryReaderEventState::Joined,
                "invite" => arkret_sdk::HistoryReaderEventState::Invited,
                "leave" | "ban" => arkret_sdk::HistoryReaderEventState::Removed,
                _ => arkret_sdk::HistoryReaderEventState::None,
            };
        }
    }
    arkret_sdk::HistoryReaderEventState::None
}

fn realm_key_share_source(
    share: &arkret_sdk::RealmKeySharePayload,
) -> arkret_sdk::HistoryKeySource {
    if share
        .recipient_device_id
        .as_ref()
        .map(arkret_sdk::DeviceId::as_str)
        == Some(share.sender_device_id.as_str())
    {
        arkret_sdk::HistoryKeySource::OwnDevice
    } else if share.encrypted_key_ref.is_some() {
        arkret_sdk::HistoryKeySource::KeyBackup
    } else {
        arkret_sdk::HistoryKeySource::VerifiedMemberDevice
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
        != Some(arkret_sdk::events::EventKind::REALM_MODERATION_POLICY)
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
        return Err(arkret_sdk::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL);
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
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("ak.content.poll.response") {
        return Ok(());
    }
    let Some(poll_id) = poll_id_from_content(content) else {
        return Ok(());
    };
    let projection = state.projection.lock();
    if projection.poll(&poll_id).is_some_and(|poll| poll.closed) {
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
        Some(
            arkret_sdk::events::EventKind::MESSAGE_CREATE
                | arkret_sdk::events::EventKind::MESSAGE_REVISE
        )
    ) {
        return Ok(());
    }
    let mentions = operation_audience_mentions(operation)?;
    if mentions.is_empty() {
        return Ok(());
    }
    let actor = operation.actor().ok_or("audience_mention_actor_missing")?;
    let actor = actor.as_str();
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
        arkret_sdk::CapabilityActionId::MESSAGE_MENTION_BROADCAST,
        resource,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
    if !authz.allowed {
        return Err("ak.message.mention.broadcast required for audience_mention");
    }
    if !authz
        .grants
        .iter()
        .any(grant_has_broadcast_safety_constraints)
    {
        return Err(
            "ak.message.mention.broadcast grant requires temporal and rate_limiting constraints",
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
    let members = {
        let realms = state.realms.lock();
        arkret_sdk::RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|id| realms.get(&id))
            .map(|realm| realm.members.iter().map(ToString::to_string).collect())
            .unwrap_or_default()
    };
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
                {
                    let projection = state.projection.lock();
                    Some({
                        projection
                            .messages_for_thread(strand_id)
                            .into_iter()
                            .map(|message| message.sender.as_str())
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                    })
                }
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
        .filter(|value| value.starts_with("ak:event:"))
        .is_none()
    {
        return Err("ak.morph.schema_migrate requires authorization_ref");
    }
    let action = operation
        .payload
        .get("capability_action")
        .or_else(|| operation.payload.get("action"))
        .and_then(serde_json::Value::as_str);
    // `capability-action-registry.json` is canonical: the action id is the
    // same-name `ak.morph.schema_migrate`. The dotted `ak.morph.schema.migrate`
    // spelling used in some prose is accepted as an alias so existing callers
    // are not broken.
    if !matches!(
        action,
        Some("ak.morph.schema_migrate" | "ak.morph.schema.migrate")
    ) {
        return Err("ak.morph.schema_migrate requires ak.morph.schema_migrate capability");
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
            "event_id": "ak:event:01904100-0000-7000-8000-000000000702",
            "sender": "did:web:alice.example",
            "hlc": "2026-06-14T10:00:00Z/node/1",
            "seal_ref": "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }))
        .unwrap();

        assert_eq!(
            policy.disclosure,
            arkret_sdk::ReadReceiptDisclosure::Required
        );
    }
}
