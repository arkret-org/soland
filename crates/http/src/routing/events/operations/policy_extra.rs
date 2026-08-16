use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::events_payloads::{RealmKeyShareMaterial, RealmKeyShareTarget};
use arkret_models_collaboration::objects::read_receipts::{
    ReadReceiptPolicy, ReadReceiptPolicyChildViolation,
};
use arkret_wire::EventKind;
use serde_json::Value;

use super::*;

pub(crate) async fn validate_history_visibility_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::RealmHistoryVisibility)
    {
        return Ok(());
    }
    if operation.payload.get("value").and_then(Value::as_str) != Some("restricted") {
        return Ok(());
    }
    let Some(meta) = state
        .realms()
        .realm_metadata(operation.realm_id.as_str())
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
        Some(arkret_wire::EventKind::RealmCreate)
        | Some(arkret_wire::EventKind::RealmHistoryVisibility)
        | Some(arkret_wire::EventKind::RealmPolicyBundle) => {}
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
    arkret_models_collaboration::governance::history_visibility::validate_history_visibility_content_scheme_values(
        &history_visibility,
        content_scheme.as_deref(),
    )
}

/// `history_visibility=restricted` requires an effective
/// `ak.realm.history_sharing_policy` (history-visibility.md §3). This is the
/// batch-level half of that rule, for the `ak.realm.create` genesis case.
///
/// The Realm object cannot carry the policy — `realm.schema.json` is closed and
/// declares no `history_sharing_policy` property — so there are exactly two
/// admissible sources:
///
/// * a Principal Control Realm takes the profile-fixed baseline from `ak.profile.principal_control_
///   realm.v1`, because the facet kind is absent from its event-kind allowlist and its genesis is a
///   closed unit (realm-and-space.md §2.8.1);
/// * every other Realm MUST accept `ak.realm.history_sharing_policy` in the same ordered submit
///   batch, where it is a registered seal_basis-exempt bootstrap follow-up (realm-and-space.md
///   §2.5), or already have one projected.
pub(crate) async fn validate_restricted_history_sharing_policy_present(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match restricted_history_sharing_requirement(operations, operation)? {
        RestrictedHistorySharingRequirement::NotApplicable => Ok(()),
        RestrictedHistorySharingRequirement::SatisfiedInBatch => Ok(()),
        // Nothing in this batch supplies the policy; the Realm may still have
        // one from an earlier accepted Event.
        RestrictedHistorySharingRequirement::NeedsProjectedPolicy => {
            let projected = state
                .realms()
                .realm_metadata(operation.realm_id.as_str())
                .await
                .ok()
                .flatten()
                .is_some_and(|meta| meta.history_sharing_policy.is_some());
            if projected {
                Ok(())
            } else {
                Err("history_sharing_policy_missing")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RestrictedHistorySharingRequirement {
    NotApplicable,
    SatisfiedInBatch,
    NeedsProjectedPolicy,
}

/// The batch-visible half of the decision, kept pure so the rule is testable
/// without an `AppState`. Returns `Err` only for the PCR case whose profile-fixed
/// baseline is unreadable — a PCR with no evaluable policy MUST fail closed
/// rather than be admitted as if history sharing were open.
fn restricted_history_sharing_requirement(
    operations: &[Operation],
    operation: &Operation,
) -> Result<RestrictedHistorySharingRequirement, &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::RealmCreate) {
        return Ok(RestrictedHistorySharingRequirement::NotApplicable);
    }
    let Some(object) = operation.payload.get("object") else {
        return Ok(RestrictedHistorySharingRequirement::NotApplicable);
    };
    if object.get("history_visibility").and_then(Value::as_str) != Some("restricted") {
        return Ok(RestrictedHistorySharingRequirement::NotApplicable);
    }
    if arkret_models_collaboration::objects::realm::realm_object_is_principal_control(object) {
        arkret_policy::history_visibility::principal_control_realm_history_sharing_policy()
            .map_err(|_| "history_sharing_policy_missing")?;
        return Ok(RestrictedHistorySharingRequirement::NotApplicable);
    }
    let realm_id = operation.realm_id.as_str();
    let in_batch = operations.iter().any(|candidate| {
        kinds::canonical_kind_for_operation(candidate)
            == Some(arkret_wire::EventKind::RealmHistorySharingPolicy)
            && candidate.realm_id.as_str() == realm_id
            && candidate.payload.get("value").is_some()
    });
    Ok(if in_batch {
        RestrictedHistorySharingRequirement::SatisfiedInBatch
    } else {
        RestrictedHistorySharingRequirement::NeedsProjectedPolicy
    })
}

async fn realm_is_principal_control(state: &AppState, realm_id: &str) -> bool {
    let projection = state.projections().snapshot();
    projection.realm_is_principal_control(realm_id)
}

const READ_RECEIPT_VISIBILITY_COMBINATION_INVALID: &str =
    "read_receipt_visibility_combination_invalid";
const READ_RECEIPT_FORCED_PUBLIC_WORLD_READABLE_FORBIDDEN: &str =
    "read_receipt_forced_public_world_readable_forbidden";

pub(crate) async fn validate_read_receipt_policy_combination_write(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::RealmReadReceiptPolicy) => {
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
        Some(arkret_wire::EventKind::RealmHistoryVisibility) => {
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
    serde_json::from_value(payload.clone())
        .map_err(|_| "ak.realm.read_receipt_policy payload is invalid")
}

async fn intended_history_visibility_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> String {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmHistoryVisibility)
            && operation.realm_id.as_str() == realm_id
            && let Some(value) = operation.payload.get("value").and_then(Value::as_str)
        {
            return value.to_owned();
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmCreate)
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
        .realms()
        .realm_metadata(realm_id)
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
            == Some(arkret_wire::EventKind::RealmPolicyBundle)
            && let Some(value) = policy_bundle_content_scheme(&operation.payload)
        {
            return Some(value);
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmCreate)
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
        let projection = state.projections().snapshot();
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
                == Some(arkret_wire::EventKind::RealmCreate)
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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .and_then(|meta| meta.encryption_profile)
}

fn policy_bundle_content_scheme(payload: &Value) -> Option<String> {
    let value = payload.clone();
    value
        .get("content_scheme")
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
            == Some(arkret_wire::EventKind::RealmReadReceiptPolicy)
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
        || policy.visibility
            != arkret_models_collaboration::objects::read_receipts::ReadReceiptVisibility::Public
    {
        return Ok(());
    }
    if !policy
        .receipt_compliance_opt_in
        .public_receipts_on_world_readable
    {
        return Err(READ_RECEIPT_VISIBILITY_COMBINATION_INVALID);
    }
    if policy.disclosure
        == arkret_models_collaboration::objects::read_receipts::ReadReceiptDisclosure::Required
        && !policy
            .receipt_compliance_opt_in
            .forced_public_world_readable_receipts
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
            arkret_wire::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
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
        let projection = state.projections().snapshot();
        projection.realm_inheritance_policy(realm_id).cloned()
    }?;
    if !policy
        .allowed_policies
        .iter()
        .any(|policy| policy == EventKind::RealmReadReceiptPolicy.as_str())
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
            != Some(arkret_wire::EventKind::RealmInheritancePolicy)
            || operation.realm_id.as_str() != realm_id
        {
            continue;
        }
        let policies =
            soland_services::operation_semantics::inheritance_allowed_policies(&operation.payload);
        if !policies
            .iter()
            .any(|policy| policy == EventKind::RealmReadReceiptPolicy.as_str())
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
        if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::RealmLink)
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
        let projection = state.projections().snapshot();
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
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::RealmKeyShare)
    {
        return Ok(());
    }
    let share = operation
        .typed_payload::<arkret_wire::event_spec::RealmKeyShare>()
        .map_err(|error| {
            tracing::debug!(%error, "realm key share projection payload parse failed");
            "policy_denied"
        })?;
    // encryption-and-audit.md §2.10.8 — a `ak.realm_key.share` with
    // `share_kind=realm_recovery_key` is the Realm Recovery Key (RRK) eager-
    // sealing path: provider-initiated, the recipient is an OFFLINE recovery org
    // (NOT an MLS member, not in the ratchet tree). It MUST NOT be forced through
    // the member history-share gate (it would reject `not_member`). The canonical
    // discriminator is the `share_kind` field (event-payload.schema.json); an
    // RRK-class share MUST validate as a declared `durability_policy`
    // recovery recipient or it is rejected.
    if matches!(
        share.share_kind,
        arkret_models_collaboration::events_payloads::RealmKeyShareClass::RealmRecoveryKey
    ) {
        return validate_rrk_targeted_realm_key_share(state, operation.realm_id.as_str(), &share)
            .unwrap_or(Err("durability_recovery_recipient_unverified"));
    }
    // share_kind=member_device from here: the typed target names the device.
    let RealmKeyShareTarget::MemberDevice {
        ref recipient_device_id,
    } = share.target
    else {
        return Err("policy_denied");
    };
    let recipient_device_id = recipient_device_id.as_str();
    let Some(meta) = state
        .realms()
        .realm_metadata(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Err("history_sharing_policy_missing");
    };
    // Principal Control and Direct Conversation Realms have no projected
    // policy cell and never can: each profile supplies one fixed effective
    // baseline.  An absent Event is therefore not a missing policy for either
    // constrained Realm role.
    let policy = if let Some(policy_value) = meta.history_sharing_policy.as_ref() {
        let policy = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::HistorySharingPolicyPayloadValue,
        >(policy_value.clone())
        .map_err(|_| "policy_denied")?;
        arkret_policy::history_visibility::validate_history_sharing_policy(&policy)
            .map_err(|_| "policy_denied")?;
        policy
    } else if realm_is_principal_control(state, operation.realm_id.as_str()).await {
        arkret_policy::history_visibility::principal_control_realm_history_sharing_policy()
            .map_err(|_| "history_sharing_policy_missing")?
    } else if is_direct_conversation_realm(state, operation.realm_id.as_str()) {
        arkret_policy::history_visibility::direct_conversation_realm_history_sharing_policy()
            .map_err(|_| "history_sharing_policy_missing")?
    } else {
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
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: share.recipient_principal_id.to_string(),
            device_id: recipient_device_id.to_owned(),
        })
        .await
        .map_err(|_| "policy_denied")?
        .ok_or("policy_denied")?;
    let visibility = share.key_scope.history_visibility.unwrap_or_else(|| {
        meta.history_visibility
            .parse()
            .unwrap_or(arkret_wire::primitives::HistoryVisibility::Restricted)
    });
    let receiver_state = realm_key_share_receiver_event_state(
        state,
        operation.realm_id.as_str(),
        share.recipient_principal_id.as_str(),
    );
    let input = arkret_policy::history_visibility::HistoryKeyShareGateInput {
        visibility,
        reader: arkret_models_collaboration::governance::history_visibility::HistoryReaderContext {
            current_active_member: true,
            event_state: receiver_state,
            has_discoverability: true,
            has_preview_token: false,
        },
        range: arkret_models_collaboration::governance::history_visibility::HistoryRangeContext {
            since_invite: true,
            since_join: receiver_state == arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState::Joined,
            epoch_span: realm_key_share_epoch_span(
                share.key_scope.from_epoch,
                share.key_scope.to_epoch,
            ),
        },
        policy: Some(&policy),
        key_source: realm_key_share_source(&share),
        scope: None,
        device: arkret_models_collaboration::governance::history_visibility::HistoryDeviceGate {
            revoked: device.revoked_at.is_some(),
            verified: device.verification_state == "verified",
        },
        safety_policy_allows: true,
        audit: arkret_models_collaboration::governance::history_visibility::HistoryAuditGate {
            required: policy.audit.share_audit_event_required,
            satisfied: !policy.audit.share_audit_event_required,
        },
    };
    let decision = arkret_policy::history_visibility::evaluate_history_key_share_gates(input);
    if decision.allowed {
        Ok(())
    } else {
        Err(match decision.withheld_reason_code {
            Some(arkret_models_collaboration::governance::history_visibility::RealmKeyWithheldReasonCode::NotMember) => "not_member",
            Some(arkret_models_collaboration::governance::history_visibility::RealmKeyWithheldReasonCode::HistoryNotVisible) => {
                "history_not_visible"
            }
            Some(arkret_models_collaboration::governance::history_visibility::RealmKeyWithheldReasonCode::PolicyDenied) => "policy_denied",
            Some(arkret_models_collaboration::governance::history_visibility::RealmKeyWithheldReasonCode::BlacklistedDevice) => "device_revoked",
            Some(arkret_models_collaboration::governance::history_visibility::RealmKeyWithheldReasonCode::UnverifiedDevice) => "policy_denied",
            Some(arkret_models_collaboration::governance::history_visibility::RealmKeyWithheldReasonCode::UnknownSession) => "policy_denied",
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
    share: &arkret_models_collaboration::events_payloads::RealmKeySharePayload,
) -> Option<Result<(), &'static str>> {
    use arkret_models_collaboration::objects::realm::DurabilityMode;

    // Snapshot the durability policy off the projection without holding the lock
    // across any await (this function is sync).
    let durability = {
        let projection = state.projections().snapshot();
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
    let RealmKeyShareTarget::RealmRecoveryKey {
        ref recipient_verification_method,
        ref recovery_recipient_id,
    } = share.target
    else {
        return Some(Err("durability_recovery_recipient_unverified"));
    };
    if recovery_recipient_id.as_str() != matched.recipient_id.as_str()
        || recipient_verification_method.as_str() != matched.verification_method.as_str()
    {
        return Some(Err("durability_recovery_recipient_unverified"));
    }
    // RRK-targeted: the key_scope must reference this Realm with a sane epoch
    // range. Membership / history-visibility gates do NOT apply (the recipient
    // is an offline org, not a member). Exactly-one material is a wire
    // invariant, so only a whitespace-only ciphertext still needs guarding.
    if let RealmKeyShareMaterial::Ciphertext { ref ciphertext } = share.material
        && ciphertext.trim().is_empty()
    {
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
        let projection = state.projections().snapshot();
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
) -> arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState {
    {
        let projection = state.projections().snapshot();
        if let Some(member) = projection.member(realm_id, receiver) {
            return match member.state.as_str() {
                "join" => arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState::Joined,
                "invite" => arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState::Invited,
                "leave" | "ban" => arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState::Removed,
                _ => arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState::None,
            };
        }
    }
    arkret_models_collaboration::governance::history_visibility::HistoryReaderEventState::None
}

fn realm_key_share_source(
    share: &arkret_models_collaboration::events_payloads::RealmKeySharePayload,
) -> arkret_models_collaboration::governance::history_visibility::HistoryKeySource {
    let recipient_device_id = match &share.target {
        RealmKeyShareTarget::MemberDevice {
            recipient_device_id,
        } => Some(recipient_device_id.as_str()),
        RealmKeyShareTarget::RealmRecoveryKey { .. } => None,
    };
    if recipient_device_id == Some(share.sender_device_id.as_str()) {
        arkret_models_collaboration::governance::history_visibility::HistoryKeySource::OwnDevice
    } else if matches!(
        share.material,
        RealmKeyShareMaterial::EncryptedKeyRef { .. }
    ) {
        arkret_models_collaboration::governance::history_visibility::HistoryKeySource::KeyBackup
    } else {
        arkret_models_collaboration::governance::history_visibility::HistoryKeySource::VerifiedMemberDevice
    }
}

fn realm_key_share_epoch_span(from_epoch: Option<u64>, to_epoch: Option<u64>) -> Option<u64> {
    Some(to_epoch?.saturating_sub(from_epoch?).saturating_add(1))
}

pub(crate) fn membership_target(operation: &Operation) -> Option<&str> {
    Some(
        operation
            .payload
            .get("actor_id")
            .or_else(|| operation.payload.get("member"))
            .or_else(|| operation.payload.get("actor"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| operation.context.sender.as_str()),
    )
}

pub(crate) async fn validate_realm_moderation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::RealmModerationPolicy)
    {
        return Ok(());
    }
    let realm_id = operation.realm_id.as_str();
    let Some(policy) = operation
        .payload
        .get("value")
        .filter(|value| value.is_object())
    else {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    };
    let requires_approval = crate::routing::organizations::realm_policy_override_requires_approval(
        state, realm_id, policy,
    )
    .await;
    let has_approval =
        crate::routing::organizations::realm_policy_override_has_approval(state, realm_id, policy)
            .await;
    if requires_approval && !has_approval {
        return Err(arkret_wire::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL);
    }
    Ok(())
}

pub(crate) async fn validate_audience_mention_operation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise)
    ) {
        return Ok(());
    }
    validate_sidecar_mention_subjects(state, operation).await?;
    let mentions = operation_audience_mentions(operation)?;
    if mentions.is_empty() {
        return Ok(());
    }
    let actor = operation.context.sender.as_str();
    let realm_id = operation.realm_id.as_str();
    let resource = operation
        .payload
        .get("strand_id")
        .or_else(|| operation.payload.get("target_ref"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id);
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    let authz = state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            actor_principal_server_id: Some(operation.context.principal_server_id.as_str()),
            action: arkret_wire::CapabilityActionId::MESSAGE_MENTION_BROADCAST,
            resource,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        });
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
        let audience = mention.audience.as_wire();
        let count = estimate_audience_recipient_count(audience, &members, operation, state);
        audience_mention_policy_allows(&policy, audience, count)?;
    }
    Ok(())
}

async fn validate_sidecar_mention_subjects(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let sidecar_id = operation.payload.get("sidecar_id").and_then(Value::as_str);
    let Some((controller_id, realm_id)) = sidecar_id.and_then(|sidecar_id| {
        let projection = state.projections().snapshot();
        projection
            .sidecars
            .get(sidecar_id)
            .map(|sidecar| (sidecar.controller_id.clone(), sidecar.realm_id.clone()))
    }) else {
        return Ok(());
    };
    let subjects = match operation.payload.get("content") {
        Some(content) => mention_subject_ids(content)?,
        None => Vec::new(),
    };
    if subjects.is_empty() {
        return Ok(());
    }
    let desired = crate::routing::identity::agents::sidecar::derive_sidecar_desired_agent_ids(
        state,
        &realm_id,
        &controller_id,
    )
    .await
    .map_err(|_| "addressed_agent_not_eligible")?;
    if subjects
        .iter()
        .any(|subject| !desired.iter().any(|agent| agent == subject.as_str()))
    {
        Err("addressed_agent_not_eligible")
    } else {
        Ok(())
    }
}

pub(crate) async fn realm_owner_and_members(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let meta = state.realms().realm_metadata(realm_id).await.ok().flatten();
    let owner = meta.map(|meta| meta.owner);
    let members = {
        let realms = state.realm_directory().snapshot();
        arkret_identifiers::RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|id| realms.get(&id))
            .map(|realm| realm.members.iter().map(ToString::to_string).collect())
            .unwrap_or_default()
    };
    (owner, members)
}

/// The single Realm-governance issuer predicate every review surface uses.
///
/// `authz/capabilities.md` section 3.2 makes the Realm owner aggregate an
/// authorization source in its own right, so a governance decision is allowed
/// when either of two independent, revocable-by-governance sources holds:
///
/// 1. `actor` speaks for the owner aggregate - it is the controller of the registered
///    `ak.component.realm.authority_root.v1` cell, or it holds a live `ak.realm.owner` co-owner
///    grant;
/// 2. `actor` holds one of `actions` verbatim, through the projected capability-grant cells or the
///    engine read index over them.
///
/// Realm membership and the discardable `realm_states[..].owner` presentation
/// mirror are never inputs. Every caller goes through this function so the two
/// legs cannot drift apart per surface.
pub(crate) async fn actor_governs_realm(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    actor_principal_server_id: Option<&str>,
    actions: &[&str],
    evaluation_basis: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(actor_principal_server_id) = actor_principal_server_id else {
        return false;
    };
    if state.projections().snapshot().actor_governs_realm(
        realm_id,
        actor,
        actor_principal_server_id,
        actions,
        evaluation_basis,
    ) {
        return true;
    }
    // The engine grant map is a read index over the same projected cells; it is
    // still consulted so an index entry that has not been re-projected yet does
    // not silently drop a governance capability.
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    actions.iter().any(|action| {
        state
            .authorization()
            .check(soland_services::authorization::AuthorizationCheck {
                actor,
                actor_principal_server_id: Some(actor_principal_server_id),
                action,
                resource: realm_id,
                realm_id,
                owner: owner.as_deref(),
                members: &members,
                resource_facets: &[],
            })
            .allowed
    })
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
        .event_queries()
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
                    let projection = state.projections().snapshot();
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
        .filter(|value| value.starts_with("ak:grant:"))
        .is_none()
    {
        return Err("ak.morph.schema_migrate requires authorization_ref");
    }
    let action = operation
        .payload
        .get("capability_action")
        .or_else(|| operation.payload.get("action"))
        .and_then(serde_json::Value::as_str);
    // `capability-action-registry.json` is canonical: there is no dotted alias.
    if action != Some(arkret_wire::CapabilityActionId::MORPH_SCHEMA_MIGRATE) {
        return Err("ak.morph.schema_migrate requires ak.morph.schema_migrate capability");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm_create_op(realm_id: &str, object: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(realm_id).unwrap(),
            arkret_wire::EventKind::RealmCreate.as_str(),
            json!({"object": object}),
        )
    }

    fn history_sharing_policy_op(realm_id: &str) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(realm_id).unwrap(),
            arkret_wire::EventKind::RealmHistorySharingPolicy.as_str(),
            json!({"value": {"version": 1}}),
        )
    }

    const TEST_REALM: &str = "ak:realm:AdZZE-oq_ajB9qhMdhGsoZ00nbkTKuQc52revNalDJtB";
    const OTHER_REALM: &str = "ak:realm:Ad0vyieMPSwHhJrufgQFMCDbPEI90kF_TEQVJchouhw2";

    /// `history_visibility=restricted` on an ordinary Realm MUST be backed by an
    /// `ak.realm.history_sharing_policy`. It cannot come from the closed Realm
    /// object, so the only in-batch source is the sibling facet Event.
    #[test]
    fn ordinary_restricted_create_is_satisfied_only_by_a_same_realm_batch_policy() {
        let create = realm_create_op(TEST_REALM, json!({"history_visibility": "restricted"}));

        // Alone in the batch: falls through to the projected-policy lookup.
        assert_eq!(
            restricted_history_sharing_requirement(std::slice::from_ref(&create), &create).unwrap(),
            RestrictedHistorySharingRequirement::NeedsProjectedPolicy
        );

        // Sibling facet Event for the same Realm satisfies it in-batch.
        let batch = vec![create.clone(), history_sharing_policy_op(TEST_REALM)];
        assert_eq!(
            restricted_history_sharing_requirement(&batch, &create).unwrap(),
            RestrictedHistorySharingRequirement::SatisfiedInBatch
        );

        // A policy Event for a DIFFERENT Realm must not satisfy this create.
        let cross_realm = vec![create.clone(), history_sharing_policy_op(OTHER_REALM)];
        assert_eq!(
            restricted_history_sharing_requirement(&cross_realm, &create).unwrap(),
            RestrictedHistorySharingRequirement::NeedsProjectedPolicy
        );
    }

    /// The canonical `purpose` discriminator selects the PCR profile-fixed
    /// baseline. A profile ref without that discriminator remains an ordinary
    /// Realm and must carry the projected policy.
    #[test]
    fn principal_control_purpose_skips_the_history_sharing_policy_requirement() {
        let pcr = realm_create_op(
            TEST_REALM,
            json!({
                "history_visibility": "restricted",
                "purpose": "principal_control",
                "schema_refs": [
                    "ak.schema.realm.v1",
                    "ak.profile.principal_control_realm.v1"
                ]
            }),
        );
        assert_eq!(
            restricted_history_sharing_requirement(std::slice::from_ref(&pcr), &pcr).unwrap(),
            RestrictedHistorySharingRequirement::NotApplicable
        );

        let purpose_only = realm_create_op(
            TEST_REALM,
            json!({
                "history_visibility": "restricted",
                "purpose": "principal_control"
            }),
        );
        assert_eq!(
            restricted_history_sharing_requirement(
                std::slice::from_ref(&purpose_only),
                &purpose_only,
            )
            .unwrap(),
            RestrictedHistorySharingRequirement::NotApplicable
        );

        let profile_ref_only = realm_create_op(
            TEST_REALM,
            json!({
                "history_visibility": "restricted",
                "schema_refs": [
                    "ak.schema.realm.v1",
                    "ak.profile.principal_control_realm.v1"
                ]
            }),
        );
        assert_eq!(
            restricted_history_sharing_requirement(
                std::slice::from_ref(&profile_ref_only),
                &profile_ref_only,
            )
            .unwrap(),
            RestrictedHistorySharingRequirement::NeedsProjectedPolicy,
            "a profile ref without the principal_control purpose keeps the ordinary requirement"
        );
    }

    /// A non-restricted create carries no requirement at all.
    #[test]
    fn non_restricted_create_carries_no_history_sharing_requirement() {
        let create = realm_create_op(TEST_REALM, json!({"history_visibility": "shared"}));
        assert_eq!(
            restricted_history_sharing_requirement(std::slice::from_ref(&create), &create).unwrap(),
            RestrictedHistorySharingRequirement::NotApplicable
        );
    }
}
