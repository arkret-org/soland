use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::objects::read_receipts::{
    ReadReceiptPolicy, ReadReceiptPolicyChildViolation,
};
use arkret_wire::EventKind;
use serde_json::Value;

use super::*;

/// `realm-and-space.md` section 2.3 cross-field constraint.
///
/// Only `content_scheme=mls_rfc9420` pins `history_access` to `since_join`;
/// plaintext and `mls_exporter_aead_v1` may use either state. The scheme itself
/// is frozen by the accepted MLS group Genesis, never by `ak.realm.create`:
/// `realm-genesis.schema.json` is `additionalProperties:false` and does not
/// declare `content_scheme`, so a Realm whose MLS group Genesis has not been
/// accepted yet has no effective scheme to compare against. Treating that
/// absence as a violation rejected every MLS-backed Realm create.
pub(crate) async fn validate_history_access_content_scheme_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::RealmCreate)
        | Some(arkret_wire::EventKind::RealmHistoryAccess) => {}
        _ => return Ok(()),
    }
    let realm_id = operation.realm_id.as_str();
    let encryption_profile =
        intended_encryption_profile_for_realm(state, operations, realm_id).await;
    if encryption_profile.as_deref() != Some("mls_rfc9420") {
        return Ok(());
    }
    let Some(content_scheme) = intended_content_scheme_for_realm(state, realm_id) else {
        return Ok(());
    };
    if content_scheme != "mls_rfc9420" {
        return Ok(());
    }
    let history_access = intended_history_access_for_realm(state, operations, realm_id).await;
    if history_access == "since_join" {
        Ok(())
    } else {
        Err("history_access_requires_history_capable_scheme")
    }
}

pub(crate) async fn validate_read_receipt_policy_combination_write(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::RealmReadReceiptPolicy) => {
            let policy = read_receipt_policy_projection_from_payload(&operation.payload)?;
            validate_read_receipt_child_policy_write(state, operations, operation, &policy).await
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

async fn intended_history_access_for_realm(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
) -> String {
    for operation in operations.iter().rev() {
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmHistoryAccess)
            && operation.realm_id.as_str() == realm_id
            && let Some(value) = operation.payload.get("to").and_then(Value::as_str)
        {
            return value.to_owned();
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmCreate)
            && operation.realm_id.as_str() == realm_id
            && let Some(value) = operation
                .payload
                .get("object")
                .and_then(|object| object.get("history_access"))
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
        .map(|meta| meta.history_access)
        .unwrap_or_else(|| "since_join".to_owned())
}

/// The Realm's effective `content_scheme`, or `None` while no accepted MLS
/// group Genesis has fixed one.
///
/// There is no same-batch source: `ak.realm.create` structurally cannot carry
/// the value, and the scheme is create-locked, so scanning the pending
/// operations would only re-read a field the closed genesis schema forbids.
fn intended_content_scheme_for_realm(state: &AppState, realm_id: &str) -> Option<String> {
    let projection = state.projections().snapshot();
    projection.realm_content_scheme(realm_id)
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

/// The principal an `ak.member.state` / `ak.circle.member.state` operation acts
/// on.
///
/// `event-payload.schema.json#/$defs/membership_payload` and
/// `#/$defs/circle_member_state_payload` both name it `actor_id` and are
/// `additionalProperties:false`; `member` / `actor` are not spec fields. When
/// the payload omits `actor_id` the subject is the Event author.
pub(crate) fn membership_target(operation: &Operation) -> Option<&str> {
    Some(
        operation
            .payload
            .get("actor_id")
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
