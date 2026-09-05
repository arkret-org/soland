use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::membership_invite::InviteClaimPayload;
use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;
use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;
use arkret_wire::{AccountId, ActorId, PlaintextDataClassKind};
use serde_json::Value;
use soland_services::events::RealmInviteState as RealmInviteRecord;
use soland_services::operation_semantics as kinds;

use super::*;
use crate::state::AppState;

/// Spec invite-addressing.md / event-kind-registry — project an accepted
/// `ak.invite.accept` durable event. The invitee_id submits it to close the
/// group-invite loop:
///   1. resolve the referenced invite, validating it is still `pending` and that the accepting
///      sender == the invite's `invitee_id`;
///   2. flip the `RealmInviteRecord` to `accepted`;
///   3. cascade membership — activate the invitee_id's `ak.member.state(join)` in the target Realm
///      (in-memory member index) so the capability grants carried on the invite take effect.
///
/// Replays and mismatched senders are ignored fail-closed.
pub(super) async fn project_invite_accept_operation(state: &AppState, operation: &Operation) {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::InviteAccept {
        return;
    }
    let Some(account) = operation.context.sender.as_account_id() else {
        return;
    };
    let accepter = account.to_string();
    let member = operation.context.sender.to_string();
    let Some(invite_id) = invite_acceptance_ref_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.invite.accept missing valid invite_ref/invite_id"
        );
        return;
    };
    let invites = state.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        tracing::warn!(invite_id = %invite_id, "ak.invite.accept references unknown invite");
        return;
    };
    if record.invitee_id.as_deref() != Some(accepter.as_str()) {
        tracing::warn!(
            invite_id = %invite_id,
            accepter = %accepter,
            "ak.invite.accept sender is not the invitee_id; ignored"
        );
        return;
    }
    if record.realm_id != operation.realm_id.as_str() {
        tracing::warn!(
            invite_id = %invite_id,
            record_realm = %record.realm_id,
            operation_realm = %operation.realm_id,
            "ak.invite.accept realm mismatch; ignored"
        );
        return;
    }
    if !matches!(record.status.as_str(), "pending" | "claimed") {
        tracing::debug!(
            invite_id = %invite_id,
            status = %record.status,
            "ak.invite.accept on non-acceptable invite; ignored"
        );
        return;
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        tracing::warn!(invite_id = %invite_id, "ak.invite.accept on expired invite; ignored");
        return;
    }
    record.status = "accepted".to_owned();
    record.updated_at = Some(operation.created_at);
    record.invite_token.clear();
    let realm_id = record.realm_id.clone();
    let invite_created_at = record.created_at;
    if let Err(error) = invites.put(record).await {
        tracing::warn!(%error, invite_id = %invite_id, "failed to mark invite accepted");
        return;
    }
    // Cascade membership: activate the invitee_id's join in the target Realm
    // member index so subsequent realm-scoped reads include them.
    if let Ok(realm_id_typed) = RealmId::new(realm_id.clone()) {
        state
            .realm_directory()
            .add_member(&realm_id_typed, account.principal_id.clone());
    }
    project_invite_accept_membership(state, &realm_id, &member, invite_created_at, operation);
    touch_realm(state, &realm_id).await;
    tracing::info!(
        invite_id = %invite_id,
        invitee_id = %accepter,
        realm_id = %realm_id,
        "ak.invite.accept projected: invite accepted + membership cascaded"
    );
}

fn project_invite_accept_membership(
    state: &AppState,
    realm_id: &str,
    member: &str,
    invite_created_at: chrono::DateTime<chrono::Utc>,
    operation: &Operation,
) {
    state
        .projections()
        .project_invite_acceptance(realm_id, member, invite_created_at, operation);
}

pub(super) async fn project_invite_cancel_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::InviteCancel {
        return;
    }
    project_invite_terminal_operation(state, origin, operation, InviteTerminalEvent::Cancel).await;
}

/// Every invite kind whose registered contract declares
/// `pre_state_requirements` over `ak.component.invite.lifecycle.v1`.
///
/// `ak.invite.cancel` binds its required `invitee_account_id`;
/// `ak.invite.accept` and `ak.invite.revoke` bind their optional one with
/// `stored_field_matches_payload`, which is what stops a third-party invite
/// from releasing somebody else's live-target slot and stops a directed invite
/// from stranding its own (`governance-objects.md` section 5.3).
pub(in crate::routing::events) const INVITE_LIFECYCLE_PRE_STATE_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::INVITE_ACCEPT,
    arkret_wire::event_kind_str::INVITE_CANCEL,
    arkret_wire::event_kind_str::INVITE_REVOKE,
];

/// Freeze the authoritative lifecycle row and its registered cell before an
/// invite lifecycle Move reaches durable acceptance.
///
/// The caller holds the per-Invite lifecycle admission lock while this
/// snapshot is built and consumed. The SDK pre-state predicates and Soland's
/// lifecycle/member checks therefore inspect exactly the same values.
pub(in crate::routing::events) async fn freeze_invite_lifecycle_pre_state(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<arkret_schema::FrozenPreState, &'static str> {
    let mut frozen = arkret_schema::FrozenPreState::new();
    if !INVITE_LIFECYCLE_PRE_STATE_KINDS.contains(&event.kind.as_str()) {
        return Ok(frozen);
    }
    let invite_id = event
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .ok_or("reducer_projection_failed")?;
    let record = state
        .realm_invites()
        .get(invite_id)
        .await
        .map_err(|_| "reducer_projection_failed")?
        .ok_or("reducer_projection_failed")?;
    if record.realm_id != event.realm_id.as_str() {
        return Err("reducer_projection_failed");
    }
    if record.third_party_invite.is_none() && record.invitee_id.is_none() {
        return Err("reducer_projection_failed");
    }

    let lifecycle_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"
    ))
    .map_err(|_| "reducer_projection_failed")?;
    let projection = state.projections().snapshot();
    let lifecycle_value = projection
        .cell_value(&lifecycle_cell)
        .ok_or("reducer_projection_failed")?;
    let lifecycle_status = lifecycle_value
        .as_str()
        .or_else(|| lifecycle_value.get("state").and_then(Value::as_str))
        .ok_or("reducer_projection_failed")?;
    if lifecycle_status != record.status {
        return Err("reducer_projection_failed");
    }

    let mut lifecycle = serde_json::Map::from_iter([
        ("invite_id".to_owned(), Value::String(record.invite_id)),
        ("realm_id".to_owned(), Value::String(record.realm_id)),
        ("state".to_owned(), Value::String(record.status)),
        (
            "third_party".to_owned(),
            Value::Bool(record.third_party_invite.is_some()),
        ),
    ]);
    if record.third_party_invite.is_none()
        && let Some(invitee_id) = record.invitee_id
    {
        let account: AccountId =
            serde_json::from_str(&invitee_id).map_err(|_| "reducer_projection_failed")?;
        lifecycle.insert(
            "invitee_account_id".to_owned(),
            serde_json::to_value(account).map_err(|_| "reducer_projection_failed")?,
        );
    }
    frozen.insert(lifecycle_cell, Value::Object(lifecycle));
    Ok(frozen)
}

/// Validate the remaining lifecycle predicates against the exact pre-state
/// already consumed by the SDK registered-write projector.
///
/// Projection-time rejection is too late: once the Event is durable, skipping
/// the lifecycle/member projection would permanently split the two cells.
pub(in crate::routing::events) fn validate_invite_cancel_pre_admission(
    _origin: &str,
    operation: &Operation,
    frozen_pre_state: &arkret_schema::FrozenPreState,
) -> Result<(), &'static str> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::InviteCancel {
        return Ok(());
    }
    let invite_id =
        invite_acceptance_ref_for_operation(operation).ok_or("reducer_projection_failed")?;
    let lifecycle_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"
    ))
    .map_err(|_| "reducer_projection_failed")?;
    let lifecycle = frozen_pre_state
        .get(&lifecycle_cell)
        .ok_or("reducer_projection_failed")?;
    if lifecycle.get("realm_id").and_then(Value::as_str) != Some(operation.realm_id.as_str()) {
        return Err("reducer_projection_failed");
    }
    if lifecycle.get("third_party").and_then(Value::as_bool) == Some(true) {
        return Err("invite_kind_requires_revoke");
    }
    let account: AccountId = serde_json::from_value(
        lifecycle
            .get("invitee_account_id")
            .cloned()
            .ok_or("reducer_projection_failed")?,
    )
    .map_err(|_| "reducer_projection_failed")?;
    if invitee_for_operation(operation).as_ref() != Some(&account) {
        return Err("reducer_projection_failed");
    }
    if !matches!(
        lifecycle.get("state").and_then(Value::as_str),
        Some("pending" | "claimed" | "send_failed")
    ) {
        return Err("reducer_projection_failed");
    }
    let terminal_status = invite_terminal_transition_target(operation, &invite_id)
        .ok_or("reducer_projection_failed")?;
    let expected_status = if operation.context.sender.as_account_id() == Some(&account) {
        "rejected"
    } else {
        "revoked"
    };
    if terminal_status != expected_status {
        return Err("reducer_projection_failed");
    }
    Ok(())
}

/// Why an `ak.invite.create` cannot claim its invitee's Realm live-target slot.
pub(in crate::routing::events) enum InviteLiveTargetRejection {
    /// The registered contract cannot be evaluated for this Event at all.
    ProjectionFailed(&'static str),
    /// Another live directed Invite already holds the slot.
    Occupied(Box<arkret_wire::InviteLiveTargetOccupiedProblem>),
}

/// Reject a duplicate directed invite before it is accepted.
///
/// `governance-objects.md` section 5.3 makes
/// `ak.component.invite.live_target.v1` the sole truth source for "one live
/// directed Invite per invitee per Realm", and gives the duplicate exactly one
/// outcome: `failed_precondition` + `invite_live_target_occupied`, with the
/// Event refused, absent from canonical history, and deriving no cell write,
/// projection or notification. There is no idempotent-replay branch — the
/// second Event cannot compute the first one's `invite_id`, and admitting it
/// with zero registered writes is the contract violation this whole slot
/// exists to remove.
///
/// The slot is read from the same materialized head `check_move_preconditions`
/// compares against, so a client that carried the required
/// `head_eq: null` and one that omitted it are both refused here — the
/// difference is only that this lane names the sub-reason and echoes the
/// occupant so the client can act (`details.create_event_id` is the slot value
/// and therefore the `head_eq` a release Move must carry).
pub(in crate::routing::events) fn validate_invite_live_target_admission(
    operation: &Operation,
    projection: &soland_domain::reducer::ProjectionState,
) -> Result<(), InviteLiveTargetRejection> {
    if !kinds::operation_is_invite_create(operation) {
        return Ok(());
    }
    let invitee_account = invitee_for_operation(operation).ok_or(
        InviteLiveTargetRejection::ProjectionFailed("reducer_projection_failed"),
    )?;
    let cell = arkret_schema::invite_live_target_cell(&invitee_account)
        .map_err(|_| InviteLiveTargetRejection::ProjectionFailed("reducer_projection_failed"))?;
    let Some(value) = projection.realm_cell_value(operation.realm_id.as_str(), &cell) else {
        return Ok(());
    };
    let slot = arkret_schema::InviteLiveTargetSlot::from_cell_value(value)
        .map_err(|_| InviteLiveTargetRejection::ProjectionFailed("reducer_projection_failed"))?;
    match slot.create_event_id() {
        None => Ok(()),
        Some(create_event_id) => Err(InviteLiveTargetRejection::Occupied(Box::new(
            arkret_wire::InviteLiveTargetOccupiedProblem::new(create_event_id.clone()),
        ))),
    }
}

pub(super) async fn project_invite_revoke_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::InviteRevoke {
        return;
    }
    project_invite_terminal_operation(state, origin, operation, InviteTerminalEvent::Revoke).await;
}

#[derive(Clone, Copy)]
enum InviteTerminalEvent {
    Cancel,
    Revoke,
}

async fn project_invite_terminal_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
    terminal_event: InviteTerminalEvent,
) {
    let Some(invite_id) = invite_acceptance_ref_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "invite terminal event missing valid invite_id"
        );
        return;
    };
    let invites = state.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        tracing::warn!(invite_id = %invite_id, "invite terminal event references unknown invite");
        return;
    };
    if record.realm_id != operation.realm_id.as_str() {
        tracing::warn!(
            invite_id = %invite_id,
            record_realm = %record.realm_id,
            operation_realm = %operation.realm_id,
            "invite terminal event realm mismatch"
        );
        return;
    }
    if matches!(
        record.status.as_str(),
        "accepted"
            | "rejected"
            | "revoked"
            | "revoked_by_capability_loss"
            | "revoked_by_inviter_left"
            | "expired"
            | "invalidated_by_rate_limit"
    ) {
        tracing::debug!(
            invite_id = %invite_id,
            status = %record.status,
            "invite terminal event on terminal invite ignored"
        );
        return;
    }
    let Some(terminal_status) = invite_terminal_transition_target(operation, &invite_id) else {
        tracing::warn!(
            invite_id = %invite_id,
            "invite terminal event omits its lifecycle transition"
        );
        return;
    };
    let sender_account = operation
        .context
        .sender
        .as_account_id()
        .map(ToString::to_string);
    let expected_cancel_status =
        if record.invitee_id.is_some() && record.invitee_id == sender_account {
            "rejected"
        } else {
            "revoked"
        };
    let terminal_status_allowed = match terminal_event {
        InviteTerminalEvent::Cancel => terminal_status == expected_cancel_status,
        // `send_failed` is the one non-terminal `ak.invite.revoke` target. Its
        // only legal in-edge is `pending -> send_failed`
        // (`governance-objects.md` section 5.3), and it keeps the invite inside
        // the live set, so it releases no live-target slot.
        InviteTerminalEvent::Revoke if terminal_status == "send_failed" => {
            record.status == "pending"
        }
        InviteTerminalEvent::Revoke => matches!(
            terminal_status,
            "revoked"
                | "expired"
                | "revoked_by_capability_loss"
                | "revoked_by_inviter_left"
                | "invalidated_by_rate_limit"
        ),
    };
    if !terminal_status_allowed {
        tracing::warn!(
            invite_id = %invite_id,
            status = %terminal_status,
            "invite terminal event carries an invalid lifecycle target"
        );
        return;
    }
    let direct_invitee = record.invitee_id.clone();
    // `send_failed` derives no live-target write, so the payload schema forbids
    // `invitee_account_id` on it and there is nothing to match. Every other
    // terminal target carries it and MUST match the stored account byte for
    // byte — the SDK pre-state predicate already refused a mismatch, this keeps
    // the read-model projection on the same rule.
    if terminal_status != "send_failed"
        && let Some(invitee_id) = direct_invitee.as_deref()
        && invitee_for_operation(operation)
            .map(|account| account.to_string())
            .as_deref()
            != Some(invitee_id)
    {
        tracing::warn!(
            invite_id = %invite_id,
            "direct invite terminal event has a missing or mismatched invitee_id"
        );
        return;
    };
    let direct_member = direct_invitee
        .as_deref()
        .and_then(|key| serde_json::from_str::<AccountId>(key).ok())
        .map(|account| ActorId::account(account).to_string());
    if direct_invitee.is_some() && direct_member.is_none() {
        return;
    }
    record.status = terminal_status.to_owned();
    record.updated_at = Some(operation.created_at);
    record.invite_token.clear();
    remove_third_party_active_material(
        &mut record.third_party_invite,
        terminal_status != "rejected",
    );
    let realm_id = record.realm_id.clone();
    match invites.put(record).await {
        Ok(()) => {
            touch_realm(state, &realm_id).await;
            tracing::info!(
                invite_id = %invite_id,
                actor = %origin,
                realm_id = %realm_id,
                status = %terminal_status,
                "invite terminal event projected"
            );
        }
        Err(error) => {
            tracing::warn!(%error, invite_id = %invite_id, "failed to project invite terminal event")
        }
    }
}

fn invite_terminal_transition_target<'a>(
    operation: &'a Operation,
    invite_id: &str,
) -> Option<&'a str> {
    operation
        .payload
        .get("target_state")
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("effects")
                .and_then(Value::as_array)?
                .iter()
                .find(|effect| {
                    effect
                        .get("cell")
                        .and_then(Value::as_str)
                        .is_some_and(|cell| {
                            cell == format!("ak:cell:ak.component.invite.lifecycle.v1:{invite_id}")
                        })
                })
                .and_then(|effect| effect.pointer("/op/to"))
                .and_then(Value::as_str)
        })
}

pub(super) async fn project_invite_third_party_operation(state: &AppState, operation: &Operation) {
    if !kinds::operation_is_invite_third_party(operation) {
        return;
    }
    let Some(payload) = operation.payload.as_object() else {
        return;
    };
    let invite_id =
        arkret_identifiers::InviteId::from_event_id(&operation.context.event_id).to_string();
    let Some(inviter) = operation.context.sender.as_account_id() else {
        return;
    };
    let inviter_id = inviter.to_string();
    let Some(third_party_invite_value) = payload.get("third_party_invite").cloned() else {
        tracing::warn!(invite_id = %invite_id, "ak.invite.third_party missing third_party_invite");
        return;
    };
    let third_party_invite =
        match serde_json::from_value::<ThirdPartyInvite>(third_party_invite_value) {
            Ok(third_party_invite) => third_party_invite,
            Err(error) => {
                tracing::warn!(
                    invite_id = %invite_id,
                    %error,
                    "ak.invite.third_party third_party_invite fails the closed schema"
                );
                return;
            }
        };
    let expires_at = string_field(payload, "expires_at")
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
        .map(|value| value.with_timezone(&chrono::Utc));
    let created_at = operation.created_at;
    let invites = state.realm_invites();
    if matches!(invites.get(&invite_id).await, Ok(Some(_))) {
        return;
    }
    let mut third_party_invite = Some(third_party_invite);
    let mut status = "pending".to_owned();
    if expires_at.is_some_and(|expires_at| expires_at <= operation.created_at) {
        status = "expired".to_owned();
        remove_third_party_active_material(&mut third_party_invite, true);
    }
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: operation.realm_id.to_string(),
        inviter_id,
        invitee_id: None,
        introduction_evidence_digest: None,
        third_party_invite,
        invite_token: String::new(),
        status,
        claim_nonces: std::collections::BTreeMap::new(),
        expires_at,
        created_at,
        updated_at: Some(operation.created_at),
    };
    match invites.put(record).await {
        Ok(()) => touch_realm(state, operation.realm_id.as_str()).await,
        Err(error) => {
            tracing::warn!(%error, invite_id = %invite_id, "failed to project third-party invite")
        }
    }
}

pub(super) async fn project_invite_claim_operation(state: &AppState, operation: &Operation) {
    if !kinds::operation_is_invite_claim(operation) {
        return;
    }
    let Ok(claim) = serde_json::from_value::<InviteClaimPayload>(operation.payload.clone()) else {
        return;
    };
    if claim.validate().is_err() {
        return;
    }
    let invite_id = claim.invite_id.as_str().to_owned();
    let subject_id = claim.subject_account_id.to_string();
    let token_commitment = claim.token_commitment.as_str().to_owned();
    let claim_nonce = claim.claim_nonce.clone();
    let invites = state.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        return;
    };
    match record.claim_nonces.get(&claim_nonce) {
        Some(existing_operation_id) if existing_operation_id != operation.operation_id.as_str() => {
            tracing::debug!(invite_id = %invite_id, "duplicate ak.invite.claim nonce ignored");
            return;
        }
        Some(_) => {}
        None => {
            record
                .claim_nonces
                .insert(claim_nonce.clone(), operation.operation_id.to_string());
        }
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        record.status = "expired".to_owned();
        record.updated_at = Some(operation.created_at);
        record.invite_token.clear();
        remove_third_party_active_material(&mut record.third_party_invite, true);
        let _ = invites.put(record).await;
        return;
    }
    if record.realm_id != operation.realm_id.as_str() || record.status != "pending" {
        return;
    }
    if record
        .third_party_invite
        .as_ref()
        .and_then(third_party_token_commitment)
        != Some(token_commitment.as_str())
    {
        let _ = invites.put(record).await;
        return;
    }
    if !claim_binding_matches(&record, &claim, operation.created_at) {
        let _ = invites.put(record).await;
        return;
    }
    record.status = "claimed".to_owned();
    record.invitee_id = Some(subject_id);
    record.updated_at = Some(operation.created_at);
    record.invite_token.clear();
    remove_third_party_active_material(&mut record.third_party_invite, false);
    match invites.put(record).await {
        Ok(()) => touch_realm(state, operation.realm_id.as_str()).await,
        Err(error) => {
            tracing::warn!(%error, invite_id = %invite_id, "failed to project invite claim")
        }
    }
}

pub(super) fn invite_acceptance_ref_for_operation(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("invite_ref")
        .or_else(|| operation.payload.get("invite_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| arkret_identifiers::InviteId::new((*value).to_owned()).is_ok())
        .map(str::to_owned)
}

pub(super) async fn project_invite_create_operation(state: &AppState, operation: &Operation) {
    if !kinds::operation_is_invite_create(operation) {
        return;
    }
    let Some(invitee_account) = invitee_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "ak.invite.create missing valid invitee_account_id"
        );
        return;
    };
    let invitee_id = invitee_account.to_string();
    let invitee_actor = ActorId::account(invitee_account).to_string();
    let Some(invite_id) = invite_id_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "ak.invite.create missing valid invite id"
        );
        return;
    };
    if crate::routing::spaces::space::realm_has_member_by_id(
        state,
        operation.realm_id.as_str(),
        &invitee_actor,
    )
    .await
    {
        tracing::debug!(
            invite_id = %invite_id,
            invitee_id = %invitee_id.as_str(),
            realm_id = %operation.realm_id,
            "ak.invite.create projection skipped: invitee_id is already a member"
        );
        return;
    }

    let Some(inviter) = operation.context.sender.as_account_id() else {
        return;
    };
    let inviter_id = inviter.to_string();
    let expires_at = operation
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .or_else(|| Some(operation.created_at + chrono::Duration::days(7)));
    let introduction_evidence_digest = introduction_evidence_digest_for_operation(operation);
    let invites = state.realm_invites();
    match invites.get(&invite_id).await {
        Ok(Some(existing)) => {
            let reconciles_private_delivery = existing.status == "pending"
                && existing.realm_id == operation.realm_id.as_str()
                && existing.inviter_id == inviter_id
                && existing.invitee_id.as_deref() == Some(invitee_id.as_str())
                && existing.introduction_evidence_digest == introduction_evidence_digest
                && existing.third_party_invite.is_none()
                && existing.claim_nonces.is_empty()
                && existing.expires_at == expires_at
                && existing.created_at == operation.created_at;
            if reconciles_private_delivery {
                touch_realm(state, operation.realm_id.as_str()).await;
                tracing::info!(
                    invite_id = %invite_id,
                    invitee_id = %invitee_id.as_str(),
                    realm_id = %operation.realm_id,
                    "reconciled shared ak.invite.create after private invite delivery"
                );
            } else {
                tracing::warn!(
                    invite_id = %invite_id,
                    status = %existing.status,
                    "existing invite conflicts with shared ak.invite.create projection"
                );
            }
            return;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, invite_id = %invite_id, "failed to read projected invite");
            return;
        }
    }
    // No duplicate scan here. Live directed-invite uniqueness is carried by the
    // registered `ak.component.invite.live_target.v1` slot and enforced at
    // admission by `validate_invite_live_target_admission`
    // (`governance-objects.md` section 5.3). A projection-time scan would be a
    // second, implementation-private truth source: it cannot revoke a cell the
    // registered reducer already wrote, it silently omits a registered write
    // (a contract violation in its own right), and it made "is this invite
    // live" depend on a local `expires_at` comparison, which the same section
    // forbids. An Event that reaches this point has already been admitted with
    // its `head_eq` on the slot.
    let invite_token = crate::routing::generate_invite_token(
        &invite_id,
        operation.realm_id.as_str(),
        invitee_id.as_str(),
    );
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: operation.realm_id.to_string(),
        inviter_id,
        invitee_id: Some(invitee_id.as_str().to_owned()),
        introduction_evidence_digest,
        third_party_invite: None,
        invite_token,
        // The accepted create always initializes the reducer lifecycle at
        // `pending`. A private delivery target is routing metadata, not a
        // second lifecycle state; delivery failure requires its own signed
        // transition to `send_failed`.
        status: "pending".to_owned(),
        claim_nonces: std::collections::BTreeMap::new(),
        expires_at,
        created_at: operation.created_at,
        updated_at: None,
    };
    match invites.put(record).await {
        Ok(()) => {
            // Invite lifecycle is independent from `ak.member.state`. Create
            // records only the pending Invite; accept performs the registered
            // atomic lifecycle + member `leave -> join` transition.
            tracing::info!(
                invite_id = %invite_id,
                invitee_id = %invitee_id.as_str(),
                realm_id = %operation.realm_id,
                "projected invite via ak.invite.create event"
            );
            touch_realm(state, operation.realm_id.as_str()).await;
        }
        Err(error) => tracing::warn!(%error, invite_id = %invite_id, "failed to project invite"),
    }
}

/// `invite` is an Event-derived kind, so its only legitimate identity is the
/// create Event's 33-byte token retyped. A producer-supplied `invite_id` is
/// accepted only when it equals that derivation; nothing may be minted from the
/// producer-allocated `operation_id`, which would fabricate an identity the
/// creating Event never bound.
fn invite_id_for_operation(operation: &Operation) -> Option<String> {
    let event_id = operation.context.event_id.clone();
    let derived = arkret_identifiers::InviteId::from_event_id(&event_id).to_string();
    if let Some(invite_id) = operation
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && invite_id != derived
    {
        tracing::warn!(
            operation_id = %operation.operation_id,
            invite_id = %invite_id,
            "ak.invite.create supplied an invite_id that is not the create Event token"
        );
        return None;
    }
    Some(derived)
}

fn string_field(payload: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn third_party_token_commitment(third_party_invite: &ThirdPartyInvite) -> Option<&str> {
    third_party_invite
        .token_commitment
        .as_ref()
        .map(arkret_identifiers::Hash::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn remove_third_party_active_material(
    third_party_invite: &mut Option<ThirdPartyInvite>,
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

fn claim_binding_matches(
    record: &RealmInviteRecord,
    claim: &InviteClaimPayload,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let binding = &claim.binding_proof;
    let service_id = binding.verification_id.as_str();
    if record
        .third_party_invite
        .as_ref()
        .map(|third_party| third_party.verification_id.as_str())
        != Some(service_id)
    {
        return false;
    }
    let Some(expires_at) = chrono::DateTime::parse_from_rfc3339(&binding.expires_at)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
    else {
        return false;
    };
    binding.subject_account_id == claim.subject_account_id
        && binding.realm_id.as_str() == record.realm_id
        && binding.claim_nonce == claim.claim_nonce
        && expires_at > now
        && record
            .expires_at
            .is_none_or(|invite_expiry| expires_at <= invite_expiry)
}

fn invitee_for_operation(operation: &Operation) -> Option<AccountId> {
    operation
        .payload
        .get("invitee_account_id")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

/// Only the tests below name this cell: the invite lifecycle deliberately never
/// writes it, and asserting that requires addressing it.
#[cfg(test)]
fn invite_member_cell(account: &AccountId) -> Result<arkret_identifiers::CellRef, &'static str> {
    let actor = ActorId::account(account.clone());
    let subject = arkret_wire::composite_subject(&[actor.to_string()])
        .map_err(|_| "reducer_projection_failed")?;
    arkret_identifiers::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
        .map_err(|_| "reducer_projection_failed")
}

fn introduction_evidence_digest_for_operation(operation: &Operation) -> Option<String> {
    let digest = operation
        .payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if arkret_identifiers::Hash::new(digest.to_owned()).is_err() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.invite.create supplied invalid introduction_evidence_digest"
        );
        return None;
    }
    Some(digest.to_owned())
}

pub(super) fn plaintext_services_from_operation(operation: &Operation) -> Vec<String> {
    plaintext_visible_services_payload(operation)
        .map(|payload| {
            payload
                .services
                .into_iter()
                .map(|service| service.service_id.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn plaintext_service_classes_from_operation(
    operation: &Operation,
) -> BTreeMap<String, BTreeSet<PlaintextDataClassKind>> {
    let mut by_service: BTreeMap<String, BTreeSet<PlaintextDataClassKind>> = BTreeMap::new();
    if let Some(payload) = plaintext_visible_services_payload(operation) {
        for service in payload.services {
            let classes = by_service
                .entry(service.service_id.as_str().to_owned())
                .or_default();
            classes.extend(service.data_classes);
        }
    }
    by_service
}

fn plaintext_visible_services_payload(
    operation: &Operation,
) -> Option<PlaintextVisibleServicesPayload> {
    let payload = if let Some(services) = operation.payload.get("services") {
        serde_json::json!({ "services": services })
    } else {
        let services = operation
            .payload
            .pointer("/object/plaintext_visible_services")?
            .clone();
        serde_json::json!({ "services": services })
    };
    serde_json::from_value(payload).ok()
}

pub(super) async fn project_plaintext_visible_services_operation(
    state: &AppState,
    operation: &Operation,
) {
    let services = plaintext_services_from_operation(operation);
    let service_classes = plaintext_service_classes_from_operation(operation);
    if services.is_empty() && service_classes.is_empty() {
        return;
    }
    let service = state.realms();
    let Ok(Some(mut record)) = service.realm_metadata(operation.realm_id.as_str()).await else {
        return;
    };
    for service in services {
        if !record
            .plaintext_visible_services
            .iter()
            .any(|existing| existing == &service)
        {
            record.plaintext_visible_services.insert(service);
        }
    }
    for (service, classes) in service_classes {
        record.plaintext_visible_services.insert(service.clone());
        record
            .plaintext_visible_service_classes
            .entry(service)
            .or_default()
            .extend(classes);
    }
    record.updated_at = operation.created_at;
    if let Err(error) = service
        .store_realm_metadata(operation.realm_id.as_str(), record)
        .await
    {
        tracing::warn!(%error, "failed to project plaintext visible services");
    }
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::DidCoreId;
    use serde_json::json;

    use super::*;

    const CANCEL_REALM: &str = "ak:realm:AeMdjqxM9dnJ8ik-DD-XWcNeb1liwy0eVEWHTvxfesqr";
    const CANCEL_INVITE: &str = "ak:invite:ARlxuxcITxQTVrXf396EgxLPdvGfJpZqw0WToWbVAKXW";
    const CANCEL_INVITER: &str = "did:web:alice.example";
    const CANCEL_INVITEE: &str = "did:web:bob.example";

    fn fixture_account(did: &str) -> AccountId {
        AccountId::new(
            crate::test_actor_id_str(did),
            crate::test_event::station_id(),
        )
    }

    fn fixture_actor(did: &str) -> String {
        ActorId::account(fixture_account(did)).to_string()
    }

    fn invite_test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        )
    }

    fn cancel_event(invitee_id: Option<&str>) -> arkret_wire::Event {
        let mut payload = json!({
            "invite_id": CANCEL_INVITE,
            "target_state": "revoked",
        });
        if let Some(invitee_id) = invitee_id {
            payload["invitee_account_id"] = json!(fixture_account(invitee_id));
        }
        crate::test_event::raw_event(
            arkret_wire::EventKind::InviteCancel.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(CANCEL_REALM).unwrap(),
            },
            crate::test_actor_id_str(CANCEL_INVITER),
            0,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            payload,
        )
        .unwrap()
    }

    fn cancel_operation(invitee_id: Option<&str>) -> Operation {
        let event = cancel_event(invitee_id);
        arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000000523",
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
    }

    async fn seed_cancel_invite(state: &AppState, third_party: bool) {
        let created_at = "2026-07-29T10:00:00Z".parse().unwrap();
        state
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id: CANCEL_INVITE.to_owned(),
                realm_id: CANCEL_REALM.to_owned(),
                inviter_id: fixture_account(CANCEL_INVITER).to_string(),
                invitee_id: (!third_party).then(|| fixture_account(CANCEL_INVITEE).to_string()),
                introduction_evidence_digest: None,
                third_party_invite: third_party.then(|| ThirdPartyInvite {
                    oob_code_kind:
                        arkret_models_collaboration::governance::third_party_invite::ThirdPartyInviteOobKind::OfflineToken,
                    display_name_hint: None,
                    token_commitment: Some(
                        arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64)))
                            .unwrap(),
                    ),
                    token_salt_id: Some("salt-1".to_owned()),
                    token_entropy_bits: Some(128),
                    lookup_table_ref: None,
                    pepper_id: None,
                    max_claims: 1,
                    verification_id: DidCoreId::new(
                        "ak:did_core:web:verify.example".to_owned(),
                    )
                    .unwrap(),
                    verification_public_key: "did:web:verify.example#invite-key".to_owned(),
                }),
                invite_token: "private-token".to_owned(),
                status: "pending".to_owned(),
                claim_nonces: BTreeMap::new(),
                expires_at: Some("2026-08-05T10:00:00Z".parse().unwrap()),
                created_at,
                updated_at: None,
            })
            .await
            .unwrap();
        state.projections().cache_cell(
            arkret_identifiers::CellRef::new(format!(
                "ak:cell:ak.component.invite.lifecycle.v1:{CANCEL_INVITE}"
            ))
            .unwrap(),
            json!("pending"),
        );
        let _ = third_party;
    }

    async fn assert_cancel_state_unchanged(state: &AppState, expected_invitee: Option<&str>) {
        assert!(
            state
                .event_queries()
                .accepted_events()
                .await
                .unwrap()
                .is_empty(),
            "pre-admission failure must not accept a canonical Event"
        );
        let record = state
            .realm_invites()
            .get(CANCEL_INVITE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.status, "pending");
        assert_eq!(
            record.invitee_id,
            expected_invitee.map(|did| fixture_account(did).to_string())
        );
        assert_eq!(record.invite_token, "private-token");
        assert_eq!(
            state.projections().cell_value(
                &arkret_identifiers::CellRef::new(format!(
                    "ak:cell:ak.component.invite.lifecycle.v1:{CANCEL_INVITE}"
                ))
                .unwrap()
            ),
            Some(json!("pending"))
        );
        if let Some(invitee_id) = expected_invitee {
            assert_eq!(
                state
                    .projections()
                    .cell_value(&invite_member_cell(&fixture_account(invitee_id)).unwrap()),
                None,
                "Invite lifecycle must not synthesize an ak.member.state cell"
            );
            assert!(
                state
                    .projections()
                    .snapshot()
                    .member(CANCEL_REALM, &fixture_actor(invitee_id))
                    .is_none(),
                "Invite lifecycle must not synthesize a member projection"
            );
        }
    }

    #[tokio::test]
    async fn direct_invite_cancel_uses_only_the_frozen_invite_lifecycle() {
        let state = invite_test_state();
        seed_cancel_invite(&state, false).await;
        let event = cancel_event(Some(CANCEL_INVITEE));
        let frozen = freeze_invite_lifecycle_pre_state(&state, &event)
            .await
            .unwrap();
        let writes = state
            .projections()
            .project_cell_writes_with_pre_state(&event, &frozen)
            .unwrap();

        // Two writes since the live-target slot landed (`governance-objects.md`
        // section 5.3): the lifecycle transition, and the release that puts the
        // invitee's slot back to `null` so a later invite can claim it.
        // Neither touches member state — that is what "only the frozen invite
        // lifecycle" means here.
        let families = writes
            .iter()
            .map(|write| {
                write
                    .cell_id
                    .as_str()
                    .split(':')
                    .nth(2)
                    .expect("cell ref carries its family")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            families,
            vec![
                arkret_wire::CellFamilyId::INVITE_LIFECYCLE_V1.to_owned(),
                arkret_wire::CellFamilyId::INVITE_LIVE_TARGET_V1.to_owned(),
            ]
        );
        validate_invite_cancel_pre_admission(
            CANCEL_INVITER,
            &cancel_operation(Some(CANCEL_INVITEE)),
            &frozen,
        )
        .unwrap();
        assert_cancel_state_unchanged(&state, Some(CANCEL_INVITEE)).await;
    }

    #[tokio::test]
    async fn direct_invite_cancel_missing_or_mismatched_invitee_has_zero_side_effects() {
        for supplied_invitee in [None, Some("did:web:mallory.example")] {
            let state = invite_test_state();
            seed_cancel_invite(&state, false).await;
            let event = cancel_event(supplied_invitee);
            let frozen = freeze_invite_lifecycle_pre_state(&state, &event)
                .await
                .unwrap();
            let error = state
                .projections()
                .project_cell_writes_with_pre_state(&event, &frozen)
                .unwrap_err();

            assert_eq!(error.reason_code(), "reducer_projection_failed");
            assert_cancel_state_unchanged(&state, Some(CANCEL_INVITEE)).await;
        }
    }

    #[tokio::test]
    async fn invite_cancel_cannot_retarget_the_same_principal_at_another_station() {
        let state = invite_test_state();
        seed_cancel_invite(&state, false).await;
        let mut event = cancel_event(Some(CANCEL_INVITEE));
        event.payload.get_mut("invitee_account_id").unwrap()["station_id"] =
            json!("ak:did_core:web:other-station.example");
        let frozen = freeze_invite_lifecycle_pre_state(&state, &event)
            .await
            .unwrap();
        assert_eq!(
            state
                .projections()
                .project_cell_writes_with_pre_state(&event, &frozen)
                .unwrap_err()
                .reason_code(),
            "reducer_projection_failed"
        );
        assert_cancel_state_unchanged(&state, Some(CANCEL_INVITEE)).await;
    }

    #[test]
    fn directed_invite_requires_the_exact_account_field() {
        let mut operation = cancel_operation(Some(CANCEL_INVITEE));
        assert_eq!(
            invitee_for_operation(&operation),
            Some(fixture_account(CANCEL_INVITEE))
        );
        operation.payload = json!({"invitee_account_id": CANCEL_INVITEE});
        assert!(invitee_for_operation(&operation).is_none());
        operation.payload = json!({"invitee_id": fixture_account(CANCEL_INVITEE)});
        assert!(invitee_for_operation(&operation).is_none());
    }

    #[tokio::test]
    async fn third_party_invite_cancel_requires_revoke_with_zero_side_effects() {
        let state = invite_test_state();
        seed_cancel_invite(&state, true).await;
        let event = cancel_event(Some(CANCEL_INVITEE));
        let frozen = freeze_invite_lifecycle_pre_state(&state, &event)
            .await
            .unwrap();
        let error = state
            .projections()
            .project_cell_writes_with_pre_state(&event, &frozen)
            .unwrap_err();

        assert_eq!(error.reason_code(), "invite_kind_requires_revoke");
        assert_cancel_state_unchanged(&state, None).await;
    }

    #[tokio::test]
    async fn unknown_invite_cancel_is_reducer_failure_with_zero_side_effects() {
        let state = invite_test_state();
        let error = freeze_invite_lifecycle_pre_state(&state, &cancel_event(Some(CANCEL_INVITEE)))
            .await
            .unwrap_err();

        assert_eq!(error, "reducer_projection_failed");
        assert!(
            state
                .event_queries()
                .accepted_events()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            state
                .realm_invites()
                .get(CANCEL_INVITE)
                .await
                .unwrap()
                .is_none()
        );
    }

    // ------------------------------------------------------------------
    // ak.component.invite.live_target.v1 (governance-objects.md section 5.3)
    // ------------------------------------------------------------------

    /// The `ak.invite.create` Event that claims the slot in the tests below.
    /// Its `event_id` is the slot value, verbatim and in `ak:event:` form.
    fn live_target_create_event(invitee_did: &str, actor_seq: u64) -> arkret_wire::Event {
        crate::test_event::raw_event(
            arkret_wire::EventKind::InviteCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(CANCEL_REALM).unwrap(),
            },
            crate::test_actor_id_str(CANCEL_INVITER),
            actor_seq,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            json!({
                "invitee_account_id": fixture_account(invitee_did),
                "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
                "expires_at": "2026-08-05T10:00:00Z",
            }),
        )
        .unwrap()
    }

    fn operation_for(event: &arkret_wire::Event, operation_id: &str) -> Operation {
        arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            arkret_identifiers::OperationId::new(operation_id).unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
    }

    fn revoke_event(target_state: &str, invitee_did: Option<&str>) -> arkret_wire::Event {
        let mut payload = json!({
            "invite_id": CANCEL_INVITE,
            "target_state": target_state,
        });
        if let Some(invitee_did) = invitee_did {
            payload["invitee_account_id"] = json!(fixture_account(invitee_did));
        }
        crate::test_event::raw_event(
            arkret_wire::EventKind::InviteRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(CANCEL_REALM).unwrap(),
            },
            crate::test_actor_id_str(CANCEL_INVITER),
            0,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            payload,
        )
        .unwrap()
    }

    fn live_target_cell(invitee_did: &str) -> arkret_identifiers::CellRef {
        arkret_schema::invite_live_target_cell(&fixture_account(invitee_did)).unwrap()
    }

    /// Put the slot into the state the given create Event would leave it in.
    fn claim_live_target(state: &AppState, invitee_did: &str, create: &arkret_wire::Event) {
        state.projections().cache_cell(
            live_target_cell(invitee_did),
            json!(create.event_id.as_str()),
        );
    }

    fn head_eq_precondition(
        cell_id: arkret_identifiers::CellRef,
        value: Value,
    ) -> arkret_wire::Precondition {
        arkret_wire::Precondition {
            cell_id,
            predicate: arkret_wire::Predicate {
                op: arkret_wire::PredicateOp::HeadEq,
                value: Some(value),
                values: None,
                predicate_id: None,
            },
        }
    }

    #[tokio::test]
    async fn first_directed_create_claims_the_free_live_target_slot() {
        let state = invite_test_state();
        let mut create = live_target_create_event(CANCEL_INVITEE, 0);
        // The registered contract, not this test, decides the target and the
        // stored value.
        let writes = state.projections().project_cell_writes(&create).unwrap();
        let claim = writes
            .iter()
            .find(|write| write.cell_id == live_target_cell(CANCEL_INVITEE))
            .expect("ak.invite.create must claim the live-target slot");
        let arkret_wire::cba::ProjectedOp::Direct(op) = &claim.op else {
            panic!("the claim write is a direct set");
        };
        assert_eq!(op.value.as_ref(), Some(&json!(create.event_id.as_str())));

        // An unwritten cell reads `null`, so the very first invite in a Realm
        // satisfies `head_eq: null`.
        create.preconditions = vec![head_eq_precondition(
            live_target_cell(CANCEL_INVITEE),
            arkret_schema::invite_live_target_free_value(),
        )];
        let operation = operation_for(&create, "ak:operation:01904100-0000-7000-8000-000000000601");
        assert_eq!(
            state
                .projections()
                .snapshot()
                .check_move_preconditions(&operation),
            Ok(())
        );
        assert!(
            validate_invite_live_target_admission(&operation, &state.projections().snapshot())
                .is_ok(),
            "a free slot admits the create"
        );
    }

    #[tokio::test]
    async fn second_directed_create_for_the_same_account_is_rejected_with_zero_writes() {
        let state = invite_test_state();
        let first = live_target_create_event(CANCEL_INVITEE, 0);
        claim_live_target(&state, CANCEL_INVITEE, &first);

        // A distinct second create Event. It is an invalid duplicate, never an
        // idempotent replay: it cannot compute the first invite's id, and
        // admitting it with zero registered writes is the contract violation
        // this slot exists to remove.
        let second = live_target_create_event(CANCEL_INVITEE, 1);
        let rejection = validate_invite_live_target_admission(
            &operation_for(&second, "ak:operation:01904100-0000-7000-8000-000000000611"),
            &state.projections().snapshot(),
        )
        .expect_err("an occupied slot rejects the duplicate");
        let InviteLiveTargetRejection::Occupied(problem) = rejection else {
            panic!("a claimed slot must report invite_live_target_occupied");
        };
        assert_eq!(
            problem.reason_code(),
            arkret_wire::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED
        );
        assert_eq!(problem.create_event_id().as_str(), first.event_id.as_str());
        assert_eq!(
            problem.invite_id().as_str(),
            arkret_wire::InviteId::from_event_id(&first.event_id).as_str()
        );
        assert!(
            state
                .event_queries()
                .accepted_events()
                .await
                .unwrap()
                .is_empty(),
            "the duplicate must not enter canonical history"
        );
    }

    #[tokio::test]
    async fn concurrent_directed_creates_resolve_to_one_slot_holder() {
        // Two concurrent creates contend on one cell rather than each writing
        // its own, which is what makes the outcome independent of any private
        // index or insertion order. Both carry `head_eq: null`; once
        // either lands, the other's precondition no longer holds.
        let state = invite_test_state();
        let winner = live_target_create_event(CANCEL_INVITEE, 0);
        let mut loser = live_target_create_event(CANCEL_INVITEE, 1);
        let cell = live_target_cell(CANCEL_INVITEE);
        assert_ne!(winner.event_id, loser.event_id);
        for event in [&winner, &loser] {
            assert!(
                state
                    .projections()
                    .project_cell_writes(event)
                    .unwrap()
                    .iter()
                    .any(|write| write.cell_id == cell),
                "concurrent creates must contend on one cell"
            );
        }

        claim_live_target(&state, CANCEL_INVITEE, &winner);
        loser.preconditions = vec![head_eq_precondition(
            cell,
            arkret_schema::invite_live_target_free_value(),
        )];
        assert_eq!(
            state
                .projections()
                .snapshot()
                .check_move_preconditions(&operation_for(
                    &loser,
                    "ak:operation:01904100-0000-7000-8000-000000000621"
                )),
            Err("failed_precondition")
        );
    }

    #[tokio::test]
    async fn terminal_release_then_reinvite_is_accepted() {
        let state = invite_test_state();
        let first = live_target_create_event(CANCEL_INVITEE, 0);
        claim_live_target(&state, CANCEL_INVITEE, &first);

        // The release write sets the slot back to `null`, which is why the next
        // create's `head_eq: null` holds again. `null` is a reusable register
        // value here, not a terminal sentinel — the release keeps its own head
        // (spec section 9.3.1.2), which is what a later head-identity guard
        // will use to tell "released now" from "released one round ago".
        seed_cancel_invite(&state, false).await;
        let revoke = revoke_event("revoked", Some(CANCEL_INVITEE));
        let frozen = freeze_invite_lifecycle_pre_state(&state, &revoke)
            .await
            .unwrap();
        let release = state
            .projections()
            .project_cell_writes_with_pre_state(&revoke, &frozen)
            .unwrap()
            .into_iter()
            .find(|write| write.cell_id == live_target_cell(CANCEL_INVITEE))
            .expect("a directed terminal revoke releases the slot");
        let arkret_wire::cba::ProjectedOp::Direct(op) = &release.op else {
            panic!("the release write is a direct set");
        };
        let free = arkret_schema::invite_live_target_free_value();
        assert_eq!(op.value.as_ref(), Some(&free));

        state
            .projections()
            .cache_cell(live_target_cell(CANCEL_INVITEE), free);
        let reinvite = live_target_create_event(CANCEL_INVITEE, 2);
        assert!(
            validate_invite_live_target_admission(
                &operation_for(
                    &reinvite,
                    "ak:operation:01904100-0000-7000-8000-000000000631"
                ),
                &state.projections().snapshot(),
            )
            .is_ok(),
            "a released slot admits a new invite"
        );
    }

    #[tokio::test]
    async fn expired_at_wall_clock_alone_does_not_release_the_slot() {
        // Liveness is the slot, never a local clock comparison. The second
        // create is stamped long after the invite's `expires_at`, and the slot
        // still refuses it until a registered Move frees it.
        let state = invite_test_state();
        let first = live_target_create_event(CANCEL_INVITEE, 0);
        claim_live_target(&state, CANCEL_INVITEE, &first);
        let mut later = live_target_create_event(CANCEL_INVITEE, 3);
        later.created_at = "2099-01-01T00:00:00Z".parse().unwrap();
        assert!(matches!(
            validate_invite_live_target_admission(
                &operation_for(&later, "ak:operation:01904100-0000-7000-8000-000000000641"),
                &state.projections().snapshot(),
            ),
            Err(InviteLiveTargetRejection::Occupied(_))
        ));
    }

    #[tokio::test]
    async fn send_failed_holder_keeps_the_slot_claimed() {
        // `send_failed` stays inside the live set, so the payload schema
        // forbids `invitee_account_id` there and the Move derives no release
        // write. The condition simply does not fire: it MUST NOT be written as
        // a same-value no-op (`event-and-patch.md` section 2.4.2).
        let state = invite_test_state();
        seed_cancel_invite(&state, false).await;
        let send_failed = revoke_event("send_failed", None);
        let frozen = freeze_invite_lifecycle_pre_state(&state, &send_failed)
            .await
            .unwrap();
        let writes = state
            .projections()
            .project_cell_writes_with_pre_state(&send_failed, &frozen)
            .unwrap();
        assert!(
            writes
                .iter()
                .all(|write| write.cell_id != live_target_cell(CANCEL_INVITEE)),
            "send_failed must derive no live-target write at all"
        );

        let first = live_target_create_event(CANCEL_INVITEE, 0);
        claim_live_target(&state, CANCEL_INVITEE, &first);
        let replacement = live_target_create_event(CANCEL_INVITEE, 4);
        assert!(
            matches!(
                validate_invite_live_target_admission(
                    &operation_for(
                        &replacement,
                        "ak:operation:01904100-0000-7000-8000-000000000651"
                    ),
                    &state.projections().snapshot(),
                ),
                Err(InviteLiveTargetRejection::Occupied(_))
            ),
            "a send_failed holder must be revoked before a replacement create"
        );
    }

    #[tokio::test]
    async fn third_party_revoke_forging_invitee_account_id_is_reducer_projection_failed() {
        // Stored absent, payload present: `stored_field_matches_payload` fails,
        // so a third-party invite cannot release somebody else's directed slot.
        let state = invite_test_state();
        seed_cancel_invite(&state, true).await;
        let forged = revoke_event("revoked", Some(CANCEL_INVITEE));
        let frozen = freeze_invite_lifecycle_pre_state(&state, &forged)
            .await
            .unwrap();
        assert_eq!(
            state
                .projections()
                .project_cell_writes_with_pre_state(&forged, &frozen)
                .unwrap_err()
                .reason_code(),
            "reducer_projection_failed"
        );
        assert_cancel_state_unchanged(&state, None).await;
    }

    #[tokio::test]
    async fn directed_revoke_omitting_invitee_account_id_is_reducer_projection_failed() {
        // Stored present, payload absent: the same predicate fails in the other
        // direction, so a directed invite cannot strand its own slot by
        // omitting the field on a terminal revoke.
        let state = invite_test_state();
        seed_cancel_invite(&state, false).await;
        let omitted = revoke_event("revoked", None);
        let frozen = freeze_invite_lifecycle_pre_state(&state, &omitted)
            .await
            .unwrap();
        assert_eq!(
            state
                .projections()
                .project_cell_writes_with_pre_state(&omitted, &frozen)
                .unwrap_err()
                .reason_code(),
            "reducer_projection_failed"
        );
        assert_cancel_state_unchanged(&state, Some(CANCEL_INVITEE)).await;
    }

    #[tokio::test]
    async fn release_head_eq_spelled_as_invite_id_is_failed_precondition() {
        // The slot stores `ak:event:`; the `ak:invite:` retype of the same
        // 33-octet token is a different string and never compares equal. The
        // failure would otherwise only surface the second time this account is
        // invited, with the slot stranded for good.
        let state = invite_test_state();
        let first = live_target_create_event(CANCEL_INVITEE, 0);
        claim_live_target(&state, CANCEL_INVITEE, &first);
        let invite_id = arkret_wire::InviteId::from_event_id(&first.event_id);

        let mut wrong = revoke_event("revoked", Some(CANCEL_INVITEE));
        wrong.preconditions = vec![head_eq_precondition(
            live_target_cell(CANCEL_INVITEE),
            json!(invite_id.as_str()),
        )];
        assert_eq!(
            state
                .projections()
                .snapshot()
                .check_move_preconditions(&operation_for(
                    &wrong,
                    "ak:operation:01904100-0000-7000-8000-000000000661"
                )),
            Err("failed_precondition")
        );

        // The SDK helper produces the accepted spelling from the same InviteId.
        let mut right = revoke_event("revoked", Some(CANCEL_INVITEE));
        right.preconditions = vec![
            arkret_schema::InviteLiveTargetSlot::held_by_invite(&invite_id)
                .precondition(&fixture_account(CANCEL_INVITEE))
                .unwrap(),
        ];
        assert_eq!(
            state
                .projections()
                .snapshot()
                .check_move_preconditions(&operation_for(
                    &right,
                    "ak:operation:01904100-0000-7000-8000-000000000662"
                )),
            Ok(())
        );
    }

    #[tokio::test]
    async fn shared_invite_create_reconciles_exact_private_delivery_before_replay() {
        let state = AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id =
            RealmId::new("ak:realm:ATgPyXyxa7nHOBDf8wno4jWA7fVMO63Mba64ZIYHssA9").unwrap();
        let invite_id = "ak:invite:ATDCCDepUfY2x8Ah8veGLjoJl1foYqzljIn1qxn7iDSg";
        let inviter_id = fixture_account("did:web:alice.example").to_string();
        let invitee = fixture_account("did:web:bob.example");
        let invitee_id = invitee.to_string();
        let member = ActorId::account(invitee.clone()).to_string();
        let created_at = "2026-07-29T10:00:00Z".parse().unwrap();
        let expires_at = "2026-08-05T10:00:00Z".parse().unwrap();
        let evidence_digest = format!("sha256:{}", "a".repeat(64));
        state
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id: invite_id.to_owned(),
                realm_id: realm_id.to_string(),
                inviter_id: inviter_id.to_owned(),
                invitee_id: Some(invitee_id.to_owned()),
                introduction_evidence_digest: Some(evidence_digest.clone()),
                third_party_invite: None,
                invite_token: "private-token".to_owned(),
                status: "pending".to_owned(),
                claim_nonces: BTreeMap::new(),
                expires_at: Some(expires_at),
                created_at,
                updated_at: None,
            })
            .await
            .unwrap();
        assert!(
            state
                .projections()
                .snapshot()
                .member(realm_id.as_str(), &member)
                .is_none()
        );

        let mut event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::InviteCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id_str("did:web:alice.example"),
            0,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            json!({
                "invitee_account_id": invitee,
                "introduction_evidence_digest": evidence_digest,
                "expires_at": "2026-08-05T10:00:00.000Z"
            }),
            created_at,
        )
        .unwrap();
        event.event_id =
            arkret_identifiers::EventId::new(invite_id.replacen("ak:invite:", "ak:event:", 1))
                .unwrap();
        let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000000503",
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        project_invite_create_operation(&state, &operation).await;

        assert!(
            state
                .projections()
                .snapshot()
                .member(realm_id.as_str(), &member)
                .is_none(),
            "reconciling private delivery must not create membership"
        );
        let retained = state.realm_invites().get(invite_id).await.unwrap().unwrap();
        assert_eq!(
            retained.invite_token, "private-token",
            "private delivery material stays out of the Invite object"
        );
    }

    #[tokio::test]
    async fn shared_invite_create_does_not_reconcile_conflicting_private_delivery() {
        let state = AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id =
            RealmId::new("ak:realm:Ad-NSApg_uD02vD0do9fZZZJ1Zmt7NwwVBcwb04N9zN6").unwrap();
        let invite_id = "ak:invite:AdC0j3vbvw3GtVXF8ur0n33PvcSmEMMhI4ROVwQk3ypg";
        let invitee = fixture_account("did:web:bob.example");
        let invitee_id = invitee.to_string();
        let member = ActorId::account(invitee.clone()).to_string();
        let created_at = "2026-07-29T10:00:00Z".parse().unwrap();
        state
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id: invite_id.to_owned(),
                realm_id: realm_id.to_string(),
                inviter_id: fixture_account("did:web:mallory.example").to_string(),
                invitee_id: Some(invitee_id.to_owned()),
                introduction_evidence_digest: None,
                third_party_invite: None,
                invite_token: "private-token".to_owned(),
                status: "pending".to_owned(),
                claim_nonces: BTreeMap::new(),
                expires_at: Some("2026-08-05T10:00:00Z".parse().unwrap()),
                created_at,
                updated_at: None,
            })
            .await
            .unwrap();
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000000513",
            )
            .unwrap(),
            realm_id.clone(),
            arkret_wire::EventKind::InviteCreate.as_str(),
            json!({
                "invitee_account_id": invitee,
                "expires_at": "2026-08-05T10:00:00.000Z"
            }),
        );
        operation.payload["event_id"] = json!(invite_id.replacen("ak:invite:", "ak:event:", 1));
        operation.created_at = created_at;

        project_invite_create_operation(&state, &operation).await;

        assert!(
            state
                .projections()
                .snapshot()
                .member(realm_id.as_str(), &member)
                .is_none()
        );
    }
}
