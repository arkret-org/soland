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
    if !state
        .projections()
        .invite_member_can_accept(record.realm_id.as_str(), &member)
    {
        tracing::warn!(
            invite_id = %invite_id,
            invitee_id = %accepter,
            "ak.invite.accept requires the invited-or-atomically-joined member state"
        );
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

/// Freeze the authoritative lifecycle row and its two registered cells before
/// an `ak.invite.cancel` reaches durable acceptance.
///
/// The caller holds the per-Invite lifecycle admission lock while this
/// snapshot is built and consumed. The SDK pre-state predicates and Soland's
/// lifecycle/member checks therefore inspect exactly the same values.
pub(in crate::routing::events) async fn freeze_invite_cancel_pre_state(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<arkret_schema::FrozenPreState, &'static str> {
    let mut frozen = arkret_schema::FrozenPreState::new();
    if event.kind != arkret_wire::EventKind::InviteCancel {
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
        let member_cell = invite_member_cell(&account)?;
        let member_value = projection
            .cell_value(&member_cell)
            .cloned()
            .ok_or("reducer_projection_failed")?;
        lifecycle.insert(
            "invitee_account_id".to_owned(),
            serde_json::to_value(account).map_err(|_| "reducer_projection_failed")?,
        );
        frozen.insert(member_cell, member_value);
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
    let member_cell = invite_member_cell(&account)?;
    if frozen_pre_state.get(&member_cell).and_then(Value::as_str) != Some("invite") {
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
    if let Some(invitee_id) = direct_invitee.as_deref()
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
    if let Some(invitee_id) = direct_member.as_deref()
        && !state
            .projections()
            .invite_member_is_invited(record.realm_id.as_str(), invitee_id)
    {
        tracing::warn!(
            invite_id = %invite_id,
            invitee_id = %invitee_id,
            "direct invite terminal event requires member state invite"
        );
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
            if let Some(invitee_id) = direct_member.as_deref()
                && !state.projections().project_invite_termination(
                    operation,
                    invitee_id,
                    operation
                        .payload
                        .get("reason_code")
                        .or_else(|| operation.payload.get("reason"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                )
            {
                tracing::warn!(
                    invite_id = %invite_id,
                    invitee_id = %invitee_id,
                    "validated invite terminal projection unexpectedly lost its invite membership"
                );
            }
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
                if !state
                    .projections()
                    .invite_member_is_invited(operation.realm_id.as_str(), &invitee_actor)
                {
                    project_invite_creation(state, operation, &invitee_actor);
                    touch_realm(state, operation.realm_id.as_str()).await;
                    tracing::info!(
                        invite_id = %invite_id,
                        invitee_id = %invitee_id.as_str(),
                        realm_id = %operation.realm_id,
                        "reconciled shared ak.invite.create after private invite delivery"
                    );
                } else {
                    tracing::debug!(
                        invite_id = %invite_id,
                        status = %existing.status,
                        "ak.invite.create projection replay skipped"
                    );
                }
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
    let already_live = invites
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|existing| {
            existing.realm_id == operation.realm_id.as_str()
                && existing.invitee_id.as_deref() == Some(invitee_id.as_str())
                && existing.third_party_invite.is_none()
                && matches!(
                    existing.status.as_str(),
                    "pending" | "claimed" | "send_failed"
                )
                && existing
                    .expires_at
                    .is_none_or(|expires_at| expires_at > operation.created_at)
        });
    if already_live {
        tracing::debug!(
            invite_id = %invite_id,
            invitee_id = %invitee_id.as_str(),
            realm_id = %operation.realm_id,
            "ak.invite.create projection skipped: live direct invite already exists"
        );
        return;
    }

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
            // Invite creation advances only the membership lifecycle
            // `leave -> invite`. The invite's exact AccountId does not grant
            // membership or participate in Realm fanout until an accepted join.
            project_invite_creation(state, operation, &invitee_actor);
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

fn project_invite_creation(state: &AppState, operation: &Operation, invitee_id: &str) {
    state
        .projections()
        .project_invite_creation(operation, invitee_id);
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
        if !third_party {
            let mut create = arkret_event_draft::test_support::raw_projected_operation(
                arkret_identifiers::OperationId::new(
                    "ak:operation:01904100-0000-7000-8000-000000000524",
                )
                .unwrap(),
                RealmId::new(CANCEL_REALM).unwrap(),
                arkret_wire::EventKind::InviteCreate.as_str(),
                json!({"invitee_account_id": fixture_account(CANCEL_INVITEE)}),
            );
            create.created_at = created_at;
            state
                .projections()
                .project_invite_creation(&create, &fixture_actor(CANCEL_INVITEE));
        }
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
                Some(json!("invite"))
            );
            assert!(
                state
                    .projections()
                    .invite_member_is_invited(CANCEL_REALM, &fixture_actor(invitee_id))
            );
        }
    }

    #[tokio::test]
    async fn direct_invite_cancel_uses_one_frozen_lifecycle_and_member_pre_state() {
        let state = invite_test_state();
        seed_cancel_invite(&state, false).await;
        let event = cancel_event(Some(CANCEL_INVITEE));
        let frozen = freeze_invite_cancel_pre_state(&state, &event)
            .await
            .unwrap();
        let writes = state
            .projections()
            .project_cell_writes_with_pre_state(&event, &frozen)
            .unwrap();

        assert_eq!(writes.len(), 1);
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
            let frozen = freeze_invite_cancel_pre_state(&state, &event)
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
        let frozen = freeze_invite_cancel_pre_state(&state, &event)
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
        let frozen = freeze_invite_cancel_pre_state(&state, &event)
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
        let error = freeze_invite_cancel_pre_state(&state, &cancel_event(Some(CANCEL_INVITEE)))
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
            !state
                .projections()
                .invite_member_is_invited(realm_id.as_str(), &member)
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
                .invite_member_is_invited(realm_id.as_str(), &member)
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
            !state
                .projections()
                .invite_member_is_invited(realm_id.as_str(), &member)
        );
    }
}
