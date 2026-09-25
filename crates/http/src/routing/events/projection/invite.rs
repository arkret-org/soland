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

/// The former Cell/Seal pre-state checker has no current authority provider.
/// These Event kinds must be evaluated against one committed RealmCommit cut
/// together with the typed invite lifecycle and directed-invitee results.
pub(in crate::routing::events) const INVITE_LIFECYCLE_PRE_STATE_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::INVITE_ACCEPT,
    arkret_wire::event_kind_str::INVITE_CANCEL,
    arkret_wire::event_kind_str::INVITE_REVOKE,
];

/// Refuse the legacy pre-state path until it can consume the current committed
/// authority cut. An uncommitted RealmInvite mirror is not an admission basis.
pub(in crate::routing::events) async fn freeze_invite_lifecycle_pre_state(
    _state: &AppState,
    _event: &arkret_wire::Event,
) -> Result<(), &'static str> {
    Err("reducer_projection_failed")
}

pub(in crate::routing::events) fn validate_invite_cancel_pre_admission(
    _origin: &str,
    _operation: &Operation,
    _frozen_pre_state: &(),
) -> Result<(), &'static str> {
    Err("reducer_projection_failed")
}

/// A directed Invite cannot be admitted without a transactional typed-current
/// slot read and CAS against the same authority cut as its RealmCommit.
pub(in crate::routing::events) enum InviteLiveTargetRejection {
    ProjectionFailed(&'static str),
    Occupied(Box<arkret_wire::InviteLiveTargetOccupiedProblem>),
}

pub(in crate::routing::events) fn validate_invite_live_target_admission(
    operation: &Operation,
    _projection: &soland_domain::reducer::ProjectionState,
) -> Result<(), InviteLiveTargetRejection> {
    if !kinds::operation_is_invite_create(operation) {
        return Ok(());
    }
    Err(InviteLiveTargetRejection::ProjectionFailed(
        "reducer_projection_failed",
    ))
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
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: operation.realm_id.to_string(),
        inviter_id,
        invitee_id: Some(invitee_id.as_str().to_owned()),
        introduction_evidence_digest,
        third_party_invite: None,
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
    use arkret_identifiers::{DidCoreId, OperationId, RealmId};
    use serde_json::json;

    use super::*;

    fn operation(kind: arkret_wire::EventKind, payload: serde_json::Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new("ak:operation:01904100-0000-7000-8000-000000000601").unwrap(),
            RealmId::new("ak:realm:AeMdjqxM9dnJ8ik-DD-XWcNeb1liwy0eVEWHTvxfesqr").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn directed_invite_uses_the_exact_account_identifier() {
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let valid = operation(
            arkret_wire::EventKind::InviteCreate,
            json!({"invitee_account_id": account}),
        );
        assert_eq!(invitee_for_operation(&valid), Some(account));
        let did_only = operation(
            arkret_wire::EventKind::InviteCreate,
            json!({"invitee_account_id": "did:web:bob.example"}),
        );
        assert!(invitee_for_operation(&did_only).is_none());
    }

    #[test]
    fn directed_invite_refuses_missing_committed_slot_provider() {
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let create = operation(
            arkret_wire::EventKind::InviteCreate,
            json!({"invitee_account_id": account}),
        );
        let projection = soland_domain::reducer::ProjectionState::new();
        assert!(matches!(
            validate_invite_live_target_admission(&create, &projection),
            Err(InviteLiveTargetRejection::ProjectionFailed(
                "reducer_projection_failed"
            ))
        ));
    }

    #[test]
    fn cancel_refuses_legacy_uncommitted_pre_state() {
        let cancel = operation(
            arkret_wire::EventKind::InviteCancel,
            json!({"invite_id": "ak:invite:ARlxuxcITxQTVrXf396EgxLPdvGfJpZqw0WToWbVAKXW"}),
        );
        assert_eq!(
            validate_invite_cancel_pre_admission("fixture", &cancel, &()),
            Err("reducer_projection_failed")
        );
    }
}
