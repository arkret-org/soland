use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::lattice::CellState;
use arkret_sdk::{
    CellRef, Did, Operation, PlaintextDataClassKind, PlaintextVisibleServicesPayload, RealmId,
};
use serde_json::Value;

use super::*;
use crate::reducer::SolandMembershipState;
use crate::state::{AppState, RealmInviteRecord};
use crate::{ids, kinds};

/// Spec invite-addressing.md / event-kind-registry — project an accepted
/// `ak.invite.accept` durable event. The invitee submits it to close the
/// group-invite loop:
///   1. resolve the referenced invite, validating it is still `pending` and that the accepting
///      sender == the invite's `invitee`;
///   2. flip the `RealmInviteRecord` to `accepted`;
///   3. cascade membership — activate the invitee's `ak.member.state(join)` in the target Realm
///      (in-memory member index) so the capability grants carried on the invite take effect.
///
/// Replays and mismatched senders are ignored fail-closed.
pub(super) async fn project_invite_accept_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind_string(operation) != "ak.invite.accept" {
        return;
    }
    let accepter = operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("invitee"))
        .or_else(|| operation.payload.get("actor_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(origin)
        .to_owned();
    let Some(invite_id) = invite_acceptance_ref_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.invite.accept missing valid invite_ref/invite_id"
        );
        return;
    };
    let invites = state.persistence.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        tracing::warn!(invite_id = %invite_id, "ak.invite.accept references unknown invite");
        return;
    };
    if record.invitee.as_deref() != Some(accepter.as_str()) {
        tracing::warn!(
            invite_id = %invite_id,
            accepter = %accepter,
            "ak.invite.accept sender is not the invitee; ignored"
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
    let invite_delivery_target = record.invite_delivery_target.clone();
    if let Err(error) = invites.put(record).await {
        tracing::warn!(%error, invite_id = %invite_id, "failed to mark invite accepted");
        return;
    }
    // Cascade membership: activate the invitee's join in the target Realm
    // member index so subsequent realm-scoped reads include them.
    if let (Ok(realm_id_typed), Ok(member_did)) =
        (RealmId::new(realm_id.clone()), Did::new(accepter.clone()))
    {
        let mut realms = state.realms.lock();
        if let Some(entry) = realms.get(&realm_id_typed) {
            let mut updated = entry.clone();
            if updated.members.insert(member_did) {
                realms.upsert(updated);
            }
        }
    }
    project_invite_accept_membership(
        state,
        &realm_id,
        &accepter,
        invite_created_at,
        invite_delivery_target.as_ref(),
        operation,
    );
    touch_realm(state, &realm_id).await;
    tracing::info!(
        invite_id = %invite_id,
        invitee = %accepter,
        realm_id = %realm_id,
        "ak.invite.accept projected: invite accepted + membership cascaded"
    );
}

fn project_invite_accept_membership(
    state: &AppState,
    realm_id: &str,
    member: &str,
    invite_created_at: chrono::DateTime<chrono::Utc>,
    invite_delivery_target: Option<&Value>,
    operation: &Operation,
) {
    let recipient_service_did = invite_delivery_target
        .and_then(|target| target.get("recipient_service_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    let delivery_status = recipient_service_did
        .as_ref()
        .map(|_| "routable".to_owned())
        .or_else(|| Some("unroutable".to_owned()));
    let membership_event_ref = Some(operation.operation_id.as_str().to_owned());
    let delivery_binding_frontier = recipient_service_did
        .as_ref()
        .and(membership_event_ref.clone());

    let mut projection = state.projection.lock();
    let key = (realm_id.to_owned(), member.to_owned());
    let previous = projection.members.get(&key).cloned();
    let joined_at = previous
        .as_ref()
        .filter(|membership| membership.state == "join")
        .map(|membership| membership.joined_at)
        .unwrap_or(operation.created_at);
    projection.members.insert(
        key,
        SolandMembershipState {
            member: member.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status,
            recipient_service_did,
            membership_event_ref,
            delivery_binding_frontier,
            invited_at: previous
                .as_ref()
                .and_then(|membership| membership.invited_at)
                .or(Some(invite_created_at)),
            joined_at,
            updated_at: operation.created_at,
        },
    );
    if let Ok(cell_id) = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{member}")) {
        projection
            .cells
            .insert(cell_id, CellState::Value(Value::String("join".to_owned())));
    }
}

pub(super) async fn project_invite_cancel_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind_string(operation) != arkret_sdk::events::kinds::INVITE_CANCEL {
        return;
    }
    project_invite_terminal_operation(state, origin, operation, InviteTerminalEvent::Cancel).await;
}

pub(super) async fn project_invite_revoke_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind_string(operation) != arkret_sdk::events::kinds::INVITE_REVOKE {
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
    let invites = state.persistence.realm_invites();
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
    let terminal_status = if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        "expired"
    } else {
        match terminal_event {
            InviteTerminalEvent::Cancel if record.invitee.as_deref() == Some(origin.trim()) => {
                "rejected"
            }
            InviteTerminalEvent::Cancel | InviteTerminalEvent::Revoke => "revoked",
        }
    };
    record.status = terminal_status.to_owned();
    record.updated_at = Some(operation.created_at);
    record.invite_token.clear();
    remove_third_party_active_material(&mut record.third_party_id, terminal_status != "rejected");
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

pub(super) async fn project_invite_third_party_operation(state: &AppState, operation: &Operation) {
    if !kinds::operation_is_invite_third_party(operation) {
        return;
    }
    let Some(payload) = operation.payload.as_object() else {
        return;
    };
    let invite = payload.get("invite").and_then(Value::as_object);
    let Some(invite_id) = invite_string_field(payload, invite, "invite_id", "id") else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.invite.third_party missing invite id"
        );
        return;
    };
    if arkret_sdk::InviteId::new(invite_id.clone()).is_err() {
        tracing::warn!(invite_id = %invite_id, "ak.invite.third_party malformed invite id");
        return;
    }
    let realm_id = invite_string_field(payload, invite, "realm_id", "realm_id")
        .unwrap_or_else(|| operation.realm_id.to_string());
    if realm_id != operation.realm_id.as_str() {
        tracing::warn!(
            invite_id = %invite_id,
            realm_id = %realm_id,
            operation_realm = %operation.realm_id,
            "ak.invite.third_party realm mismatch"
        );
        return;
    }
    let Some(inviter) = invite_string_field(payload, invite, "inviter", "inviter") else {
        tracing::warn!(invite_id = %invite_id, "ak.invite.third_party missing inviter");
        return;
    };
    let Some(third_party_id) = invite_value_field(payload, invite, "third_party_id").cloned()
    else {
        tracing::warn!(invite_id = %invite_id, "ak.invite.third_party missing third_party_id");
        return;
    };
    let expires_at = invite_string_field(payload, invite, "expires_at", "expires_at")
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
        .map(|value| value.with_timezone(&chrono::Utc));
    let created_at = invite_string_field(payload, invite, "created_at", "created_at")
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or(operation.created_at);
    let join_rule_snapshot = invite_value_field(payload, invite, "join_rule_snapshot")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"join_rule": "invite"}));
    let invites = state.persistence.realm_invites();
    if matches!(invites.get(&invite_id).await, Ok(Some(_))) {
        return;
    }
    let mut third_party_id = Some(third_party_id);
    let mut status = "pending".to_owned();
    if expires_at.is_some_and(|expires_at| expires_at <= operation.created_at) {
        status = "expired".to_owned();
        remove_third_party_active_material(&mut third_party_id, true);
    }
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: operation.realm_id.to_string(),
        inviter,
        invitee: None,
        invite_delivery_target: None,
        introduction_evidence_digest: None,
        third_party_id,
        join_rule_snapshot: Some(join_rule_snapshot),
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
    let Some(payload) = operation.payload.as_object() else {
        return;
    };
    let Some(invite_id) = string_field(payload, "invite_id") else {
        return;
    };
    let Some(subject_id) = string_field(payload, "subject_id") else {
        return;
    };
    let Some(token_commitment) = string_field(payload, "token_commitment") else {
        return;
    };
    let Some(claim_nonce) = string_field(payload, "claim_nonce") else {
        return;
    };
    let invites = state.persistence.realm_invites();
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
        remove_third_party_active_material(&mut record.third_party_id, true);
        let _ = invites.put(record).await;
        return;
    }
    if record.realm_id != operation.realm_id.as_str() || record.status != "pending" {
        return;
    }
    if record
        .third_party_id
        .as_ref()
        .and_then(third_party_token_commitment)
        != Some(token_commitment.as_str())
    {
        let _ = invites.put(record).await;
        return;
    }
    if !claim_binding_matches(
        &record,
        payload,
        &subject_id,
        &claim_nonce,
        operation.created_at,
    ) {
        let _ = invites.put(record).await;
        return;
    }
    record.status = "claimed".to_owned();
    record.invitee = Some(subject_id);
    record.updated_at = Some(operation.created_at);
    record.invite_token.clear();
    remove_third_party_active_material(&mut record.third_party_id, false);
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
        .filter(|value| ids::parse_typed_uuid(value, "invite").is_some())
        .map(str::to_owned)
}

pub(super) async fn project_invite_create_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if !kinds::operation_is_invite_create(operation) {
        return;
    }
    let Some(invitee) = invitee_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "ak.invite.create missing valid invitee DID"
        );
        return;
    };
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
        invitee.as_str(),
    )
    .await
    {
        tracing::debug!(
            invite_id = %invite_id,
            invitee = %invitee.as_str(),
            realm_id = %operation.realm_id,
            "ak.invite.create projection skipped: invitee is already a member"
        );
        return;
    }

    let invites = state.persistence.realm_invites();
    match invites.get(&invite_id).await {
        Ok(Some(existing)) => {
            tracing::debug!(
                invite_id = %invite_id,
                status = %existing.status,
                "ak.invite.create projection replay skipped"
            );
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
                && existing.invitee.as_deref() == Some(invitee.as_str())
                && existing.third_party_id.is_none()
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
            invitee = %invitee.as_str(),
            realm_id = %operation.realm_id,
            "ak.invite.create projection skipped: live direct invite already exists"
        );
        return;
    }

    let inviter = operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("inviter"))
        .or_else(|| operation.payload.get("issuer"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(origin);
    let expires_at = operation
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .or_else(|| Some(operation.created_at + chrono::Duration::days(7)));
    let invite_token = crate::routing::generate_invite_token(
        &invite_id,
        operation.realm_id.as_str(),
        invitee.as_str(),
    );
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: operation.realm_id.to_string(),
        inviter: inviter.to_owned(),
        invitee: Some(invitee.as_str().to_owned()),
        invite_delivery_target: invite_delivery_target_for_operation(operation),
        introduction_evidence_digest: introduction_evidence_digest_for_operation(operation),
        third_party_id: None,
        join_rule_snapshot: None,
        invite_token,
        status: "pending".to_owned(),
        claim_nonces: std::collections::BTreeMap::new(),
        expires_at,
        created_at: operation.created_at,
        updated_at: None,
    };
    match invites.put(record).await {
        Ok(()) => {
            tracing::info!(
                invite_id = %invite_id,
                invitee = %invitee.as_str(),
                realm_id = %operation.realm_id,
                "projected invite via ak.invite.create event"
            );
            touch_realm(state, operation.realm_id.as_str()).await;
        }
        Err(error) => tracing::warn!(%error, invite_id = %invite_id, "failed to project invite"),
    }
}

fn invite_id_for_operation(operation: &Operation) -> Option<String> {
    if let Some(invite_id) = operation
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if ids::parse_typed_uuid(invite_id, "invite").is_some() {
            return Some(invite_id.to_owned());
        }
        tracing::warn!(
            operation_id = %operation.operation_id,
            invite_id = %invite_id,
            "ak.invite.create supplied malformed invite_id; deriving stable invite id"
        );
    }
    ids::typed_uuid_part(operation.operation_id.as_str())
        .map(|uuid| ids::format_typed_uuid("invite", &uuid))
}

fn invite_string_field(
    payload: &serde_json::Map<String, Value>,
    invite: Option<&serde_json::Map<String, Value>>,
    payload_field: &str,
    invite_field: &str,
) -> Option<String> {
    invite
        .and_then(|object| object.get(invite_field))
        .or_else(|| payload.get(payload_field))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn invite_value_field<'a>(
    payload: &'a serde_json::Map<String, Value>,
    invite: Option<&'a serde_json::Map<String, Value>>,
    field: &str,
) -> Option<&'a Value> {
    invite
        .and_then(|object| object.get(field))
        .or_else(|| payload.get(field))
}

fn string_field(payload: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn third_party_token_commitment(third_party_id: &Value) -> Option<&str> {
    third_party_id
        .get("token_commitment")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn remove_third_party_active_material(third_party_id: &mut Option<Value>, remove_commitment: bool) {
    let Some(value) = third_party_id.as_mut() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in [
        "token_salt",
        "token_salt_id",
        "lookup_table_ref",
        "pepper",
        "pepper_id",
    ] {
        object.remove(key);
    }
    if remove_commitment {
        object.remove("token_commitment");
    }
}

fn claim_binding_matches(
    record: &RealmInviteRecord,
    payload: &serde_json::Map<String, Value>,
    subject_id: &str,
    claim_nonce: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(binding) = payload.get("binding_proof").and_then(Value::as_object) else {
        return false;
    };
    if binding.get("subject_id").and_then(Value::as_str) != Some(subject_id) {
        return false;
    }
    if binding.get("realm_id").and_then(Value::as_str) != Some(record.realm_id.as_str()) {
        return false;
    }
    if binding.get("audience").and_then(Value::as_str) != Some("arkret.invite.claim") {
        return false;
    }
    if binding.get("claim_nonce").and_then(Value::as_str) != Some(claim_nonce) {
        return false;
    }
    let Some(service_did) = binding
        .get("verification_service_did")
        .and_then(Value::as_str)
    else {
        return false;
    };
    if record
        .third_party_id
        .as_ref()
        .and_then(|third_party| third_party.get("verification_service_did"))
        .and_then(Value::as_str)
        != Some(service_did)
    {
        return false;
    }
    let Some(expires_at) = binding
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
    else {
        return false;
    };
    expires_at > now
        && record
            .expires_at
            .is_none_or(|invite_expiry| expires_at <= invite_expiry)
}

fn invitee_for_operation(operation: &Operation) -> Option<Did> {
    operation
        .payload
        .get("invitee")
        .or_else(|| operation.payload.get("actor_id"))
        .or_else(|| operation.payload.get("member"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| Did::new(value.to_owned()).ok())
}

fn invite_delivery_target_for_operation(operation: &Operation) -> Option<Value> {
    let target = operation.payload.get("invite_delivery_target")?;
    let object = target.as_object()?;
    let service_did = object
        .get("recipient_service_did")
        .and_then(Value::as_str)?;
    if Did::new(service_did.to_owned()).is_err() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.invite.create supplied invalid invite_delivery_target.recipient_service_did"
        );
        return None;
    }
    if let Some(service_type) = object.get("recipient_service_type").and_then(Value::as_str)
        && service_type != "principal_server"
    {
        tracing::warn!(
            operation_id = %operation.operation_id,
            service_type = %service_type,
            "ak.invite.create supplied invalid invite_delivery_target.recipient_service_type"
        );
        return None;
    }
    Some(target.clone())
}

fn introduction_evidence_digest_for_operation(operation: &Operation) -> Option<String> {
    let digest = operation
        .payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if arkret_sdk::Hash::new(digest.to_owned()).is_err() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.invite.create supplied invalid introduction_evidence_digest"
        );
        return None;
    }
    Some(digest.to_owned())
}

pub(super) fn plaintext_services_from_operation(operation: &Operation) -> Vec<String> {
    let mut services = Vec::new();
    collect_plaintext_services_from_value(&operation.payload, &mut services);
    if let Some(object) = operation.payload.get("object") {
        collect_plaintext_services_from_value(object, &mut services);
    }
    services
}

fn collect_plaintext_services_from_value(payload: &Value, services: &mut Vec<String>) {
    let mut push_service = |value: &str| {
        let service = value.trim();
        if !service.is_empty() && !services.iter().any(|existing| existing == service) {
            services.push(service.to_owned());
        }
    };
    if let Some(items) = payload
        .get("plaintext_visible_services")
        .and_then(|value| value.as_array())
    {
        for item in items {
            if let Some(service) = item.as_str() {
                push_service(service);
            }
        }
    }
    if let Some(items) = payload.get("services").and_then(|value| value.as_array()) {
        for item in items {
            if let Some(service) = item.as_str() {
                push_service(service);
            } else if let Some(service) = item.get("service_did").and_then(|value| value.as_str()) {
                push_service(service);
            }
        }
    }
}

pub(super) fn plaintext_service_classes_from_operation(
    operation: &Operation,
) -> BTreeMap<String, BTreeSet<PlaintextDataClassKind>> {
    let mut by_service = plaintext_service_classes_from_value(&operation.payload);
    if let Some(object) = operation.payload.get("object") {
        for (service, classes) in plaintext_service_classes_from_value(object) {
            by_service.entry(service).or_default().extend(classes);
        }
    }
    by_service
}

pub(crate) fn plaintext_service_classes_from_value(
    payload: &Value,
) -> BTreeMap<String, BTreeSet<PlaintextDataClassKind>> {
    let mut by_service = BTreeMap::new();
    if let Some(items) = payload.get("services").and_then(Value::as_array) {
        merge_typed_plaintext_services(items, &mut by_service);
    }
    if let Some(items) = payload
        .get("plaintext_visible_services")
        .and_then(Value::as_array)
    {
        merge_typed_plaintext_services(items, &mut by_service);
    }
    by_service
}

fn merge_typed_plaintext_services(
    items: &[Value],
    by_service: &mut BTreeMap<String, BTreeSet<PlaintextDataClassKind>>,
) {
    let typed = serde_json::to_value(serde_json::json!({ "services": items }))
        .ok()
        .and_then(|value| serde_json::from_value::<PlaintextVisibleServicesPayload>(value).ok());
    if let Some(typed) = typed {
        for service in typed.services {
            let classes = by_service
                .entry(service.service_did.as_str().to_owned())
                .or_default();
            classes.extend(service.data_classes);
        }
        return;
    }

    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(service_did) = object
            .get("service_did")
            .or_else(|| object.get("did"))
            .and_then(Value::as_str)
            .filter(|value| Did::new((*value).to_owned()).is_ok())
        else {
            continue;
        };
        let classes = object
            .get("data_classes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| {
                serde_json::from_value::<PlaintextDataClassKind>(value.clone()).ok()
            })
            .collect::<BTreeSet<_>>();
        if !classes.is_empty() {
            by_service
                .entry(service_did.to_owned())
                .or_default()
                .extend(classes);
        }
    }
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
    let store = state.persistence.realm_meta();
    let Ok(Some(mut record)) = store.get(operation.realm_id.as_str()).await else {
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
    if let Err(error) = store.put(operation.realm_id.as_str(), &record).await {
        tracing::warn!(%error, "failed to project plaintext visible services");
    }
}
