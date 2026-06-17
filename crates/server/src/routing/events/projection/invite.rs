use cokret_sdk::{Did, Operation, RealmId};
use serde_json::Value;

use super::*;
use crate::state::{AppState, RealmInviteRecord};
use crate::{ids, kinds};

/// Spec invite-addressing.md / event-kind-registry — project an accepted
/// `ck.invite.accept` durable event. The invitee submits it to close the
/// group-invite loop:
///   1. resolve the referenced invite, validating it is still `pending` and that the accepting
///      sender == the invite's `invitee`;
///   2. flip the `RealmInviteRecord` to `accepted`;
///   3. cascade membership — activate the invitee's `ck.member.state(join)` in the target Realm
///      (in-memory member index) so the capability grants carried on the invite take effect.
/// Replays and mismatched senders are ignored fail-closed.
pub(super) async fn project_invite_accept_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind_string(operation) != "ck.invite.accept" {
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
            "ck.invite.accept missing valid invite_ref/invite_id"
        );
        return;
    };
    let invites = state.persistence.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        tracing::warn!(invite_id = %invite_id, "ck.invite.accept references unknown invite");
        return;
    };
    if record.invitee.as_deref() != Some(accepter.as_str()) {
        tracing::warn!(
            invite_id = %invite_id,
            accepter = %accepter,
            "ck.invite.accept sender is not the invitee; ignored"
        );
        return;
    }
    if record.status != "pending" {
        tracing::debug!(
            invite_id = %invite_id,
            status = %record.status,
            "ck.invite.accept on non-pending invite; ignored"
        );
        return;
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        tracing::warn!(invite_id = %invite_id, "ck.invite.accept on expired invite; ignored");
        return;
    }
    record.status = "accepted".to_owned();
    let realm_id = record.realm_id.clone();
    if let Err(error) = invites.put(record).await {
        tracing::warn!(%error, invite_id = %invite_id, "failed to mark invite accepted");
        return;
    }
    // Cascade membership: activate the invitee's join in the target Realm
    // member index so subsequent realm-scoped reads include them.
    if let (Ok(realm_id_typed), Ok(member_did)) =
        (RealmId::new(realm_id.clone()), Did::new(accepter.clone()))
    {
        let mut realms = state.realms.lock().expect("realms lock");
        if let Some(entry) = realms.get(&realm_id_typed) {
            let mut updated = entry.clone();
            if updated.members.insert(member_did) {
                realms.upsert(updated);
            }
        }
    }
    touch_realm(state, &realm_id).await;
    tracing::info!(
        invite_id = %invite_id,
        invitee = %accepter,
        realm_id = %realm_id,
        "ck.invite.accept projected: invite accepted + membership cascaded"
    );
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
            "ck.invite.create missing valid invitee DID"
        );
        return;
    };
    let Some(invite_id) = invite_id_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "ck.invite.create missing valid invite id"
        );
        return;
    };

    let invites = state.persistence.realm_invites();
    match invites.get(&invite_id).await {
        Ok(Some(existing)) => {
            tracing::debug!(
                invite_id = %invite_id,
                status = %existing.status,
                "ck.invite.create projection replay skipped"
            );
            return;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, invite_id = %invite_id, "failed to read projected invite");
            return;
        }
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
        invite_token,
        status: "pending".to_owned(),
        expires_at,
        created_at: operation.created_at,
    };
    match invites.put(record).await {
        Ok(()) => {
            tracing::info!(
                invite_id = %invite_id,
                invitee = %invitee.as_str(),
                realm_id = %operation.realm_id,
                "projected invite via ck.invite.create event"
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
            "ck.invite.create supplied malformed invite_id; deriving stable invite id"
        );
    }
    ids::typed_uuid_part(operation.operation_id.as_str())
        .map(|uuid| ids::format_typed_uuid("invite", &uuid))
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
            "ck.invite.create supplied invalid invite_delivery_target.recipient_service_did"
        );
        return None;
    }
    if let Some(service_type) = object.get("recipient_service_type").and_then(Value::as_str)
        && service_type != "principal_server"
    {
        tracing::warn!(
            operation_id = %operation.operation_id,
            service_type = %service_type,
            "ck.invite.create supplied invalid invite_delivery_target.recipient_service_type"
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
    if cokret_sdk::Hash::new(digest.to_owned()).is_err() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ck.invite.create supplied invalid introduction_evidence_digest"
        );
        return None;
    }
    Some(digest.to_owned())
}

pub(super) fn plaintext_services_from_operation(operation: &Operation) -> Vec<String> {
    let mut services = Vec::new();
    let mut push_service = |value: &str| {
        let service = value.trim();
        if !service.is_empty() && !services.iter().any(|existing| existing == service) {
            services.push(service.to_owned());
        }
    };
    if let Some(items) = operation
        .payload
        .get("plaintext_visible_services")
        .and_then(|value| value.as_array())
    {
        for item in items {
            if let Some(service) = item.as_str() {
                push_service(service);
            }
        }
    }
    if let Some(items) = operation
        .payload
        .get("services")
        .and_then(|value| value.as_array())
    {
        for item in items {
            if let Some(service) = item.as_str() {
                push_service(service);
            } else if let Some(service) = item.get("service_did").and_then(|value| value.as_str()) {
                push_service(service);
            }
        }
    }
    services
}

pub(super) async fn project_plaintext_visible_services_operation(
    state: &AppState,
    operation: &Operation,
) {
    let services = plaintext_services_from_operation(operation);
    if services.is_empty() {
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
    record.updated_at = operation.created_at;
    if let Err(error) = store.put(operation.realm_id.as_str(), &record).await {
        tracing::warn!(%error, "failed to project plaintext visible services");
    }
}
