use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::membership_invite::InviteClaimPayload;
use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;
use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;
use arkret_wire::PlaintextDataClassKind;
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
