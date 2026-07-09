//! Ephemeral `ck.realm_key.request` relay (realm-and-space.md history-sharing,
//! `ck.feature.realm_key.peer_relay.v1`).
//!
//! A member device that joined a Realm late asks a *provider* device (a verified
//! member that retained the history secret) to seal `history_secret[from..to]`
//! to the requester's HPKE public key. The request is wire-scope **ephemeral**
//! (`event-payload.schema.json#/$defs/realm_key_request_payload`,
//! `reducer_input=false`): it is NOT a durable Event and never enters the
//! reducer. It rides the provider device's to-device queue; the provider answers
//! out-of-band with a durable `ck.realm_key.share` carrying the sealed material.
//!
//! This module mirrors `read_receipts::relay_ephemeral_read_receipt` (ephemeral
//! envelope handling) and `operations::policy_extra::validate_realm_key_share_policy`
//! (the SDK `evaluate_history_key_share_gates` policy gate), specialised for the
//! request direction:
//!
//! - the *sender* must be a current joined member of the Realm,
//! - the Realm must carry a projected `history_sharing_policy`,
//! - the named provider device (`target_source_ref`) must be a syntactically valid `ak:device:<id>`
//!   and resolve to an active (non-revoked) device of its declared owning principal
//!   (`target_principal_id`),
//! - the SDK history-key-share gates must admit the share for the requesting reader before the
//!   request is relayed.

use arkret_sdk::EphemeralEnvelope;
use serde_json::Value;

use crate::error::AppError;
use crate::routing::events::projection::project_realm_key_request_to_device;
use crate::state::{AppState, SessionRecord};

/// Outcome of resolving the provider device named by `target_source_ref`.
struct ResolvedTarget {
    principal_id: String,
    device_id: String,
}

/// Admit and relay one ephemeral `ck.realm_key.request` envelope. The sender's
/// bearer session is already authenticated and confirmed to match
/// `envelope.actor_id` by the caller; here we enforce the history-sharing policy
/// gate and enqueue the request onto the provider device's to-device queue.
pub(crate) async fn relay_ephemeral_realm_key_request(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
    envelope: &EphemeralEnvelope,
) -> Result<(), AppError> {
    let request: arkret_sdk::RealmKeyRequestPayload =
        serde_json::from_value(envelope.payload.clone()).map_err(|error| {
            AppError::invalid_param(format!(
                "ak.realm_key.request payload is malformed: {error}"
            ))
        })?;
    request.validate().map_err(|error| {
        AppError::invalid_param(format!("ak.realm_key.request invalid: {error}"))
    })?;

    // The sender (requesting reader) must be a current joined member.
    if !realm_member_is_joined(state, realm_id, &session.actor).await {
        return Err(AppError::capability_denied(
            "ak.realm_key.request sender is not a joined member of the realm",
        ));
    }

    // Resolve the provider device named by `target_source_ref`. The request now
    // carries `target_principal_id` (the provider device's owning principal)
    // directly, so we address the device by `(target_principal_id,
    // target_source_ref)` instead of scanning Realm membership — we only verify
    // that `target_source_ref` is a syntactically valid `ak:device:<id>` and
    // resolves to an active (non-revoked) device of that principal.
    let target = resolve_target_provider_device(
        state,
        request.target_principal_id.as_str(),
        &request.target_source_ref,
    )
    .await
    .ok_or_else(|| {
        AppError::invalid_param(
            "ak.realm_key.request target_source_ref does not resolve to an active provider device",
        )
    })?;

    // The Realm must carry a projected history-sharing policy, and the SDK
    // history-key-share gates must admit a share to the requesting reader.
    let decision = evaluate_request_gate(state, realm_id, session, &request, &target).await?;
    if !decision {
        return Err(AppError::capability_denied(
            "ak.realm_key.request denied by history-sharing policy",
        ));
    }

    let request_id = realm_key_request_id(envelope, &request);
    project_realm_key_request_to_device(
        state,
        session.actor.as_str(),
        session.device_id.as_str(),
        realm_id,
        &request_id,
        &target.principal_id,
        &target.device_id,
        &envelope.payload,
        request.created_at,
        envelope.expires_at,
    )
    .await;
    Ok(())
}

/// Deterministic relay id for the request: prefer the envelope's own id-bearing
/// fields, else derive a stable digest over the canonical payload so a replayed
/// envelope collapses onto the same to-device `idempotency_key`.
fn realm_key_request_id(
    envelope: &EphemeralEnvelope,
    request: &arkret_sdk::RealmKeyRequestPayload,
) -> String {
    if let Some(id) = envelope
        .payload
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return id.to_owned();
    }
    let basis = format!(
        "{}|{}|{}|{}",
        envelope.actor_id.as_str(),
        request.target_source_ref,
        request.recipient_device_id,
        request.created_at.to_rfc3339()
    );
    arkret_sdk::canonical::sha256_digest(basis.as_bytes())
}

/// True iff `actor` is projected (or persisted) as a current joined member.
async fn realm_member_is_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    {
        let projection = state.projection.lock();
        if let Some(member) = projection.member(realm_id, actor) {
            return member.state == "join";
        }
    }
    crate::routing::spaces::space::realm_has_member_by_id(state, realm_id, actor).await
}

/// Resolve `target_device_ref` against its declared owning principal
/// (`target_principal_id`). The request now addresses the provider device
/// directly, so there is no membership scan: we only confirm `target_device_ref`
/// is a syntactically valid `ak:device:<id>` and that `(principal_id,
/// device_id)` names an active (non-revoked) device row. `None` when the device
/// id is malformed or the device is absent/revoked.
async fn resolve_target_provider_device(
    state: &AppState,
    principal_id: &str,
    target_device_ref: &str,
) -> Option<ResolvedTarget> {
    let device_id = target_device_ref.trim();
    if device_id.is_empty() || arkret_sdk::DeviceId::new(device_id.to_owned()).is_err() {
        return None;
    }
    let device = state
        .persistence
        .devices()
        .get(principal_id, device_id)
        .await
        .ok()
        .flatten()?;
    if device.revoked_at.is_some() {
        return None;
    }
    if crate::routing::identity::auth::is_device_revoked(state, principal_id, device_id).await {
        return None;
    }
    Some(ResolvedTarget {
        principal_id: principal_id.to_owned(),
        device_id: device_id.to_owned(),
    })
}

/// Run the SDK `evaluate_history_key_share_gates` for the request direction. The
/// requesting reader plays the share *recipient*; the provider device named by
/// `target_source_ref` is the source. Returns the gate `allowed` decision, or an
/// error when the Realm carries no usable history-sharing policy.
async fn evaluate_request_gate(
    state: &AppState,
    realm_id: &str,
    session: &SessionRecord,
    request: &arkret_sdk::RealmKeyRequestPayload,
    target: &ResolvedTarget,
) -> Result<bool, AppError> {
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            AppError::invalid_param("ak.realm_key.request realm has no history-sharing policy")
        })?;
    let policy_value = meta.history_sharing_policy.as_ref().ok_or_else(|| {
        AppError::invalid_param("ak.realm_key.request realm has no history-sharing policy")
    })?;
    let policy = serde_json::from_value::<arkret_sdk::HistorySharingPolicyPayloadValue>(
        policy_value.clone(),
    )
    .map_err(|_| {
        AppError::invalid_param("ak.realm_key.request history-sharing policy is malformed")
    })?;
    arkret_sdk::validate_history_sharing_policy(&policy).map_err(|_| {
        AppError::invalid_param("ak.realm_key.request history-sharing policy is invalid")
    })?;

    // The requesting reader's projected membership event-state drives the
    // since-join range gate (mirrors the share-direction policy).
    let reader_state = reader_event_state(state, realm_id, &session.actor);
    let visibility = request.key_scope.history_visibility.unwrap_or_else(|| {
        meta.history_visibility
            .parse()
            .unwrap_or(arkret_sdk::HistoryVisibility::Restricted)
    });

    // The provider device's verification/revocation gate.
    let provider_device = state
        .persistence
        .devices()
        .get(&target.principal_id, &target.device_id)
        .await
        .ok()
        .flatten();
    let (provider_revoked, provider_verified) = provider_device
        .map(|device| {
            (
                device.revoked_at.is_some(),
                device.verification_state == "verified",
            )
        })
        .unwrap_or((true, false));

    let input = arkret_sdk::HistoryKeyShareGateInput {
        visibility,
        reader: arkret_sdk::HistoryReaderContext {
            current_active_member: true,
            event_state: reader_state,
            has_discoverability: true,
            has_preview_token: false,
        },
        range: arkret_sdk::HistoryRangeContext {
            since_invite: true,
            since_join: reader_state == arkret_sdk::HistoryReaderEventState::Joined,
            epoch_span: Some(epoch_span(
                request.key_scope.from_epoch,
                request.key_scope.to_epoch,
            )),
        },
        policy: Some(&policy),
        key_source: request.requested_source_class,
        scope: None,
        device: arkret_sdk::HistoryDeviceGate {
            revoked: provider_revoked,
            verified: provider_verified,
        },
        safety_policy_allows: true,
        audit: arkret_sdk::HistoryAuditGate {
            required: policy.audit.share_audit_event_required,
            satisfied: !policy.audit.share_audit_event_required,
        },
    };
    Ok(arkret_sdk::evaluate_history_key_share_gates(input).allowed)
}

fn reader_event_state(
    state: &AppState,
    realm_id: &str,
    reader: &str,
) -> arkret_sdk::HistoryReaderEventState {
    {
        let projection = state.projection.lock();
        if let Some(member) = projection.member(realm_id, reader) {
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

fn epoch_span(from_epoch: u64, to_epoch: u64) -> u64 {
    to_epoch.saturating_sub(from_epoch).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use soland_data::Db;

    use super::*;

    fn test_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-realm-key-request-test-blobs"),
            ),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: Some([9u8; 32]),
            ..crate::config::AppConfig::test_default()
        }
    }

    // BS3/BS4 — the ephemeral `ck.realm_key.request` relay enqueues the request
    // onto the *target provider device's* to-device queue with a
    // `realm_key_request:` idempotency-key prefix, carrying the request payload
    // verbatim so the provider can answer with a `ck.realm_key.share`.
    #[tokio::test]
    async fn realm_key_request_is_relayed_to_target_device_queue() {
        let state = AppState::new(test_config(), Db { pool: None });
        let realm_id = "ak:realm:01904100-0000-7000-8000-00000000ab01";
        let sender_actor = "did:web:bob.example";
        let sender_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
        let provider_principal = "did:web:alice.example";
        let provider_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
        let request_id = "req-0001";
        let created_at = chrono::Utc::now();
        let expires_at = created_at + chrono::Duration::minutes(5);
        let payload = serde_json::json!({
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id},
                "from_epoch": 0,
                "to_epoch": 3
            },
            "recipient_principal_id": sender_actor,
            "recipient_device_id": sender_device,
            "recipient_hpke_public_key": "cHVia2V5",
            "requested_source_class": "verified_member_device",
            "target_source_ref": provider_device,
            "target_principal_id": provider_principal,
            "created_at": "2026-06-25T00:00:00Z"
        });

        // The relay addresses the provider device by the `target_principal_id`
        // carried in the request payload (no membership scan): the delivery
        // target principal MUST equal that field.
        let target_principal = payload["target_principal_id"].as_str().unwrap();
        assert_eq!(target_principal, provider_principal);

        // The target device's queue is empty before the relay.
        let before = state
            .persistence
            .device_messages()
            .list_after(provider_principal, provider_device, 0)
            .await
            .unwrap();
        assert!(before.is_empty(), "queue must start empty");

        project_realm_key_request_to_device(
            &state,
            sender_actor,
            sender_device,
            realm_id,
            request_id,
            target_principal,
            provider_device,
            &payload,
            created_at,
            expires_at,
        )
        .await;

        let queued = state
            .persistence
            .device_messages()
            .list_after(provider_principal, provider_device, 0)
            .await
            .unwrap();
        assert_eq!(queued.len(), 1, "exactly one request relayed");
        let message = &queued[0];
        assert_eq!(message.recipient, provider_principal);
        assert_eq!(message.device_id, provider_device);
        assert_eq!(
            message.idempotency_key,
            format!("realm_key_request:{request_id}")
        );
        assert_eq!(message.content["kind"], "ak.realm_key.request");
        assert_eq!(message.content["sender_device_id"], sender_device);
        assert_eq!(message.content["content"]["realm_id"], realm_id);
        assert_eq!(message.content["content"]["request_id"], request_id);
        assert_eq!(message.content["content"]["payload"], payload);

        let delivered =
            crate::routing::identity::device_messages::device_message_envelopes_after(&queued);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].content["realm_id"], realm_id);
        assert_eq!(delivered[0].content["request_id"], request_id);
        assert_eq!(delivered[0].content["payload"], payload);
        assert_eq!(delivered[0].expires_at, expires_at);

        // The requester's own device queue stays empty — this is a directed
        // relay to the provider, not a broadcast.
        let requester_queue = state
            .persistence
            .device_messages()
            .list_after(sender_actor, sender_device, 0)
            .await
            .unwrap();
        assert!(
            requester_queue.is_empty(),
            "request must not echo to the requester device"
        );
    }
}
