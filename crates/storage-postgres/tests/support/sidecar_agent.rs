//! Accepted Agent fixture material shared by the Sidecar authority matrix.
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl, EventKind, RealmId};

use super::device_authorization_history;
pub(super) fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:successor", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    commit.producer_signer_fact_digest = None;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

pub(super) fn station_genesis_commit(
    template: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::RealmCommit {
    let realm_id = RealmId::from_event_id(&event.event_id);
    let mut commit = template.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:genesis", event.event_id).as_bytes(),
    ));
    commit.realm_id = realm_id.clone();
    commit.stream_ref = arkret_wire::CommitStreamRef::Realm { realm_id };
    commit.stream_position = 0;
    commit.previous_commit_ref = None;
    commit.event_ref = event.event_id.clone();
    commit.governance_generation = 0;
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.committed_at = committed_at;
    commit.producer_signer_fact_digest = None;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

#[allow(clippy::too_many_arguments)]
pub(super) fn agent_provision_event(
    controller: &AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    agent_id: &DidCoreId,
    agent_pcr_id: &RealmId,
    controller_authorization_ref: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AgentProvision.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        controller.principal_id.clone(),
        controller.station_id.clone(),
        serde_json::json!({
            "schema": "ak.schema.agent_provision.v1",
            "agent_id": agent_id,
            "controller_principal_id": controller.principal_id,
            "principal_control_realm_id": agent_pcr_id,
            "controller_authorization_ref": controller_authorization_ref,
            "agent_slug": format!("sidecar-{}",uuid::Uuid::now_v7().simple()),
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "b".repeat(64)),
            "selector_visibility": "private",
            "created_at": arkret_canonical::format_timestamp_canonical(created_at)
        }),
        created_at,
    )
    .unwrap();
    device_authorization_history::sign_event(event, method.clone(), seed)
}

pub(super) fn agent_control_event(
    controller_method: &DidUrl,
    signing_seed: [u8; 32],
    controller: &AccountId,
    agent: &AccountId,
    agent_pcr: &RealmId,
    authorization_ref: &str,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr.clone(),
        },
        ActorId::account(agent.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(ActorId::account(controller.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_authorization_history::sign_event(event, controller_method.clone(), signing_seed)
}

pub(super) fn agent_key_authorization(
    agent_did: &arkret_wire::Did,
    controller: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let method = format!("{agent_did}#runtime-1");
    let submit = arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1;
    serde_json::json!({
        "agent_id": arkret_wire::project_did_to_core_id(agent_did).unwrap(),
        "key_id": method,
        "verification_method": method,
        "public_key": {
            "kty": "OKP",
            "kid": method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]).verifying_key().as_bytes()
            )
        },
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [submit],
            "resources": [{"kind": "operation", "operation": submit}]
        },
        "audience": ["ak:did_core:web:direct-conversation.example"],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence": {
            "kind": "pairing_request",
            "request_canonical_digest": format!("sha256:{}", "d".repeat(64)),
            "pairing_request_id": format!("agent_pairing_request:{}", uuid::Uuid::now_v7()),
            "approved_by": controller
        }
    })
}
