use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentRuntimeApprovalControllerProjection,
};
use arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding;
use arkret_wire::{DidUrl, OpaqueLocalId, ServiceAccountId};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PendingAgentPairingCommitIntent {
    pub request_digest: String,
    pub authorize_event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_binding: Option<AgentSigningKeyBinding>,
}

#[derive(Clone, Debug)]
pub struct IssueAgentProvisioningAbandonmentChallenge {
    pub controller_id: String,
    pub agent_id: String,
    pub principal_control_realm_id: String,
    pub allocation_handle: String,
    pub request_digest: String,
    pub credential_fingerprint: String,
    pub challenge_outcome: Value,
}

#[derive(Clone, Debug)]
pub struct ConfirmAgentProvisioningAbandonment {
    pub controller_id: String,
    pub agent_id: String,
    pub principal_control_realm_id: String,
    pub allocation_handle: String,
    pub challenge_id: String,
    pub challenge: String,
    pub request_digest: String,
    pub credential_fingerprint: String,
    pub now: DateTime<Utc>,
    pub terminal_outcome: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentProvisioningAbandonmentWriteOutcome {
    Challenge(Value),
    Abandoned(Value),
    NotFound,
    ProvisionMismatch,
    GenesisAccepted,
    ChallengeMissing,
    ChallengeExpired,
    ChallengeConsumed,
    CredentialReused,
}

const ABANDONMENT_STATE_FIELD: &str = "provisioning_abandonment";

/// Apply challenge issuance to one locked Agent row. Storage adapters call
/// this only while the corresponding accepted-Event store is locked (memory)
/// or in the same database transaction (PostgreSQL), so the genesis check and
/// challenge write form one durable decision.
pub fn apply_agent_provisioning_abandonment_challenge(
    record: &mut AgentPrincipalRecord,
    genesis_accepted: bool,
    command: &IssueAgentProvisioningAbandonmentChallenge,
) -> AgentProvisioningAbandonmentWriteOutcome {
    if record.id != command.agent_id || record.controller_id != command.controller_id {
        return AgentProvisioningAbandonmentWriteOutcome::NotFound;
    }
    if genesis_accepted {
        return AgentProvisioningAbandonmentWriteOutcome::GenesisAccepted;
    }
    let Some(refs) = record
        .provision_event_refs
        .as_mut()
        .and_then(Value::as_object_mut)
    else {
        return AgentProvisioningAbandonmentWriteOutcome::ProvisionMismatch;
    };
    if record.principal_control_realm_id != command.principal_control_realm_id
        || refs.get("allocation_handle").and_then(Value::as_str)
            != Some(command.allocation_handle.as_str())
        || refs.get("pcr_genesis_accepted").and_then(Value::as_bool) != Some(false)
    {
        return AgentProvisioningAbandonmentWriteOutcome::ProvisionMismatch;
    }
    if let Some(existing) = refs.get(ABANDONMENT_STATE_FIELD) {
        if existing
            .get("terminal_outcome")
            .is_some_and(|outcome| !outcome.is_null())
        {
            return AgentProvisioningAbandonmentWriteOutcome::ChallengeConsumed;
        }
        if existing
            .get("challenge_request_digest")
            .and_then(Value::as_str)
            == Some(command.request_digest.as_str())
            && let Some(outcome) = existing.get("challenge_outcome")
        {
            return AgentProvisioningAbandonmentWriteOutcome::Challenge(outcome.clone());
        }
        return AgentProvisioningAbandonmentWriteOutcome::ChallengeConsumed;
    }
    refs.insert(
        ABANDONMENT_STATE_FIELD.to_owned(),
        serde_json::json!({
            "challenge_request_digest": command.request_digest,
            "issuance_credential_fingerprint": command.credential_fingerprint,
            "challenge_outcome": command.challenge_outcome,
            "consumed_request_digest": null,
            "terminal_outcome": null,
            "tombstone_count": 0
        }),
    );
    AgentProvisioningAbandonmentWriteOutcome::Challenge(command.challenge_outcome.clone())
}

/// Consume a challenge and hide/release the provisional projection in one
/// locked-row mutation. The accepted provision Event and the realm-id claim
/// stay in `provision_event_refs`; clearing only `agent_slug` releases the
/// selector while retaining a permanent no-reuse tombstone for the Realm id.
pub fn apply_agent_provisioning_abandonment(
    record: &mut AgentPrincipalRecord,
    genesis_accepted: bool,
    command: &ConfirmAgentProvisioningAbandonment,
) -> AgentProvisioningAbandonmentWriteOutcome {
    if record.id != command.agent_id || record.controller_id != command.controller_id {
        return AgentProvisioningAbandonmentWriteOutcome::NotFound;
    }
    let Some(refs) = record
        .provision_event_refs
        .as_mut()
        .and_then(Value::as_object_mut)
    else {
        return AgentProvisioningAbandonmentWriteOutcome::ProvisionMismatch;
    };
    if record.principal_control_realm_id != command.principal_control_realm_id
        || refs.get("allocation_handle").and_then(Value::as_str)
            != Some(command.allocation_handle.as_str())
    {
        return AgentProvisioningAbandonmentWriteOutcome::ProvisionMismatch;
    }
    let Some(state) = refs
        .get_mut(ABANDONMENT_STATE_FIELD)
        .and_then(Value::as_object_mut)
    else {
        return AgentProvisioningAbandonmentWriteOutcome::ChallengeMissing;
    };
    if let Some(outcome) = state
        .get("terminal_outcome")
        .filter(|value| !value.is_null())
    {
        return if state.get("consumed_request_digest").and_then(Value::as_str)
            == Some(command.request_digest.as_str())
        {
            AgentProvisioningAbandonmentWriteOutcome::Abandoned(outcome.clone())
        } else {
            AgentProvisioningAbandonmentWriteOutcome::ChallengeConsumed
        };
    }
    if genesis_accepted {
        return AgentProvisioningAbandonmentWriteOutcome::GenesisAccepted;
    }
    let Some(challenge_outcome) = state.get("challenge_outcome") else {
        return AgentProvisioningAbandonmentWriteOutcome::ChallengeMissing;
    };
    if challenge_outcome
        .get("challenge_id")
        .and_then(Value::as_str)
        != Some(command.challenge_id.as_str())
        || challenge_outcome.get("challenge").and_then(Value::as_str)
            != Some(command.challenge.as_str())
        || challenge_outcome.get("agent_id").and_then(Value::as_str)
            != Some(command.agent_id.as_str())
        || challenge_outcome
            .get("principal_control_realm_id")
            .and_then(Value::as_str)
            != Some(command.principal_control_realm_id.as_str())
        || challenge_outcome
            .get("allocation_handle")
            .and_then(Value::as_str)
            != Some(command.allocation_handle.as_str())
    {
        return AgentProvisioningAbandonmentWriteOutcome::ProvisionMismatch;
    }
    let expired = challenge_outcome
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc) <= command.now)
        .unwrap_or(true);
    if expired {
        return AgentProvisioningAbandonmentWriteOutcome::ChallengeExpired;
    }
    if state
        .get("issuance_credential_fingerprint")
        .and_then(Value::as_str)
        == Some(command.credential_fingerprint.as_str())
    {
        return AgentProvisioningAbandonmentWriteOutcome::CredentialReused;
    }

    let released_slug = record.agent_slug.take();
    state.insert(
        "consumed_request_digest".to_owned(),
        Value::String(command.request_digest.clone()),
    );
    state.insert(
        "terminal_outcome".to_owned(),
        command.terminal_outcome.clone(),
    );
    state.insert("tombstone_count".to_owned(), Value::from(1));
    if let Some(slug) = released_slug {
        state.insert("released_agent_slug".to_owned(), Value::String(slug));
    }
    record.pairing_request_id = None;
    record.pairing_code = None;
    record.pairing_expires_at = None;
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.updated_at = command.now;
    AgentProvisioningAbandonmentWriteOutcome::Abandoned(command.terminal_outcome.clone())
}

pub fn agent_provisioning_is_abandoned(record: &AgentPrincipalRecord) -> bool {
    record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get(ABANDONMENT_STATE_FIELD))
        .and_then(|state| state.get("terminal_outcome"))
        .is_some_and(|outcome| !outcome.is_null())
}

#[cfg(test)]
mod provisioning_abandonment_tests {
    use arkret_wire::DidUrl;
    use chrono::{Duration, TimeZone as _};

    use super::*;

    fn fixture() -> (
        AgentPrincipalRecord,
        IssueAgentProvisioningAbandonmentChallenge,
        ConfirmAgentProvisioningAbandonment,
    ) {
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).single().unwrap();
        let mut record = AgentPrincipalRecord::new(
            "ak:did_core:AbBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            "ak:did_core:AcCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned(),
            "ak:realm:AdDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_owned(),
            DidUrl::new("did:webvh:zFixture:agent.example#managed-controller").unwrap(),
            AgentLifecycleState::Active,
            issued_at,
        );
        record.agent_slug = Some("fixture-agent".to_owned());
        record.provision_event_refs = Some(serde_json::json!({
            "provision_event_id": "ak:event:AeEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
            "allocation_handle": "allocation-fixture",
            "pcr_genesis_accepted": false
        }));
        let challenge_outcome = serde_json::json!({
            "request_id": "abandon-challenge-request",
            "challenge_id": "challenge-fixture",
            "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
            "agent_id": record.id,
            "principal_control_realm_id": record.principal_control_realm_id,
            "allocation_handle": "allocation-fixture",
            "expires_at": "2026-08-10T00:05:00.000Z"
        });
        let issue = IssueAgentProvisioningAbandonmentChallenge {
            controller_id: record.controller_id.clone(),
            agent_id: record.id.clone(),
            principal_control_realm_id: record.principal_control_realm_id.clone(),
            allocation_handle: "allocation-fixture".to_owned(),
            request_digest: "sha256:challenge-request".to_owned(),
            credential_fingerprint: "credential-old".to_owned(),
            challenge_outcome,
        };
        let confirm = ConfirmAgentProvisioningAbandonment {
            controller_id: record.controller_id.clone(),
            agent_id: record.id.clone(),
            principal_control_realm_id: record.principal_control_realm_id.clone(),
            allocation_handle: "allocation-fixture".to_owned(),
            challenge_id: "challenge-fixture".to_owned(),
            challenge: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            request_digest: "sha256:confirm-request".to_owned(),
            credential_fingerprint: "credential-fresh".to_owned(),
            now: issued_at + Duration::minutes(1),
            terminal_outcome: serde_json::json!({
                "request_id": "abandon-confirm-request",
                "status": "abandoned",
                "agent_id": record.id,
                "principal_control_realm_id": record.principal_control_realm_id,
                "abandoned_at": "2026-08-10T00:01:00.000Z"
            }),
        };
        (record, issue, confirm)
    }

    #[test]
    fn abandonment_is_single_tombstone_and_exactly_replayable() {
        let (mut record, issue, confirm) = fixture();
        assert!(matches!(
            apply_agent_provisioning_abandonment_challenge(&mut record, false, &issue),
            AgentProvisioningAbandonmentWriteOutcome::Challenge(_)
        ));

        let before_reused_credential = record.clone();
        let mut reused = confirm.clone();
        reused.credential_fingerprint = issue.credential_fingerprint.clone();
        assert_eq!(
            apply_agent_provisioning_abandonment(&mut record, false, &reused),
            AgentProvisioningAbandonmentWriteOutcome::CredentialReused
        );
        assert_eq!(record, before_reused_credential);

        let before_genesis_race = record.clone();
        assert_eq!(
            apply_agent_provisioning_abandonment(&mut record, true, &confirm),
            AgentProvisioningAbandonmentWriteOutcome::GenesisAccepted
        );
        assert_eq!(record, before_genesis_race);

        let first = apply_agent_provisioning_abandonment(&mut record, false, &confirm);
        let after_first = record.clone();
        assert!(matches!(
            first,
            AgentProvisioningAbandonmentWriteOutcome::Abandoned(_)
        ));
        assert!(agent_provisioning_is_abandoned(&record));
        assert!(record.agent_slug.is_none());
        assert_eq!(
            record
                .provision_event_refs
                .as_ref()
                .and_then(|refs| refs.pointer("/provisioning_abandonment/tombstone_count"))
                .and_then(Value::as_u64),
            Some(1)
        );

        assert!(matches!(
            apply_agent_provisioning_abandonment(&mut record, false, &confirm),
            AgentProvisioningAbandonmentWriteOutcome::Abandoned(_)
        ));
        assert_eq!(record, after_first);
        assert_eq!(
            apply_agent_provisioning_abandonment_challenge(&mut record, false, &issue),
            AgentProvisioningAbandonmentWriteOutcome::ChallengeConsumed
        );
    }
}

/// Durable projection of a managed Agent principal.
///
/// The controller, PCR, and controller-authorization fields form the immutable
/// identity binding. Adapters preserve those immutable fields during updates.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPrincipalRecord {
    pub id: String,
    pub controller_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: DidUrl,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: AgentLifecycleState,
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<OpaqueLocalId>,
    pub paired_pairing_request_id: Option<OpaqueLocalId>,
    pub paired_request_digest: Option<String>,
    pub pending_pairing_commit_intent: Option<PendingAgentPairingCommitIntent>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<OpaqueLocalId>,
    pub controller_account_id: Option<ServiceAccountId>,
    pub recipient_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub approval_notification_id: Option<Uuid>,
    pub runtime_key_request: Option<AgentRuntimeApprovalControllerProjection>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_signing_key_binding: Option<AgentSigningKeyBinding>,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentPrincipalRecord {
    pub fn new(
        id: String,
        controller_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: DidUrl,
        state: AgentLifecycleState,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            controller_id,
            principal_control_realm_id,
            controller_authorization_ref,
            display_name: None,
            agent_slug: None,
            avatar_blob_ref: None,
            state,
            requested_scope: None,
            accountability: None,
            provision_event_refs: None,
            pairing_request_id: None,
            paired_pairing_request_id: None,
            paired_request_digest: None,
            pending_pairing_commit_intent: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_id: None,
            recipient_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            authorized_signing_key_binding: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }
}
