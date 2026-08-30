use arkret_identifiers::{Did, DidCoreId, project_did_to_core_id};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_wire::{DidUrl, OpaqueLocalId};
use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde_json::Value;
use soland_storage::{AccountPk, AgentPrincipalRecord, PersistenceError};
use uuid::Uuid;

use crate::schema::agent_principals;

#[derive(Clone, Debug, PartialEq, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = agent_principals)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(treat_none_as_null = true)]
pub(crate) struct AgentPrincipalRow {
    #[diesel(skip_update)]
    pub id: DidCoreId,
    #[diesel(skip_update)]
    pub controller_id: DidCoreId,
    #[diesel(skip_update)]
    pub principal_control_realm_id: String,
    #[diesel(skip_update)]
    pub controller_authorization_ref: String,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: String,
    #[diesel(skip_update)]
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<OpaqueLocalId>,
    pub paired_pairing_request_id: Option<OpaqueLocalId>,
    pub paired_request_digest: Option<String>,
    pub pending_pairing_commit_intent: Option<Value>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<OpaqueLocalId>,
    pub controller_account_pk: Option<i64>,
    pub recipient_id: Option<DidCoreId>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub approval_notification_id: Option<Uuid>,
    pub runtime_key_request: Option<Value>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_signing_key_binding: Option<Value>,
    pub state_changed_at: Option<DateTime<Utc>>,
    #[diesel(skip_update)]
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<AgentPrincipalRecord> for AgentPrincipalRow {
    type Error = PersistenceError;

    fn try_from(record: AgentPrincipalRecord) -> Result<Self, Self::Error> {
        let id = DidCoreId::new(record.id).map_err(|error| {
            PersistenceError::SchemaViolation(format!("Agent id is not a did_core_id: {error}"))
        })?;
        let controller_id = DidCoreId::new(record.controller_id).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Agent controller_id is not a did_core_id: {error}"
            ))
        })?;
        let recipient_id = record
            .recipient_id
            .map(DidCoreId::new)
            .transpose()
            .map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "Agent recipient_id is not a did_core_id: {error}"
                ))
            })?;
        validate_managed_agent_identity_binding(&id, &record.controller_authorization_ref)?;
        Ok(Self {
            id,
            controller_id,
            principal_control_realm_id: record.principal_control_realm_id,
            controller_authorization_ref: record.controller_authorization_ref.to_string(),
            display_name: record.display_name,
            agent_slug: record.agent_slug,
            avatar_blob_ref: record.avatar_blob_ref,
            state: record.state.as_wire_str().to_owned(),
            requested_scope: record.requested_scope,
            accountability: record.accountability,
            provision_event_refs: record.provision_event_refs,
            pairing_request_id: record.pairing_request_id,
            paired_pairing_request_id: record.paired_pairing_request_id,
            paired_request_digest: record.paired_request_digest,
            pending_pairing_commit_intent: record
                .pending_pairing_commit_intent
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "encode pending Agent pairing commit intent: {error}"
                    ))
                })?,
            pairing_code: record.pairing_code,
            pairing_expires_at: record.pairing_expires_at,
            approval_request_id: record.approval_request_id,
            controller_account_pk: record.controller_account_pk.map(AccountPk::get),
            recipient_id,
            runtime_key_binding_digest: record.runtime_key_binding_digest,
            runtime_public_key_digest: record.runtime_public_key_digest,
            runtime_attestation_digest: record.runtime_attestation_digest,
            approval_notification_id: record.approval_notification_id,
            runtime_key_request: record
                .runtime_key_request
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "encode typed Agent runtime key request: {error}"
                    ))
                })?,
            approval_requested_at: record.approval_requested_at,
            authorized_event_ref: record.authorized_event_ref,
            authorized_verification_method: record.authorized_verification_method,
            authorized_public_key_digest: record.authorized_public_key_digest,
            authorized_signing_key_binding: record
                .authorized_signing_key_binding
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "encode typed Agent signing-key binding: {error}"
                    ))
                })?,
            state_changed_at: record.state_changed_at,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }
}

fn validate_managed_agent_identity_binding(
    agent_id: &DidCoreId,
    controller_authorization_ref: &DidUrl,
) -> Result<(), PersistenceError> {
    let (agent_did, fragment) = controller_authorization_ref
        .as_str()
        .split_once('#')
        .ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "Agent controller_authorization_ref has no fragment".to_owned(),
            )
        })?;
    if fragment != "managed-controller" {
        return Err(PersistenceError::SchemaViolation(
            "Agent controller_authorization_ref is not the managed-controller delegation"
                .to_owned(),
        ));
    }
    let agent_did = Did::new(agent_did.to_owned()).map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "Agent controller_authorization_ref does not contain a valid DID: {error}"
        ))
    })?;
    let projected = project_did_to_core_id(&agent_did).map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "Agent controller_authorization_ref DID projection failed: {error}"
        ))
    })?;
    if projected != *agent_id {
        return Err(PersistenceError::SchemaViolation(
            "Agent controller_authorization_ref does not belong to the Agent id".to_owned(),
        ));
    }
    Ok(())
}

impl TryFrom<AgentPrincipalRow> for AgentPrincipalRecord {
    type Error = PersistenceError;

    fn try_from(row: AgentPrincipalRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id.to_string(),
            controller_id: row.controller_id.to_string(),
            principal_control_realm_id: row.principal_control_realm_id,
            controller_authorization_ref: DidUrl::new(row.controller_authorization_ref).map_err(
                |error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored Agent controller_authorization_ref is invalid: {error}"
                    ))
                },
            )?,
            display_name: row.display_name,
            agent_slug: row.agent_slug,
            avatar_blob_ref: row.avatar_blob_ref,
            state: AgentLifecycleState::from_wire_str(&row.state).ok_or_else(|| {
                PersistenceError::SchemaViolation(format!(
                    "stored Agent lifecycle state is invalid: {}",
                    row.state
                ))
            })?,
            requested_scope: row.requested_scope,
            accountability: row.accountability,
            provision_event_refs: row.provision_event_refs,
            pairing_request_id: row.pairing_request_id,
            paired_pairing_request_id: row.paired_pairing_request_id,
            paired_request_digest: row.paired_request_digest,
            pending_pairing_commit_intent: row
                .pending_pairing_commit_intent
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored pending Agent pairing commit intent is invalid: {error}"
                    ))
                })?,
            pairing_code: row.pairing_code,
            pairing_expires_at: row.pairing_expires_at,
            approval_request_id: row.approval_request_id,
            controller_account_pk: row.controller_account_pk.map(AccountPk),
            recipient_id: row.recipient_id.map(|id| id.to_string()),
            runtime_key_binding_digest: row.runtime_key_binding_digest,
            runtime_public_key_digest: row.runtime_public_key_digest,
            runtime_attestation_digest: row.runtime_attestation_digest,
            approval_notification_id: row.approval_notification_id,
            runtime_key_request: row
                .runtime_key_request
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored Agent runtime key request is invalid: {error}"
                    ))
                })?,
            approval_requested_at: row.approval_requested_at,
            authorized_event_ref: row.authorized_event_ref,
            authorized_verification_method: row.authorized_verification_method,
            authorized_public_key_digest: row.authorized_public_key_digest,
            authorized_signing_key_binding: row
                .authorized_signing_key_binding
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored Agent signing-key binding is invalid: {error}"
                    ))
                })?,
            state_changed_at: row.state_changed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_agent_binding_accepts_did_delegation_for_projected_core() {
        let authorization_ref =
            DidUrl::new("did:webvh:z6mkfixtureagent:agent.example#managed-controller").unwrap();
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixtureagent").unwrap();

        validate_managed_agent_identity_binding(&agent_id, &authorization_ref)
            .expect("the delegation DID projects to the stored Agent core id");
    }

    #[test]
    fn managed_agent_binding_rejects_controller_did_or_wrong_fragment() {
        let controller_delegation =
            DidUrl::new("did:web:controller.example#managed-controller").unwrap();
        let agent_id = DidCoreId::new("ak:did_core:webvh:z6mkfixtureagent").unwrap();
        assert!(
            validate_managed_agent_identity_binding(&agent_id, &controller_delegation).is_err()
        );

        let wrong_fragment =
            DidUrl::new("did:webvh:z6mkfixtureagent:agent.example#controller").unwrap();
        assert!(validate_managed_agent_identity_binding(&agent_id, &wrong_fragment).is_err());
    }
}
