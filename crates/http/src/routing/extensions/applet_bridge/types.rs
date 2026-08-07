//! Wire and storage types for the applet bridge surface.

use arkret_models_integration::{
    AppletInstallOutcome, AppletPackage, AppletRegistrationEpochEvidence, AppletWireNamespaces,
};
use arkret_wire::{Event, ScopeRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::applet_manifest::AppletManifest;

pub(super) const SOLAND_EDGE_APPLET_ID: &str = "ak:applet:00000000-0000-7000-8000-000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletRecord {
    pub applet_id: String,
    pub namespace: String,
    pub owner_actor_id: String,
    pub registry_did: String,
    pub bot_actor_id: String,
    pub portal_realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    pub capabilities: Vec<String>,
    pub manifest: AppletManifest,
    #[serde(default)]
    pub package: Option<AppletPackage>,
    /// Durable copy of the evidence intentionally excluded from the signed
    /// AppletPackage serialization transcript. Runtime authorization must be
    /// able to revalidate the installed registration epoch after reload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_epoch_evidence: Option<AppletRegistrationEpochEvidence>,
    #[serde(default)]
    pub namespaces: Option<AppletWireNamespaces>,
    #[serde(default)]
    pub ghost_actors_allowed: bool,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub install_body_digest: Option<String>,
    #[serde(default)]
    pub install_id: Option<String>,
    #[serde(default)]
    pub install_response: Option<AppletInstallOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_event: Option<Event>,
    #[serde(default)]
    pub capability_grant_events: Vec<Event>,
    #[serde(default)]
    pub install_execution: Option<Value>,
    #[serde(default)]
    pub revoke_execution: Option<Value>,
    #[serde(default)]
    pub ghosts: Vec<GhostActorRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostActorRecord {
    pub ghost_actor_id: String,
    pub external_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_event_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_grant_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletRevokeRecordOutcome {
    pub applet_id: String,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub bot_actor_id: String,
    pub ghost_actor_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AppletInstallPaths {
    pub preview_path: String,
    pub commit_path: String,
    pub revoke_preview_path: String,
    pub revoke_path: String,
    pub ghost_actor_provision_path: String,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletProtocolDescribeOutcome {
    pub contract: String,
    pub install: AppletInstallPaths,
    pub transaction_path: String,
    pub transaction_auth: Value,
    pub package_schema: String,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletManifestRegisterRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_json: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_registry_did: Option<String>,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletView {
    pub applet_id: String,
    pub namespace: String,
    pub owner_actor_id: String,
    pub registry_did: String,
    pub bot_actor_id: String,
    pub portal_realm_id: String,
    pub capabilities: Vec<String>,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub ghost_actor_ids: Vec<String>,
    pub manifest: AppletManifest,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AppletExternalUserInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletGhostIngressRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_user: Option<AppletExternalUserInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletPortalMessageRequestBody {
    pub realm_id: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletPortalMessageOutcome {
    pub message_id: String,
    pub event_id: String,
    pub operation_id: String,
    pub realm_id: String,
    pub portal_realm_id: String,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletGhostIngressOutcome {
    pub applet_id: String,
    pub ghost_actor_id: String,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub accountability: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal_realm_id: Option<String>,
}
