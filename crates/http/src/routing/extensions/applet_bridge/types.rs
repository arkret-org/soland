//! Wire and storage types for the applet bridge surface.

use arkret_models_integration::{AppletInstallOutcome, AppletPackage};
use arkret_wire::{AppletId, Event, ScopeRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) const SOLAND_EDGE_APPLET_ID: &str = "ak:applet:00000000-0000-7000-8000-000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRecord {
    pub applet_id: AppletId,
    pub owner_actor_id: String,
    pub registry_did: String,
    pub bot_actor_id: String,
    pub bot_actor_principal_server_id: String,
    pub bot_actor_provision_ref: String,
    pub bot_principal_control_realm_id: String,
    pub portal_realm_id: String,
    pub effective_scope: ScopeRef,
    pub capabilities: Vec<String>,
    pub package: AppletPackage,
    pub ghost_actors_allowed: bool,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub idempotency_key: String,
    pub install_body_digest: String,
    pub install_id: String,
    pub install_response: AppletInstallOutcome,
    pub registration_event: Event,
    pub capability_grant_events: Vec<Event>,
    pub bot_actor_provision_event: Event,
    pub bot_pcr_genesis_event: Event,
    pub bot_accountability_grant_event: Event,
    pub bot_profile_event: Event,
    pub install_execution: Value,
    #[serde(default)]
    pub revoke_execution: Option<Value>,
    pub ghosts: Vec<GhostActorRecord>,
}

pub(crate) fn registration_epoch_evidence_from_event(
    event: &Event,
) -> Result<arkret_models_integration::AppletRegistrationEpochEvidence, String> {
    let evidence = event
        .payload
        .get("manifest")
        .and_then(Value::as_object)
        .and_then(|manifest| manifest.get("registration_epoch_evidence"))
        .cloned()
        .ok_or_else(|| {
            "registration Event payload.manifest.registration_epoch_evidence is missing".to_owned()
        })?;
    serde_json::from_value(evidence)
        .map_err(|error| format!("registration Event epoch evidence is invalid: {error}"))
}

pub(crate) fn registration_epoch_evidence_from_record(
    record: &AppletRecord,
) -> Result<arkret_models_integration::AppletRegistrationEpochEvidence, String> {
    registration_epoch_evidence_from_event(&record.registration_event)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorRecord {
    pub ghost_actor_id: String,
    pub actor_principal_server_id: String,
    pub managed_actor_provision_ref: String,
    pub principal_control_realm_id: String,
    pub external_ref: arkret_models_integration::GhostExternalTuple,
    #[serde(default)]
    pub display_name: Option<String>,
    pub request_digest: String,
    pub profile_event_ref: String,
    pub accountability_grant_ref: String,
    pub authorization_ref: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletRevokeRecordOutcome {
    pub applet_id: AppletId,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub bot_actor_id: String,
    pub ghost_actor_ids: Vec<String>,
}
