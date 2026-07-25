//! Deployment-local device signing-key directory contracts.
//!
//! Nothing in this module is part of the `/_arkret/` protocol surface. These
//! DTOs are shared by Arkret products (soland serves the directory, coauth
//! consumes it) so producers and consumers still use one strong type without
//! presenting product-local endpoints as protocol models.

use arkret_identifiers::{DeviceId, Did, EventId};
use arkret_models_crypto::DeviceStatus;
use serde::{Deserialize, Serialize};

/// Request for the product-local device signing-key directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceSigningKeyDirectoryQueryRequestBody {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_ids: Vec<DeviceId>,
}

/// One authorized, non-revoked device signing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AuthorizedDeviceSigningKey {
    pub device_id: DeviceId,
    pub device_signing_key: String,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_status: DeviceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
}

/// Response from the product-local device signing-key directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceSigningKeyDirectoryOutcome {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<AuthorizedDeviceSigningKey>,
}
