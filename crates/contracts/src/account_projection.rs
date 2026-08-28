//! Deployment-private Account Authority -> Principal Server projection contract.
//!
//! This edge materializes an already verified account binding before an initial
//! session grant may escape the Account Authority. It is deliberately outside
//! the interoperable `/_arkret/` surface and must not be advertised as
//! `ak.gate.account.command.register.v1`, which is owned by the Account
//! Authority registration flow.

use arkret_identifiers::{DeviceId, Did, DidCoreId};
use serde::{Deserialize, Serialize};

pub const ACCOUNT_PROJECTION_PATH: &str = "/_soland/gate/account/project";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountProjectionRequestBody {
    pub principal_id: DidCoreId,
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
}

impl AccountProjectionRequestBody {
    pub fn validate(&self) -> Result<(), String> {
        let projected = arkret_identifiers::project_did_to_core_id(&self.did)
            .map_err(|error| format!("did cannot be projected: {error}"))?;
        if projected != self.principal_id {
            return Err("did must project to principal_id".to_owned());
        }
        Ok(())
    }
}
