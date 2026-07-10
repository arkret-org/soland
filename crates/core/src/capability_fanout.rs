//! Shared wire contract for the coauth → soland capability fanout S2S call
//! (`POST /_soland/root/authz/capability-fanout`,
//! `org.arkret.soland.root.authz.capability_fanout.submit`).
//!
//! This is a deployment-internal product contract (service-http-binding.md
//! §2.1.3(b)), not a spec operation, so the types live in `soland-core`
//! rather than the SDK registry surface — the same pattern the sodmin admin
//! seal DTOs already use. Both ends (soland handler, coauth producer) MUST
//! consume these definitions instead of hand-writing mirrors (SOL-DRY-03).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body coauth POSTs to `/_soland/root/authz/capability-fanout`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityFanoutBody {
    /// Fixed envelope kind `ak.coauth.collaboration_capability.fanout.v1`.
    pub kind: String,
    /// The coauth-side operation this fanout materializes (e.g. grant /
    /// revoke), echoed back in the response.
    pub operation: String,
    pub issuer_service_did: String,
    /// Durable event kind the fanout projects (grant / revoke event kind).
    pub event_kind: String,
    pub event_id: String,
    pub capability_grant_id: String,
    /// The event payload to project; treated as an opaque canonical-JSON
    /// value at this boundary and validated by the receiving reducer.
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_servers: Vec<Value>,
}

/// Response from the soland fanout handler.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityFanoutResponse {
    pub accepted: Vec<String>,
    pub duplicate: Vec<String>,
    pub event_id: String,
    pub capability_grant_id: String,
    pub operation: String,
    pub authz_state: CapabilityFanoutAuthzState,
}

/// Post-projection authorization state the fanout handler observed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityFanoutAuthzState {
    pub projected: bool,
    pub effective: bool,
    pub revoked: bool,
    pub grant_present: bool,
}
