//! Deployment-local, read-only service-route operations projection.
//!
//! These DTOs expose only state already verified and persisted by Soland.
//! They are not Arkret discovery artifacts and carry no authorization.

use arkret_wire::ServiceId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteSummary {
    pub service_id: ServiceId,
    pub service_kind: String,
    pub known: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_expires_at: Option<DateTime<Utc>>,
    pub notice_count: u32,
    pub notices_truncated: bool,
    pub ack_count: u32,
    pub acks_truncated: bool,
    pub quarantined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteList {
    #[serde(default)]
    pub routes: Vec<AdminServiceRouteSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteFloor {
    pub record_sequence: u64,
    pub record_digest: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteCurrentRecord {
    pub full_id: String,
    pub method_history_head: String,
    pub version_id: String,
    pub record_sequence: u64,
    pub record_digest: String,
    pub base_url: String,
    pub current_record_url: String,
    pub describe_digest: String,
    pub verified_at: DateTime<Utc>,
    pub refresh_after: DateTime<Utc>,
    pub signed_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteCache {
    pub cached_at: DateTime<Utc>,
    pub cache_expires_at: DateTime<Utc>,
    pub routable_at_observed_at: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteNotice {
    pub handover_id: String,
    pub notice_revision: u32,
    pub notice_digest: String,
    pub state: String,
    pub from_record_sequence: u64,
    pub from_record_digest: String,
    pub expires_at: DateTime<Utc>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteAck {
    pub request_id: String,
    pub source_service_id: String,
    pub receiver_service_id: String,
    pub realm_id: String,
    pub request_digest: String,
    pub artifact_digest: String,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteQuarantine {
    pub artifact_family: String,
    pub artifact_key: String,
    pub accepted_digest: String,
    pub conflicting_digest: String,
    pub quarantined_at: DateTime<Utc>,
    /// Admin-private local diagnostic context. It is never protocol evidence.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub diagnostic: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteDetail {
    pub service_id: ServiceId,
    pub service_kind: String,
    /// False means no locally persisted verified state exists for this key.
    pub known: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<AdminServiceRouteFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_record: Option<AdminServiceRouteCurrentRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<AdminServiceRouteCache>,
    #[serde(default)]
    pub notices: Vec<AdminServiceRouteNotice>,
    pub notices_truncated: bool,
    #[serde(default)]
    pub acks: Vec<AdminServiceRouteAck>,
    pub acks_truncated: bool,
    #[serde(default)]
    pub quarantine: Vec<AdminServiceRouteQuarantine>,
    pub quarantine_truncated: bool,
    pub observed_at: DateTime<Utc>,
    pub authority: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_route_is_explicit_and_sparse() {
        let detail: AdminServiceRouteDetail = serde_json::from_value(serde_json::json!({
            "service_id": "ak:did_core:webvh:z6Mkroute",
            "service_kind": "principal_server",
            "known": false,
            "notices_truncated": false,
            "acks_truncated": false,
            "quarantine_truncated": false,
            "observed_at": "2026-08-10T00:00:00Z",
            "authority": "local_verified_persistence"
        }))
        .unwrap();
        assert!(!detail.known);
        assert!(detail.floor.is_none());
        assert!(detail.current_record.is_none());
        assert!(detail.notices.is_empty());
    }
}
