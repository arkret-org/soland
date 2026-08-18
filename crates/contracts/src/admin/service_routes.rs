//! Deployment-local, read-only service-route operations projection.
//!
//! These DTOs expose only state already verified and persisted by Soland.
//! They are not Arkret discovery artifacts and carry no authorization.

use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteSummary {
    pub service_id: DidCoreId,
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
    pub service_id: DidCoreId,
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

/// One signed notice revision this deployment issued.
///
/// The signed bytes themselves are not exposed: an operator surface exists to
/// show what state the plan is in, not to hand out artifacts a peer should
/// obtain through the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteHandoverRevision {
    pub notice_revision: u32,
    pub notice_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_notice_digest: Option<String>,
    /// `scheduled` or `cancelled`.
    pub state: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteHandoverSummary {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub handover_id: String,
    /// Exact current record the plan is bound to. A plan whose basis moved is
    /// invalid and must be rebuilt rather than re-targeted.
    pub basis_record_sequence: u64,
    pub basis_record_digest: String,
    pub candidate_base_url: String,
    pub candidate_record_url: String,
    pub not_before: DateTime<Utc>,
    pub cutover_at: DateTime<Utc>,
    pub grace_until: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// `draft` | `publishing` | `preannounced` | `ready` | `cutover` |
    /// `grace` | `completed` | `cancelled` | `failed` | `quarantined`.
    pub lifecycle_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_notice_revision: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_notice_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteHandoverList {
    #[serde(default)]
    pub handovers: Vec<AdminServiceRouteHandoverSummary>,
    pub handovers_truncated: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteHandoverDetail {
    #[serde(flatten)]
    pub plan: AdminServiceRouteHandoverSummary,
    #[serde(default)]
    pub revisions: Vec<AdminServiceRouteHandoverRevision>,
    pub revisions_truncated: bool,
    pub observed_at: DateTime<Utc>,
}

/// Operator input for a new planned handover.
///
/// `candidate_record_url` is intentionally absent: it is derived from
/// `candidate_base_url`, because a hand-written locator could point somewhere
/// the base does not and every recipient re-derives it anyway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteHandoverPlanBody {
    pub handover_id: String,
    pub candidate_base_url: String,
    pub not_before: DateTime<Utc>,
    pub cutover_at: DateTime<Utc>,
    pub grace_until: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminServiceRouteHandoverCancelBody {
    /// Digest of the revision the cancellation chains onto. Supplying it makes
    /// a cancel that raced another revision fail instead of forking the chain.
    pub expected_previous_notice_digest: String,
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

    #[test]
    fn handover_plan_body_refuses_a_caller_supplied_record_url() {
        let error =
            serde_json::from_value::<AdminServiceRouteHandoverPlanBody>(serde_json::json!({
                "handover_id": "h-1",
                "candidate_base_url": "https://new.example/",
                "candidate_record_url": "https://attacker.example/",
                "not_before": "2026-08-19T01:00:00Z",
                "cutover_at": "2026-08-19T02:00:00Z",
                "grace_until": "2026-08-19T06:00:00Z",
                "expires_at": "2026-08-19T12:00:00Z"
            }))
            .unwrap_err();
        assert!(error.to_string().contains("candidate_record_url"));
    }

    #[test]
    fn handover_detail_round_trips_with_its_flattened_plan() {
        let value = serde_json::json!({
            "service_id": "ak:did_core:webvh:z6Mkroute",
            "service_kind": "principal_server",
            "handover_id": "h-1",
            "basis_record_sequence": 3,
            "basis_record_digest": "sha256:aa",
            "candidate_base_url": "https://new.example/",
            "candidate_record_url": "https://new.example/_arkret/open/services/x/resolution",
            "not_before": "2026-08-19T01:00:00Z",
            "cutover_at": "2026-08-19T02:00:00Z",
            "grace_until": "2026-08-19T06:00:00Z",
            "expires_at": "2026-08-19T12:00:00Z",
            "lifecycle_state": "publishing",
            "active_notice_revision": 0,
            "active_notice_digest": "sha256:bb",
            "created_at": "2026-08-19T00:00:00Z",
            "updated_at": "2026-08-19T00:00:00Z",
            "revisions": [{
                "notice_revision": 0,
                "notice_digest": "sha256:bb",
                "state": "scheduled",
                "issued_at": "2026-08-19T00:00:00Z",
                "expires_at": "2026-08-19T12:00:00Z"
            }],
            "revisions_truncated": false,
            "observed_at": "2026-08-19T00:00:00Z"
        });
        let detail: AdminServiceRouteHandoverDetail =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(detail.plan.basis_record_sequence, 3);
        assert_eq!(detail.revisions.len(), 1);
        assert!(detail.revisions[0].previous_notice_digest.is_none());
        assert_eq!(serde_json::to_value(&detail).unwrap(), value);
    }
}
