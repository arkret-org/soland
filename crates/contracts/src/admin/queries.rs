//! Production admin query projections (D14).
//!
//! Frozen wire contract for the operator-facing read endpoints served by a
//! principal server under `/_soland/admin/{actors,audit,capabilities,devices}`
//! (deployment-local `/admin/*` namespace, no `/_arkret/` protocol prefix).
//! These replace the dev-only `admin/{resource}` snapshot collection for the
//! four resources sodmin manages.
//!
//! Contract rules (D14-001):
//!
//! - Every list envelope carries `{ <rows>, total, next_cursor, has_more, filters }`. `filters`
//!   echoes exactly the server-applied filter set so a client can detect ignored parameters.
//!   `next_cursor` is the last row id of the page — opaque to clients, resumable server-side by id
//!   lookup. A cursor that no longer resolves is rejected with `cursor-expired` (410); a malformed
//!   cursor with `invalid-param` (400).
//! - All types are `deny_unknown_fields`: unknown wire fields fail closed instead of being silently
//!   dropped, so producer/consumer drift is caught at the boundary.
//! - Security-relevant fields (`status`, `is_admin`, `deactivation_federation_incomplete`) are
//!   `Option`: `None` means the server could not answer authoritatively — never a defaulted
//!   `false`.
//! - Closed-set enums reuse the canonical registries (e.g. [`AccountStatus`]); unknown wire values
//!   fail deserialization.

use std::collections::BTreeMap;

use arkret_core::{AccountStatus, Did, GrantConstraint};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One actor row in the admin actors projection.
///
/// Sourced from the account store joined with the lifecycle registry and the
/// admin-principal configuration. `id` is the canonical actor id (the DID
/// string) and is always present.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminActor {
    /// Canonical actor id (the DID string).
    pub id: String,
    pub did: Did,
    /// Durable surrogate account row id (`ak:account:<uuid7>`), stable across
    /// DID rotation. Account-lifecycle admin endpoints address accounts by
    /// DID, not by this id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Account lifecycle status. `None` = the lifecycle registry could not
    /// answer for this DID (never a defaulted `Active`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AccountStatus>,
    /// Whether the DID is listed as an admin principal. `None` = the
    /// authorization source was unavailable (never a defaulted `false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_admin: Option<bool>,
    /// `Some(true)` when the account is deactivated locally but at least one
    /// federated peer has not confirmed the deactivation. `None` when the
    /// account is not deactivated or the fanout state is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivation_federation_incomplete: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    /// Last activity timestamp. `None` = not tracked by this deployment.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub last_active_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_count: Option<u64>,
}

/// Cursor-paginated admin actors page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminActorList {
    #[serde(default)]
    pub actors: Vec<AdminActor>,
    /// Total rows matching the applied filters (pre-pagination).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    /// Echo of the server-applied filters (`filter[...]` → value).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filters: BTreeMap<String, String>,
}

/// One audit-log row in the admin audit projection.
///
/// Mirrors the durable audit record exactly: `target_type` / `target_id` /
/// `source_ip` / `effective_scope` are intentionally absent — the store does
/// not persist them as top-level columns, and this contract does not invent
/// them. Action-specific detail lives in `payload`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminAuditEntry {
    /// Audit record id (`audit_id`).
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Action-specific structured detail (AKP-0008 `executed_by` /
    /// `authorization_ref` / `actor_kind` live here when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
}

/// Cursor-paginated admin audit page (newest first).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminAuditList {
    #[serde(default)]
    pub entries: Vec<AdminAuditEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filters: BTreeMap<String, String>,
}

/// Lifecycle visibility selector for capability grants.
///
/// Closed set; unknown wire values fail deserialization (this gates what an
/// operator sees, so it must not degrade silently).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CapabilityGrantState {
    Active,
    Revoked,
    All,
}

impl CapabilityGrantState {
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityGrantState::Active => "active",
            CapabilityGrantState::Revoked => "revoked",
            CapabilityGrantState::All => "all",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "active" => Some(CapabilityGrantState::Active),
            "revoked" => Some(CapabilityGrantState::Revoked),
            "all" => Some(CapabilityGrantState::All),
            _ => None,
        }
    }
}

/// One capability grant row in the admin capabilities projection.
///
/// Flat summary of the authz read-index `Grant` (the projection of
/// `ak.component.capability.grant.v1` cells).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CapabilitySummary {
    pub grant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    pub issuer: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    pub revoked: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    /// Parent grant id when issued via re-delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_from: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Cursor-paginated admin capabilities page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminCapabilityList {
    #[serde(default)]
    pub capabilities: Vec<CapabilitySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filters: BTreeMap<String, String>,
}

/// One device row in the non-protocol product-admin projection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminDevice {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Cursor-paginated product-admin devices page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminDeviceList {
    #[serde(default)]
    pub devices: Vec<AdminDevice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filters: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_actor_unknown_field_fails_closed() {
        let wire = serde_json::json!({
            "id": "did:web:alice.example",
            "did": "did:web:alice.example",
            "surprise": true,
        });
        assert!(serde_json::from_value::<AdminActor>(wire).is_err());
    }

    #[test]
    fn admin_actor_security_fields_default_to_unknown_not_false() {
        let wire = serde_json::json!({
            "id": "did:web:alice.example",
            "did": "did:web:alice.example",
        });
        let actor: AdminActor = serde_json::from_value(wire).expect("minimal row parses");
        assert_eq!(actor.status, None);
        assert_eq!(actor.is_admin, None);
        assert_eq!(actor.deactivation_federation_incomplete, None);
        assert_eq!(actor.device_count, None);
    }

    #[test]
    fn admin_actor_status_is_closed_set() {
        let wire = serde_json::json!({
            "id": "did:web:alice.example",
            "did": "did:web:alice.example",
            "status": "very_active",
        });
        assert!(serde_json::from_value::<AdminActor>(wire).is_err());
    }

    #[test]
    fn audit_list_round_trips_and_skips_empty_filters() {
        let list = AdminAuditList {
            entries: vec![AdminAuditEntry {
                id: "audit-1".to_owned(),
                request_id: Some("req-1".to_owned()),
                action: "admin.actors.query".to_owned(),
                actor_id: Some("did:web:op.example".to_owned()),
                device_id: None,
                realm_id: None,
                operation_id: None,
                outcome: Some("accepted".to_owned()),
                payload: None,
                created_at: None,
            }],
            total: Some(1),
            next_cursor: None,
            has_more: false,
            filters: BTreeMap::new(),
        };
        let wire = serde_json::to_value(&list).expect("serialize");
        assert!(wire.get("filters").is_none(), "empty filters echo omitted");
        let back: AdminAuditList = serde_json::from_value(wire).expect("round trip");
        assert_eq!(back, list);
    }

    #[test]
    fn capability_grant_state_rejects_unknown_wire_value() {
        assert!(
            serde_json::from_value::<CapabilityGrantState>(serde_json::json!("paused")).is_err()
        );
        assert_eq!(
            CapabilityGrantState::from_wire("all"),
            Some(CapabilityGrantState::All)
        );
    }

    #[test]
    fn capability_summary_round_trip() {
        let wire = serde_json::json!({
            "grant_id": "ak:grant:01904100-0000-7000-8000-000000000abc",
            "realm_id": "ak:realm:01904100-0000-7000-8000-0000000000aa",
            "issuer": "did:web:owner.example",
            "subject": "did:web:member.example",
            "resource": "realm",
            "actions": ["ak.realm.read"],
            "revoked": false,
            "created_at": "2026-07-10T00:00:00.000Z",
        });
        let summary: CapabilitySummary = serde_json::from_value(wire).expect("parses");
        assert_eq!(summary.actions, vec!["ak.realm.read".to_owned()]);
        assert!(!summary.revoked);
        assert!(summary.delegated_from.is_none());
    }
}
