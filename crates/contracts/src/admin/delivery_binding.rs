//! Shared DTOs for Soland's delivery-binding admin surface.
//!
//! Soland produces these deployment-local views and Sodmin consumes them.
//! They are product contracts, not Arkret protocol wire types.

use arkret_wire::ErrorCode;
use serde::{Deserialize, Serialize};

/// Effective `ak.component.realm.delivery_binding_policy.v1` for a Realm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RealmDeliveryBindingPolicy {
    /// Realm identifier (security boundary).
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_recipient_services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_source_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_frontier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// One row in the per-Realm member-routability table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MemberRoutabilityRow {
    pub actor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_id: Option<String>,
    pub in_allowed_list: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<String>,
}

/// One row in the delivery-binding handover audit panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeliveryBindingHandoverRow {
    pub realm_id: String,
    pub actor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_recipient_service_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_recipient_service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handover_frontier: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

impl DeliveryBindingHandoverRow {
    pub fn classified_reason(&self) -> Option<ErrorCode> {
        self.reason_code
            .as_deref()
            .and_then(ErrorCode::from_wire)
            .filter(|reason| {
                matches!(
                    *reason,
                    ErrorCode::DeliveryBindingStale
                        | ErrorCode::DeliveryBindingHandedOver
                        | ErrorCode::HistoricalOnly
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_boundary_identifiers_fail_closed() {
        assert!(
            serde_json::from_value::<RealmDeliveryBindingPolicy>(
                serde_json::json!({"allowed_recipient_services": []})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<MemberRoutabilityRow>(
                serde_json::json!({"in_allowed_list": false})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeliveryBindingHandoverRow>(
                serde_json::json!({"realm_id": "ak:realm:test"})
            )
            .is_err()
        );
    }

    #[test]
    fn sparse_optional_fields_remain_compatible() {
        let policy: RealmDeliveryBindingPolicy =
            serde_json::from_value(serde_json::json!({"realm_id": "ak:realm:test"}))
                .expect("optional policy fields may be absent");
        assert!(policy.allowed_recipient_services.is_empty());

        let handover: DeliveryBindingHandoverRow = serde_json::from_value(serde_json::json!({
            "realm_id": "ak:realm:test",
            "actor_id": "did:web:example.test"
        }))
        .expect("optional handover fields may be absent");
        assert!(handover.handover_frontier.is_empty());
    }
}
