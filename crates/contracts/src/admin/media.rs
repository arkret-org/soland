//! Media aggregation and Realm `media_service` admin projections.
//!
//! Shared by the soland producer
//! (`soland/crates/http/src/routing/admin/media.rs`) and the sodmin
//! operator console, so a field rename breaks both sides at compile time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Blob count and byte total for one grouping key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaBucket {
    pub count: u64,
    pub total_size: u64,
}

/// Per-uploader media roll-up row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaByActorRow {
    pub actor_id: String,
    pub display_name: Option<String>,
    pub blob_count: u64,
    pub total_size: u64,
}

/// `GET /_soland/admin/media/statistics` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaStatistics {
    pub total_blobs: u64,
    pub total_size: u64,
    pub encrypted_count: u64,
    /// Always `0` today: soland has no quarantine store for blobs, so the
    /// counter is reported rather than invented.
    pub quarantined_count: u64,
    pub by_media_type: BTreeMap<String, AdminMediaBucket>,
    pub by_realm: BTreeMap<String, AdminMediaBucket>,
    pub by_actor: Vec<AdminMediaByActorRow>,
}

/// `GET /_soland/admin/media/by-actor` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaByActorList {
    pub data: Vec<AdminMediaByActorRow>,
    pub total: usize,
    pub next_cursor: Option<String>,
}

/// One focus in a Realm's `media_service.foci[]` set. Each focus binds a
/// single SFU backend the Realm advertises to clients
/// (`media-service-binding.md` §2).
///
/// Only `focus_id` and `type` are required here. The spec marks
/// `token_endpoint` and `connect_url` normative, but the reducer accepts —
/// and soland's own media token issuer reads — descriptors that carry
/// provider-specific issuance fields instead
/// (`crates/http/src/routing/interop/webrtc.rs::MediaFocusDescriptor`).
/// This is a read-only operator view: a Realm whose descriptors diverge from
/// the spec must still be *visible* in the console, otherwise the one screen
/// that would reveal the misconfiguration is the screen that fails. Unknown
/// keys are likewise tolerated because provider bindings may add fields the
/// console does not render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminMediaServiceFocus {
    pub focus_id: String,
    /// SFU backend kind, e.g. `livekit` / `mediasoup` / `janus` /
    /// `arkret_native` / `moq_relay`.
    #[serde(rename = "type")]
    pub focus_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Token exchange endpoint (`media-service-binding.md` §3). `None` marks
    /// a descriptor the console must render as incomplete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_url: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cascade_group: Option<String>,
}

/// Effective `ak.component.realm.media_service.v1` cell for a Realm,
/// surfaced read-only. `foci` is reducer-projected; nothing here is
/// operator-mutable, so the console renders it without an edit affordance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminRealmMediaService {
    /// Realm identifier (security boundary).
    pub realm_id: String,
    /// Media service DID the foci are sealed to; absent until the Realm
    /// commits a media_service epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub foci: Vec<AdminMediaServiceFocus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_requires_its_identity_fields() {
        for missing in ["focus_id", "type"] {
            let mut value = serde_json::json!({
                "focus_id": "fra-1",
                "type": "livekit",
                "token_endpoint": "https://media.example/_arkret/self/rtc/token",
                "connect_url": "wss://media.example"
            });
            value
                .as_object_mut()
                .expect("focus fixture is an object")
                .remove(missing);
            assert!(
                serde_json::from_value::<AdminMediaServiceFocus>(value).is_err(),
                "missing {missing} must fail closed"
            );
        }
    }

    #[test]
    fn optional_focus_metadata_may_be_absent() {
        let focus: AdminMediaServiceFocus = serde_json::from_value(serde_json::json!({
            "focus_id": "fra-1",
            "type": "livekit",
            "token_endpoint": "https://media.example/_arkret/self/rtc/token",
            "connect_url": "wss://media.example"
        }))
        .expect("optional focus metadata may be absent");
        assert!(focus.capabilities.is_empty());
        assert!(focus.region.is_none());
    }

    /// The descriptors soland actually stores today carry provider issuance
    /// fields and omit `token_endpoint`. The operator view must render them.
    #[test]
    fn provider_specific_descriptor_still_renders() {
        let focus: AdminMediaServiceFocus = serde_json::from_value(serde_json::json!({
            "focus_id": "ak:focus:livekit:green",
            "type": "livekit",
            "connect_url": "wss://media.example/livekit",
            "issuer_kid": "did:web:media.example#livekit-2026-05",
            "audience": "livekit-demo",
            "ttl_seconds": 300
        }))
        .expect("provider descriptors must stay visible to the operator");
        assert_eq!(focus.focus_id, "ak:focus:livekit:green");
        assert!(focus.token_endpoint.is_none());
    }

    #[test]
    fn media_service_without_epoch_serializes_sparsely() {
        let wire = serde_json::to_value(AdminRealmMediaService {
            realm_id: "ak:realm:1".to_owned(),
            service_id: None,
            foci: Vec::new(),
        })
        .expect("serialize");
        assert_eq!(wire, serde_json::json!({ "realm_id": "ak:realm:1" }));
    }
}
