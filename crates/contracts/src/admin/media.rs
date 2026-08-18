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
/// The field set is exactly the one `event-payload.schema.json`
/// `$defs/media_service_focus` declares, and `token_endpoint` / `connect_url`
/// are required because the spec makes them normative. This mirror used to
/// relax both to `Option` and stay open to unknown keys, because soland stored
/// provider issuance fields here instead; that divergence is closed — issuance
/// configuration is deployment configuration, not Realm state — so the mirror
/// no longer needs to tolerate it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminMediaServiceFocus {
    pub focus_id: String,
    /// SFU backend kind, e.g. `livekit` / `mediasoup` / `janus` /
    /// `arkret_native` / `moq_relay`.
    pub focus_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Token exchange endpoint (`media-service-binding.md` §3).
    pub token_endpoint: String,
    pub connect_url: String,
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
        for missing in ["focus_id", "focus_kind", "token_endpoint", "connect_url"] {
            let mut value = serde_json::json!({
                "focus_id": "fra-1",
                "focus_kind": "livekit",
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
            "focus_kind": "livekit",
            "token_endpoint": "https://media.example/_arkret/self/rtc/token",
            "connect_url": "wss://media.example"
        }))
        .expect("optional focus metadata may be absent");
        assert!(focus.capabilities.is_empty());
        assert!(focus.region.is_none());
    }

    /// Provider issuance configuration is deployment configuration, not a
    /// Realm cell field. A descriptor carrying it is malformed rather than a
    /// variant the console has to render.
    #[test]
    fn provider_issuance_fields_are_rejected() {
        assert!(
            serde_json::from_value::<AdminMediaServiceFocus>(serde_json::json!({
                "focus_id": "livekit_green",
                "focus_kind": "livekit",
                "token_endpoint": "https://media.example/_arkret/self/rtc/token",
                "connect_url": "wss://media.example/livekit",
                "issuer_kid": "did:webvh:z6mkfixture:media.example#livekit-2026-05",
                "audience": "livekit-demo",
                "ttl_seconds": 300
            }))
            .is_err()
        );
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
