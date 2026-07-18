//! Effective mention-routing policy for Realm notifications.

use arkret_sdk::{MentionRoutingHint, effective_mention_routing_hint};

use crate::state::AppState;

/// Resolve the effective mention-routing hint from projected Realm metadata.
/// Missing metadata and unknown declarations fail closed to `disabled`.
pub(crate) async fn effective_realm_mention_routing_hint(
    state: &AppState,
    realm_id: &str,
    declared_hint: Option<&str>,
) -> MentionRoutingHint {
    let Some(record) = state.realm_meta_store().get(realm_id).await.ok().flatten() else {
        return MentionRoutingHint::Disabled;
    };
    let mut profiles = Vec::new();
    if let Some(profile) = record.encryption_profile {
        profiles.push(profile);
    }
    if record.minimal_metadata_realm {
        profiles.push(arkret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE.to_owned());
    }
    effective_mention_routing_hint(&profiles, declared_hint)
}
