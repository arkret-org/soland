//! identity_link cache policy-frontier digest + invalidation triggers.
//!
//! Spec T13 (cokret-spec round 2+3 cleanup, 8b7978d): an identity_link
//! routing-cache entry is keyed by a four-field policy frontier digest;
//! a tightening change to any of the four governance inputs MUST eagerly
//! invalidate the cached decision.
//!
//! Spec reference surface — these helpers are exercised by the conformance
//! suite and out-of-tree signers; not all are wired into a soland route yet.
#![allow(dead_code)]

use cokret_sdk::compute_policy_frontier_digest;
use serde_json::Value;

/// Spec T13 — compute the four-field policy frontier hash for an
/// identity_link cache entry via SDK.
pub fn identity_link_policy_frontier_digest(
    disclosure_policy: &Value,
    history_visibility: &Value,
    identity_disclosure_profile: &Value,
    minimal_metadata_mode: &Value,
) -> [u8; 32] {
    compute_policy_frontier_digest(
        disclosure_policy,
        history_visibility,
        identity_disclosure_profile,
        minimal_metadata_mode,
    )
    .unwrap_or([0u8; 32])
}

/// Spec T13 — five governance-input change classifications that MUST
/// eagerly invalidate cached identity_link routing decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityLinkInvalidationTrigger {
    DisclosurePolicyStricter,
    MinimalMetadataStricter,
    HistoryVisibilityTighter,
    IdentityDisclosureProfileChange,
    LinkedRealmTighter,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn identity_link_policy_frontier_digest_is_deterministic() {
        let a = identity_link_policy_frontier_digest(
            &json!({"mode": "strict"}),
            &json!("members_only"),
            &json!({"profile": "default"}),
            &json!(false),
        );
        let b = identity_link_policy_frontier_digest(
            &json!({"mode": "strict"}),
            &json!("members_only"),
            &json!({"profile": "default"}),
            &json!(false),
        );
        assert_eq!(a, b);
    }
}
