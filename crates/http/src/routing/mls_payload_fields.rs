//! Canonical field readers for the MLS event payloads.
//!
//! Every accessor here names exactly one field, taken from
//! `spec/v1/artifacts/schemas/event-payload.schema.json`. All three MLS payload
//! shapes are `additionalProperties:false`, so no legacy spelling can reach an
//! accepted payload and no reader may carry a fallback:
//!
//! | operation kind    | `$defs`                | group carrier  | binding carrier       |
//! | ----------------- | ---------------------- | -------------- | --------------------- |
//! | `ak.mls.genesis`  | `mls_genesis_payload`  | `mls_group_id` | `governance_binding`  |
//! | `ak.mls.commit`   | `mls_commit_payload`   | `mls_group_id` | `governance_binding`  |
//! | `ak.mls.welcome`  | `mls_welcome_payload`  | `mls_group_id` | `governance_binding`  |
//!
//! `group_id` is a canonical property name in `encrypted-envelope.schema.json`
//! only; it is never an MLS event payload field. `mls_governance_binding` is
//! not a field name anywhere in the spec — it appears solely as the profile id
//! `ak.profile.mls_governance_binding.full.v1` and in reason codes such as
//! `mls_governance_binding_stale`.

use serde_json::Value;

/// `mls_genesis_payload` / `mls_commit_payload` / `mls_welcome_payload` all
/// require `mls_group_id`.
pub(crate) fn mls_group_id(payload: &Value) -> Option<&str> {
    payload
        .get("mls_group_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

/// The `mls_governance_binding` object all three MLS payloads require under
/// the name `governance_binding`.
pub(crate) fn governance_binding(value: &Value) -> Option<&Value> {
    value.get("governance_binding")
}

/// `mls_commit_payload.base_epoch` — the epoch the commit builds on. The
/// accepted commit therefore established `base_epoch + 1`.
pub(crate) fn commit_base_epoch(payload: &Value) -> Option<u64> {
    payload.get("base_epoch").and_then(Value::as_u64)
}

/// `mls_welcome_payload.recipient_principal_id` — the principal the Welcome is
/// addressed to.
pub(crate) fn welcome_recipient_principal_id(payload: &Value) -> Option<&str> {
    payload
        .get("recipient_principal_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The scope an accepted genesis / commit event pins the group to.
///
/// `mls_genesis_payload` carries `effective_scope` at the payload root;
/// `mls_commit_payload` has no root scope and carries it inside
/// `governance_binding.effective_scope`. Both are canonical, so this is a
/// per-kind union, not an alias chain.
pub(crate) fn group_state_effective_scope(payload: &Value) -> Option<Value> {
    payload.get("effective_scope").cloned().or_else(|| {
        governance_binding(payload)
            .and_then(|binding| binding.get("effective_scope"))
            .cloned()
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn mls_group_id_reads_only_the_canonical_field() {
        assert_eq!(
            mls_group_id(&json!({"mls_group_id": "mls-group-g1"})),
            Some("mls-group-g1")
        );
        // `group_id` belongs to `encrypted-envelope.schema.json`, never to an
        // MLS event payload.
        assert_eq!(mls_group_id(&json!({"group_id": "mls-group-g1"})), None);
    }

    #[test]
    fn governance_binding_reads_only_the_canonical_field() {
        let canonical = json!({"governance_binding": {"mls_group_id": "mls-group-g1"}});
        assert_eq!(
            governance_binding(&canonical).and_then(|b| b.get("mls_group_id")),
            Some(&json!("mls-group-g1"))
        );
        let legacy = json!({"mls_governance_binding": {"mls_group_id": "mls-group-g1"}});
        assert!(governance_binding(&legacy).is_none());
    }

    #[test]
    fn commit_base_epoch_reads_only_the_canonical_field() {
        assert_eq!(commit_base_epoch(&json!({"base_epoch": 7})), Some(7));
        assert_eq!(commit_base_epoch(&json!({"expected_prev_epoch": 7})), None);
    }

    #[test]
    fn welcome_recipient_reads_only_the_canonical_field() {
        assert_eq!(
            welcome_recipient_principal_id(
                &json!({"recipient_principal_id": "ak:did_core:web:bob.example"})
            ),
            Some("ak:did_core:web:bob.example")
        );
        assert_eq!(
            welcome_recipient_principal_id(
                &json!({"recipient_actor_id": "ak:did_core:web:bob.example"})
            ),
            None
        );
    }

    #[test]
    fn group_state_effective_scope_covers_both_canonical_carriers() {
        let genesis = json!({"effective_scope": {"kind": "realm", "realm_id": "ak:realm:r"}});
        assert_eq!(
            group_state_effective_scope(&genesis),
            Some(json!({"kind": "realm", "realm_id": "ak:realm:r"}))
        );
        let commit = json!({
            "governance_binding": {
                "effective_scope": {"kind": "realm", "realm_id": "ak:realm:r"}
            }
        });
        assert_eq!(
            group_state_effective_scope(&commit),
            Some(json!({"kind": "realm", "realm_id": "ak:realm:r"}))
        );
        let legacy = json!({
            "mls_governance_binding": {
                "effective_scope": {"kind": "realm", "realm_id": "ak:realm:r"}
            }
        });
        assert!(group_state_effective_scope(&legacy).is_none());
    }
}
