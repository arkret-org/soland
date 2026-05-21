//! G3.S2 — `cx.realm.policy_server` reducer.
//!
//! Projects the per-Realm `cx.realm.policy_server` declaration into:
//!
//! 1. the canonical `cx.component.realm.policy_server.v1` cas-register
//!    cell (per SDK `lattice_registry::RealmPolicyServer`); and
//! 2. the structured side-band cache
//!    [`crate::reducer::ProjectionState::realm_policy_servers`].
//!
//! Org-level fallback (when a child Realm has no declaration of its
//! own) is resolved at *query time* in
//! [`crate::reducer::ProjectionState::realm_policy_server_config`] by
//! walking the `governed_by` link chain — there's no projection
//! mirror; the resolver just walks one link per hop until a configured
//! Realm appears or the chain runs out.
//!
//! Spec: `contrix-spec/spec/v1/zh/authz/policy-server.md` §2.

use contrix_sdk::lattice::CellState;
use contrix_sdk::{CellRef, Operation};
use serde_json::Value;

use crate::reducer::{ProjectionEffect, ProjectionState, RealmPolicyServerConfig};

/// Default `cache_ttl_seconds` per spec §2 (300).
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;
/// Default `timeout_ms` — matches coauth's own `/policy/check` outer
/// deadline so the soland-side outbound timeout doesn't fire spuriously
/// against a healthy upstream that's just slightly behind its own 2 s
/// inner budget.
const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// Default `on_timeout` — `fail_closed` aligns with spec §6 default
/// for any Realm that does not opt-out.
const DEFAULT_ON_TIMEOUT: &str = "fail_closed";

/// Apply a `cx.realm.policy_server` event to projection state.
///
/// Payload schema (subset enforced here):
/// ```json
/// {
///   "policy_server_did": "did:web:policy.example.com",
///   "policy_server_url": "https://policy.example.com/api/v1/policy/check",
///   "cache_ttl_seconds": 300,
///   "timeout_ms": 2000,
///   "on_timeout": "fail_closed"
/// }
/// ```
///
/// Older / longer-form payloads using `server_id` / `endpoint` (from
/// `policy-server.md` §2 declaration) are accepted as aliases so
/// administrators can submit either shape without a parallel
/// translation in admin tooling.
pub fn apply_realm_policy_server(
    state: &mut ProjectionState,
    operation: &Operation,
) -> ProjectionEffect {
    let realm_id = operation.space_id.to_string();
    let payload = &operation.payload;

    let Some(policy_server_did) = payload
        .get("policy_server_did")
        .or_else(|| payload.get("server_id"))
        .and_then(Value::as_str)
    else {
        return ProjectionEffect::Rejected {
            reason: "policy_server_did_missing".to_owned(),
        };
    };
    if policy_server_did.is_empty() {
        return ProjectionEffect::Rejected {
            reason: "policy_server_did_empty".to_owned(),
        };
    }

    let Some(policy_server_url) = payload
        .get("policy_server_url")
        .or_else(|| payload.get("endpoint"))
        .and_then(Value::as_str)
    else {
        return ProjectionEffect::Rejected {
            reason: "policy_server_url_missing".to_owned(),
        };
    };
    if !(policy_server_url.starts_with("http://") || policy_server_url.starts_with("https://")) {
        return ProjectionEffect::Rejected {
            reason: "policy_server_url_invalid_scheme".to_owned(),
        };
    }

    let cache_ttl_seconds = payload
        .get("cache_ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_CACHE_TTL_SECONDS);
    let timeout_ms = payload
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    if timeout_ms == 0 {
        return ProjectionEffect::Rejected {
            reason: "policy_server_timeout_ms_zero".to_owned(),
        };
    }
    let on_timeout = payload
        .get("on_timeout")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_ON_TIMEOUT);
    if !matches!(on_timeout, "fail_closed" | "deny") {
        return ProjectionEffect::Rejected {
            reason: "policy_server_on_timeout_invalid".to_owned(),
        };
    }

    let now = operation.created_at;

    // Cell write — `cx.component.realm.policy_server.v1` (cas-register,
    // keyed by realm_id per SDK lattice_registry).
    if let Ok(cell_id) = CellRef::new(format!(
        "cx:cell:cx.component.realm.policy_server.v1:{realm_id}"
    )) {
        let value = serde_json::json!({
            "realm_id": realm_id,
            "policy_server_did": policy_server_did,
            "policy_server_url": policy_server_url,
            "cache_ttl_seconds": cache_ttl_seconds,
            "timeout_ms": timeout_ms,
            "on_timeout": on_timeout,
            "updated_at": now.to_rfc3339(),
        });
        state.cells.insert(cell_id, CellState::Value(value));
    }

    state.realm_policy_servers.insert(
        realm_id.clone(),
        RealmPolicyServerConfig {
            realm_id: realm_id.clone(),
            policy_server_did: policy_server_did.to_owned(),
            policy_server_url: policy_server_url.to_owned(),
            cache_ttl_seconds,
            timeout_ms,
            on_timeout: on_timeout.to_owned(),
            updated_at: now,
        },
    );

    ProjectionEffect::RealmPolicyServerProjected {
        realm_id,
        policy_server_did: policy_server_did.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reducer::RealmLinkState;
    use contrix_sdk::{Operation, OperationId, SpaceId};
    use serde_json::json;

    const REALM_CHILD: &str = "cx:space:01904100-0000-7000-8000-cccccccccccc";
    const REALM_ORG: &str = "cx:space:01904100-0000-7000-8000-000000000000";

    fn op(space_id: &str, payload: Value) -> Operation {
        Operation::create(
            OperationId::new(format!("cx:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            SpaceId::new(space_id).unwrap(),
            crate::kinds::CX_REALM_POLICY_SERVER,
            payload,
        )
    }

    #[test]
    fn apply_writes_config() {
        let mut state = ProjectionState::new();
        let effect = apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_did": "did:web:policy.example.com",
                    "policy_server_url": "https://policy.example.com/api/v1/policy/check",
                    "cache_ttl_seconds": 60,
                    "timeout_ms": 1500,
                    "on_timeout": "fail_closed",
                }),
            ),
        );
        match effect {
            ProjectionEffect::RealmPolicyServerProjected {
                realm_id,
                policy_server_did,
            } => {
                assert_eq!(realm_id, REALM_CHILD);
                assert_eq!(policy_server_did, "did:web:policy.example.com");
            }
            other => panic!("expected RealmPolicyServerProjected, got {other:?}"),
        }

        let cfg = state
            .realm_policy_server_config(REALM_CHILD)
            .expect("cached");
        assert_eq!(cfg.policy_server_did, "did:web:policy.example.com");
        assert_eq!(cfg.cache_ttl_seconds, 60);
        assert_eq!(cfg.timeout_ms, 1500);
        assert_eq!(cfg.on_timeout, "fail_closed");

        // Cell projection.
        let cell_id = CellRef::new(format!(
            "cx:cell:cx.component.realm.policy_server.v1:{REALM_CHILD}"
        ))
        .unwrap();
        let value = state.cell_value(&cell_id).expect("cell present");
        assert_eq!(
            value.get("policy_server_did").and_then(Value::as_str),
            Some("did:web:policy.example.com")
        );
    }

    #[test]
    fn apply_org_fallback_when_realm_has_none() {
        let mut state = ProjectionState::new();
        // Write a policy server on the ORG realm only.
        apply_realm_policy_server(
            &mut state,
            &op(
                REALM_ORG,
                json!({
                    "policy_server_did": "did:web:org.example.com",
                    "policy_server_url": "https://org.example.com/api/v1/policy/check",
                }),
            ),
        );
        // Wire a `governed_by` link from CHILD → ORG so the
        // org-fallback walker can resolve it.
        let now = chrono::Utc::now();
        state
            .realm_links
            .entry(REALM_CHILD.to_owned())
            .or_default()
            .push(RealmLinkState {
                realm_id: REALM_CHILD.to_owned(),
                target_realm_id: REALM_ORG.to_owned(),
                link_kind: "governed_by".to_owned(),
                status: "active".to_owned(),
                label: None,
                commitment: None,
                created_at: now,
                updated_at: now,
            });

        // CHILD has no row of its own, but the resolver should walk the
        // `governed_by` link and find ORG's policy server.
        let cfg = state
            .realm_policy_server_config(REALM_CHILD)
            .expect("org-fallback config");
        assert_eq!(cfg.realm_id, REALM_ORG);
        assert_eq!(cfg.policy_server_did, "did:web:org.example.com");
    }

    #[test]
    fn apply_invalid_payload_rejected() {
        let mut state = ProjectionState::new();
        // Missing both server_did and url.
        match apply_realm_policy_server(&mut state, &op(REALM_CHILD, json!({}))) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_did_missing");
            }
            other => panic!("expected Rejected(policy_server_did_missing), got {other:?}"),
        }
        // Missing URL but DID present.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({"policy_server_did": "did:web:p.example"}),
            ),
        ) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_url_missing");
            }
            other => panic!("expected Rejected(policy_server_url_missing), got {other:?}"),
        }
        // Bad scheme.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_did": "did:web:p.example",
                    "policy_server_url": "ftp://nope.example",
                }),
            ),
        ) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_url_invalid_scheme");
            }
            other => panic!("expected Rejected(policy_server_url_invalid_scheme), got {other:?}"),
        }
        // `on_timeout` outside the {fail_closed, deny} set.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_did": "did:web:p.example",
                    "policy_server_url": "https://p.example/policy/check",
                    "on_timeout": "soft_pass",
                }),
            ),
        ) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_on_timeout_invalid");
            }
            other => panic!("expected Rejected(policy_server_on_timeout_invalid), got {other:?}"),
        }
        // Zero timeout.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_did": "did:web:p.example",
                    "policy_server_url": "https://p.example/policy/check",
                    "timeout_ms": 0,
                }),
            ),
        ) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_timeout_ms_zero");
            }
            other => panic!("expected Rejected(policy_server_timeout_ms_zero), got {other:?}"),
        }
    }
}
