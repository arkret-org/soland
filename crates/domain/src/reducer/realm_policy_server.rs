//! G3.S2 — `ak.realm.policy_server` reducer.
//!
//! Projects the per-Realm `ak.realm.policy_server` declaration into:
//!
//! 1. the canonical `ak.component.realm.policy_server.v1` cas-register cell (per SDK
//!    `lattice_registry::RealmPolicyServer`); and
//! 2. the structured side-band cache [`crate::reducer::ProjectionState::realm_policy_servers`].
//!
//! Org-level fallback (when a child Realm has no declaration of its
//! own) is resolved at *query time* in
//! [`crate::reducer::ProjectionState::realm_policy_server_config`] by
//! walking the `governed_by` link chain — there's no projection
//! mirror; the resolver just walks one link per hop until a configured
//! Realm appears or the chain runs out.
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §2.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::governance::realm_governance::{
    RealmPolicyServerOnTimeout, RealmPolicyServerPayload,
};
use arkret_state::lattice::CellState;
use serde_json::Value;
use url::Url;

use crate::reducer::{
    ProjectionEffect, ProjectionState, RealmPolicyServerConfig, RealmPolicyServerHead,
};

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

const POLICY_SERVER_CELL_ID: &str = "ak:cell:ak.component.realm.policy_server.v1:null";

/// The canonical cell value a raw policy-server payload denotes.
///
/// The reducer sees the same accepted Move more than once (admission
/// projection, then Seal apply / cell reload) and the two paths attach
/// different projection-context fields. Comparing raw payloads would read a
/// replay as a conflicting sibling, so every head/basis comparison goes
/// through the closed DTO: two payloads denote the same cell value exactly
/// when they parse to the same `RealmPolicyServerPayload`.
fn canonical_policy_server_value(payload: &Value) -> Option<Value> {
    let parsed = serde_json::from_value::<RealmPolicyServerPayload>(payload.clone()).ok()?;
    serde_json::to_value(parsed).ok()
}

/// The frozen basis a `ak.realm.policy_server` Move cites: the `head_eq`
/// expected value of its policy-server cell precondition, or `None` for an
/// initial write against the never-written cell.
fn policy_server_move_basis(preconditions: &[arkret_wire::Precondition]) -> Option<Value> {
    preconditions.iter().find_map(|precondition| {
        if precondition.cell.as_str() != POLICY_SERVER_CELL_ID {
            return None;
        }
        if precondition.predicate.op != arkret_wire::cba::PredicateOp::HeadEq {
            return None;
        }
        precondition
            .predicate
            .value
            .as_ref()
            .and_then(canonical_policy_server_value)
    })
}

enum PolicyServerHeadDecision {
    Advance,
    Idempotent,
    SiblingConflict,
}

fn policy_server_head_decision(
    head: Option<&RealmPolicyServerHead>,
    move_basis: &Option<Value>,
    new_value: &Value,
) -> PolicyServerHeadDecision {
    let Some(head) = head else {
        return PolicyServerHeadDecision::Advance;
    };
    if new_value == &head.value {
        return PolicyServerHeadDecision::Idempotent;
    }
    if move_basis == &head.basis {
        return PolicyServerHeadDecision::SiblingConflict;
    }
    // A basis that names neither the current head nor the head's own basis is
    // stale, but rejecting it here would duplicate — and could disagree with —
    // the authoritative `head_eq` CAS gate in `check_move_preconditions`. The
    // reducer's job on this cell is the one thing that gate cannot express:
    // two accepted Moves on the SAME frozen basis join to bottom.
    PolicyServerHeadDecision::Advance
}

fn join_policy_server_cell_bottom(
    state: &mut ProjectionState,
    realm_id: String,
    operation: &Operation,
    move_basis: Option<Value>,
    new_value: Value,
) -> ProjectionEffect {
    let head = state
        .realm_policy_server_heads
        .get(&realm_id)
        .expect("sibling conflict requires an accepted head");
    let bottom = arkret_wire::Bottom {
        kind: arkret_wire::BottomKind::Conflict,
        cells: vec![
            arkret_identifiers::CellRef::new(POLICY_SERVER_CELL_ID.to_owned())
                .expect("policy-server cell id is a valid CellRef"),
        ],
        move_ids: Vec::new(),
        seal_view: None,
        heads: vec![
            serde_json::json!({
                "move_id": head.operation_id.as_str(),
                "value": head.value,
                "basis": head.basis,
            }),
            serde_json::json!({
                "move_id": operation.operation_id.as_str(),
                "value": new_value,
                "basis": move_basis,
            }),
        ],
        details: Some(arkret_wire::bottom_details([
            (
                "cell_family",
                serde_json::json!(arkret_wire::CellFamilyId::REALM_POLICY_SERVER_V1),
            ),
            (
                "reason",
                serde_json::json!("policy_server_same_basis_sibling_conflict"),
            ),
        ])),
        escalated_at: None,
    };
    state.realm_null_subject_cells.insert(
        (realm_id.clone(), POLICY_SERVER_CELL_ID.to_owned()),
        CellState::Bottom(bottom),
    );
    state.realm_policy_servers.remove(&realm_id);
    ProjectionEffect::RealmPolicyServerConflicted { realm_id }
}

/// Apply a declaration or durable value tombstone to the Realm policy-server cell.
pub fn apply_realm_policy_server(
    state: &mut ProjectionState,
    operation: &Operation,
) -> ProjectionEffect {
    let realm_id = operation.realm_id.to_string();
    let wire_payload = operation.payload.clone();
    let payload = match operation.typed_payload::<arkret_wire::event_spec::RealmPolicyServer>() {
        Ok(payload) => payload,
        Err(_) => {
            return ProjectionEffect::Rejected {
                reason: "policy_server_payload_invalid".to_owned(),
            };
        }
    };
    let cell_id = POLICY_SERVER_CELL_ID.to_owned();
    let cell_key = (realm_id.clone(), cell_id.clone());
    // `⊥` is sticky: once siblings joined to Bottom, later Moves cannot
    // overwrite the conflict short of an explicit conflict-recovery flow.
    if matches!(
        state.realm_null_subject_cells.get(&cell_key),
        Some(CellState::Bottom(_))
    ) {
        return ProjectionEffect::RealmPolicyServerConflicted { realm_id };
    }
    let move_basis = policy_server_move_basis(&operation.context.preconditions);
    let canonical_value = match canonical_policy_server_value(&wire_payload) {
        Some(value) => value,
        None => {
            return ProjectionEffect::Rejected {
                reason: "policy_server_payload_invalid".to_owned(),
            };
        }
    };
    let head_decision = policy_server_head_decision(
        state.realm_policy_server_heads.get(&realm_id),
        &move_basis,
        &canonical_value,
    );
    match head_decision {
        PolicyServerHeadDecision::Advance => {}
        PolicyServerHeadDecision::Idempotent => {
            return match payload {
                RealmPolicyServerPayload::Declaration(payload) => {
                    ProjectionEffect::RealmPolicyServerProjected {
                        realm_id,
                        policy_server_service_id: payload.policy_server_service_id,
                    }
                }
                RealmPolicyServerPayload::Tombstone(_) => {
                    ProjectionEffect::RealmPolicyServerTombstoned { realm_id }
                }
            };
        }
        PolicyServerHeadDecision::SiblingConflict => {
            return join_policy_server_cell_bottom(
                state,
                realm_id,
                operation,
                move_basis,
                canonical_value,
            );
        }
    }

    let payload = match payload {
        RealmPolicyServerPayload::Declaration(payload) => payload,
        RealmPolicyServerPayload::Tombstone(tombstone) => {
            if tombstone.validate().is_err() {
                return ProjectionEffect::Rejected {
                    reason: "policy_server_payload_invalid".to_owned(),
                };
            }
            state.realm_policy_server_heads.insert(
                realm_id.clone(),
                RealmPolicyServerHead {
                    basis: move_basis,
                    operation_id: operation.operation_id.to_string(),
                    value: canonical_value,
                },
            );
            state
                .realm_null_subject_cells
                .insert((realm_id.clone(), cell_id), CellState::Value(wire_payload));
            state.realm_policy_servers.remove(&realm_id);
            return ProjectionEffect::RealmPolicyServerTombstoned { realm_id };
        }
    };
    let policy_server_service_id = payload.policy_server_service_id;

    let policy_server_url = payload.policy_server_url;
    if !policy_server_url.starts_with("https://") {
        return ProjectionEffect::Rejected {
            reason: "policy_server_url_invalid_scheme".to_owned(),
        };
    }
    if let Err(reason) = validate_policy_server_url(&policy_server_url) {
        return ProjectionEffect::Rejected {
            reason: reason.to_owned(),
        };
    }

    let cache_ttl_seconds = payload
        .cache_ttl_seconds
        .unwrap_or(DEFAULT_CACHE_TTL_SECONDS);
    let timeout_ms = payload.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if timeout_ms == 0 {
        return ProjectionEffect::Rejected {
            reason: "policy_server_timeout_ms_zero".to_owned(),
        };
    }
    let on_timeout = match payload.on_timeout {
        Some(RealmPolicyServerOnTimeout::FailClosed) | None => DEFAULT_ON_TIMEOUT,
        Some(RealmPolicyServerOnTimeout::Deny) => "deny",
    };

    let now = operation.created_at;

    state.realm_policy_server_heads.insert(
        realm_id.clone(),
        RealmPolicyServerHead {
            basis: move_basis,
            operation_id: operation.operation_id.to_string(),
            value: canonical_value,
        },
    );
    state
        .realm_null_subject_cells
        .insert((realm_id.clone(), cell_id), CellState::Value(wire_payload));

    state.realm_policy_servers.insert(
        realm_id.clone(),
        RealmPolicyServerConfig {
            realm_id: realm_id.clone(),
            policy_server_service_id: policy_server_service_id.clone(),
            policy_server_url,
            cache_ttl_seconds,
            timeout_ms,
            on_timeout: on_timeout.to_owned(),
            updated_at: now,
        },
    );

    ProjectionEffect::RealmPolicyServerProjected {
        realm_id,
        policy_server_service_id,
    }
}

fn validate_policy_server_url(raw_url: &str) -> Result<(), &'static str> {
    let Ok(url) = Url::parse(raw_url) else {
        return Err("policy_server_url_invalid");
    };
    if url.scheme() != "https" {
        return Err("policy_server_url_invalid_scheme");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("policy_server_url_auth_material_forbidden");
    }
    if url.path() != "/_arkret/self/policy/check" {
        return Err("policy_server_url_invalid_path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::{Value, json};

    use super::*;
    use crate::reducer::RealmLinkState;

    const REALM_CHILD: &str = "ak:realm:Aemw9elq19fDvIg-i7BJI44N3RJHLqzlZ0EYQW_cgutY";
    const REALM_ORG: &str = "ak:realm:AZvKsJv4SbKilJ8M35HH6gwhZE4wsi0ZHaNeeTs-d54E";

    fn op(realm_id: &str, mut payload: Value) -> Operation {
        let preconditions = payload
            .as_object_mut()
            .and_then(|payload| payload.remove("preconditions"))
            .map(serde_json::from_value)
            .transpose()
            .unwrap()
            .unwrap_or_default();
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            RealmId::new(realm_id).unwrap(),
            arkret_wire::EventKind::RealmPolicyServer.as_str(),
            payload,
        );
        operation.context.preconditions = preconditions;
        operation
    }

    #[test]
    fn apply_writes_config() {
        let mut state = ProjectionState::new();
        let effect = apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_service_id": "ak:did_core:web:policy.example.com",
                    "policy_server_url": "https://policy.example.com/_arkret/self/policy/check",
                    "cache_ttl_seconds": 60,
                    "timeout_ms": 1500,
                    "on_timeout": "fail_closed",
                }),
            ),
        );
        match effect {
            ProjectionEffect::RealmPolicyServerProjected {
                realm_id,
                policy_server_service_id,
            } => {
                assert_eq!(realm_id, REALM_CHILD);
                assert_eq!(
                    policy_server_service_id.as_str(),
                    "ak:did_core:web:policy.example.com"
                );
            }
            other => panic!("expected RealmPolicyServerProjected, got {other:?}"),
        }

        let cfg = state
            .try_realm_policy_server_config(REALM_CHILD)
            .expect("resolvable policy-server chain")
            .expect("cached");
        assert_eq!(
            cfg.policy_server_service_id.as_str(),
            "ak:did_core:web:policy.example.com"
        );
        assert_eq!(cfg.cache_ttl_seconds, 60);
        assert_eq!(cfg.timeout_ms, 1500);
        assert_eq!(cfg.on_timeout, "fail_closed");

        // Cell projection.
        let value = state
            .realm_null_subject_cell_value(
                REALM_CHILD,
                arkret_wire::CellFamilyId::REALM_POLICY_SERVER_V1,
            )
            .expect("cell present");
        assert_eq!(
            value
                .get("policy_server_service_id")
                .and_then(Value::as_str),
            Some("ak:did_core:web:policy.example.com")
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
                    "policy_server_service_id": "ak:did_core:web:org.example.com",
                    "policy_server_url": "https://org.example.com/_arkret/self/policy/check",
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
            .try_realm_policy_server_config(REALM_CHILD)
            .expect("resolvable policy-server chain")
            .expect("org-fallback config");
        assert_eq!(cfg.realm_id, REALM_ORG);
        assert_eq!(
            cfg.policy_server_service_id.as_str(),
            "ak:did_core:web:org.example.com"
        );
    }

    #[test]
    fn apply_invalid_payload_rejected() {
        let mut state = ProjectionState::new();
        // Missing both server_did and url.
        match apply_realm_policy_server(&mut state, &op(REALM_CHILD, json!({}))) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_payload_invalid");
            }
            other => panic!("expected Rejected(policy_server_payload_invalid), got {other:?}"),
        }
        // Missing URL but DID present.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({"policy_server_service_id": "ak:did_core:web:p.example"}),
            ),
        ) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_payload_invalid");
            }
            other => panic!("expected Rejected(policy_server_payload_invalid), got {other:?}"),
        }
        // Bad scheme.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_service_id": "ak:did_core:web:p.example",
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
                    "policy_server_service_id": "ak:did_core:web:p.example",
                    "policy_server_url": "https://p.example/_arkret/self/policy/check",
                    "on_timeout": "soft_pass",
                }),
            ),
        ) {
            ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "policy_server_payload_invalid");
            }
            other => panic!("expected Rejected(policy_server_payload_invalid), got {other:?}"),
        }
        // Zero timeout.
        match apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_service_id": "ak:did_core:web:p.example",
                    "policy_server_url": "https://p.example/_arkret/self/policy/check",
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

    #[test]
    fn tombstone_removes_direct_config_and_restores_org_fallback() {
        let mut state = ProjectionState::new();
        apply_realm_policy_server(
            &mut state,
            &op(
                REALM_ORG,
                json!({
                    "policy_server_service_id": "ak:did_core:web:org.example.com",
                    "policy_server_url": "https://org.example.com/_arkret/self/policy/check",
                }),
            ),
        );
        apply_realm_policy_server(
            &mut state,
            &op(
                REALM_CHILD,
                json!({
                    "policy_server_service_id": "ak:did_core:web:child.example.com",
                    "policy_server_url": "https://child.example.com/_arkret/self/policy/check",
                }),
            ),
        );
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

        let tombstone_move = json!({
            "tombstone": true,
            "preconditions": [{
                "cell": "ak:cell:ak.component.realm.policy_server.v1:null",
                "predicate": {"op": "head_eq", "value": {
                    "policy_server_service_id": "ak:did_core:web:child.example.com",
                    "policy_server_url": "https://child.example.com/_arkret/self/policy/check",
                }},
            }],
        });
        let first = apply_realm_policy_server(&mut state, &op(REALM_CHILD, tombstone_move.clone()));
        assert!(matches!(
            first,
            ProjectionEffect::RealmPolicyServerTombstoned { .. }
        ));
        let inherited = state
            .try_realm_policy_server_config(REALM_CHILD)
            .expect("resolvable policy-server chain")
            .expect("organization fallback");
        assert_eq!(inherited.realm_id, REALM_ORG);
        assert_eq!(
            state.realm_null_subject_cell_value(
                REALM_CHILD,
                arkret_wire::CellFamilyId::REALM_POLICY_SERVER_V1
            ),
            Some(&json!({"tombstone": true}))
        );

        let repeated = apply_realm_policy_server(&mut state, &op(REALM_CHILD, tombstone_move));
        assert!(matches!(
            repeated,
            ProjectionEffect::RealmPolicyServerTombstoned { .. }
        ));
        assert_eq!(
            state.realm_null_subject_cell_value(
                REALM_CHILD,
                arkret_wire::CellFamilyId::REALM_POLICY_SERVER_V1
            ),
            Some(&json!({"tombstone": true}))
        );
    }

    #[test]
    fn stale_policy_server_head_eq_is_rejected() {
        let mut state = ProjectionState::new();
        let first_value = json!({
            "policy_server_service_id": "ak:did_core:web:first.example",
            "policy_server_url": "https://first.example/_arkret/self/policy/check",
        });
        apply_realm_policy_server(&mut state, &op(REALM_CHILD, first_value.clone()));

        let mut replacement = op(
            REALM_CHILD,
            json!({
                "policy_server_service_id": "ak:did_core:web:second.example",
                "policy_server_url": "https://second.example/_arkret/self/policy/check",
            }),
        );
        replacement.context.preconditions = serde_json::from_value(json!([{
            "cell": "ak:cell:ak.component.realm.policy_server.v1:null",
            "predicate": {"op": "head_eq", "value": first_value},
        }]))
        .unwrap();
        assert_eq!(state.check_move_preconditions(&replacement), Ok(()));
        apply_realm_policy_server(&mut state, &replacement);

        let stale_delete = op(
            REALM_CHILD,
            json!({
                "tombstone": true,
                "preconditions": [{
                    "cell": "ak:cell:ak.component.realm.policy_server.v1:null",
                    "predicate": {
                        "op": "head_eq",
                        "value": {
                            "policy_server_service_id": "ak:did_core:web:first.example",
                            "policy_server_url": "https://first.example/_arkret/self/policy/check",
                        },
                    },
                }],
            }),
        );
        assert_eq!(
            state.check_move_preconditions(&stale_delete),
            Err("failed_precondition")
        );
    }
}
