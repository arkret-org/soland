//! G3.S5 — Realm-link state machine and explicit
//! policy inheritance.
//!
//! ## Architecture
//!
//! The wire-level `ak.realm.link` projection (`ProjectionState::apply_realm_link`
//! in `reducer.rs`) handles the cell write + the structured
//! `realm_links` / `realm_links_inbound` side-band caches. This module
//! layers the cross-link semantics on top of that projection:
//!
//! 1. **State machine** — links use the SDK's canonical `fsm/reject` transition matrix. General
//!    directed cycles are valid graph shapes; only a self-reference is rejected at admission.
//!
//! 2. **Explicit inheritance** — `realm-links.md §6` requires the child Realm to opt in via
//!    `ak.realm.inheritance_policy`. Walking the link graph for policy without that opt-in MUST NOT
//!    yield any inherited rules ("no implicit cascading", §5). The [`effective_policy_for_realm`]
//!    helper enforces this: when no `RealmInheritancePolicyState` is present for the realm,
//!    `inheritance_mode` is `"none"` and the chain is empty regardless of how many `governed_by` /
//!    `inherits_policy_from` parents exist in the link graph.
//!
//! 3. **Effective policy** — computed on demand from
//!    [`ProjectionState::realm_inheritance_policies`] + [`ProjectionState::realm_links`]. We
//!    deliberately do NOT cache this in projection state: caching is bounded only by the (small)
//!    link-graph fanout, and re-computing on each query keeps the invalidation surface ("recompute
//!    on link change OR policy change") trivially correct.
//!
//! Per `realm-links.md §6.3`, local deny / revoke / ban overrides inherited
//! allow. At this layer we expose the inherited
//! set; downstream policy evaluators apply the local-override rule on
//! top.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{ProjectionState, RealmInheritancePolicyState, RealmLinkState};

/// Projection-local cell id for a Realm Link composite subject.
///
/// The protocol subject is `(target_realm_id, link_kind)` inside an enclosing
/// Realm. `ProjectionState::cells` is a flat process-wide map, so its local key
/// prepends that enclosing Realm before applying the SDK's canonical composite
/// subject hash. This key is internal and is never emitted as the wire subject.
pub fn realm_link_projection_cell_ref(
    source_realm_id: &str,
    target_realm_id: &str,
    link_kind: &str,
) -> Option<arkret_identifiers::CellRef> {
    let subject =
        arkret_wire::composite_subject(&[source_realm_id, target_realm_id, link_kind]).ok()?;
    arkret_identifiers::CellRef::new(format!("ak:cell:ak.component.realm.link.v1:{subject}")).ok()
}

/// Inheritance mode emitted on the effective-policy response.
///
/// `Explicit` mirrors `realm-links.md §6` opt-in semantics: the realm
/// has projected a `ak.realm.inheritance_policy` declaring which parent
/// policies / capability bundles it accepts. `None` means no
/// declaration; per §5 "no implicit cascading", the effective policy is the
/// realm's own local policy only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InheritanceMode {
    Explicit,
    None,
}

impl InheritanceMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::None => "none",
        }
    }
}

/// Computed effective policy for one Realm.
///
/// - `realm_id` echoes the queried Realm.
/// - `inheritance_mode` is `Explicit` iff the Realm has a `ak.realm.inheritance_policy` projection
///   (opt-in per spec §6).
/// - `inheritance_chain` lists ancestor realm ids in walk order (`source_realm_id` of the projected
///   inheritance policy, then any transitive parents discovered via `governed_by` /
///   `inherits_policy_from` active links). Capped at [`MAX_INHERITANCE_CHAIN`] to bound traversal
///   cost (spec §6.4 caps `max_depth` at 1 today; the cap here is a generous safety net for future
///   multi-depth profiles).
/// - `effective_policy` is the JSON merge of the realm's own declared `allowed_policies` /
///   `allowed_capability_bundles` plus the union contributed by each ancestor in the chain. Per
///   spec §6.2 derived grants MUST NOT be wider than the source — at this layer we surface the
///   union; the policy evaluator applies the narrow-only intersection at decision time (see
///   `routing/access/policy.rs`).
/// Cap on the depth the DFS walks while assembling the inheritance
/// chain. Spec §6.4 currently caps `max_depth` at 1, but the cap here
/// is set higher so a misconfigured profile can't make the response
/// blow up if the cap is lifted. Cycle detection (above) also protects
/// us from infinite walks.
pub const MAX_INHERITANCE_CHAIN: usize = 8;

/// Compute the SDK effective-policy outcome for `realm_id`.
///
/// Invariants:
/// - Returns `inheritance_mode = "none"` and an empty `inheritance_chain` when the Realm has no
///   `ak.realm.inheritance_policy` projection — per spec §5 inheritance MUST be explicit.
/// - Walks `governed_by` / `inherits_policy_from` `active` links only. Rejected / tombstoned links
///   contribute nothing (spec §4 + §6.3).
/// - Stops at [`MAX_INHERITANCE_CHAIN`] depth or upon revisiting a realm already in the chain;
///   general Realm Link graphs may contain cycles.
pub fn effective_policy_for_realm(
    state: &ProjectionState,
    realm_id: &str,
) -> arkret_models_collaboration::governance::realm_governance::RealmEffectivePolicyOutcome {
    let own = state.realm_inheritance_policy(realm_id);
    let inheritance_mode = if own.is_some() {
        InheritanceMode::Explicit
    } else {
        InheritanceMode::None
    };

    let mut chain: Vec<String> = Vec::new();
    let mut allowed_policies: BTreeSet<String> = BTreeSet::new();
    let mut allowed_capability_bundles: BTreeSet<String> = BTreeSet::new();

    if let Some(own_decl) = own {
        // The realm's own declaration contributes its own allow-lists
        // unconditionally — but the chain walk to the declared
        // `source_realm_id` requires a *currently active* `governed_by`
        // / `inherits_policy_from` link from `realm_id` to that source.
        // Spec §6.3: local deny / revoke / ban overrides inherited allow.
        // tombstoning or rejecting the underlying link severs the
        // inheritance even if the inheritance_policy declaration is
        // still on file.
        let source_is_self = own_decl.source_realm_id == realm_id;
        let has_active_link_to_source = !source_is_self
            && state
                .realm_links
                .get(realm_id)
                .map(|links| {
                    links.iter().any(|l| {
                        l.target_realm_id == own_decl.source_realm_id
                            && l.status == "active"
                            && matches!(
                                l.link_kind.as_str(),
                                "governed_by" | "inherits_policy_from"
                            )
                    })
                })
                .unwrap_or(false);
        if source_is_self || has_active_link_to_source {
            for p in &own_decl.allowed_policies {
                allowed_policies.insert(p.clone());
            }
            for b in &own_decl.allowed_capability_bundles {
                allowed_capability_bundles.insert(b.clone());
            }
        }
        if has_active_link_to_source {
            chain.push(own_decl.source_realm_id.clone());

            // Transitive walk: follow `governed_by` /
            // `inherits_policy_from` active links from the declared
            // source. Each ancestor we visit contributes its own
            // declared allow-lists (the union, narrowed downstream by
            // the policy evaluator).
            let mut visited: BTreeSet<String> = BTreeSet::new();
            visited.insert(realm_id.to_owned());
            visited.insert(own_decl.source_realm_id.clone());
            walk_inheritance(
                state,
                &own_decl.source_realm_id,
                &mut chain,
                &mut visited,
                &mut allowed_policies,
                &mut allowed_capability_bundles,
                1,
            );
        }
    }

    // realm-links.md §6.2 — derived grants MUST NOT be wider than ANY source.
    // The union above stays for the single-source aggregate read; alongside it we
    // surface the narrow-only INTERSECTION across every source the child has
    // opted into via a currently-active governance link. A policy survives the
    // narrowing only when EVERY opted-in source declares it, which is the
    // assertable narrow-only result for multi-`governed_by` children.
    let (narrowed_policies, narrowed_capability_bundles) =
        narrowed_inheritance_intersection(state, realm_id);

    let effective_policy = BTreeMap::from([
        (
            "allowed_policies".to_owned(),
            json!(allowed_policies.into_iter().collect::<Vec<_>>()),
        ),
        (
            "allowed_capability_bundles".to_owned(),
            json!(allowed_capability_bundles.into_iter().collect::<Vec<_>>()),
        ),
        ("narrowed_policies".to_owned(), json!(narrowed_policies)),
        (
            "narrowed_capability_bundles".to_owned(),
            json!(narrowed_capability_bundles),
        ),
    ]);

    arkret_models_collaboration::governance::realm_governance::RealmEffectivePolicyOutcome {
        realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
            .expect("projected realm ids are validated"),
        effective_policy,
        inheritance_chain: chain
            .into_iter()
            .map(|realm_id| {
                arkret_identifiers::RealmId::new(realm_id)
                    .expect("projected inheritance Realm ids are validated")
            })
            .collect(),
        inheritance_mode: match inheritance_mode {
            InheritanceMode::Explicit => arkret_models_collaboration::governance::realm_governance::RealmEffectivePolicyInheritanceMode::Explicit,
            InheritanceMode::None => arkret_models_collaboration::governance::realm_governance::RealmEffectivePolicyInheritanceMode::None,
        },
    }
}

/// realm-links.md §6.2 narrow-only — compute the INTERSECTION of the
/// `allowed_policies` / `allowed_capability_bundles` across every source the
/// child Realm has opted into via a currently-active `governed_by` /
/// `inherits_policy_from` link.
///
/// Each opted-in source contributes its own declared narrowed allow-list; a
/// policy survives only when EVERY active source declares it (so adding a
/// stricter governance source can only narrow, never widen, the derived set —
/// the spec's narrow-only invariant — realm-links.md §2: an effective
/// policy may only tighten, never widen, the linked Realm's policy).
/// Sources whose underlying link is rejected
/// / tombstoned do not participate. Returns `(narrowed_policies,
/// narrowed_capability_bundles)` in deterministic sorted order. With zero
/// active sources both sets are empty (nothing is inherited).
fn narrowed_inheritance_intersection(
    state: &ProjectionState,
    realm_id: &str,
) -> (Vec<String>, Vec<String>) {
    let active_link_to = |source: &str| {
        state
            .realm_links
            .get(realm_id)
            .map(|links| {
                links.iter().any(|l| {
                    l.target_realm_id == source
                        && l.status == "active"
                        && matches!(l.link_kind.as_str(), "governed_by" | "inherits_policy_from")
                })
            })
            .unwrap_or(false)
    };

    // The child's per-source opt-in declarations naming a real, currently
    // active governance source.
    let opt_ins: Vec<&RealmInheritancePolicyState> = state
        .realm_inheritance_policies_for_child(realm_id)
        .into_iter()
        .filter(|decl| decl.source_realm_id != realm_id && active_link_to(&decl.source_realm_id))
        .collect();

    if opt_ins.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // For each opted-in source S: the inheritable set is S's OWN declared
    // allow-list (its self-declaration), optionally further narrowed by the
    // child's opt-in list when the child restricts what it accepts. Then
    // intersect across all sources — a policy survives only when EVERY active
    // source declares it (narrow-only, §6.2).
    let per_source = |selector: fn(&RealmInheritancePolicyState) -> &Vec<String>| {
        let mut acc: Option<BTreeSet<String>> = None;
        for opt_in in &opt_ins {
            // The source's OWN narrowing declaration is its self-declaration
            // `(source, source)`; prefer that over the source's last-write
            // single-source row so a source that itself inherits elsewhere
            // still contributes the set it published for downstream children.
            let source_self_key = (
                opt_in.source_realm_id.clone(),
                opt_in.source_realm_id.clone(),
            );
            let source_decl = state
                .realm_inheritance_policies_by_source
                .get(&source_self_key)
                .or_else(|| state.realm_inheritance_policy(&opt_in.source_realm_id));
            let source_declared: BTreeSet<String> = source_decl
                .map(|decl| selector(decl).iter().cloned().collect())
                .unwrap_or_default();
            let child_filter: BTreeSet<String> = selector(opt_in).iter().cloned().collect();
            // Empty child opt-in = accept the source's full declared set;
            // non-empty = intersect with what the child explicitly accepts.
            let inheritable: BTreeSet<String> = if child_filter.is_empty() {
                source_declared
            } else {
                source_declared
                    .intersection(&child_filter)
                    .cloned()
                    .collect()
            };
            acc = Some(match acc {
                Some(prev) => prev.intersection(&inheritable).cloned().collect(),
                None => inheritable,
            });
        }
        acc.unwrap_or_default().into_iter().collect::<Vec<_>>()
    };

    (
        per_source(|decl| &decl.allowed_policies),
        per_source(|decl| &decl.allowed_capability_bundles),
    )
}

/// Inner DFS for [`effective_policy_for_realm`]. Bounded by
/// [`MAX_INHERITANCE_CHAIN`] and a visited set; folds each ancestor's
/// `allowed_policies` / `allowed_capability_bundles` into the
/// accumulators.
fn walk_inheritance(
    state: &ProjectionState,
    current: &str,
    chain: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
    allowed_policies: &mut BTreeSet<String>,
    allowed_capability_bundles: &mut BTreeSet<String>,
    depth: usize,
) {
    if depth >= MAX_INHERITANCE_CHAIN {
        return;
    }
    // Fold this ancestor's own declared allow-lists if it also has an
    // inheritance_policy projection.
    if let Some(decl) = state.realm_inheritance_policy(current) {
        for p in &decl.allowed_policies {
            allowed_policies.insert(p.clone());
        }
        for b in &decl.allowed_capability_bundles {
            allowed_capability_bundles.insert(b.clone());
        }
    }
    // Follow `governed_by` / `inherits_policy_from` active links from
    // the current ancestor — these are the spec's policy-bearing links
    // (`realm-links.md §3` table: rows where authorization derivation is MAY).
    let Some(outbound) = state.realm_links.get(current) else {
        return;
    };
    for link in outbound {
        if link.status != "active" {
            continue;
        }
        if !matches!(
            link.link_kind.as_str(),
            "governed_by" | "inherits_policy_from"
        ) {
            continue;
        }
        if visited.insert(link.target_realm_id.clone()) {
            chain.push(link.target_realm_id.clone());
            walk_inheritance(
                state,
                &link.target_realm_id,
                chain,
                visited,
                allowed_policies,
                allowed_capability_bundles,
                depth + 1,
            );
        }
    }
}

/// Convenience accessor: list every outbound link projection for
/// `realm_id` regardless of direction filter (the HTTP route filters
/// per query). Returns an empty slice for unknown realms.
pub fn outbound_links<'a>(state: &'a ProjectionState, realm_id: &str) -> &'a [RealmLinkState] {
    state
        .realm_links
        .get(realm_id)
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Preflight admission check for a proposed `ak.realm.link` write.
/// Mirrors the validation `ProjectionState::apply_realm_link` runs
/// post-projection, but as a pure read against `state` so HTTP
/// handlers can reject **before** the projection pipeline (the
/// existing pipeline silently drops rejected projections — see
/// `project_accepted_operations`).
///
/// Returns the spec rejection reason code on failure (e.g.
/// `realm_link_self_reference`, `realm_link_kind_invalid`,
/// `realm_link_status_invalid`, `realm_link_invalid_transition`), or `Ok(())` when
/// the link is admissible.
pub fn check_realm_link_admissible(
    state: &ProjectionState,
    source_realm_id: &str,
    target_realm_id: &str,
    link_kind: &str,
    status: &str,
) -> Result<(), &'static str> {
    if arkret_models_collaboration::governance::realm_governance::RealmLinkKind::parse(link_kind)
        .is_none()
    {
        return Err("realm_link_kind_invalid");
    }
    if source_realm_id == target_realm_id {
        return Err("realm_link_self_reference");
    }
    let Some(next_status) =
        arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(status)
    else {
        return Err("realm_link_status_invalid");
    };
    let current_status = state
        .realm_links
        .get(source_realm_id)
        .and_then(|links| {
            links
                .iter()
                .find(|link| link.target_realm_id == target_realm_id && link.link_kind == link_kind)
        })
        .and_then(|link| {
            arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(
                &link.status,
            )
        });
    if current_status.is_some_and(|current| !current.can_transition_to(next_status)) {
        return Err(arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_event_draft::Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_models_collaboration::governance::realm_governance::RealmEffectivePolicyInheritanceMode;
    use serde_json::{Value, json};

    use super::*;
    use crate::hlc::ServerHlc;

    const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-aaaaaaaaaaa1";
    const REALM_B: &str = "ak:realm:01904100-0000-7000-8000-bbbbbbbbbbb2";
    const REALM_C: &str = "ak:realm:01904100-0000-7000-8000-ccccccccccc3";
    const REALM_D: &str = "ak:realm:01904100-0000-7000-8000-ddddddddddd4";

    fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
        Operation::create(
            OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            RealmId::new(realm_id).unwrap(),
            kind,
            payload,
        )
    }

    fn link_op(source: &str, target: &str, link_kind: &str, status: &str) -> Operation {
        op(
            arkret_wire::events::EventKind::REALM_LINK,
            source,
            json!({
                "target_realm_id": target,
                "link_kind": link_kind,
                "status": status,
            }),
        )
    }

    fn inherit_op(child: &str, parent: &str, allowed_policies: &[&str]) -> Operation {
        op(
            arkret_wire::events::EventKind::REALM_INHERITANCE_POLICY,
            child,
            json!({
                "source_realm_id": parent,
                "allowed_policies": allowed_policies,
                "max_depth": 1,
            }),
        )
    }

    fn inherit_op_spec_payload(child: &str, parent: &str, policy_rules: &[&str]) -> Operation {
        op(
            arkret_wire::events::EventKind::REALM_INHERITANCE_POLICY,
            child,
            json!({
                "source_realm_id": parent,
                "inherits": {
                    "policy_rules": policy_rules,
                },
                "mode": "narrow_only",
                "max_depth": 1,
            }),
        )
    }

    #[test]
    fn apply_link_active_succeeds() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // A → B → C, all governed_by.
        let e1 = state.apply(&link_op(REALM_A, REALM_B, "governed_by", "active"), &hlc);
        let e2 = state.apply(&link_op(REALM_B, REALM_C, "governed_by", "active"), &hlc);
        assert!(matches!(
            e1,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
        assert!(matches!(
            e2,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
        // A fresh D → A active link succeeds even though A reaches a chain.
        let e3 = state.apply(&link_op(REALM_D, REALM_A, "governed_by", "active"), &hlc);
        assert!(matches!(
            e3,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
    }

    #[test]
    fn apply_link_general_directed_cycle_is_allowed() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Realm Link is a general graph. A → B → C → A is valid.
        state.apply(&link_op(REALM_A, REALM_B, "governed_by", "active"), &hlc);
        state.apply(&link_op(REALM_B, REALM_C, "governed_by", "active"), &hlc);
        let cycle = state.apply(&link_op(REALM_C, REALM_A, "governed_by", "active"), &hlc);
        assert!(matches!(
            cycle,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
        let rows = outbound_links(&state, REALM_C);
        assert!(
            rows.iter().any(|r| r.target_realm_id == REALM_A),
            "accepted cycle edge missing from the projection cache: {rows:?}"
        );
    }

    #[test]
    fn apply_link_self_link_rejected() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Self-reference is the only graph-shape admission rejection.
        let effect = state.apply(&link_op(REALM_A, REALM_A, "governed_by", "active"), &hlc);
        match effect {
            crate::reducer::ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "realm_link_self_reference");
            }
            other => panic!("expected Rejected(realm_link_self_reference), got {other:?}"),
        }
    }

    #[test]
    fn apply_link_symmetric_pair_is_allowed() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // mirror_of pairs are inherently symmetric for DR/replication setups.
        let e1 = state.apply(&link_op(REALM_A, REALM_B, "mirror_of", "active"), &hlc);
        let e2 = state.apply(&link_op(REALM_B, REALM_A, "mirror_of", "active"), &hlc);
        assert!(matches!(
            e1,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
        assert!(matches!(
            e2,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
    }

    #[test]
    fn apply_link_tombstone_is_terminal() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(&link_op(REALM_A, REALM_B, "governed_by", "active"), &hlc);
        state.apply(
            &link_op(REALM_A, REALM_B, "governed_by", "tombstoned"),
            &hlc,
        );
        let effect = state.apply(&link_op(REALM_A, REALM_B, "governed_by", "active"), &hlc);
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION
        ));
    }

    #[test]
    fn apply_link_accepts_the_sdk_fsm_matrix() {
        let hlc = ServerHlc::new("test");
        for initial in
            arkret_models_collaboration::governance::realm_governance::REALM_LINK_INITIAL_STATES
        {
            let mut state = ProjectionState::new();
            let effect = state.apply(
                &link_op(REALM_A, REALM_B, "governed_by", initial.as_str()),
                &hlc,
            );
            assert!(matches!(
                effect,
                crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
            ));
        }

        for (from, to) in arkret_models_collaboration::governance::realm_governance::REALM_LINK_ALLOWED_TRANSITIONS {
            let mut state = ProjectionState::new();
            state.apply(
                &link_op(REALM_A, REALM_B, "governed_by", from.as_str()),
                &hlc,
            );
            let effect = state.apply(&link_op(REALM_A, REALM_B, "governed_by", to.as_str()), &hlc);
            assert!(
                matches!(
                    effect,
                    crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
                ),
                "declared transition {} -> {} was rejected: {effect:?}",
                from.as_str(),
                to.as_str()
            );
        }
    }

    #[test]
    fn effective_policy_walks_parents_when_explicit() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Two-level chain: D inherits from C, C inherits from B.
        // governed_by links carry the chain at the link-graph layer.
        state.apply(&link_op(REALM_D, REALM_C, "governed_by", "active"), &hlc);
        state.apply(&link_op(REALM_C, REALM_B, "governed_by", "active"), &hlc);
        // Explicit opt-in at each level (spec §6.1).
        state.apply(&inherit_op(REALM_D, REALM_C, &["d.policy"]), &hlc);
        state.apply(&inherit_op(REALM_C, REALM_B, &["c.policy"]), &hlc);
        state.apply(&inherit_op(REALM_B, REALM_A, &["b.policy"]), &hlc);

        let ep = effective_policy_for_realm(&state, REALM_D);
        assert_eq!(
            ep.inheritance_mode,
            RealmEffectivePolicyInheritanceMode::Explicit
        );
        // Chain must include C (declared parent) and walk through B
        // (C's declared parent reachable via the governed_by edge).
        assert!(
            ep.inheritance_chain
                .iter()
                .any(|realm_id| realm_id.as_str() == REALM_C),
            "expected REALM_C in chain: {:?}",
            ep.inheritance_chain
        );
        assert!(
            ep.inheritance_chain
                .iter()
                .any(|realm_id| realm_id.as_str() == REALM_B),
            "expected REALM_B in chain (2-level walk): {:?}",
            ep.inheritance_chain
        );
        let allow = ep
            .effective_policy
            .get("allowed_policies")
            .and_then(Value::as_array)
            .expect("allowed_policies array");
        let allow_strs: Vec<&str> = allow.iter().filter_map(Value::as_str).collect();
        assert!(allow_strs.contains(&"d.policy"));
        assert!(allow_strs.contains(&"c.policy"));
        // B's own declared allow-list contributes too, since the walk
        // reached B via the governed_by edge.
        assert!(allow_strs.contains(&"b.policy"));
    }

    #[test]
    fn effective_policy_accepts_spec_inheritance_policy_payload() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(&link_op(REALM_D, REALM_C, "governed_by", "active"), &hlc);
        state.apply(
            &inherit_op_spec_payload(REALM_C, REALM_C, &["parent.policy"]),
            &hlc,
        );
        state.apply(
            &inherit_op_spec_payload(REALM_D, REALM_C, &["child.policy"]),
            &hlc,
        );

        let ep = effective_policy_for_realm(&state, REALM_D);
        assert_eq!(
            ep.inheritance_mode,
            RealmEffectivePolicyInheritanceMode::Explicit
        );
        assert!(
            ep.inheritance_chain
                .iter()
                .any(|realm_id| realm_id.as_str() == REALM_C),
            "expected REALM_C in chain: {:?}",
            ep.inheritance_chain
        );
        let allow = ep
            .effective_policy
            .get("allowed_policies")
            .and_then(Value::as_array)
            .expect("allowed_policies array");
        let allow_strs: Vec<&str> = allow.iter().filter_map(Value::as_str).collect();
        assert!(allow_strs.contains(&"child.policy"));
        assert!(allow_strs.contains(&"parent.policy"));
    }

    #[test]
    fn effective_policy_drops_cross_realm_rules_when_link_is_rejected() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(&link_op(REALM_D, REALM_C, "governed_by", "active"), &hlc);
        state.apply(&inherit_op(REALM_D, REALM_C, &["child.policy"]), &hlc);
        state.apply(&link_op(REALM_D, REALM_C, "governed_by", "rejected"), &hlc);

        let ep = effective_policy_for_realm(&state, REALM_D);
        assert!(ep.inheritance_chain.is_empty());
        assert_eq!(
            ep.effective_policy.get("allowed_policies"),
            Some(&serde_json::json!([]))
        );
    }

    #[test]
    fn effective_policy_skips_inheritance_when_none() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Realm D is governed by C (and C inherits from B). But D
        // itself never published a `ak.realm.inheritance_policy` —
        // §5 forbids implicit inheritance, so the effective policy
        // MUST be empty / `inheritance_mode = "none"`.
        state.apply(&link_op(REALM_D, REALM_C, "governed_by", "active"), &hlc);
        state.apply(&link_op(REALM_C, REALM_B, "governed_by", "active"), &hlc);
        state.apply(&inherit_op(REALM_C, REALM_B, &["c.policy"]), &hlc);

        let ep = effective_policy_for_realm(&state, REALM_D);
        assert_eq!(
            ep.inheritance_mode,
            RealmEffectivePolicyInheritanceMode::None,
            "no inheritance_policy declared on D: {ep:?}"
        );
        assert!(
            ep.inheritance_chain.is_empty(),
            "chain must be empty when mode=none: {:?}",
            ep.inheritance_chain
        );
        let allow = ep
            .effective_policy
            .get("allowed_policies")
            .and_then(Value::as_array)
            .expect("allowed_policies array");
        assert!(
            allow.is_empty(),
            "no inherited policies when mode=none: {allow:?}"
        );
    }
}
