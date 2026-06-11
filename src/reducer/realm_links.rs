//! G3.S5 — Realm-link state machine, cycle detection, and explicit
//! policy inheritance.
//!
//! ## Architecture
//!
//! The wire-level `ck.realm.link` projection (`ProjectionState::apply_realm_link`
//! in `reducer.rs`) handles the cell write + the structured
//! `realm_links` / `realm_links_inbound` side-band caches. This module
//! layers the cross-link semantics on top of that projection:
//!
//! 1. **State machine** — links transition through `active → rejected` or `active → tombstoned`.
//!    Per `realm-links.md §4` `status` is the terminal field on the cell; a new event for the same
//!    `(source, target, link_kind)` triple replaces the previous status. Projection-derived
//!    statuses (`confirmed` / `unconfirmed_link`) live one level above the cell and are not stored
//!    in the cell itself.
//!
//! 2. **Cycle detection** — before an `active` link is admitted, the reducer walks the existing
//!    link graph DFS from the proposed `target_realm_id` and rejects with `realm_link_cycle` if any
//!    directed path leads back to `source_realm_id`. Only the **directed governance / inheritance**
//!    link kinds participate in the cycle check (`governed_by`, `inherits_policy_from`,
//!    `confidential_extension_of`, `split_from`, `replaces`). `discoverable_from`,
//!    `join_gate_from`, and `mirror_of` are symmetric / advisory and MAY form cycles — the spec
//!    doesn't forbid e.g. `A mirror_of B` paired with `B mirror_of A`.
//!
//!    **Complexity**: O(V + E) per check, where V/E are the realms /
//!    directed-kind edges visited from the proposed `target_realm_id`.
//!    A `BTreeSet<String>` visited set short-circuits revisits.
//!    Acceptable for the link graph cardinalities the spec anticipates
//!    (single-digit governance roots, dozens of children per root).
//!    TODO: migrate to incremental cycle detection (PK / Bender et al.,
//!    "A New Approach to Incremental Cycle Detection and Related
//!    Problems") if the link graph grows past ~10⁴ edges.
//!
//! 3. **Explicit inheritance** — `realm-links.md §6` requires the child Realm to opt in via
//!    `ck.realm.inheritance_policy`. Walking the link graph for policy without that opt-in MUST NOT
//!    yield any inherited rules ("no implicit cascading", §5). The [`effective_policy_for_realm`] helper
//!    enforces this: when no `RealmInheritancePolicyState` is present for the realm,
//!    `inheritance_mode` is `"none"` and the chain is empty regardless of how many `governed_by` /
//!    `inherits_policy_from` parents exist in the link graph.
//!
//! 4. **Effective policy** — computed on demand from
//!    [`ProjectionState::realm_inheritance_policies`] + [`ProjectionState::realm_links`]. We
//!    deliberately do NOT cache this in projection state: caching is bounded only by the (small)
//!    link-graph fanout, and re-computing on each query keeps the invalidation surface ("recompute
//!    on link change OR policy change") trivially correct.
//!
//! Per `realm-links.md §6.3`, local deny / revoke / ban overrides inherited
//! allow. At this layer we expose the inherited
//! set; downstream policy evaluators apply the local-override rule on
//! top.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{ProjectionState, RealmLinkState};

/// Directed link kinds for which the reducer enforces cycle detection.
///
/// Mirror'd / discoverable / join-gate links are advisory pointers and
/// the spec does not forbid them participating in cycles
/// (`mirror_of` in particular is naturally symmetric for DR pairs).
const CYCLE_CHECKED_LINK_KINDS: &[&str] = &[
    "governed_by",
    "inherits_policy_from",
    "confidential_extension_of",
    "split_from",
    "replaces",
];

/// Returns `true` if `link_kind` participates in cycle detection.
pub fn is_cycle_checked_kind(link_kind: &str) -> bool {
    CYCLE_CHECKED_LINK_KINDS.contains(&link_kind)
}

/// Walk the existing realm-link graph DFS starting from
/// `start_realm_id` and return `true` if any directed path made of
/// **active** + cycle-checked links reaches `forbidden_realm_id`.
///
/// Used by `ProjectionState::apply_realm_link` to reject a proposed
/// `source → target` link when an existing chain `target → ... → source`
/// already exists (which the new edge would close into a cycle).
///
/// Algorithm: bounded DFS with a `BTreeSet<String>` visited set.
/// Complexity O(V + E) where V/E count the realms and directed-kind
/// edges reachable from `start_realm_id`. See module docs.
pub fn path_exists(
    state: &ProjectionState,
    start_realm_id: &str,
    forbidden_realm_id: &str,
) -> bool {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = vec![start_realm_id.to_owned()];
    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if current == forbidden_realm_id {
            return true;
        }
        if let Some(outbound) = state.realm_links.get(&current) {
            for link in outbound {
                if link.status != "active" {
                    continue;
                }
                if !is_cycle_checked_kind(&link.link_kind) {
                    continue;
                }
                if !visited.contains(&link.target_realm_id) {
                    stack.push(link.target_realm_id.clone());
                }
            }
        }
    }
    false
}

/// Inheritance mode emitted on the effective-policy response.
///
/// `Explicit` mirrors `realm-links.md §6` opt-in semantics: the realm
/// has projected a `ck.realm.inheritance_policy` declaring which parent
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
/// - `inheritance_mode` is `Explicit` iff the Realm has a `ck.realm.inheritance_policy` projection
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub realm_id: String,
    pub inheritance_mode: String,
    pub inheritance_chain: Vec<String>,
    pub effective_policy: Value,
}

/// Cap on the depth the DFS walks while assembling the inheritance
/// chain. Spec §6.4 currently caps `max_depth` at 1, but the cap here
/// is set higher so a misconfigured profile can't make the response
/// blow up if the cap is lifted. Cycle detection (above) also protects
/// us from infinite walks.
pub const MAX_INHERITANCE_CHAIN: usize = 8;

/// Compute the effective policy for `realm_id`. See [`EffectivePolicy`]
/// for the returned shape.
///
/// Invariants:
/// - Returns `inheritance_mode = "none"` and an empty `inheritance_chain` when the Realm has no
///   `ck.realm.inheritance_policy` projection — per spec §5 inheritance MUST be explicit.
/// - Walks `governed_by` / `inherits_policy_from` `active` links only. Rejected / tombstoned links
///   contribute nothing (spec §4 + §6.3).
/// - Stops at [`MAX_INHERITANCE_CHAIN`] depth or upon revisiting a realm already in the chain
///   (defence-in-depth — the cycle check on `apply_realm_link` should already prevent loops, but
///   the read path can be invoked on a corrupted projection during recovery).
pub fn effective_policy_for_realm(state: &ProjectionState, realm_id: &str) -> EffectivePolicy {
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
        for p in &own_decl.allowed_policies {
            allowed_policies.insert(p.clone());
        }
        for b in &own_decl.allowed_capability_bundles {
            allowed_capability_bundles.insert(b.clone());
        }
        let has_active_link_to_source = own_decl.source_realm_id != realm_id
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

    let effective_policy = json!({
        "allowed_policies": allowed_policies.into_iter().collect::<Vec<_>>(),
        "allowed_capability_bundles": allowed_capability_bundles.into_iter().collect::<Vec<_>>(),
    });

    EffectivePolicy {
        realm_id: realm_id.to_owned(),
        inheritance_mode: inheritance_mode.as_str().to_owned(),
        inheritance_chain: chain,
        effective_policy,
    }
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

/// Preflight admission check for a proposed `ck.realm.link` write.
/// Mirrors the validation `ProjectionState::apply_realm_link` runs
/// post-projection, but as a pure read against `state` so HTTP
/// handlers can reject **before** the projection pipeline (the
/// existing pipeline silently drops rejected projections — see
/// `project_accepted_operations`).
///
/// Returns the spec rejection reason code on failure (e.g.
/// `realm_link_self_reference`, `realm_link_kind_invalid`,
/// `realm_link_status_invalid`, `realm_link_cycle`), or `Ok(())` when
/// the link is admissible.
pub fn check_realm_link_admissible(
    state: &ProjectionState,
    source_realm_id: &str,
    target_realm_id: &str,
    link_kind: &str,
    status: &str,
) -> Result<(), &'static str> {
    if cokret_sdk::RealmLinkKind::parse(link_kind).is_none() {
        return Err("realm_link_kind_invalid");
    }
    if source_realm_id == target_realm_id {
        return Err("realm_link_self_reference");
    }
    if !matches!(status, "active" | "rejected" | "tombstoned") {
        return Err("realm_link_status_invalid");
    }
    if status == "active"
        && is_cycle_checked_kind(link_kind)
        && path_exists(state, target_realm_id, source_realm_id)
    {
        return Err("realm_link_cycle");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cokret_sdk::{Operation, OperationId, RealmId};
    use serde_json::json;

    use super::*;
    use crate::hlc::ServerHlc;
    use crate::kinds::{CK_REALM_INHERITANCE_POLICY, CK_REALM_LINK};

    const REALM_A: &str = "ck:realm:01904100-0000-7000-8000-aaaaaaaaaaa1";
    const REALM_B: &str = "ck:realm:01904100-0000-7000-8000-bbbbbbbbbbb2";
    const REALM_C: &str = "ck:realm:01904100-0000-7000-8000-ccccccccccc3";
    const REALM_D: &str = "ck:realm:01904100-0000-7000-8000-ddddddddddd4";

    fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
        Operation::create(
            OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            RealmId::new(realm_id).unwrap(),
            kind,
            payload,
        )
    }

    fn link_op(source: &str, target: &str, link_kind: &str, status: &str) -> Operation {
        op(
            CK_REALM_LINK,
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
            CK_REALM_INHERITANCE_POLICY,
            child,
            json!({
                "source_realm_id": parent,
                "allowed_policies": allowed_policies,
                "max_depth": 1,
            }),
        )
    }

    #[test]
    fn apply_link_active_succeeds_when_no_cycle() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // A → B → C, all governed_by. No back edge from C to A, so the
        // graph is acyclic and every accept should land.
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
        // No cycle: a fresh D → A active link succeeds even though A
        // reaches a chain of children.
        let e3 = state.apply(&link_op(REALM_D, REALM_A, "governed_by", "active"), &hlc);
        assert!(matches!(
            e3,
            crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
        ));
    }

    #[test]
    fn apply_link_cycle_rejected_with_realm_link_cycle() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // A → B → C, all governed_by. Then attempt C → A — DFS from A
        // finds a path back to C, so the new edge C → A would close the
        // triangle.
        state.apply(&link_op(REALM_A, REALM_B, "governed_by", "active"), &hlc);
        state.apply(&link_op(REALM_B, REALM_C, "governed_by", "active"), &hlc);
        let cycle = state.apply(&link_op(REALM_C, REALM_A, "governed_by", "active"), &hlc);
        match cycle {
            crate::reducer::ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "realm_link_cycle");
            }
            other => panic!("expected Rejected(realm_link_cycle), got {other:?}"),
        }
        // Sanity: the rejected edge MUST NOT appear in the structured
        // cache (cycle reject happens before the upsert).
        let rows = outbound_links(&state, REALM_C);
        assert!(
            rows.iter().all(|r| r.target_realm_id != REALM_A),
            "rejected cycle edge leaked into the projection cache: {rows:?}"
        );
    }

    #[test]
    fn apply_link_self_link_rejected() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Self-reference is caught by the pre-existing
        // `realm_link_self_reference` guard, independent of the cycle
        // check — both are correctness invariants.
        let effect = state.apply(&link_op(REALM_A, REALM_A, "governed_by", "active"), &hlc);
        match effect {
            crate::reducer::ProjectionEffect::Rejected { reason } => {
                assert_eq!(reason, "realm_link_self_reference");
            }
            other => panic!("expected Rejected(realm_link_self_reference), got {other:?}"),
        }
    }

    #[test]
    fn apply_link_cycle_skipped_for_mirror_or_discoverable() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // mirror_of pairs are inherently symmetric (DR / replication
        // setups) — A mirror_of B + B mirror_of A is the canonical
        // healthy shape, NOT a cycle the reducer should reject.
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
    fn apply_link_cycle_allowed_when_existing_edges_rejected() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Build A → B → C, then flip A → B to `rejected`. The cycle
        // detector MUST treat rejected edges as severed, so re-adding
        // C → A is now safe.
        state.apply(&link_op(REALM_A, REALM_B, "governed_by", "active"), &hlc);
        state.apply(&link_op(REALM_B, REALM_C, "governed_by", "active"), &hlc);
        // Sever A → B.
        state.apply(&link_op(REALM_A, REALM_B, "governed_by", "rejected"), &hlc);
        let effect = state.apply(&link_op(REALM_C, REALM_A, "governed_by", "active"), &hlc);
        assert!(
            matches!(
                effect,
                crate::reducer::ProjectionEffect::RealmLinkProjected { .. }
            ),
            "expected RealmLinkProjected after severing the A→B edge, got {effect:?}"
        );
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
        assert_eq!(ep.inheritance_mode, "explicit");
        // Chain must include C (declared parent) and walk through B
        // (C's declared parent reachable via the governed_by edge).
        assert!(
            ep.inheritance_chain.contains(&REALM_C.to_owned()),
            "expected REALM_C in chain: {:?}",
            ep.inheritance_chain
        );
        assert!(
            ep.inheritance_chain.contains(&REALM_B.to_owned()),
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
    fn effective_policy_skips_inheritance_when_none() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // Realm D is governed by C (and C inherits from B). But D
        // itself never published a `ck.realm.inheritance_policy` —
        // §5 forbids implicit inheritance, so the effective policy
        // MUST be empty / `inheritance_mode = "none"`.
        state.apply(&link_op(REALM_D, REALM_C, "governed_by", "active"), &hlc);
        state.apply(&link_op(REALM_C, REALM_B, "governed_by", "active"), &hlc);
        state.apply(&inherit_op(REALM_C, REALM_B, &["c.policy"]), &hlc);

        let ep = effective_policy_for_realm(&state, REALM_D);
        assert_eq!(
            ep.inheritance_mode, "none",
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

    #[test]
    fn is_cycle_checked_kind_covers_directed_governance() {
        // Pin the set in case the spec adds a new directed kind — the
        // test fails loudly so the maintainer must consciously decide
        // whether it should be cycle-checked.
        for k in [
            "governed_by",
            "inherits_policy_from",
            "confidential_extension_of",
            "split_from",
            "replaces",
        ] {
            assert!(is_cycle_checked_kind(k), "{k} must be cycle-checked");
        }
        for k in ["discoverable_from", "join_gate_from", "mirror_of"] {
            assert!(
                !is_cycle_checked_kind(k),
                "{k} must NOT be cycle-checked (symmetric / advisory)"
            );
        }
    }
}
