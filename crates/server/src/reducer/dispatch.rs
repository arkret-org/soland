//! Per-kind `apply_*_dispatch` adapters + the canonical
//! `event_kind → ApplyFn` registry consumed by
//! [`super::ProjectionState::apply`].
//!
//! The adapter free functions exist solely to turn the per-kind
//! `(now, hlc, lifecycle_enum_variant, ...)` arg signatures into the
//! uniform `(state, op, hlc) -> ProjectionEffect` shape the registry
//! needs. They contain no projection logic — that all stays in the
//! `apply_*` methods on `ProjectionState`.
//!
//! Split out of the `reducer` mod file; the registry, the `ApplyFn`
//! type, and the realm-link / event-ref helpers are re-exported there so
//! the `crate::reducer::*` paths and sibling `super::*` access stay
//! unchanged.

use cokret_sdk::{AgentLifecycleState, Operation};
use serde_json::Value;

use super::{
    AgentActionRequestStatus, CircleLifecycleState, ObjectLifecycleTransition, ProjectionEffect,
    ProjectionState, RealmLinkState, SpaceContainerLifecycleTransition, apply_moderation, mls,
};
use crate::hlc::ServerHlc;

/// R3.1 — upsert a realm-link row into a per-Realm Vec cache. Matches
/// on the composite key `(realm_id, target_realm_id, link_kind)`; an
/// update replaces in place (keeping the original `created_at`).
pub(crate) fn upsert_realm_link(vec: &mut Vec<RealmLinkState>, row: &RealmLinkState) {
    if let Some(existing) = vec.iter_mut().find(|r| {
        r.realm_id == row.realm_id
            && r.target_realm_id == row.target_realm_id
            && r.link_kind == row.link_kind
    }) {
        let created_at = existing.created_at;
        *existing = row.clone();
        existing.created_at = created_at;
    } else {
        vec.push(row.clone());
    }
}

/// R3.2 — extract a string EventRef id from an `EventRef`-shaped
/// payload field. Accepts both the canonical object shape
/// `{"id": "ck:event:...", "role": "..."}` and a bare string form
/// (older client tolerance).
pub(crate) fn extract_event_ref_id(payload: &Value, field: &str) -> Option<String> {
    let v = payload.get(field)?;
    if let Some(s) = v.as_str() {
        return Some(s.to_owned());
    }
    v.get("id").and_then(Value::as_str).map(ToOwned::to_owned)
}

// ────────────────────────── apply() dispatch registry ──────────────────────────
//
// `ProjectionState::apply()` used to be a 30-arm `match` on
// `canonical_kind_for_operation`. Each arm delegated to a `self.apply_*`
// helper, sometimes with extra carrier args (the lifecycle enums, the
// raw kind string for `apply_realm_lifecycle`, the HLC for relations).
//
// This registry keeps the dispatch table out of the match: every
// canonical event_kind maps to a single `ApplyFn` adapter that calls
// the corresponding `apply_*` helper with the per-kind extra args
// baked in. `apply()` becomes a HashMap lookup + indirect call, with
// the "unknown kind → ProjectionEffect::Ignored" tolerance preserved
// in the fallthrough.

/// Adapter signature for entries in [`default_apply_registry`].
pub type ApplyFn = fn(&mut ProjectionState, &Operation, &ServerHlc) -> ProjectionEffect;

fn apply_message_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_message(op, op.created_at)
}
fn apply_message_revise_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_message_revise(op, op.created_at)
}
fn apply_redaction_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_redaction(op)
}
fn apply_reaction_add_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_reaction_add(op, op.created_at)
}
fn apply_reaction_remove_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_reaction_remove(op)
}
fn apply_rsvp_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_rsvp_set(op, op.created_at)
}
fn apply_pin_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_pin(op, op.created_at)
}
fn apply_read_cursor_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_read_cursor(op, op.created_at)
}
fn apply_relation_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_create(op, op.created_at)
}
fn apply_relation_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_update(op, op.created_at, hlc)
}
fn apply_relation_delete_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_delete(op)
}
fn apply_container_position_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_container_position(op, op.created_at)
}
fn apply_membership_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_membership(op, op.created_at)
}
fn apply_invite_third_party_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_invite_third_party(op, op.created_at)
}
fn apply_invite_claim_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_invite_claim(op, op.created_at)
}
fn apply_key_backup_active_series_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_key_backup_active_series(op)
}
fn apply_realm_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, cokret_sdk::events::kinds::REALM_CREATE)
}
fn apply_realm_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, cokret_sdk::events::kinds::REALM_UPDATE)
}
fn apply_realm_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, cokret_sdk::events::kinds::REALM_ARCHIVE)
}
fn apply_realm_freeze_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, cokret_sdk::events::kinds::REALM_FREEZE)
}
fn apply_realm_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(
        op,
        op.created_at,
        cokret_sdk::events::kinds::REALM_TOMBSTONE,
    )
}
fn apply_realm_destroy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, cokret_sdk::events::kinds::REALM_DESTROY)
}
fn apply_realm_set_default_strand_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_set_default_strand(op, op.created_at)
}
fn apply_erasure_receipt_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_audit_erasure_receipt(op, op.created_at)
}
fn apply_conflict_repair_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_conflict_repair(op, op.created_at)
}
fn apply_space_container_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_create(op, op.created_at)
}
fn apply_space_container_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_update(op, op.created_at)
}
fn apply_space_container_parent_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_parent(op, op.created_at)
}
fn apply_space_container_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Archive,
    )
}
fn apply_space_container_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Restore,
    )
}
fn apply_space_container_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Tombstone,
    )
}
fn apply_strand_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_create(op, op.created_at)
}
fn apply_strand_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_update(op, op.created_at)
}
fn apply_strand_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_lifecycle(op, op.created_at, ObjectLifecycleTransition::Archive)
}
fn apply_strand_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_lifecycle(op, op.created_at, ObjectLifecycleTransition::Restore)
}
fn apply_strand_position_touch_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_position_touch(op, op.created_at)
}
fn apply_strand_watch_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_watch_set(op, op.created_at)
}
fn apply_strand_track_touch_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_track_touch(op, op.created_at)
}

fn apply_morph_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_create(op, op.created_at)
}
fn apply_morph_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_update(op, op.created_at)
}
fn apply_morph_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_lifecycle(op, op.created_at, ObjectLifecycleTransition::Archive)
}
fn apply_morph_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_lifecycle(op, op.created_at, ObjectLifecycleTransition::Restore)
}

// CKP-0007 — Circle dispatch wrappers.
fn apply_circle_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_create(op, op.created_at)
}
fn apply_circle_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_update(op, op.created_at)
}
fn apply_circle_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Archived)
}
fn apply_circle_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Active)
}
fn apply_circle_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Tombstoned)
}
fn apply_circle_member_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_member_state(op, op.created_at)
}

fn apply_applet_registration_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_applet_registration(op, op.created_at)
}
fn apply_applet_discovery_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_applet_discovery(op, op.created_at)
}
fn apply_agent_endpoint_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_endpoint(op, op.created_at)
}

// REDU-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — FSM-lattice
// dispatch for `ck.agent.{pause,resume,deactivate}`. Bottom = `Reject`;
// `Deactivated` is terminal (no transition out, no resume after).
fn apply_agent_pause_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Paused)
}
fn apply_agent_resume_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Active)
}
fn apply_agent_deactivate_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Deactivated)
}

/// CKP-0008 §4.5 / D3 — dispatch for `ck.agent.key.authorize`. Records the
/// authorized key and clears `effective_after_first_authorized_key` on the
/// agent's pending capability grants.
fn apply_agent_key_authorize_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_key_authorize(op)
}

/// CKP-0008 §4.11 — dispatch for `ck.agent.key.revoke`.
fn apply_agent_key_revoke_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_key_revoke(op)
}

// REDU-2 — actor_private_event dispatchers. `reducer_input=false`: do
// NOT advance the seal frontier / actor_seq. Wire-accepted only;
// projection consumers (sodmin draft inbox, action approval queue) read
// them through the audit log. TODO(R3.1): persist into per-actor
// private projections and surface to the controller.
fn apply_agent_draft_propose_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::AgentPrivateEventAccepted {
        kind: cokret_sdk::events::kinds::AGENT_DRAFT_PROPOSE,
        event_id: op.operation_id.to_string(),
    }
}
fn apply_agent_action_request_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_action_request(op)
}
fn apply_agent_action_approve_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_action_resolution(op, AgentActionRequestStatus::Approved)
}
fn apply_agent_action_reject_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_action_resolution(op, AgentActionRequestStatus::Rejected)
}
/// MID-1..6 (R3.1/R3.2, cokret-spec @ b56cab1) — reducer-side dispatch for
/// `ck.member.identity.update`. The full ordered-log projection +
/// per-actor effective-set / `member_display_state_digest` materialization
/// happens on `AppState::member_identity` (see
/// `routing::events::projection::project_member_identity_update`);
/// `ProjectionState` itself doesn't hold a MemberIdentity facet, so this
/// dispatcher only emits the lifecycle effect.
fn apply_member_identity_update_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let realm_id = op
        .payload
        .get("realm_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let actor_id = op
        .payload
        .get("actor_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let segment = op
        .payload
        .get("segment")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if realm_id.is_empty() || actor_id.is_empty() || segment.is_empty() {
        return ProjectionEffect::Rejected {
            reason: "member_identity_update_missing_subject".to_owned(),
        };
    }
    if segment != "member_identity" {
        return ProjectionEffect::Rejected {
            reason: crate::error::reasons::MEMBER_IDENTITY_UNKNOWN_SEGMENT.to_owned(),
        };
    }
    ProjectionEffect::MemberIdentityProjected {
        realm_id,
        actor_id,
        segment,
        event_id: op.operation_id.to_string(),
    }
}

/// Dispatch for `ck.realm.delivery_binding_policy`; cell family is
/// `ck.component.realm.delivery_binding_policy.v1`.
fn apply_delivery_binding_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_delivery_binding_policy(op)
}

/// Dispatch for `ck.realm.policy_components`; cell family is
/// `ck.component.realm.policy_components.v1`.
fn apply_realm_policy_components_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_policy_components(op)
}

fn apply_realm_disappearing_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_disappearing_policy(op)
}

fn apply_realm_search_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_search_policy(op)
}

/// Dispatch for `ck.realm.media_service`; cell family is
/// `ck.component.realm.media_service.v1`.
fn apply_realm_media_service_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_media_service(op)
}

/// Dispatch for `ck.call.state`; cell family is
/// `ck.component.call.state.v1` (`cell_subject = payload.call_id`).
fn apply_call_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_state(op)
}

/// Dispatch for `ck.call.summary`; cell family is
/// `ck.component.call.summary.v1` (`cell_subject = payload.call_id`,
/// cas_register, write-once).
fn apply_call_summary_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_summary(op)
}

/// R3.1 — dispatch for `ck.realm.link`. Projects the typed link payload
/// into the `ck.component.realm.link.v1` or_set cell + structured
/// `realm_links` / `realm_links_inbound` caches.
fn apply_realm_link_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_link(op, op.created_at)
}

/// R3.2 — dispatch for `ck.realm.inheritance_policy`. Projects the
/// cas-register cell + structured cache; validates parent grant bounds
/// when the relevant parent grant cells are available.
fn apply_realm_inheritance_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_inheritance_policy(op, op.created_at)
}

/// R3.2 — dispatch for `ck.capability.derived`. Projects the cas-
/// register cell + structured cache after reducer-side derive evaluation.
fn apply_capability_derived_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_derived(op, op.created_at)
}

/// P1 — dispatch for `ck.capability.grant`. Projects the grant snapshot as
/// an or_set add into the `ck.component.capability.grant.v1` cell keyed by
/// `payload.grant_id`.
fn apply_capability_grant_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_grant(op, op.created_at)
}

/// P1 — dispatch for `ck.capability.revoke`. Projects an observed-remove on
/// the target grant cell (capabilities.md §12 / §12.1).
fn apply_capability_revoke_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_revoke(op, op.created_at)
}

/// P1 — dispatch for `ck.capability.delegate`. Projects into the delegate
/// cell + parent grant chain.
fn apply_capability_delegate_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_delegate(op, op.created_at)
}

/// P2 — dispatch for `ck.moderation.decision`. Projects the decision snapshot
/// as an or_set add into the `ck.component.moderation_state.v1` cell keyed by
/// `payload.target_ref`.
fn apply_moderation_decision_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision(op, op.created_at)
}

/// P2 — dispatch for `ck.moderation.decision.lift`. Projects an observed-
/// remove / supersede on the moderation_state target cell, marking the
/// `payload.decision_ref` decision lifted.
fn apply_moderation_decision_lift_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision_lift(op, op.created_at)
}

/// P2 — dispatch for `ck.moderation.appeal.{submit,review,decision,close}`.
/// Resolves the target FSM state from the canonical kind and projects the
/// transition (with §5.5.2 reducer constraints) onto the appeal cell.
fn apply_moderation_appeal_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let Some(kind) = crate::kinds::canonical_kind_for_operation(op) else {
        return ProjectionEffect::Ignored;
    };
    let Some(target_state) = apply_moderation::appeal_target_state(kind) else {
        return ProjectionEffect::Rejected {
            reason: "moderation_appeal_kind_unknown".to_owned(),
        };
    };
    s.apply_moderation_appeal(op, target_state)
}

// ── G3.S1: MLS lifecycle dispatch adapters ────────────────────────────
//
// Each adapter forwards to the free function in `reducer::mls`. The
// inline `ProjectionState` impls stay out of `reducer.rs` so the MLS
// module can grow independently (see top-level `pub mod mls;`).
//
// Canonical event kinds per
// `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`: a single
// `ck.mls.keypackage` kind covers both publish and claim. The reducer
// dispatches on `payload.action == "publish" | "claim"` (the publish-
// vs-claim split lives at the HTTP operation_id layer:
// `ck.self.keys.keypackages.upload.create` vs `ck.self.keys.keypackages.command.claim`).

fn apply_mls_keypackage_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    match op.payload.get("action").and_then(Value::as_str) {
        Some("publish") => mls::apply_keypackage_publish(s, op),
        Some("claim") => mls::apply_keypackage_claim(s, op),
        Some(other) => ProjectionEffect::Rejected {
            reason: format!("mls_keypackage_action_unknown:{other}"),
        },
        None => ProjectionEffect::Rejected {
            reason: "mls_keypackage_action_missing".to_owned(),
        },
    }
}

fn apply_mls_welcome_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_welcome_enqueue(s, op)
}

fn apply_mls_genesis_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_group_genesis(s, op)
}

fn apply_mls_commit_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_commit_epoch(s, op)
}

fn apply_realm_key_share_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_key_share(op)
}

// G3.S2: dispatch adapter for `ck.realm.policy_server`. The reducer
// helper lives in the dedicated `reducer::realm_policy_server` module;
// this adapter normalises its `(state, op) -> effect` signature to the
// registry's `(state, op, hlc) -> effect` shape.
fn apply_realm_policy_server_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    crate::reducer::realm_policy_server::apply_realm_policy_server(s, op)
}

fn apply_device_push_route_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_device_push_route(op)
}

/// Build the canonical `event_kind → ApplyFn` registry consumed by
/// [`super::ProjectionState::apply`]. Public so out-of-crate tests can assert
/// the registry covers every canonical kind they care about.
pub fn default_apply_registry() -> std::collections::HashMap<&'static str, ApplyFn> {
    use crate::kinds::*;
    let mut m: std::collections::HashMap<&'static str, ApplyFn> =
        std::collections::HashMap::with_capacity(40);
    m.insert(
        cokret_sdk::events::kinds::MESSAGE_CREATE,
        apply_message_dispatch as ApplyFn,
    );
    m.insert(
        cokret_sdk::events::kinds::MESSAGE_REVISE,
        apply_message_revise_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MESSAGE_REDACT,
        apply_redaction_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REDACTION,
        apply_redaction_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REACTION_ADD,
        apply_reaction_add_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REACTION_REMOVE,
        apply_reaction_remove_dispatch,
    );
    m.insert(cokret_sdk::events::kinds::RSVP_SET, apply_rsvp_set_dispatch);
    m.insert(cokret_sdk::events::kinds::PIN_ADD, apply_pin_dispatch);
    m.insert(cokret_sdk::events::kinds::PIN_REMOVE, apply_pin_dispatch);
    m.insert(cokret_sdk::events::kinds::PIN_REORDER, apply_pin_dispatch);
    m.insert(
        cokret_sdk::events::kinds::READ_CURSOR_ADVANCE,
        apply_read_cursor_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::RELATION_CREATE,
        apply_relation_create_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::RELATION_UPDATE,
        apply_relation_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::RELATION_TOMBSTONE,
        apply_relation_delete_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CONTAINER_MOVE_ITEM,
        apply_container_position_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CONTAINER_REBALANCE,
        apply_container_position_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MEMBER_STATE,
        apply_membership_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::INVITE_THIRD_PARTY,
        apply_invite_third_party_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::INVITE_CLAIM,
        apply_invite_claim_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::KEY_BACKUP_ACTIVE_SERIES,
        apply_key_backup_active_series_dispatch,
    );
    // MID-1..6 (R3.1/R3.2 spec-sync, cokret-spec @ b56cab1) —
    // `ck.member.identity.update`. Cell family
    // `ck.component.member.identity.v1`, lattice `ordered_log`, bottom
    // `expose`. The ordered-log projection (effective-set filter,
    // member_display_state_digest materialization) lives on
    // `AppState::member_identity`
    // (see `routing::events::projection::project_member_identity_update`)
    // because it spans cells; the in-process reducer just records that
    // the event was accepted so subscribers observe the lifecycle effect.
    m.insert(
        cokret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE,
        apply_member_identity_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_CREATE,
        apply_realm_create_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_UPDATE,
        apply_realm_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_ARCHIVE,
        apply_realm_archive_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_FREEZE,
        apply_realm_freeze_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_TOMBSTONE,
        apply_realm_tombstone_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_DESTROY,
        apply_realm_destroy_dispatch,
    );
    // COT-06-004 — Realm default-Strand pointer.
    m.insert(
        cokret_sdk::events::kinds::REALM_SET_DEFAULT_STRAND,
        apply_realm_set_default_strand_dispatch,
    );
    m.insert(CONFLICT_REPAIR, apply_conflict_repair_dispatch);
    m.insert(
        cokret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT,
        apply_erasure_receipt_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::SPACE_CREATE,
        apply_space_container_create_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::SPACE_UPDATE,
        apply_space_container_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::SPACE_PARENT,
        apply_space_container_parent_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::SPACE_ARCHIVE,
        apply_space_container_archive_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::SPACE_RESTORE,
        apply_space_container_restore_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::SPACE_TOMBSTONE,
        apply_space_container_tombstone_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_CREATE,
        apply_strand_create_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_UPDATE,
        apply_strand_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_ARCHIVE,
        apply_strand_archive_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_RESTORE,
        apply_strand_restore_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_MOVE,
        apply_strand_position_touch_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_REORDER,
        apply_strand_position_touch_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::STRAND_WATCH_SET,
        apply_strand_watch_set_dispatch,
    );
    // Unified tracks patch. Payload-shape validation (presence of `tracks`
    // patch map) lives in the wire validator. TODO: apply patch ops
    // against soland-side Strand.tracks projection once the server-side
    // projection carries the tracks map.
    m.insert(
        cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE,
        apply_strand_track_touch_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MORPH_CREATE,
        apply_morph_create_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MORPH_UPDATE,
        apply_morph_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MORPH_ARCHIVE,
        apply_morph_archive_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MORPH_RESTORE,
        apply_morph_restore_dispatch,
    );
    // CKP-0007 — Circle lifecycle / membership dispatch. The seventh
    // active kind, `ck.circle.seal_commit`, is reducer-derived (sub-
    // seal on the Circle's profile cadence) and listed in the SDK's
    // `NON_REDUCER_EVENT_KINDS` set, so no dispatch entry is added for
    // it here.
    m.insert(
        cokret_sdk::events::kinds::CIRCLE_CREATE,
        apply_circle_create_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CIRCLE_UPDATE,
        apply_circle_update_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CIRCLE_ARCHIVE,
        apply_circle_archive_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CIRCLE_RESTORE,
        apply_circle_restore_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CIRCLE_TOMBSTONE,
        apply_circle_tombstone_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
        apply_circle_member_state_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::APPLET_REGISTRATION,
        apply_applet_registration_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::APPLET_DISCOVERY,
        apply_applet_discovery_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_ENDPOINT,
        apply_agent_endpoint_dispatch,
    );
    // REDU-1 (R3 spec-sync) — agent lifecycle FSM dispatch. bottom=reject,
    // deactivate is terminal.
    m.insert(
        cokret_sdk::events::kinds::AGENT_PAUSE,
        apply_agent_pause_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_RESUME,
        apply_agent_resume_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_DEACTIVATE,
        apply_agent_deactivate_dispatch,
    );
    // REDU-2 — actor_private_event kinds (reducer_input=false). These
    // accept but do NOT advance the seal frontier / actor_seq;
    // downstream consumers read them from the audit log.
    m.insert(
        cokret_sdk::events::kinds::AGENT_DRAFT_PROPOSE,
        apply_agent_draft_propose_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_ACTION_REQUEST,
        apply_agent_action_request_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_ACTION_APPROVE,
        apply_agent_action_approve_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_ACTION_REJECT,
        apply_agent_action_reject_dispatch,
    );
    // delivery_binding_policy is Realm-scoped with cell_family
    // `ck.component.realm.delivery_binding_policy.v1`.
    m.insert(
        cokret_sdk::events::kinds::REALM_DELIVERY_BINDING_POLICY,
        apply_delivery_binding_policy_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
        apply_realm_policy_components_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_DISAPPEARING_POLICY,
        apply_realm_disappearing_policy_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_SEARCH_POLICY,
        apply_realm_search_policy_dispatch,
    );
    // media_service is Realm-scoped with cell_family
    // `ck.component.realm.media_service.v1`; consumed by the CKP-0010
    // media token exchange in `routing::interop::webrtc`.
    m.insert(
        cokret_sdk::events::kinds::REALM_MEDIA_SERVICE,
        apply_realm_media_service_dispatch,
    );
    // `ck.call.state` — durable call lifecycle + recording/transcribe/
    // moderation projection. Cell family `ck.component.call.state.v1`,
    // `cell_subject = payload.call_id` (`call-state.md` §4.2 / §5).
    m.insert(
        cokret_sdk::events::kinds::CALL_STATE,
        apply_call_state_dispatch,
    );
    // `ck.call.summary` — durable terminal summary projection. Cell family
    // `ck.component.call.summary.v1`, write-once cas_register (`call-state.md`
    // §7).
    m.insert(
        cokret_sdk::events::kinds::CALL_SUMMARY,
        apply_call_summary_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::DEVICE_PUSH_ROUTE,
        apply_device_push_route_dispatch,
    );
    // R3.1 / R3.2 / R3.3 — Realm-governance event kinds. Each writes a
    // cell + a structured side-band cache; see the per-kind apply
    // helpers for cell-family naming.
    m.insert(
        cokret_sdk::events::kinds::REALM_LINK,
        apply_realm_link_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_INHERITANCE_POLICY,
        apply_realm_inheritance_policy_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CAPABILITY_DERIVED,
        apply_capability_derived_dispatch,
    );
    // P1 — capability control-plane projection (grant / revoke / delegate).
    // grant + revoke share the `ck.component.capability.grant.v1` or_set
    // cell; delegate writes `ck.component.capability.delegate.v1` + parent
    // chain. Acceptance fail-closed lives in `apply_capability.rs`.
    m.insert(
        cokret_sdk::events::kinds::CAPABILITY_GRANT,
        apply_capability_grant_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CAPABILITY_REVOKE,
        apply_capability_revoke_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::CAPABILITY_DELEGATE,
        apply_capability_delegate_dispatch,
    );
    // CKP-0008 §4.5 / §4.11 / D3 — agent runtime key authorization +
    // revocation. authorize records the key and clears the agent's pending
    // `effective_after_first_authorized_key` grants; revoke removes the key.
    m.insert(
        cokret_sdk::events::kinds::AGENT_KEY_AUTHORIZE,
        apply_agent_key_authorize_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::AGENT_KEY_REVOKE,
        apply_agent_key_revoke_dispatch,
    );
    // P2 — moderation control-plane projection (decision / lift / appeal.*).
    // decision + lift share the `ck.component.moderation_state.v1` or_set
    // cell; the four appeal kinds drive the `ck.component.moderation.appeal.v1`
    // fsm cell. §5.5.2 reducer constraints + acceptance fail-closed live in
    // `apply_moderation.rs`.
    m.insert(
        cokret_sdk::events::kinds::MODERATION_DECISION,
        apply_moderation_decision_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MODERATION_DECISION_LIFT,
        apply_moderation_decision_lift_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT,
        apply_moderation_appeal_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MODERATION_APPEAL_REVIEW,
        apply_moderation_appeal_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MODERATION_APPEAL_DECISION,
        apply_moderation_appeal_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MODERATION_APPEAL_CLOSE,
        apply_moderation_appeal_dispatch,
    );
    // G3.S1: MLS lifecycle. KeyPackage publish/claim (atomic CAS),
    // Welcome to-device persistence, commit monotonic-epoch bump, and
    // governance covered_seals accumulation.
    // Canonical event kinds — the publish/claim distinction lives at the
    // HTTP operation_id layer and is conveyed inside the kind's payload
    // via `action ∈ {"publish","claim"}`; the event log itself stores
    // only the canonical `ck.mls.keypackage` kind.
    // Deferred (TODO(G3.S1-followup)): decryption_pending. See
    // `reducer/mls.rs`.
    m.insert(
        cokret_sdk::events::kinds::MLS_KEYPACKAGE,
        apply_mls_keypackage_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MLS_WELCOME,
        apply_mls_welcome_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MLS_GENESIS,
        apply_mls_genesis_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::MLS_COMMIT,
        apply_mls_commit_dispatch,
    );
    m.insert(
        cokret_sdk::events::kinds::REALM_KEY_SHARE,
        apply_realm_key_share_dispatch,
    );
    // G3.S2: policy server cell
    m.insert(
        cokret_sdk::events::kinds::REALM_POLICY_SERVER,
        apply_realm_policy_server_dispatch,
    );
    m
}

pub(crate) static APPLY_REGISTRY: std::sync::LazyLock<
    std::collections::HashMap<&'static str, ApplyFn>,
> = std::sync::LazyLock::new(default_apply_registry);
