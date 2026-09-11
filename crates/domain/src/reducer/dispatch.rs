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
//! type, and the realm-link helpers are re-exported there so
//! the `crate::reducer::*` paths and sibling `super::*` access stay
//! unchanged.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_wire::EventKind;
use serde_json::Value;

use super::{
    CircleLifecycleState, ObjectLifecycleTransition, ProjectionEffect, ProjectionState,
    RealmLinkState, SpaceContainerLifecycleTransition, mls,
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
// baked in. `apply()` becomes a typed HashMap lookup + indirect call.
// Every active reducer-input kind is present: kinds without a local
// structured projection use the explicit no-op adapter, while unknown kinds
// remain fail-closed before lookup.

fn projection_received_at(op: &Operation) -> chrono::DateTime<chrono::Utc> {
    op.payload
        .get("event_received_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or(op.created_at)
}

/// Adapter signature for entries in [`default_apply_registry`].
pub type ApplyFn = fn(&mut ProjectionState, &Operation, &ServerHlc) -> ProjectionEffect;

fn apply_noop_dispatch(
    _state: &mut ProjectionState,
    _operation: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::Ignored
}

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
fn apply_container_move_item_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_container_move_item(op)
}
fn apply_container_rebalance_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_container_rebalance(op)
}
fn apply_membership_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_membership(op, projection_received_at(op))
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
fn apply_invite_create_dispatch(
    _s: &mut ProjectionState,
    _op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::Ignored
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
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmCreate)
}
fn apply_identity_resolution_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_identity_resolution_update(op)
}
fn apply_realm_profile_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmProfile)
}
fn apply_realm_upgrade_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_upgrade(op)
}
fn apply_realm_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmArchive)
}
fn apply_realm_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmRestore)
}
fn apply_realm_freeze_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmFreeze)
}
fn apply_realm_unfreeze_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmUnfreeze)
}
fn apply_realm_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmTombstone)
}
fn apply_realm_destroy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, arkret_wire::EventKind::RealmDestroy)
}
fn apply_realm_owner_transfer_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_authority_transition(op, arkret_wire::EventKind::RealmOwnerTransfer)
}
fn apply_realm_authority_reset_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_authority_transition(op, arkret_wire::EventKind::RealmAuthorityReset)
}
fn apply_realm_set_default_strand_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_set_default_strand(op, op.created_at)
}
fn apply_realm_notary_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_notary(op)
}
fn apply_realm_digest_suite_transition_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_digest_suite_transition(op)
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
fn apply_strand_stage_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_strand_stage_set(op, op.created_at)
}
fn apply_morph_stage_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_stage_set(op, op.created_at)
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
// AKP-0007 — Circle dispatch wrappers.
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
    s.apply_circle_member_state(op, projection_received_at(op))
}

fn apply_realm_history_access_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_history_access(op)
}

fn apply_circle_history_access_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_history_access(op)
}

fn apply_sidecar_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_sidecar_create(op)
}

fn apply_sidecar_context_attach_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_sidecar_context_attach(op)
}

fn apply_sidecar_exchange_control_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_sidecar_exchange_control(op)
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

// REDU-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — FSM-lattice
// dispatch for `ak.agent.{pause,resume,deactivate}`. Bottom = `Reject`;
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

/// Dispatch for `ak.agent.key.authorize`. Pairing records the authorized key
/// without changing independent Realm grants.
fn apply_agent_key_authorize_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_key_authorize(op)
}

/// AKP-0008 §4.11 — dispatch for `ak.agent.key.revoke`.
fn apply_agent_key_revoke_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_key_revoke(op)
}

/// MID-1..6 (R3.1/R3.2, arkret-spec @ b56cab1) — reducer-side dispatch for
/// `ak.member.identity.update`. The full ordered-log projection +
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
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        .map(|actor| actor.to_string())
        .unwrap_or_default();
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
            reason: arkret_wire::ReasonCode::MEMBER_IDENTITY_UNKNOWN_SEGMENT.to_owned(),
        };
    }
    ProjectionEffect::MemberIdentityProjected {
        realm_id,
        actor_id,
        segment,
        event_id: op.operation_id.to_string(),
    }
}

/// Dispatch for `ak.realm.policy_bundle`; cell family is
/// `ak.component.realm.policy_bundle.v1`.
fn apply_realm_policy_bundle_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_policy_bundle(op)
}

fn apply_realm_search_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_search_policy(op)
}

/// Dispatch for `ak.realm.media_service`; cell family is
/// `ak.component.realm.media_service.v1`.
fn apply_realm_media_service_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_media_service(op)
}

/// Dispatch for `ak.call.create`; CallId is derived from the accepted Event.
fn apply_call_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_create(op)
}

fn apply_audit_binding_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_audit_binding_create(op)
}

fn apply_audit_binding_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_audit_binding_state(op)
}

fn apply_audit_session_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_audit_session(op)
}

fn apply_audit_release_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_audit_release(op)
}

/// Dispatch for `ak.call.state`; cell family is
/// `ak.component.call.state.v1` (`cell_subject = payload.call_id`).
fn apply_call_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_state(op)
}

fn apply_call_recording_start_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_recording_start(op)
}

/// Dispatch for `ak.call.summary`; cell family is
/// `ak.component.call.summary.v1` (`cell_subject = payload.call_id`,
/// cas_register, write-once).
fn apply_call_summary_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_call_summary(op)
}

/// R3.1 — dispatch for `ak.realm.link`. Projects the typed link payload
/// into the `ak.component.realm.link.v1` FSM cell + structured
/// `realm_links` / `realm_links_inbound` caches.
fn apply_realm_link_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_link(op, op.created_at)
}

/// SOL-ORG-02 — dispatch for `ak.realm.organization`. Projects the
/// organization-authorized Realm relationship statement (cas-register cell
/// keyed by `(organization_id, relationship)` + structured cache) after the
/// SDK organization-side verifier passes.
fn apply_realm_organization_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_organization(op, op.created_at)
}

/// R3.2 — dispatch for `ak.realm.inheritance_policy`. Projects the
/// cas-register cell + structured cache; validates parent grant bounds
/// when the relevant parent grant cells are available.
fn apply_realm_inheritance_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_inheritance_policy(op, op.created_at)
}

/// R3.2 — dispatch for `ak.capability.derived`. Projects the OR-set cell
/// and structured cache after reducer-side derive evaluation.
fn apply_capability_derived_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_derived(op, op.created_at)
}

/// P1 — dispatch for `ak.capability.grant`. Projects the grant snapshot as
/// an or_set add into the `ak.component.capability.grant.v1` cell keyed by
/// the Event-derived GrantId.
fn apply_capability_grant_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_grant(op, op.created_at)
}

/// P1 — dispatch for `ak.capability.revoke`. Projects an observed-remove on
/// the target grant cell (capabilities.md §12 / §12.1).
fn apply_capability_revoke_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_revoke(op, op.created_at)
}

fn apply_capability_relinquish_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_relinquish(op, op.created_at)
}

/// P2 — dispatch for `ak.moderation.decision`. Projects the decision snapshot
/// as an or_set add into the `ak.component.moderation_state.v1` cell keyed by
/// `payload.target_ref`.
fn apply_moderation_decision_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision(op)
}

/// P2 — dispatch for `ak.moderation.decision.lift`. Projects an observed-
/// remove / supersede on the moderation_state target cell, marking the
/// `payload.decision_ref` decision lifted.
fn apply_moderation_decision_lift_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision_lift(op, op.created_at)
}

// ── G3.S1: MLS lifecycle dispatch adapters ────────────────────────────
//
// Each adapter forwards to the free function in `reducer::mls`. The
// inline `ProjectionState` impls stay out of `reducer.rs` so the MLS
// module can grow independently (see top-level `pub mod mls;`).
//
// Canonical event kinds per
// `arkret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`: a single
// `ak.mls.keypackage` kind covers both publish and claim. The reducer
// dispatches on `payload.action == "publish" | "claim"` (the publish-
// vs-claim split lives at the HTTP operation_id layer:
// `ak.self.keys.keypackages.upload.create.v1` vs `ak.self.keys.keypackages.command.claim.v1`).

fn apply_mls_keypackage_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    match op.payload.get("action").and_then(Value::as_str) {
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

fn apply_mls_proposal_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_remove_proposal(s, op)
}

fn apply_mls_commit_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_commit_epoch(s, op)
}

/// Build the canonical `event_kind → ApplyFn` registry consumed by
/// [`super::ProjectionState::apply`]. Public so out-of-crate tests can assert
/// exact coverage of the active reducer-input set.
pub fn default_apply_registry() -> std::collections::HashMap<EventKind, ApplyFn> {
    let mut m: std::collections::HashMap<EventKind, ApplyFn> =
        std::collections::HashMap::with_capacity(EventKind::ALL.len());
    m.insert(
        arkret_wire::EventKind::MessageCreate,
        apply_message_dispatch as ApplyFn,
    );
    m.insert(
        arkret_wire::EventKind::MessageRevise,
        apply_message_revise_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MessageRedact,
        apply_redaction_dispatch,
    );
    m.insert(arkret_wire::EventKind::Redaction, apply_redaction_dispatch);
    m.insert(
        arkret_wire::EventKind::ReactionAdd,
        apply_reaction_add_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::ReactionRemove,
        apply_reaction_remove_dispatch,
    );
    m.insert(arkret_wire::EventKind::RsvpSet, apply_rsvp_set_dispatch);
    m.insert(arkret_wire::EventKind::PinAdd, apply_pin_dispatch);
    m.insert(arkret_wire::EventKind::PinRemove, apply_pin_dispatch);
    m.insert(arkret_wire::EventKind::PinReorder, apply_pin_dispatch);
    m.insert(
        arkret_wire::EventKind::RelationCreate,
        apply_relation_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RelationUpdate,
        apply_relation_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RelationTombstone,
        apply_relation_delete_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::ContainerMoveItem,
        apply_container_move_item_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::ContainerRebalance,
        apply_container_rebalance_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MemberState,
        apply_membership_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::InviteThirdParty,
        apply_invite_third_party_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::InviteClaim,
        apply_invite_claim_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::InviteCreate,
        apply_invite_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::KeyBackupActiveSeries,
        apply_key_backup_active_series_dispatch,
    );
    // MID-1..6 (R3.1/R3.2 spec-sync, arkret-spec @ b56cab1) —
    // `ak.member.identity.update`. Cell family
    // `ak.component.member.identity.v1`, lattice `ordered_log`, bottom
    // `expose`. The ordered-log projection (effective-set filter,
    // member_display_state_digest materialization) lives on
    // `AppState::member_identity`
    // (see `routing::events::projection::project_member_identity_update`)
    // because it spans cells; the in-process reducer just records that
    // the event was accepted so subscribers observe the lifecycle effect.
    m.insert(
        arkret_wire::EventKind::MemberIdentityUpdate,
        apply_member_identity_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmCreate,
        apply_realm_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmHistoryAccess,
        apply_realm_history_access_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::IdentityResolutionUpdate,
        apply_identity_resolution_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmProfile,
        apply_realm_profile_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmUpgrade,
        apply_realm_upgrade_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmArchive,
        apply_realm_archive_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmRestore,
        apply_realm_restore_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmFreeze,
        apply_realm_freeze_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmUnfreeze,
        apply_realm_unfreeze_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmTombstone,
        apply_realm_tombstone_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmDestroy,
        apply_realm_destroy_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmOwnerTransfer,
        apply_realm_owner_transfer_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmAuthorityReset,
        apply_realm_authority_reset_dispatch,
    );
    // COT-06-004 — Realm default-Strand pointer.
    m.insert(
        arkret_wire::EventKind::RealmSetDefaultStrand,
        apply_realm_set_default_strand_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmNotary,
        apply_realm_notary_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmDigestSuiteTransition,
        apply_realm_digest_suite_transition_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SpaceCreate,
        apply_space_container_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SpaceUpdate,
        apply_space_container_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SpaceParent,
        apply_space_container_parent_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SpaceArchive,
        apply_space_container_archive_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SpaceRestore,
        apply_space_container_restore_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SpaceTombstone,
        apply_space_container_tombstone_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandCreate,
        apply_strand_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandUpdate,
        apply_strand_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandArchive,
        apply_strand_archive_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandRestore,
        apply_strand_restore_dispatch,
    );
    // `common-fields.md` §5.3 — the business-progression axis. Its own event
    // kind exists for capability slicing and audit filtering, so it needs its
    // own reducer arm: `ak.strand.update` patches on `stage` /
    // `stage_changed_at` are forbidden wire.
    m.insert(
        arkret_wire::EventKind::StrandStageSet,
        apply_strand_stage_set_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandMove,
        apply_strand_position_touch_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandReorder,
        apply_strand_position_touch_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::StrandWatchSet,
        apply_strand_watch_set_dispatch,
    );
    // Unified tracks patch. Payload-shape validation (presence of `tracks`
    // patch map) lives in the wire validator. TODO: apply patch ops
    // against soland-side Strand.tracks projection once the server-side
    // projection carries the tracks map.
    m.insert(
        arkret_wire::EventKind::StrandTracksUpdate,
        apply_strand_track_touch_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MorphCreate,
        apply_morph_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MorphUpdate,
        apply_morph_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MorphArchive,
        apply_morph_archive_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MorphRestore,
        apply_morph_restore_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MorphStageSet,
        apply_morph_stage_set_dispatch,
    );
    // AKP-0007 — Circle lifecycle / membership dispatch. The seventh
    // active kind, `ak.circle.seal_commit`, is reducer-derived (sub-
    // seal on the Circle's profile cadence) and listed in the SDK's
    // `NON_REDUCER_EVENT_KINDS` set, so no dispatch entry is added for
    // it here.
    m.insert(
        arkret_wire::EventKind::CircleCreate,
        apply_circle_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CircleUpdate,
        apply_circle_update_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CircleArchive,
        apply_circle_archive_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CircleRestore,
        apply_circle_restore_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CircleTombstone,
        apply_circle_tombstone_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CircleMemberState,
        apply_circle_member_state_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CircleHistoryAccess,
        apply_circle_history_access_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SidecarCreate,
        apply_sidecar_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SidecarContextAttach,
        apply_sidecar_context_attach_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AgentSidecarExchangeControl,
        apply_sidecar_exchange_control_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AppletRegistration,
        apply_applet_registration_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AppletDiscovery,
        apply_applet_discovery_dispatch,
    );
    // REDU-1 (R3 spec-sync) — agent lifecycle FSM dispatch. bottom=reject,
    // deactivate is terminal.
    m.insert(
        arkret_wire::EventKind::SelfAgentPause,
        apply_agent_pause_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SelfAgentResume,
        apply_agent_resume_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::SelfAgentDeactivate,
        apply_agent_deactivate_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmPolicyBundle,
        apply_realm_policy_bundle_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmSearchPolicy,
        apply_realm_search_policy_dispatch,
    );
    // media_service is Realm-scoped with cell_family
    // `ak.component.realm.media_service.v1`; consumed by the AKP-0010
    // media token exchange in `routing::interop::webrtc`.
    m.insert(
        arkret_wire::EventKind::RealmMediaService,
        apply_realm_media_service_dispatch,
    );
    // `ak.call.create` establishes the Event-derived CallId before any
    // signaling or state event may refer to it.
    m.insert(
        arkret_wire::EventKind::CallCreate,
        apply_call_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AuditAppletBindingCreate,
        apply_audit_binding_create_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AuditAppletBindingState,
        apply_audit_binding_state_dispatch,
    );
    // `audited-e2ee.md` sections 3-4 — the sealed release session and its
    // release manifests. Without these the four release gates
    // (binding / scope / notice / non-retroactive) have no evaluation point.
    m.insert(
        arkret_wire::EventKind::AuditSessionRequest,
        apply_audit_session_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AuditSessionAuthorize,
        apply_audit_session_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AuditSessionNotice,
        apply_audit_session_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AuditSessionClose,
        apply_audit_session_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AuditRelease,
        apply_audit_release_dispatch,
    );
    // `ak.call.state` — durable call lifecycle + recording/transcribe/
    // moderation projection. Cell family `ak.component.call.state.v1`,
    // `cell_subject = payload.call_id` (`call-state.md` §4.2 / §5).
    m.insert(arkret_wire::EventKind::CallState, apply_call_state_dispatch);
    m.insert(
        arkret_wire::EventKind::CallRecordingStart,
        apply_call_recording_start_dispatch,
    );
    // `ak.call.summary` — durable terminal summary projection. Cell family
    // `ak.component.call.summary.v1`, write-once cas_register (`call-state.md`
    // §7).
    m.insert(
        arkret_wire::EventKind::CallSummary,
        apply_call_summary_dispatch,
    );
    // R3.1 / R3.2 / R3.3 — Realm-governance event kinds. Each writes a
    // cell + a structured side-band cache; see the per-kind apply
    // helpers for cell-family naming.
    m.insert(arkret_wire::EventKind::RealmLink, apply_realm_link_dispatch);
    // SOL-ORG-02 — organization-authorized Realm relationship statement.
    m.insert(
        arkret_wire::EventKind::RealmOrganization,
        apply_realm_organization_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::RealmInheritancePolicy,
        apply_realm_inheritance_policy_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CapabilityDerived,
        apply_capability_derived_dispatch,
    );
    // Capability control-plane projection. Grant adds to the canonical grant
    // cell; revoke and subject-only relinquish perform observed-remove.
    m.insert(
        arkret_wire::EventKind::CapabilityGrant,
        apply_capability_grant_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CapabilityRevoke,
        apply_capability_revoke_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::CapabilityRelinquish,
        apply_capability_relinquish_dispatch,
    );
    // Agent runtime key authorization + revocation. Authorize records the
    // key; revoke removes it. Neither operation changes Realm grants.
    m.insert(
        arkret_wire::EventKind::AgentKeyAuthorize,
        apply_agent_key_authorize_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::AgentKeyRevoke,
        apply_agent_key_revoke_dispatch,
    );
    // P2 — moderation control-plane projection. Decision + lift share the
    // `ak.component.moderation_state.v1` or_set cell; acceptance fail-closed
    // rules live in `apply_moderation.rs`.
    m.insert(
        arkret_wire::EventKind::ModerationDecision,
        apply_moderation_decision_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::ModerationDecisionLift,
        apply_moderation_decision_lift_dispatch,
    );
    // G3.S1: MLS lifecycle. KeyPackage publish/claim (atomic CAS),
    // Welcome to-device persistence, commit monotonic-epoch bump, and
    // governance binding projection.
    // Canonical event kinds — the publish/claim distinction lives at the
    // HTTP operation_id layer and is conveyed inside the kind's payload
    // via `action ∈ {"publish","claim"}`; the event log itself stores
    // only the canonical `ak.mls.keypackage` kind.
    // Deferred (TODO(G3.S1-followup)): decryption_pending. See
    // `reducer/mls.rs`.
    m.insert(
        arkret_wire::EventKind::MlsKeypackage,
        apply_mls_keypackage_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MlsWelcome,
        apply_mls_welcome_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MlsGenesis,
        apply_mls_genesis_dispatch,
    );
    m.insert(
        arkret_wire::EventKind::MlsProposal,
        apply_mls_proposal_dispatch,
    );
    m.insert(arkret_wire::EventKind::MlsCommit, apply_mls_commit_dispatch);
    for kind in EventKind::ALL.iter().filter(|kind| kind.is_reducer_input()) {
        m.entry(kind.clone()).or_insert(apply_noop_dispatch);
    }
    debug_assert!(m.keys().all(EventKind::is_reducer_input));
    debug_assert_eq!(
        m.len(),
        EventKind::ALL
            .iter()
            .filter(|kind| kind.is_reducer_input())
            .count()
    );
    m
}

pub(crate) static APPLY_REGISTRY: std::sync::LazyLock<
    std::collections::HashMap<EventKind, ApplyFn>,
> = std::sync::LazyLock::new(default_apply_registry);

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use arkret_wire::EventKind;

    use super::default_apply_registry;

    #[test]
    fn member_identity_dispatch_preserves_the_complete_actor() {
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL",
        )
        .unwrap();
        let mut actors = Vec::new();
        for station in [
            "ak:did_core:web:first.example",
            "ak:did_core:web:second.example",
        ] {
            let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new(station).unwrap(),
            ));
            let mut operation = arkret_event_draft::test_support::raw_projected_operation(
                arkret_identifiers::OperationId::new(
                    "ak:operation:01904100-0000-7000-8000-57d7d85564c5",
                )
                .unwrap(),
                realm_id.clone(),
                EventKind::MemberIdentityUpdate.as_str(),
                serde_json::json!({
                    "realm_id": realm_id,
                    "actor_id": actor,
                    "segment": "member_identity",
                }),
            );
            let mut state = super::ProjectionState::default();
            let hlc = super::ServerHlc::new("member-identity-test");
            let super::ProjectionEffect::MemberIdentityProjected { actor_id, .. } =
                super::apply_member_identity_update_dispatch(&mut state, &operation, &hlc)
            else {
                panic!("complete Actor must project")
            };
            assert_eq!(actor_id, actor.to_string());
            actors.push(actor_id);
            operation.payload["actor_id"] = serde_json::json!(actor.signing_principal_id());
            assert!(matches!(
                super::apply_member_identity_update_dispatch(&mut state, &operation, &hlc),
                super::ProjectionEffect::Rejected { .. },
            ));
        }
        assert_ne!(actors[0], actors[1]);
    }

    #[test]
    fn apply_registry_exactly_covers_active_reducer_inputs() {
        let actual = default_apply_registry().into_keys().collect::<HashSet<_>>();
        let expected = EventKind::ALL
            .iter()
            .filter(|kind| kind.is_reducer_input())
            .cloned()
            .collect::<HashSet<_>>();

        assert_eq!(actual, expected);
    }
}
