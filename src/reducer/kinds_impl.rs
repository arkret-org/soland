//! Concrete `ReducerKind` impls for every canonical kind soland projects.
//!
//! Each impl is a stateless ZST (`#[derive(Default)]` zero-sized type)
//! that delegates `project()` to the corresponding `ProjectionState`
//! method. T1-1 phase: zero LOC moves between files. T1-2 will split
//! these into `src/reducer/kinds/<kind>.rs` files.
//!
//! Spec Phase 1-5 stubs (per-facet space kinds, host, consent) are
//! registered here with full subject derivation but a no-op `project`
//! method — T1-3 lands the actual reducer bodies kind-by-kind.

#![allow(missing_docs)]

use contrix_sdk::Operation;

use crate::hlc::ServerHlc;
use crate::kinds;
use crate::reducer::registry::{
    assert_no_legacy_state_key, optional_payload_string, ComponentDescriptor, Criticality,
    ReducerKind, ReducerKindError, StateCardinality,
};
use crate::reducer::{ProjectionEffect, ProjectionState};

// ─────────────────────────────────────────────────────────────────────
// Macro: declare a singleton-cardinality state-event kind whose
// `project` body delegates to a `ProjectionState` method named
// `apply_<delegate>`.
// ─────────────────────────────────────────────────────────────────────
macro_rules! singleton_state_kind {
    (
        $struct:ident,
        kind = $kind:expr,
        component = $component:expr,
        version = $version:expr,
        criticality = $criticality:expr,
        delegate = |$op:ident, $state:ident, $hlc:ident| $body:expr $(,)?
    ) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $struct;
        impl ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> StateCardinality {
                StateCardinality::Singleton
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: $component,
                    component_version: $version,
                    criticality: $criticality,
                }
            }
            fn subject_for_event(
                &self,
                operation: &Operation,
            ) -> Result<Option<String>, ReducerKindError> {
                assert_no_legacy_state_key(operation, $kind)?;
                Ok(None)
            }
            fn project(
                &self,
                $op: &Operation,
                $state: &mut ProjectionState,
                $hlc: &ServerHlc,
            ) -> ProjectionEffect {
                $body
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// Macro: declare a non-state (cardinality::None) operation kind. No
// subject derivation; pure projection mutation. Used for messages,
// reactions, redactions etc. — events that are inputs to non-state
// projection (timeline, reaction map) without a state slot.
// ─────────────────────────────────────────────────────────────────────
macro_rules! non_state_kind {
    (
        $struct:ident,
        kind = $kind:expr,
        component = $component:expr,
        version = $version:expr,
        criticality = $criticality:expr,
        delegate = |$op:ident, $state:ident, $hlc:ident| $body:expr $(,)?
    ) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $struct;
        impl ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> StateCardinality {
                StateCardinality::None
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: $component,
                    component_version: $version,
                    criticality: $criticality,
                }
            }
            fn project(
                &self,
                $op: &Operation,
                $state: &mut ProjectionState,
                $hlc: &ServerHlc,
            ) -> ProjectionEffect {
                $body
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// Active projecting kinds (T1-1 migration)
// ─────────────────────────────────────────────────────────────────────

non_state_kind!(
    MessageCreate,
    kind = kinds::CX_MESSAGE_CREATE,
    component = "cx.component.message.create.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_message(op, op.created_at),
);

non_state_kind!(
    MessageRevise,
    kind = kinds::CX_MESSAGE_REVISE,
    component = "cx.component.message.revise.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_message_revise(op, op.created_at),
);

non_state_kind!(
    MessageRedact,
    kind = kinds::CX_MESSAGE_REDACT,
    component = "cx.component.message.redact.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_redaction(op),
);

non_state_kind!(
    Redaction,
    kind = kinds::CX_REDACTION,
    component = "cx.component.redaction.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_redaction(op),
);

non_state_kind!(
    ReactionAdd,
    kind = kinds::CX_REACTION_ADD,
    component = "cx.component.reaction.v1",
    version = 1,
    criticality = Criticality::Optional,
    delegate = |op, state, _hlc| state.apply_reaction_add(op, op.created_at),
);

non_state_kind!(
    ReactionRemove,
    kind = kinds::CX_REACTION_REMOVE,
    component = "cx.component.reaction.v1",
    version = 1,
    criticality = Criticality::Optional,
    delegate = |op, state, _hlc| state.apply_reaction_remove(op),
);

non_state_kind!(
    ReadMarker,
    kind = kinds::CX_READ_MARKER,
    component = "cx.component.read.marker.v1",
    version = 1,
    criticality = Criticality::Optional,
    delegate = |op, state, _hlc| state.apply_read_marker(op, op.created_at),
);

non_state_kind!(
    EntityCreate,
    kind = kinds::CX_ENTITY_CREATE,
    component = "cx.component.entity.create.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_entity_create(op, op.created_at),
);

non_state_kind!(
    EntityUpdate,
    kind = kinds::CX_ENTITY_UPDATE,
    component = "cx.component.entity.update.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, hlc| state.apply_entity_update(op, op.created_at, hlc),
);

non_state_kind!(
    EntityDelete,
    kind = kinds::CX_ENTITY_DELETE,
    component = "cx.component.entity.delete.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_entity_delete(op),
);

non_state_kind!(
    FieldPositionMove,
    kind = kinds::CX_FIELD_POSITION_MOVE,
    component = "cx.component.entity.update.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, hlc| state.apply_entity_update(op, op.created_at, hlc),
);

non_state_kind!(
    FieldPositionReorder,
    kind = kinds::CX_FIELD_POSITION_REORDER,
    component = "cx.component.entity.update.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, hlc| state.apply_entity_update(op, op.created_at, hlc),
);

non_state_kind!(
    RelationCreate,
    kind = kinds::CX_RELATION_CREATE,
    component = "cx.component.relation.create.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_relation_create(op, op.created_at),
);

non_state_kind!(
    RelationUpdate,
    kind = kinds::CX_RELATION_UPDATE,
    component = "cx.component.relation.update.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, hlc| state.apply_relation_update(op, op.created_at, hlc),
);

non_state_kind!(
    RelationDelete,
    kind = kinds::CX_RELATION_DELETE,
    component = "cx.component.relation.delete.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_relation_delete(op),
);

non_state_kind!(
    ContainerMoveItem,
    kind = kinds::CX_CONTAINER_MOVE_ITEM,
    component = "cx.component.container.position.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_container_position(op, op.created_at),
);

non_state_kind!(
    ContainerRebalance,
    kind = kinds::CX_CONTAINER_REBALANCE,
    component = "cx.component.container.position.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_container_position(op, op.created_at),
);

// ─────────────────────────────────────────────────────────────────────
// Membership (legacy cx.membership.* kinds; per_subject by member DID)
// ─────────────────────────────────────────────────────────────────────

macro_rules! legacy_membership_kind {
    ($struct:ident, kind = $kind:expr) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $struct;
        impl ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> StateCardinality {
                StateCardinality::PerSubject
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: "cx.component.member.state.v1",
                    component_version: 1,
                    criticality: Criticality::Required,
                }
            }
            fn subject_for_event(
                &self,
                operation: &Operation,
            ) -> Result<Option<String>, ReducerKindError> {
                assert_no_legacy_state_key(operation, $kind)?;
                // Legacy membership payload uses `member` field for the
                // target principal DID. T1-3 will swap to `cx.member.state`
                // with `payload.actor_id` (spec-correct).
                let subject = optional_payload_string(operation, "member")
                    .or_else(|| optional_payload_string(operation, "actor_id"))
                    .or_else(|| optional_payload_string(operation, "principal_id"))
                    .ok_or(ReducerKindError::MissingSubjectField {
                        kind: $kind,
                        field: "member",
                    })?;
                Ok(Some(subject))
            }
            fn project(
                &self,
                operation: &Operation,
                state: &mut ProjectionState,
                _hlc: &ServerHlc,
            ) -> ProjectionEffect {
                state.apply_membership(operation, operation.created_at, $kind)
            }
        }
    };
}

legacy_membership_kind!(MembershipJoin, kind = kinds::CX_MEMBERSHIP_JOIN);
legacy_membership_kind!(MembershipLeave, kind = kinds::CX_MEMBERSHIP_LEAVE);
legacy_membership_kind!(MembershipKick, kind = kinds::CX_MEMBERSHIP_KICK);
legacy_membership_kind!(MembershipBan, kind = kinds::CX_MEMBERSHIP_BAN);
legacy_membership_kind!(MembershipUnban, kind = kinds::CX_MEMBERSHIP_UNBAN);
legacy_membership_kind!(MembershipKnock, kind = kinds::CX_MEMBERSHIP_KNOCK);

// ─────────────────────────────────────────────────────────────────────
// Space lifecycle (singleton state)
// ─────────────────────────────────────────────────────────────────────

singleton_state_kind!(
    SpaceCreate,
    kind = kinds::CX_SPACE_CREATE,
    component = "cx.component.space.create.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_space_lifecycle(op, op.created_at),
);

singleton_state_kind!(
    SpaceUpdate,
    kind = kinds::CX_SPACE_UPDATE,
    component = "cx.component.space.update.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_space_lifecycle(op, op.created_at),
);

singleton_state_kind!(
    SpaceDestroy,
    kind = kinds::CX_SPACE_DESTROY,
    component = "cx.component.space.destroy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |op, state, _hlc| state.apply_space_lifecycle(op, op.created_at),
);

// ─────────────────────────────────────────────────────────────────────
// cx.member.state (per_subject by payload.actor_id) — Phase 1
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct MemberState;
impl ReducerKind for MemberState {
    fn kind(&self) -> &'static str {
        "cx.member.state"
    }
    fn cardinality(&self) -> StateCardinality {
        StateCardinality::PerSubject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.member.state.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_event(
        &self,
        operation: &Operation,
    ) -> Result<Option<String>, ReducerKindError> {
        assert_no_legacy_state_key(operation, "cx.member.state")?;
        let subject = optional_payload_string(operation, "actor_id")
            .or_else(|| optional_payload_string(operation, "principal_id"))
            .ok_or(ReducerKindError::MissingSubjectField {
                kind: "cx.member.state",
                field: "actor_id",
            })?;
        Ok(Some(subject))
    }
    fn project(
        &self,
        _op: &Operation,
        _state: &mut ProjectionState,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        // T1-3: project to ProjectionState.memberships under
        // (space_id, actor_id). Currently membership state is driven by
        // legacy cx.membership.* kinds above; this stub will replace them
        // when T1-3 lands.
        ProjectionEffect::Ignored
    }
}

// ─────────────────────────────────────────────────────────────────────
// Spec Phase 1 per-facet space policy / lifecycle stubs
//
// All singleton-cardinality. `project` is a no-op pending T1-3.
// ─────────────────────────────────────────────────────────────────────

singleton_state_kind!(
    SpacePolicy,
    kind = "cx.space.policy",
    component = "cx.component.space.policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceJoinRule,
    kind = "cx.space.join_rule",
    component = "cx.component.space.join_rule.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceHistoryVisibility,
    kind = "cx.space.history_visibility",
    component = "cx.component.space.history_visibility.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceDiscovery,
    kind = "cx.space.discovery",
    component = "cx.component.space.discovery.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpacePolicyServer,
    kind = "cx.space.policy_server",
    component = "cx.component.space.policy_server.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpacePolicyComponents,
    kind = "cx.space.policy_components",
    component = "cx.component.space.policy_components.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceHistorySharingPolicy,
    kind = "cx.space.history_sharing_policy",
    component = "cx.component.space.history_sharing_policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceAssetPrivacyPolicy,
    kind = "cx.space.asset_privacy_policy",
    component = "cx.component.space.asset_privacy_policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceModerationPolicy,
    kind = "cx.space.moderation_policy",
    component = "cx.component.space.moderation_policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpacePlaintextVisibleServices,
    kind = "cx.space.plaintext_visible_services",
    component = "cx.component.space.plaintext_visible_services.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceMediaService,
    kind = "cx.space.media_service",
    component = "cx.component.space.media_service.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceSchema,
    kind = "cx.space.schema",
    component = "cx.component.space.schema.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceArchive,
    kind = "cx.space.archive",
    component = "cx.component.space.archive.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceFreeze,
    kind = "cx.space.freeze",
    component = "cx.component.space.freeze.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceTombstone,
    kind = "cx.space.tombstone",
    component = "cx.component.space.tombstone.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

// ─────────────────────────────────────────────────────────────────────
// cx.space.inheritance_policy (per_subject by payload.parent_space_id)
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct SpaceInheritancePolicy;
impl ReducerKind for SpaceInheritancePolicy {
    fn kind(&self) -> &'static str {
        "cx.space.inheritance_policy"
    }
    fn cardinality(&self) -> StateCardinality {
        StateCardinality::PerSubject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.space.inheritance_policy.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_event(
        &self,
        operation: &Operation,
    ) -> Result<Option<String>, ReducerKindError> {
        assert_no_legacy_state_key(operation, "cx.space.inheritance_policy")?;
        let subject = optional_payload_string(operation, "parent_space_id").ok_or(
            ReducerKindError::MissingSubjectField {
                kind: "cx.space.inheritance_policy",
                field: "parent_space_id",
            },
        )?;
        Ok(Some(subject))
    }
    fn project(
        &self,
        _op: &Operation,
        _state: &mut ProjectionState,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        ProjectionEffect::Ignored
    }
}

// ─────────────────────────────────────────────────────────────────────
// Phase 4 hub-writer: cx.space.host (singleton) + cx.space.host.transfer
// (per_subject by payload.transfer_id)
// ─────────────────────────────────────────────────────────────────────

singleton_state_kind!(
    SpaceHost,
    kind = "cx.space.host",
    component = "cx.component.space.host.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

#[derive(Clone, Copy, Debug, Default)]
pub struct SpaceHostTransfer;
impl ReducerKind for SpaceHostTransfer {
    fn kind(&self) -> &'static str {
        "cx.space.host.transfer"
    }
    fn cardinality(&self) -> StateCardinality {
        StateCardinality::PerSubject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.space.host.transfer.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_event(
        &self,
        operation: &Operation,
    ) -> Result<Option<String>, ReducerKindError> {
        assert_no_legacy_state_key(operation, "cx.space.host.transfer")?;
        let subject = optional_payload_string(operation, "transfer_id").ok_or(
            ReducerKindError::MissingSubjectField {
                kind: "cx.space.host.transfer",
                field: "transfer_id",
            },
        )?;
        Ok(Some(subject))
    }
    fn project(
        &self,
        _op: &Operation,
        _state: &mut ProjectionState,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        ProjectionEffect::Ignored
    }
}

// ─────────────────────────────────────────────────────────────────────
// Phase 5 consent: cx.consent.{grant,revoke} share state slot via
// payload.consent_id — both kinds report the same component_type
// (`cx.component.consent.grant.v1`) per spec
// `component_slot_alias_of` rule.
// ─────────────────────────────────────────────────────────────────────

macro_rules! consent_kind {
    ($struct:ident, kind = $kind:expr) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $struct;
        impl ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> StateCardinality {
                StateCardinality::PerSubject
            }
            fn component(&self) -> ComponentDescriptor {
                // grant + revoke share component_type via slot aliasing.
                ComponentDescriptor {
                    component_type: "cx.component.consent.grant.v1",
                    component_version: 1,
                    criticality: Criticality::Required,
                }
            }
            fn subject_for_event(
                &self,
                operation: &Operation,
            ) -> Result<Option<String>, ReducerKindError> {
                assert_no_legacy_state_key(operation, $kind)?;
                let subject = optional_payload_string(operation, "consent_id").ok_or(
                    ReducerKindError::MissingSubjectField {
                        kind: $kind,
                        field: "consent_id",
                    },
                )?;
                Ok(Some(subject))
            }
            fn project(
                &self,
                _op: &Operation,
                _state: &mut ProjectionState,
                _hlc: &ServerHlc,
            ) -> ProjectionEffect {
                ProjectionEffect::Ignored
            }
        }
    };
}

consent_kind!(ConsentGrant, kind = "cx.consent.grant");
consent_kind!(ConsentRevoke, kind = "cx.consent.revoke");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_kinds_return_no_subject() {
        let kind = SpaceMediaService;
        // Build a minimal operation — payload empty, no state_key.
        let op = make_op("cx.space.media_service", serde_json::json!({}));
        let subject = kind.subject_for_event(&op).unwrap();
        assert_eq!(subject, None);
    }

    #[test]
    fn per_subject_inheritance_requires_parent_space_id() {
        let kind = SpaceInheritancePolicy;
        let bad = make_op("cx.space.inheritance_policy", serde_json::json!({}));
        assert!(matches!(
            kind.subject_for_event(&bad),
            Err(ReducerKindError::MissingSubjectField { field: "parent_space_id", .. })
        ));

        let good = make_op(
            "cx.space.inheritance_policy",
            serde_json::json!({"parent_space_id": "cx:space:01parent00000000000000000"}),
        );
        let subject = kind.subject_for_event(&good).unwrap();
        assert_eq!(subject.as_deref(), Some("cx:space:01parent00000000000000000"));
    }

    #[test]
    fn legacy_state_key_field_is_rejected() {
        let kind = SpaceMediaService;
        let bad = make_op(
            "cx.space.media_service",
            serde_json::json!({"state_key": "should-not-exist"}),
        );
        assert!(matches!(
            kind.subject_for_event(&bad),
            Err(ReducerKindError::LegacyStateKey { .. })
        ));
    }

    #[test]
    fn consent_grant_and_revoke_share_component_type() {
        let grant = ConsentGrant.component();
        let revoke = ConsentRevoke.component();
        assert_eq!(grant.component_type, revoke.component_type);
        assert_eq!(grant.component_type, "cx.component.consent.grant.v1");
    }

    fn make_op(kind: &str, payload: serde_json::Value) -> Operation {
        use contrix_sdk::{OperationId, SpaceId};
        Operation::create(
            OperationId::new("cx:operation:01js0op0000000000000000000").unwrap(),
            SpaceId::new("cx:space:01js0sp0000000000000000000").unwrap(),
            kind,
            payload,
        )
    }
}
