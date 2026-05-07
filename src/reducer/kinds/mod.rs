//! Per-kind `ReducerKind` implementations (T1-2 split).
//!
//! Layout: each Contrix domain gets its own file. The shared macros
//! (`singleton_state_kind!`, `non_state_kind!`, `legacy_membership_kind!`,
//! `consent_kind!`) live here so siblings can pull them via
//! `use super::<macro>;`. T1-3 will replace each `Ignored` stub with a
//! real `project()` body, often promoting a single struct out of a
//! domain-grouped file into its own `kinds/<kind>.rs`.

#![allow(missing_docs)]

// ─────────────────────────────────────────────────────────────────────
// Shared macros — declared here, re-exported `pub(crate) use` so
// sibling modules can `use super::<name>;` to pull them into scope.
// ─────────────────────────────────────────────────────────────────────

/// Declare a singleton-cardinality state-event kind whose `project`
/// body delegates to a `ProjectionState` method.
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
        impl $crate::reducer::registry::ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> $crate::reducer::registry::StateCardinality {
                $crate::reducer::registry::StateCardinality::Singleton
            }
            fn component(&self) -> $crate::reducer::registry::ComponentDescriptor {
                $crate::reducer::registry::ComponentDescriptor {
                    component_type: $component,
                    component_version: $version,
                    criticality: $criticality,
                }
            }
            fn subject_for_event(
                &self,
                _operation: &contrix_sdk::Operation,
            ) -> Result<Option<String>, $crate::reducer::registry::ReducerKindError> {
                Ok(None)
            }
            fn project(
                &self,
                $op: &contrix_sdk::Operation,
                $state: &mut $crate::reducer::ProjectionState,
                $hlc: &$crate::hlc::ServerHlc,
            ) -> $crate::reducer::ProjectionEffect {
                $body
            }
        }
    };
}

/// Declare a non-state (cardinality::None) operation kind. No subject
/// derivation; pure projection mutation.
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
        impl $crate::reducer::registry::ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> $crate::reducer::registry::StateCardinality {
                $crate::reducer::registry::StateCardinality::None
            }
            fn component(&self) -> $crate::reducer::registry::ComponentDescriptor {
                $crate::reducer::registry::ComponentDescriptor {
                    component_type: $component,
                    component_version: $version,
                    criticality: $criticality,
                }
            }
            fn project(
                &self,
                $op: &contrix_sdk::Operation,
                $state: &mut $crate::reducer::ProjectionState,
                $hlc: &$crate::hlc::ServerHlc,
            ) -> $crate::reducer::ProjectionEffect {
                $body
            }
        }
    };
}

/// Declare a legacy `cx.membership.*` kind (per_subject by `member` /
/// `actor_id` / `principal_id` payload field).
macro_rules! legacy_membership_kind {
    ($struct:ident, kind = $kind:expr) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $struct;
        impl $crate::reducer::registry::ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> $crate::reducer::registry::StateCardinality {
                $crate::reducer::registry::StateCardinality::PerSubject
            }
            fn component(&self) -> $crate::reducer::registry::ComponentDescriptor {
                $crate::reducer::registry::ComponentDescriptor {
                    component_type: "cx.component.member.state.v1",
                    component_version: 1,
                    criticality: $crate::reducer::registry::Criticality::Required,
                }
            }
            fn subject_for_event(
                &self,
                operation: &contrix_sdk::Operation,
            ) -> Result<Option<String>, $crate::reducer::registry::ReducerKindError> {
                let subject = $crate::reducer::registry::optional_payload_string(operation, "member")
                    .or_else(|| $crate::reducer::registry::optional_payload_string(operation, "actor_id"))
                    .or_else(|| $crate::reducer::registry::optional_payload_string(operation, "principal_id"))
                    .ok_or($crate::reducer::registry::ReducerKindError::MissingSubjectField {
                        kind: $kind,
                        field: "member",
                    })?;
                Ok(Some(subject))
            }
            fn project(
                &self,
                operation: &contrix_sdk::Operation,
                state: &mut $crate::reducer::ProjectionState,
                _hlc: &$crate::hlc::ServerHlc,
            ) -> $crate::reducer::ProjectionEffect {
                state.apply_membership(operation, operation.created_at, $kind)
            }
        }
    };
}

/// Declare a `cx.consent.*` kind (per-subject by `consent_id`).
/// Grant + revoke share the same cell family per spec or-set semantics.
macro_rules! consent_kind {
    ($struct:ident, kind = $kind:expr) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $struct;
        impl $crate::reducer::registry::ReducerKind for $struct {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn cardinality(&self) -> $crate::reducer::registry::StateCardinality {
                $crate::reducer::registry::StateCardinality::PerSubject
            }
            fn component(&self) -> $crate::reducer::registry::ComponentDescriptor {
                $crate::reducer::registry::ComponentDescriptor {
                    component_type: "cx.component.consent.grant.v1",
                    component_version: 1,
                    criticality: $crate::reducer::registry::Criticality::Required,
                }
            }
            fn subject_for_event(
                &self,
                operation: &contrix_sdk::Operation,
            ) -> Result<Option<String>, $crate::reducer::registry::ReducerKindError> {
                let subject = $crate::reducer::registry::optional_payload_string(operation, "consent_id")
                    .ok_or($crate::reducer::registry::ReducerKindError::MissingSubjectField {
                        kind: $kind,
                        field: "consent_id",
                    })?;
                Ok(Some(subject))
            }
            fn project(
                &self,
                _op: &contrix_sdk::Operation,
                _state: &mut $crate::reducer::ProjectionState,
                _hlc: &$crate::hlc::ServerHlc,
            ) -> $crate::reducer::ProjectionEffect {
                $crate::reducer::ProjectionEffect::Ignored
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// Per-domain submodules. Each pulls the macros above into scope via
// `macro_rules!` textual hoisting (children of the defining module
// inherit the macros without an explicit `use`).
// ─────────────────────────────────────────────────────────────────────

pub mod consent;
pub mod container;
pub mod entity;
pub mod member_state;
pub mod membership;
pub mod messages;
pub mod reactions;
pub mod read_marker;
pub mod relation;
pub mod space_facets;
pub mod space_inheritance;
pub mod space_lifecycle;

pub use consent::*;
pub use container::*;
pub use entity::*;
pub use member_state::*;
pub use membership::*;
pub use messages::*;
pub use reactions::*;
pub use read_marker::*;
pub use relation::*;
pub use space_facets::*;
pub use space_inheritance::*;
pub use space_lifecycle::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reducer::registry::{ReducerKind, ReducerKindError};

    #[test]
    fn singleton_kinds_return_no_subject() {
        let kind = SpaceMediaService;
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
    fn consent_grant_and_revoke_share_component_type() {
        let grant = ConsentGrant.component();
        let revoke = ConsentRevoke.component();
        assert_eq!(grant.component_type, revoke.component_type);
        assert_eq!(grant.component_type, "cx.component.consent.grant.v1");
    }

    fn make_op(kind: &str, payload: serde_json::Value) -> contrix_sdk::Operation {
        use contrix_sdk::{Operation, OperationId, SpaceId};
        Operation::create(
            OperationId::new("cx:operation:01js0op0000000000000000000").unwrap(),
            SpaceId::new("cx:space:01js0sp0000000000000000000").unwrap(),
            kind,
            payload,
        )
    }
}
