//! `cx.space.inheritance_policy` — per_subject by `payload.parent_space_id`.

use contrix_sdk::Operation;

use crate::hlc::ServerHlc;
use crate::reducer::ProjectionEffect;
use crate::reducer::ProjectionState;
use crate::reducer::registry::{
    ComponentDescriptor, Criticality, ReducerKind, ReducerKindError, StateCardinality,
    assert_no_legacy_state_key, optional_payload_string,
};

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
