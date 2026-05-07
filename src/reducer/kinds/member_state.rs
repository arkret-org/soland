//! Typed `cx.member.state` kind (per-subject by `payload.actor_id`).
//! Stub: project body lands in T1-3.

use contrix_sdk::Operation;

use crate::hlc::ServerHlc;
use crate::reducer::ProjectionEffect;
use crate::reducer::ProjectionState;
use crate::reducer::registry::{
    ComponentDescriptor, Criticality, ReducerKind, ReducerKindError, StateCardinality,
    optional_payload_string,
};

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
        // legacy cx.membership.* kinds; this stub will replace them when
        // T1-3 lands.
        ProjectionEffect::Ignored
    }
}
