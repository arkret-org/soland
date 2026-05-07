//! Spec Phase 4 hub-writer kinds: `cx.space.host` (singleton) +
//! `cx.space.host.transfer` (per_subject by `payload.transfer_id`).

use contrix_sdk::Operation;

use crate::hlc::ServerHlc;
use crate::reducer::ProjectionEffect;
use crate::reducer::ProjectionState;
use crate::reducer::registry::{
    ComponentDescriptor, Criticality, ReducerKind, ReducerKindError, StateCardinality,
    assert_no_legacy_state_key, optional_payload_string,
};

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
