//! Space lifecycle kinds (`cx.space.{create,update,destroy}`).

use crate::kinds;
use crate::reducer::registry::Criticality;

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
