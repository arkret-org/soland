//! Entity kinds (`cx.entity.*` + `cx.field.position.*` migration aliases).

use crate::kinds;
use crate::reducer::registry::Criticality;

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
