//! Relation kinds (`cx.relation.*`).

use crate::kinds;
use crate::reducer::registry::Criticality;

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
