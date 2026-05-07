//! Container position kinds (`cx.container.move_item`, `cx.container.rebalance`).

use crate::kinds;
use crate::reducer::registry::Criticality;

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
