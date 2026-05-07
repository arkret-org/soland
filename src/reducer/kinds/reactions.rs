//! Reaction kinds (`cx.reaction.add`, `cx.reaction.remove`).

use crate::kinds;
use crate::reducer::registry::Criticality;

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
