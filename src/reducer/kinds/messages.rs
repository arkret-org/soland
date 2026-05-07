//! Message + redaction kinds (`cx.message.*`, `cx.redaction`).

use crate::kinds;
use crate::reducer::registry::Criticality;

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
