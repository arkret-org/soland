//! Read marker kind (`cx.read.marker`).

use crate::kinds;
use crate::reducer::registry::Criticality;

non_state_kind!(
    ReadMarker,
    kind = kinds::CX_READ_MARKER,
    component = "cx.component.read.marker.v1",
    version = 1,
    criticality = Criticality::Optional,
    delegate = |op, state, _hlc| state.apply_read_marker(op, op.created_at),
);
