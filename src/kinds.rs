use contrix_sdk::Operation;
use serde_json::Value;

pub const CX_MESSAGE_CREATE: &str = "cx.message.create";
pub const CX_MESSAGE_REVISE: &str = "cx.message.revise";
pub const CX_MESSAGE_REDACT: &str = "cx.message.redact";
pub const CX_REACTION_ADD: &str = "cx.reaction.add";
pub const CX_REACTION_REMOVE: &str = "cx.reaction.remove";
// `cx.entity.*` was a soland-local abstraction that never landed in
// `contrix-spec/v1`. Typed objects in the protocol are `cx:flow:` /
// `cx:place:` / `cx:morph:` / `cx:relation:` / `cx:view:`, each with its
// own dedicated event kind (`cx.flow.create`, `cx.morph.create`, …). The
// `cx.entity.*` constants and operation schemas were removed in round 6.
pub const CX_RELATION_CREATE: &str = "cx.relation.create";
pub const CX_RELATION_UPDATE: &str = "cx.relation.update";
pub const CX_RELATION_DELETE: &str = "cx.relation.delete";
pub const CX_VIEW_CREATE: &str = "cx.view.create";
pub const CX_VIEW_UPDATE: &str = "cx.view.update";
pub const CX_VIEW_RECONCILE: &str = "cx.view.reconcile";
pub const CX_PLACE_CREATE: &str = "cx.place.create";
pub const CX_PLACE_UPDATE: &str = "cx.place.update";
pub const CX_PLACE_PARENT: &str = "cx.place.parent";
pub const CX_PLACE_ARCHIVE: &str = "cx.place.archive";
pub const CX_PLACE_RESTORE: &str = "cx.place.restore";
pub const CX_PLACE_TOMBSTONE: &str = "cx.place.tombstone";
// Flow lifecycle (round 13 — Flow projection state machine). spec
// `common-fields.md §5.1` Flow row: active / archived / redacted / deleted.
// Flow has no dedicated `cx.flow.tombstone` event (terminal state reached
// via `cx.redaction`); only archive/restore are state-machine transitions
// here.
pub const CX_FLOW_CREATE: &str = "cx.flow.create";
pub const CX_FLOW_UPDATE: &str = "cx.flow.update";
pub const CX_FLOW_ARCHIVE: &str = "cx.flow.archive";
pub const CX_FLOW_RESTORE: &str = "cx.flow.restore";
// Round 14 — Flow position events. Not state-machine transitions; they
// write to the `cx.component.flow.position.v1` cell family keyed by
// (board_place_id, flow_id). The Event-Envelope path only validates
// payload shape and bumps the Flow's updated_at/by; the cell write
// happens on the Move/Anchor pipeline (out of scope for the reducer's
// structured cache).
pub const CX_FLOW_MOVE: &str = "cx.flow.move";
pub const CX_FLOW_REORDER: &str = "cx.flow.reorder";
// Round 14d (2026-05-16) — Flow track sub-events. Manage individual
// entries in `Flow.tracks: BTreeMap<String, FlowTrackConfig>` (SDK has
// the reducer for these as of SDK round 12). soland's wire validator
// enforces payload shape (flow_id + track_id [+ patch for update]) and
// the spec common-fields.md §5.1 update-on-non-active state guard.
// FlowProjection still doesn't carry `tracks` server-side; the touch
// just bumps `updated_at` (mirror of cx.flow.move/reorder pattern).
pub const CX_FLOW_TRACK_DISABLE: &str = "cx.flow.track.disable";
pub const CX_FLOW_TRACK_ENABLE: &str = "cx.flow.track.enable";
pub const CX_FLOW_TRACK_SET_PRIMARY: &str = "cx.flow.track.set_primary";
pub const CX_FLOW_TRACK_UPDATE: &str = "cx.flow.track.update";
// Morph lifecycle (round 13). Same shape as Flow — no dedicated tombstone.
pub const CX_MORPH_CREATE: &str = "cx.morph.create";
pub const CX_MORPH_UPDATE: &str = "cx.morph.update";
pub const CX_MORPH_ARCHIVE: &str = "cx.morph.archive";
pub const CX_MORPH_RESTORE: &str = "cx.morph.restore";
pub const CX_FIELD_POSITION_MOVE: &str = "cx.field.position.move";
pub const CX_FIELD_POSITION_REORDER: &str = "cx.field.position.reorder";
pub const CX_CONTAINER_MOVE_ITEM: &str = "cx.container.move_item";
pub const CX_CONTAINER_REBALANCE: &str = "cx.container.rebalance";
pub const CX_MEMBER_STATE: &str = "cx.member.state";
pub const CX_READ_MARKER: &str = "cx.read.marker";
pub const CX_SPACE_CREATE: &str = "cx.space.create";
pub const CX_SPACE_UPDATE: &str = "cx.space.update";
pub const CX_SPACE_DESTROY: &str = "cx.space.destroy";
pub const CX_REDACTION: &str = "cx.redaction";
// Round 14e+ (2026-05-16) — Applet protocol family. Spec
// `extensions/applet-integration.md`. soland's role at this layer is to
// validate wire shape + persist + dispatch; applet bridge state machine
// lives client-side (yougen) and at the applet service itself.
pub const CX_APPLET_REGISTRATION: &str = "cx.applet.registration";
pub const CX_APPLET_DISCOVERY: &str = "cx.applet.discovery";
pub const CX_APPLET_PROTOCOL_SESSION_START: &str = "cx.applet.protocol_session.start";
pub const CX_APPLET_PROTOCOL_SESSION_STATUS: &str = "cx.applet.protocol_session.status";
pub const CX_APPLET_BRIDGE_ERROR: &str = "cx.applet.bridge_error";
// Round 14e+ (2026-05-16) — Agent protocol family. Spec
// `extensions/agent-integration.md`. Mirror of applet but with a
// terminal `*.result` event that carries the signed audit binding.
pub const CX_AGENT_ENDPOINT: &str = "cx.agent.endpoint";
pub const CX_AGENT_PROTOCOL_SESSION_START: &str = "cx.agent.protocol_session.start";
pub const CX_AGENT_PROTOCOL_SESSION_STATUS: &str = "cx.agent.protocol_session.status";
pub const CX_AGENT_PROTOCOL_SESSION_RESULT: &str = "cx.agent.protocol_session.result";
pub const LEGACY_KIND_MIGRATION_PROFILE: &str = "cx.profile.legacy_kind_migration.v1";

pub fn canonical_kind_for_operation(operation: &Operation) -> Option<&'static str> {
    canonical_kind_for_payload(&operation.object_type, &operation.payload)
}

pub fn canonical_kind_string(operation: &Operation) -> String {
    canonical_kind_for_operation(operation)
        .unwrap_or(operation.object_type.as_str())
        .to_owned()
}

pub fn canonical_kind_for_payload(object_type: &str, _payload: &Value) -> Option<&'static str> {
    canonical_registered_kind(object_type)
}

fn canonical_registered_kind(object_type: &str) -> Option<&'static str> {
    match object_type {
        CX_MESSAGE_CREATE => Some(CX_MESSAGE_CREATE),
        CX_MESSAGE_REVISE => Some(CX_MESSAGE_REVISE),
        CX_MESSAGE_REDACT => Some(CX_MESSAGE_REDACT),
        CX_REDACTION => Some(CX_REDACTION),
        CX_REACTION_ADD => Some(CX_REACTION_ADD),
        CX_REACTION_REMOVE => Some(CX_REACTION_REMOVE),
        CX_RELATION_CREATE => Some(CX_RELATION_CREATE),
        CX_RELATION_UPDATE => Some(CX_RELATION_UPDATE),
        CX_RELATION_DELETE => Some(CX_RELATION_DELETE),
        CX_VIEW_CREATE => Some(CX_VIEW_CREATE),
        CX_VIEW_UPDATE => Some(CX_VIEW_UPDATE),
        CX_VIEW_RECONCILE => Some(CX_VIEW_RECONCILE),
        CX_PLACE_CREATE => Some(CX_PLACE_CREATE),
        CX_PLACE_UPDATE => Some(CX_PLACE_UPDATE),
        CX_PLACE_PARENT => Some(CX_PLACE_PARENT),
        CX_PLACE_ARCHIVE => Some(CX_PLACE_ARCHIVE),
        CX_PLACE_RESTORE => Some(CX_PLACE_RESTORE),
        CX_PLACE_TOMBSTONE => Some(CX_PLACE_TOMBSTONE),
        CX_FLOW_CREATE => Some(CX_FLOW_CREATE),
        CX_FLOW_UPDATE => Some(CX_FLOW_UPDATE),
        CX_FLOW_ARCHIVE => Some(CX_FLOW_ARCHIVE),
        CX_FLOW_RESTORE => Some(CX_FLOW_RESTORE),
        CX_FLOW_MOVE => Some(CX_FLOW_MOVE),
        CX_FLOW_REORDER => Some(CX_FLOW_REORDER),
        CX_FLOW_TRACK_DISABLE => Some(CX_FLOW_TRACK_DISABLE),
        CX_FLOW_TRACK_ENABLE => Some(CX_FLOW_TRACK_ENABLE),
        CX_FLOW_TRACK_SET_PRIMARY => Some(CX_FLOW_TRACK_SET_PRIMARY),
        CX_FLOW_TRACK_UPDATE => Some(CX_FLOW_TRACK_UPDATE),
        CX_MORPH_CREATE => Some(CX_MORPH_CREATE),
        CX_MORPH_UPDATE => Some(CX_MORPH_UPDATE),
        CX_MORPH_ARCHIVE => Some(CX_MORPH_ARCHIVE),
        CX_MORPH_RESTORE => Some(CX_MORPH_RESTORE),
        CX_FIELD_POSITION_MOVE => Some(CX_FIELD_POSITION_MOVE),
        CX_FIELD_POSITION_REORDER => Some(CX_FIELD_POSITION_REORDER),
        CX_CONTAINER_MOVE_ITEM => Some(CX_CONTAINER_MOVE_ITEM),
        CX_CONTAINER_REBALANCE => Some(CX_CONTAINER_REBALANCE),
        CX_READ_MARKER => Some(CX_READ_MARKER),
        CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY => Some(match object_type {
            CX_SPACE_CREATE => CX_SPACE_CREATE,
            CX_SPACE_DESTROY => CX_SPACE_DESTROY,
            _ => CX_SPACE_UPDATE,
        }),
        CX_MEMBER_STATE => Some(CX_MEMBER_STATE),
        // Applet protocol family (round 14e+).
        CX_APPLET_REGISTRATION => Some(CX_APPLET_REGISTRATION),
        CX_APPLET_DISCOVERY => Some(CX_APPLET_DISCOVERY),
        CX_APPLET_PROTOCOL_SESSION_START => Some(CX_APPLET_PROTOCOL_SESSION_START),
        CX_APPLET_PROTOCOL_SESSION_STATUS => Some(CX_APPLET_PROTOCOL_SESSION_STATUS),
        CX_APPLET_BRIDGE_ERROR => Some(CX_APPLET_BRIDGE_ERROR),
        // Agent protocol family (round 14e+).
        CX_AGENT_ENDPOINT => Some(CX_AGENT_ENDPOINT),
        CX_AGENT_PROTOCOL_SESSION_START => Some(CX_AGENT_PROTOCOL_SESSION_START),
        CX_AGENT_PROTOCOL_SESSION_STATUS => Some(CX_AGENT_PROTOCOL_SESSION_STATUS),
        CX_AGENT_PROTOCOL_SESSION_RESULT => Some(CX_AGENT_PROTOCOL_SESSION_RESULT),
        _ => None,
    }
}

/// Sprint Q1 第十四增量 — applet + agent family classifiers used by
/// projection/audit dispatchers that want to fan out the whole family
/// without listing every kind individually.
pub fn is_applet_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_APPLET_REGISTRATION
            | CX_APPLET_DISCOVERY
            | CX_APPLET_PROTOCOL_SESSION_START
            | CX_APPLET_PROTOCOL_SESSION_STATUS
            | CX_APPLET_BRIDGE_ERROR
    )
}

pub fn is_agent_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_AGENT_ENDPOINT
            | CX_AGENT_PROTOCOL_SESSION_START
            | CX_AGENT_PROTOCOL_SESSION_STATUS
            | CX_AGENT_PROTOCOL_SESSION_RESULT
    )
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CX_MESSAGE_CREATE)
}

pub fn operation_is_redaction(operation: &Operation) -> bool {
    matches!(
        canonical_kind_for_operation(operation),
        Some(CX_MESSAGE_REDACT | CX_REDACTION)
    )
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CX_MEMBER_STATE)
}

pub fn operation_is_space_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_space_lifecycle_kind)
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, CX_MESSAGE_REDACT | CX_REDACTION | "redaction")
}

pub fn is_membership_kind(kind: &str) -> bool {
    kind == CX_MEMBER_STATE
}

pub fn is_space_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY)
}

pub fn is_place_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_PLACE_ARCHIVE | CX_PLACE_RESTORE | CX_PLACE_TOMBSTONE)
}

/// Flow has no dedicated `cx.flow.tombstone` event in the spec event-kind
/// registry — terminal state is reached via `cx.redaction`. Only archive /
/// restore are lifecycle state-machine transitions here.
pub fn is_flow_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_FLOW_ARCHIVE | CX_FLOW_RESTORE)
}

/// Morph has no dedicated tombstone event for the same reason as Flow.
pub fn is_morph_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_MORPH_ARCHIVE | CX_MORPH_RESTORE)
}

/// Flow track sub-events (round 14d). Distinct from lifecycle events
/// (`is_flow_lifecycle_kind`) because tracks don't transition Flow.state;
/// they manage entries in `Flow.tracks` per SDK round 12. The state
/// guard for these is "parent Flow MUST be Active" (spec §5.1 update
/// rule), enforced via `check_flow_track_transition`.
pub fn is_flow_track_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_FLOW_TRACK_DISABLE
            | CX_FLOW_TRACK_ENABLE
            | CX_FLOW_TRACK_SET_PRIMARY
            | CX_FLOW_TRACK_UPDATE
    )
}
