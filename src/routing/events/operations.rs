//! Operation envelope + payload validators.
//!
//! Surfaces:
//! - `OperationPayloadSchema` / `PayloadRequirement` — per-kind required / optional / enum field
//!   schemas.
//! - `validate_operation_semantics` / `validate_operation_schema` — the entrypoint validators
//!   called from `event_log::submit_event`, `projection::project_accepted_operations`, and the
//!   federation ingest path.
//! - `validate_operation_policy` — high-level policy gate (plaintext-Space gating + B-09 redact
//!   constraints).
//! - `validate_canonical_json_value` (+ `_inner`) — the canonical-JSON shape gate that operation
//!   payloads MUST pass.
//! - `validate_content_blocks` / `validate_mentions` / `validate_content_block` — message body
//!   shape.
//! - `validate_encrypted_payload_envelope` — `cx.profile.encrypted_payload.v1` envelope shape (MLS
//!   sender / scheme / version / `key_ref`).
//! - `validate_device_message_payload` — to-device payload shape.
//! - `validate_no_removed_legacy_contracts` (+ scanners) — kicks payloads that reference the
//!   removed legacy `cx.subject.*` / `cx.room.*` / `cx.card.*` contracts.
//! - `validate_rfc3339_utc_z` — UTC-Z timestamp shape.
//! - `canonical_json_digest` — sha256 over canonical-JSON bytes.
//!
//! Spec items still pending here are tracked in `_todos.md` (notably
//! Stream-A19 for B-09 redact `actor_seq` preservation, B-22 for
//! encrypted-attachment `key_ref` shape, and the operation-schema gaps
//! around the 100+ event kinds the reducer doesn't cover yet).

use contrix_sdk::{Hash, Operation};

use super::{is_json_integer, is_valid_sha256_digest, validate_did};
use crate::kinds;
use crate::state::AppState;

#[derive(Clone, Copy)]
pub struct OperationPayloadSchema {
    requirements: &'static [PayloadRequirement],
    validate: Option<fn(&Operation) -> Result<(), &'static str>>,
}

#[derive(Clone, Copy)]
pub enum PayloadRequirement {
    Required(&'static str, &'static str),
    AnyOf(&'static [&'static str], &'static str),
}

const MESSAGE_CREATE_FIELDS: &[&str] = &["body", "content", "event_id"];
const MESSAGE_TARGET_FIELDS: &[&str] = &["target_event_id", "event_id", "target"];
const MESSAGE_CONTENT_FIELDS: &[&str] = &["content", "body"];
const REDACTION_TARGET_FIELDS: &[&str] = &["target_event_id", "target", "redacts"];
const REACTION_TARGET_FIELDS: &[&str] = &[
    "event_id",
    "target_event_id",
    "message_id",
    "target_message_id",
];
const REACTION_ACTOR_FIELDS: &[&str] = &["actor", "sender"];
const REACTION_KEY_FIELDS: &[&str] = &["key", "reaction", "reaction_key"];
const RELATION_ID_FIELDS: &[&str] = &["relation_id", "id"];
const RELATION_KIND_FIELDS: &[&str] = &["relation_kind", "kind"];
const RELATION_FROM_FIELDS: &[&str] = &["from_ref", "from"];
const RELATION_TO_FIELDS: &[&str] = &["to_ref", "to"];
const MEMBER_ACTOR_FIELDS: &[&str] = &["actor_id", "member", "actor", "sender"];
const READ_MARKER_ACTOR_FIELDS: &[&str] = &["actor", "sender"];

const MESSAGE_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MESSAGE_CREATE_FIELDS,
    "message operation requires body, content, or event_id",
)];
const MESSAGE_REVISE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        MESSAGE_TARGET_FIELDS,
        "message revision requires target_event_id",
    ),
    PayloadRequirement::AnyOf(
        MESSAGE_CONTENT_FIELDS,
        "message revision requires content or body",
    ),
];
const REDACTION_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    REDACTION_TARGET_FIELDS,
    "redaction operation requires target_event_id",
)];
const REACTION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        REACTION_TARGET_FIELDS,
        "reaction operation requires target event",
    ),
    PayloadRequirement::AnyOf(REACTION_ACTOR_FIELDS, "reaction operation requires actor"),
    PayloadRequirement::AnyOf(
        REACTION_KEY_FIELDS,
        "reaction operation requires reaction key",
    ),
];
const RELATION_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        RELATION_ID_FIELDS,
        "relation operation requires relation_id",
    ),
    PayloadRequirement::AnyOf(
        RELATION_KIND_FIELDS,
        "relation create requires relation_kind",
    ),
    PayloadRequirement::AnyOf(RELATION_FROM_FIELDS, "relation create requires from"),
    PayloadRequirement::AnyOf(RELATION_TO_FIELDS, "relation create requires to"),
];
const RELATION_ID_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    RELATION_ID_FIELDS,
    "relation operation requires relation_id",
)];
const VIEW_ID_FIELDS: &[&str] = &["view_id"];
const VIEW_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    VIEW_ID_FIELDS,
    "view operation requires view_id",
)];
const MEMBERSHIP_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(MEMBER_ACTOR_FIELDS, "membership operation requires member"),
    PayloadRequirement::Required(
        "membership",
        "membership operation requires member and membership",
    ),
];
const SPACE_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "action",
    "space lifecycle operation requires action",
)];
// `cx.place.archive` / `cx.place.restore` / `cx.place.tombstone` share the same
// shape: a single `place_id` field naming the target Place. The state-machine
// guard (`place_not_archived` for restore) lives in both the SDK reducer
// (`crates/sdk/src/resolver/state.rs::restore_place`) and soland's
// server-side guard (`event_log::ensure_place_state_machine_allows`).
const PLACE_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "place_id",
    "place lifecycle operation requires place_id",
)];
// `cx.place.create` carries a full Place object under `object`.
const PLACE_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "object",
    "place create operation requires object",
)];
// `cx.place.update` carries `place_id` + `patch`.
const PLACE_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("place_id", "place update operation requires place_id"),
    PayloadRequirement::Required("patch", "place update operation requires patch"),
];
// `cx.place.parent` carries `place_id` + `parent_ref` (parent is cx:place: or
// cx:space: within the same Space).
const PLACE_PARENT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("place_id", "place parent operation requires place_id"),
    PayloadRequirement::Required("parent_ref", "place parent operation requires parent_ref"),
];
// Flow / Morph lifecycle payload requirements. Spec
// `common-fields.md §5.1` mandates the same `<kind>_id`-only payload for
// archive / restore as Place uses for archive/restore/tombstone. Create
// carries a full object; update carries `<kind>_id` + `patch`.
// `cx.flow.archive` / `cx.flow.restore` payload: just `flow_id`.
const FLOW_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "flow_id",
    "flow lifecycle operation requires flow_id",
)];
const FLOW_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "object",
    "flow create operation requires object",
)];
const FLOW_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow update operation requires flow_id"),
    PayloadRequirement::Required("patch", "flow update operation requires patch"),
];
// `cx.morph.archive` / `cx.morph.restore` payload: just `morph_id`.
const MORPH_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "morph_id",
    "morph lifecycle operation requires morph_id",
)];
const MORPH_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "object",
    "morph create operation requires object",
)];
const MORPH_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("morph_id", "morph update operation requires morph_id"),
    PayloadRequirement::Required("patch", "morph update operation requires patch"),
];
// Flow position events (cx.flow.move / cx.flow.reorder).
// Spec event-kind-registry sets `cell_subject` = (board_place_id, flow_id);
// both fields are MUST-present in the payload. Additional optional fields
// (target_place_id for move, rank for reorder) carry the actual position
// change but are policed at the cell-family layer, not here.
const FLOW_POSITION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow position operation requires flow_id"),
    PayloadRequirement::Required(
        "board_place_id",
        "flow position operation requires board_place_id",
    ),
];
// Flow watch event (cx.flow.watch.set).
// Spec event-kind-registry sets `cell_subject` = (flow_id, actor_did);
// both fields are MUST-present in the payload. `level` is also required
// (null = clear); enum + level_public validation lives at the
// flow_watch_set_payload schema layer.
const FLOW_WATCH_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow watch operation requires flow_id"),
    PayloadRequirement::Required("actor_did", "flow watch operation requires actor_did"),
    PayloadRequirement::Required(
        "level",
        "flow watch operation requires level (use null to clear)",
    ),
];
// Flow track sub-events. Required fields per SDK schemas:
//   `cx.flow.track.{disable,enable,set_primary}` -> flow_id + track_id
//   `cx.flow.track.update`                      -> flow_id + track_id + patch
const FLOW_TRACK_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow track operation requires flow_id"),
    PayloadRequirement::Required("track_id", "flow track operation requires track_id"),
];
const FLOW_TRACK_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow track update requires flow_id"),
    PayloadRequirement::Required("track_id", "flow track update requires track_id"),
    PayloadRequirement::Required("patch", "flow track update requires patch"),
];
// Applet protocol family.
//
// Spec `extensions/applet-integration.md` + event-kind-registry rows:
//   `cx.applet.registration` → service_did + namespace + capabilities
//   `cx.applet.discovery`    → service_did + manifest
//   `cx.applet.protocol_session.start`  → applet_id + session_id + params
//   `cx.applet.protocol_session.status` → session_id + status + detail
//   `cx.applet.bridge_error`            → session_id + errcode + message
//
// We require the structurally-identifying fields; richer policy
// (capability gating, manifest schema, signed bundles) is enforced by
// the applet bridge layer + per-applet contract validators that read
// the payload after admission.
const APPLET_REGISTRATION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("service_did", "applet registration requires service_did"),
    PayloadRequirement::Required("namespace", "applet registration requires namespace"),
];
const APPLET_DISCOVERY_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("service_did", "applet discovery requires service_did"),
    PayloadRequirement::Required("manifest", "applet discovery requires manifest"),
];
const APPLET_SESSION_START_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "applet_id",
        "applet protocol_session.start requires applet_id",
    ),
    PayloadRequirement::Required(
        "session_id",
        "applet protocol_session.start requires session_id",
    ),
];
const APPLET_SESSION_STATUS_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "applet protocol_session.status requires session_id",
    ),
    PayloadRequirement::Required("status", "applet protocol_session.status requires status"),
];
const APPLET_BRIDGE_ERROR_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("session_id", "applet bridge_error requires session_id"),
    PayloadRequirement::Required("errcode", "applet bridge_error requires errcode"),
];

// Agent protocol family. Mirror of applet but with a terminal
// `*.result` event that carries the audit-binding proof + signed agent
// result.
const AGENT_ENDPOINT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("agent_did", "agent endpoint requires agent_did"),
    PayloadRequirement::Required("protocol", "agent endpoint requires protocol"),
];
const AGENT_SESSION_START_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_did",
        "agent protocol_session.start requires agent_did",
    ),
    PayloadRequirement::Required(
        "session_id",
        "agent protocol_session.start requires session_id",
    ),
    PayloadRequirement::Required(
        "capability_proof",
        "agent protocol_session.start requires capability_proof",
    ),
];
const AGENT_SESSION_STATUS_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "agent protocol_session.status requires session_id",
    ),
    PayloadRequirement::Required("status", "agent protocol_session.status requires status"),
];
const AGENT_SESSION_RESULT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "agent protocol_session.result requires session_id",
    ),
    PayloadRequirement::Required("result", "agent protocol_session.result requires result"),
    PayloadRequirement::Required(
        "audit_binding",
        "agent protocol_session.result requires audit_binding",
    ),
];

// `cx.profile.agent_workspace.v1` — agent_task object + 3 FSM cell transitions
// + cancel alias. Spec: contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §3.6.
const AGENT_TASK_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("task_id", "agent_task.create requires task_id"),
    PayloadRequirement::Required(
        "target_agent_id",
        "agent_task.create requires target_agent_id",
    ),
    PayloadRequirement::Required("instruction", "agent_task.create requires instruction"),
];
const AGENT_TASK_TRANSITION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("task_id", "agent_task transition requires task_id"),
    PayloadRequirement::Required("cell", "agent_task transition requires cell"),
    PayloadRequirement::Required("op", "agent_task transition requires op=transition"),
    PayloadRequirement::Required("from", "agent_task transition requires from"),
    PayloadRequirement::Required("to", "agent_task transition requires to"),
];
const AGENT_TASK_CANCEL_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "task_id",
    "agent_task.cancel requires task_id",
)];

// Reservation Moves on `mirror_*_by_source` cells. Spec §6.2 / §6.3 / §6.4.
const AGENT_WORKSPACE_RESERVATION_SET_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "cell_namespace",
        "reservation.set requires cell_namespace (mirror_space_by_source | mirror_flow_by_source)",
    ),
    PayloadRequirement::Required(
        "cell_namespace_subject",
        "reservation.set requires cell_namespace_subject (source object id)",
    ),
    PayloadRequirement::Required(
        "reservation_id",
        "reservation.set requires reservation_id (pre-allocated mirror_*_id)",
    ),
];
const AGENT_WORKSPACE_RESERVATION_RECOVER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "cell_namespace",
        "reservation.recover requires cell_namespace",
    ),
    PayloadRequirement::Required(
        "cell_namespace_subject",
        "reservation.recover requires cell_namespace_subject",
    ),
    PayloadRequirement::Required(
        "conflict_heads",
        "reservation.recover requires conflict_heads[] (>=2 candidate cell heads from ⊥ diagnostic)",
    ),
    PayloadRequirement::Required(
        "winner",
        "reservation.recover requires winner (MUST equal lex-min(conflict_heads))",
    ),
];
const AGENT_WORKSPACE_RESERVATION_CLEANUP_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "cell_namespace",
        "reservation.cleanup requires cell_namespace",
    ),
    PayloadRequirement::Required(
        "cell_namespace_subject",
        "reservation.cleanup requires cell_namespace_subject",
    ),
    PayloadRequirement::Required(
        "stale_reservation_id",
        "reservation.cleanup requires stale_reservation_id (cell head_eq predicate target)",
    ),
    PayloadRequirement::Required(
        "ttl_evidence",
        "reservation.cleanup requires anchor-based ttl_evidence (NOT self-reported wall-clock)",
    ),
];

const READ_MARKER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        READ_MARKER_ACTOR_FIELDS,
        "read marker operation requires actor",
    ),
    PayloadRequirement::Required("event_id", "read marker operation requires event_id"),
];

const REMOVED_LEGACY_TYPED_ID_PREFIXES: &[&str] = &["cx:subject:", "cx:room:", "cx:card:"];
const REMOVED_LEGACY_SCHEMA_IDS: &[&str] = &[
    "cx.schema.subject.v1",
    "cx.schema.room.v1",
    "cx.schema.card.v1",
];
const REMOVED_LEGACY_EVENT_PREFIXES: &[&str] = &["cx.subject.", "cx.room.", "cx.card."];
const ACTIVE_WIRE_LEGACY_CONTRACT_ERROR: &str =
    "removed legacy subject/room/card contract is forbidden on the active v1 wire";

pub fn is_removed_legacy_contract_string(value: &str) -> bool {
    REMOVED_LEGACY_TYPED_ID_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
        || REMOVED_LEGACY_SCHEMA_IDS
            .iter()
            .any(|schema_id| value == *schema_id)
        || REMOVED_LEGACY_EVENT_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

pub fn value_contains_removed_legacy_contract(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => is_removed_legacy_contract_string(value),
        serde_json::Value::Array(values) => {
            values.iter().any(value_contains_removed_legacy_contract)
        }
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(key.as_str(), "room_id" | "card_id" | "subject_id")
                || value_contains_removed_legacy_contract(value)
        }),
        _ => false,
    }
}

pub fn validate_no_removed_legacy_contracts(value: &serde_json::Value) -> Result<(), &'static str> {
    if value_contains_removed_legacy_contract(value) {
        Err(ACTIVE_WIRE_LEGACY_CONTRACT_ERROR)
    } else {
        Ok(())
    }
}

pub fn validate_operation_semantics(
    _state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        operation
            .validate_payload_object()
            .map_err(|_| "operation payload must be a JSON object")?;
        if is_removed_legacy_contract_string(operation.object_type.as_str())
            || operation
                .object_id
                .as_deref()
                .is_some_and(is_removed_legacy_contract_string)
        {
            return Err(ACTIVE_WIRE_LEGACY_CONTRACT_ERROR);
        }
        validate_no_removed_legacy_contracts(&operation.payload)?;
        validate_canonical_json_value(&operation.payload)?;
        let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
            return Err("unregistered operation kind");
        };
        let Some(schema) = operation_schema_for_kind(kind) else {
            return Err("unregistered operation kind");
        };
        validate_operation_schema(operation, schema)?;
    }
    Ok(())
}

pub fn operation_schema_for_kind(kind: &str) -> Option<OperationPayloadSchema> {
    let schema = match kind {
        kinds::CX_MESSAGE_CREATE => OperationPayloadSchema {
            requirements: MESSAGE_CREATE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        kinds::CX_MESSAGE_REVISE => OperationPayloadSchema {
            requirements: MESSAGE_REVISE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        kinds::CX_MESSAGE_REDACT | kinds::CX_REDACTION => OperationPayloadSchema {
            requirements: REDACTION_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_REACTION_ADD | kinds::CX_REACTION_REMOVE => OperationPayloadSchema {
            requirements: REACTION_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_RELATION_CREATE => OperationPayloadSchema {
            requirements: RELATION_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_RELATION_UPDATE | kinds::CX_RELATION_DELETE => OperationPayloadSchema {
            requirements: RELATION_ID_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_VIEW_CREATE | kinds::CX_VIEW_UPDATE | kinds::CX_VIEW_RECONCILE => {
            // `cx.view.*` events route through the `cx.component.view.*.v1`
            // cell families in the lattice registry (see
            // `reducer::lattice_kinds::ViewCreate / ViewUpdate / ViewReconcile`).
            // The validator just enforces a `view_id` payload key — the
            // reducer / cell-family pipeline owns mv-register semantics.
            OperationPayloadSchema {
                requirements: VIEW_CREATE_REQUIREMENTS,
                validate: None,
            }
        }
        kinds::CX_READ_MARKER => OperationPayloadSchema {
            requirements: READ_MARKER_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_membership_kind(kind) => OperationPayloadSchema {
            requirements: MEMBERSHIP_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_space_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: SPACE_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_place_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: PLACE_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_PLACE_CREATE => OperationPayloadSchema {
            requirements: PLACE_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_PLACE_UPDATE => OperationPayloadSchema {
            requirements: PLACE_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_PLACE_PARENT => OperationPayloadSchema {
            requirements: PLACE_PARENT_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_flow_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: FLOW_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_CREATE => OperationPayloadSchema {
            requirements: FLOW_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_UPDATE => OperationPayloadSchema {
            requirements: FLOW_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_MOVE | kinds::CX_FLOW_REORDER => OperationPayloadSchema {
            requirements: FLOW_POSITION_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_WATCH_SET => OperationPayloadSchema {
            requirements: FLOW_WATCH_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_TRACK_DISABLE
        | kinds::CX_FLOW_TRACK_ENABLE
        | kinds::CX_FLOW_TRACK_SET_PRIMARY => OperationPayloadSchema {
            requirements: FLOW_TRACK_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_TRACK_UPDATE => OperationPayloadSchema {
            requirements: FLOW_TRACK_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_morph_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: MORPH_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_MORPH_CREATE => OperationPayloadSchema {
            requirements: MORPH_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_MORPH_UPDATE => OperationPayloadSchema {
            requirements: MORPH_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kind if matches!(
            kind,
            kinds::CX_FIELD_POSITION_MOVE | kinds::CX_FIELD_POSITION_REORDER
        ) =>
        {
            // Flow / place position ops carry a `flow_id` or `place_id`
            // payload — relation_id requirements cover both because every
            // positional op runs through `cx.relation.position.*` cells.
            OperationPayloadSchema {
                requirements: RELATION_ID_REQUIREMENTS,
                validate: None,
            }
        }
        kind if matches!(
            kind,
            kinds::CX_CONTAINER_MOVE_ITEM | kinds::CX_CONTAINER_REBALANCE
        ) =>
        {
            OperationPayloadSchema {
                requirements: RELATION_ID_REQUIREMENTS,
                validate: None,
            }
        }
        // Applet protocol family.
        kinds::CX_APPLET_REGISTRATION => OperationPayloadSchema {
            requirements: APPLET_REGISTRATION_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_APPLET_DISCOVERY => OperationPayloadSchema {
            requirements: APPLET_DISCOVERY_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_APPLET_PROTOCOL_SESSION_START => OperationPayloadSchema {
            requirements: APPLET_SESSION_START_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_APPLET_PROTOCOL_SESSION_STATUS => OperationPayloadSchema {
            requirements: APPLET_SESSION_STATUS_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_APPLET_BRIDGE_ERROR => OperationPayloadSchema {
            requirements: APPLET_BRIDGE_ERROR_REQUIREMENTS,
            validate: None,
        },
        // Agent protocol family.
        kinds::CX_AGENT_ENDPOINT => OperationPayloadSchema {
            requirements: AGENT_ENDPOINT_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_PROTOCOL_SESSION_START => OperationPayloadSchema {
            requirements: AGENT_SESSION_START_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_PROTOCOL_SESSION_STATUS => OperationPayloadSchema {
            requirements: AGENT_SESSION_STATUS_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_PROTOCOL_SESSION_RESULT => OperationPayloadSchema {
            requirements: AGENT_SESSION_RESULT_REQUIREMENTS,
            validate: None,
        },
        // `cx.profile.agent_workspace.v1` — agent_task lifecycle + 3 FSM cells.
        kinds::CX_AGENT_TASK_CREATE => OperationPayloadSchema {
            requirements: AGENT_TASK_CREATE_REQUIREMENTS,
            validate: Some(validate_agent_task_create_payload),
        },
        kinds::CX_AGENT_TASK_EXECUTION_TRANSITION
        | kinds::CX_AGENT_TASK_TRANSPARENCY_TRANSITION
        | kinds::CX_AGENT_TASK_SOURCE_AUTHORITY_TRANSITION => OperationPayloadSchema {
            requirements: AGENT_TASK_TRANSITION_REQUIREMENTS,
            validate: Some(validate_agent_task_transition_payload),
        },
        kinds::CX_AGENT_TASK_CANCEL => OperationPayloadSchema {
            requirements: AGENT_TASK_CANCEL_REQUIREMENTS,
            validate: None,
        },
        // Reservation Moves on the workspace root + mirror Space cells.
        kinds::CX_AGENT_WORKSPACE_RESERVATION_SET => OperationPayloadSchema {
            requirements: AGENT_WORKSPACE_RESERVATION_SET_REQUIREMENTS,
            validate: Some(validate_agent_workspace_reservation_set_payload),
        },
        kinds::CX_AGENT_WORKSPACE_RESERVATION_RECOVER => OperationPayloadSchema {
            requirements: AGENT_WORKSPACE_RESERVATION_RECOVER_REQUIREMENTS,
            validate: Some(validate_agent_workspace_reservation_recover_payload),
        },
        kinds::CX_AGENT_WORKSPACE_RESERVATION_CLEANUP => OperationPayloadSchema {
            requirements: AGENT_WORKSPACE_RESERVATION_CLEANUP_REQUIREMENTS,
            validate: Some(validate_agent_workspace_reservation_cleanup_payload),
        },
        _ => return None,
    };
    Some(schema)
}

// ── `cx.profile.agent_workspace.v1` semantic validators ─────────────────────
//
// These augment the field-presence checks above with the spec's content-shape
// rules. Returning `Err` here surfaces as an `unprocessable_entity` rejection
// before the Move ever reaches the lattice projection layer.

fn validate_agent_task_create_payload(op: &Operation) -> Result<(), &'static str> {
    let payload = &op.payload;
    let task_id = payload
        .get("task_id")
        .and_then(|v| v.as_str())
        .ok_or("agent_task.create task_id must be a string")?;
    if !task_id.starts_with("cx:agent_task:") {
        return Err("agent_task.create task_id MUST be cx:agent_task:<uuid>");
    }
    let target = payload
        .get("target_agent_id")
        .and_then(|v| v.as_str())
        .ok_or("agent_task.create target_agent_id must be a string")?;
    validate_did(target).map_err(|_| "agent_task.create target_agent_id is not a valid DID")?;
    if !payload.get("instruction").is_some_and(|v| v.is_object()) {
        return Err("agent_task.create instruction MUST be a content block object");
    }
    Ok(())
}

fn validate_agent_task_transition_payload(op: &Operation) -> Result<(), &'static str> {
    let payload = &op.payload;
    if payload.get("op").and_then(|v| v.as_str()) != Some("transition") {
        return Err("agent_task transition payload op MUST be 'transition'");
    }
    let cell = payload
        .get("cell")
        .and_then(|v| v.as_str())
        .ok_or("agent_task transition cell must be a string")?;
    if !cell.starts_with("agent_task.") {
        return Err("agent_task transition cell MUST start with agent_task.");
    }
    let suffix_ok = cell.ends_with(".execution_state")
        || cell.ends_with(".transparency")
        || cell.ends_with(".source_authority");
    if !suffix_ok {
        return Err(
            "agent_task transition cell suffix MUST be .execution_state / .transparency / .source_authority",
        );
    }
    let task_id = payload
        .get("task_id")
        .and_then(|v| v.as_str())
        .ok_or("agent_task transition task_id must be a string")?;
    if !cell.contains(task_id) {
        return Err("agent_task transition cell MUST embed task_id");
    }
    if payload.get("from").and_then(|v| v.as_str()).is_none() {
        return Err("agent_task transition from must be a string");
    }
    if payload.get("to").and_then(|v| v.as_str()).is_none() {
        return Err("agent_task transition to must be a string");
    }
    Ok(())
}

fn validate_cell_namespace(value: &str) -> Result<(), &'static str> {
    match value {
        "mirror_space_by_source" | "mirror_flow_by_source" => Ok(()),
        _ => Err("cell_namespace MUST be mirror_space_by_source or mirror_flow_by_source"),
    }
}

fn validate_agent_workspace_reservation_set_payload(op: &Operation) -> Result<(), &'static str> {
    let payload = &op.payload;
    let namespace = payload
        .get("cell_namespace")
        .and_then(|v| v.as_str())
        .ok_or("reservation.set cell_namespace must be a string")?;
    validate_cell_namespace(namespace)?;
    let subject = payload
        .get("cell_namespace_subject")
        .and_then(|v| v.as_str())
        .ok_or("reservation.set cell_namespace_subject must be a string")?;
    let expected_prefix = match namespace {
        "mirror_space_by_source" => "cx:space:",
        "mirror_flow_by_source" => "cx:flow:",
        _ => unreachable!(),
    };
    if !subject.starts_with(expected_prefix) {
        return Err(
            "reservation.set cell_namespace_subject prefix MUST match cell_namespace (cx:space: or cx:flow:)",
        );
    }
    let res_id = payload
        .get("reservation_id")
        .and_then(|v| v.as_str())
        .ok_or("reservation.set reservation_id must be a string")?;
    if !res_id.starts_with(expected_prefix) {
        return Err(
            "reservation.set reservation_id prefix MUST match cell_namespace (cx:space:/cx:flow:)",
        );
    }
    if let Some(ttl) = payload.get("reservation_ttl_seconds") {
        if !is_json_integer(ttl) || ttl.as_i64().unwrap_or(0) < 1 {
            return Err("reservation.set reservation_ttl_seconds MUST be a positive integer");
        }
    }
    Ok(())
}

fn validate_agent_workspace_reservation_recover_payload(
    op: &Operation,
) -> Result<(), &'static str> {
    let payload = &op.payload;
    let namespace = payload
        .get("cell_namespace")
        .and_then(|v| v.as_str())
        .ok_or("reservation.recover cell_namespace must be a string")?;
    validate_cell_namespace(namespace)?;
    let heads = payload
        .get("conflict_heads")
        .and_then(|v| v.as_array())
        .ok_or("reservation.recover conflict_heads must be an array")?;
    if heads.len() < 2 {
        return Err("reservation.recover conflict_heads MUST contain >=2 candidate heads");
    }
    let mut head_strs: Vec<&str> = Vec::with_capacity(heads.len());
    for head in heads {
        head_strs.push(
            head.as_str()
                .ok_or("reservation.recover conflict_heads entries must be strings")?,
        );
    }
    let winner = payload
        .get("winner")
        .and_then(|v| v.as_str())
        .ok_or("reservation.recover winner must be a string")?;
    // Lex-min deterministic winner enforcement per spec §8.
    let computed_winner = head_strs
        .iter()
        .min()
        .copied()
        .ok_or("reservation.recover conflict_heads is empty")?;
    if winner != computed_winner {
        return Err("reservation.recover winner MUST equal lex-min(conflict_heads)");
    }
    Ok(())
}

fn validate_agent_workspace_reservation_cleanup_payload(
    op: &Operation,
) -> Result<(), &'static str> {
    let payload = &op.payload;
    validate_cell_namespace(
        payload
            .get("cell_namespace")
            .and_then(|v| v.as_str())
            .ok_or("reservation.cleanup cell_namespace must be a string")?,
    )?;
    if payload
        .get("stale_reservation_id")
        .and_then(|v| v.as_str())
        .is_none()
    {
        return Err("reservation.cleanup stale_reservation_id must be a string");
    }
    let ttl = payload
        .get("ttl_evidence")
        .and_then(|v| v.as_object())
        .ok_or("reservation.cleanup ttl_evidence must be an object")?;
    for required in ["reservation_anchor_ref", "current_anchor_ref"] {
        if !ttl.contains_key(required) {
            return Err(
                "reservation.cleanup ttl_evidence requires reservation_anchor_ref + current_anchor_ref",
            );
        }
    }
    let res_idx = ttl
        .get("reservation_anchor_index")
        .ok_or("ttl_evidence.reservation_anchor_index required")?;
    let cur_idx = ttl
        .get("current_anchor_index")
        .ok_or("ttl_evidence.current_anchor_index required")?;
    let ttl_dist = ttl
        .get("ttl_anchor_distance")
        .ok_or("ttl_evidence.ttl_anchor_distance required")?;
    if !is_json_integer(res_idx) || !is_json_integer(cur_idx) || !is_json_integer(ttl_dist) {
        return Err("ttl_evidence indices and distance MUST be integers");
    }
    let res_idx = res_idx.as_i64().unwrap_or(-1);
    let cur_idx = cur_idx.as_i64().unwrap_or(-1);
    let ttl_dist = ttl_dist.as_i64().unwrap_or(0);
    if res_idx < 0 || cur_idx < 0 || ttl_dist < 1 {
        return Err("ttl_evidence indices MUST be >=0 and ttl_anchor_distance >=1");
    }
    // Spec §6.4: current_anchor_index >= reservation_anchor_index + ttl_anchor_distance.
    if cur_idx < res_idx.saturating_add(ttl_dist) {
        return Err(
            "reservation.cleanup ttl_evidence FAILED: current_anchor_index < reservation_anchor_index + ttl_anchor_distance",
        );
    }
    Ok(())
}

pub fn validate_operation_schema(
    operation: &Operation,
    schema: OperationPayloadSchema,
) -> Result<(), &'static str> {
    for requirement in schema.requirements {
        match requirement {
            PayloadRequirement::Required(field, message) => {
                if !payload_field_present(&operation.payload, field) {
                    return Err(message);
                }
            }
            PayloadRequirement::AnyOf(fields, message) => {
                if !fields
                    .iter()
                    .any(|field| payload_field_present(&operation.payload, field))
                {
                    return Err(message);
                }
            }
        }
    }
    if let Some(validate) = schema.validate {
        validate(operation)?;
    }
    Ok(())
}

pub fn payload_field_present(payload: &serde_json::Value, field: &str) -> bool {
    payload.get(field).is_some_and(|value| !value.is_null())
}

pub fn validate_message_operation_payload(operation: &Operation) -> Result<(), &'static str> {
    if operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        let Some(content) = operation.payload.get("content") else {
            return Err("encrypted message operation requires content envelope");
        };
        validate_encrypted_payload_envelope(content)?;
    } else if let Some(content) = operation.payload.get("content") {
        validate_content_blocks(content)?;
        validate_mentions(content)?;
    }
    Ok(())
}

pub fn validate_operation_policy(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        if kinds::operation_is_message_create(operation)
            && !message_operation_is_encrypted(operation)
            && known_space_denies_plaintext_service(state, operation.space_id.as_str())
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
    }
    Ok(())
}

pub fn message_operation_is_encrypted(operation: &Operation) -> bool {
    operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub fn known_space_denies_plaintext_service(state: &AppState, space_id: &str) -> bool {
    state
        .persistence
        .space_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| {
            record.discoverability != "public"
                && !record
                    .plaintext_visible_services
                    .contains(&state.config.service_did)
        })
}

pub fn validate_device_message_payload(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(message) = content.as_object() else {
        return Err("device message must be a JSON object");
    };
    if !message
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("device message requires type");
    }
    let Some(envelope) = message.get("content") else {
        return Err("device message requires encrypted content envelope");
    };
    validate_encrypted_payload_envelope(envelope)
}

pub fn validate_content_blocks(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(blocks) = content.get("blocks") else {
        return Ok(());
    };
    let Some(blocks) = blocks.as_array() else {
        return Err("content.blocks must be an array");
    };
    if blocks.is_empty() {
        return Err("content.blocks must not be empty");
    }
    for block in blocks {
        validate_content_block(block)?;
    }
    Ok(())
}

pub fn validate_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(mentions) = content.get("mentions") else {
        return Ok(());
    };
    let Some(mentions) = mentions.as_array() else {
        return Err("mentions must be an array");
    };
    for mention in mentions {
        if let Some(did) = mention.as_str() {
            validate_did(did).map_err(|_| "mention DID is invalid")?;
            continue;
        }
        let Some(mention) = mention.as_object() else {
            return Err("mention must be a DID string or reference object");
        };
        match mention.get("type").and_then(|value| value.as_str()) {
            Some("actor") => {
                let Some(did) = mention.get("did").and_then(|value| value.as_str()) else {
                    return Err("actor mention requires did");
                };
                validate_did(did).map_err(|_| "mention DID is invalid")?;
            }
            Some("flow") => {
                if !mention
                    .get("flow_id")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.starts_with("cx:flow:"))
                {
                    return Err("flow mention requires flow_id");
                }
            }
            _ => return Err("mention type must be actor or flow"),
        }
    }
    Ok(())
}

pub fn validate_canonical_json_value(value: &serde_json::Value) -> Result<(), &'static str> {
    validate_canonical_json_value_inner(value, true)
}

pub fn validate_canonical_json_value_inner(
    value: &serde_json::Value,
    root: bool,
) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err("canonical JSON does not allow floating point numbers");
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_canonical_json_value_inner(value, false)?;
            }
        }
        serde_json::Value::Object(object) => {
            let mut prev_key: Option<&str> = None;
            for key in object.keys() {
                // snake_case validation: lowercase alphanumeric and underscores,
                // with an exception for $-prefixed JSON Schema fields ($id, $schema, $ref, etc.).
                if key.is_empty() {
                    return Err("canonical JSON field name must not be empty");
                }
                let name_part = if let Some(stripped) = key.strip_prefix('$') {
                    if stripped.is_empty() {
                        return Err("canonical JSON field name '$' alone is not valid");
                    }
                    stripped
                } else {
                    key.as_str()
                };
                if !name_part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    return Err(
                        "canonical JSON field name must be snake_case (lowercase alphanumeric and underscores)",
                    );
                }
                if name_part.starts_with('_') || name_part.ends_with('_') {
                    return Err("canonical JSON field name must not start or end with underscore");
                }
                if name_part.contains("__") {
                    return Err(
                        "canonical JSON field name must not contain consecutive underscores",
                    );
                }
                // Unicode code point ascending order.
                if let Some(prev) = prev_key {
                    if key.as_bytes() <= prev.as_bytes() {
                        return Err("canonical JSON object keys must be sorted in ascending order");
                    }
                }
                prev_key = Some(key);
            }
            for value in object.values() {
                validate_canonical_json_value_inner(value, false)?;
            }
            // RFC3339 UTC Z timestamp validation for fields named *_at or *_at_ms.
            for (key, value) in object {
                if key.ends_with("_at") {
                    if let Some(s) = value.as_str() {
                        validate_rfc3339_utc_z(s)?;
                    }
                }
            }
        }
        _ => {}
    }
    // At the top level, attempt a canonical byte roundtrip to ensure full compliance.
    if root {
        if let Err(_) = contrix_sdk::canonical::canonical_json_bytes(value) {
            return Err("value fails canonical JSON byte serialization");
        }
    }
    Ok(())
}

pub fn validate_rfc3339_utc_z(s: &str) -> Result<(), &'static str> {
    // Must end with 'Z' (UTC) and contain 'T' separator.
    if !s.ends_with('Z') {
        return Err("timestamp must use UTC 'Z' suffix");
    }
    if !s.contains('T') {
        return Err("timestamp must use 'T' date-time separator");
    }
    // Basic structural validation: YYYY-MM-DDTHH:MM:SS...Z
    let date_part = &s[..s.find('T').unwrap()];
    let time_part = &s[s.find('T').unwrap() + 1..s.len() - 1];
    let date_segments: Vec<&str> = date_part.split('-').collect();
    if date_segments.len() != 3 {
        return Err("timestamp date must be YYYY-MM-DD");
    }
    if date_segments[0].len() != 4 || date_segments[1].len() != 2 || date_segments[2].len() != 2 {
        return Err("timestamp date segments must be zero-padded");
    }
    // Time must have at least HH:MM:SS.
    let time_segments: Vec<&str> = time_part.split(':').collect();
    if time_segments.len() < 3 {
        return Err("timestamp time must be HH:MM:SS[Z]");
    }
    Ok(())
}

/// Compute a canonical SHA-256 digest of a JSON value using SDK canonical encoding.
#[allow(dead_code)]
pub fn canonical_json_digest(value: &serde_json::Value) -> Result<Hash, String> {
    contrix_sdk::canonical::canonical_sha256(value)
        .and_then(|digest| {
            Hash::new(digest).map_err(|e| contrix_sdk::Error::Protocol(e.to_string()))
        })
        .map_err(|e| e.to_string())
}

pub fn validate_content_block(block: &serde_json::Value) -> Result<(), &'static str> {
    let Some(block) = block.as_object() else {
        return Err("content block must be a JSON object");
    };
    // Per spec 2026-05-09 (C21): content_block.type → content_block.kind.
    // Accept new `kind` only; v1 not yet released → no compat for legacy `type`.
    let Some(block_kind) = block.get("kind").and_then(|value| value.as_str()) else {
        return Err("content block requires kind");
    };
    match block_kind {
        "text" | "formatted_text" => {
            if !block
                .get("text")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err("text content block requires text");
            }
        }
        "code" => {
            if !block
                .get("text")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.is_empty())
            {
                return Err("code content block requires text");
            }
        }
        "image" | "video" | "audio" | "file" => {
            let has_blob_ref = block
                .get("blob_ref")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.starts_with("cx:blob:sha256:"));
            let has_url = block
                .get("url")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            if !has_blob_ref && !has_url {
                return Err("media content block requires blob_ref or url");
            }
        }
        "location" => {
            if !block.get("latitude").is_some_and(is_json_integer)
                || !block.get("longitude").is_some_and(is_json_integer)
            {
                return Err("location content block requires latitude and longitude");
            }
        }
        "poll" => {
            if !block
                .get("question")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
                || !block
                    .get("options")
                    .and_then(|value| value.as_array())
                    .is_some_and(|options| options.len() >= 2)
            {
                return Err("poll content block requires question and at least two options");
            }
        }
        // `cx.profile.agent_workspace.v1` content blocks.
        // Spec: agent-workspace-profile.md §8.1 / §8.2.
        "cx.content.mention_redirect" => {
            // Privacy invariant: source-side stub MUST NOT leak mirror IDs.
            // body / target_actor_id / authority_grant_ref / redirect_pair_id
            // are required (per content-mention-redirect.schema.json).
            if block.get("body").and_then(|v| v.as_str()).is_none() {
                return Err("mention_redirect requires body (Content Block fallback)");
            }
            let target = block
                .get("target_actor_id")
                .and_then(|v| v.as_str())
                .ok_or("mention_redirect requires target_actor_id")?;
            validate_did(target)
                .map_err(|_| "mention_redirect target_actor_id is not a valid DID")?;
            let grant_ref = block
                .get("authority_grant_ref")
                .and_then(|v| v.as_str())
                .ok_or("mention_redirect requires authority_grant_ref")?;
            if !grant_ref.starts_with("cx:grant:") {
                return Err("mention_redirect authority_grant_ref MUST be cx:grant:<uuidv7>");
            }
            let pair_id = block
                .get("redirect_pair_id")
                .and_then(|v| v.as_str())
                .ok_or("mention_redirect requires redirect_pair_id")?;
            if pair_id.trim().is_empty() {
                return Err("mention_redirect redirect_pair_id MUST be a non-empty opaque UUIDv7");
            }
            // Defensive: reject leaked private workspace pointers from old
            // drafts. Per spec §3.3 these fields were explicitly removed in
            // Rev 2 to preserve workspace existence non-enumerability.
            for forbidden in [
                "redirect_to_space_id",
                "redirect_to_flow_id",
                "redirect_event_id",
                "redirect_event_commitment",
            ] {
                if block.contains_key(forbidden) {
                    return Err(
                        "mention_redirect MUST NOT carry redirect_to_* / redirect_event_* (privacy invariant)",
                    );
                }
            }
        }
        "cx.content.import_attestation" => {
            if block.get("body").and_then(|v| v.as_str()).is_none() {
                return Err("import_attestation requires body (Content Block fallback)");
            }
            let claimed = block
                .get("claimed_origin")
                .and_then(|v| v.as_object())
                .ok_or("import_attestation requires claimed_origin object")?;
            for field in [
                "space_id",
                "flow_id",
                "message_id",
                "actor_id",
                "created_at",
            ] {
                if !claimed.contains_key(field) {
                    return Err(
                        "import_attestation claimed_origin requires space_id / flow_id / message_id / actor_id / created_at",
                    );
                }
            }
            let importer = block
                .get("importer")
                .and_then(|v| v.as_object())
                .ok_or("import_attestation requires importer object")?;
            if !importer.contains_key("actor_id") || !importer.contains_key("imported_at") {
                return Err("import_attestation importer requires actor_id + imported_at");
            }
            if block
                .get("import_signature")
                .and_then(|v| v.as_str())
                .is_none()
            {
                return Err("import_attestation requires import_signature");
            }
            if !block.get("content").is_some_and(|v| v.is_object()) {
                return Err("import_attestation requires re-encrypted content block");
            }
        }
        _ => return Err("unsupported content block type"),
    }
    Ok(())
}

/// Returns the canonical critical_extension feature ID a payload's
/// `requirements.critical_extensions[]` MUST contain. None when no
/// agent_workspace-gated content block is present.
//
// SO-4: not worth refactoring at current arm count (1 named arm + wildcard);
// revisit when it grows. A HashMap-keyed dispatcher (one free
// `fn(&Value) -> Result<(), AppError>` per content kind) only pays off once
// the match has ~10+ arms — at that point every new content kind ought to
// land as its own helper rather than a one-line arm here.
pub fn agent_workspace_required_feature_id(content: &serde_json::Value) -> Option<&'static str> {
    match content.get("kind").and_then(|v| v.as_str()) {
        Some("cx.content.mention_redirect") => Some("cx.feature.mention_redirect.v1"),
        _ => None,
    }
}

#[cfg(test)]
mod agent_workspace_tests {
    use super::*;
    use contrix_sdk::Operation;
    use serde_json::json;

    fn op_with(_kind: &str, payload: serde_json::Value) -> Operation {
        // Note: the `kind` selector is the result of
        // canonical_kind_for_operation() lookup on the operation's
        // object_type + payload, not a struct field on Operation itself.
        // Tests here only exercise payload-shape validators which take a
        // `&Operation` and only read `.payload`; the object_type / id are
        // irrelevant.
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            "agent_task",
            payload,
        )
    }

    #[test]
    fn agent_task_create_accepts_valid_payload() {
        let op = op_with(
            kinds::CX_AGENT_TASK_CREATE,
            json!({
                "task_id": "cx:agent_task:01964200-0000-7000-8000-000000000001",
                "target_agent_id": "did:web:agent.example",
                "instruction": { "kind": "cx.content.text", "body": "do X" }
            }),
        );
        assert!(validate_agent_task_create_payload(&op).is_ok());
    }

    #[test]
    fn agent_task_create_rejects_bad_task_id_prefix() {
        let op = op_with(
            kinds::CX_AGENT_TASK_CREATE,
            json!({
                "task_id": "cx:flow:01964200-0000-7000-8000-000000000001",
                "target_agent_id": "did:web:agent.example",
                "instruction": { "kind": "cx.content.text" }
            }),
        );
        assert!(validate_agent_task_create_payload(&op).is_err());
    }

    #[test]
    fn transition_payload_rejects_wrong_op() {
        let op = op_with(
            kinds::CX_AGENT_TASK_EXECUTION_TRANSITION,
            json!({
                "task_id": "cx:agent_task:01964200-0000-7000-8000-000000000001",
                "cell": "agent_task.cx:agent_task:01964200-0000-7000-8000-000000000001.execution_state",
                "op": "set",
                "from": "pending_source_stub",
                "to": "active"
            }),
        );
        assert!(validate_agent_task_transition_payload(&op).is_err());
    }

    #[test]
    fn transition_payload_rejects_cell_mismatch() {
        let op = op_with(
            kinds::CX_AGENT_TASK_EXECUTION_TRANSITION,
            json!({
                "task_id": "cx:agent_task:01964200-0000-7000-8000-000000000001",
                "cell": "agent_task.cx:agent_task:02000000-0000-0000-0000-000000000000.execution_state",
                "op": "transition",
                "from": "pending_source_stub",
                "to": "active"
            }),
        );
        assert!(validate_agent_task_transition_payload(&op).is_err());
    }

    #[test]
    fn reservation_set_rejects_prefix_mismatch() {
        let op = op_with(
            kinds::CX_AGENT_WORKSPACE_RESERVATION_SET,
            json!({
                "cell_namespace": "mirror_space_by_source",
                "cell_namespace_subject": "cx:flow:01964200-0000-7000-8000-000000000010",
                "reservation_id": "cx:space:01964200-0000-7000-8000-000000000020"
            }),
        );
        let err = validate_agent_workspace_reservation_set_payload(&op);
        assert!(err.is_err());
    }

    #[test]
    fn reservation_recover_enforces_lex_min_winner() {
        let op = op_with(
            kinds::CX_AGENT_WORKSPACE_RESERVATION_RECOVER,
            json!({
                "cell_namespace": "mirror_space_by_source",
                "cell_namespace_subject": "cx:space:01964200-0000-7000-8000-000000000010",
                "conflict_heads": [
                    "cx:space:01964200-0000-7000-8000-0000000000a0",
                    "cx:space:01964200-0000-7000-8000-0000000000b0"
                ],
                "winner": "cx:space:01964200-0000-7000-8000-0000000000b0"
            }),
        );
        let err = validate_agent_workspace_reservation_recover_payload(&op);
        assert!(err.is_err(), "non-lex-min winner MUST be rejected");
    }

    #[test]
    fn reservation_recover_accepts_lex_min_winner() {
        let op = op_with(
            kinds::CX_AGENT_WORKSPACE_RESERVATION_RECOVER,
            json!({
                "cell_namespace": "mirror_space_by_source",
                "cell_namespace_subject": "cx:space:01964200-0000-7000-8000-000000000010",
                "conflict_heads": [
                    "cx:space:01964200-0000-7000-8000-0000000000b0",
                    "cx:space:01964200-0000-7000-8000-0000000000a0"
                ],
                "winner": "cx:space:01964200-0000-7000-8000-0000000000a0"
            }),
        );
        assert!(validate_agent_workspace_reservation_recover_payload(&op).is_ok());
    }

    #[test]
    fn reservation_cleanup_enforces_anchor_distance() {
        // current_index < reservation_index + ttl_distance -> MUST reject.
        let op = op_with(
            kinds::CX_AGENT_WORKSPACE_RESERVATION_CLEANUP,
            json!({
                "cell_namespace": "mirror_space_by_source",
                "cell_namespace_subject": "cx:space:01964200-0000-7000-8000-000000000010",
                "stale_reservation_id": "cx:space:01964200-0000-7000-8000-0000000000a0",
                "ttl_evidence": {
                    "reservation_anchor_ref": "cx:anchor:abc",
                    "reservation_anchor_index": 100,
                    "current_anchor_ref": "cx:anchor:def",
                    "current_anchor_index": 110,
                    "ttl_anchor_distance": 20
                }
            }),
        );
        assert!(validate_agent_workspace_reservation_cleanup_payload(&op).is_err());
    }

    #[test]
    fn reservation_cleanup_accepts_when_ttl_elapsed() {
        let op = op_with(
            kinds::CX_AGENT_WORKSPACE_RESERVATION_CLEANUP,
            json!({
                "cell_namespace": "mirror_flow_by_source",
                "cell_namespace_subject": "cx:flow:01964200-0000-7000-8000-000000000011",
                "stale_reservation_id": "cx:flow:01964200-0000-7000-8000-0000000000a0",
                "ttl_evidence": {
                    "reservation_anchor_ref": "cx:anchor:abc",
                    "reservation_anchor_index": 100,
                    "current_anchor_ref": "cx:anchor:def",
                    "current_anchor_index": 200,
                    "ttl_anchor_distance": 50
                }
            }),
        );
        assert!(validate_agent_workspace_reservation_cleanup_payload(&op).is_ok());
    }

    #[test]
    fn mention_redirect_required_feature_id() {
        assert_eq!(
            agent_workspace_required_feature_id(&json!({"kind": "cx.content.mention_redirect"})),
            Some("cx.feature.mention_redirect.v1"),
        );
        assert_eq!(
            agent_workspace_required_feature_id(&json!({"kind": "cx.content.text"})),
            None,
        );
    }

    #[test]
    fn content_block_mention_redirect_rejects_leaked_redirect_to_fields() {
        let block = json!({
            "kind": "cx.content.mention_redirect",
            "body": "asked privately",
            "target_actor_id": "did:web:agent.example",
            "authority_grant_ref": "cx:grant:01964200-0000-7000-8000-000000000001",
            "redirect_pair_id": "01964200-0000-7000-8000-aaaaaaaaaaaa",
            "redirect_to_space_id": "cx:space:leak"
        });
        assert!(validate_content_block(&block).is_err());
    }

    #[test]
    fn content_block_mention_redirect_accepts_minimal() {
        let block = json!({
            "kind": "cx.content.mention_redirect",
            "body": "asked privately",
            "target_actor_id": "did:web:agent.example",
            "authority_grant_ref": "cx:grant:01964200-0000-7000-8000-000000000001",
            "redirect_pair_id": "01964200-0000-7000-8000-aaaaaaaaaaaa"
        });
        assert!(validate_content_block(&block).is_ok());
    }

    #[test]
    fn content_block_import_attestation_requires_claimed_origin() {
        let block = json!({
            "kind": "cx.content.import_attestation",
            "body": "imported",
            "importer": { "actor_id": "did:web:agent.example", "imported_at": "2026-05-17T10:00:00Z" },
            "import_signature": "sig",
            "content": { "kind": "cx.content.text", "body": "hi" }
        });
        assert!(validate_content_block(&block).is_err());
    }
}

pub fn validate_encrypted_payload_envelope(
    content: &serde_json::Value,
) -> Result<(), &'static str> {
    let Some(envelope) = content.as_object() else {
        return Err("encrypted content must be a JSON object");
    };
    for field in [
        "scheme",
        "group_id",
        "content_type",
        "ciphertext",
        "authentication_tag",
    ] {
        if !envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("encrypted content envelope is missing required string fields");
        }
    }
    if !envelope
        .get("version")
        .is_some_and(|value| value.as_u64().is_some() || value.as_str().is_some())
    {
        return Err("encrypted content envelope requires version");
    }
    if !envelope
        .get("epoch")
        .is_some_and(|value| value.as_u64().is_some())
    {
        return Err("encrypted content envelope requires numeric epoch");
    }
    if !envelope.get("aad").is_some() {
        return Err("encrypted content envelope requires aad");
    }
    if !envelope
        .get("key_ref")
        .is_some_and(|value| value.is_object() || value.as_str().is_some())
    {
        return Err("encrypted content envelope requires key_ref");
    }
    let Some(digests) = envelope.get("digests").and_then(|value| value.as_object()) else {
        return Err("encrypted content envelope requires digests");
    };
    if digests.is_empty() {
        return Err("encrypted content envelope requires digests");
    }
    if !digests.values().all(|value| {
        value
            .as_str()
            .is_some_and(|digest| is_valid_sha256_digest(digest))
    }) {
        return Err("encrypted content envelope digests must be sha256:<64 lowercase hex>");
    }
    Ok(())
}
