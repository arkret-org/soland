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
//! - `validate_rfc3339_utc_z` — UTC-Z timestamp shape.
//! - `canonical_json_digest` — sha256 over canonical-JSON bytes.
//!
//! Spec items still pending here are tracked in `_todos.md` (notably
//! Stream-A19 for B-09 redact `actor_seq` preservation, B-22 for
//! encrypted-attachment `key_ref` shape, and the operation-schema gaps
//! around the 100+ event kinds the reducer doesn't cover yet).

use contrix_sdk::{Hash, Operation, schema::event_payload_validator_catalog};

use super::{is_json_integer, is_valid_sha256_digest, validate_did};
use crate::kinds;
use crate::state::AppState;

const CX_CROSS_SIGNING_RESET: &str = "cx.cross_signing.reset";
const CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS: i64 = 300;

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
const MORPH_SCHEMA_MIGRATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "morph_id",
        "morph schema_migrate operation requires morph_id",
    ),
    PayloadRequirement::Required(
        "from_schema_refs",
        "morph schema_migrate operation requires from_schema_refs",
    ),
    PayloadRequirement::Required(
        "to_schema_refs",
        "morph schema_migrate operation requires to_schema_refs",
    ),
    PayloadRequirement::Required(
        "compatibility_class",
        "morph schema_migrate operation requires compatibility_class",
    ),
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
// Flow tracks update event. Required fields per SDK schema:
//   `cx.flow.tracks.update` -> flow_id + (patch | tracks)
const FLOW_TRACKS_UPDATE_FIELDS: &[&str] = &["patch", "tracks"];
const FLOW_TRACKS_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow tracks update requires flow_id"),
    PayloadRequirement::AnyOf(
        FLOW_TRACKS_UPDATE_FIELDS,
        "flow tracks update requires patch or tracks",
    ),
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
const CROSS_SIGNING_RESET_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("principal_id", "cross_signing reset requires principal_id"),
    PayloadRequirement::Required(
        "previous_generation",
        "cross_signing reset requires previous_generation",
    ),
    PayloadRequirement::Required(
        "new_generation",
        "cross_signing reset requires new_generation",
    ),
    PayloadRequirement::Required("reset_reason", "cross_signing reset requires reset_reason"),
    PayloadRequirement::Required("proof", "cross_signing reset requires proof"),
    PayloadRequirement::Required("issued_at", "cross_signing reset requires issued_at"),
    // Round R2/R3 (T08) — wire-breaking required fields.
    PayloadRequirement::Required(
        "trust_domain",
        "cross_signing reset requires trust_domain (Round R2/R3 wire-break)",
    ),
    PayloadRequirement::Required(
        "reset_event_id",
        "cross_signing reset requires reset_event_id (Round R2/R3 wire-break)",
    ),
];

const READ_MARKER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        READ_MARKER_ACTOR_FIELDS,
        "read marker operation requires actor",
    ),
    PayloadRequirement::Required("event_id", "read marker operation requires event_id"),
];

pub fn validate_operation_semantics(
    _state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    validate_cross_signing_reset_replay_batch(operations)?;
    for operation in operations {
        operation
            .validate_payload_object()
            .map_err(|_| "operation payload must be a JSON object")?;
        validate_canonical_json_value(&operation.payload)?;
        let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
            return Err("unregistered operation kind");
        };
        // Round 4 (B1.13 / B1.14) — typed payload validators for the
        // new wire-broken shapes. These run BEFORE the per-kind schema
        // check so a legacy `target_ref` payload is rejected with the
        // round-4 reason rather than the generic SDK schema error.
        round4_validate_payload(kind, operation)?;
        if let Some(schema) = operation_schema_for_kind(kind) {
            validate_operation_schema(operation, schema)?;
        } else {
            validate_operation_schema_from_sdk_artifact(kind, operation)?;
        }
    }
    Ok(())
}

/// Round 4 (B1.13 / B1.14 / B1.15) — typed payload validators dispatched
/// on the canonical event kind. Hooks the SDK round-4 typed payload
/// shapes (SpaceStateTransition / SpaceObjectTombstone / ConsentRevoke)
/// into the soland operation admission pipeline.
///
/// For the space lifecycle events the SDK's typed payload requires
/// `space_id` + `new_state`. Soland's pre-round-4 fixtures still use
/// `place_id` (the post-R1.2 rename kept the field name) — the
/// validator here HARD-REJECTS the wire-broken `target_ref` form but
/// remains tolerant of the soland-internal `place_id` field so the
/// in-tree reducer / fixture surface keeps building. Producers that
/// emit `space_id` (the round-4 wire shape) MUST parse through
/// `SpaceStateTransitionPayload` cleanly.
fn round4_validate_payload(kind: &str, operation: &Operation) -> Result<(), &'static str> {
    match kind {
        // cx.space.archive / cx.space.restore use the typed
        // SpaceStateTransitionPayload (space_id, new_state, reason?).
        // The legacy top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind PLACE_LIFECYCLE_REQUIREMENTS validator below.
        "cx.space.archive" | "cx.space.restore" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "cx.space.archive/restore legacy `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // cx.space.tombstone — same legacy reject rule.
        "cx.space.tombstone" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "cx.space.tombstone legacy `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // cx.consent.revoke — observed_dots[] required; implicit
        // cascade is schema_violation. We accept the call sites that
        // do not yet emit consent.revoke events (no payload to check)
        // by returning Ok when the payload doesn't even resemble a
        // consent revoke (missing consent_id) — the per-kind schema
        // dispatcher will catch totally-empty payloads separately.
        "cx.consent.revoke" => {
            if operation.payload.get("consent_id").is_none()
                && operation.payload.get("observed_dots").is_none()
            {
                return Ok(());
            }
            crate::round4::validate_consent_revoke_payload(&operation.payload)
                .map(|_| ())
                .map_err(|_| {
                    "cx.consent.revoke payload violates round-4 observed_dots requirement"
                })
        }
        // cx.cross_signing.publish — round 4 CAS-register cell with
        // required `expected_previous_generation`. The reducer accepts
        // only when expected_previous_generation == current_generation
        // and new_generation == current_generation + 1. We enforce
        // schema shape here; the actual CAS comparison happens during
        // reducer apply once the cell row is read.
        "cx.cross_signing.publish" => {
            if operation
                .payload
                .get("expected_previous_generation")
                .is_none()
            {
                return Err(
                    "cx.cross_signing.publish payload requires expected_previous_generation \
                     (round-4 CAS wire break)",
                );
            }
            if operation.payload.get("new_generation").is_none() {
                // ROUND4-ALLOW: error message string for the round-4 CAS contract.
                return Err(
                    "cx.cross_signing.publish payload requires new_generation (round-4 CAS)",
                );
            }
            if operation.payload.get("trust_domain").is_none() {
                // ROUND4-ALLOW: error message string for the round-4 wire break.
                return Err(
                    "cx.cross_signing.publish payload requires trust_domain (round-4 wire break)",
                );
            }
            Ok(())
        }
        // cx.applet.protocol_session.start — round 4 requires the
        // `applet_id` to be either a DID or a strictly-validated
        // `cx:applet:<uuidv7>` typed id.
        "cx.applet.protocol_session.start" => {
            if let Some(applet_id) = operation.payload.get("applet_id").and_then(|v| v.as_str())
            {
                crate::round4::validate_applet_id(applet_id)
                    .map(|_| ())
                    .map_err(|_| {
                        "applet_id must be a DID or cx:applet:<uuidv7> (round-4 wire break)"
                    })?;
            }
            Ok(())
        }
        // cx.audit.policy_access — when `access_kind=e2ee_late_recovery`
        // the payload MUST carry `late_recovery_original_event_id`.
        "cx.audit.policy_access" => {
            if let Some(access_kind) = operation
                .payload
                .get("access_kind")
                .and_then(|v| v.as_str())
                && access_kind == "e2ee_late_recovery"
                && operation
                    .payload
                    .get("late_recovery_original_event_id")
                    .is_none()
            {
                return Err(
                    "cx.audit.policy_access access_kind=e2ee_late_recovery requires \
                     late_recovery_original_event_id (round-4 wire break)",
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_operation_schema_from_sdk_artifact(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    event_payload_validator_catalog()
        .validate_payload(kind, &operation.payload)
        .map_err(|_| "operation payload violates SDK artifact schema")
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
        kinds::CX_FLOW_TRACKS_UPDATE => OperationPayloadSchema {
            requirements: FLOW_TRACKS_UPDATE_REQUIREMENTS,
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
            validate: Some(validate_morph_update_payload),
        },
        kinds::CX_MORPH_SCHEMA_MIGRATE => OperationPayloadSchema {
            requirements: MORPH_SCHEMA_MIGRATE_REQUIREMENTS,
            validate: Some(validate_morph_schema_migrate_payload),
        },
        // `cx.field.position.move` / `cx.field.position.reorder` were removed
        // in revision 0a5ab85 (see contrix-spec
        // `artifacts/registry/removed-event-kinds.json`). The generic
        // unknown-event-kind path in `event_log::submit_event` already
        // hard-rejects these kinds; no operation schema branch is needed.
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
        CX_CROSS_SIGNING_RESET => OperationPayloadSchema {
            requirements: CROSS_SIGNING_RESET_REQUIREMENTS,
            validate: Some(validate_cross_signing_reset_payload),
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
    validate_sender_commitment_payload_binding(&operation.payload)?;
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

const SENDER_COMMITMENT_FEATURE: &str = "cx.profile.franking.sender_commitment.v1";

fn validate_sender_commitment_payload_binding(
    payload: &serde_json::Value,
) -> Result<(), &'static str> {
    if !payload
        .pointer("/requirements/features")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|features| {
            features
                .iter()
                .any(|feature| feature.as_str() == Some(SENDER_COMMITMENT_FEATURE))
        })
    {
        return Ok(());
    }
    let Some(declared_digest) = payload
        .pointer("/franking/sender_commitment_digest")
        .and_then(serde_json::Value::as_str)
        .filter(|digest| is_valid_sha256_digest(digest))
    else {
        return Err("sender_commitment_missing");
    };
    let Some(commitment) = payload
        .pointer("/unsigned/franking/sender_commitment")
        .or_else(|| payload.pointer("/_unsigned/franking/sender_commitment"))
    else {
        return Err("sender_commitment_missing");
    };
    let expected_digest =
        canonical_json_digest(commitment).map_err(|_| "sender_commitment_invalid")?;
    if declared_digest != expected_digest.as_str() {
        return Err("sender_commitment_invalid");
    }
    Ok(())
}

fn validate_morph_update_payload(operation: &Operation) -> Result<(), &'static str> {
    if operation
        .payload
        .get("patch")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|patch| patch.contains_key("schema_refs"))
    {
        return Err("morph_schema_refs_evolution_unauthorized");
    }
    Ok(())
}

fn validate_morph_schema_migrate_payload(operation: &Operation) -> Result<(), &'static str> {
    validate_nonempty_unique_string_array(
        operation.payload.get("from_schema_refs"),
        "from_schema_refs",
    )?;
    validate_nonempty_unique_string_array(
        operation.payload.get("to_schema_refs"),
        "to_schema_refs",
    )?;
    match operation
        .payload
        .get("compatibility_class")
        .and_then(serde_json::Value::as_str)
    {
        Some("additive") => Ok(()),
        Some("breaking" | "transformation") => Err("morph_schema_refs_transformation_unsupported"),
        _ => Err("morph schema_migrate compatibility_class is invalid"),
    }
}

fn validate_nonempty_unique_string_array(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<(), &'static str> {
    let Some(items) = value.and_then(serde_json::Value::as_array) else {
        return Err(match field {
            "from_schema_refs" => "from_schema_refs must be a non-empty string array",
            "to_schema_refs" => "to_schema_refs must be a non-empty string array",
            _ => "field must be a non-empty string array",
        });
    };
    if items.is_empty() {
        return Err(match field {
            "from_schema_refs" => "from_schema_refs must be a non-empty string array",
            "to_schema_refs" => "to_schema_refs must be a non-empty string array",
            _ => "field must be a non-empty string array",
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        let Some(text) = item.as_str().filter(|text| !text.trim().is_empty()) else {
            return Err(match field {
                "from_schema_refs" => "from_schema_refs must contain only non-empty strings",
                "to_schema_refs" => "to_schema_refs must contain only non-empty strings",
                _ => "field must contain only non-empty strings",
            });
        };
        if !seen.insert(text) {
            return Err(match field {
                "from_schema_refs" => "from_schema_refs must be unique",
                "to_schema_refs" => "to_schema_refs must be unique",
                _ => "field must be unique",
            });
        }
    }
    Ok(())
}

fn validate_cross_signing_reset_payload(operation: &Operation) -> Result<(), &'static str> {
    let reset: contrix_sdk::crypto_protocol::CrossSigningResetContent =
        serde_json::from_value(operation.payload.clone())
            .map_err(|_| "cross_signing reset payload violates reset profile")?;
    reset
        .validate_structure()
        .map_err(|_| "cross_signing reset payload violates reset profile")?;
    let now = chrono::Utc::now();
    let skew = (now - reset.issued_at).num_seconds().abs();
    if skew > CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS {
        return Err("cross_signing_reset_clock_skew_exceeded");
    }
    Ok(())
}

fn validate_cross_signing_reset_replay_batch(operations: &[Operation]) -> Result<(), &'static str> {
    let mut seen = std::collections::BTreeSet::new();
    for operation in operations {
        if kinds::canonical_kind_for_operation(operation) != Some(CX_CROSS_SIGNING_RESET) {
            continue;
        }
        let Some(principal_id) = operation
            .payload
            .get("principal_id")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(previous_generation) = operation
            .payload
            .get("previous_generation")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if !seen.insert((principal_id, previous_generation)) {
            return Err("cross_signing_reset_replay");
        }
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
        if kinds::canonical_kind_for_operation(operation) == Some(kinds::CX_MORPH_SCHEMA_MIGRATE) {
            validate_morph_schema_migrate_capability(operation)?;
        }
    }
    Ok(())
}

fn validate_morph_schema_migrate_capability(operation: &Operation) -> Result<(), &'static str> {
    if operation
        .payload
        .get("authorization_ref")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("cx:event:"))
        .is_none()
    {
        return Err("cx.morph.schema_migrate requires authorization_ref");
    }
    let action = operation
        .payload
        .get("capability_action")
        .or_else(|| operation.payload.get("action"))
        .and_then(serde_json::Value::as_str);
    if action != Some("cx.morph.schema.migrate") {
        return Err("cx.morph.schema_migrate requires cx.morph.schema.migrate capability");
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

#[cfg(test)]
mod flow_tracks_update_tests {
    use super::*;
    use contrix_sdk::Operation;
    use serde_json::json;

    fn op(payload: serde_json::Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kinds::CX_FLOW_TRACKS_UPDATE,
            payload,
        )
    }

    #[test]
    fn canonical_flow_tracks_update_accepts_patch_payload() {
        let operation = op(json!({
            "flow_id": "cx:flow:01904100-0000-7000-8000-000000000001",
            "patch": {
                "tracks": {
                    "discussion": {"profile": "discussion"}
                }
            }
        }));
        assert_eq!(
            kinds::canonical_kind_for_operation(&operation),
            Some(kinds::CX_FLOW_TRACKS_UPDATE)
        );
        let schema = operation_schema_for_kind(kinds::CX_FLOW_TRACKS_UPDATE).unwrap();
        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn canonical_flow_tracks_update_accepts_tracks_payload() {
        let operation = op(json!({
            "flow_id": "cx:flow:01904100-0000-7000-8000-000000000001",
            "tracks": {
                "review": {"profile": "review"}
            }
        }));
        let schema = operation_schema_for_kind(kinds::CX_FLOW_TRACKS_UPDATE).unwrap();
        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn canonical_flow_tracks_update_requires_flow_id_and_patch_or_tracks() {
        let schema = operation_schema_for_kind(kinds::CX_FLOW_TRACKS_UPDATE).unwrap();

        let missing_flow_id = op(json!({
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }));
        assert_eq!(
            validate_operation_schema(&missing_flow_id, schema),
            Err("flow tracks update requires flow_id")
        );

        let missing_patch_or_tracks = op(json!({
            "flow_id": "cx:flow:01904100-0000-7000-8000-000000000001"
        }));
        assert_eq!(
            validate_operation_schema(&missing_patch_or_tracks, schema),
            Err("flow tracks update requires patch or tracks")
        );
    }
}

#[cfg(test)]
mod spec_sync_validator_tests {
    use super::*;
    use contrix_sdk::Operation;
    use serde_json::json;

    fn op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn sender_commitment_feature_requires_matching_unsigned_sidecar() {
        let commitment = json!({
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "seq": 1
        });
        let digest = canonical_json_digest(&commitment).unwrap().to_string();
        let valid = op(
            kinds::CX_MESSAGE_CREATE,
            json!({
                "body": "hello",
                "requirements": {"features": [SENDER_COMMITMENT_FEATURE]},
                "franking": {"sender_commitment_digest": digest},
                "unsigned": {"franking": {"sender_commitment": commitment}}
            }),
        );
        assert!(validate_message_operation_payload(&valid).is_ok());

        let missing = op(
            kinds::CX_MESSAGE_CREATE,
            json!({
                "body": "hello",
                "requirements": {"features": [SENDER_COMMITMENT_FEATURE]},
                "franking": {}
            }),
        );
        assert_eq!(
            validate_message_operation_payload(&missing),
            Err("sender_commitment_missing")
        );

        let invalid = op(
            kinds::CX_MESSAGE_CREATE,
            json!({
                "body": "hello",
                "requirements": {"features": [SENDER_COMMITMENT_FEATURE]},
                "franking": {"sender_commitment_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
                "unsigned": {"franking": {"sender_commitment": {"seq": 2}}}
            }),
        );
        assert_eq!(
            validate_message_operation_payload(&invalid),
            Err("sender_commitment_invalid")
        );
    }

    #[test]
    fn morph_schema_refs_use_migrate_gate() {
        let update = op(
            kinds::CX_MORPH_UPDATE,
            json!({
                "morph_id": "cx:morph:01904100-0000-7000-8000-000000000001",
                "patch": {"schema_refs": ["cx.schema.new"]}
            }),
        );
        let update_schema = operation_schema_for_kind(kinds::CX_MORPH_UPDATE).unwrap();
        assert_eq!(
            validate_operation_schema(&update, update_schema),
            Err("morph_schema_refs_evolution_unauthorized")
        );

        let migrate = op(
            kinds::CX_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "cx:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["cx.schema.old"],
                "to_schema_refs": ["cx.schema.old", "cx.schema.new"],
                "compatibility_class": "additive",
                "authorization_ref": "cx:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "cx.morph.schema.migrate"
            }),
        );
        let migrate_schema = operation_schema_for_kind(kinds::CX_MORPH_SCHEMA_MIGRATE).unwrap();
        assert!(validate_operation_schema(&migrate, migrate_schema).is_ok());
        assert!(validate_morph_schema_migrate_capability(&migrate).is_ok());

        let missing_gate = op(
            kinds::CX_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "cx:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["cx.schema.old"],
                "to_schema_refs": ["cx.schema.new"],
                "compatibility_class": "additive"
            }),
        );
        assert_eq!(
            validate_morph_schema_migrate_capability(&missing_gate),
            Err("cx.morph.schema_migrate requires authorization_ref")
        );

        let unsupported = op(
            kinds::CX_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "cx:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["cx.schema.old"],
                "to_schema_refs": ["cx.schema.new"],
                "compatibility_class": "breaking",
                "authorization_ref": "cx:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "cx.morph.schema.migrate"
            }),
        );
        assert_eq!(
            validate_operation_schema(&unsupported, migrate_schema),
            Err("morph_schema_refs_transformation_unsupported")
        );
    }
}

#[cfg(test)]
mod sdk_artifact_schema_tests {
    use super::*;
    use contrix_sdk::Operation;
    use serde_json::json;

    fn cross_signing_reset(payload: serde_json::Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            "cx.cross_signing.reset",
            payload,
        )
    }

    #[test]
    fn artifact_backed_kind_and_payload_validator_cover_cross_signing_reset() {
        let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Round R2/R3 (T08) — trust_domain + reset_event_id are now wire-breaking
        // required fields.
        let operation = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason": "rotation",
            "proof": {
                "kind": "principal_signing",
                "signed_by": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "trust_domain": "cx:trust_domain:soland.local",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000001",
            "issued_at": issued_at
        }));
        assert_eq!(
            kinds::canonical_kind_for_operation(&operation),
            Some("cx.cross_signing.reset")
        );
        assert!(operation_schema_for_kind("cx.cross_signing.reset").is_some());
        validate_operation_schema_from_sdk_artifact("cx.cross_signing.reset", &operation).unwrap();
        validate_operation_schema(
            &operation,
            operation_schema_for_kind("cx.cross_signing.reset").unwrap(),
        )
        .unwrap();

        let missing_proof = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason": "rotation",
            "trust_domain": "cx:trust_domain:soland.local",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_operation_schema_from_sdk_artifact("cx.cross_signing.reset", &missing_proof),
            Err("operation payload violates SDK artifact schema")
        );

        // Round R2/R3 (T08) — missing trust_domain MUST hard-reject.
        let missing_trust_domain = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason": "rotation",
            "proof": {
                "kind": "principal_signing",
                "signed_by": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert!(
            validate_operation_schema(
                &missing_trust_domain,
                operation_schema_for_kind("cx.cross_signing.reset").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn cross_signing_reset_profile_rejects_replay_and_clock_skew() {
        let reset = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason": "rotation",
            "proof": {
                "kind": "principal_signing",
                "signed_by": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "trust_domain": "cx:trust_domain:soland.local",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_cross_signing_reset_replay_batch(&[reset.clone(), reset.clone()]),
            Err("cross_signing_reset_replay")
        );

        let stale = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason": "rotation",
            "proof": {
                "kind": "principal_signing",
                "signed_by": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "trust_domain": "cx:trust_domain:soland.local",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000002",
            "issued_at": (chrono::Utc::now() - chrono::Duration::seconds(CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS + 1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_cross_signing_reset_payload(&stale),
            Err("cross_signing_reset_clock_skew_exceeded")
        );
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
