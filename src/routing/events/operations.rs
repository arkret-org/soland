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
    AnyKey(&'static [&'static str], &'static str),
}

const MESSAGE_CREATE_FIELDS: &[&str] = &["body", "content", "event_id"];
const MESSAGE_TARGET_FIELDS: &[&str] = &["target_event_id", "event_id", "target"];
const MESSAGE_CONTENT_FIELDS: &[&str] = &["content", "body"];
const REDACTION_TARGET_FIELDS: &[&str] = &["target_event_id", "target", "redacts"];
const REACTION_TARGET_FIELDS: &[&str] = &[
    "target_ref",
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
const READ_MARKER_ACTOR_FIELDS: &[&str] = &["actor_id"];
const CONSENT_PEER_FIELDS: &[&str] = &["peer", "peer_did", "grantee_did"];
const CONSENT_SCOPE_FIELDS: &[&str] = &["consent_scope", "scope"];
const MLS_COMMIT_GROUP_FIELDS: &[&str] = &["group_id", "mls_group_id"];
const MLS_COMMIT_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MLS_COMMIT_GROUP_FIELDS,
    "cx.mls.commit requires group_id for reducer projection",
)];
const MLS_GENESIS_GROUP_FIELDS: &[&str] = &["group_id", "mls_group_id"];
const MLS_GENESIS_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MLS_GENESIS_GROUP_FIELDS,
    "cx.mls.genesis requires mls_group_id for reducer projection",
)];
const MLS_WELCOME_GROUP_FIELDS: &[&str] = &["group_id", "mls_group_id"];
const MLS_WELCOME_RECIPIENT_FIELDS: &[&str] = &["recipient_actor_did", "recipient_principal_id"];
const MLS_WELCOME_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        MLS_WELCOME_GROUP_FIELDS,
        "cx.mls.welcome requires mls_group_id for reducer projection",
    ),
    PayloadRequirement::AnyOf(
        MLS_WELCOME_RECIPIENT_FIELDS,
        "cx.mls.welcome requires recipient principal for reducer projection",
    ),
];
const MLS_KEYPACKAGE_ACTION_FIELDS: &[&str] = &["action", "state"];
const MLS_KEYPACKAGE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MLS_KEYPACKAGE_ACTION_FIELDS,
    "cx.mls.keypackage requires action/state for reducer projection",
)];

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
// G3.S5 — `cx.realm.link` Move payload. The wire schema also permits
// `status` / `label` / `commitment`, but those are optional and the
// reducer assigns defaults. Required fields only.
const REALM_LINK_TARGET_FIELDS: &[&str] = &["target_realm_id"];
const REALM_LINK_KIND_FIELDS: &[&str] = &["link_kind"];
const REALM_LINK_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        REALM_LINK_TARGET_FIELDS,
        "cx.realm.link requires target_realm_id",
    ),
    PayloadRequirement::AnyOf(REALM_LINK_KIND_FIELDS, "cx.realm.link requires link_kind"),
];
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
const REALM_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "object",
    "cx.realm.create operation requires payload.object",
)];
// `cx.realm.update` / `cx.realm.destroy` carry an `action` string +
// per-action fields (mirrors space-container / morph lifecycle for non-create
// paths).
const SPACE_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "action",
    "space lifecycle operation requires action",
)];
// `cx.space.archive` / `cx.space.restore` / `cx.space.tombstone` share the
// spec-canonical `space_id` target field.
const SPACE_CONTAINER_LIFECYCLE_ID_FIELDS: &[&str] = &["space_id"];
const SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    SPACE_CONTAINER_LIFECYCLE_ID_FIELDS,
    "space lifecycle operation requires space_id",
)];
// `cx.space.create` carries a full Space object under `object`.
const SPACE_CONTAINER_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "object",
    "space create operation requires object",
)];
// `cx.space.update` carries `space_id` + `patch`.
const SPACE_CONTAINER_UPDATE_ID_FIELDS: &[&str] = &["space_id"];
const SPACE_CONTAINER_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        SPACE_CONTAINER_UPDATE_ID_FIELDS,
        "space update operation requires space_id",
    ),
    PayloadRequirement::Required("patch", "space update operation requires patch"),
];
// `cx.space.parent` carries `space_id` + `expected_parent_space_id`, with
// optional `parent_space_id`.
const SPACE_CONTAINER_PARENT_ID_FIELDS: &[&str] = &["space_id"];
const SPACE_CONTAINER_PARENT_EXPECTED_FIELDS: &[&str] = &["expected_parent_space_id"];
const SPACE_CONTAINER_PARENT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        SPACE_CONTAINER_PARENT_ID_FIELDS,
        "space parent operation requires space_id",
    ),
    PayloadRequirement::AnyKey(
        SPACE_CONTAINER_PARENT_EXPECTED_FIELDS,
        "space parent operation requires expected_parent_space_id",
    ),
];
// Flow / Morph lifecycle payload requirements. The spec
// `event-payload.schema.json` `object_lifecycle_payload` shape requires one
// of `target_ref` / `object_ref` / `status`; soland additionally accepts the
// legacy `flow_id` field name for backwards compatibility with older
// builders. The first field present (in spec-canonical order) names the
// target Flow; `apply_flow_lifecycle` reads them with the same precedence.
const FLOW_LIFECYCLE_ID_FIELDS: &[&str] = &["target_ref", "object_ref", "flow_id"];
const FLOW_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    FLOW_LIFECYCLE_ID_FIELDS,
    "flow lifecycle operation requires target_ref (or flow_id)",
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
const FLOW_POSITION_BOARD_FIELDS: &[&str] = &["board_space_id"];
const FLOW_MOVE_TARGET_FIELDS: &[&str] = &["target_space_id"];
const FLOW_REORDER_SPACE_FIELDS: &[&str] = &["space_id", "list_space_id"];
const FLOW_MOVE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow position operation requires flow_id"),
    PayloadRequirement::AnyOf(
        FLOW_POSITION_BOARD_FIELDS,
        "flow position operation requires board_space_id",
    ),
    PayloadRequirement::AnyOf(
        FLOW_MOVE_TARGET_FIELDS,
        "flow move operation requires target_space_id",
    ),
    PayloadRequirement::Required("rank", "flow move operation requires rank"),
];
const FLOW_REORDER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow position operation requires flow_id"),
    PayloadRequirement::AnyOf(
        FLOW_POSITION_BOARD_FIELDS,
        "flow position operation requires board_space_id",
    ),
    PayloadRequirement::AnyOf(
        FLOW_REORDER_SPACE_FIELDS,
        "flow reorder operation requires space_id",
    ),
    PayloadRequirement::Required("rank", "flow reorder operation requires rank"),
];
// Flow watch event (cx.flow.watch.set).
// Spec event-kind-registry sets `cell_subject` = (flow_id, watcher_actor_id);
// both fields are MUST-present in the payload. `level` is also required
// (null = clear); enum + level_public validation lives at the
// flow_watch_set_payload schema layer.
const FLOW_WATCH_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("flow_id", "flow watch operation requires flow_id"),
    PayloadRequirement::Required(
        "watcher_actor_id",
        "flow watch operation requires watcher_actor_id",
    ),
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
    PayloadRequirement::Required("read_scope", "read marker operation requires read_scope"),
    PayloadRequirement::Required("position", "read marker operation requires position"),
];
const CONSENT_GRANT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("consent_id", "consent grant requires consent_id"),
    PayloadRequirement::AnyOf(CONSENT_PEER_FIELDS, "consent grant requires peer"),
    PayloadRequirement::AnyOf(CONSENT_SCOPE_FIELDS, "consent grant requires scope"),
];
const CONSENT_REVOKE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("consent_id", "consent revoke requires consent_id"),
    PayloadRequirement::Required("observed_dots", "consent revoke requires observed_dots"),
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
/// `space_id` + `new_state`. The validator here HARD-REJECTS the
/// wire-broken `target_ref` form; producers must emit canonical `space_id`.
fn round4_validate_payload(kind: &str, operation: &Operation) -> Result<(), &'static str> {
    match kind {
        // cx.space.archive / cx.space.restore use the typed
        // SpaceStateTransitionPayload (space_id, new_state, reason?).
        // The legacy top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS validator below.
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
                return Err("cx.space.tombstone legacy `target_ref` form rejected by round-4 wire");
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
                .or_else(|_| validate_observed_dots_payload(operation))
                .map_err(|_| "cx.consent.revoke payload violates round-4 observed_dots requirement")
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
            if let Some(applet_id) = operation.payload.get("applet_id").and_then(|v| v.as_str()) {
                crate::round4::validate_applet_id(applet_id)
                    .map(|_| ())
                    .map_err(
                        |_| "applet_id must be a DID or cx:applet:<uuidv7> (round-4 wire break)",
                    )?;
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
        // G3.S5 — `cx.realm.link`. Permissive schema (target_realm_id +
        // link_kind required; the reducer's `apply_realm_link`
        // enforces the rest including cycle detection). We register
        // here so `accept_local_operations` doesn't fall through to
        // the SDK artifact validator (whose `realm_id` pattern is
        // stricter than the in-tree fixtures need for testing —
        // existing reducer-level tests use `cx:space:` prefixes).
        kinds::CX_REALM_LINK => OperationPayloadSchema {
            requirements: REALM_LINK_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_MLS_COMMIT => OperationPayloadSchema {
            requirements: MLS_COMMIT_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_MLS_GENESIS => OperationPayloadSchema {
            requirements: MLS_GENESIS_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_MLS_WELCOME => OperationPayloadSchema {
            requirements: MLS_WELCOME_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_MLS_KEYPACKAGE => OperationPayloadSchema {
            requirements: MLS_KEYPACKAGE_REQUIREMENTS,
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
            validate: Some(validate_read_marker_payload),
        },
        "cx.consent.grant" => OperationPayloadSchema {
            requirements: CONSENT_GRANT_REQUIREMENTS,
            validate: None,
        },
        "cx.consent.revoke" => OperationPayloadSchema {
            requirements: CONSENT_REVOKE_REQUIREMENTS,
            validate: Some(validate_observed_dots_payload),
        },
        kind if kinds::is_membership_kind(kind) => OperationPayloadSchema {
            requirements: MEMBERSHIP_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_REALM_CREATE => OperationPayloadSchema {
            // `cx.realm.create` is technically lifecycle but carries the
            // full Realm `object` rather than an `action`. Match it
            // explicitly so the broader `is_realm_lifecycle_kind` branch
            // below stays focused on update / destroy.
            requirements: REALM_CREATE_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_realm_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: SPACE_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_space_container_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_SPACE_CONTAINER_CREATE => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_SPACE_CONTAINER_UPDATE => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_SPACE_CONTAINER_PARENT => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_PARENT_REQUIREMENTS,
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
        kinds::CX_FLOW_MOVE => OperationPayloadSchema {
            requirements: FLOW_MOVE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_FLOW_REORDER => OperationPayloadSchema {
            requirements: FLOW_REORDER_REQUIREMENTS,
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
        CX_CROSS_SIGNING_RESET => OperationPayloadSchema {
            requirements: CROSS_SIGNING_RESET_REQUIREMENTS,
            validate: Some(validate_cross_signing_reset_payload),
        },
        _ => return None,
    };
    Some(schema)
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
            PayloadRequirement::AnyKey(fields, message) => {
                if !fields
                    .iter()
                    .any(|field| payload_key_present(&operation.payload, field))
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

pub fn payload_key_present(payload: &serde_json::Value, field: &str) -> bool {
    payload
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

pub fn validate_message_operation_payload(operation: &Operation) -> Result<(), &'static str> {
    validate_sender_commitment_payload_binding(&operation.payload)?;
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_payload").is_some();
    if encrypted {
        let Some(content) = operation
            .payload
            .get("encrypted_payload")
            .or_else(|| operation.payload.get("content"))
        else {
            return Err("encrypted message operation requires content envelope");
        };
        validate_encrypted_payload_envelope(content)?;
    } else if let Some(content) = operation.payload.get("content") {
        validate_content_blocks(content)?;
        validate_mentions(content)?;
    }
    Ok(())
}

fn validate_read_marker_payload(operation: &Operation) -> Result<(), &'static str> {
    let read_scope = operation
        .payload
        .get("read_scope")
        .and_then(|value| value.as_object())
        .ok_or("read marker read_scope must be an object")?;
    let kind = read_scope
        .get("kind")
        .and_then(|value| value.as_str())
        .ok_or("read marker read_scope.kind is required")?;
    match kind {
        "realm" => {
            if read_scope.get("ref").is_some_and(|value| !value.is_null()) {
                return Err("read marker read_scope.ref must be omitted for realm");
            }
        }
        "flow" | "thread" | "view" | "message" | "morph" => {
            if read_scope
                .get("ref")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("read marker read_scope.ref is required");
            }
        }
        "flow_discussion" | "flow_synthesis" => {
            return Err("read marker read_scope.kind removed; use flow plus track");
        }
        _ => return Err("read marker read_scope.kind is invalid"),
    }
    if let Some(track) = read_scope.get("track").and_then(|value| value.as_str()) {
        if kind != "flow" {
            return Err("read marker read_scope.track requires kind flow");
        }
        validate_read_scope_track(track)?;
    }
    let position = operation
        .payload
        .get("position")
        .and_then(|value| value.as_object())
        .ok_or("read marker position must be an object")?;
    if position
        .get("event_id")
        .and_then(|value| value.as_str())
        .is_none_or(|value| !value.starts_with("cx:event:"))
    {
        return Err("read marker position.event_id is invalid");
    }
    let hlc = position
        .get("hlc")
        .and_then(|value| value.as_str())
        .ok_or("read marker position.hlc is required")?;
    validate_read_cursor_hlc(hlc)?;
    Ok(())
}

fn validate_observed_dots_payload(operation: &Operation) -> Result<(), &'static str> {
    if operation
        .payload
        .get("observed_dots")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|dots| !dots.is_empty())
    {
        Ok(())
    } else {
        Err("consent revoke observed_dots must be a non-empty array")
    }
}

fn validate_read_scope_track(track: &str) -> Result<(), &'static str> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err("read marker read_scope.track is invalid");
    };
    if !first.is_ascii_lowercase()
        || track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("read marker read_scope.track is invalid");
    }
    Ok(())
}

fn validate_read_cursor_hlc(hlc: &str) -> Result<(), &'static str> {
    let parts = hlc.split('-').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0].len() != 12
        || parts[1].len() != 4
        || parts[2].len() != 8
        || !parts.iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err("read marker position.hlc is invalid");
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
            && known_space_denies_plaintext_service(state, operation.realm_id.as_str())
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
        if kinds::canonical_kind_for_operation(operation) == Some(kinds::CX_MORPH_SCHEMA_MIGRATE) {
            validate_morph_schema_migrate_capability(operation)?;
        }
        validate_poll_operation_policy(state, operation)?;
    }
    Ok(())
}

fn validate_poll_operation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::operation_is_message_create(operation) {
        return Ok(());
    }
    let Some(content) = operation.payload.get("content") else {
        return Ok(());
    };
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("cx.content.poll.response") {
        return Ok(());
    }
    let Some(poll_id) = content.get("poll_id").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let Ok(projection) = state.projection.lock() else {
        return Ok(());
    };
    if projection.poll(poll_id).is_some_and(|poll| poll.closed) {
        Err("poll_closed")
    } else {
        Ok(())
    }
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
        || operation.payload.get("encrypted_payload").is_some()
}

pub fn known_space_denies_plaintext_service(state: &AppState, space_id: &str) -> bool {
    state
        .persistence
        .realm_meta()
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
    if content.get("blocks").is_some() {
        return Err("content.blocks is not permitted; use content.parts");
    }
    validate_content_block(content)
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
    if block.get("blocks").is_some() {
        return Err("content.blocks is not permitted; use content.parts");
    }
    let block_kind = block_kind.strip_prefix("cx.content.").unwrap_or(block_kind);
    match block_kind {
        "composite" => {
            let Some(parts) = block.get("parts").and_then(|value| value.as_array()) else {
                return Err("composite content block requires parts");
            };
            if parts.is_empty() {
                return Err("content.parts must not be empty");
            }
            for part in parts {
                validate_content_block(part)?;
            }
        }
        "text" | "formatted_text" => {
            if !block
                .get("text")
                .or_else(|| block.get("body"))
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err("text content block requires text");
            }
        }
        "code" => {
            if !block
                .get("text")
                .or_else(|| block.get("body"))
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
        "poll.response" => {
            if !block
                .get("poll_id")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
                || !(block
                    .get("choice")
                    .and_then(|value| value.as_str())
                    .is_some()
                    || block
                        .get("choices")
                        .and_then(|value| value.as_array())
                        .is_some_and(|choices| !choices.is_empty()))
            {
                return Err("poll response content block requires poll_id and choice");
            }
        }
        "poll.close" => {
            if !block
                .get("poll_id")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err("poll close content block requires poll_id");
            }
        }
        _ => return Err("unsupported content block type"),
    }
    Ok(())
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
            contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
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

    fn flow_position_op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c6")
                .unwrap(),
            contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn canonical_flow_move_requires_board_target_and_rank() {
        let schema = operation_schema_for_kind(kinds::CX_FLOW_MOVE).unwrap();
        let operation = flow_position_op(
            kinds::CX_FLOW_MOVE,
            json!({
                "board_space_id": "cx:space:01904100-0000-7000-8000-000000000001",
                "flow_id": "cx:flow:01904100-0000-7000-8000-000000000002",
                "target_space_id": "cx:space:01904100-0000-7000-8000-000000000003",
                "rank": "a1"
            }),
        );
        assert!(validate_operation_schema(&operation, schema).is_ok());

        let missing_target = flow_position_op(
            kinds::CX_FLOW_MOVE,
            json!({
                "board_space_id": "cx:space:01904100-0000-7000-8000-000000000001",
                "flow_id": "cx:flow:01904100-0000-7000-8000-000000000002",
                "rank": "a1"
            }),
        );
        assert_eq!(
            validate_operation_schema(&missing_target, schema),
            Err("flow move operation requires target_space_id")
        );
    }

    #[test]
    fn canonical_flow_reorder_requires_board_space_and_rank() {
        let schema = operation_schema_for_kind(kinds::CX_FLOW_REORDER).unwrap();
        let operation = flow_position_op(
            kinds::CX_FLOW_REORDER,
            json!({
                "board_space_id": "cx:space:01904100-0000-7000-8000-000000000001",
                "flow_id": "cx:flow:01904100-0000-7000-8000-000000000002",
                "space_id": "cx:space:01904100-0000-7000-8000-000000000003",
                "rank": "a1"
            }),
        );
        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    fn space_container_op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c7")
                .unwrap(),
            contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn canonical_space_update_requires_space_id_and_patch() {
        let schema = operation_schema_for_kind(kinds::CX_SPACE_CONTAINER_UPDATE).unwrap();
        let operation = space_container_op(
            kinds::CX_SPACE_CONTAINER_UPDATE,
            json!({
                "space_id": "cx:space:01904100-0000-7000-8000-000000000003",
                "patch": {"title": "Launch v2"}
            }),
        );
        assert!(validate_operation_schema(&operation, schema).is_ok());

        let missing_space_id = space_container_op(
            kinds::CX_SPACE_CONTAINER_UPDATE,
            json!({"patch": {"title": "Launch v2"}}),
        );
        assert_eq!(
            validate_operation_schema(&missing_space_id, schema),
            Err("space update operation requires space_id")
        );
    }

    #[test]
    fn canonical_space_parent_requires_space_id_and_expected_parent() {
        let schema = operation_schema_for_kind(kinds::CX_SPACE_CONTAINER_PARENT).unwrap();
        let operation = space_container_op(
            kinds::CX_SPACE_CONTAINER_PARENT,
            json!({
                "space_id": "cx:space:01904100-0000-7000-8000-000000000003",
                "parent_space_id": "cx:space:01904100-0000-7000-8000-000000000004",
                "expected_parent_space_id": null
            }),
        );
        assert!(validate_operation_schema(&operation, schema).is_ok());

        let missing_expected = space_container_op(
            kinds::CX_SPACE_CONTAINER_PARENT,
            json!({
                "space_id": "cx:space:01904100-0000-7000-8000-000000000003",
                "parent_space_id": "cx:space:01904100-0000-7000-8000-000000000004"
            }),
        );
        assert_eq!(
            validate_operation_schema(&missing_expected, schema),
            Err("space parent operation requires expected_parent_space_id")
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
            contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
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
            contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
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
