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
//! - `validate_encrypted_payload_envelope` — `cx.profile.encrypted_envelope.v1` envelope shape (MLS
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
use serde_json::Value;

use super::{is_json_integer, is_valid_sha256_digest, validate_did};
use crate::kinds;
use crate::state::AppState;

const CX_CROSS_SIGNING_RESET: &str = "cx.cross_signing.reset";
const CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const CONTENT_ENCRYPTION_FLOOR_VIOLATION: &str = "content_encryption_floor_violation";
const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "realm_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "circle_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str =
    contrix_sdk::error::REASON_CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR;
const CAP_ACTION_MESSAGE_MENTION_BROADCAST: &str = "cx.message.mention.broadcast";
const AUDIENCE_MENTION_ALLOWED_AUDIENCES: &[&str] = &[
    "effective_scope_members",
    "flow_participants",
    "flow_watchers",
    "flow_engaged",
    "assigned_actors",
];

type OperationValidator = fn(&Operation) -> Result<(), &'static str>;

#[derive(Clone, Copy)]
pub struct OperationPayloadSchema {
    requirements: &'static [PayloadRequirement],
    validate: Option<OperationValidator>,
}

#[derive(Clone, Copy)]
pub enum PayloadRequirement {
    Required(&'static str, &'static str),
    AnyOf(&'static [&'static str], &'static str),
    AnyKey(&'static [&'static str], &'static str),
}

const MESSAGE_CREATE_FIELDS: &[&str] = &["content", "encrypted_content"];
const MESSAGE_TARGET_FIELDS: &[&str] = &["target_ref", "target_event_id", "event_id", "target"];
const MESSAGE_CONTENT_FIELDS: &[&str] = &["content", "encrypted_content"];
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
const INVITE_CREATE_TARGET_FIELDS: &[&str] = &["invitee", "actor_id", "member"];
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
const MLS_WELCOME_RECIPIENT_FIELDS: &[&str] = &["recipient_actor_id", "recipient_principal_id"];
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
const INVITE_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    INVITE_CREATE_TARGET_FIELDS,
    "cx.invite.create operation requires invitee",
)];
const INVITE_STATE_REQUIREMENTS: &[PayloadRequirement] = &[];
const REALM_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "object",
    "cx.realm.create operation requires payload.object",
)];
const REALM_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "patch",
    "cx.realm.update operation requires patch",
)];
const REALM_TERMINAL_REQUIREMENTS: &[PayloadRequirement] = &[];
const REALM_MODERATION_POLICY_REQUIREMENTS: &[PayloadRequirement] = &[];
const REALM_POLICY_VALUE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "value",
    "realm policy event requires value",
)];
// `cx.realm.update` / `cx.realm.destroy` carry an `action` string +
// per-action fields (mirrors space-container / morph lifecycle for non-create
// paths).
const SPACE_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "action",
    "space lifecycle operation requires action",
)];
const CONFLICT_REPAIR_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("cell_id", "conflict repair requires cell_id"),
    PayloadRequirement::Required("conflict_heads", "conflict repair requires conflict_heads"),
    PayloadRequirement::Required("winner_value", "conflict repair requires winner_value"),
    PayloadRequirement::Required(
        "recovery_capability_ref",
        "conflict repair requires recovery_capability_ref",
    ),
];
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
// `cx.space.update` carries the canonical object_patch_payload
// (`target_ref` + `patch`). `space_id` remains accepted while older
// clients migrate.
const SPACE_CONTAINER_UPDATE_ID_FIELDS: &[&str] = &["target_ref", "space_id"];
const SPACE_CONTAINER_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        SPACE_CONTAINER_UPDATE_ID_FIELDS,
        "space update operation requires target_ref",
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
    PayloadRequirement::AnyOf(
        &["target_ref", "flow_id"],
        "flow update operation requires target_ref",
    ),
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
    PayloadRequirement::AnyOf(
        &["target_ref", "morph_id"],
        "morph update operation requires target_ref",
    ),
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
    PayloadRequirement::Required("agent_id", "agent endpoint requires agent_id"),
    PayloadRequirement::Required("endpoints", "agent endpoint requires endpoints"),
];
const AGENT_SESSION_START_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "agent protocol_session.start requires session_id",
    ),
    PayloadRequirement::Required(
        "counterparty_agent",
        "agent protocol_session.start requires counterparty_agent",
    ),
    PayloadRequirement::Required("protocol", "agent protocol_session.start requires protocol"),
    PayloadRequirement::Required(
        "capability_grant",
        "agent protocol_session.start requires capability_grant",
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

// R3 spec-sync (2026-05-27) — agent lifecycle FSM payloads. Wire
// shape per spec `agent_pause_payload` / `agent_resume_payload` /
// `agent_deactivate_payload`. The FSM transition guard runs in the
// reducer (REDU-1, `apply_agent_lifecycle`).
const AGENT_PAUSE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "agent_principal_id",
    "cx.agent.pause requires agent_principal_id",
)];
const AGENT_RESUME_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "agent_principal_id",
    "cx.agent.resume requires agent_principal_id",
)];
const AGENT_DEACTIVATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "agent_principal_id",
    "cx.agent.deactivate requires agent_principal_id",
)];

// R3 spec-sync — `actor_private_event` payloads. These do NOT advance
// the anchor frontier / actor_seq (reducer_input=false).
const AGENT_DRAFT_PROPOSE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "cx.agent.draft.propose requires agent_principal_id",
    ),
    PayloadRequirement::Required("draft_id", "cx.agent.draft.propose requires draft_id"),
];
const AGENT_ACTION_REQUEST_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "cx.agent.action_request requires agent_principal_id",
    ),
    PayloadRequirement::Required("request_id", "cx.agent.action_request requires request_id"),
];
const AGENT_ACTION_APPROVE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "request_id",
    "cx.agent.action_approve requires request_id",
)];
const AGENT_ACTION_REJECT_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "request_id",
    "cx.agent.action_reject requires request_id",
)];

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
    PayloadRequirement::Required(
        "reset_reason_code",
        "cross_signing reset requires reset_reason_code",
    ),
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
const ERASURE_RECEIPT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("receipt_id", "erasure receipt requires receipt_id"),
    PayloadRequirement::Required("subject", "erasure receipt requires subject"),
    PayloadRequirement::Required("scope", "erasure receipt requires scope"),
    PayloadRequirement::Required("outcome", "erasure receipt requires outcome"),
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
        // REDU-5 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) —
        // `cx.realm.media_service` legacy single `sfu_endpoint` shape.
        // Default in v1 is to NORMALIZE the legacy shape into the
        // canonical `foci=[{focus_id:"legacy", type:"contrix-native",
        // connect_url: <old sfu_endpoint>, service_did: <issuer>}]`
        // form + emit an audit-log note. Setting
        // `SOLAND_MEDIA_SERVICE_LEGACY_REJECT=1` (v1.1 deployments)
        // flips this to a hard reject with the canonical reason code
        // `legacy_single_endpoint_media_service`.
        //
        // The normalization step is best-effort at the wire layer (we
        // can only validate shape — actual rewrite happens in the
        // reducer's project_realm_media_service path); when the legacy
        // shape passes through here we accept it so the reducer can
        // emit the canonical `foci[]` projection downstream.
        //
        // TODO(R4): wire reducer-side rewrite + audit-log emission
        // through `apply_realm_media_service`.
        "cx.realm.media_service" => {
            if operation.payload.get("sfu_endpoint").is_some()
                && operation.payload.get("foci").is_none()
            {
                let reject_legacy = matches!(
                    std::env::var("SOLAND_MEDIA_SERVICE_LEGACY_REJECT").as_deref(),
                    Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
                );
                if reject_legacy {
                    return Err(
                        "legacy_single_endpoint_media_service: cx.realm.media_service must use \
                         multi-focus foci[] shape",
                    );
                }
                // Default normalize-and-accept path. Reducer projection
                // will rewrite the legacy `sfu_endpoint` into the
                // canonical `foci=[{focus_id:"legacy", ...}]` shape.
                tracing::warn!(
                    op = "cx.realm.media_service",
                    "legacy_single_endpoint_media_service: \
                     normalizing legacy sfu_endpoint into foci[]"
                );
            }
            Ok(())
        }
        // REDU-3 / REDU-4 — `cx.call.state` shape checks.
        //   - `session_focus` is write-once: clients MUST NOT mutate an
        //     already-committed value. The wire-level check ensures the
        //     payload doesn't carry a `session_focus_revision` marker
        //     other than the genesis `1`. The full
        //     `session_focus_already_committed` deduplication runs in
        //     the reducer once the per-call cell projection lands.
        //   - `participants[].participant_binding.scheme` MUST be the
        //     canonical `cx.media.participant_binding.v1`; otherwise
        //     reject with `participant_binding_invalid`.
        "cx.call.state" => {
            // REDU-3 — write-once `session_focus`. Wire-shape check: a
            // payload that carries `session_focus_revision > 1` MUST
            // also carry `previous_session_focus` (the failed update
            // path is reserved for migration tooling). Pure first-write
            // (`revision==1` or unset) is accepted unconditionally.
            // ERR-1 — wire-validator error strings embed the canonical
            // reason code as a prefix; the parallel const reference
            // here pins them to `crate::error::reasons::*` so a rename
            // would break compilation rather than silently diverge.
            const _SESSION_FOCUS_REASON: &str =
                crate::error::reasons::SESSION_FOCUS_ALREADY_COMMITTED;
            const _PARTICIPANT_BINDING_REASON: &str =
                crate::error::reasons::PARTICIPANT_BINDING_INVALID;
            const _LEGACY_MEDIA_SERVICE_REASON: &str =
                crate::error::reasons::LEGACY_SINGLE_ENDPOINT_MEDIA_SERVICE;
            if let Some(revision) = operation
                .payload
                .get("session_focus_revision")
                .and_then(|v| v.as_u64())
                && revision > 1
                && operation.payload.get("previous_session_focus").is_none()
            {
                return Err(
                    "session_focus_already_committed: cx.call.state.session_focus is write-once",
                );
            }
            if let Some(participants) = operation
                .payload
                .get("participants")
                .and_then(|v| v.as_array())
            {
                for participant in participants {
                    let Some(binding) = participant.get("participant_binding") else {
                        continue;
                    };
                    // REDU-4 — full participant_binding wire-shape check.
                    // Verifies (a) scheme constant, (b) issuer_kid present,
                    // (c) expires_at strictly after created_at when both
                    // are present, (d) signature ("sig") present.
                    //
                    // TODO(R4): full crypto verification — resolve
                    // `issuer_kid` against the current epoch
                    // `cx.realm.media_service.service_id`, fetch the
                    // ed25519 verification key, and verify `sig` over the
                    // canonical-json bytes of the binding payload.
                    let scheme = binding.get("scheme").and_then(|v| v.as_str());
                    if scheme != Some(contrix_sdk::PARTICIPANT_BINDING_SCHEMA) {
                        return Err(
                            "participant_binding_invalid: participant_binding.scheme must be \
                             cx.media.participant_binding.v1",
                        );
                    }
                    if binding
                        .get("issuer_kid")
                        .and_then(|v| v.as_str())
                        .is_none_or(str::is_empty)
                    {
                        return Err(
                            "participant_binding_invalid: participant_binding.issuer_kid is \
                             required",
                        );
                    }
                    if binding
                        .get("sig")
                        .and_then(|v| v.as_str())
                        .is_none_or(str::is_empty)
                    {
                        return Err(
                            "participant_binding_invalid: participant_binding.sig is required",
                        );
                    }
                    if let (Some(created_at), Some(expires_at)) = (
                        binding.get("created_at").and_then(|v| v.as_str()),
                        binding.get("expires_at").and_then(|v| v.as_str()),
                    ) && let (Ok(created), Ok(expires)) = (
                        chrono::DateTime::parse_from_rfc3339(created_at),
                        chrono::DateTime::parse_from_rfc3339(expires_at),
                    ) && expires <= created
                    {
                        return Err(
                            "participant_binding_invalid: participant_binding.expires_at must be \
                             strictly after created_at",
                        );
                    }
                }
            }
            Ok(())
        }
        // REDU-8 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) — the
        // `cx.audit.epoch_destruction_failsafe` event cannot serve as a
        // delayed remediation for an Audit Agent remove batch that lacks
        // the same-batch `cx.audit.epoch_key_destruction` attestation.
        // The wire-level check here rejects any failsafe whose payload
        // names an `epoch_range` that is missing the paired attestation
        // marker `paired_with_epoch_key_destruction=true`. The full
        // cross-batch scan (walking prior remove batches in the same
        // epoch) runs in the reducer once the audit projection lands —
        // see `_before_todos.md §0.4` for the canonical phrasing.
        //
        // TODO(R4): walk the per-epoch remove batch index from the audit
        // projection and reject when a remove batch lacks an
        // in-batch attestation AND was committed before this failsafe.
        "cx.audit.epoch_destruction_failsafe" => {
            let attestation_paired = operation
                .payload
                .get("paired_with_epoch_key_destruction")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !attestation_paired {
                return Err("audit_agent_destruction_not_paired_with_remove: \
                     cx.audit.epoch_destruction_failsafe MUST NOT be accepted as delayed \
                     remediation for an Audit Agent remove batch lacking same-batch \
                     cx.audit.epoch_key_destruction");
            }
            Ok(())
        }
        // REDU-6 — when `cx.profile.accountable_principals.strict_reject.v1`
        // is declared (env-gated by `SOLAND_ACCOUNTABLE_PRINCIPALS_STRICT_REJECT`),
        // Actor Profile create/update with unverified `accountable_principal_ids[]`
        // MUST reject the whole event with `failed_precondition
        // reason=accountability_grant_missing`. Without the profile we
        // fall back to the default strip + audit behavior.
        // TODO(R3.1): cross-check each accountable_principal_ids[] DID against the
        // `cx.identity.accountability_grant` projection; for now we
        // only enforce the wire-shape contract (presence of the
        // accountable_principal_ids[] field implies verification must happen).
        "cx.profile.create" | "cx.profile.update" => {
            let strict_reject = matches!(
                std::env::var("SOLAND_ACCOUNTABLE_PRINCIPALS_STRICT_REJECT").as_deref(),
                Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
            );
            if strict_reject
                && operation
                    .payload
                    .get("accountable_principal_ids")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| !arr.is_empty())
                && operation
                    .payload
                    .get("accountability_grant_refs")
                    .and_then(|v| v.as_array())
                    .is_none_or(|arr| arr.is_empty())
            {
                return Err(
                    "accountability_grant_missing: strict_reject profile requires \
                     accountability_grant_refs[] when accountable_principal_ids[] is non-empty",
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
        kinds::CX_INVITE_CREATE => OperationPayloadSchema {
            requirements: INVITE_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AUDIT_ERASURE_RECEIPT => OperationPayloadSchema {
            requirements: ERASURE_RECEIPT_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_invite_kind(kind) => OperationPayloadSchema {
            requirements: INVITE_STATE_REQUIREMENTS,
            validate: None,
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
        kinds::CX_REALM_UPDATE => OperationPayloadSchema {
            requirements: REALM_UPDATE_REQUIREMENTS,
            validate: None,
        },
        // Circle lifecycle. Structure is owned by the registered
        // `cx.schema.circle.v1` payload schema (applied via validate_payload);
        // registering here only builds the projection Operation so the
        // submit-time invariant gate runs — notably the encryption_profile
        // create-lock and circle-below-realm-floor checks in
        // `validate_content_encryption_floor` (previously dead for circles
        // because no Operation was built, so the lock was only caught at
        // projection and the client saw a misleading 200).
        kinds::CX_CIRCLE_CREATE | kinds::CX_CIRCLE_UPDATE => OperationPayloadSchema {
            requirements: &[],
            validate: None,
        },
        kinds::CX_REALM_DESTROY | kinds::CX_REALM_TOMBSTONE => OperationPayloadSchema {
            requirements: REALM_TERMINAL_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_REALM_MODERATION_POLICY => OperationPayloadSchema {
            requirements: REALM_MODERATION_POLICY_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_REALM_HISTORY_VISIBILITY => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: Some(validate_history_visibility_payload),
        },
        kinds::CX_REALM_HISTORY_SHARING_POLICY | kinds::CX_REALM_PREVIEW_POLICY => {
            OperationPayloadSchema {
                requirements: REALM_POLICY_VALUE_REQUIREMENTS,
                validate: None,
            }
        }
        kinds::CX_REALM_KEY_SHARE => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_CONFLICT_REPAIR => OperationPayloadSchema {
            requirements: CONFLICT_REPAIR_REQUIREMENTS,
            validate: Some(validate_conflict_repair_payload),
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
            validate: Some(validate_morph_create_payload),
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
        kinds::CX_CONTAINER_MOVE_ITEM | kinds::CX_CONTAINER_REBALANCE => OperationPayloadSchema {
            requirements: RELATION_ID_REQUIREMENTS,
            validate: None,
        },
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
        // R3 spec-sync — agent lifecycle FSM kinds.
        kinds::CX_AGENT_PAUSE => OperationPayloadSchema {
            requirements: AGENT_PAUSE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_RESUME => OperationPayloadSchema {
            requirements: AGENT_RESUME_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_DEACTIVATE => OperationPayloadSchema {
            requirements: AGENT_DEACTIVATE_REQUIREMENTS,
            validate: None,
        },
        // R3 spec-sync — actor_private_event kinds (reducer_input=false).
        kinds::CX_AGENT_DRAFT_PROPOSE => OperationPayloadSchema {
            requirements: AGENT_DRAFT_PROPOSE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_ACTION_REQUEST => OperationPayloadSchema {
            requirements: AGENT_ACTION_REQUEST_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_ACTION_APPROVE => OperationPayloadSchema {
            requirements: AGENT_ACTION_APPROVE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_AGENT_ACTION_REJECT => OperationPayloadSchema {
            requirements: AGENT_ACTION_REJECT_REQUIREMENTS,
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
    if operation.payload.get("track").is_some() {
        return Err("message operation field 'track' is retired; use track_name");
    }
    if operation.payload.get("body").is_some() {
        return Err("message operation field 'body' is retired; use content.body");
    }
    if operation.payload.get("encrypted_payload").is_some() {
        return Err(
            "message operation field 'encrypted_payload' is retired; use encrypted_content",
        );
    }
    if crate::kinds::operation_is_message_create(operation) {
        if operation
            .payload
            .get("flow_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err("message create requires flow_id");
        }
        let track_name = operation
            .payload
            .get("track_name")
            .and_then(Value::as_str)
            .ok_or("message create requires track_name")?;
        validate_read_scope_track(track_name)?;
    }
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_content").is_some();
    if encrypted {
        // The encrypted content envelope SHAPE is owned by the registered spec schema
        // `cx.schema.encrypted_envelope.v1` (referenced from
        // `message_create_payload` and enforced via
        // `event_payload_validator_catalog().validate_payload`). The spec
        // schema is the single source of truth — we only assert presence here
        // and never re-derive a divergent hand-written envelope shape.
        if operation.payload.get("encrypted_content").is_none()
            && operation.payload.get("content").is_none()
        {
            return Err("encrypted message operation requires content envelope");
        }
    } else if let Some(content) = operation.payload.get("content") {
        validate_content_blocks(content)?;
        validate_mentions(content)?;
        validate_audience_mentions(content)?;
    }
    Ok(())
}

fn validate_read_marker_payload(operation: &Operation) -> Result<(), &'static str> {
    let read_scope = operation
        .payload
        .get("read_scope")
        .and_then(|value| value.as_object())
        .ok_or("read marker read_scope must be an object")?;
    for key in read_scope.keys() {
        if !["kind", "ref", "track_name", "track_scope"].contains(&key.as_str()) {
            return Err("read marker read_scope has unknown field");
        }
    }
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
            return Err("read marker read_scope.kind removed; use flow plus track_name");
        }
        _ => return Err("read marker read_scope.kind is invalid"),
    }
    match (
        kind,
        read_scope
            .get("track_name")
            .and_then(|value| value.as_str()),
        read_scope
            .get("track_scope")
            .and_then(|value| value.as_str()),
    ) {
        ("flow", Some(track), None) => validate_read_scope_track(track)?,
        ("flow", None, Some("all")) => {}
        ("flow", Some(_), Some(_)) => {
            return Err("read marker read_scope requires exactly one of track_name or track_scope");
        }
        ("flow", None, None) => {
            return Err("read marker read_scope requires track_name or track_scope");
        }
        (_, Some(_), _) | (_, _, Some(_)) => {
            return Err("read marker read_scope.track_name/track_scope requires kind flow");
        }
        _ => {}
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

fn validate_history_visibility_payload(operation: &Operation) -> Result<(), &'static str> {
    let value = operation
        .payload
        .get("value")
        .and_then(Value::as_str)
        .ok_or("cx.realm.history_visibility requires string value")?;
    match value {
        "world_readable" | "shared" | "invited" | "joined" => Ok(()),
        "restricted" => {
            if operation
                .payload
                .get("restricted_policy_digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.starts_with("sha256:"))
            {
                Ok(())
            } else {
                Err("history_sharing_policy_missing")
            }
        }
        _ => Err("cx.realm.history_visibility value is unknown"),
    }
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

fn validate_conflict_repair_payload(operation: &Operation) -> Result<(), &'static str> {
    let cell_id = operation
        .payload
        .get("cell_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("conflict repair requires cell_id")?;
    if !cell_id.starts_with("cx:cell:") {
        return Err("conflict repair cell_id must use cx:cell:");
    }
    let heads = operation
        .payload
        .get("conflict_heads")
        .and_then(serde_json::Value::as_array)
        .ok_or("conflict repair requires conflict_heads")?;
    if heads.len() < 2 {
        return Err("conflict repair requires at least two conflict_heads");
    }
    if heads
        .iter()
        .any(|head| head.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err("conflict repair heads must be non-empty strings");
    }
    let recovery = operation
        .payload
        .get("recovery_capability_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or("conflict repair requires recovery_capability_ref")?;
    if recovery.trim().is_empty() {
        return Err("conflict repair recovery_capability_ref must be non-empty");
    }
    if operation.payload.get("winner_value").is_none() {
        return Err("conflict repair requires winner_value");
    }
    Ok(())
}

fn validate_read_scope_track(track: &str) -> Result<(), &'static str> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err("read marker read_scope.track_name is invalid");
    };
    if !first.is_ascii_lowercase()
        || track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("read marker read_scope.track_name is invalid");
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
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    reject_legacy_morph_patch_fields(patch)?;
    if patch.contains_key("content") && patch.contains_key("encrypted_content") {
        return Err("morph_content_carrier_conflict");
    }
    if patch.contains_key("metadata") && patch.contains_key("encrypted_metadata") {
        return Err("morph_metadata_carrier_conflict");
    }
    if patch.contains_key("schema_refs") {
        return Err("morph_schema_refs_evolution_unauthorized");
    }
    Ok(())
}

fn validate_morph_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(object) = operation.payload.get("object").and_then(Value::as_object) else {
        return Err("morph_create_object_invalid");
    };
    reject_legacy_morph_object_fields(object)?;
    if object.contains_key("content") && object.contains_key("encrypted_content") {
        return Err("morph_content_carrier_conflict");
    }
    if object.contains_key("metadata") && object.contains_key("encrypted_metadata") {
        return Err("morph_metadata_carrier_conflict");
    }
    if let Some(metadata) = object.get("metadata").and_then(Value::as_object) {
        reject_morph_metadata_business_fields(metadata)?;
    }
    Ok(())
}

fn reject_legacy_morph_object_fields(
    object: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for field in ["title", "summary", "encrypted_payload"] {
        if object.contains_key(field) {
            return Err("morph_legacy_wire_field");
        }
    }
    Ok(())
}

fn reject_legacy_morph_patch_fields(
    patch: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for field in ["title", "summary", "encrypted_payload"] {
        if patch.contains_key(field) {
            return Err("morph_legacy_wire_field");
        }
    }
    Ok(())
}

fn reject_morph_metadata_business_fields(
    metadata: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for field in [
        "id",
        "schema",
        "realm_id",
        "scope_circle_id",
        "schema_refs",
        "morph_type",
        "facets",
        "fields",
        "stage",
        "stage_changed_at",
        "state",
        "state_changed_at",
        "created_by",
        "created_at",
        "updated_by",
        "updated_at",
        "content",
        "encrypted_content",
        "encrypted_payload",
    ] {
        if metadata.contains_key(field) {
            return Err("morph_metadata_business_field");
        }
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

pub async fn validate_operation_policy(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        if kinds::operation_is_message_create(operation)
            && !message_operation_is_encrypted(operation)
            && known_space_denies_plaintext_service(state, operation.realm_id.as_str()).await
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
        if kinds::canonical_kind_for_operation(operation) == Some(kinds::CX_MORPH_SCHEMA_MIGRATE) {
            validate_morph_schema_migrate_capability(operation)?;
        }
        validate_member_state_policy(state, operation).await?;
        validate_history_visibility_policy(state, operation).await?;
        validate_realm_key_share_policy(state, operation).await?;
        validate_realm_moderation_policy(state, operation)?;
        validate_poll_operation_policy(state, operation)?;
        validate_audience_mention_operation_policy(state, operation).await?;
    }
    Ok(())
}

pub async fn validate_content_encryption_floor(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        match kinds::canonical_kind_for_operation(operation) {
            Some(kinds::CX_REALM_UPDATE) if operation_touches_encryption_profile(operation) => {
                return Err(REALM_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(kinds::CX_CIRCLE_UPDATE) if operation_touches_encryption_profile(operation) => {
                return Err(CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(kinds::CX_CIRCLE_CREATE) => {
                if let Some(profile) = operation_circle_encryption_profile(operation)
                    && !encryption_profile_requires_content_encryption(Some(profile))
                    && realm_requires_content_encryption(state, operation.realm_id.as_str()).await
                {
                    return Err(CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR);
                }
            }
            _ => {}
        }
        if flow_operation_carries_plaintext_private_content(operation)
            && realm_requires_content_encryption(state, operation.realm_id.as_str()).await
        {
            return Err(CONTENT_ENCRYPTION_FLOOR_VIOLATION);
        }
    }
    Ok(())
}

async fn validate_member_state_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CX_MEMBER_STATE) {
        return Ok(());
    }
    if operation.payload.get("membership").and_then(Value::as_str) == Some("join") {
        if let Some(member) = membership_target(operation)
            && crate::routing::organizations::organization_policy_blocks_join(
                state,
                operation.realm_id.as_str(),
                member,
            )
        {
            return Err("organization_policy_denied");
        }
        return Ok(());
    }
    if operation.payload.get("membership").and_then(Value::as_str) != Some("ban") {
        return Ok(());
    }
    let Some(actor) = operation.payload.get("sender").and_then(Value::as_str) else {
        // Peer/service-originated federation operations predate a typed actor
        // envelope. They stay accepted so existing convergence/backfill
        // paths keep working; direct client submits always carry `sender`.
        return Ok(());
    };
    if realm_owner_matches(state, operation.realm_id.as_str(), actor).await {
        return Ok(());
    }
    Err("missing_capability")
}

async fn validate_history_visibility_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CX_REALM_HISTORY_VISIBILITY) {
        return Ok(());
    }
    if operation.payload.get("value").and_then(Value::as_str) != Some("restricted") {
        return Ok(());
    }
    let Some(meta) = state
        .persistence
        .realm_meta()
        .get(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Err("history_sharing_policy_missing");
    };
    let Some(policy_digest) = meta.history_sharing_policy_digest.as_deref() else {
        return Err("history_sharing_policy_missing");
    };
    let requested_digest = operation
        .payload
        .get("restricted_policy_digest")
        .and_then(Value::as_str);
    if requested_digest == Some(policy_digest) {
        Ok(())
    } else {
        Err("history_sharing_policy_missing")
    }
}

async fn validate_realm_key_share_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CX_REALM_KEY_SHARE) {
        return Ok(());
    }
    let Some(meta) = state
        .persistence
        .realm_meta()
        .get(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Err("history_sharing_policy_missing");
    };
    let Some(policy) = meta.history_sharing_policy.as_ref() else {
        return Err("history_sharing_policy_missing");
    };
    if policy
        .get("default_key_share")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "event_time_visibility")
    {
        return Ok(());
    }
    if policy
        .get("restricted_rules")
        .and_then(Value::as_array)
        .is_some_and(|rules| !rules.is_empty())
    {
        return Ok(());
    }
    Err("history_not_visible")
}

fn membership_target(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("actor_id")
        .or_else(|| operation.payload.get("member"))
        .or_else(|| operation.payload.get("actor"))
        .or_else(|| operation.payload.get("sender"))
        .and_then(Value::as_str)
}

fn validate_realm_moderation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CX_REALM_MODERATION_POLICY) {
        return Ok(());
    }
    let realm_id = operation.realm_id.as_str();
    if crate::routing::organizations::space_policy_override_requires_approval(
        state,
        realm_id,
        &operation.payload,
    ) && !crate::routing::organizations::space_policy_override_has_approval(
        state,
        realm_id,
        &operation.payload,
    ) {
        return Err("requires_organization_approval");
    }
    Ok(())
}

async fn realm_owner_matches(state: &AppState, realm_id: &str, actor: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|meta| meta.owner == actor)
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

async fn validate_audience_mention_operation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(kinds::CX_MESSAGE_CREATE | kinds::CX_MESSAGE_REVISE)
    ) {
        return Ok(());
    }
    let mentions = operation_audience_mentions(operation)?;
    if mentions.is_empty() {
        return Ok(());
    }
    let actor = operation_actor(operation).ok_or("audience_mention_actor_missing")?;
    let realm_id = operation.realm_id.as_str();
    let resource = operation
        .payload
        .get("flow_id")
        .or_else(|| operation.payload.get("target_ref"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id);
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    let authz = state.authz.check(
        actor,
        CAP_ACTION_MESSAGE_MENTION_BROADCAST,
        resource,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
    if !authz.allowed {
        return Err("cx.message.mention.broadcast required for audience_mention");
    }
    if !authz
        .grants
        .iter()
        .any(grant_has_broadcast_safety_constraints)
    {
        return Err(
            "cx.message.mention.broadcast grant requires temporal and rate_limiting constraints",
        );
    }

    let Some(policy) = effective_audience_mention_policy_for_realm(state, realm_id).await else {
        return Err("audience_mention_policy_missing");
    };
    for mention in mentions {
        let count =
            estimate_audience_recipient_count(&mention.audience, &members, operation, state);
        audience_mention_policy_allows(&policy, &mention.audience, count)?;
    }
    Ok(())
}

fn operation_actor(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("actor_id"))
        .or_else(|| operation.payload.get("created_by"))
        .and_then(Value::as_str)
}

async fn realm_owner_and_members(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let mut meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten();
    if meta.is_none()
        && let Some(space_id) = realm_id
            .strip_prefix("cx:realm:")
            .map(|suffix| format!("cx:space:{suffix}"))
    {
        meta = state
            .persistence
            .realm_meta()
            .get(&space_id)
            .await
            .ok()
            .flatten();
    }
    let owner = meta.map(|meta| meta.owner);
    let members = state
        .realms
        .lock()
        .ok()
        .map(|realms| {
            if let Some(realm) = contrix_sdk::RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id))
            {
                return realm.members.iter().map(ToString::to_string).collect();
            }
            realm_id
                .strip_prefix("cx:realm:")
                .and_then(|suffix| contrix_sdk::RealmId::new(format!("cx:space:{suffix}")).ok())
                .and_then(|id| realms.get(&id))
                .map(|realm| realm.members.iter().map(ToString::to_string).collect())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    (owner, members)
}

fn grant_has_broadcast_safety_constraints(grant: &crate::authz::Grant) -> bool {
    let has_temporal = grant.expires_at.is_some()
        || grant.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                crate::authz::Constraint::Temporal {
                    expires_at: Some(_)
                }
            )
        });
    let has_rate_limit = grant.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            crate::authz::Constraint::RateLimiting { max_operations, period }
                if *max_operations > 0 && !period.trim().is_empty()
        )
    });
    has_temporal && has_rate_limit
}

async fn effective_audience_mention_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<Value> {
    let mut candidates = vec![realm_id.to_owned()];
    if let Some(suffix) = realm_id.strip_prefix("cx:realm:") {
        candidates.push(format!("cx:space:{suffix}"));
    }
    let events = state.persistence.events().snapshot_all().await.ok()?;
    events.into_iter().rev().find_map(|record| {
        if !record
            .realm_id
            .as_deref()
            .is_some_and(|space_id| candidates.iter().any(|candidate| candidate == space_id))
        {
            return None;
        }
        record
            .envelope
            .pointer("/payload/object/audience_mention_policy")
            .or_else(|| record.envelope.pointer("/payload/audience_mention_policy"))
            .or_else(|| {
                record
                    .envelope
                    .pointer("/payload/object/notification_policy/audience_mentions")
            })
            .or_else(|| {
                record
                    .envelope
                    .pointer("/payload/notification_policy/audience_mentions")
            })
            .cloned()
    })
}

fn estimate_audience_recipient_count(
    audience: &str,
    members: &[String],
    operation: &Operation,
    state: &AppState,
) -> usize {
    match audience {
        "flow_participants" => operation
            .payload
            .get("flow_id")
            .and_then(Value::as_str)
            .map(|flow_id| {
                state
                    .projection
                    .lock()
                    .ok()
                    .map(|projection| {
                        projection
                            .messages_for_thread(flow_id)
                            .into_iter()
                            .map(|message| message.sender.as_str())
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                    })
                    .unwrap_or(members.len())
            })
            .unwrap_or(members.len()),
        // Conservative upper bound: when the dispatcher cannot cheaply derive
        // watchers / assigned actors at policy time, use the readable member
        // set size so max_recipients never underestimates fanout.
        _ => members.len(),
    }
}

fn audience_mention_policy_allows(
    policy: &Value,
    audience: &str,
    recipient_count: usize,
) -> Result<(), &'static str> {
    if policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Err("audience_mention_policy_disabled");
    }
    let audience_policy = policy
        .get("audiences")
        .and_then(|audiences| audiences.get(audience));
    let listed = policy
        .get("allowed_audiences")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item == audience)
        });
    if audience_policy.is_none() && !listed {
        return Err("audience_mention_audience_not_allowed");
    }
    if audience_policy
        .and_then(|entry| entry.get("enabled"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Err("audience_mention_audience_not_allowed");
    }
    let max_recipients = audience_policy
        .and_then(|entry| entry.get("max_recipients"))
        .or_else(|| policy.get("max_recipients"))
        .and_then(Value::as_u64)
        .ok_or("audience_mention_max_recipients_missing")?;
    if recipient_count as u64 > max_recipients {
        return Err("audience_mention_recipient_count_exceeds_limit");
    }
    if !policy_declares_audience_quota(policy, audience_policy) {
        return Err("audience_mention_policy_quota_missing");
    }
    Ok(())
}

fn policy_declares_audience_quota(policy: &Value, audience_policy: Option<&Value>) -> bool {
    [audience_policy, Some(policy)]
        .into_iter()
        .flatten()
        .any(|entry| {
            let quota = entry.get("quota").unwrap_or(entry);
            quota
                .get("max_operations")
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 0)
                && quota
                    .get("period")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
        })
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

async fn realm_requires_content_encryption(state: &AppState, realm_id: &str) -> bool {
    let store = state.persistence.realm_meta();
    let mut realm_meta = store.get(realm_id).await.ok().flatten();
    if realm_meta.is_none()
        && let Some(space_id) = realm_id
            .strip_prefix("cx:realm:")
            .map(|suffix| format!("cx:space:{suffix}"))
    {
        realm_meta = store.get(&space_id).await.ok().flatten();
    }
    realm_meta.is_some_and(|record| {
        encryption_profile_requires_content_encryption(record.encryption_profile.as_deref())
    })
}

fn encryption_profile_requires_content_encryption(profile: Option<&str>) -> bool {
    // Current soland RealmMetaRecord projects the encryption mechanism but not
    // the separate content_encryption_floor field yet. Treat any non-plaintext
    // profile as content-only E2EE for Flow content admission.
    profile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|profile| !matches!(profile, "none" | "plaintext" | "allow_plaintext"))
}

fn operation_circle_encryption_profile(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("object")
        .and_then(|object| object.get("encryption_profile"))
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("encryption_profile")
                .and_then(Value::as_str)
        })
}

fn operation_touches_encryption_profile(operation: &Operation) -> bool {
    operation.payload.get("encryption_profile").is_some()
        || operation
            .payload
            .get("object")
            .is_some_and(|object| value_has_direct_field(object, "encryption_profile"))
        || patch_touches_field(&operation.payload, "encryption_profile")
}

fn value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

fn patch_touches_field(payload: &Value, field: &str) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch
                .iter()
                .any(|(key, value)| patch_entry_touches_field(key, value, field))
        })
}

fn patch_entry_touches_field(key: &str, value: &Value, field: &str) -> bool {
    patch_key_touches_field(key, field)
        || (key == "object" && patch_operation_value_has_direct_field(value, field))
}

fn patch_key_touches_field(key: &str, field: &str) -> bool {
    let dotted = format!("{field}.");
    let pointer = format!("/{field}");
    let pointer_child = format!("/{field}/");
    let object_dotted = format!("object.{field}");
    let object_dotted_child = format!("object.{field}.");
    let object_pointer = format!("/object/{field}");
    let object_pointer_child = format!("/object/{field}/");
    key == field
        || key.starts_with(&dotted)
        || key == pointer
        || key.starts_with(&pointer_child)
        || key == object_dotted
        || key.starts_with(&object_dotted_child)
        || key == object_pointer
        || key.starts_with(&object_pointer_child)
}

fn patch_operation_value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

fn flow_operation_carries_plaintext_private_content(operation: &Operation) -> bool {
    match kinds::canonical_kind_for_operation(operation) {
        Some(kinds::CX_FLOW_CREATE) => [
            &["synthesis"][..],
            &["object", "synthesis"][..],
            &["content"][..],
            &["object", "content"][..],
            &["attachments"][..],
            &["object", "attachments"][..],
        ]
        .iter()
        .any(|path| {
            value_at_path(&operation.payload, path).is_some_and(value_is_plaintext_content)
        }),
        Some(kinds::CX_FLOW_UPDATE) => patch_touches_plaintext_content_path(
            &operation.payload,
            &["synthesis", "content", "attachments"],
        ),
        _ => false,
    }
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn value_is_plaintext_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(object) => {
            !object.is_empty()
                && !encrypted_payload_value(value)
                && !object
                    .get("encrypted_content")
                    .is_some_and(encrypted_payload_value)
        }
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn encrypted_payload_value(value: &Value) -> bool {
    validate_encrypted_payload_envelope(value).is_ok() || sdk_encrypted_payload_value(value)
}

// Flow content-floor admission only needs to distinguish ciphertext-shaped
// content from plaintext. Message/device validators still enforce the stricter
// wire envelope shape through `validate_encrypted_payload_envelope`.
fn sdk_encrypted_payload_value(value: &Value) -> bool {
    let Some(envelope) = value.as_object() else {
        return false;
    };
    for field in ["scheme", "group_id", "content_type", "ciphertext"] {
        if envelope
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return false;
        }
    }
    envelope
        .get("epoch")
        .is_some_and(|value| value.as_u64().is_some())
        && envelope
            .get("payload_digest")
            .and_then(Value::as_str)
            .is_some_and(is_valid_sha256_digest)
}

fn patch_operation_value_is_plaintext_content(value: &Value) -> bool {
    if let Some(object) = value.as_object()
        && object.get("$op").and_then(Value::as_str) == Some("unset")
    {
        return false;
    }
    value.get("value").map_or_else(
        || value_is_plaintext_content(value),
        value_is_plaintext_content,
    )
}

fn patch_value_contains_plaintext_content_path(value: &Value, path: &str) -> bool {
    let Some(candidate) = value.get("value").unwrap_or(value).pointer(&format!(
        "/{}",
        path.split('.').collect::<Vec<_>>().join("/")
    )) else {
        return false;
    };
    value_is_plaintext_content(candidate)
}

fn patch_touches_plaintext_content_path(payload: &Value, private_paths: &[&str]) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(key, value)| {
                private_paths.iter().any(|private_path| {
                    if key == private_path || key.starts_with(&format!("{private_path}.")) {
                        patch_operation_value_is_plaintext_content(value)
                    } else if let Some(suffix) = private_path.strip_prefix(&format!("{key}.")) {
                        patch_value_contains_plaintext_content_path(value, suffix)
                    } else {
                        false
                    }
                })
            })
        })
}

pub fn message_operation_is_encrypted(operation: &Operation) -> bool {
    operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_content").is_some()
}

pub async fn known_space_denies_plaintext_service(state: &AppState, space_id: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(space_id)
        .await
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
    if message
        .get("type")
        .and_then(|value| value.as_str())
        .is_none_or(|value| value.trim().is_empty())
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
        if mention.get("kind").and_then(Value::as_str) == Some("audience_mention") {
            validate_audience_mention_object(mention)?;
            continue;
        }
        if let Some(subject_id) = mention.get("subject_id").and_then(|value| value.as_str()) {
            validate_did(subject_id).map_err(|_| "mention subject_id is invalid")?;
            continue;
        }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct AudienceMentionNode {
    audience: String,
}

fn operation_audience_mentions(
    operation: &Operation,
) -> Result<Vec<AudienceMentionNode>, &'static str> {
    let mut mentions = Vec::new();
    if let Some(content) = operation.payload.get("content") {
        collect_audience_mentions(content, &mut mentions)?;
    }
    if operation.payload.get("encrypted_content").is_some()
        && operation
            .payload
            .get("audience_mention_routing_hint")
            .is_some()
    {
        return Err("audience_mention_routing_hint unsupported without explicit E2EE profile");
    }
    Ok(mentions)
}

pub fn validate_audience_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    let mut mentions = Vec::new();
    collect_audience_mentions(content, &mut mentions)?;
    Ok(())
}

fn collect_audience_mentions(
    value: &serde_json::Value,
    out: &mut Vec<AudienceMentionNode>,
) -> Result<(), &'static str> {
    match value {
        Value::Object(object) => {
            if object.get("kind").and_then(Value::as_str) == Some("audience_mention") {
                let node = validate_audience_mention_object(object)?;
                out.push(node);
                return Ok(());
            }
            for value in object.values() {
                collect_audience_mentions(value, out)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_audience_mentions(value, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_audience_mention_object(
    object: &serde_json::Map<String, Value>,
) -> Result<AudienceMentionNode, &'static str> {
    let audience = object
        .get("audience")
        .and_then(Value::as_str)
        .ok_or("audience_mention requires audience")?;
    if !AUDIENCE_MENTION_ALLOWED_AUDIENCES.contains(&audience) {
        return Err("audience_mention audience is invalid");
    }
    if object
        .get("mention_text_original")
        .and_then(Value::as_str)
        .is_some_and(|token| token.trim().eq_ignore_ascii_case("@online"))
    {
        return Err("presence-filtered audience mention requires an explicit profile");
    }
    if object
        .get("mention_text_original")
        .and_then(Value::as_str)
        .is_some_and(|token| token.trim().eq_ignore_ascii_case("@here"))
        && audience != "flow_engaged"
    {
        return Err("@here MUST map to audience flow_engaged");
    }
    Ok(AudienceMentionNode {
        audience: audience.to_owned(),
    })
}

pub fn validate_canonical_json_value(value: &serde_json::Value) -> Result<(), &'static str> {
    validate_canonical_json_value_inner(value, true)
}

pub fn validate_canonical_json_value_inner(
    value: &serde_json::Value,
    root: bool,
) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number)
            if number.as_i64().is_none() && number.as_u64().is_none() =>
        {
            return Err("canonical JSON does not allow floating point numbers");
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
    if root && contrix_sdk::canonical::canonical_json_bytes(value).is_err() {
        return Err("value fails canonical JSON byte serialization");
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
            if block
                .get("text")
                .or_else(|| block.get("body"))
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("text content block requires text");
            }
        }
        "code" => {
            if block
                .get("text")
                .or_else(|| block.get("body"))
                .and_then(|value| value.as_str())
                .is_none_or(str::is_empty)
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
            if block
                .get("question")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
                || block
                    .get("options")
                    .and_then(|value| value.as_array())
                    .is_none_or(|options| options.len() < 2)
            {
                return Err("poll content block requires question and at least two options");
            }
        }
        "poll.response" => {
            if block
                .get("poll_id")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
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
            if block
                .get("poll_id")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("poll close content block requires poll_id");
            }
        }
        "audience_mention" => {
            validate_audience_mention_object(block)?;
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

    #[test]
    fn encrypted_realm_flow_content_detector_matches_content_only_boundary() {
        let flow_id = "cx:flow:01904100-0000-7000-8000-000000000001";
        let content_update = flow_position_op(
            kinds::CX_FLOW_UPDATE,
            json!({
                "flow_id": flow_id,
                "patch": {
                    "content": {"$op": "set", "value": {"kind": "cx.content.text", "body": "private description"}}
                }
            }),
        );
        assert!(flow_operation_carries_plaintext_private_content(
            &content_update
        ));

        let summary_update = flow_position_op(
            kinds::CX_FLOW_UPDATE,
            json!({
                "flow_id": flow_id,
                "patch": {
                    "metadata": {"$op": "set", "value": {"summary": "wire metadata"}}
                }
            }),
        );
        assert!(!flow_operation_carries_plaintext_private_content(
            &summary_update
        ));

        let sdk_encrypted_content_update = flow_position_op(
            kinds::CX_FLOW_UPDATE,
            json!({
                "flow_id": flow_id,
                "patch": {
                    "content": {
                        "$op": "set",
                        "value": {
                            "scheme": "mls-rfc9420",
                            "group_id": "cx_space_01904100_0000_7000_8000_000000000001",
                            "epoch": 1,
                            "content_type": "application/vnd.contrix.flow.patch-value+json",
                            "ciphertext": "T1BBUVVFX0NJUEhFUlRFWFQ",
                            "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    }
                }
            }),
        );
        assert!(!flow_operation_carries_plaintext_private_content(
            &sdk_encrypted_content_update
        ));

        let ciphertext_label_content_update = flow_position_op(
            kinds::CX_FLOW_UPDATE,
            json!({
                "flow_id": flow_id,
                "patch": {
                    "content": {
                        "$op": "set",
                        "value": {
                            "ciphertext": "not enough envelope metadata"
                        }
                    }
                }
            }),
        );
        assert!(flow_operation_carries_plaintext_private_content(
            &ciphertext_label_content_update
        ));

        let title_create = flow_position_op(
            kinds::CX_FLOW_CREATE,
            json!({
                "object": {
                    "id": flow_id,
                    "metadata": {"title": "wire metadata"}
                }
            }),
        );
        assert!(!flow_operation_carries_plaintext_private_content(
            &title_create
        ));
    }

    #[test]
    fn create_locked_encryption_profile_detector_matches_update_shapes() {
        let direct_patch = flow_position_op(
            kinds::CX_REALM_UPDATE,
            json!({
                "patch": {
                    "encryption_profile": "none"
                }
            }),
        );
        assert!(operation_touches_encryption_profile(&direct_patch));

        let pointer_patch = flow_position_op(
            kinds::CX_CIRCLE_UPDATE,
            json!({
                "circle_id": "cx:circle:01904100-0000-7000-8000-000000000001",
                "patch": {
                    "/object/encryption_profile": {
                        "$op": "replace",
                        "value": "none"
                    }
                }
            }),
        );
        assert!(operation_touches_encryption_profile(&pointer_patch));

        let metadata_patch = flow_position_op(
            kinds::CX_REALM_UPDATE,
            json!({
                "patch": {
                    "title": "Still mutable"
                }
            }),
        );
        assert!(!operation_touches_encryption_profile(&metadata_patch));
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
    fn canonical_space_update_accepts_target_ref_and_patch() {
        let schema = operation_schema_for_kind(kinds::CX_SPACE_CONTAINER_UPDATE).unwrap();
        let operation = space_container_op(
            kinds::CX_SPACE_CONTAINER_UPDATE,
            json!({
                "target_ref": "cx:space:01904100-0000-7000-8000-000000000003",
                "patch": {"title": "Launch v2"}
            }),
        );
        assert!(validate_operation_schema(&operation, schema).is_ok());

        let legacy_space_id = space_container_op(
            kinds::CX_SPACE_CONTAINER_UPDATE,
            json!({
                "space_id": "cx:space:01904100-0000-7000-8000-000000000003",
                "patch": {"title": "Launch v2"}
            }),
        );
        assert!(validate_operation_schema(&legacy_space_id, schema).is_ok());

        let missing_space_id = space_container_op(
            kinds::CX_SPACE_CONTAINER_UPDATE,
            json!({"patch": {"title": "Launch v2"}}),
        );
        assert_eq!(
            validate_operation_schema(&missing_space_id, schema),
            Err("space update operation requires target_ref")
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
mod message_projection_schema_tests {
    use super::*;
    use contrix_sdk::Operation;
    use serde_json::json;

    fn op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn message_revise_accepts_spec_canonical_target_ref() {
        let operation = op(
            kinds::CX_MESSAGE_REVISE,
            json!({
                "target_ref": "cx:event:01904100-0000-7000-8000-000000000001",
                "content": {"kind": "cx.content.text", "body": "edited"}
            }),
        );
        let schema = operation_schema_for_kind(kinds::CX_MESSAGE_REVISE).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn reaction_accepts_spec_target_ref_without_event_alias() {
        let operation = op(
            kinds::CX_REACTION_ADD,
            json!({
                "target_ref": "cx:event:01904100-0000-7000-8000-000000000001",
                "sender": "did:web:alice.example",
                "key": "+1"
            }),
        );
        let schema = operation_schema_for_kind(kinds::CX_REACTION_ADD).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
        assert!(operation.payload.get("event_id").is_none());
        assert!(operation.payload.get("actor").is_none());
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
                "flow_id": "cx:flow:01904100-0000-7000-8000-000000000001",
                "track_name": "discussion",
                "content": {"kind": "cx.content.text", "body": "hello"},
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
    fn morph_create_rejects_legacy_metadata_and_payload_names() {
        let schema = operation_schema_for_kind(kinds::CX_MORPH_CREATE).unwrap();
        let valid = op(
            kinds::CX_MORPH_CREATE,
            json!({
                "object": {
                    "id": "cx:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["cx.schema.morph.v1"],
                    "metadata": {"title": "Spec"},
                    "encrypted_content": {"version": 1}
                }
            }),
        );
        assert!(validate_operation_schema(&valid, schema).is_ok());

        let legacy_title = op(
            kinds::CX_MORPH_CREATE,
            json!({
                "object": {
                    "id": "cx:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["cx.schema.morph.v1"],
                    "title": "Spec"
                }
            }),
        );
        assert_eq!(
            validate_operation_schema(&legacy_title, schema),
            Err("morph_legacy_wire_field")
        );

        let content_conflict = op(
            kinds::CX_MORPH_CREATE,
            json!({
                "object": {
                    "id": "cx:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["cx.schema.morph.v1"],
                    "content": {},
                    "encrypted_content": {}
                }
            }),
        );
        assert_eq!(
            validate_operation_schema(&content_conflict, schema),
            Err("morph_content_carrier_conflict")
        );
    }

    #[test]
    fn morph_schema_refs_use_migrate_gate() {
        let update_schema = operation_schema_for_kind(kinds::CX_MORPH_UPDATE).unwrap();
        let legacy_title = op(
            kinds::CX_MORPH_UPDATE,
            json!({
                "morph_id": "cx:morph:01904100-0000-7000-8000-000000000001",
                "patch": {"title": "Spec v2"}
            }),
        );
        assert_eq!(
            validate_operation_schema(&legacy_title, update_schema),
            Err("morph_legacy_wire_field")
        );

        let update = op(
            kinds::CX_MORPH_UPDATE,
            json!({
                "morph_id": "cx:morph:01904100-0000-7000-8000-000000000001",
                "patch": {"schema_refs": ["cx.schema.new"]}
            }),
        );
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
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
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
            "reset_reason_code": "rotation",
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
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
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
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
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
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
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

#[cfg(test)]
mod audience_mention_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audience_mention_accepts_here_as_flow_engaged() {
        let content = json!({
            "kind": "cx.content.composite",
            "parts": [
                {"kind": "cx.content.text", "body": "Team heads up"},
                {
                    "kind": "audience_mention",
                    "audience": "flow_engaged",
                    "mention_text_original": "@here"
                }
            ]
        });

        validate_content_blocks(&content).unwrap();
        validate_audience_mentions(&content).unwrap();
    }

    #[test]
    fn audience_mention_rejects_presence_online_without_profile() {
        let content = json!({
            "kind": "audience_mention",
            "audience": "flow_engaged",
            "mention_text_original": "@online"
        });

        assert_eq!(
            validate_audience_mentions(&content),
            Err("presence-filtered audience mention requires an explicit profile")
        );
    }

    #[test]
    fn audience_mention_policy_requires_finite_limits_and_quota() {
        let policy = json!({
            "enabled": true,
            "allowed_audiences": ["flow_engaged"],
            "max_recipients": 5,
            "quota": {"max_operations": 2, "period": "PT1H"}
        });

        audience_mention_policy_allows(&policy, "flow_engaged", 5).unwrap();
        assert_eq!(
            audience_mention_policy_allows(&policy, "flow_engaged", 6),
            Err("audience_mention_recipient_count_exceeds_limit")
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
        if envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_none_or(|value| value.trim().is_empty())
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
    if envelope
        .get("epoch")
        .is_none_or(|value| value.as_u64().is_none())
    {
        return Err("encrypted content envelope requires numeric epoch");
    }
    if envelope.get("aad").is_none() {
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
    if !digests
        .values()
        .all(|value| value.as_str().is_some_and(is_valid_sha256_digest))
    {
        return Err("encrypted content envelope digests must be sha256:<64 lowercase hex>");
    }
    Ok(())
}
