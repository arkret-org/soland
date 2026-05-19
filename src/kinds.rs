use contrix_sdk::Operation;
use serde_json::Value;

use crate::artifacts;

pub const CX_MESSAGE_CREATE: &str = "cx.message.create";
pub const CX_MESSAGE_REVISE: &str = "cx.message.revise";
pub const CX_MESSAGE_REDACT: &str = "cx.message.redact";
pub const CX_REACTION_ADD: &str = "cx.reaction.add";
pub const CX_REACTION_REMOVE: &str = "cx.reaction.remove";
pub const CX_RELATION_CREATE: &str = "cx.relation.create";
pub const CX_RELATION_UPDATE: &str = "cx.relation.update";
pub const CX_RELATION_DELETE: &str = "cx.relation.delete";
pub const CX_VIEW_CREATE: &str = "cx.view.create";
pub const CX_VIEW_UPDATE: &str = "cx.view.update";
pub const CX_VIEW_RECONCILE: &str = "cx.view.reconcile";
// Realm/Space reversal (R1.2): the v1 protocol renames the old security
// boundary `Space` to `Realm`, and the old container `Place` to `Space`.
// These constants now point at the new wire strings. Internal Rust
// identifiers (e.g. `CX_SPACE_CREATE`, struct `PlaceProjection`) retain
// their pre-rename names — they're internal-only and a follow-up TODO
// will rename them in a non-mechanical refactor.
//
// New container `cx.space.*` (was `cx.place.*`). Container lifecycle.
pub const CX_PLACE_CREATE: &str = "cx.space.create";
pub const CX_PLACE_UPDATE: &str = "cx.space.update";
pub const CX_PLACE_PARENT: &str = "cx.space.parent";
pub const CX_PLACE_ARCHIVE: &str = "cx.space.archive";
pub const CX_PLACE_RESTORE: &str = "cx.space.restore";
pub const CX_PLACE_TOMBSTONE: &str = "cx.space.tombstone";
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
// Round 16 — Flow watch subscription event. Writes the
// `cx.component.flow.watch.v1` cas-register cell keyed by
// (flow_id, actor_did). Spec:
// contrix-spec/spec/v1/zh/models/flow-and-message.md §8. Like the
// flow position events the Event-Envelope path only validates payload
// shape; cell write happens on the Move/Anchor pipeline. The Flow
// projection's updated_at is NOT bumped — watch is a per-(flow, actor)
// subscription that does not represent a Flow state mutation.
pub const CX_FLOW_WATCH_SET: &str = "cx.flow.watch.set";
// Unified Flow tracks update event. `payload.patch` uses `cx.patch.v1`
// against the `Flow.tracks` map; atomic across multiple tracks. soland's
// wire validator enforces payload shape (flow_id + patch | tracks) and
// the spec common-fields.md §5.1 update-on-non-active state guard.
// FlowProjection doesn't carry `tracks` server-side; the touch just
// bumps `updated_at` (mirror of cx.flow.move/reorder pattern).
pub const CX_FLOW_TRACKS_UPDATE: &str = "cx.flow.tracks.update";
// Morph lifecycle (round 13). Same shape as Flow — no dedicated tombstone.
pub const CX_MORPH_CREATE: &str = "cx.morph.create";
pub const CX_MORPH_UPDATE: &str = "cx.morph.update";
pub const CX_MORPH_ARCHIVE: &str = "cx.morph.archive";
pub const CX_MORPH_RESTORE: &str = "cx.morph.restore";
// `cx.field.position.move` and `cx.field.position.reorder` were removed in
// revision 0a5ab85 (see contrix-spec
// `artifacts/registry/removed-event-kinds.json`). Field-level position move
// was subsumed by track-relative ordering and the per-cell ordered-log
// lattice. No replacement; reducer/wire MUST hard_reject these kinds. The
// generic unknown-event-kind path in `event_log::submit_event` already
// rejects them because they no longer appear in `active_durable_event_kinds`.
pub const CX_CONTAINER_MOVE_ITEM: &str = "cx.container.move_item";
pub const CX_CONTAINER_REBALANCE: &str = "cx.container.rebalance";
pub const CX_MEMBER_STATE: &str = "cx.member.state";
pub const CX_READ_MARKER: &str = "cx.read.marker";
// Realm boundary (was the old `cx.space.*` security namespace). The
// Rust identifiers retain the old name to keep the diff mechanical; the
// `&str` values point at the new `cx.realm.*` wire strings.
pub const CX_SPACE_CREATE: &str = "cx.realm.create";
pub const CX_SPACE_UPDATE: &str = "cx.realm.update";
pub const CX_SPACE_DESTROY: &str = "cx.realm.destroy";
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

// `cx.profile.agent_workspace.v1` — Agent Workspace task & FSM events.
// Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md`.
// Mirror Space–scoped event kinds. Three orthogonal FSM cells:
// execution_state / transparency / source_authority. Cancel is an alias for
// execution.transition(to=cancelled_by_controller).
pub const CX_AGENT_TASK_CREATE: &str = "cx.agent_task.create";
pub const CX_AGENT_TASK_EXECUTION_TRANSITION: &str = "cx.agent_task.execution.transition";
pub const CX_AGENT_TASK_TRANSPARENCY_TRANSITION: &str = "cx.agent_task.transparency.transition";
pub const CX_AGENT_TASK_SOURCE_AUTHORITY_TRANSITION: &str =
    "cx.agent_task.source_authority.transition";
pub const CX_AGENT_TASK_CANCEL: &str = "cx.agent_task.cancel";

// `cx.profile.agent_workspace.v1` — reservation Moves on mirror_*_by_source
// cells (cas-register + empty sentinel pattern). Spec §6.2 / §6.3 / §6.4.
pub const CX_AGENT_WORKSPACE_RESERVATION_SET: &str = "cx.agent_workspace.reservation.set";
pub const CX_AGENT_WORKSPACE_RESERVATION_RECOVER: &str = "cx.agent_workspace.reservation.recover";
pub const CX_AGENT_WORKSPACE_RESERVATION_CLEANUP: &str = "cx.agent_workspace.reservation.cleanup";

// Round C45 (2026-05-18 main; spec 346f347) — registry refactor dropped the
// `.v1` suffix from these audit event kinds. Wire schema versioning now
// flows through `requirements.features` (e.g. `cx.feature.audit_destruction_v1`).
// `attested_hardware` Audit Agent removal MUST emit
// `cx.audit.epoch_key_destruction` in the same anchor batch as the paired
// `cx.mls.commit`. If the deadline passes without the attestation, soland
// forces a `cx.realm.audit_policy_downgrade` event (R1.2: was
// `cx.space.audit_policy_downgrade` pre-Realm/Space reversal) that drops
// `audit_assurance` from attested_hardware to disclosed_policy and triggers
// a UI banner. Reducer-level validation lives in `src/reducer.rs` under
// `apply_audit_epoch_key_destruction` / `apply_audit_policy_downgrade`
// (still TODO stubs pending full attestation-chain verification).
pub const CX_AUDIT_EPOCH_KEY_DESTRUCTION: &str = "cx.audit.epoch_key_destruction";
// Realm reversal (R1.2): `cx.space.audit_policy_downgrade` →
// `cx.realm.audit_policy_downgrade`.
pub const CX_SPACE_AUDIT_POLICY_DOWNGRADE: &str = "cx.realm.audit_policy_downgrade";

// Round C45 (2026-05-18 main) — new event kinds.
//
// `cx.identity.accountability_grant` (identity / reducer_input): issuer-signed
//   endorsement that a subject DID is accountable_to the issuer for a declared
//   scope. Required to verify `Actor Profile.accountable_to[]` entries; reducer
//   strips unverified DIDs from accountable_to (or rejects with
//   `accountability_grant_missing`, per deployment policy). zh/models/actor.md §3.3.1.
// `cx.morph.schema_migrate` (morph / reducer_input): one-shot Morph
//   `schema_refs[]` evolution event with explicit compatibility class.
//   zh/models/morph.md §4.1 S3.
// `cx.attestation.range_completeness` (audit / non-reducer): range-bound
//   completeness attestation; backs cross-issuer fork detection.
//   zh/sync/operations-sync.md §4.2.
pub const CX_IDENTITY_ACCOUNTABILITY_GRANT: &str = "cx.identity.accountability_grant";
pub const CX_MORPH_SCHEMA_MIGRATE: &str = "cx.morph.schema_migrate";
pub const CX_ATTESTATION_RANGE_COMPLETENESS: &str = "cx.attestation.range_completeness";

// Round C46 (2026-05-19; spec 0a5ab85) — Realm-scoped delivery binding
// governance + per-device push route binding. R1.2 (Realm/Space
// reversal) renamed the event_kind and cell_family from the old
// `cx.space.*` security namespace to `cx.realm.*`.
//
// `cx.realm.delivery_binding_policy` (realm / reducer_input): Realm
//   policy constraining which `binding_source` values are admissible,
//   which recipient services are allowed, which endorsers are required,
//   whether DID Document fallback / unroutable membership are permitted,
//   and who may sign rebind. cell_family
//   `cx.component.realm.delivery_binding_policy.v1`, cas-register.
//   Governs reducer acceptance of `cx.member.state{join}`
//   delivery_binding. The reducer projects the policy cell + applies
//   binding-source / recipient-service / service-acceptance / policy-
//   frontier checks against routable joins.
//
// `cx.device.push_route` (device / actor_private_event / reducer_input):
//   per-device push route binding for the composite tuple
//   `(recipient_service_did, principal, device, push_route)`. MUST NOT be
//   replicated outside the binding's recipient_service_did context. Stored
//   as actor-private state on the recipient Principal Server only.
// Realm reversal (R1.2): `cx.space.delivery_binding_policy` →
// `cx.realm.delivery_binding_policy`. cell_family also renamed from
// `cx.component.space.delivery_binding_policy.v1` →
// `cx.component.realm.delivery_binding_policy.v1`.
pub const CX_SPACE_DELIVERY_BINDING_POLICY: &str = "cx.realm.delivery_binding_policy";
// `cx.device.push_route` is device-scoped — unchanged by the rename.
pub const CX_DEVICE_PUSH_ROUTE: &str = "cx.device.push_route";

// Round R1.2 — new event kinds introduced by the Realm/Space reversal.
// Wire-accept + projection no-op stubs; full semantics are TODO.
//
// `cx.realm.link` (realm / reducer_input): typed link between Realm boundaries.
// Replaces the old `cx.space.parent` / `cx.space.child` (security) shapes;
// canonical `link_kind` handling is TODO(realm-rework).
pub const CX_REALM_LINK: &str = "cx.realm.link";
// `cx.realm.inheritance_policy` (realm / reducer_input): declares which
// realm-scoped policies a child Realm inherits from its parent boundary.
// Drives capability derivation alongside `cx.capability.derived`.
pub const CX_REALM_INHERITANCE_POLICY: &str = "cx.realm.inheritance_policy";
// `cx.capability.derived` (capability / reducer_input): records a capability
// derived from a parent Realm's policy + a child Realm's inheritance
// declaration. Full derive logic is TODO(realm-rework).
pub const CX_CAPABILITY_DERIVED: &str = "cx.capability.derived";

pub fn canonical_kind_for_operation(operation: &Operation) -> Option<&str> {
    canonical_kind_for_payload(&operation.object_type, &operation.payload)
}

pub fn canonical_kind_string(operation: &Operation) -> String {
    canonical_kind_for_operation(operation)
        .unwrap_or(operation.object_type.as_str())
        .to_owned()
}

pub fn canonical_kind_for_payload<'a>(object_type: &'a str, _payload: &Value) -> Option<&'a str> {
    canonical_registered_kind(object_type)
}

fn canonical_registered_kind(object_type: &str) -> Option<&str> {
    if !artifacts::active_durable_event_kinds().contains(object_type) {
        return None;
    }
    let kind = match object_type {
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
        CX_FLOW_WATCH_SET => Some(CX_FLOW_WATCH_SET),
        CX_FLOW_TRACKS_UPDATE => Some(CX_FLOW_TRACKS_UPDATE),
        CX_MORPH_CREATE => Some(CX_MORPH_CREATE),
        CX_MORPH_UPDATE => Some(CX_MORPH_UPDATE),
        CX_MORPH_ARCHIVE => Some(CX_MORPH_ARCHIVE),
        CX_MORPH_RESTORE => Some(CX_MORPH_RESTORE),
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
        // Tier-0 S6 audit kinds (C44 wire-valid, C45 renamed off `.v1`).
        // Projection is currently `Ignored` pending full attestation-chain
        // verification.
        CX_AUDIT_EPOCH_KEY_DESTRUCTION => Some(CX_AUDIT_EPOCH_KEY_DESTRUCTION),
        CX_SPACE_AUDIT_POLICY_DOWNGRADE => Some(CX_SPACE_AUDIT_POLICY_DOWNGRADE),
        // Round C45 — new event kinds. Wire-valid; reducer dispatch is TODO
        // (accountability_grant strips unverified DIDs from accountable_to;
        // morph.schema_migrate enforces capability + compatibility_class
        // gate; range_completeness is non-reducer audit-side evidence).
        CX_IDENTITY_ACCOUNTABILITY_GRANT => Some(CX_IDENTITY_ACCOUNTABILITY_GRANT),
        CX_MORPH_SCHEMA_MIGRATE => Some(CX_MORPH_SCHEMA_MIGRATE),
        CX_ATTESTATION_RANGE_COMPLETENESS => Some(CX_ATTESTATION_RANGE_COMPLETENESS),
        // Round C46 — delivery binding governance + push route binding.
        // Wire-valid; reducer projection is TODO pending full policy /
        // push registration plumbing.
        CX_SPACE_DELIVERY_BINDING_POLICY => Some(CX_SPACE_DELIVERY_BINDING_POLICY),
        CX_DEVICE_PUSH_ROUTE => Some(CX_DEVICE_PUSH_ROUTE),
        // Round R1.2 (Realm/Space reversal) — schema-level accept; reducer
        // projection is TODO(realm-rework) for link_kind / inheritance /
        // capability derive semantics.
        CX_REALM_LINK => Some(CX_REALM_LINK),
        CX_REALM_INHERITANCE_POLICY => Some(CX_REALM_INHERITANCE_POLICY),
        CX_CAPABILITY_DERIVED => Some(CX_CAPABILITY_DERIVED),
        _ => Some(object_type),
    };
    kind
}

/// Applet + agent family classifiers used by projection/audit
/// dispatchers that want to fan out the whole family without listing
/// every kind individually.
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
    matches!(
        kind,
        CX_PLACE_ARCHIVE | CX_PLACE_RESTORE | CX_PLACE_TOMBSTONE
    )
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

/// Flow tracks update events. Distinct from lifecycle events
/// (`is_flow_lifecycle_kind`) because tracks don't transition Flow.state;
/// they manage entries in `Flow.tracks`. The state guard is "parent Flow
/// MUST be Active" (spec §5.1 update rule), enforced via
/// `check_flow_tracks_transition`.
pub fn is_flow_tracks_kind(kind: &str) -> bool {
    matches!(kind, CX_FLOW_TRACKS_UPDATE)
}
