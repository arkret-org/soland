use cokret_sdk::Operation;
use serde_json::Value;

use crate::artifacts;

pub use cokret_sdk::events::kinds::MESSAGE_CREATE as CX_MESSAGE_CREATE;
pub use cokret_sdk::events::kinds::MESSAGE_REVISE as CX_MESSAGE_REVISE;
pub use cokret_sdk::events::kinds::MESSAGE_REDACT as CX_MESSAGE_REDACT;
pub use cokret_sdk::events::kinds::REACTION_ADD as CX_REACTION_ADD;
pub use cokret_sdk::events::kinds::REACTION_REMOVE as CX_REACTION_REMOVE;
pub use cokret_sdk::events::kinds::RELATION_CREATE as CX_RELATION_CREATE;
pub use cokret_sdk::events::kinds::RELATION_UPDATE as CX_RELATION_UPDATE;
pub use cokret_sdk::events::kinds::RELATION_TOMBSTONE as CX_RELATION_DELETE;
pub use cokret_sdk::events::kinds::VIEW_CREATE as CX_VIEW_CREATE;
pub use cokret_sdk::events::kinds::VIEW_UPDATE as CX_VIEW_UPDATE;
pub use cokret_sdk::events::kinds::VIEW_RECONCILE as CX_VIEW_RECONCILE;
// Space-container lifecycle (`cx.space.*`). Spec
// `cokret-spec/spec/v1/zh/models/realm-and-space.md` — the v1 protocol
// container, distinct from the `cx.realm.*` security boundary below.
pub use cokret_sdk::events::kinds::SPACE_CREATE as CX_SPACE_CONTAINER_CREATE;
pub use cokret_sdk::events::kinds::SPACE_UPDATE as CX_SPACE_CONTAINER_UPDATE;
pub use cokret_sdk::events::kinds::SPACE_PARENT as CX_SPACE_CONTAINER_PARENT;
pub use cokret_sdk::events::kinds::SPACE_ARCHIVE as CX_SPACE_CONTAINER_ARCHIVE;
pub use cokret_sdk::events::kinds::SPACE_RESTORE as CX_SPACE_CONTAINER_RESTORE;
pub use cokret_sdk::events::kinds::SPACE_TOMBSTONE as CX_SPACE_CONTAINER_TOMBSTONE;
// Flow lifecycle (round 13 — Flow projection state machine). spec
// `common-fields.md §5.1` Flow row: active / archived / redacted / deleted.
// Flow has no dedicated `cx.flow.tombstone` event (terminal state reached
// via `cx.redaction`); only archive/restore are state-machine transitions
// here.
pub use cokret_sdk::events::kinds::FLOW_CREATE as CX_FLOW_CREATE;
pub use cokret_sdk::events::kinds::FLOW_UPDATE as CX_FLOW_UPDATE;
pub use cokret_sdk::events::kinds::FLOW_ARCHIVE as CX_FLOW_ARCHIVE;
pub use cokret_sdk::events::kinds::FLOW_RESTORE as CX_FLOW_RESTORE;
// Round 14 — Flow position events. Not state-machine transitions; they
// write to the `ck.component.flow.position.v1` cell family keyed by
// (board_space_id, flow_id). The Event-Envelope path only validates
// payload shape and bumps the Flow's updated_at/by; the cell write
// happens on the Move/Anchor pipeline (out of scope for the reducer's
// structured cache).
pub use cokret_sdk::events::kinds::FLOW_MOVE as CX_FLOW_MOVE;
pub use cokret_sdk::events::kinds::FLOW_REORDER as CX_FLOW_REORDER;
// Round 16 — Flow watch subscription event. Writes the
// `ck.component.flow.watch.v1` cas-register cell keyed by
// (flow_id, watcher_actor_id). Spec:
// cokret-spec/spec/v1/zh/models/flow-and-message.md §8. Like the
// flow position events the Event-Envelope path only validates payload
// shape; cell write happens on the Move/Anchor pipeline. The Flow
// projection's updated_at is NOT bumped — watch is a per-(flow, actor)
// subscription that does not represent a Flow state mutation.
pub use cokret_sdk::events::kinds::FLOW_WATCH_SET as CX_FLOW_WATCH_SET;
// Unified Flow tracks update event. `payload.patch` uses `ck.patch.v1`
// against the `Flow.tracks` map; atomic across multiple tracks. soland's
// wire validator enforces payload shape (flow_id + patch | tracks) and
// the spec common-fields.md §5.1 update-on-non-active state guard.
// FlowProjection doesn't carry `tracks` server-side; the touch just
// bumps `updated_at` (mirror of ck.flow.move/reorder pattern).
pub use cokret_sdk::events::kinds::FLOW_TRACKS_UPDATE as CX_FLOW_TRACKS_UPDATE;
// CXP-0007 (spec b7d35be) — Circle lifecycle / membership events. Seven
// active durable kinds registered in
// `spec/v1/artifacts/registry/event-kind-registry.json`. The reducer
// dispatch is wired in `src/reducer.rs`; the wire-layer admission check
// runs through the generic `active_durable_event_kinds` registry.
//
// `ck.circle.anchor_commit` is reducer-DERIVED (sub-anchor emitted on
// the Circle's profile cadence) and MUST NOT be submitted directly via
// `ck.events.submit`. The SDK gates this in
// `kinds::is_reducer_input_event_kind`.
pub use cokret_sdk::events::kinds::CIRCLE_CREATE as CX_CIRCLE_CREATE;
pub use cokret_sdk::events::kinds::CIRCLE_UPDATE as CX_CIRCLE_UPDATE;
pub use cokret_sdk::events::kinds::CIRCLE_ARCHIVE as CX_CIRCLE_ARCHIVE;
pub use cokret_sdk::events::kinds::CIRCLE_RESTORE as CX_CIRCLE_RESTORE;
pub use cokret_sdk::events::kinds::CIRCLE_TOMBSTONE as CX_CIRCLE_TOMBSTONE;
pub use cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE as CX_CIRCLE_MEMBER_STATE;

// CXP-0007 — typed Relation kind couples a "wide synthesis" Flow (often
// Realm-default scope) to a "narrow discussion" Flow bound to a
// `scope_circle_id` Circle. Stored on `ck.relation.create` /
// `ck.relation.update` payloads as `relation_kind`. Spec
// `zh/models/circle.md` §7.2.
pub const RELATION_KIND_CONFIDENTIAL_DISCUSSION_OF: &str = "confidential_discussion_of";

// Morph lifecycle (round 13). Same shape as Flow — no dedicated tombstone.
pub use cokret_sdk::events::kinds::MORPH_CREATE as CX_MORPH_CREATE;
pub use cokret_sdk::events::kinds::MORPH_UPDATE as CX_MORPH_UPDATE;
pub use cokret_sdk::events::kinds::MORPH_ARCHIVE as CX_MORPH_ARCHIVE;
pub use cokret_sdk::events::kinds::MORPH_RESTORE as CX_MORPH_RESTORE;
// `cx.field.position.move` and `cx.field.position.reorder` were removed in
// revision 0a5ab85 (see cokret-spec
// `artifacts/registry/removed-event-kinds.json`). Field-level position move
// was subsumed by track-relative ordering and the per-cell ordered-log
// lattice. No replacement; reducer/wire MUST hard_reject these kinds. The
// generic unknown-event-kind path in `event_log::submit_event` already
// rejects them because they no longer appear in `active_durable_event_kinds`.
pub use cokret_sdk::events::kinds::CONTAINER_MOVE_ITEM as CX_CONTAINER_MOVE_ITEM;
pub use cokret_sdk::events::kinds::CONTAINER_REBALANCE as CX_CONTAINER_REBALANCE;
pub use cokret_sdk::events::kinds::INVITE_CREATE as CX_INVITE_CREATE;
pub use cokret_sdk::events::kinds::MEMBER_STATE as CX_MEMBER_STATE;
// R3.1 spec-sync (2026-05-27, cokret-spec @ 7157ee8) — Realm-scoped
// MemberIdentity append-only replacement event. Cell family
// `ck.component.member.identity.v1`; lattice `ordered_log`; bottom
// `expose`. Composite cell subject is
// `(payload.realm_id, payload.actor_id, payload.segment)`. Reducer
// dispatch lives in `reducer::apply_member_identity_update`; persistence
// is in `state::MemberIdentityRegistry`.
pub use cokret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE as CX_MEMBER_IDENTITY_UPDATE;
pub use cokret_sdk::events::kinds::READ_CURSOR_ADVANCE as CX_READ_MARKER;
// Realm security-boundary lifecycle (`cx.realm.*`). Spec
// `cokret-spec/spec/v1/zh/models/realm-and-space.md` §1 + §4.
//
// `ck.realm.tombstone` is the irreversible terminal-state event that
// freezes the Realm and triggers the erasure-receipt fanout chain via
// `ck.audit.erasure_receipt`. Distinct from `ck.realm.destroy`, which
// is the GDPR-grade hard-delete request that retains a `retained_stub_digest`.
pub use cokret_sdk::events::kinds::REALM_CREATE as CX_REALM_CREATE;
pub use cokret_sdk::events::kinds::REALM_UPDATE as CX_REALM_UPDATE;
pub use cokret_sdk::events::kinds::REALM_DESTROY as CX_REALM_DESTROY;
pub use cokret_sdk::events::kinds::REALM_TOMBSTONE as CX_REALM_TOMBSTONE;
pub use cokret_sdk::events::kinds::REALM_MODERATION_POLICY as CX_REALM_MODERATION_POLICY;
pub use cokret_sdk::events::kinds::REALM_HISTORY_VISIBILITY as CX_REALM_HISTORY_VISIBILITY;
pub use cokret_sdk::events::kinds::REALM_HISTORY_SHARING_POLICY as CX_REALM_HISTORY_SHARING_POLICY;
pub use cokret_sdk::events::kinds::REALM_PREVIEW_POLICY as CX_REALM_PREVIEW_POLICY;
pub use cokret_sdk::events::kinds::REALM_KEY_SHARE as CX_REALM_KEY_SHARE;
pub const CX_CONFLICT_REPAIR: &str = "cx.conflict.repair";
pub use cokret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT as CX_AUDIT_ERASURE_RECEIPT;
pub use cokret_sdk::events::kinds::REDACTION as CX_REDACTION;
// Round 14e+ (2026-05-16) — Applet protocol family. Spec
// `extensions/applet-integration.md`. soland's role at this layer is to
// validate wire shape + persist + dispatch; applet bridge state machine
// lives client-side (yougen) and at the applet service itself.
pub use cokret_sdk::events::kinds::APPLET_REGISTRATION as CX_APPLET_REGISTRATION;
pub use cokret_sdk::events::kinds::APPLET_DISCOVERY as CX_APPLET_DISCOVERY;
pub use cokret_sdk::events::kinds::APPLET_PROTOCOL_SESSION_START as CX_APPLET_PROTOCOL_SESSION_START;
pub use cokret_sdk::events::kinds::APPLET_PROTOCOL_SESSION_STATUS as CX_APPLET_PROTOCOL_SESSION_STATUS;
pub use cokret_sdk::events::kinds::APPLET_BRIDGE_ERROR as CX_APPLET_BRIDGE_ERROR;
// Round 14e+ (2026-05-16) — Agent protocol family. Spec
// `extensions/agent-integration.md`. Mirror of applet but with a
// terminal `*.result` event that carries the signed audit binding.
pub use cokret_sdk::events::kinds::AGENT_ENDPOINT as CX_AGENT_ENDPOINT;
pub const CX_AGENT_PROTOCOL_SESSION_START: &str = "ck.agent.protocol_session.start";
pub use cokret_sdk::events::kinds::AGENT_PROTOCOL_SESSION_STATUS as CX_AGENT_PROTOCOL_SESSION_STATUS;
pub use cokret_sdk::events::kinds::AGENT_PROTOCOL_SESSION_RESULT as CX_AGENT_PROTOCOL_SESSION_RESULT;

// R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — agent lifecycle FSM
// event kinds. `lattice` is `fsm` with `bottom=reject`; deactivate is
// terminal. Reducer enforcement of the (active → paused → active →
// deactivated) transitions lives in `reducer::apply_agent_lifecycle`
// (REDU-1).
pub use cokret_sdk::events::kinds::AGENT_PAUSE as CX_AGENT_PAUSE;
pub use cokret_sdk::events::kinds::AGENT_RESUME as CX_AGENT_RESUME;
pub use cokret_sdk::events::kinds::AGENT_DEACTIVATE as CX_AGENT_DEACTIVATE;

// R3 spec-sync — new actor_private_event kinds (reducer_input=false; do
// NOT advance the anchor frontier / actor_seq). Wire-accepted only.
pub use cokret_sdk::events::kinds::AGENT_DRAFT_PROPOSE as CX_AGENT_DRAFT_PROPOSE;
pub use cokret_sdk::events::kinds::AGENT_ACTION_REQUEST as CX_AGENT_ACTION_REQUEST;
pub use cokret_sdk::events::kinds::AGENT_ACTION_APPROVE as CX_AGENT_ACTION_APPROVE;
pub use cokret_sdk::events::kinds::AGENT_ACTION_REJECT as CX_AGENT_ACTION_REJECT;

// Round C45 (2026-05-18 main; spec 346f347) — registry refactor dropped the
// `.v1` suffix from these audit event kinds. Wire schema versioning now
// flows through `requirements.features` (e.g. `ck.feature.audit_destruction_v1`).
// `attested_hardware` Audit Agent removal MUST emit
// `ck.audit.epoch_key_destruction` in the same anchor batch as the paired
// `ck.mls.commit`. If the deadline passes without the attestation, soland
// forces a `ck.realm.audit_policy_downgrade` event that drops
// `audit_assurance` from attested_hardware to disclosed_policy and triggers
// a UI banner. Reducer-level validation lives in `src/reducer.rs` under
// `apply_audit_epoch_key_destruction` / `apply_audit_policy_downgrade`
// (still TODO stubs pending full attestation-chain verification).
pub use cokret_sdk::events::kinds::REALM_AUDIT_POLICY_DOWNGRADE as CX_REALM_AUDIT_POLICY_DOWNGRADE;

// REDU-8 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — the
// `cx.audit.epoch_destruction_failsafe` event cannot serve as a delayed
// remediation for a missing same-batch attestation. The spec wording
// (see _before_todos.md §0.4) is: the failsafe MUST NOT be accepted in
// place of the in-batch `ck.audit.epoch_key_destruction` paired with
// the audit agent remove; soland keeps the existing forced
// `ck.realm.audit_policy_downgrade` write path described above so the
// downgrade ratchet stays the only correct remediation.
// TODO(R3.1): when the failsafe kind reaches the reducer admission
// pipeline, reject it whenever the matching epoch's
// `ck.audit.epoch_key_destruction` is missing from the same batch with
// `audit_agent_destruction_proof_missing` / the canonical attested-
// hardware reason; do NOT silently accept it as remediation.

// Round C45 (2026-05-18 main) — new event kinds.
//
// `ck.identity.accountability_grant` (identity / reducer_input): issuer-signed
//   endorsement that a subject DID is accountable to the issuer for a declared
//   scope. Required to verify `Actor Profile.accountable_principal_ids[]`;
//   reducer strips unverified DIDs from accountable_principal_ids (or rejects with
//   `accountability_grant_missing`, per deployment policy). zh/models/actor.md §3.3.1.
// `ck.morph.schema_migrate` (morph / reducer_input): one-shot Morph
//   `schema_refs[]` evolution event with explicit compatibility class.
//   zh/models/morph.md §4.1 S3.
// `ck.attestation.range_completeness` (audit / non-reducer): range-bound
//   completeness attestation; backs cross-issuer fork detection.
//   zh/sync/operations-sync.md §4.2.
pub use cokret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE as CX_MORPH_SCHEMA_MIGRATE;

// Round C46 (2026-05-19; spec 0a5ab85) — Realm-scoped delivery binding
// governance + per-device push route binding.
//
// `ck.realm.delivery_binding_policy` (realm / reducer_input): Realm
//   policy constraining which `binding_source` values are admissible,
//   which recipient services are allowed, which endorsers are required,
//   whether DID Document fallback / unroutable membership are permitted,
//   and who may sign rebind. cell_family
//   `ck.component.realm.delivery_binding_policy.v1`, cas-register.
//   Governs reducer acceptance of `ck.member.state{join}`
//   delivery_binding. The reducer projects the policy cell + applies
//   binding-source / recipient-service / service-acceptance / policy-
//   frontier checks against routable joins.
//
// `ck.device.push_route` (device / actor_private_event / reducer_input):
//   per-device push route binding for the composite tuple
//   `(recipient_service_did, principal, device, push_route)`. MUST NOT be
//   replicated outside the binding's recipient_service_did context. Stored
//   as actor-private state on the recipient Principal Server only.
pub use cokret_sdk::events::kinds::REALM_DELIVERY_BINDING_POLICY as CX_REALM_DELIVERY_BINDING_POLICY;
// `ck.device.push_route` is device-scoped.
pub use cokret_sdk::events::kinds::DEVICE_PUSH_ROUTE as CX_DEVICE_PUSH_ROUTE;

// Realm graph + capability derivation event kinds. Reducer dispatch
// (`apply_realm_link` / `apply_realm_inheritance_policy` /
// `apply_capability_derived`) is fully wired in `src/reducer.rs`;
// validators and HTTP surfaces live in `src/routing/realms.rs`.
//
// `ck.realm.link` (realm / reducer_input): typed link between Realm
// boundaries. Canonical `link_kind` parsing + cycle/self-reference
// rejection runs in `reducer::realm_links::check_realm_link_admissible`
// (R3.1). The CXP-0007 P2A.4 pass lifts the previous TODO(realm-rework)
// marker: the canonical link kinds (`governed_by`, `inherits_policy_from`,
// `mirror_of`, `references`, `audited_by`) all evaluate, and the
// `/_cokret/self/realms/{realm_id}/effective-policy` surface walks the
// ancestor chain per the inheritance declaration. Outstanding
// follow-up: rich `link_kind`-specific authz constraints (TODO(P2B.x)).
pub use cokret_sdk::events::kinds::REALM_LINK as CX_REALM_LINK;
// `ck.realm.inheritance_policy` (realm / reducer_input): declares which
// realm-scoped policies a child Realm inherits from its parent boundary.
// Reducer maintains a `ck.component.realm.inheritance_policy.v1`
// cas-register cell; capability derivation runs against the projected
// chain alongside `ck.capability.derived`.
pub use cokret_sdk::events::kinds::REALM_INHERITANCE_POLICY as CX_REALM_INHERITANCE_POLICY;
// `ck.capability.derived` (capability / reducer_input): records a
// capability derived from a parent Realm's policy + a child Realm's
// inheritance declaration. Reducer projects into
// `ck.component.capability.derived.v1`; full derive logic now runs
// through the same chain as the rest of the Realm-graph family. Any
// remaining cross-Realm derivation gaps are tracked as
// TODO(circle-rollout-P2A.4): cross-Realm `allowed_circle_ids`
// derivation under audited-high-risk policies.
pub use cokret_sdk::events::kinds::CAPABILITY_DERIVED as CX_CAPABILITY_DERIVED;

// G3.S2 — `ck.realm.policy_server` (realm / reducer_input): declares the
// pluggable policy-decision service for a Realm. cell_family
// `ck.component.realm.policy_server.v1` (cas-register per SDK lattice
// registry). Spec `cokret-spec/spec/v1/zh/authz/policy-server.md` §2.
pub use cokret_sdk::events::kinds::REALM_POLICY_SERVER as CX_REALM_POLICY_SERVER;

// G3.S1 — MLS / E2EE lifecycle event kinds.
//
// Canonical kinds per
// `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json` (kind enum):
//   - `ck.mls.keypackage`    — KeyPackage publication. The publish/claim distinction lives at the
//     HTTP operation_id layer (`ck.keys.keypackages.upload` / `ck.keys.keypackages.claim`); the
//     event log stores only the canonical kind. The reducer dispatches publish-vs-claim on the
//     `payload.action == "publish" | "claim"` field.
//   - `ck.mls.welcome`       — Welcome envelope reference. Per-(recipient, device) queue semantics
//     are conveyed via payload shape; no separate `.enqueue` suffix.
//   - `ck.mls.commit`        — MLS commit (bumps the group's stored epoch by +1 from
//     `payload.expected_prev_epoch`). The "epoch" semantics live in the payload, not in the kind
//     suffix.
//   - `ck.mls.proposal`      — MLS proposal (wire-only; no reducer projection yet).
//   - `ck.mls.genesis`       — MLS group genesis (initializes epoch 0 and the covered-frontier
//     accumulator).
//   - `ck.mls.commit_failed` — diagnostic of a failed commit / Welcome processing path (wire-only;
//     no reducer projection yet).
//
// TODO(G3.S1-followup): decryption_pending — deferred-decryption queue +
// retry path for messages that arrived before the key material; today the
// recipient silently drops them.
// MLS commits now require a governance binding with an attested
// membership/covered frontier; the soland reducer accumulates that
// frontier in `MlsCommitEpoch.covered_frontier`. Welcome envelopes are
// accepted only in minimal routing form: opaque Welcome bytes plus the
// recipient delivery tuple.
pub use cokret_sdk::events::kinds::MLS_KEYPACKAGE as CX_MLS_KEYPACKAGE;
pub use cokret_sdk::events::kinds::MLS_WELCOME as CX_MLS_WELCOME;
pub use cokret_sdk::events::kinds::MLS_COMMIT as CX_MLS_COMMIT;
pub use cokret_sdk::events::kinds::MLS_GENESIS as CX_MLS_GENESIS;

pub fn validate_mls_governance_binding(payload: &Value) -> Result<(), &'static str> {
    let binding = payload
        .get("governance_binding")
        .or_else(|| payload.get("mls_governance_binding"))
        .ok_or("mls_governance_binding_missing")?;
    if binding.get("binding_version").and_then(Value::as_u64) != Some(1) {
        return Err("mls_governance_binding_version_invalid");
    }
    if binding.get("encoding_profile").and_then(Value::as_str)
        != Some("cbor-deterministic-rfc8949-v1")
    {
        return Err("mls_governance_binding_encoding_profile_invalid");
    }
    let Some(group_id) = payload
        .get("mls_group_id")
        .or_else(|| payload.get("group_id"))
        .and_then(Value::as_str)
    else {
        return Err("mls_commit_group_missing");
    };
    if binding.get("mls_group_id").and_then(Value::as_str) != Some(group_id) {
        return Err("mls_governance_binding_group_mismatch");
    }
    let expected_prev_epoch = payload
        .get("expected_prev_epoch")
        .or_else(|| payload.get("base_epoch"))
        .and_then(Value::as_u64)
        .ok_or("mls_commit_expected_prev_epoch_missing")?;
    let expected_next_epoch = payload
        .get("next_epoch")
        .and_then(Value::as_u64)
        .ok_or("mls_commit_next_epoch_missing")?;
    if expected_prev_epoch.checked_add(1) != Some(expected_next_epoch) {
        return Err("mls_governance_binding_next_epoch_mismatch");
    }
    if binding.get("previous_epoch").and_then(Value::as_u64) != Some(expected_prev_epoch) {
        return Err("mls_governance_binding_previous_epoch_mismatch");
    }
    if binding.get("next_epoch").and_then(Value::as_u64) != Some(expected_next_epoch) {
        return Err("mls_governance_binding_next_epoch_mismatch");
    }
    let Some(realm_id) = binding.get("realm_id").and_then(Value::as_str) else {
        return Err("mls_governance_binding_realm_missing");
    };
    let Some(scope) = binding.get("effective_scope").and_then(Value::as_object) else {
        return Err("mls_governance_binding_scope_missing");
    };
    if scope.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err("mls_governance_binding_scope_mismatch");
    }
    match scope.get("kind").and_then(Value::as_str) {
        Some("realm") => {
            if binding.get("circle_id").is_some() {
                return Err("mls_governance_binding_scope_mismatch");
            }
        }
        Some("circle") => {
            let Some(circle_id) = scope.get("circle_id").and_then(Value::as_str) else {
                return Err("mls_governance_binding_scope_mismatch");
            };
            if binding.get("circle_id").and_then(Value::as_str) != Some(circle_id) {
                return Err("mls_governance_binding_scope_mismatch");
            }
        }
        _ => return Err("mls_governance_binding_scope_missing"),
    }
    let Some(frontier) = binding.get("membership_frontier").and_then(Value::as_array) else {
        return Err("mls_governance_binding_membership_frontier_missing");
    };
    if frontier.is_empty()
        || frontier
            .iter()
            .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err("mls_governance_binding_membership_frontier_missing");
    }
    if binding
        .get("policy_root")
        .and_then(Value::as_str)
        .is_none_or(|value| !value.starts_with("sha256:"))
    {
        return Err("mls_governance_binding_policy_root_missing");
    }
    Ok(())
}

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
    if !artifacts::active_local_operation_event_kinds().contains(object_type)
        && object_type != CX_CONFLICT_REPAIR
    {
        return None;
    }
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
        CX_SPACE_CONTAINER_CREATE => Some(CX_SPACE_CONTAINER_CREATE),
        CX_SPACE_CONTAINER_UPDATE => Some(CX_SPACE_CONTAINER_UPDATE),
        CX_SPACE_CONTAINER_PARENT => Some(CX_SPACE_CONTAINER_PARENT),
        CX_SPACE_CONTAINER_ARCHIVE => Some(CX_SPACE_CONTAINER_ARCHIVE),
        CX_SPACE_CONTAINER_RESTORE => Some(CX_SPACE_CONTAINER_RESTORE),
        CX_SPACE_CONTAINER_TOMBSTONE => Some(CX_SPACE_CONTAINER_TOMBSTONE),
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
        CX_INVITE_CREATE => Some(CX_INVITE_CREATE),
        CX_READ_MARKER => Some(CX_READ_MARKER),
        CX_REALM_CREATE | CX_REALM_UPDATE | CX_REALM_DESTROY | CX_REALM_TOMBSTONE => {
            Some(match object_type {
                CX_REALM_CREATE => CX_REALM_CREATE,
                CX_REALM_DESTROY => CX_REALM_DESTROY,
                CX_REALM_TOMBSTONE => CX_REALM_TOMBSTONE,
                _ => CX_REALM_UPDATE,
            })
        }
        CX_REALM_MODERATION_POLICY => Some(CX_REALM_MODERATION_POLICY),
        CX_REALM_HISTORY_VISIBILITY => Some(CX_REALM_HISTORY_VISIBILITY),
        CX_REALM_HISTORY_SHARING_POLICY => Some(CX_REALM_HISTORY_SHARING_POLICY),
        CX_REALM_PREVIEW_POLICY => Some(CX_REALM_PREVIEW_POLICY),
        CX_REALM_KEY_SHARE => Some(CX_REALM_KEY_SHARE),
        CX_CONFLICT_REPAIR => Some(CX_CONFLICT_REPAIR),
        CX_AUDIT_ERASURE_RECEIPT => Some(CX_AUDIT_ERASURE_RECEIPT),
        CX_MEMBER_STATE => Some(CX_MEMBER_STATE),
        // R3.1 — MemberIdentity append-only replacement event.
        CX_MEMBER_IDENTITY_UPDATE => Some(CX_MEMBER_IDENTITY_UPDATE),
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
        // R3 spec-sync — agent lifecycle (FSM, reducer_input=true).
        CX_AGENT_PAUSE => Some(CX_AGENT_PAUSE),
        CX_AGENT_RESUME => Some(CX_AGENT_RESUME),
        CX_AGENT_DEACTIVATE => Some(CX_AGENT_DEACTIVATE),
        // R3 spec-sync — actor_private_event kinds (reducer_input=false).
        CX_AGENT_DRAFT_PROPOSE => Some(CX_AGENT_DRAFT_PROPOSE),
        CX_AGENT_ACTION_REQUEST => Some(CX_AGENT_ACTION_REQUEST),
        CX_AGENT_ACTION_APPROVE => Some(CX_AGENT_ACTION_APPROVE),
        CX_AGENT_ACTION_REJECT => Some(CX_AGENT_ACTION_REJECT),
        // Tier-0 S6 audit kinds (C44 wire-valid, C45 renamed off `.v1`).
        // Projection is currently `Ignored` pending full attestation-chain
        // verification.
        CX_REALM_AUDIT_POLICY_DOWNGRADE => Some(CX_REALM_AUDIT_POLICY_DOWNGRADE),
        // Round C45 — new event kinds. Wire-valid; reducer dispatch is TODO
        // (morph.schema_migrate enforces capability + compatibility_class gate).
        CX_MORPH_SCHEMA_MIGRATE => Some(CX_MORPH_SCHEMA_MIGRATE),
        // Round C46 — delivery binding governance + push route binding.
        // Wire-valid; reducer projection is TODO pending full policy /
        // push registration plumbing.
        CX_REALM_DELIVERY_BINDING_POLICY => Some(CX_REALM_DELIVERY_BINDING_POLICY),
        CX_DEVICE_PUSH_ROUTE => Some(CX_DEVICE_PUSH_ROUTE),
        // Realm graph — schema-level accept; reducer projection is
        // TODO(realm-rework) for link_kind / inheritance / capability
        // derive semantics.
        CX_REALM_LINK => Some(CX_REALM_LINK),
        CX_REALM_INHERITANCE_POLICY => Some(CX_REALM_INHERITANCE_POLICY),
        CX_CAPABILITY_DERIVED => Some(CX_CAPABILITY_DERIVED),
        // G3.S2 — policy server declaration.
        CX_REALM_POLICY_SERVER => Some(CX_REALM_POLICY_SERVER),
        _ => Some(object_type),
    }
}

/// True for any `cx.audit.*` event kind. Used by the Realm terminal-state
/// admission guard (`routing::events::event_log::terminal_realm_check`) to
/// admit audit-class
/// writes even after a Realm has reached `ck.realm.tombstone` /
/// `ck.realm.destroy` terminal state. Spec
/// `cokret-spec/spec/v1/zh/models/realm-and-space.md` §2.5.1.
pub fn is_audit_kind(kind: &str) -> bool {
    kind.starts_with("cx.audit.")
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
            | CX_AGENT_PAUSE
            | CX_AGENT_RESUME
            | CX_AGENT_DEACTIVATE
            | CX_AGENT_DRAFT_PROPOSE
            | CX_AGENT_ACTION_REQUEST
            | CX_AGENT_ACTION_APPROVE
            | CX_AGENT_ACTION_REJECT
    )
}

/// R3 spec-sync (2026-05-27) — FSM-lattice agent lifecycle kinds.
pub fn is_agent_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_AGENT_PAUSE | CX_AGENT_RESUME | CX_AGENT_DEACTIVATE)
}

/// R3 spec-sync — `actor_private_event` kinds (reducer_input=false).
/// These MUST NOT advance the anchor frontier / actor_seq; the reducer
/// dispatches them through the audit-log projection only.
pub fn is_actor_private_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_AGENT_DRAFT_PROPOSE
            | CX_AGENT_ACTION_REQUEST
            | CX_AGENT_ACTION_APPROVE
            | CX_AGENT_ACTION_REJECT
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

pub fn operation_is_invite(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_invite_kind)
}

pub fn operation_is_invite_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CX_INVITE_CREATE)
}

pub fn operation_is_realm_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_realm_lifecycle_kind)
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, CX_MESSAGE_REDACT | CX_REDACTION | "redaction")
}

pub fn is_membership_kind(kind: &str) -> bool {
    matches!(kind, CX_MEMBER_STATE | CX_MEMBER_IDENTITY_UPDATE)
}

pub fn is_invite_kind(kind: &str) -> bool {
    matches!(kind, CX_INVITE_CREATE | "ck.invite.accept" | "ck.invite.cancel")
}

pub fn is_realm_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_REALM_CREATE | CX_REALM_UPDATE | CX_REALM_DESTROY | CX_REALM_TOMBSTONE
    )
}

pub fn is_space_container_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_SPACE_CONTAINER_ARCHIVE | CX_SPACE_CONTAINER_RESTORE | CX_SPACE_CONTAINER_TOMBSTONE
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

// G3.S9: extensions (applet/bot/tsp) — stub event kinds. Wire-accept +
// reducer no-op projection (we keep the structured caches in
// `routing::extensions::{bot_actor, tsp}`). Full state-machine semantics
// land with the protocol implementations themselves; the constants are
// here so the reducer registry can dispatch.
//
// Spec anchors:
//   - `extensions/applet-integration.md` §3–§5 (bot / ghost actor accountability model)
//   - `identity/tsp-integration.md` §3–§5 (transport declaration, route, audit chain)
pub const CX_EXTENSIONS_BOT_REGISTER: &str = "cx.extensions.bot_actor.register";
pub const CX_EXTENSIONS_BOT_REVOKE: &str = "cx.extensions.bot_actor.revoke";
pub const CX_EXTENSIONS_TSP_TRANSPORT_DECLARE: &str = "cx.extensions.tsp.transport_declare";
pub const CX_EXTENSIONS_TSP_ROUTE_ESTABLISH: &str = "cx.extensions.tsp.route_establish";
pub const CX_EXTENSIONS_TSP_AUDIT_APPEND: &str = "cx.extensions.tsp.audit_append";

// ────────────────────────────────────────────────────────────────────────
// Audit-compliance profiles + Realm terminal-state classifier (spec T07/T09/T23).
// ────────────────────────────────────────────────────────────────────────

/// Active audit-compliance profile ids. Spec T09.
pub const AUDIT_COMPLIANCE_PROFILES: &[&str] = &[
    "ck.profile.attested_audit.e2ee.v1",
    "ck.profile.disclosed_audit.e2ee.v1",
];

/// Spec T07 — Realm lifecycle state classifier; mirror of the SDK
/// [`cokret_sdk::events::RealmLifecycleState`] terminal predicate.
pub fn realm_state_is_terminal(state: cokret_sdk::events::RealmLifecycleState) -> bool {
    cokret_sdk::events::is_terminal_realm_state(state)
}

/// Spec T23 — true when `ck.audit.ryw_receipt` may be accepted as a durable
/// Event. Requires `ck.profile.attested_audit.e2ee.v1` to be in the Realm's
/// active profile set.
pub fn ryw_receipt_durable_event_allowed(active_profiles: &[String]) -> bool {
    active_profiles
        .iter()
        .any(|p| p == "ck.profile.attested_audit.e2ee.v1")
}

#[cfg(test)]
mod audit_profile_tests {
    use super::*;

    #[test]
    fn ryw_receipt_durable_only_under_attested_profile() {
        assert!(!ryw_receipt_durable_event_allowed(&[]));
        assert!(ryw_receipt_durable_event_allowed(&[
            "ck.profile.attested_audit.e2ee.v1".to_owned()
        ]));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn mls_governance_binding_requires_current_wire_shape() {
        let payload = json!({
            "mls_group_id": "mls-group-a",
            "base_epoch": 7,
            "next_epoch": 8,
            "governance_binding": {
                "binding_version": 1,
                "encoding_profile": "cbor-deterministic-rfc8949-v1",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000"
                },
                "mls_group_id": "mls-group-a",
                "previous_epoch": 7,
                "next_epoch": 8,
                "membership_frontier": ["ck:event:0196419b-0000-7000-8000-000000000001"],
                "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            }
        });

        validate_mls_governance_binding(&payload).unwrap();
    }

    #[test]
    fn mls_governance_binding_rejects_epoch_or_scope_mismatch() {
        let stale = json!({
            "mls_group_id": "mls-group-a",
            "base_epoch": 7,
            "next_epoch": 8,
            "governance_binding": {
                "binding_version": 1,
                "encoding_profile": "cbor-deterministic-rfc8949-v1",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000"
                },
                "mls_group_id": "mls-group-a",
                "previous_epoch": 6,
                "next_epoch": 8,
                "membership_frontier": ["ck:event:0196419b-0000-7000-8000-000000000001"],
                "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            }
        });
        assert_eq!(
            validate_mls_governance_binding(&stale),
            Err("mls_governance_binding_previous_epoch_mismatch")
        );

        let scope_mismatch = json!({
            "mls_group_id": "mls-group-a",
            "base_epoch": 7,
            "next_epoch": 8,
            "governance_binding": {
                "binding_version": 1,
                "encoding_profile": "cbor-deterministic-rfc8949-v1",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000999"
                },
                "mls_group_id": "mls-group-a",
                "previous_epoch": 7,
                "next_epoch": 8,
                "membership_frontier": ["ck:event:0196419b-0000-7000-8000-000000000001"],
                "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            }
        });
        assert_eq!(
            validate_mls_governance_binding(&scope_mismatch),
            Err("mls_governance_binding_scope_mismatch")
        );
    }
}
