use cokret_sdk::Operation;
// CKP-0007 (spec b7d35be) — Circle lifecycle / membership events. Seven
// active durable kinds registered in
// `spec/v1/artifacts/registry/event-kind-registry.json`. The reducer
// dispatch is wired in `src/reducer.rs`; the wire-layer admission check
// runs through the generic local-operation event registry.
//
// `ck.circle.seal_commit` is reducer-DERIVED (sub-seal emitted on
// the Circle's profile cadence) and MUST NOT be submitted directly via
// `ck.self.events.command.submit`. The SDK gates this in
// `kinds::is_reducer_input_event_kind`.
pub use cokret_sdk::events::kinds::CIRCLE_CREATE as CK_CIRCLE_CREATE;
// Flow lifecycle (round 13 — Flow projection state machine). spec
// `common-fields.md §5.1` Flow row: active / archived / redacted / deleted.
// Flow has no dedicated `ck.flow.tombstone` event (terminal state reached
// via `ck.redaction`); only archive/restore are state-machine transitions
// here.
pub use cokret_sdk::events::kinds::FLOW_CREATE as CK_FLOW_CREATE;
// Round 14 — Flow position events. Not state-machine transitions; they
// write to the `ck.component.flow.position.v1` cell family keyed by
// (board_space_id, flow_id). The Event-Envelope path only validates
// payload shape and bumps the Flow's updated_at/by; the cell write
// happens on the Move/Seal pipeline (out of scope for the reducer's
// structured cache).
pub use cokret_sdk::events::kinds::FLOW_MOVE as CK_FLOW_MOVE;
// Unified Flow tracks update event. `payload.patch` uses `ck.patch.v1`
// against the `Flow.tracks` map; atomic across multiple tracks. soland's
// wire validator enforces payload shape (flow_id + patch | tracks) and
// the spec common-fields.md §5.1 update-on-non-active state guard.
// FlowProjection doesn't carry `tracks` server-side; the touch just
// bumps `updated_at` (mirror of ck.flow.move/reorder pattern).
pub use cokret_sdk::events::kinds::FLOW_TRACKS_UPDATE as CK_FLOW_TRACKS_UPDATE;
// Round 16 — Flow watch subscription event. Writes the
// `ck.component.flow.watch.v1` cas-register cell keyed by
// (flow_id, watcher_actor_id). Spec:
// cokret-spec/spec/v1/zh/models/flow-and-message.md §8. Like the
// flow position events the Event-Envelope path only validates payload
// shape; cell write happens on the Move/Seal pipeline. The Flow
// projection's updated_at is NOT bumped — watch is a per-(flow, actor)
// subscription that does not represent a Flow state mutation.
pub use cokret_sdk::events::kinds::FLOW_WATCH_SET as CK_FLOW_WATCH_SET;
// Space-container lifecycle (`ck.space.*`). Spec
// `cokret-spec/spec/v1/zh/models/realm-and-space.md` — the v1 protocol
// container, distinct from the `ck.realm.*` security boundary below.
pub use cokret_sdk::events::kinds::SPACE_CREATE as CK_SPACE_CONTAINER_CREATE;
pub use cokret_sdk::events::kinds::{
    CIRCLE_ARCHIVE as CK_CIRCLE_ARCHIVE, CIRCLE_MEMBER_STATE as CK_CIRCLE_MEMBER_STATE,
    CIRCLE_RESTORE as CK_CIRCLE_RESTORE, CIRCLE_TOMBSTONE as CK_CIRCLE_TOMBSTONE,
    CIRCLE_UPDATE as CK_CIRCLE_UPDATE, FLOW_ARCHIVE as CK_FLOW_ARCHIVE,
    FLOW_REORDER as CK_FLOW_REORDER, FLOW_RESTORE as CK_FLOW_RESTORE,
    FLOW_UPDATE as CK_FLOW_UPDATE, MESSAGE_CREATE as CK_MESSAGE_CREATE,
    MESSAGE_REDACT as CK_MESSAGE_REDACT, MESSAGE_REVISE as CK_MESSAGE_REVISE,
    PIN_ADD as CK_PIN_ADD, PIN_REMOVE as CK_PIN_REMOVE, PIN_REORDER as CK_PIN_REORDER,
    REACTION_ADD as CK_REACTION_ADD, REACTION_REMOVE as CK_REACTION_REMOVE,
    RELATION_CREATE as CK_RELATION_CREATE, RELATION_TOMBSTONE as CK_RELATION_DELETE,
    RELATION_UPDATE as CK_RELATION_UPDATE, RSVP_SET as CK_RSVP_SET,
    SPACE_ARCHIVE as CK_SPACE_CONTAINER_ARCHIVE, SPACE_PARENT as CK_SPACE_CONTAINER_PARENT,
    SPACE_RESTORE as CK_SPACE_CONTAINER_RESTORE, SPACE_TOMBSTONE as CK_SPACE_CONTAINER_TOMBSTONE,
    SPACE_UPDATE as CK_SPACE_CONTAINER_UPDATE, VIEW_CREATE as CK_VIEW_CREATE,
    VIEW_RECONCILE as CK_VIEW_RECONCILE, VIEW_UPDATE as CK_VIEW_UPDATE,
};
use serde_json::Value;

use crate::artifacts;

// CKP-0007 — typed Relation kind couples a "wide synthesis" Flow (often
// Realm-default scope) to a "narrow discussion" Flow bound to a
// `scope_circle_id` Circle. Stored on `ck.relation.create` /
// `ck.relation.update` payloads as `relation_kind`. Spec
// `zh/models/circle.md` §7.2.
pub const RELATION_KIND_CONFIDENTIAL_DISCUSSION_OF: &str = "confidential_discussion_of";

// Morph lifecycle (round 13). Same shape as Flow — no dedicated tombstone.
// `ck.field.position.move` and `ck.field.position.reorder` were removed in
// revision 0a5ab85 (see cokret-spec
// `artifacts/registry/removed-event-kinds.json`). Field-level position move
// was subsumed by track-relative ordering and the per-cell ordered-log
// lattice. No replacement; reducer/wire MUST hard_reject these kinds. The
// generic unknown-event-kind path in `event_log::submit_event` already
// rejects them because they no longer appear in `active_durable_event_kinds`.
// R3.1 spec-sync (2026-05-27, cokret-spec @ 7157ee8) — Realm-scoped
// MemberIdentity append-only replacement event. Cell family
// `ck.component.member.identity.v1`; lattice `ordered_log`; bottom
// `expose`. Composite cell subject is
// `(payload.realm_id, payload.actor_id, payload.segment)`. Reducer
// dispatch lives in `reducer::apply_member_identity_update`; persistence
// is in `state::MemberIdentityRegistry`.
// Realm security-boundary lifecycle (`ck.realm.*`). Spec
// `cokret-spec/spec/v1/zh/models/realm-and-space.md` §1 + §4.
//
// `ck.realm.tombstone` is the irreversible terminal-state event that
// freezes the Realm and triggers the erasure-receipt fanout chain via
// `ck.audit.erasure_receipt`. Distinct from `ck.realm.destroy`, which
// is the GDPR-grade hard-delete request that retains a `retained_stub_digest`.
pub use cokret_sdk::events::kinds::{
    CONTAINER_MOVE_ITEM as CK_CONTAINER_MOVE_ITEM, CONTAINER_REBALANCE as CK_CONTAINER_REBALANCE,
    INVITE_CREATE as CK_INVITE_CREATE, MEMBER_IDENTITY_UPDATE as CK_MEMBER_IDENTITY_UPDATE,
    MEMBER_STATE as CK_MEMBER_STATE, MORPH_ARCHIVE as CK_MORPH_ARCHIVE,
    MORPH_CREATE as CK_MORPH_CREATE, MORPH_RESTORE as CK_MORPH_RESTORE,
    MORPH_UPDATE as CK_MORPH_UPDATE, READ_CURSOR_ADVANCE as CK_READ_MARKER,
    REALM_ARCHIVE as CK_REALM_ARCHIVE, REALM_CREATE as CK_REALM_CREATE,
    REALM_DESTROY as CK_REALM_DESTROY, REALM_DISAPPEARING_POLICY as CK_REALM_DISAPPEARING_POLICY,
    REALM_HISTORY_SHARING_POLICY as CK_REALM_HISTORY_SHARING_POLICY,
    REALM_HISTORY_VISIBILITY as CK_REALM_HISTORY_VISIBILITY, REALM_KEY_SHARE as CK_REALM_KEY_SHARE,
    REALM_MODERATION_POLICY as CK_REALM_MODERATION_POLICY,
    REALM_POLICY_COMPONENTS as CK_REALM_POLICY_COMPONENTS,
    REALM_PREVIEW_POLICY as CK_REALM_PREVIEW_POLICY, REALM_SEARCH_POLICY as CK_REALM_SEARCH_POLICY,
    REALM_TOMBSTONE as CK_REALM_TOMBSTONE, REALM_UPDATE as CK_REALM_UPDATE,
};
pub const CK_CONFLICT_REPAIR: &str = "ck.conflict.repair";
pub const CK_ACCOUNT_DATA_SET: &str = "ck.account_data.set";
// Round 14e+ (2026-05-16) — Agent protocol family. Spec
// `extensions/agent-integration.md`. Mirror of applet but with a
// terminal `*.result` event that carries the signed audit binding.
// Round 14e+ (2026-05-16) — Applet protocol family. Spec
// `extensions/applet-integration.md`. soland's role at this layer is to
// validate wire shape + persist + dispatch; applet bridge state machine
// lives client-side (yougen) and at the applet service itself.
pub use cokret_sdk::events::kinds::{
    AGENT_ENDPOINT as CK_AGENT_ENDPOINT, APPLET_BRIDGE_ERROR as CK_APPLET_BRIDGE_ERROR,
    APPLET_DISCOVERY as CK_APPLET_DISCOVERY,
    APPLET_INTEROP_SESSION_START as CK_APPLET_INTEROP_SESSION_START,
    APPLET_INTEROP_SESSION_STATUS as CK_APPLET_INTEROP_SESSION_STATUS,
    APPLET_REGISTRATION as CK_APPLET_REGISTRATION,
    AUDIT_ERASURE_RECEIPT as CK_AUDIT_ERASURE_RECEIPT, REDACTION as CK_REDACTION,
};
pub const CK_AGENT_INTEROP_SESSION_START: &str = "ck.agent.interop_session.start";
// R3 spec-sync — new actor_private_event kinds (reducer_input=false; do
// NOT advance the seal frontier / actor_seq). Wire-accepted only.
// R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — agent lifecycle FSM
// event kinds. `lattice` is `fsm` with `bottom=reject`; deactivate is
// terminal. Reducer enforcement of the (active → paused → active →
// deactivated) transitions lives in `reducer::apply_agent_lifecycle`
// (REDU-1).
// `ck.capability.derived` (capability / reducer_input): records a
// capability derived from a parent Realm's policy + a child Realm's
// inheritance declaration. Reducer projects into
// `ck.component.capability.derived.v1`; full derive logic now runs
// through the same chain as the rest of the Realm-graph family. Any
// remaining cross-Realm derivation gaps are tracked as
// TODO(circle-rollout-P2A.4): cross-Realm `allowed_circle_ids`
// derivation under audited-high-risk policies.
// `ck.device.push_route` is device-scoped.
// G3.S1 — MLS / E2EE lifecycle event kinds.
//
// Canonical kinds per
// `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json` (kind enum):
//   - `ck.mls.keypackage`    — KeyPackage publication. The publish/claim distinction lives at the
//     HTTP operation_id layer (`ck.self.keys.keypackages.upload.create` /
//     `ck.self.keys.keypackages.command.claim`); the event log stores only the canonical kind. The
//     reducer dispatches publish-vs-claim on the `payload.action == "publish" | "claim"` field.
//   - `ck.mls.welcome`       — Welcome envelope reference. Per-(recipient, device) queue semantics
//     are conveyed via payload shape; no separate `.enqueue` suffix.
//   - `ck.mls.commit`        — MLS commit (bumps the group's stored epoch by +1 from
//     `payload.expected_prev_epoch`). The "epoch" semantics live in the payload, not in the kind
//     suffix.
//   - `ck.mls.proposal`      — MLS proposal (wire-only; no reducer projection yet).
//   - `ck.mls.genesis`       — MLS group genesis (initializes epoch 0 and the covered_seals
//     accumulator).
//   - `ck.mls.commit_failed` — diagnostic of a failed commit / Welcome processing path (wire-only;
//     no reducer projection yet).
//
// TODO(G3.S1-followup): decryption_pending — deferred-decryption queue +
// retry path for messages that arrived before the key material; today the
// recipient silently drops them.
// MLS commits now require a governance binding with an attested
// membership / covered_seals evidence; the soland reducer accumulates that
// frontier in `MlsCommitEpoch.covered_seals`. Welcome envelopes are
// accepted only in minimal routing form: opaque Welcome bytes plus the
// recipient delivery tuple.
// Audit model migration (spec @ 2026-06-04): the standing-audit-member
// events `ck.audit.epoch_key_destruction` and `ck.realm.audit_policy_downgrade`
// (and the `ck.audit.epoch_destruction_failsafe` remediation) were removed
// from the registry. Cokret v1 audit now uses the Audit Applet Binding +
// sealed historical release session model (`ck.audit.applet_binding`,
// `ck.audit.session.*`, `ck.audit.release`); audit applets are not MLS members
// and no epoch-key-destruction / downgrade event is accepted.

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
// `ck.realm.inheritance_policy` (realm / reducer_input): declares which
// realm-scoped policies a child Realm inherits from its parent boundary.
// Reducer maintains a `ck.component.realm.inheritance_policy.v1`
// cas-register cell; capability derivation runs against the projected
// chain alongside `ck.capability.derived`.
// Realm graph + capability derivation event kinds. Reducer dispatch
// (`apply_realm_link` / `apply_realm_inheritance_policy` /
// `apply_capability_derived`) is fully wired in `src/reducer.rs`;
// validators and HTTP surfaces live in `src/routing/realms.rs`.
//
// `ck.realm.link` (realm / reducer_input): typed link between Realm
// boundaries. Canonical `link_kind` parsing + cycle/self-reference
// rejection runs in `reducer::realm_links::check_realm_link_admissible`
// (R3.1). The canonical link kinds (`governed_by`, `inherits_policy_from`,
// `mirror_of`, `references`, `audited_by`) all evaluate, and the
// `/_soland/self/realms/{realm_id}/effective-policy` surface walks the
// ancestor chain per the inheritance declaration. Outstanding
// follow-up: rich `link_kind`-specific authz constraints (TODO(P2B.x)).
// G3.S2 — `ck.realm.policy_server` (realm / reducer_input): declares the
// pluggable policy-decision service for a Realm. cell_family
// `ck.component.realm.policy_server.v1` (cas-register per SDK lattice
// registry). Spec `cokret-spec/spec/v1/zh/authz/policy-server.md` §2.
pub use cokret_sdk::events::kinds::{
    AGENT_ACTION_APPROVE as CK_AGENT_ACTION_APPROVE, AGENT_ACTION_REJECT as CK_AGENT_ACTION_REJECT,
    AGENT_ACTION_REQUEST as CK_AGENT_ACTION_REQUEST, AGENT_DEACTIVATE as CK_AGENT_DEACTIVATE,
    AGENT_DRAFT_PROPOSE as CK_AGENT_DRAFT_PROPOSE,
    AGENT_INTEROP_SESSION_RESULT as CK_AGENT_INTEROP_SESSION_RESULT,
    AGENT_INTEROP_SESSION_STATUS as CK_AGENT_INTEROP_SESSION_STATUS, AGENT_PAUSE as CK_AGENT_PAUSE,
    AGENT_RESUME as CK_AGENT_RESUME, CAPABILITY_DERIVED as CK_CAPABILITY_DERIVED,
    DEVICE_PUSH_ROUTE as CK_DEVICE_PUSH_ROUTE, MLS_COMMIT as CK_MLS_COMMIT,
    MLS_GENESIS as CK_MLS_GENESIS, MLS_KEYPACKAGE as CK_MLS_KEYPACKAGE,
    MLS_WELCOME as CK_MLS_WELCOME, MORPH_SCHEMA_MIGRATE as CK_MORPH_SCHEMA_MIGRATE,
    REALM_DELIVERY_BINDING_POLICY as CK_REALM_DELIVERY_BINDING_POLICY,
    REALM_INHERITANCE_POLICY as CK_REALM_INHERITANCE_POLICY, REALM_LINK as CK_REALM_LINK,
    REALM_POLICY_SERVER as CK_REALM_POLICY_SERVER,
};

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
        && object_type != CK_CONFLICT_REPAIR
    {
        return None;
    }
    match object_type {
        CK_MESSAGE_CREATE => Some(CK_MESSAGE_CREATE),
        CK_MESSAGE_REVISE => Some(CK_MESSAGE_REVISE),
        CK_MESSAGE_REDACT => Some(CK_MESSAGE_REDACT),
        CK_REDACTION => Some(CK_REDACTION),
        CK_REACTION_ADD => Some(CK_REACTION_ADD),
        CK_REACTION_REMOVE => Some(CK_REACTION_REMOVE),
        CK_RELATION_CREATE => Some(CK_RELATION_CREATE),
        CK_RELATION_UPDATE => Some(CK_RELATION_UPDATE),
        CK_RELATION_DELETE => Some(CK_RELATION_DELETE),
        CK_VIEW_CREATE => Some(CK_VIEW_CREATE),
        CK_VIEW_UPDATE => Some(CK_VIEW_UPDATE),
        CK_VIEW_RECONCILE => Some(CK_VIEW_RECONCILE),
        CK_SPACE_CONTAINER_CREATE => Some(CK_SPACE_CONTAINER_CREATE),
        CK_SPACE_CONTAINER_UPDATE => Some(CK_SPACE_CONTAINER_UPDATE),
        CK_SPACE_CONTAINER_PARENT => Some(CK_SPACE_CONTAINER_PARENT),
        CK_SPACE_CONTAINER_ARCHIVE => Some(CK_SPACE_CONTAINER_ARCHIVE),
        CK_SPACE_CONTAINER_RESTORE => Some(CK_SPACE_CONTAINER_RESTORE),
        CK_SPACE_CONTAINER_TOMBSTONE => Some(CK_SPACE_CONTAINER_TOMBSTONE),
        CK_FLOW_CREATE => Some(CK_FLOW_CREATE),
        CK_FLOW_UPDATE => Some(CK_FLOW_UPDATE),
        CK_FLOW_ARCHIVE => Some(CK_FLOW_ARCHIVE),
        CK_FLOW_RESTORE => Some(CK_FLOW_RESTORE),
        CK_FLOW_MOVE => Some(CK_FLOW_MOVE),
        CK_FLOW_REORDER => Some(CK_FLOW_REORDER),
        CK_FLOW_WATCH_SET => Some(CK_FLOW_WATCH_SET),
        CK_FLOW_TRACKS_UPDATE => Some(CK_FLOW_TRACKS_UPDATE),
        CK_MORPH_CREATE => Some(CK_MORPH_CREATE),
        CK_MORPH_UPDATE => Some(CK_MORPH_UPDATE),
        CK_MORPH_ARCHIVE => Some(CK_MORPH_ARCHIVE),
        CK_MORPH_RESTORE => Some(CK_MORPH_RESTORE),
        CK_CONTAINER_MOVE_ITEM => Some(CK_CONTAINER_MOVE_ITEM),
        CK_CONTAINER_REBALANCE => Some(CK_CONTAINER_REBALANCE),
        CK_INVITE_CREATE => Some(CK_INVITE_CREATE),
        CK_READ_MARKER => Some(CK_READ_MARKER),
        CK_REALM_CREATE | CK_REALM_UPDATE | CK_REALM_ARCHIVE | CK_REALM_DESTROY
        | CK_REALM_TOMBSTONE => Some(match object_type {
            CK_REALM_CREATE => CK_REALM_CREATE,
            CK_REALM_ARCHIVE => CK_REALM_ARCHIVE,
            CK_REALM_DESTROY => CK_REALM_DESTROY,
            CK_REALM_TOMBSTONE => CK_REALM_TOMBSTONE,
            _ => CK_REALM_UPDATE,
        }),
        CK_REALM_MODERATION_POLICY => Some(CK_REALM_MODERATION_POLICY),
        CK_REALM_DISAPPEARING_POLICY => Some(CK_REALM_DISAPPEARING_POLICY),
        CK_REALM_HISTORY_VISIBILITY => Some(CK_REALM_HISTORY_VISIBILITY),
        CK_REALM_HISTORY_SHARING_POLICY => Some(CK_REALM_HISTORY_SHARING_POLICY),
        CK_REALM_POLICY_COMPONENTS => Some(CK_REALM_POLICY_COMPONENTS),
        CK_REALM_PREVIEW_POLICY => Some(CK_REALM_PREVIEW_POLICY),
        CK_REALM_SEARCH_POLICY => Some(CK_REALM_SEARCH_POLICY),
        CK_REALM_KEY_SHARE => Some(CK_REALM_KEY_SHARE),
        CK_RSVP_SET => Some(CK_RSVP_SET),
        CK_PIN_ADD => Some(CK_PIN_ADD),
        CK_PIN_REMOVE => Some(CK_PIN_REMOVE),
        CK_PIN_REORDER => Some(CK_PIN_REORDER),
        CK_CONFLICT_REPAIR => Some(CK_CONFLICT_REPAIR),
        CK_AUDIT_ERASURE_RECEIPT => Some(CK_AUDIT_ERASURE_RECEIPT),
        CK_MEMBER_STATE => Some(CK_MEMBER_STATE),
        // R3.1 — MemberIdentity append-only replacement event.
        CK_MEMBER_IDENTITY_UPDATE => Some(CK_MEMBER_IDENTITY_UPDATE),
        // Applet protocol family (round 14e+).
        CK_APPLET_REGISTRATION => Some(CK_APPLET_REGISTRATION),
        CK_APPLET_DISCOVERY => Some(CK_APPLET_DISCOVERY),
        CK_APPLET_INTEROP_SESSION_START => Some(CK_APPLET_INTEROP_SESSION_START),
        CK_APPLET_INTEROP_SESSION_STATUS => Some(CK_APPLET_INTEROP_SESSION_STATUS),
        CK_APPLET_BRIDGE_ERROR => Some(CK_APPLET_BRIDGE_ERROR),
        // Agent protocol family (round 14e+).
        CK_AGENT_ENDPOINT => Some(CK_AGENT_ENDPOINT),
        CK_AGENT_INTEROP_SESSION_START => Some(CK_AGENT_INTEROP_SESSION_START),
        CK_AGENT_INTEROP_SESSION_STATUS => Some(CK_AGENT_INTEROP_SESSION_STATUS),
        CK_AGENT_INTEROP_SESSION_RESULT => Some(CK_AGENT_INTEROP_SESSION_RESULT),
        // R3 spec-sync — agent lifecycle (FSM, reducer_input=true).
        CK_AGENT_PAUSE => Some(CK_AGENT_PAUSE),
        CK_AGENT_RESUME => Some(CK_AGENT_RESUME),
        CK_AGENT_DEACTIVATE => Some(CK_AGENT_DEACTIVATE),
        // R3 spec-sync — actor_private_event kinds (reducer_input=false).
        CK_AGENT_DRAFT_PROPOSE => Some(CK_AGENT_DRAFT_PROPOSE),
        CK_AGENT_ACTION_REQUEST => Some(CK_AGENT_ACTION_REQUEST),
        CK_AGENT_ACTION_APPROVE => Some(CK_AGENT_ACTION_APPROVE),
        CK_AGENT_ACTION_REJECT => Some(CK_AGENT_ACTION_REJECT),
        // Round C45 — new event kinds. Wire-valid; reducer dispatch is TODO
        // (morph.schema_migrate enforces capability + compatibility_class gate).
        CK_MORPH_SCHEMA_MIGRATE => Some(CK_MORPH_SCHEMA_MIGRATE),
        // Round C46 — delivery binding governance + push route binding.
        // Wire-valid; reducer projection is TODO pending full policy /
        // push registration plumbing.
        CK_REALM_DELIVERY_BINDING_POLICY => Some(CK_REALM_DELIVERY_BINDING_POLICY),
        CK_DEVICE_PUSH_ROUTE => Some(CK_DEVICE_PUSH_ROUTE),
        // Realm graph — schema-level accept; reducer projection handles
        // link_kind / inheritance / capability derive semantics.
        CK_REALM_LINK => Some(CK_REALM_LINK),
        CK_REALM_INHERITANCE_POLICY => Some(CK_REALM_INHERITANCE_POLICY),
        CK_CAPABILITY_DERIVED => Some(CK_CAPABILITY_DERIVED),
        // G3.S2 — policy server declaration.
        CK_REALM_POLICY_SERVER => Some(CK_REALM_POLICY_SERVER),
        _ => Some(object_type),
    }
}

/// True for any `ck.audit.*` event kind. Used by the Realm terminal-state
/// admission guard (`routing::events::event_log::terminal_realm_check`) to
/// admit audit-class
/// writes even after a Realm has reached `ck.realm.tombstone` /
/// `ck.realm.destroy` terminal state. Spec
/// `cokret-spec/spec/v1/zh/models/realm-and-space.md` §2.5.1.
pub fn is_audit_kind(kind: &str) -> bool {
    kind.starts_with("ck.audit.")
}

/// Applet + agent family classifiers used by projection/audit
/// dispatchers that want to fan out the whole family without listing
/// every kind individually.
pub fn is_applet_kind(kind: &str) -> bool {
    matches!(
        kind,
        CK_APPLET_REGISTRATION
            | CK_APPLET_DISCOVERY
            | CK_APPLET_INTEROP_SESSION_START
            | CK_APPLET_INTEROP_SESSION_STATUS
            | CK_APPLET_BRIDGE_ERROR
    )
}

pub fn is_agent_kind(kind: &str) -> bool {
    matches!(
        kind,
        CK_AGENT_ENDPOINT
            | CK_AGENT_INTEROP_SESSION_START
            | CK_AGENT_INTEROP_SESSION_STATUS
            | CK_AGENT_INTEROP_SESSION_RESULT
            | CK_AGENT_PAUSE
            | CK_AGENT_RESUME
            | CK_AGENT_DEACTIVATE
            | CK_AGENT_DRAFT_PROPOSE
            | CK_AGENT_ACTION_REQUEST
            | CK_AGENT_ACTION_APPROVE
            | CK_AGENT_ACTION_REJECT
    )
}

/// R3 spec-sync (2026-05-27) — FSM-lattice agent lifecycle kinds.
pub fn is_agent_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CK_AGENT_PAUSE | CK_AGENT_RESUME | CK_AGENT_DEACTIVATE)
}

/// R3 spec-sync — `actor_private_event` kinds (reducer_input=false).
/// These MUST NOT advance the seal frontier / actor_seq; the reducer
/// dispatches them through the audit-log projection only.
pub fn is_actor_private_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        CK_ACCOUNT_DATA_SET
            | CK_READ_MARKER
            | CK_AGENT_DRAFT_PROPOSE
            | CK_AGENT_ACTION_REQUEST
            | CK_AGENT_ACTION_APPROVE
            | CK_AGENT_ACTION_REJECT
    )
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CK_MESSAGE_CREATE)
}

pub fn operation_is_redaction(operation: &Operation) -> bool {
    matches!(
        canonical_kind_for_operation(operation),
        Some(CK_MESSAGE_REDACT | CK_REDACTION)
    )
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CK_MEMBER_STATE)
}

pub fn operation_is_invite(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_invite_kind)
}

pub fn operation_is_invite_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CK_INVITE_CREATE)
}

pub fn operation_is_realm_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_realm_lifecycle_kind)
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, CK_MESSAGE_REDACT | CK_REDACTION | "redaction")
}

pub fn is_membership_kind(kind: &str) -> bool {
    matches!(kind, CK_MEMBER_STATE | CK_MEMBER_IDENTITY_UPDATE)
}

pub fn is_invite_kind(kind: &str) -> bool {
    matches!(
        kind,
        CK_INVITE_CREATE | "ck.invite.accept" | "ck.invite.cancel"
    )
}

pub fn is_realm_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        CK_REALM_CREATE
            | CK_REALM_UPDATE
            | CK_REALM_ARCHIVE
            | CK_REALM_DESTROY
            | CK_REALM_TOMBSTONE
    )
}

pub fn is_pin_kind(kind: &str) -> bool {
    matches!(kind, CK_PIN_ADD | CK_PIN_REMOVE | CK_PIN_REORDER)
}

pub fn is_space_container_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        CK_SPACE_CONTAINER_ARCHIVE | CK_SPACE_CONTAINER_RESTORE | CK_SPACE_CONTAINER_TOMBSTONE
    )
}

/// Flow has no dedicated `ck.flow.tombstone` event in the spec event-kind
/// registry — terminal state is reached via `ck.redaction`. Only archive /
/// restore are lifecycle state-machine transitions here.
pub fn is_flow_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CK_FLOW_ARCHIVE | CK_FLOW_RESTORE)
}

/// Morph has no dedicated tombstone event for the same reason as Flow.
pub fn is_morph_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CK_MORPH_ARCHIVE | CK_MORPH_RESTORE)
}

/// Flow tracks update events. Distinct from lifecycle events
/// (`is_flow_lifecycle_kind`) because tracks don't transition Flow.state;
/// they manage entries in `Flow.tracks`. The state guard is "parent Flow
/// MUST be Active" (spec §5.1 update rule), enforced via
/// `check_flow_tracks_transition`.
pub fn is_flow_tracks_kind(kind: &str) -> bool {
    matches!(kind, CK_FLOW_TRACKS_UPDATE)
}

// G3.S9: extensions (applet/bot/tsp) — stub event kinds. Wire-accept +
// reducer no-op projection (we keep the structured caches in
// `routing::extensions::{bot_actor, tsp}`). Full state-machine semantics
// land with the protocol implementations themselves; the constants are
// here so the reducer registry can dispatch.
//
// Spec seals:
//   - `extensions/applet-integration.md` §3–§5 (bot / ghost actor accountability model)
//   - `identity/tsp-integration.md` §3–§5 (transport declaration, route, audit chain)
pub const CK_EXTENSIONS_BOT_REGISTER: &str = "ck.extensions.bot_actor.register";
pub const CK_EXTENSIONS_BOT_REVOKE: &str = "ck.extensions.bot_actor.revoke";
pub const CK_EXTENSIONS_TSP_TRANSPORT_DECLARE: &str = "ck.extensions.tsp.transport_declare";
pub const CK_EXTENSIONS_TSP_ROUTE_ESTABLISH: &str = "ck.extensions.tsp.route_establish";
pub const CK_EXTENSIONS_TSP_AUDIT_APPEND: &str = "ck.extensions.tsp.audit_append";

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

/// SEC-08 — does this Realm-lifecycle payload (`ck.realm.create` /
/// `ck.realm.policy_components`) declare the minimal-metadata profile
/// [`cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE`]
/// (`crypto-media/encryption-and-audit.md` §2.9)?
///
/// The declaration is the `profiles[]` / `active_profiles[]` array the T09/T12
/// path already reads off the same payloads. Used to latch
/// `RealmMetaRecord::minimal_metadata_realm` so the message-ingest aad gate can
/// fail closed on non-`hidden` `aad_visibility_event_id`.
pub fn payload_declares_minimal_metadata_realm(payload: &serde_json::Value) -> bool {
    ["profiles", "active_profiles"].iter().any(|field| {
        payload
            .get(*field)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|profiles| {
                profiles.iter().any(|profile| {
                    profile.as_str() == Some(cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE)
                })
            })
    })
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

    #[test]
    fn minimal_metadata_realm_detected_from_profiles_arrays() {
        use serde_json::json;
        // SEC-08 — declaration is recognised under `profiles[]` and
        // `active_profiles[]`; absent / other profiles are not minimal.
        assert!(payload_declares_minimal_metadata_realm(&json!({
            "profiles": ["ck.profile.mls.minimal_metadata_realm.v1"]
        })));
        assert!(payload_declares_minimal_metadata_realm(&json!({
            "active_profiles": ["ck.profile.core.v1", "ck.profile.mls.minimal_metadata_realm.v1"]
        })));
        assert!(!payload_declares_minimal_metadata_realm(&json!({
            "profiles": ["ck.profile.core.v1"]
        })));
        assert!(!payload_declares_minimal_metadata_realm(&json!({})));
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
