use arkret_event_draft::Operation;
// Standard protocol event kind constants intentionally live in the SDK.
// Soland code should refer to `arkret_wire::events::kinds::*` directly instead
// of re-exporting legacy aliases from this module.
use serde_json::Value;

use crate::artifacts;

pub const MLS_GOVERNANCE_BINDING_FULL_PROFILE: &str = "ak.profile.mls_governance_binding.full.v1";
pub const MLS_REDUCER_PROFILE_V1: &str = "ak.reducer.v1";

// AKP-0007 — typed Relation kind couples a "wide synthesis" Strand (often
// Realm-default scope) to a "narrow discussion" Strand bound to a
// `scope_circle_id` Circle. Stored on `ak.relation.create` /
// `ak.relation.update` payloads as `relation_kind`. Spec
// `zh/models/circle.md` §7.2.
pub const RELATION_KIND_CONFIDENTIAL_DISCUSSION_OF: &str = "confidential_discussion_of";

// COT-06-004: Realm default-Strand pointer event. The canonical event kind
// constant is exposed as `arkret_wire::events::EventKind::REALM_SET_DEFAULT_STRAND`.

// Morph lifecycle (round 13). Same shape as Strand — no dedicated tombstone.
// `ak.field.position.move` and `ak.field.position.reorder` were removed in
// revision 0a5ab85 (see arkret-spec
// `artifacts/registry/removed-event-kinds.json`). Field-level position move
// was subsumed by track-relative ordering and the per-cell ordered-log
// lattice. No replacement; reducer/wire MUST hard_reject these kinds. The
// generic unknown-event-kind path in `event_log::submit_event` already
// rejects them because they no longer appear in `active_durable_event_kinds`.
// R3.1 spec-sync (2026-05-27, arkret-spec @ 7157ee8) — Realm-scoped
// MemberIdentity append-only replacement event. Cell family
// `ak.component.member.identity.v1`; lattice `ordered_log`; bottom
// `expose`. Composite cell subject is
// `(payload.realm_id, payload.actor_id, payload.segment)`. Reducer
// dispatch lives in `reducer::apply_member_identity_update`; persistence
// is in `state::MemberIdentityRegistry`.
// Realm security-boundary lifecycle (`ak.realm.*`). Spec
// `arkret-spec/spec/v1/zh/models/realm-and-space.md` §2.6.
//
// `ak.realm.freeze` is reversible read-only hold. `ak.realm.tombstone` is a
// terminal migration to a successor Realm. `ak.realm.destroy` is terminal
// no-successor retirement ("dissolve/close Realm" at product level).
pub const CONFLICT_REPAIR: &str = "ak.conflict.repair";
// Round 14e+ (2026-05-16) — Agent protocol family. Spec
// `extensions/agent-integration.md`. Mirror of applet but with a
// terminal `*.result` event that carries the signed audit binding.
// Round 14e+ (2026-05-16) — Applet protocol family. Spec
// `extensions/applet-integration.md`. soland's role at this layer is to
// validate wire shape + persist + dispatch; applet bridge state machine
// lives client-side (inkson) and at the applet service itself.
// R3 spec-sync — new actor_private_event kinds (reducer_input=false; do
// NOT advance the seal frontier / actor_seq). Wire-accepted only.
// R3 spec-sync (2026-05-27, arkret-spec b47ff6ec) — agent lifecycle FSM
// event kinds. `lattice` is `fsm` with `bottom=reject`; deactivate is
// terminal. Reducer enforcement of the (active → paused → active →
// deactivated) transitions lives in `reducer::apply_agent_lifecycle`
// (REDU-1).
// `ak.capability.derived` (capability / reducer_input): records a
// capability derived from a parent Realm's policy + a child Realm's
// inheritance declaration. Reducer projects into
// `ak.component.capability.derived.v1`; full derive logic now runs
// through the same chain as the rest of the Realm-graph family. Any
// remaining cross-Realm derivation gaps are tracked as
// TODO(circle-rollout-P2A.4): cross-Realm `allowed_circle_ids`
// derivation under audited-high-risk policies.
// `ak.device.push_route` is device-scoped.
// G3.S1 — MLS / E2EE lifecycle event kinds.
//
// Canonical kinds per
// `arkret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json` (kind enum):
//   - `ak.mls.keypackage`    — KeyPackage publication. The publish/claim distinction lives at the
//     HTTP operation_id layer (`ak.self.keys.keypackages.upload.create` /
//     `ak.self.keys.keypackages.command.claim`); the event log stores only the canonical kind. The
//     reducer dispatches publish-vs-claim on the `payload.action == "publish" | "claim"` field.
//   - `ak.mls.welcome`       — Welcome envelope reference. Per-(recipient, device) queue semantics
//     are conveyed via payload shape; no separate `.enqueue` suffix.
//   - `ak.mls.commit`        — MLS commit (bumps the group's stored epoch by +1 from
//     `payload.expected_prev_epoch`). The "epoch" semantics live in the payload, not in the kind
//     suffix.
//   - `ak.mls.proposal`      — MLS proposal (Remove proposals are indexed for commit validation).
//   - `ak.mls.genesis`       — MLS group genesis (initializes epoch 0 and the covered_seals
//     accumulator).
//   - `ak.mls.commit_failed` — diagnostic of a failed commit / Welcome processing path (wire-only;
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
// events `ak.audit.epoch_key_destruction` and `ak.realm.audit_policy_downgrade`
// (and the `ak.audit.epoch_destruction_failsafe` remediation) were removed
// from the registry. Arkret v1 audit now uses the Audit Applet Binding +
// sealed historical release session model (`ak.audit.applet_binding`,
// `ak.audit.session.*`, `ak.audit.release`); audit applets are not MLS members
// and no epoch-key-destruction / downgrade event is accepted.

// Round C45 (2026-05-18 main) — new event kinds.
//
// `ak.identity.accountability_grant` (identity / reducer_input): issuer-signed
//   endorsement that a subject DID is accountable to the issuer for a declared
//   scope. Required to verify `Actor Profile.accountable_principal_ids[]`;
//   reducer strips unverified DIDs from accountable_principal_ids (or rejects with
//   `accountability_grant_missing`, per deployment policy). zh/models/actor.md §3.3.1.
// `ak.morph.schema_migrate` (morph / reducer_input): one-shot Morph
//   `schema_refs[]` evolution event with explicit compatibility class.
//   zh/models/morph.md §4.1 S3.
// `ak.attestation.range_completeness` (audit / non-reducer): range-bound
//   completeness attestation; backs cross-issuer fork detection.
//   zh/sync/operations-sync.md §4.2.
// Round C46 (2026-05-19; spec 0a5ab85) — Realm-scoped delivery binding
// governance + per-device push route binding.
//
// `ak.realm.delivery_binding_policy` (realm / reducer_input): Realm
//   policy constraining which `binding_source` values are admissible,
//   which recipient services are allowed, which endorsers are required,
//   whether DID Document fallback / unroutable membership are permitted,
//   and who may sign rebind. cell_family
//   `ak.component.realm.delivery_binding_policy.v1`, cas-register.
//   Governs reducer acceptance of `ak.member.state{join}`
//   delivery_binding. The reducer projects the policy cell + applies
//   binding-source / recipient-service / service-acceptance / policy-
//   frontier checks against routable joins.
//
// `ak.device.push_route` (device / actor_private_event / reducer_input):
//   per-device push route binding for the composite tuple
//   `(recipient_service_id, principal, device, push_route)`. MUST NOT be
//   replicated outside the binding's recipient_service_id context. Stored
//   as actor-private state on the recipient Principal Server only.
// `ak.realm.inheritance_policy` (realm / reducer_input): declares which
// realm-scoped policies a child Realm inherits from its parent boundary.
// Reducer maintains a `ak.component.realm.inheritance_policy.v1`
// cas-register cell; capability derivation runs against the projected
// chain alongside `ak.capability.derived`.
// Realm graph + capability derivation event kinds. Reducer dispatch
// (`apply_realm_link` / `apply_realm_inheritance_policy` /
// `apply_capability_derived`) is fully wired in `src/reducer.rs`;
// validators and HTTP surfaces live in `src/routing/realms.rs`.
//
// `ak.realm.link` (realm / reducer_input): typed link between Realm
// boundaries. Canonical `link_kind` parsing + cycle/self-reference
// rejection runs in `reducer::realm_links::check_realm_link_admissible`
// (R3.1). The canonical link kinds (`governed_by`, `inherits_policy_from`,
// `mirror_of`, `references`, `audited_by`) all evaluate, and the
// `/_soland/self/realms/{realm_id}/effective-policy` surface walks the
// ancestor chain per the inheritance declaration. Outstanding
// follow-up: rich `link_kind`-specific authz constraints (TODO(P2B.x)).
// G3.S2 — `ak.realm.policy_server` (realm / reducer_input): declares the
// pluggable policy-decision service for a Realm. cell_family
// `ak.component.realm.policy_server.v1` (cas-register per SDK lattice
// registry). Spec `arkret-spec/spec/v1/zh/authz/policy-server.md` §2.

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
    if binding.get("binding_profile").and_then(Value::as_str)
        != Some(MLS_GOVERNANCE_BINDING_FULL_PROFILE)
    {
        return Err("mls_governance_binding_profile_invalid");
    }
    if binding.get("reducer_profile").and_then(Value::as_str) != Some(MLS_REDUCER_PROFILE_V1) {
        return Err("mls_governance_binding_reducer_profile_invalid");
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
    let object_type = operation.object_type.as_str();
    if artifacts::active_local_operation_event_kinds().contains(object_type)
        || object_type == CONFLICT_REPAIR
    {
        Some(object_type)
    } else {
        None
    }
}

pub fn canonical_kind_string(operation: &Operation) -> String {
    canonical_kind_for_operation(operation)
        .unwrap_or(operation.object_type.as_str())
        .to_owned()
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(arkret_wire::events::EventKind::MESSAGE_CREATE)
}

pub fn operation_is_redaction(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        .is_some_and(arkret_wire::events::kinds::is_redaction_kind)
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        .is_some_and(arkret_wire::events::kinds::is_membership_kind)
}

pub fn operation_is_invite(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(arkret_wire::events::kinds::is_invite_kind)
}

pub fn operation_is_invite_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(arkret_wire::events::EventKind::INVITE_CREATE)
}

pub fn operation_is_invite_claim(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(arkret_wire::events::EventKind::INVITE_CLAIM)
}

pub fn operation_is_invite_third_party(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        == Some(arkret_wire::events::EventKind::INVITE_THIRD_PARTY)
}

pub fn operation_is_realm_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation)
        .is_some_and(arkret_wire::events::kinds::is_realm_lifecycle_kind)
}

// ────────────────────────────────────────────────────────────────────────
// Audit-compliance profiles + Realm terminal-state classifier (spec T07/T09/T23).
// ────────────────────────────────────────────────────────────────────────

/// Active audit-compliance profile ids. Spec T09.
pub const AUDIT_COMPLIANCE_PROFILES: &[&str] = &[
    "ak.profile.attested_audit.e2ee.v1",
    "ak.profile.disclosed_audit.e2ee.v1",
];

/// Spec T23 — true when `ak.audit.ryw_receipt` may be accepted as a durable
/// Event. Requires `ak.profile.attested_audit.e2ee.v1` to be in the Realm's
/// active profile set.
pub fn ryw_receipt_durable_event_allowed(active_profiles: &[String]) -> bool {
    active_profiles
        .iter()
        .any(|p| p == "ak.profile.attested_audit.e2ee.v1")
}

/// SEC-08 — does this Realm-lifecycle payload (`ak.realm.create` /
/// `ak.realm.policy_components`) declare the minimal-metadata profile
/// [`arkret_mls::MINIMAL_METADATA_REALM_PROFILE`]
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
                    profile.as_str() == Some(arkret_models_crypto::MINIMAL_METADATA_REALM_PROFILE)
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
            "ak.profile.attested_audit.e2ee.v1".to_owned()
        ]));
    }

    #[test]
    fn minimal_metadata_realm_detected_from_profiles_arrays() {
        use serde_json::json;
        // SEC-08 — declaration is recognised under `profiles[]` and
        // `active_profiles[]`; absent / other profiles are not minimal.
        assert!(payload_declares_minimal_metadata_realm(&json!({
            "profiles": ["ak.profile.mls.minimal_metadata_realm.v1"]
        })));
        assert!(payload_declares_minimal_metadata_realm(&json!({
            "active_profiles": ["ak.profile.core.v1", "ak.profile.mls.minimal_metadata_realm.v1"]
        })));
        assert!(!payload_declares_minimal_metadata_realm(&json!({
            "profiles": ["ak.profile.core.v1"]
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
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000"
                },
                "mls_group_id": "mls-group-a",
                "previous_epoch": 7,
                "next_epoch": 8,
                "membership_frontier": ["ak:event:0196419b-0000-7000-8000-000000000001"],
                "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "binding_profile": MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                "reducer_profile": MLS_REDUCER_PROFILE_V1
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
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000"
                },
                "mls_group_id": "mls-group-a",
                "previous_epoch": 6,
                "next_epoch": 8,
                "membership_frontier": ["ak:event:0196419b-0000-7000-8000-000000000001"],
                "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "binding_profile": MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                "reducer_profile": MLS_REDUCER_PROFILE_V1
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
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000999"
                },
                "mls_group_id": "mls-group-a",
                "previous_epoch": 7,
                "next_epoch": 8,
                "membership_frontier": ["ak:event:0196419b-0000-7000-8000-000000000001"],
                "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "binding_profile": MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                "reducer_profile": MLS_REDUCER_PROFILE_V1
            }
        });
        assert_eq!(
            validate_mls_governance_binding(&scope_mismatch),
            Err("mls_governance_binding_scope_mismatch")
        );
    }
}
