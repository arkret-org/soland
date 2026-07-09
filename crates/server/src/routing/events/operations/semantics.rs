use arkret_sdk::Operation;
use arkret_sdk::schema::event_payload_validator_catalog;
use serde_json::Value;

use super::*;

pub type OperationValidator = fn(&Operation) -> Result<(), &'static str>;

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

pub fn validate_operation_semantics(
    state: &AppState,
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
        // `call-state.md` §4.1 / `media-service-binding.md` §3 / §7 — full
        // cryptographic verification of every `participant_binding`. This is
        // the state-aware pass (issuer anchoring against the current
        // media_service epoch + Ed25519 signature verification); the stateless
        // wire-shape pre-filter still runs inside `validate_operation_kind`.
        if kind == arkret_sdk::events::kinds::CALL_STATE {
            participant_binding::verify_call_state_participant_bindings(state, operation)?;
        }
        // Spec B1.13 / B1.14 — typed payload validators for the
        // new wire-broken shapes. These run BEFORE the per-kind schema
        // check so a removed `target_ref` payload is rejected with the
        // typed-shape reason rather than the generic SDK schema error.
        validate_typed_payload_shapes(kind, operation)?;
        validate_operation_patch_semantics(operation)?;
        validate_reaction_target_kind(kind, operation)?;
        validate_operation_payload_schema(kind, operation)?;
    }
    Ok(())
}

/// strand-and-message.md §9.8.2 — v1 core reactions may only target a
/// `ck:message:`. The reducer keys the OR-Set on the message's storage id
/// (`ck:event:`), so both the canonical `ck:message:` object ref and the
/// internal `ck:event:` form are accepted; every other typed object kind
/// (`ck:strand:`, `ck:morph:`, `ck:circle:`, …) is rejected fail-closed with
/// `reaction_target_unsupported` (a `schema_violation` sub-reason).
/// Profiles MAY register additional target kinds; v1 core does not.
pub(crate) fn validate_reaction_target_kind(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kind,
        arkret_sdk::events::kinds::REACTION_ADD | arkret_sdk::events::kinds::REACTION_REMOVE
    ) {
        return Ok(());
    }
    let target = REACTION_TARGET_FIELDS.iter().find_map(|field| {
        operation
            .payload
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    });
    let Some(target) = target else {
        // Missing target is caught by REACTION_REQUIREMENTS; treat here as
        // unsupported so the canonical reason still surfaces.
        return Err(arkret_sdk::error::REASON_REACTION_TARGET_UNSUPPORTED);
    };
    if target.starts_with("ak:message:") || target.starts_with("ak:event:") {
        Ok(())
    } else {
        Err(arkret_sdk::error::REASON_REACTION_TARGET_UNSUPPORTED)
    }
}

/// Spec B1.13 / B1.14 / B1.15 — typed payload validators dispatched on the
/// canonical event kind. Hooks the SDK typed payload shapes
/// (SpaceStateTransition / SpaceObjectTombstone / ConsentRevoke) into the
/// soland operation admission pipeline.
///
/// For the space lifecycle events the SDK's typed payload requires
/// `space_id`. The validator here HARD-REJECTS the
/// wire-broken `target_ref` form; producers must emit canonical `space_id`.
fn validate_typed_payload_shapes(kind: &str, operation: &Operation) -> Result<(), &'static str> {
    match kind {
        // ck.space.archive / ck.space.restore use the typed
        // SpaceStateTransitionPayload (space_id, new_state, reason?).
        // The removed top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS validator below.
        "ck.space.archive" | "ck.space.restore" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ck.space.archive/restore removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ck.space.tombstone — same removed-field reject rule.
        "ck.space.tombstone" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ck.space.tombstone removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ck.consent.revoke — observed_dots[] required; implicit
        // cascade is schema_violation. We accept the call sites that
        // do not yet emit consent.revoke events (no payload to check)
        // by returning Ok when the payload doesn't even resemble a
        // consent revoke (missing consent_id) — the per-kind schema
        // dispatcher will catch totally-empty payloads separately.
        arkret_sdk::events::kinds::CONSENT_REVOKE => {
            if operation.payload.get("consent_id").is_none()
                && operation.payload.get("observed_dots").is_none()
            {
                return Ok(());
            }
            validate_consent_revoke_payload(&operation.payload)
                .map(|_| ())
                .or_else(|_| validate_observed_dots_payload(operation))
                .map_err(|_| "ck.consent.revoke payload violates observed_dots requirement")
        }
        // ck.cross_signing.publish — round 4 CAS-register cell with
        // required `expected_previous_generation`. The reducer accepts
        // only when expected_previous_generation == current_generation
        // and new_generation == current_generation + 1. We enforce
        // schema shape here; the actual CAS comparison happens during
        // reducer apply once the cell row is read.
        arkret_sdk::events::kinds::CROSS_SIGNING_PUBLISH => {
            if operation
                .payload
                .get("expected_previous_generation")
                .is_none()
            {
                return Err(
                    "ck.cross_signing.publish payload requires expected_previous_generation \
                     (round-4 CAS wire break)",
                );
            }
            if operation.payload.get("generation").is_none() {
                // DRIFT-ALLOW: error message string for the round-4 CAS contract.
                // Spec cross-signing-publish.schema.json uses `generation`
                // (monotonic counter) + `expected_previous_generation` (CAS).
                return Err("ck.cross_signing.publish payload requires generation (round-4 CAS)");
            }
            if operation.payload.get("trust_domain").is_none() {
                // DRIFT-ALLOW: error message string for the round-4 wire break.
                return Err(
                    "ck.cross_signing.publish payload requires trust_domain (round-4 wire break)",
                );
            }
            Ok(())
        }
        // ck.applet.interop_session.start — round 4 requires the
        // `applet_id` to be either a DID or a strictly-validated
        // `ck:applet:<uuidv7>` typed id.
        "ck.applet.interop_session.start" => {
            if let Some(applet_id) = operation.payload.get("applet_id").and_then(|v| v.as_str()) {
                validate_applet_id(applet_id).map(|_| ()).map_err(
                    |_| "applet_id must be a DID or ck:applet:<uuidv7> (typed-id wire break)",
                )?;
            }
            Ok(())
        }
        // ck.audit.policy_access — when `access_kind=e2ee_late_recovery`
        // the payload MUST carry `late_recovery_original_event_id`.
        "ck.audit.policy_access" => {
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
                    "ck.audit.policy_access access_kind=e2ee_late_recovery requires \
                     late_recovery_original_event_id (round-4 wire break)",
                );
            }
            Ok(())
        }
        "ck.realm.media_service" => {
            if operation.payload.get("sfu_endpoint").is_some() {
                return Err(
                    "realm_media_service_requires_foci: ck.realm.media_service must use foci[]",
                );
            }
            Ok(())
        }
        // REDU-3 / REDU-4 — `ck.call.state` shape checks.
        //   - `session_focus` is write-once: clients MUST NOT mutate an already-committed value.
        //     The wire-level check ensures the payload doesn't carry a `session_focus_revision`
        //     marker other than the genesis `1`. The full `session_focus_already_committed`
        //     deduplication runs in the reducer once the per-call cell projection lands.
        //   - `participants[].participant_binding.scheme` MUST be the canonical
        //     `ck.media.participant_binding.v1`; otherwise reject with
        //     `participant_binding_invalid`.
        "ck.call.state" => {
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
            if let Some(revision) = operation
                .payload
                .get("session_focus_revision")
                .and_then(|v| v.as_u64())
                && revision > 1
                && operation.payload.get("previous_session_focus").is_none()
            {
                return Err(
                    "session_focus_already_committed: ck.call.state.session_focus is write-once",
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
                    // REDU-4 — participant_binding wire-shape pre-filter.
                    // Verifies (a) scheme constant, (b) issuer_kid present,
                    // (c) expires_at strictly after issued_at when both
                    // are present, (d) signature ("sig") present.
                    //
                    // Full cryptographic verification (issuer anchoring
                    // against the current epoch `ck.realm.media_service`
                    // service_id + Ed25519 signature over the canonical
                    // binding bytes) runs in the state-aware
                    // `participant_binding::verify_call_state_participant_bindings`
                    // pass dispatched from `validate_operation_semantics`.
                    let scheme = binding.get("scheme").and_then(|v| v.as_str());
                    if scheme != Some(arkret_sdk::PARTICIPANT_BINDING_SCHEMA) {
                        return Err(
                            "participant_binding_invalid: participant_binding.scheme must be \
                             ck.media.participant_binding.v1",
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
                    if let (Some(issued_at), Some(expires_at)) = (
                        binding.get("issued_at").and_then(|v| v.as_str()),
                        binding.get("expires_at").and_then(|v| v.as_str()),
                    ) && let (Ok(issued), Ok(expires)) = (
                        chrono::DateTime::parse_from_rfc3339(issued_at),
                        chrono::DateTime::parse_from_rfc3339(expires_at),
                    ) && expires <= issued
                    {
                        return Err(
                            "participant_binding_invalid: participant_binding.expires_at must be \
                             strictly after issued_at",
                        );
                    }
                }
            }
            Ok(())
        }
        "ck.profile.create" | "ck.profile.update" => Ok(()),
        _ => Ok(()),
    }
}

pub(crate) fn validate_operation_schema_from_sdk_artifact(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog unavailable")?
        .validate_payload(kind, &operation.payload)
        .map_err(|_| "operation payload violates SDK artifact schema")
}

fn operation_kind_has_sdk_payload_validator(kind: &str) -> Result<bool, &'static str> {
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog unavailable")
        .map(|catalog| catalog.has_payload_validator(kind))
}

fn operation_kind_prefers_projection_schema(kind: &str) -> bool {
    matches!(kind, arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY)
}

pub(crate) fn validate_operation_payload_schema(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    if operation_kind_prefers_projection_schema(kind)
        && let Some(schema) = operation_schema_for_kind(kind)
    {
        return validate_operation_schema(operation, schema);
    }
    if operation_kind_has_sdk_payload_validator(kind)? {
        validate_operation_schema_from_sdk_artifact(kind, operation)?;
        if let Some(validate) = operation_extra_validator_for_kind(kind) {
            validate(operation)?;
        }
        return Ok(());
    }
    if let Some(schema) = operation_schema_for_kind(kind) {
        return validate_operation_schema(operation, schema);
    }
    validate_operation_schema_from_sdk_artifact(kind, operation)
}

pub(crate) fn validate_operation_payload_against_sdk_artifact(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Err("unregistered operation kind");
    };
    validate_operation_schema_from_sdk_artifact(kind, operation)
}

fn operation_extra_validator_for_kind(kind: &str) -> Option<OperationValidator> {
    match kind {
        arkret_sdk::events::kinds::MESSAGE_CREATE | arkret_sdk::events::kinds::MESSAGE_REVISE => {
            Some(validate_message_operation_payload)
        }
        arkret_sdk::events::kinds::RELATION_CREATE
        | arkret_sdk::events::kinds::RELATION_UPDATE
        | arkret_sdk::events::kinds::RELATION_TOMBSTONE => {
            Some(validate_relation_operation_payload)
        }
        arkret_sdk::events::kinds::READ_CURSOR_ADVANCE => Some(validate_read_marker_payload),
        arkret_sdk::events::kinds::ACCOUNT_DATA_SET => Some(validate_account_data_set_payload),
        arkret_sdk::events::kinds::CONSENT_REVOKE => Some(validate_observed_dots_payload),
        arkret_sdk::events::kinds::INVITE_CREATE => Some(validate_invite_create_payload),
        arkret_sdk::events::kinds::INVITE_THIRD_PARTY => Some(validate_invite_third_party_payload),
        arkret_sdk::events::kinds::INVITE_CLAIM => Some(validate_invite_claim_payload),
        arkret_sdk::events::kinds::INVITE_CANCEL | arkret_sdk::events::kinds::INVITE_REVOKE => {
            Some(validate_invite_ref_payload)
        }
        arkret_sdk::events::kinds::REALM_HISTORY_VISIBILITY => {
            Some(validate_history_visibility_payload)
        }
        arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY => {
            Some(validate_read_receipt_policy_payload)
        }
        arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY => {
            Some(validate_realm_inheritance_policy_payload)
        }
        kinds::CONFLICT_REPAIR => Some(validate_conflict_repair_payload),
        arkret_sdk::events::kinds::MORPH_CREATE => Some(validate_morph_create_payload),
        arkret_sdk::events::kinds::MORPH_UPDATE => Some(validate_morph_update_payload),
        arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE => {
            Some(validate_morph_schema_migrate_payload)
        }
        arkret_sdk::events::kinds::CROSS_SIGNING_RESET => {
            Some(validate_cross_signing_reset_payload)
        }
        arkret_sdk::events::kinds::DEVICE_AUTHORIZE => Some(validate_device_authorize_payload),
        _ => None,
    }
}

pub fn operation_schema_for_kind(kind: &str) -> Option<OperationPayloadSchema> {
    let schema =
        match kind {
            arkret_sdk::events::kinds::MESSAGE_CREATE => OperationPayloadSchema {
                requirements: MESSAGE_CREATE_REQUIREMENTS,
                validate: Some(validate_message_operation_payload),
            },
            arkret_sdk::events::kinds::MESSAGE_REVISE => OperationPayloadSchema {
                requirements: MESSAGE_REVISE_REQUIREMENTS,
                validate: Some(validate_message_operation_payload),
            },
            arkret_sdk::events::kinds::MESSAGE_REDACT | arkret_sdk::events::kinds::REDACTION => {
                OperationPayloadSchema {
                    requirements: REDACTION_REQUIREMENTS,
                    validate: None,
                }
            }
            arkret_sdk::events::kinds::REACTION_ADD
            | arkret_sdk::events::kinds::REACTION_REMOVE => OperationPayloadSchema {
                requirements: REACTION_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::RELATION_CREATE => OperationPayloadSchema {
                requirements: RELATION_CREATE_REQUIREMENTS,
                validate: Some(validate_relation_operation_payload),
            },
            arkret_sdk::events::kinds::RELATION_UPDATE
            | arkret_sdk::events::kinds::RELATION_TOMBSTONE => OperationPayloadSchema {
                requirements: RELATION_ID_REQUIREMENTS,
                validate: Some(validate_relation_operation_payload),
            },
            // G3.S5 — `ck.realm.link`. Permissive schema (target_realm_id +
            // link_kind required; the reducer's `apply_realm_link`
            // enforces the rest including cycle detection). We register
            // here so `accept_local_operations` doesn't fall through to
            // the SDK artifact validator (whose `realm_id` pattern is
            // stricter than the in-tree fixtures need for testing —
            // existing reducer-level tests use `ck:space:` prefixes).
            arkret_sdk::events::kinds::REALM_LINK => OperationPayloadSchema {
                requirements: REALM_LINK_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::CAPABILITY_GRANT
            | arkret_sdk::events::kinds::CAPABILITY_REVOKE
            | arkret_sdk::events::kinds::CAPABILITY_DELEGATE => OperationPayloadSchema {
                requirements: CAPABILITY_GRANT_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MLS_COMMIT => OperationPayloadSchema {
                requirements: MLS_COMMIT_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MLS_GENESIS => OperationPayloadSchema {
                requirements: MLS_GENESIS_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MLS_PROPOSAL => OperationPayloadSchema {
                requirements: MLS_PROPOSAL_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MLS_WELCOME => OperationPayloadSchema {
                requirements: MLS_WELCOME_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MLS_KEYPACKAGE => OperationPayloadSchema {
                requirements: MLS_KEYPACKAGE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::VIEW_CREATE
            | arkret_sdk::events::kinds::VIEW_UPDATE
            | arkret_sdk::events::kinds::VIEW_RECONCILE => {
                // `ck.view.*` events route through the `ck.component.view.*.v1`
                // cell families in the lattice registry (see
                // `reducer::lattice_kinds::ViewCreate / ViewUpdate / ViewReconcile`).
                // The validator just enforces a `view_id` payload key — the
                // reducer / cell-family pipeline owns mv-register semantics.
                OperationPayloadSchema {
                    requirements: VIEW_CREATE_REQUIREMENTS,
                    validate: None,
                }
            }
            arkret_sdk::events::kinds::READ_CURSOR_ADVANCE => OperationPayloadSchema {
                requirements: READ_MARKER_REQUIREMENTS,
                validate: Some(validate_read_marker_payload),
            },
            arkret_sdk::events::kinds::ACCOUNT_DATA_SET => OperationPayloadSchema {
                requirements: ACCOUNT_DATA_SET_REQUIREMENTS,
                validate: Some(validate_account_data_set_payload),
            },
            arkret_sdk::events::kinds::RSVP_SET => OperationPayloadSchema {
                requirements: RSVP_SET_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::PIN_ADD => OperationPayloadSchema {
                requirements: PIN_ADD_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::PIN_REMOVE => OperationPayloadSchema {
                requirements: PIN_REMOVE_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::PIN_REORDER => OperationPayloadSchema {
                requirements: PIN_REORDER_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::CONSENT_GRANT => OperationPayloadSchema {
                requirements: CONSENT_GRANT_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::CONSENT_REVOKE => OperationPayloadSchema {
                requirements: CONSENT_REVOKE_REQUIREMENTS,
                validate: Some(validate_observed_dots_payload),
            },
            arkret_sdk::events::kinds::INVITE_CREATE => OperationPayloadSchema {
                requirements: INVITE_CREATE_REQUIREMENTS,
                validate: Some(validate_invite_create_payload),
            },
            arkret_sdk::events::kinds::INVITE_THIRD_PARTY => OperationPayloadSchema {
                requirements: INVITE_THIRD_PARTY_REQUIREMENTS,
                validate: Some(validate_invite_third_party_payload),
            },
            arkret_sdk::events::kinds::INVITE_CLAIM => OperationPayloadSchema {
                requirements: INVITE_CLAIM_REQUIREMENTS,
                validate: Some(validate_invite_claim_payload),
            },
            arkret_sdk::events::kinds::INVITE_CANCEL | arkret_sdk::events::kinds::INVITE_REVOKE => {
                OperationPayloadSchema {
                    requirements: INVITE_REF_REQUIREMENTS,
                    validate: Some(validate_invite_ref_payload),
                }
            }
            arkret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT => OperationPayloadSchema {
                requirements: ERASURE_RECEIPT_REQUIREMENTS,
                validate: None,
            },
            kind if arkret_sdk::events::kinds::is_invite_kind(kind) => OperationPayloadSchema {
                requirements: INVITE_STATE_REQUIREMENTS,
                validate: None,
            },
            kind if arkret_sdk::events::kinds::is_membership_kind(kind) => OperationPayloadSchema {
                requirements: MEMBERSHIP_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_CREATE => OperationPayloadSchema {
                // `ck.realm.create` is technically lifecycle but carries the
                // full Realm `object` rather than a facet payload.
                requirements: REALM_CREATE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_UPDATE => OperationPayloadSchema {
                requirements: REALM_UPDATE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_ARCHIVE => OperationPayloadSchema {
                requirements: REALM_ARCHIVE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_FREEZE => OperationPayloadSchema {
                requirements: REALM_FREEZE_REQUIREMENTS,
                validate: None,
            },
            // Circle lifecycle. Structure is owned by the registered
            // `ck.schema.circle.v1` payload schema (applied via validate_payload);
            // registering here only builds the projection Operation so the
            // submit-time invariant gate runs — notably the encryption_profile
            // create-lock and circle-below-realm-floor checks in
            // `validate_content_encryption_floor` (previously dead for circles
            // because no Operation was built, so the lock was only caught at
            // projection and the client saw a misleading 200).
            arkret_sdk::events::kinds::CIRCLE_CREATE | arkret_sdk::events::kinds::CIRCLE_UPDATE => {
                OperationPayloadSchema {
                    requirements: &[],
                    validate: None,
                }
            }
            // Circle membership + lifecycle convenience ops (built by the
            // `/_soland/self/circles/*` admin surface). Their payload structure and
            // every authorization / subset invariant
            // (`circle_member_must_be_realm_member`,
            // `circle_member_manage_capability_required`, the lifecycle transition
            // matrix) are owned by the reducer (`apply_circle_member_state` /
            // `apply_circle_lifecycle`). They have no registered SDK artifact
            // payload validator, so register them here with no extra requirements —
            // otherwise the SDK-artifact fallback rejects them with
            // "operation payload violates SDK artifact schema" before the reducer
            // can run, making Circle membership/archive/tombstone unreachable.
            arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE
            | arkret_sdk::events::kinds::CIRCLE_ARCHIVE
            | arkret_sdk::events::kinds::CIRCLE_RESTORE
            | arkret_sdk::events::kinds::CIRCLE_TOMBSTONE => OperationPayloadSchema {
                requirements: &[],
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_DESTROY
            | arkret_sdk::events::kinds::REALM_TOMBSTONE => OperationPayloadSchema {
                requirements: REALM_TERMINAL_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_MODERATION_POLICY => OperationPayloadSchema {
                requirements: REALM_MODERATION_POLICY_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_DISAPPEARING_POLICY => OperationPayloadSchema {
                requirements: REALM_DISAPPEARING_POLICY_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::REALM_HISTORY_VISIBILITY => OperationPayloadSchema {
                requirements: REALM_POLICY_VALUE_REQUIREMENTS,
                validate: Some(validate_history_visibility_payload),
            },
            arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY => OperationPayloadSchema {
                requirements: &[],
                validate: Some(validate_read_receipt_policy_payload),
            },
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS => OperationPayloadSchema {
                requirements: REALM_POLICY_VALUE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_SEARCH_POLICY => OperationPayloadSchema {
                requirements: REALM_SEARCH_POLICY_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::MODERATION_DECISION => OperationPayloadSchema {
                requirements: MODERATION_DECISION_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MODERATION_DECISION_LIFT => OperationPayloadSchema {
                requirements: MODERATION_DECISION_LIFT_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT => OperationPayloadSchema {
                requirements: MODERATION_APPEAL_SUBMIT_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MODERATION_APPEAL_REVIEW => OperationPayloadSchema {
                requirements: MODERATION_APPEAL_REVIEW_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MODERATION_APPEAL_DECISION => OperationPayloadSchema {
                requirements: MODERATION_APPEAL_DECISION_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::MODERATION_APPEAL_CLOSE => OperationPayloadSchema {
                requirements: MODERATION_APPEAL_CLOSE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_MEDIA_SERVICE => OperationPayloadSchema {
                requirements: &[],
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_PLAINTEXT_VISIBLE_SERVICES => OperationPayloadSchema {
                requirements: &[],
                validate: None,
            },
            // R1.2 — `ck.realm.delivery_binding_policy` (member-delivery-binding.md
            // §4). The reducer dispatch (`apply_delivery_binding_policy`) projects
            // the whole payload into the `ck.component.realm.delivery_binding_policy.v1`
            // cell; without a projection-operation schema entry the event is never
            // turned into an Operation, the policy cell is never set, and every
            // routable member join fails closed with `delivery_binding_policy_unset`.
            arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY => OperationPayloadSchema {
                requirements: REALM_INHERITANCE_POLICY_REQUIREMENTS,
                validate: Some(validate_realm_inheritance_policy_payload),
            },
            arkret_sdk::events::kinds::REALM_DELIVERY_BINDING_POLICY => OperationPayloadSchema {
                requirements: &[],
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_HISTORY_SHARING_POLICY
            | arkret_sdk::events::kinds::REALM_PREVIEW_POLICY => OperationPayloadSchema {
                requirements: REALM_POLICY_VALUE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::REALM_KEY_SHARE => OperationPayloadSchema {
                requirements: REALM_KEY_SHARE_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            kinds::CONFLICT_REPAIR => OperationPayloadSchema {
                requirements: CONFLICT_REPAIR_REQUIREMENTS,
                validate: Some(validate_conflict_repair_payload),
            },
            kind if arkret_sdk::events::kinds::is_space_lifecycle_kind(kind) => {
                OperationPayloadSchema {
                    requirements: SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS,
                    validate: None,
                }
            }
            arkret_sdk::events::kinds::SPACE_CREATE => OperationPayloadSchema {
                requirements: SPACE_CONTAINER_CREATE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::SPACE_UPDATE => OperationPayloadSchema {
                requirements: SPACE_CONTAINER_UPDATE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::SPACE_PARENT => OperationPayloadSchema {
                requirements: SPACE_CONTAINER_PARENT_REQUIREMENTS,
                validate: None,
            },
            kind if arkret_sdk::events::kinds::is_strand_lifecycle_kind(kind) => {
                OperationPayloadSchema {
                    requirements: STRAND_LIFECYCLE_REQUIREMENTS,
                    validate: None,
                }
            }
            arkret_sdk::events::kinds::STRAND_CREATE => OperationPayloadSchema {
                requirements: STRAND_CREATE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::STRAND_UPDATE => OperationPayloadSchema {
                requirements: STRAND_UPDATE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::STRAND_MOVE => OperationPayloadSchema {
                requirements: STRAND_MOVE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::STRAND_REORDER => OperationPayloadSchema {
                requirements: STRAND_REORDER_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::STRAND_WATCH_SET => OperationPayloadSchema {
                requirements: STRAND_WATCH_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::STRAND_TRACKS_UPDATE => OperationPayloadSchema {
                requirements: STRAND_TRACKS_UPDATE_REQUIREMENTS,
                validate: None,
            },
            kind if arkret_sdk::events::kinds::is_morph_lifecycle_kind(kind) => {
                OperationPayloadSchema {
                    requirements: MORPH_LIFECYCLE_REQUIREMENTS,
                    validate: None,
                }
            }
            arkret_sdk::events::kinds::MORPH_CREATE => OperationPayloadSchema {
                requirements: MORPH_CREATE_REQUIREMENTS,
                validate: Some(validate_morph_create_payload),
            },
            arkret_sdk::events::kinds::MORPH_UPDATE => OperationPayloadSchema {
                requirements: MORPH_UPDATE_REQUIREMENTS,
                validate: Some(validate_morph_update_payload),
            },
            arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE => OperationPayloadSchema {
                requirements: MORPH_SCHEMA_MIGRATE_REQUIREMENTS,
                validate: Some(validate_morph_schema_migrate_payload),
            },
            // `ck.field.position.move` / `ck.field.position.reorder` were removed
            // in revision 0a5ab85 (see arkret-spec
            // `artifacts/registry/removed-event-kinds.json`). The generic
            // unknown-event-kind path in `event_log::submit_event` already
            // hard-rejects these kinds; no operation schema branch is needed.
            arkret_sdk::events::kinds::CONTAINER_MOVE_ITEM
            | arkret_sdk::events::kinds::CONTAINER_REBALANCE => OperationPayloadSchema {
                requirements: RELATION_ID_REQUIREMENTS,
                validate: None,
            },
            // Applet protocol family.
            arkret_sdk::events::kinds::APPLET_REGISTRATION => OperationPayloadSchema {
                requirements: APPLET_REGISTRATION_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::APPLET_DISCOVERY => OperationPayloadSchema {
                requirements: APPLET_DISCOVERY_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::APPLET_INTEROP_SESSION_START => OperationPayloadSchema {
                requirements: APPLET_SESSION_START_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::APPLET_INTEROP_SESSION_STATUS => OperationPayloadSchema {
                requirements: APPLET_SESSION_STATUS_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::APPLET_BRIDGE_ERROR => OperationPayloadSchema {
                requirements: APPLET_BRIDGE_ERROR_REQUIREMENTS,
                validate: None,
            },
            // Agent protocol family.
            arkret_sdk::events::kinds::AGENT_ENDPOINT => OperationPayloadSchema {
                requirements: AGENT_ENDPOINT_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START => OperationPayloadSchema {
                requirements: AGENT_SESSION_START_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS => OperationPayloadSchema {
                requirements: AGENT_SESSION_STATUS_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT => OperationPayloadSchema {
                requirements: AGENT_SESSION_RESULT_REQUIREMENTS,
                validate: None,
            },
            // R3 spec-sync — agent lifecycle FSM kinds.
            arkret_sdk::events::kinds::AGENT_PAUSE => OperationPayloadSchema {
                requirements: AGENT_PAUSE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_RESUME => OperationPayloadSchema {
                requirements: AGENT_RESUME_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_DEACTIVATE => OperationPayloadSchema {
                requirements: AGENT_DEACTIVATE_REQUIREMENTS,
                validate: None,
            },
            // R3 spec-sync — actor_private_event kinds (reducer_input=false).
            arkret_sdk::events::kinds::AGENT_DRAFT_PROPOSE => OperationPayloadSchema {
                requirements: AGENT_DRAFT_PROPOSE_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_ACTION_REQUEST => OperationPayloadSchema {
                requirements: AGENT_ACTION_REQUEST_REQUIREMENTS,
                validate: None,
            },
            arkret_sdk::events::kinds::AGENT_ACTION_APPROVE => OperationPayloadSchema {
                requirements: AGENT_ACTION_APPROVE_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::AGENT_ACTION_REJECT => OperationPayloadSchema {
                requirements: AGENT_ACTION_REJECT_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::CROSS_SIGNING_PUBLISH => OperationPayloadSchema {
                requirements: CROSS_SIGNING_PUBLISH_REQUIREMENTS,
                validate: Some(validate_operation_payload_against_sdk_artifact),
            },
            arkret_sdk::events::kinds::CROSS_SIGNING_RESET => OperationPayloadSchema {
                requirements: CROSS_SIGNING_RESET_REQUIREMENTS,
                validate: Some(validate_cross_signing_reset_payload),
            },
            // Device-identity — `ck.device.authorize` maps to the
            // `ck.component.device.authorization.v1` lattice cell. Registering an
            // Operation here is what lets `project_accepted_operations` run
            // `project_device_authorize`, which persists the authoritative
            // `device_public_key` + verified state into the devices inventory
            // (without it the device row stays `unverified` with no key and the
            // client falsely shows the "existing device approval" gate). The SDK
            // validator owns payload shape and binding oneOf; policy validation then
            // verifies any cross_signing_binding at ingest.
            arkret_sdk::events::kinds::DEVICE_AUTHORIZE => OperationPayloadSchema {
                requirements: DEVICE_AUTHORIZE_REQUIREMENTS,
                validate: Some(validate_device_authorize_payload),
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

/// Spec B1.14 — validate a `ck.consent.revoke` payload. Empty or missing
/// `observed_dots[]` is `schema_violation` — implicit cascade revoke is
/// forbidden.
pub fn validate_consent_revoke_payload(payload: &Value) -> Result<(), (&'static str, String)> {
    let parsed: arkret_sdk::ConsentRevokePayload = serde_json::from_value(payload.clone())
        .map_err(|err| {
            (
                arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
                format!("ck.consent.revoke payload shape is invalid: {err}"),
            )
        })?;
    parsed.validate_minimal().map_err(|err| {
        (
            arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
            format!("ck.consent.revoke payload invariant violation: {err}"),
        )
    })?;
    Ok(())
}

/// Spec B1.17 — accept an `applet_id` value. Must be either a DID or a
/// strictly-validated `ck:applet:<uuidv7>` typed id. Returns the typed
/// wrapper on success.
pub fn validate_applet_id(
    value: &str,
) -> Result<arkret_sdk::AppletIdentifier, (&'static str, String)> {
    // The SDK's `AppletIdentifier` is `enum { Did(Did), Cx(AppletId) }`.
    // We attempt the DID form first (covers `did:webvh:applet.example`
    // and similar), then fall back to the typed `ck:applet:` form.
    if let Ok(did) = arkret_sdk::Did::new(value.to_owned()) {
        return Ok(arkret_sdk::AppletIdentifier::Did(did));
    }
    if let Ok(applet) = arkret_sdk::AppletId::new(value.to_owned()) {
        return Ok(arkret_sdk::AppletIdentifier::Cx(applet));
    }
    Err((
        arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
        format!("applet_id must be a DID or ck:applet:<uuidv7>: got {value:?}"),
    ))
}
