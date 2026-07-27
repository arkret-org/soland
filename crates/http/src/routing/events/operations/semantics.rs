use std::collections::BTreeMap;

use arkret_event_draft::Operation;
use arkret_schema::event_payload_validator_catalog;
use serde::de::DeserializeOwned;
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
    let mut active_series_heads = BTreeMap::<
        (String, String),
        arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesHead,
    >::new();
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
        if kind == arkret_wire::events::EventKind::CALL_STATE {
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
        if kind == arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES {
            validate_key_backup_active_series_transition(
                state,
                operation,
                &mut active_series_heads,
            )?;
        }
    }
    Ok(())
}

fn validate_key_backup_active_series_transition(
    state: &AppState,
    operation: &Operation,
    heads: &mut BTreeMap<
        (String, String),
        arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesHead,
    >,
) -> Result<(), &'static str> {
    let record: arkret_models_collaboration::events_payloads::KeyBackupActiveSeries =
        serde_json::from_value(projection_context_stripped_payload(&operation.payload))
            .map_err(|_| "key_backup_active_series_schema_violation")?;
    let key = (
        record.actor_id.as_str().to_owned(),
        record.backup_kind.as_str().to_owned(),
    );
    let current = heads.get(&key).cloned().or_else(|| {
        state
            .projections()
            .snapshot()
            .key_backup_active_series_head(&key.0, &key.1)
    });
    let next =
        arkret_models_collaboration::events_payloads::validate_key_backup_active_series_transition(
            current.as_ref(),
            &record,
        )
        .map_err(active_series_transition_reason)?;
    heads.insert(key, next);
    Ok(())
}

fn active_series_transition_reason(
    error: arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesTransitionError,
) -> &'static str {
    use arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesTransitionError as Error;
    match error {
        Error::SchemaMismatch => "key_backup_active_series_schema_mismatch",
        Error::SignedFieldsDuplicate => "key_backup_active_series_signed_fields_duplicate",
        Error::SignedFieldsIncomplete => "key_backup_active_series_signed_fields_incomplete",
        Error::ActiveInPrevious => "key_backup_active_series_active_in_previous",
        Error::PreviousSeriesDuplicate => "key_backup_active_series_previous_series_duplicate",
        Error::GenerationBindingMismatch => "key_backup_active_series_generation_binding_mismatch",
        Error::ActorOrClassMismatch => "key_backup_active_series_actor_or_class_mismatch",
        Error::PointerVersionRollback => "key_backup_active_series_pointer_version_rollback",
        Error::PointerVersionGap => "key_backup_active_series_pointer_version_gap",
        Error::PointerVersionFork => "key_backup_active_series_pointer_version_fork",
    }
}

/// strand-and-message.md §9.8.2 — v1 core reactions may only target a
/// `ak:message:`. The reducer keys the OR-Set on the message's storage id
/// (`ak:event:`), so both the canonical `ak:message:` object ref and the
/// internal `ak:event:` form are accepted; every other typed object kind
/// (`ak:strand:`, `ak:morph:`, `ak:circle:`, …) is rejected fail-closed with
/// `reaction_target_unsupported` (a `schema_violation` sub-reason).
/// Profiles MAY register additional target kinds; v1 core does not.
pub(crate) fn validate_reaction_target_kind(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kind,
        arkret_wire::events::EventKind::REACTION_ADD
            | arkret_wire::events::EventKind::REACTION_REMOVE
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
        return Err(arkret_wire::ReasonCode::REACTION_TARGET_UNSUPPORTED);
    };
    if target.starts_with("ak:message:") || target.starts_with("ak:event:") {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::REACTION_TARGET_UNSUPPORTED)
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
        arkret_wire::events::EventKind::CONTAINER_MOVE_ITEM => {
            let payload: arkret_models_collaboration::events_payloads::ContainerMoveItemPayload =
                typed_payload_fields(
                    operation,
                    &[
                        "item_ref",
                        "from_container_ref",
                        "container_ref",
                        "relation_kind",
                        "rank",
                        "expected_position_digest",
                    ],
                )?;
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::events::EventKind::CONTAINER_REBALANCE => {
            let payload: arkret_models_collaboration::events_payloads::ContainerRebalancePayload =
                typed_payload_fields(
                    operation,
                    &[
                        "container_ref",
                        "relation_kind",
                        "positions",
                        "expected_order_digest",
                    ],
                )?;
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::events::EventKind::REALM_NOTARY => {
            let payload: arkret_models_collaboration::events_payloads::RealmNotaryPayload =
                typed_payload_fields(operation, &["realm_id", "notary"])?;
            if payload.realm_id != operation.realm_id {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::events::EventKind::REALM_DIGEST_SUITE_TRANSITION => {
            let payload: arkret_models_collaboration::events_payloads::RealmDigestSuiteTransitionPayload = typed_payload_fields(
                operation,
                &[
                    "from_digest_algorithm",
                    "to_digest_algorithm",
                    "transition_snapshot_ref",
                    "snapshot_commitment",
                ],
            )?;
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::events::EventKind::CONSENT_GRANT => {
            let _: arkret_models_collaboration::events_payloads::ConsentGrantPayload =
                typed_payload_fields(
                    operation,
                    &[
                        "consent_id",
                        "peer",
                        "consent_scope",
                        "not_before",
                        "expires_at",
                        "constraints",
                        "evidence_ref",
                        "reason",
                    ],
                )?;
            Ok(())
        }
        // ak.space.archive / ak.space.restore use the typed
        // SpaceStateTransitionPayload (space_id, new_state, reason?).
        // The removed top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS validator below.
        "ak.space.archive" | "ak.space.restore" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ak.space.archive/restore removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ak.space.tombstone — same removed-field reject rule.
        "ak.space.tombstone" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ak.space.tombstone removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // The complete canonical typed shape is required; validating only
        // observed_dots would allow malformed identifiers.
        arkret_wire::events::EventKind::CONSENT_REVOKE => {
            let mut wire_payload = projection_context_stripped_payload(&operation.payload);
            // Event-to-projection conversion adds actor_seq so the consent
            // reducer can derive its OR-set dot. It is projection context,
            // not part of the closed consent-revoke wire payload.
            if let Some(object) = wire_payload.as_object_mut() {
                object.remove("actor_seq");
            }
            validate_consent_revoke_payload(&wire_payload)
                .map(|_| ())
                .map_err(|_| "ak.consent.revoke payload violates its canonical typed shape")
        }
        // ak.cross_signing.publish — round 4 CAS-register cell with
        // required `expected_previous_generation`. The reducer accepts
        // only when expected_previous_generation == current_generation
        // and new_generation == current_generation + 1. We enforce
        // schema shape here; the actual CAS comparison happens during
        // reducer apply once the cell row is read.
        arkret_wire::events::EventKind::CROSS_SIGNING_PUBLISH => {
            if operation
                .payload
                .get("expected_previous_generation")
                .is_none()
            {
                return Err(
                    "ak.cross_signing.publish payload requires expected_previous_generation \
                     (round-4 CAS wire break)",
                );
            }
            if operation.payload.get("generation").is_none() {
                // DRIFT-ALLOW: error message string for the round-4 CAS contract.
                // Spec cross-signing-publish.schema.json uses `generation`
                // (monotonic counter) + `expected_previous_generation` (CAS).
                return Err("ak.cross_signing.publish payload requires generation (round-4 CAS)");
            }
            if operation.payload.get("trust_domain").is_none() {
                // DRIFT-ALLOW: error message string for the round-4 wire break.
                return Err(
                    "ak.cross_signing.publish payload requires trust_domain (round-4 wire break)",
                );
            }
            Ok(())
        }
        // ak.audit.policy_access — when `access_kind=e2ee_late_recovery`
        // the payload MUST carry `late_recovery_original_event_id`.
        "ak.audit.policy_access" => {
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
                    "ak.audit.policy_access access_kind=e2ee_late_recovery requires \
                     late_recovery_original_event_id (round-4 wire break)",
                );
            }
            Ok(())
        }
        "ak.realm.media_service" => {
            if operation.payload.get("sfu_endpoint").is_some() {
                return Err(
                    "realm_media_service_requires_foci: ak.realm.media_service must use foci[]",
                );
            }
            Ok(())
        }
        "ak.call.state" => {
            let payload: arkret_models_collaboration::events_payloads::call::CallStatePayload =
                typed_payload_fields(
                    operation,
                    &[
                        "call_id",
                        "state_transition",
                        "focus",
                        "recording_transition",
                        "transcript_transition",
                        "roster_delta",
                        "moderation_delta",
                        "mute_override",
                    ],
                )?;
            payload.validate()?;
            if let Some(binding) = operation
                .payload
                .get("roster_delta")
                .filter(|delta| delta.get("op").and_then(Value::as_str) == Some("join"))
                .and_then(|delta| delta.get("participant"))
                .and_then(|participant| participant.get("participant_binding"))
            {
                let scheme = binding.get("scheme").and_then(Value::as_str);
                if scheme != Some(arkret_wire::constants::PARTICIPANT_BINDING_SCHEMA) {
                    return Err(
                        "participant_binding_invalid: participant_binding.scheme must be \
                         ak.media.participant_binding.v1",
                    );
                }
                if binding
                    .get("issuer_kid")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                    || binding
                        .get("sig")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                {
                    return Err(
                        "participant_binding_invalid: participant_binding issuer_kid and sig are \
                         required",
                    );
                }
            }
            Ok(())
        }
        "ak.profile.create" | "ak.profile.update" => Ok(()),
        _ => Ok(()),
    }
}

fn typed_payload_fields<T: DeserializeOwned>(
    operation: &Operation,
    fields: &[&str],
) -> Result<T, &'static str> {
    let Some(payload) = operation.payload.as_object() else {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    };
    let wire_payload = fields
        .iter()
        .filter_map(|field| {
            payload
                .get(*field)
                .cloned()
                .map(|value| ((*field).to_owned(), value))
        })
        .collect();
    serde_json::from_value(Value::Object(wire_payload))
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
}

pub(crate) fn validate_operation_schema_from_sdk_artifact(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = if operation.canonical_event_digest.is_some() {
        projection_context_stripped_payload(&operation.payload)
    } else {
        operation.payload.clone()
    };
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog unavailable")?
        .validate_payload(kind, &payload)
        .map_err(|_| "operation payload violates SDK artifact schema")
}

fn operation_kind_has_sdk_payload_validator(kind: &str) -> Result<bool, &'static str> {
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog unavailable")
        .map(|catalog| catalog.has_payload_validator(kind))
}

fn operation_kind_prefers_projection_schema(kind: &str) -> bool {
    matches!(
        kind,
        arkret_wire::events::EventKind::REALM_INHERITANCE_POLICY
            | arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES
            | arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE
            | arkret_wire::events::EventKind::CIRCLE_ARCHIVE
            | arkret_wire::events::EventKind::CIRCLE_RESTORE
            | arkret_wire::events::EventKind::CIRCLE_TOMBSTONE
    )
}

pub(crate) fn validate_operation_payload_schema(
    kind: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    // Event-derived Operations are reducer DTOs, not wire Event payloads.
    // `projection_operation_from_event` deliberately enriches them with
    // envelope metadata (`event_id`, `sender`, `hlc`, `effects`, ...). The
    // signed payload has already passed the SDK artifact validator in Event
    // envelope admission, so applying an `additionalProperties:false` Event
    // schema to this enriched DTO would reject every correct strict payload.
    if operation.canonical_event_digest.is_some() {
        if let Some(schema) = operation_schema_for_kind(kind) {
            return validate_operation_schema(operation, schema);
        }
        if let Some(validate) = operation_extra_validator_for_kind(kind) {
            return validate(operation);
        }
        return Ok(());
    }
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
        arkret_wire::events::EventKind::MESSAGE_CREATE
        | arkret_wire::events::EventKind::MESSAGE_REVISE => {
            Some(validate_message_operation_payload)
        }
        arkret_wire::events::EventKind::RELATION_CREATE
        | arkret_wire::events::EventKind::RELATION_UPDATE
        | arkret_wire::events::EventKind::RELATION_TOMBSTONE => {
            Some(validate_relation_operation_payload)
        }
        arkret_wire::events::EventKind::READ_CURSOR_ADVANCE => Some(validate_read_marker_payload),
        arkret_wire::events::EventKind::ACCOUNT_DATA_SET => Some(validate_account_data_set_payload),
        arkret_wire::events::EventKind::CONSENT_REVOKE => Some(validate_observed_dots_payload),
        arkret_wire::events::EventKind::INVITE_CREATE => Some(validate_invite_create_payload),
        arkret_wire::events::EventKind::INVITE_THIRD_PARTY => {
            Some(validate_invite_third_party_payload)
        }
        arkret_wire::events::EventKind::INVITE_CLAIM => Some(validate_invite_claim_payload),
        arkret_wire::events::EventKind::INVITE_CANCEL
        | arkret_wire::events::EventKind::INVITE_REVOKE => Some(validate_invite_ref_payload),
        arkret_wire::events::EventKind::REALM_HISTORY_VISIBILITY => {
            Some(validate_history_visibility_payload)
        }
        arkret_wire::events::EventKind::REALM_READ_RECEIPT_POLICY => {
            Some(validate_read_receipt_policy_payload)
        }
        arkret_wire::events::EventKind::REALM_INHERITANCE_POLICY => {
            Some(validate_realm_inheritance_policy_payload)
        }
        kinds::CONFLICT_REPAIR => Some(validate_conflict_repair_payload),
        arkret_wire::events::EventKind::MORPH_CREATE => Some(validate_morph_create_payload),
        arkret_wire::events::EventKind::MORPH_UPDATE => Some(validate_morph_update_payload),
        arkret_wire::events::EventKind::MORPH_SCHEMA_MIGRATE => {
            Some(validate_morph_schema_migrate_payload)
        }
        arkret_wire::events::EventKind::CROSS_SIGNING_RESET => {
            Some(validate_cross_signing_reset_payload)
        }
        arkret_wire::events::EventKind::DEVICE_AUTHORIZE => Some(validate_device_authorize_payload),
        _ => None,
    }
}

pub fn operation_schema_for_kind(kind: &str) -> Option<OperationPayloadSchema> {
    let schema = match kind {
        arkret_wire::events::EventKind::MESSAGE_CREATE => OperationPayloadSchema {
            requirements: MESSAGE_CREATE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        arkret_wire::events::EventKind::MESSAGE_REVISE => OperationPayloadSchema {
            requirements: MESSAGE_REVISE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        arkret_wire::events::EventKind::MESSAGE_REDACT
        | arkret_wire::events::EventKind::REDACTION => OperationPayloadSchema {
            requirements: REDACTION_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REACTION_ADD
        | arkret_wire::events::EventKind::REACTION_REMOVE => OperationPayloadSchema {
            requirements: REACTION_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::RELATION_CREATE => OperationPayloadSchema {
            requirements: RELATION_CREATE_REQUIREMENTS,
            validate: Some(validate_relation_operation_payload),
        },
        arkret_wire::events::EventKind::RELATION_UPDATE
        | arkret_wire::events::EventKind::RELATION_TOMBSTONE => OperationPayloadSchema {
            requirements: RELATION_ID_REQUIREMENTS,
            validate: Some(validate_relation_operation_payload),
        },
        // G3.S5 — `ak.realm.link`. Permissive schema (target_realm_id,
        // link_kind, and materialized status required; the reducer's `apply_realm_link`
        // enforces the rest including the canonical FSM). We register
        // here so `accept_local_operations` doesn't fall through to
        // the SDK artifact validator (whose `realm_id` pattern is
        // stricter than the in-tree fixtures need for testing —
        // existing reducer-level tests use `ak:space:` prefixes).
        arkret_wire::events::EventKind::REALM_LINK => OperationPayloadSchema {
            requirements: REALM_LINK_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::CAPABILITY_GRANT
        | arkret_wire::events::EventKind::CAPABILITY_REVOKE
        | arkret_wire::events::EventKind::CAPABILITY_DELEGATE => OperationPayloadSchema {
            requirements: CAPABILITY_GRANT_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MLS_COMMIT => OperationPayloadSchema {
            requirements: MLS_COMMIT_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MLS_GENESIS => OperationPayloadSchema {
            requirements: MLS_GENESIS_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MLS_PROPOSAL => OperationPayloadSchema {
            requirements: MLS_PROPOSAL_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MLS_WELCOME => OperationPayloadSchema {
            requirements: MLS_WELCOME_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MLS_KEYPACKAGE => OperationPayloadSchema {
            requirements: MLS_KEYPACKAGE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES => OperationPayloadSchema {
            requirements: &[],
            validate: Some(validate_key_backup_active_series_payload),
        },
        arkret_wire::events::EventKind::VIEW_CREATE
        | arkret_wire::events::EventKind::VIEW_UPDATE
        | arkret_wire::events::EventKind::VIEW_RECONCILE => {
            // `ak.view.*` events route through the `ak.component.view.*.v1`
            // cell families in the lattice registry (see
            // `reducer::lattice_kinds::ViewCreate / ViewUpdate / ViewReconcile`).
            // The validator just enforces a `view_id` payload key — the
            // reducer / cell-family pipeline owns mv-register semantics.
            OperationPayloadSchema {
                requirements: VIEW_CREATE_REQUIREMENTS,
                validate: Some(validate_view_payload),
            }
        }
        arkret_wire::events::EventKind::READ_CURSOR_ADVANCE => OperationPayloadSchema {
            requirements: READ_MARKER_REQUIREMENTS,
            validate: Some(validate_read_marker_payload),
        },
        arkret_wire::events::EventKind::ACCOUNT_DATA_SET => OperationPayloadSchema {
            requirements: ACCOUNT_DATA_SET_REQUIREMENTS,
            validate: Some(validate_account_data_set_payload),
        },
        arkret_wire::events::EventKind::RSVP_SET => OperationPayloadSchema {
            requirements: RSVP_SET_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::PIN_ADD => OperationPayloadSchema {
            requirements: PIN_ADD_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::PIN_REMOVE => OperationPayloadSchema {
            requirements: PIN_REMOVE_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::PIN_REORDER => OperationPayloadSchema {
            requirements: PIN_REORDER_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::CONSENT_GRANT => OperationPayloadSchema {
            requirements: CONSENT_GRANT_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::CONSENT_REVOKE => OperationPayloadSchema {
            requirements: CONSENT_REVOKE_REQUIREMENTS,
            validate: Some(validate_observed_dots_payload),
        },
        arkret_wire::events::EventKind::INVITE_CREATE => OperationPayloadSchema {
            requirements: INVITE_CREATE_REQUIREMENTS,
            validate: Some(validate_invite_create_payload),
        },
        arkret_wire::events::EventKind::INVITE_THIRD_PARTY => OperationPayloadSchema {
            requirements: INVITE_THIRD_PARTY_REQUIREMENTS,
            validate: Some(validate_invite_third_party_payload),
        },
        arkret_wire::events::EventKind::INVITE_CLAIM => OperationPayloadSchema {
            requirements: INVITE_CLAIM_REQUIREMENTS,
            validate: Some(validate_invite_claim_payload),
        },
        arkret_wire::events::EventKind::INVITE_CANCEL
        | arkret_wire::events::EventKind::INVITE_REVOKE => OperationPayloadSchema {
            requirements: INVITE_REF_REQUIREMENTS,
            validate: Some(validate_invite_ref_payload),
        },
        arkret_wire::events::EventKind::AUDIT_ERASURE_RECEIPT => OperationPayloadSchema {
            requirements: ERASURE_RECEIPT_REQUIREMENTS,
            validate: None,
        },
        kind if arkret_wire::events::kinds::is_invite_kind(kind) => OperationPayloadSchema {
            requirements: INVITE_STATE_REQUIREMENTS,
            validate: None,
        },
        kind if arkret_wire::events::kinds::is_membership_kind(kind) => OperationPayloadSchema {
            requirements: MEMBERSHIP_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_CREATE => OperationPayloadSchema {
            // `ak.realm.create` is technically lifecycle but carries the
            // full Realm `object` rather than a facet payload.
            requirements: REALM_CREATE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_UPDATE => OperationPayloadSchema {
            requirements: REALM_UPDATE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_ARCHIVE => OperationPayloadSchema {
            requirements: REALM_ARCHIVE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_FREEZE => OperationPayloadSchema {
            requirements: REALM_FREEZE_REQUIREMENTS,
            validate: None,
        },
        // Circle lifecycle. Structure is owned by the registered
        // `ak.schema.circle.v1` payload schema (applied via validate_payload);
        // registering here only builds the projection Operation so the
        // submit-time invariant gate runs — notably the encryption_profile
        // create-lock and circle-below-realm-floor checks in
        // `validate_content_encryption_floor` (previously dead for circles
        // because no Operation was built, so the lock was only caught at
        // projection and the client saw a misleading 200).
        arkret_wire::events::EventKind::CIRCLE_CREATE
        | arkret_wire::events::EventKind::CIRCLE_UPDATE => OperationPayloadSchema {
            requirements: &[],
            validate: None,
        },
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
        arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE
        | arkret_wire::events::EventKind::CIRCLE_ARCHIVE
        | arkret_wire::events::EventKind::CIRCLE_RESTORE
        | arkret_wire::events::EventKind::CIRCLE_TOMBSTONE => OperationPayloadSchema {
            requirements: &[],
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_DESTROY
        | arkret_wire::events::EventKind::REALM_TOMBSTONE => OperationPayloadSchema {
            requirements: REALM_TERMINAL_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_MODERATION_POLICY => OperationPayloadSchema {
            requirements: REALM_MODERATION_POLICY_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_DISAPPEARING_POLICY => OperationPayloadSchema {
            requirements: REALM_DISAPPEARING_POLICY_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::REALM_HISTORY_VISIBILITY => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: Some(validate_history_visibility_payload),
        },
        arkret_wire::events::EventKind::REALM_READ_RECEIPT_POLICY => OperationPayloadSchema {
            requirements: &[],
            validate: Some(validate_read_receipt_policy_payload),
        },
        arkret_wire::events::EventKind::REALM_POLICY_BUNDLE => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_SEARCH_POLICY => OperationPayloadSchema {
            requirements: REALM_SEARCH_POLICY_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::MODERATION_DECISION => OperationPayloadSchema {
            requirements: MODERATION_DECISION_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MODERATION_DECISION_LIFT => OperationPayloadSchema {
            requirements: MODERATION_DECISION_LIFT_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MODERATION_APPEAL_SUBMIT => OperationPayloadSchema {
            requirements: MODERATION_APPEAL_SUBMIT_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MODERATION_APPEAL_REVIEW => OperationPayloadSchema {
            requirements: MODERATION_APPEAL_REVIEW_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MODERATION_APPEAL_DECISION => OperationPayloadSchema {
            requirements: MODERATION_APPEAL_DECISION_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::MODERATION_APPEAL_CLOSE => OperationPayloadSchema {
            requirements: MODERATION_APPEAL_CLOSE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_MEDIA_SERVICE => OperationPayloadSchema {
            requirements: &[],
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_PLAINTEXT_VISIBLE_SERVICES => {
            OperationPayloadSchema {
                requirements: &[],
                validate: None,
            }
        }
        // R1.2 — `ak.realm.delivery_binding_policy` (member-delivery-binding.md
        // §4). The reducer dispatch (`apply_delivery_binding_policy`) projects
        // the whole payload into the `ak.component.realm.delivery_binding_policy.v1`
        // cell; without a projection-operation schema entry the event is never
        // turned into an Operation, the policy cell is never set, and every
        // routable member join fails closed with `delivery_binding_policy_unset`.
        arkret_wire::events::EventKind::REALM_INHERITANCE_POLICY => OperationPayloadSchema {
            requirements: REALM_INHERITANCE_POLICY_REQUIREMENTS,
            validate: Some(validate_realm_inheritance_policy_payload),
        },
        arkret_wire::events::EventKind::REALM_DELIVERY_BINDING_POLICY => OperationPayloadSchema {
            requirements: &[],
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_HISTORY_SHARING_POLICY
        | arkret_wire::events::EventKind::REALM_PREVIEW_POLICY => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::REALM_KEY_SHARE => OperationPayloadSchema {
            requirements: REALM_KEY_SHARE_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        kinds::CONFLICT_REPAIR => OperationPayloadSchema {
            requirements: CONFLICT_REPAIR_REQUIREMENTS,
            validate: Some(validate_conflict_repair_payload),
        },
        kind if arkret_wire::events::kinds::is_space_lifecycle_kind(kind) => {
            OperationPayloadSchema {
                requirements: SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS,
                validate: None,
            }
        }
        arkret_wire::events::EventKind::SPACE_CREATE => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_CREATE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::SPACE_UPDATE => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_UPDATE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::SPACE_PARENT => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_PARENT_REQUIREMENTS,
            validate: None,
        },
        kind if arkret_wire::events::kinds::is_strand_lifecycle_kind(kind) => {
            OperationPayloadSchema {
                requirements: STRAND_LIFECYCLE_REQUIREMENTS,
                validate: None,
            }
        }
        arkret_wire::events::EventKind::STRAND_CREATE => OperationPayloadSchema {
            requirements: STRAND_CREATE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::STRAND_UPDATE => OperationPayloadSchema {
            requirements: STRAND_UPDATE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::STRAND_MOVE => OperationPayloadSchema {
            requirements: STRAND_MOVE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::STRAND_REORDER => OperationPayloadSchema {
            requirements: STRAND_REORDER_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::STRAND_WATCH_SET => OperationPayloadSchema {
            requirements: STRAND_WATCH_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::STRAND_TRACKS_UPDATE => OperationPayloadSchema {
            requirements: STRAND_TRACKS_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kind if arkret_wire::events::kinds::is_morph_lifecycle_kind(kind) => {
            OperationPayloadSchema {
                requirements: MORPH_LIFECYCLE_REQUIREMENTS,
                validate: None,
            }
        }
        arkret_wire::events::EventKind::MORPH_CREATE => OperationPayloadSchema {
            requirements: MORPH_CREATE_REQUIREMENTS,
            validate: Some(validate_morph_create_payload),
        },
        arkret_wire::events::EventKind::MORPH_UPDATE => OperationPayloadSchema {
            requirements: MORPH_UPDATE_REQUIREMENTS,
            validate: Some(validate_morph_update_payload),
        },
        arkret_wire::events::EventKind::MORPH_SCHEMA_MIGRATE => OperationPayloadSchema {
            requirements: MORPH_SCHEMA_MIGRATE_REQUIREMENTS,
            validate: Some(validate_morph_schema_migrate_payload),
        },
        // `ak.field.position.move` / `ak.field.position.reorder` were removed
        // in revision 0a5ab85 (see arkret-spec
        // `artifacts/registry/removed-event-kinds.json`). The generic
        // unknown-event-kind path in `event_log::submit_event` already
        // hard-rejects these kinds; no operation schema branch is needed.
        // Applet protocol family.
        arkret_wire::events::EventKind::APPLET_REGISTRATION => OperationPayloadSchema {
            requirements: APPLET_REGISTRATION_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::APPLET_DISCOVERY => OperationPayloadSchema {
            requirements: APPLET_DISCOVERY_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::APPLET_BRIDGE_ERROR => OperationPayloadSchema {
            requirements: APPLET_BRIDGE_ERROR_REQUIREMENTS,
            validate: None,
        },
        // R3 spec-sync — agent lifecycle FSM kinds.
        arkret_wire::events::EventKind::SELF_AGENT_PAUSE => OperationPayloadSchema {
            requirements: AGENT_PAUSE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::SELF_AGENT_RESUME => OperationPayloadSchema {
            requirements: AGENT_RESUME_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::SELF_AGENT_DEACTIVATE => OperationPayloadSchema {
            requirements: AGENT_DEACTIVATE_REQUIREMENTS,
            validate: None,
        },
        // Agent runtime keys are reducer inputs backed by the SDK payload
        // schemas. Register both kinds here so accepted Events are converted
        // into Operations and reach the reducer dispatch table. The shared
        // validator removes projection-only context only for Operations that
        // carry a canonical Event digest; standalone Operations remain strict.
        arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE
        | arkret_wire::events::EventKind::AGENT_KEY_REVOKE => OperationPayloadSchema {
            requirements: &[],
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        // R3 spec-sync — actor_private_event kinds (reducer_input=false).
        arkret_wire::events::EventKind::AGENT_DRAFT_PROPOSE => OperationPayloadSchema {
            requirements: AGENT_DRAFT_PROPOSE_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::AGENT_ACTION_REQUEST => OperationPayloadSchema {
            requirements: AGENT_ACTION_REQUEST_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::AGENT_ACTION_APPROVE => OperationPayloadSchema {
            requirements: AGENT_ACTION_APPROVE_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::AGENT_ACTION_REJECT => OperationPayloadSchema {
            requirements: AGENT_ACTION_REJECT_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        arkret_wire::events::EventKind::CROSS_SIGNING_PUBLISH => OperationPayloadSchema {
            requirements: CROSS_SIGNING_PUBLISH_REQUIREMENTS,
            validate: None,
        },
        arkret_wire::events::EventKind::CROSS_SIGNING_RESET => OperationPayloadSchema {
            requirements: CROSS_SIGNING_RESET_REQUIREMENTS,
            validate: Some(validate_cross_signing_reset_payload),
        },
        // Device-identity — `ak.device.authorize` maps to the
        // `ak.component.device.authorization.v1` lattice cell. Registering an
        // Operation here is what lets `project_accepted_operations` run
        // `project_device_authorize`, which persists the authoritative
        // `device_public_key` + verified state into the devices inventory
        // (without it the device row stays `unverified` with no key and the
        // client falsely shows the "existing device approval" gate). The SDK
        // validator owns payload shape and binding oneOf; policy validation then
        // verifies any cross_signing_binding at ingest.
        arkret_wire::events::EventKind::DEVICE_AUTHORIZE => OperationPayloadSchema {
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

/// Spec B1.14 — validate a `ak.consent.revoke` payload. Empty or missing
/// `observed_dots[]` is `schema_violation` — implicit cascade revoke is
/// forbidden.
pub fn validate_consent_revoke_payload(payload: &Value) -> Result<(), (&'static str, String)> {
    let parsed: arkret_models_collaboration::governance_payloads::ConsentRevokePayload =
        serde_json::from_value(payload.clone()).map_err(|err| {
            (
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                format!("ak.consent.revoke payload shape is invalid: {err}"),
            )
        })?;
    parsed.validate_minimal().map_err(|err| {
        (
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            format!("ak.consent.revoke payload invariant violation: {err}"),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-cfc039892036";

    fn operation(kind: &str, payload: Value) -> Operation {
        Operation::create(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(REALM_ID).unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn typed_container_payload_rejects_legacy_shape() {
        let legacy = operation(
            arkret_wire::events::EventKind::CONTAINER_MOVE_ITEM,
            serde_json::json!({
                "object_ref": "ak:morph:01904100-0000-7000-8000-000000000201",
                "to_container_id": "ak:morph:01904100-0000-7000-8000-000000000101",
                "relation_kind": "contains",
                "rank": "A"
            }),
        );
        assert_eq!(
            validate_typed_payload_shapes(
                arkret_wire::events::EventKind::CONTAINER_MOVE_ITEM,
                &legacy,
            ),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }

    #[test]
    fn typed_realm_control_payloads_enforce_realm_and_transition_rules() {
        let wrong_realm = operation(
            arkret_wire::events::EventKind::REALM_NOTARY,
            serde_json::json!({
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000099",
                "notary": {"kind": "single_did", "did": "did:web:notary.example"}
            }),
        );
        assert_eq!(
            validate_typed_payload_shapes(
                arkret_wire::events::EventKind::REALM_NOTARY,
                &wrong_realm,
            ),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );

        let noop = operation(
            arkret_wire::events::EventKind::REALM_DIGEST_SUITE_TRANSITION,
            serde_json::json!({
                "from_digest_algorithm": "sha256",
                "to_digest_algorithm": "sha256",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000301",
                "snapshot_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        );
        assert_eq!(
            validate_typed_payload_shapes(
                arkret_wire::events::EventKind::REALM_DIGEST_SUITE_TRANSITION,
                &noop,
            ),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }

    #[test]
    fn agent_key_event_projection_is_not_revalidated_as_wire_payload() {
        let kind = arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE;
        let mut projected = operation(
            kind,
            serde_json::json!({
                "agent_id": "did:web:agent.example",
                "key_id": "did:web:agent.example#runtime-1",
                "verification_method": "did:web:agent.example#runtime-1",
                "public_key_digest": concat!(
                    "sha256:",
                    "1111111111111111111111111111111111111111111111111111111111111111"
                ),
                "signing_key_binding_digest": concat!(
                    "sha256:",
                    "2222222222222222222222222222222222222222222222222222222222222222"
                ),
                "accountable_principal_id": "did:web:controller.example",
                "agent_key_scope": {
                    "actions": ["ak.self.events.command.submit"],
                    "resources": [{
                        "kind": "operation",
                        "operation": "ak.self.events.command.submit"
                    }]
                },
                "audience": ["did:web:principal.example"],
                "issued_at": "2026-07-20T15:09:03.628Z",
                "approval_evidence": {
                    "kind": "pairing_request",
                    "request_canonical_digest": concat!(
                        "sha256:",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    ),
                    "pairing_request_id": "agent_pairing_request:test",
                    "approved_by": "did:web:controller.example"
                },
                "event_id": "ak:event:019f8012-cd0c-7233-9106-954399185e19",
                "sender": "did:web:agent.example",
                "accepted_event_id": "ak:event:019f8012-cd0c-7233-9106-954399185e19"
            }),
        );
        projected.canonical_event_digest = Some(
            concat!(
                "sha256:",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
            .to_owned(),
        );

        assert_eq!(validate_operation_payload_schema(kind, &projected), Ok(()));

        projected.canonical_event_digest = None;
        assert_eq!(
            validate_operation_payload_schema(kind, &projected),
            Err("operation payload violates SDK artifact schema")
        );
    }
}
