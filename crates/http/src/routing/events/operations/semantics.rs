use std::collections::BTreeMap;

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
use arkret_schema::event_payload_validator_catalog;
use serde_json::Value;

use super::*;

type OperationValidator = fn(&Operation) -> Result<(), &'static str>;

pub fn validate_operation_semantics(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
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
        if kind == arkret_wire::EventKind::CallState {
            participant_binding::verify_call_state_participant_bindings(state, operation)?;
        }
        // Spec B1.13 / B1.14 — typed payload validators for the
        // new wire-broken shapes. These run BEFORE the per-kind schema
        // check so a removed `target_ref` payload is rejected with the
        // typed-shape reason rather than the generic SDK schema error.
        validate_typed_payload_shapes(&kind, operation)?;
        validate_operation_patch_semantics(operation)?;
        validate_reaction_target_kind(&kind, operation)?;
        validate_operation_payload_schema(&kind, operation)?;
        if kind == arkret_wire::EventKind::KeyBackupActiveSeries {
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
    let record = operation
        .typed_payload::<arkret_wire::event_spec::KeyBackupActiveSeries>()
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
    error.reason_code()
}

/// strand-and-message.md §9.8.2 — v1 core reactions may only target a
/// `ak:message:`. The reducer keys the OR-Set on the message's storage id
/// (`ak:event:`), so both the canonical `ak:message:` object ref and the
/// internal `ak:event:` form are accepted; every other typed object kind
/// (`ak:strand:`, `ak:morph:`, `ak:circle:`, …) is rejected fail-closed with
/// `reaction_target_unsupported` (a `schema_violation` sub-reason).
/// Profiles MAY register additional target kinds; v1 core does not.
pub(crate) fn validate_reaction_target_kind(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kind,
        arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove
    ) {
        return Ok(());
    }
    let target = match kind {
        arkret_wire::EventKind::ReactionAdd => operation
            .typed_payload::<arkret_wire::event_spec::ReactionAdd>()
            .ok()
            .map(|payload| payload.target_ref.as_str().to_owned()),
        arkret_wire::EventKind::ReactionRemove => operation
            .typed_payload::<arkret_wire::event_spec::ReactionRemove>()
            .ok()
            .map(|payload| payload.target_ref.as_str().to_owned()),
        _ => None,
    };
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
fn validate_typed_payload_shapes(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    match kind {
        arkret_wire::EventKind::ContainerMoveItem => {
            let payload = operation
                .typed_payload::<arkret_wire::event_spec::ContainerMoveItem>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::EventKind::ContainerRebalance => {
            let payload = operation
                .typed_payload::<arkret_wire::event_spec::ContainerRebalance>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::EventKind::RealmNotary => {
            let payload = operation
                .typed_payload::<arkret_wire::event_spec::RealmNotary>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            if payload.realm_id != operation.realm_id {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::EventKind::RealmDigestSuiteTransition => {
            let payload = operation
                .typed_payload::<arkret_wire::event_spec::RealmDigestSuiteTransition>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            payload
                .validate()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        }
        arkret_wire::EventKind::ConsentGrant => {
            operation
                .typed_payload::<arkret_wire::event_spec::ConsentGrant>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            Ok(())
        }
        // ak.space.archive / ak.space.restore use the typed
        // SpaceStateTransitionPayload (space_id, new_state, reason?).
        // The removed top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS validator below.
        arkret_wire::EventKind::SpaceArchive | arkret_wire::EventKind::SpaceRestore => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ak.space.archive/restore removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ak.space.tombstone — same removed-field reject rule.
        arkret_wire::EventKind::SpaceTombstone => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ak.space.tombstone removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // The complete canonical typed shape is required; validating only
        // observed_dots would allow malformed identifiers.
        arkret_wire::EventKind::ConsentRevoke => {
            let mut wire_payload = operation.payload.clone();
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
        // ak.audit.accessed — when `access_kind=e2ee_late_recovery`
        // the payload MUST carry `late_recovery_original_event_id`.
        arkret_wire::EventKind::AuditAccessed => {
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
                return Err("ak.audit.accessed access_kind=e2ee_late_recovery requires \
                     late_recovery_original_event_id (round-4 wire break)");
            }
            Ok(())
        }
        arkret_wire::EventKind::RealmMediaService => {
            if operation.payload.get("sfu_endpoint").is_some() {
                return Err(
                    "realm_media_service_requires_foci: ak.realm.media_service must use foci[]",
                );
            }
            Ok(())
        }
        arkret_wire::EventKind::CallState => {
            let payload = operation
                .typed_payload::<arkret_wire::event_spec::CallState>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            payload.validate()?;
            if let Some(binding) = operation
                .payload
                .get("roster_delta")
                .filter(|delta| delta.get("op").and_then(Value::as_str) == Some("join"))
                .and_then(|delta| delta.get("participant"))
                .and_then(|participant| participant.get("participant_binding"))
            {
                let scheme = binding.get("scheme").and_then(Value::as_str);
                if scheme != Some(ParticipantBinding::SCHEMA) {
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
        arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate => Ok(()),
        _ => Ok(()),
    }
}

pub(crate) fn validate_operation_schema_from_sdk_artifact(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    event_payload_validator_catalog()
        .map_err(|_| "operation payload validator catalog unavailable")?
        .validate_payload(kind.as_str(), &operation.payload)
        .map_err(|_| "operation payload violates SDK artifact schema")
}

pub(crate) fn validate_operation_payload_schema(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    validate_operation_schema_from_sdk_artifact(kind, operation)?;
    if let Some(validate) = operation_extra_validator_for_kind(kind) {
        validate(operation)?;
    }
    Ok(())
}

pub(crate) fn validate_operation_payload_against_sdk_artifact(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Err("unregistered operation kind");
    };
    validate_operation_schema_from_sdk_artifact(&kind, operation)
}

fn operation_extra_validator_for_kind(kind: &arkret_wire::EventKind) -> Option<OperationValidator> {
    match kind {
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise => {
            Some(validate_message_operation_payload)
        }
        arkret_wire::EventKind::RelationCreate
        | arkret_wire::EventKind::RelationUpdate
        | arkret_wire::EventKind::RelationTombstone => Some(validate_relation_operation_payload),
        arkret_wire::EventKind::ReadCursorAdvance => Some(validate_read_marker_payload),
        arkret_wire::EventKind::AccountDataSet => Some(validate_account_data_set_payload),
        arkret_wire::EventKind::ConsentRevoke => Some(validate_observed_dots_payload),
        arkret_wire::EventKind::InviteCreate => Some(validate_invite_create_payload),
        arkret_wire::EventKind::InviteThirdParty => Some(validate_invite_third_party_payload),
        arkret_wire::EventKind::InviteClaim => Some(validate_invite_claim_payload),
        arkret_wire::EventKind::InviteCancel | arkret_wire::EventKind::InviteRevoke => {
            Some(validate_invite_ref_payload)
        }
        arkret_wire::EventKind::RealmHistoryVisibility => Some(validate_history_visibility_payload),
        arkret_wire::EventKind::RealmReadReceiptPolicy => {
            Some(validate_read_receipt_policy_payload)
        }
        arkret_wire::EventKind::RealmInheritancePolicy => {
            Some(validate_realm_inheritance_policy_payload)
        }
        arkret_wire::EventKind::MorphCreate => Some(validate_morph_create_payload),
        arkret_wire::EventKind::MorphUpdate => Some(validate_morph_update_payload),
        arkret_wire::EventKind::MorphSchemaMigrate => Some(validate_morph_schema_migrate_payload),
        arkret_wire::EventKind::DeviceAuthorize => Some(validate_device_authorize_payload),
        _ => None,
    }
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

    const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    fn operation(kind: impl AsRef<str>, payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(REALM_ID).unwrap(),
            kind.as_ref(),
            payload,
        )
    }

    #[test]
    fn typed_container_payload_rejects_legacy_shape() {
        let legacy = operation(
            arkret_wire::EventKind::ContainerMoveItem,
            serde_json::json!({
                "object_ref": "ak:morph:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "to_container_id": "ak:morph:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                "relation_kind": "contains",
                "rank": "A"
            }),
        );
        assert_eq!(
            validate_typed_payload_shapes(&arkret_wire::EventKind::ContainerMoveItem, &legacy,),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }

    #[test]
    fn typed_realm_control_payloads_enforce_realm_and_transition_rules() {
        let wrong_realm = operation(
            arkret_wire::EventKind::RealmNotary,
            serde_json::json!({
                "realm_id": "ak:realm:Ab-zkG-9qydcyuk0bIAwMd1Op6VQjpOjQ1PbK_fCMMmz",
                "notary": {
                    "kind": "single_did",
                    "actor_id": "ak:did_core:web:notary.example"
                }
            }),
        );
        assert_eq!(
            validate_typed_payload_shapes(&arkret_wire::EventKind::RealmNotary, &wrong_realm,),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );

        let noop = operation(
            arkret_wire::EventKind::RealmDigestSuiteTransition,
            serde_json::json!({
                "from_digest_algorithm": "sha256",
                "to_digest_algorithm": "sha256",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000301",
                "snapshot_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        );
        assert_eq!(
            validate_typed_payload_shapes(
                &arkret_wire::EventKind::RealmDigestSuiteTransition,
                &noop,
            ),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }
}
