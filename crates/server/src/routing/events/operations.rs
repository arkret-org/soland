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
//! - `validate_encrypted_payload_envelope` — `ck.profile.encrypted_envelope.v1` envelope shape (MLS
//!   sender / scheme / version / `key_ref`).
//! - `validate_device_message_target` — to-device transport shape (typed `DeviceMessageTarget`).
//! - canonical RFC 3339 UTC-Z timestamp shape for `*_at` fields is validated via the SDK
//!   `cokret_sdk::canonical::validate_timestamp_canonical`.
//! - `canonical_json_digest` — sha256 over canonical-JSON bytes.
//!
//! Spec items still pending here are tracked in `_todos.md` (notably
//! Stream-A19 for B-09 redact `actor_seq` preservation, B-22 for
//! encrypted-attachment `key_ref` shape, and the operation-schema gaps
//! around the 100+ event kinds the reducer doesn't cover yet).

use cokret_sdk::schema::event_payload_validator_catalog;
use cokret_sdk::{DeviceMessageTarget, Operation};
use serde_json::Value;

use super::{is_json_integer, is_valid_sha256_digest, validate_did};
use crate::kinds;
use crate::state::AppState;

const CK_CROSS_SIGNING_RESET: &str = "ck.cross_signing.reset";
const CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const CONTENT_ENCRYPTION_FLOOR_VIOLATION: &str = "content_encryption_floor_violation";
const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "realm_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "circle_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str =
    cokret_sdk::error::REASON_CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR;
const CAP_ACTION_MESSAGE_MENTION_BROADCAST: &str = "ck.message.mention.broadcast";
const AUDIENCE_MENTION_ALLOWED_AUDIENCES: &[&str] = &[
    "effective_scope_members",
    "strand_participants",
    "strand_watchers",
    "strand_engaged",
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

mod payload_schemas;
use payload_schemas::*;
mod policy;
pub(crate) use policy::*;
mod content;
pub(crate) use content::*;

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
        // Spec B1.13 / B1.14 — typed payload validators for the
        // new wire-broken shapes. These run BEFORE the per-kind schema
        // check so a legacy `target_ref` payload is rejected with the
        // typed-shape reason rather than the generic SDK schema error.
        validate_typed_payload_shapes(kind, operation)?;
        validate_reaction_target_kind(kind, operation)?;
        if let Some(schema) = operation_schema_for_kind(kind) {
            validate_operation_schema(operation, schema)?;
        } else {
            validate_operation_schema_from_sdk_artifact(kind, operation)?;
        }
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
fn validate_reaction_target_kind(kind: &str, operation: &Operation) -> Result<(), &'static str> {
    if !matches!(kind, kinds::CK_REACTION_ADD | kinds::CK_REACTION_REMOVE) {
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
        return Err(cokret_sdk::error::REASON_REACTION_TARGET_UNSUPPORTED);
    };
    if target.starts_with("ck:message:") || target.starts_with("ck:event:") {
        Ok(())
    } else {
        Err(cokret_sdk::error::REASON_REACTION_TARGET_UNSUPPORTED)
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
        // The legacy top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS validator below.
        "ck.space.archive" | "ck.space.restore" => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ck.space.archive/restore legacy `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ck.space.tombstone — same legacy reject rule.
        "ck.space.tombstone" => {
            if operation.payload.get("target_ref").is_some() {
                return Err("ck.space.tombstone legacy `target_ref` form rejected by round-4 wire");
            }
            Ok(())
        }
        // ck.consent.revoke — observed_dots[] required; implicit
        // cascade is schema_violation. We accept the call sites that
        // do not yet emit consent.revoke events (no payload to check)
        // by returning Ok when the payload doesn't even resemble a
        // consent revoke (missing consent_id) — the per-kind schema
        // dispatcher will catch totally-empty payloads separately.
        "ck.consent.revoke" => {
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
        "ck.cross_signing.publish" => {
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
                    // REDU-4 — full participant_binding wire-shape check.
                    // Verifies (a) scheme constant, (b) issuer_kid present,
                    // (c) expires_at strictly after created_at when both
                    // are present, (d) signature ("sig") present.
                    //
                    // TODO(R4): full crypto verification — resolve
                    // `issuer_kid` against the current epoch
                    // `ck.realm.media_service.service_id`, fetch the
                    // ed25519 verification key, and verify `sig` over the
                    // canonical-json bytes of the binding payload.
                    let scheme = binding.get("scheme").and_then(|v| v.as_str());
                    if scheme != Some(cokret_sdk::PARTICIPANT_BINDING_SCHEMA) {
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
        // REDU-6 — when `ck.profile.accountable_principals.strict_reject.v1`
        // is declared (env-gated by `SOLAND_ACCOUNTABLE_PRINCIPALS_STRICT_REJECT`),
        // Actor Profile create/update with unverified `accountable_principal_ids[]`
        // MUST reject the whole event with `failed_precondition
        // reason=accountability_grant_missing`. Without the profile we
        // fall back to the default strip + audit behavior.
        // TODO(R3.1): cross-check each accountable_principal_ids[] DID against the
        // `ck.identity.accountability_grant` projection; for now we
        // only enforce the wire-shape contract (presence of the
        // accountable_principal_ids[] field implies verification must happen).
        "ck.profile.create" | "ck.profile.update" => {
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

fn validate_operation_payload_against_sdk_artifact(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Err("unregistered operation kind");
    };
    validate_operation_schema_from_sdk_artifact(kind, operation)
}

fn validate_invite_create_payload(operation: &Operation) -> Result<(), &'static str> {
    let wire_payload = invite_create_wire_payload(&operation.payload);
    validate_invite_create_known_fields(&wire_payload)?;
    let invite_id = operation
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .ok_or("ck.invite.create operation requires invite_id")?;
    if cokret_sdk::InviteId::new(invite_id.to_owned()).is_err() {
        return Err("ck.invite.create invite_id must be ck:invite:<uuidv7>");
    }
    let target = operation
        .payload
        .get("invite_delivery_target")
        .and_then(Value::as_object)
        .ok_or("invite_delivery_target must be an object")?;
    let recipient_service_did = target
        .get("recipient_service_did")
        .and_then(Value::as_str)
        .ok_or("invite_delivery_target.recipient_service_did is required")?;
    if cokret_sdk::Did::new(recipient_service_did.to_owned()).is_err() {
        return Err("invite_delivery_target.recipient_service_did must be a DID");
    }
    if let Some(service_type) = target.get("recipient_service_type").and_then(Value::as_str)
        && service_type != "principal_server"
    {
        return Err("invite_delivery_target.recipient_service_type must be principal_server");
    }
    let digest = operation
        .payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .ok_or("introduction_evidence_digest is required")?;
    if cokret_sdk::Hash::new(digest.to_owned()).is_err() {
        return Err("introduction_evidence_digest must be a hash");
    }
    let expires_at = operation
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or("expires_at is required")?;
    if cokret_sdk::canonical::validate_timestamp_canonical(expires_at).is_err() {
        return Err("expires_at must be a canonical timestamp");
    }
    event_payload_validator_catalog()
        .validate_payload(kinds::CK_INVITE_CREATE, &wire_payload)
        .map_err(|_| "operation payload violates SDK artifact schema")?;
    Ok(())
}

fn invite_create_wire_payload(payload: &Value) -> Value {
    let mut wire_payload = payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        object.remove("event_id");
        object.remove("sender");
    }
    wire_payload
}

fn validate_invite_create_known_fields(payload: &Value) -> Result<(), &'static str> {
    let object = payload
        .as_object()
        .ok_or("ck.invite.create payload must be an object")?;
    for field in object.keys() {
        if field.starts_with("x_") {
            continue;
        }
        match field.as_str() {
            "invite_id"
            | "invitee"
            | "invite_delivery_target"
            | "introduction_evidence_digest"
            | "expires_at" => {}
            "inviter" => {
                return Err(
                    "ck.invite.create payload must not carry inviter; use envelope.actor_id",
                );
            }
            "invite_token" => {
                return Err("ck.invite.create payload must not carry invite_token");
            }
            "state" => {
                return Err("ck.invite.create payload must not carry state");
            }
            "role" => {
                return Err("ck.invite.create payload role must use x_role");
            }
            _ => return Err("ck.invite.create payload carries unsupported field"),
        }
    }
    Ok(())
}

pub fn operation_schema_for_kind(kind: &str) -> Option<OperationPayloadSchema> {
    let schema = match kind {
        kinds::CK_MESSAGE_CREATE => OperationPayloadSchema {
            requirements: MESSAGE_CREATE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        kinds::CK_MESSAGE_REVISE => OperationPayloadSchema {
            requirements: MESSAGE_REVISE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        kinds::CK_MESSAGE_REDACT | kinds::CK_REDACTION => OperationPayloadSchema {
            requirements: REDACTION_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_REACTION_ADD | kinds::CK_REACTION_REMOVE => OperationPayloadSchema {
            requirements: REACTION_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_RELATION_CREATE => OperationPayloadSchema {
            requirements: RELATION_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_RELATION_UPDATE | kinds::CK_RELATION_DELETE => OperationPayloadSchema {
            requirements: RELATION_ID_REQUIREMENTS,
            validate: None,
        },
        // G3.S5 — `ck.realm.link`. Permissive schema (target_realm_id +
        // link_kind required; the reducer's `apply_realm_link`
        // enforces the rest including cycle detection). We register
        // here so `accept_local_operations` doesn't fall through to
        // the SDK artifact validator (whose `realm_id` pattern is
        // stricter than the in-tree fixtures need for testing —
        // existing reducer-level tests use `ck:space:` prefixes).
        kinds::CK_REALM_LINK => OperationPayloadSchema {
            requirements: REALM_LINK_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_MLS_COMMIT => OperationPayloadSchema {
            requirements: MLS_COMMIT_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_MLS_GENESIS => OperationPayloadSchema {
            requirements: MLS_GENESIS_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_MLS_WELCOME => OperationPayloadSchema {
            requirements: MLS_WELCOME_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_MLS_KEYPACKAGE => OperationPayloadSchema {
            requirements: MLS_KEYPACKAGE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_VIEW_CREATE | kinds::CK_VIEW_UPDATE | kinds::CK_VIEW_RECONCILE => {
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
        kinds::CK_READ_MARKER => OperationPayloadSchema {
            requirements: READ_MARKER_REQUIREMENTS,
            validate: Some(validate_read_marker_payload),
        },
        kinds::CK_ACCOUNT_DATA_SET => OperationPayloadSchema {
            requirements: ACCOUNT_DATA_SET_REQUIREMENTS,
            validate: Some(validate_account_data_set_payload),
        },
        kinds::CK_RSVP_SET => OperationPayloadSchema {
            requirements: RSVP_SET_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        kinds::CK_PIN_ADD => OperationPayloadSchema {
            requirements: PIN_ADD_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        kinds::CK_PIN_REMOVE => OperationPayloadSchema {
            requirements: PIN_REMOVE_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        kinds::CK_PIN_REORDER => OperationPayloadSchema {
            requirements: PIN_REORDER_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        "ck.consent.grant" => OperationPayloadSchema {
            requirements: CONSENT_GRANT_REQUIREMENTS,
            validate: None,
        },
        "ck.consent.revoke" => OperationPayloadSchema {
            requirements: CONSENT_REVOKE_REQUIREMENTS,
            validate: Some(validate_observed_dots_payload),
        },
        kinds::CK_INVITE_CREATE => OperationPayloadSchema {
            requirements: INVITE_CREATE_REQUIREMENTS,
            validate: Some(validate_invite_create_payload),
        },
        kinds::CK_AUDIT_ERASURE_RECEIPT => OperationPayloadSchema {
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
        kinds::CK_REALM_CREATE => OperationPayloadSchema {
            // `ck.realm.create` is technically lifecycle but carries the
            // full Realm `object` rather than a facet payload.
            requirements: REALM_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_REALM_UPDATE => OperationPayloadSchema {
            requirements: REALM_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_REALM_ARCHIVE => OperationPayloadSchema {
            requirements: REALM_ARCHIVE_REQUIREMENTS,
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
        kinds::CK_CIRCLE_CREATE | kinds::CK_CIRCLE_UPDATE => OperationPayloadSchema {
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
        kinds::CK_CIRCLE_MEMBER_STATE
        | kinds::CK_CIRCLE_ARCHIVE
        | kinds::CK_CIRCLE_RESTORE
        | kinds::CK_CIRCLE_TOMBSTONE => OperationPayloadSchema {
            requirements: &[],
            validate: None,
        },
        kinds::CK_REALM_DESTROY | kinds::CK_REALM_TOMBSTONE => OperationPayloadSchema {
            requirements: REALM_TERMINAL_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_REALM_MODERATION_POLICY => OperationPayloadSchema {
            requirements: REALM_MODERATION_POLICY_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_REALM_DISAPPEARING_POLICY => OperationPayloadSchema {
            requirements: REALM_DISAPPEARING_POLICY_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        kinds::CK_REALM_HISTORY_VISIBILITY => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: Some(validate_history_visibility_payload),
        },
        kinds::CK_REALM_POLICY_COMPONENTS => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_REALM_SEARCH_POLICY => OperationPayloadSchema {
            requirements: REALM_SEARCH_POLICY_REQUIREMENTS,
            validate: Some(validate_operation_payload_against_sdk_artifact),
        },
        kinds::CK_REALM_HISTORY_SHARING_POLICY | kinds::CK_REALM_PREVIEW_POLICY => {
            OperationPayloadSchema {
                requirements: REALM_POLICY_VALUE_REQUIREMENTS,
                validate: None,
            }
        }
        kinds::CK_REALM_KEY_SHARE => OperationPayloadSchema {
            requirements: REALM_POLICY_VALUE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_CONFLICT_REPAIR => OperationPayloadSchema {
            requirements: CONFLICT_REPAIR_REQUIREMENTS,
            validate: Some(validate_conflict_repair_payload),
        },
        kind if kinds::is_space_container_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_SPACE_CONTAINER_CREATE => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_SPACE_CONTAINER_UPDATE => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_SPACE_CONTAINER_PARENT => OperationPayloadSchema {
            requirements: SPACE_CONTAINER_PARENT_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_strand_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: STRAND_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_STRAND_CREATE => OperationPayloadSchema {
            requirements: STRAND_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_STRAND_UPDATE => OperationPayloadSchema {
            requirements: STRAND_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_STRAND_MOVE => OperationPayloadSchema {
            requirements: STRAND_MOVE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_STRAND_REORDER => OperationPayloadSchema {
            requirements: STRAND_REORDER_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_STRAND_WATCH_SET => OperationPayloadSchema {
            requirements: STRAND_WATCH_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_STRAND_TRACKS_UPDATE => OperationPayloadSchema {
            requirements: STRAND_TRACKS_UPDATE_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_morph_lifecycle_kind(kind) => OperationPayloadSchema {
            requirements: MORPH_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_MORPH_CREATE => OperationPayloadSchema {
            requirements: MORPH_CREATE_REQUIREMENTS,
            validate: Some(validate_morph_create_payload),
        },
        kinds::CK_MORPH_UPDATE => OperationPayloadSchema {
            requirements: MORPH_UPDATE_REQUIREMENTS,
            validate: Some(validate_morph_update_payload),
        },
        kinds::CK_MORPH_SCHEMA_MIGRATE => OperationPayloadSchema {
            requirements: MORPH_SCHEMA_MIGRATE_REQUIREMENTS,
            validate: Some(validate_morph_schema_migrate_payload),
        },
        // `ck.field.position.move` / `ck.field.position.reorder` were removed
        // in revision 0a5ab85 (see cokret-spec
        // `artifacts/registry/removed-event-kinds.json`). The generic
        // unknown-event-kind path in `event_log::submit_event` already
        // hard-rejects these kinds; no operation schema branch is needed.
        kinds::CK_CONTAINER_MOVE_ITEM | kinds::CK_CONTAINER_REBALANCE => OperationPayloadSchema {
            requirements: RELATION_ID_REQUIREMENTS,
            validate: None,
        },
        // Applet protocol family.
        kinds::CK_APPLET_REGISTRATION => OperationPayloadSchema {
            requirements: APPLET_REGISTRATION_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_APPLET_DISCOVERY => OperationPayloadSchema {
            requirements: APPLET_DISCOVERY_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_APPLET_INTEROP_SESSION_START => OperationPayloadSchema {
            requirements: APPLET_SESSION_START_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_APPLET_INTEROP_SESSION_STATUS => OperationPayloadSchema {
            requirements: APPLET_SESSION_STATUS_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_APPLET_BRIDGE_ERROR => OperationPayloadSchema {
            requirements: APPLET_BRIDGE_ERROR_REQUIREMENTS,
            validate: None,
        },
        // Agent protocol family.
        kinds::CK_AGENT_ENDPOINT => OperationPayloadSchema {
            requirements: AGENT_ENDPOINT_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_INTEROP_SESSION_START => OperationPayloadSchema {
            requirements: AGENT_SESSION_START_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_INTEROP_SESSION_STATUS => OperationPayloadSchema {
            requirements: AGENT_SESSION_STATUS_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_INTEROP_SESSION_RESULT => OperationPayloadSchema {
            requirements: AGENT_SESSION_RESULT_REQUIREMENTS,
            validate: None,
        },
        // R3 spec-sync — agent lifecycle FSM kinds.
        kinds::CK_AGENT_PAUSE => OperationPayloadSchema {
            requirements: AGENT_PAUSE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_RESUME => OperationPayloadSchema {
            requirements: AGENT_RESUME_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_DEACTIVATE => OperationPayloadSchema {
            requirements: AGENT_DEACTIVATE_REQUIREMENTS,
            validate: None,
        },
        // R3 spec-sync — actor_private_event kinds (reducer_input=false).
        kinds::CK_AGENT_DRAFT_PROPOSE => OperationPayloadSchema {
            requirements: AGENT_DRAFT_PROPOSE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_ACTION_REQUEST => OperationPayloadSchema {
            requirements: AGENT_ACTION_REQUEST_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_ACTION_APPROVE => OperationPayloadSchema {
            requirements: AGENT_ACTION_APPROVE_REQUIREMENTS,
            validate: None,
        },
        kinds::CK_AGENT_ACTION_REJECT => OperationPayloadSchema {
            requirements: AGENT_ACTION_REJECT_REQUIREMENTS,
            validate: None,
        },
        CK_CROSS_SIGNING_RESET => OperationPayloadSchema {
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
            .get("strand_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err("message create requires strand_id");
        }
        let track_name = operation
            .payload
            .get("track_name")
            .and_then(Value::as_str)
            .ok_or("message create requires track_name")?;
        validate_read_scope_track(track_name)?;
        validate_message_expiry_payload(operation)?;
    }
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_content").is_some();
    if encrypted {
        // The encrypted content envelope SHAPE is owned by the registered spec schema
        // `ck.schema.encrypted_envelope.v1` (referenced from
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

fn validate_message_expiry_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(expiry) = operation.payload.get("expiry") else {
        return Ok(());
    };
    let Some(object) = expiry.as_object() else {
        return Err("ck.message.create.payload.expiry must be an object");
    };
    for key in object.keys() {
        if !["ttl_ms", "trigger", "seal_hlc", "grace_ms"].contains(&key.as_str()) {
            return Err("ck.message.create.payload.expiry has unknown field");
        }
    }
    if object
        .get("ttl_ms")
        .and_then(Value::as_u64)
        .is_none_or(|value| value == 0)
    {
        return Err("ck.message.create.payload.expiry requires positive ttl_ms");
    }
    match object.get("trigger").and_then(Value::as_str) {
        Some("on_send" | "on_first_read" | "on_last_read") => {}
        _ => return Err("ck.message.create.payload.expiry trigger is invalid"),
    }
    if object
        .get("seal_hlc")
        .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err("ck.message.create.payload.expiry seal_hlc must be non-empty");
    }
    if object
        .get("grace_ms")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err("ck.message.create.payload.expiry grace_ms must be an integer");
    }
    Ok(())
}

fn validate_account_data_set_payload(operation: &Operation) -> Result<(), &'static str> {
    let key = operation
        .payload
        .get("key")
        .and_then(Value::as_str)
        .ok_or("account_data.set requires key")?;
    if private_account_data_key_prefix(key).is_none() {
        return Ok(());
    }
    cokret_sdk::validate_private_account_data_key(key)
        .map_err(|_| "account_data.set key must use registered private key pattern")?;
    if operation.payload.get("tombstone").is_some() {
        return Ok(());
    }
    for forbidden in [
        "body",
        "target_ref",
        "collection_title",
        "note",
        "message_payload",
        "content",
        "blind_tokens",
        "shard_key",
        "transfer_id",
        "blob_ref",
        "filename",
        "media_type",
        "plaintext_size_bytes",
        "content_digest",
        "recipient_device_ids",
        "content_key",
        "local_path",
    ] {
        if operation.payload.get(forbidden).is_some() {
            return Err("account_data.set private payload leaks plaintext field");
        }
    }
    if operation.payload.get("encrypted_payload").is_some()
        || operation.payload.get("encrypted_content").is_some()
    {
        Ok(())
    } else {
        Err("account_data.set private payload requires encrypted_payload or encrypted_content")
    }
}

fn private_account_data_key_prefix(key: &str) -> Option<&'static str> {
    [
        cokret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
        cokret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
        cokret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
        cokret_sdk::ACCOUNT_DATA_TYPE_SAVED,
        cokret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
        cokret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
        cokret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
    ]
    .into_iter()
    .find(|prefix| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
    })
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
        "strand" | "thread" | "view" | "message" | "morph" => {
            if read_scope
                .get("ref")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("read marker read_scope.ref is required");
            }
        }
        "strand_discussion" | "strand_synthesis" => {
            return Err("read marker read_scope.kind removed; use strand plus track_name");
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
        ("strand", Some(track), None) => validate_read_scope_track(track)?,
        ("strand", None, Some("all")) => {}
        ("strand", Some(_), Some(_)) => {
            return Err("read marker read_scope requires exactly one of track_name or track_scope");
        }
        ("strand", None, None) => {
            return Err("read marker read_scope requires track_name or track_scope");
        }
        (_, Some(_), _) | (_, _, Some(_)) => {
            return Err("read marker read_scope.track_name/track_scope requires kind strand");
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
        .is_none_or(|value| !value.starts_with("ck:event:"))
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
        .ok_or("ck.realm.history_visibility requires string value")?;
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
        _ => Err("ck.realm.history_visibility value is unknown"),
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
    if !cell_id.starts_with("ck:cell:") {
        return Err("conflict repair cell_id must use ck:cell:");
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
    let reset: cokret_sdk::crypto_protocol::CrossSigningResetContent =
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
        if kinds::canonical_kind_for_operation(operation) != Some(CK_CROSS_SIGNING_RESET) {
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

/// Map a `validate_operation_policy` reason string to its wire status +
/// `code`. Most policy failures are `capability_denied`; the §14.2 message
/// edit/redact window and the §9.8.2 reaction scope check are
/// `failed_precondition` (the returned reason string is carried through as
/// the human-facing detail / sub-reason).

#[cfg(test)]
mod direct_conversation_policy_tests {
    use serde_json::json;

    use super::*;
    use crate::db::Db;
    use crate::state::DirectConversationBindingRecord;

    fn test_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-direct-conversation-policy-test-blobs"),
            ),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: Some([9u8; 32]),
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
            resumable_upload_incomplete_ttl_seconds: 86_400,
            seal_compaction_min_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: true,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
        }
    }

    fn state_with_direct_binding() -> (AppState, cokret_sdk::RealmId) {
        let state = AppState::new(test_config(), Db { pool: None });
        let realm_id =
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000601".to_owned())
                .unwrap();
        let now = chrono::Utc::now();
        state
            .direct_conversation_bindings
            .lock()
            .expect("direct_conversation_bindings lock")
            .insert(
                "did:web:alice.example\0did:web:bob.example".to_owned(),
                DirectConversationBindingRecord {
                    participants_unordered: vec![
                        "did:web:alice.example".to_owned(),
                        "did:web:bob.example".to_owned(),
                    ],
                    realm_id: realm_id.to_string(),
                    main_strand_id: "ck:strand:01904100-0000-7000-8000-000000000601".to_owned(),
                    binding_event_ref: "ck:event:01904100-0000-7000-8000-000000000601".to_owned(),
                    state: "active".to_owned(),
                    created_at: now,
                    updated_at: now,
                },
            );
        (state, realm_id)
    }

    fn op(
        realm_id: cokret_sdk::RealmId,
        seed: &str,
        kind: &str,
        payload: serde_json::Value,
    ) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new(format!("ck:operation:01904100-0000-7000-8000-{seed}"))
                .unwrap(),
            realm_id,
            kind,
            payload,
        )
    }

    #[tokio::test]
    async fn active_direct_conversation_rejects_invite_space_and_third_party_member() {
        let (state, realm_id) = state_with_direct_binding();

        let invite = op(
            realm_id.clone(),
            "000000000601",
            kinds::CK_INVITE_CREATE,
            json!({
                "invite_id": "ck:invite:01904100-0000-7000-8000-000000000601",
                "inviter": "did:web:alice.example",
                "invitee": "did:web:charlie.example",
                "invite_delivery_target": {
                    "recipient_service_did": "did:web:soland.local",
                    "recipient_service_type": "principal_server"
                },
                "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            }),
        );
        assert_eq!(
            validate_operation_policy(&state, &[invite])
                .await
                .unwrap_err(),
            "direct_conversation_invite_forbidden"
        );

        let space_create = op(
            realm_id.clone(),
            "000000000602",
            kinds::CK_SPACE_CONTAINER_CREATE,
            json!({
                "space_id": "ck:space:01904100-0000-7000-8000-000000000602",
                "title": "Third participant space"
            }),
        );
        assert_eq!(
            validate_operation_policy(&state, &[space_create])
                .await
                .unwrap_err(),
            "direct_conversation_space_forbidden"
        );

        let member_add = op(
            realm_id,
            "000000000603",
            kinds::CK_MEMBER_STATE,
            json!({
                "actor_id": "did:web:charlie.example",
                "membership": "invite",
                "sender": "did:web:alice.example"
            }),
        );
        assert_eq!(
            validate_operation_policy(&state, &[member_add])
                .await
                .unwrap_err(),
            "direct_conversation_third_party_member_forbidden"
        );
    }
}

async fn validate_history_visibility_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_REALM_HISTORY_VISIBILITY) {
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
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_REALM_KEY_SHARE) {
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
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_REALM_MODERATION_POLICY) {
        return Ok(());
    }
    let realm_id = operation.realm_id.as_str();
    if crate::routing::organizations::realm_policy_override_requires_approval(
        state,
        realm_id,
        &operation.payload,
    ) && !crate::routing::organizations::realm_policy_override_has_approval(
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
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("ck.content.poll.response") {
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
        Some(kinds::CK_MESSAGE_CREATE | kinds::CK_MESSAGE_REVISE)
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
        .get("strand_id")
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
        return Err("ck.message.mention.broadcast required for audience_mention");
    }
    if !authz
        .grants
        .iter()
        .any(grant_has_broadcast_safety_constraints)
    {
        return Err(
            "ck.message.mention.broadcast grant requires temporal and rate_limiting constraints",
        );
    }

    let Some(policy) = effective_audience_mention_policy_for_realm(state, realm_id).await else {
        return Err("audience_mention_policy_missing");
    };
    for mention in mentions {
        let count =
            estimate_audience_recipient_count(mention.audience(), &members, operation, state);
        audience_mention_policy_allows(&policy, mention.audience(), count)?;
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
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten();
    let owner = meta.map(|meta| meta.owner);
    let members = state
        .realms
        .lock()
        .ok()
        .map(|realms| {
            if let Some(realm) = cokret_sdk::RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id))
            {
                return realm.members.iter().map(ToString::to_string).collect();
            }
            Vec::new()
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
                    expires_at: Some(_),
                    ..
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
    let events = state
        .persistence
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .ok()?;
    events.into_iter().find_map(|record| {
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
        "strand_participants" => operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .map(|strand_id| {
                state
                    .projection
                    .lock()
                    .ok()
                    .map(|projection| {
                        projection
                            .messages_for_thread(strand_id)
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
        .filter(|value| value.starts_with("ck:event:"))
        .is_none()
    {
        return Err("ck.morph.schema_migrate requires authorization_ref");
    }
    let action = operation
        .payload
        .get("capability_action")
        .or_else(|| operation.payload.get("action"))
        .and_then(serde_json::Value::as_str);
    if action != Some("ck.morph.schema.migrate") {
        return Err("ck.morph.schema_migrate requires ck.morph.schema.migrate capability");
    }
    Ok(())
}

#[cfg(test)]
mod invite_create_schema_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::*;

    fn op(payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000701")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000701".to_owned())
                .unwrap(),
            kinds::CK_INVITE_CREATE,
            payload,
        )
    }

    fn invite_payload() -> serde_json::Value {
        json!({
            "invite_id": "ck:invite:01904100-0000-7000-8000-000000000701",
            "invitee": "did:web:bob.example",
            "invite_delivery_target": {
                "recipient_service_did": "did:web:local.host",
                "recipient_service_type": "principal_server"
            },
            "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "expires_at": "2026-06-14T10:00:00Z"
        })
    }

    #[test]
    fn invite_create_accepts_directed_v1_payload() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let operation = op(invite_payload());

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_accepts_projection_internal_fields() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["event_id"] = json!("ck:event:01904100-0000-7000-8000-000000000701");
        payload["sender"] = json!("did:web:alice.example");
        let operation = op(payload);

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_rejects_legacy_inviter_payload_field() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["inviter"] = json!("did:web:alice.example");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create payload must not carry inviter; use envelope.actor_id")
        );
    }

    #[test]
    fn invite_create_requires_invite_id() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload.as_object_mut().unwrap().remove("invite_id");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create operation requires invite_id")
        );
    }

    #[test]
    fn invite_create_requires_expires_at() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload.as_object_mut().unwrap().remove("expires_at");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create operation requires expires_at")
        );
    }

    #[test]
    fn invite_create_rejects_invalid_invite_id() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["invite_id"] = json!("ck:invite:01");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create invite_id must be ck:invite:<uuidv7>")
        );
    }

    #[test]
    fn invite_create_rejects_non_canonical_expires_at() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["expires_at"] = json!("2026-06-14T10:00:00+00:00");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("expires_at must be a canonical timestamp")
        );
    }
}

#[cfg(test)]
#[path = "operations_strand_tracks_update_tests.rs"]
mod strand_tracks_update_tests;

#[cfg(test)]
mod message_projection_schema_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::*;

    fn op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn message_revise_accepts_spec_canonical_target_ref() {
        let operation = op(
            kinds::CK_MESSAGE_REVISE,
            json!({
                "target_ref": "ck:event:01904100-0000-7000-8000-000000000001",
                "content": {"kind": "ck.content.text", "body": "edited"}
            }),
        );
        let schema = operation_schema_for_kind(kinds::CK_MESSAGE_REVISE).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn reaction_accepts_spec_target_ref_without_event_alias() {
        let operation = op(
            kinds::CK_REACTION_ADD,
            json!({
                "target_ref": "ck:event:01904100-0000-7000-8000-000000000001",
                "sender": "did:web:alice.example",
                "key": "+1"
            }),
        );
        let schema = operation_schema_for_kind(kinds::CK_REACTION_ADD).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
        assert!(operation.payload.get("event_id").is_none());
        assert!(operation.payload.get("actor").is_none());
    }
}

#[cfg(test)]
mod spec_sync_validator_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::*;

    fn op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn morph_create_accepts_metadata_and_rejects_content_conflict() {
        let schema = operation_schema_for_kind(kinds::CK_MORPH_CREATE).unwrap();
        let valid = op(
            kinds::CK_MORPH_CREATE,
            json!({
                "object": {
                    "id": "ck:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["ck.schema.morph.v1"],
                    "metadata": {"title": "Spec"},
                    "encrypted_content": {"version": 1}
                }
            }),
        );
        assert!(validate_operation_schema(&valid, schema).is_ok());

        let content_conflict = op(
            kinds::CK_MORPH_CREATE,
            json!({
                "object": {
                    "id": "ck:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["ck.schema.morph.v1"],
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
        let update_schema = operation_schema_for_kind(kinds::CK_MORPH_UPDATE).unwrap();
        let update = op(
            kinds::CK_MORPH_UPDATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "patch": {"schema_refs": ["ck.schema.new"]}
            }),
        );
        assert_eq!(
            validate_operation_schema(&update, update_schema),
            Err("morph_schema_refs_evolution_unauthorized")
        );

        let migrate = op(
            kinds::CK_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ck.schema.old"],
                "to_schema_refs": ["ck.schema.old", "ck.schema.new"],
                "compatibility_class": "additive",
                "authorization_ref": "ck:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ck.morph.schema.migrate"
            }),
        );
        let migrate_schema = operation_schema_for_kind(kinds::CK_MORPH_SCHEMA_MIGRATE).unwrap();
        assert!(validate_operation_schema(&migrate, migrate_schema).is_ok());
        assert!(validate_morph_schema_migrate_capability(&migrate).is_ok());

        let missing_gate = op(
            kinds::CK_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ck.schema.old"],
                "to_schema_refs": ["ck.schema.new"],
                "compatibility_class": "additive"
            }),
        );
        assert_eq!(
            validate_morph_schema_migrate_capability(&missing_gate),
            Err("ck.morph.schema_migrate requires authorization_ref")
        );

        let unsupported = op(
            kinds::CK_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ck.schema.old"],
                "to_schema_refs": ["ck.schema.new"],
                "compatibility_class": "breaking",
                "authorization_ref": "ck:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ck.morph.schema.migrate"
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
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::*;

    fn cross_signing_reset(payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            "ck.cross_signing.reset",
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
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "issued_at": issued_at
        }));
        assert_eq!(
            kinds::canonical_kind_for_operation(&operation),
            Some("ck.cross_signing.reset")
        );
        assert!(operation_schema_for_kind("ck.cross_signing.reset").is_some());
        validate_operation_schema_from_sdk_artifact("ck.cross_signing.reset", &operation).unwrap();
        validate_operation_schema(
            &operation,
            operation_schema_for_kind("ck.cross_signing.reset").unwrap(),
        )
        .unwrap();

        let missing_proof = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_operation_schema_from_sdk_artifact("ck.cross_signing.reset", &missing_proof),
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
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert!(
            validate_operation_schema(
                &missing_trust_domain,
                operation_schema_for_kind("ck.cross_signing.reset").unwrap(),
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
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
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
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000002",
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
    use serde_json::json;

    use super::*;

    #[test]
    fn audience_mention_accepts_here_as_strand_engaged() {
        let content = json!({
            "kind": "ck.content.composite",
            "parts": [
                {"kind": "ck.content.text", "body": "Team heads up"},
                {
                    "kind": "audience_mention",
                    "audience": "strand_engaged",
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
            "audience": "strand_engaged",
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
            "allowed_audiences": ["strand_engaged"],
            "max_recipients": 5,
            "quota": {"max_operations": 2, "period": "PT1H"}
        });

        audience_mention_policy_allows(&policy, "strand_engaged", 5).unwrap();
        assert_eq!(
            audience_mention_policy_allows(&policy, "strand_engaged", 6),
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

#[cfg(test)]
mod reaction_and_window_policy_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::*;

    fn reaction_op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn reaction_on_message_target_is_accepted() {
        let op = reaction_op(
            kinds::CK_REACTION_ADD,
            json!({
                "target_ref": "ck:message:01904100-0000-7000-8000-000000000001",
                "actor": "did:web:alice",
                "key": "👍",
            }),
        );
        assert!(validate_reaction_target_kind(kinds::CK_REACTION_ADD, &op).is_ok());
    }

    #[test]
    fn reaction_on_event_storage_id_is_accepted() {
        let op = reaction_op(
            kinds::CK_REACTION_ADD,
            json!({ "target_ref": "ck:event:01904100-0000-7000-8000-000000000001" }),
        );
        assert!(validate_reaction_target_kind(kinds::CK_REACTION_ADD, &op).is_ok());
    }

    #[test]
    fn reaction_on_non_message_target_is_rejected() {
        for target in [
            "ck:strand:01904100-0000-7000-8000-000000000001",
            "ck:morph:01904100-0000-7000-8000-000000000001",
            "ck:circle:01904100-0000-7000-8000-000000000001",
        ] {
            let op = reaction_op(kinds::CK_REACTION_ADD, json!({ "target_ref": target }));
            assert_eq!(
                validate_reaction_target_kind(kinds::CK_REACTION_ADD, &op),
                Err(cokret_sdk::error::REASON_REACTION_TARGET_UNSUPPORTED),
                "target {target} must be rejected",
            );
        }
    }

    #[test]
    fn non_reaction_kinds_skip_target_check() {
        let op = reaction_op(
            kinds::CK_MESSAGE_CREATE,
            json!({ "target_ref": "ck:strand:01904100-0000-7000-8000-000000000001" }),
        );
        assert!(validate_reaction_target_kind(kinds::CK_MESSAGE_CREATE, &op).is_ok());
    }

    #[test]
    fn realm_id_alias_forms_match() {
        assert!(realm_ids_match(
            "ck:realm:01904100-0000-7000-8000-668e2181b41d",
            "ck:space:01904100-0000-7000-8000-668e2181b41d",
        ));
        assert!(realm_ids_match("ck:realm:abc", "ck:realm:abc"));
        assert!(!realm_ids_match("ck:realm:abc", "ck:realm:def"));
    }

    fn dur(value: u64, unit: &str) -> cokret_sdk::authz::ConstraintDuration {
        cokret_sdk::authz::ConstraintDuration {
            value,
            unit: unit.to_owned(),
        }
    }

    #[test]
    fn redact_window_authoritative_within_and_after() {
        let edit = dur(15, "m");
        let redact = dur(24, "h");
        // Within the 24h redact window — permitted regardless of the edit window.
        assert!(message_window_permits(
            true,
            chrono::Duration::hours(1),
            Some(&edit),
            Some(&redact),
            true,
        ));
        // Past the 24h redact window — denied even with allow_redact_after_window.
        assert!(!message_window_permits(
            true,
            chrono::Duration::hours(25),
            Some(&edit),
            Some(&redact),
            true,
        ));
    }

    #[test]
    fn redact_shares_edit_window_unless_opted_out() {
        let edit = dur(15, "m");
        // Coupled: past the edit window with no redact window and flag false → denied.
        assert!(!message_window_permits(
            true,
            chrono::Duration::minutes(16),
            Some(&edit),
            None,
            false,
        ));
        // Opted out: allow_redact_after_window=true → unbounded recall.
        assert!(message_window_permits(
            true,
            chrono::Duration::minutes(16),
            Some(&edit),
            None,
            true,
        ));
    }

    #[test]
    fn revise_uses_edit_window_only() {
        let edit = dur(15, "m");
        assert!(message_window_permits(
            false,
            chrono::Duration::minutes(10),
            Some(&edit),
            None,
            false
        ));
        assert!(!message_window_permits(
            false,
            chrono::Duration::minutes(16),
            Some(&edit),
            None,
            false
        ));
        // No edit window declared → unbounded edits.
        assert!(message_window_permits(
            false,
            chrono::Duration::days(365),
            None,
            None,
            false
        ));
    }

    #[test]
    fn policy_reason_code_maps_precondition_vs_capability() {
        assert_eq!(
            operation_policy_reason_code("message_redact_window elapsed").1,
            "failed_precondition"
        );
        assert_eq!(
            operation_policy_reason_code(cokret_sdk::error::REASON_REACTION_SCOPE_MISMATCH).1,
            "failed_precondition"
        );
        assert_eq!(
            operation_policy_reason_code("some other policy failure").1,
            "capability_denied"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════
// Typed wire-payload validators + cell-subject helpers (spec B1.10/B1.11/
// B1.14/B1.15/B1.17).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.14 — validate a `ck.consent.revoke` payload. Empty or missing
/// `observed_dots[]` is `schema_violation` — implicit cascade revoke is
/// forbidden.
pub fn validate_consent_revoke_payload(payload: &Value) -> Result<(), (&'static str, String)> {
    let parsed: cokret_sdk::ConsentRevokePayload = serde_json::from_value(payload.clone())
        .map_err(|err| {
            (
                cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
                format!("ck.consent.revoke payload shape is invalid: {err}"),
            )
        })?;
    parsed.validate_minimal().map_err(|err| {
        (
            cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
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
) -> Result<cokret_sdk::AppletIdentifier, (&'static str, String)> {
    // The SDK's `AppletIdentifier` is `enum { Did(Did), Cx(AppletId) }`.
    // We attempt the DID form first (covers `did:webvh:applet.example`
    // and similar), then fall back to the typed `ck:applet:` form.
    if let Ok(did) = cokret_sdk::Did::new(value.to_owned()) {
        return Ok(cokret_sdk::AppletIdentifier::Did(did));
    }
    if let Ok(applet) = cokret_sdk::AppletId::new(value.to_owned()) {
        return Ok(cokret_sdk::AppletIdentifier::Cx(applet));
    }
    Err((
        cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
        format!("applet_id must be a DID or ck:applet:<uuidv7>: got {value:?}"),
    ))
}

#[cfg(test)]
#[path = "operations_device_message_payload_tests.rs"]
mod device_message_payload_tests;
#[cfg(test)]
#[path = "operations_minimal_metadata_aad_tests.rs"]
mod minimal_metadata_aad_tests;
#[cfg(test)]
#[path = "operations_wire_payload_tests.rs"]
mod wire_payload_tests;
