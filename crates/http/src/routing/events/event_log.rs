//! Signed Event Envelope ingestion + read API (`/_arkret/self/events/*`).
//!
//! Surfaces:
//! - `QUERY /_arkret/self/events/describe` — declare the active event registry, schema/reducer
//!   profiles, and limits.
//! - `POST /_arkret/self/events`           — submit one canonical Event Envelope or an `events[]`
//!   account-client batch.
//! - `GET  /_arkret/self/events/{event_id}` — fetch one envelope.
//! - `QUERY /_arkret/self/events/resolve`  — resolve up to `MAX_EVENT_RESOLVE`.
//! - `GET  /_arkret/self/events`            — paginated list (filtered by actor / realm).
//! - `QUERY /_arkret/self/events/frontier`  — per-actor Event frontier.
//! - `QUERY /_arkret/self/seals/frontier`   — per-Realm Seal frontier.
//!
//! The validator block (`validate_event_envelope` + helpers) lives in the
//! `validation` submodule.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical as canonical;
use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{DeviceId, DidCoreId, EventId, Hash, Hlc, OperationId, RealmId};
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingAcceptanceReceipt,
    DirectConversationFoundingAcceptanceStatus, DirectConversationFoundingAuthorizationCore,
    DirectConversationFoundingPlan, DirectConversationFoundingUnitKind,
    DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::event_sync::{
    ActorAggregateFrontierKind, ActorAggregateFrontierView, AgentPcrSealHeadReceipt,
    AgentPcrSealHeadReceiptKind, EventsFrontierState, EventsFrontierView,
    EventsSubmitFederationBatchRequestBody, FederationServiceBindingRef, RealmActorFrontierView,
    RealmSealFrontierView, SealFrontierState,
};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector, SealPrepareFenceResultOutcome,
    SealPrepareFenceResultRequestBody, SealPrepareOutcome, SealPrepareRequestBody,
};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventDeliveryTargetState,
    EventDeliveryTargetStatus, EventSealSubmitOutcome, EventView, EventsResolveOutcome,
    EventsResolveRequestBody, EventsSubmitOutcome, EventsSubmitStatus,
};
use arkret_wire::{
    Event, MAX_EVENT_ENVELOPE_BYTES, MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_RESOLVE,
    MAX_EVENT_SUBMIT_BATCH, Seal, proof_kind,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode, error_http_status};
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::AcceptedEvent;
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::{operation_semantics as kinds, protocol_artifacts as artifacts};
pub(in crate::routing) use validation::{
    validate_join_gate_proof_signatures, validate_message_authoring_candidate,
};

use super::projection::{
    actor_erased_in_realm, retention_risk_audit_flag, retention_risk_reason,
    retention_risk_ui_flag, retention_tombstone_for_event,
};
use super::{
    append_audit_log, auth_or_render, now, realm_allows_plaintext_service_for_data_class,
    realm_event_visible_to_session, realm_has_member, render_error, sha256_hex,
    validate_agent_participation_ceiling, validate_agent_reply_participation,
    validate_content_encryption_floor, validate_operation_policy,
    validate_operation_policy_with_plaintext_service_binding, validate_operation_semantics,
    validate_space_id,
};
use crate::routing::organizations;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::describe;

fn current_query_error(error: arkret_wire::WireError) -> AppError {
    let code = match error.error_code() {
        Some(ErrorCode::PayloadTooLarge) => ErrorCode::PayloadTooLarge,
        _ => ErrorCode::SchemaViolation,
    };
    AppError::from_rejection(code, error.to_string())
}

fn current_result_error(error: arkret_wire::WireError, fallback: ErrorCode) -> AppError {
    let code = match error.error_code() {
        Some(ErrorCode::LimitExceeded) => ErrorCode::LimitExceeded,
        _ => fallback,
    };
    AppError::from_rejection(code, error.to_string())
}

#[cfg(test)]
mod current_budget_error_tests {
    use arkret_wire::WireError;

    use super::*;

    #[test]
    fn current_query_budget_codes_do_not_depend_on_error_text() {
        let oversized = current_query_error(WireError::ProtocolCode {
            code: ErrorCode::PayloadTooLarge,
            message: "canonical request exceeds its budget".to_owned(),
        });
        assert_eq!(oversized.code, ErrorCode::PayloadTooLarge);
        assert_eq!(
            error_http_status(oversized.code),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let invalid = current_query_error(WireError::Protocol(
            "payload_too_large appears in this invalid field".to_owned(),
        ));
        assert_eq!(invalid.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn malformed_current_result_is_not_reported_as_a_budget_failure() {
        let invalid = current_result_error(
            WireError::Protocol("limit_exceeded is only diagnostic text".to_owned()),
            ErrorCode::StateMismatch,
        );
        assert_eq!(invalid.code, ErrorCode::StateMismatch);
        let oversized = current_result_error(
            WireError::ProtocolCode {
                code: ErrorCode::LimitExceeded,
                message: "response cannot fit".to_owned(),
            },
            ErrorCode::FrontierUnavailable,
        );
        assert_eq!(oversized.code, ErrorCode::LimitExceeded);
    }
}

/// Match a human session's exact AccountId against its durable PCR lineage.
///
/// Registration commits this record before the rebuildable projection catches
/// up, so every self PCR authorization surface must use the same durable
/// source. Looking up by the complete AccountId also keeps equal principals at
/// different Stations isolated.
async fn durable_account_owns_pcr(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    realm_id: &RealmId,
) -> Result<bool, AppError> {
    let Some(account_id) = actor.as_account_id() else {
        return Ok(false);
    };
    state
        .persistence()
        .principal_resolution_by_account_id(account_id)
        .await
        .map(|resolution| resolution.is_some_and(|record| record.pcr_realm_id == *realm_id))
        .map_err(|error| AppError::internal(format!("principal resolution lookup failed: {error}")))
}

// scalability-constraints.md §2: prev_refs ≤ 128 (with MUST-dedup), refs[] total
// ≤ 128, and the `authorized_by` role ≤ 64 within that total. These are the v1
// interop maxima a conformant receiver MUST accept; a stricter local cap would
// reject another node's valid wire object (spec §1).
mod admission;
pub use admission::{
    EventsSubmitRequestBody, events_submit_pre_admit_check, frozen_realm_check,
    realm_policy_bundle_check, terminal_realm_check,
};
use admission::{policy_bundle_value_from_state_payload, validate_federation_service_binding};

pub(crate) mod endpoints;
pub(crate) mod governance_proof;
mod history_authority;
mod mls_accepted_artifact;
mod mls_welcome_refs;
pub(in crate::routing::events) use endpoints::router;

mod inception;
use inception::{
    canonical_value_digest, event_ref_list, require_object_field, resolve_event_root_anchor_method,
};

mod realm_index;
pub(in crate::routing) use realm_index::realm_is_indexed;
use realm_index::{
    bootstrap_realm_member_index, event_string_field,
    invite_claim_actor_claims_pending_third_party_invite, invite_create_actor_is_inviter,
    invitee_cancels_pending_invite, member_join_accepts_pending_invite, member_self_knock,
    realm_create_actor_is_creator, realm_exists_in_index,
};

mod submit;
pub(crate) use submit::verify_historical_producer;

/// Reuse the durable, closed Ack-less admission classification for external PCR signing.
pub(crate) async fn validate_pcr_prepare_ackless_ingress(
    state: &AppState,
    event: &Event,
    digest: &Hash,
) -> Result<(), String> {
    let snapshot = state
        .projections()
        .control_proposal_snapshot(digest)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "PCR preparation has no durable Control Move admission".to_owned())?;
    // Event proofs remain byte-identical after producer authoring
    // row is stored. Compare the signed content address, not that proof list.
    let recorded_digest = snapshot
        .event
        .event_digest_with_digest_suite(snapshot.digest_suite)
        .map_err(|error| error.to_string())?;
    let requested_digest = event
        .event_digest_with_digest_suite(snapshot.digest_suite)
        .map_err(|error| error.to_string())?;
    if snapshot.event.event_id != event.event_id
        || recorded_digest != digest.as_str()
        || requested_digest != digest.as_str()
        || snapshot.control_proposal_ack.is_some()
    {
        return Err("PCR preparation admission does not bind the exact Event".to_owned());
    }
    let arkret_state::state::store::ControlProposalIngressClass::AcklessSelfPrincipal(class) =
        snapshot.ingress_class
    else {
        return Err("PCR preparation cannot omit an Ack-required admission".to_owned());
    };
    if let Some(reason) =
        submit::replay_ackless_self_principal_ingress(state, event, &class).await?
    {
        return Err(reason.to_owned());
    }
    Ok(())
}
pub(crate) use endpoints::{VerifiedActorPredecessors, load_realm_actor_frontier};
pub(super) use submit::submit_federation_events;
pub(in crate::routing) use submit::{
    DevicePairingAdmission, EventCommitIdempotency, EventValidationError, InternalEventAdmission,
    RecoveryTerminalIntent, ValidatedEventEnvelope, admit_frontier_backfill_event,
    prepare_service_franking_proof_event_value, service_event_authoring_lock,
    submit_account_data_event_value, submit_agent_membership_cascade, submit_applet_install_batch,
    submit_direct_conversation_founding_unit, submit_event_value, submit_ghost_provision_batch,
    submit_initial_event_batch_outcome, submit_initial_event_submission,
    submit_initial_event_submission_with_contact_projection,
    submit_initial_event_submission_with_device_pairing, submit_mimi_event_value,
    submit_mimi_reporter_initial_event_submission, submit_one_error_to_app_error,
    submit_peer_pcr_genesis, submit_proof_authenticated_publication,
    submit_recovery_identity_anchor_batch, submit_sidecar_ensure_batch,
    verify_federated_event_admission, verify_frontier_backfill_event,
};
use submit::{
    IDEMPOTENCY_KEY_TTL_SECONDS, RealmBootstrapBatchContext, SubmitOneError, SubmittedEventOutcome,
    event_validation_error, events_submit_outcome, render_submit_one_error,
};
pub(crate) use submit::{accepted_event_digest_suites, publish_confirmed_realm_bootstrap};

mod validation;
use validation::*;
pub(in crate::routing) use validation::{
    validate_event_envelope_with_context, validate_private_invite_envelope,
};
mod sdk_projection;
pub(crate) use sdk_projection::*;
mod control_proposal_ack_issue;
pub(crate) mod lease_issue;

#[cfg(test)]
#[path = "event_log/admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "event_log_proof_strictness_tests.rs"]
mod proof_strictness_tests;
