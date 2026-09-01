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
use arkret_models_collaboration::events_payloads::contact::ContactRequestedPayload;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector, SealAvailabilityReceiptIssueOutcome,
    SealAvailabilityReceiptIssueRequest,
};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventDeliveryTargetState,
    EventDeliveryTargetStatus, EventSealSubmitOutcome, EventView, EventsResolveOutcome,
    EventsResolveRequestBody, EventsSubmitOutcome, EventsSubmitStatus,
};
use arkret_wire::{
    Event, MAX_EVENT_ENVELOPE_BYTES, MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_RESOLVE,
    MAX_EVENT_SUBMIT_BATCH, NotarySig, Seal, proof_kind,
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

// scalability-constraints.md §2: prev_refs ≤ 128 (with MUST-dedup), refs[] total
// ≤ 128, and the `authorized_by` role ≤ 64 within that total. These are the v1
// interop maxima a conformant receiver MUST accept; a stricter local cap would
// reject another node's valid wire object (spec §1).
mod admission;
use admission::policy_bundle_value_from_state_payload;
pub use admission::{
    SolandEventsSubmitRequestBody, events_submit_pre_admit_check, frozen_realm_check,
    realm_policy_bundle_check, terminal_realm_check,
};

pub(crate) mod endpoints;
pub(crate) mod governance_proof;
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
pub(crate) use endpoints::load_realm_actor_frontier;
pub(crate) use submit::accepted_event_digest_suites;
pub(super) use submit::submit_federation_events;
pub(in crate::routing) use submit::{
    DevicePairingAdmission, EventCommitIdempotency, InternalEventAdmission, ValidatedEventEnvelope,
    admit_frontier_backfill_event, prepare_service_franking_proof_event_value,
    service_event_authoring_lock, submit_account_data_event_value, submit_agent_membership_cascade,
    submit_applet_install_batch, submit_direct_conversation_founding_unit, submit_event_value,
    submit_ghost_provision_batch, submit_initial_event_batch_outcome,
    submit_initial_event_submission, submit_initial_event_submission_with_contact_projection,
    submit_initial_event_submission_with_device_pairing, submit_initial_identity_anchor_batch,
    submit_mimi_event_value, submit_mimi_reporter_initial_event_submission,
    submit_one_error_to_app_error, submit_peer_pcr_genesis, submit_sidecar_ensure_batch,
    verify_frontier_backfill_event,
};
use submit::{
    EventValidationError, IDEMPOTENCY_KEY_TTL_SECONDS, RealmBootstrapBatchContext, SubmitOneError,
    SubmittedEventOutcome, event_validation_error, events_submit_outcome, render_submit_one_error,
    submit_event_value_with_idempotency,
};

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
