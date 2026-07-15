//! Signed Event Envelope ingestion + read API (`/_arkret/self/events/*`).
//!
//! Surfaces:
//! - `GET  /_arkret/self/events/describe`  — declare the active event registry, schema/reducer
//!   profiles, and limits.
//! - `POST /_arkret/self/events`           — submit one canonical Event Envelope or an `events[]`
//!   account-client batch.
//! - `GET  /_arkret/self/events/{event_id}` — fetch one envelope.
//! - `POST /_arkret/self/events/resolve`    — resolve up to `MAX_EVENT_RESOLVE`.
//! - `GET  /_arkret/self/events`            — paginated list (filtered by actor / realm).
//! - `GET  /_arkret/self/events/frontier`   — per-actor / per-realm frontier.
//!
//! The validator block (`validate_event_envelope` + helpers) lives in the
//! `validation` submodule.

use std::collections::BTreeMap;

use arkret_sdk::http::{
    EventView, EventsQueryOutcome, EventsResolveOutcome, EventsResolveRequestBody,
    EventsSubmitOutcome, EventsSubmitStatus,
};
use arkret_sdk::{
    ActorFrontierView, Audience, Did, Event, EventId, EventRef, EventsFrontierAccountClientState,
    EventsFrontierView, EventsSubmitFederationRequestBody, FederationServiceBindingRef, Hash, Hlc,
    MAX_EVENT_ENVELOPE_BYTES, MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_RESOLVE,
    MAX_EVENT_SUBMIT_BATCH, Operation, OperationId, Proof, RealmId, RealmSealFrontierView,
    TypedTrustDomainId, canonical, proof_kind,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::projection::{
    retention_risk_audit_flag, retention_risk_reason, retention_risk_ui_flag,
    retention_tombstone_for_event, retention_tombstone_payload_value,
};
use super::{
    append_audit_log, auth_or_render, is_valid_hash_digest, now, query_param, query_param_all,
    realm_allows_plaintext_service_for_data_class, realm_event_visible_to_session,
    realm_has_member, render_error, sha256_hex, validate_agent_participation_ceiling,
    validate_agent_reply_participation, validate_content_encryption_floor, validate_did,
    validate_operation_policy, validate_operation_semantics, validate_space_id,
};
use crate::error::{AppError, ErrorCode, error_http_status};
use crate::result::{JsonResult, json_ok};
use crate::routing::organizations;
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, CanonicalEventRecord, SessionRecord};
use crate::wire::describe;
use crate::{artifacts, kinds};

// scalability-constraints.md §2: prev_refs ≤ 128 (with MUST-dedup), refs[] total
// ≤ 128, and the `authorized_by` role ≤ 64 within that total. These are the v1
// interop maxima a conformant receiver MUST accept; a stricter local cap would
// reject another node's valid wire object (spec §1).
mod admission;
use admission::policy_components_value_from_state_payload;
pub use admission::{
    SolandEventsSubmitRequestBody, cross_signing_reset_replay_check, events_submit_pre_admit_check,
    federation_delivery_binding_frontier_is_current, frozen_realm_check,
    realm_policy_components_check, terminal_realm_check,
};

mod endpoints;
pub(crate) mod governance_proof;
pub(in crate::routing::events) use endpoints::router;

mod inception;
use inception::{
    canonical_value_digest, event_ref_list, principal_control_genesis_shape, require_object_field,
    resolve_event_root_anchor_method,
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
pub(in crate::routing) use submit::submit_event_value;
pub(super) use submit::submit_federation_events;
use submit::{
    EventValidationError, RealmBootstrapBatchContext, SubmitOneError, SubmittedEventOutcome,
    ValidatedEventEnvelope, event_validation_error, events_submit_outcome, render_submit_one_error,
    submit_event_batch, submit_event_batch_outcome,
};

mod validation;
use validation::*;
mod sdk_projection;
pub(crate) use sdk_projection::*;

#[cfg(test)]
#[path = "event_log/admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "event_log_proof_strictness_tests.rs"]
mod proof_strictness_tests;
