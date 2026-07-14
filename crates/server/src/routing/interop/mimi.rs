//! MIMI (Messaging Layer Interop) provider-facade handlers.
//!
//! Surfaces under `/_arkret/open/mimi/*` plus the well-known
//! `mimi-protocol-directory`. Writes from the MIMI side map into the
//! canonical Arkret reducer chain:
//!
//!   * `POST /mimi/strands/{strand_id}/messages` -> emits a `MessageRecord` + a `ak.message.create`
//!     projection event so the MIMI ingress shows up on the canonical Arkret timeline.
//!   * `POST /mimi/strands/{strand_id}/update` -> emits a `ak.mimi.room_binding` projection event
//!     whenever the update body carries a `room_binding` block.
//!   * `POST /mimi/strands/{strand_id}/notify` -> broadcasts a synthetic
//!     `ak.open.mimi.command.notify` projection event so live subscribers observe MIMI fanout.
//!   * `POST /mimi/report-abuse` -> persists the moderation report row AND emits a
//!     `ak.self.moderation.report` projection event so the audit timeline reflects the report.
//!
//! Each canonical event carries `payload.mimi_provenance` metadata
//! (provider id, original MIMI envelope hash, MIMI message id) so
//! the receiving Arkret consumer can prove the message arrived
//! through the MIMI facade rather than as a native signed Move.

use std::collections::BTreeMap;

use arkret_sdk::models::proof_kind;
use arkret_sdk::{
    Base64UrlString, Did, EventId, Hash, MimiDelivery, MimiDeliveryStatus, MimiGroupInfo,
    MimiGroupInfoOutcome, MimiIdentifierMatch, MimiIdentifierQueryOutcome,
    MimiIdentifierQueryRequestBody, MimiKeyMaterialOutcome, MimiKeyMaterialRequestBody,
    MimiNotifyOutcome, MimiNotifyRequestBody, MimiProxyDownloadOutcome,
    MimiProxyDownloadRequestBody, MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
    MimiRequestConsentOutcome, MimiRequestConsentRequestBody, MimiRoomUpdateOutcome,
    MimiRoomUpdateRequestBody, MimiSubmitMessageOutcome, MimiSubmitMessageRequestBody, MlsGroupId,
    MimiUpdateConsentOutcome, MimiUpdateConsentRequestBody, Proof, ReportId, canonical,
};
use chrono::Duration;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::moderation::{
    moderation_request_source_ip_hash, moderation_request_source_service,
    validate_moderation_report_safety,
};
use super::{append_audit_log, now, sha256_hex};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::http_signature::{self, SignatureBaseComponent, SignatureWindowViolation};
use crate::routing::identity::consent::{
    materialize_mimi_consent_request, materialize_mimi_consent_update_by_id,
};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, CanonicalEventRecord, MessageRecord, ProjectionEventRecord};

const EVENT_SCHEMA_ID: &str = "ak.schema.event.v1";
const MIMI_REASON_GOVERNANCE_BINDING_MISSING: &str = "mimi_governance_binding_missing";
const MIMI_REASON_GOVERNANCE_BINDING_MISMATCH: &str = "mimi_governance_binding_mismatch";
const MIMI_REASON_OBSERVER_WRITE_FORBIDDEN: &str = "mimi_observer_write_forbidden";
const MIMI_REASON_ROOM_STATE_INCOMPATIBLE: &str = "mimi_room_state_incompatible";
const MIMI_REASON_ROOM_BINDING_TRANSITION_INVALID: &str =
    "mimi_room_binding_status_transition_invalid";

struct MimiRoomBindingProjection {
    event_id: String,
    realm_id: String,
    binding: Value,
}

mod binding;
mod handlers;
mod payload;
mod signature;

use binding::*;
use handlers::*;
use payload::*;
use signature::*;

pub(super) fn router() -> Router {
    Router::with_path("mimi")
        .push(Router::with_path("provider-directory").get(mimi_provider_directory))
        .push(Router::with_path("key-material").post(mimi_key_material))
        .push(Router::with_path("strands/{strand_id}/update").post(mimi_room_update))
        .push(Router::with_path("strands/{strand_id}/notify").post(mimi_notify))
        .push(Router::with_path("strands/{strand_id}/messages").post(mimi_room_message))
        .push(Router::with_path("strands/{strand_id}/group-info").get(mimi_group_info))
        .push(Router::with_path("consent/request").post(mimi_consent_request))
        .push(Router::with_path("consent/update").post(mimi_consent_update))
        .push(Router::with_path("identifiers/query").post(mimi_identifiers_query))
        .push(Router::with_path("report-abuse").post(mimi_report_abuse))
        .push(Router::with_path("proxy-download").post(mimi_proxy_download))
}

pub(super) fn well_known_router() -> Router {
    Router::with_path(".well-known/mimi-protocol-directory").get(mimi_protocol_directory)
}
