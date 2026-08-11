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

use arkret_identifiers::{DidFullId, EventId, Hash, ReportId};
use arkret_models_collaboration::http_bodies::{
    MimiGroupInfoOutcome, MimiIdentifierQueryOutcome, MimiIdentifierQueryRequestBody,
    MimiKeyMaterialOutcome, MimiKeyMaterialRequestBody, MimiNotifyOutcome, MimiNotifyRequestBody,
    MimiProxyDownloadOutcome, MimiProxyDownloadRequestBody, MimiReportAbuseOutcome,
    MimiReportAbuseRequestBody, MimiRequestConsentOutcome, MimiRequestConsentRequestBody,
    MimiRoomUpdateOutcome, MimiRoomUpdateRequestBody, MimiSubmitMessageOutcome,
    MimiSubmitMessageRequestBody, MimiUpdateConsentOutcome, MimiUpdateConsentRequestBody,
};
use arkret_models_collaboration::objects::mimi::{
    MimiConsentPurpose, MimiConsentTargetKind, MimiDelivery, MimiDeliveryStatus, MimiGroupInfo,
    MimiIdentifierMatch,
};
use arkret_signatures::http_signature::{
    Component, HttpMessageVerificationError, SignatureError, SignatureInput, SignaturePolicyError,
    SignatureVerificationPolicy,
};
use arkret_wire::{Audience, Base64UrlString, MlsGroupId};
use chrono::Duration;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::http_signature;
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::MimiConsentCorrelation;

use super::moderation::{
    moderation_request_source_ip_hash, moderation_request_source_service,
    persist_mimi_facade_moderation_report_event, validate_moderation_report_safety,
};
use super::{append_audit_log, now};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

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
