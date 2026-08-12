//! Identity / DID handlers.
//!
//! Surfaces:
//! - `GET  /_arkret/root/identity/describe`     — service identity capability descriptor
//! - `POST /_arkret/root/identity/resolve`      — resolve a DID via SDK + local store
//! - `GET  /_arkret/root/identity/document`     — fetch the locally-cached DID document
//! - `GET  /_arkret/root/identity/log`          — return the local key log for a DID
//! - `POST /_soland/root/identity/webvh/register` — register through the embedded webvh provider
//! - `GET  /webvh/{local_id}/did.json` — embedded webvh DID document
//! - `GET  /webvh/{local_id}/did.jsonl` — embedded webvh log
//! - `POST /_arkret/root/identity/submit-did-operation` — submit a DID operation
//! - `GET  /_arkret/root/identity/receipts`     — issuer receipts for the local key log
//!
//! Long-term DID state is accessed through the identity application service; the
//! `did_resolver` remains an in-process bounded cache over durable records.

use arkret_identifiers::{DidCoreId, DidFullId, Hash};
use arkret_models_identity::http_bodies::IdentityDocumentViewOutcome;
use arkret_models_identity::identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDocumentView,
    IdentityResolveOutcome,
};
use salvo::http::{StatusCode, header};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::{
    DidDocumentState as WebvhDocumentRecord, DidLogCommitResult as WebvhLogCommitOutcome,
    DidLogEvent as WebvhLogRecord,
};

use super::webvh_validation::{
    WebvhLogEntry, derive_webvh_scid_from_skeleton, validate_log_chain,
    validate_rotation_authorization_for_log, validate_witness_policy_for_log, verify_log_subject,
    verify_scid_against_did, verify_webvh_log_proof, webvh_entry_hash_multibase,
};
use super::{append_audit_log, bearer_token, now, render_error, sha256_hex, validate_did};
use crate::state::AppState;
use crate::wire::{IdentityLogListOutcome, IdentityReceiptListOutcome, IdentityResolveRequestBody};

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";

mod document;
mod endpoints;
mod webvh;

// Used by routing::tests and directory handle verification.
pub(in crate::routing) use document::identity_document_record;
#[cfg(test)]
pub(in crate::routing) use document::validate_did_document_services;
use document::{render_json_bytes, run_webvh_resolution_checks};
// Endpoint handlers referenced by identity/mod.rs router().
pub(super) use endpoints::{
    embedded_webvh_document, embedded_webvh_log, embedded_webvh_register, embedded_webvh_rotate,
    identity_describe, identity_did_document, identity_document, identity_log, identity_receipts,
    identity_resolve, identity_submit_did_operation,
};
pub(in crate::routing::identity) use webvh::*;
