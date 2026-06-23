//! Identity / DID handlers.
//!
//! Surfaces:
//! - `GET  /_cokret/root/identity/describe`     — service identity capability descriptor
//! - `POST /_cokret/root/identity/resolve`      — resolve a DID via SDK + local store
//! - `GET  /_cokret/root/identity/document`     — fetch the locally-cached DID document
//! - `GET  /_cokret/root/identity/log`          — return the local key log for a DID
//! - `POST /_soland/root/identity/webvh/register` — register through the embedded webvh provider
//! - `GET  /webvh/{local_id}/did.json` — embedded webvh DID document
//! - `GET  /webvh/{local_id}/did.jsonl` — embedded webvh log
//! - `POST /_cokret/root/identity/submit-did-operation` — submit a DID operation
//! - `GET  /_cokret/root/identity/receipts`     — issuer receipts for the local key log
//!
//! All long-term state lives behind `state.persistence.webvh()`; the
//! `did_resolver` is still an in-process resolver chain. Production must move it onto a
//! durable store (see todo F2) — currently in-memory.

use cokret_sdk::http::IdentityDocumentViewOutcome;
use cokret_sdk::identity::DidResolver;
use cokret_sdk::{
    Did, DidDocumentRef, DidOperationSubmitOutcome, DidOperationSubmitRequestBody, Hash,
    IdentityDocumentView, IdentityResolveOutcome,
};
use salvo::http::{StatusCode, header};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::webvh_validation::{
    WebvhLogEntry, derive_webvh_scid_from_skeleton, validate_log_chain,
    validate_witness_policy_for_log, verify_scid_against_did, verify_webvh_log_proof,
    webvh_entry_hash_multibase,
};
use super::{append_audit_log, bearer_token, now, render_error, sha256_hex, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, WebvhDocumentRecord, WebvhLogRecord};
use crate::wire::{IdentityLogOutcome, IdentityReceiptsOutcome, IdentityResolveRequestBody};

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";

mod document;
mod endpoints;
mod webvh;

// Used by routing::tests and directory handle verification.
pub(in crate::routing) use document::identity_document_record;
#[cfg(test)]
pub(in crate::routing) use document::validate_did_document_services;
use document::{
    did_document_from_operation, did_operation_from_body, ensure_did_document_id,
    render_json_bytes, run_webvh_resolution_checks, string_field,
};
// Endpoint handlers referenced by identity/mod.rs router().
pub(super) use endpoints::{
    embedded_webvh_document, embedded_webvh_log, embedded_webvh_register, identity_describe,
    identity_did_document, identity_document, identity_log, identity_receipts, identity_resolve,
    identity_submit_did_operation,
};
use webvh::*;
