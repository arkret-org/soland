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
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Verifier, VerifyingKey};
use salvo::http::{StatusCode, header};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_witness_policy_for_log, verify_scid_against_did,
};
use super::{append_audit_log, bearer_token, now, render_error, sha256_hex, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, WebvhDocumentRecord, WebvhLogRecord};
use crate::wire::{IdentityLogOutcome, IdentityReceiptsOutcome, IdentityResolveRequestBody};

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
#[serde(transparent)]
pub struct RawDidDocumentJson(
    #[salvo(schema(value_type = serde_json::Value))] pub serde_json::Value,
);

#[endpoint(
    operation_id = "ck.root.identity.registry.query.describe",
    tags("identity"),
    summary = "Identity registry capability description"
)]
#[tracing::instrument(skip_all, fields(op = "identity_describe"))]
pub(super) async fn identity_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did_webvh = did_webvh_descriptor(state);
    let mut profiles = vec![
        "ck.profile.identity_registry.v1".to_owned(),
        "ck.identity.local-dev.v1".to_owned(),
    ];
    if did_webvh["enabled"].as_bool().unwrap_or(false) {
        profiles.push("ck.identity.webvh.provider.v1".to_owned());
    }
    if let Err(error) = Did::new(state.config.service_did.clone()) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("invalid configured service_did: {error}"),
        );
        return;
    };
    let supported_did_methods = state
        .config
        .did_resolver_allow_methods
        .iter()
        .map(|method| format!("did:{method}"))
        .collect::<Vec<_>>();
    let trust_roots = identity_trust_roots(state);
    let supported_features = vec![
        "ck.feature.identity.resolve.v1",
        "ck.feature.identity.receipts.v1",
        "ck.feature.identity.did_webvh.v1",
    ];

    res.render(Json(json!({
        "protocol_version": cokret_sdk::PROTOCOL_VERSION,
        "service_type": "identity_registry",
        "service_did": state.config.service_did,
        "trust_domain": state.config.trust_domain,
        "registry_mode": "development_local",
        "supported_receipts": ["local"],
        "profiles": profiles,
        "supported_profiles": profiles,
        "supported_operations": [
            "ck.root.identity.registry.query.describe",
            "ck.root.identity.query.resolve",
            "ck.root.identity.document.resource.get",
            "ck.root.identity.log.query.list",
            "ck.root.identity.receipts.query.list",
            "ck.root.identity.command.submit_did_operation"
        ],
        "supported_bindings": [{
            "kind": "http",
            "base_url": state.config.public_base_url,
            "paths": [
                "/_cokret/root/identity/describe",
                "/_cokret/root/identity/resolve",
                "/_cokret/root/identity/document",
                "/_cokret/root/identity/log",
                "/_cokret/root/identity/receipts",
                "/_cokret/root/identity/submit-did-operation"
            ]
        }],
        "supported_features": supported_features,
        "auth_metadata": {
            "mode": if state.config.development_mode { "development" } else { "production" },
            "read": "public_metadata"
        },
        "limits": {},
        "plaintext_visibility": {
            "default": "metadata_only",
            "services": []
        },
        "implemented_features": supported_features,
        "claimed_profiles": [{
            "profile_id": "ck.profile.identity_registry.v1",
            "claim_kind": "self_claimed"
        }],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": state.config.development_mode,
        "rate_limit_policy": {
            "kind": "windowed",
            "per_minute": 600
        },
        "supported_did_methods": supported_did_methods,
        "resolver_policy": {
            "allow_methods": state.config.did_resolver_allow_methods,
            "freshness_receipts": {
                "endpoint_template": "/_cokret/root/identity/receipts?did={did}"
            },
            "webvh_validation": {
                "witness_quorum": "enforced_for_local_webvh_records"
            },
            "trust_roots": trust_roots
        },
        "registry_visibility": {
            "mode": "development_local",
            "public_resolution": true,
            "public_receipts": true,
            "write_policy": "local_registry"
        },
        "did_webvh": did_webvh,
        "todos": []
    })));
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EmbeddedWebvhRegisterRequestBody {
    #[serde(default)]
    pub local_id: Option<String>,
    pub did_public_key_multibase: String,
    pub update_public_key_multibase: String,
    #[serde(default)]
    pub did_key_id: Option<String>,
    #[serde(default)]
    pub update_key_id: Option<String>,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub version_time: Option<String>,
    #[serde(default)]
    pub proof: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EmbeddedWebvhRegisterOutcome {
    pub status: String,
    pub provider_id: String,
    pub did: String,
    pub did_key_id: String,
    pub update_key_id: String,
    pub did_public_key_multibase: String,
    pub update_public_key_multibase: String,
    pub seq: u64,
    pub key_log_head: String,
    pub document_url: String,
    pub log_url: String,
    pub did_document: Value,
    pub did_log: Vec<Value>,
}

#[endpoint(
    operation_id = "org.cokret.soland.identity.webvh.register",
    tags("identity"),
    summary = "Register through the embedded did:webvh provider",
    status_codes(201, 400, 401, 404, 409, 500, 503)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.identity.webvh.register"))]
pub(super) async fn embedded_webvh_register(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<EmbeddedWebvhRegisterRequestBody>,
) -> JsonResult<EmbeddedWebvhRegisterOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    if !state.config.embedded_webvh_provider_enabled {
        return Err(AppError::not_found(
            "embedded did:webvh provider is disabled",
        ));
    }
    require_embedded_webvh_registration_bearer(state, req)?;
    let body = body.into_inner();
    if !valid_multibase_key(&body.did_public_key_multibase) {
        return Err(AppError::invalid_param(
            "did_public_key_multibase must be a non-empty multibase value",
        ));
    }
    if !valid_multibase_key(&body.update_public_key_multibase) {
        return Err(AppError::invalid_param(
            "update_public_key_multibase must be a non-empty multibase value",
        ));
    }
    if body.did_public_key_multibase == body.update_public_key_multibase {
        return Err(AppError::invalid_param(
            "did_public_key_multibase and update_public_key_multibase must be separate keys",
        ));
    }
    let version_time = match body.version_time.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => {
            if chrono::DateTime::parse_from_rfc3339(value).is_err() {
                return Err(AppError::invalid_param(
                    "version_time must be an RFC3339 timestamp",
                ));
            }
            value.to_owned()
        }
        _ => {
            return Err(AppError::invalid_param(
                "version_time is required so the client can sign the webvh log entry",
            ));
        }
    };
    let Some(proof) = body.proof.clone() else {
        return Err(AppError::unauthenticated(
            "embedded did:webvh registration requires a client-signed log proof",
        ));
    };
    let local_id = body
        .local_id
        .as_deref()
        .and_then(normalize_webvh_local_id)
        .or_else(|| {
            let digest = sha256_hex(body.did_public_key_multibase.as_bytes());
            normalize_webvh_local_id(&format!("user-{}", &digest[..12]))
        })
        .ok_or_else(|| AppError::invalid_param("invalid local_id"))?;
    let did_key_fragment =
        normalize_webvh_key_fragment(body.did_key_id.as_deref().unwrap_or("did-key-1"))
            .ok_or_else(|| AppError::invalid_param("invalid did_key_id"))?;
    let update_key_fragment =
        normalize_webvh_key_fragment(body.update_key_id.as_deref().unwrap_or("update-key-1"))
            .ok_or_else(|| AppError::invalid_param("invalid update_key_id"))?;
    let (method_authority, https_authority) =
        embedded_webvh_authority(&state.config.public_base_url).map_err(|message| {
            AppError::new(ErrorCode::TemporarilyUnavailable, message)
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    if state
        .persistence
        .webvh()
        .get_embedded_webvh_document_by_local_id(&local_id)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "embedded did:webvh local_id is already registered",
        ));
    }

    let now = now();
    let placeholder_did = embedded_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let did_key_id = format!("{}#{}", placeholder_did, did_key_fragment);
    let service_endpoint = state
        .config
        .public_base_url
        .trim_end_matches('/')
        .to_owned();
    let did_document_skeleton = embedded_webvh_document_value(
        &placeholder_did,
        &did_key_id,
        body.did_public_key_multibase.as_str(),
        &body.also_known_as,
        service_endpoint.as_str(),
    );
    let entry_skeleton = json!({
        "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [body.update_public_key_multibase.clone()],
        },
        "state": did_document_skeleton,
    });
    let scid = derive_webvh_scid(&entry_skeleton).map_err(AppError::invalid_param)?;
    let location =
        embedded_webvh_location_with_scid(&method_authority, &https_authority, &local_id, &scid);
    let did_key_id = format!("{}#{}", location.did, did_key_fragment);
    let update_key_id = format!("{}#{}", location.did, update_key_fragment);
    let mut log_entry = substitute_webvh_scid(entry_skeleton, &scid);
    let version_hash = webvh_entry_hash_multibase(&log_entry).map_err(AppError::invalid_param)?;
    let version_id = format!("1-{version_hash}");
    if let Value::Object(map) = &mut log_entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
        map.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    let did_document = log_entry
        .get("state")
        .cloned()
        .unwrap_or_else(|| json!({"id": location.did}));
    if let Err(message) = verify_webvh_log_proof(&log_entry) {
        return Err(AppError::new(ErrorCode::InvalidSignature, message)
            .with_status(StatusCode::UNAUTHORIZED));
    }
    if let Err(error) = state
        .persistence
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: location.did.clone(),
            did_document: did_document.clone(),
            key_log_head: Some(version_id.clone()),
            seq: 1,
            method_evidence: json!({
                "mode": "embedded_webvh_provider",
                "provider_id": "soland.embedded",
                "local_id": local_id,
                "document_url": location.document_url,
                "log_url": location.log_url,
                "scid": location.scid,
                "updateKeys": [body.update_public_key_multibase.clone()],
            }),
            // put_document authoritatively overwrites freshness evidence with
            // the ingestion instant, so placeholders are enough here.
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        })
        .await
    {
        tracing::error!(%error, "failed to persist embedded webvh document");
        return Err(AppError::internal(
            "failed to persist embedded webvh document",
        ));
    }
    if let Err(error) = state
        .persistence
        .webvh()
        .append_log_event(WebvhLogRecord {
            event_digest: version_id.clone(),
            did: location.did.clone(),
            seq: 1,
            operation: log_entry.clone(),
            created_at: now,
        })
        .await
    {
        tracing::error!(%error, "failed to append embedded webvh log entry");
        return Err(AppError::internal(
            "failed to append embedded webvh log entry",
        ));
    }
    append_audit_log(
        state,
        Some(&location.did),
        "identity.webvh_register",
        json!({
            "did": location.did,
            "local_id": local_id,
            "provider_id": "soland.embedded",
            "version_id": version_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    json_ok(EmbeddedWebvhRegisterOutcome {
        status: "created".to_owned(),
        provider_id: "soland.embedded".to_owned(),
        did: location.did,
        did_key_id,
        update_key_id,
        did_public_key_multibase: body.did_public_key_multibase,
        update_public_key_multibase: body.update_public_key_multibase,
        seq: 1,
        key_log_head: version_id,
        document_url: location.document_url,
        log_url: location.log_url,
        did_document,
        did_log: vec![log_entry],
    })
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "embedded_webvh_document"))]
pub(super) async fn embedded_webvh_document(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res).await else {
        return;
    };
    render_json_bytes(
        res,
        "application/did+json; charset=utf-8",
        &record.did_document,
    );
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "embedded_webvh_log"))]
pub(super) async fn embedded_webvh_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res).await else {
        return;
    };
    let events = state
        .persistence
        .webvh()
        .list_log_events(&record.did)
        .await
        .unwrap_or_default();
    if events.is_empty() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "did log not found");
        return;
    }
    let mut body = String::new();
    for event in events {
        body.push_str(&serde_json::to_string(&event.operation).unwrap_or_else(|_| "{}".to_owned()));
        body.push('\n');
    }
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/jsonl; charset=utf-8".parse().unwrap(),
    );
    res.headers_mut().insert(
        header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    res.write_body(body.into_bytes()).ok();
}

#[endpoint(
    operation_id = "ck.root.identity.query.resolve",
    tags("identity"),
    summary = "Resolve a DID via local webvh store + SDK resolver chain"
)]
#[tracing::instrument(skip_all, fields(op = "ck.root.identity.query.resolve"))]
pub(super) async fn identity_resolve(
    body: JsonBody<IdentityResolveRequestBody>,
    depot: &mut Depot,
) -> JsonResult<IdentityResolveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = body.did.as_str();
    if let Ok(Some(record)) = state.persistence.webvh().get_document(did).await {
        // G3.S3: every did:webvh resolution MUST first re-validate the
        // log chain, SCID derivation, and configured witness quorum.
        // Rotation entries fail closed when witness quorum is missing;
        // non-rotation entries may only remain in degraded_no_witness
        // for the spec's 24h window. Spec: identity-did.md §3.4 +
        // §4.2.1.
        //
        // TODO(G3.S3-followup): emergency rotation path
        // (key-management.md §3.3 recovery key). Today rotation entries
        // must be controller-signed; recovery-key-only rotations are
        // not yet accepted.
        if did.starts_with("did:webvh:") {
            run_webvh_resolution_checks(state, did).await?;
        }
        return json_ok(identity_resolve_outcome(
            body.did,
            record.did_document,
            key_log_head_hash(record.key_log_head)?,
            Some(record.seq),
            record.method_evidence,
        ));
    }
    let sdk_document = {
        state
            .did_resolver
            .lock()
            .expect("did resolver lock")
            .resolve_did(&body.did)
            .ok()
    };
    if let Some(doc) = sdk_document {
        return json_ok(identity_resolve_outcome(
            body.did,
            json!({
                "id": doc.id.as_str(),
                "verificationMethod": doc.verification_methods,
                "alsoKnownAs": doc.also_known_as,
            }),
            None,
            None,
            json!({"mode": "sdk_resolver", "source": "did_resolver"}),
        ));
    }
    let record = identity_document_record(state, did).await;
    json_ok(identity_resolve_outcome(
        body.did,
        record.did_document,
        key_log_head_hash(record.key_log_head)?,
        Some(record.seq),
        record.method_evidence,
    ))
}

#[endpoint(
    operation_id = "ck.root.identity.document.resource.get",
    tags("identity"),
    summary = "Fetch the locally-cached DID document for a DID"
)]
#[tracing::instrument(skip_all, fields(op = "ck.root.identity.document.resource.get"))]
pub(super) async fn identity_document(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityDocumentViewOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let typed_did = Did::new(did.clone()).map_err(|_| AppError::invalid_param("invalid did"))?;
    let record = identity_document_record(state, &did).await;
    let head_event_digest = key_log_head_hash(record.key_log_head.clone())?;
    json_ok(IdentityDocumentViewOutcome(IdentityDocumentView {
        did_document: DidDocumentRef {
            did: typed_did,
            document: record.did_document,
        },
        head_event_digest,
        seq: Some(record.seq),
        receipts: Vec::new(),
    }))
}

fn key_log_head_hash(value: Option<String>) -> Result<Option<Hash>, AppError> {
    value
        .map(Hash::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("invalid key_log_head digest: {error}")))
}

fn identity_resolve_outcome(
    did: Did,
    document: Value,
    key_log_head: Option<Hash>,
    seq: Option<u64>,
    method_evidence: Value,
) -> IdentityResolveOutcome {
    IdentityResolveOutcome {
        did_document: DidDocumentRef { did, document },
        key_log_head,
        seq,
        receipts: Vec::new(),
        method_evidence,
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.identity.get_path_did_document",
    tags("identity"),
    summary = "Fetch a DID document by DID path segment"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.identity.get_path_did_document")
)]
pub(super) async fn identity_did_document(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<RawDidDocumentJson> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = req
        .param::<String>("did")
        .ok_or_else(|| AppError::missing_param("did path segment required"))?;
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    if let Some(document) =
        crate::routing::extensions::applet_bridge::did_document_for_extension_actor(state, &did)
            .await?
    {
        return json_ok(RawDidDocumentJson(document));
    }
    let record = identity_document_record(state, &did).await;
    json_ok(RawDidDocumentJson(record.did_document))
}

#[endpoint(
    operation_id = "ck.root.identity.log.query.list",
    tags("identity"),
    summary = "Return the local webvh key-log events for a DID"
)]
#[tracing::instrument(skip_all, fields(op = "ck.root.identity.log.query.list"))]
pub(super) async fn identity_log(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityLogOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let events = state
        .persistence
        .webvh()
        .list_log_events(&did)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|event| {
            json!({
                "event_digest": event.event_digest,
                "did": event.did,
                "seq": event.seq,
                "operation": event.operation,
                "created_at": event.created_at,
            })
        })
        .collect();
    json_ok(IdentityLogOutcome {
        events,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ck.root.identity.receipts.query.list",
    tags("identity"),
    summary = "Read issuer receipts for the local webvh key-log of a DID"
)]
#[tracing::instrument(skip_all, fields(op = "ck.root.identity.receipts.query.list"))]
pub(super) async fn identity_receipts(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityReceiptsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let record = state
        .persistence
        .webvh()
        .get_document(&did)
        .await
        .ok()
        .flatten();
    json_ok(IdentityReceiptsOutcome {
        receipts: record
            .map(|record| {
                vec![json!({
                    "service_did": state.config.service_did.clone(),
                    "did": record.did,
                    "head_event_digest": record.key_log_head,
                    "seq": record.seq,
                    "issued_at": record.updated_at,
                })]
            })
            .unwrap_or_default(),
        threshold_met: Some(true),
    })
}

#[endpoint(
    operation_id = "ck.root.identity.command.submit_did_operation",
    tags("identity"),
    summary = "Submit a method-neutral DID operation to the local registry",
    status_codes(200, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.root.identity.command.submit_did_operation"))]
pub(super) async fn identity_submit_did_operation(
    depot: &mut Depot,
    body: JsonBody<DidOperationSubmitRequestBody>,
) -> JsonResult<DidOperationSubmitOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = serde_json::to_value(body.into_inner())
        .map_err(|error| AppError::internal(format!("DID operation serialize: {error}")))?;
    let did = string_field(&body, "did")
        .or_else(|| {
            body.get("operation")
                .and_then(|operation| operation.get("did"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            body.get("operation")
                .and_then(|operation| operation.get("state"))
                .and_then(|state| state.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            body.get("did_document")
                .and_then(|document| document.get("id"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| AppError::invalid_param("did is required"))?
        .to_owned();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let typed_did = Did::new(did.clone()).map_err(|_| AppError::invalid_param("invalid did"))?;

    let existing = state
        .persistence
        .webvh()
        .get_document(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let next_seq = body
        .get("seq")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| existing.as_ref().map_or(1, |record| record.seq + 1));
    if existing
        .as_ref()
        .is_some_and(|record| next_seq <= record.seq)
    {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "DID operation seq must advance the current document",
        ));
    }

    let operation = did_operation_from_body(&body)?;
    let mut document = did_document_from_operation(&did, existing.as_ref(), &body, &operation)?;
    ensure_did_document_id(&did, &mut document)?;
    let submitted_at = now();
    let event_payload = json!({
        "did": did.clone(),
        "seq": next_seq,
        "previous": existing.as_ref().and_then(|record| record.key_log_head.clone()),
        "operation": operation,
        "submitted_at": submitted_at,
    });
    let event_digest = format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(&event_payload).unwrap_or_default())
    );
    let method_evidence = json!({
        "mode": "submitted_operation",
        "source": "ck.root.identity.command.submit_did_operation",
        "previous": existing
            .as_ref()
            .map(|record| record.method_evidence.clone())
            .unwrap_or_else(|| json!({"mode": "development_local"})),
    });
    state
        .persistence
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.clone(),
            did_document: document.clone(),
            key_log_head: Some(event_digest.clone()),
            seq: next_seq,
            method_evidence,
            // put_document authoritatively overwrites freshness evidence with
            // the ingestion instant, so placeholders are enough here.
            fetched_at: submitted_at,
            expires_at: submitted_at,
            updated_at: submitted_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .persistence
        .webvh()
        .append_log_event(WebvhLogRecord {
            event_digest: event_digest.clone(),
            did: did.clone(),
            seq: next_seq,
            operation: event_payload,
            created_at: submitted_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&did),
        "identity.submit_did_operation",
        json!({
            "did": did.clone(),
            "seq": next_seq,
            "head_event_digest": event_digest.clone(),
        }),
        "accepted",
    )
    .await;
    let head_event_digest = Hash::new(event_digest.clone()).map_err(|error| {
        AppError::internal(format!(
            "DID operation digest failed SDK type validation: {error}"
        ))
    })?;
    json_ok(DidOperationSubmitOutcome {
        status: "accepted".to_owned(),
        did: typed_did,
        seq: Some(next_seq),
        head_event_digest: Some(head_event_digest),
        operation_ref: None,
        receipts: vec![json!({
            "service_did": state.config.service_did.clone(),
            "did": did,
            "head_event_digest": event_digest,
            "seq": next_seq,
            "issued_at": submitted_at,
        })],
    })
}

#[derive(Clone, Debug)]
struct EmbeddedWebvhLocation {
    did: String,
    scid: String,
    document_url: String,
    log_url: String,
}

fn identity_trust_roots(state: &AppState) -> Vec<Value> {
    let mut trust_roots = vec![json!({
        "id": "soland.local_identity_store",
        "kind": "local_identity_store",
        "profile": "ck.profile.identity_registry.v1",
        "service_did": state.config.service_did,
        "trust_domain": state.config.trust_domain,
        "proof_verification": {
            "controller_proof": "eddsa-jcs-2022",
            "webvh_log_chain": "required",
            "webvh_scid": "required",
            "webvh_witness_quorum": "required_when_policy_present"
        }
    })];
    if let Some(url) = state.config.external_webvh_provider_url.as_deref() {
        trust_roots.push(json!({
            "id": "external.webvh",
            "kind": "external",
            "profile": "ck.identity.webvh.provider.v1",
            "base_url": url,
            "expected_trust_domain": state.config.trust_domain
        }));
    }
    trust_roots
}

fn did_webvh_descriptor(state: &AppState) -> Value {
    let embedded_id = "soland.embedded";
    let external_id = "external.webvh";
    let embedded_enabled = state.config.embedded_webvh_provider_enabled;
    let embedded_registration_auth_configured = state
        .config
        .embedded_webvh_registration_bearer
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let embedded_authority = embedded_webvh_authority(&state.config.public_base_url);
    let external_enabled = state.config.external_webvh_provider_url.is_some();
    let default_provider_id = state
        .config
        .default_webvh_provider_id
        .as_deref()
        .filter(|id| {
            (*id == embedded_id && embedded_enabled) || (*id == external_id && external_enabled)
        })
        .map(ToOwned::to_owned)
        .or_else(|| embedded_enabled.then(|| embedded_id.to_owned()))
        .or_else(|| external_enabled.then(|| external_id.to_owned()));

    let mut providers = Vec::new();
    if embedded_enabled {
        let (active, probe, document_url_template, log_url_template) = match &embedded_authority {
            Ok((_, https_authority)) => {
                let document_url_template = Some(format!(
                    "https://{https_authority}/webvh/{{local_id}}/did.json"
                ));
                let log_url_template = Some(format!(
                    "https://{https_authority}/webvh/{{local_id}}/did.jsonl"
                ));
                if embedded_registration_auth_configured {
                    (
                        true,
                        "ok".to_owned(),
                        document_url_template,
                        log_url_template,
                    )
                } else {
                    (
                        false,
                        "missing_registration_bearer".to_owned(),
                        document_url_template,
                        log_url_template,
                    )
                }
            }
            Err(message) => (false, message.clone(), None, None),
        };
        providers.push(json!({
            "id": embedded_id,
            "kind": "embedded",
            "label": "Soland embedded did:webvh",
            "method": "did:webvh",
            "default": default_provider_id.as_deref() == Some(embedded_id),
            "active": active,
            "registration_url": format!("{}/_soland/root/identity/webvh/register", state.config.public_base_url.trim_end_matches('/')),
            "resolver_url": format!("{}/_cokret/root/identity", state.config.public_base_url.trim_end_matches('/')),
            "document_url_template": document_url_template,
            "log_url_template": log_url_template,
            "registration_auth": {
                "required": true,
                "mode": "bearer",
                "header": "Authorization",
                "scheme": "Bearer",
                "configured": embedded_registration_auth_configured,
            },
            "health": {
                "active": active,
                "probe": probe,
            },
        }));
    }
    if let Some(url) = &state.config.external_webvh_provider_url {
        providers.push(json!({
            "id": external_id,
            "kind": "external",
            "label": "External did:webvh provider",
            "method": "did:webvh",
            "default": default_provider_id.as_deref() == Some(external_id),
            "active": state.config.external_webvh_provider_active,
            "base_url": url,
            // STA-07-002 — advertise the canonical generic server-describe
            // endpoint (operation_id ck.server.query.describe) the resolver
            // freshness probe now targets, not the retired starid
            // `<URL>/describe`.
            "describe_url": format!(
                "{}{}",
                url.trim_end_matches('/'),
                crate::state::did_resolver_chain::CANONICAL_DESCRIBE_PATH
            ),
            "freshness_probe": crate::state::did_resolver_chain::CANONICAL_DESCRIBE_PATH,
            "health": {
                "active": state.config.external_webvh_provider_active,
                "probe": if state.config.external_webvh_provider_active {
                    "ok"
                } else {
                    "probe_failed_at_boot"
                },
            },
        }));
    }

    let enabled = !providers.is_empty();
    let provider_count = providers.len();
    let default_missing = default_provider_id.is_none();
    json!({
        "method": "did:webvh",
        "profile": "ck.identity.webvh.provider.v1",
        "enabled": enabled,
        "default_provider_id": default_provider_id,
        "providers": providers,
        "selection": {
            "coauth_prompt": provider_count > 1,
            "required_when_default_missing": default_missing,
        },
    })
}

fn require_embedded_webvh_registration_bearer(
    state: &AppState,
    req: &Request,
) -> Result<(), AppError> {
    let Some(expected) = state
        .config
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "embedded did:webvh registration requires SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        )
        .with_status(StatusCode::SERVICE_UNAVAILABLE));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "embedded did:webvh registration requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid embedded did:webvh registration bearer",
        ));
    }
    Ok(())
}

async fn embedded_webvh_record_for_request(
    state: &AppState,
    req: &mut Request,
    res: &mut Response,
) -> Option<WebvhDocumentRecord> {
    if !state.config.embedded_webvh_provider_enabled {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "embedded did:webvh provider is disabled",
        );
        return None;
    }
    let Some(raw_local_id) = req.param::<String>("local_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "local_id is required",
        );
        return None;
    };
    let Some(local_id) = normalize_webvh_local_id(&raw_local_id) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid local_id",
        );
        return None;
    };
    match state
        .persistence
        .webvh()
        .get_embedded_webvh_document_by_local_id(&local_id)
        .await
    {
        Ok(Some(record)) => Some(record),
        Ok(None) => {
            render_error(
                res,
                StatusCode::NOT_FOUND,
                "not_found",
                "did document not found",
            );
            None
        }
        Err(error) => {
            tracing::error!(%error, "failed to read embedded webvh document");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read did document",
            );
            None
        }
    }
}

fn embedded_webvh_location_with_scid(
    method_authority: &str,
    https_authority: &str,
    local_id: &str,
    scid: &str,
) -> EmbeddedWebvhLocation {
    let path_url = format!("webvh/{local_id}");
    EmbeddedWebvhLocation {
        did: embedded_webvh_did(method_authority, scid, local_id),
        scid: scid.to_owned(),
        document_url: format!("https://{https_authority}/{path_url}/did.json"),
        log_url: format!("https://{https_authority}/{path_url}/did.jsonl"),
    }
}

fn embedded_webvh_did(method_authority: &str, scid: &str, local_id: &str) -> String {
    format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}")
}

fn embedded_webvh_authority(public_base_url: &str) -> Result<(String, String), String> {
    let parsed = reqwest::Url::parse(public_base_url)
        .map_err(|e| format!("SOLAND_PUBLIC_BASE_URL is not a valid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "SOLAND_PUBLIC_BASE_URL must include a host".to_owned())?;
    if !host.contains('.') {
        return Err("SOLAND_PUBLIC_BASE_URL host must contain a dot for did:webvh".to_owned());
    }
    let method_authority = match parsed.port() {
        Some(port) => format!("{host}%3A{port}"),
        None => host.to_owned(),
    };
    let https_authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok((method_authority, https_authority))
}

fn embedded_webvh_document_value(
    did: &str,
    did_key_id: &str,
    did_public_key_multibase: &str,
    also_known_as: &[String],
    service_endpoint: &str,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": did_key_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": did_public_key_multibase,
        }],
        "authentication": [did_key_id],
        "assertionMethod": [did_key_id],
        "alsoKnownAs": also_known_as,
        "service": [{
            "id": format!("{did}#soland"),
            "type": "CokretPrincipalServer",
            "serviceEndpoint": service_endpoint,
        }],
    })
}

fn derive_webvh_scid(skeleton: &Value) -> Result<String, String> {
    if !contains_webvh_placeholder(skeleton) {
        return Err(format!(
            "inception log entry must contain {WEBVH_SCID_PLACEHOLDER} placeholders"
        ));
    }
    let canonical =
        cokret_sdk::canonical::canonical_json_bytes(skeleton).map_err(|error| error.to_string())?;
    Ok(sha256_multihash_multibase(&canonical))
}

fn contains_webvh_placeholder(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains(WEBVH_SCID_PLACEHOLDER),
        Value::Array(items) => items.iter().any(contains_webvh_placeholder),
        Value::Object(map) => map.values().any(contains_webvh_placeholder),
        _ => false,
    }
}

fn substitute_webvh_scid(value: Value, scid: &str) -> Value {
    let Ok(text) = serde_json::to_string(&value) else {
        return value;
    };
    serde_json::from_str(&text.replace(WEBVH_SCID_PLACEHOLDER, scid)).unwrap_or(value)
}

fn webvh_entry_hash_multibase(value: &Value) -> Result<String, String> {
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&strip_webvh_entry_for_hash(value))
        .map_err(|error| error.to_string())?;
    Ok(sha256_multihash_multibase(&canonical))
}

fn strip_webvh_entry_for_hash(value: &Value) -> Value {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.remove("versionId");
    }
    clone
}

fn sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    format!("z{}", bs58::encode(multihash).into_string())
}

fn verify_webvh_log_proof(entry: &Value) -> Result<(), String> {
    let proof = entry
        .get("proof")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or_else(|| "entry must include proof[0]".to_owned())?;
    let proof_type = proof
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proof_type != "DataIntegrityProof" {
        return Err("proof type must be DataIntegrityProof".to_owned());
    }
    let cryptosuite = proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if cryptosuite != "eddsa-jcs-2022" {
        return Err("proof cryptosuite must be eddsa-jcs-2022".to_owned());
    }
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_key_multibase = verification_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(verification_method);
    let update_keys = entry
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if !update_keys.contains(&public_key_multibase) {
        return Err("proof verificationMethod must reference updateKeys[0]".to_owned());
    }
    let public_key = decode_ed25519_public_key(public_key_multibase)?;
    let signature = decode_webvh_signature(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let mut canonical = entry.clone();
    if let Value::Object(map) = &mut canonical {
        map.remove("proof");
    }
    let payload = cokret_sdk::canonical::canonical_json_bytes(&canonical)
        .map_err(|error| error.to_string())?;
    public_key
        .verify(&payload, &signature)
        .map_err(|_| "webvh log proof signature is invalid".to_owned())
}

fn decode_ed25519_public_key(value: &str) -> Result<VerifyingKey, String> {
    let rest = value
        .strip_prefix('z')
        .ok_or_else(|| "public key must use base58btc multibase".to_owned())?;
    let raw = bs58::decode(rest)
        .into_vec()
        .map_err(|error| format!("public key base58 decode failed: {error}"))?;
    let bytes = raw
        .strip_prefix(&ED25519_MULTICODEC_PREFIX)
        .ok_or_else(|| "public key must be ed25519-pub multicodec".to_owned())?;
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err("ed25519 public key must be 32 bytes".to_owned());
    }
    let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
    key_bytes.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| "invalid ed25519 public key".to_owned())
}

fn decode_webvh_signature(value: &str) -> Result<Signature, String> {
    let rest = value
        .strip_prefix('z')
        .ok_or_else(|| "proofValue must use base58btc multibase".to_owned())?;
    let raw = bs58::decode(rest)
        .into_vec()
        .map_err(|error| format!("proofValue base58 decode failed: {error}"))?;
    if raw.len() != SIGNATURE_LENGTH {
        return Err("ed25519 proofValue must be 64 bytes".to_owned());
    }
    let mut signature_bytes = [0u8; SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(&raw);
    Ok(Signature::from_bytes(&signature_bytes))
}

fn valid_multibase_key(value: &str) -> bool {
    value.starts_with('z') && value.len() >= 2
}

fn normalize_webvh_local_id(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && !normalized.contains("..")
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}

fn normalize_webvh_key_fragment(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('#').to_owned();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}

fn render_json_bytes(res: &mut Response, content_type: &str, value: &Value) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    res.headers_mut()
        .insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    res.headers_mut().insert(
        header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    res.write_body(body).ok();
}

/// Run G3.S3 webvh validation gates (prev_hash chain + SCID mismatch +
/// witness quorum/degraded-window validation) over a DID's locally-cached
/// log before trusting the resolved document. Spec: identity-did.md
/// §3.4 / §4.2.1 / §3 ("DNS hijack protection") / §3.4 "controller
/// proof".
async fn run_webvh_resolution_checks(state: &AppState, did: &str) -> Result<(), AppError> {
    let events = state
        .persistence
        .webvh()
        .list_log_events(did)
        .await
        .map_err(|error| {
            tracing::error!(%error, %did, "failed to read webvh log during resolution checks");
            AppError::internal("failed to read did:webvh log")
        })?;
    if events.is_empty() {
        // No local log to validate — the resolver falls through to the
        // SDK / default-document path higher up. We do not fail closed
        // here because the cached document may legitimately come from
        // an external resolver.
        return Ok(());
    }
    let log: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    validate_log_chain(&log)?;
    let genesis = &log[0];
    verify_scid_against_did(did, genesis)?;
    validate_witness_policy_for_log(&log, now().timestamp())?;
    Ok(())
}

async fn identity_document_record(state: &AppState, did: &str) -> WebvhDocumentRecord {
    if let Some(did_document) =
        crate::routing::extensions::applet_bridge::did_document_for_extension_actor(state, did)
            .await
            .map_err(|error| {
                tracing::warn!(%error, %did, "failed to read applet extension DID document");
                error
            })
            .ok()
            .flatten()
    {
        return WebvhDocumentRecord {
            did: did.to_owned(),
            did_document,
            key_log_head: None,
            seq: 0,
            method_evidence: json!({"mode": "extension_actor_registry"}),
            // Local immediate temporary projection, treated as fresh and not
            // entered into the high-risk persistence gate.
            fetched_at: now(),
            expires_at: now()
                + chrono::Duration::seconds(crate::persistence::WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS),
            updated_at: now(),
        };
    }
    state
        .persistence
        .webvh()
        .get_document(did)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| WebvhDocumentRecord {
            did: did.to_owned(),
            did_document: default_did_document(Some(state), did),
            key_log_head: None,
            seq: 0,
            method_evidence: json!({"mode": "development_local"}),
            // Local default document (dev fallback), treated as fresh.
            fetched_at: now(),
            expires_at: now()
                + chrono::Duration::seconds(crate::persistence::WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS),
            updated_at: now(),
        })
}

fn default_did_document(state: Option<&AppState>, did: &str) -> Value {
    let mut verification_methods = Vec::new();
    let mut authentication = Vec::new();
    let mut assertion_method = Vec::new();
    if let Some(state) = state
        && did == state.config.service_did
    {
        let public_key = cokret_sdk::ed25519_pubkey_to_did_key_multibase(
            state.notary_signing_key().verifying_key().as_bytes(),
        );
        for fragment in ["notary-key", "snapshot-key-1"] {
            let key_id = format!("{did}#{fragment}");
            verification_methods.push(json!({
                "id": key_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": public_key.clone(),
            }));
            authentication.push(json!(key_id));
            assertion_method.push(json!(key_id));
        }
    }
    json!({
        "id": did,
        "verificationMethod": verification_methods,
        "authentication": authentication,
        "assertionMethod": assertion_method,
        "service": [{"id": "soland", "type": "CokretPrincipalServer", "serviceEndpoint": "/_cokret"}]
    })
}

fn did_operation_from_body(body: &Value) -> Result<Value, AppError> {
    if let Some(operation) = body.get("operation") {
        if !operation.is_object() {
            return Err(AppError::invalid_param("operation must be an object"));
        }
        return Ok(operation.clone());
    }
    if let Some(document) = body.get("did_document") {
        if !document.is_object() {
            return Err(AppError::invalid_param("did_document must be an object"));
        }
        return Ok(json!({"type": "replace", "state": document}));
    }
    if let Some(patch) = body.get("patch") {
        if !patch.is_object() {
            return Err(AppError::invalid_param("patch must be an object"));
        }
        return Ok(json!({"type": "patch", "patch": patch}));
    }
    Err(AppError::invalid_param(
        "operation, did_document, or patch is required",
    ))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn did_document_from_operation(
    did: &str,
    existing: Option<&WebvhDocumentRecord>,
    body: &Value,
    operation: &Value,
) -> Result<Value, AppError> {
    if let Some(state) = operation.get("state") {
        if !state.is_object() {
            return Err(AppError::invalid_param("operation.state must be an object"));
        }
        return Ok(state.clone());
    }
    if let Some(document) = body.get("did_document") {
        if !document.is_object() {
            return Err(AppError::invalid_param("did_document must be an object"));
        }
        return Ok(document.clone());
    }
    let mut document = existing
        .map(|record| record.did_document.clone())
        .unwrap_or_else(|| default_did_document(None, did));
    if let Some(patch) = operation
        .get("patch")
        .or_else(|| body.get("patch"))
        .and_then(Value::as_object)
    {
        let Some(target) = document.as_object_mut() else {
            return Err(AppError::invalid_param(
                "existing DID document is not an object",
            ));
        };
        for (key, value) in patch {
            if value.is_null() {
                target.remove(key);
            } else {
                target.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(document)
}

fn ensure_did_document_id(did: &str, document: &mut Value) -> Result<(), AppError> {
    let Some(map) = document.as_object_mut() else {
        return Err(AppError::invalid_param("DID document must be an object"));
    };
    match map.get("id").and_then(Value::as_str) {
        Some(value) if value == did => Ok(()),
        Some(_) => Err(AppError::invalid_param(
            "DID document id does not match did",
        )),
        None => {
            map.insert("id".to_owned(), Value::String(did.to_owned()));
            Ok(())
        }
    }
}

#[allow(dead_code)] // used by routing::tests::did_*; production path runs through validate_did_document
pub(in crate::routing) fn validate_did_document_services(
    did: &str,
    document: &Value,
    development_mode: bool,
) -> Result<(), &'static str> {
    let services = document.get("service").and_then(|v| v.as_array());
    if let Some(services) = services {
        for service in services {
            let endpoint = service.get("serviceEndpoint").and_then(|v| v.as_str());
            match endpoint {
                None | Some("") => {
                    if !development_mode {
                        return Err("DID document service must have a non-empty serviceEndpoint");
                    }
                }
                Some(ep) => {
                    if !ep.starts_with("http://")
                        && !ep.starts_with("https://")
                        && !ep.starts_with('/')
                    {
                        return Err("DID document serviceEndpoint must be an absolute URL or path");
                    }
                }
            }
        }
    }
    if did.starts_with("did:web:") && services.is_none_or(|s| s.is_empty()) && !development_mode {
        return Err("did:web document must declare at least one service endpoint");
    }
    Ok(())
}
