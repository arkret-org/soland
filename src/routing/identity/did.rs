//! Identity / DID handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/identity/describe`     — service identity capability descriptor
//! - `POST /api/v1/identity/resolve`      — resolve a DID via SDK + local store
//! - `GET  /api/v1/identity/document`     — fetch the locally-cached DID document
//! - `GET  /api/v1/identity/log`          — return the local key log for a DID
//! - `POST /api/v1/identity/webvh/register` — register through the embedded webvh provider
//! - `GET  /webvh/{local_id}/did.json` — embedded webvh DID document
//! - `GET  /webvh/{local_id}/did.jsonl` — embedded webvh log
//! - `POST /api/v1/identity/did-operation`— submit a DID-operation (rotate/recover)
//! - `GET  /api/v1/identity/receipts`     — issuer receipts for the local key log
//!
//! All long-term state lives behind `state.persistence.webvh()`; the
//! `did_resolver` is still an in-process resolver chain. Production must move it onto a
//! durable store (see todo F2) — currently in-memory.

use contrix_sdk::identity::DidResolver;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Verifier, VerifyingKey};
use salvo::http::{StatusCode, header};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::webvh_validation::{
    WebvhLogEntry, validate_log_chain, verify_scid_against_did, verify_witness_signature,
};
use super::{append_audit_log, bearer_token, now, render_error, sha256_hex, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, WebvhDocumentRecord, WebvhLogRecord};
use crate::wire::{
    IdentityDescribeResBody, IdentityLogResBody, IdentityReceiptsResBody, IdentityResolveReqBody,
    IdentityResolveResBody,
};

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

#[endpoint]
pub(super) async fn identity_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let allow_methods = state.config.did_resolver_allow_methods.clone();
    let did_webvh = did_webvh_descriptor(state);
    let mut profiles = vec!["cx.identity.local-dev.v1".to_owned()];
    if did_webvh["enabled"].as_bool().unwrap_or(false) {
        profiles.push("cx.identity.webvh.provider.v1".to_owned());
    }
    res.render(Json(IdentityDescribeResBody {
        service_did: state.config.service_did.clone(),
        registry_mode: "development_local".to_owned(),
        supported_receipts: vec!["local".to_owned()],
        protocol_version: "1.0".to_owned(),
        profiles,
        resolver_policy: json!({
            "allow_methods": allow_methods,
            "default_methods": ["did:webvh", "did:web", "did:key"],
            "cache_ttl_seconds": 300,
            "required_profile_fail_mode": if state.config.development_mode {
                "development_local_fallback"
            } else {
                "fail_closed"
            },
            "trust_roots": [],
        }),
        did_webvh,
        todos: vec!["publish resolver trust roots and freshness receipts".to_owned()],
    }));
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EmbeddedWebvhRegisterRequest {
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
pub struct EmbeddedWebvhRegisterResponse {
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
    operation_id = "cx.identity.webvh.register",
    tags("identity"),
    summary = "Register through the embedded did:webvh provider",
    status_codes(201, 400, 401, 404, 409, 500, 503)
)]
pub(super) async fn embedded_webvh_register(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<EmbeddedWebvhRegisterRequest>,
) -> JsonResult<EmbeddedWebvhRegisterResponse> {
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
    let scid =
        derive_webvh_scid(&entry_skeleton).map_err(|message| AppError::invalid_param(message))?;
    let location =
        embedded_webvh_location_with_scid(&method_authority, &https_authority, &local_id, &scid);
    let did_key_id = format!("{}#{}", location.did, did_key_fragment);
    let update_key_id = format!("{}#{}", location.did, update_key_fragment);
    let mut log_entry = substitute_webvh_scid(entry_skeleton, &scid);
    let version_hash = webvh_entry_hash_multibase(&log_entry)
        .map_err(|message| AppError::invalid_param(message))?;
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
    if let Err(error) = state.persistence.webvh().put_document(WebvhDocumentRecord {
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
        updated_at: now,
    }) {
        tracing::error!(%error, "failed to persist embedded webvh document");
        return Err(AppError::internal(
            "failed to persist embedded webvh document",
        ));
    }
    if let Err(error) = state.persistence.webvh().append_log_event(WebvhLogRecord {
        event_hash: version_id.clone(),
        did: location.did.clone(),
        seq: 1,
        operation: log_entry.clone(),
        created_at: now,
    }) {
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
    );
    res.status_code(StatusCode::CREATED);
    json_ok(EmbeddedWebvhRegisterResponse {
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
pub(super) async fn embedded_webvh_document(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res) else {
        return;
    };
    render_json_bytes(
        res,
        "application/did+json; charset=utf-8",
        &record.did_document,
    );
}

#[endpoint]
pub(super) async fn embedded_webvh_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res) else {
        return;
    };
    let events = state
        .persistence
        .webvh()
        .list_log_events(&record.did)
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
    operation_id = "cx.identity.resolve",
    tags("identity"),
    summary = "Resolve a DID via local webvh store + SDK resolver chain"
)]
pub(super) async fn identity_resolve(
    body: JsonBody<IdentityResolveReqBody>,
    depot: &mut Depot,
) -> JsonResult<IdentityResolveResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if validate_did(&body.did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    if let Ok(Some(record)) = state.persistence.webvh().get_document(&body.did) {
        // G3.S3: every did:webvh resolution MUST first re-validate the
        // log chain and SCID derivation, AND any witness signatures
        // present on individual entries. Spec: identity-did.md §3.4 +
        // §4.2.1.
        //
        // TODO(G3.S3-followup): multi-witness quorum + 24h
        // degraded_no_witness window. Today we only verify single-party
        // witness signatures (if present) and never fail closed on
        // absent witnesses — the degraded-mode state machine is the
        // next slice (see identity-did.md §4.2.1 and the E9.4 fixme in
        // cotest/e2e/tests/identity/webvh-rotation.spec.ts).
        //
        // TODO(G3.S3-followup): emergency rotation path
        // (key-management.md §3.3 recovery key). Today rotation entries
        // must be controller-signed; recovery-key-only rotations are
        // not yet accepted.
        if body.did.starts_with("did:webvh:") {
            run_webvh_resolution_checks(state, &body.did)?;
        }
        return json_ok(IdentityResolveResBody {
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            receipts: Vec::new(),
            method_evidence: record.method_evidence,
        });
    }
    let sdk_did = contrix_sdk::Did::new(body.did.clone());
    let sdk_document = sdk_did.ok().and_then(|did| {
        state
            .did_resolver
            .lock()
            .expect("did resolver lock")
            .resolve_did(&did)
            .ok()
    });
    if let Some(doc) = sdk_document {
        return json_ok(IdentityResolveResBody {
            did_document: json!({
                "id": doc.id.as_str(),
                "verificationMethod": doc.verification_methods,
                "alsoKnownAs": doc.also_known_as,
            }),
            key_log_head: None,
            seq: 0,
            receipts: Vec::new(),
            method_evidence: json!({"mode": "sdk_resolver", "source": "did_resolver"}),
        });
    }
    let record = identity_document_record(state, &body.did);
    json_ok(IdentityResolveResBody {
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        receipts: Vec::new(),
        method_evidence: record.method_evidence,
    })
}

#[endpoint(
    operation_id = "cx.identity.document",
    tags("identity"),
    summary = "Fetch the locally-cached DID document for a DID"
)]
pub(super) async fn identity_document(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityResolveResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let record = identity_document_record(state, &did);
    json_ok(IdentityResolveResBody {
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        receipts: Vec::new(),
        method_evidence: record.method_evidence,
    })
}

#[endpoint(
    operation_id = "cx.identity.log",
    tags("identity"),
    summary = "Return the local webvh key-log events for a DID"
)]
pub(super) async fn identity_log(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityLogResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let events = state
        .persistence
        .webvh()
        .list_log_events(&did)
        .unwrap_or_default()
        .into_iter()
        .map(|event| {
            json!({
                "event_hash": event.event_hash,
                "did": event.did,
                "seq": event.seq,
                "operation": event.operation,
                "created_at": event.created_at,
            })
        })
        .collect();
    json_ok(IdentityLogResBody {
        events,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "cx.identity.receipts",
    tags("identity"),
    summary = "Read issuer receipts for the local webvh key-log of a DID"
)]
pub(super) async fn identity_receipts(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityReceiptsResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let record = state.persistence.webvh().get_document(&did).ok().flatten();
    json_ok(IdentityReceiptsResBody {
        receipts: record
            .map(|record| {
                vec![json!({
                    "service_did": state.config.service_did.clone(),
                    "did": record.did,
                    "head_event_hash": record.key_log_head,
                    "seq": record.seq,
                    "issued_at": record.updated_at,
                })]
            })
            .unwrap_or_default(),
        threshold_met: true,
    })
}

#[derive(Clone, Debug)]
struct EmbeddedWebvhLocation {
    did: String,
    scid: String,
    document_url: String,
    log_url: String,
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
            "registration_url": format!("{}/api/v1/identity/webvh/register", state.config.public_base_url.trim_end_matches('/')),
            "resolver_url": format!("{}/api/v1/identity", state.config.public_base_url.trim_end_matches('/')),
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
            "describe_url": format!("{}/describe", url.trim_end_matches('/')),
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
        "profile": "cx.identity.webvh.provider.v1",
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

fn embedded_webvh_record_for_request(
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
            "type": "ContrixPrincipalServer",
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
    let canonical = contrix_sdk::canonical::canonical_json_bytes(skeleton)
        .map_err(|error| error.to_string())?;
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
    let canonical =
        contrix_sdk::canonical::canonical_json_bytes(&strip_webvh_entry_for_hash(value))
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
    if !update_keys.iter().any(|key| *key == public_key_multibase) {
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
    let payload = contrix_sdk::canonical::canonical_json_bytes(&canonical)
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
/// single-witness signature) over a DID's locally-cached log before
/// trusting the resolved document. Spec: identity-did.md §3.4 / §4.2.1
/// / §3 ("DNS hijack protection") / §3.4 "controller proof".
///
/// TODO(G3.S3-followup): plug a resolver-policy-driven witness key set
/// in once `trusted_witnesses` configuration lands (identity-did.md
/// §4.1). For now we accept any witness key referenced by the entry's
/// own proof, which suffices to catch a forged-signature attack but not
/// a fully untrusted-witness one.
fn run_webvh_resolution_checks(state: &AppState, did: &str) -> Result<(), AppError> {
    let events = state
        .persistence
        .webvh()
        .list_log_events(did)
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
    // Resolver-policy-driven witness keys are not wired yet — pass an
    // empty allow-list so `verify_witness_signature` only enforces the
    // "if a proof is present, its signature MUST verify" rule. The
    // "MUST come from a trusted witness" rule is the followup TODO
    // above.
    for entry in &log {
        verify_witness_signature(entry, &[])?;
    }
    Ok(())
}

fn identity_document_record(state: &AppState, did: &str) -> WebvhDocumentRecord {
    state
        .persistence
        .webvh()
        .get_document(did)
        .ok()
        .flatten()
        .unwrap_or_else(|| WebvhDocumentRecord {
            did: did.to_owned(),
            did_document: default_did_document(did),
            key_log_head: None,
            seq: 0,
            method_evidence: json!({"mode": "development_local"}),
            updated_at: now(),
        })
}

fn default_did_document(did: &str) -> Value {
    json!({
        "id": did,
        "verificationMethod": [],
        "authentication": [],
        "service": [{"id": "soland", "type": "ContrixPrincipalServer", "serviceEndpoint": "/api/v1"}]
    })
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
    if did.starts_with("did:web:") && services.map_or(true, |s| s.is_empty()) && !development_mode {
        return Err("did:web document must declare at least one service endpoint");
    }
    Ok(())
}
