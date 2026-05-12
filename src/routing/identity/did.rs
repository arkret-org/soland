//! Identity / DID handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/identity/describe`     — service identity capability descriptor
//! - `POST /api/v1/identity/resolve`      — resolve a DID via SDK + local store
//! - `GET  /api/v1/identity/document`     — fetch the locally-cached DID document
//! - `GET  /api/v1/identity/log`          — return the local key log for a DID
//! - `POST /api/v1/identity/webvh/register` — register through the embedded webvh provider
//! - `GET  /api/v1/identity/webvh/{local_id}/did.json` — embedded webvh DID document
//! - `GET  /api/v1/identity/webvh/{local_id}/did.jsonl` — embedded webvh log
//! - `POST /api/v1/identity/did-operation`— submit a DID-operation (rotate/recover)
//! - `GET  /api/v1/identity/receipts`     — issuer receipts for the local key log
//!
//! All long-term state lives behind `state.persistence.identity()`; the
//! `did_resolver` is still an in-process resolver chain. Production must move it onto a
//! durable store (see todo F2) — currently in-memory.

use contrix_sdk::identity::DidResolver;
use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    append_audit_log, bearer_token, now, query_param, render_error, sha256_hex, validate_did,
};
use crate::state::{AppState, IdentityDocumentRecord, IdentityLogRecord};
use crate::wire::{
    IdentityDescribeResponse, IdentityLogResponse, IdentityReceiptsResponse,
    IdentityResolveRequest, IdentityResolveResponse, SubmitDidOperationRequest,
    SubmitDidOperationResponse,
};

#[endpoint]
pub(super) async fn identity_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let allow_methods = state.config.did_resolver_allow_methods.clone();
    let did_webvh = did_webvh_descriptor(state);
    let mut profiles = vec!["cx.identity.local-dev.v1".to_owned()];
    if did_webvh["enabled"].as_bool().unwrap_or(false) {
        profiles.push("cx.identity.webvh.provider.v1".to_owned());
    }
    res.render(Json(IdentityDescribeResponse {
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

#[derive(Debug, Deserialize)]
pub struct EmbeddedWebvhRegisterRequest {
    #[serde(default)]
    pub local_id: Option<String>,
    pub public_key_multibase: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub also_known_as: Vec<String>,
}

#[endpoint]
pub(super) async fn embedded_webvh_register(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    if !state.config.embedded_webvh_provider_enabled {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "embedded did:webvh provider is disabled",
        );
        return;
    }
    if !require_embedded_webvh_registration_bearer(state, req, res) {
        return;
    }
    let body = match req.parse_json::<EmbeddedWebvhRegisterRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid embedded webvh register request",
            );
            return;
        }
    };
    if !body.public_key_multibase.starts_with('z') || body.public_key_multibase.len() < 2 {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "public_key_multibase must be a non-empty multibase value",
        );
        return;
    }
    let local_id = match body
        .local_id
        .as_deref()
        .and_then(normalize_webvh_local_id)
        .or_else(|| {
            let digest = sha256_hex(body.public_key_multibase.as_bytes());
            normalize_webvh_local_id(&format!("user-{}", &digest[..12]))
        }) {
        Some(local_id) => local_id,
        None => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid local_id",
            );
            return;
        }
    };
    let key_fragment = normalize_webvh_key_fragment(body.key_id.as_deref().unwrap_or("key-1"));
    let Some(key_fragment) = key_fragment else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid key_id",
        );
        return;
    };
    let location = match embedded_webvh_location(&state.config.public_base_url, &local_id) {
        Ok(location) => location,
        Err(message) => {
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "invalid_config",
                &message,
            );
            return;
        }
    };
    if state
        .persistence
        .identity()
        .get_document(&location.did)
        .ok()
        .flatten()
        .is_some()
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cas_conflict",
            "embedded did:webvh local_id is already registered",
        );
        return;
    }

    let now = now();
    let version_time = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let key_id = format!("{}#{}", location.did, key_fragment);
    let did_document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": location.did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Multikey",
            "controller": location.did,
            "publicKeyMultibase": body.public_key_multibase,
        }],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "alsoKnownAs": body.also_known_as,
        "service": [{
            "id": format!("{}#soland", location.did),
            "type": "ContrixPrincipalServer",
            "serviceEndpoint": state.config.public_base_url,
        }],
    });
    let version_hash = sha256_hex(did_document.to_string().as_bytes());
    let version_id = format!("1-{}", &version_hash[..16]);
    let log_entry = json!({
        "versionId": version_id,
        "versionTime": version_time,
        "parameters": {
            "scid": location.scid,
            "method": "did:webvh:1.0",
            "updateKeys": [body.public_key_multibase],
        },
        "state": did_document,
        "proof": [],
    });
    if let Err(error) = state
        .persistence
        .identity()
        .put_document(IdentityDocumentRecord {
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
            }),
            updated_at: now,
        })
    {
        tracing::error!(%error, "failed to persist embedded webvh document");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to persist embedded webvh document",
        );
        return;
    }
    if let Err(error) = state
        .persistence
        .identity()
        .append_log_event(IdentityLogRecord {
            event_hash: version_id.clone(),
            did: location.did.clone(),
            seq: 1,
            operation: log_entry.clone(),
            created_at: now,
        })
    {
        tracing::error!(%error, "failed to append embedded webvh log entry");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to append embedded webvh log entry",
        );
        return;
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
    res.render(Json(json!({
        "status": "created",
        "provider_id": "soland.embedded",
        "did": location.did,
        "key_id": key_id,
        "seq": 1,
        "key_log_head": version_id,
        "document_url": location.document_url,
        "log_url": location.log_url,
        "did_document": did_document,
        "did_log": [log_entry],
    })));
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
        .identity()
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

#[endpoint]
pub(super) async fn identity_resolve(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<IdentityResolveRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid identity resolve request",
            );
            return;
        }
    };
    if validate_did(&body.did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    if let Ok(Some(record)) = state.persistence.identity().get_document(&body.did) {
        res.render(Json(IdentityResolveResponse {
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            receipts: Vec::new(),
            method_evidence: record.method_evidence,
        }));
        return;
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
        res.render(Json(IdentityResolveResponse {
            did_document: json!({
                "id": doc.id.as_str(),
                "verificationMethod": doc.verification_methods,
                "alsoKnownAs": doc.also_known_as,
            }),
            key_log_head: None,
            seq: 0,
            receipts: Vec::new(),
            method_evidence: json!({"mode": "sdk_resolver", "source": "did_resolver"}),
        }));
        return;
    }
    let record = identity_document_record(state, &body.did);
    res.render(Json(IdentityResolveResponse {
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        receipts: Vec::new(),
        method_evidence: record.method_evidence,
    }));
}

#[endpoint]
pub(super) async fn identity_document(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    render_identity_document(state, res, did);
}

#[endpoint]
pub(super) async fn identity_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let events = state
        .persistence
        .identity()
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
    res.render(Json(IdentityLogResponse {
        events,
        next_cursor: None,
        has_more: false,
    }));
}

#[endpoint]
pub(super) async fn submit_did_operation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<SubmitDidOperationRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid DID operation request",
            );
            return;
        }
    };
    if validate_did(&body.did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    if body.proofs.is_empty() {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "DID operation requires proof material",
        );
        return;
    }
    if !state.config.development_mode {
        for proof in &body.proofs {
            if proof.get("alg").and_then(|v| v.as_str()) == Some("none") {
                render_error(
                    res,
                    StatusCode::UNAUTHORIZED,
                    "invalid_signature",
                    "production DID operations must not use alg:none",
                );
                return;
            }
            if proof.get("jws").and_then(|v| v.as_str()) == Some("dev-proof") {
                render_error(
                    res,
                    StatusCode::UNAUTHORIZED,
                    "invalid_signature",
                    "production DID operations must not use dev-proof",
                );
                return;
            }
        }
    }
    if body.seq > 1 {
        let prev_doc = state
            .persistence
            .identity()
            .get_document(&body.did)
            .ok()
            .flatten()
            .map(|r| r.did_document);
        if let Some(doc) = prev_doc {
            let verification_keys = did_document_verification_method_ids(&doc);
            let recovery_keys: Vec<String> = doc
                .get("recovery_keys")
                .and_then(|v| v.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let all_active_keys: Vec<&str> = verification_keys
                .iter()
                .chain(recovery_keys.iter())
                .map(|s| s.as_str())
                .collect();
            if !all_active_keys.is_empty() {
                let proof_has_active_key = body.proofs.iter().any(|proof| {
                    let vm = proof
                        .get("verification_method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let key_id = vm.rsplit('#').next().unwrap_or(vm);
                    all_active_keys.contains(&key_id)
                        || all_active_keys.iter().any(|k| k.ends_with(key_id))
                });
                if !proof_has_active_key {
                    render_error(
                        res,
                        StatusCode::UNAUTHORIZED,
                        "invalid_signature",
                        "DID operation signer is not an active verification or recovery key",
                    );
                    return;
                }
            }
        }
    }
    let previous = state
        .persistence
        .identity()
        .get_document(&body.did)
        .ok()
        .flatten();
    if let Some(previous) = &previous {
        if body.seq != previous.seq + 1 {
            render_error(
                res,
                StatusCode::CONFLICT,
                "cas_conflict",
                "DID operation seq must advance the current key log",
            );
            return;
        }
        if body.prev_event_hash.as_deref() != previous.key_log_head.as_deref() {
            render_error(
                res,
                StatusCode::CONFLICT,
                "cas_conflict",
                "prev_event_hash does not match current key log head",
            );
            return;
        }
    } else if body.seq != 1 {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cas_conflict",
            "first DID operation seq must be 1",
        );
        return;
    }
    let head_event_hash = format!("sha256:{}", sha256_hex(body.patch.to_string().as_bytes()));
    let did_document = did_document_from_patch(&body.did, &body.patch)
        .unwrap_or_else(|| default_did_document(&body.did));
    if let Err(message) =
        validate_did_document_services(&body.did, &did_document, state.config.development_mode)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    let now = now();
    if let Err(error) = state
        .persistence
        .identity()
        .put_document(IdentityDocumentRecord {
            did: body.did.clone(),
            did_document,
            key_log_head: Some(head_event_hash.clone()),
            seq: body.seq,
            method_evidence: json!({"mode": "development_local", "source": "did_operation"}),
            updated_at: now,
        })
    {
        tracing::error!(%error, "failed to persist identity document");
    }
    if let Err(error) = state
        .persistence
        .identity()
        .append_log_event(IdentityLogRecord {
            event_hash: head_event_hash.clone(),
            did: body.did.clone(),
            seq: body.seq,
            operation: body.patch,
            created_at: now,
        })
    {
        tracing::error!(%error, "failed to append identity log event");
    }
    append_audit_log(
        state,
        Some(&body.did),
        "identity.did_operation",
        json!({"did": body.did, "seq": body.seq, "head_event_hash": head_event_hash.clone()}),
        "accepted",
    );
    res.render(Json(SubmitDidOperationResponse {
        status: "accepted".to_owned(),
        head_event_hash,
        seq: body.seq,
        receipts: vec![json!({"service_did": state.config.service_did.clone(), "issued_at": now})],
    }));
}

#[endpoint]
pub(super) async fn identity_receipts(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(did) = query_param(req, "did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "did is required",
        );
        return;
    };
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let record = state
        .persistence
        .identity()
        .get_document(&did)
        .ok()
        .flatten();
    res.render(Json(IdentityReceiptsResponse {
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
    }));
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
                    "https://{https_authority}/api/v1/identity/webvh/{{local_id}}/did.json"
                ));
                let log_url_template = Some(format!(
                    "https://{https_authority}/api/v1/identity/webvh/{{local_id}}/did.jsonl"
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
    res: &mut Response,
) -> bool {
    let Some(expected) = state
        .config
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        render_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_config",
            "embedded did:webvh registration requires SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        );
        return false;
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "embedded did:webvh registration requires Authorization: Bearer <token>",
        );
        return false;
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid embedded did:webvh registration bearer",
        );
        return false;
    }
    true
}

fn embedded_webvh_record_for_request(
    state: &AppState,
    req: &mut Request,
    res: &mut Response,
) -> Option<IdentityDocumentRecord> {
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
    let location = match embedded_webvh_location(&state.config.public_base_url, &local_id) {
        Ok(location) => location,
        Err(message) => {
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "invalid_config",
                &message,
            );
            return None;
        }
    };
    match state.persistence.identity().get_document(&location.did) {
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

fn embedded_webvh_location(
    public_base_url: &str,
    local_id: &str,
) -> Result<EmbeddedWebvhLocation, String> {
    let (method_authority, https_authority) = embedded_webvh_authority(public_base_url)?;
    let path = format!("api:v1:identity:webvh:{local_id}");
    let path_url = format!("api/v1/identity/webvh/{local_id}");
    let scid = embedded_webvh_scid(&method_authority, local_id);
    Ok(EmbeddedWebvhLocation {
        did: format!("did:webvh:{scid}:{method_authority}:{path}"),
        scid,
        document_url: format!("https://{https_authority}/{path_url}/did.json"),
        log_url: format!("https://{https_authority}/{path_url}/did.jsonl"),
    })
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

fn embedded_webvh_scid(method_authority: &str, local_id: &str) -> String {
    let material = format!("soland:webvh:v1:{method_authority}:api:v1:identity:webvh:{local_id}");
    let digest = sha256_hex(material.as_bytes());
    format!("z{}", &digest[..24])
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

fn render_identity_document(state: &AppState, res: &mut Response, did: String) {
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let record = identity_document_record(state, &did);
    res.render(Json(IdentityResolveResponse {
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        receipts: Vec::new(),
        method_evidence: record.method_evidence,
    }));
}

fn identity_document_record(state: &AppState, did: &str) -> IdentityDocumentRecord {
    state
        .persistence
        .identity()
        .get_document(did)
        .ok()
        .flatten()
        .unwrap_or_else(|| IdentityDocumentRecord {
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

fn did_document_verification_methods(document: &Value) -> Option<&Value> {
    document
        .get("verificationMethod")
        .or_else(|| document.get("verification_method"))
}

fn did_document_verification_method_ids(document: &Value) -> Vec<String> {
    match did_document_verification_methods(document) {
        Some(Value::Object(methods)) => methods.keys().cloned().collect(),
        Some(Value::Array(methods)) => methods
            .iter()
            .filter_map(|method| match method {
                Value::String(id) => Some(id.clone()),
                Value::Object(object) => object
                    .get("id")
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn did_document_from_patch(did: &str, patch: &Value) -> Option<Value> {
    let document = patch
        .get("did_document")
        .or_else(|| patch.get("document"))
        .cloned()?;
    (document.get("id").and_then(|value| value.as_str()) == Some(did)).then_some(document)
}

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
