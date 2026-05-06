//! Identity / DID handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/identity/describe`     — service identity capability descriptor
//! - `POST /api/v1/identity/resolve`      — resolve a DID via SDK + local store
//! - `GET  /api/v1/identity/document`     — fetch the locally-cached DID document
//! - `GET  /api/v1/identity/log`          — return the local key log for a DID
//! - `POST /api/v1/identity/did-operation`— submit a DID-operation (rotate/recover)
//! - `GET  /api/v1/identity/receipts`     — issuer receipts for the local key log
//!
//! All long-term state lives behind locks in [`AppState`] (`identity_documents`,
//! `identity_log_events`, `did_resolver`). Production must move this onto a
//! durable store (see todo F2) — currently in-memory.

use contrix_sdk::identity::DidResolver;
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::{AppState, IdentityDocumentRecord, IdentityLogRecord},
    wire::{
        IdentityDescribeResponse, IdentityLogResponse, IdentityReceiptsResponse,
        IdentityResolveRequest, IdentityResolveResponse, SubmitDidOperationRequest,
        SubmitDidOperationResponse,
    },
};

use super::{
    append_audit_log, now, query_param, render_error, sha256_hex, validate_did,
};

#[endpoint]
pub async fn identity_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(IdentityDescribeResponse {
        service_did: state.config.service_did.clone(),
        registry_mode: "development_local".to_owned(),
        supported_receipts: vec!["local".to_owned()],
        protocol_version: "1.0".to_owned(),
        profiles: vec!["cx.identity.local-dev.v1".to_owned()],
    }));
}

#[endpoint]
pub async fn identity_resolve(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
pub async fn identity_document(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
pub async fn identity_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
        .identity_log_events
        .lock()
        .expect("identity log lock")
        .get(&did)
        .cloned()
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
pub async fn submit_did_operation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
            .identity_documents
            .lock()
            .expect("identity documents lock")
            .get(&body.did)
            .map(|r| r.did_document.clone());
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
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .get(&body.did)
        .cloned();
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
    if let Ok(did) = contrix_sdk::Did::new(body.did.clone()) {
        if let Some((key_id, public_key)) = did_document_first_verification_method(&did_document) {
            let doc = contrix_sdk::identity::DidDocument::new(did.clone(), key_id, public_key);
            let mut resolver = state.did_resolver.lock().expect("did resolver lock");
            match did.method() {
                "uuid" => {
                    let mut r = contrix_sdk::identity::DidUuidResolver::new();
                    let _ = r.insert(doc);
                    resolver.push(r);
                }
                "web" => {
                    let mut r = contrix_sdk::identity::DidWebResolver::new();
                    let _ = r.insert(doc);
                    resolver.push(r);
                }
                _ => {}
            }
        }
    }
    state
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .insert(
            body.did.clone(),
            IdentityDocumentRecord {
                did: body.did.clone(),
                did_document,
                key_log_head: Some(head_event_hash.clone()),
                seq: body.seq,
                method_evidence: json!({"mode": "development_local", "source": "did_operation"}),
                updated_at: now,
            },
        );
    state
        .identity_log_events
        .lock()
        .expect("identity log lock")
        .entry(body.did.clone())
        .or_default()
        .push(IdentityLogRecord {
            event_hash: head_event_hash.clone(),
            did: body.did.clone(),
            seq: body.seq,
            operation: body.patch,
            created_at: now,
        });
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
pub async fn identity_receipts(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .get(&did)
        .cloned();
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
        .identity_documents
        .lock()
        .expect("identity documents lock")
        .get(did)
        .cloned()
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

fn did_document_first_verification_method(document: &Value) -> Option<(String, String)> {
    match did_document_verification_methods(document)? {
        Value::Object(methods) => methods.iter().next().map(|(key_id, key_value)| {
            let public_key = key_value
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| key_value.to_string());
            (key_id.clone(), public_key)
        }),
        Value::Array(methods) => methods.iter().find_map(|method| {
            let object = method.as_object()?;
            let key_id = object.get("id")?.as_str()?.to_owned();
            let public_key = object
                .get("publicKeyMultibase")
                .or_else(|| object.get("publicKeyJwk"))
                .map(|value| {
                    value
                        .as_str()
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
                .unwrap_or_default();
            Some((key_id, public_key))
        }),
        _ => None,
    }
}

fn did_document_from_patch(did: &str, patch: &Value) -> Option<Value> {
    let document = patch
        .get("did_document")
        .or_else(|| patch.get("document"))
        .cloned()?;
    (document.get("id").and_then(|value| value.as_str()) == Some(did)).then_some(document)
}

pub fn validate_did_document_services(
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
