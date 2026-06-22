//! DID document rendering, validation, and operation-application helpers.

use super::*;

pub(super) fn render_json_bytes(res: &mut Response, content_type: &str, value: &Value) {
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
pub(super) async fn run_webvh_resolution_checks(
    state: &AppState,
    did: &str,
) -> Result<(), AppError> {
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

pub(in crate::routing) async fn identity_document_record(
    state: &AppState,
    did: &str,
) -> WebvhDocumentRecord {
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
    let record = state
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
        });
    with_default_also_known_as(record, state, did)
}

pub(super) fn default_did_document(state: Option<&AppState>, did: &str) -> Value {
    let mut verification_methods = Vec::new();
    let mut authentication = Vec::new();
    let mut assertion_method = Vec::new();
    let also_known_as = default_also_known_as(state, did);
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
        "alsoKnownAs": also_known_as,
        "verificationMethod": verification_methods,
        "authentication": authentication,
        "assertionMethod": assertion_method,
        "service": [{"id": "soland", "type": "CokretPrincipalServer", "serviceEndpoint": "/_cokret"}]
    })
}

fn default_also_known_as(state: Option<&AppState>, did: &str) -> Vec<String> {
    let Some(state) = state else {
        return Vec::new();
    };
    if !state.config.development_mode || did != "did:web:alice.example" {
        return Vec::new();
    }
    let domain = reqwest::Url::parse(&state.config.public_base_url)
        .ok()
        .and_then(|url| url.host_str().and_then(valid_handle_domain_candidate))
        .or_else(|| {
            state
                .config
                .service_did
                .strip_prefix("did:web:")
                .and_then(|value| valid_handle_domain_candidate(&value.replace(':', ".")))
        })
        .unwrap_or_else(|| "soland.local".to_owned());
    vec![format!("acct:alice@{domain}")]
}

fn valid_handle_domain_candidate(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    cokret_sdk::models::Handle::parse(&format!("alice:{domain}"))
        .ok()
        .map(|handle| handle.domain().to_owned())
}

fn with_default_also_known_as(
    mut record: WebvhDocumentRecord,
    state: &AppState,
    did: &str,
) -> WebvhDocumentRecord {
    let aliases = default_also_known_as(Some(state), did);
    if aliases.is_empty() {
        return record;
    }
    let Some(object) = record.did_document.as_object_mut() else {
        return record;
    };
    let entry = object
        .entry("alsoKnownAs".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(array) = entry.as_array_mut() else {
        return record;
    };
    for alias in aliases {
        if !array
            .iter()
            .any(|value| value.as_str() == Some(alias.as_str()))
        {
            array.push(Value::String(alias));
        }
    }
    record
}

pub(super) fn did_operation_from_body(body: &Value) -> Result<Value, AppError> {
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

pub(super) fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn did_document_from_operation(
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

pub(super) fn ensure_did_document_id(did: &str, document: &mut Value) -> Result<(), AppError> {
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
