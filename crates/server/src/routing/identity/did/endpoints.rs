//! Identity / DID endpoint handlers.

use super::*;

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
pub(crate) async fn identity_describe(depot: &mut Depot, res: &mut Response) {
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
    /// DID (`did:key:z…`) of the device enrollment authority the registering
    /// client designates in the inception document via a
    /// `CokretDeviceEnrollmentAuthority` service entry (decision 0002 / D1).
    /// When present it MUST be reflected in the reconstructed document so the
    /// SCID + log proof verify; absent for callers that designate no authority.
    #[serde(default)]
    pub device_enrollment_authority_did: Option<String>,
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
pub(crate) async fn embedded_webvh_register(
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
        body.device_enrollment_authority_did.as_deref(),
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
pub(crate) async fn embedded_webvh_document(
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
pub(crate) async fn embedded_webvh_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
pub(crate) async fn identity_resolve(
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
pub(crate) async fn identity_document(
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
pub(crate) async fn identity_did_document(
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
pub(crate) async fn identity_log(
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
pub(crate) async fn identity_receipts(
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
pub(crate) async fn identity_submit_did_operation(
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
