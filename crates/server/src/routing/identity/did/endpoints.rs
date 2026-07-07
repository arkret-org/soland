//! Identity / DID endpoint handlers.

use super::*;

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
#[serde(transparent)]
pub struct RawDidDocumentJson(
    #[salvo(schema(value_type = serde_json::Value))] pub serde_json::Value,
);

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryDescription {
    pub protocol_version: String,
    pub service_type: String,
    pub service_did: Did,
    pub trust_domain: String,
    pub registry_mode: String,
    pub supported_receipts: Vec<String>,
    pub profiles: Vec<String>,
    pub supported_profiles: Vec<String>,
    pub supported_operations: Vec<String>,
    pub supported_bindings: Vec<IdentityRegistryBinding>,
    pub supported_features: Vec<String>,
    pub auth_metadata: IdentityRegistryAuthMetadata,
    #[salvo(schema(value_type = serde_json::Value))]
    pub limits: Value,
    pub plaintext_visibility: IdentityRegistryPlaintextVisibility,
    pub implemented_features: Vec<String>,
    pub claimed_profiles: Vec<IdentityRegistryClaimedProfile>,
    pub verified_profiles: Vec<IdentityRegistryVerifiedProfile>,
    pub experimental_features: Vec<String>,
    pub compat_surfaces: Vec<String>,
    pub development_mode: bool,
    pub rate_limit_policy: IdentityRegistryRateLimitPolicy,
    pub supported_did_methods: Vec<String>,
    pub resolver_policy: IdentityResolverPolicy,
    pub registry_visibility: IdentityRegistryVisibility,
    #[salvo(schema(value_type = serde_json::Value))]
    pub did_webvh: Value,
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryBinding {
    pub kind: String,
    pub base_url: String,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryAuthMetadata {
    pub mode: String,
    pub read: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryPlaintextVisibility {
    pub default: String,
    pub services: Vec<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryClaimedProfile {
    pub profile_id: String,
    pub claim_kind: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryVerifiedProfile {
    pub profile_id: String,
    pub verifier: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryRateLimitPolicy {
    pub kind: String,
    pub per_minute: u32,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityResolverPolicy {
    pub allow_methods: Vec<String>,
    pub freshness_receipts: IdentityFreshnessReceiptsPolicy,
    pub webvh_validation: IdentityWebvhValidationPolicy,
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    pub trust_roots: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityFreshnessReceiptsPolicy {
    pub endpoint_template: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityWebvhValidationPolicy {
    pub witness_quorum: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityRegistryVisibility {
    pub mode: String,
    pub public_resolution: bool,
    pub public_receipts: bool,
    pub write_policy: String,
}

#[endpoint(
    operation_id = "ck.root.identity.registry.query.describe",
    tags("identity"),
    summary = "Identity registry capability description"
)]
#[tracing::instrument(skip_all, fields(op = "identity_describe"))]
pub(crate) async fn identity_describe(
    depot: &mut Depot,
) -> JsonResult<IdentityRegistryDescription> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let did_webvh = did_webvh_descriptor(state);
    let mut profiles = vec![
        "ck.profile.identity_registry.v1".to_owned(),
        "ck.identity.local-dev.v1".to_owned(),
    ];
    if did_webvh["enabled"].as_bool().unwrap_or(false) {
        profiles.push("ck.identity.webvh.provider.v1".to_owned());
    }
    let service_did = Did::new(state.config.service_did.clone())
        .map_err(|error| AppError::internal(format!("invalid configured service_did: {error}")))?;
    let supported_did_methods = state
        .config
        .did_resolver_allow_methods
        .iter()
        .map(|method| format!("did:{method}"))
        .collect::<Vec<_>>();
    let trust_roots = identity_trust_roots(state);
    let supported_features = vec![
        "ck.feature.identity.resolve.v1".to_owned(),
        "ck.feature.identity.receipts.v1".to_owned(),
        "ck.feature.identity.did_webvh.v1".to_owned(),
    ];

    json_ok(IdentityRegistryDescription {
        protocol_version: cokret_sdk::PROTOCOL_VERSION.to_owned(),
        service_type: "identity_registry".to_owned(),
        service_did,
        trust_domain: state.config.trust_domain.clone(),
        registry_mode: "development_local".to_owned(),
        supported_receipts: vec!["local".to_owned()],
        profiles: profiles.clone(),
        supported_profiles: profiles,
        supported_operations: vec![
            "ck.root.identity.registry.query.describe".to_owned(),
            "ck.root.identity.query.resolve".to_owned(),
            "ck.root.identity.document.resource.get".to_owned(),
            "ck.root.identity.log.query.list".to_owned(),
            "ck.root.identity.receipts.query.list".to_owned(),
            "ck.root.identity.command.submit_did_operation".to_owned(),
        ],
        supported_bindings: vec![IdentityRegistryBinding {
            kind: "http".to_owned(),
            base_url: state.config.public_base_url.clone(),
            paths: vec![
                "/_cokret/root/identity/describe".to_owned(),
                "/_cokret/root/identity/resolve".to_owned(),
                "/_cokret/root/identity/document".to_owned(),
                "/_cokret/root/identity/log".to_owned(),
                "/_cokret/root/identity/receipts".to_owned(),
                "/_cokret/root/identity/submit-did-operation".to_owned(),
            ],
        }],
        supported_features: supported_features.clone(),
        auth_metadata: IdentityRegistryAuthMetadata {
            mode: if state.config.development_mode {
                "development".to_owned()
            } else {
                "production".to_owned()
            },
            read: "public_metadata".to_owned(),
        },
        limits: json!({}),
        plaintext_visibility: IdentityRegistryPlaintextVisibility {
            default: "metadata_only".to_owned(),
            services: Vec::new(),
        },
        implemented_features: supported_features,
        claimed_profiles: vec![IdentityRegistryClaimedProfile {
            profile_id: "ck.profile.identity_registry.v1".to_owned(),
            claim_kind: "self_claimed".to_owned(),
        }],
        verified_profiles: Vec::new(),
        experimental_features: Vec::new(),
        compat_surfaces: Vec::new(),
        development_mode: state.config.development_mode,
        rate_limit_policy: IdentityRegistryRateLimitPolicy {
            kind: "windowed".to_owned(),
            per_minute: 600,
        },
        supported_did_methods,
        resolver_policy: IdentityResolverPolicy {
            allow_methods: state.config.did_resolver_allow_methods.clone(),
            freshness_receipts: IdentityFreshnessReceiptsPolicy {
                endpoint_template: "/_cokret/root/identity/receipts?did={did}".to_owned(),
            },
            webvh_validation: IdentityWebvhValidationPolicy {
                witness_quorum: "enforced_for_local_webvh_records".to_owned(),
            },
            trust_roots,
        },
        registry_visibility: IdentityRegistryVisibility {
            mode: "development_local".to_owned(),
            public_resolution: true,
            public_receipts: true,
            write_policy: "local_registry".to_owned(),
        },
        did_webvh,
        todos: Vec::new(),
    })
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
    /// Genesis-declared emergency recovery keys (multibase ed25519 public
    /// keys). When present they are written into `parameters.recoveryKeys` so a
    /// later emergency rotation (key-management.md §3.3) can be authorised by a
    /// recovery key without a previous-controller signature. The registering
    /// client MUST include the same values it signed over (they affect the SCID
    /// and entry hash).
    #[serde(default)]
    pub recovery_keys: Vec<String>,
    /// Genesis-declared organization governance threshold (identity-did.md §8).
    /// `{ "threshold": { "required": N, "eligible_methods": [...] } }`. When
    /// present it is written into `parameters.governance` so every later
    /// rotation MUST clear the N-of-M quorum. The registering client MUST
    /// include the same value it signed over.
    #[serde(default)]
    pub governance: Option<Value>,
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let mut parameters = json!({
        "scid": WEBVH_SCID_PLACEHOLDER,
        "method": WEBVH_METHOD_VERSION,
        "updateKeys": [body.update_public_key_multibase.clone()],
    });
    // Optional genesis-declared recovery keys + governance threshold. They are
    // part of the signed entry, so the client MUST have signed over the same
    // values — they flow through SCID derivation and the entry hash unchanged.
    if let Value::Object(map) = &mut parameters {
        if !body.recovery_keys.is_empty() {
            map.insert(
                "recoveryKeys".to_owned(),
                Value::Array(
                    body.recovery_keys
                        .iter()
                        .map(|key| Value::String(key.clone()))
                        .collect(),
                ),
            );
        }
        if let Some(governance) = body.governance.clone() {
            map.insert("governance".to_owned(), governance);
        }
    }
    let entry_skeleton = json!({
        "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
        "versionTime": version_time,
        "parameters": parameters,
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
    let event_digest = did_log_event_digest(&log_entry)?;
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
            key_log_head: Some(event_digest.clone()),
            seq: 1,
            method_evidence: json!({
                "mode": "embedded_webvh_provider",
                "provider_id": "soland.embedded",
                "local_id": local_id,
                "document_url": location.document_url,
                "log_url": location.log_url,
                "scid": location.scid,
                "version_id": version_id,
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
            event_digest: event_digest.clone(),
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
            "head_event_digest": event_digest,
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
        key_log_head: event_digest,
        document_url: location.document_url,
        log_url: location.log_url,
        did_document,
        did_log: vec![log_entry],
    })
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EmbeddedWebvhRotateRequestBody {
    /// The DID whose `did.jsonl` history a rotation entry is appended to.
    pub did: String,
    /// The next `did:webvh` log entry, already shaped by the client:
    /// `versionId` (`<seq>-<multibase-multihash>`), `previousVersionId`
    /// (the current head's `versionId`), `versionTime`, `parameters`
    /// (`updateKeys`, optional `witnesses` / `witness_threshold`), `state`
    /// (the new DID document), `proof[]` (controller / recovery / governance
    /// signatures), and optional `witness[]` attestations. soland appends it
    /// verbatim and re-validates the whole chain (hash chain, SCID, witness
    /// quorum, rotation authorisation) before persisting.
    #[salvo(schema(value_type = serde_json::Value))]
    pub log_entry: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EmbeddedWebvhRotateOutcome {
    pub status: String,
    pub did: String,
    pub seq: u64,
    pub key_log_head: String,
    pub did_document: Value,
    pub entry_count: usize,
}

/// Append a client-signed rotation entry to an embedded `did:webvh` history.
///
/// Unlike `submit-did-operation` (a method-neutral document replace), this
/// endpoint appends a real `did:webvh` log entry to `did.jsonl` and then runs
/// the full resolver validation gate over the resulting chain
/// (`run_webvh_resolution_checks`): hash chain link, SCID, witness quorum /
/// degraded window, and rotation control authorisation (controller proof,
/// recovery key, or organization governance quorum). It fails closed on any
/// integrity / authorisation break, so E9.1 (tampered prev hash), E9.3
/// (governance N-of-M) and E9.5 (recovery key) are all enforced at write time.
/// Spec: identity-did.md §3.4 / §4.2.1 / §7 / §8 + key-management.md §3.3.
#[endpoint(
    operation_id = "org.cokret.soland.identity.webvh.rotate",
    tags("identity"),
    summary = "Append a rotation entry to an embedded did:webvh history",
    status_codes(200, 400, 401, 404, 409, 422, 500, 503)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.identity.webvh.rotate"))]
pub(crate) async fn embedded_webvh_rotate(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<EmbeddedWebvhRotateRequestBody>,
) -> JsonResult<EmbeddedWebvhRotateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if !state.config.embedded_webvh_provider_enabled {
        return Err(AppError::not_found(
            "embedded did:webvh provider is disabled",
        ));
    }
    require_embedded_webvh_registration_bearer(state, req)?;
    let body = body.into_inner();
    let did = body.did.trim().to_owned();
    if validate_did(&did).is_err() || !did.starts_with("did:webvh:") {
        return Err(AppError::invalid_param("did must be a valid did:webvh"));
    }
    let entry = body.log_entry;
    if !entry.is_object() {
        return Err(AppError::invalid_param("log_entry must be an object"));
    }
    let version_id = entry
        .get("versionId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid_param("log_entry.versionId is required"))?;
    let new_document = entry
        .get("state")
        .filter(|state| state.is_object())
        .cloned()
        .ok_or_else(|| {
            AppError::invalid_param("log_entry.state (the new DID document) is required")
        })?;
    ensure_webvh_document_id(&did, &new_document)?;
    let event_digest = did_log_event_digest(&entry)?;

    // Load the existing log; the rotation MUST extend a known history.
    let mut events = state
        .persistence
        .webvh()
        .list_log_events(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if events.is_empty() {
        return Err(AppError::not_found(
            "no existing did:webvh history for did; register the genesis entry first",
        ));
    }
    let next_seq = events.iter().map(|event| event.seq).max().unwrap_or(0) + 1;

    // Build the candidate chain (existing entries + the new entry) and run the
    // full resolver validation gate over it before persisting anything.
    let mut candidate: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    candidate.push(WebvhLogEntry::new(entry.clone()));
    validate_log_chain(&candidate)?;
    verify_scid_against_did(&did, &candidate[0])?;
    validate_witness_policy_for_log(&candidate, now().timestamp())?;
    validate_rotation_authorization_for_log(&candidate)?;

    let submitted_at = now();
    state
        .persistence
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.clone(),
            did_document: new_document.clone(),
            key_log_head: Some(event_digest.clone()),
            seq: next_seq,
            method_evidence: json!({
                "mode": "embedded_webvh_provider",
                "provider_id": "soland.embedded",
                "rotation": true,
                "version_id": version_id,
            }),
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
            operation: entry,
            created_at: submitted_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    events.push(WebvhLogRecord {
        event_digest: event_digest.clone(),
        did: did.clone(),
        seq: next_seq,
        operation: json!({}),
        created_at: submitted_at,
    });
    append_audit_log(
        state,
        Some(&did),
        "identity.webvh_rotate",
        json!({
            "did": did.clone(),
            "seq": next_seq,
            "version_id": version_id.clone(),
            "head_event_digest": event_digest.clone(),
        }),
        "accepted",
    )
    .await;
    json_ok(EmbeddedWebvhRotateOutcome {
        status: "accepted".to_owned(),
        did,
        seq: next_seq,
        key_log_head: event_digest,
        did_document: new_document,
        entry_count: events.len(),
    })
}

fn ensure_webvh_document_id(did: &str, document: &Value) -> Result<(), AppError> {
    match document.get("id").and_then(Value::as_str) {
        Some(value) if value == did => Ok(()),
        Some(_) => Err(AppError::invalid_param(
            "log_entry.state.id does not match did",
        )),
        None => Err(AppError::invalid_param("log_entry.state.id is required")),
    }
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "embedded_webvh_document"))]
pub(crate) async fn embedded_webvh_document(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = body.did.as_str();
    if let Ok(Some(record)) = state.persistence.webvh().get_document(did).await {
        // G3.S3: every did:webvh resolution MUST first re-validate the
        // log chain, SCID derivation, configured witness quorum, and
        // rotation control authorisation. Rotation entries fail closed
        // when witness quorum is missing; non-rotation entries may only
        // remain in degraded_no_witness for the spec's 24h window.
        // Rotation control authorisation accepts a previous-controller
        // proof, a genesis-declared recovery key (key-management.md §3.3),
        // or an organization governance quorum (identity-did.md §8.1–§8.2).
        // Spec: identity-did.md §3.4 + §4.2.1 + §7 + §8.
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
    let sdk_document = state.did_resolver.resolve_did(&body.did).ok();
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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

fn did_log_event_digest(operation: &Value) -> Result<String, AppError> {
    cokret_sdk::canonical::canonical_sha256(operation)
        .map_err(|error| AppError::internal(format!("DID log entry digest failed: {error}")))
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
) -> JsonResult<IdentityLogListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    json_ok(IdentityLogListOutcome {
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
) -> JsonResult<IdentityReceiptListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    json_ok(IdentityReceiptListOutcome {
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
        "operation": operation.clone(),
        "submitted_at": submitted_at,
    });
    let submit_event_digest = format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(&event_payload).unwrap_or_default())
    );
    let operation_version_id = operation
        .get("versionId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let is_webvh_did = did.starts_with("did:webvh:");
    let is_webvh_log_operation = is_webvh_did && operation_version_id.is_some();
    let append_log_event = !is_webvh_did || is_webvh_log_operation;
    let (event_digest, log_operation) = if is_webvh_log_operation {
        (did_log_event_digest(&operation)?, operation.clone())
    } else {
        (submit_event_digest, event_payload.clone())
    };
    let previous_method_evidence = existing
        .as_ref()
        .map(|record| record.method_evidence.clone())
        .unwrap_or_else(|| json!({"mode": "development_local"}));
    let method_evidence = if let Some(version_id) = operation_version_id {
        json!({
            "mode": "submitted_operation",
            "source": "ck.root.identity.command.submit_did_operation",
            "version_id": version_id,
            "previous": previous_method_evidence,
        })
    } else if is_webvh_did {
        json!({
            "mode": "submitted_document",
            "source": "ck.root.identity.command.submit_did_operation",
            "previous": previous_method_evidence,
        })
    } else {
        json!({
            "mode": "submitted_operation",
            "source": "ck.root.identity.command.submit_did_operation",
            "previous": previous_method_evidence,
        })
    };
    state
        .persistence
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.clone(),
            did_document: document.clone(),
            key_log_head: append_log_event.then(|| event_digest.clone()),
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
    if append_log_event {
        state
            .persistence
            .webvh()
            .append_log_event(WebvhLogRecord {
                event_digest: event_digest.clone(),
                did: did.clone(),
                seq: next_seq,
                operation: log_operation,
                created_at: submitted_at,
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    append_audit_log(
        state,
        Some(&did),
        "identity.submit_did_operation",
        json!({
            "did": did.clone(),
            "seq": next_seq,
            "head_event_digest": append_log_event.then(|| event_digest.clone()),
        }),
        "accepted",
    )
    .await;
    let head_event_digest = if append_log_event {
        Some(Hash::new(event_digest.clone()).map_err(|error| {
            AppError::internal(format!(
                "DID operation digest failed SDK type validation: {error}"
            ))
        })?)
    } else {
        None
    };
    let receipts = if append_log_event {
        vec![json!({
            "service_did": state.config.service_did.clone(),
            "did": did,
            "head_event_digest": event_digest,
            "seq": next_seq,
            "issued_at": submitted_at,
        })]
    } else {
        Vec::new()
    };
    json_ok(DidOperationSubmitOutcome {
        status: "accepted".to_owned(),
        did: typed_did,
        seq: Some(next_seq),
        head_event_digest,
        operation_ref: None,
        receipts,
    })
}
