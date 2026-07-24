//! Identity / DID endpoint handlers.

use std::collections::BTreeMap;

use super::*;

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct RawDidDocumentJson(pub serde_json::Value);

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryDescription {
    pub protocol_version: String,
    pub service_type: String,
    pub service_id: Did,
    pub trust_domain: String,
    pub registry_mode: String,
    pub supported_receipts: Vec<String>,
    pub profiles: Vec<String>,
    pub supported_profiles: Vec<String>,
    pub supported_operations: Vec<String>,
    pub supported_bindings: Vec<IdentityRegistryBinding>,
    pub supported_features: Vec<String>,
    pub auth_metadata: IdentityRegistryAuthMetadata,

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

    pub did_webvh: Value,
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryBinding {
    pub kind: String,
    pub base_url: String,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryAuthMetadata {
    pub mode: String,
    pub read: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryPlaintextVisibility {
    pub default: String,
    pub services: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryClaimedProfile {
    pub profile_id: String,
    pub claim_kind: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryVerifiedProfile {
    pub profile_id: String,
    pub verifier: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryRateLimitPolicy {
    pub kind: String,
    pub per_minute: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityResolverPolicy {
    pub allow_methods: Vec<String>,
    pub freshness_receipts: IdentityFreshnessReceiptsPolicy,
    pub webvh_validation: IdentityWebvhValidationPolicy,

    pub trust_roots: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityFreshnessReceiptsPolicy {
    pub endpoint_template: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityWebvhValidationPolicy {
    pub witness_quorum: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityRegistryVisibility {
    pub mode: String,
    pub public_resolution: bool,
    pub public_receipts: bool,
    pub write_policy: String,
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "identity_describe"))]
pub(crate) async fn identity_describe(
    depot: &mut Depot,
) -> JsonResult<IdentityRegistryDescription> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let did_webvh = did_webvh_descriptor(state);
    let mut profiles = vec![
        "ak.profile.identity_registry.v1".to_owned(),
        "ak.identity.local-dev.v1".to_owned(),
    ];
    if did_webvh["enabled"].as_bool().unwrap_or(false) {
        profiles.push("ak.identity.webvh.provider.v1".to_owned());
    }
    let service_id = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid configured service_id: {error}")))?;
    let supported_did_methods = state
        .config()
        .did_resolver_allow_methods
        .iter()
        .map(|method| format!("did:{method}"))
        .collect::<Vec<_>>();
    let trust_roots = identity_trust_roots(state);
    let supported_features = vec![
        "ak.feature.identity.resolve.v1".to_owned(),
        "ak.feature.identity.receipts.v1".to_owned(),
        "ak.feature.identity.did_webvh.v1".to_owned(),
    ];

    json_ok(IdentityRegistryDescription {
        protocol_version: arkret_wire::constants::PROTOCOL_VERSION.to_owned(),
        service_type: "identity_registry".to_owned(),
        service_id,
        trust_domain: state.config().trust_domain.clone(),
        registry_mode: "development_local".to_owned(),
        supported_receipts: vec!["local".to_owned()],
        profiles: profiles.clone(),
        supported_profiles: profiles,
        supported_operations: vec![
            "ak.root.identity.registry.query.describe".to_owned(),
            "ak.root.identity.query.resolve".to_owned(),
            "ak.root.identity.document.resource.get".to_owned(),
            "ak.root.identity.log.query.list".to_owned(),
            "ak.root.identity.receipts.query.list".to_owned(),
            "ak.root.identity.command.submit_did_operation".to_owned(),
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE
                .to_owned(),
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_RESOURCE_GET
                .to_owned(),
        ],
        supported_bindings: vec![IdentityRegistryBinding {
            kind: "http".to_owned(),
            base_url: state.config().public_base_url.clone(),
            paths: vec![
                "/_arkret/root/identity/describe".to_owned(),
                "/_arkret/root/identity/resolve".to_owned(),
                "/_arkret/root/identity/document".to_owned(),
                "/_arkret/root/identity/log".to_owned(),
                "/_arkret/root/identity/receipts".to_owned(),
                "/_arkret/root/identity/submit-did-operation".to_owned(),
                arkret_models_identity::service_identity::SERVICE_REGISTRATION_ENSURE_PATH
                    .to_owned(),
                arkret_models_identity::service_identity::SERVICE_REGISTRATION_GET_PATH.to_owned(),
            ],
        }],
        supported_features: supported_features.clone(),
        auth_metadata: IdentityRegistryAuthMetadata {
            mode: if state.config().development_mode {
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
            profile_id: "ak.profile.identity_registry.v1".to_owned(),
            claim_kind: "self_claimed".to_owned(),
        }],
        verified_profiles: Vec::new(),
        experimental_features: Vec::new(),
        compat_surfaces: Vec::new(),
        development_mode: state.config().development_mode,
        rate_limit_policy: IdentityRegistryRateLimitPolicy {
            kind: "windowed".to_owned(),
            per_minute: 600,
        },
        supported_did_methods,
        resolver_policy: IdentityResolverPolicy {
            allow_methods: state.config().did_resolver_allow_methods.clone(),
            freshness_receipts: IdentityFreshnessReceiptsPolicy {
                endpoint_template: "/_arkret/root/identity/receipts?did={did}".to_owned(),
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

#[derive(Debug, Deserialize)]
pub struct EmbeddedWebvhRegisterRequestBody {
    #[serde(default)]
    pub local_id: Option<String>,
    pub did_public_key_multibase: String,
    pub update_public_key_multibase: String,
    pub next_update_public_key_multibase: String,
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
    /// `ArkretDeviceEnrollmentAuthority` service entry (decision 0002 / D1).
    /// When present it MUST be reflected in the reconstructed document so the
    /// SCID + log proof verify; absent for callers that designate no authority.
    #[serde(default)]
    pub device_enrollment_authority_did: Option<String>,
    /// Genesis-declared organization governance threshold (identity-did.md §8).
    /// `{ "threshold": { "required": N, "eligible_methods": [...] } }`. When
    /// present it is written into `parameters.governance` so every later
    /// rotation MUST clear the N-of-M quorum. The registering client MUST
    /// include the same value it signed over.
    #[serde(default)]
    pub governance: Option<Value>,
}

#[derive(Debug, Serialize)]
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.identity.webvh.register"))]
pub(crate) async fn embedded_webvh_register(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<EmbeddedWebvhRegisterRequestBody>,
) -> JsonResult<EmbeddedWebvhRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if !state.config().embedded_webvh_provider_enabled {
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
    if !valid_multibase_key(&body.next_update_public_key_multibase) {
        return Err(AppError::invalid_param(
            "next_update_public_key_multibase must be a non-empty multibase value",
        ));
    }
    for (role, key) in [
        ("DID authentication", body.did_public_key_multibase.as_str()),
        (
            "active identity root",
            body.update_public_key_multibase.as_str(),
        ),
        (
            "next identity root",
            body.next_update_public_key_multibase.as_str(),
        ),
    ] {
        crate::routing::identity::webvh_validation::decode_ed25519_public_key(key)
            .map_err(|error| AppError::invalid_param(format!("{role} key is invalid: {error}")))?;
    }
    if body.did_public_key_multibase == body.update_public_key_multibase
        || body.did_public_key_multibase == body.next_update_public_key_multibase
        || body.update_public_key_multibase == body.next_update_public_key_multibase
    {
        return Err(AppError::invalid_param(
            "DID authentication key, active identity root, and next identity root must be distinct",
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
        embedded_webvh_authority(&state.config().public_base_url).map_err(|message| {
            AppError::new(ErrorCode::TemporarilyUnavailable, message)
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    if state
        .dids()
        .embedded_document(&local_id)
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
        .config()
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
        "nextKeyHashes": [
            crate::routing::identity::webvh_validation::sha256_multihash_base58btc(
                body.next_update_public_key_multibase.as_bytes()
            )
        ],
    });
    // Optional governance threshold is part of the signed entry and therefore
    // flows through SCID derivation and the entry hash unchanged.
    if let Value::Object(map) = &mut parameters
        && let Some(governance) = body.governance.clone()
    {
        map.insert("governance".to_owned(), governance);
    }
    let entry_skeleton = json!({
        "versionId": WEBVH_SCID_PLACEHOLDER,
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
    let version_hash =
        webvh_entry_hash_multibase(&log_entry, &scid).map_err(AppError::invalid_param)?;
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
    let inception = [WebvhLogEntry::new(log_entry.clone())];
    validate_log_chain(&inception)?;
    verify_scid_against_did(&location.did, &inception[0])?;
    verify_log_subject(&location.did, &inception)?;
    validate_witness_policy_for_log(&inception, now.timestamp())?;
    validate_rotation_authorization_for_log(&inception)?;
    let document_record = WebvhDocumentRecord {
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
    };
    let commit = state
        .dids()
        .commit_log_operation(
            None,
            document_record.clone(),
            WebvhLogRecord {
                event_digest: event_digest.clone(),
                did: location.did.clone(),
                seq: 1,
                operation: log_entry.clone(),
                created_at: now,
            },
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if commit != WebvhLogCommitOutcome::Accepted {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "embedded did:webvh inception conflicts with existing history",
        ));
    }
    if let Err(error) = state
        .dids()
        .cache_resolved_document_state(document_record)
    {
        tracing::warn!(%error, "failed to cache embedded webvh DID document");
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

#[derive(Debug, Deserialize)]
pub struct EmbeddedWebvhRotateRequestBody {
    /// The DID whose `did.jsonl` history a rotation entry is appended to.
    pub did: String,
    /// The next `did:webvh` log entry, already shaped by the client:
    /// `versionId` (`<seq>-<multibase-multihash>`), `versionTime`, `parameters`
    /// (`updateKeys`, optional `witnesses` / `witness_threshold`), `state`
    /// (the new DID document), `proof[]` (controller / recovery / governance
    /// signatures), and optional `witness[]` attestations. soland appends it
    /// verbatim and re-validates the whole chain (hash chain, SCID, witness
    /// quorum, rotation authorisation) before persisting.
    pub log_entry: Value,
}

#[derive(Debug, Serialize)]
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
/// Like the standard `submit-did-operation` adapter, this provider-specific
/// endpoint appends a real `did:webvh` log entry to `did.jsonl` and runs the
/// full resolver validation gate over the resulting chain
/// (`run_webvh_resolution_checks`): hash chain link, SCID, witness quorum /
/// degraded window, and rotation control authorisation (controller proof,
/// recovery key, or organization governance quorum). It fails closed on any
/// integrity / authorisation break, so E9.1 (tampered prev hash), E9.3
/// (governance N-of-M) and E9.5 (recovery key) are all enforced at write time.
/// Spec: identity-did.md §3.4 / §4.2.1 / §7 / §8 + key-management.md §3.3.
#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.identity.webvh.rotate"))]
pub(crate) async fn embedded_webvh_rotate(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<EmbeddedWebvhRotateRequestBody>,
) -> JsonResult<EmbeddedWebvhRotateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if !state.config().embedded_webvh_provider_enabled {
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
        .dids()
        .log_events(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if events.is_empty() {
        return Err(AppError::not_found(
            "no existing did:webvh history for did; register the genesis entry first",
        ));
    }
    let current_head = events.last().expect("non-empty checked above");
    let next_seq = current_head.seq.checked_add(1).ok_or_else(|| {
        AppError::new(
            ErrorCode::CasConflict,
            "current did:webvh sequence cannot advance",
        )
    })?;
    let expected_current_head = Some(current_head.event_digest.clone());

    // Build the candidate chain (existing entries + the new entry) and run the
    // full resolver validation gate over it before persisting anything.
    let mut candidate: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    candidate.push(WebvhLogEntry::new(entry.clone()));
    validate_log_chain(&candidate)?;
    verify_scid_against_did(&did, &candidate[0])?;
    verify_log_subject(&did, &candidate)?;
    validate_witness_policy_for_log(&candidate, now().timestamp())?;
    validate_rotation_authorization_for_log(&candidate)?;

    let submitted_at = now();
    let document_record = WebvhDocumentRecord {
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
    };
    let commit = state
        .dids()
        .commit_log_operation(
            expected_current_head,
            document_record.clone(),
            WebvhLogRecord {
                event_digest: event_digest.clone(),
                did: did.clone(),
                seq: next_seq,
                operation: entry,
                created_at: submitted_at,
            },
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if commit != WebvhLogCommitOutcome::Accepted {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "did:webvh rotation lost the current head comparison",
        ));
    }
    if let Err(error) = state
        .dids()
        .cache_resolved_document_state(document_record)
    {
        tracing::warn!(%error, "failed to cache rotated webvh DID document");
    }
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

#[handler]
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "embedded_webvh_log"))]
pub(crate) async fn embedded_webvh_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res).await else {
        return;
    };
    let events = state
        .dids()
        .log_events(&record.did)
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.query.resolve"))]
pub(crate) async fn identity_resolve(
    body: JsonBody<IdentityResolveRequestBody>,
    depot: &mut Depot,
) -> JsonResult<IdentityResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = body.did.as_str();
    if let Ok(Some(record)) = state.dids().document(did).await {
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
    let sdk_document = state.dids().resolve_did(&body.did).await.ok();
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.document.resource.get"))]
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
    let mut did_document = serde_json::from_value::<BTreeMap<String, Value>>(record.did_document)
        .map_err(|error| {
        AppError::internal(format!("stored DID document is invalid: {error}"))
    })?;
    did_document
        .entry("id".to_owned())
        .or_insert_with(|| Value::String(typed_did.as_str().to_owned()));
    json_ok(IdentityDocumentViewOutcome(IdentityDocumentView {
        did_document,
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
    arkret_canonical::canonical_sha256(operation)
        .map_err(|error| AppError::internal(format!("DID log entry digest failed: {error}")))
}

fn identity_resolve_outcome(
    did: Did,
    document: Value,
    key_log_head: Option<Hash>,
    seq: Option<u64>,
    _method_evidence: Value,
) -> IdentityResolveOutcome {
    let mut did_document =
        serde_json::from_value::<BTreeMap<String, Value>>(document).unwrap_or_default();
    did_document
        .entry("id".to_owned())
        .or_insert_with(|| Value::String(did.as_str().to_owned()));
    IdentityResolveOutcome {
        did_document,
        key_log_head,
        seq,
        receipts: Vec::new(),
    }
}

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.identity.get_path_did_document")
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.log.query.list"))]
pub(crate) async fn identity_log(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityLogListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let records = state
        .dids()
        .log_events(&did)
        .await
        .unwrap_or_default();
    let mut previous_digest = None;
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let operation_name = record
            .operation
            .get("operation")
            .or_else(|| record.operation.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let operation = if record.seq == 0 {
            arkret_models_identity::DidKeyLogOperation::Inception
        } else if operation_name.contains("deactivate") {
            arkret_models_identity::DidKeyLogOperation::Deactivate
        } else if operation_name.contains("recover") {
            arkret_models_identity::DidKeyLogOperation::Recover
        } else if operation_name.contains("rotate") {
            arkret_models_identity::DidKeyLogOperation::Rotate
        } else {
            arkret_models_identity::DidKeyLogOperation::ServiceUpdate
        };
        let Some(operation_body) = record.operation.as_object().cloned() else {
            continue;
        };
        let Ok(mut entry) = arkret_models_identity::DidKeyLogEntry::build(
            Did::new(record.did).map_err(|error| AppError::internal(error.to_string()))?,
            record.seq,
            operation,
            previous_digest.clone(),
            operation_body,
            record.created_at,
        ) else {
            continue;
        };
        entry.head_event_digest = Hash::new(record.event_digest)
            .map_err(|error| AppError::internal(error.to_string()))?;
        previous_digest = Some(entry.head_event_digest.clone());
        events.push(entry);
    }
    json_ok(IdentityLogListOutcome {
        events,
        next_cursor: None,
        has_more: false,
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.receipts.query.list"))]
pub(crate) async fn identity_receipts(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityReceiptListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let record = state.dids().document(&did).await.ok().flatten();
    json_ok(IdentityReceiptListOutcome {
        receipts: Vec::new(),
        threshold_met: Some(record.is_none()),
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.command.submit_did_operation"))]
pub(crate) async fn identity_submit_did_operation(
    depot: &mut Depot,
    body: JsonBody<DidOperationSubmitRequestBody>,
) -> JsonResult<DidOperationSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = body.did.as_str().to_owned();
    let typed_did = body.did;
    let did_method = did
        .strip_prefix("did:")
        .and_then(|value| value.split(':').next())
        .ok_or_else(|| AppError::invalid_param("invalid did"))?;
    if body.did_method != did_method {
        return Err(AppError::invalid_param(
            "did_method must exactly match the DID method discriminator",
        ));
    }
    if did_method != "webvh" {
        return Err(AppError::invalid_param(
            "DID method is not supported by this operation adapter",
        ));
    }
    let next_seq = body
        .seq
        .ok_or_else(|| AppError::invalid_param("seq is required for did:webvh submission"))?;
    if next_seq > i64::MAX as u64 {
        return Err(AppError::invalid_param(
            "seq exceeds the supported persistence range",
        ));
    }
    let expected_previous_head = body
        .prev_event_digest
        .as_ref()
        .map(|digest| digest.as_str().to_owned());
    let operation = Value::Object(body.operation.into_iter().collect());
    let version_id = operation
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("operation.versionId is required"))?;
    let operation_seq = version_id
        .split_once('-')
        .and_then(|(sequence, hash)| (!hash.is_empty()).then_some(sequence))
        .and_then(|sequence| sequence.parse::<u64>().ok())
        .ok_or_else(|| AppError::invalid_param("operation.versionId must be <seq>-<hash>"))?;
    if operation_seq != next_seq {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "request seq must equal the native operation versionId sequence",
        ));
    }
    let document = operation
        .get("state")
        .filter(|document| document.is_object())
        .cloned()
        .ok_or_else(|| AppError::invalid_param("operation.state is required"))?;
    ensure_webvh_document_id(&did, &document)?;
    let event_digest = did_log_event_digest(&operation)?;
    let existing = state
        .dids()
        .document(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let events = state
        .dids()
        .log_events(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(existing_event) = events.iter().find(|event| {
        event.seq == next_seq
            || event.operation.get("versionId").and_then(Value::as_str) == Some(version_id)
    }) {
        if existing_event.event_digest == event_digest && existing_event.operation == operation {
            return did_operation_submit_outcome("duplicate", typed_did, next_seq, &event_digest);
        }
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "DID operation conflicts with an existing sequence or versionId",
        ));
    }
    let expected_next_seq = match events.last() {
        None => 1,
        Some(event) => event.seq.checked_add(1).ok_or_else(|| {
            AppError::new(
                ErrorCode::CasConflict,
                "current DID operation sequence cannot advance",
            )
        })?,
    };
    if next_seq != expected_next_seq {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "DID operation seq must advance the current log head exactly once",
        ));
    }
    let current_head = events.last().map(|event| event.event_digest.clone());
    if expected_previous_head
        .as_ref()
        .is_some_and(|expected| current_head.as_ref() != Some(expected))
    {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "prev_event_digest does not match the current log head",
        ));
    }
    let stored_state_matches_log = match (existing.as_ref(), events.last()) {
        (None, None) => true,
        (Some(document), Some(head)) => {
            document.seq == head.seq
                && document.key_log_head.as_deref() == Some(head.event_digest.as_str())
        }
        _ => false,
    };
    if !stored_state_matches_log {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "stored DID document and native log head are inconsistent",
        ));
    }

    let mut candidate: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    candidate.push(WebvhLogEntry::new(operation.clone()));
    validate_log_chain(&candidate)?;
    verify_scid_against_did(&did, &candidate[0])?;
    verify_log_subject(&did, &candidate)?;
    validate_witness_policy_for_log(&candidate, now().timestamp())?;
    validate_rotation_authorization_for_log(&candidate)?;

    let submitted_at = now();
    let document_record = WebvhDocumentRecord {
        did: did.clone(),
        did_document: document.clone(),
        key_log_head: Some(event_digest.clone()),
        seq: next_seq,
        method_evidence: json!({
            "mode": "submitted_operation",
            "source": "ak.root.identity.command.submit_did_operation",
            "version_id": version_id,
        }),
        // put_document authoritatively overwrites freshness evidence with
        // the ingestion instant, so placeholders are enough here.
        fetched_at: submitted_at,
        expires_at: submitted_at,
        updated_at: submitted_at,
    };
    let commit = state
        .dids()
        .commit_log_operation(
            current_head,
            document_record.clone(),
            WebvhLogRecord {
                event_digest: event_digest.clone(),
                did: did.clone(),
                seq: next_seq,
                operation,
                created_at: submitted_at,
            },
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    match commit {
        WebvhLogCommitOutcome::Conflict => {
            return Err(AppError::new(
                ErrorCode::CasConflict,
                "DID operation lost a concurrent head comparison",
            ));
        }
        WebvhLogCommitOutcome::Duplicate => {
            return did_operation_submit_outcome("duplicate", typed_did, next_seq, &event_digest);
        }
        WebvhLogCommitOutcome::Accepted => {}
    }
    if let Err(error) = state
        .dids()
        .cache_resolved_document_state(document_record)
    {
        tracing::warn!(%error, "failed to cache submitted DID document");
    }
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
    did_operation_submit_outcome("accepted", typed_did, next_seq, &event_digest)
}

fn did_operation_submit_outcome(
    status: &str,
    did: Did,
    seq: u64,
    event_digest: &str,
) -> JsonResult<DidOperationSubmitOutcome> {
    let head_event_digest = Hash::new(event_digest.to_owned()).map_err(|error| {
        AppError::internal(format!(
            "DID operation digest failed SDK type validation: {error}"
        ))
    })?;
    json_ok(DidOperationSubmitOutcome {
        status: status.to_owned(),
        did,
        seq: Some(seq),
        head_event_digest: Some(head_event_digest),
        operation_ref: None,
        receipts: Vec::new(),
    })
}
