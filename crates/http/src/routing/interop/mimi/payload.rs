use super::*;

pub(super) fn typed_body_value<T: Serialize>(
    body: T,
    context: &'static str,
) -> Result<Value, AppError> {
    serde_json::to_value(body)
        .map_err(|error| AppError::internal(format!("{context} request body serialize: {error}")))
}

pub(super) async fn persist_mimi_canonical_message_event(
    state: &AppState,
    realm_id: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: Value,
) -> Result<String, AppError> {
    let service_event_lock = crate::routing::events::event_log::service_event_authoring_lock();
    let _service_event_guard = service_event_lock.lock().await;
    let actor_id = state.service_id().as_str();
    let scoped_records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id, actor_id)
        .await
        .map_err(|error| AppError::internal(format!("MIMI actor frontier lookup: {error}")))?;
    let max_actor_seq = scoped_records.iter().map(|record| record.actor_seq).max();
    let mut prev_refs = scoped_records
        .into_iter()
        .filter(|record| Some(record.actor_seq) == max_actor_seq)
        .map(|record| {
            arkret_identifiers::EventId::new(record.event_id).map_err(|error| {
                AppError::internal(format!("stored MIMI actor frontier id invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    prev_refs.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    prev_refs.dedup();
    let actor_seq = max_actor_seq
        .map(|value| {
            value.checked_add(1).ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierSequenceExhausted,
                    "MIMI service actor sequence is exhausted",
                )
                .with_status(StatusCode::CONFLICT)
            })
        })
        .transpose()?
        .unwrap_or(0);
    let service_did = state.service_resolution_commitment().full_id.clone();
    let service_actor_id = arkret_wire::project_full_id_to_core_id(&service_did)
        .map_err(|error| AppError::internal(format!("service DID cannot be projected: {error}")))?;
    let hlc = arkret_identifiers::Hlc::new(state.hlc().now())
        .map_err(|error| AppError::internal(format!("MIMI HLC invalid: {error}")))?;
    let typed_payload: arkret_models_collaboration::events_payloads::MessageCreatePayload =
        serde_json::from_value(payload)
            .map_err(|error| AppError::internal(format!("MIMI Event payload invalid: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(format!("{service_did}#notary-key"))
        .map_err(|error| {
            AppError::internal(format!(
                "service notary verification method is invalid: {error}"
            ))
        })?;
    let realm = arkret_identifiers::RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::internal(format!("MIMI Realm id invalid: {error}")))?;
    let seal = crate::notary::ensure_realm_seal_head(state, &realm)
        .map_err(|error| AppError::internal(format!("MIMI Realm Seal lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "MIMI target Realm has no accepted Seal",
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    let digest_suite = state.projections().realm_digest_suite(realm.as_str());
    // The CBA basis is a producer-signed envelope member, so it belongs on the
    // draft. Attaching it after authoring only worked while signing silently
    // re-derived `event_id`, which is exactly the identity hole this closes.
    let auth_context = arkret_wire::AuthContext {
        actor_id: service_actor_id.clone(),
        key_id: arkret_wire::OpaqueLocalId::new("notary-key").expect("notary key id is opaque"),
        key_epoch: 0,
        credential_epoch: None,
    };
    let mut event =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            service_actor_id.clone(),
            service_actor_id,
            typed_payload,
        )
        .and_then(|draft| {
            draft
                .with_prev_refs(prev_refs)
                .with_seal_ref(seal.id)
                .with_auth_context(auth_context)
                .author_with_digest_suite(actor_seq, hlc, created_at, digest_suite)
        })
        .map_err(|error| AppError::internal(format!("MIMI Event build failed: {error}")))?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        service_did,
        verification_method.clone(),
    );
    let canonical_created_at = event.created_at;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(canonical_created_at),
    )
    .map_err(|error| AppError::internal(format!("MIMI Event signing failed: {error}")))?;
    let event_id = event.event_id().to_string();
    let now = chrono::Utc::now();
    let session = soland_services::identity::SessionIdentityState {
        token_hash: "mimi-provider-facade".to_owned(),
        actor: state.service_id().clone(),
        // Service session: this internal admission authenticates a service
        // identity, which owns no device (see `envelope_core`).
        device_id: String::new(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now + chrono::Duration::minutes(5),
        created_at: now,
        revoked_at: None,
    };
    let envelope = serde_json::to_value(event)
        .map_err(|error| AppError::internal(format!("MIMI Event serialize failed: {error}")))?;
    let binding_ref = envelope
        .get("payload")
        .and_then(|payload| payload.get("metadata"))
        .and_then(|metadata| metadata.get("mimi_provenance"))
        .and_then(|provenance| provenance.get("mimi_room_binding_ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("MIMI room binding ref missing from Event payload"))?
        .to_owned();
    crate::routing::events::event_log::submit_mimi_event_value(
        state,
        &session,
        envelope,
        realm_id,
        &binding_ref,
    )
    .await
    .map_err(|error| {
        AppError::new(
            soland_http::error::ErrorCode::ParamInvalid,
            format!("MIMI Event admission failed: {}", error.message),
        )
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    Ok(event_id)
}

pub(super) fn decode_mimi_update_payload(body: &Value) -> Result<Option<Value>, AppError> {
    let Some(opaque) = body.get("update").and_then(|update| update.get("payload")) else {
        return Err(
            AppError::param_invalid("MIMI room update requires update.payload")
                .with_wire_code("mimi_payload_invalid"),
        );
    };
    decode_optional_mimi_opaque_json(opaque, "payload_digest", "MIMI room update payload")
}

pub(super) fn mimi_room_binding_payload(update_payload: &Value) -> Option<&Value> {
    if update_payload.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::event_kind_str::MIMI_ROOM_BINDING)
    {
        return None;
    }
    update_payload.get("payload")
}

pub(super) fn decode_mimi_ciphertext_payload(
    ciphertext: &MimiCiphertext,
) -> Result<Value, AppError> {
    let bytes =
        arkret_canonical::base64url_decode(ciphertext.payload.as_str()).map_err(|error| {
            AppError::param_invalid(format!("MIMI ciphertext payload is not base64url: {error}"))
                .with_wire_code("mimi_payload_invalid")
        })?;
    if arkret_canonical::sha256_digest(&bytes) != ciphertext.ciphertext_digest.as_str() {
        return Err(
            AppError::param_invalid("MIMI ciphertext payload digest mismatch")
                .with_wire_code("mimi_payload_digest_mismatch"),
        );
    }
    arkret_canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
        AppError::param_invalid(format!(
            "MIMI ciphertext payload is not canonical JSON: {error}"
        ))
        .with_wire_code("mimi_payload_invalid")
    })
}

pub(super) fn decode_mimi_associated_data(
    associated_data: Option<&MimiOpaquePayload>,
) -> Result<Option<Value>, AppError> {
    let Some(associated_data) = associated_data else {
        return Ok(None);
    };
    let Some(payload) = associated_data.payload.as_ref() else {
        return Ok(None);
    };
    let bytes = arkret_canonical::base64url_decode(payload.as_str()).map_err(|error| {
        AppError::param_invalid(format!("MIMI associated_data is not base64url: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })?;
    if arkret_canonical::sha256_digest(&bytes) != associated_data.payload_digest.as_str() {
        return Err(
            AppError::param_invalid("MIMI associated_data digest mismatch")
                .with_wire_code("mimi_payload_digest_mismatch"),
        );
    }
    arkret_canonical::from_canonical_json_slice::<Value>(&bytes)
        .map(Some)
        .map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI associated_data is not canonical JSON: {error}"
            ))
            .with_wire_code("mimi_payload_invalid")
        })
}

pub(super) fn decode_optional_mimi_opaque_json(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Option<Value>, AppError> {
    let Some(bytes) = decode_mimi_opaque_bytes(opaque, digest_field, context)? else {
        return Ok(None);
    };
    let value = arkret_canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
        AppError::param_invalid(format!("{context} is not canonical JSON: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })?;
    Ok(Some(value))
}

pub(super) fn decode_mimi_opaque_bytes(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Option<Vec<u8>>, AppError> {
    let digest = opaque
        .get(digest_field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid(format!("{context} requires {digest_field}"))
                .with_wire_code("mimi_payload_invalid")
        })?;
    let payload = match opaque.get("payload").and_then(Value::as_str) {
        Some(payload) if !payload.trim().is_empty() => payload,
        _ => return Ok(None),
    };
    let bytes = arkret_canonical::base64url_decode(payload).map_err(|error| {
        AppError::param_invalid(format!("{context} payload is not base64url: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })?;
    let observed = arkret_canonical::sha256_digest(&bytes);
    if observed != digest {
        return Err(
            AppError::param_invalid(format!("{context} digest mismatch"))
                .with_wire_code("mimi_payload_digest_mismatch"),
        );
    }
    Ok(Some(bytes))
}

pub(super) fn mimi_provider_directory_value(
    state: &AppState,
) -> Result<arkret_models_collaboration::objects::interop::ProviderDirectory, AppError> {
    use arkret_models_collaboration::objects::interop::{
        ProviderDirectory, ProviderDirectoryEndpoint, ProviderDirectoryMimi, ProviderDirectoryProof,
    };
    use arkret_wire::PayloadSigner as _;

    // ProviderDirectory still carries the resolution-bearing DID shape. The
    // service's stable core id is used in transport headers; obtain the full
    // controller from the verified local resolution commitment instead of
    // trying to reconstruct a DID from the core id.
    let service_full_id = state.service_resolution_commitment().full_id.clone();
    let service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service core id invalid: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(format!("{}#notary-key", service_full_id))
        .map_err(|error| {
        AppError::internal(format!("service notary key id invalid: {error}"))
    })?;
    let placeholder = arkret_wire::PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
            .map_err(|error| AppError::internal(format!("placeholder digest invalid: {error}")))?,
        created_at: chrono::Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
    };
    let mut directory = ProviderDirectory {
        schema: arkret_wire::SchemaId::MIMI_INTEROP_V1.to_owned(),
        service_id: service_id.clone(),
        service_kind: "mimi_provider_facade".to_owned(),
        supported_profiles: vec![arkret_wire::ProfileId::MIMI_INTEROP_V1.to_owned()],
        mimi: ProviderDirectoryMimi {
            protocol_draft: "draft-ietf-mimi-protocol-06".to_owned(),
            content_draft: "draft-ietf-mimi-content-08".to_owned(),
            room_policy_draft: "draft-ietf-mimi-room-policy-03".to_owned(),
            identifier_draft: "draft-kohbrok-mimi-identifiers-01".to_owned(),
            base_url: mimi_base_url(state),
            provider_id: MimiUri::new(mimi_provider_id(state)).map_err(|error| {
                AppError::internal(format!("derived MIMI provider id is invalid: {error}"))
            })?,
            endpoints: [
                ("consent", "/consent/request"),
                ("group_info", "/strands/{strand_id}/group-info"),
                ("identifier_query", "/identifiers/query"),
                ("key_material", "/key-material"),
                ("notify", "/strands/{strand_id}/notify"),
                ("proxy_download", "/proxy-download"),
                ("report_abuse", "/report-abuse"),
                ("room_update", "/strands/{strand_id}/update"),
                ("submit_message", "/strands/{strand_id}/messages"),
            ]
            .into_iter()
            .map(|(endpoint_id, relative_path)| ProviderDirectoryEndpoint {
                endpoint_id: endpoint_id.to_owned(),
                relative_path: relative_path.to_owned(),
            })
            .collect(),
            features: [
                "consent",
                "group_info",
                "identifier_query",
                "key_material",
                "notify",
                "proxy_download",
                "report_abuse",
                "room_update",
                "submit_message",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            mls_cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            content_profiles: [
                "application/mimi-content",
                "application/vnd.arkret.content+json",
                "text/markdown;variant=GFM-MIMI",
                "text/plain;charset=utf-8",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            room_policy_components: [
                "asset_privacy",
                "history_access",
                "join_rule",
                "membership",
                "message_expiration",
                "roles",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            extra: Default::default(),
        },
        proof: ProviderDirectoryProof(placeholder),
        extra: Default::default(),
    };
    let projection = directory.unsigned_projection_bytes().map_err(|error| {
        AppError::internal(format!(
            "MIMI provider directory canonicalization failed: {error}"
        ))
    })?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        service_full_id,
        verification_method,
    );
    let signature = signer.sign_payload(&projection).map_err(|error| {
        AppError::internal(format!("MIMI provider directory signing failed: {error}"))
    })?;
    directory.proof = ProviderDirectoryProof(arkret_wire::PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: signature.verification_method,
        payload_digest: signature.payload_digest,
        created_at: signature.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: signature.jws,
    });
    Ok(directory)
}

pub(super) fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/_arkret/open/mimi",
        state.config().public_base_url.trim_end_matches('/')
    )
}

pub(super) fn mimi_provider_id(state: &AppState) -> String {
    service_id_mimi_provider_id(state.service_full_id().as_str())
}

/// A `did:web` / `did:webvh` service id projected onto the MIMI provider id.
///
/// The DID form escapes an authority port as `%3A`, and a DID may be written
/// with a mixed-case host. Both are decoded/folded here so the derived value
/// meets the canonical `mimi://` authority rules of
/// `zh/extensions/mimi-interop.md` §4; every room URI built on top of it is the
/// `ak.component.mimi.room_binding.v1` cell subject, where two spellings would
/// address two cells.
pub(super) fn service_id_mimi_provider_id(service_id: &str) -> String {
    if let Some(domain) = service_id.strip_prefix("did:web:") {
        return format!("mimi://{}", canonical_mimi_authority(domain));
    }
    if let Some(rest) = service_id.strip_prefix("did:webvh:") {
        let mut parts = rest.splitn(2, ':');
        if parts.next().is_some_and(|scid| !scid.is_empty())
            && let Some(authority_and_path) = parts.next()
            && !authority_and_path.is_empty()
        {
            return format!("mimi://{}", canonical_mimi_authority(authority_and_path));
        }
    }
    format!("mimi://{}", service_id.replace(':', ".").to_lowercase())
}

/// DID authority (`host%3Aport:path:segments`) -> canonical `host[:port]/path`.
///
/// The two separators are decoded in this order on purpose: `:` is the DID path
/// separator and becomes `/`, while the escaped `%3A` is the authority port
/// separator and becomes `:`. Decoding the escape first would turn a port into
/// a path segment.
fn canonical_mimi_authority(authority: &str) -> String {
    authority
        .replace(':', "/")
        .replace("%3A", ":")
        .replace("%3a", ":")
        .to_lowercase()
}

/// Canonical room URI for a locally hosted MIMI room.
///
/// Validated through the SDK type rather than string-formatted, because a
/// non-canonical value would either be rejected downstream by the payload
/// schema or, worse, address a second cell for the same room.
pub(super) fn mimi_room_uri(state: &AppState, room_id: &str) -> Result<MimiRoomUri, AppError> {
    MimiRoomUri::new(format!("{}/rooms/{room_id}", mimi_provider_id(state))).map_err(|error| {
        AppError::param_invalid(format!(
            "room_id does not form a canonical MIMI room URI: {error}"
        ))
    })
}

pub(super) fn mimi_receipt(
    state: &AppState,
    operation_id: &str,
    body: &Value,
    extra: Value,
) -> Value {
    json!({
        "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
        "operation_id": operation_id,
        "service_id": state.service_id(),
        "provider_id": mimi_provider_id(state),
        "request_hash": arkret_canonical::sha256_digest(body.to_string().as_bytes()),
        "accepted_at": now(),
        "drafts": {
            "protocol": "draft-ietf-mimi-protocol-06",
            "content": "draft-ietf-mimi-content-08",
            "room_policy": "draft-ietf-mimi-room-policy-03",
            "identifiers": "draft-kohbrok-mimi-identifiers-01"
        },
        "extra": extra
    })
}

pub(super) struct MimiMappedContent {
    pub(super) content: Value,
    pub(super) policy: Value,
    pub(super) quarantine: Option<Value>,
    pub(super) status: &'static str,
}

pub(super) fn map_mimi_message_content(
    body: &Value,
    source_format: &str,
) -> Result<MimiMappedContent, AppError> {
    let mut content = mimi_content_payload(body, source_format);
    if !content.is_object() {
        return Err(AppError::param_invalid(
            "unsupported MIMI content format: content must map to an Arkret content block",
        ));
    }
    let content_kind = mimi_content_kind(body, &content).map(str::to_owned);
    if let Some(kind) = content_kind.as_deref()
        && matches!(
            kind,
            "m.text" | "text/plain" | "text/markdown" | "m.markdown"
        )
    {
        let object = content
            .as_object_mut()
            .expect("content object checked above");
        object.insert(
            "kind".to_owned(),
            Value::String(
                arkret_models_collaboration::events_payloads::CONTENT_KIND_TEXT.to_owned(),
            ),
        );
        object
            .entry("source_format".to_owned())
            .or_insert_with(|| Value::String(kind.to_owned()));
    }
    let e2ee_boundary = mimi_e2ee_boundary(body, &content);
    let plaintext_detected = mimi_plaintext_detected(body) || mimi_plaintext_detected(&content);
    let transcript_binding = mimi_transcript_binding(body, &content).cloned();
    let explicit_downgrade = mimi_explicit_downgrade(body, &content);

    if e2ee_boundary && plaintext_detected && transcript_binding.is_none() && !explicit_downgrade {
        return Err(AppError::param_invalid(
            "MIMI E2EE plaintext requires transcript_binding or explicit e2ee_downgrade marker",
        )
        .with_wire_code("mimi_e2ee_boundary_unmarked"));
    }

    let mut policy = json!({
        "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
        "e2ee_boundary": "none",
        "plaintext_detected": plaintext_detected,
        "plaintext_guard": "not_e2ee",
    });
    if e2ee_boundary && explicit_downgrade {
        let object = content.as_object_mut().expect("content object");
        object.insert(
            "e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        policy = json!({
            "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
            "e2ee_boundary": "explicit_downgrade",
            "plaintext_detected": plaintext_detected,
            "plaintext_guard": "marked_explicit_downgrade",
            "downgrade_marker": "mimi_bridge",
        });
    } else if e2ee_boundary {
        if let Some(binding) = transcript_binding {
            let object = content.as_object_mut().expect("content object");
            object.insert("transcript_binding".to_owned(), binding.clone());
            policy = json!({
                "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
                "e2ee_boundary": "transcript_bound",
                "plaintext_detected": plaintext_detected,
                "plaintext_guard": "transcript_binding",
                "transcript_binding": binding,
            });
        } else {
            policy = json!({
                "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
                "e2ee_boundary": "opaque_ciphertext",
                "plaintext_detected": false,
                "plaintext_guard": "opaque_ciphertext_only",
            });
        }
    }

    if let Some(kind) = content_kind
        .as_deref()
        .filter(|kind| !valid_mimi_content_kind(kind))
    {
        let quarantine_id = ids::generate("mimi_quarantine");
        let quarantine = json!({
            "quarantine_id": quarantine_id,
            "unknown_content_kind": kind,
            "reason": "unknown_mimi_content_kind",
            "raw_payload_hash": arkret_canonical::sha256_digest(content.to_string().as_bytes()),
        });
        let content = json!({
            "kind": "ak.content.text",
            "body": "unsupported content from MIMI",
            "unknown_content_kind": kind,
            "quarantine": quarantine.clone(),
        });
        let mut policy = policy;
        if let Some(object) = policy.as_object_mut() {
            object.insert(
                "content_quarantine".to_owned(),
                Value::String("unknown_mimi_content_kind".to_owned()),
            );
        }
        return Ok(MimiMappedContent {
            content,
            policy,
            quarantine: Some(quarantine),
            status: "quarantined",
        });
    }

    Ok(MimiMappedContent {
        content,
        policy,
        quarantine: None,
        status: "mapped",
    })
}

pub(super) fn mimi_content_payload(body: &Value, source_format: &str) -> Value {
    body.get("content").cloned().unwrap_or_else(|| {
        let text = body
            .get("body")
            .or_else(|| body.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        json!({
            "kind": "ak.content.text",
            "body": text,
            "raw_mimi_source_format": source_format,
        })
    })
}

pub(super) fn mimi_content_kind<'a>(body: &'a Value, content: &'a Value) -> Option<&'a str> {
    body.get("content_kind")
        .or_else(|| body.get("mimi_content_kind"))
        .and_then(Value::as_str)
        .or_else(|| content.get("kind").and_then(Value::as_str))
}

pub(super) fn valid_mimi_content_kind(kind: &str) -> bool {
    matches!(
        kind,
        "m.text"
            | "text/plain"
            | "text/markdown"
            | "m.markdown"
            | arkret_wire::event_kind_str::MESSAGE_REVISE
            | arkret_wire::event_kind_str::MESSAGE_REDACT
            | "ak.content.text"
            | "ak.content.composite"
    )
}

pub(super) fn mimi_e2ee_boundary(body: &Value, content: &Value) -> bool {
    truthy_field(body, "e2ee")
        || truthy_field(body, "encrypted")
        || truthy_field(content, "e2ee")
        || truthy_field(content, "encrypted")
        || encryption_profile_enabled(body.get("encryption_profile"))
        || encryption_profile_enabled(body.get("source_encryption"))
        || encryption_profile_enabled(content.get("encryption_profile"))
        || encryption_profile_enabled(content.get("source_encryption"))
}

pub(super) fn truthy_field(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => matches!(
            value.as_str(),
            "true" | "e2ee" | "encrypted" | "mls" | "mls_rfc9420" | "mimi_mls"
        ),
        _ => false,
    }
}

pub(super) fn encryption_profile_enabled(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|profile| !matches!(profile, "" | "none" | "plaintext" | "unencrypted"))
}

pub(super) fn mimi_transcript_binding<'a>(
    body: &'a Value,
    content: &'a Value,
) -> Option<&'a Value> {
    body.get("transcript_binding")
        .or_else(|| body.get("mls_transcript_binding"))
        .or_else(|| content.get("transcript_binding"))
        .or_else(|| content.get("mls_transcript_binding"))
}

pub(super) fn mimi_explicit_downgrade(body: &Value, content: &Value) -> bool {
    downgrade_marker(body.get("e2ee_downgrade")) || downgrade_marker(content.get("e2ee_downgrade"))
}

pub(super) fn downgrade_marker(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|marker| marker == "mimi_bridge" || marker == "explicit")
}

pub(super) fn mimi_plaintext_detected(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            if matches!(
                key.as_str(),
                "body" | "text" | "plain_text" | "markdown" | "html"
            ) {
                value.as_str().is_some_and(|text| !text.trim().is_empty())
            } else if matches!(
                key.as_str(),
                "ciphertext" | "ciphertext_hash" | "digest" | "hash" | "original_envelope_hash"
            ) {
                false
            } else {
                mimi_plaintext_detected(value)
            }
        }),
        Value::Array(values) => values.iter().any(mimi_plaintext_detected),
        _ => false,
    }
}
