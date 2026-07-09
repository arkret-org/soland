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
    event_id: &str,
    realm_id: &str,
    actor_id: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: Value,
) -> Result<(), AppError> {
    let actor_seq = state
        .persistence
        .events()
        .max_actor_seq(actor_id)
        .await
        .map_err(|error| AppError::internal(format!("MIMI actor frontier lookup: {error}")))?
        .unwrap_or(0)
        + 1;
    let mut envelope = json!({
        "event_id": event_id,
        "kind": arkret_sdk::events::kinds::MESSAGE_CREATE,
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "hlc": state.hlc.now(),
        "prev_refs": [],
        "payload": payload,
        "executed_by": state.config.service_did,
    });
    let canonical_source = mimi_event_canonical_source(&envelope);
    let canonical_bytes = canonical::canonical_json_bytes(&canonical_source).map_err(|error| {
        AppError::internal(format!("MIMI event canonicalization failed: {error}"))
    })?;
    let canonical_digest = canonical::sha256_digest(&canonical_bytes);
    let proof = mimi_event_proof(state, actor_id, &canonical_digest, created_at)?;
    envelope
        .as_object_mut()
        .ok_or_else(|| AppError::internal("MIMI event envelope is not an object"))?
        .insert("proofs".to_owned(), json!([proof]));
    let record = CanonicalEventRecord {
        event_id: event_id.to_owned(),
        actor_id: actor_id.to_owned(),
        actor_seq,
        realm_id: Some(realm_id.to_owned()),
        kind: arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned(),
        schema_id: EVENT_SCHEMA_ID.to_owned(),
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: created_at,
    };
    if let Err(error) = state.persistence.events().put(record).await {
        tracing::error!(%error, "mimi: failed to persist canonical message event");
        return Err(AppError::internal("MIMI canonical event store unavailable"));
    }
    Ok(())
}

pub(super) fn mimi_event_canonical_source(envelope: &Value) -> Value {
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
}

pub(super) fn mimi_event_proof(
    state: &AppState,
    actor_id: &str,
    event_digest: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Proof, AppError> {
    let verification_method = format!("{}#mimi-provider-facade-key", state.config.service_did);
    let binding = json!({
        "kind": "mimi_provider_service_proof",
        "event_digest": event_digest,
        "actor_id": actor_id,
        "verification_method": verification_method,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!(
            "MIMI proof binding canonicalization failed: {error}"
        ))
    })?;
    let jws =
        arkret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| {
                AppError::internal(format!("MIMI event proof signing failed: {error}"))
            })?;
    Ok(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(event_digest.to_owned())
            .map_err(|error| AppError::internal(format!("MIMI event digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        jws,
    })
}

pub(super) fn decode_mimi_update_payload(body: &Value) -> Result<Option<Value>, AppError> {
    let Some(opaque) = body.get("update").and_then(|update| update.get("payload")) else {
        return Err(
            AppError::invalid_param("MIMI room update requires update.payload")
                .with_wire_code("mimi_payload_invalid"),
        );
    };
    decode_optional_mimi_opaque_json(opaque, "payload_digest", "MIMI room update payload")
}

pub(super) fn mimi_room_binding_payload(update_payload: &Value) -> Option<&Value> {
    if update_payload.get("kind").and_then(Value::as_str) != Some("ck.mimi.room_binding") {
        return None;
    }
    update_payload.get("payload")
}

pub(super) fn decode_mimi_message_payload(body: &Value) -> Result<Value, AppError> {
    let opaque = body
        .get("ciphertext")
        .ok_or_else(|| AppError::invalid_param("MIMI submit_message requires ciphertext"))?;
    decode_required_mimi_opaque_json(opaque, "ciphertext_digest", "MIMI ciphertext payload")
}

pub(super) fn decode_optional_mimi_opaque_json(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Option<Value>, AppError> {
    let Some(bytes) = decode_mimi_opaque_bytes(opaque, digest_field, context, false)? else {
        return Ok(None);
    };
    let value =
        arkret_sdk::canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
            AppError::invalid_param(format!("{context} is not canonical JSON: {error}"))
                .with_wire_code("mimi_payload_invalid")
        })?;
    Ok(Some(value))
}

pub(super) fn decode_required_mimi_opaque_json(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Value, AppError> {
    let bytes = decode_mimi_opaque_bytes(opaque, digest_field, context, true)?
        .expect("required opaque payload returns bytes");
    arkret_sdk::canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
        AppError::invalid_param(format!("{context} is not canonical JSON: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })
}

pub(super) fn decode_mimi_opaque_bytes(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
    require_payload: bool,
) -> Result<Option<Vec<u8>>, AppError> {
    let digest = opaque
        .get(digest_field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::invalid_param(format!("{context} requires {digest_field}"))
                .with_wire_code("mimi_payload_invalid")
        })?;
    let payload = match opaque.get("payload").and_then(Value::as_str) {
        Some(payload) if !payload.trim().is_empty() => payload,
        _ if require_payload => {
            return Err(
                AppError::invalid_param(format!("{context} requires payload"))
                    .with_wire_code("mimi_payload_invalid"),
            );
        }
        _ => return Ok(None),
    };
    let bytes = arkret_sdk::base64url_decode(payload).map_err(|error| {
        AppError::invalid_param(format!("{context} payload is not base64url: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })?;
    let observed = arkret_sdk::canonical::sha256_digest(&bytes);
    if observed != digest {
        return Err(
            AppError::invalid_param(format!("{context} digest mismatch"))
                .with_wire_code("mimi_payload_digest_mismatch"),
        );
    }
    Ok(Some(bytes))
}

pub(super) fn mimi_provider_directory_value(state: &AppState) -> Value {
    json!({
        "schema": "ck.schema.mimi_interop.v1",
        "service_did": state.config.service_did.clone(),
        "service_type": "mimi_provider_facade",
        "supported_profiles": ["ck.profile.mimi_interop.v1"],
        "mimi": {
            "protocol_draft": "draft-ietf-mimi-protocol-06",
            "content_draft": "draft-ietf-mimi-content-08",
            "room_policy_draft": "draft-ietf-mimi-room-policy-03",
            "identifier_draft": "draft-kohbrok-mimi-identifiers-01",
            "base_url": mimi_base_url(state),
            "provider_id": mimi_provider_id(state),
            "features": [
                "key_material",
                "room_update",
                "notify",
                "submit_message",
                "group_info",
                "consent",
                "identifier_query",
                "report_abuse",
                "proxy_download"
            ],
            "mls_cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "content_profiles": [
                "application/mimi-content",
                "text/plain;charset=utf-8",
                "text/markdown;variant=GFM-MIMI",
                "application/vnd.arkret.content+json"
            ],
            "room_policy_components": [
                "roles",
                "membership",
                "history_visibility",
                "join_rule",
                "message_expiration",
                "asset_privacy"
            ]
        },
        "proof": {
            "type": "dev_service_digest",
            "kid": format!("{}#mimi-provider", state.config.service_did),
            "alg": "sha256-dev",
            "sig": sha256_hex(format!("{}:ck.profile.mimi_interop.v1", state.config.service_did).as_bytes())
        }
    })
}

pub(super) fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/_arkret/open/mimi",
        state.config.public_base_url.trim_end_matches('/')
    )
}

pub(super) fn mimi_provider_id(state: &AppState) -> String {
    service_did_mimi_provider_id(&state.config.service_did)
}

pub(super) fn service_did_mimi_provider_id(service_did: &str) -> String {
    if let Some(domain) = service_did.strip_prefix("did:web:") {
        return format!("mimi://{}", domain.replace(':', "/"));
    }
    if let Some(rest) = service_did.strip_prefix("did:webvh:") {
        let mut parts = rest.splitn(2, ':');
        if parts.next().is_some_and(|scid| !scid.is_empty())
            && let Some(authority_and_path) = parts.next()
            && !authority_and_path.is_empty()
        {
            return format!("mimi://{}", authority_and_path.replace(':', "/"));
        }
    }
    format!("mimi://{}", service_did.replace(':', "."))
}

pub(super) fn mimi_room_uri(state: &AppState, room_id: &str) -> String {
    format!("{}/rooms/{room_id}", mimi_provider_id(state))
}

pub(super) fn mimi_receipt(
    state: &AppState,
    operation_id: &str,
    body: &Value,
    extra: Value,
) -> Value {
    json!({
        "profile": "ck.profile.mimi_interop.v1",
        "operation_id": operation_id,
        "service_did": state.config.service_did,
        "provider_id": mimi_provider_id(state),
        "request_hash": arkret_sdk::canonical::sha256_digest(body.to_string().as_bytes()),
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
    pub(super) encrypted: bool,
    pub(super) policy: Value,
    pub(super) quarantine: Option<Value>,
    pub(super) status: &'static str,
}

pub(super) fn map_mimi_message_content(
    body: &Value,
    source_format: &str,
) -> Result<MimiMappedContent, AppError> {
    let mut content = mimi_content_payload(body, source_format);
    let content_kind = mimi_content_kind(body, &content).map(str::to_owned);
    let e2ee_boundary = mimi_e2ee_boundary(body, &content);
    let plaintext_detected = mimi_plaintext_detected(body) || mimi_plaintext_detected(&content);
    let transcript_binding = mimi_transcript_binding(body, &content).cloned();
    let explicit_downgrade = mimi_explicit_downgrade(body, &content);

    if e2ee_boundary && plaintext_detected && transcript_binding.is_none() && !explicit_downgrade {
        return Err(AppError::invalid_param(
            "MIMI E2EE plaintext requires transcript_binding or explicit e2ee_downgrade marker",
        )
        .with_wire_code("mimi_e2ee_boundary_unmarked"));
    }

    let mut policy = json!({
        "profile": "ck.profile.mimi_interop.v1",
        "e2ee_boundary": "none",
        "plaintext_detected": plaintext_detected,
        "plaintext_guard": "not_e2ee",
    });
    let mut encrypted = e2ee_boundary && !explicit_downgrade;

    if e2ee_boundary && explicit_downgrade {
        ensure_content_object(&mut content);
        let object = content.as_object_mut().expect("content object");
        object.insert(
            "ck.morph.e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        object.insert(
            "e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        policy = json!({
            "profile": "ck.profile.mimi_interop.v1",
            "e2ee_boundary": "explicit_downgrade",
            "plaintext_detected": plaintext_detected,
            "plaintext_guard": "marked_explicit_downgrade",
            "downgrade_marker": "mimi_bridge",
        });
        encrypted = false;
    } else if e2ee_boundary {
        if let Some(binding) = transcript_binding {
            ensure_content_object(&mut content);
            let object = content.as_object_mut().expect("content object");
            object.insert("transcript_binding".to_owned(), binding.clone());
            object.insert(
                "ck.morph.e2ee_boundary".to_owned(),
                Value::String("transcript_bound".to_owned()),
            );
            policy = json!({
                "profile": "ck.profile.mimi_interop.v1",
                "e2ee_boundary": "transcript_bound",
                "plaintext_detected": plaintext_detected,
                "plaintext_guard": "transcript_binding",
                "transcript_binding": binding,
            });
        } else {
            policy = json!({
                "profile": "ck.profile.mimi_interop.v1",
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
            "raw_payload_hash": arkret_sdk::canonical::sha256_digest(content.to_string().as_bytes()),
        });
        let content = json!({
            "kind": "ck.content.unsupported",
            "body": "unsupported content from MIMI",
            "ck.morph.unknown_content_kind": kind,
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
            encrypted: false,
            policy,
            quarantine: Some(quarantine),
            status: "quarantined",
        });
    }

    Ok(MimiMappedContent {
        content,
        encrypted,
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
            "kind": "ck.content.text",
            "body": text,
            "raw_mimi_source_format": source_format,
        })
    })
}

pub(super) fn ensure_content_object(content: &mut Value) {
    if !content.is_object() {
        let raw = content.clone();
        *content = json!({
            "kind": "ck.content.opaque",
            "raw_mimi_content": raw,
        });
    }
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
            | "ck.message.text"
            | "ck.message.revise"
            | "ck.message.redact"
            | "ck.content.text"
            | "ck.content.composite"
            | "ck.content.markdown"
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
    downgrade_marker(body.get("e2ee_downgrade"))
        || downgrade_marker(body.get("ck.morph.e2ee_downgrade"))
        || downgrade_marker(content.get("e2ee_downgrade"))
        || downgrade_marker(content.get("ck.morph.e2ee_downgrade"))
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
