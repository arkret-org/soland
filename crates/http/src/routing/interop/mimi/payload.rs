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
    created_at: chrono::DateTime<chrono::Utc>,
    payload: Value,
) -> Result<(), AppError> {
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
    let service_did = arkret_identifiers::Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_identifiers::EventId::new(event_id.to_owned())
            .map_err(|error| AppError::internal(format!("MIMI event id invalid: {error}")))?,
        arkret_wire::EventKind::MESSAGE_CREATE,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .map_err(|error| AppError::internal(format!("MIMI realm id invalid: {error}")))?,
        },
        service_did.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(state.hlc().now())
            .map_err(|error| AppError::internal(format!("MIMI HLC invalid: {error}")))?,
        payload,
        created_at,
    )
    .map_err(|error| AppError::internal(format!("MIMI Event build failed: {error}")))?;
    event.prev_refs = prev_refs;
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_id())).map_err(
            |error| {
                AppError::internal(format!(
                    "service notary verification method is invalid: {error}"
                ))
            },
        )?;
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
    event.seal_ref = Some(seal.id);
    event.auth_context = Some(arkret_wire::AuthContext {
        did: service_did.clone(),
        key_id: "notary-key".to_owned(),
        key_epoch: 0,
        credential_epoch: None,
    });
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
    let now = chrono::Utc::now();
    let session = soland_services::identity::SessionIdentityState {
        token_hash: "mimi-provider-facade".to_owned(),
        actor: state.service_id().clone(),
        device_id: "mimi-provider-facade".to_owned(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
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
            soland_http::error::ErrorCode::InvalidParam,
            format!("MIMI Event admission failed: {}", error.message),
        )
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    Ok(())
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
    if update_payload.get("kind").and_then(Value::as_str) != Some("ak.mimi.room_binding") {
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
    let value = arkret_canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
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
    arkret_canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
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
    let bytes = arkret_canonical::base64url_decode(payload).map_err(|error| {
        AppError::invalid_param(format!("{context} payload is not base64url: {error}"))
            .with_wire_code("mimi_payload_invalid")
    })?;
    let observed = arkret_canonical::sha256_digest(&bytes);
    if observed != digest {
        return Err(
            AppError::invalid_param(format!("{context} digest mismatch"))
                .with_wire_code("mimi_payload_digest_mismatch"),
        );
    }
    Ok(Some(bytes))
}

pub(super) fn mimi_provider_directory_value(
    state: &AppState,
) -> arkret_models_collaboration::objects::interop::ProviderDirectory {
    use arkret_models_collaboration::objects::interop::{
        ProviderDirectory, ProviderDirectoryMimi, ProviderDirectoryProof,
    };

    let signature =
        sha256_hex(format!("{}:ak.profile.mimi_interop.v1", state.service_id()).as_bytes());
    ProviderDirectory {
        schema: Some("ak.schema.mimi_interop.v1".to_owned()),
        service_id: Some(
            arkret_identifiers::Did::new(state.service_id().clone())
                .expect("validated service_id must be a DID"),
        ),
        service_kind: "mimi_provider_facade".to_owned(),
        supported_profiles: vec!["ak.profile.mimi_interop.v1".to_owned()],
        mimi: ProviderDirectoryMimi {
            protocol_draft: "draft-ietf-mimi-protocol-06".to_owned(),
            content_draft: "draft-ietf-mimi-content-08".to_owned(),
            room_policy_draft: Some("draft-ietf-mimi-room-policy-03".to_owned()),
            identifier_draft: Some("draft-kohbrok-mimi-identifiers-01".to_owned()),
            base_url: mimi_base_url(state),
            provider_id: mimi_provider_id(state),
            features: [
                "key_material",
                "room_update",
                "notify",
                "submit_message",
                "group_info",
                "consent",
                "identifier_query",
                "report_abuse",
                "proxy_download",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            mls_cipher_suites: Some(vec![
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            ]),
            content_profiles: Some(
                [
                    "application/mimi-content",
                    "text/plain;charset=utf-8",
                    "text/markdown;variant=GFM-MIMI",
                    "application/vnd.arkret.content+json",
                ]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            ),
            room_policy_components: Some(
                [
                    "roles",
                    "membership",
                    "history_visibility",
                    "join_rule",
                    "message_expiration",
                    "asset_privacy",
                ]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            ),
            extra: Default::default(),
        },
        proof: Some(ProviderDirectoryProof {
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#mimi-provider",
                state.service_id()
            ))
            .expect("service DID plus #mimi-provider is a DID URL"),
            signature,
            extra: [
                ("type".to_owned(), json!("dev_service_digest")),
                ("alg".to_owned(), json!("sha256-dev")),
            ]
            .into_iter()
            .collect(),
        }),
        extra: Default::default(),
    }
}

pub(super) fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/_arkret/open/mimi",
        state.config().public_base_url.trim_end_matches('/')
    )
}

pub(super) fn mimi_provider_id(state: &AppState) -> String {
    service_id_mimi_provider_id(state.service_id())
}

pub(super) fn service_id_mimi_provider_id(service_id: &str) -> String {
    if let Some(domain) = service_id.strip_prefix("did:web:") {
        return format!("mimi://{}", domain.replace(':', "/"));
    }
    if let Some(rest) = service_id.strip_prefix("did:webvh:") {
        let mut parts = rest.splitn(2, ':');
        if parts.next().is_some_and(|scid| !scid.is_empty())
            && let Some(authority_and_path) = parts.next()
            && !authority_and_path.is_empty()
        {
            return format!("mimi://{}", authority_and_path.replace(':', "/"));
        }
    }
    format!("mimi://{}", service_id.replace(':', "."))
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
        "profile": "ak.profile.mimi_interop.v1",
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
        "profile": "ak.profile.mimi_interop.v1",
        "e2ee_boundary": "none",
        "plaintext_detected": plaintext_detected,
        "plaintext_guard": "not_e2ee",
    });
    if e2ee_boundary && explicit_downgrade {
        ensure_content_object(&mut content);
        let object = content.as_object_mut().expect("content object");
        object.insert(
            "e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        policy = json!({
            "profile": "ak.profile.mimi_interop.v1",
            "e2ee_boundary": "explicit_downgrade",
            "plaintext_detected": plaintext_detected,
            "plaintext_guard": "marked_explicit_downgrade",
            "downgrade_marker": "mimi_bridge",
        });
    } else if e2ee_boundary {
        if let Some(binding) = transcript_binding {
            ensure_content_object(&mut content);
            let object = content.as_object_mut().expect("content object");
            object.insert("transcript_binding".to_owned(), binding.clone());
            policy = json!({
                "profile": "ak.profile.mimi_interop.v1",
                "e2ee_boundary": "transcript_bound",
                "plaintext_detected": plaintext_detected,
                "plaintext_guard": "transcript_binding",
                "transcript_binding": binding,
            });
        } else {
            policy = json!({
                "profile": "ak.profile.mimi_interop.v1",
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

pub(super) fn ensure_content_object(content: &mut Value) {
    if !content.is_object() {
        let raw = content.clone();
        *content = json!({
            "kind": "ak.content.opaque",
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
            | "ak.message.text"
            | "ak.message.revise"
            | "ak.message.redact"
            | "ak.content.text"
            | "ak.content.composite"
            | "ak.content.markdown"
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
