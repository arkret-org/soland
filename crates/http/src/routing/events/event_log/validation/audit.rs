use super::super::*;

pub(crate) async fn append_encrypted_message_franking(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    let Some(proof) = encrypted_message_franking_proof(state.service_id(), parsed, envelope) else {
        return;
    };
    append_audit_log(
        state,
        Some(&parsed.actor_id),
        arkret_wire::EventKind::MODERATION_FRANKING_PROOF,
        proof,
        "accepted",
    )
    .await;
}

fn encrypted_message_franking_proof(
    service_id: &str,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Option<Value> {
    if parsed.kind != arkret_wire::EventKind::MESSAGE_CREATE {
        return None;
    }
    let ciphertext_digest = encrypted_message_ciphertext_digest(envelope)?;
    let mut proof = json!({
        "kind": arkret_wire::EventKind::MODERATION_FRANKING_PROOF,
        "realm_id": parsed.realm_id,
        "target_event_id": parsed.event_id,
        "sender_did": parsed.actor_id,
        "receiving_service_id": service_id,
        "ciphertext_digest": ciphertext_digest,
        "event_canonical_digest": parsed.canonical_digest,
        "timestamp": now(),
    });
    let proof_digest = franking_proof_digest(&proof);
    proof["proof_digest"] = json!(proof_digest);
    Some(proof)
}

fn encrypted_message_ciphertext_digest(envelope: &Value) -> Option<String> {
    if let Some(digest) = envelope
        .pointer("/payload/encrypted_content/payload_digest")
        .and_then(Value::as_str)
        && is_valid_hash_digest(digest)
    {
        return Some(digest.to_owned());
    }
    None
}

fn franking_proof_digest(proof: &Value) -> String {
    let material = json!({
        "kind": proof
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or(arkret_wire::EventKind::MODERATION_FRANKING_PROOF),
        "target_event_id": proof.get("target_event_id").and_then(Value::as_str).unwrap_or_default(),
        "sender_did": proof.get("sender_did").and_then(Value::as_str).unwrap_or_default(),
        "receiving_service_id": proof.get("receiving_service_id").and_then(Value::as_str).unwrap_or_default(),
        "ciphertext_digest": proof.get("ciphertext_digest").and_then(Value::as_str).unwrap_or_default(),
        "event_canonical_digest": proof.get("event_canonical_digest").and_then(Value::as_str).unwrap_or_default(),
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_default();
    arkret_canonical::sha256_digest(&bytes)
}

pub(super) fn validate_audit_accessed_payload(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::EventKind::AUDIT_ACCESSED {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "ak.audit.accessed payload must be an object",
            )
        })?;
    const ALLOWED: &[&str] = &[
        "access_kind",
        "accessed_at",
        "cell_head_after",
        "cell_head_before",
        "paired_event_digest",
        "paired_event_id",
        "purpose",
        "ryw_required",
        "target_actor_id",
        "target_cell_id",
        "target_ref",
        "writer_did",
    ];
    if payload.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed payload contains an unknown field",
        ));
    }
    let access_kind = required_payload_string(payload, "access_kind")?;
    if !matches!(
        access_kind.as_str(),
        "watch_set_others"
            | "watch_audit_read"
            | "e2ee_plaintext_release"
            | "join_application_review"
            | "policy_audit_read"
            | "other"
    ) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed access_kind is invalid",
        ));
    }
    let writer_did = required_payload_string(payload, "writer_did")?;
    validate_did(&writer_did).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed writer_did must be a DID",
        )
    })?;
    if object.get("actor_id").and_then(Value::as_str) != Some(writer_did.as_str()) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "ak.audit.accessed writer_did must match actor_id",
        ));
    }
    let target_ref = required_payload_string(payload, "target_ref")?;
    if !target_ref.starts_with("ak:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed target_ref must be a typed object ref",
        ));
    }
    if required_payload_string(payload, "purpose")?
        .trim()
        .is_empty()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed purpose must be non-empty",
        ));
    }
    let accessed_at = required_payload_string(payload, "accessed_at")?;
    DateTime::parse_from_rfc3339(&accessed_at).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed accessed_at must be RFC3339",
        )
    })?;
    match access_kind.as_str() {
        "watch_set_others" => {
            validate_watch_audit_payload_fields(payload)?;
            for field in ["paired_event_id", "paired_event_digest"] {
                let value = required_payload_string(payload, field)?;
                if (field == "paired_event_id" && !is_valid_event_id(&value))
                    || (field == "paired_event_digest" && !is_valid_hash_digest(&value))
                {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "ak.audit.accessed paired event fields are invalid",
                    ));
                }
            }
            for field in ["cell_head_before", "cell_head_after"] {
                if !payload.get(field).is_some_and(|value| {
                    value.is_null() || value.as_str().is_some_and(is_valid_hash_digest)
                }) {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "ak.audit.accessed cell heads must be null or hash digest",
                    ));
                }
            }
        }
        "watch_audit_read" => {
            validate_watch_audit_payload_fields(payload)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_watch_audit_payload_fields(
    payload: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let target_actor = required_payload_string(payload, "target_actor_id")?;
    validate_did(&target_actor).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed target_actor_id must be a DID",
        )
    })?;
    let target_cell_id = required_payload_string(payload, "target_cell_id")?;
    if arkret_identifiers::CellRef::new(target_cell_id).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ak.audit.accessed target_cell_id must use canonical ak:cell:ak.component.*.v<n>:<subject> form",
        ));
    }
    Ok(())
}

fn required_payload_string(
    payload: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, EventValidationError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("ak.audit.accessed requires {field}"),
            )
        })
}

pub(super) async fn validate_strand_watch_audit_pair(
    state: &AppState,
    kind: &str,
    object: &serde_json::Map<String, Value>,
    event_id: &str,
    actor_id: &str,
    canonical_digest: &str,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::EventKind::STRAND_WATCH_SET {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "strand watch payload must be an object",
            )
        })?;
    let target_actor = payload
        .get("watcher_actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "strand watch payload requires watcher_actor_id",
            )
        })?;
    if target_actor == actor_id {
        return Ok(());
    }
    if payload.get("level").and_then(Value::as_str) == Some("muted")
        || payload
            .get("level_public")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::WATCH_SET_OTHERS_AUDIT_MISSING,
            "manage_others strand watch writes cannot set muted or public levels",
        ));
    }
    let audit_refs = event_refs_with_role(object, "audit_pair")?;
    let Some(audit_ref) = audit_refs.first() else {
        return Err(manage_others_audit_error(
            "cross-actor strand watch writes require refs[role=audit_pair]",
        ));
    };
    if audit_refs.len() != 1 {
        return Err(manage_others_audit_error(
            "cross-actor strand watch writes require exactly one audit_pair ref",
        ));
    }
    let audit_record = state
        .event_queries()
        .canonical_event(audit_ref)
        .await
        .map_err(|_| manage_others_audit_error("audit_pair event lookup failed"))?
        .ok_or_else(|| manage_others_audit_error("audit_pair event is not accepted"))?;
    if audit_record.kind != arkret_wire::EventKind::AUDIT_ACCESSED {
        return Err(manage_others_audit_error(
            "audit_pair ref must point to ak.audit.accessed",
        ));
    }
    let audit_payload = audit_record
        .envelope
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| manage_others_audit_error("audit_pair payload is invalid"))?;
    let strand_id = payload
        .get("strand_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let checks = [
        ("access_kind", "watch_set_others"),
        ("writer_did", actor_id),
        ("target_actor_id", target_actor),
        ("target_ref", strand_id),
        ("paired_event_id", event_id),
        ("paired_event_digest", canonical_digest),
    ];
    for (field, expected) in checks {
        if audit_payload.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(manage_others_audit_error(
                "audit_pair payload does not match the strand watch event",
            ));
        }
    }
    Ok(())
}

fn event_refs_with_role(
    object: &serde_json::Map<String, Value>,
    role: &str,
) -> Result<Vec<String>, EventValidationError> {
    let Some(values) = object.get("refs").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            continue;
        };
        if reference.get("role").and_then(Value::as_str) == Some(role) {
            let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "refs entries require id",
                )
            })?;
            if !is_valid_event_id(id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "audit_pair refs must use ak:event: typed ids",
                ));
            }
            refs.push(id.to_owned());
        }
    }
    Ok(refs)
}

fn manage_others_audit_error(message: impl Into<String>) -> EventValidationError {
    event_validation_error(
        StatusCode::PRECONDITION_FAILED,
        arkret_wire::ReasonCode::WATCH_SET_OTHERS_AUDIT_MISSING,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(kind: &str) -> ValidatedEventEnvelope {
        ValidatedEventEnvelope {
            event_id: "ak:event:01904100-0000-8000-8000-000000000001".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
            actor_seq: 1,
            realm_id: "ak:realm:01904100-0000-8000-8000-000000000003".to_owned(),
            kind: kind.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            prev_refs: Vec::new(),
            authorized_refs: Vec::new(),
            canonical_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            canonical_bytes: Vec::new(),
            data_event_query_grade: DataEventQueryGrade::Observed,
        }
    }

    #[test]
    fn encrypted_message_franking_is_not_gated_by_audit_applet_policy() {
        let proof = encrypted_message_franking_proof(
            "did:web:soland.example",
            &parsed(arkret_wire::EventKind::MESSAGE_CREATE),
            &json!({
                "payload": {
                    "encrypted_content": {
                        "payload_digest":
                            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    }
                }
            }),
        )
        .expect("encrypted messages get a local moderation franking proof");

        assert_eq!(
            proof.get("kind").and_then(Value::as_str),
            Some(arkret_wire::EventKind::MODERATION_FRANKING_PROOF)
        );
        assert_eq!(
            proof.get("receiving_service_id").and_then(Value::as_str),
            Some("did:web:soland.example")
        );
        assert!(proof.get("audit_disclosure_policy").is_none());
        assert!(proof.get("proof_digest").is_some());
    }

    #[test]
    fn plaintext_messages_do_not_get_a_franking_proof() {
        assert!(
            encrypted_message_franking_proof(
                "did:web:soland.example",
                &parsed(arkret_wire::EventKind::MESSAGE_CREATE),
                &json!({"payload": {"content": {"body": "hello"}}}),
            )
            .is_none()
        );
    }
}
