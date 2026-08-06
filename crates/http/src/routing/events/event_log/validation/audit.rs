use super::super::*;
use super::envelope::{event_digest_for_suite, event_digest_suite};

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

/// Per-event half of the `.others` watch rules: the level constraints, which need
/// nothing but this envelope.
///
/// The audit pairing itself is **not** checked here. Under content-bound ids the audit
/// Event is authored after the write it records (encoding.md 6.0.1 forbids the two from
/// naming each other), so the pairing is only decidable once the whole submit batch is in
/// hand — see [`validate_watch_set_others_audit_pairs`].
pub(super) fn validate_strand_watch_manage_others_levels(
    kind: &str,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
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
    Ok(())
}

/// Batch half: every cross-actor `.others` watch write MUST be paired with exactly one
/// `ak.audit.accessed` Event **in the same submit batch**, and the pairing edge runs
/// audit -> write (strand-and-message.md 8.4).
///
/// The direction is forced: `refs` is inside the `event_digest` preimage and `event_id`
/// derives from that digest, so a write naming its audit while the audit commits to the
/// write's id and digest would make the two Events preimages of each other, with no fixed
/// point (encoding.md 6.0.1). The write is therefore formed first and the audit second,
/// which is also why this cannot be decided one envelope at a time.
pub(in crate::routing) fn validate_watch_set_others_audit_pairs(
    state: &AppState,
    envelopes: &[Value],
) -> Result<(), EventValidationError> {
    validate_watch_set_others_audit_pairs_with_digest(envelopes, |envelope, object, realm_id| {
        let suite = event_digest_suite(
            state,
            arkret_wire::EventKind::STRAND_WATCH_SET,
            realm_id,
            object,
        )?;
        let canonical_bytes = event_canonical_bytes(envelope)?;
        event_digest_for_suite(&canonical_bytes, &suite)
    })
}

/// Digest resolution is injected so the pairing rule itself is testable without an
/// `AppState`; the only thing the state supplies is the Realm's live digest suite.
fn validate_watch_set_others_audit_pairs_with_digest<F>(
    envelopes: &[Value],
    write_digest: F,
) -> Result<(), EventValidationError>
where
    F: Fn(&Value, &serde_json::Map<String, Value>, &str) -> Result<String, EventValidationError>,
{
    let mut audits: Vec<&serde_json::Map<String, Value>> = Vec::new();
    for envelope in envelopes {
        let Some(object) = envelope.as_object() else {
            continue;
        };
        if object.get("kind").and_then(Value::as_str)
            == Some(arkret_wire::EventKind::AUDIT_ACCESSED)
        {
            audits.push(object);
        }
    }

    for envelope in envelopes {
        let Some(object) = envelope.as_object() else {
            continue;
        };
        if object.get("kind").and_then(Value::as_str)
            != Some(arkret_wire::EventKind::STRAND_WATCH_SET)
        {
            continue;
        }
        let (Some(actor_id), Some(event_id)) = (
            object.get("actor_id").and_then(Value::as_str),
            object.get("event_id").and_then(Value::as_str),
        ) else {
            continue;
        };
        let Some(payload) = object.get("payload").and_then(Value::as_object) else {
            continue;
        };
        let Some(target_actor) = payload.get("watcher_actor_id").and_then(Value::as_str) else {
            continue;
        };
        if target_actor == actor_id {
            continue;
        }
        let strand_id = payload
            .get("strand_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let realm_id = object
            .get("realm_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let canonical_digest = write_digest(envelope, object, realm_id)?;

        let expected = [
            ("access_kind", "watch_set_others"),
            ("writer_did", actor_id),
            ("target_actor_id", target_actor),
            ("target_ref", strand_id),
            ("paired_event_id", event_id),
            ("paired_event_digest", canonical_digest.as_str()),
        ];
        let matches = audits
            .iter()
            .filter(|audit| {
                audit
                    .get("payload")
                    .and_then(Value::as_object)
                    .is_some_and(|audit_payload| {
                        expected.iter().all(|(field, value)| {
                            audit_payload.get(*field).and_then(Value::as_str) == Some(*value)
                        })
                    })
            })
            .count();
        match matches {
            1 => {}
            0 => {
                return Err(manage_others_audit_error(
                    "cross-actor strand watch writes require a same-batch ak.audit.accessed                      event whose paired_event_id and paired_event_digest name this write",
                ));
            }
            _ => {
                return Err(manage_others_audit_error(
                    "cross-actor strand watch writes require exactly one paired                      ak.audit.accessed event in the batch",
                ));
            }
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

    const WRITE_ID: &str = "ak:event:01904100-0000-8000-8000-00000000aa01";
    const WRITE_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const WRITER: &str = "did:web:alice.example";
    const TARGET: &str = "did:web:bob.example";
    const STRAND: &str = "ak:strand:01904100-0000-8000-8000-00000000bb01";

    fn others_watch_write() -> Value {
        json!({
            "event_id": WRITE_ID,
            "kind": arkret_wire::EventKind::STRAND_WATCH_SET,
            "actor_id": WRITER,
            "realm_id": "ak:realm:01904100-0000-8000-8000-000000000003",
            "payload": {
                "strand_id": STRAND,
                "watcher_actor_id": TARGET,
                "level": "participating"
            }
        })
    }

    fn paired_audit() -> Value {
        json!({
            "event_id": "ak:event:01904100-0000-8000-8000-00000000aa02",
            "kind": arkret_wire::EventKind::AUDIT_ACCESSED,
            "actor_id": WRITER,
            "refs": [{"id": WRITE_ID, "role": "audit_pair", "critical": true}],
            "payload": {
                "access_kind": "watch_set_others",
                "writer_did": WRITER,
                "target_actor_id": TARGET,
                "target_ref": STRAND,
                "paired_event_id": WRITE_ID,
                "paired_event_digest": WRITE_DIGEST
            }
        })
    }

    fn check(envelopes: &[Value]) -> Result<(), EventValidationError> {
        validate_watch_set_others_audit_pairs_with_digest(envelopes, |_, _, _| {
            Ok(WRITE_DIGEST.to_owned())
        })
    }

    #[test]
    fn others_watch_write_needs_a_same_batch_audit_naming_it() {
        check(&[others_watch_write(), paired_audit()]).expect("the paired batch is admissible");

        let alone = check(&[others_watch_write()]).expect_err("a lone .others write is rejected");
        assert_eq!(
            alone.code,
            arkret_wire::ReasonCode::WATCH_SET_OTHERS_AUDIT_MISSING
        );
        assert_eq!(alone.status, StatusCode::PRECONDITION_FAILED);

        // The write does not name the audit, so a stale digest is the only thing that can
        // point the audit at a different write.
        let mut wrong_digest = paired_audit();
        wrong_digest["payload"]["paired_event_digest"] =
            json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        check(&[others_watch_write(), wrong_digest])
            .expect_err("an audit that names another write does not pair");

        let mut wrong_target = paired_audit();
        wrong_target["payload"]["target_actor_id"] = json!("did:web:carol.example");
        check(&[others_watch_write(), wrong_target])
            .expect_err("an audit for another target does not pair");
    }

    #[test]
    fn duplicate_audits_for_one_write_are_rejected() {
        check(&[others_watch_write(), paired_audit(), paired_audit()])
            .expect_err("two audits naming the same write are ambiguous");
    }

    #[test]
    fn self_watch_writes_need_no_audit() {
        let mut own = others_watch_write();
        own["payload"]["watcher_actor_id"] = json!(WRITER);
        check(&[own]).expect("writing your own watch state needs no audit pair");
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
