use super::*;

pub(crate) fn event_semantic_refs(
    object: &serde_json::Map<String, Value>,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get("refs") else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "refs must be an array",
        ));
    };
    // scalability-constraints.md §2 — total refs[] across all roles ≤ 128.
    if values.len() > max_len {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "refs_too_large",
            "refs[] exceeds the v1 maximum of 128 entries",
        ));
    }
    let mut authorized_refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "refs entries must be objects",
            ));
        };
        let id = event_string_field(reference, &["id"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "refs entries require id",
            )
        })?;
        let role = event_string_field(reference, &["role"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "refs entries require role",
            )
        })?;
        if role == "authorized_by" {
            if !is_valid_event_id(&id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "authorized_by refs must use the ck:event: typed prefix",
                ));
            }
            authorized_refs.push(id);
        }
    }
    // scalability-constraints.md §2 — the `authorized_by` role is capped at 64
    // within the 128 total; authorized_by refs MUST be the minimal authorizing
    // state set (event-and-patch.md §2.2).
    if authorized_refs.len() > MAX_AUTHORIZED_BY_REFS {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "refs_too_large",
            "authorized_by refs exceed the v1 maximum of 64 entries",
        ));
    }
    Ok(authorized_refs)
}

fn event_canonical_source(envelope: &Value) -> Value {
    // Per cokret-spec conformance-vectors.md §1.6: both the event digest and
    // every proof's `event_digest` MUST be derived from canonical event bytes
    // with `proofs` and `unsigned` removed. Stripping derived `canonical_*`
    // slots as well keeps fixtures that round-trip them in the envelope from
    // poisoning the digest.
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
}

pub(crate) fn event_canonical_bytes(envelope: &Value) -> Result<Vec<u8>, EventValidationError> {
    canonical::canonical_json_bytes(&event_canonical_source(envelope)).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "event envelope cannot be canonicalized",
        )
    })
}

pub(crate) fn event_digest(bytes: &[u8]) -> String {
    cokret_sdk::canonical::sha256_digest(bytes)
}

pub(crate) fn is_valid_event_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ck:event:") else {
        return false;
    };
    !rest.is_empty()
        && value.len() <= 160
        && rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

pub(crate) async fn event_submit_response(
    state: &AppState,
    status: EventsSubmitStatus,
    event_id: String,
) -> SubmittedEventOutcome {
    let duplicate = matches!(status, EventsSubmitStatus::Duplicate);
    SubmittedEventOutcome {
        event_id: event_id.clone(),
        duplicate,
        outcome: events_submit_outcome(
            status,
            vec![event_id.clone()],
            if duplicate {
                vec![event_id]
            } else {
                Vec::new()
            },
            Vec::new(),
            Some(super::super::sync::sync_token_for_state(state).await),
        ),
    }
}

pub(crate) fn projection_operation_from_event(
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Option<Operation> {
    if super::super::operations::operation_schema_for_kind(&parsed.kind).is_none() {
        tracing::debug!(kind = %parsed.kind, "projection: no schema for kind");
        return None;
    }
    let realm_id_raw = parsed.realm_id.clone();
    let realm_id = match RealmId::new(realm_id_raw.clone()) {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(kind = %parsed.kind, realm_id = %realm_id_raw, %error, "projection: RealmId::new failed");
            return None;
        }
    };
    let mut payload = envelope
        .get("payload")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let Some(payload_object) = payload.as_object_mut() else {
        tracing::debug!(kind = %parsed.kind, "projection: payload not an object");
        return None;
    };
    payload_object
        .entry("event_id".to_owned())
        .or_insert_with(|| Value::String(parsed.event_id.clone()));
    payload_object
        .entry("sender".to_owned())
        .or_insert_with(|| Value::String(parsed.actor_id.clone()));
    if parsed.kind == kinds::CK_RELATION_CREATE {
        normalize_relation_create_payload(payload_object, parsed);
    }
    if let Some(target_ref) = payload_object
        .get("target_ref")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    {
        if target_ref.starts_with("ck:strand:") {
            payload_object
                .entry("strand_id".to_owned())
                .or_insert_with(|| Value::String(target_ref.clone()));
        }
        if target_ref.starts_with("ck:morph:") {
            payload_object
                .entry("morph_id".to_owned())
                .or_insert_with(|| Value::String(target_ref));
        }
    }
    if !payload_object.contains_key("thread_id")
        && let Some(strand_id) = payload_object
            .get("strand_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    {
        payload_object.insert("thread_id".to_owned(), Value::String(strand_id));
    }
    if matches!(
        parsed.kind.as_str(),
        kinds::CK_MESSAGE_CREATE | kinds::CK_REACTION_ADD
    ) {
        payload_object.remove("executed_by");
        payload_object.remove("authorization_ref");
        if let Some(executed_by) = envelope.get("executed_by").and_then(Value::as_str) {
            payload_object.insert(
                "executed_by".to_owned(),
                Value::String(executed_by.to_owned()),
            );
            if let Some(authorization_ref) =
                envelope.get("authorization_ref").and_then(Value::as_str)
            {
                payload_object.insert(
                    "authorization_ref".to_owned(),
                    Value::String(authorization_ref.to_owned()),
                );
            }
        }
    }
    if matches!(
        parsed.kind.as_str(),
        "ck.consent.grant" | "ck.consent.revoke"
    ) {
        payload_object
            .entry("actor_seq".to_owned())
            .or_insert_with(|| Value::from(parsed.actor_seq));
    }
    if parsed.kind == kinds::CK_MORPH_SCHEMA_MIGRATE {
        if let Some(authorization_ref) = parsed.authorized_refs.first() {
            payload_object
                .entry("authorization_ref".to_owned())
                .or_insert_with(|| Value::String(authorization_ref.clone()));
        }
        payload_object
            .entry("capability_action".to_owned())
            .or_insert_with(|| Value::String("ck.morph.schema.migrate".to_owned()));
    }
    if let Some(seal_ref) = envelope.get("seal_ref").and_then(Value::as_str) {
        payload_object
            .entry("seal_ref".to_owned())
            .or_insert_with(|| Value::String(seal_ref.to_owned()));
    }

    let Some(operation_id) = event_operation_id(envelope, &parsed.event_id) else {
        tracing::debug!(kind = %parsed.kind, event_id = %parsed.event_id, "projection: event_operation_id failed");
        return None;
    };
    let mut operation = Operation::create(
        operation_id,
        realm_id,
        parsed.kind.clone(),
        Value::Object(payload_object.clone()),
    );
    operation.created_at = envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(now);
    Some(operation)
}

fn normalize_relation_create_payload(
    payload_object: &mut serde_json::Map<String, Value>,
    parsed: &ValidatedEventEnvelope,
) {
    if let Some(relation) = payload_object
        .get("relation")
        .and_then(Value::as_object)
        .cloned()
    {
        if let Some(id) = relation
            .get("id")
            .or_else(|| relation.get("relation_id"))
            .and_then(Value::as_str)
        {
            payload_object
                .entry("relation_id".to_owned())
                .or_insert_with(|| Value::String(id.to_owned()));
        }
        if let Some(relation_kind) = relation
            .get("relation_kind")
            .or_else(|| relation.get("kind"))
            .and_then(Value::as_str)
        {
            payload_object
                .entry("relation_kind".to_owned())
                .or_insert_with(|| Value::String(relation_kind.to_owned()));
        }
        for field in ["from_ref", "to_ref", "rank", "fields"] {
            if let Some(value) = relation.get(field) {
                payload_object
                    .entry(field.to_owned())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    if !payload_object.contains_key("relation_id")
        && !payload_object.contains_key("id")
        && let Some(suffix) = parsed.event_id.strip_prefix("ck:event:")
    {
        payload_object.insert(
            "relation_id".to_owned(),
            Value::String(format!("ck:relation:{suffix}")),
        );
    }
}

fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    // Prefer the client-supplied alias when it's a valid OperationId
    // (`ck:operation:<uuid v7>` per `cokret-rust-sdk/identifiers`).
    // Older yougen builds shipped the event_id (ck:event:) verbatim in
    // this slot; soland MUST NOT silently drop projection for such
    // events ── fall through to the event_id-derived form so the
    // projection chain (`project_accepted_operations` →
    // `project_membership_operation` → RealmInviteRecord write) still
    // runs. The alias-when-present remains the dedupe key for clients
    // that submit it correctly.
    if let Some(alias) = envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        && let Ok(operation_id) = OperationId::new(alias.to_owned())
    {
        return Some(operation_id);
    }
    let suffix = event_id.strip_prefix("ck:event:")?;
    OperationId::new(format!("ck:operation:{suffix}")).ok()
}

/// CKP-0007 — resolve the canonical `effective_scope` for an Event
/// Envelope on read. Returns `Some(circle_id)` when the envelope (or its
/// payload) names a Circle scope, `Some("realm:<realm_id>")` when the
/// scope is the Realm default, or `None` when neither can be derived.
pub(crate) fn effective_scope_for_envelope(envelope: &Value) -> Option<String> {
    let object = envelope.as_object()?;
    // Server-stamped authoritative scope. For messages this is set at ingest
    // from the message's Strand (see submit_event_value); it always wins.
    if let Some(scope) = object.get("effective_scope").and_then(Value::as_str) {
        return Some(scope.to_owned());
    }
    if let Some(scope) = object.get("effective_scope").and_then(Value::as_object) {
        return match scope.get("kind").and_then(Value::as_str) {
            Some("circle") => scope
                .get("circle_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some("realm") => scope
                .get("realm_id")
                .and_then(Value::as_str)
                .map(|realm_id| format!("realm:{realm_id}")),
            _ => None,
        };
    }
    // Messages NEVER carry their own scope (spec: `scope_circle_id` is a Strand
    // field, not a message field). A message's effective circle-scope is the
    // server-stamped `effective_scope` above, derived from its Strand at ingest.
    // There is deliberately no client-supplied fallback, so a message cannot
    // spoof its own visibility scope.
    if object.get("kind").and_then(Value::as_str) == Some(kinds::CK_MESSAGE_CREATE) {
        return None;
    }
    // Non-message events (e.g. ck.strand.create / ck.strand.update) legitimately
    // carry the object's own `scope_circle_id`.
    let payload = object.get("payload").and_then(Value::as_object)?;
    if let Some(scope_circle_id) = payload.get("scope_circle_id").and_then(Value::as_str) {
        return Some(scope_circle_id.to_owned());
    }
    if let Some(payload_object) = payload.get("object").and_then(Value::as_object)
        && let Some(scope_circle_id) = payload_object
            .get("scope_circle_id")
            .and_then(Value::as_str)
    {
        return Some(scope_circle_id.to_owned());
    }
    None
}

pub(crate) async fn event_view_for_state(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> JsonResult<EventView> {
    json_ok(EventView {
        event: sdk_event_for_state(state, record)?,
        visibility: event_visibility_metadata(state, record),
        receipts: crate::routing::events::read_receipts::visible_read_receipts_for_event(
            state, record, session,
        )
        .await,
    })
}

pub(crate) fn sdk_event_for_state(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<Event, AppError> {
    sdk_event_from_record(
        record,
        retention_tombstone_for_event(state, &record.event_id),
    )
}

fn sdk_event_from_record(
    record: &CanonicalEventRecord,
    tombstone: Option<crate::state::RetentionTombstoneRecord>,
) -> Result<Event, AppError> {
    let object = record
        .envelope
        .as_object()
        .ok_or_else(|| AppError::internal("stored event envelope is not an object"))?;
    let realm_id = canonical_realm_id_for_record(record)
        .ok_or_else(|| AppError::internal("stored event missing realm_id"))?;
    let realm_id = RealmId::new(realm_id).map_err(|error| AppError::internal(error.to_string()))?;
    let event_id = EventId::new(record.event_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let actor_id = cokret_sdk::Did::new(record.actor_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let created_at = object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(record.received_at);
    let hlc = object
        .get("hlc")
        .and_then(Value::as_str)
        .and_then(|value| Hlc::new(value.to_owned()).ok())
        .unwrap_or_else(|| synthetic_hlc(record.received_at));
    let mut payload = object.get("payload").cloned().unwrap_or_else(|| json!({}));
    let mut unsigned: BTreeMap<String, Value> = object
        .get("unsigned")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();
    if let Some(tombstone) = tombstone {
        payload = retention_tombstone_payload_value(&payload, &tombstone);
        unsigned.insert("retention_tombstone".to_owned(), json!(true));
        unsigned.insert("retention_state".to_owned(), json!("tombstoned"));
        unsigned.insert(
            "retention_reason".to_owned(),
            json!(tombstone.reason.as_str()),
        );
        unsigned.insert(
            "retention_expired_at".to_owned(),
            json!(tombstone.expired_at.to_rfc3339()),
        );
        unsigned.insert(
            "retention_tombstoned_at".to_owned(),
            json!(tombstone.tombstoned_at.to_rfc3339()),
        );
        unsigned.insert(
            "retention_seal_preserved".to_owned(),
            json!(tombstone.sealed),
        );
        unsigned.insert("physical_delete".to_owned(), json!(false));
    }
    Ok(Event {
        event_id,
        kind: record.kind.clone().into(),
        realm_id: realm_id.clone(),
        actor_id,
        actor_seq: record.actor_seq,
        created_at,
        hlc,
        prev_refs: event_id_list(object.get("prev_refs"))?,
        effective_scope: sdk_effective_scope(record, &realm_id),
        refs: event_refs(object.get("refs")),
        preconditions: json_array_field(object, "preconditions"),
        effects: json_array_field(object, "effects"),
        seal_ref: object
            .get("seal_ref")
            .and_then(Value::as_str)
            .and_then(|value| cokret_sdk::SealId::new(value.to_owned()).ok()),
        auth_context: object
            .get("auth_context")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        seal_basis: object
            .get("seal_basis")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        requirements: object
            .get("requirements")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default(),
        redacts: object
            .get("redacts")
            .and_then(Value::as_str)
            .and_then(|value| EventId::new(value.to_owned()).ok()),
        content: payload,
        executed_by: object
            .get("executed_by")
            .and_then(Value::as_str)
            .and_then(|value| cokret_sdk::Did::new(value.to_owned()).ok()),
        authorization_ref: object
            .get("authorization_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        applet_id: object
            .get("applet_id")
            .and_then(Value::as_str)
            .and_then(|value| cokret_sdk::AppletId::new(value.to_owned()).ok()),
        external_ref: object
            .get("external_ref")
            .filter(|value| !value.is_null())
            .cloned(),
        actor_kind: object
            .get("actor_kind")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        unsigned,
        proofs: sdk_event_proofs(record, object, created_at)?,
    })
}

fn event_visibility_metadata(state: &AppState, record: &CanonicalEventRecord) -> Value {
    let mut metadata = json!({
        "event_id": record.event_id.clone(),
        "actor_id": record.actor_id.clone(),
        "actor_seq": record.actor_seq,
        "realm_id": canonical_realm_id_for_record(record),
        "kind": record.kind.clone(),
        "schema_id": record.schema_id.clone(),
        "canonical_digest": record.canonical_digest.clone(),
        "received_at": record.received_at,
    });
    if let Some(scope) = effective_scope_for_envelope(&record.envelope) {
        metadata["effective_scope"] = json!(scope);
    }
    if let Some(tombstone) = retention_tombstone_for_event(state, &record.event_id) {
        metadata["retention_state"] = json!("tombstoned");
        metadata["retention_reason"] = json!(tombstone.reason.as_str());
        metadata["retention_expired_at"] = json!(tombstone.expired_at.to_rfc3339());
        metadata["retention_tombstoned_at"] = json!(tombstone.tombstoned_at.to_rfc3339());
        metadata["retention_seal_preserved"] = json!(tombstone.sealed);
        metadata["physical_delete"] = json!(false);
    }
    metadata
}

fn event_id_list(value: Option<&Value>) -> Result<Vec<EventId>, AppError> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .filter_map(Value::as_str)
        .map(|value| {
            EventId::new(value.to_owned()).map_err(|error| AppError::internal(error.to_string()))
        })
        .collect()
}

fn event_refs(value: Option<&Value>) -> Vec<EventRef> {
    value
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn json_array_field<T>(object: &serde_json::Map<String, Value>, field: &str) -> Vec<T>
where
    T: serde::de::DeserializeOwned,
{
    object
        .get(field)
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn sdk_effective_scope(
    record: &CanonicalEventRecord,
    realm_id: &RealmId,
) -> Option<cokret_sdk::models::EffectiveScope> {
    if let Some(scope) = record
        .envelope
        .get("effective_scope")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        return Some(scope);
    }
    match effective_scope_for_envelope(&record.envelope).as_deref() {
        Some(scope) if scope.starts_with("ck:circle:") => {
            cokret_sdk::CircleId::new(scope.to_owned())
                .ok()
                .map(|circle_id| cokret_sdk::models::EffectiveScope::Circle {
                    realm_id: realm_id.clone(),
                    circle_id,
                })
        }
        Some(scope) if scope.starts_with("realm:") => {
            Some(cokret_sdk::models::EffectiveScope::Realm {
                realm_id: realm_id.clone(),
            })
        }
        _ => None,
    }
}

fn synthetic_hlc(received_at: DateTime<Utc>) -> Hlc {
    let millis = received_at.timestamp_millis().max(0) as u64;
    Hlc::new(format!("{millis:012x}-0000-00000000")).expect("synthetic HLC is valid")
}

fn sdk_event_proofs(
    record: &CanonicalEventRecord,
    object: &serde_json::Map<String, Value>,
    created_at: DateTime<Utc>,
) -> Result<Vec<Proof>, AppError> {
    if let Some(proofs) = object
        .get("proofs")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<Proof>>(value).ok())
        .filter(|proofs| !proofs.is_empty())
    {
        return Ok(proofs);
    }
    let proof = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(Value::as_object);
    let verification_method = proof
        .and_then(|proof| proof.get("verification_method"))
        .and_then(Value::as_str)
        .unwrap_or("did:web:soland.local#dev")
        .to_owned();
    let domain = proof
        .and_then(|proof| proof.get("domain"))
        .or_else(|| object.get("domain"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let audience = proof
        .and_then(|proof| proof.get("audience"))
        .or_else(|| object.get("audience"))
        .and_then(sdk_audience);
    let event_digest = Hash::new(record.canonical_digest.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(vec![Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: proof
            .and_then(|proof| proof.get("alg"))
            .and_then(Value::as_str)
            .unwrap_or("EdDSA")
            .to_owned(),
        verification_method,
        event_digest,
        created_at,
        domain,
        audience,
        jws: proof
            .and_then(|proof| proof.get("jws").or_else(|| proof.get("detached_jws")))
            .and_then(Value::as_str)
            .unwrap_or("ZGV2..c2ln")
            .to_owned(),
    }])
}

fn sdk_audience(value: &Value) -> Option<Audience> {
    if let Some(single) = value.as_str() {
        return Some(Audience::Single(single.to_owned()));
    }
    value.as_array().map(|items| {
        Audience::Multiple(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
        )
    })
}

/// SPEC-SOL-003 — pre-acceptance validation for the durable
/// `ck.device.revoke` Control Move. v1 scaffold scope: only the principal
/// may revoke its own sibling devices (recovery-service revocation lands
/// with the recovery strands), and a device MUST NOT revoke itself
/// (`device-lifecycle.md` §2.2 self-lockout rule). The principal-control
/// realm binding itself is enforced by
/// `validate_principal_control_realm_binding`; payload field presence by
/// the registry payload schema.
pub(crate) fn validate_device_revoke_submission(
    session: &SessionRecord,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Result<String, SubmitOneError> {
    let payload = envelope.get("payload").cloned().unwrap_or(Value::Null);
    let principal_id = payload
        .get("principal_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let device_id = payload
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if device_id.is_empty() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.device.revoke payload.device_id is required",
        ));
    }
    if principal_id != parsed.actor_id {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "ck.device.revoke payload.principal_id must be the submitting actor",
        ));
    }
    if device_id == session.device_id {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "cannot_self_revoke",
            "a device cannot revoke itself; revoke from a peer device",
        ));
    }
    Ok(device_id.to_owned())
}

pub(crate) fn canonical_realm_id_for_record(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| record.realm_id.as_deref().map(normalize_persisted_realm_id))
}

fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}

pub(crate) async fn event_visible_to_session(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    if record.actor_id == session.actor {
        return true;
    }
    match canonical_realm_id_for_record(record) {
        Some(realm_id) => {
            realm_event_visible_to_session(
                state,
                &realm_id,
                record.received_at,
                Some(&record.actor_id),
                Some(session),
            )
            .await
                && circle_event_visible_to_session(state, record, session)
        }
        None => false,
    }
}

fn circle_event_visible_to_session(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    let Some(scope_circle_id) = effective_scope_for_envelope(&record.envelope)
        .filter(|scope| scope.starts_with("ck:circle:"))
    else {
        return true;
    };
    if record.actor_id == session.actor {
        return true;
    }
    state
        .projection
        .lock()
        .expect("projection mutex")
        .circle_scope_visible_to_actor(&scope_circle_id, &session.actor)
}

/// Scan the durable Event store for the most
/// recent `ck.realm.read_receipt_policy` event in `realm_id` and return
/// `(disclosure, visibility, scope_overrides_allowed,
/// allow_public_receipts_on_world_readable)` from its payload.
/// Returns `None` when no policy event has been written for this Realm —
/// caller treats that as the spec default `Optional` / `Members` /
/// `scope_overrides_allowed=true` /
/// `allow_public_receipts_on_world_readable=false`.
///
/// Used by ephemeral `ck.receipt.read` admission and future receipt fanout
/// handlers to enforce the Realm policy.
///
/// **Note**: this is a linear scan of the durable event store. For the
/// production fanout path it should be projected into `AppState` once the
/// reducer kind delegates from `Ignored` to a real projection.
pub async fn effective_read_receipt_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<(String, String, bool, bool)> {
    // Cell-keyed fast path. The Move/Seal pipeline writes the
    // `ck.component.realm.read_receipt_policy.v1` resolved CasRegister
    // value into `ProjectionState::cells` after every apply_seal; we
    // read directly from there. (R1.2 renamed the cell family from
    // `ck.component.realm.read_receipt_policy.v1` along with the event
    // kind.)
    if let Ok(proj) = state.projection.lock() {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.read_receipt_policy.v1:{realm_id}"
        ))
        .ok()?;
        if let Some(value) = proj.cell_value(&cell_id) {
            let disclosure = value
                .get("disclosure")
                .and_then(Value::as_str)
                .unwrap_or("optional")
                .to_owned();
            let visibility = value
                .get("visibility")
                .and_then(Value::as_str)
                .unwrap_or("members")
                .to_owned();
            let scope_overrides_allowed = value
                .get("scope_overrides_allowed")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let allow_public_receipts_on_world_readable = value
                .get("allow_public_receipts_on_world_readable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            return Some((
                disclosure,
                visibility,
                scope_overrides_allowed,
                allow_public_receipts_on_world_readable,
            ));
        }
    }
    // Cold-path fallback: linear scan of the durable Event store. Used at
    // boot before the projection has been rehydrated, or when a server is
    // running with persistence disabled.
    let records = state.persistence.events().snapshot_all().await.ok()?;
    let mut latest: Option<&CanonicalEventRecord> = None;
    for record in &records {
        // CanonicalEventRecord uses `kind` (not event_kind) for the
        // canonical Cokret event kind string.
        if record.kind != "ck.realm.read_receipt_policy" {
            continue;
        }
        if canonical_realm_id_for_record(record).as_deref() != Some(realm_id) {
            continue;
        }
        match latest {
            Some(prev) if prev.received_at >= record.received_at => {}
            _ => latest = Some(record),
        }
    }
    let record = latest?;
    // The policy state lives on the envelope payload; CanonicalEventRecord
    // stores the full envelope, so we drill down to `envelope.payload`.
    let payload = record.envelope.get("payload").and_then(Value::as_object)?;
    let disclosure = payload
        .get("disclosure")
        .and_then(Value::as_str)
        .unwrap_or("optional")
        .to_owned();
    let visibility = payload
        .get("visibility")
        .and_then(Value::as_str)
        .unwrap_or("members")
        .to_owned();
    let scope_overrides_allowed = payload
        .get("scope_overrides_allowed")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let allow_public_receipts_on_world_readable = payload
        .get("allow_public_receipts_on_world_readable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some((
        disclosure,
        visibility,
        scope_overrides_allowed,
        allow_public_receipts_on_world_readable,
    ))
}

#[cfg(test)]
mod refs_limit_tests {
    use serde_json::json;

    use super::*;

    fn refs_object(refs: serde_json::Value) -> serde_json::Map<String, Value> {
        json!({ "refs": refs }).as_object().unwrap().clone()
    }

    // scalability-constraints.md §2 — total refs[] across all roles ≤ 128.
    #[test]
    fn total_refs_over_max_rejected_as_refs_too_large() {
        let refs: Vec<Value> = (0..(MAX_EVENT_REFS + 1))
            .map(|_| json!({"id": "ck:event:e", "role": "after"}))
            .collect();
        let err = event_semantic_refs(&refs_object(json!(refs)), MAX_EVENT_REFS).unwrap_err();
        assert_eq!(err.code, "refs_too_large");
    }

    // §2 — `authorized_by` role ≤ 64 within the 128 total.
    #[test]
    fn authorized_by_over_max_rejected_as_refs_too_large() {
        let refs: Vec<Value> = (0..(MAX_AUTHORIZED_BY_REFS + 1))
            .map(|_| json!({"id": "ck:event:e1", "role": "authorized_by"}))
            .collect();
        let err = event_semantic_refs(&refs_object(json!(refs)), MAX_EVENT_REFS).unwrap_err();
        assert_eq!(err.code, "refs_too_large");
    }

    #[test]
    fn within_limits_collects_only_authorized_by_refs() {
        let refs = json!([
            {"id": "ck:event:e1", "role": "authorized_by"},
            {"id": "ck:event:e2", "role": "after"}
        ]);
        let out = event_semantic_refs(&refs_object(refs), MAX_EVENT_REFS).unwrap();
        assert_eq!(out, vec!["ck:event:e1".to_owned()]);
    }
}
