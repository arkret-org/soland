use super::*;
use crate::routing::events::event_log::DataEventQueryGrade;

/// The registry projection evaluator for a bootstrap unit.
///
/// A genesis unit has no accepted Realm yet, so there is no
/// `ak.component.realm.digest_suite.v1` cell to read and the protocol baseline
/// suite is the only defined one (`conformance/encoding.md` §4). Post-genesis
/// callers MUST use `ProjectionService::project_cell_writes`, which reads the
/// Realm's effective suite.
pub(in crate::routing) fn genesis_cell_write_projector(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::cba::ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}

pub(in crate::routing) fn event_semantic_refs(
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
    if values.len() > max_len
        || arkret_wire::event_envelope::validate_event_ref_count(values.len()).is_err()
    {
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
            if arkret_identifiers::GrantId::new(id.clone()).is_err() {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "authorized_by refs must use the ak:grant: typed prefix",
                ));
            }
            authorized_refs.push(id);
        }
    }
    // scalability-constraints.md §2 — the `authorized_by` role is capped at 64
    // within the 128 total; authorized_by refs MUST be the minimal authorizing
    // state set (event-and-patch.md §2.2).
    if arkret_wire::event_envelope::validate_authorized_by_ref_count(authorized_refs.len()).is_err()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "refs_too_large",
            "authorized_by refs exceed the v1 maximum of 64 entries",
        ));
    }
    Ok(authorized_refs)
}

fn event_for_canonical_digest(envelope: &Value) -> Result<Event, EventValidationError> {
    // `canonical_*` are storage adapter metadata, not Event fields. All
    // protocol exclusions (`proofs`, `unsigned`, reducer-stamped fields) are
    // owned by SDK `Event::digest_payload`; Soland must not mirror that list.
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    serde_json::from_value(value).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            format!("event envelope is not an SDK Event: {error}"),
        )
    })
}

pub(in crate::routing) fn event_canonical_bytes(
    envelope: &Value,
) -> Result<Vec<u8>, EventValidationError> {
    let event = event_for_canonical_digest(envelope)?;
    let payload = event.digest_payload().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            format!("event digest payload cannot be built: {error}"),
        )
    })?;
    canonical::canonical_json_bytes(&payload).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "event envelope cannot be canonicalized",
        )
    })
}

pub(crate) fn is_valid_event_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:event:") else {
        return false;
    };
    !rest.is_empty()
        && value.len() <= 160
        && rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

pub(in crate::routing) async fn event_submit_response(
    state: &AppState,
    session: &SessionRecord,
    status: EventsSubmitStatus,
    event_id: String,
    realm_actor_frontier: RealmActorFrontierView,
) -> SubmittedEventOutcome {
    let duplicate = matches!(status, EventsSubmitStatus::Duplicate);
    let mut outcome = events_submit_outcome(
        status,
        vec![event_id.clone()],
        if duplicate {
            vec![event_id.clone()]
        } else {
            Vec::new()
        },
        Vec::new(),
        Vec::new(),
        Some(super::super::sync::sync_barrier_token_for_event(state, session, &event_id).await),
    );
    outcome.realm_actor_frontiers = vec![realm_actor_frontier];
    SubmittedEventOutcome {
        event_id: event_id.clone(),
        duplicate,
        outcome,
    }
}

pub(in crate::routing) fn projection_operation_from_event(
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Option<Operation> {
    if arkret_wire::events::EventKind::try_new(&parsed.kind).is_none() {
        tracing::debug!(kind = %parsed.kind, "projection: kind is not registered");
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
    if matches!(parsed.data_event_query_grade, DataEventQueryGrade::Stale) {
        payload_object.insert("query_grade".to_owned(), Value::String("stale".to_owned()));
    }
    if let Some(hlc) = envelope.get("hlc").and_then(Value::as_str) {
        payload_object
            .entry("hlc".to_owned())
            .or_insert_with(|| Value::String(hlc.to_owned()));
    }
    // morph.md §4.1 S1 — the schema-migration preflight validates that the
    // event `requirements.schema[]` binds the migration schema set. That field
    // lives on the envelope, not the payload, so surface it on the projection
    // operation for this kind (scoped to avoid changing other reducers' payload
    // shape).
    if parsed.kind == arkret_wire::events::EventKind::MORPH_SCHEMA_MIGRATE
        && let Some(requirements) = envelope.get("requirements")
    {
        payload_object
            .entry("requirements".to_owned())
            .or_insert_with(|| requirements.clone());
    }
    // ak.rsvp.set converges through the mv_register cell, so the projection
    // needs the envelope causal edges: they decide both the schedule-basis
    // subset admission and which existing heads this response dominates.
    // Scoped to this kind so other reducers keep their payload shape.
    if matches!(
        parsed.kind.as_str(),
        arkret_wire::events::EventKind::RSVP_SET | arkret_wire::events::EventKind::STRAND_UPDATE
    ) {
        if let Some(causal_refs) = envelope.get("causal_refs") {
            payload_object.insert("envelope_causal_refs".to_owned(), causal_refs.clone());
        }
    }
    if parsed.kind == arkret_wire::events::EventKind::RSVP_SET {
        if let Some(digest) = envelope
            .get("proofs")
            .and_then(Value::as_array)
            .and_then(|proofs| proofs.first())
            .and_then(|proof| proof.get("event_digest"))
        {
            payload_object
                .entry("canonical_event_digest".to_owned())
                .or_insert_with(|| digest.clone());
        }
    }
    if parsed.kind == arkret_wire::events::EventKind::APPLET_REGISTRATION
        && let Some(scope_ref) = envelope.get("scope_ref")
    {
        payload_object.insert("accepted_scope_ref".to_owned(), scope_ref.clone());
    }
    if parsed.kind == arkret_wire::events::EventKind::RELATION_CREATE {
        normalize_relation_create_payload(payload_object, parsed);
    }
    if let Some(target_ref) = payload_object
        .get("target_ref")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        && target_ref.starts_with("ak:strand:")
    {
        payload_object
            .entry("strand_id".to_owned())
            .or_insert_with(|| Value::String(target_ref.clone()));
    }
    if !payload_object.contains_key("thread_id")
        && let Some(strand_id) = payload_object
            .get("strand_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    {
        payload_object.insert("thread_id".to_owned(), Value::String(strand_id));
    }
    payload_object.remove("executed_by");
    payload_object.remove("authorization_ref");
    if let Some(executed_by) = envelope.get("executed_by").and_then(Value::as_str) {
        payload_object.insert(
            "executed_by".to_owned(),
            Value::String(executed_by.to_owned()),
        );
        if let Some(authorization_ref) = envelope.get("authorization_ref").and_then(Value::as_str) {
            payload_object.insert(
                "authorization_ref".to_owned(),
                Value::String(authorization_ref.to_owned()),
            );
        }
    }
    if matches!(
        parsed.kind.as_str(),
        "ak.consent.grant" | "ak.consent.revoke"
    ) {
        payload_object
            .entry("actor_seq".to_owned())
            .or_insert_with(|| Value::from(parsed.actor_seq));
    }
    if parsed.kind == arkret_wire::events::EventKind::MORPH_SCHEMA_MIGRATE {
        if let Some(authorization_ref) = parsed.authorized_refs.first() {
            payload_object
                .entry("authorization_ref".to_owned())
                .or_insert_with(|| Value::String(authorization_ref.clone()));
        }
        payload_object
            .entry("capability_action".to_owned())
            .or_insert_with(|| Value::String("ak.morph.schema.migrate".to_owned()));
    }
    if let Some(seal_ref) = envelope.get("seal_ref").and_then(Value::as_str) {
        payload_object
            .entry("seal_ref".to_owned())
            .or_insert_with(|| Value::String(seal_ref.to_owned()));
    }
    if let Some(seal_basis) = envelope.get("seal_basis") {
        payload_object
            .entry("seal_basis".to_owned())
            .or_insert_with(|| seal_basis.clone());
    }
    if let Some(preconditions) = envelope.get("preconditions") {
        payload_object
            .entry("preconditions".to_owned())
            .or_insert_with(|| preconditions.clone());
    }
    if let Some(effects) = envelope.get("effects") {
        payload_object
            .entry("effects".to_owned())
            .or_insert_with(|| effects.clone());
    }
    if matches!(
        parsed.kind.as_str(),
        arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE
            | arkret_wire::events::EventKind::AGENT_KEY_REVOKE
            | arkret_wire::events::EventKind::CALL_RECORDING_START
    ) {
        payload_object.insert(
            "accepted_event_id".to_owned(),
            Value::String(parsed.event_id.clone()),
        );
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
    operation.refs = event_refs(envelope.get("refs"));
    operation.canonical_event_digest = Some(parsed.canonical_digest.clone());
    operation.created_at = envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(now);
    Some(operation)
}

/// Rebuild the exact internal projection DTO used at admission from one
/// canonical Event record.  Hydration must not invent a second Event ->
/// Operation mapping: the accepted wire envelope is the source of truth and
/// this delegates to the same mapper used by the live submit path.
pub(crate) fn projection_operation_from_canonical_record(
    record: &CanonicalEventRecord,
) -> Option<Operation> {
    let object = record.envelope.as_object()?;
    let realm_id = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| record.realm_id.clone())?;
    let prev_refs = record
        .envelope
        .get("prev_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    let authorized_refs = object
        .get("refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|reference| reference.get("role").and_then(Value::as_str) == Some("authorized_by"))
        .filter_map(|reference| reference.get("id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    let parsed = ValidatedEventEnvelope {
        event_id: record.event_id.clone(),
        actor_id: record.actor_id.clone(),
        device_id: object
            .get("device_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        actor_seq: record.actor_seq,
        realm_id,
        kind: record.kind.clone(),
        schema_id: record.schema_id.clone(),
        prev_refs,
        authorized_refs,
        canonical_digest: record.canonical_digest.clone(),
        canonical_bytes: record.canonical_bytes.clone(),
        data_event_query_grade: DataEventQueryGrade::Observed,
    };
    projection_operation_from_event(&parsed, &record.envelope)
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
        for field in ["from_ref", "to_ref", "rank", "fields", "scope_circle_id"] {
            if let Some(value) = relation.get(field) {
                payload_object
                    .entry(field.to_owned())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    if !payload_object.contains_key("relation_id")
        && !payload_object.contains_key("id")
        && let Some(suffix) = parsed.event_id.strip_prefix("ak:event:")
    {
        payload_object.insert(
            "relation_id".to_owned(),
            Value::String(format!("ak:relation:{suffix}")),
        );
    }
}

fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    // Prefer the client-supplied alias when it's a valid OperationId
    // (`ak:operation:<uuid v7>` per `arkret-rust-sdk/identifiers`).
    // Older inkson builds shipped the event_id (ak:event:) verbatim in
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
    let suffix = event_id.strip_prefix("ak:event:")?;
    OperationId::new(format!("ak:operation:{suffix}")).ok()
}

#[cfg(test)]
mod projection_operation_tests {
    use serde_json::json;

    use super::*;

    fn parsed(kind: &str) -> ValidatedEventEnvelope {
        ValidatedEventEnvelope {
            event_id: "ak:event:01904100-0000-7000-8000-000000000001".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
            actor_seq: 1,
            realm_id: "ak:realm:01904100-0000-7000-8000-000000000003".to_owned(),
            kind: kind.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            prev_refs: Vec::new(),
            authorized_refs: Vec::new(),
            canonical_digest: "sha256:test".to_owned(),
            canonical_bytes: Vec::new(),
            data_event_query_grade: DataEventQueryGrade::Observed,
        }
    }

    #[test]
    fn accepted_event_id_is_only_projected_for_agent_key_authorize() {
        let agent_key = projection_operation_from_event(
            &parsed(arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE),
            &json!({ "payload": { "agent_id": "did:web:agent.example", "key_id": "ak:agent_key:test" } }),
        )
        .unwrap();
        assert_eq!(
            agent_key
                .payload
                .get("accepted_event_id")
                .and_then(Value::as_str),
            Some("ak:event:01904100-0000-7000-8000-000000000001")
        );

        let device_authorize = projection_operation_from_event(
            &parsed(arkret_wire::events::EventKind::DEVICE_AUTHORIZE),
            &json!({ "payload": {} }),
        )
        .unwrap();
        assert!(device_authorize.payload.get("accepted_event_id").is_none());

        let agent_key_revoke = projection_operation_from_event(
            &parsed(arkret_wire::events::EventKind::AGENT_KEY_REVOKE),
            &json!({ "payload": {} }),
        )
        .unwrap();
        assert_eq!(
            agent_key_revoke
                .payload
                .get("accepted_event_id")
                .and_then(Value::as_str),
            Some("ak:event:01904100-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn agent_key_authorize_projection_passes_reducer_schema_validation() {
        let kind = arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE;
        let operation = projection_operation_from_event(
            &parsed(kind),
            &json!({
                "payload": {
                    "agent_id": "did:web:agent.example",
                    "key_id": "did:web:agent.example#runtime-1",
                    "verification_method": "did:web:agent.example#runtime-1",
                    "public_key_digest": concat!(
                        "sha256:",
                        "1111111111111111111111111111111111111111111111111111111111111111"
                    ),
                    "signing_key_binding_digest": concat!(
                        "sha256:",
                        "2222222222222222222222222222222222222222222222222222222222222222"
                    ),
                    "accountable_principal_id": "did:web:controller.example",
                    "agent_key_scope": {
                        "actions": ["ak.self.events.command.submit"],
                        "resources": [{
                            "kind": "operation",
                            "operation": "ak.self.events.command.submit"
                        }]
                    },
                    "audience": ["did:web:principal.example"],
                    "issued_at": "2026-07-20T15:09:03.628Z",
                    "approval_evidence": {
                        "kind": "pairing_request",
                        "request_canonical_digest": concat!(
                            "sha256:",
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        ),
                        "pairing_request_id": "agent_pairing_request:test",
                        "approved_by": "did:web:controller.example"
                    }
                }
            }),
        )
        .expect("valid Agent key Event must build its canonical projection Operation");

        assert_eq!(
            crate::routing::events::operations::validate_operation_payload_schema(kind, &operation),
            Ok(())
        );
    }

    #[test]
    fn realm_bootstrap_join_and_discovery_facets_are_projectable() {
        for (kind, value) in [
            (arkret_wire::events::EventKind::REALM_JOIN_RULE, "invite"),
            (arkret_wire::events::EventKind::REALM_DISCOVERY, "listed"),
        ] {
            let operation = projection_operation_from_event(
                &parsed(kind),
                &json!({ "payload": { "value": value } }),
            )
            .unwrap_or_else(|| panic!("{kind} must build a projection Operation"));

            assert_eq!(
                operation.payload.get("value").and_then(Value::as_str),
                Some(value)
            );
        }
    }
}

/// AKP-0007 — resolve the canonical `effective_scope` for an Event
/// Envelope on read. Returns `Some(circle_id)` when the envelope (or its
/// payload) names a Circle scope, `Some("realm:<realm_id>")` when the
/// scope is the Realm default, or `None` when neither can be derived.
pub(crate) fn effective_scope_for_envelope(envelope: &Value) -> Option<String> {
    let object = envelope.as_object()?;
    // Server-stamped authoritative scope. For messages this is set at ingest
    // from the message's Strand (see submit_event_value); it always wins.
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
    if object.get("kind").and_then(Value::as_str)
        == Some(arkret_wire::events::EventKind::MESSAGE_CREATE)
    {
        return None;
    }
    // Non-message events (e.g. ak.strand.create / ak.strand.update) legitimately
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
) -> JsonResult<EventView> {
    let receipts = state
        .event_queries()
        .canonical_batch_receipts_for_event(&record.event_id)
        .await
        .map_err(|error| AppError::internal(format!("Event Batch Receipt lookup failed: {error}")))?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::internal(format!("Event Batch Receipt encode failed: {error}"))
        })?;
    json_ok(EventView {
        event: sdk_event_for_state(state, record)?,
        visibility: Some(event_visibility_metadata(state, record)),
        receipts,
    })
}

pub(crate) fn sdk_event_for_state(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<Event, AppError> {
    let realm_id = canonical_realm_id_for_record(record);
    let actor_erased = record.kind != arkret_wire::events::EventKind::AUDIT_ERASURE_RECEIPT
        && realm_id.as_deref().is_some_and(|realm_id| {
            actor_erased_in_realm(&state.projections().snapshot(), &record.actor_id, realm_id)
        });
    sdk_event_from_record(
        record,
        retention_tombstone_for_event(state, &record.event_id),
        actor_erased,
    )
}

fn sdk_event_from_record(
    record: &CanonicalEventRecord,
    tombstone: Option<soland_services::governance::RetentionTombstoneRecord>,
    actor_erased: bool,
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
    let actor_id = arkret_identifiers::Did::new(record.actor_id.clone())
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
    if actor_erased {
        payload = erasure_tombstone_payload_value(&payload);
        unsigned.insert("erasure_tombstone".to_owned(), json!(true));
    }
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
            json!(arkret_canonical::format_timestamp_canonical(
                tombstone.expired_at
            )),
        );
        unsigned.insert(
            "retention_tombstoned_at".to_owned(),
            json!(arkret_canonical::format_timestamp_canonical(
                tombstone.tombstoned_at
            )),
        );
        unsigned.insert(
            "retention_seal_preserved".to_owned(),
            json!(tombstone.sealed),
        );
        unsigned.insert("physical_delete".to_owned(), json!(false));
        unsigned.insert(
            "retention_risk_ui".to_owned(),
            json!(retention_risk_ui_flag(&tombstone)),
        );
        unsigned.insert(
            "retention_risk_audit".to_owned(),
            json!(retention_risk_audit_flag(&tombstone)),
        );
        unsigned.insert(
            "retention_risk_reason".to_owned(),
            json!(retention_risk_reason(&tombstone)),
        );
    }
    Ok(Event {
        event_id,
        kind: record.kind.clone().into(),
        realm_id: realm_id.clone(),
        actor_id,
        actor_seq: record.actor_seq,
        created_at,
        hlc: Some(hlc),
        prev_refs: event_id_list(object.get("prev_refs"))?,
        scope_ref: sdk_scope_ref(record, &realm_id),
        refs: event_refs(object.get("refs")),
        causal_refs: hash_list(object.get("causal_refs"))?,
        preconditions: json_array_field(object, "preconditions"),
        seal_ref: object
            .get("seal_ref")
            .and_then(Value::as_str)
            .and_then(|value| arkret_identifiers::SealId::new(value.to_owned()).ok()),
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
        payload: serde_json::from_value(payload).map_err(|error| {
            AppError::internal(format!("stored event payload must be an object: {error}"))
        })?,
        executed_by: object
            .get("executed_by")
            .and_then(Value::as_str)
            .and_then(|value| arkret_identifiers::Did::new(value.to_owned()).ok()),
        authorization_ref: object
            .get("authorization_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        applet_id: object
            .get("applet_id")
            .and_then(Value::as_str)
            .and_then(|value| arkret_identifiers::AppletId::new(value.to_owned()).ok()),
        external_ref: object
            .get("external_ref")
            .filter(|value| !value.is_null())
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        actor_kind: object
            .get("actor_kind")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        unsigned,
        proofs: sdk_event_proofs(record, object, created_at)?,
    })
}

fn event_visibility_metadata(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> std::collections::BTreeMap<String, Value> {
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
        metadata["retention_expired_at"] = json!(arkret_canonical::format_timestamp_canonical(
            tombstone.expired_at
        ));
        metadata["retention_tombstoned_at"] = json!(arkret_canonical::format_timestamp_canonical(
            tombstone.tombstoned_at
        ));
        metadata["retention_seal_preserved"] = json!(tombstone.sealed);
        metadata["physical_delete"] = json!(false);
        metadata["retention_risk_ui"] = json!(retention_risk_ui_flag(&tombstone));
        metadata["retention_risk_audit"] = json!(retention_risk_audit_flag(&tombstone));
        metadata["retention_risk_reason"] = json!(retention_risk_reason(&tombstone));
    }
    metadata
        .as_object()
        .expect("event visibility metadata is an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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

fn hash_list(value: Option<&Value>) -> Result<Vec<Hash>, AppError> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .filter_map(Value::as_str)
        .map(|value| {
            Hash::new(value.to_owned())
                .map_err(|error| AppError::internal(format!("stored hash: {error}")))
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

/// The Event's signed security scope.
///
/// `scope_ref` is a required, producer-signed member of the v1 envelope, so the
/// stored bytes carry it. The payload-derived fallback exists only for rows
/// stored before it became mandatory and resolves to the Realm-default scope,
/// which is the narrowest safe answer: reading a Circle scope back out of a
/// payload would be recomputing a signed field rather than reading it.
fn sdk_scope_ref(record: &CanonicalEventRecord, realm_id: &RealmId) -> arkret_wire::ScopeRef {
    if let Some(scope) = record
        .envelope
        .get("scope_ref")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        return scope;
    }
    match effective_scope_for_envelope(&record.envelope).as_deref() {
        Some(scope) if scope.starts_with("ak:circle:") => {
            match arkret_identifiers::CircleId::new(scope.to_owned()) {
                Ok(circle_id) => arkret_wire::ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id,
                },
                Err(_) => arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
            }
        }
        _ => arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
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
        .unwrap_or("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#dev")
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
        proof_purpose: None,
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
/// `ak.device.revoke` Control Move. v1 scaffold scope: only the principal
/// may revoke its own sibling devices (recovery-service revocation lands
/// with the recovery strands), and a device MUST NOT revoke itself
/// (`device-lifecycle.md` §2.2 self-lockout rule). The principal-control
/// realm binding itself is enforced by
/// `validate_principal_control_realm_binding`; payload field presence by
/// the registry payload schema.
pub(in crate::routing) fn validate_device_revoke_submission(
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
            "ak.device.revoke payload.device_id is required",
        ));
    }
    if principal_id != parsed.actor_id {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "ak.device.revoke payload.principal_id must be the submitting actor",
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
        .filter(|scope| scope.starts_with("ak:circle:"))
    else {
        return true;
    };
    if record.actor_id == session.actor {
        return true;
    }
    state
        .projections()
        .snapshot()
        .circle_scope_visible_to_actor_at(&scope_circle_id, &session.actor, record.received_at)
}

/// Scan the projected cell or durable Event store for the most recent
/// `ak.realm.read_receipt_policy` event in `realm_id` and return its typed
/// SDK policy payload. Returns `None` when no policy event has been written
/// for this Realm; callers use `ReadReceiptPolicy::default()`.
///
/// Used by ephemeral `ak.receipt.read` admission and future receipt fanout
/// handlers to enforce the Realm policy.
///
/// **Note**: this is a linear scan of the durable event store. For the
/// production fanout path it should be projected into `AppState` once the
/// reducer kind delegates from `Ignored` to a real projection.
pub async fn effective_read_receipt_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<arkret_models_collaboration::objects::read_receipts::ReadReceiptPolicy> {
    // Cell-keyed fast path. The Move/Seal pipeline writes the
    // `ak.component.realm.read_receipt_policy.v1` resolved CasRegister
    // value into `ProjectionState::cells` after every apply_seal; we
    // read directly from there. (R1.2 renamed the cell family from
    // `ak.component.realm.read_receipt_policy.v1` along with the event
    // kind.)
    {
        let proj = state.projections().snapshot();
        let cell_id = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.read_receipt_policy.v1:{realm_id}"
        ))
        .ok()?;
        if let Some(value) = proj.cell_value(&cell_id) {
            return read_receipt_policy_from_value(value);
        }
    }
    // Cold-path fallback: linear scan of the durable Event store. Used at
    // boot before the projection has been rehydrated, or when a server is
    // running with persistence disabled.
    let records = state.event_queries().canonical_events().await.ok()?;
    let mut latest: Option<&CanonicalEventRecord> = None;
    for record in &records {
        // CanonicalEventRecord uses `kind` (not event_kind) for the
        // canonical Arkret event kind string.
        if record.kind != "ak.realm.read_receipt_policy" {
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
    let payload = record.envelope.get("payload")?;
    read_receipt_policy_from_value(payload)
}

fn read_receipt_policy_from_value(
    value: &Value,
) -> Option<arkret_models_collaboration::objects::read_receipts::ReadReceiptPolicy> {
    serde_json::from_value(value.clone()).ok()
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
            .map(|_| json!({"id": "ak:event:e", "role": "after"}))
            .collect();
        let err = event_semantic_refs(&refs_object(json!(refs)), MAX_EVENT_REFS).unwrap_err();
        assert_eq!(err.code, "refs_too_large");
    }

    // §2 — `authorized_by` role ≤ 64 within the 128 total.
    #[test]
    fn authorized_by_over_max_rejected_as_refs_too_large() {
        let refs: Vec<Value> = (0..(arkret_wire::event_envelope::MAX_AUTHORIZED_BY_REFS + 1))
            .map(|index| {
                json!({
                    "id": format!("ak:grant:019fa9da-0000-7000-8000-{index:012x}"),
                    "role": "authorized_by"
                })
            })
            .collect();
        let err = event_semantic_refs(&refs_object(json!(refs)), MAX_EVENT_REFS).unwrap_err();
        assert_eq!(err.code, "refs_too_large");
    }

    #[test]
    fn within_limits_collects_only_authorized_by_refs() {
        let refs = json!([
            {
                "id": "ak:grant:019fa9da-0000-7000-8000-000000000001",
                "role": "authorized_by"
            },
            {"id": "ak:event:e2", "role": "after"}
        ]);
        let out = event_semantic_refs(&refs_object(refs), MAX_EVENT_REFS).unwrap();
        assert_eq!(
            out,
            vec!["ak:grant:019fa9da-0000-7000-8000-000000000001".to_owned()]
        );
    }

    #[test]
    fn authorized_by_rejects_event_id_alias() {
        let refs = json!([{
            "id": "ak:event:019fa9da-0000-7000-8000-000000000001",
            "role": "authorized_by"
        }]);
        let err = event_semantic_refs(&refs_object(refs), MAX_EVENT_REFS).unwrap_err();
        assert_eq!(err.code, "invalid_param");
    }
}
