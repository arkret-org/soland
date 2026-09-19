use sha2::{Digest, Sha256};

use super::*;
/// The registry projection evaluator for a bootstrap unit.
///
/// A genesis unit has no accepted Realm yet, so there is no
/// `ak.component.realm.digest_suite.v1` cell to read and the protocol baseline
/// suite is the only defined one (`conformance/encoding.md` §4). Post-genesis
/// callers MUST use `ProjectionService::project_cell_writes`, which reads the
/// Realm's effective suite.
pub(in crate::routing) fn genesis_cell_write_projector(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::cbs::ProjectedCellWrite>, String> {
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
            "param_invalid",
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
                "param_invalid",
                "refs entries must be objects",
            ));
        };
        let id = event_string_field(reference, &["id"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "refs entries require id",
            )
        })?;
        let role = event_string_field(reference, &["role"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "refs entries require role",
            )
        })?;
        if role == "authorized_by" {
            if arkret_identifiers::GrantId::new(id.clone()).is_err() {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
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
    EventId::new(value.to_owned()).is_ok()
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
    outcome.frontiers = vec![realm_actor_frontier];
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
    projection_operation_from_wire(&parsed.kind, parsed.event_id.as_str(), envelope)
}

/// Pre-derive the batch-visible Operation for one not-yet-validated submit
/// envelope.
///
/// The sibling-policy scan (`operations::policy_extra`) is defined over the
/// whole submit batch, but per-Event admission only materializes its own
/// Operation after envelope validation. Batch surfaces run the same
/// Event -> Operation contract on each raw envelope up front so the lane can
/// hand the full sibling set to those validators. An envelope that cannot map
/// yet is simply absent from the scan and fails its own admission on its
/// turn, so this never widens what a single Event may pass.
pub(in crate::routing) fn projection_operation_from_envelope(
    envelope: &Value,
) -> Option<Operation> {
    let kind = envelope.get("kind").and_then(Value::as_str)?;
    let event_id = envelope.get("event_id").and_then(Value::as_str)?;
    projection_operation_from_wire(kind, event_id, envelope)
}

/// The single Event -> `Operation` mapper.
///
/// It is deliberately a function of the accepted wire envelope alone. The
/// authenticated submitting device is request context, not an Event field
/// (`event-envelope.schema.json` declares no `device_id` and closes the
/// object), so replay can reach exactly the same Operation as admission did.
fn projection_operation_from_wire(
    kind: &str,
    event_id: &str,
    envelope: &Value,
) -> Option<Operation> {
    if arkret_wire::EventKind::try_new(kind).is_none() {
        tracing::debug!(kind, "projection: kind is not registered");
        return None;
    }
    let Some(operation_id) = event_operation_id(envelope, event_id) else {
        tracing::debug!(kind, event_id, "projection: event_operation_id failed");
        return None;
    };
    let event = event_for_canonical_digest(envelope)
        .map_err(|error| {
            tracing::debug!(
                kind,
                event_id,
                ?error,
                "projection: SDK Event decode failed"
            );
            error
        })
        .ok()?;
    Operation::from_accepted_event(
        operation_id,
        arkret_wire::OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| {
        tracing::debug!(
            kind,
            event_id,
            %error,
            "projection: SDK accepted Event projection failed"
        );
        error
    })
    .ok()
}

/// Rebuild the exact internal projection DTO used at admission from one
/// canonical Event record.  Hydration must not invent a second Event ->
/// Operation mapping: the accepted wire envelope is the source of truth and
/// this delegates to the same mapper used by the live submit path.
pub(crate) fn projection_operation_from_canonical_record(
    record: &AcceptedEvent,
) -> Option<Operation> {
    // The stored envelope is the accepted Event verbatim, so every typed
    // field it carries (`realm_id`, `actor_id`, `prev_refs`, …) is revalidated
    // by the SDK `Event` decode inside the shared mapper. Rebuilding an
    // admission-shaped DTO here would only reintroduce request context that
    // replay does not have.
    projection_operation_from_wire(&record.kind, &record.event_id, &record.envelope)
}

/// Domain separator for the Operation handle soland derives for an accepted
/// Event. Versioned and distinct from protocol identity domains. This is a
/// Soland-local operation handle and is not a Realm identity derivation.
const EVENT_PROJECTION_OPERATION_DOMAIN: &[u8] = b"ak:operation:soland-event-projection:v1:";

fn event_projection_operation_uuid(event_id: &str) -> uuid::Uuid {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_PROJECTION_OPERATION_DOMAIN);
    hasher.update(event_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

pub(crate) fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    // Prefer the client-supplied alias when it's a valid OperationId
    // (`ak:operation:<uuid v7>` per `arkret-rust-sdk/identifiers`). A client
    // that authored the draft locally already dedupes on that value, so
    // honouring it keeps a resubmission idempotent end to end.
    //
    // The alias lives in `unsigned`, which is outside the signed canonical
    // Event transcript, so it is routinely absent: a federated Event, a
    // non-SDK submitter, and every Event soland authors itself carry none.
    // Server correctness MUST NOT depend on it — returning `None` here drops
    // the entire projection chain for the Event, and with it
    // `validate_operation_semantics`, so a payload the kind's registered
    // validator would have rejected gets durably accepted instead.
    if let Some(alias) = envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        && let Ok(operation_id) = OperationId::new(alias.to_owned())
    {
        return Some(operation_id);
    }
    // Otherwise soland allocates the handle. `Operation` is
    // `ak.local.operation_draft.v1` — an SDK-local reducer DTO, not a wire
    // fact — so its id is the receiver's to mint, and `id-kind-registry.json`
    // makes `operation` producer-allocated (UUIDv7). Deriving it from the
    // Event id under a domain separator is what keeps it reproducible: live
    // admission and `projection_operation_from_canonical_record` hydration
    // must land on the same handle or the projection would re-key on reboot.
    //
    // Retyping the Event id into `ak:operation:<uuid>` — what this used to do
    // — cannot work: an Event id is a content-bound full-digest token
    // (`encoding.md` §4.0), while an Operation id is producer-allocated
    // (UUIDv7), so the retyped
    // value never validated and this function always returned `None`.
    let event_id = EventId::new(event_id.to_owned()).ok()?;
    OperationId::new(format!(
        "ak:operation:{}",
        event_projection_operation_uuid(event_id.as_str())
    ))
    .ok()
}

/// Resolve the Event's producer-signed `scope_ref` for read-path visibility.
pub(crate) fn effective_scope_for_envelope(envelope: &Value) -> Option<String> {
    let scope = envelope.get("scope_ref")?.as_object()?;
    match scope.get("kind").and_then(Value::as_str) {
        Some("circle") => scope
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        Some("realm") => scope
            .get("realm_id")
            .and_then(Value::as_str)
            .map(|realm_id| format!("realm:{realm_id}")),
        _ => None,
    }
}

pub(crate) async fn event_view_for_state(
    state: &AppState,
    record: &AcceptedEvent,
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
        event: canonical_event_read_row(state, record).await?,
        visibility: Some(event_visibility_metadata(state, record)),
        receipts,
    })
}

/// Strict accepted-envelope materialization for canonical scans. Privacy views
/// are applied by the caller; signed payloads must never be rewritten in place.
pub(crate) fn canonical_event_for_read(record: &AcceptedEvent) -> Result<Event, AppError> {
    let event: Event = serde_json::from_value(record.envelope.clone())
        .map_err(|error| AppError::internal(format!("invalid canonical Event: {error}")))?;
    if event.event_id.as_str() != record.event_id
        || event
            .derive_event_id_with_digest_suite(record.digest_suite)
            .map_err(|error| AppError::internal(error.to_string()))?
            != event.event_id
        || event.kind.as_str() != record.kind
        || event.actor_id.to_string() != record.actor_id
        || event.actor_seq != record.actor_seq
        || record
            .realm_id
            .as_deref()
            .is_some_and(|realm| realm != event.realm_id.as_str())
        || event
            .event_digest_with_digest_suite(record.digest_suite)
            .map_err(|error| AppError::internal(error.to_string()))?
            != record.canonical_digest
    {
        return Err(AppError::internal(
            "canonical Event index or digest mismatch",
        ));
    }
    Ok(event)
}

pub(crate) fn sdk_event_for_state(
    state: &AppState,
    record: &AcceptedEvent,
) -> Result<Event, AppError> {
    let event = canonical_event_for_read(record)?;
    if retention_tombstone_for_event(state, &record.event_id).is_some() {
        return Err(AppError::internal(
            "Event-only surface cannot materialize a privacy-redacted Event",
        ));
    }
    Ok(event)
}

/// Read surfaces with an EventReadRow union keep the slot without rewriting
/// signed bytes. Derive Message redaction from accepted history even when no
/// independent projection row exists.
pub(crate) async fn canonical_event_read_row(
    state: &AppState,
    record: &AcceptedEvent,
) -> Result<arkret_models_collaboration::http_bodies::EventReadRow, AppError> {
    use arkret_models_collaboration::http_bodies::EventRedactionReason;
    let event = canonical_event_for_read(record)?;
    let reason = if retention_tombstone_for_event(state, &record.event_id).is_some() {
        Some(EventRedactionReason::RetentionPruned)
    } else if matches!(
        event.kind,
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise
    ) {
        let message_id = if event.kind == arkret_wire::EventKind::MessageCreate {
            record.event_id.replacen("ak:event:", "ak:message:", 1)
        } else {
            event
                .payload
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::internal("revision has no canonical message target"))?
                .to_owned()
        };
        let records = state
            .event_queries()
            .canonical_events()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let mut redacted = false;
        for candidate in records {
            let Some(kind) = arkret_wire::EventKind::try_new(&candidate.kind) else {
                continue;
            };
            if !arkret_wire::events::kinds::is_redaction_kind(&kind)
                || canonical_realm_id_for_record(&candidate).as_deref()
                    != Some(event.realm_id.as_str())
            {
                continue;
            }
            let target = soland_domain::reducer::message_redaction_target_ref(
                &candidate.envelope["payload"],
            );
            if target.as_deref().is_some_and(|target| {
                target == message_id || target == message_id.replacen("ak:message:", "ak:event:", 1)
            }) {
                canonical_event_for_read(&candidate)?;
                redacted = true;
            }
        }
        redacted.then_some(EventRedactionReason::Redacted)
    } else {
        None
    };
    Ok(match reason {
        Some(reason) => redacted_event_read_row(event, reason),
        None => event.into(),
    })
}

pub(crate) fn redacted_event_read_row(
    event: Event,
    reason: arkret_models_collaboration::http_bodies::EventRedactionReason,
) -> arkret_models_collaboration::http_bodies::EventReadRow {
    use arkret_models_collaboration::http_bodies::{
        EventReadRow, HiddenEventField, HiddenEventFields, RedactedEventView,
        RedactedEventViewKind, ReducerInputFalse,
    };
    EventReadRow::Redacted(RedactedEventView {
        view_kind: RedactedEventViewKind::RedactedEventView,
        event_id: event.event_id,
        kind: event.kind,
        realm_id: event.realm_id,
        created_at: Some(event.created_at),
        payload_digest: None,
        redaction_reason: reason,
        hidden_fields: HiddenEventFields::new(
            ["payload", "proofs", "unsigned"]
                .into_iter()
                .map(|field| HiddenEventField::new(field).expect("registered hidden field"))
                .collect(),
        )
        .expect("unique hidden fields"),
        inclusion_proof: None,
        reducer_input: ReducerInputFalse,
    })
}

fn event_visibility_metadata(
    state: &AppState,
    record: &AcceptedEvent,
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
    envelope: &Value,
) -> Result<String, SubmitOneError> {
    let payload = envelope.get("payload").cloned().unwrap_or(Value::Null);
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
    if device_id == session.device_id {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "cannot_self_revoke",
            "a device cannot revoke itself; revoke from a peer device",
        ));
    }
    Ok(device_id.to_owned())
}

pub(crate) fn canonical_realm_id_for_record(record: &AcceptedEvent) -> Option<String> {
    if record.kind == arkret_wire::EventKind::RealmCreate.as_str() {
        return record
            .event_id
            .strip_prefix("ak:event:")
            .map(|token| format!("ak:realm:{token}"));
    }
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

fn session_actor_id(state: &AppState, session: &SessionRecord) -> Option<arkret_wire::ActorId> {
    crate::routing::identity::session_actor::session_actor_from_credential(state, session).ok()
}

fn is_governance_replay_input(record: &AcceptedEvent) -> bool {
    let is_anchor_unit = matches!(
        record.kind.as_str(),
        arkret_wire::event_kind_str::REALM_CREATE | arkret_wire::event_kind_str::DEVICE_REANCHOR
    );
    is_anchor_unit
        || (record.envelope.get("seal_basis").is_some()
            && record.envelope.get("auth_context").is_none())
}

async fn is_validated_realm_bootstrap_member(state: &AppState, record: &AcceptedEvent) -> bool {
    if record.actor_seq > 9
        || !matches!(
            record.kind.as_str(),
            arkret_wire::event_kind_str::REALM_CREATE
                | arkret_wire::event_kind_str::REALM_PROFILE
                | arkret_wire::event_kind_str::REALM_POLICY_BUNDLE
                | arkret_wire::event_kind_str::REALM_JOIN_RULE
                | arkret_wire::event_kind_str::REALM_HISTORY_ACCESS
                | arkret_wire::event_kind_str::REALM_DISCOVERY
                | arkret_wire::event_kind_str::REALM_ALIAS
                | arkret_wire::event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES
                | arkret_wire::event_kind_str::MEMBER_STATE
        )
    {
        return false;
    }
    let Ok(event_digest) = Hash::new(record.canonical_digest.clone()) else {
        return false;
    };
    let Ok(covering_seals) = state
        .projections()
        .seals_covering_event(&event_digest)
        .await
    else {
        return false;
    };
    let genesis_seals = covering_seals
        .into_iter()
        .filter(|seal| seal.predecessor_ref.is_none())
        .collect::<Vec<_>>();
    if genesis_seals.is_empty() {
        return false;
    }
    let Ok(records) = state.event_queries().canonical_events().await else {
        return false;
    };
    genesis_seals.into_iter().any(|seal| {
        let delta = seal.delta.iter().map(Hash::as_str).collect::<BTreeSet<_>>();
        let mut events = records
            .iter()
            .filter(|candidate| delta.contains(candidate.canonical_digest.as_str()))
            .filter_map(|candidate| canonical_event_for_read(candidate).ok())
            .collect::<Vec<_>>();
        if events.len() != delta.len() {
            return false;
        }
        events.sort_by_key(|event| event.actor_seq);
        events
            .iter()
            .any(|event| event.event_id.as_str() == record.event_id)
            && arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events).is_ok()
    })
}

pub(crate) async fn event_visible_to_session(
    state: &AppState,
    record: &AcceptedEvent,
    session: &SessionRecord,
) -> bool {
    let Some(session_actor) = session_actor_id(state, session) else {
        return false;
    };
    if session_actor.to_string() == record.actor_id {
        return true;
    }
    // A Contact participant may resolve the exact bilateral request/response
    // after acceptance as well. This does not disclose the peer's PCR: only
    // the Events already named by this pair's accepted Contact are visible.
    if matches!(
        record.kind.as_str(),
        "ak.contact.requested" | "ak.contact.accepted"
    ) {
        let Ok(author) = serde_json::from_str::<arkret_wire::ActorId>(&record.actor_id) else {
            return false;
        };
        if let Ok(Some(contact)) = state.contacts().contact_any(&author, &session_actor).await
            && contact.status == "accepted"
            && ((contact.requester_id == author && contact.target_id == session_actor)
                || (contact.target_id == author && contact.requester_id == session_actor))
            && (contact
                .request_event_ref
                .as_ref()
                .is_some_and(|id| id.as_str() == record.event_id)
                || contact
                    .response_event_ref
                    .as_ref()
                    .is_some_and(|id| id.as_str() == record.event_id))
        {
            return true;
        }
    }
    match canonical_realm_id_for_record(record) {
        Some(realm_id) => {
            // Agent PCR Events are authored as the Agent Actor, while the
            // delegated human controller owns the device key that signs the
            // accepted Seal. The controller must be able to resolve the exact
            // Event closure named by that Seal in order to verify and pin the
            // Agent PCR checkpoint; Agent PCRs intentionally have no ordinary
            // membership row.
            if crate::routing::identity::agent_pcr::controller_manages_agent_pcr(
                state,
                &session.actor,
                &realm_id,
            )
            .await
            .unwrap_or(false)
            {
                return circle_event_visible_to_session(state, record, session);
            }
            // Governance verification is not content-history backfill. A
            // current member must be able to resolve every accepted Control
            // Move named by the Realm Seal closure so a new member can perform
            // the T1/T3 replay required by encryption-and-audit.md §2.5.4.
            // `since_join` continues to crop ordinary Events below.
            let realm_visible = if is_governance_replay_input(record)
                || is_validated_realm_bootstrap_member(state, record).await
            {
                crate::routing::realm_has_member(state, &realm_id, &session_actor.to_string()).await
            } else {
                realm_event_visible_to_session(
                    state,
                    &realm_id,
                    record.received_at,
                    Some(&record.actor_id),
                    Some(session),
                )
                .await
            };
            realm_visible && circle_event_visible_to_session(state, record, session)
        }
        None => false,
    }
}

fn circle_event_visible_to_session(
    state: &AppState,
    record: &AcceptedEvent,
    session: &SessionRecord,
) -> bool {
    let Some(scope_circle_id) = effective_scope_for_envelope(&record.envelope)
        .filter(|scope| scope.starts_with("ak:circle:"))
    else {
        return true;
    };
    let Some(session_actor) = session_actor_id(state, session) else {
        return false;
    };
    if record.actor_id == session_actor.to_string() {
        return true;
    }
    state
        .projections()
        .snapshot()
        .circle_scope_visible_to_actor_at(
            &scope_circle_id,
            &session_actor.to_string(),
            record.received_at,
        )
}

/// Settled `realm.read_receipt_policy` facet of `realm_id`, as its typed SDK
/// policy payload. Returns `None` when no accepted `ak.realm.read_receipt_policy`
/// Event has written the facet; callers use `ReadReceiptPolicy::default()`.
///
/// Used by ephemeral `ak.receipt.read` admission and receipt fanout handlers
/// to enforce the Realm policy.
pub async fn effective_read_receipt_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<arkret_models_collaboration::objects::read_receipts::ReadReceiptPolicy> {
    let proj = state.projections().snapshot();
    proj.read_receipt_policy_value(realm_id)
        .and_then(read_receipt_policy_from_value)
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

    #[tokio::test]
    async fn own_event_visibility_never_crosses_station_accounts() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let session = SessionRecord {
            token_hash: "test".into(),
            account_pk: None,
            actor: "ak:did_core:web:alice.example".into(),
            device_id: "device".into(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let mut record = visibility_record(
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            json!({"scope_ref": {"kind": "circle", "circle_id": "ak:circle:fixture"}}),
        );
        record.actor_id = session_actor_id(&state, &session).unwrap().to_string();
        assert!(event_visible_to_session(&state, &record, &session).await);
        assert!(circle_event_visible_to_session(&state, &record, &session));
        record.actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ))
        .to_string();
        assert!(!event_visible_to_session(&state, &record, &session).await);
        assert!(!circle_event_visible_to_session(&state, &record, &session));
    }

    fn refs_object(refs: serde_json::Value) -> serde_json::Map<String, Value> {
        json!({ "refs": refs }).as_object().unwrap().clone()
    }

    fn visibility_record(kind: &str, envelope: Value) -> AcceptedEvent {
        AcceptedEvent {
            event_id: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM".to_owned(),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            actor_seq: 0,
            realm_id: None,
            kind: kind.to_owned(),
            schema_id: "ak.schema.test.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            canonical_bytes: Vec::new(),
            envelope,
            received_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn accepted_contact_exposes_only_exact_pair_events() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let session = SessionRecord {
            token_hash: "contact-visibility".into(),
            account_pk: None,
            actor: "ak:did_core:web:alice.example".into(),
            device_id: "device".into(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let alice = session_actor_id(&state, &session).unwrap();
        let bob = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
            state.service_core_id(),
        ));
        let mut record = visibility_record("ak.contact.requested", json!({}));
        record.actor_id = bob.to_string();
        let mut contact = soland_domain::identity::ContactRecord {
            requester_id: bob,
            target_id: alice,
            contact_round_id: None,
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".into()],
            granted_to_requester_scopes: vec!["direct_message".into()],
            status: "accepted".into(),
            pending_incoming_admitted: true,
            request_event_ref: Some(arkret_wire::EventId::new(record.event_id.clone()).unwrap()),
            request_slot_states: Vec::new(),
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state
            .contacts()
            .save_contact(contact.clone())
            .await
            .unwrap();
        assert!(event_visible_to_session(&state, &record, &session).await);
        record.kind = "ak.device.authorize".into();
        assert!(!event_visible_to_session(&state, &record, &session).await);
        record.kind = "ak.contact.requested".into();
        contact.request_event_ref = None;
        state
            .contacts()
            .save_contact(contact.clone())
            .await
            .unwrap();
        assert!(!event_visible_to_session(&state, &record, &session).await);
        contact.request_event_ref =
            Some(arkret_wire::EventId::new(record.event_id.clone()).unwrap());
        contact.status = "tombstoned".into();
        state.contacts().save_contact(contact).await.unwrap();
        assert!(!event_visible_to_session(&state, &record, &session).await);
    }

    #[test]
    fn governance_replay_visibility_does_not_classify_ordinary_events_as_control_moves() {
        let message = visibility_record(
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            json!({"auth_context": {}}),
        );
        let control = visibility_record(
            arkret_wire::event_kind_str::MEMBER_STATE,
            json!({"seal_basis": {"leaves": []}}),
        );
        let genesis = visibility_record(arkret_wire::event_kind_str::REALM_CREATE, json!({}));

        assert!(!is_governance_replay_input(&message));
        assert!(is_governance_replay_input(&control));
        assert!(is_governance_replay_input(&genesis));
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
                let event_id = arkret_identifiers::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [index as u8; 32],
                );
                let grant_id = arkret_identifiers::GrantId::from_event_id(&event_id);
                json!({
                    "id": grant_id,
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
                "id": "ak:grant:Aews9kH_oZbsLC9YX_XMJSaKOrsppWb0OKlspPS-1a6p",
                "role": "authorized_by"
            },
            {"id": "ak:event:e2", "role": "after"}
        ]);
        let out = event_semantic_refs(&refs_object(refs), MAX_EVENT_REFS).unwrap();
        assert_eq!(
            out,
            vec!["ak:grant:Aews9kH_oZbsLC9YX_XMJSaKOrsppWb0OKlspPS-1a6p".to_owned()]
        );
    }

    #[test]
    fn authorized_by_rejects_event_id_alias() {
        let refs = json!([{
            "id": "ak:event:Aews9kH_oZbsLC9YX_XMJSaKOrsppWb0OKlspPS-1a6p",
            "role": "authorized_by"
        }]);
        let err = event_semantic_refs(&refs_object(refs), MAX_EVENT_REFS).unwrap_err();
        assert_eq!(err.code, "param_invalid");
    }
}
