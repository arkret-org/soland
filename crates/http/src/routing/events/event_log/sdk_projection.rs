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
        event: sdk_event_for_state(state, record)?.into(),
        visibility: Some(event_visibility_metadata(state, record)),
        receipts,
    })
}

pub(crate) fn sdk_event_for_state(
    state: &AppState,
    record: &AcceptedEvent,
) -> Result<Event, AppError> {
    let realm_id = canonical_realm_id_for_record(record);
    let actor_erased = record.kind != arkret_wire::EventKind::AuditErasureReceipt.as_str()
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
    record: &AcceptedEvent,
    tombstone: Option<soland_services::governance::RetentionTombstoneRecord>,
    actor_erased: bool,
) -> Result<Event, AppError> {
    let preserves_signed_content = tombstone.is_none() && !actor_erased;
    let object = record
        .envelope
        .as_object()
        .ok_or_else(|| AppError::internal("stored event envelope is not an object"))?;
    let realm_id = canonical_realm_id_for_record(record)
        .ok_or_else(|| AppError::internal("stored event missing realm_id"))?;
    let realm_id = RealmId::new(realm_id).map_err(|error| AppError::internal(error.to_string()))?;
    let event_id = EventId::new(record.event_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let actor_id = arkret_wire::DidCoreId::new(record.actor_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let principal_server_id = object
        .get("principal_server_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("stored event missing principal_server_id"))
        .and_then(|value| {
            arkret_wire::DidCoreId::new(value.to_owned())
                .map_err(|error| AppError::internal(error.to_string()))
        })?;
    let created_at = object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(record.received_at);
    let hlc = object
        .get("hlc")
        .and_then(Value::as_str)
        .and_then(|value| Hlc::new(value.to_owned()).ok());
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
    let event = Event {
        event_id,
        kind: record.kind.clone().into(),
        realm_id: realm_id.clone(),
        actor_id,
        principal_server_id,
        actor_seq: record.actor_seq,
        created_at,
        // `hlc` is a producer-signed optional field. A read path must preserve
        // its absence; synthesizing one from `received_at` changes the Event
        // digest and makes a client-built successor Seal name a digest the
        // canonical store has never accepted.
        hlc,
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
        payload: serde_json::from_value(payload).map_err(|error| {
            AppError::internal(format!("stored event payload must be an object: {error}"))
        })?,
        executed_by: object
            .get("executed_by")
            .and_then(Value::as_str)
            .and_then(|value| arkret_wire::DidCoreId::new(value.to_owned()).ok()),
        authorization_ref: object
            .get("authorization_ref")
            .and_then(Value::as_str)
            .and_then(|value| arkret_wire::AuthorizationRef::new(value.to_owned()).ok()),
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
    };
    if preserves_signed_content {
        let reconstructed_digest = event
            .event_digest_with_digest_suite(record.digest_suite)
            .map_err(|error| {
                AppError::internal(format!(
                    "stored Event digest reconstruction failed: {error}"
                ))
            })?;
        if reconstructed_digest != record.canonical_digest {
            return Err(AppError::internal(format!(
                "stored Event read reconstruction changed canonical digest: expected {}, got {}",
                record.canonical_digest, reconstructed_digest
            )));
        }
    }
    Ok(event)
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
fn sdk_scope_ref(record: &AcceptedEvent, realm_id: &RealmId) -> arkret_wire::ScopeRef {
    record
        .envelope
        .get("scope_ref")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_else(|| arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        })
}

fn sdk_event_proofs(
    record: &AcceptedEvent,
    object: &serde_json::Map<String, Value>,
    created_at: DateTime<Utc>,
) -> Result<Vec<arkret_wire::EventProof>, AppError> {
    if let Some(proofs) = object
        .get("proofs")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<arkret_wire::EventProof>>(value).ok())
        .filter(|proofs| !proofs.is_empty())
    {
        return Ok(proofs);
    }
    let proof = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(Value::as_object);
    let verification_method = arkret_wire::DidUrl::new(
        proof
            .and_then(|proof| proof.get("verification_method"))
            .and_then(Value::as_str)
            .unwrap_or("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#dev")
            .to_owned(),
    )
    .map_err(|error| {
        AppError::internal(format!("projected proof verification_method is invalid: {error}"))
    })?;
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
    Ok(vec![arkret_wire::EventProof::Producer(
        ProducerEventProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            proof_purpose: None,
            verification_method,
            event_digest,
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at,
            domain,
            audience,
            jws: proof
                .and_then(|proof| proof.get("jws").or_else(|| proof.get("detached_jws")))
                .and_then(Value::as_str)
                .unwrap_or("ZGV2..c2ln")
                .to_owned(),
        },
    )])
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
    if principal_id != parsed.actor_id.as_str() {
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

pub(crate) fn canonical_realm_id_for_record(record: &AcceptedEvent) -> Option<String> {
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

fn session_actor_core_id(session: &SessionRecord) -> Option<arkret_wire::DidCoreId> {
    arkret_wire::DidCoreId::new(session.actor.clone()).ok()
}

pub(crate) async fn event_visible_to_session(
    state: &AppState,
    record: &AcceptedEvent,
    session: &SessionRecord,
) -> bool {
    if session_actor_core_id(session)
        .is_some_and(|session_actor| session_actor.as_str() == record.actor_id)
    {
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
    record: &AcceptedEvent,
    session: &SessionRecord,
) -> bool {
    let Some(scope_circle_id) = effective_scope_for_envelope(&record.envelope)
        .filter(|scope| scope.starts_with("ak:circle:"))
    else {
        return true;
    };
    let Some(session_actor) = session_actor_core_id(session) else {
        return false;
    };
    if record.actor_id == session_actor.as_str() {
        return true;
    }
    state
        .projections()
        .snapshot()
        .circle_scope_visible_to_actor_at(
            &scope_circle_id,
            session_actor.as_str(),
            record.received_at,
        )
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
    let mut latest: Option<&AcceptedEvent> = None;
    for record in &records {
        // AcceptedEvent uses `kind` (not event_kind) for the
        // canonical Arkret event kind string.
        if record.kind != arkret_wire::event_kind_str::REALM_READ_RECEIPT_POLICY {
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
    // The policy state lives on the envelope payload; AcceptedEvent
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
