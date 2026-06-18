use super::*;

#[derive(Debug)]
pub(in crate::routing) struct ValidatedEventEnvelope {
    pub(in crate::routing) event_id: String,
    pub(in crate::routing) actor_id: String,
    pub(in crate::routing) device_id: String,
    pub(in crate::routing) actor_seq: u64,
    pub(in crate::routing) realm_id: String,
    pub(in crate::routing) kind: String,
    pub(in crate::routing) schema_id: String,
    pub(in crate::routing) prev_refs: Vec<String>,
    pub(in crate::routing) authorized_refs: Vec<String>,
    pub(in crate::routing) canonical_digest: String,
    pub(in crate::routing) canonical_bytes: Vec<u8>,
}

#[derive(Debug)]
pub(in crate::routing) struct EventValidationError {
    pub(in crate::routing) status: StatusCode,
    pub(in crate::routing) code: &'static str,
    pub(in crate::routing) message: String,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmitOneError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmittedEventOutcome {
    pub event_id: String,
    pub duplicate: bool,
    pub outcome: EventsSubmitOutcome,
}

impl SubmitOneError {
    pub(in crate::routing) fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<EventValidationError> for SubmitOneError {
    fn from(error: EventValidationError) -> Self {
        Self::new(error.status, error.code, error.message)
    }
}

pub(super) fn event_validation_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> EventValidationError {
    EventValidationError {
        status,
        code,
        message: message.into(),
    }
}

pub(super) fn render_submit_one_error(res: &mut Response, error: SubmitOneError) {
    render_error(res, error.status, &error.code, &error.message);
}

pub(super) async fn submit_event_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Event>,
    res: &mut Response,
) {
    if envelopes.is_empty() {
        render_submit_one_error(
            res,
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "events submit batch must contain at least one envelope",
            ),
        );
        return;
    }
    if envelopes.len() > MAX_EVENT_SUBMIT_BATCH {
        render_submit_one_error(
            res,
            SubmitOneError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "events submit batch exceeds max batch size",
            ),
        );
        return;
    }
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();

    for envelope in envelopes {
        let envelope = match serde_json::to_value(envelope) {
            Ok(value) => value,
            Err(error) => {
                rejected.push(json!({
                    "id": "unknown",
                    "reason_code": "bad_json",
                    "detail": format!("event envelope re-encode failed: {error}"),
                }));
                continue;
            }
        };
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        match submit_event_value(state, session, envelope).await {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
            }
            Err(error) => rejected.push(json!({
                "id": id,
                "reason_code": error.code,
                "detail": error.message,
            })),
        }
    }

    let status = if !rejected.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    res.render(Json(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        Some(super::super::sync::sync_token_for_state(state).await),
    )));
}

pub(crate) async fn submit_federation_events(
    state: &AppState,
    req: &Request,
    body: EventsSubmitFederationRequestBody,
    res: &mut Response,
) {
    let body_value = match serde_json::to_value(&body) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("invalid ck.peer.events.command.submit shape: {error}"),
            );
            return;
        }
    };

    let trust_headers =
        match crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(
            req,
        ) {
            Ok(headers) => headers,
            Err(violation) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    violation.error_code(),
                    &violation.message(),
                );
                return;
            }
        };
    let expected_destination = match TypedTrustDomainId::new(state.config.trust_domain.clone()) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "configured trust_domain failed typed validation");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "service trust_domain is invalid",
            );
            return;
        }
    };
    if trust_headers
        .verify_destination(&expected_destination)
        .is_err()
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "federation Destination-Trust-Domain header does not match this service",
        );
        return;
    }
    let request_hash = match canonical::canonical_sha256(&body_value) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("ck.peer.events.command.submit body is not canonical-hashable: {error}"),
            );
            return;
        }
    };
    if request_hash != trust_headers.request_canonical_digest.as_str() {
        crate::metrics::record_digest_mismatch("events_federation_request_binding");
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "Request-Canonical-Digest does not match the canonical request body",
        );
        return;
    }

    let submit = body;
    if let Err((code, message)) =
        SolandEventsSubmitRequestBody::validate_federation_binding(&submit)
    {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    if submit.events.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "ck.peer.events.command.submit must contain at least one event",
        );
        return;
    }
    if submit.events.len() > MAX_EVENT_SUBMIT_BATCH {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ck.peer.events.command.submit exceeds max batch size",
        );
        return;
    }

    let binding_realm = submit.service_binding_ref.realm_id.as_str().to_owned();
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let created_at = now();
    let source_trust_domain = trust_headers.source_trust_domain.as_str().to_owned();

    for envelope in submit.events {
        let envelope = match serde_json::to_value(envelope) {
            Ok(value) => value,
            Err(error) => {
                rejected.push(json!({
                    "id": "unknown",
                    "reason_code": "bad_json",
                    "detail": format!("event envelope re-encode failed: {error}"),
                }));
                continue;
            }
        };
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let event_realm = event_string_field_from_value(&envelope, "realm_id");
        if event_realm.as_deref() != Some(binding_realm.as_str()) {
            rejected.push(json!({
                "id": id,
                "reason_code": "schema_violation",
                "detail": "event realm_id must match service_binding_ref.realm_id",
            }));
            continue;
        }
        let Some(actor) = event_string_field_from_value(&envelope, "actor_id") else {
            rejected.push(json!({
                "id": id,
                "reason_code": "missing_param",
                "detail": "actor_id is required",
            }));
            continue;
        };
        if validate_did(&actor).is_err() {
            rejected.push(json!({
                "id": id,
                "reason_code": "invalid_param",
                "detail": "actor_id must be a DID",
            }));
            continue;
        }
        // SOL-02-007 — bind the envelope actor to the asserted source trust
        // domain BEFORE constructing a session, instead of leaving author
        // identity entirely to the downstream proof chain. Two acceptance
        // paths:
        //   1. the actor's home trust domain (derived from its DID host, same derivation as the
        //      service-DID → trust-domain rule) equals the `source-trust-domain` header; or
        //   2. the actor is already a member of the binding Realm in the local membership index
        //      (the source domain is then relaying for a known member; identity is re-verified
        //      downstream by `validate_event_envelope`'s proof checks).
        if !federation_actor_origin_acceptable(state, &actor, &source_trust_domain, &binding_realm)
            .await
        {
            rejected.push(json!({
                "id": id,
                "reason_code": "capability_denied",
                "detail": "actor_id home domain does not match source-trust-domain and the actor is not a known member of the binding realm",
            }));
            continue;
        }
        let device_id = event_string_field_from_value(&envelope, "device_id")
            .unwrap_or_else(|| format!("federation:{source_trust_domain}"));
        let session = SessionRecord {
            token_hash: format!("federation:{source_trust_domain}:{}", request_hash),
            actor,
            device_id,
            audience: state.config.service_did.clone(),
            session_public_key: None,
            expires_at: created_at + Duration::minutes(5),
            created_at,
            revoked_at: None,
        };
        match submit_event_value(state, &session, envelope).await {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
            }
            Err(error) => rejected.push(json!({
                "id": id,
                "reason_code": error.code,
                "detail": error.message,
            })),
        }
    }

    let status = if !rejected.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    let status_label = events_submit_status_label(status);
    append_audit_log(
        state,
        None,
        "peer.events.submit",
        json!({
            "realm_id": binding_realm,
            "source_trust_domain": source_trust_domain,
            "request_canonical_digest": request_hash,
            "accepted": accepted,
            "duplicate": duplicate,
            "rejected_count": rejected.len()
        }),
        status_label,
    )
    .await;
    res.render(Json(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        Some(super::super::sync::sync_token_for_state(state).await),
    )));
}

pub(super) fn event_string_field_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| event_string_field(object, &[field]))
}

/// SOL-02-007 — federation actor↔source binding. Accept the envelope actor
/// when its derived home trust domain equals the asserted
/// `source-trust-domain`, or when the actor is already present in the local
/// membership index of the binding Realm (the source domain relays for a
/// known member; proofs are still verified downstream).
async fn federation_actor_origin_acceptable(
    state: &AppState,
    actor: &str,
    source_trust_domain: &str,
    binding_realm: &str,
) -> bool {
    let actor_home_domain =
        crate::routing::federation::federation::trust_domain_from_service_did(actor);
    if actor_home_domain == source_trust_domain {
        return true;
    }
    realm_has_member(state, binding_realm, actor).await
}

fn events_submit_status_label(status: EventsSubmitStatus) -> &'static str {
    match status {
        EventsSubmitStatus::Accepted => "accepted",
        EventsSubmitStatus::Duplicate => "duplicate",
        EventsSubmitStatus::Partial => "partial",
        EventsSubmitStatus::HistoricalOnly => "historical_only",
    }
}

pub(super) fn events_submit_outcome(
    status: EventsSubmitStatus,
    accepted: Vec<String>,
    duplicate: Vec<String>,
    rejected: Vec<Value>,
    cursor: Option<String>,
) -> EventsSubmitOutcome {
    EventsSubmitOutcome {
        status,
        accepted: accepted
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        duplicate: duplicate
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        rejected,
        quarantine: Vec::new(),
        actor_frontier: Value::Null,
        realm_frontier: Value::Null,
        cursor,
        original_outcome: None,
    }
}

pub(in crate::routing) async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    mut envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            "event envelope cannot be encoded",
        )
    })?;
    if raw_bytes.len() > MAX_EVENT_BYTES {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "event envelope exceeds max_event_bytes",
        ));
    }

    let parsed = validate_event_envelope(state, session, &envelope).await?;
    let received_at = now();
    let store = state.persistence.events();
    if let Ok(Some(existing)) = store.get(&parsed.event_id).await {
        if existing.canonical_bytes == parsed.canonical_bytes {
            return Ok(event_submit_response(
                state,
                EventsSubmitStatus::Duplicate,
                existing.event_id.clone(),
            )
            .await);
        }
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "reason": "duplicate_conflict",
                "canonical_digest": parsed.canonical_digest
            }),
            "duplicate_conflict",
        )
        .await;
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "event_id already exists with different canonical bytes",
        ));
    }
    if let Ok(Some(max_seq)) = store.max_actor_seq(&parsed.actor_id).await
        && parsed.actor_seq <= max_seq
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq must be strictly increasing for the actor",
        ));
    }
    for prev_ref in &parsed.prev_refs {
        if !store.contains(prev_ref).await.unwrap_or(false) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        }
    }
    for authorized_ref in &parsed.authorized_refs {
        if !store.contains(authorized_ref).await.unwrap_or(false) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "refs[role=authorized_by] must reference accepted authorization events",
            ));
        }
    }

    let projection_operation = projection_operation_from_event(&parsed, &envelope);
    tracing::debug!(
        event_id = %parsed.event_id,
        kind = %parsed.kind,
        realm_id = %parsed.realm_id,
        has_projection = projection_operation.is_some(),
        "submit_event"
    );
    let mut strand_status_audit_payload = None;
    if let Some(operation) = projection_operation.as_ref() {
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(operation)) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                message,
            ));
        }
        if let Err(reason) =
            validate_content_encryption_floor(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // CKP-0016 — reject agent_participation ceiling writes that widen
        // the parent scope's ceiling (tighten-only invariant).
        if let Err(reason) =
            validate_agent_participation_ceiling(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // CKP-0016 §5.2 — a native personal agent may only author messages
        // where its effective participation `reply` bit is true. Per
        // 0016-agent-participation-policy.md §6: an agent with no effective
        // reply grant for the scope is rejected `failed_precondition` (the
        // missing materialised `ck.message.create` grant is a precondition,
        // not an authorization-context denial).
        if let Err(reason) =
            validate_agent_reply_participation(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(operation)).await
        {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            return Err(SubmitOneError::new(status, code, message));
        }
        if let Err(rejection) = policy_gate::enforce_operation_policy_server(
            state,
            &parsed.actor_id,
            operation,
            PolicyGateSurface::LocalSubmit,
        )
        .await
        {
            return Err(SubmitOneError::new(
                rejection.status,
                rejection.code,
                rejection.message,
            ));
        }
        {
            // Admission checks below are mandatory and MUST NOT be skipped
            // (fail-closed). The projection lock is the poison-free
            // `state::Mutex`, so acquiring it cannot fail and this block
            // always runs.
            let proj = state.projection.lock().expect("projection lock");
            if let Err(reason) = proj.check_space_container_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_status_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            strand_status_audit_payload =
                proj.strand_status_transition_audit_payload(operation, &parsed.actor_id);
            if let Err(reason) = proj.check_morph_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_redaction_target_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_tracks_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_bottom_cell_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_membership_join_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // relation.md §4 — structural contains/belongs_to MUST stay within a
            // single Realm; reject cross-Realm structural relations at ingest.
            if let Err(reason) = proj.check_relation_cross_realm(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_child_scope_policy_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // capabilities.md §10.2 — a ck.capability.delegate that closes a
            // delegation cycle MUST be rejected before it projects.
            if let Err(reason) = proj.check_delegation_cycle(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Some(reason) = preflight_mls_projection_reject(&proj, operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            // P2 — moderation §5.5.2 reducer constraints (separation of
            // duties, overturn↔lift, modify↔new-decision) fail-closed at
            // ingest. The clone sees cells already advanced by earlier
            // in-batch decision / lift submits, so the atomicity checks
            // resolve against the live moderation_state cell.
            if let Some(reason) =
                preflight_moderation_projection_reject(&proj, operation, &state.hlc)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
        }
    }

    // SEC-04 — receiver-side independent 24h inception-key online-window cap
    // (`identity/key-management.md` §5.0.1 step 5). When an inception-bootstrap
    // self-authorization (`ck.device.authorize` / `ck.session.grant` carrying a
    // `refs[role=did_inception]` evidence ref) is signed by the inception key,
    // the receiver MUST seal on the verifiable bootstrap timestamp
    // (`did:webvh` entry-0 `versionTime`) and reject the event when the
    // inception key age exceeds the 24h protocol hard cap — regardless of any
    // longer window the deployment self-reports. Runs against the full envelope
    // because the `did_inception` evidence ref lives on the envelope `refs[]`,
    // not on the projection operation payload.
    enforce_inception_key_online_window(state, &parsed, &envelope).await?;

    // SPEC-SOL-003 follow-through — an accepted durable `ck.device.revoke`
    // is the canonical revocation trigger (device-lifecycle.md §2.2).
    // Validate the revocation against the submitting session, then flip the
    // device record the auth gate reads BEFORE persisting the event: a
    // failed flip rejects the submission (no event-without-enforcement),
    // while a flipped record with a failed persist only over-revokes — the
    // safe direction, the peer device can resubmit.
    if parsed.kind == "ck.device.revoke" {
        let target_device_id = validate_device_revoke_submission(session, &parsed, &envelope)?;
        crate::routing::identity::auth::revoke_device_record(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device revocation enforcement failed: {error}"),
            )
        })?;
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "device.revoke",
            json!({
                "revoked_device_id": target_device_id,
                "by_device_id": session.device_id.clone(),
                "via": "ck.device.revoke",
                "event_id": parsed.event_id.clone(),
            }),
            "accepted",
        )
        .await;
    }

    // CKP-0007: stamp the authoritative top-level `effective_scope` onto the
    // stored envelope so read-path visibility gating
    // (`effective_scope_for_envelope` → `circle_event_visible_to_session`)
    // hides circle-scoped activity from realm members outside the Circle.
    //
    // Create events carry `scope_circle_id` in `payload.object` and the reader
    // extracts it directly, so they need no stamp. But events whose payload
    // does NOT carry the scope — a message (scope is a Strand field, never on
    // the message) and Strand update / lifecycle (scope is create-locked, not
    // re-sent) — would otherwise resolve to no scope and leak to non-members.
    // Resolve the authoritative Strand scope from the durable projection
    // (projection_strands.scope_circle_id survives restart) and stamp it.
    let scope_strand_id: Option<String> = envelope
        .get("payload")
        .and_then(|payload| match parsed.kind.as_str() {
            kinds::CK_MESSAGE_CREATE | kinds::CK_STRAND_UPDATE => {
                payload.get("strand_id").and_then(Value::as_str)
            }
            kinds::CK_STRAND_ARCHIVE
            | kinds::CK_STRAND_RESTORE
            | kinds::CK_STRAND_MOVE
            | kinds::CK_STRAND_REORDER => payload
                .get("target_ref")
                .or_else(|| payload.get("strand_id"))
                .and_then(Value::as_str),
            _ => None,
        })
        .map(ToOwned::to_owned);
    if let Some(scope_strand_id) = scope_strand_id {
        let scope = state
            .projection
            .lock()
            .ok()
            .and_then(|proj| proj.strand_scope_circle_id(&scope_strand_id));
        if let Some(scope) = scope
            && let Some(object) = envelope.as_object_mut()
        {
            object.insert("effective_scope".to_owned(), Value::String(scope));
        }
    }

    let envelope_for_bootstrap = envelope.clone();
    if let Err(error) = store
        .put(CanonicalEventRecord {
            event_id: parsed.event_id.clone(),
            actor_id: parsed.actor_id.clone(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.clone()),
            kind: parsed.kind.clone(),
            schema_id: parsed.schema_id.clone(),
            canonical_digest: parsed.canonical_digest.clone(),
            canonical_bytes: parsed.canonical_bytes.clone(),
            envelope,
            received_at,
        })
        .await
    {
        tracing::error!(%error, "failed to persist canonical event");
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "events store unavailable",
        ));
    }
    if let Some(operation) = projection_operation {
        super::super::projection::project_accepted_operations_from_device(
            state,
            &parsed.actor_id,
            &parsed.device_id,
            &[operation],
        )
        .await;
    }
    if !session.token_hash.starts_with("federation:") {
        enqueue_peer_event_fanout(state, &parsed, &envelope_for_bootstrap).await;
    }
    if let Some(payload) = strand_status_audit_payload {
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "incident.status.transition",
            payload,
            "accepted",
        )
        .await;
    }
    if parsed.kind == "ck.realm.create"
        && let Some(envelope_object) = envelope_for_bootstrap.as_object()
    {
        bootstrap_realm_member_index(state, &parsed.realm_id, &parsed.actor_id, envelope_object)
            .await;
        organizations::record_realm_organizations_from_event(
            state,
            &parsed.realm_id,
            &envelope_for_bootstrap,
        );
    }
    append_encrypted_message_franking(state, &parsed, &envelope_for_bootstrap).await;
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    )
    .await;
    Ok(event_submit_response(state, EventsSubmitStatus::Accepted, parsed.event_id).await)
}

async fn enqueue_peer_event_fanout(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    let peers = configured_peer_event_targets(state);
    if peers.is_empty() {
        return;
    }
    let event_id = parsed.event_id.as_str();
    let binding_payload = json!({
        "domain": "ck.peer.events.command.submit.service_binding.v1",
        "realm_id": parsed.realm_id,
        "event_id": event_id,
        "canonical_digest": parsed.canonical_digest,
    });
    let service_binding_ref = match (
        RealmId::new(parsed.realm_id.clone()),
        Hash::new(canonical_json_hash(&binding_payload)),
        EventId::new(event_id.to_owned()),
        Hash::new(cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST.to_owned()),
    ) {
        (Ok(realm_id), Ok(realm_policy_digest), Ok(event_id), Ok(reducer_profile_digest)) => {
            cokret_sdk::FederationServiceBindingRef {
                realm_id,
                realm_policy_digest,
                membership_frontier: vec![event_id.clone()],
                delivery_binding_frontier: vec![event_id],
                destination_service_type: "principal_server".to_owned(),
                reducer_profile_digest,
            }
        }
        _ => {
            tracing::warn!(
                event_id,
                "failed to build typed ck.peer.events.command.submit service binding"
            );
            return;
        }
    };
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(state.config.service_did.as_bytes());
    hasher_input.extend_from_slice(b"|");
    hasher_input.extend_from_slice(event_id.as_bytes());
    hasher_input.extend_from_slice(b"|");
    hasher_input.extend_from_slice(parsed.canonical_digest.as_bytes());
    let idempotency_key = format!("ck:outbox:event:{}", sha256_hex(&hasher_input));
    let event = match serde_json::from_value::<Event>(envelope.clone()) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(
                %error,
                event_id,
                "failed to type checked peer fanout event envelope"
            );
            return;
        }
    };
    let body = EventsSubmitFederationRequestBody {
        service_binding_ref,
        events: vec![event],
        idempotency_key: Some(idempotency_key.clone()),
    };
    let payload = match canonical::canonical_json_bytes(&body)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(payload) => payload,
        None => {
            tracing::warn!(
                event_id,
                "failed to encode ck.peer.events.command.submit body"
            );
            return;
        }
    };
    for (peer_url, peer_did) in peers {
        if peer_did == state.config.service_did {
            continue;
        }
        if let Err(error) = crate::routing::federation::outbox::enqueue_outbound(
            state,
            peer_url.as_str(),
            peer_did.as_str(),
            "/_cokret/peer/events",
            &idempotency_key,
            &payload,
        )
        .await
        {
            tracing::warn!(
                %error,
                event_id,
                peer = %peer_url,
                peer_did = %peer_did,
                "failed to enqueue ck.peer.events.command.submit fanout"
            );
        }
    }
}

fn configured_peer_event_targets(state: &AppState) -> Vec<(String, String)> {
    let entries = match state.config.federation_policy {
        crate::config::FederationPolicy::Mesh => state.config.federation_peers.clone(),
        crate::config::FederationPolicy::Hub => state
            .config
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    entries
        .into_iter()
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let (url, did) = trimmed.split_once('|')?;
            let url = url.trim().trim_end_matches('/').to_owned();
            let did = did.trim().to_owned();
            if url.is_empty() || validate_did(&did).is_err() {
                None
            } else {
                Some((url, did))
            }
        })
        .collect()
}
