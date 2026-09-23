use super::*;

/// The named admission context of one Event submit.
///
/// Everything here participates in admission judgement. Commit-only data
/// (idempotency records, contact projections, extra deliveries) is not
/// admission context; it travels inside [`SubmitMode::Commit`] so a
/// prepare-only admission cannot silently carry commit effects.
pub(super) struct SubmitEventContext<'a> {
    pub(super) publication_event: Option<&'a Event>,
    pub(super) realm_bootstrap_contexts: &'a [RealmBootstrapBatchContext],
    /// The pre-derived Operations of the whole submit batch this Event
    /// belongs to (`sdk_projection::projection_operation_from_envelope`).
    /// Empty outside a batch surface, where the lane falls back to the
    /// Event's own Operation. Batch-aware policy validators scan this slice
    /// for sibling writes (`operations::policy_extra`).
    pub(super) batch_operations: &'a [arkret_event_draft::ProjectedEventOperation],
    pub(super) internal_admission: Option<&'a InternalEventAdmission>,
    pub(super) federation_source_id: Option<&'a str>,
    pub(super) membership_compensation_evidence:
        Option<&'a arkret_wire::MembershipCompensationSubmissionEvidence>,
}

impl SubmitEventContext<'_> {
    /// The ordinary single-Event context: no bootstrap batch, no internal
    /// admission substitution, no publication evidence.
    pub(super) fn empty() -> Self {
        Self {
            publication_event: None,
            realm_bootstrap_contexts: &[],
            batch_operations: &[],
            internal_admission: None,
            federation_source_id: None,
            membership_compensation_evidence: None,
        }
    }
}

/// Marker that the atomic `pair_device` admission gate verified this
/// submission.
///
/// The gate is what entitles an `ak.device.authorize` Event to declare the
/// `accepted_device` authorization binding, so the marker doubles as the
/// admission input for that payload class. The paired commit authorization is
/// commit data: it is present exactly when the pair request named a
/// `device_pairing_request_id` to close out.
pub(in crate::routing) struct DevicePairingAdmission {
    pub(in crate::routing) commit_authorization:
        Option<soland_services::events::CommitDevicePairingAuthorization>,
}

/// The one idempotency record a commit may persist. Two idempotency sources
/// on one commit were only ever a caller bug; the enum makes that state
/// unrepresentable instead of a runtime rejection.
pub(super) enum SubmitCommitIdempotency {
    /// A fully built response record from a two-phase commit surface.
    Prepared(soland_services::events::IdempotentResponse),
}

/// Commit-only data for an immediate commit. None of it participates in
/// admission judgement; it lands on the commit command / response.
pub(super) struct SubmitCommitOptions<'a> {
    pub(super) idempotency: Option<SubmitCommitIdempotency>,
    pub(super) device_pairing: Option<&'a DevicePairingAdmission>,
    pub(super) contact_completion_draft: Option<&'a soland_storage::ContactCompletionDraft>,
    pub(super) contact_projection: Option<&'a soland_services::events::CommitContactProjection>,
    pub(super) additional_deliveries: &'a [soland_services::federation::FederationDeliveryRecord],
}

impl SubmitCommitOptions<'_> {
    pub(super) fn none() -> Self {
        Self {
            idempotency: None,
            device_pairing: None,
            contact_projection: None,
            contact_completion_draft: None,
            additional_deliveries: &[],
        }
    }
}

/// Legacy internal admission mode while callers migrate to guarded authority
/// transactions. Every path through this mode currently refuses writes.
pub(super) enum SubmitMode<'a> {
    Commit(Box<SubmitCommitOptions<'a>>),
    /// Admit an internally-authored Event through the ordinary canonical
    /// lane, but return its commit command to a larger atomic aggregate.
    PrepareInternal(&'a mut Option<soland_services::events::CommitAcceptedEventCommand>),
}

/// Classify a failed origin-selector derivation on the origin Station's own `/_arkret/self/*` write
/// path.
///
/// The derivation-domain section of `device-lifecycle.md` separates this surface from
/// the peer gate: locally the write MUST fail closed with `device_unauthorized`
/// *before* the revocation record is consulted and before any business effect
/// lands, rather than answering with a signed anti-enumeration receipt. A row
/// that claims verified / current while omitting its schema-required
/// authorization Event id or generation ref is instead a projection integrity
/// failure, which surfaces as an internal availability fault and never as an
/// authorization answer.
pub(super) fn local_device_authorization_error(
    error: soland_services::ServiceError,
) -> SubmitOneError {
    let (status, code) = if error.is_not_found() {
        (StatusCode::FORBIDDEN, "device_unauthorized")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    };
    SubmitOneError::new(
        status,
        code,
        format!("Event author device authorization unavailable: {error}"),
    )
}

pub(super) fn typed_event_to_canonical_value(envelope: Event) -> Result<Value, SubmitOneError> {
    serde_json::to_value(envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "json_invalid",
            format!("event envelope re-encode failed: {error}"),
        )
    })
}

pub(in crate::routing) async fn submit_event_value(
    _state: &AppState,
    _session: &SessionRecord,
    envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let event: Event = serde_json::from_value(envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            error.to_string(),
        )
    })?;
    arkret_schema::validate_event_for_submit(&event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            error.to_string(),
        )
    })?;
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "internal Event authoring awaits guarded Event/RealmCommit admission",
    ))
}
/// Internal compatibility boundary for one current Event admission submission.
/// The public self route uses the authority protocol directly; internal callers
/// must wait for the guarded Event/RealmCommit/current-effects unit of work.
pub(in crate::routing) async fn submit_initial_event_submission(
    _state: &AppState,
    _session: &SessionRecord,
    submission: arkret_wire::EventAdmissionSubmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submission.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid Event admission submission: {error}"),
        )
    })?;
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "internal Event submission awaits guarded Event/RealmCommit unit of work",
    ))
}

pub(in crate::routing) async fn submit_initial_event_submission_with_device_pairing(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventAdmissionSubmission,
    _device_pairing: DevicePairingAdmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_initial_event_submission(state, session, submission).await
}

pub(in crate::routing) async fn submit_initial_event_submission_with_contact_projection(
    _state: &AppState,
    _session: &SessionRecord,
    submission: arkret_wire::EventAdmissionSubmission,
    _contact_projection: soland_services::events::CommitContactProjection,
    _completion_draft: soland_storage::ContactCompletionDraft,
    _deliveries: Vec<soland_services::federation::FederationDeliveryRecord>,
    _idempotency: Option<soland_services::events::IdempotentResponse>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submission.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid Contact Event submission: {error}"),
        )
    })?;
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Contact atomic Event/RealmCommit admission is unavailable",
    ))
}
pub(in crate::routing) async fn submit_account_data_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    owner: &arkret_wire::ActorId,
    key: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    // The admission actor is the holder, not this service. `ak.account_data.set`'s
    // actor-private cell subject is composite[envelope.actor_id, payload.key], so an
    // Event admitted under the service DID would land every holder's value for one
    // key in a single cell keyed by the service, sharing one server_revision_cas
    // counter. The admission still only substitutes for the ordinary Realm-membership
    // check; schema, proof, actor-lock and reducer admission all still run.
    let admission = InternalEventAdmission::account_data(
        realm_id,
        owner.clone(),
        session.device_id.as_str(),
        key,
    );
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(Box::new(SubmitCommitOptions::none())),
    )
    .await
}

pub(in crate::routing) async fn prepare_service_franking_proof_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    target_event_id: &str,
) -> Result<soland_services::events::CommitAcceptedEventCommand, SubmitOneError> {
    let admission = InternalEventAdmission::service_franking_proof(
        realm_id,
        arkret_wire::ActorId::service(state.service_core_id().clone()),
        target_event_id,
    );
    let mut prepared = None;
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            ..SubmitEventContext::empty()
        },
        SubmitMode::PrepareInternal(&mut prepared),
    )
    .await?;
    prepared.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "franking proof preparation encountered an already accepted Event",
        )
    })
}

/// Attach the STORED ingress receipt to a submit outcome.
///
/// `offline-publication.md` §2.1 requires the receipt this service persisted for
/// the digest to come back on every response for that digest, including an
/// idempotent duplicate — byte-identically, never re-stamped.
pub(super) fn exact_producer_retry(existing_bytes: &[u8], submitted: &Event) -> bool {
    let Ok(existing) = serde_json::from_slice::<arkret_wire::Event>(existing_bytes) else {
        return false;
    };
    if submitted.producer_proof.is_none() {
        return false;
    }
    existing == *submitted
}

pub(super) fn moderation_franking_replay_nonce(
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
    consumed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<soland_storage::FrankingReplayNonceCommit>, SubmitOneError> {
    if parsed.kind != arkret_wire::EventKind::SelfModerationReport.as_str() {
        return Ok(None);
    }
    let payload = envelope.get("payload").cloned().ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "moderation report Event has no payload",
        )
    })?;
    let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(payload).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("moderation report payload is invalid: {error}"),
            )
        })?;
    Ok(payload
        .franking_proof
        .map(|proof| soland_storage::FrankingReplayNonceCommit {
            realm_id: parsed.realm_id.to_string(),
            received_by: proof.received_by,
            replay_nonce: proof.replay_nonce,
            report_event_id: parsed.event_id.to_string(),
            consumed_at,
        }))
}

fn membership_compensation_signature_bytes<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, SubmitOneError> {
    let mut value = serde_json::to_value(value).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("membership compensation evidence cannot be encoded: {error}"),
        )
    })?;
    value
        .as_object_mut()
        .and_then(|object| object.remove("signature"))
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "membership compensation signed object is missing signature",
            )
        })?;
    arkret_canonical::canonical_json_bytes(&value).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("membership compensation transcript is not canonicalizable: {error}"),
        )
    })
}

async fn verify_membership_compensation_signature<T: serde::Serialize>(
    state: &AppState,
    value: &T,
    signature: &arkret_wire::ProtocolSignature,
    issuer_id: &arkret_wire::DidCoreId,
    label: &str,
) -> Result<(), SubmitOneError> {
    let bytes = membership_compensation_signature_bytes(value)?;
    crate::jws_verify::verify_did_controlled_ed25519_signature_async(
        &bytes,
        signature.jws.as_str(),
        signature.verification_method.as_str(),
        issuer_id.as_str(),
        state,
    )
    .await
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            format!("{label} signature is invalid: {error}"),
        )
    })
}

pub(in crate::routing::events::event_log) async fn validate_membership_compensation_live_state(
    state: &AppState,
    event: &Event,
    evidence: &arkret_wire::MembershipCompensationSubmissionEvidence,
) -> Result<(), SubmitOneError> {
    evidence.validate_for_event(event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            format!("membership compensation evidence is invalid: {error}"),
        )
    })?;
    let core = &evidence.delegation.core;
    let producer_method = event
        .producer_proof
        .as_ref()
        .map(|proof| &proof.verification_method);
    if producer_method != Some(&core.executor_proof_key_kid)
        || evidence.delegation.signature.verification_method != core.verification_method
        || evidence.terminal_certificate.issuer_id != *core.executor_id.signing_principal_id()
        || evidence.single_use_cas_token.issuer_id != *core.executor_id.signing_principal_id()
        || evidence.join_accepted_proof.accepted_at > evidence.terminal_certificate.certified_at
        || evidence.terminal_certificate.certified_at > event.created_at
        || evidence.single_use_cas_token.issued_at > event.created_at
        || event.created_at >= evidence.single_use_cas_token.expires_at
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation signer or canonical time binding is invalid",
        ));
    }
    verify_membership_compensation_signature(
        state,
        &evidence.delegation,
        &evidence.delegation.signature,
        core.join_actor_id.signing_principal_id(),
        "delegation",
    )
    .await?;
    verify_membership_compensation_signature(
        state,
        &evidence.join_accepted_proof,
        &evidence.join_accepted_proof.signature,
        &evidence.join_accepted_proof.issuer_id,
        "join accepted proof",
    )
    .await?;
    verify_membership_compensation_signature(
        state,
        &evidence.terminal_certificate,
        &evidence.terminal_certificate.signature,
        &evidence.terminal_certificate.issuer_id,
        "terminal certificate",
    )
    .await?;
    verify_membership_compensation_signature(
        state,
        &evidence.single_use_cas_token,
        &evidence.single_use_cas_token.signature,
        &evidence.single_use_cas_token.issuer_id,
        "single-use CAS token",
    )
    .await?;

    let accepted_join = state
        .event_queries()
        .canonical_event(core.join_event_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("membership compensation join lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "membership compensation join Event is unavailable",
            )
        })?;
    let accepted_join_event =
        serde_json::from_value::<Event>(accepted_join.envelope).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored membership compensation join Event is invalid: {error}"),
            )
        })?;
    let join_producer_method = accepted_join_event
        .producer_proof
        .as_ref()
        .map(|proof| &proof.verification_method);
    if accepted_join_event.kind != arkret_wire::EventKind::MemberState
        || accepted_join_event.realm_id != core.resource_id
        || evidence.join_accepted_proof.issuer_id
            != *accepted_join_event.actor_id.route_service_id()
        || accepted_join_event.actor_id != core.join_actor_id
        || accepted_join_event.executed_by != core.executed_by
        || accepted_join_event.authorization_ref != core.authorization_ref
        || join_producer_method != Some(&core.verification_method)
        || serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(serde_json::to_value(&accepted_join_event.payload).unwrap_or(Value::Null))
        .map(|payload| payload.member_id)
        .ok()
            != Some(core.member_id.clone())
        || accepted_join_event
            .payload
            .get("membership")
            .and_then(Value::as_str)
            != Some("join")
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation does not bind the accepted join provenance",
        ));
    }
    let current_membership = state
        .projections()
        .snapshot()
        .member(core.resource_id.as_str(), &core.member_id.to_string())
        .cloned();
    let Some(current_membership) = current_membership else {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation target is already absent",
        ));
    };
    if current_membership.state != "join"
        || current_membership.membership_event_ref.as_deref() != Some(core.join_event_id.as_str())
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation target was superseded by another membership incarnation",
        ));
    }
    Ok(())
}

pub(super) async fn submit_event_value_with_context(
    _state: &AppState,
    _session: &SessionRecord,
    envelope: Value,
    _context: SubmitEventContext<'_>,
    _mode: SubmitMode<'_>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let event: Event = serde_json::from_value(envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid Event: {error}"),
        )
    })?;
    arkret_schema::validate_event_for_submit(&event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid Event: {error}"),
        )
    })?;
    // The legacy Cell/Seal path cannot commit an Event, RealmCommit, current
    // effects and delivery intents in one guarded authority transaction.
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "legacy Event submit awaits guarded Event/RealmCommit unit of work",
    ))
}
pub(super) async fn preflight_moderation_dismiss(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), SubmitOneError> {
    if operation.event_kind != arkret_wire::EventKind::ModerationDecision
        || operation.payload.get("decision").and_then(Value::as_str) != Some("dismiss")
    {
        return Ok(());
    }
    let target_ref = operation
        .payload
        .get("target_ref")
        .and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("id").and_then(Value::as_str))
        })
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "moderation_dismiss_requires_report_event",
            )
        })?;
    let report = state
        .event_queries()
        .canonical_event(target_ref)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("moderation report target lookup failed: {error}"),
            )
        })?;
    if report.as_ref().is_none_or(|report| {
        report.kind != arkret_wire::EventKind::SelfModerationReport.as_str()
            || report.realm_id.as_deref() != Some(operation.realm_id.as_str())
    }) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "moderation_dismiss_requires_report_event",
        ));
    }
    Ok(())
}

pub(super) async fn resolve_moderation_dismiss_queue_item(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
    decision_event_id: &str,
) {
    if operation.event_kind != arkret_wire::EventKind::ModerationDecision
        || operation.payload.get("decision").and_then(Value::as_str) != Some("dismiss")
    {
        return;
    }
    let Some(target_ref) = operation.payload.get("target_ref").and_then(|value| {
        value
            .as_str()
            .or_else(|| value.get("id").and_then(Value::as_str))
    }) else {
        return;
    };
    let Ok(item) = state
        .governance()
        .submitted_moderation_queue_item_for_report_event(target_ref)
        .await
    else {
        tracing::warn!(target_ref, "moderation queue lookup failed after dismiss");
        return;
    };
    let Some(mut item) = item else {
        return;
    };
    if let Some(object) = item.as_object_mut() {
        object.insert("status".to_owned(), Value::String("resolved".to_owned()));
        object.insert(
            "resolution".to_owned(),
            json!({
                "decision": "dismiss",
                "effective_verdict": "none",
                "decision_event_id": decision_event_id,
            }),
        );
        object.insert("resolved_at".to_owned(), json!(now()));
    }
    if let Err(error) = state.governance().upsert_moderation_queue_item(item).await {
        tracing::warn!(%error, target_ref, "moderation queue dismiss projection failed");
    }
}

pub(super) async fn preflight_account_data_cas(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<Option<soland_services::events::CommitAccountDataCas>, SubmitOneError> {
    let (key, expected_revision, revision, payload, tombstone, updated_at) = match operation
        .event_kind
    {
        arkret_wire::EventKind::AccountDataSet => {
            let typed = operation
                .typed_payload::<arkret_wire::event_spec::AccountDataSet>()
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        format!("account_data payload violates its typed SDK contract: {error}"),
                    )
                })?;
            let expected_revision = typed.expected_server_revision;
            let revision = expected_revision.checked_add(1).ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "cas_conflict",
                    "account data revision high-water mark is exhausted",
                )
            })?;
            let value = if typed.tombstone {
                Value::Null
            } else {
                operation
                    .payload
                    .get("body")
                    .or_else(|| operation.payload.get("encrypted_payload"))
                    .cloned()
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::BAD_REQUEST,
                            "schema_violation",
                            "account_data payload has no value",
                        )
                    })?
            };
            (
                typed.key.as_str().to_owned(),
                expected_revision,
                revision,
                value,
                typed.tombstone,
                typed.updated_at.unwrap_or(operation.created_at),
            )
        }
        arkret_wire::EventKind::AccountBlocklist => {
            let typed = operation
                .typed_payload::<arkret_wire::event_spec::AccountBlocklist>()
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        format!(
                            "account blocklist payload violates its typed SDK contract: {error}"
                        ),
                    )
                })?;
            let expected_revision = typed.version.checked_sub(1).ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "account blocklist version must be at least 1",
                )
            })?;
            (
                arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST.to_owned(),
                expected_revision,
                typed.version,
                operation.payload.clone(),
                typed.entries.is_empty(),
                typed.updated_at.unwrap_or(operation.created_at),
            )
        }
        _ => return Ok(None),
    };
    let Some(account_id) = operation.context.sender.as_account_id() else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "policy_violation",
            "actor-private account data requires an account actor",
        ));
    };
    if account_id.station_id != state.service_core_id() {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "policy_violation",
            "actor-private account data belongs to the actor's selected Account Station",
        ));
    }
    let owner = operation.context.sender.to_string();
    let current = state
        .account_data()
        .entry(&owner, &key)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("account_data state lookup failed: {error}"),
            )
        })?;
    let current_revision = current.as_ref().map_or(0, |record| record.revision);
    if current_revision == expected_revision {
        return Ok(Some(soland_services::events::CommitAccountDataCas {
            record: soland_services::identity::AccountDataState {
                actor_id: owner,
                account_data_key: key,
                revision,
                payload,
                tombstone,
                updated_at,
            },
            expected_revision,
            conflict_code: "cas_conflict".to_owned(),
        }));
    }

    let mut details = json!({
        "account_data_key": key,
        "current_revision": current_revision,
    });
    if let Some(record) = current.filter(|record| !record.tombstone) {
        details["current_entry"] = json!({
            "account_data_key": record.account_data_key,
            "revision": record.revision,
            "content": record.payload,
            "updated_at": arkret_canonical::format_timestamp_canonical(record.updated_at),
        });
    }
    Err(SubmitOneError::new(
        StatusCode::CONFLICT,
        "cas_conflict",
        "expected_revision does not match current account data revision",
    )
    .with_details(details))
}

/// client-sync.md 8.1: the optional `expected_state_digest` on
/// `ak.member.identity.update` is an optimistic-concurrency guard over the
/// current effective-set digest for the same `(realm_id, member_id, segment)`.
/// A mismatch MUST reject the Event rather than apply it as a valid
/// replacement, so the guard runs at admission with zero writes instead of
/// being discovered after acceptance, where dropping the projection would leave
/// an accepted Event that no reader can see.
pub(super) fn preflight_member_identity_state_guard(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), SubmitOneError> {
    if operation.event_kind != arkret_wire::EventKind::MemberIdentityUpdate {
        return Ok(());
    }
    let Some(expected) = operation
        .payload
        .get("expected_state_digest")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let (Some(realm_id), Some(actor_id)) = (
        operation.payload.get("realm_id").and_then(Value::as_str),
        operation
            .payload
            .get("actor_id")
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()),
    ) else {
        // Shape validation owns the missing-carrier case and reports it as a
        // schema violation; the guard has nothing to compare against.
        return Ok(());
    };
    let current = state.member_identity_state_digest(realm_id, &actor_id.to_string());
    match current.as_deref() {
        // No accepted identity event yet: the writer observed the empty set,
        // which no digest can name, so the guard cannot be satisfied.
        None => Ok(()),
        Some(current) if current == expected => Ok(()),
        Some(current) => Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::MEMBER_IDENTITY_STATE_MISMATCH,
            "expected_state_digest does not match the current member identity effective set",
        )
        .with_details(json!({ "current_state_digest": current }))),
    }
}

/// profiles-presence.md section 2.3: an optional
/// `ak.profile.update.payload.expected_state_digest` is the writer-observed
/// digest of the folded Actor Profile current row. The check must happen
/// before the authority transaction so a stale update produces neither an
/// accepted Event nor a projected value. The authority transaction's stream
/// head CAS closes the race between this read and commit: a concurrent winner
/// prevents the loser from committing, and any retry re-enters admission
/// against the new row.
pub(super) async fn preflight_actor_profile_state_guard(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), SubmitOneError> {
    if operation.event_kind != arkret_wire::EventKind::ProfileUpdate {
        return Ok(());
    }
    let Some(expected) = operation
        .payload
        .get("expected_state_digest")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let Some(target_ref) = operation.payload.get("target_ref").and_then(Value::as_str) else {
        // Payload schema validation owns a missing or malformed target_ref.
        return Ok(());
    };
    let current = crate::routing::identity::account::accepted_account_profile(
        state,
        operation.context.sender.signing_principal_id().as_str(),
    )
    .await
    .map_err(SubmitOneError::from_app_error)?
    .filter(|profile| {
        profile
            .id
            .as_ref()
            .is_some_and(|id| id.as_str() == target_ref)
            && profile.realm_id.as_ref() == Some(&operation.realm_id)
    })
    .map(|profile| serde_json::to_value(profile))
    .transpose()
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("materialized Actor Profile cannot be serialized: {error}"),
        )
    })?;
    validate_actor_profile_state_digest(expected, current.as_ref())
}

fn validate_actor_profile_state_digest(
    expected: &str,
    current: Option<&Value>,
) -> Result<(), SubmitOneError> {
    let current = current.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "profile update target has no settled current row",
        )
    })?;
    let current_digest = arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(current).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("materialized Actor Profile cannot be canonicalized: {error}"),
            )
        })?,
    );
    if current_digest == expected {
        return Ok(());
    }
    Err(SubmitOneError::new(
        StatusCode::PRECONDITION_FAILED,
        "failed_precondition",
        "expected_state_digest does not match the current Actor Profile",
    )
    .with_details(json!({ "current_state_digest": current_digest })))
}

#[cfg(test)]
mod actor_profile_state_guard_tests {
    use super::*;

    const PROFILE_ID: &str = "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC";

    fn current_profile() -> Value {
        json!({
            "id": PROFILE_ID,
            "schema": "ak.schema.actor_profile.v1",
            "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            "principal_id": "ak:did_core:web:alice.example",
            "actor_kind": "user",
            "display_name": "Alice",
            "created_at": "2026-09-20T00:00:00.000Z"
        })
    }

    #[test]
    fn stale_profile_digest_is_rejected() {
        let current = current_profile();
        let error = validate_actor_profile_state_digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            Some(&current),
        )
        .expect_err("a stale profile writer must not be admitted");
        let rejection = error
            .rejection()
            .expect("the guard rejects, never quarantines");
        assert_eq!(rejection.wire_code(), "failed_precondition");
        assert_eq!(current["display_name"], "Alice");
    }

    #[test]
    fn observed_profile_digest_is_admitted() {
        let current = current_profile();
        let digest = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&current).unwrap(),
        );
        assert!(validate_actor_profile_state_digest(&digest, Some(&current)).is_ok());
    }

    #[test]
    fn guarded_profile_update_requires_an_existing_settled_row() {
        assert!(
            validate_actor_profile_state_digest(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                None,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod member_identity_state_guard_tests {
    use super::*;

    const GUARD_REALM: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    fn guard_actor() -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            crate::test_event::station_id(),
        ))
    }

    fn guard_state() -> AppState {
        use crate::state::{MemberIdentityEventRecord, MemberIdentitySubjectKey};
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let identity_payload = json!({
            "member_identity": {
                "subject_actor_id": guard_actor(),
                "display_profile": { "display_name": "Alice" }
            }
        });
        let payload_digest = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&identity_payload).unwrap(),
        );
        state.test_insert_member_identity(MemberIdentityEventRecord {
            event_id: "ak:event:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx".to_owned(),
            subject: MemberIdentitySubjectKey {
                realm_id: GUARD_REALM.to_owned(),
                actor_id: guard_actor().to_string(),
                segment: "member_identity".to_owned(),
            },
            payload_digest,
            replaces: Vec::new(),
            raw_event: json!({
                "event_id": "ak:event:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx",
                "payload": {
                    "realm_id": GUARD_REALM,
                    "actor_id": guard_actor(),
                    "segment": "member_identity",
                    "identity_payload": identity_payload,
                }
            }),
        });
        state
    }

    fn guard_operation(expected_state_digest: Option<&str>) -> Operation {
        let mut payload = json!({
            "realm_id": GUARD_REALM,
            "actor_id": guard_actor(),
            "segment": "member_identity",
            "identity_payload": {"member_identity": {"subject_actor_id": guard_actor()}},
        });
        if let Some(digest) = expected_state_digest {
            payload["expected_state_digest"] = json!(digest);
        }
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-00000000000a")
                .unwrap(),
            arkret_wire::RealmId::new(GUARD_REALM).unwrap(),
            arkret_wire::EventKind::MemberIdentityUpdate.as_str(),
            payload,
        )
    }

    #[test]
    fn a_stale_expected_state_digest_is_refused_at_admission() {
        let state = guard_state();
        let error = preflight_member_identity_state_guard(
            &state,
            &guard_operation(Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )),
        )
        .expect_err("a stale writer must not be admitted");
        let rejection = error.rejection().expect("guard rejects, never quarantines");
        assert_eq!(rejection.wire_code(), "failed_precondition");
        assert_eq!(
            rejection.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::MEMBER_IDENTITY_STATE_MISMATCH)
        );
    }

    #[test]
    fn the_observed_effective_set_digest_is_admitted() {
        let state = guard_state();
        let current = state
            .member_identity_state_digest(GUARD_REALM, &guard_actor().to_string())
            .expect("the seeded record has an effective-set digest");
        assert!(
            preflight_member_identity_state_guard(&state, &guard_operation(Some(&current))).is_ok()
        );
    }

    #[test]
    fn an_absent_guard_stays_optional() {
        let state = guard_state();
        assert!(preflight_member_identity_state_guard(&state, &guard_operation(None)).is_ok());
    }
}

#[cfg(test)]
mod account_data_cas_tests {
    use super::*;

    #[tokio::test]
    async fn account_data_cas_preflight_rejects_a_same_principal_foreign_station() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        state
            .account_data()
            .compare_and_set(
                soland_services::identity::AccountDataState {
                    actor_id: local.to_string(),
                    account_data_key: "ak.dnd_schedule".into(),
                    revision: 1,
                    payload: json!({"opaque": "local"}),
                    tombstone: false,
                    updated_at: chrono::Utc::now(),
                },
                0,
            )
            .await
            .unwrap();
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            arkret_wire::EventKind::AccountDataSet.as_str(),
            json!({"key": "ak.dnd_schedule", "expected_server_revision": 1, "tombstone": true}),
        );
        operation.context.sender = local;
        let staged = preflight_account_data_cas(&state, &operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(staged.expected_revision, 1);
        assert_eq!(staged.record.revision, 2);
        operation.context.sender = foreign;
        assert_eq!(
            preflight_account_data_cas(&state, &operation)
                .await
                .unwrap_err()
                .code(),
            "policy_violation"
        );
        operation.context.sender = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal,
            state.service_core_id(),
        ));
        operation.payload["expected_server_revision"] = json!(0);
        assert_eq!(
            preflight_account_data_cas(&state, &operation)
                .await
                .unwrap_err()
                .code(),
            "cas_conflict"
        );
        operation.payload["unknown_holder_field"] = json!("ak:did_core:web:other-holder.example");
        assert_eq!(
            preflight_account_data_cas(&state, &operation)
                .await
                .unwrap_err()
                .code(),
            "schema_violation"
        );
    }

    #[tokio::test]
    async fn account_blocklist_stages_the_shared_high_water_as_a_whole_value() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            state.service_core_id(),
        ));
        state
            .account_data()
            .compare_and_set(
                soland_services::identity::AccountDataState {
                    actor_id: actor.to_string(),
                    account_data_key: arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST.into(),
                    revision: 1,
                    payload: json!({"version": 1, "entries": [{"legacy": true}]}),
                    tombstone: false,
                    updated_at: chrono::Utc::now(),
                },
                0,
            )
            .await
            .unwrap();
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000004")
                .unwrap(),
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            arkret_wire::EventKind::AccountBlocklist.as_str(),
            json!({"version": 2, "entries": []}),
        );
        operation.context.sender = actor;
        let staged = preflight_account_data_cas(&state, &operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            staged.record.account_data_key,
            arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST
        );
        assert_eq!(staged.expected_revision, 1);
        assert_eq!(staged.record.revision, 2);
        assert_eq!(staged.record.payload, operation.payload);
        assert!(staged.record.tombstone);

        operation.payload["version"] = json!(3);
        assert_eq!(
            preflight_account_data_cas(&state, &operation)
                .await
                .unwrap_err()
                .code(),
            "cas_conflict"
        );
    }
}
