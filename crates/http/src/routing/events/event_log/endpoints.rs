use arkret_state::state::store::ControlProposalIngressClass;

use super::*;

/// Resolve governance health with the one Ack-less authority class replayed
/// from its durable ingress classification.
///
/// Persistence records Ack-less Human PCR controls as pending rows carrying
/// the `AcklessSelfPrincipal` classification captured at first admission. The
/// generic projection service cannot resolve device authorization records, so
/// the HTTP boundary replays that stored classification against its stable
/// references and supplies exact revalidated Event digests; every other
/// missing-Ack row remains a fail-closed store error.
/// This service's observation coordinate for a Realm Seal frontier read.
///
/// `event-auth-state-resolution.md` fixes `current` as the serving service's
/// verified durable view at this coordinate, never a global wall-clock latest
/// claim. The sequence is the count of accepted canonical Realm Events this
/// service has durably applied: it is monotone non-decreasing per service and
/// advances exactly when the durable view can change.
pub(crate) async fn realm_seal_frontier_observation_coordinate(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<arkret_models_collaboration::event_sync::RealmSealFrontierObservationCoordinate, AppError>
{
    let service_id = arkret_wire::DidCoreId::new(state.service_id().to_owned())
        .map_err(|error| AppError::internal(format!("serving service DID invalid: {error}")))?;
    let stats = state
        .event_queries()
        .realm_event_stats(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("Realm observation coordinate unavailable: {error}"))
        })?;
    Ok(
        arkret_models_collaboration::event_sync::RealmSealFrontierObservationCoordinate {
            service_id,
            sequence: stats.count,
            observed_at: chrono::Utc::now(),
        },
    )
}

/// Materialize the serving service's durable current accepted Seal head
/// for an already-authorized caller. Visibility checks stay at the self/peer
/// transport boundary.
pub(crate) async fn load_realm_seal_frontier(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<arkret_models_collaboration::event_sync::RealmSealFrontierView, AppError> {
    // The durable accepted Seal store is written by the admission/commit path.
    // Discovery reuses that result; it does not replay all canonical Events.
    let head = state
        .projections()
        .realm_seal_head(realm_id)
        .await
        .map_err(|error| AppError::internal(format!("accepted frontier unavailable: {error}")))?;
    let Some(head) = head else {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm has no accepted Seal"
        ));
    };
    let seal_basis = arkret_wire::SealBasis { leaves: vec![head] };
    seal_basis
        .validate_protocol_bounds()
        .map_err(|error| AppError::internal(format!("invalid accepted frontier: {error}")))?;
    let live_digest_suite = state
        .projections()
        .seal_basis_digest_suite(realm_id, &seal_basis.leaves)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "accepted frontier digest suite unavailable: {error}"
            ))
        })?;
    let governance_policy = crate::control_proposal::control_proposal_policy(state, realm_id, &[])
        .await
        .map_err(|error| {
            AppError::internal(format!("control governance policy unavailable: {error}"))
        })?;
    let governance_health =
        frontier_control_governance_health(state, realm_id, governance_policy).await?;
    let observation_coordinate =
        realm_seal_frontier_observation_coordinate(state, realm_id).await?;
    Ok(
        arkret_models_collaboration::event_sync::RealmSealFrontierView::new(
            realm_id.clone(),
            seal_basis,
            live_digest_suite,
            governance_health,
            observation_coordinate,
        ),
    )
}

pub(crate) async fn frontier_control_governance_health(
    state: &AppState,
    realm_id: &RealmId,
    policy: arkret_wire::ControlProposalDecisionPolicy,
) -> Result<arkret_models_collaboration::event_sync::ControlGovernanceHealth, AppError> {
    let limit =
        arkret_models_collaboration::event_sync::ControlGovernanceHealth::MAX_PENDING_PROPOSALS + 1;
    let pending = state
        .projections()
        .pending_control_records(realm_id, limit)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "control governance pending rows unavailable: {error}"
            ))
        })?;
    let mut ackless_authorized = std::collections::BTreeSet::new();
    let mut ackless_rejections = Vec::new();
    for (event, ingress_class, digest_suite) in pending
        .iter()
        .filter(|record| record.control_proposal_ack.is_none())
        .map(|record| (&record.event, &record.ingress_class, record.digest_suite))
    {
        let digest =
            arkret_state::state::control_event_digest(event, digest_suite).map_err(|error| {
                AppError::internal(format!("Ack-less Control Move digest invalid: {error}"))
            })?;
        let rejection = match ingress_class {
            // An Ack-required row without its Ack is the impossible durable
            // state the ingress invariant forbids; surface it as a diagnostic
            // instead of guessing a class from the Event shape.
            ControlProposalIngressClass::AckRequired => Some(
                "Control Move was classified Ack-required at ingress but stored without its Ack",
            ),
            ControlProposalIngressClass::AcklessSelfPrincipal(class) => {
                super::submit::replay_ackless_self_principal_ingress(state, event, class)
                    .await
                    .map_err(|error| {
                        AppError::internal(format!(
                            "Ack-less Control Move authority unavailable: {error}"
                        ))
                    })?
            }
        };
        match rejection {
            None => {
                ackless_authorized.insert(digest);
            }
            Some(reason) => ackless_rejections.push(format!("{reason} @ {}", event.event_id)),
        }
    }
    let mut health = state
        .projections()
        .control_governance_health_with_ackless_authorities(
            realm_id,
            chrono::Utc::now(),
            policy,
            &ackless_authorized,
        )
        .await
        .map_err(|error| {
            let diagnostic = if ackless_rejections.is_empty() {
                String::new()
            } else {
                format!(
                    "; Ack-less authority revalidation failed: {}",
                    ackless_rejections.join(", ")
                )
            };
            AppError::internal(format!(
                "control governance health unavailable: {error}{diagnostic}"
            ))
        })?;
    for proposal in &mut health.pending_proposals {
        let digest = &proposal.control_proposal_ack.proposal_digest;
        let event = state
            .projections()
            .control_event(digest)
            .await
            .map_err(|error| AppError::internal(format!("pending proposal unavailable: {error}")))?
            .ok_or_else(|| AppError::internal("pending proposal Event is missing"))?;
        if event.kind != arkret_wire::EventKind::DeviceRevoke {
            continue;
        }
        let record = soland_storage::DeviceRevocationStore::target_for_proposal(
            state.persistence(),
            digest.as_str(),
        )
        .await
        .map_err(|error| AppError::internal(format!("pending revoke target unavailable: {error}")))?
        .ok_or_else(|| AppError::internal("pending revoke has no durable target"))?;
        let revocation = crate::routing::identity::account::device_revocation_gate_record(record)
            .transpose()?
            .ok_or_else(|| {
                crate::app_error!(FrontierUnavailable, "revoke settled during frontier read")
            })?;
        let arkret_wire::DeviceRevocationGateRecord::Pending(mut revocation) = revocation else {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "revoke sealed during frontier read"
            ));
        };
        // Both mirrors use the same observation snapshot; target identity and
        // acceptance sequence come only from the immutable reducer record.
        revocation.decision_state = match proposal.decision_state {
            arkret_models_collaboration::event_sync::ControlProposalDecisionState::Pending => {
                arkret_wire::DeviceRevocationDecisionState::Pending
            }
            arkret_models_collaboration::event_sync::ControlProposalDecisionState::Deferred => {
                arkret_wire::DeviceRevocationDecisionState::Deferred
            }
            arkret_models_collaboration::event_sync::ControlProposalDecisionState::Overdue => {
                arkret_wire::DeviceRevocationDecisionState::Overdue
            }
        };
        revocation.decisions = (!proposal.decisions.is_empty()).then(|| proposal.decisions.clone());
        revocation.fault_reason = proposal
            .fault_reason
            .map(|_| arkret_wire::DeviceRevocationFaultReason::ControlProposalDecisionOverdue);
        proposal.device_revocation_state = Some(revocation);
    }
    health.validate_with_policy(policy).map_err(|error| {
        AppError::internal(format!("pending revoke projection invalid: {error}"))
    })?;
    Ok(health)
}

pub(in crate::routing::events) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/delivery-status").query(event_delivery_status))
        .push(
            Router::with_path("committed-events/subscribe")
                .get(super::super::sync::events_subscribe),
        )
        .push(Router::with_path("events").post(submit_event))
        .push(Router::with_path("committed-events/{event_id}").get(get_committed_event))
}

#[allow(dead_code)]
async fn events_describe(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_discovery::ServiceDescribe> {
    if req.method().as_str() == "QUERY" {
        req.parse_json::<arkret_models_collaboration::event_query::EventsDescribeRequestBody>()
            .await
            .map_err(|_| {
                AppError::json_invalid("invalid retired event service description request body")
            })?;
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut description = describe(
        state.service_resolution_commitment().as_ref(),
        state.jobs().storage_mode(),
        state.config(),
    );
    crate::routing::events::sync::websocket::advertise_websocket_binding(state, &mut description);
    crate::routing::system::describe::apply_conformance_evidence(
        &mut description,
        state.verified_profiles(),
    );
    // Advertise the live rate-limit ceilings (see the canonical describe
    // handler) so wire and enforcement stay in lock-step after a hot-swap.
    description.rate_limit_policy = Some(
        state
            .settings()
            .rate_limit
            .to_limiter_config()
            .advertised_policy(),
    );
    {
        let limits = &mut description.limits.extensions;
        limits.insert(
            "max_event_bytes".to_owned(),
            json!(MAX_EVENT_ENVELOPE_BYTES),
        );
        limits.insert("max_prev_refs".to_owned(), json!(MAX_EVENT_PREV_REFS));
        limits.insert("max_semantic_refs".to_owned(), json!(MAX_SEMANTIC_REFS));
        limits.insert(
            "max_batch_item_count".to_owned(),
            json!(MAX_EVENT_SUBMIT_BATCH),
        );
        limits.insert("max_resolve".to_owned(), json!(MAX_EVENT_RESOLVE));
        limits.insert("max_list_limit".to_owned(), json!(100));
    }
    json_ok(description)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.command.submit.v1"))]
async fn submit_event(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // api-conventions.md §6 — read the generic `Idempotency-Key` header before
    // the body is consumed; an empty / blank value is treated as absent so a
    // misconfigured client does not collapse every write onto one key.
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let submit = match req.parse_json::<EventsSubmitRequestBody>().await {
        Ok(body) => body,
        Err(salvo::http::ParseError::SerdeJson(error)) if error.is_data() => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "expected a registered self Event submission carrier",
            );
            return;
        }
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "json_invalid",
                "invalid event envelope",
            );
            return;
        }
    };

    if matches!(
        submit,
        EventsSubmitRequestBody::DirectConversationFounding(_)
    ) && idempotency_key.is_some()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Direct Conversation founding carries idempotency_key only in its body",
        );
        return;
    }
    let carries_transport_credential =
        req.headers().contains_key("authorization") || req.headers().contains_key("dpop");
    if !carries_transport_credential && let EventsSubmitRequestBody::Initial(submission) = &submit {
        let digest_suite = state
            .projections()
            .realm_digest_suite(submission.event.realm_id.as_str());
        if let Ok(publication) =
            arkret_wire::ProofAuthenticatedPublication::new(submission.clone(), digest_suite)
        {
            let signing_key = match verify_federated_event_admission(
                state,
                &publication.submission().event,
                digest_suite,
            )
            .await
            {
                Ok((_, key)) => key,
                Err(error) if error.starts_with("dependency_missing:") => {
                    render_error(res, StatusCode::CONFLICT, "dependency_missing", &error);
                    return;
                }
                Err(error) => {
                    render_error(res, StatusCode::BAD_REQUEST, "invalid_proof", &error);
                    return;
                }
            };
            let event = &publication.submission().event;
            let signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
            let now = crate::wire::now();
            let session = SessionRecord {
                token_hash: format!("proof-authenticated:{}", event.event_id),
                account_pk: None,
                actor: signer.signing_principal_id().to_string(),
                device_id: String::new(),
                audience: state.service_id().clone(),
                session_public_key: None,
                agent_session: None,
                session_grant: None,
                expires_at: now + chrono::Duration::minutes(5),
                created_at: now,
                revoked_at: None,
            };
            let admission = InternalEventAdmission::proof_authenticated_event(
                event,
                String::new(),
                signing_key,
            );
            match submit_proof_authenticated_publication(state, &session, publication, &admission)
                .await
            {
                Ok(response) => res.render(Json(response.outcome)),
                Err(error) => render_submit_one_error(res, error),
            }
            return;
        }
    }
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if let Err(error) = super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    ) {
        render_error(res, error.http_status(), error.wire_code(), &error.message);
        return;
    }

    submit_event_authenticated(state, &session, idempotency_key, submit, res).await;
}

fn submit_event_authenticated<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    idempotency_key: Option<String>,
    submit: EventsSubmitRequestBody,
    res: &'a mut Response,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        // §6 generic idempotency key path. When present, the key is scoped to the
        // authenticated principal: a replay carrying the SAME canonical body
        // returns the cached first response; the SAME key with a DIFFERENT
        // canonical body is a `duplicate_conflict`. Event-ID idempotency below
        // still applies independently (a write with no header relies on it).
        if let Some(key) = idempotency_key.as_deref() {
            let request_hash = match arkret_canonical::canonical_sha256(&submit) {
                Ok(hash) => hash,
                Err(error) => {
                    render_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        &format!("request body is not canonical-hashable: {error}"),
                    );
                    return;
                }
            };
            let authenticated_actor =
                match crate::routing::identity::session_actor::session_actor_from_credential(
                    state, session,
                ) {
                    Ok(actor) => actor,
                    Err(error) => {
                        render_error(res, error.http_status(), error.wire_code(), &error.message);
                        return;
                    }
                };
            match state
                .jobs()
                .scoped_idempotency_record(
                    &authenticated_actor,
                    "ak.self.events.command.submit.v1",
                    key,
                )
                .await
            {
                Ok(Some(record))
                    if is_direct_conversation_admission_rejection(&record.response_body) =>
                {
                    // Pre-0318 builds could have cached a rejection.  It is not
                    // an exact committed replay identity; ignore it and fully
                    // re-evaluate against current authority state.
                }
                Ok(Some(record)) if record.request_hash == request_hash => {
                    // Replay: re-emit the cached first response verbatim, no
                    // re-execution and no second side effect.
                    let status = StatusCode::from_u16(record.response_status as u16)
                        .unwrap_or(StatusCode::OK);
                    res.status_code(status);
                    res.render(Json(record.response_body));
                    return;
                }
                Ok(Some(_)) => {
                    render_error(
                        res,
                        StatusCode::CONFLICT,
                        "duplicate_conflict",
                        "Idempotency-Key was reused with a different request body",
                    );
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    render_error(
                        res,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        &format!("idempotency lookup failed: {error}"),
                    );
                    return;
                }
            }
            let (status, body) = submit_event_dispatch(state, session, submit).await;
            // Only deterministic outcomes are cached: a 5xx is transient, so caching
            // it would wrongly pin a server-side failure under the key and block a
            // legitimate retry. The client may safely re-send the same key.
            if should_persist_idempotency_response(status, &body) {
                persist_idempotency_first_response(
                    state,
                    &authenticated_actor,
                    key,
                    &request_hash,
                    status,
                    &body,
                )
                .await;
            }
            res.status_code(status);
            if status.is_client_error() || status.is_server_error() {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_TYPE,
                    salvo::http::HeaderValue::from_static("application/problem+json"),
                );
            }
            res.render(Json(body));
            return;
        }

        match submit {
            EventsSubmitRequestBody::AgentMembershipCascade(submission) => {
                match submit_agent_membership_cascade(state, session, submission).await {
                    Ok(outcome) => res.render(Json(outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            EventsSubmitRequestBody::DirectConversationFounding(submission) => {
                match submit_direct_conversation_founding_unit(state, session, submission).await {
                    Ok(outcome) => res.render(Json(outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            EventsSubmitRequestBody::Initial(submission) => {
                let envelope =
                    serde_json::to_value(&submission.event).expect("Event serialization");
                match submit_initial_event_submission(state, session, submission).await {
                    Ok(response) => {
                        maybe_delay_test_chaos_breakpoint(state, &envelope, &response).await;
                        res.render(Json(response.outcome));
                    }
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            EventsSubmitRequestBody::InitialBatch(batch) => {
                match submit_initial_event_batch_outcome(state, session, batch.events).await {
                    Ok(outcome) => res.render(Json(outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
        }
    })
}

/// How long a generic `Idempotency-Key` mapping is retained. api-conventions.md
/// §6 only requires "at least until the related Event is fully synced or
/// expired"; 24h comfortably covers a client's retry horizon while keeping the
/// table bounded under the periodic TTL sweep.
/// Run the (already-authenticated, non-federation) submit and reduce it to the
/// rendered `(status, body)` pair — the same value either rendered directly or
/// cached under an `Idempotency-Key`. Mirrors the no-key match arms exactly so
/// the cached first response is byte-for-byte what a keyless write would emit.
async fn submit_event_dispatch(
    state: &AppState,
    session: &SessionRecord,
    submit: EventsSubmitRequestBody,
) -> (StatusCode, Value) {
    match submit {
        EventsSubmitRequestBody::AgentMembershipCascade(submission) => {
            match submit_agent_membership_cascade(state, session, submission).await {
                Ok(outcome) => (StatusCode::OK, submit_outcome_value(&outcome)),
                Err(error) => submit_one_error_value(error),
            }
        }
        EventsSubmitRequestBody::DirectConversationFounding(submission) => {
            match submit_direct_conversation_founding_unit(state, session, submission).await {
                Ok(outcome) => (
                    StatusCode::OK,
                    serde_json::to_value(outcome)
                        .unwrap_or_else(|_| json!({"unit_kind":"direct_conversation_founding"})),
                ),
                Err(error) => submit_one_error_value(error),
            }
        }
        EventsSubmitRequestBody::Initial(submission) => {
            let envelope = serde_json::to_value(&submission.event).expect("Event serialization");
            match submit_initial_event_submission(state, session, submission).await {
                Ok(response) => {
                    maybe_delay_test_chaos_breakpoint(state, &envelope, &response).await;
                    (StatusCode::OK, submit_outcome_value(&response.outcome))
                }
                Err(error) => submit_one_error_value(error),
            }
        }
        EventsSubmitRequestBody::InitialBatch(batch) => {
            match submit_initial_event_batch_outcome(state, session, batch.events).await {
                Ok(outcome) => (StatusCode::OK, submit_outcome_value(&outcome)),
                Err(error) => submit_one_error_value(error),
            }
        }
    }
}

fn submit_outcome_value(
    outcome: &arkret_models_collaboration::http_bodies::EventsSubmitOutcome,
) -> Value {
    serde_json::to_value(outcome).unwrap_or_else(|_| json!({"status": "accepted"}))
}

/// Render a `SubmitOneError` to the same `(status, body)` shape
/// `render_submit_one_error` writes: a quarantine error becomes a 200 `partial`
/// outcome, every other error becomes the standard error envelope.
fn submit_one_error_value(error: SubmitOneError) -> (StatusCode, Value) {
    if let SubmitOneError::Quarantined { event_id, .. } = error {
        let outcome = events_submit_outcome(
            arkret_models_collaboration::http_bodies::EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![event_id],
            None,
        );
        return (StatusCode::OK, submit_outcome_value(&outcome));
    }
    if let Some(reason_code) = error.direct_conversation_admission_reason() {
        let outcome = arkret_wire::AuthoritySubmitOutcome::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: reason_code.to_owned(),
        };
        return (
            StatusCode::OK,
            serde_json::to_value(outcome).expect("authority rejection is serializable"),
        );
    }
    let SubmitOneError::Rejected { error, details } = error else {
        unreachable!();
    };
    let mut body = json!(
        arkret_wire::problem_details::Problem::from_code(
            error.wire_code(),
            error.message.as_ref(),
        )
            .with_instance(crate::ids::generate_request_id())
    );
    if let Some(details) = details.as_ref().and_then(Value::as_object)
        && let Some(problem) = body.as_object_mut()
    {
        problem.extend(details.clone());
    }
    (error.http_status(), body)
}

fn is_direct_conversation_admission_rejection(body: &Value) -> bool {
    body.get("reason_code")
        .and_then(Value::as_str)
        .or_else(|| body.pointer("/details/reason_code").and_then(Value::as_str))
        .is_some_and(is_direct_conversation_admission_reason)
}

fn should_persist_idempotency_response(status: StatusCode, body: &Value) -> bool {
    !status.is_server_error() && !is_direct_conversation_admission_rejection(body)
}

/// Persist the FIRST response under an `Idempotency-Key`. Best-effort: a failed
/// write is downgraded to a warning rather than failing the request the caller
/// already executed — a missing mapping only costs a later replay its cache hit
/// (it re-executes, and Event-ID idempotency still de-duplicates the work).
async fn persist_idempotency_first_response(
    state: &AppState,
    authenticated_actor: &arkret_wire::ActorId,
    idempotency_key: &str,
    request_hash: &str,
    status: StatusCode,
    body: &Value,
) {
    let created_at = now();
    let record = soland_services::jobs::IdempotencyState {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: "ak.self.events.command.submit.v1".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        request_hash: request_hash.to_owned(),
        response_status: status.as_u16() as i32,
        response_body: body.clone(),
        created_at,
        expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
    };
    if let Err(error) = state.jobs().store_idempotency_record(record).await {
        tracing::warn!(%error, idempotency_key, "idempotency first-response persist failed");
    }
}

async fn maybe_delay_test_chaos_breakpoint(
    state: &AppState,
    envelope: &Value,
    response: &SubmittedEventOutcome,
) {
    let operation_id = envelope_operation_id(envelope);
    crate::routing::events::test_chaos::maybe_delay_before_event_response(
        state,
        operation_id.as_deref(),
        &response.event_id,
    )
    .await;
}

fn envelope_operation_id(envelope: &Value) -> Option<String> {
    envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:operation:"))
        .map(ToOwned::to_owned)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.committed_event.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.committed_event.resource.get.v1"))]
async fn get_committed_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CommittedEventView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let event_id = EventId::new(event_id.into_inner())
        .map_err(|_| AppError::not_found("committed event not found"))?;
    let record = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("committed event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("committed event not found"));
    }
    let committed = state
        .persistence()
        .committed_event(&event_id)
        .await
        .map_err(|error| AppError::internal(format!("committed Event lookup failed: {error}")))?
        .ok_or_else(|| AppError::not_found("committed event not found"))?;
    let view = CommittedEventView::Full(CommittedEventFullView {
        commit: committed.commit,
        event: committed.event,
    });
    view.validate_shape().map_err(|error| {
        AppError::internal(format!("durable committed Event view is invalid: {error}"))
    })?;
    json_ok(view)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.read.delivery_status", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.delivery_status.v1"))]
async fn event_delivery_status(
    aa: AuthArgs,
    body: JsonBody<EventDeliveryStatusRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventDeliveryStatusOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
    )?;
    let body = body.into_inner();
    let event_id = body.event_id.as_str();
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    let deliveries = state
        .federation()
        .deliveries_for_event(event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Event delivery status unavailable: {error}"))
        })?;
    let mut targets = BTreeMap::new();
    for delivery in deliveries {
        let Some(mut target) =
            soland_services::federation::event_delivery_target_status(&delivery, event_id)
                .map_err(|error| AppError::internal(error.to_string()))?
        else {
            continue;
        };
        let binding =
            delivery.delivery.realm_fanout.as_ref().ok_or_else(|| {
                AppError::internal("projected Realm fanout target lost its binding")
            })?;
        let can_read_service_id = caller_can_read_delivery_target_service(
            state,
            &session,
            binding,
            delivery.delivery.peer_id.as_str(),
        )
        .await;
        if can_read_service_id {
            target.service_id = Some(delivery.delivery.peer_id.clone());
        }
        if targets.insert(target.target_id.clone(), target).is_some() {
            return Err(AppError::internal(
                "duplicate durable Realm fanout target for one Event",
            ));
        }
    }
    let targets = targets.into_values().collect::<Vec<_>>();
    let outcome = EventDeliveryStatusOutcome {
        event_id: body.event_id,
        targets,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(format!("invalid Event delivery status: {error}")))?;
    json_ok(outcome)
}

async fn caller_can_read_delivery_target_service(
    state: &AppState,
    session: &SessionRecord,
    binding: &soland_services::federation::RealmFanoutBinding,
    recipient_id: &str,
) -> bool {
    for witness in &binding.authority_witnesses {
        let member_key = witness.member_id.to_string();
        let witness_is_current = state
            .projections()
            .snapshot()
            .member(&binding.realm_id, &member_key)
            .is_some_and(|member| {
                member.state == "join"
                    && witness.member_id.route_service_id().as_str() == recipient_id
                    && member.membership_event_ref.as_deref()
                        == Some(witness.membership_event_ref.as_str())
            });
        if !witness_is_current {
            continue;
        }
        let Ok(Some(membership_event)) = state
            .event_queries()
            .canonical_event(&witness.membership_event_ref)
            .await
        else {
            continue;
        };
        if !event_visible_to_session(state, &membership_event, session).await {
            continue;
        }
        return true;
    }
    false
}

#[allow(dead_code)]
async fn resolve_events(
    aa: AuthArgs,
    body: JsonBody<EventsResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if body.history_traversal_access.is_some() && body.include_payload == Some(false) {
        return Err(AppError::param_invalid(
            "history traversal requires the complete accepted Event payload",
        ));
    }
    if body.event_ids.len() + body.event_digests.len() > MAX_EVENT_RESOLVE {
        return Err(crate::app_error!(
            LimitExceeded,
            "too many events requested",
        ));
    }
    if let Some(access) = body.history_traversal_access.clone() {
        let caller = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                AppError::internal(format!("session actor is invalid: {error}"))
            })?,
            state.service_core_id().clone(),
        ));
        let retained = state
            .persistence()
            .governance_history_service()
            .resolve_self_retained_events_for_access(access, &caller, now())
            .await
            .map_err(|error| AppError::internal(format!("history traversal access: {error}")))?;
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for event_id in &body.event_ids {
            match retained.iter().find(|event| event.event_id == *event_id) {
                Some(event) => found.push(event.clone()),
                None => missing.push(event_id.to_string()),
            }
        }
        for digest in &body.event_digests {
            let event = retained.iter().find(|event| {
                arkret::signed_event_digest_claim(event).is_ok_and(|retained_digest| {
                    retained_digest == *digest
                        && retained_digest.digest_suite().is_ok_and(|digest_suite| {
                            event
                                .event_digest_with_digest_suite(digest_suite)
                                .is_ok_and(|actual| actual == digest.as_str())
                        })
                })
            });
            match event {
                Some(event)
                    if !found.iter().any(|found_event: &arkret_wire::Event| {
                        found_event.event_id == event.event_id
                    }) =>
                {
                    found.push(event.clone());
                }
                Some(_) => {}
                None => missing.push(digest.to_string()),
            }
        }
        let outcome = EventsResolveOutcome {
            events: found,
            missing,
            unauthorized: Vec::new(),
        };
        let encoded = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| AppError::internal(format!("events resolve outcome: {error}")))?;
        let byte_limit = body.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
        if encoded.len() > byte_limit {
            return Err(crate::app_error!(
                LimitExceeded,
                "events resolve outcome exceeds max_response_bytes",
            ));
        }
        return json_ok(outcome);
    }
    let service = state.event_queries();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    let include_payload = body.include_payload.unwrap_or(true);
    for event_id in &body.event_ids {
        let event_id_string = event_id.to_string();
        match service
            .canonical_event(&event_id_string)
            .await
            .ok()
            .flatten()
        {
            Some(record) if event_visible_to_session(state, &record, &session).await => {
                let mut event = sdk_event_for_state(state, &record)?;
                if !include_payload {
                    event.payload.clear();
                }
                found.push(event);
            }
            _ => missing.push(event_id_string),
        }
    }
    if !body.event_digests.is_empty() {
        let records = service
            .canonical_events()
            .await
            .map_err(|error| AppError::internal(format!("events resolve: {error}")))?;
        for digest in &body.event_digests {
            let Some(record) = records
                .iter()
                .find(|record| record.canonical_digest == digest.as_str())
            else {
                missing.push(digest.to_string());
                continue;
            };
            if !event_visible_to_session(state, record, &session).await {
                missing.push(digest.to_string());
                continue;
            }
            if !found
                .iter()
                .any(|event| event.event_id.as_str() == record.event_id)
            {
                let mut event = sdk_event_for_state(state, record)?;
                if !include_payload {
                    event.payload.clear();
                }
                found.push(event);
            }
        }
    }
    let outcome = EventsResolveOutcome {
        events: found,
        missing,
        unauthorized: Vec::new(),
    };
    let encoded = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("events resolve outcome: {error}")))?;
    let byte_limit = body.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
    if encoded.len() > byte_limit {
        return Err(crate::app_error!(
            LimitExceeded,
            "events resolve outcome exceeds max_response_bytes",
        ));
    }
    json_ok(outcome)
}

#[cfg(test)]
#[allow(
    clippy::items_after_test_module,
    reason = "the focused regression tests stay adjacent to their endpoint helpers"
)]
mod endpoint_regression_tests {
    use super::*;

    #[test]
    fn direct_conversation_admission_rejection_is_a_closed_uncached_outcome() {
        let error = SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            arkret_wire::ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID,
        )
        .with_details(serde_json::json!({
            "reason_code": arkret_wire::ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID,
        }));
        let (status, body) = submit_one_error_value(error);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({
                "status": "rejected",
                "reason_code": "direct_conversation_member_count_invalid",
            })
        );
        assert!(!should_persist_idempotency_response(status, &body));
        assert!(should_persist_idempotency_response(
            StatusCode::OK,
            &serde_json::json!({"status": "committed"}),
        ));
    }

    #[tokio::test]
    async fn submit_idempotency_first_response_uses_exact_actor_and_operation_scope() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal,
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let first = serde_json::json!({"status": "accepted", "cursor": "opaque-first-response"});
        persist_idempotency_first_response(
            &state,
            &local,
            "test-key",
            "test-request-hash",
            StatusCode::OK,
            &first,
        )
        .await;
        let record = state
            .jobs()
            .scoped_idempotency_record(&local, "ak.self.events.command.submit.v1", "test-key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.response_body, first);
        assert!(
            state
                .jobs()
                .scoped_idempotency_record(&foreign, "ak.self.events.command.submit.v1", "test-key")
                .await
                .unwrap()
                .is_none()
        );
        for other_operation in ["other.operation.v1", "ak.self.events.command.submit"] {
            assert!(
                state
                    .jobs()
                    .scoped_idempotency_record(&local, other_operation, "test-key")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn canonical_frontier_keeps_same_principal_station_sequences_independent() {
        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm = RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        for (station, sequence) in [("station-a", 7_u64), ("station-b", 20_u64)] {
            let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
            ));
            let event = arkret_wire::test_support::raw_event_for_actor_at(
                "ak.member.state",
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                actor.clone(),
                sequence,
                arkret_wire::Hlc::new(format!("019041000000-{sequence:04x}-00000001")).unwrap(),
                serde_json::json!({"member_id": actor, "membership": "join", "realm_id": realm}),
                chrono::Utc::now(),
            )
            .unwrap();
            let envelope = serde_json::to_value(&event).unwrap();
            state
                .event_queries()
                .store_canonical_event(soland_services::events::AcceptedEvent {
                    event_id: event.event_id.to_string(),
                    actor_id: actor.to_string(),
                    actor_seq: sequence,
                    realm_id: Some(realm.to_string()),
                    kind: event.kind.to_string(),
                    schema_id: "ak.event.v1".to_owned(),
                    digest_suite: arkret_canonical::DigestSuite::Sha256,
                    canonical_digest: event
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .unwrap(),
                    canonical_bytes: crate::routing::events::event_log::event_canonical_bytes(
                        &envelope,
                    )
                    .unwrap(),
                    envelope,
                    received_at: chrono::Utc::now(),
                })
                .await
                .unwrap();
        }
        for (station, expected_sequence) in [("station-a", 8), ("station-b", 21)] {
            let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
            ));
            let frontier = load_realm_actor_frontier(
                &state,
                realm.clone(),
                actor.clone(),
                VerifiedActorPredecessors::none(),
            )
            .await
            .unwrap();
            assert_eq!(frontier.actor_id, actor);
            assert_eq!(frontier.next_actor_seq, expected_sequence);
            assert_eq!(frontier.frontier_event_ids.len(), 1);
        }
    }
}

/// `sync/federation.md` section 5.3.4, "decidable empty frontier".
///
/// `next_actor_seq = 0` with an empty `frontier_event_ids` asserts that this
/// actor has never authored in this Realm. "The accepted-events query returned
/// no rows" does not establish that, and initializing an actor chain from it is
/// how a rejoin silently restarts at sequence 0 on top of history this Station
/// merely failed to see. The four conditions below are the only way to reach
/// that assertion; anything else — including anything undecidable — is
/// `frontier_unavailable`, which stays retryable.
///
/// Condition 4 ("this bootstrap's `applicant_predecessor_events` verify to the
/// empty set") is carried by [`VerifiedActorPredecessors`]: every caller states
/// what it verified, so a future section 5.3.1 bootstrap cannot reach an empty
/// frontier by routing around this check.
async fn require_decidable_empty_realm_actor_frontier(
    state: &AppState,
    realm_id: &RealmId,
    actor_id: &arkret_wire::ActorId,
    verified_predecessors: VerifiedActorPredecessors<'_>,
) -> Result<(), AppError> {
    // 1. Single authoring entry. Every Event this actor can have in this Realm is produced through
    //    this Station's own submit surface, which makes "never authored" a local fact this Station
    //    is authoritative about rather than a claim about the whole network.
    if *actor_id.route_service_id() != state.service_core_id() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "actor frontier initialization is not decidable for a foreign authoring Station",
        ));
    }
    // 2. Unbroken authoring record. Only an account has a local inception this Station can anchor;
    //    a Service actor has no such anchor and is therefore undecidable rather than continuous.
    let Some(account_id) = actor_id.as_account_id() else {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "actor frontier initialization has no account authoring continuity anchor",
        ));
    };
    if !state
        .persistence()
        .account_authoring_record_is_continuous(account_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("account authoring continuity is unavailable: {error}"),
            )
        })?
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "this Station does not hold an unbroken authoring record for the account",
        ));
    }
    // 3. Deterministic, exhaustive, empty enumeration. The accepted-events read above is not that
    //    enumeration: it hides quarantined Events and fork-resolution losers, both of which still
    //    occupy a sequence.
    if state
        .event_queries()
        .realm_actor_position_occupied(realm_id.as_str(), &actor_id.to_string())
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("actor position enumeration did not complete: {error}"),
            )
        })?
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "the actor already occupies a position this Station cannot read as accepted",
        ));
    }
    // 4. No counter-evidence. A verified applicant predecessor for exactly this actor proves the
    //    chain is not initial, so an empty frontier MUST NOT be claimed from it. Deriving the
    //    frontier from that material is the bootstrap merge path, not this initialization gate.
    if !verified_predecessors.is_empty() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "verified applicant predecessors contradict an initial actor state",
        ));
    }
    Ok(())
}

/// Applicant predecessor Events already verified under the ordinary Event acceptance rules for
/// exactly this `(realm_id, actor_id)`.
///
/// `sync/federation.md` section 5.3.4 makes an empty verified set one of the four conditions for a
/// decidable empty frontier, so the set has to reach the gate as an argument rather than as an
/// assumption. Ordinary authoring surfaces hold no such material and say so with [`Self::none`];
/// `ak.peer.realm_join.read.bootstrap.v1` supplies what it verified with
/// [`Self::from_verified`]. Neither constructor accepts unverified remote material.
#[derive(Clone, Copy)]
pub(crate) struct VerifiedActorPredecessors<'a>(&'a [arkret_wire::Event]);

impl<'a> VerifiedActorPredecessors<'a> {
    /// This surface holds no bootstrap material at all.
    pub(crate) const fn none() -> Self {
        Self(&[])
    }

    /// Events that already passed the ordinary acceptance rules for this actor and Realm.
    pub(crate) const fn from_verified(events: &'a [arkret_wire::Event]) -> Self {
        Self(events)
    }

    const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

pub(crate) async fn load_realm_actor_frontier(
    state: &AppState,
    realm_id: RealmId,
    actor_id: arkret_wire::ActorId,
    verified_predecessors: VerifiedActorPredecessors<'_>,
) -> Result<RealmActorFrontierView, AppError> {
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), &actor_id.to_string())
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    for event in verified_predecessors.0 {
        if event.realm_id != realm_id || event.actor_id != actor_id {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "verified applicant predecessor crosses the requested Realm or actor",
            ));
        }
    }
    let max_seq = records
        .iter()
        .map(|record| record.actor_seq)
        .chain(verified_predecessors.0.iter().map(|event| event.actor_seq))
        .max();
    let (next_actor_seq, frontier_event_ids) = if let Some(max_seq) = max_seq {
        let next_actor_seq = max_seq.checked_add(1).ok_or_else(|| {
            crate::app_error!(FrontierSequenceExhausted, "actor sequence is exhausted",)
        })?;
        let mut ids = records
            .iter()
            .filter(|record| record.actor_seq == max_seq)
            .map(|record| {
                EventId::new(record.event_id.clone())
                    .map_err(|_| AppError::internal("stored event_id is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ids.extend(
            verified_predecessors
                .0
                .iter()
                .filter(|event| event.actor_seq == max_seq)
                .map(|event| event.event_id.clone()),
        );
        ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        ids.dedup();
        (next_actor_seq, ids)
    } else {
        require_decidable_empty_realm_actor_frontier(
            state,
            &realm_id,
            &actor_id,
            verified_predecessors,
        )
        .await?;
        (0, Vec::new())
    };
    build_realm_actor_frontier(
        state,
        realm_id,
        actor_id,
        next_actor_seq,
        frontier_event_ids,
    )
}

pub(super) fn build_realm_actor_frontier(
    state: &AppState,
    realm_id: RealmId,
    actor_id: arkret_wire::ActorId,
    next_actor_seq: u64,
    frontier_event_ids: Vec<EventId>,
) -> Result<RealmActorFrontierView, AppError> {
    let suite_name = state
        .projections()
        .snapshot()
        .realm_digest_algorithm(realm_id.as_str())
        .unwrap_or_else(|| "sha256".to_owned());
    let suite = canonical::digest_suite(&suite_name)
        .map_err(|_| AppError::internal("Realm digest algorithm is unsupported"))?;
    RealmActorFrontierView::new(
        realm_id,
        actor_id,
        next_actor_seq,
        frontier_event_ids,
        suite,
    )
    .map_err(|error| AppError::internal(format!("actor frontier is invalid: {error}")))
}
