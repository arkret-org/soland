use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

pub(in crate::routing::events) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/describe").get(events_describe))
        .push(Router::with_path("events/subscribe").get(super::super::sync::events_subscribe))
        .push(
            Router::with_path("events")
                .post(submit_event)
                .get(super::super::sync::events_query),
        )
        .push(Router::with_path("events/query").post(super::super::sync::events_query_post))
        .push(Router::with_path("events/resolve").post(resolve_events))
        .push(Router::with_path("events/frontier").get(events_frontier))
        .push(Router::with_path("events/seals").post(submit_event_seal))
        .push(
            Router::with_path("events/mls-governance-proof")
                .post(super::governance_proof::mls_governance_proof),
        )
        .push(Router::with_path("events/{event_id}").get(get_event))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.command.submit_seal", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.command.submit_seal"))]
async fn submit_event_seal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Seal>,
) -> JsonResult<EventSealSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(&session, "ak.self.events.command.submit_seal")?;
    let seal = body.into_inner();
    let expected_realm = soland_services::identity::principal_control_realm_for_did(&session.actor);
    let managed_agent = if seal.realm_id.as_str() == expected_realm {
        None
    } else {
        crate::routing::identity::managed_agent_pcr::managed_agent_record_for_controller_pcr(
            state,
            &session.actor,
            seal.realm_id.as_str(),
        )
        .await?
    };
    if seal.realm_id.as_str() != expected_realm && managed_agent.is_none() {
        return Err(AppError::new(
            ErrorCode::PolicyViolation,
            "Seal submission is limited to the caller's own or delegated Agent principal-control Realm",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let expected_method = format!("{}#{}", session.actor, session.device_id);
    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(AppError::new(
            ErrorCode::PolicyViolation,
            "principal-control Seal submission requires one bound device signature",
        )
        .with_status(StatusCode::FORBIDDEN));
    };
    if signature.verification_method != expected_method {
        return Err(AppError::new(
            ErrorCode::PolicyViolation,
            "Seal signer does not match the authenticated session device",
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    let effect = if let Some(agent_record) = managed_agent.as_ref() {
        crate::routing::federation::move_seal::apply_managed_agent_event_seal(
            state,
            &seal,
            agent_record,
            &session.device_id,
        )
        .await?
    } else {
        crate::routing::federation::move_seal::apply_inbound_seal(state, &seal).await?
    };
    json_ok(EventSealSubmitOutcome {
        seal_id: effect.seal,
        accepted_event_digests: effect.accepted_move_ids,
        post_state_root: effect.post_state_root,
    })
}

#[salvo::oapi::endpoint(operation_id = "events_describe", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "events_describe"))]
async fn events_describe(
    depot: &mut Depot,
) -> JsonResult<arkret_models_discovery::ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut description = describe(
        state.service_id(),
        &state.config().public_base_url,
        state.jobs().storage_mode(),
        state.config().development_mode,
        state.config().account_authority_url.as_deref(),
        state.config().account_authority_enrollment_did.as_deref(),
        state.config().oidc_client_id.as_deref(),
        &state.config().trust_domain,
        state.config().resumable_upload_incomplete_ttl_seconds,
        state.config().to_device_queue_capacity,
    );
    crate::routing::system::describe::apply_claim_level_partition(
        &mut description,
        state.verified_profiles(),
        state.settings().candidate_join_policy_enabled,
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
        limits.insert("max_refs".to_owned(), json!(MAX_EVENT_REFS));
        limits.insert(
            "max_batch_item_count".to_owned(),
            json!(MAX_EVENT_SUBMIT_BATCH),
        );
        limits.insert("max_resolve".to_owned(), json!(MAX_EVENT_RESOLVE));
        limits.insert("max_list_limit".to_owned(), json!(100));
    }
    json_ok(description)
}

#[salvo::oapi::endpoint(operation_id = "submit_event", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "submit_event"))]
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
    let submit = match req.parse_json::<SolandEventsSubmitRequestBody>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid event envelope",
            );
            return;
        }
    };
    if matches!(submit, SolandEventsSubmitRequestBody::Federation(_)) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "federation peer event submission uses /_arkret/peer/events",
        );
        return;
    }
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if let Err(error) = super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
    ) {
        render_error(res, error.http_status(), error.wire_code(), &error.message);
        return;
    }

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
        match state.jobs().idempotency_record(&session.actor, key).await {
            Ok(Some(record)) if record.request_hash == request_hash => {
                // Replay: re-emit the cached first response verbatim, no
                // re-execution and no second side effect.
                let status =
                    StatusCode::from_u16(record.response_status as u16).unwrap_or(StatusCode::OK);
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
        let (status, body, idempotency_committed) = match submit {
            SolandEventsSubmitRequestBody::Single(envelope) => {
                let envelope_for_chaos = envelope.clone();
                let result = submit_event_value_with_idempotency(
                    state,
                    &session,
                    envelope,
                    EventCommitIdempotency {
                        principal_id: session.actor.clone(),
                        key: key.to_owned(),
                        service_id: state.service_id().clone(),
                        request_hash: request_hash.clone(),
                    },
                )
                .await;
                match result {
                    Ok(response) => {
                        maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response)
                            .await;
                        let committed = !response.duplicate;
                        (
                            StatusCode::OK,
                            submit_outcome_value(&response.outcome),
                            committed,
                        )
                    }
                    Err(error) => {
                        let (status, body) = submit_one_error_value(error);
                        (status, body, false)
                    }
                }
            }
            other => {
                let (status, body) = submit_event_dispatch(state, &session, other).await;
                (status, body, false)
            }
        };
        // Only deterministic outcomes are cached: a 5xx is transient, so caching
        // it would wrongly pin a server-side failure under the key and block a
        // legitimate retry. The client may safely re-send the same key.
        if !status.is_server_error() && !idempotency_committed {
            persist_idempotency_first_response(
                state,
                &session.actor,
                key,
                &request_hash,
                status,
                &body,
            )
            .await;
        }
        res.status_code(status);
        res.render(Json(body));
        return;
    }

    match submit {
        SolandEventsSubmitRequestBody::Federation(_) => unreachable!("handled before auth"),
        SolandEventsSubmitRequestBody::Batch(batch) => {
            submit_event_batch(state, &session, batch.events, res).await;
        }
        SolandEventsSubmitRequestBody::Single(envelope) => {
            let envelope_for_chaos = envelope.clone();
            match submit_event_value(state, &session, envelope).await {
                Ok(response) => {
                    maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response).await;
                    res.render(Json(response.outcome));
                }
                Err(error) => render_submit_one_error(res, error),
            }
        }
    }
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
    submit: SolandEventsSubmitRequestBody,
) -> (StatusCode, Value) {
    match submit {
        SolandEventsSubmitRequestBody::Federation(_) => unreachable!("handled before auth"),
        SolandEventsSubmitRequestBody::Batch(batch) => {
            match submit_event_batch_outcome(state, session, batch.events).await {
                Ok(outcome) => (StatusCode::OK, submit_outcome_value(&outcome)),
                Err(error) => submit_one_error_value(error),
            }
        }
        SolandEventsSubmitRequestBody::Single(envelope) => {
            let envelope_for_chaos = envelope.clone();
            match submit_event_value(state, session, envelope).await {
                Ok(response) => {
                    maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response).await;
                    (StatusCode::OK, submit_outcome_value(&response.outcome))
                }
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
    if let Some(event_id) = error.quarantine_event_id {
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
    let mut body = json!(
        arkret_wire::problem_details::ErrorEnvelope::new(error.code.clone(), error.message.clone())
            .with_request_id(crate::ids::generate_request_id())
    );
    if let Some(details) = error.details.as_ref().and_then(Value::as_object)
        && let Some(error_body) = body
            .as_object_mut()
            .and_then(|object| object.get_mut("error"))
            .and_then(Value::as_object_mut)
    {
        error_body.insert("details".to_owned(), Value::Object(details.clone()));
    }
    if error.status == StatusCode::PRECONDITION_FAILED
        && error.code == "failed_precondition"
        && error.message != error.code
        && let Some(object) = body.as_object_mut()
    {
        object.insert("reason".to_owned(), json!(error.message.clone()));
        if let Some(error_body) = object.get_mut("error").and_then(Value::as_object_mut) {
            error_body.insert("reason".to_owned(), json!(error.message.clone()));
        }
    }
    (error.status, body)
}

/// Persist the FIRST response under an `Idempotency-Key`. Best-effort: a failed
/// write is downgraded to a warning rather than failing the request the caller
/// already executed — a missing mapping only costs a later replay its cache hit
/// (it re-executes, and Event-ID idempotency still de-duplicates the work).
async fn persist_idempotency_first_response(
    state: &AppState,
    principal_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    status: StatusCode,
    body: &Value,
) {
    let created_at = now();
    let record = soland_services::jobs::IdempotencyState {
        principal_id: principal_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        service_id: state.service_id().clone(),
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
    if !state.config().development_mode {
        return;
    }
    let Ok(breakpoint) = std::env::var("SOLAND_TEST_CHAOS_BREAKPOINT") else {
        return;
    };
    if !matches!(
        breakpoint.as_str(),
        "post_commit_pre_response" | "post_wal_pre_response"
    ) {
        return;
    }
    let delay_ms = std::env::var("SOLAND_TEST_CHAOS_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(0);
    if delay_ms == 0 {
        return;
    }
    let operation_id = envelope_operation_id(envelope);
    if let Ok(expected) = std::env::var("SOLAND_TEST_CHAOS_OPERATION_ID")
        && Some(expected.as_str()) != operation_id.as_deref()
        && expected != response.event_id
    {
        return;
    }
    tracing::warn!(
        breakpoint = %breakpoint,
        delay_ms,
        event_id = %response.event_id,
        operation_id = ?operation_id,
        "test chaos delay before event response"
    );
    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
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

#[salvo::oapi::endpoint(operation_id = "ak.self.events.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.resource.get"))]
async fn get_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let event_id = event_id.into_inner();
    let record = state
        .event_queries()
        .canonical_event(&event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    event_view_for_state(state, &record, &session).await
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.query.resolve", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.query.resolve"))]
async fn resolve_events(
    aa: AuthArgs,
    body: JsonBody<EventsResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.event_ids.len() + body.event_digests.len() > MAX_EVENT_RESOLVE {
        return Err(AppError::new(
            ErrorCode::QuotaExceeded,
            "too many events requested",
        ));
    }
    let service = state.event_queries();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for event_id in body.event_ids {
        let event_id_string = event_id.to_string();
        match service
            .canonical_event(&event_id_string)
            .await
            .ok()
            .flatten()
        {
            Some(record) if event_visible_to_session(state, &record, &session).await => {
                found.push(sdk_event_for_state(state, &record)?);
            }
            _ => missing.push(event_id_string),
        }
    }
    json_ok(EventsResolveOutcome {
        events: found,
        missing,
        unauthorized: Vec::new(),
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.query.frontier", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.query.frontier"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<EventsFrontierAccountClientState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = query_param(req, "actor_id").or_else(|| query_param(req, "actor"));
    let realm_selector = query_param(req, "realm_id");
    if actor_id.is_none() && realm_selector.is_none() {
        return Err(AppError::invalid_param(
            "events.frontier requires at least one of realm_id or actor_id",
        ));
    }

    // A combined actor + Realm selector is the realm-scoped actor frontier
    // used for authoring. Realm-only remains the Seal frontier surface.
    let actor_realm_selector = actor_id.as_ref().zip(realm_selector.as_ref());

    // Realm selector → Realm Seal view `{realm_id, seal_id,
    // control_event_set_root, state_root, hlc}`: the registered sourcing for
    // single-leaf Control Move `seal_basis` (`leaves=[seal_id]`) and
    // DataEvent `seal_ref`.
    if actor_realm_selector.is_none()
        && let Some(realm_value) = realm_selector.as_ref()
    {
        let realm_id = RealmId::new(realm_value.clone())
            .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
        let own_pcr = soland_services::identity::principal_control_realm_for_did(&session.actor);
        let managed_agent_pcr =
            crate::routing::identity::managed_agent_pcr::controller_manages_agent_pcr(
                state,
                &session.actor,
                realm_value,
            )
            .await?;
        let accessible = realm_value == &own_pcr
            || managed_agent_pcr
            || crate::routing::spaces::space::realm_id_accessible(
                state,
                realm_value,
                Some(&session),
            )
            .await;
        if !accessible {
            // Same code as invisible-event reads: existence must not leak.
            return Err(AppError::not_found("realm not found"));
        }
        if managed_agent_pcr {
            // Managed Agent PCR Seals are device-generation artifacts. When
            // accepted Events are ahead of the accepted Seal, return the
            // previous signed head so the delegated controller can author the
            // successor; the service must not try to synthesize that Seal.
            let Some(seal) =
                crate::routing::identity::managed_agent_pcr::managed_agent_event_seal_head(
                    state,
                    realm_id.as_str(),
                )
                .await?
            else {
                return Err(AppError::new(
                    ErrorCode::FrontierUnavailable,
                    "managed Agent PCR has no accepted device-signed Seal",
                )
                .with_status(StatusCode::SERVICE_UNAVAILABLE));
            };
            let frontier = RealmSealFrontierView::new(
                realm_id,
                seal.id.clone(),
                seal.control_event_set_root.clone(),
                seal.state_root.clone(),
                Some(seal.hlc.clone()),
            );
            return soland_http::result::json_ok(EventsFrontierAccountClientState {
                frontier: EventsFrontierView::RealmSeal(frontier),
                receipts: vec![ManagedAgentPcrSealHeadReceipt {
                    kind: ManagedAgentPcrSealHeadReceiptKind::ManagedAgentPcrSealHeadV1,
                    seal,
                }],
            });
        }
        let head = crate::notary::ensure_realm_seal_head(state, &realm_id)
            .map_err(|e| AppError::internal(format!("seal head unavailable: {e}")))?;
        // The Realm frontier is the registered source for seal_basis/seal_ref.
        // Re-materialize on every read so accepted Control Events advance a
        // locally notarized Realm even after its bootstrap Seal already
        // exists. Returning `head` unconditionally here left every later
        // capability/policy Move permanently outside the authorization state.
        let stats = state
            .event_queries()
            .realm_event_stats(realm_id.as_str())
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "canonical Realm Event preflight unavailable: {error}"
                ))
            })?;
        if stats.count == 0 {
            return Err(AppError::not_found(
                "realm has no accepted Seal on this deployment",
            ));
        }
        let seal =
            match crate::routing::events::event_log::governance_proof::materialize_realm_event_seal(
                state, &realm_id,
            )
            .await
            {
                Ok(view) => view.accepted_seal,
                // A Realm notarized by another DID may legitimately have accepted
                // Events ahead of the locally visible signed head. Preserve that
                // authoritative head; only the designated notary may advance it.
                Err(error) if error.code == ErrorCode::FrontierUnavailable && head.is_some() => {
                    head.expect("checked existing Realm Seal head")
                }
                Err(error) => return Err(error),
            };
        return soland_http::result::json_ok(EventsFrontierAccountClientState {
            frontier: EventsFrontierView::RealmSeal(RealmSealFrontierView::new(
                realm_id,
                seal.id,
                seal.control_event_set_root,
                seal.state_root,
                Some(seal.hlc),
            )),
            receipts: Vec::new(),
        });
    }

    // Actor selectors are split deliberately: combined Realm+actor is the
    // only authoring surface; actor-only is a read-only per-Realm aggregate.
    let actor = actor_id.expect("selector presence checked above");
    let actor_id = Did::new(actor.clone())
        .map_err(|_| AppError::invalid_param("actor_id must be a valid DID"))?;
    if let Some(realm_value) = realm_selector {
        let realm_id = RealmId::new(realm_value.clone())
            .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
        let own_actor_pcr = actor == session.actor
            && realm_value == soland_services::identity::principal_control_realm_for_did(&actor);
        let managed_actor_pcr = state
            .agent_pairings()
            .agent(&actor)
            .await
            .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
            .is_some_and(|record| {
                record.controller_id == session.actor
                    && record.state != AgentLifecycleState::Deactivated
                    && record.principal_control_realm_id == realm_value
            });
        let invited_actor = actor == session.actor
            && crate::routing::spaces::space::realm_member_invited_or_joined_at(
                state,
                realm_id.as_str(),
                &actor,
            )
            .await
            .is_some();
        if !own_actor_pcr
            && !managed_actor_pcr
            && !invited_actor
            && !crate::routing::spaces::space::realm_id_accessible(
                state,
                realm_id.as_str(),
                Some(&session),
            )
            .await
        {
            return Err(AppError::not_found("realm not found"));
        }
        let frontier = load_realm_actor_frontier(state, realm_id, actor_id).await?;
        return soland_http::result::json_ok(EventsFrontierAccountClientState {
            frontier: EventsFrontierView::RealmActor(frontier),
            receipts: Vec::new(),
        });
    }

    let managed_actor_pcr = state
        .agent_pairings()
        .agent(&actor)
        .await
        .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
        .filter(|record| {
            record.controller_id == session.actor
                && record.state != AgentLifecycleState::Deactivated
        })
        .map(|record| record.principal_control_realm_id);
    let records = state
        .event_queries()
        .canonical_events_for_actor(actor_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    let mut realm_ids = records
        .iter()
        .filter_map(|record| record.realm_id.clone())
        .collect::<Vec<_>>();
    realm_ids.sort();
    realm_ids.dedup();
    let mut realms = Vec::new();
    for realm_value in realm_ids {
        let visible = managed_actor_pcr.as_deref() == Some(realm_value.as_str())
            || crate::routing::spaces::space::realm_id_accessible(
                state,
                &realm_value,
                Some(&session),
            )
            .await;
        if !visible {
            continue;
        }
        let realm_id = RealmId::new(realm_value)
            .map_err(|_| AppError::internal("stored realm_id is invalid"))?;
        realms.push(load_realm_actor_frontier(state, realm_id, actor_id.clone()).await?);
    }
    let aggregate = ActorAggregateFrontierView {
        kind: ActorAggregateFrontierKind::ActorAggregate,
        actor_id,
        realms,
    };
    aggregate
        .validate()
        .map_err(|error| AppError::internal(format!("actor aggregate is invalid: {error}")))?;
    soland_http::result::json_ok(EventsFrontierAccountClientState {
        frontier: EventsFrontierView::ActorAggregate(aggregate),
        receipts: Vec::new(),
    })
}

pub(super) async fn load_realm_actor_frontier(
    state: &AppState,
    realm_id: RealmId,
    actor_id: Did,
) -> Result<RealmActorFrontierView, AppError> {
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), actor_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    let (next_actor_seq, frontier_event_ids) =
        if let Some(max_seq) = records.iter().map(|record| record.actor_seq).max() {
            let next_actor_seq = max_seq.checked_add(1).ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierSequenceExhausted,
                    "actor sequence is exhausted",
                )
                .with_status(StatusCode::CONFLICT)
            })?;
            let mut ids = records
                .iter()
                .filter(|record| record.actor_seq == max_seq)
                .map(|record| {
                    EventId::new(record.event_id.clone())
                        .map_err(|_| AppError::internal("stored event_id is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            ids.dedup();
            (next_actor_seq, ids)
        } else {
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
    actor_id: Did,
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
