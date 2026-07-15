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
        .push(
            Router::with_path("events/mls-governance-proof")
                .post(super::governance_proof::mls_governance_proof),
        )
        .push(Router::with_path("events/{event_id}").get(get_event))
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "events_describe"))]
async fn events_describe(depot: &mut Depot) -> JsonResult<arkret_sdk::ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut description = describe(
        &state.service_id,
        &state.config.public_base_url,
        state.db.mode(),
        state.config.development_mode,
        state.config.account_authority_url.as_deref(),
        state.config.oidc_client_id.as_deref(),
        &state.config.trust_domain,
        state.config.resumable_upload_incomplete_ttl_seconds,
        state.config.to_device_queue_capacity,
    );
    crate::routing::system::describe::apply_claim_level_partition(
        &mut description,
        state.verified_profiles.as_ref(),
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
        limits.insert("max_batch_size".to_owned(), json!(MAX_EVENT_SUBMIT_BATCH));
        limits.insert("max_resolve".to_owned(), json!(MAX_EVENT_RESOLVE));
        limits.insert("max_list_limit".to_owned(), json!(100));
    }
    json_ok(description)
}

#[endpoint]
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
        super::super::AGENT_SCOPE_EVENTS_COMMAND_SUBMIT,
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
        let request_hash = match arkret_sdk::canonical::canonical_sha256(&submit) {
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
        match state
            .persistence
            .idempotency_keys()
            .get(&session.actor, key)
            .await
        {
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
        let (status, body) = submit_event_dispatch(state, &session, submit).await;
        // Only deterministic outcomes are cached: a 5xx is transient, so caching
        // it would wrongly pin a server-side failure under the key and block a
        // legitimate retry. The client may safely re-send the same key.
        if !status.is_server_error() {
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
const IDEMPOTENCY_KEY_TTL_SECONDS: i64 = 86_400;

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

fn submit_outcome_value(outcome: &arkret_sdk::EventsSubmitOutcome) -> Value {
    serde_json::to_value(outcome).unwrap_or_else(|_| json!({"status": "accepted"}))
}

/// Render a `SubmitOneError` to the same `(status, body)` shape
/// `render_submit_one_error` writes: a quarantine error becomes a 200 `partial`
/// outcome, every other error becomes the standard error envelope.
fn submit_one_error_value(error: SubmitOneError) -> (StatusCode, Value) {
    if let Some(event_id) = error.quarantine_event_id {
        let outcome = events_submit_outcome(
            arkret_sdk::EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![event_id],
            None,
        );
        return (StatusCode::OK, submit_outcome_value(&outcome));
    }
    let mut body = json!(
        arkret_sdk::ErrorEnvelope::new(error.code.clone(), error.message.clone())
            .with_request_id(crate::ids::generate_request_id())
    );
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
    let record = crate::persistence::IdempotencyRecord {
        principal_id: principal_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        service_id: state.service_id.clone(),
        request_hash: request_hash.to_owned(),
        response_status: status.as_u16() as i32,
        response_body: body.clone(),
        created_at,
        expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
    };
    if let Err(error) = state.persistence.idempotency_keys().record(&record).await {
        tracing::warn!(%error, idempotency_key, "idempotency first-response persist failed");
    }
}

async fn maybe_delay_test_chaos_breakpoint(
    state: &AppState,
    envelope: &Value,
    response: &SubmittedEventOutcome,
) {
    if !state.config.development_mode {
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

#[endpoint(
    operation_id = "ak.self.events.resource.get",
    tags("events"),
    summary = "Fetch one canonical Event Envelope by event_id"
)]
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
        .persistence
        .events()
        .get(&event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    event_view_for_state(state, &record, &session).await
}

#[endpoint(
    operation_id = "ak.self.events.query.resolve",
    tags("events"),
    summary = "Resolve up to MAX_EVENT_RESOLVE canonical Event Envelopes by event_id"
)]
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
    let store = state.persistence.events();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for event_id in body.event_ids {
        let event_id_string = event_id.to_string();
        match store.get(&event_id_string).await.ok().flatten() {
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

/// Internal durable-Event-store reader, kept for actor-scoped audit reads
/// that bypass the projection layer. Not wired to a public route in the
/// current API shape —
/// the canonical `ak.self.events.query.scan` path at `GET /_arkret/self/events` goes to the
/// projection-aware handler in `routing/sync.rs::events_query` so message
/// timeline reads work through `POST /_arkret/self/events` → `events_query`
/// round-trips.
///
/// Supports the multi-value selector `realms[]` ∪ `actors[]` (via
/// repeated query args) **and** real backward iteration (`direction=backward`
/// returns events older than `from` cursor in reverse time order, with
/// `prev_cursor` driving further pages).
/// Plain async helper version of [`events_query_durable_scope`] so other
/// handlers (e.g. the projection-aware `routing::events::sync::events_query`) can
/// dispatch to the durable-store reader when the selector contains only
/// `actors[]` (no `realms[]`). Both the `#[endpoint]` wrapper and the
/// sync-side dispatcher call this impl.
///
/// Returns `Result<EventsQueryOutcome, AppError>` so the wrapper can be a
/// typed `JsonResult<T>` handler and the sync-side dispatcher can map the
/// typed result into its own `&mut Response` shape with a single `match`.
pub(in crate::routing::events) async fn events_query_durable_scope_impl(
    state: &AppState,
    session: &SessionRecord,
    req: &Request,
) -> Result<EventsQueryOutcome, AppError> {
    // Repeated query-arg selector: `actors[]` ∪ `realms[]`.
    let mut actors = query_param_all(req, "actors");
    if let Some(single) = query_param(req, "actor").or_else(|| query_param(req, "actor_id"))
        && !actors.contains(&single)
    {
        actors.push(single);
    }
    let mut realms = query_param_all(req, "realms");
    if let Some(single) = query_param(req, "realm_id")
        && !realms.contains(&single)
    {
        realms.push(single);
    }
    for actor in &actors {
        if validate_did(actor).is_err() {
            return Err(AppError::invalid_param(format!("invalid actor: {actor}")));
        }
    }
    for realm in &mut realms {
        if RealmId::new(realm.clone()).is_err() {
            return Err(AppError::invalid_param(format!("invalid realm: {realm}")));
        }
    }
    // Round C44 (spec dc01ad7): query refactor — `from` / `until` /
    // `direction` removed. `after=<cursor>` paginates forward; `before=<cursor>`
    // paginates backward. Specifying both is an `invalid_param`; specifying
    // neither defaults to forward-from-start.
    let after = query_param(req, "after");
    let before = query_param(req, "before");
    if after.is_some() && before.is_some() {
        return Err(AppError::invalid_param(
            "specify either 'after' or 'before', not both",
        ));
    }
    let (cursor, direction) = match (after, before) {
        (Some(cursor), None) => (Some(cursor), "forward"),
        (None, Some(cursor)) => (Some(cursor), "backward"),
        (None, None) => (None, "forward"),
        (Some(_), Some(_)) => unreachable!("validated above"),
    };
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 100);
    let actors_set: std::collections::BTreeSet<&str> = actors.iter().map(String::as_str).collect();
    let realms_set: std::collections::BTreeSet<&str> = realms.iter().map(String::as_str).collect();
    let scoped = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|record| {
            // Spec selector semantics: union — match actor OR realm membership.
            // Empty selector means "all reachable" (handler will still gate
            // through `event_visible_to_session`).
            if actors_set.is_empty() && realms_set.is_empty() {
                return true;
            }
            let actor_match = actors_set.contains(record.actor_id.as_str());
            let realm_match = record
                .realm_id
                .as_deref()
                .is_some_and(|realm| realms_set.contains(realm));
            actor_match || realm_match
        });
    let mut records = Vec::new();
    for record in scoped {
        if event_visible_to_session(state, &record, session).await {
            records.push(record);
        }
    }
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    if direction == "backward" {
        records.reverse();
    }
    let start = cursor
        .as_deref()
        .and_then(|cursor| records.iter().position(|record| record.event_id == cursor))
        .map(|index| index + 1)
        .unwrap_or(0);
    let mut page = records
        .into_iter()
        .skip(start)
        .take(limit + 1)
        .collect::<Vec<_>>();
    let has_more = page.len() > limit;
    if has_more {
        page.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| page.last().map(|record| record.event_id.clone()))
        .flatten();
    let events = page
        .iter()
        .map(|record| sdk_event_for_state(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor: None,
        has_more,
        range_completeness: None,
    })
}

/// Salvo `#[endpoint]` wrapper around [`events_query_durable_scope_impl`] so
/// the actor-scoped durable-store reader can be wired to a route directly
/// (currently used only as a fallback dispatched from `routing::events::sync::events_query`
/// when the selector has no `realms[]`).
#[endpoint(
    operation_id = "org.arkret.soland.events.query_durable",
    tags("events"),
    summary = "Durable-store reader (bypasses projection; actor-scoped audit queries)"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.events.query_durable"))]
async fn events_query_durable_scope(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let response = events_query_durable_scope_impl(state, &session, req).await?;
    json_ok(response)
}

#[endpoint(
    operation_id = "ak.self.events.query.frontier",
    tags("events"),
    summary = "Actor frontier or Realm Seal view (registered seal_basis / seal_ref sourcing)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.query.frontier"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsFrontierAccountClientState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = query_param(req, "actor_id").or_else(|| query_param(req, "actor"));
    let realm_selector = query_param(req, "realm_id");
    if actor_id.is_none() && realm_selector.is_none() {
        return Err(AppError::invalid_param(
            "events.frontier requires at least one of realm_id or actor_id",
        ));
    }

    // Realm selector → Realm Seal view `{realm_id, seal_id,
    // control_event_set_root, state_root, hlc}`: the registered sourcing for
    // single-leaf Control Move `seal_basis` (`leaves=[seal_id]`) and
    // DataEvent `seal_ref`. Takes precedence when both selectors are passed.
    if let Some(realm_value) = realm_selector {
        let realm_id = RealmId::new(realm_value.clone())
            .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
        let own_pcr =
            crate::routing::identity::recovery::principal_control_realm_for_did(&session.actor);
        let managed_agent_pcr =
            crate::routing::identity::managed_agent_pcr::controller_manages_agent_pcr(
                state,
                &session.actor,
                &realm_value,
            )
            .await?;
        let accessible = realm_value == own_pcr
            || managed_agent_pcr
            || crate::routing::spaces::space::realm_id_accessible(
                state,
                &realm_value,
                Some(&session),
            )
            .await;
        if !accessible {
            // Same code as invisible-event reads: existence must not leak.
            return Err(AppError::not_found("realm not found"));
        }
        if managed_agent_pcr {
            let frontier =
                crate::routing::identity::managed_agent_pcr::managed_agent_event_frontier(
                    state,
                    &realm_value,
                )
                .await?
                .ok_or_else(|| AppError::not_found("realm has no accepted Event frontier"))?;
            return crate::result::json_ok(EventsFrontierAccountClientState {
                frontier: EventsFrontierView::RealmSealView(frontier),
                receipts: Vec::new(),
            });
        }
        let head = crate::notary::ensure_realm_seal_head(state, &realm_id)
            .map_err(|e| AppError::internal(format!("seal head unavailable: {e}")))?;
        let Some(seal) = head else {
            return Err(AppError::not_found(
                "realm has no accepted Seal on this deployment",
            ));
        };
        return crate::result::json_ok(EventsFrontierAccountClientState {
            frontier: EventsFrontierView::RealmSealView(RealmSealFrontierView {
                realm_id,
                seal_id: seal.id,
                control_event_set_root: seal.control_event_set_root,
                state_root: seal.state_root,
                hlc: Some(seal.hlc),
            }),
            receipts: Vec::new(),
        });
    }

    // Actor selector → `{actor_id, actor_seq, event_id?}`: highest accepted
    // actor_seq among events visible to the caller. An empty frontier is a
    // successful genesis state rather than an expected-error probe.
    let actor = actor_id.expect("selector presence checked above");
    let actor_id = Did::new(actor.clone())
        .map_err(|_| AppError::invalid_param("actor_id must be a valid DID"))?;
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let managed_actor_pcr = state
        .persistence
        .agents()
        .get(&actor)
        .await
        .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
        .filter(|record| record.controller_id == session.actor && record.state != "deactivated")
        .map(|record| record.principal_control_realm_id);
    let mut best: Option<(u64, String)> = None;
    for record in &events {
        if record.actor_id != actor {
            continue;
        }
        let record_realm_id = record
            .envelope
            .get("realm_id")
            .and_then(Value::as_str)
            .or(record.realm_id.as_deref());
        let managed_actor_event_visible = managed_actor_pcr
            .as_deref()
            .is_some_and(|pcr_id| record_realm_id == Some(pcr_id));
        if !managed_actor_event_visible && !event_visible_to_session(state, record, &session).await
        {
            continue;
        }
        if best.as_ref().is_none_or(|(seq, _)| record.actor_seq > *seq) {
            best = Some((record.actor_seq, record.event_id.clone()));
        }
    }
    let (actor_seq, event_id) = match best {
        Some((actor_seq, event_id)) => (
            actor_seq,
            Some(
                EventId::new(event_id)
                    .map_err(|_| AppError::internal("stored event_id is invalid"))?,
            ),
        ),
        // Unknown, invisible, and genuinely empty actors deliberately share
        // the same response so this surface does not disclose existence.
        None => (0, None),
    };
    crate::result::json_ok(EventsFrontierAccountClientState {
        frontier: EventsFrontierView::Actor(ActorFrontierView {
            actor_id,
            actor_seq,
            event_id,
        }),
        receipts: Vec::new(),
    })
}
