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
        .push(Router::with_path("events/{event_id}").get(get_event))
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "events_describe"))]
async fn events_describe(depot: &mut Depot) -> JsonResult<cokret_sdk::ServerDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let mut description = describe(
        &state.config.service_did,
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
    );
    if let Some(limits) = description.limits.as_object_mut() {
        limits.insert("max_event_bytes".to_owned(), json!(MAX_EVENT_BYTES));
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
            "federation peer event submission uses /_cokret/peer/events",
        );
        return;
    }
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
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
        .filter(|value| value.starts_with("ck:operation:"))
        .map(ToOwned::to_owned)
}

#[endpoint(
    operation_id = "ck.self.events.resource.get",
    tags("events"),
    summary = "Fetch one canonical Event Envelope by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.resource.get"))]
async fn get_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventView> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    operation_id = "ck.self.events.query.resolve",
    tags("events"),
    summary = "Resolve up to MAX_EVENT_RESOLVE canonical Event Envelopes by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.resolve"))]
async fn resolve_events(
    aa: AuthArgs,
    body: JsonBody<EventsResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
/// the canonical `ck.self.events.query.scan` path at `GET /_cokret/self/events` goes to the
/// projection-aware handler in `routing/sync.rs::events_query` so message
/// timeline reads work through `POST /_cokret/self/events` → `events_query`
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
    if let Some(single) = query_param(req, "actor").or_else(|| query_param(req, "actor_id")) {
        if !actors.contains(&single) {
            actors.push(single);
        }
    }
    let mut realms = query_param_all(req, "realms");
    if let Some(single) = query_param(req, "realm_id") {
        if !realms.contains(&single) {
            realms.push(single);
        }
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
        range_completeness: Value::Null,
    })
}

/// Salvo `#[endpoint]` wrapper around [`events_query_durable_scope_impl`] so
/// the actor-scoped durable-store reader can be wired to a route directly
/// (currently used only as a fallback dispatched from `routing::events::sync::events_query`
/// when the selector has no `realms[]`).
#[endpoint(
    operation_id = "org.cokret.soland.events.query_durable",
    tags("events"),
    summary = "Durable-store reader (bypasses projection; actor-scoped audit queries)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.events.query_durable"))]
async fn events_query_durable_scope(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let response = events_query_durable_scope_impl(state, &session, req).await?;
    json_ok(response)
}

#[endpoint(
    operation_id = "ck.self.events.query.frontier",
    tags("events"),
    summary = "Actor frontier or Realm Seal view (registered seal_basis / seal_ref sourcing)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.frontier"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsFrontierAccountClientState> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        let accessible = realm_value == own_pcr
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

    // Actor selector → `{actor_id, actor_seq, event_id}`: highest accepted
    // actor_seq among events visible to the caller.
    let actor = actor_id.expect("selector presence checked above");
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut best: Option<(u64, String)> = None;
    for record in &events {
        if record.actor_id != actor {
            continue;
        }
        if !event_visible_to_session(state, record, &session).await {
            continue;
        }
        if best.as_ref().is_none_or(|(seq, _)| record.actor_seq > *seq) {
            best = Some((record.actor_seq, record.event_id.clone()));
        }
    }
    let Some((actor_seq, event_id)) = best else {
        // Same code regardless of "unknown actor" vs "nothing visible":
        // private DIDs must not leak through the frontier surface.
        return Err(AppError::not_found("no visible events for actor"));
    };
    let actor_id =
        Did::new(actor).map_err(|_| AppError::invalid_param("actor_id must be a valid DID"))?;
    let event_id =
        EventId::new(event_id).map_err(|_| AppError::internal("stored event_id is invalid"))?;
    crate::result::json_ok(EventsFrontierAccountClientState {
        frontier: EventsFrontierView::Actor(ActorFrontierView {
            actor_id,
            actor_seq,
            event_id,
        }),
        receipts: Vec::new(),
    })
}
