use super::*;

#[endpoint(
    operation_id = "ck.find.directory.query.private_contact_discovery",
    tags("directory"),
    summary = "Privacy-preserving contact discovery over padded identifier batches"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.find.directory.query.private_contact_discovery")
)]
pub(super) async fn private_contact_discovery(
    body: JsonBody<DirectoryPrivateContactDiscoveryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryPrivateContactDiscoveryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let session = authenticated_session(state, req).await.ok();
    let body = body.into_inner();
    let contacts = body.contacts;
    let mut visible: Vec<Value> = Vec::new();
    for actor in demo_actors(state).await {
        if actor_visible_to(state, &actor, session.as_ref()).await {
            visible.push(actor);
        }
    }
    // SEC-09 — the probing requester for the (requester, holder) rate limit /
    // audit dimension. Unauthenticated probes share a single conservative
    // `anonymous` bucket.
    let requester = session
        .as_ref()
        .map(|s| s.actor.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let mut matches = Vec::new();
    // SEC-09 — max client backoff across all rate-limited (requester, holder)
    // pairs in this batch.
    let mut retry_after_ms: u64 = 0;
    for contact in contacts {
        let needle = contact
            .get("identifier")
            .or_else(|| contact.get("handle"))
            .or_else(|| contact.get("did"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if needle.is_empty() {
            continue;
        }
        if let Some(actor) = visible.iter().find(|actor| {
            actor
                .get("did")
                .and_then(Value::as_str)
                .is_some_and(|did| did.eq_ignore_ascii_case(&needle))
                || actor
                    .get("handle")
                    .and_then(Value::as_str)
                    .is_some_and(|handle| handle.eq_ignore_ascii_case(&needle))
        }) {
            let holder = actor
                .get("did")
                .and_then(Value::as_str)
                .unwrap_or(&needle)
                .to_owned();
            // SEC-09 — rate-limit this (requester, holder) probe and record it
            // in the holder-auditable access log so the holder can later detect
            // repeated probing.
            let outcome = state.record_psi_probe(&requester, &holder);
            append_audit_log(
                state,
                Some(&holder),
                "psi_contact_discovery_probe",
                json!({
                    "requester": requester,
                    "probe_count": outcome.count,
                    "rate_limited": outcome.rate_limited,
                }),
                if outcome.rate_limited {
                    "rate_limited"
                } else {
                    "ok"
                },
            )
            .await;
            // SEC-09 — once a pair exceeds the window cap, withhold the fresh
            // match result (so high-frequency probing cannot read the holder's
            // hit-bit flip timing) and surface a backoff.
            if outcome.rate_limited {
                retry_after_ms = retry_after_ms.max(outcome.retry_after_ms.max(0) as u64);
                continue;
            }
            matches.push(json!({
                "contact_ref": contact.get("ref").cloned().unwrap_or(Value::Null),
                "did": actor.get("did").cloned().unwrap_or(Value::Null),
                "handle": actor.get("handle").cloned().unwrap_or(Value::Null),
                "proof": {
                    "type": "directory_private_contact_discovery_dev",
                    // SEC-09 — coarse hit bucket: the moment a holder's
                    // reachability bit flipped is floored to PSI_HIT_BUCKET_SECS
                    // rather than exposed at second resolution.
                    "issued_at": AppState::psi_bucket_timestamp(now()),
                }
            }));
        }
    }
    json_ok(DirectoryPrivateContactDiscoveryOutcome {
        matches,
        proofs: Vec::new(),
        retry_after_ms: (retry_after_ms > 0).then_some(retry_after_ms),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.command.announce",
    tags("directory"),
    summary = "Announce a discoverable directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.command.announce"))]
pub(super) async fn directory_announce(
    body: JsonBody<DirectoryAnnounceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryAnnounceOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            AppError::invalid_param(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    let body = body.into_inner();
    let resource_kind = directory_resource_kind_str(body.resource_kind);
    let resource_id = body.resource_id.as_str();
    if resource_kind == "realm"
        && !super::realm_has_member(state, resource_id, &session.actor).await
    {
        return Err(AppError::capability_denied(
            "directory announcement requires realm membership",
        ));
    }
    let announcement_id = format!(
        "ck:announcement:{}",
        super::sha256_hex(
            format!("{}:{}:{}", session.actor, resource_kind, resource_id).as_bytes()
        )
    );
    let indexed_at = now();
    let effective_ttl_seconds = body.ttl_seconds.unwrap_or(86_400);
    let next_revalidation_after = indexed_at.clone()
        + chrono::Duration::seconds(effective_ttl_seconds.min(i64::MAX as u64) as i64);
    json_ok(DirectoryAnnounceOutcome {
        announce_id: announcement_id,
        indexed_at,
        effective_ttl_seconds,
        next_revalidation_after,
        warnings: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.command.withdraw",
    tags("directory"),
    summary = "Withdraw a previously-announced directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.command.withdraw"))]
pub(super) async fn directory_withdraw(
    body: JsonBody<DirectoryWithdrawRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryWithdrawOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            AppError::invalid_param(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    let body = body.into_inner();
    let withdrawal_ref = format!(
        "ck:withdrawal:{}",
        super::sha256_hex(format!("{}:realm:{}", session.actor, body.resource_id).as_bytes())
    );
    json_ok(DirectoryWithdrawOutcome {
        withdrawal_ref,
        acked_at: now(),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.push.command.register",
    tags("directory"),
    summary = "Subscribe to directory update notifications"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.push.command.register"))]
pub(super) async fn directory_subscribe(
    body: JsonBody<DirectoryPushRegisterRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryPushRegisterOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = authenticated_session(state, req).await.ok();
    let body = body.into_inner();
    let _ = body;
    json_ok(DirectoryPushRegisterOutcome {
        subscription_id: ids::generate("directory_subscription"),
        effective_at: now(),
    })
}

pub(super) fn directory_resource_kind_str(kind: DirectoryResourceKind) -> &'static str {
    match kind {
        DirectoryResourceKind::Realm => "realm",
        DirectoryResourceKind::Organization => "organization",
        DirectoryResourceKind::Actor => "actor",
        DirectoryResourceKind::Applet => "applet",
        DirectoryResourceKind::Handle => "handle",
    }
}

// ── Helpers shared with the rest of `crate::routing` ───────────────────────
//
// These remain public for sibling routing modules that share directory
// authorization and visibility checks.

pub async fn has_accepted_contact(state: &AppState, left: &str, right: &str) -> bool {
    state
        .persistence
        .contacts()
        .list_for_actor(left)
        .await
        .unwrap_or_default()
        .iter()
        .any(|contact| {
            contact.status == "accepted"
                && ((contact.requester == left && contact.target == right)
                    || (contact.requester == right && contact.target == left))
        })
}

pub async fn actor_visible_to(
    state: &AppState,
    actor: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(did) = actor["did"].as_str() else {
        return false;
    };
    if did == "did:web:alice.example" {
        return true;
    }
    match session {
        Some(session) => {
            session.actor == did || has_accepted_contact(state, &session.actor, did).await
        }
        None => false,
    }
}
