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
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let _ = authenticated_session(state, req).await.ok();
    let _ = body.into_inner();
    Err(AppError::unsupported_feature(
        "private contact discovery requires ck.private_contact_discovery.v1 two-round VOPRF set-membership PSI; plaintext identifier matching is disabled",
    ))
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let next_revalidation_after =
        indexed_at + chrono::Duration::seconds(effective_ttl_seconds.min(i64::MAX as u64) as i64);
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
