use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.search_actors", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.search_actors.v1"))]
pub(super) async fn search_actors(
    body: JsonBody<DirectorySearchActorsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryActorSearchOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    if let Some(organization_principal_id) = body.organization_principal_id.as_ref()
        && organization_principal_id.as_str() != state.service_id()
    {
        return json_ok(DirectoryActorSearchOutcome {
            actors: Vec::new(),
            next_cursor: None,
            has_more: false,
        });
    }

    let session = authenticated_session(state, req).await.ok();
    let mut results: Vec<ActorPreview> = Vec::new();
    for actor in demo_actors(state).await {
        if results.len() > limit {
            break;
        }
        if actor_visible_to(state, &actor, session.as_ref()).await
            && query_matches(&actor, body.query.as_deref())
        {
            results.push(actor_preview_from_value(&actor)?);
        }
    }
    let has_more = results.len() > limit;
    if has_more {
        results.truncate(limit);
    }
    json_ok(DirectoryActorSearchOutcome {
        actors: results,
        next_cursor: None,
        has_more,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.search_users", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.search_users.v1"))]
pub(super) async fn search_users(
    body: JsonBody<DirectorySearchUsersRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryUserSearchOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    let query = body.query;
    let session = authenticated_session(state, req).await.ok();
    // DIR-1 (R3.1, arkret-spec @ 7157ee8) — `ak.find.directory.read.search_users.v1`
    // response rows MUST NOT carry `handle_uri`. Only `handle` (canonical
    // `<localpart>:<domain>`) + optional `display_name`/`verified`/`subject`
    // survive the rename. Other actor metadata (presence, organization,
    // avatar) goes through `ak.find.directory.read.search_actors.v1` or
    // `ak.directory.resolve-handle`.
    let mut results: Vec<UserSearchOutcome> = Vec::new();
    for actor in demo_actors(state).await {
        if results.len() > limit {
            break;
        }
        if actor_visible_to(state, &actor, session.as_ref()).await
            && query_matches(&actor, Some(query.as_str()))
        {
            results.push(project_search_users_row(state, &actor)?);
        }
    }
    let has_more = results.len() > limit;
    if has_more {
        results.truncate(limit);
    }
    json_ok(DirectoryUserSearchOutcome {
        users: results,
        next_cursor: None,
        has_more,
    })
}

/// DIR-1 — project a [`demo_actors`] row into the spec-shape
/// `ak.find.directory.read.search_users.v1` response entry. Only `handle` (canonical
/// `<localpart>:<domain>` per handle-claim.schema.json, arkret-spec @
/// 7157ee8) + optional `display_name`/`verified`/`subject` survive.
pub(super) fn project_search_users_row(
    state: &AppState,
    actor: &Value,
) -> Result<UserSearchOutcome, AppError> {
    let service_domain = service_handle_domain(state);
    let canonical = actor
        .get("handle")
        .and_then(Value::as_str)
        .and_then(|handle| canonicalize_handle_for_service(handle, &service_domain))
        .unwrap_or_default();
    let principal_id = actor
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("directory user search row missing actor_id"))?;
    Ok(UserSearchOutcome {
        handle: (!canonical.is_empty()).then_some(canonical),
        principal_id: Some(directory_actor_core_id(principal_id)?),
        display_name: actor
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        avatar_blob_ref: None,
        membership: None,
        verified: actor.get("verified").and_then(Value::as_bool),
        member_delivery_binding: None,
    })
}
