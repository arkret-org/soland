use super::*;

#[endpoint(
    operation_id = "ck.find.directory.query.search_organizations",
    tags("directory"),
    summary = "Fuzzy-text search across known organizations (demo data for now)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.search_organizations"))]
pub(super) async fn search_organizations(
    body: JsonBody<DirectorySearchOrganizationsRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryOrganizationSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    organizations::refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut results = organizations::organization_records_for_directory(state)
        .into_iter()
        .filter(|organization| query_matches(organization, body.query.as_deref()))
        .collect::<Vec<_>>();
    let realm_entries = live_realm_entries(state).await;
    let realm_refs: Vec<&RealmDirectoryEntry> = realm_entries.iter().collect();
    let organization = demo_organization(&realm_refs, &state.config.service_did);
    if state.config.development_mode && query_matches(&organization, body.query.as_deref()) {
        results.push(organization);
    }
    let has_more = results.len() > limit;
    json_ok(DirectoryOrganizationSearchOutcome {
        organizations: results
            .into_iter()
            .take(limit)
            .map(|organization| organization_preview_from_value(&organization, state))
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor: None,
        has_more,
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_organization",
    tags("directory"),
    summary = "Resolve an organization by organization_id or handle"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_organization"))]
pub(super) async fn resolve_organization(
    body: JsonBody<DirectoryResolveOrganizationRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryOrganizationResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.organization_did.is_none() && body.handle.is_none() {
        return Err(AppError::missing_param(
            "organization_did or handle is required",
        ));
    }
    organizations::refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(organization) = organizations::organization_records_for_directory(state)
        .into_iter()
        .find(|organization| {
            body.organization_did
                .as_ref()
                .is_some_and(|did| organization["organization_did"].as_str() == Some(did.as_str()))
                || body.handle.as_deref().is_some_and(|handle| {
                    organization["handle"]
                        .as_str()
                        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(handle))
                })
        })
    {
        let associated_realms: Vec<Value> = organization["realms"]
            .as_array()
            .into_iter()
            .flat_map(|array| array.iter())
            .filter_map(Value::as_str)
            .map(|realm_id| json!({ "realm_id": realm_id }))
            .collect();
        return json_ok(DirectoryOrganizationResolutionOutcome {
            organization_preview: organization_preview_with_spaces(
                &organization,
                associated_realms,
                state,
            )?,
            did_document_ref: None,
            endorsements: Vec::new(),
        });
    }
    if !state.config.development_mode {
        return Err(AppError::not_found("not found"));
    }

    let realm_entries = live_realm_entries(state).await;
    let realm_refs: Vec<&RealmDirectoryEntry> = realm_entries.iter().collect();
    let organization = demo_organization(&realm_refs, &state.config.service_did);
    let matches_id = body.organization_did.as_ref().is_some_and(|did| {
        did.as_str()
            == organization["organization_did"]
                .as_str()
                .unwrap_or_default()
            || did.as_str() == state.config.service_did
    });
    let matches_handle = body
        .handle
        .as_deref()
        .is_some_and(|handle| handle.eq_ignore_ascii_case("@cokret-demo"));
    if !matches_id && !matches_handle {
        return Err(AppError::not_found("not found"));
    }

    let associated_realms: Vec<Value> = realm_entries
        .into_iter()
        .map(|realm_entry| {
            json!({
                "realm_id": realm_entry.realm_id,
                "title": realm_entry.title,
                "description": realm_entry.description,
                "category": realm_entry.category,
            })
        })
        .collect();
    json_ok(DirectoryOrganizationResolutionOutcome {
        organization_preview: organization_preview_with_spaces(
            &organization,
            associated_realms,
            state,
        )?,
        did_document_ref: None,
        endorsements: Vec::new(),
    })
}
