use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.read.search_organizations",
    tags("spaces")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.find.directory.read.search_organizations.v1")
)]
pub(super) async fn search_organizations(
    body: JsonBody<DirectorySearchOrganizationsRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryOrganizationSearchOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let organization = demo_organization(&realm_refs, state.service_id());
    if state.config().development_mode && query_matches(&organization, body.query.as_deref()) {
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

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.read.resolve_organization",
    tags("spaces")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.find.directory.read.resolve_organization.v1")
)]
pub(super) async fn resolve_organization(
    body: JsonBody<DirectoryResolveOrganizationRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryOrganizationResolutionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.organization_id.is_none() && body.handle.is_none() {
        return Err(AppError::param_missing(
            "organization_id or handle is required",
        ));
    }
    // This family has no originator wire field, so the signer identity is
    // borne only by `verification_method` (`discovery-directory.md` §9.0.1).
    if !super::requester_proof::directory_requester_proofs_verified(
        state,
        &body.proofs,
        None,
        |proof| body.proof_binding_bytes(proof).ok(),
    )
    .await
    {
        return Err(AppError::not_found("not found"));
    }
    organizations::refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(organization) = organizations::organization_records_for_directory(state)
        .into_iter()
        .find(|organization| {
            body.organization_id
                .as_ref()
                .is_some_and(|did| organization["organization_id"].as_str() == Some(did.as_str()))
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
    if !state.config().development_mode {
        return Err(AppError::not_found("not found"));
    }

    let realm_entries = live_realm_entries(state).await;
    let realm_refs: Vec<&RealmDirectoryEntry> = realm_entries.iter().collect();
    let organization = demo_organization(&realm_refs, state.service_id());
    let matches_id = body.organization_id.as_ref().is_some_and(|did| {
        did.as_str() == organization["organization_id"].as_str().unwrap_or_default()
            || did.as_str() == state.service_id()
    });
    let matches_handle = body
        .handle
        .as_deref()
        .is_some_and(|handle| handle.eq_ignore_ascii_case("@arkret-demo"));
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
