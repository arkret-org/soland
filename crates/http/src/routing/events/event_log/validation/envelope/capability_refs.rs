/// Expand one authorization resource through the current committed reducer
/// projection. Callers deduplicate the aggregate candidate list.
pub(super) fn append_authz_resource_candidates(
    resources: &mut Vec<String>,
    projection: Option<&soland_domain::reducer::ProjectionState>,
    realm_id: &str,
    resource: &str,
) {
    resources.push(resource.to_owned());
    if let Some(projection) = projection {
        for candidate in projection
            .authz_resource_expr(realm_id, resource)
            .split(',')
        {
            let candidate = candidate.trim();
            if !candidate.is_empty() {
                resources.push(candidate.to_owned());
            }
        }
    }
}
