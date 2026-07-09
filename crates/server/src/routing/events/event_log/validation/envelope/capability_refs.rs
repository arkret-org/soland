use super::*;

pub(in crate::routing::events::event_log) fn validate_data_event_capability_refs(
    state: &AppState,
    actor_id: &str,
    realm_id: &str,
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let is_data_event = object.contains_key("seal_ref") || object.contains_key("auth_context");
    if !is_data_event {
        return Ok(());
    }
    if object.contains_key("seal_basis") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent must not carry seal_basis",
        ));
    }
    let seal_ref = object
        .get("seal_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent requires seal_ref to resolve the authorization pre-state",
            )
        })?;
    let seal_id = cokret_sdk::SealId::new(seal_ref.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent seal_ref must be a valid ck:seal id",
        )
    })?;
    let realm = RealmId::new(realm_id.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent realm_id must be a valid ck:realm id",
        )
    })?;
    let effects = object
        .get("effects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent requires effects[] to verify capability coverage",
            )
        })?;
    if effects.is_empty() {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "DataEvent effects[] must be non-empty for capability coverage",
        ));
    }
    let auth_context = object
        .get("auth_context")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent requires auth_context.capability_refs[]",
            )
        })?;
    let refs = auth_context
        .get("capability_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent requires auth_context.capability_refs[]",
            )
        })?;
    if refs.is_empty() {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "DataEvent capability_refs[] must be non-empty",
        ));
    }

    let state_at_ref = data_event_state_at_seal_ref(state, &realm, &seal_id)?;
    validate_data_event_covered_seals(&realm, &seal_id, object, &state_at_ref)?;
    let historical_grants = data_event_grants_from_state_at_ref(&state_at_ref);
    let auth_time = data_event_auth_time(object);
    let historical_snapshot: Vec<crate::authz::Grant> =
        historical_grants.values().cloned().collect();
    let effective_by_id =
        effective_historical_grants_for_subject(&historical_grants, actor_id, realm_id, auth_time);
    let mut referenced = Vec::with_capacity(refs.len());
    for value in refs {
        let grant_id = value.as_str().ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent capability_refs[] entries must be grant ids",
            )
        })?;
        if crate::ids::parse_typed_uuid(grant_id, "grant").is_none() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "DataEvent capability_refs[] entry is not a valid ck:grant id",
            ));
        }
        let stored = historical_grants.get(grant_id).ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent capability_ref {grant_id} is not projected at seal_ref"),
            )
        })?;
        if crate::authz::grant_revoked_upstream(&historical_snapshot, grant_id, auth_time) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                crate::authz::REASON_GRANT_REVOKED_UPSTREAM,
                format!("DataEvent capability_ref {grant_id} was revoked upstream"),
            ));
        }
        if stored.revoked {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent capability_ref {grant_id} is revoked"),
            ));
        }
        if stored.subject != actor_id || stored.realm_id != realm_id {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent capability_ref {grant_id} does not cover actor/realm"),
            ));
        }
        if crate::authz::grant_scope_valid(stored).is_err() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent capability_ref {grant_id} has invalid scope"),
            ));
        }
        validate_data_event_joined_capability_view(state, realm_id, grant_id)?;
        let Some(effective) = effective_by_id.get(grant_id) else {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent capability_ref {grant_id} is expired or delegation-broken"),
            ));
        };
        referenced.push(effective.clone());
    }

    for effect in effects {
        let cell = effect.get("cell").and_then(Value::as_str).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "DataEvent effects[] entries require cell",
            )
        })?;
        if !referenced
            .iter()
            .any(|grant| grant_covers_data_event_effect(state, grant, kind, realm_id, cell))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!(
                    "DataEvent capability_refs[] do not cover action {kind} on effect cell {cell}"
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_data_event_joined_capability_view(
    state: &AppState,
    realm_id: &str,
    grant_id: &str,
) -> Result<(), EventValidationError> {
    let cell_ref = cokret_sdk::CellRef::new(format!(
        "ak:cell:ck.component.capability.grant.v1:{grant_id}"
    ))
    .map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent capability_ref could not be mapped to a capability cell",
        )
    })?;
    let realm = RealmId::new(realm_id.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent realm_id must be a valid ck:realm id",
        )
    })?;
    let leaves = state.seal_store.list_leaves(&realm).map_err(|error| {
        event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            "stale_seal_ref",
            format!("DataEvent joined control leaves unavailable: {error}"),
        )
    })?;
    if !leaves.is_empty() {
        let joined_state = cokret_sdk::state_res::effective_state_at(
            &leaves,
            &realm,
            state.seal_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
        )
        .map_err(|error| {
            event_validation_error(
                StatusCode::PRECONDITION_FAILED,
                "stale_seal_ref",
                format!("DataEvent joined control view could not be resolved: {error}"),
            )
        })?;
        match joined_state.get(&cell_ref) {
            Some(cokret_sdk::lattice::CellState::Bottom(_)) => {
                return Err(event_validation_error(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_bottom",
                    "capability cell is bottom in joined control view",
                ));
            }
            Some(cell_state) => {
                let joined_grants = data_event_grants_from_state_at_ref(&joined_state);
                let current =
                    crate::reducer::engine_grant_from_capability_cell_state(grant_id, cell_state)
                        .or_else(|| joined_grants.get(grant_id).cloned());
                let Some(current) = current else {
                    return Err(event_validation_error(
                        StatusCode::PRECONDITION_FAILED,
                        "stale_seal_ref",
                        format!(
                            "DataEvent capability_ref {grant_id} is absent from joined control view"
                        ),
                    ));
                };
                let snapshot: Vec<crate::authz::Grant> = joined_grants.values().cloned().collect();
                if current.revoked
                    || crate::authz::grant_revoked_upstream(&snapshot, grant_id, chrono::Utc::now())
                {
                    return Err(event_validation_error(
                        StatusCode::PRECONDITION_FAILED,
                        "stale_seal_ref",
                        format!(
                            "DataEvent capability_ref {grant_id} is revoked in joined control view"
                        ),
                    ));
                }
            }
            None => {
                return Err(event_validation_error(
                    StatusCode::PRECONDITION_FAILED,
                    "stale_seal_ref",
                    format!(
                        "DataEvent capability_ref {grant_id} is missing from joined control view"
                    ),
                ));
            }
        }
    }
    // DataEvent authorization MUST be evaluated against the seal_ref pre-state
    // (the joined control view resolved from sealed leaves above), never the
    // live authz index or live projection. A grant that was valid in the sealed
    // pre-state but later revoked in the live index must still authorize the
    // historical DataEvent. Upstream steps already reject grants revoked within
    // the seal_ref pre-state, so no live-plane fallback is applied here.
    Ok(())
}

pub(super) fn data_event_state_at_seal_ref(
    state: &AppState,
    realm: &RealmId,
    seal_id: &cokret_sdk::SealId,
) -> Result<
    std::collections::BTreeMap<cokret_sdk::CellRef, cokret_sdk::lattice::CellState>,
    EventValidationError,
> {
    let seal = cokret_sdk::state_res::SealStore::get(state.seal_store.as_ref(), seal_id).map_err(
        |error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent seal_ref lookup failed: {error}"),
            )
        },
    )?;
    let Some(seal) = seal else {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "DataEvent seal_ref is not projected",
        ));
    };
    if seal.realm_id != *realm {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "DataEvent seal_ref does not belong to the event realm",
        ));
    }

    let state_at_ref = cokret_sdk::state_res::effective_state_at(
        std::slice::from_ref(seal_id),
        realm,
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            format!("DataEvent seal_ref pre-state could not be resolved: {error}"),
        )
    })?;

    Ok(state_at_ref)
}

pub(super) fn data_event_grants_from_state_at_ref(
    state_at_ref: &std::collections::BTreeMap<cokret_sdk::CellRef, cokret_sdk::lattice::CellState>,
) -> std::collections::BTreeMap<String, crate::authz::Grant> {
    let mut grants = std::collections::BTreeMap::new();
    const CAPABILITY_GRANT_CELL_PREFIX: &str = "ak:cell:ck.component.capability.grant.v1:";
    for (cell_ref, cell_state) in state_at_ref {
        let Some(grant_id) = cell_ref.as_str().strip_prefix(CAPABILITY_GRANT_CELL_PREFIX) else {
            continue;
        };
        if crate::ids::parse_typed_uuid(grant_id, "grant").is_none() {
            continue;
        }
        if let Some(grant) =
            crate::reducer::engine_grant_from_capability_cell_state(grant_id, cell_state)
        {
            grants.insert(grant_id.to_owned(), grant);
        }
    }
    grants
}

pub(super) fn validate_data_event_covered_seals(
    realm: &RealmId,
    seal_id: &cokret_sdk::SealId,
    object: &serde_json::Map<String, Value>,
    state_at_ref: &std::collections::BTreeMap<cokret_sdk::CellRef, cokret_sdk::lattice::CellState>,
) -> Result<(), EventValidationError> {
    if !data_event_payload_is_mls_e2ee(object) {
        return Ok(());
    }
    if seal_view_declares_relaxed_e2ee(realm, state_at_ref) {
        return Ok(());
    }

    let covered_cell = cokret_sdk::mls_move::covered_seals_cell_id(realm).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("DataEvent covered_seals cell id failed: {error}"),
        )
    })?;
    let Some(cokret_sdk::lattice::CellState::Value(cell_value)) = state_at_ref.get(&covered_cell)
    else {
        return Err(data_event_covered_seals_failed_precondition(
            "covered_seals_cell is missing at seal_ref",
        ));
    };
    let required_governance_seals = std::slice::from_ref(seal_id);
    if required_governance_seals
        .iter()
        .all(|required| cokret_sdk::mls_move::covered_seals_contains(cell_value, required))
    {
        return Ok(());
    }
    Err(data_event_covered_seals_failed_precondition(format!(
        "covered_seals_cell does not contain DataEvent seal_ref {}",
        seal_id.as_str()
    )))
}

pub(super) fn data_event_covered_seals_failed_precondition(
    message: impl Into<String>,
) -> EventValidationError {
    let code = cokret_sdk::ErrorCode::FailedPrecondition;
    event_validation_error(
        error_http_status(code),
        code.as_str(),
        format!(
            "{}: {}",
            cokret_sdk::REASON_MLS_GOVERNANCE_BINDING_STALE,
            message.into()
        ),
    )
}

pub(super) fn data_event_payload_is_mls_e2ee(object: &serde_json::Map<String, Value>) -> bool {
    let Some(payload) = object.get("payload") else {
        return false;
    };
    encrypted_content_is_mls(payload.get("encrypted_content"))
        || payload
            .get("object")
            .is_some_and(|object| encrypted_content_is_mls(object.get("encrypted_content")))
}

pub(super) fn encrypted_content_is_mls(value: Option<&Value>) -> bool {
    value
        .and_then(|value| value.get("scheme"))
        .and_then(Value::as_str)
        == Some("mls-rfc9420")
}

pub(super) fn seal_view_declares_relaxed_e2ee(
    realm: &RealmId,
    state_at_ref: &std::collections::BTreeMap<cokret_sdk::CellRef, cokret_sdk::lattice::CellState>,
) -> bool {
    let Ok(policy_cell) = cokret_sdk::CellRef::new(format!(
        "ak:cell:ck.component.realm.policy_components.v1:{}",
        realm.as_str()
    )) else {
        return false;
    };
    let Some(cokret_sdk::lattice::CellState::Value(policy_components)) =
        state_at_ref.get(&policy_cell)
    else {
        return false;
    };
    policy_components_declare_relaxed_e2ee(policy_components_value_from_state_payload(
        policy_components,
    ))
}

pub(super) fn policy_components_declare_relaxed_e2ee(policy_components: &Value) -> bool {
    profile_array_contains(policy_components.get("profiles"), E2EE_RELAXED_PROFILE)
        || profile_array_contains(
            policy_components.get("active_profiles"),
            E2EE_RELAXED_PROFILE,
        )
        || profile_array_contains(
            policy_components.pointer("/components/profiles"),
            E2EE_RELAXED_PROFILE,
        )
        || profile_array_contains(
            policy_components.pointer("/components/active_profiles"),
            E2EE_RELAXED_PROFILE,
        )
        || policy_components
            .pointer("/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some(E2EE_RELAXED_PROFILE)
        || policy_components
            .pointer("/components/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some(E2EE_RELAXED_PROFILE)
}

pub(super) fn profile_array_contains(value: Option<&Value>, profile: &str) -> bool {
    value.and_then(Value::as_array).is_some_and(|profiles| {
        profiles
            .iter()
            .any(|candidate| candidate.as_str() == Some(profile))
    })
}

pub(super) fn effective_historical_grants_for_subject(
    grants: &std::collections::BTreeMap<String, crate::authz::Grant>,
    actor_id: &str,
    realm_id: &str,
    auth_time: chrono::DateTime<chrono::Utc>,
) -> std::collections::BTreeMap<String, crate::authz::Grant> {
    let snapshot: Vec<crate::authz::Grant> = grants.values().cloned().collect();
    snapshot
        .iter()
        .filter(|grant| {
            grant.subject == actor_id
                && grant.realm_id == realm_id
                && !grant.revoked
                && crate::authz::grant_scope_valid(grant).is_ok()
                && !crate::authz::is_grant_expired(grant, auth_time)
                && crate::authz::delegation_chain_intact(&snapshot, &grant.grant_id, auth_time)
        })
        .map(|grant| (grant.grant_id.clone(), grant.clone()))
        .collect()
}

pub(super) fn data_event_auth_time(
    object: &serde_json::Map<String, Value>,
) -> chrono::DateTime<chrono::Utc> {
    object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now)
}

pub(super) fn grant_covers_data_event_effect(
    state: &AppState,
    grant: &crate::authz::Grant,
    action: &str,
    realm_id: &str,
    cell: &str,
) -> bool {
    grant.actions.iter().any(|candidate| candidate == action)
        && effect_resource_candidates(state, cell, realm_id)
            .iter()
            .any(|resource| crate::authz::resource_matches(&grant.resource, resource))
}

pub(super) fn effect_resource_candidates(
    state: &AppState,
    cell: &str,
    realm_id: &str,
) -> Vec<String> {
    let mut resources = Vec::new();
    let projection = state.projection.lock();
    append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, cell);
    let mut parts = cell.splitn(4, ':');
    if matches!(parts.next(), Some("ck"))
        && matches!(parts.next(), Some("cell"))
        && parts.next().is_some()
        && let Some(subject) = parts.next()
        && (subject.starts_with("ak:") || subject.starts_with("did:"))
    {
        append_authz_resource_candidates(&mut resources, Some(&*projection), realm_id, subject);
    }
    resources.sort();
    resources.dedup();
    resources
}

pub(super) fn append_authz_resource_candidates(
    resources: &mut Vec<String>,
    projection: Option<&crate::reducer::ProjectionState>,
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
