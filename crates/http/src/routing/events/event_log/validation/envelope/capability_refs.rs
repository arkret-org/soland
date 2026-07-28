use super::*;

/// Verify a DataEvent's authorization against the accepted governance basis at
/// its `seal_ref`.
///
/// `event-auth-state-resolution.md` §4.1(3) / §4.3(2): the verifier resolves
/// every capability the `kind`, the scope and the receiver-derived targets need
/// from the `seal_ref` governance state — **the producer does not select
/// candidate grants**. `event-and-patch.md` §2.2 states the same in the
/// negative: `effects` and producer-selected `auth_context.capability_refs` are
/// not v1 wire fields and a receiver MUST answer `schema_violation` when it
/// meets either.
///
/// So the two producer-supplied inputs this check used to read are refused
/// here, and what it reads instead is what v1 actually carries:
///
/// - `derived_cells` — the receiver's own registry projection of `kind + payload`
///   (`arkret_schema::project_registered_cell_writes`), which replaces the producer's `effects[]`
///   as the set the capability must cover;
/// - `refs[]` entries with `role=authorized_by` — semantic, non-authoritative citations that MUST
///   still resolve and be valid at `seal_ref`, exactly as `arkret_state`'s `verify_capability_refs`
///   requires of a Control Move.
pub(in crate::routing::events::event_log) fn validate_data_event_capability_refs(
    state: &AppState,
    actor_id: &str,
    realm_id: &str,
    kind: &str,
    object: &serde_json::Map<String, Value>,
    derived_cells: &[String],
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
    if object.contains_key("effects") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects is not a v1 Event Envelope field; reducer targets are derived from kind + payload",
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
    let seal_id = arkret_identifiers::SealId::new(seal_ref.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent seal_ref must be a valid ak:seal id",
        )
    })?;
    let realm = RealmId::new(realm_id.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent realm_id must be a valid ak:realm id",
        )
    })?;
    let auth_context = object
        .get("auth_context")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "DataEvent requires auth_context",
            )
        })?;
    if auth_context.contains_key("capability_refs") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "auth_context is closed over {did, key_id, key_epoch, credential_epoch}; effective capabilities are derived from the governance basis at seal_ref",
        ));
    }
    if derived_cells.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "DataEvent derives no data-plane write from its registered reducer contract",
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

    // `refs[role=authorized_by]` is a critical semantic citation, not a
    // capability selector: it never widens the effective set, but an entry that
    // does not resolve to a live grant at `seal_ref` MUST fail the Event closed
    // (`event-and-patch.md` §2.2 — unrecognized critical refs fail closed;
    // `arkret_state::verify_capability_refs` applies the same rule on the
    // control plane).
    for reference in data_event_authorized_by_refs(object)? {
        let grant_id = reference.as_str();
        if crate::ids::parse_typed_uuid(grant_id, "grant").is_none() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent refs[role=authorized_by] {grant_id} is not a valid ak:grant id"),
            ));
        }
        let stored = historical_grants.get(grant_id).ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} is not projected at seal_ref"),
            )
        })?;
        if crate::authz::grant_revoked_upstream(&historical_snapshot, grant_id, auth_time) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                arkret_wire::ReasonCode::GRANT_REVOKED_UPSTREAM,
                format!("DataEvent authorized_by grant {grant_id} was revoked upstream"),
            ));
        }
        if stored.revoked {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} is revoked"),
            ));
        }
        if stored.subject != actor_id || stored.realm_id != realm_id {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} does not cover actor/realm"),
            ));
        }
        if crate::authz::grant_scope_valid(stored).is_err() {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} has invalid scope"),
            ));
        }
        validate_data_event_joined_capability_view(state, realm_id, grant_id)?;
        if !effective_by_id.contains_key(grant_id) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("DataEvent authorized_by grant {grant_id} is expired or delegation-broken"),
            ));
        }
    }

    // Coverage is decided over the whole effective set the governance basis
    // yields for this actor, never over a producer-chosen subset, and over the
    // cells the receiver itself derived, never over a producer-chosen write
    // list.
    for cell in derived_cells {
        if !effective_by_id
            .values()
            .any(|grant| grant_covers_data_event_effect(state, grant, kind, realm_id, cell))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                format!("no capability at seal_ref covers action {kind} on derived cell {cell}"),
            ));
        }
    }
    Ok(())
}

/// `refs[]` entries carrying `role=authorized_by`.
///
/// `refs[]` is a required envelope member whose items are `SemanticRef`
/// objects; a malformed entry is a schema violation rather than a silently
/// skipped ref.
fn data_event_authorized_by_refs(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<String>, EventValidationError> {
    let Some(refs) = object.get("refs") else {
        return Ok(Vec::new());
    };
    let refs = refs.as_array().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "refs must be an array of SemanticRef objects",
        )
    })?;
    let mut authorized_by = Vec::new();
    for reference in refs {
        let reference = reference.as_object().ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "refs[] entries must be SemanticRef objects",
            )
        })?;
        if reference.get("role").and_then(Value::as_str)
            != Some(arkret_wire::event_envelope::EVENT_REF_ROLE_AUTHORIZED_BY)
        {
            continue;
        }
        let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "refs[] entries require id",
            )
        })?;
        authorized_by.push(id.to_owned());
    }
    Ok(authorized_by)
}

pub(super) fn validate_data_event_joined_capability_view(
    state: &AppState,
    realm_id: &str,
    grant_id: &str,
) -> Result<(), EventValidationError> {
    let cell_ref = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
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
            "DataEvent realm_id must be a valid ak:realm id",
        )
    })?;
    let leaves = state
        .projections()
        .realm_seal_leaves(&realm)
        .map_err(|error| {
            event_validation_error(
                StatusCode::PRECONDITION_FAILED,
                "stale_seal_ref",
                format!("DataEvent joined control leaves unavailable: {error}"),
            )
        })?;
    if !leaves.is_empty() {
        let joined_state = state
            .projections()
            .effective_state_at(&leaves, &realm)
            .map_err(|error| {
                event_validation_error(
                    StatusCode::PRECONDITION_FAILED,
                    "stale_seal_ref",
                    format!("DataEvent joined control view could not be resolved: {error}"),
                )
            })?;
        match joined_state.get(&cell_ref) {
            Some(arkret_state::lattice::CellState::Bottom(_)) => {
                return Err(event_validation_error(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_bottom",
                    "capability cell is bottom in joined control view",
                ));
            }
            Some(cell_state) => {
                let joined_grants = data_event_grants_from_state_at_ref(&joined_state);
                let current = soland_services::projection::engine_grant_from_capability_cell_state(
                    grant_id, cell_state,
                )
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
    seal_id: &arkret_identifiers::SealId,
) -> Result<
    std::collections::BTreeMap<arkret_identifiers::CellRef, arkret_state::lattice::CellState>,
    EventValidationError,
> {
    let seal = state.projections().seal_by_id(seal_id).map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            format!("DataEvent seal_ref lookup failed: {error}"),
        )
    })?;
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

    let state_at_ref = state
        .projections()
        .effective_state_at(std::slice::from_ref(seal_id), realm)
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
    state_at_ref: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
) -> std::collections::BTreeMap<String, crate::authz::Grant> {
    let mut grants = std::collections::BTreeMap::new();
    const CAPABILITY_GRANT_CELL_PREFIX: &str = "ak:cell:ak.component.capability.grant.v1:";
    for (cell_ref, cell_state) in state_at_ref {
        let Some(grant_id) = cell_ref.as_str().strip_prefix(CAPABILITY_GRANT_CELL_PREFIX) else {
            continue;
        };
        if crate::ids::parse_typed_uuid(grant_id, "grant").is_none() {
            continue;
        }
        if let Some(grant) = soland_services::projection::engine_grant_from_capability_cell_state(
            grant_id, cell_state,
        ) {
            grants.insert(grant_id.to_owned(), grant);
        }
    }
    grants
}

pub(super) fn validate_data_event_covered_seals(
    realm: &RealmId,
    seal_id: &arkret_identifiers::SealId,
    object: &serde_json::Map<String, Value>,
    state_at_ref: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
) -> Result<(), EventValidationError> {
    if !data_event_payload_is_mls_e2ee(object) {
        return Ok(());
    }
    if seal_view_declares_relaxed_e2ee(realm, state_at_ref) {
        return Ok(());
    }

    let covered_cell =
        arkret_state::mls_move::covered_seals_cell_id(realm.as_str()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("DataEvent covered_seals cell id failed: {error}"),
            )
        })?;
    let Some(arkret_state::lattice::CellState::Value(cell_value)) = state_at_ref.get(&covered_cell)
    else {
        return Err(data_event_covered_seals_failed_precondition(
            "covered_seals_cell is missing at seal_ref",
        ));
    };
    let required_governance_seals = std::slice::from_ref(seal_id);
    if required_governance_seals
        .iter()
        .all(|required| arkret_state::mls_move::covered_seals_contains(cell_value, required))
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
    let code = arkret_wire::ErrorCode::FailedPrecondition;
    event_validation_error(
        error_http_status(code),
        code.as_str(),
        format!(
            "{}: {}",
            arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
            message.into()
        ),
    )
}

pub(super) fn data_event_payload_is_mls_e2ee(object: &serde_json::Map<String, Value>) -> bool {
    let Some(payload) = object.get("payload") else {
        return false;
    };
    encrypted_content_is_mls_e2ee(payload.get("encrypted_content"))
        || payload
            .get("object")
            .is_some_and(|object| encrypted_content_is_mls_e2ee(object.get("encrypted_content")))
}

/// Both MLS-backed content schemes are gated by `covered_seals_cell`.
///
/// `encryption-and-audit.md` §2.5 phrases the gate over "E2EE application
/// DataEvent", not over one scheme: `mls_exporter_aead_v1` derives its content
/// key from the same MLS key schedule as `mls_rfc9420`, so a ban / revoke that
/// has not reached `covered_seals_cell` is just as invisible to it.
pub(super) fn encrypted_content_is_mls_e2ee(value: Option<&Value>) -> bool {
    matches!(
        value
            .and_then(|value| value.get("scheme"))
            .and_then(Value::as_str),
        Some("mls_rfc9420" | "mls_exporter_aead_v1")
    )
}

pub(super) fn seal_view_declares_relaxed_e2ee(
    _realm: &RealmId,
    state_at_ref: &std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        arkret_state::lattice::CellState,
    >,
) -> bool {
    let Ok(policy_cell) = arkret_identifiers::CellRef::new(
        "ak:cell:ak.component.realm.policy_bundle.v1:null".to_owned(),
    ) else {
        return false;
    };
    let Some(arkret_state::lattice::CellState::Value(policy_bundle)) =
        state_at_ref.get(&policy_cell)
    else {
        return false;
    };
    policy_bundle_declare_relaxed_e2ee(policy_bundle_value_from_state_payload(policy_bundle))
}

pub(super) fn policy_bundle_declare_relaxed_e2ee(policy_bundle: &Value) -> bool {
    profile_array_contains(policy_bundle.get("profiles"), E2EE_RELAXED_PROFILE)
        || profile_array_contains(policy_bundle.get("active_profiles"), E2EE_RELAXED_PROFILE)
        || profile_array_contains(
            policy_bundle.pointer("/components/profiles"),
            E2EE_RELAXED_PROFILE,
        )
        || profile_array_contains(
            policy_bundle.pointer("/components/active_profiles"),
            E2EE_RELAXED_PROFILE,
        )
        || policy_bundle
            .pointer("/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some(E2EE_RELAXED_PROFILE)
        || policy_bundle
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
    grant.actions.iter().any(|candidate| {
        candidate == action
            || arkret_schema::capability_action(candidate).is_some_and(|descriptor| {
                descriptor.event_mapping_kind != "non_event_surface"
                    && descriptor
                        .target_event_kinds
                        .iter()
                        .any(|target| *target == action)
            })
    }) && effect_resource_candidates(state, cell, realm_id)
        .iter()
        .any(|resource| crate::authz::resource_matches(&grant.resource, resource))
}

pub(super) fn effect_resource_candidates(
    state: &AppState,
    cell: &str,
    realm_id: &str,
) -> Vec<String> {
    let mut resources = Vec::new();
    let projection = state.projections().snapshot();
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, cell);
    let mut parts = cell.splitn(4, ':');
    if matches!(parts.next(), Some("ak"))
        && matches!(parts.next(), Some("cell"))
        && parts.next().is_some()
        && let Some(subject) = parts.next()
        && (subject.starts_with("ak:") || subject.starts_with("did:"))
    {
        append_authz_resource_candidates(&mut resources, Some(&projection), realm_id, subject);
    }
    resources.sort();
    resources.dedup();
    resources
}

pub(super) fn append_authz_resource_candidates(
    resources: &mut Vec<String>,
    projection: Option<&soland_services::projection::ProjectionSnapshot>,
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
