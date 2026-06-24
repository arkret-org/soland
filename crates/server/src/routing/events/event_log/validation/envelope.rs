use super::super::*;
use super::audit::{validate_audit_accessed_payload, validate_strand_watch_audit_pair};
use super::enrollment::validate_device_enrollment_authority_binding;
use super::mls_governance::{
    projected_media_plaintext_service_present, projected_mls_governance_binding_covers_policy_root,
    projected_mls_governance_binding_metadata_digest,
};
use super::payload_shape::{
    validate_conflict_repair_event_payload, validate_event_audience_fields,
    validate_pre_schema_wire_shape, validate_realm_create_policy_constraints,
    validate_space_container_lifecycle_payload,
};

const E2EE_RELAXED_PROFILE: &str = "ck.profile.e2ee_relaxed.v1";
const LOCAL_EVENT_CRITICAL_FEATURES: [&str; 3] = [
    "ck.event_envelope.v1",
    "ck.profile.core_event_store.v1",
    "ck.proof.event_digest.v1",
];

pub(crate) fn canonical_json_hash(value: &Value) -> String {
    canonical::canonical_sha256(value).unwrap_or_else(|_| {
        let bytes = serde_json::to_vec(value).unwrap_or_default();
        cokret_sdk::canonical::sha256_digest(&bytes)
    })
}

fn event_digest_suite(
    state: &AppState,
    kind: &str,
    realm_id: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let suite = if kind == cokret_sdk::events::kinds::REALM_CREATE {
        realm_create_digest_algorithm(object)
    } else {
        state
            .projection
            .lock()
            .expect("projection lock")
            .realm_digest_algorithm(realm_id)
    }
    .unwrap_or_else(|| "sha256".to_owned());
    cokret_sdk::canonical::digest_suite(&suite)
        .map(|_| suite.clone())
        .map_err(|_| unsupported_digest_algorithm_error(&suite))
}

fn realm_create_digest_algorithm(object: &serde_json::Map<String, Value>) -> Option<String> {
    object
        .get("payload")
        .and_then(|payload| {
            payload
                .get("object")
                .and_then(|object| object.get("digest_algorithm"))
                .or_else(|| payload.get("digest_algorithm"))
        })
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn event_digest_for_suite(bytes: &[u8], suite: &str) -> Result<String, EventValidationError> {
    cokret_sdk::canonical::canonical_digest_with_suite(bytes, suite)
        .map_err(|_| unsupported_digest_algorithm_error(suite))
}

fn unsupported_digest_algorithm_error(suite: &str) -> EventValidationError {
    let code = cokret_sdk::ErrorCode::UnsupportedDigestAlgorithm;
    event_validation_error(
        error_http_status(code),
        code.as_str(),
        format!("unsupported digest algorithm: {suite}"),
    )
}

pub(crate) fn preflight_mls_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    match kind.as_str() {
        cokret_sdk::events::kinds::MLS_KEYPACKAGE
        | cokret_sdk::events::kinds::MLS_WELCOME
        | cokret_sdk::events::kinds::MLS_GENESIS
        | cokret_sdk::events::kinds::MLS_COMMIT => {
            let mut snapshot = proj.clone();
            let effect = match kind.as_str() {
                cokret_sdk::events::kinds::MLS_KEYPACKAGE => {
                    match operation.payload.get("action").and_then(Value::as_str) {
                        Some("publish") => {
                            crate::reducer::mls::apply_keypackage_publish(&mut snapshot, operation)
                        }
                        Some("claim") => {
                            crate::reducer::mls::apply_keypackage_claim(&mut snapshot, operation)
                        }
                        Some(other) => crate::reducer::ProjectionEffect::Rejected {
                            reason: format!("mls_keypackage_action_unknown:{other}"),
                        },
                        None => crate::reducer::ProjectionEffect::Rejected {
                            reason: "mls_keypackage_action_missing".to_owned(),
                        },
                    }
                }
                cokret_sdk::events::kinds::MLS_WELCOME => {
                    crate::reducer::mls::apply_welcome_enqueue(&mut snapshot, operation)
                }
                cokret_sdk::events::kinds::MLS_GENESIS => {
                    crate::reducer::mls::apply_group_genesis(&mut snapshot, operation)
                }
                cokret_sdk::events::kinds::MLS_COMMIT => {
                    crate::reducer::mls::apply_commit_epoch(&mut snapshot, operation)
                }
                _ => crate::reducer::ProjectionEffect::Ignored,
            };
            match effect {
                crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
                _ => None,
            }
        }
        _ => None,
    }
}

/// P2 — surface the moderation reducer's §5.5.2 fail-closed rejections at
/// ingest, mirroring [`preflight_mls_projection_reject`]. Runs the moderation
/// reducer against a clone of the live projection so the
/// separation-of-duties / overturn↔lift / modify↔new-decision constraints
/// reject the event with the canonical reason_code BEFORE it is committed.
///
/// The clone sees the same already-applied cells as the real apply will —
/// within an ordered submit batch the paired `ck.moderation.decision.lift` /
/// new `ck.moderation.decision` were applied to the live projection by their
/// own earlier `submit_event_value` calls, so the cell already reflects them.
pub(crate) fn preflight_moderation_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    let is_moderation = matches!(
        kind.as_str(),
        cokret_sdk::events::kinds::MODERATION_DECISION
            | cokret_sdk::events::kinds::MODERATION_DECISION_LIFT
            | cokret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT
            | cokret_sdk::events::kinds::MODERATION_APPEAL_REVIEW
            | cokret_sdk::events::kinds::MODERATION_APPEAL_DECISION
            | cokret_sdk::events::kinds::MODERATION_APPEAL_CLOSE
    );
    if !is_moderation {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

pub(crate) fn preflight_invite_projection_reject(
    _state: &AppState,
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    if !matches!(
        kind.as_str(),
        cokret_sdk::events::kinds::INVITE_THIRD_PARTY | cokret_sdk::events::kinds::INVITE_CLAIM
    ) {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

pub(crate) fn preflight_calendar_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    if !matches!(
        kind.as_str(),
        cokret_sdk::events::kinds::STRAND_CREATE
            | cokret_sdk::events::kinds::STRAND_UPDATE
            | cokret_sdk::events::kinds::RSVP_SET
    ) {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

fn event_realm_id(object: &serde_json::Map<String, Value>) -> Result<String, EventValidationError> {
    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "realm_id must use the ck:realm: typed prefix",
            ));
        }
        return Ok(realm_id.clone());
    }

    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "missing_param",
        "realm_id is required",
    ))
}

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

fn validate_data_event_joined_capability_view(
    state: &AppState,
    realm_id: &str,
    grant_id: &str,
) -> Result<(), EventValidationError> {
    let cell_ref = cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.capability.grant.v1:{grant_id}"
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
    if let Ok(projection) = state.projection.lock()
        && matches!(
            projection.cell(&cell_ref),
            Some(cokret_sdk::lattice::CellState::Bottom(_))
        )
    {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            "failed_bottom",
            "cell_in_bottom_state",
        ));
    }
    let snapshot = state.authz.grants_snapshot();
    if let Some(current) = snapshot.iter().find(|grant| grant.grant_id == grant_id)
        && (current.revoked
            || crate::authz::grant_revoked_upstream(&snapshot, grant_id, chrono::Utc::now()))
    {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            "stale_seal_ref",
            format!("DataEvent capability_ref {grant_id} is revoked in joined control view"),
        ));
    }
    Ok(())
}

fn data_event_state_at_seal_ref(
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

fn data_event_grants_from_state_at_ref(
    state_at_ref: &std::collections::BTreeMap<cokret_sdk::CellRef, cokret_sdk::lattice::CellState>,
) -> std::collections::BTreeMap<String, crate::authz::Grant> {
    let mut grants = std::collections::BTreeMap::new();
    const CAPABILITY_GRANT_CELL_PREFIX: &str = "ck:cell:ck.component.capability.grant.v1:";
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

fn validate_data_event_covered_seals(
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

fn data_event_covered_seals_failed_precondition(
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

fn data_event_payload_is_mls_e2ee(object: &serde_json::Map<String, Value>) -> bool {
    let Some(payload) = object.get("payload") else {
        return false;
    };
    encrypted_content_is_mls(payload.get("encrypted_content"))
        || payload
            .get("object")
            .is_some_and(|object| encrypted_content_is_mls(object.get("encrypted_content")))
}

fn encrypted_content_is_mls(value: Option<&Value>) -> bool {
    value
        .and_then(|value| value.get("scheme"))
        .and_then(Value::as_str)
        == Some("mls-rfc9420")
}

fn seal_view_declares_relaxed_e2ee(
    realm: &RealmId,
    state_at_ref: &std::collections::BTreeMap<cokret_sdk::CellRef, cokret_sdk::lattice::CellState>,
) -> bool {
    let Ok(policy_cell) = cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.realm.policy_components.v1:{}",
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

fn policy_components_declare_relaxed_e2ee(policy_components: &Value) -> bool {
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

fn profile_array_contains(value: Option<&Value>, profile: &str) -> bool {
    value.and_then(Value::as_array).is_some_and(|profiles| {
        profiles
            .iter()
            .any(|candidate| candidate.as_str() == Some(profile))
    })
}

fn effective_historical_grants_for_subject(
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

fn data_event_auth_time(object: &serde_json::Map<String, Value>) -> chrono::DateTime<chrono::Utc> {
    object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now)
}

fn grant_covers_data_event_effect(
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

fn effect_resource_candidates(state: &AppState, cell: &str, realm_id: &str) -> Vec<String> {
    let mut resources = Vec::new();
    let projection = state.projection.lock().ok();
    append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, cell);
    let mut parts = cell.splitn(4, ':');
    if matches!(parts.next(), Some("ck"))
        && matches!(parts.next(), Some("cell"))
        && parts.next().is_some()
        && let Some(subject) = parts.next()
        && (subject.starts_with("ck:") || subject.starts_with("did:"))
    {
        append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, subject);
    }
    resources.sort();
    resources.dedup();
    resources
}

fn append_authz_resource_candidates(
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

async fn validate_applet_delegated_authorization_chain(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    kind: &str,
    actor_id: &str,
    realm_id: &str,
) -> Result<(), EventValidationError> {
    let Some(applet_id) = event_string_field(object, &["applet_id"]) else {
        return Ok(());
    };
    let executed_by = event_string_field(object, &["executed_by"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            crate::error::reasons::EXECUTED_BY_MISSING,
            "applet-originated delegated Event requires executed_by",
        )
    })?;
    let authorization_ref =
        event_string_field(object, &["authorization_ref"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "authorization_ref_missing",
                "applet-originated Event requires authorization_ref",
            )
        })?;
    if !authorization_ref.starts_with("ck:grant:") {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_invalid",
            "applet-originated Event authorization_ref must reference an accepted capability grant",
        ));
    }

    let record_value = state
        .persistence
        .applets()
        .get(&applet_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet record for delegated event");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "applet authorization store unavailable",
            )
        })?
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_unauthorized",
                "applet_id does not identify an active installed applet",
            )
        })?;
    let record: crate::routing::extensions::applet_bridge::AppletRecord =
        serde_json::from_value(record_value).map_err(|error| {
            tracing::error!(%error, %applet_id, "stored applet record is invalid");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "stored applet record is invalid",
            )
        })?;
    if record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_revoked",
            "applet install has been revoked",
        ));
    }
    if record.portal_realm_id != realm_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_effective_scope_mismatch",
            "applet Event realm_id is outside the installed effective scope",
        ));
    }
    let package = record.package.as_ref().ok_or_else(|| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_install_required",
            "applet delegated Event requires a package install",
        )
    })?;
    if !applet_executor_in_subject_set(&record, package.service_did.as_str(), &executed_by) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_namespace_mismatch",
            "executed_by is outside the installed applet subject set",
        ));
    }
    let actor_is_managed = applet_actor_is_managed(&record, actor_id);
    if !actor_is_managed && !applet_actor_matches_exact_namespace(&record, actor_id) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_namespace_mismatch",
            "actor_id is outside the installed applet actor namespace",
        ));
    }

    let grants = state.authz.grants_for_subject(&executed_by, realm_id);
    let grant = grants
        .iter()
        .find(|grant| grant.grant_id.as_str() == authorization_ref.as_str())
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "authorization_ref_inactive",
                "authorization_ref does not identify an active grant for executed_by",
            )
        })?;
    if !grant.actions.iter().any(|action| action == kind) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "authorization_ref grant does not cover this Event kind",
        ));
    }
    let event_id = event_string_field(object, &["event_id"]).unwrap_or_default();
    let resources =
        delegated_applet_resource_candidates(state, object, realm_id, actor_id, &event_id);
    if !resources
        .iter()
        .any(|resource| crate::authz::resource_matches(&grant.resource, resource))
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "authorization_ref grant does not cover this Event resource",
        ));
    }
    if !actor_is_managed && grant.issuer.as_str() != actor_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "authorization_ref_scope",
            "native-principal applet delegation must be issued by the acted-for actor_id",
        ));
    }
    validate_applet_registration_epoch_binding(
        state,
        object,
        package,
        grant,
        &applet_id,
        &executed_by,
    )
    .await?;
    Ok(())
}

async fn validate_applet_registration_epoch_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    package: &cokret_sdk::AppletPackage,
    grant: &crate::authz::Grant,
    applet_id: &str,
    executed_by: &str,
) -> Result<(), EventValidationError> {
    crate::authz::validate_applet_delegation_binding(
        grant,
        applet_id,
        executed_by,
        package.registration_epoch.as_str(),
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            applet_delegation_binding_reason(error),
            "authorization_ref grant is not bound to the installed applet registration epoch",
        )
    })?;

    let evidence = package
        .registration_epoch_evidence
        .as_ref()
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_epoch_evidence_missing",
                "installed applet package is missing registration_epoch evidence",
            )
        })?;
    let document =
        crate::jws_verify::resolve_did_document(state, &package.service_did).map_err(|reason| {
            tracing::debug!(%reason, %applet_id, "applet registration_epoch DID resolution failed");
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_epoch_evidence_mismatch",
                "installed applet service DID document could not be resolved",
            )
        })?;
    evidence
        .validate_against_did_document(&document)
        .map_err(|reason| {
            tracing::debug!(%reason, %applet_id, "applet registration_epoch evidence mismatch");
            event_validation_error(
                StatusCode::FORBIDDEN,
                "applet_registration_epoch_evidence_mismatch",
                "installed applet registration_epoch evidence does not match the current service DID document",
            )
        })?;

    if executed_by == package.service_did.as_str()
        && let Some(verification_method) = first_event_proof_verification_method(object)
        && !evidence.contains_signing_key(&verification_method)
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_registration_epoch_signing_key_mismatch",
            "event proof signing key is outside the applet registration_epoch evidence",
        ));
    }
    Ok(())
}

fn applet_delegation_binding_reason(
    error: crate::authz::AppletDelegationBindingError,
) -> &'static str {
    match error {
        crate::authz::AppletDelegationBindingError::Missing => {
            "applet_registration_epoch_binding_missing"
        }
        crate::authz::AppletDelegationBindingError::AppletIdMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        crate::authz::AppletDelegationBindingError::ExecutedByMismatch => {
            "applet_registration_epoch_binding_mismatch"
        }
        crate::authz::AppletDelegationBindingError::RegistrationEpochMismatch => {
            "applet_registration_epoch_mismatch"
        }
    }
}

fn applet_executor_in_subject_set(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    service_did: &str,
    executed_by: &str,
) -> bool {
    executed_by == service_did
        || executed_by == record.bot_actor_id
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id == executed_by && ghost.revoked_at.is_none())
        || applet_actor_matches_exact_namespace(record, executed_by)
}

fn applet_actor_is_managed(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    actor_id == record.bot_actor_id
        || record
            .ghosts
            .iter()
            .any(|ghost| ghost.ghost_actor_id == actor_id && ghost.revoked_at.is_none())
}

fn applet_actor_matches_exact_namespace(
    record: &crate::routing::extensions::applet_bridge::AppletRecord,
    actor_id: &str,
) -> bool {
    record.namespaces.as_ref().is_some_and(|namespaces| {
        namespaces.actors.iter().any(|entry| {
            !applet_namespace_pattern_is_wildcard(&entry.pattern)
                && cokret_sdk::namespace_pattern_matches(
                    cokret_sdk::AppletNamespaceDomain::Actors,
                    &entry.pattern,
                    actor_id,
                )
        })
    })
}

fn applet_namespace_pattern_is_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.ends_with(':') || pattern.ends_with('/')
}

fn delegated_applet_resource_candidates(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    realm_id: &str,
    actor_id: &str,
    event_id: &str,
) -> Vec<String> {
    let mut resources = Vec::new();
    let projection = state.projection.lock().ok();
    append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, realm_id);
    append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, actor_id);
    append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, event_id);
    if let Some(redacts) = event_string_field(object, &["redacts"]) {
        append_authz_resource_candidates(&mut resources, projection.as_deref(), realm_id, &redacts);
    }
    if let Some(payload) = object.get("payload").and_then(Value::as_object) {
        for field in [
            "strand_id",
            "thread_id",
            "message_id",
            "object_id",
            "target_ref",
        ] {
            if let Some(value) = event_string_field(payload, &[field]) {
                append_authz_resource_candidates(
                    &mut resources,
                    projection.as_deref(),
                    realm_id,
                    &value,
                );
            }
        }
    }
    resources.sort();
    resources.dedup();
    resources
}

fn first_event_proof_verification_method(
    object: &serde_json::Map<String, Value>,
) -> Option<String> {
    object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(Value::as_object)
        .and_then(|proof| event_string_field(proof, &["verification_method"]))
}

#[cfg(test)]
pub(crate) async fn validate_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    validate_event_envelope_with_context(state, session, envelope, &[]).await
}

pub(crate) async fn validate_event_envelope_with_context(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let object = envelope.as_object().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "Event Envelope must be a JSON object",
        )
    })?;
    validate_event_critical_features(state, object)?;

    let event_id = event_string_field(object, &["event_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event_id is required",
        )
    })?;
    if !is_valid_event_id(&event_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event_id must use the ck:event: typed prefix",
        ));
    }

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    // Round R2/R3 (T02/T23) — reject ephemeral kinds & receipt-object-only
    // kinds at the submit entrypoint. Aggressive mode: no compat path —
    // pre-Round-R2/R3 senders MUST switch to ck.schema.ephemeral_envelope.v1
    // (broadcast forms) or ck.schema.device_message.v1 (ck.key.verification.*).
    if let Some((code, reason)) = events_submit_pre_admit_check(&kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    if !artifacts::active_local_operation_event_kinds().contains(&kind)
        && kind != kinds::CONFLICT_REPAIR
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_event_kind",
            "event kind is not in the active registry",
        ));
    }

    let schema_id = event_requirements_schema_id(state, object)?;

    let actor_id = event_string_field(object, &["actor_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "actor_id is required",
        )
    })?;
    if validate_did(&actor_id).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_id must be a DID",
        ));
    }
    if actor_id != session.actor {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "event actor_id must match the bearer session actor",
        ));
    }

    // REDU-7 / CKP-0008 / CKP-0009 (R3 spec-sync 2026-05-27,
    // cokret-spec b47ff6ec) — Envelope `actor_kind` is reducer-managed:
    // reject any client-supplied value with the spec-canonical
    // `actor_kind_reducer_managed` reason code. The reducer derives the
    // canonical `EnvelopeActorKind` (Native/Ghost/Service/Agent) from
    // the Actor Profile after the bearer-session derivation lands.
    // TODO(P2-impl): once the deep reducer pipeline runs here, stamp the
    // canonical `EnvelopeActorKind` onto the persisted projection envelope.
    if object.get("actor_kind").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            crate::error::reasons::ACTOR_KIND_REDUCER_MANAGED,
            "envelope.actor_kind is reducer-managed; clients MUST NOT supply it",
        ));
    }
    if object.get("effective_scope").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            crate::error::reasons::EFFECTIVE_SCOPE_REDUCER_MANAGED,
            "envelope.effective_scope is reducer-managed; clients MUST NOT supply it",
        ));
    }

    // CKP-0008 / CKP-0009 — when `executed_by` is present the reducer MUST
    // verify the DID resolved from `proof.verification_method` matches
    // `executed_by` (signs-as-X-on-behalf-of-Y attribution proof). This
    // check uses the FIRST proof's verification_method as the proxy for
    // the resolver-derived DID; deep DID-document resolution can replace
    // the prefix match once the agent runtime authorization plumbing
    // lands.
    if let Some(executed_by) = event_string_field(object, &["executed_by"]) {
        if validate_did(&executed_by).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "executed_by must be a DID",
            ));
        }
        let proofs = object
            .get("proofs")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_object);
        let vm = proofs.and_then(|proof| event_string_field(proof, &["verification_method"]));
        let vm_did = vm
            .as_deref()
            .map(|raw| raw.split_once('#').map_or(raw, |(did, _)| did));
        if vm_did != Some(executed_by.as_str()) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "executed_by_mismatch",
                "envelope.executed_by must match the DID derived from proof.verification_method",
            ));
        }
    }

    let actor_seq = object
        .get("actor_seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "actor_seq is required",
            )
        })?;
    if actor_seq == 0 {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_seq must be greater than zero",
        ));
    }
    validate_event_time_fields(state, object)?;

    let realm_id = event_realm_id(object)?;
    let is_applet_delegated = object.get("applet_id").is_some();
    validate_applet_delegated_authorization_chain(state, object, &kind, &actor_id, &realm_id)
        .await?;
    // Round R2/R3 (T07) + Stream-F (Wave 1B) — Realm in terminal state
    // (`ck.realm.tombstone` OR `ck.realm.destroy` applied) refuses every
    // non-audit-class write. Spec `realm-and-space.md` §2.5 / §2.5.1.
    // The projection lock is poison-free (`state::Mutex`), so this check is
    // always evaluated — a terminal Realm can never be written to because a
    // lock failure defaulted the answer to "not terminal" (fail-open).
    let realm_terminal = state
        .projection
        .lock()
        .expect("projection lock")
        .realm_is_in_terminal_state(&realm_id);
    if let Some((code, reason)) = terminal_realm_check(realm_terminal, &kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    let realm_frozen = state
        .projection
        .lock()
        .expect("projection lock")
        .realm_is_frozen_at(&realm_id, chrono::Utc::now());
    if let Some(reason) = frozen_realm_check(realm_frozen, &kind) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            cokret_sdk::ERROR_CODE_REALM_FROZEN,
            reason,
        ));
    }
    // Spec realm-and-space.md §2.5 — `ck.realm.create` is the genesis
    // event for both the Realm metadata cell AND the creator's first
    // member-state cell. The reducer MUST treat `created_by`
    // as already-a-member when admitting this event; otherwise spec-
    // correct clients can never bootstrap a Realm through the canonical
    // event-submission path. The submit_event commit path (below)
    // materialises the member set in state.realms immediately after
    // store.put succeeds, so any follow-up facet event in the same
    // session naturally passes the regular realm_has_member check.
    let realm_exists = realm_exists_in_index(state, &realm_id);
    if kind == cokret_sdk::events::kinds::REALM_CREATE && realm_exists {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "realm_already_exists",
            "realm already exists",
        ));
    }
    let is_realm_create_bootstrap = kind == "ck.realm.create"
        && realm_create_actor_is_creator(object, &session.actor)
        && !realm_exists;
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session.actor, &realm_id).await;
    let is_invitee_invite_cancel =
        invitee_cancels_pending_invite(state, object, &session.actor, &realm_id).await;
    let is_third_party_invite_claim = invite_claim_actor_claims_pending_third_party_invite(
        state,
        object,
        &session.actor,
        &realm_id,
    )
    .await;
    // A private cross-PS invite delivery (`POST /_cokret/peer/invites`) submits
    // the inviter-signed `ck.invite.create` on the *recipient* PS so the local
    // subject can list + accept it. That realm lives on the inviter's PS, so the
    // recipient PS has no member record for it — yet it MUST still record the
    // pending invite for its subject. Admit `ck.invite.create` from its own
    // inviter into a realm this PS does not host (spec invite-addressing.md §5).
    let is_foreign_invite_delivery = kind == "ck.invite.create"
        && invite_create_actor_is_inviter(object, &session.actor)
        && !realm_exists;
    let is_realm_bootstrap_followup = is_realm_bootstrap_followup_kind(&kind)
        && realm_bootstrap_contexts
            .iter()
            .any(|context| context.realm_id == realm_id && context.actor_id == actor_id);
    // join-policy.md §7.1 — a not-yet-member applicant MUST be able to submit
    // their own `ck.member.state{membership=knock}` (and the profile-private
    // application sub-payload it carries). Gate / review enforcement happens at
    // the later `join` transition, not on the knock itself.
    let is_member_self_knock = member_self_knock(object, &session.actor);
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !is_invitee_invite_cancel
        && !is_third_party_invite_claim
        && !is_foreign_invite_delivery
        && !is_applet_delegated
        && !is_member_self_knock
        && !realm_has_member(state, &realm_id, &session.actor).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    validate_event_schema_and_payload(state, &kind, &schema_id, envelope, object)?;
    validate_data_event_capability_refs(state, &actor_id, &realm_id, &kind, object)?;
    validate_cba_effect_planes(object)?;
    validate_control_move_seal_basis(object, is_realm_bootstrap_followup)?;
    if kind == cokret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE {
        validate_member_identity_proof(state, object.get("payload").unwrap_or(&Value::Null))?;
    }
    if kind == "ck.device.authorize" {
        validate_device_enrollment_authority_binding(state, object, &actor_id).await?;
    }
    validate_audit_accessed_payload(&kind, object)?;
    // Round R2/R3 (T08) — cross_domain replay defence MUST run BEFORE the
    // signature check (verified below in `validate_event_proofs`). Aggressive
    // mode: payload missing the new required fields surfaces as
    // schema_violation here; payload with mismatched trust_domain surfaces as
    // the registered `cross_domain_replay_rejected` (409) code.
    if kind == "ck.cross_signing.reset" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        if let Err((code, reason)) =
            cross_signing_reset_replay_check(&payload, &event_id, &state.config.trust_domain)
        {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }
    // Round R2/R3 (T09 + T12) — realm.policy_components hard ceiling,
    // e2ee_relaxed mutex, and media plaintext triple binding. Active
    // profile set comes from the submitted policy-components payload;
    // cross-policy bindings come from the materialized Realm metadata /
    // MLS cells, with the current payload used only for same-event writes.
    if kind == "ck.realm.policy_components" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        let policy_components = policy_components_value_from_state_payload(&payload);
        // Best-effort: collect active profiles from the payload's own
        // `profiles[]` field plus any payload-asserted "active_profiles".
        let mut active_profiles: Vec<String> = policy_components
            .get("profiles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(extra) = policy_components
            .get("active_profiles")
            .and_then(Value::as_array)
        {
            for v in extra {
                if let Some(s) = v.as_str() {
                    active_profiles.push(s.to_owned());
                }
            }
        }
        let media_plaintext_service_present =
            projected_media_plaintext_service_present(state, &realm_id, policy_components).await;
        let mls_governance_binding_covers_policy_root =
            projected_mls_governance_binding_covers_policy_root(
                state,
                &realm_id,
                policy_components,
            );
        let binding_discussion_metadata_digest =
            projected_mls_governance_binding_metadata_digest(state, &realm_id);
        if let Err((code, reason)) = realm_policy_components_check(
            policy_components,
            &active_profiles,
            media_plaintext_service_present,
            mls_governance_binding_covers_policy_root,
            binding_discussion_metadata_digest.as_deref(),
        ) {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }
    // Round R2/R3 (T04) — Seal frontier entries MUST be sha256:<hex>.
    // We tighten the validator on the events ingest side for the
    // `ck.realm.seal.submit` payload shape used by federation push;
    // the deeper canonical-bytes path uses SDK `seal_canonical_bytes`
    // which already excludes id + notary_sig (notary.rs:217).
    if let Some(frontier) = object
        .get("payload")
        .and_then(|p| p.get("frontier"))
        .and_then(Value::as_array)
    {
        let entries: Vec<String> = frontier
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
        if let Err((code, reason)) =
            crate::routing::federation::move_seal::validate_seal_delta_entries(&entries)
        {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }

    let prev_refs = event_ref_list(object, "prev_refs", MAX_EVENT_PREV_REFS)?;
    let authorized_refs = event_semantic_refs(object, MAX_EVENT_REFS)?;
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let digest_suite = event_digest_suite(state, &kind, &realm_id, object)?;
    let canonical_digest = event_digest_for_suite(&canonical_bytes, &digest_suite)?;
    validate_strand_watch_audit_pair(
        state,
        &kind,
        object,
        &event_id,
        &actor_id,
        &canonical_digest,
    )
    .await?;
    validate_event_proofs(object, state, session, &actor_id, &canonical_digest).await?;
    reject_revoked_actor_device_signature(object, state, session, &actor_id).await?;
    let device_id =
        event_string_field(object, &["device_id"]).unwrap_or_else(|| session.device_id.clone());

    Ok(ValidatedEventEnvelope {
        event_id,
        actor_id,
        device_id,
        actor_seq,
        realm_id,
        kind,
        schema_id,
        prev_refs,
        authorized_refs,
        canonical_digest,
        canonical_bytes,
    })
}

fn validate_control_move_seal_basis(
    object: &serde_json::Map<String, Value>,
    allow_realm_bootstrap_followup_without_basis: bool,
) -> Result<(), EventValidationError> {
    let has_effects = object
        .get("effects")
        .and_then(Value::as_array)
        .is_some_and(|effects| !effects.is_empty());
    if object.get("kind").and_then(Value::as_str) == Some(cokret_sdk::events::kinds::REALM_CREATE) {
        if object.contains_key("seal_ref")
            || object.contains_key("auth_context")
            || object.contains_key("seal_basis")
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "ck.realm.create genesis bootstrap must not carry seal_ref, auth_context, or seal_basis",
            ));
        }
        return Ok(());
    }
    if !has_effects {
        return Ok(());
    }
    if allow_realm_bootstrap_followup_without_basis
        && !object.contains_key("seal_ref")
        && !object.contains_key("auth_context")
        && !object.contains_key("seal_basis")
    {
        return Ok(());
    }
    if object.contains_key("seal_ref") || object.contains_key("auth_context") {
        return Ok(());
    }
    let leaves = object
        .get("seal_basis")
        .and_then(Value::as_object)
        .and_then(|basis| basis.get("leaves"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "Control Move with effects requires seal_basis.leaves",
            )
        })?;
    if leaves.is_empty() {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "schema_violation",
            "Control Move seal_basis.leaves must be non-empty",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CbaEffectPlane {
    Data,
    Control,
}

const DATA_PLANE_CELL_FAMILIES: &[&str] = &[
    "ck.component.strand.discussion.timeline.v1",
    "ck.component.message.reactions.v1",
    "ck.component.pin.v1",
];

fn validate_cba_effect_planes(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let Some(effects) = object.get("effects").and_then(Value::as_array) else {
        return Ok(());
    };
    if effects.is_empty() {
        return Ok(());
    }
    let is_data_event = object.contains_key("seal_ref") || object.contains_key("auth_context");
    let is_control_move = object.contains_key("seal_basis");
    if !is_data_event && !is_control_move {
        return Ok(());
    }
    for effect in effects {
        let family = cba_effect_cell_family(effect)?;
        match cba_cell_family_plane(family)? {
            CbaEffectPlane::Control if is_data_event => {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "plane_cross_write",
                    "DataEvent effects[] must not write control-plane cell",
                ));
            }
            CbaEffectPlane::Data if is_control_move => {
                return Err(event_validation_error(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_plane",
                    "Control Move effects[] must not write data-plane cell",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn cba_effect_cell_family(effect: &Value) -> Result<&str, EventValidationError> {
    let cell = effect.get("cell").and_then(Value::as_str).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[] entries require cell",
        )
    })?;
    let Some(rest) = cell.strip_prefix("ck:cell:") else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must use the ck:cell: typed prefix",
        ));
    };
    let Some((family, subject)) = rest.split_once(':') else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must include a cell family and subject",
        ));
    };
    if family.trim().is_empty() || subject.trim().is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must include a non-empty cell family and subject",
        ));
    }
    Ok(family)
}

fn cba_cell_family_plane(family: &str) -> Result<CbaEffectPlane, EventValidationError> {
    if DATA_PLANE_CELL_FAMILIES.contains(&family) {
        return Ok(CbaEffectPlane::Data);
    }
    if crate::artifacts::cell_family_bindings()
        .iter()
        .any(|binding| binding.cell_family == family)
    {
        return Ok(CbaEffectPlane::Control);
    }
    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "schema_violation",
        format!("effects[].cell references unknown cell family {family}"),
    ))
}

fn is_realm_bootstrap_followup_kind(kind: &str) -> bool {
    matches!(
        kind,
        cokret_sdk::events::kinds::MEMBER_STATE
            | cokret_sdk::events::kinds::REALM_HISTORY_VISIBILITY
            | cokret_sdk::events::kinds::REALM_POLICY_COMPONENTS
            | cokret_sdk::events::kinds::REALM_DISCOVERY
            | cokret_sdk::events::kinds::REALM_JOIN_RULE
            | cokret_sdk::events::kinds::REALM_PLAINTEXT_VISIBLE_SERVICES
    )
}

async fn reject_revoked_actor_device_signature(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
) -> Result<(), EventValidationError> {
    let proof_devices = object
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|proof| event_string_field(proof, &["verification_method"]))
        .filter_map(|vm| actor_device_id_from_verification_method(&vm, actor_id))
        .collect::<std::collections::BTreeSet<_>>();

    let mut candidate_devices = proof_devices;
    candidate_devices.insert(session.device_id.clone());
    if let Some(device_id) = event_string_field(object, &["device_id"]) {
        candidate_devices.insert(device_id);
    }

    for device_id in candidate_devices {
        let revoked = state
            .persistence
            .devices()
            .get(actor_id, &device_id)
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("device revocation lookup failed: {error}"),
                )
            })?
            .is_some_and(|device| device.revoked_at.is_some());
        if revoked {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "actor_signature_revoked",
                "event proof was signed by a revoked actor device",
            ));
        }
    }
    Ok(())
}

fn actor_device_id_from_verification_method(
    verification_method: &str,
    actor_id: &str,
) -> Option<String> {
    verification_method
        .strip_prefix(actor_id)
        .and_then(|suffix| suffix.strip_prefix('#'))
        .map(str::trim)
        .filter(|fragment| !fragment.is_empty())
        .map(|fragment| {
            if fragment.starts_with("ck:device:") {
                fragment.to_owned()
            } else {
                format!("ck:device:{fragment}")
            }
        })
}

pub(crate) fn validate_event_critical_features(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let supported_features = service_declared_event_requirement_features(state);
    for key in ["crit", "critical", "critical_features"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let features = match value {
            Value::Array(values) => values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>(),
            Value::String(value) => Some(vec![value.clone()]),
            _ => None,
        }
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "critical features must be strings",
            )
        })?;
        for feature in features {
            if !LOCAL_EVENT_CRITICAL_FEATURES.contains(&feature.as_str()) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_critical_feature",
                    "unknown critical Event feature is not supported",
                ));
            }
        }
    }
    if let Some(features) = object
        .get("requirements")
        .and_then(|requirements| requirements.get("features"))
    {
        let Some(features) = features.as_array() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "requirements.features must be an array",
            ));
        };
        for feature in features {
            let Some(feature) = feature.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "requirements.features entries must be strings",
                ));
            };
            if !supported_features.contains(feature) {
                return Err(event_validation_error(
                    StatusCode::NOT_IMPLEMENTED,
                    "unsupported_feature",
                    "unknown requirements.features entry is not supported",
                ));
            }
        }
    }
    let Some(critical_extensions) = object
        .get("requirements")
        .and_then(|requirements| requirements.get("critical_extensions"))
    else {
        return Ok(());
    };
    let Some(critical_extensions) = critical_extensions.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "requirements.critical_extensions must be an array",
        ));
    };
    for extension in critical_extensions {
        let (id, fail_closed) = match extension {
            Value::String(id) => (id.as_str(), true),
            Value::Object(object) => {
                let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "requirements.critical_extensions[].id is required",
                    )
                })?;
                let fail_closed = object
                    .get("fail_closed")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                (id, fail_closed)
            }
            _ => {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "requirements.critical_extensions entries must be strings or objects",
                ));
            }
        };
        if fail_closed
            && !LOCAL_EVENT_CRITICAL_FEATURES.contains(&id)
            && !supported_features.contains(id)
        {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "unknown requirements.critical_extensions entry is not supported",
            ));
        }
    }
    Ok(())
}

fn service_declared_event_requirement_features(
    state: &AppState,
) -> std::collections::BTreeSet<String> {
    let mut declared = std::collections::BTreeSet::new();
    declared.extend(
        LOCAL_EVENT_CRITICAL_FEATURES
            .iter()
            .map(|feature| (*feature).to_owned()),
    );
    let mut description = crate::wire::describe(
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
    declared.extend(description.supported_features);
    declared.extend(description.implemented_features);
    declared.extend(description.experimental_features);
    declared
}

pub(crate) fn validate_event_time_fields(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let created_at_value = object.get("created_at");
    if created_at_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "created_at must be a string",
        ));
    }
    match created_at_value.and_then(Value::as_str) {
        Some(value) => canonical::validate_timestamp_canonical(value).map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "created_at must use canonical RFC3339 UTC form",
            )
        })?,
        None if !state.config.development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "created_at is required in production mode",
            ));
        }
        None => {}
    }

    let hlc_value = object.get("hlc");
    if hlc_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "hlc must be a string",
        ));
    }
    match hlc_value.and_then(Value::as_str) {
        Some(value) => {
            Hlc::new(value).map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "hlc must use canonical lower-hex HLC form",
                )
            })?;
        }
        None if !state.config.development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "hlc is required in production mode",
            ));
        }
        None => {}
    }

    Ok(())
}

pub(crate) fn validate_event_schema_and_payload(
    state: &AppState,
    kind: &str,
    _schema_id: &str,
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if !state.config.development_mode {
        let registry = cokret_sdk::schema::schema_registry_from_default_spec_artifacts()
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event schema registry could not be loaded",
                )
            })?
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event schema registry is unavailable",
                )
            })?;
        registry
            .validate_value("ck.schema.event.v1", envelope)
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event envelope violates ck.schema.event.v1",
                )
            })?;
    }

    let payload = object.get("payload").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )
    })?;
    // Wire-shape validators that must run before the registered payload
    // schema validator to surface their precise reason codes.
    validate_pre_schema_wire_shape(kind, payload)?;
    if kind == kinds::CONFLICT_REPAIR {
        return validate_conflict_repair_event_payload(payload);
    }
    if matches!(
        kind,
        cokret_sdk::events::kinds::SPACE_ARCHIVE
            | cokret_sdk::events::kinds::SPACE_RESTORE
            | cokret_sdk::events::kinds::SPACE_TOMBSTONE
    ) {
        return validate_space_container_lifecycle_payload(payload);
    }
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(kind, payload)
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("event payload violates the registered payload schema: {error}"),
            )
        })?;
    validate_realm_create_policy_constraints(kind, payload)?;
    Ok(())
}

pub(crate) fn validate_member_identity_proof(
    state: &AppState,
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(identity_payload) = payload.get("identity_payload") else {
        return Ok(());
    };
    let Some(member_identity_value) = identity_payload.get("member_identity") else {
        if identity_payload.get("encrypted_payload").is_some() {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "encrypted MemberIdentity proof verification is not wired; refusing fail-closed",
            ));
        }
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "identity_payload must carry member_identity or encrypted_payload",
        ));
    };
    let identity: cokret_sdk::MemberIdentity =
        serde_json::from_value(member_identity_value.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("MemberIdentity payload shape is invalid: {error}"),
            )
        })?;
    let payload_realm = payload.get("realm_id").and_then(Value::as_str);
    let payload_actor = payload.get("actor_id").and_then(Value::as_str);
    if payload_realm != Some(identity.realm_id.as_str())
        || payload_actor != Some(identity.actor_id.as_str())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "MemberIdentity realm_id/actor_id must match the update payload subject",
        ));
    }
    let canonical_bytes = identity.canonical_payload_bytes().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity canonical payload failed: {error}"),
        )
    })?;
    let payload_digest = identity.canonical_payload_sha256().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity payload digest failed: {error}"),
        )
    })?;
    if identity.proof.payload_digest.as_str() != payload_digest {
        crate::metrics::record_digest_mismatch("member_identity_payload_digest");
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "proof_event_digest_mismatch",
            "MemberIdentityProof.payload_digest does not match the canonical payload",
        ));
    }
    if !matches!(
        identity.proof.signature_algorithm,
        cokret_sdk::MemberIdentitySignatureAlgorithm::Ed25519
    ) {
        let code = crate::error::ErrorCode::UnsupportedSignatureAlg;
        return Err(event_validation_error(
            crate::error::error_http_status(code),
            code.as_str(),
            "only Ed25519 MemberIdentityProof.signature_algorithm is supported",
        ));
    }
    crate::jws_verify::validate_verification_method_controller(
        identity.subject_id.as_str(),
        &identity.proof.verification_method,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "proof_invalid",
            format!("MemberIdentity proof controller mismatch: {error}"),
        )
    })?;
    let public_key =
        crate::jws_verify::resolve_ed25519_pubkey(state, &identity.proof.verification_method)
            .map_err(|error| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    "proof_invalid",
                    format!("MemberIdentity proof verification key resolution failed: {error}"),
                )
            })?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(identity.proof.signature.as_bytes())
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_invalid",
                format!("MemberIdentity proof signature is not base64url: {error}"),
            )
        })?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "proof_invalid",
            "MemberIdentity proof signature must be 64 bytes",
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    public_key
        .verify(&canonical_bytes, &signature)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "proof_invalid",
                format!("MemberIdentity proof signature verification failed: {error}"),
            )
        })
}

pub(crate) fn event_requirements_schema_id(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let canonical_schema_id = object
        .get("requirements")
        .and_then(|requirements| requirements.get("schema"))
        .and_then(Value::as_array)
        .and_then(|schemas| schemas.first())
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if !state.config.development_mode && canonical_schema_id.is_none() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "requirements.schema[] is required in production mode",
        ));
    }
    let schema_id = canonical_schema_id
        .or_else(|| {
            object
                .get("schema_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "ck.schema.event.v1".to_owned());
    if !schema_id.starts_with("ck.schema.") || !artifacts::schema_ids().contains(&schema_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_schema",
            "event schema_id is not in the cokret-spec schema registry",
        ));
    }
    Ok(schema_id)
}

pub(crate) async fn validate_event_proofs(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
    expected_payload_digest: &str,
) -> Result<(), EventValidationError> {
    let proofs = object
        .get("proofs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "proofs are required",
            )
        })?;
    if proofs.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "proofs must contain at least one proof",
        ));
    }
    // Proof validation forks on `state.config.development_mode`:
    // - **Production** (`development_mode=false`): EVERY proof MUST be a full detached-JWS proof
    //   with `kind`/`alg`/`verification_method`/ `event_digest`/`created_at`/`jws`, hashing the
    //   full canonical envelope. The `type=="dev-proof"` and payload-only hash forms are NOT
    //   accepted under any circumstance — a malicious client claiming `type="dev-proof"` in
    //   production fails-closed here.
    // - **Development** (`development_mode=true`): the minimal dev-proof shape (`type="dev-proof"`,
    //   `verification_method`, `payload_digest`-of-payload) is also accepted so integration
    //   fixtures round-trip without keying.
    let is_production = !state.config.development_mode;
    // Device-identity B-model (device-lifecycle.md §5.4): a delegated-execution
    // envelope (`executed_by` present) is signed by the executing authority's
    // key, NOT by a key rooted in `actor_id`. When `executed_by` is set the
    // proof `verification_method` MUST be rooted in `executed_by` and the JWS
    // is verified against the authority DID; the signed proof-binding transcript
    // still names `actor_id` (the record subject) per encoding.md §6. Absent
    // `executed_by`, the original actor_id rooting applies. The envelope-level
    // schema already requires `authorization_ref` whenever `executed_by` is
    // present, and the actor/executed_by DID validity + vm-DID==executed_by
    // checks ran earlier in this function.
    let proof_root =
        event_string_field(object, &["executed_by"]).unwrap_or_else(|| actor_id.to_owned());
    for proof in proofs {
        let Some(proof_object) = proof.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proofs must be JSON objects",
            ));
        };
        // Production NEVER falls into the dev-proof branch, even if the client
        // claims `type="dev-proof"`. That stops a downgrade attack where a
        // production server is tricked into accepting a weak proof.
        let is_dev_proof = !is_production
            && event_string_field(proof_object, &["type"]).as_deref() == Some("dev-proof");
        let required_fields: &[&str] = if is_dev_proof {
            &["verification_method", "payload_digest"]
        } else {
            &[
                "kind",
                "alg",
                "verification_method",
                "event_digest",
                "created_at",
                "jws",
            ]
        };
        for field in required_fields {
            if !proof_object.contains_key(*field) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof is missing required fields",
                ));
            }
        }
        if !is_dev_proof
            && event_string_field(proof_object, &["kind"]).as_deref() != Some("detached_jws")
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof kind must be detached_jws",
            ));
        }
        if !is_dev_proof && event_string_field(proof_object, &["alg"]).as_deref() != Some("EdDSA") {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof alg must be EdDSA",
            ));
        }
        let proof_digest_key = if is_dev_proof {
            "payload_digest"
        } else {
            "event_digest"
        };
        let proof_event_digest =
            event_string_field(proof_object, &[proof_digest_key]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof event_digest is required",
                )
            })?;
        // Production: the proof's event_digest MUST match the canonical
        // envelope digest. Dev-only: also accept the payload-only form under
        // the same digest suite so test fixtures keep round-tripping.
        // Production never falls back.
        let payload_only_hash_accept = if is_dev_proof {
            let expected_suite = expected_payload_digest
                .split_once(':')
                .map(|(suite, _)| suite)
                .unwrap_or("sha256");
            object.get("payload").map(|payload| {
                let bytes = canonical::canonical_json_bytes(payload).unwrap_or_default();
                cokret_sdk::canonical::digest_with_suite(expected_suite, &bytes)
                    .unwrap_or_else(|_| cokret_sdk::canonical::sha256_digest(&bytes))
            })
        } else {
            None
        };
        if proof_event_digest != expected_payload_digest
            && payload_only_hash_accept.as_deref() != Some(&proof_event_digest)
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_event_digest_mismatch",
                "proof event_digest does not match the event payload",
            ));
        }
        validate_event_audience_fields(proof_object, state, session)?;
        let verification_method = event_string_field(proof_object, &["verification_method"])
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof verification_method is required",
                )
            })?;
        if verification_method != proof_root
            && !verification_method.starts_with(&format!("{proof_root}#"))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "proof verification method must be rooted in the proof signer (executed_by when present, else actor_id)",
            ));
        }
        if is_production {
            let jws = event_string_field(proof_object, &["jws"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof jws is required",
                )
            })?;
            let created_at =
                event_string_field(proof_object, &["created_at"]).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "proof created_at is required",
                    )
                })?;
            // The signed proof-binding transcript names `actor_id` (record
            // subject) regardless of who signed it (encoding.md §6); only the
            // resolved signer DID (`proof_root`) switches to `executed_by` for
            // delegated execution.
            let proof_binding_bytes = event_proof_binding_bytes(
                &proof_event_digest,
                actor_id,
                &verification_method,
                &created_at,
                proof_object,
            )?;
            // High-risk path: enforce DID document freshness before event
            // proof verification (fail-closed-on-stale). Stale or missing
            // evidence must not be used for signature verification. The signer
            // DID is `proof_root` (the enrollment authority for service_attested
            // device.authorize, else actor_id); freshness + key resolution both
            // target it. did:key signers have no persisted webvh record and are
            // resolved purely cryptographically by the SDK verifier below, so
            // the freshness gate (which only covers cached webvh documents)
            // only applies to webvh signers.
            let signer_did = cokret_sdk::Did::new(proof_root.clone()).map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("event proof signer DID is not a valid DID: {error}"),
                )
            })?;
            if signer_did.method() != "key" {
                crate::jws_verify::enforce_high_risk_did_freshness(state, &signer_did)
                    .await
                    .map_err(|reason| {
                        tracing::debug!(%reason, "event proof DID freshness gate failed");
                        event_validation_error(
                            StatusCode::BAD_REQUEST,
                            "stale_did_document",
                            "event proof DID document is stale or unavailable for verification",
                        )
                    })?;
            }
            crate::jws_verify::verify_jws_ed25519(
                &proof_binding_bytes,
                &jws,
                &verification_method,
                signer_did.as_str(),
                state,
            )
            .map_err(|reason| {
                tracing::debug!(%reason, "event proof JWS verification failed");
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof JWS verification failed",
                )
            })?;
        }
    }
    Ok(())
}

fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &str,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, EventValidationError> {
    let mut binding = serde_json::Map::new();
    binding.insert("event_digest".to_owned(), json!(event_digest));
    binding.insert("actor_id".to_owned(), json!(actor_id));
    binding.insert("verification_method".to_owned(), json!(verification_method));
    binding.insert("created_at".to_owned(), json!(created_at));
    for optional in ["domain", "audience"] {
        if let Some(value) = proof_object.get(optional) {
            binding.insert(optional.to_owned(), value.clone());
        }
    }
    canonical::canonical_json_bytes(&Value::Object(binding)).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("proof binding canonicalization failed: {error}"),
        )
    })
}
