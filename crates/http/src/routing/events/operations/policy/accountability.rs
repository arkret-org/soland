use super::*;

pub(super) fn validate_pin_scope_safety(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::canonical_kind_for_operation(operation)
        .is_some_and(|kind| arkret_wire::events::kinds::is_pin_kind(&kind))
    {
        return Ok(());
    }
    let projection = state.projections().snapshot();
    projection.check_pin_scope_safety(operation)
}

pub(super) async fn validate_accountability_profile_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind(operation).as_str(),
        arkret_wire::event_kind_str::PROFILE_CREATE | arkret_wire::event_kind_str::PROFILE_UPDATE
    ) {
        return Ok(());
    }
    let accountable_principal_ids = profile_accountable_principal_ids(operation);
    if accountable_principal_ids.is_empty() {
        return Ok(());
    }
    let Some(principal_id) = profile_principal_id(operation) else {
        return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
    };
    let frozen_at = operation.created_at;
    let mut grants = accountability_grants_at_frozen_basis(state, operation).await?;
    merge_atomic_accountability_grants(&mut grants, operations, operation.realm_id.as_str());
    for issuer in accountable_principal_ids {
        let active = grants.values().any(|grant| {
            grant.issuer_id.as_str() == issuer
                && grant.subject_id.as_str() == principal_id
                && grant.validate_lifecycle_at(frozen_at).is_ok()
        });
        if !active {
            return Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        }
    }
    Ok(())
}

type AccountabilityGrantKey = (String, String, String);
type AccountabilityGrant =
    arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;

async fn accountability_grants_at_frozen_basis(
    state: &AppState,
    operation: &Operation,
) -> Result<std::collections::BTreeMap<AccountabilityGrantKey, AccountabilityGrant>, &'static str> {
    let realm = operation.realm_id.clone();
    let basis = accountability_seal_basis(operation)?;
    if !basis.is_empty() {
        let frozen = state
            .projections()
            .effective_state_at(&basis, &realm)
            .await
            .map_err(|_| "accountability grant frozen basis unavailable")?;
        let mut grants = std::collections::BTreeMap::new();
        for (cell_ref, cell_state) in frozen {
            if !cell_ref
                .as_str()
                .starts_with("ak:cell:ak.component.identity.accountability.v1:")
            {
                continue;
            }
            let arkret_state::lattice::CellState::Value(value) = cell_state else {
                continue;
            };
            if let Some(grant) = parse_accountability_grant(&value)
                && let Some(key) = accountability_grant_key(&grant)
            {
                grants.insert(key, grant);
            }
        }
        return Ok(grants);
    }

    // Test/support callers that construct Operations directly have no CBA
    // envelope context. Keep that path deterministic by folding accepted grant
    // events by event id and the profile Event's signed created_at. Production
    // Control Moves always take the sealed-cell path above.
    let mut records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|_| "accountability grant frozen basis unavailable")?;
    records.sort_by(|left, right| left.event_id.as_bytes().cmp(right.event_id.as_bytes()));
    let mut grants = std::collections::BTreeMap::new();
    for record in records {
        if record.kind != arkret_wire::EventKind::IdentityAccountabilityGrant.as_str()
            || record.realm_id.as_deref() != Some(operation.realm_id.as_str())
        {
            continue;
        }
        let payload = record.envelope.get("payload").unwrap_or(&record.envelope);
        let Some(grant) = parse_accountability_grant(payload) else {
            continue;
        };
        if !accountability_grant_envelope_signed_by(&record, grant.issuer_id.as_str())
            || grant.proof.created_at > operation.created_at
        {
            continue;
        }
        if let Some(key) = accountability_grant_key(&grant) {
            insert_accountability_grant_revoke_wins(&mut grants, key, grant);
        }
    }
    Ok(grants)
}

fn accountability_seal_basis(
    operation: &Operation,
) -> Result<Vec<arkret_identifiers::SealId>, &'static str> {
    let mut ids = Vec::new();
    if let Some(seal_ref) = &operation.context.seal_ref {
        ids.push(seal_ref.clone());
    }
    if let Some(seal_basis) = &operation.context.seal_basis {
        ids.extend(seal_basis.leaves.iter().cloned());
    }
    ids.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    ids.dedup();
    Ok(ids)
}

fn merge_atomic_accountability_grants(
    grants: &mut std::collections::BTreeMap<AccountabilityGrantKey, AccountabilityGrant>,
    operations: &[Operation],
    realm_id: &str,
) {
    for operation in operations {
        if kinds::canonical_kind(operation) != arkret_wire::EventKind::IdentityAccountabilityGrant
            || operation.realm_id.as_str() != realm_id
        {
            continue;
        }
        let Some(grant) = parse_accountability_grant(&operation.payload) else {
            continue;
        };
        if !accountability_grant_operation_signed_by(operation, grant.issuer_id.as_str()) {
            continue;
        }
        if let Some(key) = accountability_grant_key(&grant) {
            insert_accountability_grant_revoke_wins(grants, key, grant);
        }
    }
}

fn insert_accountability_grant_revoke_wins(
    grants: &mut std::collections::BTreeMap<AccountabilityGrantKey, AccountabilityGrant>,
    key: AccountabilityGrantKey,
    grant: AccountabilityGrant,
) {
    use arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus;
    if grants
        .get(&key)
        .is_some_and(|current| current.grant_status == AccountabilityGrantStatus::Revoked)
        && grant.grant_status == AccountabilityGrantStatus::Active
    {
        return;
    }
    grants.insert(key, grant);
}

fn accountability_grant_key(grant: &AccountabilityGrant) -> Option<AccountabilityGrantKey> {
    Some((
        grant.issuer_id.as_str().to_owned(),
        grant.subject_id.as_str().to_owned(),
        grant.accountability_scope.scope_set_component().ok()?,
    ))
}

fn parse_accountability_grant(value: &Value) -> Option<AccountabilityGrant> {
    serde_json::from_value(value.clone()).ok()
}

pub(super) fn profile_body_value(operation: &Operation) -> &Value {
    operation
        .payload
        .get("profile")
        .or_else(|| operation.payload.get("object"))
        .or_else(|| operation.payload.get("value"))
        .unwrap_or(&operation.payload)
}

pub(super) fn profile_principal_id(operation: &Operation) -> Option<String> {
    let body = profile_body_value(operation);
    body.get("principal_id")
        .or_else(|| body.get("actor_id"))
        .or_else(|| operation.payload.get("principal_id"))
        .or_else(|| operation.payload.get("actor_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn profile_accountable_principal_ids(operation: &Operation) -> Vec<String> {
    let body = profile_body_value(operation);
    body.get("accountable_principal_ids")
        .or_else(|| operation.payload.get("accountable_principal_ids"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn accountability_grant_operation_signed_by(
    operation: &Operation,
    issuer: &str,
) -> bool {
    operation
        .context
        .executed_by
        .as_ref()
        .unwrap_or(&operation.context.sender)
        .signing_principal_id()
        .as_str()
        == issuer
}

pub(super) fn accountability_grant_envelope_signed_by(
    record: &soland_services::events::AcceptedEvent,
    issuer: &str,
) -> bool {
    soland_services::events::accepted_event_executor(record)
        .is_some_and(|actor| actor.signing_principal_id().as_str() == issuer)
}

pub(super) fn accountability_grant_value_active_for(
    value: &Value,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(grant) = parse_accountability_grant(value) else {
        return false;
    };
    grant.issuer_id.as_str() == issuer
        && grant.subject_id.as_str() == subject
        && grant.validate_lifecycle_at(now).is_ok()
}
