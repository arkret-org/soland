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
    _state: &AppState,
    _operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind(operation).as_str(),
        arkret_wire::event_kind_str::PROFILE_CREATE | arkret_wire::event_kind_str::PROFILE_UPDATE
    ) {
        return Ok(());
    }
    if profile_accountable_principal_ids(operation).is_empty() {
        return Ok(());
    }
    // The retired Seal/Cell view and canonical-Event scan cannot prove an
    // accountability grant at the profile Event's exact authority Commit cut.
    // The scan also misses the Agent-provision atomic grant projection. Reject
    // until the authority service provides that committed current result.
    Err(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)
}

type AccountabilityGrant =
    arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;

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
