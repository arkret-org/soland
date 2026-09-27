//! Reject the retired Cell-based Realm authority-root proof surface.
//!
//! Current Event admission is authorized at its accepted RealmCommit cut. A
//! submitted `authorization_ref` naming the former authority-root Cell cannot
//! establish current governance authority and must not be treated as a grant.
//! Other closed authorization_ref branches remain valid and are checked by
//! their own committed-state gate.

use super::*;

pub(in crate::routing) async fn validate_realm_authority_root_authorization(
    _state: &AppState,
    object: &serde_json::Map<String, Value>,
    kind: &str,
    _realm_id: &str,
    _actor_id: &arkret_wire::ActorId,
    _bootstrap_unit_member: bool,
    _realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<(), EventValidationError> {
    if object
        .get("authorization_ref")
        .and_then(Value::as_str)
        .is_some_and(|reference| reference.starts_with("ak:cell:"))
    {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "Cell-based authorization_ref is not a v1 Event authority proof",
        ));
    }
    if arkret_schema::capability_action(kind).is_some_and(|action| action.root_control_only) {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "failed_precondition",
            "root-control admission requires the same-cut authority-root current result",
        ));
    }
    Ok(())
}
