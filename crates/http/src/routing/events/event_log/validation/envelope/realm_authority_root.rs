//! Realm authority-root authorization (`authz/capabilities.md` §3.2).
//!
//! `ak:cell:ak.component.realm.authority_root.v1:null` is a closed constant of
//! the `authorization_ref` union, and it is the only member that resolves to
//! Realm owner authority instead of to a grant. An Event that cites it is
//! claiming to be authored by the cell's current controller.
//!
//! The claim has exactly two proof forms and they are not interchangeable:
//! inside the atomic genesis unit the root is the value the batch's own
//! `ak.realm.create` derived (no accepted Seal covers it yet), and everywhere
//! else it MUST be read out of an accepted-Seal inclusion proof. Accepting one
//! in the other's context would let a genesis-window credential be replayed for
//! the lifetime of the Realm, so a mismatch is rejected as
//! `realm_authority_controller_mismatch`.

use super::*;

/// Validate an Event whose `authorization_ref` is the Realm authority-root cell.
///
/// Events that cite anything else are unaffected.
pub(super) fn validate_realm_authority_root_authorization(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    kind: &str,
    realm_id: &str,
    actor_id: &str,
    bootstrap_unit_member: bool,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<(), EventValidationError> {
    let authorization_ref = event_string_field(object, &["authorization_ref"]);
    let root_control_only = arkret_schema::embedded_capability_action(kind)
        .ok()
        .flatten()
        .is_some_and(|descriptor| descriptor.root_control_only);
    if root_control_only
        && authorization_ref.as_deref() != Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "realm_authority_controller_mismatch",
            "root-control Event requires the current Realm authority-root proof",
        ));
    }
    if authorization_ref.as_deref() != Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL) {
        return Ok(());
    }
    // The authorizing principal is whoever actually signed for the Realm:
    // `executed_by` when the Event is executed on behalf of `actor_id`.
    let subject =
        event_string_field(object, &["executed_by"]).unwrap_or_else(|| actor_id.to_owned());

    let root = if bootstrap_unit_member {
        staged_genesis_root(realm_id, actor_id, realm_bootstrap_contexts)?
    } else {
        accepted_seal_root(state, object, realm_id)?
    };

    if root.controller_id.as_str() != subject {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "realm_authority_controller_mismatch",
            "Event cites the Realm authority root but is not authored by its current controller",
        ));
    }
    // Which kinds may appear at all inside the atomic genesis unit is already a
    // closed question, answered by
    // `arkret_policy::realm_bootstrap::is_realm_bootstrap_followup_kind` before
    // the batch reached this validator. Re-asking it here through the owner
    // aggregate's operational coverage would contradict that rule: the closed
    // follow-up set deliberately contains kinds the aggregate does not cover on
    // its own (`ak.member.state` is governed by `ak.realm.admin` /
    // `ak.realm.join.review` outside genesis). The staged root proves *who*
    // speaks for the Realm during genesis; the unit whitelist fixes *what* may
    // be said.
    if !bootstrap_unit_member
        && !root_control_only
        && !arkret_policy::owner_may_author_event_kind(kind).unwrap_or(false)
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            format!("ak.realm.owner does not authorize authoring {kind}"),
        ));
    }
    Ok(())
}

/// Staged root proof, valid only inside the atomic genesis unit.
///
/// The value is the one the batch's own `ak.realm.create` derived; the shared
/// unit validator already bound every follow-up to that create by actor, Realm
/// and `prev_refs` chain, so membership of the unit is the causal binding. An
/// Event that claims a staged proof without being a member of a unit for this
/// (Realm, actor) has no create to descend from and is rejected.
fn staged_genesis_root(
    realm_id: &str,
    actor_id: &str,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<arkret_policy::realm_bootstrap::RealmAuthorityRootValue, EventValidationError> {
    realm_bootstrap_contexts
        .iter()
        .find(|context| context.realm_id == realm_id && context.actor_id == actor_id)
        .and_then(|context| context.authority_root.clone())
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "realm_authority_controller_mismatch",
                "a staged Realm authority-root proof is valid only inside its own genesis unit",
            )
        })
}

/// Accepted-Seal proof: the registered cell must be included in the state the
/// Event's own governance basis resolves to.
fn accepted_seal_root(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    realm_id: &str,
) -> Result<arkret_policy::realm_bootstrap::RealmAuthorityRootValue, EventValidationError> {
    let realm = RealmId::new(realm_id.to_owned()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "realm_id must be a valid ak:realm id",
        )
    })?;
    let leaves = governance_basis_leaves(object)?;
    let effective = state
        .projections()
        .effective_state_at(&leaves, &realm)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "realm_authority_root_missing",
                format!("Realm authority-root inclusion proof could not be resolved: {error}"),
            )
        })?;
    let cell = arkret_identifiers::CellRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned())
        .expect("the authority-root cell ref constant is well-formed");
    let value = match effective.get(&cell) {
        Some(arkret_state::lattice::CellState::Value(value)) => value.clone(),
        Some(arkret_state::lattice::CellState::Bottom(_)) => {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "realm_authority_root_conflict",
                "the Realm authority-root cell is in conflict at the Event's governance basis",
            ));
        }
        None => {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "realm_authority_root_missing",
                "no accepted Seal at the Event's governance basis includes the Realm \
                 authority-root cell",
            ));
        }
    };
    serde_json::from_value(value).map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "realm_authority_root_conflict",
            format!("the Realm authority-root cell value is not a registered root: {error}"),
        )
    })
}

/// Seal leaves the Event pins its authorization pre-state to.
///
/// A DataEvent names one accepted Seal in `seal_ref`; a Control Move names its
/// joined basis in `seal_basis.leaves`. An Event with neither carries no
/// accepted-Seal proof at all and cannot speak for the authority root.
fn governance_basis_leaves(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<arkret_identifiers::SealId>, EventValidationError> {
    let mut raw = Vec::new();
    if let Some(seal_ref) = event_string_field(object, &["seal_ref"]) {
        raw.push(seal_ref);
    }
    raw.extend(
        object
            .get("seal_basis")
            .and_then(Value::as_object)
            .and_then(|basis| basis.get("leaves"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned),
    );
    if raw.is_empty() {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "realm_authority_root_missing",
            "an Event citing the Realm authority root outside its genesis unit requires an \
             accepted-Seal governance basis",
        ));
    }
    raw.into_iter()
        .map(|leaf| {
            arkret_identifiers::SealId::new(leaf).map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "governance basis leaf is not a valid ak:seal id",
                )
            })
        })
        .collect()
}
