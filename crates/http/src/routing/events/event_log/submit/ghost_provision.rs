//! Applet managed-actor admission boundary.
//!
//! The former writer staged Cell/Seal effects and fixed its idempotent HTTP
//! response before issuing any RealmCommit. Applet install's formal outcome
//! now carries exact CommittedEventRef coordinates, including for Events in
//! different streams. This entry point must not accept an Event-only batch or
//! claim a completed installation until one authority UoW returns all signed
//! Commit references and persists the derived record and replay result.

use super::*;

fn validate_applet_unit(events: &[Event]) -> Result<(), SubmitOneError> {
    if events.is_empty() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Applet formal Event unit must not be empty",
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for event in events {
        event.validate_for_submit_structural().map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid Applet formal Event: {error}"),
            )
        })?;
        if !ids.insert(event.event_id.clone()) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "Applet formal unit repeats an Event id",
            ));
        }
    }
    Ok(())
}

fn applet_commit_unit_unavailable() -> SubmitOneError {
    SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Applet atomic Event/RealmCommit installation is unavailable",
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::routing) async fn submit_ghost_provision_batch(
    _state: &AppState,
    service_id: &str,
    ghost_actor_id: &str,
    realm_id: &str,
    managed_provision: Event,
    pcr_genesis: Event,
    accountability: Event,
    profile: Event,
    _applet_id: arkret_wire::AppletId,
    _target_station_id: arkret_wire::DidCoreId,
    _applet_identity: Value,
    _producer_verification_method: arkret_wire::DidUrl,
    _producer_signing_key: arkret_wire::DidKey,
    _expected_applet_record: Value,
    _applet_record: Value,
    _authoring_preview_subject_key: String,
    _authoring_request_digest: String,
    _idempotency: EventCommitIdempotency,
    _response_body: Value,
) -> Result<(), SubmitOneError> {
    let events = [managed_provision, pcr_genesis, accountability, profile];
    validate_applet_unit(&events)?;
    if events[0].kind != arkret_wire::EventKind::AppletManagedActorProvision
        || events[1].kind != arkret_wire::EventKind::RealmCreate
        || events[2].kind != arkret_wire::EventKind::IdentityAccountabilityGrant
        || events[3].kind != arkret_wire::EventKind::ProfileCreate
        || events[0].actor_id.signing_principal_id().as_str() != service_id
        || events[1].actor_id.signing_principal_id().as_str() != ghost_actor_id
        || events[2].realm_id.as_str() != realm_id
        || events[3].realm_id.as_str() != realm_id
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Ghost formal Event unit actor or Realm binding differs from the validated request",
        ));
    }
    Err(applet_commit_unit_unavailable())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::routing) async fn submit_applet_install_batch(
    _state: &AppState,
    events: Vec<Event>,
    _applet_id: arkret_wire::AppletId,
    _target_station_id: arkret_wire::DidCoreId,
    _expected_applet_identity: Option<Value>,
    _applet_identity: Value,
    _producer_verification_method: arkret_wire::DidUrl,
    _producer_signing_key: arkret_wire::DidKey,
    _applet_record: Value,
    _authoring_preview_subject_key: String,
    _authoring_request_digest: String,
    _idempotency: EventCommitIdempotency,
    _response_body: Value,
) -> Result<(), SubmitOneError> {
    validate_applet_unit(&events)?;
    Err(applet_commit_unit_unavailable())
}
