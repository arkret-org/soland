use arkret_models_collaboration::applet_installation_authority::AppletInstallationAuthority;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_wire::{DidCoreId, Event, GrantId};

use super::*;

pub(super) async fn current_installation_authority(
    state: &AppState,
    event: &Event,
) -> Result<Option<AppletInstallationAuthority>, String> {
    let Some(applet_id) = &event.applet_id else {
        return Ok(None);
    };
    let record = crate::routing::extensions::applet_bridge::record::applet_record(
        state,
        applet_id.as_str(),
        &event.scope_ref,
    )
    .await
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "Applet exact installation is missing".to_owned())?;
    if record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
    {
        return Err("Applet installation is revoked".to_owned());
    }
    let grant_id = GrantId::new(
        event
            .authorization_ref
            .clone()
            .ok_or_else(|| "Applet authorization_ref is missing".to_owned())?
            .as_str()
            .to_owned(),
    )
    .map_err(|error| error.to_string())?;
    let grant_event_id = arkret_wire::EventId::from_token_bytes(grant_id.token_bytes())
        .map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    for id in [&record.registration_event.event_id, &grant_event_id] {
        let stored = state
            .event_queries()
            .canonical_event(id.as_str())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Applet accepted authority Event is unavailable".to_owned())?;
        let accepted: Event =
            serde_json::from_value(stored.envelope).map_err(|error| error.to_string())?;
        events.push(accepted);
    }
    let grant = events.pop().expect("two authority Events");
    let authority = AppletInstallationAuthority {
        registration_event: events.pop().expect("registration Event"),
        capability_grant_event: grant,
    };
    let target = arkret_policy::applet_admission::verify_applet_installation_authority(
        event,
        &authority,
        |dependency| {
            dependency.validate_station_admission_binding(
                dependency.event_id.event_digest().digest_suite()?,
            )
        },
    )
    .map_err(|error| error.to_string())?;
    if target.as_str() != state.service_id() || target != *record.bot_actor_id.route_service_id() {
        return Err("Applet installation target does not match this Station".to_owned());
    }
    Ok(Some(authority))
}

pub(super) async fn historical_installation_origin(
    state: &AppState,
    event: &Event,
) -> Result<DidCoreId, String> {
    if event.applet_id.is_none() {
        return Ok(event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .route_service_id()
            .clone());
    }
    let admission = event
        .proofs
        .last()
        .and_then(arkret_wire::EventProof::as_station_admission)
        .ok_or_else(|| "Applet admission is missing".to_owned())?;
    let digest = admission
        .applet_installation_digest
        .clone()
        .ok_or_else(|| "Applet installation authority dependency is missing".to_owned())?;
    let selector = GovernanceDependencySelector::AppletInstallationAuthority {
        content_digest: digest,
    };
    let controller = admission
        .verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| "admission method has no controller".to_owned())?
        .0;
    let source = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new(controller.to_owned()).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let dependency =
        resolve_admission_dependency(state, &event.realm_id, &source, selector).await?;
    let GovernanceDependency::AppletInstallationAuthority {
        applet_installation_authority: authority,
        ..
    } = dependency
    else {
        return Err("Applet installation dependency kind mismatch".to_owned());
    };
    authority
        .validate_structural()
        .map_err(|error| error.to_string())?;
    for dependency in [
        &authority.registration_event,
        &authority.capability_grant_event,
    ] {
        let suite = dependency
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| error.to_string())?;
        Box::pin(super::verify_federated_event_admission(
            state, dependency, suite,
        ))
        .await?;
    }
    arkret_policy::applet_admission::validate_applet_installation_coordinates(event, &authority)
        .map_err(|error| error.to_string())
}

pub(super) async fn resolve_admission_dependency(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    source: &DidCoreId,
    selector: GovernanceDependencySelector,
) -> Result<GovernanceDependency, String> {
    let store = state.persistence().governance_dependency_store();
    if let Some(item) = store
        .get(realm_id, &selector)
        .await
        .map_err(|error| error.to_string())?
    {
        return Ok(item);
    }
    if matches!(
        selector,
        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { .. }
    ) {
        if let Some(item) = store
            .get_unscoped_signer_evidence(&selector)
            .await
            .map_err(|error| error.to_string())?
        {
            return Ok(item);
        }
    }
    if source.as_str() == state.service_id() {
        return Err("dependency_missing: local admission dependency is unavailable".to_owned());
    }
    let request = arkret_models_collaboration::governance_dependencies::PeerGovernanceDependencyResolveRequest {
        realm_id: realm_id.clone(), selectors: vec![selector.clone()], byte_limit: 8 * 1024 * 1024, history_traversal_access: None,
    };
    let outcome = crate::routing::federation::rhrk_acquisition::fetch_peer_governance_dependencies(
        state, source, &request,
    )
    .await
    .map_err(|error| format!("dependency_missing: {error}"))?;
    outcome
        .validate_for_peer_request(&request)
        .map_err(|error| error.to_string())?;
    let [item] = outcome.items.as_slice() else {
        return Err("dependency_missing: admission dependency is unavailable".to_owned());
    };
    // This is content-addressed evidence, never a business-state projection.
    // Every consumer still authenticates its signatures and authority bindings.
    store
        .put_realm_object_exact(realm_id, item.clone())
        .await
        .map_err(|error| error.to_string())?;
    Ok(item.clone())
}

pub(super) async fn verify_historical_station_signature(
    state: &AppState,
    event: &Event,
    origin: &DidCoreId,
) -> Result<(), String> {
    let admission = event
        .proofs
        .last()
        .and_then(arkret_wire::EventProof::as_station_admission)
        .ok_or_else(|| "Station admission is missing".to_owned())?;
    let digest = admission
        .signer_resolution_evidence_ref
        .content_digest()
        .map_err(|error| error.to_string())?;
    let item = resolve_admission_dependency(
        state,
        &event.realm_id,
        origin,
        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: digest.clone(),
        },
    )
    .await?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: evidence,
        ..
    } = item
    else {
        return Err("Station signer evidence kind mismatch".to_owned());
    };
    if evidence
        .canonical_sha256_digest()
        .map_err(|error| error.to_string())?
        != digest
    {
        return Err("Station signer evidence digest mismatch".to_owned());
    }
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::Service {
        signer_id,
        verification_method,
        authenticated_resolution,
    } = evidence.as_ref()
    else {
        return Err("Station signer evidence is not a service authority".to_owned());
    };
    if signer_id != origin || verification_method != &admission.verification_method {
        return Err("Station signer evidence coordinates mismatch".to_owned());
    }
    let document = arkret_identity::authenticated_service_document_at(
        authenticated_resolution,
        origin,
        admission.accepted_at,
    )
    .map_err(|error| error.to_string())?;
    arkret_identity::verify_jws_with_document_relationship(
        &admission
            .canonical_binding_bytes()
            .map_err(|error| error.to_string())?,
        &admission.jws,
        &admission.verification_method,
        &document.id,
        &document,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| error.to_string())
}
