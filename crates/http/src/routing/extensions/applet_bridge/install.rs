//! Canonical applet install: package validation, plan building, registration
//! projection, portal message ingress, and the realm-admin governance gate.

use std::collections::BTreeSet;

use arkret_identifiers::{EventId, GrantId, Hash, RealmId};
use arkret_identity::DidDocument;
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope,
    AccountabilityScopeKind,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_integration::{
    AppletGhostActorMode, AppletInstallAuthoringRequestBasis, AppletInstallEffectiveStatus,
    AppletInstallOutcome, AppletInstallPlan, AppletInstallRequestBody,
    AppletManagedActorProvisionPayload, AppletManagedActorRole, AppletPackage,
    AppletRegistrationEpochEvidence, AppletRejectedItem, AppletWireNamespaces,
    CapabilityConstraint, DeniedScope, E2eeEffect, E2eePolicy, EventSubmission, NamespaceConflict,
    ScopeGrant, WidgetEffect,
};
use arkret_wire::{
    ActorId, CapabilityActionId, Event, ResourceMatchScope, ScopeRef, WireResourceSelector,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_services::identity::{PinnedDidVersionStatus, SessionIdentityState as SessionRecord};

use super::record::{
    applet_identity, applet_record, applet_records, encode_applet_identity, encode_applet_record,
};
use super::types::{AppletIdentityRecord, AppletRecord};
use crate::ids;
use crate::state::AppState;

struct ValidatedInstallEvents {
    approved_actions: Vec<String>,
    grant_ids: Vec<GrantId>,
    bot_provision: Option<AppletManagedActorProvisionPayload>,
}

pub(super) struct ValidatedAdminInstallEvents {
    pub approved_actions: Vec<String>,
    pub grant_ids: Vec<GrantId>,
}

pub(super) fn approved_scopes_from_formal_install_events(
    state: &AppState,
    commit: &AppletInstallRequestBody,
    install_actor: &ActorId,
    station_id: &str,
) -> Result<Vec<ScopeGrant>, AppError> {
    let basis = commit.authoring_request().basis.install().ok_or_else(|| {
        AppError::param_invalid("install commit basis purpose is not install_bot")
    })?;
    let validated = validate_formal_install_events(state, commit, install_actor, station_id)?;
    approved_scope_grants(&basis.effective_scope, validated.approved_actions)
}

pub(super) fn approved_scope_grants(
    effective_scope: &ScopeRef,
    approved_actions: Vec<String>,
) -> Result<Vec<ScopeGrant>, AppError> {
    if approved_actions.is_empty() {
        return Err(AppError::param_invalid(
            "applet install requires at least one approved capability grant action",
        )
        .with_wire_code("applet_install_plan_mismatch"));
    }
    let (realm_id, circle_ids) = match effective_scope {
        ScopeRef::Realm { realm_id } => (realm_id.clone(), None),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => (realm_id.clone(), Some(vec![circle_id.clone()])),
        _ => {
            return Err(AppError::param_invalid(
                "unsupported applet effective scope",
            ));
        }
    };
    Ok(vec![ScopeGrant {
        actions: approved_actions,
        realm_ids: vec![realm_id],
        circle_ids,
        constraints: Vec::new(),
    }])
}

pub(super) fn validate_hosted_applet_pcr_notary(
    actual: &arkret_wire::NotaryValue,
    expected: &arkret_wire::NotaryValue,
) -> Result<(), AppError> {
    if actual != expected {
        return Err(AppError::param_invalid(
            "Applet-managed PCR genesis notary must equal the exact hosting Station notary",
        )
        .with_wire_code("applet_managed_pcr_genesis_invalid"));
    }
    Ok(())
}

fn validate_formal_install_events(
    state: &AppState,
    commit: &AppletInstallRequestBody,
    install_actor: &ActorId,
    station_id: &str,
) -> Result<ValidatedInstallEvents, AppError> {
    let package = commit.applet_package();
    let basis = commit.authoring_request().basis.install().ok_or_else(|| {
        AppError::param_invalid("install commit basis purpose is not install_bot")
    })?;
    let admin = validate_admin_install_events(package, basis, install_actor)?;
    let bot_provision = if commit.managed_actor_bundle().is_some() {
        Some(validate_bot_managed_actor_unit(
            state,
            commit,
            &admin.grant_ids,
            station_id,
        )?)
    } else {
        None
    };
    Ok(ValidatedInstallEvents {
        approved_actions: admin.approved_actions,
        grant_ids: admin.grant_ids,
        bot_provision,
    })
}

pub(super) fn validate_admin_install_events(
    package: &AppletPackage,
    basis: &AppletInstallAuthoringRequestBasis,
    install_actor: &ActorId,
) -> Result<ValidatedAdminInstallEvents, AppError> {
    let realm_id = basis.effective_scope.realm_id();
    let registration = &basis.registration_event;
    if &basis.install_actor_id != install_actor
        || registration.kind != arkret_wire::EventKind::AppletRegistration
        || &registration.actor_id != install_actor
        || registration.actor_id.route_service_id() != &basis.target_station_id
        || &registration.realm_id != realm_id
        || registration.scope_ref != basis.effective_scope
        || registration.proofs.is_empty()
    {
        return Err(AppError::param_invalid(
            "registration_event must be a caller-signed Applet registration in the exact effective scope",
        )
        .with_wire_code("applet_install_plan_mismatch"));
    }
    let registration_epoch_evidence = registration_epoch_evidence_from_event(registration)?;
    let expected_registration =
        registration_payload_from_package(package, &registration_epoch_evidence)?;
    let submitted_registration = serde_json::to_value(&registration.payload).map_err(|error| {
        AppError::internal(format!(
            "registration_event payload cannot be canonicalized: {error}"
        ))
    })?;
    if submitted_registration != expected_registration {
        return Err(AppError::conflict(
            "registration_event payload does not match the Applet package",
        )
        .with_wire_code("applet_install_plan_mismatch"));
    }
    if basis.capability_grant_events.is_empty() {
        return Err(AppError::param_invalid(
            "capability_grant_events must contain at least one caller-signed Event",
        )
        .with_wire_code("applet_install_plan_mismatch"));
    }

    let expected_resource = match &basis.effective_scope {
        ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            let mut selector = WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
            selector.match_scope = Some(ResourceMatchScope::Exact);
            selector
        }
        _ => {
            return Err(AppError::param_invalid(
                "unsupported applet effective scope",
            ));
        }
    };
    let expected_applet_id = package.applet_id.clone();
    let requested = package
        .requested_scopes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut approved_actions = BTreeSet::new();
    let mut grant_ids = Vec::with_capacity(basis.capability_grant_events.len());
    let mut event_ids = BTreeSet::new();

    for event in &basis.capability_grant_events {
        if event.kind != arkret_wire::EventKind::CapabilityGrant
            || &event.actor_id != install_actor
            || event.actor_id.route_service_id() != &basis.target_station_id
            || &event.realm_id != realm_id
            || event.scope_ref != basis.effective_scope
            || event.proofs.is_empty()
            || !event_ids.insert(event.event_id.clone())
        {
            return Err(AppError::param_invalid(
                "every capability_grant_event must be unique, caller-signed, and use the exact effective scope",
            )
            .with_wire_code("applet_install_plan_mismatch"));
        }
        let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
                AppError::internal(format!(
                    "capability_grant_event payload cannot be canonicalized: {error}"
                ))
            })?)
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "capability_grant_event payload is invalid: {error}"
                ))
                .with_wire_code("applet_install_plan_mismatch")
            })?;
        let grant = payload.grant;
        if grant.issuer_id != event.actor_id
            || grant.realm_id.as_ref() != Some(realm_id)
            || !matches!(
                &grant.subject,
                CapabilitySubject::Actor(subject)
                    if subject == &ActorId::service(package.service_id.clone())
            )
            || grant.resources.len() != 1
            || grant.resources[0] != expected_resource
        {
            return Err(AppError::param_invalid(
                "capability grant issuer, subject authority pair, resource, or id does not match the install",
            )
            .with_wire_code("applet_install_plan_mismatch"));
        }
        let binding_count = grant
            .constraints
            .iter()
            .filter(|constraint| {
                constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                    && constraint.constraint_subkind
                        == Some(GrantConstraintSubkind::AppletAuthority)
                    && constraint.applet_id.as_ref() == Some(&expected_applet_id)
                    && constraint.executed_by.as_ref()
                        == Some(&arkret_wire::ActorId::service(package.service_id.clone()))
                    && constraint.registration_epoch.as_ref() == Some(&package.registration_epoch)
            })
            .count();
        if binding_count != 1 || grant.actions.is_empty() {
            return Err(AppError::param_invalid(
                "capability grant must carry one exact applet_authority binding and at least one action",
            )
            .with_wire_code("applet_install_plan_mismatch"));
        }
        for action in &grant.actions {
            if !requested.contains(action) || !approved_actions.insert(action.clone()) {
                return Err(AppError::param_invalid(
                    "capability grant actions must be unique and requested by the Applet package",
                )
                .with_wire_code("applet_install_plan_mismatch"));
            }
        }
        grant_ids.push(arkret_identifiers::GrantId::from_event_id(&event.event_id));
    }

    Ok(ValidatedAdminInstallEvents {
        approved_actions: approved_actions.into_iter().collect(),
        grant_ids,
    })
}

fn validate_bot_actor_station(
    bot_actor_id: &ActorId,
    target_station_id: &arkret_identifiers::DidCoreId,
) -> Result<(), AppError> {
    if bot_actor_id.route_service_id() != target_station_id {
        return Err(AppError::param_invalid(
            "Applet bot actor is not bound to the target Station",
        ));
    }
    Ok(())
}

fn validate_bot_managed_actor_unit(
    state: &AppState,
    commit: &AppletInstallRequestBody,
    grant_ids: &[GrantId],
    station_id: &str,
) -> Result<AppletManagedActorProvisionPayload, AppError> {
    let basis = commit.authoring_request().basis.install().ok_or_else(|| {
        AppError::param_invalid("install commit basis purpose is not install_bot")
    })?;
    let bundle = commit
        .managed_actor_bundle()
        .ok_or_else(|| AppError::param_invalid("install create requires a managed actor bundle"))?;
    let provision_event = &bundle.managed_actor_provision_event;
    let package = commit.applet_package();
    let expected_applet_id = package.applet_id.clone();
    let service_actor_id = ActorId::service(package.service_id.clone());
    let bot_actor_id = package.bot_actor_id.clone();
    validate_bot_actor_station(&bot_actor_id, &basis.target_station_id)?;
    if provision_event.kind.as_str() != "ak.applet.managed_actor.provision"
        || provision_event.actor_id != service_actor_id
        || provision_event.applet_id.as_ref() != Some(&expected_applet_id)
        || provision_event.realm_id != *basis.effective_scope.realm_id()
        || provision_event.proofs.is_empty()
    {
        return Err(AppError::param_invalid(
            "bot_actor_provision_event does not match the installed Applet service and scope",
        )
        .with_wire_code("applet_managed_actor_provision_invalid"));
    }
    let provision: AppletManagedActorProvisionPayload = serde_json::from_value(
        serde_json::to_value(&provision_event.payload).map_err(|error| {
            AppError::internal(format!(
                "managed actor provision serialization failed: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        AppError::param_invalid(format!("managed actor provision payload invalid: {error}"))
            .with_wire_code("applet_managed_actor_provision_invalid")
    })?;
    provision.validate().map_err(|error| {
        AppError::param_invalid(format!("managed actor provision payload invalid: {error}"))
            .with_wire_code("applet_managed_actor_provision_invalid")
    })?;
    if provision.actor_role != AppletManagedActorRole::Bot
        || provision.applet_id != expected_applet_id
        || provision.service_id != package.service_id
        || provision.actor_id != bot_actor_id
        || provision.actor_id.signing_principal_id() == &package.controller_id
        || provision.actor_id.route_service_id().as_str() != station_id
        || provision.registration_ref != basis.registration_event.event_id
        || !grant_ids.contains(&provision.applet_authority_ref)
    {
        return Err(AppError::param_invalid(
            "Bot provision authority does not exactly bind the staged registration, grant, actor, or hosting Station",
        )
        .with_wire_code("applet_managed_actor_provision_invalid"));
    }
    validate_managed_actor_method_evidence(&provision)?;

    let genesis = &bundle.pcr_genesis_event;
    let expected_realm_id = RealmId::from_event_id(&genesis.event_id);
    let genesis_object: arkret_models_collaboration::events_payloads::RealmGenesis =
        serde_json::from_value(
            genesis
                .payload
                .get("object")
                .cloned()
                .ok_or_else(|| AppError::param_missing("Bot PCR genesis object is required"))?,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("Bot PCR genesis object is invalid: {error}"))
                .with_wire_code("applet_managed_pcr_genesis_invalid")
        })?;
    let expected_host_notary = arkret_wire::NotaryValue::single_signer(
        state
            .service_notary_signer_descriptor()
            .map_err(AppError::internal)?,
    );
    validate_hosted_applet_pcr_notary(&genesis_object.notary, &expected_host_notary)?;
    let provision_ref_count = genesis
        .refs
        .iter()
        .filter(|reference| {
            reference.role == "applet_managed_actor_provision"
                && reference.critical
                && reference.id == provision_event.event_id.as_str()
        })
        .count();
    let provision_role_count = genesis
        .refs
        .iter()
        .filter(|reference| reference.role == "applet_managed_actor_provision")
        .count();
    if genesis.kind != arkret_wire::EventKind::RealmCreate
        || genesis.actor_id != bot_actor_id
        || genesis.executed_by.as_ref() != Some(&service_actor_id)
        || genesis.applet_id.as_ref() != Some(&expected_applet_id)
        || genesis.realm_id != expected_realm_id
        || genesis.authorization_ref.as_deref() != Some(provision.applet_authority_ref.as_str())
        || provision_role_count != 1
        || provision_ref_count != 1
        || genesis_object.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
        || genesis_object.initial_resolution.as_ref() != Some(&provision.initial_resolution)
    {
        return Err(AppError::param_invalid(
            "Bot PCR genesis does not exactly cross-bind its immutable provision authority",
        )
        .with_wire_code("applet_managed_pcr_genesis_invalid"));
    }
    let accountability = &bundle.accountability_grant_event;
    let profile = &bundle.profile_event;
    let registration_verification_method = package.webhook_auth.key_ref.as_str();
    let profile_accountability_ref_count = profile
        .refs
        .iter()
        .filter(|reference| {
            reference.role == "accountability"
                && reference.critical
                && reference.id == accountability.event_id.as_str()
        })
        .count();
    let profile_accountability_role_count = profile
        .refs
        .iter()
        .filter(|reference| reference.role == "accountability")
        .count();
    if accountability.kind.as_str() != "ak.identity.accountability_grant"
        || accountability.actor_id != service_actor_id
        || accountability.applet_id.as_ref() != Some(&expected_applet_id)
        || accountability.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
        || profile.kind.as_str() != "ak.profile.create"
        || profile.actor_id != bot_actor_id
        || profile.executed_by.as_ref() != Some(&service_actor_id)
        || profile.applet_id.as_ref() != Some(&expected_applet_id)
        || profile.authorization_ref.as_deref() != Some(provision.applet_authority_ref.as_str())
        || profile_accountability_role_count != 1
        || profile_accountability_ref_count != 1
        || accountability
            .proofs
            .iter()
            .chain(profile.proofs.iter())
            .any(|proof| {
                proof.as_producer().is_none_or(|proof| {
                    proof.verification_method != registration_verification_method
                })
            })
    {
        return Err(AppError::param_invalid(
            "Bot accountability/profile Events do not close the managed actor creation unit",
        )
        .with_wire_code("applet_managed_actor_profile_invalid"));
    }

    let grant: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&accountability.payload).map_err(|error| {
            AppError::param_invalid(format!(
                "Bot accountability payload cannot be encoded: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        AppError::param_invalid(format!("Bot accountability payload is invalid: {error}"))
            .with_wire_code("applet_managed_actor_profile_invalid")
    })?;
    if grant.issuer_id != package.service_id
        || grant.subject_id != *package.bot_actor_id.signing_principal_id()
        || grant.accountability_scope
            != AccountabilityScope::Single(AccountabilityScopeKind::ContractedService)
        || grant.grant_status != AccountabilityGrantStatus::Active
        || grant.proof.verification_method != registration_verification_method
    {
        return Err(AppError::param_invalid(
            "Bot accountability payload must be an active contracted-service grant from the Applet service to the canonical Bot",
        )
        .with_wire_code("applet_managed_actor_profile_invalid"));
    }
    grant
        .validate_lifecycle_at(chrono::Utc::now())
        .map_err(|error| {
            AppError::param_invalid(format!("Bot accountability payload is invalid: {error}"))
                .with_wire_code("applet_managed_actor_profile_invalid")
        })?;
    let proof_binding = grant.canonical_proof_binding_bytes().map_err(|error| {
        AppError::param_invalid(format!(
            "Bot accountability proof binding is invalid: {error}"
        ))
        .with_wire_code("applet_managed_actor_profile_invalid")
    })?;
    verify_install_registration_epoch_payload_jws(
        state,
        &registration_epoch_evidence_from_event(&basis.registration_event)?,
        &proof_binding,
        &grant.proof.jws,
        registration_verification_method,
    )?;

    let profile_payload: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(serde_json::to_value(&profile.payload).map_err(|error| {
            AppError::param_invalid(format!("Bot profile payload cannot be encoded: {error}"))
        })?)
        .map_err(|error| {
            AppError::param_invalid(format!("Bot profile payload is invalid: {error}"))
                .with_wire_code("applet_managed_actor_profile_invalid")
        })?;
    let actor_profile = profile_payload.object;
    let has_exact_accountable_principal = actor_profile.accountable_principal_ids.len() == 1
        && actor_profile.accountable_principal_ids[0].as_str() == package.service_id.as_str();
    if actor_profile.principal_id != *package.bot_actor_id.signing_principal_id()
        || actor_profile.realm_id.as_ref() != Some(basis.effective_scope.realm_id())
        || actor_profile.actor_kind != arkret_wire::ActorKind::Integration
        || actor_profile
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(package.applet_id.as_str())
        || !has_exact_accountable_principal
    {
        return Err(AppError::param_invalid(
            "Bot profile payload must bind the canonical Bot to exactly the installed Applet service",
        )
        .with_wire_code("applet_managed_actor_profile_invalid"));
    }
    Ok(provision)
}

fn verify_install_registration_epoch_payload_jws(
    state: &AppState,
    evidence: &AppletRegistrationEpochEvidence,
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
) -> Result<(), AppError> {
    if !evidence.contains_signing_key(verification_method) {
        return Err(AppError::capability_denied(
            "Bot accountability proof key is outside the installed registration epoch",
        )
        .with_wire_code("invalid_proof"));
    }
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
            AppError::param_invalid("Applet service DID document could not be resolved")
                .with_wire_code("applet_registration_epoch_evidence_mismatch")
                .with_reason_detail(reason)
        })?;
    evidence
        .validate_against_did_document(&document)
        .map_err(|error| {
            AppError::param_invalid("Applet registration-epoch DID evidence mismatch")
                .with_wire_code("applet_registration_epoch_evidence_mismatch")
                .with_reason_detail(error.to_string())
        })?;
    let verification_method =
        arkret_wire::DidUrl::new(verification_method.to_owned()).map_err(|error| {
            AppError::param_invalid(format!(
                "Bot accountability proof verification method is invalid: {error}"
            ))
            .with_wire_code("invalid_proof")
        })?;
    arkret_identity::verify_jws_with_document(
        canonical_bytes,
        jws,
        &verification_method,
        &evidence.did,
        &document,
    )
    .map_err(|error| {
        AppError::param_invalid(format!(
            "Bot accountability payload proof JWS verification failed: {error}"
        ))
        .with_wire_code("invalid_proof")
    })
}

pub(super) fn validate_managed_actor_method_evidence(
    provision: &AppletManagedActorProvisionPayload,
) -> Result<(), AppError> {
    let (_, log_entries, witness_records) = provision.method_history_evidence.webvh_material();
    let mut log_bytes = Vec::new();
    for entry in log_entries {
        log_bytes.extend(
            arkret_canonical::canonical_json_bytes(entry).map_err(|error| {
                AppError::param_invalid(format!("WebVH log entry is not canonicalizable: {error}"))
            })?,
        );
        log_bytes.push(b'\n');
    }
    let witness_bytes = serde_json::to_vec(witness_records)
        .map_err(|error| AppError::param_invalid(format!("witness evidence invalid: {error}")))?;
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &provision.initial_resolution.did,
        &log_bytes,
        Some(&witness_bytes),
    )
    .map_err(|error| {
        AppError::param_invalid(format!("Applet-managed DID evidence invalid: {error}"))
            .with_wire_code(error.reason_code())
    })?;
    let terminal = verified
        .log
        .raw_entries
        .last()
        .ok_or_else(|| AppError::param_invalid("Applet-managed DID log is empty"))?;
    let terminal_head = arkret_canonical::canonical_sha256(terminal)
        .map_err(|error| AppError::param_invalid(format!("DID terminal invalid: {error}")))?;
    if provision.initial_resolution.did.method() != "webvh"
        || verified.log.head_version_id != provision.initial_resolution.version_id
        || terminal_head != provision.initial_resolution.method_history_head
    {
        return Err(AppError::param_invalid(
            "Applet-managed WebVH evidence terminal differs from initial_resolution",
        )
        .with_wire_code("identity_method_evidence_invalid"));
    }
    Ok(())
}

pub(super) async fn validate_managed_actor_current_method_evidence(
    state: &AppState,
    provision: &AppletManagedActorProvisionPayload,
) -> Result<(), AppError> {
    let did = &provision.initial_resolution.did;
    crate::jws_verify::enforce_high_risk_did_freshness(state, did)
        .await
        .map_err(|error| {
            AppError::param_invalid(
                "Applet-managed WebVH evidence lacks a fresh trusted current resolution",
            )
            .with_wire_code("identity_method_evidence_invalid")
            .with_reason_detail(error)
        })?;
    let history_head = Hash::new(provision.initial_resolution.method_history_head.clone())
        .map_err(|error| {
            AppError::param_invalid(format!(
                "Applet-managed WebVH history head is invalid: {error}"
            ))
            .with_wire_code("identity_method_evidence_invalid")
        })?;
    let pinned = state
        .dids()
        .resolve_pinned_webvh_state(did, &provision.initial_resolution.version_id, &history_head)
        .await
        .map_err(|error| {
            AppError::param_invalid(format!(
                "Applet-managed WebVH evidence is not an accepted trusted history state: {error}"
            ))
            .with_wire_code("identity_method_evidence_invalid")
        })?;
    if !managed_actor_pinned_resolution_is_current(
        &pinned,
        did,
        &provision.initial_resolution.version_id,
        &history_head,
    ) {
        return Err(AppError::param_invalid(
            "Applet-managed WebVH evidence is a historical prefix rather than the current trusted head",
        )
        .with_wire_code("identity_method_evidence_invalid"));
    }
    Ok(())
}

fn managed_actor_pinned_resolution_is_current(
    pinned: &soland_services::identity::PinnedDidDocumentState,
    expected_did: &arkret_identifiers::Did,
    expected_version_id: &str,
    expected_history_head: &Hash,
) -> bool {
    pinned.status == PinnedDidVersionStatus::Current
        && pinned.current_version_id == expected_version_id
        && pinned.version_id == expected_version_id
        && &pinned.log_head_digest == expected_history_head
        && &pinned.did == expected_did
}

pub(super) async fn register_package_install(
    state: &AppState,
    session: &SessionRecord,
    commit: AppletInstallRequestBody,
    producer_verification_method: arkret_wire::DidUrl,
    producer_signing_key: arkret_wire::DidKey,
    idempotency_key: String,
    body_digest: String,
    authoring_preview_subject_key: String,
    authoring_request_digest: String,
    res: &mut Response,
) -> Result<AppletInstallOutcome, AppError> {
    let owner_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let owner_actor_key = owner_actor.to_string();
    let owner_actor_id = owner_actor_key.as_str();
    let validated_events =
        validate_formal_install_events(state, &commit, &owner_actor, state.service_id())?;
    let approved_actions = validated_events.approved_actions;
    let capability_grant_refs = validated_events.grant_ids;
    let basis = commit.authoring_request().basis.install().ok_or_else(|| {
        AppError::param_invalid("install commit basis purpose is not install_bot")
    })?;
    let registration_event = basis.registration_event.clone();
    let capability_grant_events = basis.capability_grant_events.clone();
    let submitted_plan_digest = commit
        .authoring_request()
        .plan_digest
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("install authoring request has no plan_digest"))?
        .to_string();
    let effective_scope = basis.effective_scope.clone();
    let actor_policy = basis.actor_policy.clone();
    let e2ee_policy = basis.e2ee_policy.clone();
    let package = commit.applet_package().clone();
    let typed_applet_id = package.applet_id.clone();
    let applet_id = package.applet_id.to_string();
    let target_station_id = basis.target_station_id.clone();
    let realm_id = effective_scope_realm_id(&effective_scope);
    let ghost_actors_allowed =
        ghost_actors_allowed_for_install(&package, &approved_actions, actor_policy.as_ref());

    if let Some(existing) = applet_record(state, &applet_id, &effective_scope).await? {
        if existing.idempotency_key == idempotency_key {
            if existing.install_body_digest.as_str() == body_digest {
                res.status_code(StatusCode::OK);
                return Ok(existing.install_response);
            }
            return Err(AppError::conflict(
                "Idempotency-Key was already used with a different applet install body",
            )
            .with_wire_code("duplicate_conflict"));
        }
        return Err(
            AppError::conflict("applet package is already installed in this scope")
                .with_wire_code("duplicate_conflict"),
        );
    }

    let existing_identity = applet_identity(state, &applet_id, target_station_id.as_str()).await?;
    let (identity, include_identity_events, expected_identity) = match commit {
        AppletInstallRequestBody::Create(create) => {
            if existing_identity.is_some() {
                return Err(AppError::conflict(
                    "applet identity already exists; install another scope with reuse_existing_managed_actor",
                )
                .with_wire_code("applet_managed_actor_reuse_required"));
            }
            let bot_provision = validated_events.bot_provision.as_ref().ok_or_else(|| {
                AppError::internal("validated create install has no Bot provision")
            })?;
            validate_managed_actor_current_method_evidence(state, bot_provision).await?;
            let bundle = create.managed_actor_bundle;
            (
                AppletIdentityRecord {
                    applet_id: package.applet_id.clone(),
                    registry_id: package.controller_id.clone(),
                    bot_actor_id: bot_provision.actor_id.clone(),
                    bot_actor_provision_ref: bundle.managed_actor_provision_event.event_id.clone(),
                    bot_principal_control_realm_id: RealmId::from_event_id(
                        &bundle.pcr_genesis_event.event_id,
                    ),
                    initial_package: package.clone(),
                    initial_owner_actor_id: registration_event.actor_id.clone(),
                    initial_effective_scope: effective_scope.clone(),
                    initial_registration_event: registration_event.clone(),
                    initial_capability_grant_refs: capability_grant_refs.clone(),
                    bot_actor_provision_event: bundle.managed_actor_provision_event,
                    bot_pcr_genesis_event: bundle.pcr_genesis_event,
                    bot_accountability_grant_event: bundle.accountability_grant_event,
                    bot_profile_event: bundle.profile_event,
                    globally_fenced_at: None,
                },
                true,
                None,
            )
        }
        AppletInstallRequestBody::Reuse(reuse) => {
            let existing = existing_identity.ok_or_else(|| {
                AppError::conflict("applet identity does not exist; first install must create it")
                    .with_wire_code("applet_managed_actor_reuse_invalid")
            })?;
            if existing.globally_fenced_at.is_some() {
                return Err(
                    AppError::conflict("applet managed identity is globally fenced")
                        .with_wire_code("applet_revoked"),
                );
            }
            let reference = reuse.reuse_existing_managed_actor;
            let initial_package = &existing.initial_package;
            if package.applet_id != initial_package.applet_id
                || package.controller_id != initial_package.controller_id
                || package.service_id != initial_package.service_id
                || package.bot_actor_id != initial_package.bot_actor_id
                || reference.actor_id != existing.bot_actor_id
                || reference.managed_actor_provision_ref != existing.bot_actor_provision_ref
                || reference.pcr_genesis_ref != existing.bot_pcr_genesis_event.event_id
                || reference.accountability_grant_ref
                    != existing.bot_accountability_grant_event.event_id
                || reference.profile_event_ref != existing.bot_profile_event.event_id
                || reference.initial_package_bot_actor_id != existing.bot_actor_id
            {
                return Err(AppError::conflict(
                    "reuse_existing_managed_actor does not match the first accepted Applet identity",
                )
                .with_wire_code("applet_managed_actor_reuse_invalid"));
            }
            let provision: AppletManagedActorProvisionPayload = serde_json::from_value(
                serde_json::to_value(&existing.bot_actor_provision_event.payload).map_err(
                    |error| {
                        AppError::internal(format!(
                            "stored Bot provision payload serialization failed: {error}"
                        ))
                    },
                )?,
            )
            .map_err(|error| {
                AppError::internal(format!("stored Bot provision payload is invalid: {error}"))
            })?;
            validate_managed_actor_current_method_evidence(state, &provision).await?;
            let expected_identity = encode_applet_identity(&existing)?;
            (existing, false, Some(expected_identity))
        }
    };
    let identity_value = encode_applet_identity(&identity)?;

    let now = chrono::Utc::now();
    let e2ee_authorization_refs =
        e2ee_authorization_refs_for_install(&package, e2ee_policy.as_ref())?;
    debug_assert!(!approved_actions.is_empty());
    let effective_status = if approved_actions.len() < package.requested_scopes.len() {
        AppletInstallEffectiveStatus::PartiallyInstalled
    } else {
        AppletInstallEffectiveStatus::Installed
    };
    let effective_status_wire = match effective_status {
        AppletInstallEffectiveStatus::Installed => "installed",
        AppletInstallEffectiveStatus::PartiallyInstalled => "partially_installed",
    };
    let install_id = ids::generate_install_id();
    let response = AppletInstallOutcome {
        install_id,
        applet_id: package.applet_id.clone(),
        registration_event_ref: registration_event.event_id.clone(),
        registration_epoch: package.registration_epoch.clone(),
        bot_actor_id: identity.bot_actor_id.clone(),
        bot_actor_provision_ref: identity.bot_actor_provision_ref.clone(),
        bot_principal_control_realm_id: identity.bot_principal_control_realm_id.clone(),
        capability_grant_refs,
        e2ee_authorization_refs,
        widget_policy_ref: None,
        effective_status,
        rejections: denied_scope_values(&package, &approved_actions)
            .into_iter()
            .map(|scope| AppletRejectedItem {
                requested_scope: Some(scope.requested_scope),
                reason_code: scope.reason_code,
            })
            .collect(),
    };
    let mut record = AppletRecord {
        identity,
        applet_id: typed_applet_id.clone(),
        owner_actor_id: registration_event.actor_id.clone(),
        portal_realm_id: RealmId::new(realm_id).map_err(|error| {
            AppError::internal(format!("validated portal realm id is invalid: {error}"))
        })?,
        effective_scope,
        capabilities: approved_actions,
        package: package.clone(),
        ghost_actors_allowed,
        status: effective_status_wire.to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key,
        install_body_digest: Hash::new(body_digest).map_err(|error| {
            AppError::internal(format!("validated install body digest is invalid: {error}"))
        })?,
        install_id: response.install_id.clone(),
        install_response: response.clone(),
        registration_event,
        capability_grant_events,
        install_execution: Value::Null,
        revoke_execution: None,
        ghosts: Vec::new(),
    };
    record.install_execution = build_install_execution_record(
        state.service_id(),
        owner_actor_id,
        &record.idempotency_key,
        record.install_body_digest.as_str(),
        &submitted_plan_digest,
        &record,
        &response,
        true,
    )?;
    let mut formal_events = Vec::with_capacity(6 + record.capability_grant_events.len());
    formal_events.push(record.registration_event.clone());
    formal_events.extend(record.capability_grant_events.iter().cloned());
    if include_identity_events {
        formal_events.push(record.bot_actor_provision_event.clone());
        formal_events.push(record.bot_pcr_genesis_event.clone());
        formal_events.push(record.bot_accountability_grant_event.clone());
        formal_events.push(record.bot_profile_event.clone());
    }
    let record_value = encode_applet_record(&record)?;
    crate::routing::events::event_log::submit_applet_install_batch(
        state,
        formal_events,
        typed_applet_id,
        target_station_id,
        expected_identity,
        identity_value,
        producer_verification_method,
        producer_signing_key,
        record_value,
        authoring_preview_subject_key,
        authoring_request_digest,
        crate::routing::events::event_log::EventCommitIdempotency {
            authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                    AppError::internal(format!("session actor invalid: {error}"))
                })?,
                state.service_core_id(),
            )),
            operation_id: "ak.self.applet.command.install".to_owned(),
            key: record.idempotency_key.clone(),
            request_hash: record.install_body_digest.to_string(),
        },
        serde_json::to_value(&response)
            .map_err(|error| AppError::internal(format!("Applet outcome invalid: {error}")))?,
    )
    .await
    .map_err(|error| {
        AppError::new(
            soland_http::error::ErrorCode::from_wire(&error.code)
                .unwrap_or(soland_http::error::ErrorCode::ParamInvalid),
            error.message,
        )
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_id),
        "applet.install",
        json!({
            "applet_id": record.applet_id.clone(),
            "namespaces": &record.package.namespaces,
            "service_id": package.service_id,
            "bot_actor_id": record.bot_actor_id,
            "registration_event_ref": response.registration_event_ref,
            "registration_epoch": package.registration_epoch,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    Ok(response)
}

fn build_install_execution_record(
    principal_id: &str,
    admin_actor_id: &str,
    idempotency_key: &str,
    body_digest: &str,
    submitted_plan_digest: &str,
    record: &AppletRecord,
    response: &AppletInstallOutcome,
    accepted: bool,
) -> Result<Value, AppError> {
    let status = if accepted { "completed" } else { "pending" };
    let produced_event_refs = if accepted {
        install_produced_event_refs(record, response)
    } else {
        Vec::new()
    };
    Ok(json!({
        "principal_id": principal_id,
        "admin_actor_id": admin_actor_id,
        "idempotency_key": idempotency_key,
        "body_hash": body_digest,
        "submitted_plan_digest": submitted_plan_digest,
        "status": status,
        "effective_status": record.status.as_str(),
        "produced_event_refs": produced_event_refs,
        "steps": install_execution_steps(record, response, accepted)?,
    }))
}

fn install_produced_event_refs(
    record: &AppletRecord,
    response: &AppletInstallOutcome,
) -> Vec<String> {
    let mut refs = Vec::with_capacity(
        5 + response.capability_grant_refs.len()
            + usize::from(response.widget_policy_ref.is_some()),
    );
    refs.push(response.registration_event_ref.to_string());
    refs.extend(
        record
            .capability_grant_events
            .iter()
            .map(|event| event.event_id.to_string()),
    );
    if record.registration_event.event_id == record.identity.initial_registration_event.event_id {
        refs.push(record.bot_actor_provision_event.event_id.to_string());
        refs.push(record.bot_pcr_genesis_event.event_id.to_string());
        refs.push(record.bot_accountability_grant_event.event_id.to_string());
        refs.push(record.bot_profile_event.event_id.to_string());
    }
    if let Some(widget_policy_ref) = &response.widget_policy_ref {
        refs.push(widget_policy_ref.to_string());
    }
    refs
}

fn install_execution_steps(
    record: &AppletRecord,
    response: &AppletInstallOutcome,
    accepted: bool,
) -> Result<Vec<Value>, AppError> {
    let package = &record.package;
    let mut steps = Vec::with_capacity(5 + response.capability_grant_refs.len());
    let event = &record.registration_event;
    steps.push(install_execution_step(
        0,
        arkret_wire::EventKind::AppletRegistration.as_str(),
        event.event_id.as_str(),
        crate::util::canonical_digest(&serde_json::to_value(event).map_err(|error| {
            AppError::internal(format!("registration Event serialization failed: {error}"))
        })?)?,
        accepted,
        None,
    ));
    for (offset, event) in record.capability_grant_events.iter().enumerate() {
        let grant_id = arkret_identifiers::GrantId::from_event_id(&event.event_id);
        steps.push(install_execution_step(
            offset + 1,
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            event.event_id.as_str(),
            crate::util::canonical_digest(&serde_json::to_value(event).map_err(|error| {
                AppError::internal(format!(
                    "capability grant Event serialization failed: {error}"
                ))
            })?)?,
            accepted,
            Some(json!({
                "applet_id": record.applet_id.as_str(),
                "grant_id": grant_id.as_str(),
                "executed_by": arkret_wire::ActorId::service(package.service_id.clone()),
                "registration_epoch": package.registration_epoch.to_string(),
            })),
        ));
    }
    if record.registration_event.event_id == record.identity.initial_registration_event.event_id {
        let base = 1 + record.capability_grant_events.len();
        for (offset, event) in [
            &record.bot_actor_provision_event,
            &record.bot_pcr_genesis_event,
            &record.bot_accountability_grant_event,
            &record.bot_profile_event,
        ]
        .into_iter()
        .enumerate()
        {
            steps.push(install_execution_step(
                base + offset,
                event.kind.as_str(),
                event.event_id.as_str(),
                crate::util::canonical_digest(&serde_json::to_value(event).map_err(|error| {
                    AppError::internal(format!(
                        "Applet-managed actor Event serialization failed: {error}"
                    ))
                })?)?,
                accepted,
                None,
            ));
        }
    }
    Ok(steps)
}

fn install_execution_step(
    step_index: usize,
    target_event_kind: &str,
    planned_event_ref: &str,
    canonical_event_body_hash: String,
    accepted: bool,
    grant_binding: Option<Value>,
) -> Value {
    let status = if accepted { "accepted" } else { "pending" };
    let event_ref = if accepted {
        Value::String(planned_event_ref.to_owned())
    } else {
        Value::Null
    };
    let mut step = json!({
        "step_index": step_index,
        "target_event_kind": target_event_kind,
        "canonical_event_body_hash": canonical_event_body_hash,
        "status": status,
        "planned_event_ref": planned_event_ref,
        "event_ref": event_ref,
    });
    if let Some(grant_binding) = grant_binding
        && let Some(object) = step.as_object_mut()
    {
        object.insert("grant_binding".to_owned(), grant_binding);
    }
    step
}

pub(super) fn validate_applet_package(
    state: &AppState,
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
) -> Result<(), AppError> {
    validate_requested_capability_actions(package)?;
    validated_registration_epoch_evidence(state, package, registration_epoch_evidence)?;
    package
        .validate_with_epoch_evidence(registration_epoch_evidence)
        .map_err(|error| {
            AppError::param_invalid(format!("applet package invalid: {error}"))
                .with_wire_code("schema_violation")
        })?;
    if let Some(expires_at) = package.expires_at
        && expires_at <= chrono::Utc::now()
    {
        return Err(AppError::conflict("applet package has expired")
            .with_wire_code("applet_package_expired"));
    }
    let expected_digest = package
        .compute_package_digest()
        .map_err(|error| AppError::internal(format!("package digest failed: {error}")))?;
    if package.package_digest.as_ref() != Some(&expected_digest) {
        return Err(
            AppError::param_invalid("applet package_digest does not match package body")
                .with_wire_code("schema_violation"),
        );
    }
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("applet package proof is required"))?;
    proof.validate().map_err(|error| {
        AppError::param_invalid(format!("applet package proof invalid: {error}"))
    })?;
    let mut unsigned = package.clone();
    unsigned.proof = None;
    let unsigned_canonical_bytes =
        arkret_canonical::canonical_json_bytes(&unsigned).map_err(|error| {
            AppError::internal(format!("package proof canonical bytes failed: {error}"))
        })?;
    let expected_payload_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&unsigned_canonical_bytes))
            .map_err(|error| AppError::internal(format!("package proof digest invalid: {error}")))?;
    if proof.payload_digest != expected_payload_digest {
        return Err(
            AppError::param_invalid("applet package proof payload_digest mismatch")
                .with_wire_code("proof_invalid"),
        );
    }
    // applet-integration.md §4.1 line 193/199 + §4b line 229: the controller
    // detached proof MUST be a real signature by `controller_id` covering the
    // canonical package body. Digest equality alone is forgeable — anyone can
    // recompute `payload_digest` over `unsigned` and sign it with an arbitrary
    // key. Anchor the proof's verification_method to `controller_id` and run
    // the same detached-JWS verifier every other soland proof path uses
    // (dev: shape-only; production: DID-resolved Ed25519). Preview/commit MUST
    // fail closed (`proof_invalid`) when the controller proof is invalid or its
    // key cannot be resolved.
    validate_controller_proof(state, package, &unsigned_canonical_bytes)?;
    Ok(())
}

pub(super) fn registration_epoch_producer_signing_key(
    state: &AppState,
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
) -> Result<arkret_wire::DidKey, AppError> {
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
            AppError::param_invalid("applet service DID document could not be resolved")
                .with_wire_code("applet_registration_epoch_evidence_mismatch")
                .with_reason_detail(reason)
        })?;
    validate_registration_epoch_evidence_for_document(package, evidence, &document)?;
    let public_key_multibase = document
        .verification_methods
        .get(package.webhook_auth.key_ref.as_str())
        .ok_or_else(|| {
            AppError::param_invalid(
                "applet webhook_auth key_ref is absent from the current service DID document",
            )
            .with_wire_code("applet_registration_epoch_signing_key_mismatch")
        })?;
    arkret_wire::DidKey::new(format!("did:key:{public_key_multibase}")).map_err(|error| {
        AppError::param_invalid(format!(
            "applet registration-epoch producer key is invalid: {error}"
        ))
        .with_wire_code("applet_registration_epoch_signing_key_mismatch")
    })
}

fn validate_requested_capability_actions(package: &AppletPackage) -> Result<(), AppError> {
    for action in &package.requested_scopes {
        match arkret_schema::capability_action(action) {
            Some(_) => {}
            None => {
                return Err(AppError::param_invalid(format!(
                    "applet package requested_scopes contains unknown capability action: {action}"
                ))
                .with_wire_code("schema_violation")
                .with_reason_detail("capability_action_unknown"));
            }
        }
    }
    Ok(())
}

/// Cryptographically verify the controller detached proof on an Applet package.
///
/// Reuses the shared soland detached-JWS verifier boundary
/// (`crate::jws_verify`), dispatching on `development_mode` exactly like
/// [`crate::routing::federation::move_seal::select_jws_verifier`]: dev mode runs
/// the RFC 7515 shape-only check (no live DID document required, but the
/// all-zero sentinel signature is still rejected), production resolves the
/// controller DID document and runs the Ed25519 verify against the
/// verification method's public key.
///
/// `controller_id` is anchored two ways: the proof's `verification_method`
/// MUST be a DID URL under `controller_id`, and the resolved public key MUST
/// come from `controller_id`'s DID document (production). A proof signed by any
/// other key — even with a correctly recomputed `payload_digest` — fails here.
fn validate_controller_proof(
    state: &AppState,
    package: &AppletPackage,
    unsigned_canonical_bytes: &[u8],
) -> Result<(), AppError> {
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("applet package proof is required"))?;
    let controller_id = package.controller_id.as_str();
    crate::jws_verify::validate_verification_method_controller(
        controller_id,
        &proof.verification_method,
    )
    .map_err(|reason| {
        AppError::param_invalid("applet package proof is not anchored to controller_id")
            .with_wire_code("proof_invalid")
            .with_reason_detail(reason)
    })?;
    let verify_result = if state.config().development_mode {
        crate::jws_verify::verify_jws_shape(
            unsigned_canonical_bytes,
            &proof.jws,
            &proof.verification_method,
            controller_id,
        )
    } else {
        crate::jws_verify::verify_did_controlled_jws(
            unsigned_canonical_bytes,
            &proof.jws,
            &proof.verification_method,
            controller_id,
            state,
        )
    };
    verify_result.map_err(|reason| {
        AppError::param_invalid("applet package controller proof signature is invalid")
            .with_wire_code("proof_invalid")
            .with_reason_detail(reason)
    })
}

fn validated_registration_epoch_evidence(
    state: &AppState,
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
) -> Result<(), AppError> {
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
            AppError::param_invalid("applet service DID document could not be resolved")
                .with_wire_code("applet_registration_epoch_evidence_mismatch")
                .with_reason_detail(reason)
        })?;
    validate_registration_epoch_evidence_for_document(package, evidence, &document)
}

fn validate_registration_epoch_evidence_for_document(
    package: &AppletPackage,
    evidence: &AppletRegistrationEpochEvidence,
    document: &DidDocument,
) -> Result<(), AppError> {
    evidence
        .validate_against_did_document(document)
        .map_err(|reason| {
            AppError::param_invalid(
                "applet registration_epoch evidence does not match service DID document",
            )
            .with_wire_code("applet_registration_epoch_evidence_mismatch")
            .with_reason_detail(reason.to_string())
        })?;
    if !evidence.contains_signing_key(&package.webhook_auth.key_ref) {
        return Err(AppError::param_invalid(
            "applet webhook_auth key_ref is outside registration_epoch evidence",
        )
        .with_wire_code("applet_registration_epoch_signing_key_mismatch"));
    }
    Ok(())
}

pub(super) async fn build_install_plan(
    state: &AppState,
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
    scope: &ScopeRef,
    approved_scopes: Vec<ScopeGrant>,
) -> Result<AppletInstallPlan, AppError> {
    let namespace_conflicts =
        namespace_conflicts_for(state, package.applet_id.as_str(), &package.namespaces).await?;
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }
    let approved_actions = actions_from_approved_scopes(&approved_scopes);
    let denied_scopes = denied_scope_values(package, &approved_actions);
    let registration_payload =
        registration_payload_from_package(package, registration_epoch_evidence)?;
    let package_digest = package
        .package_digest
        .clone()
        .ok_or_else(|| AppError::param_missing("applet_package.package_digest is required"))?;
    let seed = json!({
        "schema": arkret_wire::SchemaId::APPLET_INSTALL_PLAN_V1,
        "applet_id": package.applet_id,
        "package_digest": package_digest,
        "registration_epoch": package.registration_epoch,
        "effective_scope": scope,
        "requested_scopes": package.requested_scopes,
        "approved_scopes": approved_scopes,
        "denied_scopes": denied_scopes,
        "events_to_submit": [{
            "event_kind": arkret_wire::EventKind::AppletRegistration,
            "payload": registration_payload,
        }],
        "capability_constraints": capability_constraints_for_scope(scope),
        "namespace_conflicts": [],
        "e2ee_effect": e2ee_effect_for_package(package),
        "widget_effect": widget_effect_for_package(package),
        "warnings": [],
    });
    let plan_id = deterministic_plan_id(&seed)?;
    let event_payload = serde_json::from_value(registration_payload).map_err(|error| {
        AppError::internal(format!(
            "applet registration payload is not an object: {error}"
        ))
    })?;
    let mut plan = AppletInstallPlan {
        schema: arkret_wire::SchemaId::APPLET_INSTALL_PLAN_V1.to_owned(),
        plan_id,
        applet_id: package.applet_id.clone(),
        package_digest: package_digest.clone(),
        registration_epoch: package.registration_epoch.clone(),
        effective_scope: scope.clone(),
        requested_scopes: package.requested_scopes.clone(),
        approved_scopes,
        denied_scopes,
        event_submissions: vec![EventSubmission {
            event_kind: arkret_wire::EventKind::AppletRegistration
                .as_str()
                .to_owned(),
            payload: event_payload,
            refs: None,
        }],
        capability_constraints: capability_constraints_for_scope(scope),
        namespace_conflicts: Vec::<NamespaceConflict>::new(),
        e2ee_effect: e2ee_effect_for_package(package),
        widget_effect: widget_effect_for_package(package),
        warnings: Vec::new(),
        plan_digest: package_digest.clone(),
    };
    plan.seal()
        .map_err(|error| AppError::internal(format!("install plan digest failed: {error}")))?;
    Ok(plan)
}

pub(super) fn registration_payload_from_package(
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
) -> Result<Value, AppError> {
    Ok(json!({
        "applet_id": package.applet_id,
        "service_id": package.service_id,
        "controller_id": package.controller_id,
        "base_url": package.base_url,
        "bot_actor_id": package.bot_actor_id,
        "claimed_profiles": package.claimed_profiles,
        "protocols": package.protocols,
        "namespaces": package.namespaces,
        "receive_events": package.receive_events,
        "receive_signals": package.receive_signals,
        "rate_limited": package.rate_limited,
        "requested_scopes": package.requested_scopes,
        "registration_epoch": package.registration_epoch,
        "webhook_auth": package.webhook_auth,
        "manifest": package.manifest_snapshot(registration_epoch_evidence),
        "proof": package.proof,
        "created_at": package.created_at,
    }))
}

pub(super) fn registration_epoch_evidence_from_event(
    event: &Event,
) -> Result<AppletRegistrationEpochEvidence, AppError> {
    super::registration_epoch_evidence_from_event(event).map_err(|error| {
        AppError::param_invalid(error).with_wire_code("applet_registration_epoch_evidence_mismatch")
    })
}

pub(super) fn capability_constraints_for_scope(scope: &ScopeRef) -> Vec<CapabilityConstraint> {
    let mut params = std::collections::BTreeMap::from([(
        "realm_id".to_owned(),
        Value::String(effective_scope_realm_id(scope)),
    )]);
    if let ScopeRef::Circle { circle_id, .. } = scope {
        params.insert("circle_id".to_owned(), Value::String(circle_id.to_string()));
    }
    vec![CapabilityConstraint {
        constraint_kind: "effective_scope".to_owned(),
        params: Some(params),
    }]
}

pub(super) fn e2ee_effect_for_package(package: &AppletPackage) -> E2eeEffect {
    E2eeEffect {
        mls_join_required: package.e2ee_policy.mls_join_requested.unwrap_or(false),
        plaintext_access: "policy_declared".to_owned(),
        authorization_refs: None,
    }
}

fn package_requests_mls_join(package: &AppletPackage) -> bool {
    package.e2ee_policy.mls_join_requested.unwrap_or(false)
}

fn e2ee_authorization_refs_for_install(
    package: &AppletPackage,
    _e2ee_policy: Option<&E2eePolicy>,
) -> Result<Vec<EventId>, AppError> {
    if !package_requests_mls_join(package) {
        return Ok(Vec::new());
    }
    Err(AppError::capability_denied(
        "applet E2EE MLS join has no registered independent authorization artifact",
    )
    .with_wire_code("applet_e2ee_join_unauthorized"))
}

pub(super) fn widget_effect_for_package(package: &AppletPackage) -> WidgetEffect {
    WidgetEffect {
        widget_allowed: package.widget.is_some(),
        policy_event_ref: None,
    }
}

pub(super) fn deterministic_plan_id(plan_seed: &Value) -> Result<arkret_wire::PlanId, AppError> {
    let digest = crate::util::canonical_digest(plan_seed)?;
    arkret_wire::PlanId::new(format!("ak:plan:{}", digest.trim_start_matches("sha256:")))
        .map_err(|error| AppError::internal(error.to_string()))
}

pub(super) fn actions_from_approved_scopes(scopes: &[ScopeGrant]) -> Vec<String> {
    scopes
        .iter()
        .flat_map(|scope| scope.actions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn denied_scope_values(
    package: &AppletPackage,
    approved_actions: &[String],
) -> Vec<DeniedScope> {
    let approved = approved_actions.iter().collect::<BTreeSet<_>>();
    package
        .requested_scopes
        .iter()
        .filter(|scope| !approved.contains(scope))
        .map(|scope| DeniedScope {
            requested_scope: scope.clone(),
            reason_code: arkret_wire::ReasonCode::from_wire("not_approved"),
        })
        .collect()
}

pub(super) async fn namespace_conflicts_for(
    state: &AppState,
    applet_id: &str,
    namespaces: &AppletWireNamespaces,
) -> Result<Vec<Value>, AppError> {
    let mut conflicts = Vec::new();
    for record in applet_records(state)
        .await?
        .into_iter()
        .filter(|record| record.revoked_at.is_none() && record.applet_id.as_str() != applet_id)
    {
        let existing = &record.package.namespaces;
        for conflict in namespaces.conflicts_with(existing) {
            conflicts.push(json!({
                "namespace": conflict.pattern,
                "existing_owner": record.applet_id.to_string(),
                "resolution": "deny",
            }));
        }
    }
    Ok(conflicts)
}

pub(super) fn effective_scope_realm_id(scope: &ScopeRef) -> String {
    match scope {
        ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. } => realm_id.to_string(),
        _ => unreachable!("unsupported canonical applet effective scope"),
    }
}

/// Governance gate for canonical applet install/revoke.
///
/// An authenticated session is not enough to register or revoke a realm-scoped
/// applet install: the actor MUST hold `ak.realm.admin` over the install's
/// effective_scope realm. P1 projected capability grants into the authz index,
/// so [`SolandAuthzEngine::check`] is authoritative here. Mirrors the ban gate
/// in `routing/events/operations/policy.rs::validate_member_state_policy`.
/// fail-closed: anything other than an explicit allow is rejected with
/// `applet_registration_unauthorized`.
pub(super) async fn require_realm_admin(
    state: &AppState,
    session: &SessionRecord,
    scope: &ScopeRef,
) -> Result<(), AppError> {
    let realm_id = effective_scope_realm_id(scope);
    let (owner, members) = realm_owner_and_members(state, &realm_id).await;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor: &actor,
            action: arkret_wire::CapabilityActionId::REALM_ADMIN,
            resource: &realm_id,
            realm_id: &realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        return Ok(());
    }
    Err(
        AppError::capability_denied("actor lacks ak.realm.admin over the applet install realm")
            .with_wire_code("applet_registration_unauthorized"),
    )
}

/// Resolve the realm owner and member set, matching
/// The shared event-policy projection supplies exact Actor membership context;
/// request context alone does not imply a capability.
async fn realm_owner_and_members(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    crate::routing::events::operations::realm_owner_and_members(state, realm_id).await
}

pub(super) fn ghost_actors_allowed_for_install(
    package: &AppletPackage,
    approved_actions: &[String],
    actor_policy: Option<&arkret_models_integration::applet_models::AppletActorPolicy>,
) -> bool {
    let package_allows = package.ghost_policy.enabled;
    let scope_approved = approved_actions
        .iter()
        .any(|action| action == CapabilityActionId::APPLET_GHOST_PROVISION);
    let actor_policy_allows = actor_policy.is_some_and(|policy| {
        matches!(
            policy.ghost_actor_mode,
            Some(AppletGhostActorMode::ControllerApproved | AppletGhostActorMode::PolicyDeclared)
        )
    });
    package_allows && scope_approved && actor_policy_allows
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{Did, DidCoreId, Hash};
    use arkret_models_integration::{
        AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod, AppletNamespaceEntry,
    };
    use arkret_signatures::Ed25519PayloadSigner;

    use super::*;

    #[test]
    fn bot_install_rejects_the_same_principal_at_another_station() {
        let principal_id = DidCoreId::new("ak:did_core:web:bot.example").unwrap();
        let target_station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let foreign_station_id = DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        let local_actor = ActorId::account(arkret_wire::AccountId::new(
            principal_id.clone(),
            target_station_id.clone(),
        ));
        let foreign_actor = ActorId::account(arkret_wire::AccountId::new(
            principal_id,
            foreign_station_id,
        ));

        validate_bot_actor_station(&local_actor, &target_station_id).unwrap();
        assert_eq!(
            local_actor.signing_principal_id(),
            foreign_actor.signing_principal_id()
        );
        let error = validate_bot_actor_station(&foreign_actor, &target_station_id)
            .expect_err("the same bot principal cannot borrow another Station's install");
        assert_eq!(error.wire_code(), "param_invalid");
    }

    /// Minimal production-mode (`development_mode == false`) AppState for
    /// exercising the controller-proof verifier against the built-in
    /// `did:key` resolver. Mirrors `routing/events/operations/policy_tests.rs`
    /// but with real-crypto verification enabled.
    fn production_test_state() -> AppState {
        let config = crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-applet-proof-test-blobs"),
            ),
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: Some([9u8; 32]),
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, soland_storage_postgres::Db { pool: None })
    }

    #[test]
    fn hosted_applet_pcr_notary_rejects_actor_and_self_reported_descriptors() {
        let state = production_test_state();
        let expected = arkret_wire::NotaryValue::single_signer(
            state.service_notary_signer_descriptor().unwrap(),
        );
        validate_hosted_applet_pcr_notary(&expected, &expected).unwrap();

        let actor_did = Did::new("did:web:actor.example".to_owned()).unwrap();
        let actor_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
        let actor_descriptor = soland_services::identity::ed25519_notary_signer_descriptor(
            actor_id,
            arkret_wire::DidUrl::new("did:web:actor.example#notary-key".to_owned()).unwrap(),
            &[7_u8; 32],
        )
        .unwrap();
        assert!(
            validate_hosted_applet_pcr_notary(
                &arkret_wire::NotaryValue::single_signer(actor_descriptor),
                &expected,
            )
            .is_err()
        );

        let self_reported_descriptor = soland_services::identity::ed25519_notary_signer_descriptor(
            arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap(),
            state
                .service_verification_method("self-reported-key")
                .unwrap(),
            &[8_u8; 32],
        )
        .unwrap();
        assert!(
            validate_hosted_applet_pcr_notary(
                &arkret_wire::NotaryValue::single_signer(self_reported_descriptor),
                &expected,
            )
            .is_err()
        );
    }

    /// Derive a `did:key` DID + its `#`-fragment verification method for an
    /// Ed25519 seed, using the SDK's canonical multibase encoder so the
    /// built-in `DidKeyResolver` resolves the embedded public key.
    fn did_key_for_seed(seed: [u8; 32]) -> (Did, String) {
        let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let multibase =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&verifying.to_bytes());
        let did_str = format!("did:key:{multibase}");
        let vm = format!("{did_str}#{multibase}");
        (Did::new(did_str).unwrap(), vm)
    }

    /// Build a sealed package whose `controller_id` is a `did:key` and whose
    /// `registration_epoch_evidence` is consistent with a non-empty service
    /// DID document, then sign it with the signer/verification_method chosen
    /// by the caller. When the signer key differs from `controller_id`'s key
    /// the resulting controller proof MUST fail verification.
    fn signed_did_key_package(
        controller_seed: [u8; 32],
        signer_seed: [u8; 32],
        verification_method: &str,
    ) -> AppletPackage {
        let (controller_did, _) = did_key_for_seed(controller_seed);
        let controller_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
        let service_did = Did::new("did:web:test-applet.example".to_owned()).unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&service_did).unwrap();
        let mut package = AppletPackage::new(
            "package:ak:applet:test".to_owned(),
            arkret_identifiers::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")
                .unwrap(),
            service_id.clone(),
            service_did.clone(),
            controller_id.clone(),
            "https://test-applet.example".to_owned(),
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:bot-test-applet.example".to_owned()).unwrap(),
                service_id,
            )),
            vec!["arkret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
        );
        package.requested_scopes = vec!["ak.message.create".to_owned()];
        package.endpoint_policy.endpoints = vec![AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/events".to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        }];
        let evidence = arkret_models_integration::applet::AppletRegistrationEpochEvidence::new(
            service_did,
            Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            arkret_models_integration::applet::AppletDidMethodVersionEvidence::unversioned(
                "did:web",
            )
            .unwrap(),
            vec![
                arkret_models_integration::applet::AppletAcceptedSigningKeyEvidence {
                    key_ref: package.webhook_auth.key_ref.to_string(),
                    public_key_digest: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
                },
            ],
        );
        package.seal_registration_epoch(&evidence).unwrap();
        package.seal().unwrap();
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            signer_seed,
            controller_did,
            arkret_wire::DidUrl::new(verification_method).expect("fixture DID URL"),
        );
        package
            .sign(
                &signer,
                &arkret_wire::DidUrl::new(verification_method).expect("fixture DID URL"),
            )
            .unwrap();
        package
    }

    #[test]
    fn validate_controller_proof_rejects_wrong_key_signature() {
        let state = production_test_state();
        // controller_id is keyed by `controller_seed`, but the proof is signed
        // with `signer_seed` while still naming controller_id's verification
        // method. The forged proof recomputes the correct payload digest yet
        // the Ed25519 signature is made by the wrong key — verification MUST
        // fail closed with `proof_invalid`.
        let controller_seed = [1u8; 32];
        let signer_seed = [2u8; 32];
        let (_, controller_vm) = did_key_for_seed(controller_seed);
        let package = signed_did_key_package(controller_seed, signer_seed, &controller_vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
        let error = validate_controller_proof(&state, &package, &bytes)
            .expect_err("wrong-key controller proof must be rejected");
        assert_eq!(error.wire_code(), "proof_invalid");
    }

    #[test]
    fn requested_capability_actions_accept_registered_applet_actions() {
        let controller_seed = [1u8; 32];
        let (_, controller_vm) = did_key_for_seed(controller_seed);
        let mut package = signed_did_key_package(controller_seed, controller_seed, &controller_vm);
        package.requested_scopes = vec![
            "ak.message.create".to_owned(),
            "ak.applet.ghost.provision".to_owned(),
        ];

        validate_requested_capability_actions(&package)
            .expect("registered capability actions must pass preview validation");
    }

    #[test]
    fn validate_controller_proof_rejects_unanchored_verification_method() {
        let state = production_test_state();
        // Sign with a verification_method belonging to a *different* DID than
        // controller_id. The anchoring gate MUST reject before any crypto,
        // because the proof is not attributable to controller_id.
        let controller_seed = [1u8; 32];
        let other_seed = [2u8; 32];
        let (_, other_vm) = did_key_for_seed(other_seed);
        let package = signed_did_key_package(controller_seed, other_seed, &other_vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
        let error = validate_controller_proof(&state, &package, &bytes)
            .expect_err("controller proof not anchored to controller_id must be rejected");
        assert_eq!(error.wire_code(), "proof_invalid");
    }

    #[test]
    fn validate_controller_proof_accepts_correct_controller_signature() {
        let state = production_test_state();
        // Same key for controller_id and signer: a genuine controller proof
        // verifies against the resolved did:key public key.
        let seed = [1u8; 32];
        let (_, vm) = did_key_for_seed(seed);
        let package = signed_did_key_package(seed, seed, &vm);

        let mut unsigned = package.clone();
        unsigned.proof = None;
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
        validate_controller_proof(&state, &package, &bytes)
            .expect("genuine controller proof must verify");
    }

    fn sample_package() -> AppletPackage {
        let service_did = Did::new("did:web:test-applet.example".to_owned()).unwrap();
        AppletPackage::new(
            "package:ak:applet:test".to_owned(),
            arkret_identifiers::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")
                .unwrap(),
            arkret_wire::project_did_to_core_id(&service_did).unwrap(),
            service_did,
            DidCoreId::new("ak:did_core:web:test-registry.example".to_owned()).unwrap(),
            "https://test-applet.example".to_owned(),
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:bot-test-applet.example".to_owned()).unwrap(),
                arkret_wire::project_did_to_core_id(
                    &Did::new("did:web:test-applet.example".to_owned()).unwrap(),
                )
                .unwrap(),
            )),
            vec!["arkret.portal".to_owned()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive("bridge.test".to_owned())],
                ..Default::default()
            },
        )
    }

    #[test]
    fn ghost_actors_allowed_uses_package_ghost_policy_enabled() {
        let mut package = sample_package();
        package.ghost_policy = arkret_models_integration::applet::AppletGhostPolicy {
            enabled: true,
            accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
            ..Default::default()
        };
        let actor_policy = arkret_models_integration::applet_models::AppletActorPolicy {
            ghost_actor_mode: Some(
                arkret_models_integration::applet_models::AppletGhostActorMode::PolicyDeclared,
            ),
        };
        assert!(ghost_actors_allowed_for_install(
            &package,
            &[CapabilityActionId::APPLET_GHOST_PROVISION.to_owned()],
            Some(&actor_policy)
        ));

        package.ghost_policy = arkret_models_integration::applet::AppletGhostPolicy {
            enabled: false,
            accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
            ..Default::default()
        };
        assert!(!ghost_actors_allowed_for_install(
            &package,
            &[CapabilityActionId::APPLET_GHOST_PROVISION.to_owned()],
            Some(&actor_policy)
        ));
    }

    #[test]
    fn registration_epoch_validation_refetches_unversioned_web_document() {
        let package = sample_package();
        let document = DidDocument::new(
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            package.webhook_auth.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let evidence =
            arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
                &document,
                arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web")
                    .unwrap(),
            )
            .unwrap();
        validate_registration_epoch_evidence_for_document(&package, &evidence, &document).unwrap();
        assert!(evidence.method_version_evidence.unversioned_refetch);
    }

    #[test]
    fn registration_epoch_validation_rejects_rotation_until_new_snapshot_is_used() {
        let package = sample_package();
        let old_document = DidDocument::new(
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            package.webhook_auth.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"old"}"#,
        );
        let old_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &old_document,
            arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web")
                .unwrap(),
        )
        .unwrap();
        validate_registration_epoch_evidence_for_document(&package, &old_evidence, &old_document)
            .unwrap();

        let rotated_document = DidDocument::new(
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            package.webhook_auth.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"rotated"}"#,
        );
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &old_evidence,
                &rotated_document,
            )
            .is_err()
        );

        let rotated_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &rotated_document,
            arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web")
                .unwrap(),
        )
        .unwrap();
        validate_registration_epoch_evidence_for_document(
            &package,
            &rotated_evidence,
            &rotated_document,
        )
        .unwrap();
        assert_ne!(
            old_evidence.document_digest,
            rotated_evidence.document_digest
        );
    }

    #[test]
    fn registration_epoch_validation_rejects_deactivated_and_empty_key_documents() {
        let package = sample_package();
        let mut deactivated_document = DidDocument::new(
            Did::new("did:web:test-applet.example".to_owned()).unwrap(),
            package.webhook_auth.key_ref.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let active_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &deactivated_document,
            arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web")
                .unwrap(),
        )
        .unwrap();
        deactivated_document
            .raw_properties
            .insert("deactivated".to_owned(), json!(true));
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &active_evidence,
                &deactivated_document,
            )
            .is_err()
        );
        assert!(
            AppletRegistrationEpochEvidence::from_did_document(
                &deactivated_document,
                arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web",)
                    .unwrap(),
            )
            .is_err()
        );

        let mut keyless_document = deactivated_document.clone();
        keyless_document.raw_properties.remove("deactivated");
        keyless_document.verification_methods.clear();
        assert!(
            AppletRegistrationEpochEvidence::from_did_document(
                &keyless_document,
                arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web",)
                    .unwrap(),
            )
            .is_err()
        );
        let mut empty_evidence = active_evidence;
        empty_evidence.accepted_signing_keys.clear();
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &empty_evidence,
                &keyless_document,
            )
            .is_err()
        );
    }

    #[test]
    fn registration_epoch_validation_rejects_swapped_service_document() {
        let package = sample_package();
        let swapped_document = DidDocument::new(
            Did::new("did:web:other-applet.example".to_owned()).unwrap(),
            "did:web:other-applet.example#controller".to_owned(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"fixture"}"#,
        );
        let swapped_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &swapped_document,
            arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web")
                .unwrap(),
        )
        .unwrap();
        assert!(
            validate_registration_epoch_evidence_for_document(
                &package,
                &swapped_evidence,
                &swapped_document,
            )
            .is_err()
        );
    }

    #[test]
    fn applet_mls_join_fails_closed_without_registered_authorization_artifact() {
        let mut package = sample_package();
        package.e2ee_policy.mls_join_requested = Some(true);
        let requested_policy = E2eePolicy {
            mls_join_allowed: Some(true),
        };

        assert!(e2ee_authorization_refs_for_install(&package, Some(&requested_policy)).is_err());
    }

    #[test]
    fn managed_actor_rejects_a_self_consistent_historical_webvh_prefix() {
        let did = Did::new(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:actor.example".to_owned(),
        )
        .unwrap();
        let historical_head = Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let pinned = soland_services::identity::PinnedDidDocumentState {
            did: did.clone(),
            version_id: "1-historical".to_owned(),
            log_head_digest: historical_head.clone(),
            document: json!({"id": did}),
            update_keys: Vec::new(),
            current_version_id: "2-current".to_owned(),
            status: PinnedDidVersionStatus::Rotated,
        };

        assert!(!managed_actor_pinned_resolution_is_current(
            &pinned,
            &did,
            "1-historical",
            &historical_head,
        ));
    }
}
