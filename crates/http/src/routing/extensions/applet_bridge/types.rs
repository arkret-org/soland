//! Wire and storage types for the applet bridge surface.

use std::collections::BTreeSet;

use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope,
    AccountabilityScopeKind,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, GrantConstraintSubkind, IssuerAuthorityRef,
};
use arkret_models_integration::{
    AppletInstallEffectiveStatus, AppletInstallOutcome, AppletManagedActorProvisionPayload,
    AppletManagedActorRole, AppletPackage, GhostExternalTuple,
};
use arkret_wire::{
    ActorKind, AppletId, DidCoreId, Event, EventId, EventSubmitContext, GrantId, Hash, RealmId,
    ResourceMatchScope, ScopeRef, WireResourceSelector,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) const SOLAND_EDGE_APPLET_ID: &str = "ak:applet:00000000-0000-7000-8000-000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRecord {
    pub applet_id: AppletId,
    pub owner_actor_id: DidCoreId,
    pub registry_did: DidCoreId,
    pub bot_actor_id: DidCoreId,
    pub bot_actor_principal_server_id: DidCoreId,
    pub bot_actor_provision_ref: EventId,
    pub bot_principal_control_realm_id: RealmId,
    pub portal_realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub capabilities: Vec<String>,
    pub package: AppletPackage,
    pub ghost_actors_allowed: bool,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub idempotency_key: String,
    pub install_body_digest: Hash,
    pub install_id: String,
    pub install_response: AppletInstallOutcome,
    pub registration_event: Event,
    pub capability_grant_events: Vec<Event>,
    pub bot_actor_provision_event: Event,
    pub bot_pcr_genesis_event: Event,
    pub bot_accountability_grant_event: Event,
    pub bot_profile_event: Event,
    pub install_execution: Value,
    #[serde(default)]
    pub revoke_execution: Option<Value>,
    pub ghosts: Vec<GhostActorRecord>,
}

pub(crate) fn registration_epoch_evidence_from_event(
    event: &Event,
) -> Result<arkret_models_integration::AppletRegistrationEpochEvidence, String> {
    let evidence = event
        .payload
        .get("manifest")
        .and_then(Value::as_object)
        .and_then(|manifest| manifest.get("registration_epoch_evidence"))
        .cloned()
        .ok_or_else(|| {
            "registration Event payload.manifest.registration_epoch_evidence is missing".to_owned()
        })?;
    serde_json::from_value(evidence)
        .map_err(|error| format!("registration Event epoch evidence is invalid: {error}"))
}

pub(crate) fn registration_epoch_evidence_from_record(
    record: &AppletRecord,
) -> Result<arkret_models_integration::AppletRegistrationEpochEvidence, String> {
    registration_epoch_evidence_from_event(&record.registration_event)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorRecord {
    pub ghost_actor_id: DidCoreId,
    pub actor_principal_server_id: DidCoreId,
    pub external_ref: arkret_models_integration::GhostExternalTuple,
    #[serde(default)]
    pub display_name: Option<String>,
    pub request_digest: Hash,
    pub managed_actor_provision_event: Event,
    pub pcr_genesis_event: Event,
    pub accountability_grant_event: Event,
    pub profile_event: Event,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl GhostActorRecord {
    pub(crate) fn provision_payload(
        &self,
    ) -> Result<arkret_models_integration::AppletManagedActorProvisionPayload, String> {
        serde_json::from_value(self.managed_actor_provision_event.payload.clone())
            .map_err(|error| format!("stored Ghost provision payload is invalid: {error}"))
    }

    pub(crate) fn principal_control_realm_id(&self) -> RealmId {
        RealmId::from_event_id(&self.pcr_genesis_event.event_id)
    }
}

fn validate_stored_event(
    event: &Event,
    context: EventSubmitContext,
    label: &str,
) -> Result<(), String> {
    let digest_suite = event
        .event_id
        .event_digest()
        .digest_suite()
        .map_err(|error| format!("stored {label} Event digest suite is invalid: {error}"))?;
    event
        .validate_for_submit_structural_in_context(context)
        .map_err(|error| format!("stored {label} Event envelope is invalid: {error}"))?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| format!("stored {label} Event identity is invalid: {error}"))?;
    event
        .validate_proof_bindings_with_digest_suite(digest_suite)
        .map_err(|error| format!("stored {label} Event proof binding is invalid: {error}"))
}

fn validate_registration_epoch_proof_method(
    event: &Event,
    verification_method: &str,
    label: &str,
) -> Result<(), String> {
    if event.proofs.iter().any(|proof| {
        proof
            .as_producer()
            .is_none_or(|proof| proof.verification_method != verification_method)
    }) {
        return Err(format!(
            "stored {label} Event proof is outside the Applet registration epoch"
        ));
    }
    Ok(())
}

fn exact_role_ref(event: &Event, role: &str, event_id: &EventId) -> bool {
    event
        .refs
        .iter()
        .filter(|reference| reference.role == role)
        .collect::<Vec<_>>()
        .as_slice()
        .first()
        .is_some_and(|reference| {
            event.refs.iter().filter(|item| item.role == role).count() == 1
                && reference.critical
                && reference.id == event_id.as_str()
        })
}

fn validate_managed_actor_unit(
    record: &AppletRecord,
    role: AppletManagedActorRole,
    actor_id: &DidCoreId,
    principal_server_id: &DidCoreId,
    external_ref: Option<&GhostExternalTuple>,
    provision_event: &Event,
    pcr_event: &Event,
    accountability_event: &Event,
    profile_event: &Event,
) -> Result<AppletManagedActorProvisionPayload, String> {
    let label = match role {
        AppletManagedActorRole::Bot => "Bot",
        AppletManagedActorRole::Ghost => "Ghost",
    };
    validate_stored_event(
        provision_event,
        EventSubmitContext::Standard,
        "managed provision",
    )?;
    validate_stored_event(
        pcr_event,
        EventSubmitContext::AnchorUnit,
        "managed PCR genesis",
    )?;
    validate_stored_event(
        accountability_event,
        EventSubmitContext::Standard,
        "managed accountability",
    )?;
    validate_stored_event(
        profile_event,
        EventSubmitContext::Standard,
        "managed profile",
    )?;

    let provision: AppletManagedActorProvisionPayload =
        serde_json::from_value(provision_event.payload.clone())
            .map_err(|error| format!("stored {label} provision payload is invalid: {error}"))?;
    provision
        .validate()
        .map_err(|error| format!("stored {label} provision payload is invalid: {error}"))?;
    if provision.actor_role != role
        || provision.applet_id != record.applet_id
        || provision.service_id != record.package.service_id
        || &provision.actor_id != actor_id
        || &provision.actor_principal_server_id != principal_server_id
        || provision.registration_ref != record.registration_event.event_id
        || !record
            .install_response
            .capability_grant_refs
            .contains(&provision.applet_authority_ref)
        || provision.external_ref.as_ref() != external_ref
        || provision_event.kind.as_str() != "ak.applet.managed_actor.provision"
        || provision_event.actor_id != record.package.service_id
        || provision_event.principal_server_id != *principal_server_id
        || provision_event.realm_id != record.portal_realm_id
        || provision_event.scope_ref != record.effective_scope
        || provision_event.applet_id.as_ref() != Some(&record.applet_id)
        || provision_event.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
    {
        return Err(format!(
            "stored {label} provision anchor drifts from the accepted Applet authority"
        ));
    }

    let pcr_realm_id = RealmId::from_event_id(&pcr_event.event_id);
    let genesis: arkret_models_collaboration::events_payloads::RealmGenesis =
        serde_json::from_value(
            pcr_event
                .payload
                .get("object")
                .cloned()
                .ok_or_else(|| format!("stored {label} PCR genesis object is missing"))?,
        )
        .map_err(|error| format!("stored {label} PCR genesis object is invalid: {error}"))?;
    if pcr_event.kind != arkret_wire::EventKind::RealmCreate
        || &pcr_event.actor_id != actor_id
        || pcr_event.executed_by.as_ref() != Some(&record.package.service_id)
        || pcr_event.principal_server_id != *principal_server_id
        || pcr_event.applet_id.as_ref() != Some(&record.applet_id)
        || pcr_event.authorization_ref.as_deref() != Some(provision.applet_authority_ref.as_str())
        || pcr_event.realm_id != pcr_realm_id
        || pcr_event.scope_ref != ScopeRef::RealmGenesis
        || !exact_role_ref(
            pcr_event,
            "applet_managed_actor_provision",
            &provision_event.event_id,
        )
        || genesis.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
        || genesis.initial_resolution.as_ref() != Some(&provision.initial_resolution)
    {
        return Err(format!(
            "stored {label} PCR genesis drifts from its immutable provision"
        ));
    }

    let registration_method = record.package.webhook_auth.key_ref.as_str();
    for event in [accountability_event, profile_event] {
        validate_registration_epoch_proof_method(event, registration_method, label)?;
    }
    let accountability: AccountabilityGrantPayload =
        serde_json::from_value(accountability_event.payload.clone()).map_err(|error| {
            format!("stored {label} accountability payload is invalid: {error}")
        })?;
    accountability
        .canonical_proof_binding_bytes()
        .map_err(|error| format!("stored {label} accountability proof is invalid: {error}"))?;
    if accountability_event.kind != arkret_wire::EventKind::IdentityAccountabilityGrant
        || accountability_event.actor_id != record.package.service_id
        || accountability_event.executed_by.is_some()
        || accountability_event.principal_server_id != *principal_server_id
        || accountability_event.realm_id != record.portal_realm_id
        || accountability_event.scope_ref != record.effective_scope
        || accountability_event.applet_id.as_ref() != Some(&record.applet_id)
        || accountability_event.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
        || accountability.schema != AccountabilityGrantPayload::SCHEMA
        || accountability.issuer != record.package.service_id
        || &accountability.subject != actor_id
        || accountability.accountability_scope
            != AccountabilityScope::Single(AccountabilityScopeKind::ContractedService)
        || accountability.grant_status != AccountabilityGrantStatus::Active
        || accountability.proof.verification_method != registration_method
        || accountability
            .expires_at
            .is_some_and(|expires_at| expires_at <= accountability.not_before)
    {
        return Err(format!(
            "stored {label} accountability grant is not the accepted contracted-service authority"
        ));
    }

    let profile: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(profile_event.payload.clone())
            .map_err(|error| format!("stored {label} profile payload is invalid: {error}"))?;
    let profile = profile.object;
    let expected_external_ref = external_ref
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| format!("stored {label} external_ref cannot be encoded: {error}"))?;
    if profile_event.kind != arkret_wire::EventKind::ProfileCreate
        || &profile_event.actor_id != actor_id
        || profile_event.executed_by.as_ref() != Some(&record.package.service_id)
        || profile_event.principal_server_id != *principal_server_id
        || profile_event.realm_id != record.portal_realm_id
        || profile_event.scope_ref != record.effective_scope
        || profile_event.applet_id.as_ref() != Some(&record.applet_id)
        || profile_event.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
        || !exact_role_ref(
            profile_event,
            "accountability",
            &accountability_event.event_id,
        )
        || profile.principal_id != *actor_id
        || profile.realm_id.as_ref() != Some(&record.portal_realm_id)
        || profile.actor_kind != ActorKind::Integration
        || profile.accountable_principal_ids.as_slice() != [record.package.service_id.clone()]
        || profile
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(record.applet_id.as_str())
        || profile.profile_fields.get("external_ref") != expected_external_ref.as_ref()
    {
        return Err(format!(
            "stored {label} profile is not the exact managed-actor projection"
        ));
    }
    Ok(provision)
}

impl AppletRecord {
    pub(crate) fn validate_stored_bindings(&self) -> Result<(), String> {
        let original_status = match self.install_response.effective_status {
            AppletInstallEffectiveStatus::Installed => "installed",
            AppletInstallEffectiveStatus::PartiallyInstalled => "partially_installed",
        };
        if self.applet_id != self.package.applet_id
            || self.applet_id != self.install_response.applet_id
            || self.registry_did != self.package.controller_id
            || self.bot_actor_id != self.package.bot_actor_id
            || self.bot_actor_id != self.install_response.bot_actor_id
            || self.bot_actor_principal_server_id
                != self.install_response.bot_actor_principal_server_id
            || self.bot_actor_provision_ref != self.install_response.bot_actor_provision_ref
            || self.bot_principal_control_realm_id
                != self.install_response.bot_principal_control_realm_id
            || &self.portal_realm_id != self.effective_scope.realm_id()
            || self.install_id != self.install_response.install_id
            || self.install_response.registration_epoch != self.package.registration_epoch
            || (self.revoked_at.is_none() && self.status != original_status)
            || (self.revoked_at.is_some() && self.status != "revoked")
        {
            return Err(
                "stored Applet record coordinate mirrors drift from the accepted package/outcome"
                    .to_owned(),
            );
        }
        validate_stored_event(
            &self.registration_event,
            EventSubmitContext::Standard,
            "registration",
        )?;
        let registration: arkret_models_integration::WireAppletRegistration =
            serde_json::from_value(self.registration_event.payload.clone()).map_err(|error| {
                format!("stored registration Event payload is invalid: {error}")
            })?;
        let evidence = registration_epoch_evidence_from_event(&self.registration_event)?;
        self.package
            .validate_with_epoch_evidence(&evidence)
            .map_err(|error| format!("stored Applet package is invalid: {error}"))?;
        let expected_registration = self.package.to_registration(&evidence).map_err(|error| {
            format!("stored Applet package cannot derive registration: {error}")
        })?;
        if self.registration_event.kind != arkret_wire::EventKind::AppletRegistration
            || self.registration_event.actor_id != self.owner_actor_id
            || self.registration_event.principal_server_id != self.bot_actor_principal_server_id
            || self.registration_event.realm_id != self.portal_realm_id
            || self.registration_event.scope_ref != self.effective_scope
            || registration != expected_registration
            || self.install_response.registration_event_ref != self.registration_event.event_id
        {
            return Err(
                "stored registration Event is not the exact accepted Applet package projection"
                    .to_owned(),
            );
        }
        let bot_provision = validate_managed_actor_unit(
            self,
            AppletManagedActorRole::Bot,
            &self.bot_actor_id,
            &self.bot_actor_principal_server_id,
            None,
            &self.bot_actor_provision_event,
            &self.bot_pcr_genesis_event,
            &self.bot_accountability_grant_event,
            &self.bot_profile_event,
        )?;
        if self.bot_actor_provision_ref != self.bot_actor_provision_event.event_id
            || self.bot_principal_control_realm_id
                != RealmId::from_event_id(&self.bot_pcr_genesis_event.event_id)
            || bot_provision.applet_authority_ref.as_str()
                != self
                    .bot_actor_provision_event
                    .authorization_ref
                    .as_deref()
                    .unwrap_or_default()
        {
            return Err("stored Bot durable authority coordinates drift".to_owned());
        }

        let expected_resource = match &self.effective_scope {
            ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => {
                let mut selector =
                    WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
                selector.match_scope = Some(ResourceMatchScope::Exact);
                selector
            }
            _ => return Err("stored Applet effective scope is unsupported".to_owned()),
        };
        let expected_constraint = GrantConstraint::applet_authority(
            self.applet_id.clone(),
            self.package.service_id.clone(),
            self.package.registration_epoch.clone(),
        );
        let requested_actions = self
            .package
            .requested_scopes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut projected_actions = BTreeSet::new();
        let mut grant_event_ids = BTreeSet::new();
        let mut accepted_grants = Vec::with_capacity(self.capability_grant_events.len());
        if self.capability_grant_events.is_empty() {
            return Err("stored Applet has no accepted capability grant Event".to_owned());
        }
        for event in &self.capability_grant_events {
            validate_stored_event(event, EventSubmitContext::Standard, "capability grant")?;
            if event.kind != arkret_wire::EventKind::CapabilityGrant
                || event.actor_id != self.owner_actor_id
                || event.principal_server_id != self.bot_actor_principal_server_id
                || event.realm_id != self.portal_realm_id
                || event.scope_ref != self.effective_scope
                || !grant_event_ids.insert(event.event_id.clone())
            {
                return Err("stored capability grant Event envelope is invalid".to_owned());
            }
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                serde_json::from_value(event.payload.clone()).map_err(|error| {
                    format!("stored capability grant payload is invalid: {error}")
                })?;
            let grant = payload.grant;
            let applet_authority_constraints = grant
                .constraints
                .iter()
                .filter(|constraint| {
                    constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
                })
                .collect::<Vec<_>>();
            let authority_root_is_exact = matches!(
                grant.issuer_authority_refs.as_slice(),
                [IssuerAuthorityRef::RealmRoot { realm_id, .. }]
                    if realm_id == &self.portal_realm_id
            );
            if grant.schema != "ak.schema.capability.v1"
                || grant.issuer != self.owner_actor_id
                || grant.realm_id.as_ref() != Some(&self.portal_realm_id)
                || !matches!(&grant.subject, CapabilitySubject::CoreDid(subject)
                    if subject == &self.package.service_id)
                || grant.subject_principal_server_id.as_ref()
                    != Some(&self.bot_actor_principal_server_id)
                || grant.resources.as_slice() != [expected_resource.clone()]
                || applet_authority_constraints.as_slice() != [&expected_constraint]
                || grant.actions.is_empty()
                || !authority_root_is_exact
            {
                return Err(
                    "stored capability grant authority, resource, or constraint is invalid"
                        .to_owned(),
                );
            }
            for action in grant.actions {
                if !requested_actions.contains(&action) || !projected_actions.insert(action) {
                    return Err(
                        "stored capability grant actions are duplicated or were not requested"
                            .to_owned(),
                    );
                }
            }
            accepted_grants.push(GrantId::from_event_id(&event.event_id));
        }
        if accepted_grants != self.install_response.capability_grant_refs
            || self.capabilities != projected_actions.into_iter().collect::<Vec<_>>()
            || self.ghost_actors_allowed
                != self
                    .capabilities
                    .iter()
                    .any(|action| action == arkret_wire::CapabilityActionId::APPLET_GHOST_PROVISION)
        {
            return Err(
                "stored capability grant Events drift from the install outcome or projection"
                    .to_owned(),
            );
        }

        let mut all_event_ids = BTreeSet::from([
            self.registration_event.event_id.clone(),
            self.bot_actor_provision_event.event_id.clone(),
            self.bot_pcr_genesis_event.event_id.clone(),
            self.bot_accountability_grant_event.event_id.clone(),
            self.bot_profile_event.event_id.clone(),
        ]);
        if all_event_ids.len() != 5 {
            return Err("stored Applet fixed Event set reuses an Event id".to_owned());
        }
        for event in &self.capability_grant_events {
            if !all_event_ids.insert(event.event_id.clone()) {
                return Err("stored Applet Event set reuses an Event id".to_owned());
            }
        }
        let mut managed_actor_ids = BTreeSet::from([
            self.package.service_id.clone(),
            self.package.controller_id.clone(),
            self.bot_actor_id.clone(),
        ]);
        let mut external_refs = BTreeSet::new();
        for ghost in &self.ghosts {
            if ghost.actor_principal_server_id != self.bot_actor_principal_server_id
                || !managed_actor_ids.insert(ghost.ghost_actor_id.clone())
                || !external_refs.insert((
                    ghost.external_ref.protocol.clone(),
                    ghost.external_ref.instance_id.clone(),
                    ghost.external_ref.external_id.clone(),
                ))
            {
                return Err(
                    "stored Ghost authority pair is invalid or reuses an existing Applet authority"
                        .to_owned(),
                );
            }
            validate_managed_actor_unit(
                self,
                AppletManagedActorRole::Ghost,
                &ghost.ghost_actor_id,
                &ghost.actor_principal_server_id,
                Some(&ghost.external_ref),
                &ghost.managed_actor_provision_event,
                &ghost.pcr_genesis_event,
                &ghost.accountability_grant_event,
                &ghost.profile_event,
            )?;
            for event in [
                &ghost.managed_actor_provision_event,
                &ghost.pcr_genesis_event,
                &ghost.accountability_grant_event,
                &ghost.profile_event,
            ] {
                if !all_event_ids.insert(event.event_id.clone()) {
                    return Err("stored Ghost fixed Event set reuses an Event id".to_owned());
                }
            }
        }
        Ok(())
    }
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletRevokeRecordOutcome {
    pub applet_id: AppletId,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub bot_actor_id: String,
    pub ghost_actor_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, Hlc, ProducerEventProof};
    use serde_json::json;

    use super::*;

    fn signed_fixture_event() -> Event {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x51; 32],
        ));
        let mut event = arkret_wire::test_support::raw_event(
            "ak.test.stored_record_fixture",
            ScopeRef::Realm { realm_id },
            DidCoreId::new("ak:did_core:webvh:z6mkstoredactor").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkstoredserver").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"content": {"kind": "ak.content.text", "body": "stored"}}),
        )
        .unwrap();
        let digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        event.proofs = vec![
            ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkstoredactor:example.test#key-1".to_owned(),
                )
                .unwrap(),
                event_digest: Hash::new(digest).unwrap(),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: arkret_wire::test_support::DETACHED_JWS_FIXTURE.to_owned(),
            }
            .into(),
        ];
        event
    }

    #[test]
    fn stored_event_validation_rejects_canonical_content_tampering() {
        let event = signed_fixture_event();
        validate_stored_event(&event, EventSubmitContext::Standard, "fixture").unwrap();

        let mut tampered = event;
        tampered.payload.insert("tampered".to_owned(), json!(true));
        let error = validate_stored_event(&tampered, EventSubmitContext::Standard, "fixture")
            .expect_err("stored canonical Event content must be immutable");
        assert!(error.contains("identity") || error.contains("proof binding"));
    }

    #[test]
    fn stored_fixed_role_ref_rejects_extra_or_noncritical_refs() {
        let mut event = signed_fixture_event();
        let target = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x52; 32]);
        event.refs = vec![arkret_wire::EventRef::new(
            target.as_str(),
            "accountability",
        )];
        assert!(exact_role_ref(&event, "accountability", &target));

        event.refs.push(arkret_wire::EventRef::new(
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x53; 32]).as_str(),
            "accountability",
        ));
        assert!(!exact_role_ref(&event, "accountability", &target));
    }
}
