//! Adapter from the public authority protocol to this Station's durable store.
//!
//! Stream reads, guarded ordinary Realm bootstrap and the guarded Event unit
//! are live. A self Event whose Realm another Station governs is forwarded
//! with fresh producer device evidence, and a forwarded Event is admitted
//! here from that evidence (device-lifecycle §8.2.2). Other mutation branches
//! remain closed until the serving layer can prove the producer and current
//! authorization at the authority transaction cut.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingUnitSubmission, OrdinaryRealmBootstrapAcceptanceOutcome,
    OrdinaryRealmBootstrapUnitSubmission, PeerAuthorityForwardEventRequest,
    PeerAuthorityForwardMlsRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    EventAdmissionSubmission, MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityHandoff,
    StreamScanRequest,
};
use chrono::Utc;
use soland_services::authority_commit::AuthorityProtocolPort;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};

use super::AppState;

/// The self Event admission unit a kind reaches on this Station.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelfEventRoute {
    /// `ak.key_backup.active_series`: the same-cut pointer unit.
    KeyBackupPointer,
    /// `ak.identity.accountability_grant`: the issuer-PCR accountability unit.
    AccountabilityGrant,
    Consent,
    /// `ak.mls.genesis` and `ak.mls.commit`: the MLS public-transition unit.
    Mls,
    /// Kinds with a guarded current-result authority cut in their source scope.
    GuardedUnit,
}

/// Select the self Event unit for `kind` before any authority cut is read.
///
/// Every other active standard kind has no current-result authority cut here
/// and is refused with the universal `unsupported_event_kind`, never an
/// internal failure, so the refusal is a stable wire code and nothing is
/// written. A kind outside the registry cannot pass envelope validation; if
/// one did, it is a closed-schema violation, not an unsupported active kind.
fn self_event_route(kind: &arkret_wire::EventKind) -> ServiceResult<SelfEventRoute> {
    use arkret_wire::EventKind;
    match kind {
        EventKind::KeyBackupActiveSeries => Ok(SelfEventRoute::KeyBackupPointer),
        EventKind::IdentityAccountabilityGrant => Ok(SelfEventRoute::AccountabilityGrant),
        EventKind::ConsentGrant | EventKind::ConsentRevoke => Ok(SelfEventRoute::Consent),
        EventKind::MlsGenesis | EventKind::MlsCommit => Ok(SelfEventRoute::Mls),
        EventKind::CircleCreate
        | EventKind::RealmOrganization
        | EventKind::CircleMemberState
        | EventKind::StrandCreate
        | EventKind::RealmProfile
        | EventKind::StrandUpdate
        | EventKind::StrandArchive
        | EventKind::StrandRestore
        | EventKind::StrandStageSet
        | EventKind::StrandMove
        | EventKind::StrandReorder
        | EventKind::StrandWatchSet
        | EventKind::SpaceCreate
        | EventKind::DirectConversationBound
        | EventKind::RealmSetDefaultStrand
        | EventKind::MemberIdentityUpdate
        | EventKind::CallCreate
        | EventKind::MessageCreate
        | EventKind::MemberState
        | EventKind::CapabilityGrant
        | EventKind::MessageRevise
        | EventKind::MessageRedact
        | EventKind::ModerationDecision
        | EventKind::ModerationDecisionLift
        | EventKind::InviteCreate
        | EventKind::InviteThirdParty
        | EventKind::InviteRevoke
        | EventKind::InviteCancel
        | EventKind::InviteAccept
        | EventKind::CapabilityRevoke
        | EventKind::CapabilityRelinquish => Ok(SelfEventRoute::GuardedUnit),
        EventKind::Unknown(raw) => Err(ServiceError::SchemaViolation(format!(
            "self Event kind {raw} is not registered"
        ))),
        other => Err(ServiceError::UnsupportedEventKind(format!(
            "this Station has no self Event authority cut for {}",
            other.as_str()
        ))),
    }
}

/// actor-private-effects.md §2.1: the self Event submit and the peer Event
/// ingress admit only shared durable Events. Every `actor_private_event` kind
/// is refused as `unsupported_event_kind` before any producer, forwarding or
/// storage step, so it never enters RealmCommit coverage.
pub(super) fn refuse_actor_private_event(kind: &arkret_wire::EventKind) -> ServiceResult<()> {
    if kind.wire_scope() == arkret_wire::EventWireScope::ActorPrivateEvent {
        return Err(ServiceError::UnsupportedEventKind(format!(
            "{} is an actor-private Event and is never a shared Realm Event",
            kind.as_str()
        )));
    }
    Ok(())
}

/// A shared Event of a kind this Station admits through no unit: the
/// Direct Conversation profile table still answers first for its Realm
/// (contact-and-direct-conversation.md section 8.4), otherwise the refusal
/// stays the universal `unsupported_event_kind`. `None` for a routed kind.
pub(super) async fn refuse_unrouted_event(
    state: &AppState,
    event: &arkret_wire::Event,
) -> ServiceResult<Option<AuthoritySubmitOutcome>> {
    match self_event_route(&event.kind) {
        Ok(_) => Ok(None),
        Err(unsupported @ ServiceError::UnsupportedEventKind(_)) => {
            super::authority_direct_conversation::refuse_unadmitted_event(state, event, unsupported)
                .await
                .map(Some)
        }
        Err(error) => Err(error),
    }
}

/// Preconditions shared by every Event admitted through the guarded unit,
/// whether its producer was resolved locally or from a forward.
pub(super) fn require_guarded_unit_event(request: &EventAdmissionSubmission) -> ServiceResult<()> {
    let event = &request.event;
    if self_event_route(&event.kind)? != SelfEventRoute::GuardedUnit {
        return Err(ServiceError::UnsupportedEventKind(format!(
            "{} is admitted only on its producer's own Station",
            event.kind.as_str()
        )));
    }
    if request.approval_signatures.is_some() {
        return Err(ServiceError::Conflict(
            "Event approval signatures are not verified".to_owned(),
        ));
    }
    if !matches!(event.scope_ref, arkret_wire::ScopeRef::Realm { .. })
        && !(matches!(event.scope_ref, arkret_wire::ScopeRef::Circle { .. })
            && matches!(
                event.kind,
                arkret_wire::EventKind::CircleMemberState
                    | arkret_wire::EventKind::StrandCreate
                    | arkret_wire::EventKind::MessageCreate
                    | arkret_wire::EventKind::ModerationDecision
                    | arkret_wire::EventKind::ModerationDecisionLift
            ))
    {
        return Err(ServiceError::Conflict(
            "this Event kind has no source target cut in its signed scope".to_owned(),
        ));
    }
    Ok(())
}

/// The other Station that currently governs `realm_id`, if any. Only a
/// durable current-authority record names it; a Realm this Station knows
/// nothing about has no forwarding target.
async fn remote_governance(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
) -> ServiceResult<Option<arkret_wire::DidCoreId>> {
    Ok(state
        .authority_commits()
        .current_authority(realm_id)
        .await?
        .map(|authority| authority.service_id)
        .filter(|service_id| service_id != &state.service_core_id()))
}

#[async_trait::async_trait]
impl AuthorityProtocolPort for AppState {
    async fn submit_self_ordinary_realm_bootstrap(
        &self,
        session: &SessionIdentityState,
        request: OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: &[u8],
    ) -> ServiceResult<OrdinaryRealmBootstrapAcceptanceOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let genesis = &request.events[0].event;
        let existing = self
            .authority_commits()
            .current_authority(&genesis.realm_id)
            .await?;
        let (producer_guards, staged) =
            super::authority_bootstrap_validation::verify_ordinary_realm_bootstrap(
                self,
                session,
                &request,
                existing.is_none(),
            )
            .await?;
        let expected_authority = soland_storage::CurrentRealmAuthority {
            realm_id: genesis.realm_id.clone(),
            generation: 0,
            service_id: self.service_core_id(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis.event_id.clone(),
            ),
            last_handoff_ref: None,
        };
        let method = arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                self.service_did().as_str(),
            ),
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let committed_at = Utc::now();
        let unit = self
            .authority_commits()
            .prepare_ordinary_realm_bootstrap_unit(
                request.clone(),
                exact_request_body.to_vec(),
                &expected_authority,
                method,
                self.notary_signing_key().as_ref(),
                committed_at,
            )?;
        let result = self
            .authority_commits()
            .admit_self_ordinary_realm_bootstrap_unit(&unit, &producer_guards, committed_at)
            .await?;
        let (status, commits) = match result {
            soland_storage::OrdinaryRealmBootstrapCommitOutcome::Committed(commits) => {
                (AggregateAcceptanceStatus::Committed, commits)
            }
            soland_storage::OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits) => {
                (AggregateAcceptanceStatus::Duplicate, commits)
            }
        };
        if status == AggregateAcceptanceStatus::Committed {
            let mut repair_needed = false;
            match staged {
                Some(staged) => {
                    if let Err(error) = self.projections().install_staged_realm_bootstrap(staged) {
                        tracing::error!(realm_id = %genesis.realm_id, reason = %error.reason,
                            "durably committed ordinary bootstrap needs local projection repair");
                        repair_needed = true;
                    }
                }
                None => {
                    tracing::error!(realm_id = %genesis.realm_id,
                        "durably committed ordinary bootstrap has no staged local projection");
                    repair_needed = true;
                }
            }
            // The directory is a separate, rebuildable view used by the
            // ordinary Realm reads and subsequent local Event admission.
            // Hydrate it from confirmed Events after the transaction, then
            // install the one new Realm. The durable Commit/current rows are
            // already the truth if this read temporarily fails.
            match self.persistence().hydrate_realm_directory().await {
                Ok(directory) => {
                    if let Some(entry) = directory.get(&genesis.realm_id) {
                        self.realm_directory().upsert(entry.clone());
                    } else {
                        tracing::error!(realm_id = %genesis.realm_id,
                            "durably committed ordinary bootstrap is absent from directory hydration");
                        repair_needed = true;
                    }
                }
                Err(error) => {
                    tracing::error!(realm_id = %genesis.realm_id, %error,
                        "durably committed ordinary bootstrap directory hydration failed");
                    repair_needed = true;
                }
            }
            if repair_needed {
                let repair_state = self.clone();
                tokio::spawn(async move {
                    let mut delay = std::time::Duration::from_secs(1);
                    loop {
                        match repair_state.hydrate().await {
                            Ok(()) => break,
                            Err(error) => {
                                tracing::error!(%error, "ordinary bootstrap projection repair failed")
                            }
                        }
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(30));
                    }
                });
            }
        }
        let outcome = OrdinaryRealmBootstrapAcceptanceOutcome {
            unit_kind: request.unit_kind,
            status,
            commits,
        };
        outcome
            .validate()
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(outcome)
    }

    async fn submit_self_direct_conversation_founding(
        &self,
        session: &SessionIdentityState,
        request: DirectConversationFoundingUnitSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        super::authority_direct_conversation::submit_self_direct_conversation_founding(
            self, session, request,
        )
        .await
    }

    async fn submit_self_event(
        &self,
        session: &SessionIdentityState,
        request: EventAdmissionSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let event = &request.event;
        refuse_actor_private_event(&event.kind)?;
        if matches!(
            event.kind,
            arkret_wire::EventKind::ConsentGrant | arkret_wire::EventKind::ConsentRevoke
        ) {
            let result = super::authority_consent::submit(self, session, &request).await?;
            let (status, record) = match result {
                soland_storage::ConsentAdmissionOutcome::Committed(record) => {
                    (arkret_wire::AuthorityCommitStatus::Committed, record)
                }
                soland_storage::ConsentAdmissionOutcome::Duplicate(record) => {
                    (arkret_wire::AuthorityCommitStatus::Duplicate, record)
                }
            };
            return Ok(AuthoritySubmitOutcome::Accepted {
                status,
                commit: record.commit,
            });
        }
        // The Agent PCR genesis is executed by the controller on the Agent's
        // behalf; its unit verifies that delegated producer itself.
        if super::authority_agent_pcr_genesis::is_agent_pcr_genesis(event) {
            return super::authority_agent_pcr_genesis::submit_self_agent_pcr_genesis(
                self, session, &request,
            )
            .await;
        }
        // A key revocation is likewise controller-executed for the Agent and
        // decided by the Agent control unit.
        if event.kind == arkret_wire::EventKind::AgentKeyRevoke {
            return super::authority_agent_control::submit_self_agent_key_revoke(
                self, session, &request,
            )
            .await;
        }
        let (producer_guard, producer_key) =
            super::authority_producer_validation::verify_self_event_producer_key(
                self, session, event,
            )
            .await?;
        if let Some(governance) = remote_governance(self, &event.realm_id).await? {
            return super::authority_forward::forward_self_event(self, &governance, request).await;
        }
        if let Some(outcome) = refuse_unrouted_event(self, event).await? {
            return Ok(outcome);
        }
        match self_event_route(&event.kind)? {
            SelfEventRoute::Mls => {
                if request.approval_signatures.is_some() {
                    return Err(ServiceError::SchemaViolation(
                        "an MLS Event carries no approval signatures".to_owned(),
                    ));
                }
                return super::authority_mls_unit::admit_mls_event(
                    self,
                    event,
                    &[],
                    None,
                    super::authority_self_event_unit::AdmittedProducer::Local(producer_guard),
                    &producer_key,
                )
                .await;
            }
            SelfEventRoute::KeyBackupPointer => {
                return super::authority_key_backup_pointer::submit_self_key_backup_pointer(
                    self, &request,
                )
                .await;
            }
            SelfEventRoute::AccountabilityGrant => {
                return super::authority_accountability_grant::submit_self_accountability_grant(
                    self, &request,
                )
                .await;
            }
            SelfEventRoute::GuardedUnit => {}
            SelfEventRoute::Consent => {
                unreachable!("Consent is admitted before ordinary forwarding")
            }
        }
        require_guarded_unit_event(&request)?;
        super::authority_self_event_unit::commit_event_unit(
            self,
            &request,
            super::authority_self_event_unit::AdmittedProducer::Local(producer_guard),
            super::authority_self_event_unit::SelfEventUnitEffects::default(),
        )
        .await
    }

    async fn submit_self_mls(
        &self,
        session: &SessionIdentityState,
        request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let event = &request.commit_event;
        let (producer_guard, producer_key) =
            super::authority_producer_validation::verify_self_event_producer_key(
                self, session, event,
            )
            .await?;
        if let Some(governance) = remote_governance(self, &event.realm_id).await? {
            return super::authority_forward::forward_self_mls(self, &governance, request).await;
        }
        super::authority_mls_unit::admit_mls_event(
            self,
            event,
            &request.welcomes,
            None,
            super::authority_self_event_unit::AdmittedProducer::Local(producer_guard),
            &producer_key,
        )
        .await
    }

    async fn submit_peer_authority_forward_event(
        &self,
        peer: &soland_services::authority_commit::AuthenticatedPeerContext,
        request: PeerAuthorityForwardEventRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        super::authority_forward::admit_forwarded_event(self, peer, request, crate::wire::now())
            .await
    }

    async fn submit_peer_authority_forward_mls(
        &self,
        peer: &soland_services::authority_commit::AuthenticatedPeerContext,
        request: PeerAuthorityForwardMlsRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        super::authority_forward::admit_forwarded_mls(self, peer, request, crate::wire::now()).await
    }

    async fn submit_peer_committed_replication(
        &self,
        peer: &soland_services::authority_commit::AuthenticatedPeerContext,
        request: arkret_models_collaboration::authority_commit::PeerCommittedReplicationRequest,
    ) -> ServiceResult<arkret_models_collaboration::authority_commit::PeerCommittedReplicationOutcome>
    {
        super::committed_replication::receive(self, peer, request).await
    }

    async fn submit_peer_direct_conversation_founding(
        &self,
        peer: &soland_services::authority_commit::AuthenticatedPeerContext,
        request: arkret_models_collaboration::authority_commit::DirectConversationFoundingFederationSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        super::authority_direct_conversation::submit_peer_direct_conversation_founding(
            self, peer, request,
        )
        .await
    }

    async fn scan_stream_for_account(
        &self,
        account: &arkret_wire::AccountId,
        request: StreamScanRequest,
    ) -> ServiceResult<soland_storage::AccountStreamScan> {
        self.authority_commits()
            .scan_stream_for_account(&request, account, &self.service_core_id())
            .await
    }

    async fn scan_stream_for_peer(
        &self,
        peer: &soland_services::authority_commit::AuthenticatedPeerContext,
        request: StreamScanRequest,
    ) -> ServiceResult<soland_storage::AccountStreamScan> {
        self.authority_commits()
            .scan_stream_for_peer(&request, &peer.source_service_id, &self.service_core_id())
            .await
    }

    /// The nonce-bound genesis-to-current chain, signed by this Station's
    /// notary method and carrying its current authenticated service route.
    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle> {
        let route =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                self,
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!(
                    "current authenticated service route is unavailable: {}",
                    error.message
                ))
            })?;
        let route = serde_json::to_value(route)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let verification_method = self
            .service_verification_method("notary-key")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        self.authority_commits()
            .authority_bundle(
                &request,
                &self.service_core_id(),
                route,
                verification_method,
                self.notary_signing_key().as_ref(),
                crate::wire::now(),
            )
            .await
    }

    async fn install_authority_handoff(
        &self,
        _request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff> {
        Err(ServiceError::Internal(
            "peer handoff authentication and fencing are unavailable".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::EventKind;
    use soland_services::ServiceError;

    use super::{SelfEventRoute, refuse_actor_private_event, self_event_route};

    #[test]
    fn only_kinds_with_a_self_authority_cut_are_routed() {
        assert_eq!(
            self_event_route(&EventKind::KeyBackupActiveSeries).unwrap(),
            SelfEventRoute::KeyBackupPointer
        );
        assert_eq!(
            self_event_route(&EventKind::IdentityAccountabilityGrant).unwrap(),
            SelfEventRoute::AccountabilityGrant
        );
        for kind in [EventKind::MlsGenesis, EventKind::MlsCommit] {
            assert_eq!(self_event_route(&kind).unwrap(), SelfEventRoute::Mls);
        }
        for kind in [
            EventKind::CircleCreate,
            EventKind::CircleMemberState,
            EventKind::MemberIdentityUpdate,
            EventKind::RealmOrganization,
            EventKind::StrandCreate,
            EventKind::RealmProfile,
            EventKind::StrandUpdate,
            EventKind::StrandArchive,
            EventKind::StrandRestore,
            EventKind::StrandStageSet,
            EventKind::StrandMove,
            EventKind::StrandReorder,
            EventKind::StrandWatchSet,
            EventKind::SpaceCreate,
            EventKind::RealmSetDefaultStrand,
            EventKind::CallCreate,
            EventKind::MessageCreate,
            EventKind::MemberState,
            EventKind::CapabilityGrant,
            EventKind::MessageRevise,
            EventKind::MessageRedact,
            EventKind::ModerationDecision,
            EventKind::ModerationDecisionLift,
            EventKind::InviteCreate,
            EventKind::InviteThirdParty,
            EventKind::InviteRevoke,
            EventKind::InviteCancel,
            EventKind::InviteAccept,
            EventKind::CapabilityRevoke,
            EventKind::CapabilityRelinquish,
        ] {
            assert_eq!(
                self_event_route(&kind).unwrap(),
                SelfEventRoute::GuardedUnit
            );
        }
    }

    #[test]
    fn every_other_active_kind_is_unsupported_event_kind_not_internal() {
        let routed = [
            EventKind::ConsentGrant,
            EventKind::ConsentRevoke,
            EventKind::KeyBackupActiveSeries,
            EventKind::IdentityAccountabilityGrant,
            EventKind::MlsGenesis,
            EventKind::MlsCommit,
            EventKind::CircleCreate,
            EventKind::CircleMemberState,
            EventKind::MemberIdentityUpdate,
            EventKind::RealmOrganization,
            EventKind::StrandCreate,
            EventKind::RealmProfile,
            EventKind::StrandUpdate,
            EventKind::StrandArchive,
            EventKind::StrandRestore,
            EventKind::StrandStageSet,
            EventKind::StrandMove,
            EventKind::StrandReorder,
            EventKind::StrandWatchSet,
            EventKind::SpaceCreate,
            EventKind::DirectConversationBound,
            EventKind::RealmSetDefaultStrand,
            EventKind::CallCreate,
            EventKind::MessageCreate,
            EventKind::MemberState,
            EventKind::CapabilityGrant,
            EventKind::MessageRevise,
            EventKind::MessageRedact,
            EventKind::ModerationDecision,
            EventKind::ModerationDecisionLift,
            EventKind::InviteCreate,
            EventKind::InviteThirdParty,
            EventKind::InviteRevoke,
            EventKind::InviteCancel,
            EventKind::InviteAccept,
            EventKind::CapabilityRevoke,
            EventKind::CapabilityRelinquish,
        ];
        let mut refused = 0;
        for kind in EventKind::ALL.iter().filter(|kind| !routed.contains(kind)) {
            match self_event_route(kind) {
                Err(ServiceError::UnsupportedEventKind(detail)) => {
                    assert!(detail.contains(kind.as_str()), "{detail}");
                }
                other => panic!(
                    "{} must be unsupported_event_kind, got {other:?}",
                    kind.as_str()
                ),
            }
            refused += 1;
        }
        assert_eq!(refused, EventKind::ALL.len() - routed.len());
    }

    #[test]
    fn every_actor_private_kind_is_refused_by_the_shared_ingress() {
        let mut refused = Vec::new();
        for kind in EventKind::ALL {
            if refuse_actor_private_event(kind).is_err() {
                refused.push(kind.as_str());
            }
        }
        refused.sort_unstable();
        assert_eq!(
            refused,
            [
                "ak.account_data.set",
                "ak.agent.action_reject",
                "ak.agent.action_request",
                "ak.agent.draft.propose",
                "ak.device.push_route",
                "ak.read_cursor.advance",
            ]
        );
        assert!(matches!(
            refuse_actor_private_event(&EventKind::DevicePushRoute),
            Err(ServiceError::UnsupportedEventKind(_))
        ));
        assert!(refuse_actor_private_event(&EventKind::MessageCreate).is_ok());
    }

    #[test]
    fn an_unregistered_kind_is_a_schema_violation() {
        assert!(matches!(
            self_event_route(&EventKind::Unknown("ak.example.unregistered".to_owned())),
            Err(ServiceError::SchemaViolation(_))
        ));
    }
}
