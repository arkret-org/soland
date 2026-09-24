//! Adapter from the public authority protocol to this Station's durable store.
//!
//! Stream reads and guarded ordinary Realm bootstrap are live. Other mutation
//! branches remain closed until the serving layer can prove the producer and
//! current authorization at the authority transaction cut.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, OrdinaryRealmBootstrapAcceptanceOutcome,
    OrdinaryRealmBootstrapUnitSubmission,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    EventAdmissionSubmission, MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityHandoff,
    StreamScanOutcome, StreamScanRequest,
};
use chrono::Utc;
use soland_services::authority_commit::AuthorityProtocolPort;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};

use super::AppState;

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

    async fn submit_self_event(
        &self,
        session: &SessionIdentityState,
        request: EventAdmissionSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        let _producer_guard = super::authority_producer_validation::verify_self_event_producer(
            self,
            session,
            &request.event,
        )
        .await?;
        Err(ServiceError::Internal(
            "self Event authorization must be rechecked in the authority transaction".to_owned(),
        ))
    }

    async fn submit_self_mls(
        &self,
        _session: &SessionIdentityState,
        _request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        Err(ServiceError::Internal(
            "self MLS authority cut and atomic group installation are unavailable".to_owned(),
        ))
    }

    async fn scan_stream(&self, request: StreamScanRequest) -> ServiceResult<StreamScanOutcome> {
        self.authority_commits().scan_stream(&request).await
    }

    async fn authority_bundle(
        &self,
        _request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle> {
        Err(ServiceError::Internal(
            "verified current service route for the authority bundle is unavailable".to_owned(),
        ))
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
