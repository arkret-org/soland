//! Adapter from the public authority protocol to this Station's durable store.
//!
//! The stream read is live. Mutation branches remain closed until the serving
//! layer can prove the producer and current authorization at the same cut as
//! the authority transaction; merely validating an Event's shape is not enough.

use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    EventAdmissionSubmission, MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityHandoff,
    StreamScanOutcome, StreamScanRequest,
};
use soland_services::authority_commit::AuthorityProtocolPort;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};

use super::AppState;

#[async_trait::async_trait]
impl AuthorityProtocolPort for AppState {
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
