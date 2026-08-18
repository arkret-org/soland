//! Composition-root implementations of the owner-side handover ports.
//!
//! The planner in `soland-services` deliberately holds neither a private key
//! nor the durable identity singleton. Both live here, where the runtime
//! signer is already proven to be a current service assertion method and where
//! the record that a notice is issued against is read without minting a
//! successor.

use arkret_models_identity::{
    ServiceResolutionRecord, ServiceRouteHandoverNotice, ServiceRouteHandoverNoticeCore,
};
use async_trait::async_trait;
use soland_services::service_route_handover::{
    CurrentServiceResolutionPort, ServiceRouteNoticeSigner,
};
use soland_services::{ServiceError, ServiceResult};

use crate::state::AppState;

pub(crate) struct AppStateNoticeSigner {
    state: AppState,
}

impl AppStateNoticeSigner {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ServiceRouteNoticeSigner for AppStateNoticeSigner {
    async fn sign_handover_notice(
        &self,
        core: ServiceRouteHandoverNoticeCore,
    ) -> ServiceResult<ServiceRouteHandoverNotice> {
        let stored = self
            .state
            .stored_service_identity()
            .await
            .map_err(ServiceError::Internal)?;
        // Reuse the record signer's method selection so a notice can never be
        // signed by a key the service DID Document does not currently list as
        // an assertion method.
        let verification_method =
            crate::routing::system::service_resolution::service_assertion_method(
                &self.state,
                &stored,
            )
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        arkret_signatures::service_resolution::sign_service_route_handover_notice(
            core,
            verification_method,
            self.state.notary_signing_key().as_ref(),
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))
    }
}

pub(crate) struct AppStateCurrentResolution {
    state: AppState,
}

impl AppStateCurrentResolution {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl CurrentServiceResolutionPort for AppStateCurrentResolution {
    async fn current_record(&self) -> ServiceResult<Option<ServiceResolutionRecord>> {
        self.state
            .current_signed_service_resolution()
            .await
            .map_err(ServiceError::Internal)
    }
}
