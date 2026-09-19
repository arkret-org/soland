use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingResolveRequestBody, DevicePairingStageOutcome,
    DevicePairingStageRequestBody, DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
use async_trait::async_trait;

use crate::error::AppError;

/// Typed Station -> Account Authority boundary for the three public
/// device-pairing handoff operations.
///
/// The public handlers own request parsing, their public rate bucket, and the
/// fresh stage idempotency key. A production implementation of this port owns
/// the registered RFC 9421 service-to-service transport and any transport
/// retry. Every retry of one [`Self::stage`] call MUST reuse the supplied key;
/// a later public ingress receives a different key from the handler.
#[async_trait]
pub trait AccountAuthorityDevicePairingPort: Send + Sync {
    async fn stage(
        &self,
        request: &DevicePairingStageRequestBody,
        idempotency_key: &str,
    ) -> Result<DevicePairingStageOutcome, AppError>;

    async fn resolve(
        &self,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError>;

    async fn status(
        &self,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusOutcome, AppError>;
}

/// Fail-closed production default until a client that covers the complete
/// service-to-service signature scenario is installed.
///
/// The older deployment bearer is deliberately not consulted here: the three
/// pairing operations prohibit bearer-only authentication.
#[derive(Debug, Default)]
pub(crate) struct UnavailableAccountAuthorityDevicePairing;

impl UnavailableAccountAuthorityDevicePairing {
    fn unavailable() -> AppError {
        crate::app_error!(
            TemporarilyUnavailable,
            "device pairing Account Authority transport is unavailable"
        )
    }
}

#[async_trait]
impl AccountAuthorityDevicePairingPort for UnavailableAccountAuthorityDevicePairing {
    async fn stage(
        &self,
        _request: &DevicePairingStageRequestBody,
        _idempotency_key: &str,
    ) -> Result<DevicePairingStageOutcome, AppError> {
        Err(Self::unavailable())
    }

    async fn resolve(
        &self,
        _request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError> {
        Err(Self::unavailable())
    }

    async fn status(
        &self,
        _request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusOutcome, AppError> {
        Err(Self::unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_service_signature_transport_is_temporarily_unavailable() {
        let error = UnavailableAccountAuthorityDevicePairing::unavailable();
        assert_eq!(error.code, arkret_wire::ErrorCode::TemporarilyUnavailable);
    }
}
