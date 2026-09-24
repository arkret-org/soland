use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, CommittedEventRef, DeviceId, SignerEvidenceRef};
use async_trait::async_trait;

use crate::PersistenceResult;

/// Durable origin roots. A current issuer must use the checked same-cut write;
/// historical reads require the caller to authorize disclosure separately.
#[async_trait]
pub trait AccountDeviceSignerEvidenceStore: Send + Sync {
    async fn retain_current(
        &self,
        evidence: &AccountDeviceSignerEvidence,
        authorization_ref: &CommittedEventRef,
    ) -> PersistenceResult<SignerEvidenceRef>;

    async fn get(
        &self,
        account: &AccountId,
        device: &DeviceId,
        reference: &SignerEvidenceRef,
    ) -> PersistenceResult<Option<AccountDeviceSignerEvidence>>;
}
