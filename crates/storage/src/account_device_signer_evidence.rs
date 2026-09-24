use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, CommittedEventRef, DeviceId, SignerEvidenceRef};
use async_trait::async_trait;

use crate::{PersistenceError, PersistenceResult};

/// The complete `producer_device_evidence` a governance Station verified for
/// a cross-Station human-device producer, with its content address.
///
/// It is retained in the same transaction that writes the Event's first
/// `RealmCommit`, for audit only: nothing reads it back as device authority,
/// and historical replay relies on the Commit and the authority chain.
#[derive(Clone, Debug, PartialEq)]
pub struct ForwardedProducerDeviceEvidence {
    pub evidence: AccountDeviceSignerEvidence,
    pub evidence_ref: SignerEvidenceRef,
}

impl ForwardedProducerDeviceEvidence {
    /// Address the complete object exactly as the evidence ref rule requires.
    pub fn new(evidence: AccountDeviceSignerEvidence) -> PersistenceResult<Self> {
        let evidence_ref = evidence
            .signer_evidence_ref()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        Ok(Self {
            evidence,
            evidence_ref,
        })
    }
}

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
