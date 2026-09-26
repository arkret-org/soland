//! Private Consent-request admission cut shared by the three first-contact
//! surfaces. This is a backend-neutral internal port, not a wire operation.

use arkret_wire::{AccountId, ConsentRequestScope, NewSourceQuotaConstraints};
use chrono::{DateTime, Utc};

use crate::{AccountDataRecord, PersistenceResult, async_trait};

pub struct ConsentRequestQuarantineInput {
    pub holder: AccountId,
    pub requester: AccountId,
    pub consent_scope: ConsentRequestScope,
    /// The Station's existing keyed digest of the complete requester source.
    pub source_digest: String,
    pub received_at: DateTime<Utc>,
    pub quota_constraints: NewSourceQuotaConstraints,
}

#[derive(Debug)]
pub enum ConsentRequestQuarantineOutcome {
    Queued(AccountDataRecord),
    AlreadyPending,
    Dropped,
}

#[async_trait]
pub trait ConsentRequestQuarantineStore: Send + Sync {
    async fn admit(
        &self,
        input: ConsentRequestQuarantineInput,
    ) -> PersistenceResult<ConsentRequestQuarantineOutcome>;
}
