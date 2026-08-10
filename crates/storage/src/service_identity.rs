use arkret_identity::service_identity::StoredServiceIdentity;
use arkret_models_identity::ServiceResolutionRecord;
use arkret_wire::Hash;

use super::{PersistenceResult, async_trait};
/// Persistence for the deployment's SDK-defined, verified service identity.
///
/// The singleton row contains only public evidence and opaque `KeyRef`s. Secret
/// signing/control material belongs to the configured SDK `KeyStore` and MUST
/// never be copied into PostgreSQL.
#[async_trait]
pub trait ServiceIdentityStore: Send + Sync {
    async fn get(&self) -> PersistenceResult<Option<StoredServiceIdentity>>;
    async fn put(&self, identity: StoredServiceIdentity) -> PersistenceResult<()>;
    async fn get_resolution(&self) -> PersistenceResult<Option<ServiceResolutionRecord>>;
    /// Atomically replace the singleton signed record only when its durable
    /// predecessor digest is the caller's snapshot. `None` creates generation
    /// one and cannot overwrite an already published record.
    async fn compare_and_set_resolution(
        &self,
        expected_digest: Option<&Hash>,
        record: ServiceResolutionRecord,
    ) -> PersistenceResult<bool>;
}
/// Fixed primary key for the singleton service-identity row.
#[doc(hidden)]
pub const SINGLETON_ID: &str = "self";
