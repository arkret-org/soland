use arkret_sdk::StoredServiceIdentity;

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
}
/// Fixed primary key for the singleton service-identity row.
#[doc(hidden)]
pub const SINGLETON_ID: &str = "self";
