use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;

use super::{PersistenceResult, RealmInviteRecord, Utc, async_trait};
/// realm invite tokens.
#[async_trait]
pub trait RealmInviteStore: Send + Sync {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>>;
    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()>;
    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>>;
}
#[doc(hidden)]
pub fn remove_third_party_active_material(
    third_party_invite: &mut Option<ThirdPartyInvite>,
    remove_commitment: bool,
) {
    let Some(value) = third_party_invite.as_mut() else {
        return;
    };
    // The closed `ThirdPartyInvite` schema never admits `token_salt` /
    // `pepper` members; only the registered handles can be present.
    value.token_salt_id = None;
    value.lookup_table_ref = None;
    value.pepper_id = None;
    if remove_commitment {
        value.token_commitment = None;
    }
}
