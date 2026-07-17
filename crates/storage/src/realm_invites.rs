use super::{PersistenceResult, RealmInviteRecord, Utc, Value, async_trait};
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
    third_party_id: &mut Option<Value>,
    remove_commitment: bool,
) {
    let Some(value) = third_party_id.as_mut() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in [
        "token_salt",
        "token_salt_id",
        "lookup_table_ref",
        "pepper",
        "pepper_id",
    ] {
        object.remove(key);
    }
    if remove_commitment {
        object.remove("token_commitment");
    }
}
