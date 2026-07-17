use soland_domain::identity::{
    ConsentCellKey, ConsentCellRecord, ConsentGrantDot, ContactRecord,
    DirectConversationBindingRecord,
};

use super::{BTreeMap, PersistenceResult, Value, async_trait};
/// Trait for contact storage operations.
#[async_trait]
pub trait ContactStore: Send + Sync {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>>;
    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}
/// Durable backing for per-subject private `invite_receive_policy` overrides
/// (spec `sync/invite-addressing.md` §5). The in-memory
/// `AppState::invite_receive_policies` map remains the working projection; this
/// store hydrates it on boot and is written through on policy changes
/// (`ak.self.invite_receive_policy.resource.replace`,
/// `ak.self.contact.command.tombstone(block_peer)`).
#[async_trait]
pub trait InviteReceivePolicyStore: Send + Sync {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<arkret_sdk::InviteReceivePolicy>>;
    async fn put(&self, policy: &arkret_sdk::InviteReceivePolicy) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, arkret_sdk::InviteReceivePolicy)>>;
}
/// Durable backing for the holder-private consent-cell projection (spec
/// `consent-model.md` §3 / G3.S4). The in-memory
/// `AppState::consent_cells` map keyed by `(holder, peer, scope)` remains the
/// working OR-set projection; this store hydrates it on boot and is written
/// through after each accepted grant/revoke/pending mutation. `grant_dots` /
/// `revoked_dots` are persisted as JSONB so the `BTreeMap`/`BTreeSet`
/// round-trips losslessly.
#[async_trait]
pub trait ConsentCellStore: Send + Sync {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>>;
    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>>;
}
/// Durable backing for the direct-conversation binding projection (spec
/// `contact-and-direct-conversation.md` §5). The in-memory
/// `AppState::direct_conversation_bindings` map keyed by the sorted, NUL-joined
/// participant pair (`participants_key`) remains the working projection; this
/// store hydrates it on boot and is written through on binding create/update.
#[async_trait]
pub trait DirectConversationBindingStore: Send + Sync {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>>;
    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()>;
    async fn delete(&self, participants_key: &str) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>>;
}
#[doc(hidden)]
pub type ContactKey = (String, String, String);
/// Decode a persisted `grant_dots` JSONB object back into the in-memory
/// `BTreeMap<String, ConsentGrantDot>`.
pub fn decode_grant_dots(value: &Value) -> BTreeMap<String, ConsentGrantDot> {
    let mut dots = BTreeMap::new();
    let Some(object) = value.as_object() else {
        return dots;
    };
    for (key, entry) in object {
        let Some(dot) = entry
            .get("dot")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let granted_at = entry
            .get("granted_at")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        let expires_at = entry
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        dots.insert(
            key.clone(),
            ConsentGrantDot {
                dot,
                expires_at,
                granted_at,
            },
        );
    }
    dots
}
/// Encode the in-memory `grant_dots` map into a JSONB object for storage.
pub fn encode_grant_dots(dots: &BTreeMap<String, ConsentGrantDot>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, grant) in dots {
        map.insert(key.clone(), json_for_grant_dot(grant));
    }
    Value::Object(map)
}
#[doc(hidden)]
pub fn json_for_grant_dot(grant: &ConsentGrantDot) -> Value {
    serde_json::json!({
        "dot": grant.dot,
        "granted_at": grant.granted_at.to_rfc3339(),
        "expires_at": grant.expires_at.map(|dt| dt.to_rfc3339()),
    })
}
