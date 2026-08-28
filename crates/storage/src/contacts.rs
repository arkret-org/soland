use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use soland_domain::identity::{ConsentCellKey, ConsentCellRecord, ConsentGrantDot, ContactRecord};

use super::{BTreeMap, PersistenceResult, Utc, Value, async_trait};

/// Principal-private, non-canonical mirror of one fully verified inbound
/// `ak.contact.requested` carrier. It never participates in Realm reduction,
/// Seal construction, CBA frontiers, or state roots.
#[derive(Clone, Debug, PartialEq)]
pub struct ContactVerifiedMirrorRecord {
    pub target_holder_id: String,
    pub request_event_id: String,
    pub request_digest: String,
    pub canonical_event_bytes: Vec<u8>,
    pub source_receipt: RequestAcceptanceReceipt,
    pub issuer_id: String,
    pub verified_at: chrono::DateTime<Utc>,
}

#[async_trait]
pub trait ContactVerifiedMirrorStore: Send + Sync {
    async fn get(
        &self,
        target_holder_id: &str,
        request_event_id: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>>;
    async fn get_by_digest(
        &self,
        target_holder_id: &str,
        request_digest: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>>;

    /// CAS-insert one verified mirror. An exact replay is success; the same
    /// holder/Event key with different bytes, digest, receipt, or issuer is a
    /// conflict and MUST NOT overwrite the original evidence.
    async fn put_verified(&self, record: &ContactVerifiedMirrorRecord) -> PersistenceResult<()>;
}

/// Trait for contact storage operations.
#[async_trait]
pub trait ContactStore: Send + Sync {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    /// Replace one existing Contact row only when its durable revision still
    /// matches the revision the caller read. Callers must advance
    /// `record.updated_at`; `false` is a lost-race signal, never permission to
    /// overwrite newer receipt/evidence state.
    async fn put_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        record: &ContactRecord,
    ) -> PersistenceResult<bool>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}
/// Durable backing for per-subject private `invite_receive_policy` overrides
/// (spec `sync/invite-addressing.md` §5). The in-memory
/// `AppState::invite_receive_policies` map remains the working projection; this
/// store hydrates it on boot and is written through on policy changes
/// (`ak.self.invite_receive_policy.resource.replace.v1`,
/// `ak.self.contact.command.tombstone.v1(block_peer)`).
#[async_trait]
pub trait InviteReceivePolicyStore: Send + Sync {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    >;
    async fn put(
        &self,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            String,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    >;
}
/// Durable backing for the holder-private consent-cell projection (spec
/// `consent-model.md` sections 3 to 5), keyed by `(holder, cell_id)` because
/// `consent_id` is the cell subject. Rows are only ever written inside the
/// Event commit unit of work that accepts the grant/revoke Control Move, so
/// this store exposes reads alone; boot hydration replays it into the working
/// projection. `grant_dots` / `revoked_dots` are persisted as JSONB so the
/// `BTreeMap`/`BTreeSet` round-trip losslessly.
#[async_trait]
pub trait ConsentCellStore: Send + Sync {
    async fn get(
        &self,
        holder: &str,
        cell_id: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>>;
}

/// Service-local correlation retained by the MIMI consent facade.
///
/// This is deliberately not a consent cell or a protocol Event. It only binds
/// the opaque `consent_id` returned by `request_consent` to the authenticated
/// requester, target, scope, transport source, and optional expiry so a later
/// caller-authored Event can be checked without disclosing holder-private
/// state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimiConsentCorrelationRecord {
    pub consent_id: String,
    pub requester_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub purpose: String,
    pub strand_id: Option<String>,
    pub source_id: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

#[async_trait]
pub trait MimiConsentCorrelationStore: Send + Sync {
    async fn get(
        &self,
        consent_id: &str,
    ) -> PersistenceResult<Option<MimiConsentCorrelationRecord>>;
    async fn put(&self, record: &MimiConsentCorrelationRecord) -> PersistenceResult<()>;
}
#[doc(hidden)]
pub type ContactKey = (String, String);
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
        let not_before = entry
            .get("not_before")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        let expires_at = entry
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        dots.insert(
            key.clone(),
            ConsentGrantDot {
                dot,
                not_before,
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
        "not_before": grant
            .not_before
            .map(arkret_canonical::format_timestamp_canonical),
        "expires_at": grant
            .expires_at
            .map(arkret_canonical::format_timestamp_canonical),
        "granted_at": arkret_canonical::format_timestamp_canonical(grant.granted_at),
    })
}
