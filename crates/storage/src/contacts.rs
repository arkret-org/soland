use arkret_identifiers::CellRef;
use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use arkret_wire::ActorId;
use soland_domain::identity::{ConsentCellKey, ConsentCellRecord, ConsentGrantDot, ContactRecord};

use super::{BTreeMap, PersistenceResult, Utc, Value, async_trait};

/// Principal-private, non-canonical mirror of one fully verified inbound
/// `ak.contact.requested` carrier. It never participates in Realm reduction,
/// Seal construction, CBS frontiers, or state roots.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContactVerifiedMirrorRecord {
    pub target_holder_principal_id: String,
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
        target_holder_principal_id: &str,
        request_event_id: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>>;
    /// CAS-insert one verified mirror. An exact replay is success; the same
    /// holder/Event key with different bytes, digest, receipt, or issuer is a
    /// conflict and MUST NOT overwrite the original evidence.
    async fn put_verified(&self, record: &ContactVerifiedMirrorRecord) -> PersistenceResult<()>;
}

/// Trait for contact storage operations.
#[async_trait]
pub trait ContactStore: Send + Sync {
    async fn get(
        &self,
        requester_id: &ActorId,
        target_id: &ActorId,
    ) -> PersistenceResult<Option<ContactRecord>>;
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
    async fn list_for_actor(&self, actor_id: &ActorId) -> PersistenceResult<Vec<ContactRecord>>;
    async fn delete(&self, requester_id: &ActorId, target_id: &ActorId) -> PersistenceResult<()>;
}
/// Durable backing for per-account private `invite_receive_policy` overrides
/// (spec `sync/invite-addressing.md` §5). The in-memory
/// `AppState::invite_receive_policies` map remains the working projection; this
/// store hydrates it on boot and is written through on policy changes
/// (`ak.self.invite_receive_policy.resource.replace.v1`,
/// `ak.self.contact.command.tombstone.v1(block_peer)`).
#[async_trait]
pub trait InviteReceivePolicyStore: Send + Sync {
    async fn get(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    >;
    async fn put(
        &self,
        account_id: &arkret_wire::AccountId,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            arkret_wire::AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    >;
}

/// Bind a policy to the complete authenticated storage owner, including its
/// Station coordinate. A caller cannot write another Account's policy payload.
pub fn validate_invite_policy_account(
    account_id: &arkret_wire::AccountId,
    policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
) -> PersistenceResult<()> {
    if &policy.account_id != account_id {
        return Err(super::PersistenceError::SchemaViolation(
            "invite receive policy does not match its Account owner".to_owned(),
        ));
    }
    account_id
        .validate()
        .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))
}
/// Durable backing for the holder-private consent-cell projection (spec
/// `consent-model.md` sections 3 to 5), keyed by `(holder, cell_id)` because
/// `consent_id` is the cell subject. Rows are only ever written inside the
/// exact committed Seal transaction for the grant/revoke command, so
/// this store exposes reads alone; boot hydration replays it into the working
/// projection. `active_grants` / `revoked_grants` are persisted as JSONB so the
/// `BTreeMap`/`BTreeSet` round-trip losslessly.
#[async_trait]
pub trait ConsentCellStore: Send + Sync {
    async fn get(
        &self,
        holder_account_id: &arkret_wire::AccountId,
        cell_id: &CellRef,
    ) -> PersistenceResult<Option<ConsentCellRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>>;
}

/// Service-local correlation retained by the MIMI consent facade.
///
/// This is deliberately not a consent cell or a protocol Event. It only binds
/// the opaque `consent_id` returned by `request_consent` to the authenticated
/// requester_id, target, scope, transport source, and optional expiry so a later
/// caller-authored Event can be checked without disclosing holder-private
/// state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimiConsentCorrelationRecord {
    pub consent_id: String,
    /// Canonical JSON of the complete requester `ActorId`, exactly as signed.
    pub requester_actor_id: String,
    /// Canonical JSON of the complete holder `AccountId`, exactly as signed.
    pub holder_account_id: String,
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
pub type ContactKey = (ActorId, ActorId);
/// Decode an exact local active/audit grant map. Corrupt rows must not become
/// an empty authority view or manufacture grant timestamps from receiver time.
pub fn decode_consent_grants(
    value: &Value,
) -> PersistenceResult<BTreeMap<String, ConsentGrantDot>> {
    let grants: BTreeMap<String, ConsentGrantDot> =
        serde_json::from_value(value.clone()).map_err(|error| {
            super::PersistenceError::SchemaViolation(format!("invalid consent grant map: {error}"))
        })?;
    if grants.iter().any(|(tag, grant)| tag != &grant.dot) {
        return Err(super::PersistenceError::SchemaViolation(
            "consent grant key does not match its exact tag".to_owned(),
        ));
    }
    Ok(grants)
}
/// Encode one local active/audit grant map into a JSONB object for storage.
pub fn encode_consent_grants(dots: &BTreeMap<String, ConsentGrantDot>) -> Value {
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

#[cfg(test)]
mod consent_grant_codec_tests {
    use super::*;

    #[test]
    fn consent_grant_codec_rejects_corruption_instead_of_synthesizing_authority() {
        let grant = ConsentGrantDot {
            dot: "event:0".to_owned(),
            not_before: None,
            expires_at: None,
            granted_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        };
        let map = BTreeMap::from([(grant.dot.clone(), grant)]);
        let encoded = encode_consent_grants(&map);
        assert_eq!(decode_consent_grants(&encoded).unwrap(), map);
        let mut missing_time = encoded.clone();
        missing_time["event:0"]
            .as_object_mut()
            .unwrap()
            .remove("granted_at");
        assert!(decode_consent_grants(&missing_time).is_err());
        let mut invalid_window = encoded.clone();
        invalid_window["event:0"]["expires_at"] = serde_json::json!("invalid");
        assert!(decode_consent_grants(&invalid_window).is_err());
        let mut mismatched_tag = encoded;
        mismatched_tag["event:0"]["dot"] = serde_json::json!("different:0");
        assert!(decode_consent_grants(&mismatched_tag).is_err());
        assert!(decode_consent_grants(&serde_json::json!([])).is_err());
    }
}
