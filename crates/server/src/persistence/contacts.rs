use super::*;

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
/// (`ck.self.invite_receive_policy.resource.replace`,
/// `ck.self.contact.command.tombstone(block_peer)`).
#[async_trait]
pub trait InviteReceivePolicyStore: Send + Sync {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<cokret_sdk::InviteReceivePolicy>>;
    async fn put(&self, policy: &cokret_sdk::InviteReceivePolicy) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, cokret_sdk::InviteReceivePolicy)>>;
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

type ContactKey = (String, String, String);

pub(crate) struct MemoryContactStore {
    data: Arc<Mutex<BTreeMap<ContactKey, ContactRecord>>>,
}

impl MemoryContactStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ContactStore for MemoryContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .find(|record| {
                record.requester == requester
                    && record.target == target
                    && record.scope == "message"
            })
            .or_else(|| {
                data.values()
                    .find(|record| record.requester == requester && record.target == target)
            })
            .cloned())
    }

    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(requester.to_owned(), target.to_owned(), scope.to_owned()))
            .cloned())
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (
                record.requester.clone(),
                record.target.clone(),
                record.scope.clone(),
            ),
            record.clone(),
        );
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.retain(|(row_requester, row_target, _), _| {
            row_requester != requester || row_target != target
        });
        Ok(())
    }
}

// In-memory invite-receive policy store
pub(crate) struct MemoryInviteReceivePolicyStore {
    data: Arc<Mutex<BTreeMap<String, cokret_sdk::InviteReceivePolicy>>>,
}

impl MemoryInviteReceivePolicyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl InviteReceivePolicyStore for MemoryInviteReceivePolicyStore {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<cokret_sdk::InviteReceivePolicy>> {
        Ok(self.data.lock().expect("lock").get(subject_id).cloned())
    }

    async fn put(&self, policy: &cokret_sdk::InviteReceivePolicy) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("lock")
            .insert(policy.subject_id.as_str().to_owned(), policy.clone());
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, cokret_sdk::InviteReceivePolicy)>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

// In-memory consent-cell store
pub(crate) struct MemoryConsentCellStore {
    data: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
}

impl MemoryConsentCellStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ConsentCellStore for MemoryConsentCellStore {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let key = ConsentCellKey {
            holder: holder.to_owned(),
            peer: peer.to_owned(),
            scope: scope.to_owned(),
        };
        Ok(self.data.lock().expect("lock").get(&key).cloned())
    }

    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()> {
        let key = ConsentCellKey {
            holder: record.holder.clone(),
            peer: record.peer.clone(),
            scope: record.scope.clone(),
        };
        self.data.lock().expect("lock").insert(key, record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

// In-memory direct-conversation binding store
pub(crate) struct MemoryDirectConversationBindingStore {
    data: Arc<Mutex<BTreeMap<String, DirectConversationBindingRecord>>>,
}

impl MemoryDirectConversationBindingStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl DirectConversationBindingStore for MemoryDirectConversationBindingStore {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .get(participants_key)
            .cloned())
    }

    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("lock")
            .insert(participants_key.to_owned(), record.clone());
        Ok(())
    }

    async fn delete(&self, participants_key: &str) -> PersistenceResult<()> {
        self.data.lock().expect("lock").remove(participants_key);
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

// ── Pg-backed contact projection store ───────────────────────────────────
// Durable backing for the holder↔peer `ContactStore`. Mirrors the
// `MemoryContactStore` query shape onto the `contacts` table. Column order
// matches `state::ContactRecord`.
pub(crate) struct PgContactStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct ContactRow {
    #[diesel(sql_type = Text)]
    requester: String,
    #[diesel(sql_type = Text)]
    target: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Text>)]
    message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_service_did: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ContactRow> for ContactRecord {
    fn from(row: ContactRow) -> Self {
        Self {
            requester: row.requester,
            target: row.target,
            scope: row.scope,
            status: row.status,
            message: row.message,
            peer_service_did: row.peer_service_did,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

const CONTACT_COLUMNS: &str = "requester_id AS requester, target_id AS target, scope, status, message, peer_service_id AS peer_service_did, created_at, updated_at";

#[async_trait]
impl ContactStore for PgContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        // Mirror MemoryContactStore::get — prefer the `message` scope row, then
        // fall back to any scope for this requester/target pair.
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 AND target_id = $2 \
             ORDER BY (scope = 'message') DESC, scope ASC LIMIT 1"
        ))
        .bind::<Text, _>(requester)
        .bind::<Text, _>(target)
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(ContactRecord::from))
    }

    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 AND target_id = $2 AND scope = $3"
        ))
        .bind::<Text, _>(requester)
        .bind::<Text, _>(target)
        .bind::<Text, _>(scope)
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(ContactRecord::from))
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, scope, status, message, peer_service_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (requester_id, target_id, scope) DO UPDATE SET \
                status = EXCLUDED.status, \
                message = EXCLUDED.message, \
                peer_service_id = EXCLUDED.peer_service_id, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_did.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 OR target_id = $1 \
             ORDER BY created_at ASC, scope ASC"
        ))
        .bind::<Text, _>(actor)
        .get_results::<ContactRow>(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(ContactRecord::from).collect())
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM contacts WHERE requester_id = $1 AND target_id = $2")
            .bind::<Text, _>(requester)
            .bind::<Text, _>(target)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

// ── Pg-backed invite-receive policy store ────────────────────────────────
// Durable backing for per-subject `invite_receive_policy` overrides. The full
// `cokret_sdk::InviteReceivePolicy` is persisted as JSONB; `blocked_subjects`
// is duplicated into a TEXT[] column for cheap hard-block lookups.
pub(crate) struct PgInviteReceivePolicyStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct InviteReceivePolicyRow {
    #[diesel(sql_type = Text)]
    subject_id: String,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}

impl InviteReceivePolicyRow {
    fn into_pair(self) -> PersistenceResult<(String, cokret_sdk::InviteReceivePolicy)> {
        let policy: cokret_sdk::InviteReceivePolicy = serde_json::from_value(self.policy_payload)
            .map_err(|error| {
            PersistenceError::Internal(format!(
                "invite_receive_policy `{}` payload decode: {error}",
                self.subject_id
            ))
        })?;
        Ok((self.subject_id, policy))
    }
}

#[async_trait]
impl InviteReceivePolicyStore for PgInviteReceivePolicyStore {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<cokret_sdk::InviteReceivePolicy>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT id AS subject_id, policy_payload FROM invite_receive_policies WHERE id = $1",
        )
        .bind::<Text, _>(subject_id)
        .get_result::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .optional()?;
        row.map(|row| row.into_pair().map(|(_, policy)| policy))
            .transpose()
    }

    async fn put(&self, policy: &cokret_sdk::InviteReceivePolicy) -> PersistenceResult<()> {
        let subject_id = policy.subject_id.as_str().to_owned();
        let payload = serde_json::to_value(policy).map_err(|error| {
            PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
        })?;
        let blocked_subjects = policy
            .blocked_subjects
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO invite_receive_policies \
             (id, policy_payload, blocked_subjects, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                policy_payload = EXCLUDED.policy_payload, \
                blocked_subjects = EXCLUDED.blocked_subjects, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&subject_id)
        .bind::<Jsonb, _>(&payload)
        .bind::<Array<Text>, _>(&blocked_subjects)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, cokret_sdk::InviteReceivePolicy)>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows =
            sql_query("SELECT id AS subject_id, policy_payload FROM invite_receive_policies")
                .get_results::<InviteReceivePolicyRow>(&mut *conn)
                .await?;
        rows.into_iter()
            .map(InviteReceivePolicyRow::into_pair)
            .collect()
    }
}

// ── Pg-backed consent-cell store ─────────────────────────────────────────
// Durable backing for the holder-private consent-cell projection. Column
// order mirrors `state::ConsentCellRecord`; `grant_dots` is persisted as a
// JSONB object `{dot -> {dot, expires_at, granted_at}}` and `revoked_dots` as
// a JSONB string array so the in-memory `BTreeMap`/`BTreeSet` round-trip
// losslessly.
pub(crate) struct PgConsentCellStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct ConsentCellRow {
    #[diesel(sql_type = Text)]
    holder: String,
    #[diesel(sql_type = Text)]
    peer: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    requested_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    grant_dots: Value,
    #[diesel(sql_type = Jsonb)]
    revoked_dots: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Decode a persisted `grant_dots` JSONB object back into the in-memory
/// `BTreeMap<String, ConsentGrantDot>`.
pub(crate) fn decode_grant_dots(value: &Value) -> BTreeMap<String, ConsentGrantDot> {
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
pub(crate) fn encode_grant_dots(dots: &BTreeMap<String, ConsentGrantDot>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, grant) in dots {
        map.insert(key.clone(), json_for_grant_dot(grant));
    }
    Value::Object(map)
}

fn json_for_grant_dot(grant: &ConsentGrantDot) -> Value {
    serde_json::json!({
        "dot": grant.dot,
        "granted_at": grant.granted_at.to_rfc3339(),
        "expires_at": grant.expires_at.map(|dt| dt.to_rfc3339()),
    })
}

impl ConsentCellRow {
    fn into_pair(self) -> (ConsentCellKey, ConsentCellRecord) {
        let revoked_dots: BTreeSet<String> = self
            .revoked_dots
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let key = ConsentCellKey {
            holder: self.holder.clone(),
            peer: self.peer.clone(),
            scope: self.scope.clone(),
        };
        let record = ConsentCellRecord {
            holder: self.holder,
            peer: self.peer,
            scope: self.scope,
            cell_id: self.cell_id,
            requested_at: self.requested_at,
            grant_dots: decode_grant_dots(&self.grant_dots),
            revoked_dots,
            revoked_at: self.revoked_at,
            updated_at: self.updated_at,
        };
        (key, record)
    }
}

const CONSENT_CELL_COLUMNS: &str = "holder_id AS holder, peer_id AS peer, scope, cell_id, requested_at, grant_dots, \
     revoked_dots, revoked_at, updated_at";

#[async_trait]
impl ConsentCellStore for PgConsentCellStore {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells \
             WHERE holder_id = $1 AND peer_id = $2 AND scope = $3"
        ))
        .bind::<Text, _>(holder)
        .bind::<Text, _>(peer)
        .bind::<Text, _>(scope)
        .get_result::<ConsentCellRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(|row| row.into_pair().1))
    }

    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()> {
        let grant_dots = encode_grant_dots(&record.grant_dots);
        let revoked_dots = Value::Array(
            record
                .revoked_dots
                .iter()
                .map(|dot| Value::String(dot.clone()))
                .collect(),
        );
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO consent_cells \
             (id, holder_id, peer_id, scope, cell_id, requested_at, grant_dots, revoked_dots, revoked_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (holder_id, peer_id, scope) DO UPDATE SET \
                cell_id = EXCLUDED.cell_id, \
                requested_at = EXCLUDED.requested_at, \
                grant_dots = EXCLUDED.grant_dots, \
                revoked_dots = EXCLUDED.revoked_dots, \
                revoked_at = EXCLUDED.revoked_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.holder)
        .bind::<Text, _>(&record.peer)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.cell_id)
        .bind::<Nullable<Timestamptz>, _>(record.requested_at)
        .bind::<Jsonb, _>(&grant_dots)
        .bind::<Jsonb, _>(&revoked_dots)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!("SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells"))
            .get_results::<ConsentCellRow>(&mut *conn)
            .await?;
        Ok(rows.into_iter().map(ConsentCellRow::into_pair).collect())
    }
}

// ── Pg-backed direct-conversation binding store ──────────────────────────
// Durable backing for the DM binding projection. `participants_key` is the
// sorted, NUL-joined participant pair (the in-memory map key); the remaining
// columns mirror `state::DirectConversationBindingRecord`.
pub(crate) struct PgDirectConversationBindingStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct DirectConversationBindingRow {
    #[diesel(sql_type = Text)]
    participants_key: String,
    #[diesel(sql_type = Array<Text>)]
    participants_unordered: Vec<String>,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    main_strand_id: Uuid,
    #[diesel(sql_type = Text)]
    binding_event_ref: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl DirectConversationBindingRow {
    fn into_pair(self) -> (String, DirectConversationBindingRecord) {
        (
            self.participants_key,
            DirectConversationBindingRecord {
                participants_unordered: self.participants_unordered,
                realm_id: ids::format_typed_uuid("realm", &self.realm_id),
                main_strand_id: ids::format_typed_uuid("strand", &self.main_strand_id),
                binding_event_ref: self.binding_event_ref,
                state: self.state,
                created_at: self.created_at,
                updated_at: self.updated_at,
            },
        )
    }
}

const DIRECT_BINDING_COLUMNS: &str = "participants_key, participants_unordered, realm_id, \
     main_strand_id, binding_event_ref, state, created_at, updated_at";

#[async_trait]
impl DirectConversationBindingStore for PgDirectConversationBindingStore {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {DIRECT_BINDING_COLUMNS} FROM direct_conversation_bindings \
             WHERE participants_key = $1"
        ))
        .bind::<Text, _>(participants_key)
        .get_result::<DirectConversationBindingRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(|row| row.into_pair().1))
    }

    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO direct_conversation_bindings \
             (participants_key, participants_unordered, realm_id, main_strand_id, \
              binding_event_ref, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (participants_key) DO UPDATE SET \
                participants_unordered = EXCLUDED.participants_unordered, \
                realm_id = EXCLUDED.realm_id, \
                main_strand_id = EXCLUDED.main_strand_id, \
                binding_event_ref = EXCLUDED.binding_event_ref, \
                state = EXCLUDED.state, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(participants_key)
        .bind::<Array<Text>, _>(&record.participants_unordered)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.main_strand_id))
        .bind::<Text, _>(&record.binding_event_ref)
        .bind::<Text, _>(&record.state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, participants_key: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM direct_conversation_bindings WHERE participants_key = $1")
            .bind::<Text, _>(participants_key)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {DIRECT_BINDING_COLUMNS} FROM direct_conversation_bindings"
        ))
        .get_results::<DirectConversationBindingRow>(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(DirectConversationBindingRow::into_pair)
            .collect())
    }
}
