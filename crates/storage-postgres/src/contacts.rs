use super::{
    Array, BTreeSet, ConsentCellKey, ConsentCellRecord, ConsentCellStore, ContactRecord,
    ContactStore, DirectConversationBindingRecord, DirectConversationBindingStore,
    InviteReceivePolicyStore, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SqlUuid, Text, Timestamptz, Uuid,
    Value, async_trait, decode_grant_dots, encode_grant_dots, ids, pg_conn, sql_query,
};
// ── Pg-backed contact projection store ───────────────────────────────────
// Durable backing for the holder↔peer `ContactStore`. Mirrors the
// `MemoryContactStore` query shape onto the `contacts` table. Column order
// matches `state::ContactRecord`.
pub struct PgContactStore {
    pub pool: PgPool,
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
    request_event_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    response_event_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    tombstone_event_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_service_id: Option<String>,
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
            request_event_ref: row.request_event_ref,
            response_event_ref: row.response_event_ref,
            tombstone_event_ref: row.tombstone_event_ref,
            message: row.message,
            peer_service_id: row.peer_service_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
const CONTACT_COLUMNS: &str = "requester_id AS requester, target_id AS target, scope, status, request_event_ref, response_event_ref, tombstone_event_ref, message, peer_service_id AS peer_service_id, created_at, updated_at";
#[async_trait]
impl ContactStore for PgContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(ContactRecord::from))
    }

    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 AND target_id = $2 AND scope = $3"
        ))
        .bind::<Text, _>(requester)
        .bind::<Text, _>(target)
        .bind::<Text, _>(scope)
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(ContactRecord::from))
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, scope, status, request_event_ref, response_event_ref, tombstone_event_ref, message, peer_service_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (requester_id, target_id, scope) DO UPDATE SET \
                status = EXCLUDED.status, \
                request_event_ref = EXCLUDED.request_event_ref, \
                response_event_ref = EXCLUDED.response_event_ref, \
                tombstone_event_ref = EXCLUDED.tombstone_event_ref, \
                message = EXCLUDED.message, \
                peer_service_id = EXCLUDED.peer_service_id, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Text>, _>(record.request_event_ref.as_deref())
        .bind::<Nullable<Text>, _>(record.response_event_ref.as_deref())
        .bind::<Nullable<Text>, _>(record.tombstone_event_ref.as_deref())
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_id.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 OR target_id = $1 \
             ORDER BY created_at ASC, scope ASC"
        ))
        .bind::<Text, _>(actor)
        .get_results::<ContactRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(ContactRecord::from).collect())
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM contacts WHERE requester_id = $1 AND target_id = $2")
            .bind::<Text, _>(requester)
            .bind::<Text, _>(target)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
// ── Pg-backed invite-receive policy store ────────────────────────────────
// Durable backing for per-subject `invite_receive_policy` overrides. The full
// `InviteReceivePolicy` is persisted as JSONB; `denied_subjects`
// is duplicated into a TEXT[] column for cheap hard-block lookups.
pub struct PgInviteReceivePolicyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct InviteReceivePolicyRow {
    #[diesel(sql_type = Text)]
    subject_id: String,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}
impl InviteReceivePolicyRow {
    fn into_pair(
        self,
    ) -> PersistenceResult<(
        String,
        arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    )> {
        let policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy =
            serde_json::from_value(self.policy_payload)
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
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT id AS subject_id, policy_payload FROM invite_receive_policies WHERE id = $1",
        )
        .bind::<Text, _>(subject_id)
        .get_result::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| row.into_pair().map(|(_, policy)| policy))
            .transpose()
    }

    async fn put(
        &self,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()> {
        let subject_id = policy.subject_id.as_str().to_owned();
        let payload = serde_json::to_value(policy).map_err(|error| {
            PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
        })?;
        let denied_subjects = policy
            .denied_subjects
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO invite_receive_policies \
             (id, policy_payload, denied_subjects, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                policy_payload = EXCLUDED.policy_payload, \
                denied_subjects = EXCLUDED.denied_subjects, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&subject_id)
        .bind::<Jsonb, _>(&payload)
        .bind::<Array<Text>, _>(&denied_subjects)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            String,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows =
            sql_query("SELECT id AS subject_id, policy_payload FROM invite_receive_policies")
                .get_results::<InviteReceivePolicyRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
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
pub struct PgConsentCellStore {
    pub pool: PgPool,
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
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells \
             WHERE holder_id = $1 AND peer_id = $2 AND scope = $3"
        ))
        .bind::<Text, _>(holder)
        .bind::<Text, _>(peer)
        .bind::<Text, _>(scope)
        .get_result::<ConsentCellRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
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
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!("SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells"))
            .get_results::<ConsentCellRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(ConsentCellRow::into_pair).collect())
    }
}
// ── Pg-backed direct-conversation binding store ──────────────────────────
// Durable backing for the DM binding projection. `participants_key` is the
// sorted, NUL-joined participant pair (the in-memory map key); the remaining
// columns mirror `state::DirectConversationBindingRecord`.
pub struct PgDirectConversationBindingStore {
    pub pool: PgPool,
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
    #[diesel(sql_type = Nullable<Jsonb>)]
    authoring_context: Option<Value>,
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
                authoring_context: self.authoring_context,
                created_at: self.created_at,
                updated_at: self.updated_at,
            },
        )
    }
}
const DIRECT_BINDING_COLUMNS: &str = "participants_key, participants_unordered, realm_id, \
     main_strand_id, binding_event_ref, state, authoring_context, created_at, updated_at";
#[async_trait]
impl DirectConversationBindingStore for PgDirectConversationBindingStore {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {DIRECT_BINDING_COLUMNS} FROM direct_conversation_bindings \
             WHERE participants_key = $1"
        ))
        .bind::<Text, _>(participants_key)
        .get_result::<DirectConversationBindingRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(|row| row.into_pair().1))
    }

    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO direct_conversation_bindings \
             (participants_key, participants_unordered, realm_id, main_strand_id, \
              binding_event_ref, state, authoring_context, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (participants_key) DO UPDATE SET \
                participants_unordered = EXCLUDED.participants_unordered, \
                realm_id = EXCLUDED.realm_id, \
                main_strand_id = EXCLUDED.main_strand_id, \
                binding_event_ref = EXCLUDED.binding_event_ref, \
                state = EXCLUDED.state, \
                authoring_context = EXCLUDED.authoring_context, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(participants_key)
        .bind::<Array<Text>, _>(&record.participants_unordered)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.realm_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.main_strand_id))
        .bind::<Text, _>(&record.binding_event_ref)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(&record.authoring_context)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, participants_key: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM direct_conversation_bindings WHERE participants_key = $1")
            .bind::<Text, _>(participants_key)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {DIRECT_BINDING_COLUMNS} FROM direct_conversation_bindings"
        ))
        .get_results::<DirectConversationBindingRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows
            .into_iter()
            .map(DirectConversationBindingRow::into_pair)
            .collect())
    }
}
