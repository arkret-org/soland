use super::{
    AgentSidecarContextRecord, AgentSidecarRecord, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SidecarStore,
    SqlUuid, Text, Timestamptz, Value, async_trait, ids, pg_conn, sql_query,
};

pub struct PgSidecarStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct SidecarRow {
    #[diesel(sql_type = SqlUuid)]
    id: uuid::Uuid,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    controller_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SidecarRow> for AgentSidecarRecord {
    fn from(row: SidecarRow) -> Self {
        Self {
            sidecar_id: ids::format_typed_uuid("sidecar", &row.id),
            realm_id: row.realm_id,
            controller_id: row.controller_id,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(QueryableByName)]
struct SidecarContextRow {
    #[diesel(sql_type = SqlUuid)]
    sidecar_id: uuid::Uuid,
    #[diesel(sql_type = Text)]
    normalized_context_ref_digest: String,
    #[diesel(sql_type = Jsonb)]
    normalized_context_ref: Value,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    version: i64,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    predecessor_event_ref: Option<uuid::Uuid>,
    #[diesel(sql_type = SqlUuid)]
    attach_event_ref: uuid::Uuid,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<SidecarContextRow> for AgentSidecarContextRecord {
    fn from(row: SidecarContextRow) -> Self {
        Self {
            sidecar_id: ids::format_typed_uuid("sidecar", &row.sidecar_id),
            normalized_context_ref_digest: row.normalized_context_ref_digest,
            normalized_context_ref: row.normalized_context_ref,
            version: row.version,
            predecessor_event_ref: row
                .predecessor_event_ref
                .map(|id| ids::format_typed_uuid("event", &id)),
            attach_event_ref: ids::format_typed_uuid("event", &row.attach_event_ref),
            created_at: row.created_at,
        }
    }
}

const SIDECAR_SELECT: &str = "SELECT id, realm_id, controller_id, state, state_changed_at, created_at, updated_at FROM agent_sidecars";
const CONTEXT_SELECT: &str = "SELECT sidecar_id, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at FROM agent_sidecar_contexts";

#[async_trait]
impl SidecarStore for PgSidecarStore {
    async fn insert_or_get(
        &self,
        record: AgentSidecarRecord,
    ) -> PersistenceResult<AgentSidecarRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        let id = ids::typed_uuid_part_expect_internal(&record.sidecar_id);
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "WITH inserted AS (\
             INSERT INTO agent_sidecars (id, realm_id, controller_id, state, state_changed_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (realm_id, controller_id) DO NOTHING \
             RETURNING id, realm_id, controller_id, state, state_changed_at, created_at, updated_at) \
             SELECT * FROM inserted UNION ALL \
             SELECT id, realm_id, controller_id, state, state_changed_at, created_at, updated_at \
             FROM agent_sidecars WHERE realm_id=$2 AND controller_id=$3 LIMIT 1",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.controller_id)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .get_result::<SidecarRow>(&mut *conn)
        .await
        .map(AgentSidecarRecord::from)
        .map_err(PersistenceError::database)
    }

    async fn get(&self, sidecar_id: &str) -> PersistenceResult<Option<AgentSidecarRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let id = ids::typed_uuid_part_expect_internal(sidecar_id);
        sql_query(format!("{SIDECAR_SELECT} WHERE id=$1"))
            .bind::<SqlUuid, _>(id)
            .get_result::<SidecarRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(AgentSidecarRecord::from))
            .map_err(PersistenceError::database)
    }

    async fn get_for_realm_controller(
        &self,
        realm_id: &str,
        controller_id: &str,
    ) -> PersistenceResult<Option<AgentSidecarRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "{SIDECAR_SELECT} WHERE realm_id=$1 AND controller_id=$2"
        ))
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(controller_id)
        .get_result::<SidecarRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AgentSidecarRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn list_for_controller(
        &self,
        controller_id: &str,
        realm_id: Option<&str>,
    ) -> PersistenceResult<Vec<AgentSidecarRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "{SIDECAR_SELECT} WHERE controller_id=$1 AND ($2 IS NULL OR realm_id=$2) ORDER BY created_at,id"
        ))
        .bind::<Text, _>(controller_id)
            .bind::<Nullable<Text>, _>(realm_id)
        .load::<SidecarRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AgentSidecarRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<AgentSidecarRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!("{SIDECAR_SELECT} ORDER BY created_at,id"))
            .load::<SidecarRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(AgentSidecarRecord::from).collect())
            .map_err(PersistenceError::database)
    }

    async fn insert_or_get_context(
        &self,
        record: AgentSidecarContextRecord,
    ) -> PersistenceResult<AgentSidecarContextRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        let sidecar_id = ids::typed_uuid_part_expect_internal(&record.sidecar_id);
        let predecessor_event_ref = record
            .predecessor_event_ref
            .as_deref()
            .map(ids::typed_uuid_part_expect_internal);
        let attach_event_ref = ids::typed_uuid_part_expect_internal(&record.attach_event_ref);
        sql_query(
            "WITH inserted AS (\
             INSERT INTO agent_sidecar_contexts (sidecar_id, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (sidecar_id, normalized_context_ref_digest, version) DO NOTHING \
             RETURNING sidecar_id, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at) \
             SELECT * FROM inserted UNION ALL \
             SELECT sidecar_id, normalized_context_ref_digest, normalized_context_ref, version, predecessor_event_ref, attach_event_ref, created_at \
             FROM agent_sidecar_contexts WHERE sidecar_id=$1 AND normalized_context_ref_digest=$2 AND version=$4 LIMIT 1",
        )
        .bind::<SqlUuid, _>(sidecar_id)
        .bind::<Text, _>(&record.normalized_context_ref_digest)
        .bind::<Jsonb, _>(&record.normalized_context_ref)
        .bind::<diesel::sql_types::BigInt, _>(record.version)
        .bind::<Nullable<SqlUuid>, _>(predecessor_event_ref)
        .bind::<SqlUuid, _>(attach_event_ref)
        .bind::<Timestamptz, _>(record.created_at)
        .get_result::<SidecarContextRow>(&mut *conn)
        .await
        .map(AgentSidecarContextRecord::from)
        .map_err(PersistenceError::database)
    }

    async fn get_context(
        &self,
        sidecar_id: &str,
        normalized_context_ref_digest: &str,
    ) -> PersistenceResult<Option<AgentSidecarContextRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let sidecar_id = ids::typed_uuid_part_expect_internal(sidecar_id);
        sql_query(format!(
            "{CONTEXT_SELECT} WHERE sidecar_id=$1 AND normalized_context_ref_digest=$2 ORDER BY version DESC LIMIT 1"
        ))
        .bind::<SqlUuid, _>(sidecar_id)
        .bind::<Text, _>(normalized_context_ref_digest)
        .get_result::<SidecarContextRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AgentSidecarContextRecord::from))
        .map_err(PersistenceError::database)
    }
}
