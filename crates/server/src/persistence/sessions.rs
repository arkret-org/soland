use super::*;

/// Trait for session storage operations.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    async fn delete(&self, token: &str) -> PersistenceResult<()>;
    async fn cleanup_expired(&self) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>>;
}

// In-memory session store
pub(crate) struct MemorySessionStore {
    data: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
}

impl MemorySessionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock();
        Ok(data.get(token).cloned())
    }

    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(token);
        Ok(())
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}

pub(crate) struct PgSessionStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS token_hash, actor_id AS actor, device_id, audience, session_public_key, payload, expires_at, created_at, revoked_at \
             FROM sessions WHERE id = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SessionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let payload = encode_session_payload(record);
        sql_query(
            "INSERT INTO sessions (id, actor_id, device_id, audience, session_public_key, payload, expires_at, revoked_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (id) DO UPDATE SET actor_id = EXCLUDED.actor_id, device_id = EXCLUDED.device_id, \
             audience = EXCLUDED.audience, session_public_key = EXCLUDED.session_public_key, \
             payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at, revoked_at = EXCLUDED.revoked_at, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.token_hash)
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Text, _>(&record.audience)
        .bind::<Nullable<Text>, _>(record.session_public_key.as_deref())
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sessions WHERE id = $1")
            .bind::<Text, _>(token)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS token_hash, actor_id AS actor, device_id, audience, session_public_key, payload, expires_at, created_at, revoked_at \
             FROM sessions",
        )
        .load::<SessionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(SessionRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[derive(QueryableByName)]
struct SessionRow {
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Nullable<Text>)]
    session_public_key: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SessionRow> for SessionRecord {
    fn from(row: SessionRow) -> Self {
        Self {
            token_hash: row.token_hash,
            actor: row.actor,
            device_id: row.device_id,
            audience: row.audience,
            session_public_key: row.session_public_key,
            agent_session: decode_session_agent_payload(&row.payload),
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}

fn encode_session_payload(record: &SessionRecord) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(agent_session) = &record.agent_session
        && let Ok(value) = serde_json::to_value(agent_session)
    {
        payload.insert("agent_session".to_owned(), value);
    }
    Value::Object(payload)
}

fn decode_session_agent_payload(payload: &Value) -> Option<AgentSessionRecord> {
    payload
        .get("agent_session")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

#[cfg(test)]
mod tests {
    use arkret_sdk::FreshnessState;

    use super::*;

    #[test]
    fn session_payload_round_trips_agent_session() {
        let record = SessionRecord {
            token_hash: "grant".to_owned(),
            actor: "did:web:alice.example".to_owned(),
            device_id: "agent-session:grant".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            session_public_key: Some("{}".to_owned()),
            agent_session: Some(AgentSessionRecord {
                granted_scope: vec![
                    "ak.self.events.stream.subscribe".to_owned(),
                    "ak.self.events.query.scan".to_owned(),
                ],
                scope_details: serde_json::json!({
                    "agent_id": "did:web:agent.example",
                    "applet_id": "ak:applet:01904100-0000-7000-8000-000000000001"
                }),
                freshness_state: FreshnessState::Fresh,
            }),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };

        let payload = encode_session_payload(&record);
        let restored = decode_session_agent_payload(&payload).expect("agent session decodes");

        assert_eq!(restored.freshness_state, FreshnessState::Fresh);
        assert_eq!(
            restored.granted_scope,
            vec![
                "ak.self.events.stream.subscribe".to_owned(),
                "ak.self.events.query.scan".to_owned()
            ]
        );
        assert_eq!(
            restored.scope_details["applet_id"],
            "ak:applet:01904100-0000-7000-8000-000000000001"
        );
    }
}
