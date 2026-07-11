use super::*;

/// AKP-0010 — agent participation policy persistence. Controller
/// selections (`ak.agent.participation.v1`) and the governance ceiling
/// projection are stored as JSON records mirroring the
/// `arkret_core::AgentParticipation*` wire shape (keys:
/// agent_id, scope, scope_kind, scope_key, realm_id, reply,
/// accept_third_party_mention, act_on_behalf).
#[async_trait]
pub trait AgentParticipationStore: Send + Sync {
    /// Upsert a controller selection keyed by (agent_id, scope_key).
    async fn put_selection(&self, record: Value) -> PersistenceResult<()>;
    /// All selections for one agent.
    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>>;
    /// Ceiling rows whose scope_key is in `scope_keys`.
    async fn ceilings_for_scope_keys(&self, scope_keys: &[String])
    -> PersistenceResult<Vec<Value>>;
    /// Upsert a governance ceiling row keyed by scope_key.
    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()>;
}

fn agent_participation_record_key(record: &Value) -> (Option<String>, Option<String>) {
    (
        record
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        record
            .get("scope_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    )
}

#[derive(Default)]
pub(crate) struct MemoryAgentParticipationStore {
    selections: Mutex<Vec<Value>>,
    ceilings: Mutex<Vec<Value>>,
}

impl MemoryAgentParticipationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentParticipationStore for MemoryAgentParticipationStore {
    async fn put_selection(&self, record: Value) -> PersistenceResult<()> {
        let target = agent_participation_record_key(&record);
        let mut guard = self.selections.lock();
        guard.retain(|existing| agent_participation_record_key(existing) != target);
        guard.push(record);
        Ok(())
    }

    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .selections
            .lock()
            .iter()
            .filter(|row| row.get("agent_id").and_then(Value::as_str) == Some(agent_id))
            .cloned()
            .collect())
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .ceilings
            .lock()
            .iter()
            .filter(|row| {
                row.get("scope_key")
                    .and_then(Value::as_str)
                    .map(|key| scope_keys.iter().any(|candidate| candidate == key))
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()> {
        let key = record
            .get("scope_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut guard = self.ceilings.lock();
        guard.retain(|existing| {
            existing
                .get("scope_key")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                != key
        });
        guard.push(record);
        Ok(())
    }
}

#[derive(QueryableByName)]
struct AgentParticipationRow {
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    scope_kind: String,
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Jsonb)]
    scope: Value,
    #[diesel(sql_type = Bool)]
    reply: bool,
    #[diesel(sql_type = Bool)]
    accept_third_party_mention: bool,
    #[diesel(sql_type = Bool)]
    act_on_behalf: bool,
}

impl From<AgentParticipationRow> for Value {
    fn from(row: AgentParticipationRow) -> Self {
        serde_json::json!({
            "agent_id": row.agent_id,
            "scope_kind": row.scope_kind,
            "scope_key": row.scope_key,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "scope": row.scope,
            "reply": row.reply,
            "accept_third_party_mention": row.accept_third_party_mention,
            "act_on_behalf": row.act_on_behalf,
        })
    }
}

#[derive(QueryableByName)]
struct AgentParticipationCeilingRow {
    #[diesel(sql_type = Text)]
    scope_kind: String,
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Bool)]
    reply: bool,
    #[diesel(sql_type = Bool)]
    accept_third_party_mention: bool,
    #[diesel(sql_type = Bool)]
    act_on_behalf: bool,
}

impl From<AgentParticipationCeilingRow> for Value {
    fn from(row: AgentParticipationCeilingRow) -> Self {
        serde_json::json!({
            "scope_kind": row.scope_kind,
            "scope_key": row.scope_key,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "reply": row.reply,
            "accept_third_party_mention": row.accept_third_party_mention,
            "act_on_behalf": row.act_on_behalf,
        })
    }
}

pub(crate) struct PgAgentParticipationStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AgentParticipationStore for PgAgentParticipationStore {
    async fn put_selection(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!("agent participation record missing {key}"))
                })
        };
        let get_bool = |key: &str| record.get(key).and_then(Value::as_bool).unwrap_or(false);
        let agent_id = get_str("agent_id")?;
        let scope_kind = get_str("scope_kind")?;
        let scope_key = get_str("scope_key")?;
        let realm_id = get_str("realm_id")?;
        let scope = record.get("scope").cloned().unwrap_or(Value::Null);
        sql_query(
            "INSERT INTO agent_participation \
             (id, agent_id, scope_kind, scope_key, realm_id, scope, reply, \
              accept_third_party_mention, act_on_behalf, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (agent_id, scope_key) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             scope = EXCLUDED.scope, reply = EXCLUDED.reply, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW()",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&agent_id)
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&realm_id))
        .bind::<Jsonb, _>(&scope)
        .bind::<Bool, _>(get_bool("reply"))
        .bind::<Bool, _>(get_bool("accept_third_party_mention"))
        .bind::<Bool, _>(get_bool("act_on_behalf"))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT agent_id, scope_kind, scope_key, realm_id, scope, reply, \
             accept_third_party_mention, act_on_behalf FROM agent_participation \
             WHERE agent_id = $1 ORDER BY scope_key",
        )
        .bind::<Text, _>(agent_id)
        .load::<AgentParticipationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        if scope_keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT scope_kind, id AS scope_key, realm_id, reply, accept_third_party_mention, \
             act_on_behalf FROM agent_participation_ceiling WHERE id = ANY($1) \
             ORDER BY id",
        )
        .bind::<Array<Text>, _>(scope_keys.to_vec())
        .load::<AgentParticipationCeilingRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!(
                        "agent participation ceiling record missing {key}"
                    ))
                })
        };
        let get_bool = |key: &str| record.get(key).and_then(Value::as_bool).unwrap_or(false);
        let scope_kind = get_str("scope_kind")?;
        let scope_key = get_str("scope_key")?;
        let realm_id = get_str("realm_id")?;
        sql_query(
            "INSERT INTO agent_participation_ceiling \
             (scope_kind, id, realm_id, reply, accept_third_party_mention, \
              act_on_behalf, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             reply = EXCLUDED.reply, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW()",
        )
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&realm_id))
        .bind::<Bool, _>(get_bool("reply"))
        .bind::<Bool, _>(get_bool("accept_third_party_mention"))
        .bind::<Bool, _>(get_bool("act_on_behalf"))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

/// AKP-0008 — native personal agent principal persistence (provision /
/// list / get / lifecycle). JSON Value records carry the soland-internal
/// agent principal columns: id, controller_id,
/// display_name, agent_slug, avatar_blob_ref, state, created_at, updated_at. The wire boundary
/// projects these into the spec `agent_projection` (dropping the internal
/// columns) — see `routing::identity::agents::agent_projection_from_record`.
#[async_trait]
pub trait AgentStore: Send + Sync {
    async fn put(&self, record: Value) -> PersistenceResult<()>;
    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<Value>>;
    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<Value>>;
    async fn list_for_controller(&self, controller_id: &str) -> PersistenceResult<Vec<Value>>;
    async fn set_state(
        &self,
        agent_id: &str,
        state: &str,
        changed_at: &str,
    ) -> PersistenceResult<bool>;
}

#[derive(Default)]
pub(crate) struct MemoryAgentStore {
    data: Mutex<std::collections::BTreeMap<String, Value>>,
}

impl MemoryAgentStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentStore for MemoryAgentStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let Some(id) = record
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return Err(PersistenceError::Internal(
                "agent record missing agent_id".to_owned(),
            ));
        };
        self.data.lock().insert(id, record);
        Ok(())
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.data.lock().get(agent_id).cloned())
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .values()
            .find(|record| {
                record.get("pairing_request_id").and_then(Value::as_str) == Some(pairing_request_id)
            })
            .cloned())
    }

    async fn list_for_controller(&self, controller_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .values()
            .filter(|r| r.get("controller_id").and_then(Value::as_str) == Some(controller_id))
            .cloned()
            .collect())
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: &str,
        changed_at: &str,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        if let Some(record) = guard.get_mut(agent_id) {
            if let Some(obj) = record.as_object_mut() {
                obj.insert("state".to_owned(), Value::String(state.to_owned()));
                obj.insert(
                    "updated_at".to_owned(),
                    Value::String(changed_at.to_owned()),
                );
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(QueryableByName)]
struct AgentPrincipalRow {
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    controller_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    agent_slug: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    avatar_blob_ref: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    requested_scope: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    accountability: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    self_realm_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    provision_event_refs: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    pairing_request_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pairing_code: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pairing_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    approval_request_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    runtime_key_request: Option<Value>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    approval_requested_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    authorized_event_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    authorized_verification_method: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    authorized_public_key_digest: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

const AGENT_COLUMNS: &str = "id AS agent_id, controller_id, display_name, \
     agent_slug, avatar_blob_ref, state, requested_scope, accountability, self_realm_id, provision_event_refs, \
     pairing_request_id, pairing_code, pairing_expires_at, approval_request_id, \
     runtime_key_request, approval_requested_at, authorized_event_ref, \
     authorized_verification_method, authorized_public_key_digest, created_at, updated_at";

impl From<AgentPrincipalRow> for Value {
    fn from(row: AgentPrincipalRow) -> Self {
        serde_json::json!({
            "agent_id": row.agent_id,
            "controller_id": row.controller_id,
            "display_name": row.display_name,
            "agent_slug": row.agent_slug,
            "avatar_blob_ref": row.avatar_blob_ref,
            "state": row.state,
            "requested_scope": row.requested_scope,
            "accountability": row.accountability,
            "self_realm_id": row.self_realm_id,
            "provision_event_refs": row.provision_event_refs,
            "pairing_request_id": row.pairing_request_id,
            "pairing_code": row.pairing_code,
            "pairing_expires_at": row.pairing_expires_at
                .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            "approval_request_id": row.approval_request_id,
            "runtime_key_request": row.runtime_key_request,
            "approval_requested_at": row.approval_requested_at
                .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            "authorized_event_ref": row.authorized_event_ref,
            "authorized_verification_method": row.authorized_verification_method,
            "authorized_public_key_digest": row.authorized_public_key_digest,
            "created_at": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "updated_at": row.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
    }
}

pub(crate) struct PgAgentStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AgentStore for PgAgentStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| PersistenceError::Internal(format!("agent record missing {key}")))
        };
        let agent_id = get_str("agent_id")?;
        let controller_id = get_str("controller_id")?;
        let display_name = record
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let agent_slug = record
            .get("agent_slug")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let avatar_blob_ref = record
            .get("avatar_blob_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let state = record
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("active")
            .to_owned();
        let requested_scope = record
            .get("requested_scope")
            .cloned()
            .filter(|value| !value.is_null());
        let accountability = record
            .get("accountability")
            .cloned()
            .filter(|value| !value.is_null());
        let self_realm_id = record
            .get("self_realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let provision_event_refs = record
            .get("provision_event_refs")
            .cloned()
            .filter(|value| !value.is_null());
        let pairing_request_id = record
            .get("pairing_request_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let pairing_code = record
            .get("pairing_code")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let pairing_expires_at = record
            .get("pairing_expires_at")
            .and_then(Value::as_str)
            .map(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
                    .map_err(|err| {
                        PersistenceError::Internal(format!(
                            "agent record pairing_expires_at invalid: {err}"
                        ))
                    })
            })
            .transpose()?;
        let approval_request_id = record
            .get("approval_request_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let runtime_key_request = record
            .get("runtime_key_request")
            .cloned()
            .filter(|value| !value.is_null());
        let approval_requested_at = record
            .get("approval_requested_at")
            .and_then(Value::as_str)
            .map(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
                    .map_err(|err| {
                        PersistenceError::Internal(format!(
                            "agent record approval_requested_at invalid: {err}"
                        ))
                    })
            })
            .transpose()?;
        let authorized_event_ref = record
            .get("authorized_event_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let authorized_verification_method = record
            .get("authorized_verification_method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let authorized_public_key_digest = record
            .get("authorized_public_key_digest")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        sql_query(
            "INSERT INTO agent_principals \
             (id, controller_id, display_name, agent_slug, avatar_blob_ref, state, requested_scope, \
              accountability, self_realm_id, provision_event_refs, pairing_request_id, \
              pairing_code, pairing_expires_at, approval_request_id, runtime_key_request, \
              approval_requested_at, authorized_event_ref, authorized_verification_method, \
              authorized_public_key_digest, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW(), NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
             controller_id = EXCLUDED.controller_id, \
             display_name = EXCLUDED.display_name, agent_slug = EXCLUDED.agent_slug, \
             avatar_blob_ref = EXCLUDED.avatar_blob_ref, \
             state = EXCLUDED.state, requested_scope = EXCLUDED.requested_scope, \
             accountability = EXCLUDED.accountability, self_realm_id = EXCLUDED.self_realm_id, \
             provision_event_refs = EXCLUDED.provision_event_refs, \
             pairing_request_id = EXCLUDED.pairing_request_id, pairing_code = EXCLUDED.pairing_code, \
             pairing_expires_at = EXCLUDED.pairing_expires_at, \
             approval_request_id = EXCLUDED.approval_request_id, \
             runtime_key_request = EXCLUDED.runtime_key_request, \
             approval_requested_at = EXCLUDED.approval_requested_at, \
             authorized_event_ref = EXCLUDED.authorized_event_ref, \
             authorized_verification_method = EXCLUDED.authorized_verification_method, \
             authorized_public_key_digest = EXCLUDED.authorized_public_key_digest, updated_at = NOW()",
        )
        .bind::<Text, _>(&agent_id)
        .bind::<Text, _>(&controller_id)
        .bind::<Nullable<Text>, _>(&display_name)
        .bind::<Nullable<Text>, _>(&agent_slug)
        .bind::<Nullable<Text>, _>(&avatar_blob_ref)
        .bind::<Text, _>(&state)
        .bind::<Nullable<Jsonb>, _>(&requested_scope)
        .bind::<Nullable<Jsonb>, _>(&accountability)
        .bind::<Nullable<Text>, _>(&self_realm_id)
        .bind::<Nullable<Jsonb>, _>(&provision_event_refs)
        .bind::<Nullable<Text>, _>(&pairing_request_id)
        .bind::<Nullable<Text>, _>(&pairing_code)
        .bind::<Nullable<Timestamptz>, _>(&pairing_expires_at)
        .bind::<Nullable<Text>, _>(&approval_request_id)
        .bind::<Nullable<Jsonb>, _>(&runtime_key_request)
        .bind::<Nullable<Timestamptz>, _>(&approval_requested_at)
        .bind::<Nullable<Text>, _>(&authorized_event_ref)
        .bind::<Nullable<Text>, _>(&authorized_verification_method)
        .bind::<Nullable<Text>, _>(&authorized_public_key_digest)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {AGENT_COLUMNS} FROM agent_principals WHERE id = $1"
        ))
        .bind::<Text, _>(agent_id)
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Value::from))
        .map_err(PersistenceError::from)
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {AGENT_COLUMNS} FROM agent_principals WHERE pairing_request_id = $1"
        ))
        .bind::<Text, _>(pairing_request_id)
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Value::from))
        .map_err(PersistenceError::from)
    }

    async fn list_for_controller(&self, controller_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {AGENT_COLUMNS} FROM agent_principals WHERE controller_id = $1 ORDER BY created_at"
        ))
        .bind::<Text, _>(controller_id)
        .load::<AgentPrincipalRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: &str,
        _changed_at: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let updated = sql_query(
            "UPDATE agent_principals SET state = $2, state_changed_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind::<Text, _>(agent_id)
        .bind::<Text, _>(state)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(updated > 0)
    }
}
