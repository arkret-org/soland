use diesel::dsl::case_when;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, PgExpressionMethods, QueryDsl, SelectableHelper,
};
use soland_data::schema::agent_principals;

use super::*;

/// AKP-0010 — agent participation policy persistence. Controller
/// selections (`ak.agent.participation.v1`) and the governance ceiling
/// projection are stored as JSON records mirroring the
/// `arkret_sdk::AgentParticipation*` wire shape (keys:
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
/// list / get / lifecycle). The typed persistence model keeps database column
/// names, nullability, UUIDs, and timestamps checked at compile time. The wire
/// boundary projects it into `agent_projection`, dropping internal columns —
/// see `routing::identity::agents::agent_projection_from_record`.
#[derive(Clone, Debug)]
pub struct AgentRuntimeActivation {
    pub agent_id: String,
    pub approval_request_id: String,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: String,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    pub authorized_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct AgentRuntimeApprovalWrite {
    pub agent_id: String,
    pub pairing_request_id: String,
    pub approval_request_id: String,
    pub approval_notification_id: String,
    pub approval_requested_at: chrono::DateTime<chrono::Utc>,
    pub controller_account_id: String,
    pub recipient_service_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request: Value,
}

#[async_trait]
pub trait AgentStore: Send + Sync {
    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()>;
    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>>;
    async fn set_state(
        &self,
        agent_id: &str,
        state: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool>;
    /// Clear the retained approval/notification correlation only after the
    /// terminal account-notification delta is durable. Retaining it across the
    /// activation write makes a crash between those writes reconcilable.
    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool>;
    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
}

#[derive(Default)]
pub(crate) struct MemoryAgentStore {
    data: Mutex<std::collections::BTreeMap<String, AgentPrincipalRecord>>,
}

impl MemoryAgentStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentStore for MemoryAgentStore {
    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()> {
        let id = record.id.clone();
        let mut data = self.data.lock();
        if let Some(existing) = data.get(&id)
            && (existing.controller_id != record.controller_id
                || existing.principal_control_realm_id != record.principal_control_realm_id
                || existing.controller_authorization_ref != record.controller_authorization_ref)
        {
            return Err(PersistenceError::Conflict(format!(
                "Agent `{id}` controller/PCR authorization binding is immutable"
            )));
        }
        data.insert(id, record);
        Ok(())
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        Ok(self.data.lock().get(agent_id).cloned())
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .find(|record| record.pairing_request_id.as_deref() == Some(pairing_request_id))
            .cloned())
    }

    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .filter(|record| record.controller_id == controller_id)
            .cloned()
            .collect())
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        if let Some(record) = guard.get_mut(agent_id) {
            record.state = state.to_owned();
            record.state_changed_at = Some(changed_at);
            record.updated_at = changed_at;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(&activation.agent_id) else {
            return Ok(false);
        };
        if record.approval_request_id.as_deref() != Some(&activation.approval_request_id)
            || !matches!(
                record.state.as_str(),
                "pending_runtime_key" | "active" | "paused"
            )
            || record.runtime_key_binding_digest.as_deref()
                != Some(&activation.runtime_key_binding_digest)
            || record.pairing_request_id.as_deref() != Some(&activation.pairing_request_id)
        {
            return Ok(false);
        }
        if record.state != "paused" {
            record.state = "active".to_owned();
        }
        record.updated_at = activation.authorized_at;
        record.authorized_event_ref = Some(activation.authorized_event_ref.clone());
        record.authorized_verification_method =
            Some(activation.authorized_verification_method.clone());
        record.authorized_public_key_digest = Some(activation.authorized_public_key_digest.clone());
        record.paired_pairing_request_id = Some(activation.pairing_request_id.clone());
        record.paired_request_digest = Some(activation.paired_request_digest.clone());
        // Keep the approval and notification ids until the terminal account
        // delta is durable. They are internal correlation state and are not
        // exposed for an active/paused Agent. A retry can therefore finish the
        // notification cleanup after a crash without replaying activation.
        record.runtime_key_request = None;
        record.approval_requested_at = None;
        record.runtime_key_binding_digest = None;
        record.runtime_public_key_digest = None;
        record.runtime_attestation_digest = None;
        Ok(true)
    }

    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(agent_id) else {
            return Ok(false);
        };
        if record.approval_request_id.as_deref() != Some(approval_request_id)
            || record.authorized_event_ref.is_none()
        {
            return Ok(false);
        }
        record.approval_request_id = None;
        record.approval_notification_id = None;
        record.updated_at = Utc::now();
        Ok(true)
    }

    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut guard = self.data.lock();
        let Some(record) = guard.get_mut(&write.agent_id) else {
            return Ok(None);
        };
        let pairing_handle_was_consumed =
            record.paired_pairing_request_id.as_deref() == Some(&write.pairing_request_id);
        if record.pairing_request_id.as_deref() != Some(&write.pairing_request_id)
            || pairing_handle_was_consumed
            || !matches!(
                record.state.as_str(),
                "pending_runtime_key" | "active" | "paused"
            )
            || record
                .runtime_key_binding_digest
                .as_deref()
                .is_some_and(|digest| digest != write.runtime_key_binding_digest)
        {
            return Ok(None);
        }
        record
            .approval_request_id
            .get_or_insert_with(|| write.approval_request_id.clone());
        record.approval_notification_id.get_or_insert_with(|| {
            ids::typed_uuid_part_expect_internal(&write.approval_notification_id)
        });
        record
            .approval_requested_at
            .get_or_insert(write.approval_requested_at);
        record.controller_account_id = Some(ids::typed_uuid_part_expect_internal(
            &write.controller_account_id,
        ));
        record.recipient_service_id = Some(write.recipient_service_id.clone());
        record.runtime_key_binding_digest = Some(write.runtime_key_binding_digest.clone());
        record.runtime_public_key_digest = Some(write.runtime_public_key_digest.clone());
        record.runtime_attestation_digest = Some(write.runtime_attestation_digest.clone());
        record.runtime_key_request = Some(write.runtime_key_request.clone());
        record.updated_at = Utc::now();
        Ok(Some(record.clone()))
    }
}

pub(crate) struct PgAgentStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AgentStore for PgAgentStore {
    async fn put(&self, principal: AgentPrincipalRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let agent_id = principal.id.clone();
        let upsert = diesel::insert_into(agent_principals::table)
            .values(&principal)
            .on_conflict(agent_principals::id)
            .do_update()
            .set(&principal);
        let affected = diesel::query_dsl::methods::FilterDsl::filter(
            upsert,
            agent_principals::controller_id
                .eq(&principal.controller_id)
                .and(
                    agent_principals::principal_control_realm_id
                        .eq(&principal.principal_control_realm_id),
                )
                .and(
                    agent_principals::controller_authorization_ref
                        .eq(&principal.controller_authorization_ref),
                ),
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        if affected == 1 {
            Ok(())
        } else {
            Err(PersistenceError::Conflict(format!(
                "Agent `{agent_id}` controller/PCR authorization binding is immutable"
            )))
        }
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        agent_principals::table
            .find(agent_id)
            .select(AgentPrincipalRecord::as_select())
            .first::<AgentPrincipalRecord>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        agent_principals::table
            .filter(agent_principals::pairing_request_id.eq(pairing_request_id))
            .select(AgentPrincipalRecord::as_select())
            .first::<AgentPrincipalRecord>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)
    }

    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        agent_principals::table
            .filter(agent_principals::controller_id.eq(controller_id))
            .order(agent_principals::created_at.asc())
            .select(AgentPrincipalRecord::as_select())
            .load::<AgentPrincipalRecord>(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let updated = diesel::update(agent_principals::table.find(agent_id))
            .set((
                agent_principals::state.eq(state),
                agent_principals::state_changed_at.eq(changed_at),
                agent_principals::updated_at.eq(changed_at),
            ))
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)?;
        Ok(updated > 0)
    }

    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&activation.agent_id))
                .filter(agent_principals::state.eq_any(["pending_runtime_key", "active", "paused"]))
                .filter(agent_principals::approval_request_id.eq(&activation.approval_request_id))
                .filter(
                    agent_principals::runtime_key_binding_digest
                        .eq(&activation.runtime_key_binding_digest),
                )
                .filter(agent_principals::pairing_request_id.eq(&activation.pairing_request_id)),
        )
        .set((
            agent_principals::state.eq(case_when::<_, _, Text>(
                agent_principals::state.eq("paused"),
                "paused",
            )
            .otherwise("active")),
            agent_principals::updated_at.eq(activation.authorized_at),
            agent_principals::authorized_event_ref.eq(&activation.authorized_event_ref),
            agent_principals::authorized_verification_method
                .eq(&activation.authorized_verification_method),
            agent_principals::authorized_public_key_digest
                .eq(&activation.authorized_public_key_digest),
            agent_principals::paired_pairing_request_id.eq(&activation.pairing_request_id),
            agent_principals::paired_request_digest.eq(&activation.paired_request_digest),
            agent_principals::runtime_key_request.eq(None::<Value>),
            agent_principals::approval_requested_at.eq(None::<chrono::DateTime<chrono::Utc>>),
            agent_principals::runtime_key_binding_digest.eq(None::<String>),
            agent_principals::runtime_public_key_digest.eq(None::<String>),
            agent_principals::runtime_attestation_digest.eq(None::<String>),
        ))
        .execute(&mut *conn)
        .await
        .map(|rows| rows == 1)
        .map_err(PersistenceError::from)
    }

    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(agent_id))
                .filter(agent_principals::approval_request_id.eq(approval_request_id))
                .filter(agent_principals::authorized_event_ref.is_not_null()),
        )
        .set((
            agent_principals::approval_request_id.eq(None::<String>),
            agent_principals::approval_notification_id.eq(None::<Uuid>),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .execute(&mut *conn)
        .await
        .map(|rows| rows == 1)
        .map_err(PersistenceError::from)
    }

    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let approval_notification_id =
            ids::typed_uuid_part_expect_internal(&write.approval_notification_id);
        let controller_account_id =
            ids::typed_uuid_part_expect_internal(&write.controller_account_id);
        diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&write.agent_id))
                .filter(agent_principals::state.eq_any(["pending_runtime_key", "active", "paused"]))
                .filter(agent_principals::pairing_request_id.eq(&write.pairing_request_id))
                .filter(
                    agent_principals::paired_pairing_request_id
                        .is_distinct_from(&write.pairing_request_id),
                )
                .filter(
                    agent_principals::runtime_key_binding_digest
                        .is_null()
                        .or(agent_principals::runtime_key_binding_digest
                            .eq(&write.runtime_key_binding_digest)),
                ),
        )
        .set((
            agent_principals::approval_request_id.eq(case_when::<_, _, Nullable<Text>>(
                agent_principals::approval_request_id.is_null(),
                Some(write.approval_request_id.as_str()),
            )
            .otherwise(agent_principals::approval_request_id)),
            agent_principals::approval_notification_id.eq(case_when::<_, _, Nullable<SqlUuid>>(
                agent_principals::approval_notification_id.is_null(),
                Some(approval_notification_id),
            )
            .otherwise(agent_principals::approval_notification_id)),
            agent_principals::approval_requested_at.eq(case_when::<_, _, Nullable<Timestamptz>>(
                agent_principals::approval_requested_at.is_null(),
                Some(write.approval_requested_at),
            )
            .otherwise(agent_principals::approval_requested_at)),
            agent_principals::controller_account_id.eq(controller_account_id),
            agent_principals::recipient_service_id.eq(&write.recipient_service_id),
            agent_principals::runtime_key_binding_digest.eq(&write.runtime_key_binding_digest),
            agent_principals::runtime_public_key_digest.eq(&write.runtime_public_key_digest),
            agent_principals::runtime_attestation_digest.eq(&write.runtime_attestation_digest),
            agent_principals::runtime_key_request.eq(&write.runtime_key_request),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .returning(AgentPrincipalRecord::as_returning())
        .get_result::<AgentPrincipalRecord>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)
    }
}
