use diesel::dsl::case_when;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, PgExpressionMethods, QueryDsl, SelectableHelper,
};
use soland_storage::PendingAgentPairingCommitIntent;

use super::{
    AgentPairingCommitIntent, AgentParticipationStore, AgentPrincipalRecord, AgentPrincipalRow,
    AgentRuntimeActivation, AgentRuntimeApprovalWrite, AgentStore, Array, BigInt, Bool, Jsonb,
    Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, SqlUuid, Text, Timestamptz, Utc, Uuid, Value, async_trait, ids, pg_conn,
    sql_query,
};
use crate::schema::agent_principals;
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
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Bool)]
    reply_message: bool,
    #[diesel(sql_type = Bool)]
    reaction_add: bool,
    #[diesel(sql_type = Bool)]
    reaction_remove: bool,
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
            "version": row.version,
            "reply_message": row.reply_message,
            "reaction_add": row.reaction_add,
            "reaction_remove": row.reaction_remove,
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
    reply_message: bool,
    #[diesel(sql_type = Bool)]
    reaction_add: bool,
    #[diesel(sql_type = Bool)]
    reaction_remove: bool,
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
            "reply_message": row.reply_message,
            "reaction_add": row.reaction_add,
            "reaction_remove": row.reaction_remove,
            "accept_third_party_mention": row.accept_third_party_mention,
            "act_on_behalf": row.act_on_behalf,
        })
    }
}
pub struct PgAgentParticipationStore {
    pub pool: PgPool,
}
#[async_trait]
impl AgentParticipationStore for PgAgentParticipationStore {
    async fn compare_and_swap_selection(
        &self,
        record: Value,
        expected_version: u64,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        let accepted_version = expected_version.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("agent participation version overflow".to_owned())
        })?;
        let accepted_version = i64::try_from(accepted_version).map_err(|_| {
            PersistenceError::Internal(
                "agent participation version exceeds storage range".to_owned(),
            )
        })?;
        let expected_version = i64::try_from(expected_version).map_err(|_| {
            PersistenceError::Internal(
                "agent participation version exceeds storage range".to_owned(),
            )
        })?;
        if record.get("version").and_then(Value::as_i64) != Some(accepted_version) {
            return Err(PersistenceError::Internal(
                "agent participation record has invalid next version".to_owned(),
            ));
        }
        let agent_id = get_str("agent_id")?;
        let scope_kind = get_str("scope_kind")?;
        let scope_key = get_str("scope_key")?;
        let realm_id = get_str("realm_id")?;
        let scope = record.get("scope").cloned().unwrap_or(Value::Null);
        sql_query(
            "INSERT INTO agent_participation \
             (id, agent_id, scope_kind, scope_key, realm_id, scope, version, reply_message, \
               reaction_add, reaction_remove, accept_third_party_mention, act_on_behalf, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()) \
             ON CONFLICT (agent_id, scope_key) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             scope = EXCLUDED.scope, version = EXCLUDED.version, \
             reply_message = EXCLUDED.reply_message, reaction_add = EXCLUDED.reaction_add, \
             reaction_remove = EXCLUDED.reaction_remove, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW() \
             WHERE agent_participation.version = $13",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&agent_id)
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&realm_id))
        .bind::<Jsonb, _>(&scope)
        .bind::<BigInt, _>(accepted_version)
        .bind::<Bool, _>(get_bool("reply_message"))
        .bind::<Bool, _>(get_bool("reaction_add"))
        .bind::<Bool, _>(get_bool("reaction_remove"))
        .bind::<Bool, _>(get_bool("accept_third_party_mention"))
        .bind::<Bool, _>(get_bool("act_on_behalf"))
        .bind::<BigInt, _>(expected_version)
        .execute(&mut *conn)
        .await
        .map(|affected| affected == 1)
        .map_err(PersistenceError::database)
    }

    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT agent_id, scope_kind, scope_key, realm_id, scope, version, reply_message, \
             reaction_add, reaction_remove, accept_third_party_mention, act_on_behalf \
             FROM agent_participation \
             WHERE agent_id = $1 ORDER BY scope_key",
        )
        .bind::<Text, _>(agent_id)
        .load::<AgentParticipationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        if scope_keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT scope_kind, id AS scope_key, realm_id, reply_message, reaction_add, \
             reaction_remove, accept_third_party_mention, act_on_behalf \
             FROM agent_participation_ceiling WHERE id = ANY($1) \
             ORDER BY id",
        )
        .bind::<Array<Text>, _>(scope_keys.to_vec())
        .load::<AgentParticipationCeilingRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
             (scope_kind, id, realm_id, reply_message, reaction_add, reaction_remove, \
              accept_third_party_mention, act_on_behalf, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             reply_message = EXCLUDED.reply_message, reaction_add = EXCLUDED.reaction_add, \
             reaction_remove = EXCLUDED.reaction_remove, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW()",
        )
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&realm_id))
        .bind::<Bool, _>(get_bool("reply_message"))
        .bind::<Bool, _>(get_bool("reaction_add"))
        .bind::<Bool, _>(get_bool("reaction_remove"))
        .bind::<Bool, _>(get_bool("accept_third_party_mention"))
        .bind::<Bool, _>(get_bool("act_on_behalf"))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
pub struct PgAgentStore {
    pub pool: PgPool,
}
#[async_trait]
impl AgentStore for PgAgentStore {
    async fn put(&self, principal: AgentPrincipalRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let principal = AgentPrincipalRow::try_from(principal)?;
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
        .map_err(PersistenceError::database)?;
        if affected == 1 {
            Ok(())
        } else {
            Err(PersistenceError::Conflict(format!(
                "Agent `{agent_id}` controller/PCR authorization binding is immutable"
            )))
        }
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let record = agent_principals::table
            .find(agent_id)
            .select(AgentPrincipalRow::as_select())
            .first::<AgentPrincipalRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let record = agent_principals::table
            .filter(agent_principals::pairing_request_id.eq(pairing_request_id))
            .select(AgentPrincipalRow::as_select())
            .first::<AgentPrincipalRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let records = agent_principals::table
            .filter(agent_principals::controller_id.eq(controller_id))
            .order(agent_principals::created_at.asc())
            .select(AgentPrincipalRow::as_select())
            .load::<AgentPrincipalRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        records.into_iter().map(TryInto::try_into).collect()
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: arkret_models_collaboration::agent_operations::AgentLifecycleState,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let updated = diesel::update(agent_principals::table.find(agent_id))
            .set((
                agent_principals::state.eq(state.as_wire_str()),
                agent_principals::state_changed_at.eq(changed_at),
                agent_principals::updated_at.eq(changed_at),
            ))
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(updated > 0)
    }

    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let authorized_signing_key_binding =
            serde_json::to_value(&activation.authorized_signing_key_binding).map_err(|error| {
                PersistenceError::Internal(format!(
                    "encode typed Agent signing-key binding: {error}"
                ))
            })?;
        let pending_intent = serde_json::to_value(PendingAgentPairingCommitIntent {
            request_digest: activation.paired_request_digest.clone(),
            authorize_event_id: activation.authorized_event_ref.clone(),
            signing_key_binding: Some(activation.authorized_signing_key_binding.clone()),
        })
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "encode pending Agent pairing commit intent: {error}"
            ))
        })?;
        diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&activation.agent_id))
                .filter(agent_principals::state.eq_any(["active", "paused"]))
                .filter(
                    agent_principals::approval_request_id
                        .eq(activation.approval_request_id.as_str()),
                )
                .filter(
                    agent_principals::runtime_key_binding_digest
                        .eq(&activation.runtime_key_binding_digest),
                )
                .filter(
                    agent_principals::pairing_request_id.eq(activation.pairing_request_id.as_str()),
                )
                .filter(agent_principals::pending_pairing_commit_intent.eq(&pending_intent)),
        )
        .set((
            // Runtime key activation records the authorization; it is not a
            // lifecycle transition, so the lifecycle `state` is left untouched
            // (key-management.md §3.6.1). runtime_state derives to ready.
            agent_principals::updated_at.eq(activation.authorized_at),
            agent_principals::authorized_event_ref.eq(&activation.authorized_event_ref),
            agent_principals::authorized_verification_method
                .eq(&activation.authorized_verification_method),
            agent_principals::authorized_public_key_digest
                .eq(&activation.authorized_public_key_digest),
            agent_principals::authorized_signing_key_binding.eq(&authorized_signing_key_binding),
            agent_principals::paired_pairing_request_id.eq(activation.pairing_request_id.as_str()),
            agent_principals::paired_request_digest.eq(&activation.paired_request_digest),
            agent_principals::pending_pairing_commit_intent.eq(None::<Value>),
            agent_principals::runtime_key_request.eq(None::<Value>),
            agent_principals::approval_requested_at.eq(None::<chrono::DateTime<chrono::Utc>>),
            agent_principals::runtime_key_binding_digest.eq(None::<String>),
            agent_principals::runtime_public_key_digest.eq(None::<String>),
            agent_principals::runtime_attestation_digest.eq(None::<String>),
        ))
        .execute(&mut *conn)
        .await
        .map(|rows| rows == 1)
        .map_err(PersistenceError::database)
    }

    async fn put_pairing_commit_intent_if_compatible(
        &self,
        intent: &AgentPairingCommitIntent,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let intent_value = serde_json::to_value(PendingAgentPairingCommitIntent {
            request_digest: intent.request_digest.clone(),
            authorize_event_id: intent.authorize_event_id.clone(),
            signing_key_binding: Some(intent.signing_key_binding.clone()),
        })
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "encode pending Agent pairing commit intent: {error}"
            ))
        })?;
        let record = diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&intent.agent_id))
                .filter(agent_principals::state.eq_any(["active", "paused"]))
                .filter(
                    agent_principals::approval_request_id.eq(intent.approval_request_id.as_str()),
                )
                .filter(
                    agent_principals::runtime_key_binding_digest
                        .eq(&intent.runtime_key_binding_digest),
                )
                .filter(agent_principals::pairing_request_id.eq(intent.pairing_request_id.as_str()))
                .filter(
                    agent_principals::paired_pairing_request_id
                        .is_distinct_from(intent.pairing_request_id.as_str()),
                )
                .filter(
                    agent_principals::pending_pairing_commit_intent
                        .is_null()
                        .or(agent_principals::pending_pairing_commit_intent.eq(&intent_value)),
                ),
        )
        .set((
            agent_principals::pending_pairing_commit_intent.eq(&intent_value),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .returning(AgentPrincipalRow::as_returning())
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let approval_notification_id =
            ids::typed_uuid_part_expect_internal(&write.approval_notification_id);
        let controller_account_id =
            ids::typed_uuid_part_expect_internal(&write.controller_account_id);
        let runtime_key_request =
            serde_json::to_value(&write.runtime_key_request).map_err(|error| {
                PersistenceError::Internal(format!(
                    "encode typed Agent runtime key request: {error}"
                ))
            })?;
        let record = diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&write.agent_id))
                .filter(agent_principals::state.eq_any(["active", "paused"]))
                .filter(agent_principals::pairing_request_id.eq(write.pairing_request_id.as_str()))
                .filter(
                    agent_principals::paired_pairing_request_id
                        .is_distinct_from(write.pairing_request_id.as_str()),
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
            agent_principals::runtime_key_request.eq(&runtime_key_request),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .returning(AgentPrincipalRow::as_returning())
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }
}
