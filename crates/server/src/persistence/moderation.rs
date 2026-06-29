use super::*;

/// Moderation reports + assigned actions + decisions + appeals + queue items.
///
/// Reports and actions are append-only (back-compat). The newer methods
/// (decisions, appeals, queue items) form the spec-compliant triage
/// strand: a report becomes a queue item, a queue item gets a decision,
/// a decision can be appealed (4-state appeal FSM lives in the reducer
/// `crate::reducer::apply_moderation`).
///
/// The Pg backend stubs decisions/appeals/queue items as
/// `Err(PersistenceError::Internal("not yet wired"))` so production
/// instances fail loudly until a migration ships; the in-memory backend
/// implements them fully and is used by dev mode + tests.
#[async_trait]
pub trait ModerationStore: Send + Sync {
    async fn append_report(&self, report: Value) -> PersistenceResult<()>;
    async fn append_action(&self, action: Value) -> PersistenceResult<()>;
    async fn list_reports(&self) -> PersistenceResult<Vec<Value>>;
    #[allow(dead_code)]
    async fn list_actions(&self) -> PersistenceResult<Vec<Value>>;

    /// Append a `ck.moderation.decision` record. The JSON must carry at
    /// least `decision_id`, `target_ref`, `action`, `decided_by`,
    /// `decided_at`. Idempotent on `decision_id`.
    async fn append_decision(&self, _decision: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation decision append not wired in this backend".to_owned(),
        ))
    }
    async fn list_decisions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    async fn get_decision(&self, _decision_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(None)
    }
    /// Mark a decision as lifted (used when an appeal verdict=overturn
    /// is paired with `ck.moderation.decision.lift`). Stores the lift
    /// record verbatim; readers MUST join against `list_decisions` to
    /// determine the current active state.
    async fn append_decision_lift(&self, _lift: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation decision lift not wired in this backend".to_owned(),
        ))
    }

    /// Upsert a `ModerationQueueItem` record. The JSON must carry
    /// `id`, `status`, `visibility`, `created_at`.
    async fn upsert_queue_item(&self, _item: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation queue item upsert not wired in this backend".to_owned(),
        ))
    }
    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    async fn get_queue_item(&self, _id: &str) -> PersistenceResult<Option<Value>> {
        Ok(None)
    }

    /// Append an appeal event. `payload` MUST carry `appeal_id`,
    /// `realm_id`, and the variant-specific fields (see
    /// the SDK `ModerationAppealPayload`). The store
    /// keeps an event log per appeal; the current FSM state is derived
    /// by replaying events.
    async fn append_appeal(&self, _appeal: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation appeal append not wired in this backend".to_owned(),
        ))
    }
    /// List the latest known event for each known appeal (one record
    /// per appeal_id). Used by sodmin to render the queue.
    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    /// Full event history for one appeal, in append order.
    async fn appeal_history(&self, _appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub(crate) struct MemoryModerationStore {
    reports: Mutex<Vec<Value>>,
    actions: Mutex<Vec<Value>>,
    decisions: Mutex<Vec<Value>>,
    decision_lifts: Mutex<Vec<Value>>,
    queue_items: Mutex<Vec<Value>>,
    appeals: Mutex<Vec<Value>>,
}

impl MemoryModerationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ModerationStore for MemoryModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        self.reports.lock().expect("moderation lock").push(report);
        Ok(())
    }

    async fn append_action(&self, action: Value) -> PersistenceResult<()> {
        self.actions
            .lock()
            .expect("moderation action lock")
            .push(action);
        Ok(())
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.reports.lock().expect("moderation lock").clone())
    }

    async fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.actions.lock().expect("moderation action lock").clone())
    }

    async fn append_decision(&self, decision: Value) -> PersistenceResult<()> {
        let id = decision
            .get("decision_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation decision missing decision_id".to_owned())
            })?
            .to_owned();
        let mut decisions = self.decisions.lock().expect("moderation decisions lock");
        if !decisions
            .iter()
            .any(|d| d.get("decision_id").and_then(Value::as_str) == Some(id.as_str()))
        {
            decisions.push(decision);
        }
        Ok(())
    }

    async fn list_decisions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .decisions
            .lock()
            .expect("moderation decisions lock")
            .clone())
    }

    async fn get_decision(&self, decision_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .decisions
            .lock()
            .expect("moderation decisions lock")
            .iter()
            .find(|d| d.get("decision_id").and_then(Value::as_str) == Some(decision_id))
            .cloned())
    }

    async fn append_decision_lift(&self, lift: Value) -> PersistenceResult<()> {
        self.decision_lifts
            .lock()
            .expect("moderation decision lifts lock")
            .push(lift);
        Ok(())
    }

    async fn upsert_queue_item(&self, item: Value) -> PersistenceResult<()> {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation queue item missing id".to_owned())
            })?
            .to_owned();
        let mut queue = self.queue_items.lock().expect("moderation queue lock");
        if let Some(slot) = queue
            .iter_mut()
            .find(|i| i.get("id").and_then(Value::as_str) == Some(id.as_str()))
        {
            *slot = item;
        } else {
            queue.push(item);
        }
        Ok(())
    }

    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .queue_items
            .lock()
            .expect("moderation queue lock")
            .clone())
    }

    async fn get_queue_item(&self, id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .queue_items
            .lock()
            .expect("moderation queue lock")
            .iter()
            .find(|i| i.get("id").and_then(Value::as_str) == Some(id))
            .cloned())
    }

    async fn append_appeal(&self, appeal: Value) -> PersistenceResult<()> {
        if appeal.get("appeal_id").and_then(Value::as_str).is_none() {
            return Err(PersistenceError::Internal(
                "moderation appeal missing appeal_id".to_owned(),
            ));
        }
        self.appeals
            .lock()
            .expect("moderation appeals lock")
            .push(appeal);
        Ok(())
    }

    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        // Collapse history → one record per appeal_id, keeping the
        // last-appended event (insertion order = chronological).
        let all = self
            .appeals
            .lock()
            .expect("moderation appeals lock")
            .clone();
        let mut latest: std::collections::BTreeMap<String, Value> =
            std::collections::BTreeMap::new();
        for record in all {
            if let Some(id) = record.get("appeal_id").and_then(Value::as_str) {
                latest.insert(id.to_owned(), record);
            }
        }
        Ok(latest.into_values().collect())
    }

    async fn appeal_history(&self, appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .appeals
            .lock()
            .expect("moderation appeals lock")
            .iter()
            .filter(|a| a.get("appeal_id").and_then(Value::as_str) == Some(appeal_id))
            .cloned()
            .collect())
    }
}

pub(crate) struct PgModerationStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl ModerationStore for PgModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let extract = |key: &str| -> Option<String> {
            report
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let report_id = extract("report_id").ok_or_else(|| {
            PersistenceError::Internal("moderation report missing report_id".to_owned())
        })?;
        let reporter = extract("reporter");
        let target_actor = extract("target_actor");
        let target_event_id = extract("target_event_id");
        let realm_id = extract("realm_id");
        let report_id_uuid = ids::typed_uuid_part_expect_internal(&report_id);
        let target_event_id_uuid: Option<Uuid> = target_event_id
            .as_deref()
            .map(ids::typed_uuid_part_expect_internal);
        let realm_id_uuid: Option<Uuid> = realm_id.as_deref().map(ids::typed_uuid_part_expect_internal);
        sql_query(
            "INSERT INTO moderation_reports \
             (id, reporter_id, target_actor_id, target_event_id, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(report_id_uuid)
        .bind::<Nullable<Text>, _>(&reporter)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<SqlUuid>, _>(target_event_id_uuid)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Jsonb, _>(&report)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn append_action(&self, action: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let extract = |key: &str| -> Option<String> {
            action
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let action_id = extract("action_id").ok_or_else(|| {
            PersistenceError::Internal("moderation action missing action_id".to_owned())
        })?;
        let moderator = extract("moderator");
        let target_actor = extract("target_actor");
        let action_kind = extract("action_kind");
        let realm_id = extract("realm_id");
        let action_id_uuid = ids::typed_uuid_part_expect_internal(&action_id);
        let realm_id_uuid: Option<Uuid> = realm_id.as_deref().map(ids::typed_uuid_part_expect_internal);
        sql_query(
            "INSERT INTO moderation_actions \
             (id, moderator_id, target_actor_id, action_kind, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(action_id_uuid)
        .bind::<Nullable<Text>, _>(&moderator)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<Text>, _>(&action_kind)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Jsonb, _>(&action)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM moderation_reports ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }

    async fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM moderation_actions ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }
}
