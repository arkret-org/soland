use super::*;

/// WebRTC sessions + signals. Sessions auto-prune on `expires_at`.
#[async_trait]
pub trait WebrtcSessionStore: Send + Sync {
    async fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()>;
    async fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>>;
    async fn delete(&self, session_id: &str) -> PersistenceResult<bool>;
    async fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Closure that fills in a signal once the store has assigned a sequence.
pub type SignalBuilder<'a> = Box<dyn FnOnce(u64) -> WebrtcSignalRecord + Send + 'a>;

/// Result of `WebrtcSessionStore::append_signal` — useful when the caller
/// needs to surface the sequence number / participant set to the client.
#[derive(Debug, Clone)]
pub struct WebrtcAppendSignal {
    pub seq: u64,
}

#[derive(Default)]
pub(crate) struct MemoryWebrtcSessionStore {
    data: Mutex<BTreeMap<String, WebrtcSessionRecord>>,
}

impl MemoryWebrtcSessionStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WebrtcSessionStore for MemoryWebrtcSessionStore {
    async fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let id = record.session_id.clone();
        self.data.lock().expect("webrtc lock").insert(id, record);
        Ok(())
    }

    async fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .get(session_id)
            .cloned())
    }

    async fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .remove(session_id)
            .is_some())
    }

    async fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal> {
        let mut data = self.data.lock().expect("webrtc lock");
        let record = data
            .get_mut(session_id)
            .ok_or_else(|| PersistenceError::NotFound(session_id.to_owned()))?;
        if !record.participants.contains(actor_must_be_participant) {
            return Err(PersistenceError::Conflict(format!(
                "actor {actor_must_be_participant} is not a participant of {session_id}",
            )));
        }
        let seq = record.next_seq;
        record.next_seq += 1;
        record.signals.push(builder(seq));
        Ok(WebrtcAppendSignal { seq })
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("webrtc lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

pub(crate) struct PgWebrtcSessionStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct WebrtcSessionRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    initiator_did: String,
    #[diesel(sql_type = Jsonb)]
    signaling_state: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl WebrtcSessionRow {
    async fn into_record(self) -> PersistenceResult<WebrtcSessionRecord> {
        // The `signaling_state` envelope carries the live participants set,
        // signals vec, and next_seq counter — round-tripped via serde_json.
        let participants: BTreeSet<String> = self
            .signaling_state
            .get("participants")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let next_seq = self
            .signaling_state
            .get("next_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let signals: Vec<WebrtcSignalRecord> = self
            .signaling_state
            .get("signals")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|signal| WebrtcSignalRecord {
                        seq: signal.get("seq").and_then(Value::as_u64).unwrap_or(0),
                        sender: signal
                            .get("sender")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_default(),
                        message_type: signal
                            .get("message_type")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_default(),
                        payload: signal.get("payload").cloned().unwrap_or(Value::Null),
                        proofs: signal
                            .get("proofs")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default(),
                        created_at: signal
                            .get("created_at")
                            .and_then(Value::as_str)
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(Utc::now),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(WebrtcSessionRecord {
            session_id: ids::format_typed_uuid("webrtc", &self.id),
            realm_id: ids::format_typed_uuid("space", &self.realm_id),
            created_by: self.initiator_did,
            participants,
            mode: self
                .signaling_state
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("p2p")
                .to_owned(),
            recording_policy: self
                .signaling_state
                .get("recording_policy")
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_owned(),
            recording_started_by: self
                .signaling_state
                .get("recording_started_by")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            recording_blob_ref: self
                .signaling_state
                .get("recording_blob_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            expires_at: self.expires_at,
            created_at: self.created_at,
            next_seq,
            signals,
        })
    }
}

fn webrtc_signaling_state(record: &WebrtcSessionRecord) -> Value {
    serde_json::json!({
        "participants": record.participants.iter().cloned().collect::<Vec<_>>(),
        "mode": record.mode.clone(),
        "recording_policy": record.recording_policy.clone(),
        "recording_started_by": record.recording_started_by.clone(),
        "recording_blob_ref": record.recording_blob_ref.clone(),
        "next_seq": record.next_seq,
        "signals": record
            .signals
            .iter()
            .map(|s| serde_json::json!({
                "seq": s.seq,
                "sender": s.sender,
                "message_type": s.message_type,
                "payload": s.payload,
                "proofs": s.proofs,
                "created_at": s.created_at.to_rfc3339(),
            }))
            .collect::<Vec<_>>(),
    })
}

#[async_trait]
impl WebrtcSessionStore for PgWebrtcSessionStore {
    async fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let signaling_state = webrtc_signaling_state(&record);
        let ice_config: Value = serde_json::json!({});
        let session_id_uuid = ids::typed_uuid_part_or_panic(&record.session_id);
        let realm_id_uuid = ids::typed_uuid_part_or_panic(&record.realm_id);
        sql_query(
            "INSERT INTO webrtc_sessions \
             (id, realm_id, initiator_id, ice_config, signaling_state, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                initiator_id = EXCLUDED.initiator_id, \
                ice_config = EXCLUDED.ice_config, \
                signaling_state = EXCLUDED.signaling_state, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<SqlUuid, _>(session_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&record.created_by)
        .bind::<Jsonb, _>(&ice_config)
        .bind::<Jsonb, _>(&signaling_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let session_id_uuid = ids::typed_uuid_part_or_panic(session_id);
        let row = sql_query(
            "SELECT id, realm_id, initiator_id AS initiator_did, signaling_state, created_at, expires_at \
             FROM webrtc_sessions WHERE id = $1",
        )
        .bind::<SqlUuid, _>(session_id_uuid)
        .get_result::<WebrtcSessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)?;
        match row {
            Some(r) => Ok(Some(r.into_record().await?)),
            None => Ok(None),
        }
    }

    async fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let session_id_uuid = ids::typed_uuid_part_or_panic(session_id);
        sql_query("DELETE FROM webrtc_sessions WHERE id = $1")
            .bind::<SqlUuid, _>(session_id_uuid)
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal> {
        // Read-modify-write inside a single conn — acceptable since callers
        // serialize on the WebRTC routing handler and the conflict surface
        // is bounded by the active call session.
        let mut record = match self.get(session_id).await? {
            Some(r) => r,
            None => return Err(PersistenceError::NotFound(session_id.to_owned())),
        };
        if !record.participants.contains(actor_must_be_participant) {
            return Err(PersistenceError::Conflict(format!(
                "actor {actor_must_be_participant} is not a participant of {session_id}",
            )));
        }
        let seq = record.next_seq;
        record.next_seq += 1;
        record.signals.push(builder(seq));
        self.put(record).await?;
        Ok(WebrtcAppendSignal { seq })
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM webrtc_sessions WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }
}
