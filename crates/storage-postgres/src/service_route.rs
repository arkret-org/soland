use arkret_models_identity::{
    ServiceResolutionArtifactKey, ServiceResolutionLastSeenFloor, ServiceResolutionPublishRequest,
    ServiceResolutionRecord, ServiceRouteCacheEntry, ServiceRouteHandoverNotice,
    ServiceRouteNoticeState,
};
use arkret_wire::{DidCoreId, Hash, RealmId};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    MonotonicRouteWrite, PersistenceError, PersistenceResult, ServiceResolutionForkEvidence,
    ServiceResolutionMirrorCommit, ServiceResolutionMirrorEntry, ServiceRouteStore,
    ServiceRouteStoredKey,
};

use crate::{PgPool, PgTransactionError, async_trait, pg_conn};

pub struct PgServiceRouteStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct MirrorRow {
    #[diesel(sql_type = Text)]
    source_id: DidCoreId,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    request_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    artifact_key: String,
    #[diesel(sql_type = Text)]
    artifact_digest: String,
    #[diesel(sql_type = Jsonb)]
    artifact: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    ack: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct ExistsRow {
    #[diesel(sql_type = Bool)]
    found: bool,
}

#[derive(QueryableByName)]
struct RouteKeyRow {
    #[diesel(sql_type = Text)]
    service_id: DidCoreId,
    #[diesel(sql_type = Text)]
    service_kind: String,
}

#[derive(QueryableByName)]
struct QuarantineRow {
    #[diesel(sql_type = Text)]
    service_id: DidCoreId,
    #[diesel(sql_type = Text)]
    service_kind: String,
    #[diesel(sql_type = Text)]
    artifact_family: String,
    #[diesel(sql_type = Text)]
    artifact_key: String,
    #[diesel(sql_type = Text)]
    accepted_digest: String,
    #[diesel(sql_type = Text)]
    conflicting_digest: String,
    #[diesel(sql_type = Jsonb)]
    evidence: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    quarantined_at: chrono::DateTime<chrono::Utc>,
}

fn encode<T: serde::Serialize>(value: &T) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn key_json(key: &ServiceResolutionArtifactKey) -> PersistenceResult<String> {
    arkret_canonical::canonical_json_string(key)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

impl MirrorRow {
    fn decode(self) -> PersistenceResult<ServiceResolutionMirrorEntry> {
        Ok(ServiceResolutionMirrorEntry {
            source_id: self.source_id,
            realm_id: RealmId::new(self.realm_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            request_id: arkret_wire::RequestId::new(self.request_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            request_digest: Hash::new(self.request_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            artifact_key: serde_json::from_str(&self.artifact_key)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            artifact_digest: Hash::new(self.artifact_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            request: decode(self.artifact)?,
            ack: decode(self.ack)?,
            accepted_at: self.accepted_at,
        })
    }
}

async fn lock_route_sequence(
    conn: &mut AsyncPgConnection,
    service_id: &DidCoreId,
    service_kind: &str,
) -> Result<(), PgTransactionError> {
    let key = format!("service-route-sequence:{service_id}:{service_kind}");
    lock_transaction_key(conn, &key).await
}

async fn lock_transaction_key(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> Result<(), PgTransactionError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(key)
        .execute(conn)
        .await?;
    Ok(())
}

async fn advance_mirror_sequence(
    conn: &mut AsyncPgConnection,
    entry: &ServiceResolutionMirrorEntry,
) -> Result<Option<ServiceResolutionMirrorCommit>, PgTransactionError> {
    if let Some(record) = entry.request.service_resolution_record.as_ref() {
        lock_route_sequence(conn, &record.record.service_id, &record.record.service_kind).await?;
        let digest = Hash::new(
            arkret_canonical::canonical_sha256(record)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        )
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let current = sql_query("SELECT floor AS value FROM service_resolution_last_seen_floors WHERE service_id=$1 AND service_kind=$2 FOR UPDATE")
            .bind::<Text, _>(record.record.service_id.as_str())
            .bind::<Text, _>(&record.record.service_kind)
            .get_result::<JsonRow>(conn)
            .await
            .optional()?
            .map(|row| decode::<ServiceResolutionLastSeenFloor>(row.value))
            .transpose()?;
        match current.as_ref() {
            None if record.record.record_sequence == 0 => {}
            Some(current)
                if current.record_sequence == record.record.record_sequence
                    && current.record_digest == digest =>
            {
                return Ok(None);
            }
            Some(current) if current.record_sequence == record.record.record_sequence => {
                return Ok(Some(ServiceResolutionMirrorCommit::SequenceConflict {
                    accepted_digest: current.record_digest.clone(),
                }));
            }
            Some(current)
                if record.record.record_sequence == current.record_sequence + 1
                    && record.record.previous_record_digest.as_ref()
                        == Some(&current.record_digest) => {}
            _ => return Ok(Some(ServiceResolutionMirrorCommit::SequenceRejected)),
        }
        let floor = ServiceResolutionLastSeenFloor {
            service_id: record.record.service_id.clone(),
            service_kind: record.record.service_kind.clone(),
            record_sequence: record.record.record_sequence,
            record_digest: digest,
            verified_at: entry.accepted_at,
        };
        let value = encode(&floor)?;
        sql_query("INSERT INTO service_resolution_last_seen_floors(service_id,service_kind,floor,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(service_id,service_kind) DO UPDATE SET floor=EXCLUDED.floor,updated_at=EXCLUDED.updated_at")
            .bind::<Text, _>(floor.service_id.as_str())
            .bind::<Text, _>(&floor.service_kind)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(floor.verified_at)
            .execute(conn)
            .await?;
        return Ok(None);
    }

    if let Some(notice) = entry.request.service_route_handover_notice.as_ref() {
        lock_route_sequence(conn, &notice.notice.service_id, &notice.notice.service_kind).await?;
        let floor = sql_query("SELECT floor AS value FROM service_resolution_last_seen_floors WHERE service_id=$1 AND service_kind=$2 FOR UPDATE")
            .bind::<Text, _>(notice.notice.service_id.as_str())
            .bind::<Text, _>(&notice.notice.service_kind)
            .get_result::<JsonRow>(conn)
            .await
            .optional()?
            .map(|row| decode::<ServiceResolutionLastSeenFloor>(row.value))
            .transpose()?;
        let Some(floor) = floor else {
            return Ok(Some(ServiceResolutionMirrorCommit::SequenceRejected));
        };
        if notice.notice.from_record_sequence != floor.record_sequence
            || notice.notice.from_record_digest != floor.record_digest
        {
            return Ok(Some(ServiceResolutionMirrorCommit::SequenceRejected));
        }
        let digest = Hash::new(
            arkret_canonical::canonical_sha256(notice)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        )
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let current = sql_query("SELECT notice_state AS value FROM service_route_notice_states WHERE service_id=$1 AND service_kind=$2 AND handover_id=$3 FOR UPDATE")
            .bind::<Text, _>(notice.notice.service_id.as_str())
            .bind::<Text, _>(&notice.notice.service_kind)
            .bind::<Text, _>(&notice.notice.handover_id)
            .get_result::<JsonRow>(conn)
            .await
            .optional()?
            .map(|row| decode::<ServiceRouteNoticeState>(row.value))
            .transpose()?;
        match current.as_ref() {
            None if notice.notice.notice_revision == 0 => {}
            Some(current)
                if current.notice_revision == notice.notice.notice_revision
                    && current.notice_digest == digest =>
            {
                return Ok(None);
            }
            Some(current) if current.notice_revision == notice.notice.notice_revision => {
                return Ok(Some(ServiceResolutionMirrorCommit::SequenceConflict {
                    accepted_digest: current.notice_digest.clone(),
                }));
            }
            Some(current)
                if notice.notice.notice_revision == current.notice_revision + 1
                    && notice.notice.previous_notice_digest.as_ref()
                        == Some(&current.notice_digest) => {}
            _ => return Ok(Some(ServiceResolutionMirrorCommit::SequenceRejected)),
        }
        let state = ServiceRouteNoticeState {
            service_id: notice.notice.service_id.clone(),
            service_kind: notice.notice.service_kind.clone(),
            handover_id: notice.notice.handover_id.clone(),
            notice_revision: notice.notice.notice_revision,
            notice_digest: digest,
            state: notice.notice.state,
            from_record_sequence: notice.notice.from_record_sequence,
            from_record_digest: notice.notice.from_record_digest.clone(),
            expires_at: notice.notice.expires_at,
            verified_at: entry.accepted_at,
        };
        let value = encode(&state)?;
        sql_query("INSERT INTO service_route_notice_states(service_id,service_kind,handover_id,notice_state,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,service_kind,handover_id) DO UPDATE SET notice_state=EXCLUDED.notice_state,updated_at=EXCLUDED.updated_at")
            .bind::<Text, _>(state.service_id.as_str())
            .bind::<Text, _>(&state.service_kind)
            .bind::<Text, _>(&state.handover_id)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(state.verified_at)
            .execute(conn)
            .await?;
        return Ok(None);
    }

    Ok(Some(ServiceResolutionMirrorCommit::SequenceRejected))
}

#[async_trait]
impl ServiceRouteStore for PgServiceRouteStore {
    async fn list_stored_route_keys(
        &self,
        after: Option<&ServiceRouteStoredKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteStoredKey>> {
        let (after_service_id, after_service_kind) = after
            .map(|key| (key.service_id.as_str(), key.service_kind.as_str()))
            .unwrap_or(("", ""));
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT service_id, service_kind FROM (\
             SELECT service_id, service_kind FROM service_resolution_last_seen_floors UNION \
             SELECT service_id, service_kind FROM service_route_notice_states UNION \
             SELECT service_id, service_kind FROM service_resolution_fork_quarantine UNION \
             SELECT service_id, service_kind FROM service_route_cache) AS route_keys \
             WHERE service_id > $1 OR (service_id = $1 AND service_kind > $2) \
             ORDER BY service_id ASC, service_kind ASC LIMIT $3",
        )
        .bind::<Text, _>(after_service_id)
        .bind::<Text, _>(after_service_kind)
        .bind::<BigInt, _>(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
        .load::<RouteKeyRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                Ok(ServiceRouteStoredKey {
                    service_id: row.service_id,
                    service_kind: row.service_kind,
                })
            })
            .collect()
    }

    async fn notice_states(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteNoticeState>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT notice_state AS value FROM service_route_notice_states WHERE service_id=$1 AND service_kind=$2 ORDER BY updated_at DESC, handover_id ASC LIMIT $3")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .bind::<BigInt,_>(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
            .load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?
            .into_iter().map(|row| decode(row.value)).collect()
    }

    async fn handover_mirror_entries(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionMirrorEntry>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT source_id,realm_id,request_id,request_digest,artifact_key,artifact_digest,artifact,ack,accepted_at FROM service_resolution_mirror_ledger WHERE artifact->'service_route_handover_notice'->'notice'->>'service_id'=$1 AND artifact->'service_route_handover_notice'->'notice'->>'service_kind'=$2 ORDER BY accepted_at DESC LIMIT $3")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .bind::<BigInt,_>(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
            .load::<MirrorRow>(&mut *conn).await.map_err(PersistenceError::database)?
            .into_iter().map(MirrorRow::decode).collect()
    }

    async fn quarantine_evidence(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionForkEvidence>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query("SELECT service_id,service_kind,artifact_family,artifact_key,accepted_digest,conflicting_digest,evidence,quarantined_at FROM service_resolution_fork_quarantine WHERE service_id=$1 AND service_kind=$2 ORDER BY quarantined_at DESC LIMIT $3")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .bind::<BigInt,_>(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
            .load::<QuarantineRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                Ok(ServiceResolutionForkEvidence {
                    service_id: row.service_id,
                    service_kind: row.service_kind,
                    artifact_family: row.artifact_family,
                    artifact_key: row.artifact_key,
                    accepted_digest: Hash::new(row.accepted_digest)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                    conflicting_digest: Hash::new(row.conflicting_digest)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                    evidence: row.evidence,
                    quarantined_at: row.quarantined_at,
                })
            })
            .collect()
    }

    async fn last_seen_floor(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceResolutionLastSeenFloor>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT floor AS value FROM service_resolution_last_seen_floors WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .map(|row| decode(row.value)).transpose()
    }

    async fn advance_last_seen_floor(
        &self,
        floor: ServiceResolutionLastSeenFloor,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        let value = encode(&floor)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let changed = sql_query("INSERT INTO service_resolution_last_seen_floors(service_id,service_kind,floor,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(service_id,service_kind) DO UPDATE SET floor=EXCLUDED.floor,updated_at=EXCLUDED.updated_at WHERE ((service_resolution_last_seen_floors.floor->>'record_sequence')::bigint < $5)")
            .bind::<Text,_>(floor.service_id.as_str()).bind::<Text,_>(&floor.service_kind)
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(floor.verified_at)
            .bind::<BigInt,_>(i64::try_from(floor.record_sequence).unwrap_or(i64::MAX))
            .execute(&mut *conn).await.map_err(PersistenceError::database)? > 0;
        if changed {
            return Ok(MonotonicRouteWrite::Applied);
        }
        let current = self
            .last_seen_floor(&floor.service_id, &floor.service_kind)
            .await?
            .ok_or_else(|| PersistenceError::Internal("floor upsert lost its row".to_owned()))?;
        Ok(if current.record_sequence > floor.record_sequence {
            MonotonicRouteWrite::Stale
        } else if current.record_digest == floor.record_digest {
            MonotonicRouteWrite::Replay
        } else {
            MonotonicRouteWrite::Conflict {
                accepted_digest: current.record_digest,
            }
        })
    }

    async fn publish_route_cache(
        &self,
        floor: ServiceResolutionLastSeenFloor,
        entry: ServiceRouteCacheEntry,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        if entry.service_id != floor.service_id
            || entry.service_kind != floor.service_kind
            || entry.record_sequence != floor.record_sequence
            || entry.record_digest != floor.record_digest
        {
            return Err(PersistenceError::SchemaViolation(
                "route cache entry does not match its accepted floor".to_owned(),
            ));
        }
        let floor_value = encode(&floor)?;
        let entry_value = encode(&entry)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_route_sequence(conn, &floor.service_id, &floor.service_kind).await?;
            let current = sql_query(
                "SELECT floor AS value FROM service_resolution_last_seen_floors \
                 WHERE service_id=$1 AND service_kind=$2 FOR UPDATE",
            )
            .bind::<Text, _>(floor.service_id.as_str())
            .bind::<Text, _>(&floor.service_kind)
            .get_result::<JsonRow>(conn)
            .await
            .optional()?
            .map(|row| decode::<ServiceResolutionLastSeenFloor>(row.value))
            .transpose()?;
            let outcome = match current.as_ref() {
                Some(current) if current.record_sequence > floor.record_sequence => {
                    MonotonicRouteWrite::Stale
                }
                Some(current)
                    if current.record_sequence == floor.record_sequence
                        && current.record_digest == floor.record_digest =>
                {
                    MonotonicRouteWrite::Replay
                }
                Some(current) if current.record_sequence == floor.record_sequence => {
                    MonotonicRouteWrite::Conflict {
                        accepted_digest: current.record_digest.clone(),
                    }
                }
                _ => MonotonicRouteWrite::Applied,
            };
            if matches!(&outcome, MonotonicRouteWrite::Applied) {
                sql_query(
                    "INSERT INTO service_resolution_last_seen_floors \
                     (service_id,service_kind,floor,updated_at) VALUES($1,$2,$3,$4) \
                     ON CONFLICT(service_id,service_kind) DO UPDATE SET \
                     floor=EXCLUDED.floor,updated_at=EXCLUDED.updated_at",
                )
                .bind::<Text, _>(floor.service_id.as_str())
                .bind::<Text, _>(&floor.service_kind)
                .bind::<Jsonb, _>(&floor_value)
                .bind::<Timestamptz, _>(floor.verified_at)
                .execute(conn)
                .await?;
            }
            if matches!(
                &outcome,
                MonotonicRouteWrite::Applied | MonotonicRouteWrite::Replay
            ) {
                sql_query(
                    "INSERT INTO service_route_cache \
                     (service_id,service_kind,entry,cache_expires_at,updated_at) \
                     VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,service_kind) \
                     DO UPDATE SET entry=EXCLUDED.entry, \
                     cache_expires_at=EXCLUDED.cache_expires_at,updated_at=EXCLUDED.updated_at",
                )
                .bind::<Text, _>(entry.service_id.as_str())
                .bind::<Text, _>(&entry.service_kind)
                .bind::<Jsonb, _>(&entry_value)
                .bind::<Timestamptz, _>(entry.cache_expires_at)
                .bind::<Timestamptz, _>(entry.cached_at)
                .execute(conn)
                .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn notice_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<ServiceRouteNoticeState>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT notice_state AS value FROM service_route_notice_states WHERE service_id=$1 AND service_kind=$2 AND handover_id=$3")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind).bind::<Text,_>(handover_id)
            .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .map(|row| decode(row.value)).transpose()
    }

    async fn advance_notice_state(
        &self,
        next: ServiceRouteNoticeState,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        let value = encode(&next)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let changed = sql_query("INSERT INTO service_route_notice_states(service_id,service_kind,handover_id,notice_state,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,service_kind,handover_id) DO UPDATE SET notice_state=EXCLUDED.notice_state,updated_at=EXCLUDED.updated_at WHERE ((service_route_notice_states.notice_state->>'notice_revision')::bigint < $6)")
            .bind::<Text,_>(next.service_id.as_str()).bind::<Text,_>(&next.service_kind).bind::<Text,_>(&next.handover_id)
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(next.verified_at).bind::<BigInt,_>(i64::from(next.notice_revision))
            .execute(&mut *conn).await.map_err(PersistenceError::database)? > 0;
        if changed {
            return Ok(MonotonicRouteWrite::Applied);
        }
        let current = self
            .notice_state(&next.service_id, &next.service_kind, &next.handover_id)
            .await?
            .ok_or_else(|| PersistenceError::Internal("notice upsert lost its row".to_owned()))?;
        Ok(if current.notice_revision > next.notice_revision {
            MonotonicRouteWrite::Stale
        } else if current.notice_digest == next.notice_digest {
            MonotonicRouteWrite::Replay
        } else {
            MonotonicRouteWrite::Conflict {
                accepted_digest: current.notice_digest,
            }
        })
    }

    async fn commit_mirror(
        &self,
        entry: ServiceResolutionMirrorEntry,
    ) -> PersistenceResult<ServiceResolutionMirrorCommit> {
        entry.validate()?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let artifact_key = key_json(&entry.artifact_key)?;
            let (target_id, target_kind) =
                if let Some(record) = entry.request.service_resolution_record.as_ref() {
                    (&record.record.service_id, record.record.service_kind.as_str())
                } else if let Some(notice) =
                    entry.request.service_route_handover_notice.as_ref()
                {
                    (&notice.notice.service_id, notice.notice.service_kind.as_str())
                } else {
                    return Ok(ServiceResolutionMirrorCommit::SequenceRejected);
                };
            // Serialize both initial inserts and successors before inspecting
            // either idempotency index. This makes concurrent exact requests
            // deterministically observe and replay the first durable ACK.
            lock_route_sequence(conn, target_id, target_kind).await?;
            let mut idempotency_locks = [
                format!(
                    "service-route-artifact:{}:{}:{artifact_key}",
                    entry.source_id, entry.realm_id
                ),
                format!(
                    "service-route-transport:{}:{}:{}",
                    entry.source_id, entry.realm_id, entry.request_id
                ),
            ];
            idempotency_locks.sort();
            for key in &idempotency_locks {
                lock_transaction_key(conn, key).await?;
            }
            let by_request = sql_query("SELECT source_id,realm_id,request_id,request_digest,artifact_key,artifact_digest,artifact,ack,accepted_at FROM service_resolution_mirror_ledger WHERE source_id=$1 AND realm_id=$2 AND request_id=$3 FOR UPDATE")
                .bind::<Text, _>(entry.source_id.as_str())
                .bind::<Text, _>(entry.realm_id.as_str())
                .bind::<Text, _>(entry.request_id.as_str())
                .get_result::<MirrorRow>(conn)
                .await
                .optional()?;
            if let Some(current) = by_request {
                let current = current.decode()?;
                return Ok(if current.request_digest == entry.request_digest {
                    ServiceResolutionMirrorCommit::Replay(current.ack)
                } else {
                    ServiceResolutionMirrorCommit::TransportConflict
                });
            }
            let by_artifact = sql_query("SELECT source_id,realm_id,request_id,request_digest,artifact_key,artifact_digest,artifact,ack,accepted_at FROM service_resolution_mirror_ledger WHERE source_id=$1 AND realm_id=$2 AND artifact_key=$3 FOR UPDATE")
                .bind::<Text, _>(entry.source_id.as_str())
                .bind::<Text, _>(entry.realm_id.as_str())
                .bind::<Text, _>(&artifact_key)
                .get_result::<MirrorRow>(conn)
                .await
                .optional()?;
            if let Some(current) = by_artifact {
                return Ok(ServiceResolutionMirrorCommit::ArtifactConflict {
                    accepted_digest: current.decode()?.artifact_digest,
                });
            }
            if let Some(rejected) = advance_mirror_sequence(conn, &entry).await? {
                return Ok(rejected);
            }
            let request = encode(&entry.request)?;
            let ack = encode(&entry.ack)?;
            sql_query("INSERT INTO service_resolution_mirror_ledger(source_id,realm_id,request_id,request_digest,artifact_key,artifact_digest,artifact,ack,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind::<Text, _>(entry.source_id.as_str())
                .bind::<Text, _>(entry.realm_id.as_str())
                .bind::<Text, _>(entry.request_id.as_str())
                .bind::<Text, _>(entry.request_digest.as_str())
                .bind::<Text, _>(&artifact_key)
                .bind::<Text, _>(entry.artifact_digest.as_str())
                .bind::<Jsonb, _>(request)
                .bind::<Jsonb, _>(ack)
                .bind::<Timestamptz, _>(entry.accepted_at)
                .execute(conn)
                .await?;
            Ok(ServiceResolutionMirrorCommit::Stored(entry.ack))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn successor_records(
        &self,
        source_id: &DidCoreId,
        realm_id: &RealmId,
        target_id: &DidCoreId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query("SELECT artifact AS value FROM service_resolution_mirror_ledger WHERE source_id=$1 AND realm_id=$2 ORDER BY accepted_at ASC")
            .bind::<Text,_>(source_id.as_str()).bind::<Text,_>(realm_id.as_str())
            .load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut records = Vec::new();
        for row in rows {
            let request: ServiceResolutionPublishRequest = decode(row.value)?;
            if let Some(record) = request.service_resolution_record.filter(|record| {
                &record.record.service_id == target_id
                    && record.record.service_kind == service_kind
                    && record.record.record_sequence > after_sequence
            }) {
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.record.record_sequence);
        records.truncate(limit);
        Ok(records)
    }

    async fn latest_notice(
        &self,
        source_id: &DidCoreId,
        realm_id: &RealmId,
        target_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverNotice>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query("SELECT artifact AS value FROM service_resolution_mirror_ledger WHERE source_id=$1 AND realm_id=$2 ORDER BY accepted_at DESC")
            .bind::<Text,_>(source_id.as_str()).bind::<Text,_>(realm_id.as_str()).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut latest: Option<ServiceRouteHandoverNotice> = None;
        for row in rows {
            let request: ServiceResolutionPublishRequest = decode(row.value)?;
            if let Some(notice) = request.service_route_handover_notice.filter(|notice| {
                &notice.notice.service_id == target_id && notice.notice.service_kind == service_kind
            }) && latest.as_ref().is_none_or(|current| {
                current.notice.notice_revision < notice.notice.notice_revision
            }) {
                latest = Some(notice);
            }
        }
        Ok(latest)
    }

    async fn quarantine_fork(
        &self,
        evidence: ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()> {
        let value = encode(&evidence.evidence)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("INSERT INTO service_resolution_fork_quarantine(service_id,service_kind,artifact_family,artifact_key,accepted_digest,conflicting_digest,evidence,quarantined_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
            .bind::<Text,_>(evidence.service_id.as_str()).bind::<Text,_>(&evidence.service_kind).bind::<Text,_>(&evidence.artifact_family).bind::<Text,_>(&evidence.artifact_key)
            .bind::<Text,_>(evidence.accepted_digest.as_str()).bind::<Text,_>(evidence.conflicting_digest.as_str()).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(evidence.quarantined_at)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        Ok(())
    }

    async fn is_quarantined(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        Ok(sql_query("SELECT EXISTS(SELECT 1 FROM service_resolution_fork_quarantine WHERE service_id=$1 AND service_kind=$2) AS found")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind).get_result::<ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.found)
    }

    async fn route_cache(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteCacheEntry>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT entry AS value FROM service_route_cache WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.map(|row| decode(row.value)).transpose()
    }

    async fn put_route_cache(&self, entry: ServiceRouteCacheEntry) -> PersistenceResult<()> {
        let value = encode(&entry)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("INSERT INTO service_route_cache(service_id,service_kind,entry,cache_expires_at,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,service_kind) DO UPDATE SET entry=EXCLUDED.entry,cache_expires_at=EXCLUDED.cache_expires_at,updated_at=EXCLUDED.updated_at")
            .bind::<Text,_>(entry.service_id.as_str()).bind::<Text,_>(&entry.service_kind).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(entry.cache_expires_at).bind::<Timestamptz,_>(entry.cached_at)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        Ok(())
    }

    async fn evict_route_cache(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM service_route_cache WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text, _>(service_id.as_str())
            .bind::<Text, _>(service_kind)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(())
    }
}
