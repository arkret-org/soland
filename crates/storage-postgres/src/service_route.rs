use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceMethodState, ServiceRouteCacheEntry,
};
use arkret_wire::{DidCoreId, Hash};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use soland_storage::{
    MonotonicRouteWrite, PersistenceError, PersistenceResult, ServiceResolutionForkEvidence,
    ServiceRouteStore, ServiceRouteStoredKey,
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
             SELECT service_id, service_kind FROM service_method_states UNION \
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

    async fn method_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceMethodState>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT method_state AS value FROM service_method_states WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .map(|row| decode(row.value)).transpose()
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
    async fn publish_route_cache(
        &self,
        evidence: AuthenticatedServiceResolution,
        entry: ServiceRouteCacheEntry,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        if matches!(
            evidence.method_history_evidence,
            arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog { .. }
        ) {
            arkret_identity::verify_authenticated_service_resolution_history(
                &evidence,
                &entry.service_id,
                entry.verified_at,
            )
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        }
        if entry.cache_expires_at <= entry.verified_at
            || entry.cache_expires_at > entry.verified_at + chrono::Duration::seconds(300)
        {
            return Err(PersistenceError::SchemaViolation(
                "service route cache exceeds current verification lifetime".into(),
            ));
        }
        let projection = evidence
            .projection()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if entry.service_id != projection.service_id
            || entry.service_kind != projection.service_kind
            || entry.did != projection.did
            || entry.method_history_head != projection.method_history_head
            || entry.version_id != projection.version_id
            || entry.base_url != projection.base_url
        {
            return Err(PersistenceError::SchemaViolation(
                "route cache disagrees with DID state".into(),
            ));
        }
        let state = ServiceMethodState {
            service_id: entry.service_id.clone(),
            service_kind: entry.service_kind.clone(),
            did: entry.did.clone(),
            method_history_head: entry.method_history_head.clone(),
            version_id: entry.version_id.clone(),
            verified_at: entry.verified_at,
        };
        let state_value = encode(&state)?;
        let entry_value = encode(&entry)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("service-method:{}:{}",state.service_id,state.service_kind)).execute(conn).await?;
            let current=sql_query("SELECT method_state AS value FROM service_method_states WHERE service_id=$1 AND service_kind=$2 FOR UPDATE").bind::<Text,_>(state.service_id.as_str()).bind::<Text,_>(&state.service_kind).get_result::<JsonRow>(conn).await.optional()?.map(|r|decode::<ServiceMethodState>(r.value)).transpose()?;
            if let Some(current)=current.as_ref() {
                if arkret_identity::verify_service_resolution_floor(&evidence,current).is_err() {
                    let native_fork=match &evidence.method_history_evidence {
                        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog{log_entries,..}=>{
                            let accepted_index=current.version_id.split('-').next();
                            log_entries.iter().any(|entry|entry.get("versionId").and_then(serde_json::Value::as_str).and_then(|v|v.split('-').next())==accepted_index&&arkret_canonical::canonical_sha256(entry).is_ok_and(|head|head!=current.method_history_head))
                        },_=>false,
                    };
                    if native_fork || (current.version_id==state.version_id && current.method_history_head!=state.method_history_head) {
                        return Ok(MonotonicRouteWrite::Conflict{accepted_digest:Hash::new(current.method_history_head.clone()).map_err(|e|PersistenceError::Internal(e.to_string()))?});
                    }
                    return Ok(MonotonicRouteWrite::Stale);
                }
                if current.verified_at>state.verified_at { return Ok(MonotonicRouteWrite::Stale); }
            }
            sql_query("INSERT INTO service_method_states(service_id,service_kind,method_state,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(service_id,service_kind) DO UPDATE SET method_state=EXCLUDED.method_state,updated_at=EXCLUDED.updated_at").bind::<Text,_>(state.service_id.as_str()).bind::<Text,_>(&state.service_kind).bind::<Jsonb,_>(&state_value).bind::<Timestamptz,_>(state.verified_at).execute(conn).await?;
            sql_query("INSERT INTO service_route_cache(service_id,service_kind,entry,cache_expires_at,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,service_kind) DO UPDATE SET entry=EXCLUDED.entry,cache_expires_at=EXCLUDED.cache_expires_at,updated_at=EXCLUDED.updated_at").bind::<Text,_>(entry.service_id.as_str()).bind::<Text,_>(&entry.service_kind).bind::<Jsonb,_>(&entry_value).bind::<Timestamptz,_>(entry.cache_expires_at).bind::<Timestamptz,_>(entry.verified_at).execute(conn).await?;
            Ok(MonotonicRouteWrite::Applied)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
