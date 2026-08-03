use std::collections::BTreeMap;

use super::{
    Array, AsyncConnection, AsyncPgConnection, BigInt, Binary, Bool, CanonicalEventRecord,
    DeviceInventoryRecord, EventBatchReceipt, EventStore, ExistsRow, FederationOutboxRecord,
    IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas, IdentityAnchorReanchorSlot, Jsonb,
    MaxSeqRow, Nullable, OptionalExtension, PeerEventsPageQuery, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, PublicationEvidenceRecord, QueryableByName,
    RealmEventStats, RunQueryDsl, SqlUuid, Text, Timestamptz, Uuid, Value, async_trait,
    identity_anchor_slot_conflicts, ids, pg_conn, sql_query,
};
use crate::federation::insert_federation_outbox_row;
pub struct PgEventStore {
    pub pool: PgPool,
}
fn map_canonical_event_put_error(error: diesel::result::Error) -> PersistenceError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &error
        && info.constraint_name() == Some("canonical_events_realm_create_unique_idx")
    {
        return PersistenceError::Conflict("realm_already_exists".to_owned());
    }
    if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &error
        && info.constraint_name() == Some("canonical_events_pkey")
    {
        return PersistenceError::Conflict("duplicate_conflict".to_owned());
    }
    PersistenceError::database(error)
}
#[derive(QueryableByName)]
pub(crate) struct CanonicalEventRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    schema_id: String,
    #[diesel(sql_type = Text)]
    canonical_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct RealmEventStatsRow {
    #[diesel(sql_type = BigInt)]
    event_count: i64,
    #[diesel(sql_type = BigInt)]
    canonical_bytes: i64,
}
#[derive(QueryableByName)]
struct EventBatchReceiptRow {
    #[diesel(sql_type = Text)]
    schema: String,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    issuer: String,
    #[diesel(sql_type = Jsonb)]
    scope: Value,
    #[diesel(sql_type = Jsonb)]
    frontier: Value,
    #[diesel(sql_type = Jsonb)]
    events: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    proofs: Value,
}
#[derive(QueryableByName)]
struct SealLeafIdRow {
    #[diesel(sql_type = Text)]
    id: String,
}
impl TryFrom<EventBatchReceiptRow> for EventBatchReceipt {
    type Error = PersistenceError;

    fn try_from(row: EventBatchReceiptRow) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::json!({
            "schema": row.schema,
            "receipt_id": ids::format_typed_uuid("receipt", &row.id),
            "issuer": row.issuer,
            "scope": row.scope,
            "frontier": row.frontier,
            "events": row.events,
            "created_at": arkret_canonical::normalize_timestamp_canonical(row.created_at),
            "proofs": row.proofs,
        }))
        .map_err(|error| {
            PersistenceError::Internal(format!("stored Event Batch Receipt is invalid: {error}"))
        })
    }
}
/// Serialization key for every writer of one Realm/actor Event stream.
///
/// PostgreSQL `text` rejects embedded NUL bytes, so the Realm component is
/// length-prefixed and the transcript stays unambiguous without relying on a
/// forbidden separator. Both the standard batch commit and the identity-anchor
/// commit must derive the key here: they insert into the same rows, and a lock
/// wider than one Realm/actor pair would serialize unrelated principals.
pub(crate) fn realm_actor_lock_key(realm_id: &str, actor_id: &str) -> String {
    format!("realm_actor:{}:{}{}", realm_id.len(), realm_id, actor_id)
}

async fn lock_realm_actor(conn: &mut AsyncPgConnection, lock_key: &str) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(lock_key)
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
}

async fn insert_canonical_event(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
) -> PersistenceResult<()> {
    let event_id_uuid = ids::typed_uuid_part_expect_internal(&record.event_id);
    let realm_id_uuid = record
        .realm_id
        .as_deref()
        .map(ids::typed_uuid_part_expect_internal);
    sql_query(
        "INSERT INTO canonical_events \
         (id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<SqlUuid, _>(event_id_uuid)
    .bind::<Text, _>(&record.actor_id)
    .bind::<BigInt, _>(record.actor_seq as i64)
    .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
    .bind::<Text, _>(&record.kind)
    .bind::<Text, _>(&record.schema_id)
    .bind::<Text, _>(&record.canonical_digest)
    .bind::<Binary, _>(&record.canonical_bytes)
    .bind::<Jsonb, _>(&record.envelope)
    .bind::<Timestamptz, _>(record.received_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(map_canonical_event_put_error)
}

async fn insert_pending_control_event(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
    proposal_receipt: Option<&arkret_wire::ControlProposalReceipt>,
) -> PersistenceResult<()> {
    let event =
        serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()).map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted anchor Event is not canonical wire: {error}"
            ))
        })?;
    let digest = event.event_digest().map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: accepted anchor digest failed: {error}"
        ))
    })?;
    if digest != record.canonical_digest {
        return Err(PersistenceError::Conflict(
            "schema_violation: canonical digest differs from anchor Event digest".to_owned(),
        ));
    }
    if let Some(proposal_receipt) = proposal_receipt {
        if proposal_receipt.proposal_digest.as_str() != digest
            || proposal_receipt.realm_id != event.realm_id
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: proposal receipt does not bind anchor Event".to_owned(),
            ));
        }
        proposal_receipt
            .validate_protocol_bounds()
            .map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: invalid proposal receipt: {error}"
                ))
            })?;
    }
    let proposal_receipt = proposal_receipt
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| {
            PersistenceError::Internal(format!("proposal receipt encoding failed: {error}"))
        })?;
    sql_query(
        "INSERT INTO state_control_events \
         (event_digest, realm_id, event_json, proposal_receipt) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (event_digest) DO UPDATE SET \
           proposal_receipt = COALESCE( \
             state_control_events.proposal_receipt, EXCLUDED.proposal_receipt \
           ) \
         WHERE state_control_events.realm_id = EXCLUDED.realm_id \
           AND state_control_events.event_json = EXCLUDED.event_json \
           AND (state_control_events.proposal_receipt IS NULL \
             OR EXCLUDED.proposal_receipt IS NULL \
             OR state_control_events.proposal_receipt = EXCLUDED.proposal_receipt)",
    )
    .bind::<Text, _>(&digest)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(&record.envelope)
    .bind::<Nullable<Jsonb>, _>(proposal_receipt.as_ref())
    .execute(conn)
    .await
    .map_err(PersistenceError::database)
    .and_then(|affected| {
        if affected == 0 {
            Err(PersistenceError::Conflict(
                "duplicate_conflict: pending Control Move has different canonical bytes or receipt"
                    .to_owned(),
            ))
        } else {
            Ok(())
        }
    })
}
async fn assert_identity_anchor_frontier(
    conn: &mut AsyncPgConnection,
    expected: &IdentityAnchorFrontierCas,
) -> PersistenceResult<()> {
    // Every `state_seals` writer takes this same per-Realm advisory key before
    // it inserts, rewires, or deletes a leaf, and the leaf query below is
    // Realm-scoped on both the candidate and its successor. A table-level lock
    // would additionally block seal commits for unrelated Realms, which is what
    // made two independent principals serialize on one another.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&expected.realm_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let rows = sql_query(
        "SELECT candidate.id \
         FROM state_seals candidate \
         WHERE candidate.realm_id = $1 \
           AND NOT EXISTS ( \
             SELECT 1 FROM state_seals successor \
             WHERE successor.realm_id = candidate.realm_id \
               AND successor.predecessor_refs @> to_jsonb(ARRAY[candidate.id]::text[]) \
           ) \
         ORDER BY candidate.id",
    )
    .bind::<Text, _>(&expected.realm_id)
    .load::<SealLeafIdRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let actual = rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
    let mut raw_declared = expected.raw_leaves.clone();
    raw_declared.sort_unstable();
    if actual != raw_declared {
        return Err(PersistenceError::Conflict(
            "device_reanchor_frontier_mismatch".to_owned(),
        ));
    }
    Ok(())
}
async fn insert_event_batch_receipt(
    conn: &mut AsyncPgConnection,
    receipt: &EventBatchReceipt,
) -> PersistenceResult<()> {
    let scope = serde_json::to_value(&receipt.scope).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt scope encode failed: {error}"))
    })?;
    let frontier = serde_json::to_value(&receipt.frontier).map_err(|error| {
        PersistenceError::Internal(format!(
            "Event Batch Receipt frontier encode failed: {error}"
        ))
    })?;
    let events = serde_json::to_value(&receipt.events).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt events encode failed: {error}"))
    })?;
    let proofs = serde_json::to_value(&receipt.proofs).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt proofs encode failed: {error}"))
    })?;
    let event_ids = receipt
        .events
        .iter()
        .filter_map(|event| match event {
            arkret_wire::EventBatchReceiptEvent::Item(item) => Some(item.event_id.as_str()),
            arkret_wire::EventBatchReceiptEvent::Digest(_) => None,
        })
        .map(ids::typed_uuid_part_expect_internal)
        .collect::<Vec<_>>();
    sql_query(
        "INSERT INTO event_batch_receipts \
         (schema, id, issuer, scope, frontier, events, created_at, proofs, event_ids) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind::<Text, _>(&receipt.schema)
    .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
        receipt.receipt_id.as_str(),
    ))
    .bind::<Text, _>(receipt.issuer.as_str())
    .bind::<Jsonb, _>(scope)
    .bind::<Jsonb, _>(frontier)
    .bind::<Jsonb, _>(events)
    .bind::<Timestamptz, _>(arkret_canonical::normalize_timestamp_canonical(
        receipt.created_at,
    ))
    .bind::<Jsonb, _>(proofs)
    .bind::<Array<SqlUuid>, _>(event_ids)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}
impl From<CanonicalEventRow> for CanonicalEventRecord {
    fn from(row: CanonicalEventRow) -> Self {
        Self {
            event_id: ids::format_typed_uuid("event", &row.id),
            actor_id: row.actor_id,
            actor_seq: row.actor_seq.max(0) as u64,
            realm_id: row
                .realm_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("realm", u)),
            kind: row.kind,
            schema_id: row.schema_id,
            canonical_digest: row.canonical_digest,
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        }
    }
}

fn identity_anchor_receipt_cardinality_is_valid(
    record_count: usize,
    proposal_receipt_count: usize,
    reanchor_conflict: bool,
) -> bool {
    if reanchor_conflict {
        proposal_receipt_count == 0
    } else {
        proposal_receipt_count == 0 || proposal_receipt_count == record_count
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id_uuid = ids::typed_uuid_part_expect_internal(&record.event_id);
        let realm_id_uuid: Option<Uuid> = record
            .realm_id
            .as_deref()
            .map(ids::typed_uuid_part_expect_internal);
        sql_query(
            "INSERT INTO canonical_events \
             (id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .bind::<Text, _>(&record.actor_id)
        .bind::<BigInt, _>(record.actor_seq as i64)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.schema_id)
        .bind::<Text, _>(&record.canonical_digest)
        .bind::<Binary, _>(&record.canonical_bytes)
        .bind::<Jsonb, _>(&record.envelope)
        .bind::<Timestamptz, _>(record.received_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(map_canonical_event_put_error)
    }

    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        proposal_receipts: Vec<arkret_wire::ControlProposalReceipt>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<()> {
        let mut receipts = BTreeMap::new();
        for receipt in proposal_receipts {
            if receipts
                .insert(receipt.proposal_digest.as_str().to_owned(), receipt)
                .is_some()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: duplicate Realm bootstrap proposal receipt".to_owned(),
                ));
            }
        }
        if receipts.len() != records.len() {
            return Err(PersistenceError::Conflict(
                "schema_violation: Realm bootstrap receipt cardinality mismatch".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            for record in records {
                insert_canonical_event(conn, &record).await?;
                let proposal_receipt = receipts.get(&record.canonical_digest).ok_or_else(|| {
                    PersistenceError::Conflict(
                        "schema_violation: Realm bootstrap Event is missing proposal receipt"
                            .to_owned(),
                    )
                })?;
                insert_pending_control_event(conn, &record, Some(proposal_receipt)).await?;
            }
            // Same transaction as the Events: the delivery intent for a Realm
            // genesis unit is not a post-commit best-effort follow-up.
            for delivery in outbox {
                insert_federation_outbox_row(conn, &delivery).await?;
            }
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        proposal_receipts: Vec<arkret_wire::ControlProposalReceipt>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let mut proposal_receipts_by_digest = BTreeMap::new();
        for receipt in proposal_receipts {
            if proposal_receipts_by_digest
                .insert(receipt.proposal_digest.as_str().to_owned(), receipt)
                .is_some()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: duplicate identity anchor proposal receipt".to_owned(),
                ));
            }
        }
        let record_count = records.len();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
                // Own every Realm/actor stream this unit writes before reading
                // it back. `commit_event_batch` takes the same keys, so the two
                // commit paths exclude each other exactly where they touch the
                // same rows. Keys are deduplicated and ordered so concurrent
                // units can never acquire them in opposite orders.
                let mut lock_keys = records
                    .iter()
                    .filter_map(|record| {
                        record
                            .realm_id
                            .as_deref()
                            .map(|realm_id| realm_actor_lock_key(realm_id, &record.actor_id))
                    })
                    .collect::<Vec<_>>();
                if let Some(slot) = reanchor_slot.as_ref() {
                    // The re-anchor slot scan spans the actor's whole history,
                    // so it must also own the Realm/actor stream the re-anchor
                    // Event itself belongs to even when that record is absent.
                    lock_keys.extend(records.iter().filter_map(|record| {
                        record
                            .realm_id
                            .as_deref()
                            .map(|realm_id| realm_actor_lock_key(realm_id, &slot.actor_id))
                    }));
                }
                lock_keys.sort_unstable();
                lock_keys.dedup();
                for lock_key in &lock_keys {
                    lock_realm_actor(conn, lock_key).await?;
                }
                let reanchor_conflict = if let Some(slot) = reanchor_slot.as_ref() {
                    let existing = sql_query(
                        "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
                         FROM canonical_events WHERE actor_id = $1 AND kind = 'ak.device.reanchor'",
                    )
                    .bind::<Text, _>(&slot.actor_id)
                    .load::<CanonicalEventRow>(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?
                    .into_iter()
                    .map(CanonicalEventRecord::from)
                    .collect::<Vec<_>>();
                    identity_anchor_slot_conflicts(existing.iter(), slot)
                } else {
                    false
                };
                if !identity_anchor_receipt_cardinality_is_valid(
                    record_count,
                    proposal_receipts_by_digest.len(),
                    reanchor_conflict,
                ) {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: identity anchor receipt cardinality mismatch".to_owned(),
                    )
                    .into());
                }
                if let Some(frontier_cas) = frontier_cas {
                    assert_identity_anchor_frontier(conn, &frontier_cas).await.map_err(PersistenceError::database)?;
                }
                for record in records {
                    insert_canonical_event(conn, &record).await.map_err(PersistenceError::database)?;
                    if !reanchor_conflict {
                        insert_pending_control_event(
                            conn,
                            &record,
                            proposal_receipts_by_digest.get(&record.canonical_digest),
                        )
                        .await?;
                    }
                }
                if !reanchor_conflict
                    && let Some(device) = device
                {
                    sql_query(
                        "INSERT INTO devices (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                         ON CONFLICT (actor_id, device_id) DO UPDATE SET payload = EXCLUDED.payload, \
                         verification_state = EXCLUDED.verification_state, updated_at = EXCLUDED.updated_at, revoked_at = EXCLUDED.revoked_at",
                    )
                    .bind::<SqlUuid, _>(Uuid::now_v7())
                    .bind::<Text, _>(&device.actor)
                    .bind::<Text, _>(&device.device_id)
                    .bind::<Jsonb, _>(&device.payload)
                    .bind::<Text, _>(&device.verification_state)
                    .bind::<Timestamptz, _>(device.created_at)
                    .bind::<Timestamptz, _>(device.updated_at)
                    .bind::<Nullable<Timestamptz>, _>(device.revoked_at)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                }
                if !reanchor_conflict
                    && let Some(receipt) = receipt
                {
                    insert_event_batch_receipt(conn, &receipt).await.map_err(PersistenceError::database)?;
                }
                if !reanchor_conflict {
                    for evidence in publication_evidence {
                        let lease = serde_json::to_value(&evidence.authorization_lease)
                            .map_err(|error| PersistenceError::Internal(format!(
                                "failed to encode authorization_lease: {error}"
                            )))?;
                        let ingress_receipt = serde_json::to_value(&evidence.ingress_receipt)
                            .map_err(|error| PersistenceError::Internal(format!(
                                "failed to encode ingress_receipt: {error}"
                            )))?;
                        sql_query(
                            "INSERT INTO publication_evidence \
                             (event_digest, realm_id, authorization_lease, ingress_receipt, created_at) \
                             VALUES ($1, $2, $3, $4, NOW()) \
                             ON CONFLICT (event_digest) DO NOTHING",
                        )
                        .bind::<Text, _>(&evidence.event_digest)
                        .bind::<Text, _>(&evidence.realm_id)
                        .bind::<Jsonb, _>(&lease)
                        .bind::<Jsonb, _>(&ingress_receipt)
                        .execute(&mut *conn)
                        .await
                        .map_err(PersistenceError::database)?;
                    }
                    // A quarantined re-anchor conflict is not accepted locally,
                    // so it owes no peer anything; every other outcome commits
                    // its delivery intents right here.
                    for delivery in outbox {
                        insert_federation_outbox_row(conn, &delivery).await?;
                    }
                }
            Ok(IdentityAnchorCommitOutcome {
                reanchor_conflict,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<EventBatchReceipt>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id = ids::typed_uuid_part_expect_internal(event_id);
        let rows = sql_query(
            "SELECT schema, id, issuer, scope, frontier, events, created_at, proofs \
             FROM event_batch_receipts WHERE event_ids @> ARRAY[$1]::uuid[] ORDER BY created_at, id",
        )
        .bind::<SqlUuid, _>(event_id)
        .load::<EventBatchReceiptRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(EventBatchReceipt::try_from).collect()
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id_uuid = ids::typed_uuid_part_expect_internal(event_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE id = $1",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .get_result::<CanonicalEventRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(CanonicalEventRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id_uuid = ids::typed_uuid_part_expect_internal(event_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(event_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::database)
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT MAX(actor_seq) AS max_seq FROM canonical_events WHERE actor_id = $1")
            .bind::<Text, _>(actor_id)
            .get_result::<MaxSeqRow>(&mut *conn)
            .await
            .map(|row| row.max_seq.map(|n| n.max(0) as u64))
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        sql_query(
            "SELECT COUNT(*)::bigint AS event_count, \
             COALESCE(SUM(OCTET_LENGTH(canonical_bytes)), 0)::bigint AS canonical_bytes \
             FROM canonical_events WHERE realm_id = $1",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .get_result::<RealmEventStatsRow>(&mut *conn)
        .await
        .map(|row| RealmEventStats {
            count: row.event_count.max(0) as u64,
            canonical_bytes: row.canonical_bytes.max(0) as u64,
        })
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE actor_id = $1 ORDER BY actor_seq ASC, received_at ASC, id ASC",
        )
        .bind::<Text, _>(actor_id)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm_actor(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE realm_id = $1 AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(actor_id)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn peer_authz_state_records(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE kind IN ('ak.member.state', 'ak.circle.member.state', 'ak.invite.create', 'ak.invite.accept') \
                OR (envelope #> '{payload,sync_endpoints}') IS NOT NULL \
                OR (envelope #> '{payload,object,sync_endpoints}') IS NOT NULL \
                OR (envelope #> '{payload,patch,sync_endpoints}') IS NOT NULL \
             ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn peer_events_query_page(
        &self,
        query: &PeerEventsPageQuery,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_ids = query
            .realms
            .iter()
            .map(|realm_id| {
                ids::parse_typed_uuid(realm_id, "realm").ok_or_else(|| {
                    PersistenceError::Internal(format!("invalid peer events realm id: {realm_id}"))
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        let cursor_id = match query.cursor_event_id.as_deref() {
            Some(event_id) => ids::parse_typed_uuid(event_id, "event").ok_or_else(|| {
                PersistenceError::Internal(format!(
                    "invalid peer events cursor event id: {event_id}"
                ))
            })?,
            None => Uuid::nil(),
        };
        let no_cursor = query.cursor_event_id.is_none();
        let kind_filter = query.kind_filter.as_deref().unwrap_or_default();
        let limit = query.limit.min(i64::MAX as usize) as i64;
        let page_sql = if query.backward {
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) < (SELECT received_at, id FROM canonical_events WHERE id = $8)) \
             ORDER BY received_at DESC, id DESC \
             LIMIT $9"
        } else {
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) > (SELECT received_at, id FROM canonical_events WHERE id = $8)) \
             ORDER BY received_at ASC, id ASC \
             LIMIT $9"
        };
        sql_query(page_sql)
            .bind::<Bool, _>(realm_ids.is_empty())
            .bind::<Array<SqlUuid>, _>(realm_ids)
            .bind::<Bool, _>(query.actors.is_empty())
            .bind::<Array<Text>, _>(query.actors.clone())
            .bind::<Bool, _>(query.kind_filter.is_none())
            .bind::<Text, _>(kind_filter)
            .bind::<Bool, _>(no_cursor)
            .bind::<SqlUuid, _>(cursor_id)
            .bind::<BigInt, _>(limit)
            .load::<CanonicalEventRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
            .map_err(PersistenceError::database)
    }

    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE realm_id = $1 ORDER BY received_at DESC, id DESC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}

#[cfg(test)]
mod identity_anchor_receipt_tests {
    use super::identity_anchor_receipt_cardinality_is_valid;

    #[test]
    fn closed_anchor_units_accept_no_proposal_receipts() {
        assert!(identity_anchor_receipt_cardinality_is_valid(2, 0, false));
        assert!(identity_anchor_receipt_cardinality_is_valid(2, 2, false));
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 1, false));
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 3, false));
    }

    #[test]
    fn reanchor_conflict_cannot_attach_proposal_receipts() {
        assert!(identity_anchor_receipt_cardinality_is_valid(2, 0, true));
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 2, true));
    }
}
