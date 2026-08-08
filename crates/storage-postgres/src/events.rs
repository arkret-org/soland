use std::collections::BTreeMap;

use diesel::sql_types::SmallInt;

use super::{
    Array, AsyncConnection, AsyncPgConnection, BigInt, Binary, Bool, CanonicalEventRecord,
    DeviceBootstrapDecisionWriteOutcome, DeviceInventoryRecord,
    DirectConversationFoundingCommitOutcome, DirectConversationFoundingSlotRecord,
    EventBatchReceipt, EventStore, ExistsRow, FederationOutboxRecord, IdentityAnchorCommitOutcome,
    IdentityAnchorFrontierCas, IdentityAnchorReanchorSlot, Jsonb, MaxSeqRow, Nullable,
    OptionalExtension, PeerEventsPageQuery, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, PublicationEvidenceRecord, QueryableByName, RealmEventStats, RunQueryDsl,
    SqlUuid, Text, Timestamptz, Uuid, Value, async_trait, device_bootstrap_receipt_time_is_valid,
    identity_anchor_slot_conflicts, ids, pg_conn, same_accepted_device_bootstrap_binding,
    sql_query,
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
        && matches!(
            info.constraint_name(),
            Some(
                "canonical_events_id_key"
                    | "canonical_events_identity_key"
                    | "canonical_events_id_digest_check"
            )
        )
    {
        return PersistenceError::Conflict("event_hash_collision".to_owned());
    }
    PersistenceError::database(error)
}
#[derive(QueryableByName)]
pub(crate) struct CanonicalEventRow {
    #[diesel(sql_type = Binary)]
    id: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    pub(crate) digest_suite: i16,
    #[diesel(sql_type = Binary)]
    pub(crate) digest: Vec<u8>,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    schema_id: String,
    #[diesel(sql_type = Binary)]
    pub(crate) canonical_bytes: Vec<u8>,
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
struct PkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}
#[derive(QueryableByName)]
struct TextIdRow {
    #[diesel(sql_type = Text)]
    id: String,
}

#[derive(QueryableByName)]
struct DirectConversationFoundingSlotRow {
    #[diesel(sql_type = Text)]
    founder_id: String,
    #[diesel(sql_type = Text)]
    trust_domain_id: String,
    #[diesel(sql_type = Text)]
    pair_key: String,
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    main_strand_id: String,
    #[diesel(sql_type = Jsonb)]
    event_ids: Value,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Binary)]
    receipt_bytes: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct DeviceBootstrapDecisionRow {
    #[diesel(sql_type = Text)]
    account_authority_id: String,
    #[diesel(sql_type = Text)]
    transaction_id: String,
    #[diesel(sql_type = Text)]
    decision: String,
    #[diesel(sql_type = Text)]
    binding_digest: String,
    #[diesel(sql_type = Text)]
    canonical_outcome_bytes: String,
    #[diesel(sql_type = Jsonb)]
    receipt: Value,
}

impl TryFrom<DeviceBootstrapDecisionRow>
    for arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRecord
{
    type Error = PersistenceError;

    fn try_from(row: DeviceBootstrapDecisionRow) -> Result<Self, Self::Error> {
        use arkret_models_collaboration::contact_operations::DeviceBootstrapDecision;
        let decision = match row.decision.as_str() {
            "accepted" => DeviceBootstrapDecision::Accepted,
            "cancelled" => DeviceBootstrapDecision::Cancelled,
            "expired" => DeviceBootstrapDecision::Expired,
            other => {
                return Err(PersistenceError::SchemaViolation(format!(
                    "stored device bootstrap decision is invalid: {other}"
                )));
            }
        };
        let record = Self {
            account_authority_id: arkret_identifiers::Did::new(row.account_authority_id)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            transaction_id: arkret_wire::ProtocolOpaqueId::new(row.transaction_id)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            decision,
            binding_digest: arkret_identifiers::Hash::new(row.binding_digest)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            canonical_outcome_bytes: arkret_wire::Base64UrlString::new(row.canonical_outcome_bytes)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            receipt: serde_json::from_value(row.receipt).map_err(PersistenceError::database)?,
        };
        record
            .decode_and_validate_outcome()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        Ok(record)
    }
}

fn decision_name(
    decision: arkret_models_collaboration::contact_operations::DeviceBootstrapDecision,
) -> &'static str {
    use arkret_models_collaboration::contact_operations::DeviceBootstrapDecision;
    match decision {
        DeviceBootstrapDecision::Accepted => "accepted",
        DeviceBootstrapDecision::Cancelled => "cancelled",
        DeviceBootstrapDecision::Expired => "expired",
    }
}

async fn insert_device_bootstrap_decision(
    conn: &mut AsyncPgConnection,
    record: &arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRecord,
) -> Result<bool, PgTransactionError> {
    record
        .decode_and_validate_outcome()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if !device_bootstrap_receipt_time_is_valid(record) {
        return Err(PersistenceError::SchemaViolation(
            "device bootstrap decision receipt violates its deadline".to_owned(),
        )
        .into());
    }
    let receipt = serde_json::to_value(&record.receipt).map_err(|error| {
        PersistenceError::Internal(format!(
            "failed to encode bootstrap decision receipt: {error}"
        ))
    })?;
    let inserted = sql_query(
        "INSERT INTO device_bootstrap_decisions \
         (account_authority_id, transaction_id, decision, binding_digest, canonical_outcome_bytes, receipt, decided_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(record.account_authority_id.as_str())
    .bind::<Text, _>(record.transaction_id.as_str())
    .bind::<Text, _>(decision_name(record.decision))
    .bind::<Text, _>(record.binding_digest.as_str())
    .bind::<Text, _>(record.canonical_outcome_bytes.as_str())
    .bind::<Jsonb, _>(&receipt)
    .bind::<Timestamptz, _>(record.receipt.decided_at)
    .execute(conn)
    .await?;
    Ok(inserted == 1)
}

async fn load_device_bootstrap_decision(
    conn: &mut AsyncPgConnection,
    account_authority_id: &str,
    transaction_id: &str,
) -> Result<
    Option<arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRecord>,
    PgTransactionError,
> {
    sql_query(
        "SELECT account_authority_id, transaction_id, decision, binding_digest, canonical_outcome_bytes, receipt \
         FROM device_bootstrap_decisions WHERE account_authority_id = $1 AND transaction_id = $2",
    )
    .bind::<Text, _>(account_authority_id)
    .bind::<Text, _>(transaction_id)
    .get_result::<DeviceBootstrapDecisionRow>(conn)
    .await
    .optional()?
    .map(TryInto::try_into)
    .transpose()
    .map_err(Into::into)
}

async fn lock_device_bootstrap_decision_fence(
    conn: &mut AsyncPgConnection,
    account_authority_id: &str,
    transaction_id: &str,
) -> Result<(), PgTransactionError> {
    // The row may not exist yet, so a row lock cannot serialize the initial
    // accepted-vs-negative race. Both writers take this transaction-scoped
    // advisory lock before observing absence or installing the unique row.
    let lock_key = format!("{account_authority_id}:{transaction_id}");
    sql_query("SELECT TRUE AS present FROM pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(lock_key)
        .get_result::<ExistsRow>(conn)
        .await?;
    Ok(())
}

impl TryFrom<DirectConversationFoundingSlotRow> for DirectConversationFoundingSlotRecord {
    type Error = PersistenceError;

    fn try_from(row: DirectConversationFoundingSlotRow) -> Result<Self, Self::Error> {
        Ok(Self {
            founder_id: row.founder_id,
            trust_domain_id: row.trust_domain_id,
            pair_key: row.pair_key,
            founding_unit_digest: row.founding_unit_digest,
            realm_id: row.realm_id,
            main_strand_id: row.main_strand_id,
            event_ids: serde_json::from_value(row.event_ids).map_err(PersistenceError::database)?,
            idempotency_key: row.idempotency_key,
            receipt_bytes: row.receipt_bytes,
            accepted_at: row.accepted_at,
        })
    }
}
#[derive(QueryableByName)]
struct StoredEventIdentityRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
    #[diesel(sql_type = Binary)]
    digest: Vec<u8>,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    schema_id: String,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalInsertOutcome {
    Inserted(i64),
    Replay(i64),
    Quarantined,
    Collision,
}

enum StoreTransactionOutcome<T> {
    Committed(T),
    Collision,
}

#[derive(QueryableByName)]
struct EventPreflightRow {
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    state: String,
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

pub(crate) async fn insert_canonical_event(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
) -> PersistenceResult<CanonicalInsertOutcome> {
    let identity = ids::validated_event_identity_parts(
        &record.event_id,
        &record.canonical_digest,
        &record.canonical_bytes,
    )?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind::<Binary, _>(identity.id.to_vec())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let existing = sql_query(
        "SELECT pk, digest_suite, digest, canonical_bytes, state, actor_id, actor_seq, realm_id, kind, schema_id, envelope, received_at FROM canonical_events WHERE id = $1",
    )
    .bind::<Binary, _>(identity.id.to_vec())
    .load::<StoredEventIdentityRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    // `canonical_events.id` is UNIQUE, so this is at most one row.
    if let Some(stored) = existing.into_iter().next() {
        if stored.digest_suite != i16::from(identity.digest_suite)
            || stored.digest != identity.digest
        {
            return Err(PersistenceError::Conflict(
                "event_id_digest_mismatch".to_owned(),
            ));
        }
        if stored.canonical_bytes == record.canonical_bytes {
            return Ok(if stored.state == "accepted" {
                CanonicalInsertOutcome::Replay(stored.pk)
            } else {
                CanonicalInsertOutcome::Quarantined
            });
        }
        for (
            canonical_bytes,
            actor_id,
            actor_seq,
            realm_id,
            kind,
            schema_id,
            envelope,
            received_at,
        ) in [
            (
                stored.canonical_bytes,
                stored.actor_id,
                stored.actor_seq,
                stored.realm_id,
                stored.kind,
                stored.schema_id,
                stored.envelope,
                stored.received_at,
            ),
            (
                record.canonical_bytes.clone(),
                record.actor_id.clone(),
                record.actor_seq as i64,
                record.realm_id.clone(),
                record.kind.clone(),
                record.schema_id.clone(),
                record.envelope.clone(),
                record.received_at,
            ),
        ] {
            sql_query(
                "INSERT INTO event_collision_variants \
                 (event_pk, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (event_pk, canonical_bytes) DO NOTHING",
            )
            .bind::<BigInt, _>(stored.pk)
            .bind::<Text, _>(actor_id)
            .bind::<BigInt, _>(actor_seq)
            .bind::<Nullable<Text>, _>(realm_id)
            .bind::<Text, _>(kind)
            .bind::<Text, _>(schema_id)
            .bind::<Binary, _>(canonical_bytes)
            .bind::<Jsonb, _>(envelope)
            .bind::<Timestamptz, _>(received_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        sql_query("UPDATE canonical_events SET state = 'quarantined' WHERE pk = $1")
            .bind::<BigInt, _>(stored.pk)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM projection_events WHERE event_pk = $1 AND NOT EXISTS ( \
               SELECT 1 FROM state_control_events \
               WHERE event_digest = $2 AND sealed_by IS NOT NULL \
             )",
        )
        .bind::<BigInt, _>(stored.pk)
        .bind::<Text, _>(&record.canonical_digest)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE federation_outbox SET state = 'policy_suppressed', \
             last_error_code = 'witness_disagreement', lease_owner = NULL, lease_token = NULL, \
             lease_expires_at = NULL, completed_at = COALESCE(completed_at, created_at) \
             WHERE (event_pk = $1 OR id IN ( \
               SELECT outbox_id FROM event_federation_outbox WHERE event_pk = $1 \
             )) AND state IN ('pending', 'leased')",
        )
        .bind::<BigInt, _>(stored.pk)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM state_control_events WHERE event_digest = $1 AND sealed_by IS NULL")
            .bind::<Text, _>(&record.canonical_digest)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        return Ok(CanonicalInsertOutcome::Collision);
    }
    let realm_pk =
        crate::realm_identity::ensure_optional_realm_pk(conn, record.realm_id.as_deref()).await?;
    sql_query(
        "INSERT INTO canonical_events \
         (id, digest_suite, digest, actor_id, actor_seq, realm_id, realm_pk, kind, schema_id, canonical_bytes, envelope, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING pk",
    )
    .bind::<Binary, _>(identity.id.to_vec())
    .bind::<SmallInt, _>(i16::from(identity.digest_suite))
    .bind::<Binary, _>(identity.digest.to_vec())
    .bind::<Text, _>(&record.actor_id)
    .bind::<BigInt, _>(record.actor_seq as i64)
    .bind::<Nullable<Text>, _>(record.realm_id.as_deref())
    .bind::<Nullable<BigInt>, _>(realm_pk)
    .bind::<Text, _>(&record.kind)
    .bind::<Text, _>(&record.schema_id)
    .bind::<Binary, _>(&record.canonical_bytes)
    .bind::<Jsonb, _>(&record.envelope)
    .bind::<Timestamptz, _>(record.received_at)
    .get_result::<PkRow>(conn)
    .await
    .map(|row| CanonicalInsertOutcome::Inserted(row.pk))
    .map_err(map_canonical_event_put_error)
}

async fn preflight_canonical_events(
    conn: &mut AsyncPgConnection,
    records: &[CanonicalEventRecord],
) -> PersistenceResult<bool> {
    let mut ordered = records.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.event_id.cmp(&right.event_id));
    for record in &ordered {
        let identity = ids::validated_event_identity_parts(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
        )?;
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind::<Binary, _>(identity.id.to_vec())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    let mut incoming = BTreeMap::<String, &CanonicalEventRecord>::new();
    for record in ordered {
        let identity = ids::validated_event_identity_parts(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
        )?;
        let stored = sql_query("SELECT canonical_bytes, state FROM canonical_events WHERE id = $1")
            .bind::<Binary, _>(identity.id.to_vec())
            .get_result::<EventPreflightRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        if let Some(stored) = stored {
            if stored.canonical_bytes != record.canonical_bytes {
                debug_assert_eq!(
                    insert_canonical_event(conn, record).await?,
                    CanonicalInsertOutcome::Collision
                );
                return Ok(true);
            }
            if stored.state == "quarantined" {
                return Ok(true);
            }
            continue;
        }
        if let Some(previous) = incoming.get(&record.event_id) {
            if previous.canonical_bytes != record.canonical_bytes {
                debug_assert!(matches!(
                    insert_canonical_event(conn, previous).await?,
                    CanonicalInsertOutcome::Inserted(_)
                ));
                debug_assert_eq!(
                    insert_canonical_event(conn, record).await?,
                    CanonicalInsertOutcome::Collision
                );
                return Ok(true);
            }
        } else {
            incoming.insert(record.event_id.clone(), record);
        }
    }
    Ok(false)
}

async fn bind_event_outbox_rows(
    conn: &mut AsyncPgConnection,
    event_pks: &[i64],
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<()> {
    let outbox_id =
        sql_query("SELECT id FROM federation_outbox WHERE peer_id = $1 AND idempotency_key = $2")
            .bind::<Text, _>(&delivery.peer_did)
            .bind::<Text, _>(&delivery.idempotency_key)
            .get_result::<TextIdRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .id;
    for event_pk in event_pks {
        sql_query(
            "INSERT INTO event_federation_outbox (event_pk, outbox_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind::<BigInt, _>(*event_pk)
        .bind::<Text, _>(&outbox_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}

async fn insert_pending_control_event(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
    control_proposal_ack: Option<&arkret_wire::ControlProposalAck>,
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
    if let Some(control_proposal_ack) = control_proposal_ack {
        if control_proposal_ack.proposal_digest.as_str() != digest
            || control_proposal_ack.realm_id != event.realm_id
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: Control Proposal Ack does not bind anchor Event".to_owned(),
            ));
        }
        control_proposal_ack
            .validate_protocol_bounds()
            .map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: invalid Control Proposal Ack: {error}"
                ))
            })?;
    }
    let control_proposal_ack = control_proposal_ack
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| {
            PersistenceError::Internal(format!("Control Proposal Ack encoding failed: {error}"))
        })?;
    sql_query(
        "INSERT INTO state_control_events \
         (event_digest, realm_id, event_json, control_proposal_ack) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (event_digest) DO UPDATE SET \
           control_proposal_ack = COALESCE( \
             state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
           ) \
         WHERE state_control_events.realm_id = EXCLUDED.realm_id \
           AND state_control_events.event_json = EXCLUDED.event_json \
           AND (state_control_events.control_proposal_ack IS NULL \
             OR EXCLUDED.control_proposal_ack IS NULL \
             OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
    )
    .bind::<Text, _>(&digest)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(&record.envelope)
    .bind::<Nullable<Jsonb>, _>(control_proposal_ack.as_ref())
    .execute(conn)
    .await
    .map_err(PersistenceError::database)
    .and_then(|affected| {
        if affected == 0 {
            Err(PersistenceError::Conflict(
                "duplicate_conflict: pending Control Move has different canonical bytes or Control Proposal Ack"
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
    let receipt_pk = sql_query(
        "INSERT INTO event_batch_receipts \
         (schema, id, issuer, scope, frontier, events, created_at, proofs) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING pk",
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
    .get_result::<PkRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .pk;
    for event in &receipt.events {
        let (digest_suite, digest) = match event {
            arkret_wire::EventBatchReceiptEvent::Item(item) => {
                let identity =
                    ids::event_identity_parts(item.event_id.as_str(), item.event_digest.as_str())?;
                (identity.digest_suite, identity.digest)
            }
            arkret_wire::EventBatchReceiptEvent::Digest(digest) => {
                ids::parse_event_digest(digest.as_str()).ok_or_else(|| {
                    PersistenceError::SchemaViolation(format!(
                        "malformed Event Batch Receipt digest: {:?}",
                        digest.as_str()
                    ))
                })?
            }
        };
        let event_pk =
            sql_query("SELECT pk FROM canonical_events WHERE state = 'accepted' AND digest_suite = $1 AND digest = $2")
                .bind::<SmallInt, _>(i16::from(digest_suite))
                .bind::<Binary, _>(digest.to_vec())
                .get_result::<PkRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                "schema_violation: Event Batch Receipt references an unknown Event identity"
                    .to_owned(),
            )
                })?
                .pk;
        sql_query(
            "INSERT INTO event_batch_receipt_events (receipt_pk, event_pk) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind::<BigInt, _>(receipt_pk)
        .bind::<BigInt, _>(event_pk)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}
impl From<CanonicalEventRow> for CanonicalEventRecord {
    fn from(row: CanonicalEventRow) -> Self {
        let id: [u8; ids::EVENT_ID_BYTES] = row
            .id
            .try_into()
            .expect("canonical_events.id must be 33 bytes");
        let digest: [u8; ids::EVENT_DIGEST_BYTES] = row
            .digest
            .try_into()
            .expect("canonical_events.digest must be 32 bytes");
        Self {
            event_id: ids::format_event_id(&id),
            actor_id: row.actor_id,
            actor_seq: row.actor_seq.max(0) as u64,
            realm_id: row.realm_id,
            kind: row.kind,
            schema_id: row.schema_id,
            canonical_digest: ids::format_event_digest(row.digest_suite as u8, &digest)
                .expect("canonical_events.digest_suite must be active"),
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        }
    }
}

fn identity_anchor_receipt_cardinality_is_valid(
    record_count: usize,
    control_proposal_ack_count: usize,
    reanchor_conflict: bool,
) -> bool {
    if reanchor_conflict {
        control_proposal_ack_count == 0
    } else {
        control_proposal_ack_count == record_count
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let outcome = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                insert_canonical_event(conn, &record)
                    .await
                    .map_err(PgTransactionError::from)
            })
            .await
            .map_err(PgTransactionError::into_persistence)?;
        if matches!(
            outcome,
            CanonicalInsertOutcome::Collision | CanonicalInsertOutcome::Quarantined
        ) {
            Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    async fn collision_variants(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        sql_query(
            "SELECT parent.id, parent.digest_suite, parent.digest, variant.actor_id, variant.actor_seq, \
                    variant.realm_id, variant.kind, variant.schema_id, variant.canonical_bytes, \
                    variant.envelope, variant.received_at \
             FROM event_collision_variants variant \
             JOIN canonical_events parent ON parent.pk = variant.event_pk \
             WHERE parent.id = $1 ORDER BY variant.pk",
        )
        .bind::<Binary, _>(event_id.to_vec())
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<()> {
        let mut acks = BTreeMap::new();
        for ack in control_proposal_acks {
            if acks
                .insert(ack.proposal_digest.as_str().to_owned(), ack)
                .is_some()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: duplicate Realm bootstrap Control Proposal Ack".to_owned(),
                ));
            }
        }
        if acks.len() != records.len() {
            return Err(PersistenceError::Conflict(
                "schema_violation: Realm bootstrap Control Proposal Ack cardinality mismatch"
                    .to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let transaction_outcome = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                if preflight_canonical_events(conn, &records).await? {
                    return Ok(StoreTransactionOutcome::Collision);
                }
                let mut event_pks = Vec::with_capacity(records.len());
                for record in records {
                    let event_pk = match insert_canonical_event(conn, &record).await? {
                        CanonicalInsertOutcome::Inserted(pk)
                        | CanonicalInsertOutcome::Replay(pk) => pk,
                        CanonicalInsertOutcome::Collision | CanonicalInsertOutcome::Quarantined => {
                            unreachable!("batch collision was handled by preflight")
                        }
                    };
                    event_pks.push(event_pk);
                    let control_proposal_ack =
                        acks.get(&record.canonical_digest).ok_or_else(|| {
                            PersistenceError::Conflict(
                        "schema_violation: Realm bootstrap Event is missing Control Proposal Ack"
                            .to_owned(),
                    )
                        })?;
                    insert_pending_control_event(conn, &record, Some(control_proposal_ack)).await?;
                }
                // Same transaction as the Events: the delivery intent for a Realm
                // genesis unit is not a post-commit best-effort follow-up.
                for delivery in outbox {
                    insert_federation_outbox_row(conn, &delivery).await?;
                    bind_event_outbox_rows(conn, &event_pks, &delivery).await?;
                }
                Ok(StoreTransactionOutcome::Committed(()))
            })
            .await
            .map_err(PgTransactionError::into_persistence)?;
        match transaction_outcome {
            StoreTransactionOutcome::Committed(()) => Ok(()),
            StoreTransactionOutcome::Collision => Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            )),
        }
    }

    async fn put_direct_conversation_founding_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        slot: DirectConversationFoundingSlotRecord,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome> {
        if records.len() != 3
            || slot.event_ids
                != records
                    .iter()
                    .map(|record| record.event_id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(PersistenceError::Conflict(
                "direct_conversation_founding_unit_invalid".to_owned(),
            ));
        }
        let mut acks = BTreeMap::new();
        for ack in control_proposal_acks {
            if acks
                .insert(ack.proposal_digest.as_str().to_owned(), ack)
                .is_some()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: duplicate Direct Conversation founding Control Proposal Ack"
                        .to_owned(),
                ));
            }
        }
        if acks.len() != records.len() {
            return Err(PersistenceError::Conflict(
                "schema_violation: Direct Conversation founding Control Proposal Ack cardinality mismatch"
                    .to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(format!(
                    "direct-conversation-founding-idempotency\n{}\n{}",
                    slot.founder_id, slot.idempotency_key
                ))
                .execute(&mut *conn)
                .await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(format!(
                    "direct-conversation-founding-slot\n{}\n{}\n{}",
                    slot.founder_id, slot.trust_domain_id, slot.pair_key
                ))
                .execute(&mut *conn)
                .await?;
            let existing = sql_query(
                "SELECT founder_id, trust_domain_id, pair_key, founding_unit_digest, realm_id, \
                        main_strand_id, event_ids, idempotency_key, receipt_bytes, accepted_at \
                 FROM direct_conversation_founding_slots \
                 WHERE (founder_id = $1 AND idempotency_key = $2) \
                    OR (founder_id = $1 AND trust_domain_id = $3 AND pair_key = $4) \
                 ORDER BY CASE WHEN idempotency_key = $2 THEN 0 ELSE 1 END LIMIT 1 FOR UPDATE",
            )
            .bind::<Text, _>(&slot.founder_id)
            .bind::<Text, _>(&slot.idempotency_key)
            .bind::<Text, _>(&slot.trust_domain_id)
            .bind::<Text, _>(&slot.pair_key)
            .get_result::<DirectConversationFoundingSlotRow>(conn)
            .await
            .optional()?;
            if let Some(existing) = existing {
                let existing = DirectConversationFoundingSlotRecord::try_from(existing)?;
                if existing.idempotency_key == slot.idempotency_key
                    && existing.founding_unit_digest == slot.founding_unit_digest
                {
                    return Ok(DirectConversationFoundingCommitOutcome::ExactRetry(existing));
                }
                sql_query(
                    "INSERT INTO direct_conversation_founding_equivocations \
                     (founder_id, trust_domain_id, pair_key, committed_unit_digest, \
                      conflicting_unit_digest, idempotency_key) VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind::<Text, _>(&slot.founder_id)
                .bind::<Text, _>(&slot.trust_domain_id)
                .bind::<Text, _>(&slot.pair_key)
                .bind::<Text, _>(&existing.founding_unit_digest)
                .bind::<Text, _>(&slot.founding_unit_digest)
                .bind::<Text, _>(&slot.idempotency_key)
                .execute(conn)
                .await?;
                return Ok(if existing.idempotency_key == slot.idempotency_key {
                    DirectConversationFoundingCommitOutcome::IdempotencyConflict
                } else {
                    DirectConversationFoundingCommitOutcome::SlotConflict(existing)
                });
            }
            if preflight_canonical_events(conn, &records).await? {
                return Err(PersistenceError::Conflict("event_hash_collision".to_owned()).into());
            }
            let mut event_pks = Vec::with_capacity(records.len());
            for record in records {
                let event_pk = match insert_canonical_event(conn, &record).await? {
                    CanonicalInsertOutcome::Inserted(pk) | CanonicalInsertOutcome::Replay(pk) => pk,
                    CanonicalInsertOutcome::Collision | CanonicalInsertOutcome::Quarantined => {
                        unreachable!("founding collision was handled by preflight")
                    }
                };
                event_pks.push(event_pk);
                let ack = acks.get(&record.canonical_digest).ok_or_else(|| {
                    PersistenceError::Conflict(
                        "schema_violation: Direct Conversation founding Event is missing Control Proposal Ack"
                            .to_owned(),
                    )
                })?;
                insert_pending_control_event(conn, &record, Some(ack)).await?;
            }
            let event_ids = serde_json::to_value(&slot.event_ids).map_err(PersistenceError::database)?;
            sql_query(
                "INSERT INTO direct_conversation_founding_slots \
                 (founder_id, trust_domain_id, pair_key, founding_unit_digest, realm_id, \
                  main_strand_id, event_ids, idempotency_key, receipt_bytes, accepted_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind::<Text, _>(&slot.founder_id)
            .bind::<Text, _>(&slot.trust_domain_id)
            .bind::<Text, _>(&slot.pair_key)
            .bind::<Text, _>(&slot.founding_unit_digest)
            .bind::<Text, _>(&slot.realm_id)
            .bind::<Text, _>(&slot.main_strand_id)
            .bind::<Jsonb, _>(event_ids)
            .bind::<Text, _>(&slot.idempotency_key)
            .bind::<Binary, _>(&slot.receipt_bytes)
            .bind::<Timestamptz, _>(slot.accepted_at)
            .execute(conn)
            .await?;
            for delivery in outbox {
                insert_federation_outbox_row(conn, &delivery).await?;
                bind_event_outbox_rows(conn, &event_pks, &delivery).await?;
            }
            Ok(DirectConversationFoundingCommitOutcome::Committed)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT founder_id, trust_domain_id, pair_key, founding_unit_digest, realm_id, \
                    main_strand_id, event_ids, idempotency_key, receipt_bytes, accepted_at \
             FROM direct_conversation_founding_slots \
             WHERE founder_id = $1 AND trust_domain_id = $2 AND pair_key = $3",
        )
        .bind::<Text, _>(founder_id)
        .bind::<Text, _>(trust_domain_id)
        .bind::<Text, _>(pair_key)
        .get_result::<DirectConversationFoundingSlotRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(DirectConversationFoundingSlotRecord::try_from)
        .transpose()
    }

    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
        bootstrap_decision: Option<
            arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRecord,
        >,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let mut control_proposal_acks_by_digest = BTreeMap::new();
        for receipt in control_proposal_acks {
            if control_proposal_acks_by_digest
                .insert(receipt.proposal_digest.as_str().to_owned(), receipt)
                .is_some()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: duplicate identity anchor Control Proposal Ack".to_owned(),
                ));
            }
        }
        let record_count = records.len();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let transaction_outcome = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
                if preflight_canonical_events(conn, &records).await? {
                    return Ok(StoreTransactionOutcome::Collision);
                }
                let mut event_pks = Vec::with_capacity(records.len());
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
                    // The replacement digest comparison reads the paired
                    // authorize Event, so both unit kinds must be loaded.
                    let existing = sql_query(
                        "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
                         FROM canonical_events WHERE state = 'accepted' AND actor_id = $1 AND kind IN ('ak.device.reanchor', 'ak.device.authorize')",
                    )
                    .bind::<Text, _>(&slot.actor_id)
                    .load::<CanonicalEventRow>(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?
                    .into_iter()
                    .map(CanonicalEventRecord::from)
                    .collect::<Vec<_>>();
                    identity_anchor_slot_conflicts(&existing.iter().collect::<Vec<_>>(), slot)
                } else {
                    false
                };
                if !identity_anchor_receipt_cardinality_is_valid(
                    record_count,
                    control_proposal_acks_by_digest.len(),
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
                if let Some(record) = bootstrap_decision.as_ref() {
                    lock_device_bootstrap_decision_fence(
                        conn,
                        record.account_authority_id.as_str(),
                        record.transaction_id.as_str(),
                    )
                    .await?;
                    if let Some(existing) = load_device_bootstrap_decision(
                        conn,
                        record.account_authority_id.as_str(),
                        record.transaction_id.as_str(),
                    )
                    .await?
                    {
                        if !same_accepted_device_bootstrap_binding(&existing, record) {
                            return Err(PersistenceError::Conflict(
                                "bootstrap_decision_conflict".to_owned(),
                            ).into());
                        }
                    } else {
                        let eligible = sql_query("SELECT NOW() <= $1 AS present")
                            .bind::<Timestamptz, _>(record.receipt.bootstrap_transaction_expires_at)
                            .get_result::<ExistsRow>(conn)
                            .await?;
                        if record.decision
                            != arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted
                            || !eligible.present
                        {
                            return Err(PersistenceError::Conflict(
                                "bootstrap_decision_conflict: accepted decision is past its deadline"
                                    .to_owned(),
                            )
                            .into());
                        }
                        if !insert_device_bootstrap_decision(conn, record).await? {
                            return Err(PersistenceError::Internal(
                                "bootstrap decision fence was lost while holding its authority lock"
                                    .to_owned(),
                            )
                            .into());
                        }
                    }
                }
                for record in records {
                    let event_pk = match insert_canonical_event(conn, &record).await? {
                        CanonicalInsertOutcome::Inserted(pk) | CanonicalInsertOutcome::Replay(pk) => pk,
                        CanonicalInsertOutcome::Collision | CanonicalInsertOutcome::Quarantined => {
                            unreachable!("batch collision was handled by preflight")
                        }
                    };
                    event_pks.push(event_pk);
                    if !reanchor_conflict {
                        insert_pending_control_event(
                            conn,
                            &record,
                            control_proposal_acks_by_digest.get(&record.canonical_digest),
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
                        bind_event_outbox_rows(conn, &event_pks, &delivery).await?;
                    }
                }
            Ok(StoreTransactionOutcome::Committed(IdentityAnchorCommitOutcome {
                reanchor_conflict,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)?;
        match transaction_outcome {
            StoreTransactionOutcome::Committed(outcome) => Ok(outcome),
            StoreTransactionOutcome::Collision => Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            )),
        }
    }

    async fn device_bootstrap_decision(
        &self,
        account_authority_id: &str,
        transaction_id: &str,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRecord>,
    > {
        let mut conn = pg_conn(&self.pool).await?;
        load_device_bootstrap_decision(&mut conn, account_authority_id, transaction_id)
            .await
            .map_err(PgTransactionError::into_persistence)
    }

    async fn put_device_bootstrap_decision_atomic(
        &self,
        request: &arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
        record: arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRecord,
    ) -> PersistenceResult<DeviceBootstrapDecisionWriteOutcome> {
        request
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        record
            .receipt
            .validate_against(request)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if record.binding_digest != request.decision_request_digest {
            return Err(PersistenceError::SchemaViolation(
                "bootstrap decision row binding_digest does not match request".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_device_bootstrap_decision_fence(
                conn,
                request.account_authority_id.as_str(),
                request.transaction_id.as_str(),
            )
            .await?;
            if let Some(existing) = load_device_bootstrap_decision(
                conn,
                request.account_authority_id.as_str(),
                request.transaction_id.as_str(),
            )
            .await?
            {
                return Ok(DeviceBootstrapDecisionWriteOutcome::Existing(existing));
            }
            let eligible_query = match request.requested_decision {
                arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Cancelled => {
                    "SELECT NOW() < $1 AS present"
                }
                arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Expired => {
                    "SELECT NOW() >= $1 AS present"
                }
            };
            let eligible = sql_query(eligible_query)
                .bind::<Timestamptz, _>(request.bootstrap_transaction_expires_at)
                .get_result::<ExistsRow>(conn)
                .await?;
            if !eligible.present {
                let detail = match request.requested_decision {
                    arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Cancelled => {
                        "bootstrap_decision_conflict: cancellation deadline has elapsed"
                    }
                    arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Expired => {
                        "bootstrap_decision_conflict: bootstrap deadline has not elapsed"
                    }
                };
                    return Err(PersistenceError::Conflict(
                        detail.to_owned(),
                    )
                    .into());
            }
            if !insert_device_bootstrap_decision(conn, &record).await? {
                return Err(PersistenceError::Internal(
                    "bootstrap decision fence was lost while holding its authority lock".to_owned(),
                )
                .into());
            }
            Ok(DeviceBootstrapDecisionWriteOutcome::Inserted)
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
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let event_pk =
            sql_query("SELECT pk FROM canonical_events WHERE state = 'accepted' AND id = $1")
                .bind::<Binary, _>(event_id.to_vec())
                .get_result::<PkRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
        let Some(event_pk) = event_pk.map(|row| row.pk) else {
            return Ok(Vec::new());
        };
        let rows = sql_query(
            "SELECT receipt.schema, receipt.id, receipt.issuer, receipt.scope, receipt.frontier, \
                    receipt.events, receipt.created_at, receipt.proofs \
             FROM event_batch_receipts receipt \
             JOIN event_batch_receipt_events binding ON binding.receipt_pk = receipt.pk \
             WHERE binding.event_pk = $1 ORDER BY receipt.created_at, receipt.pk",
        )
        .bind::<BigInt, _>(event_pk)
        .load::<EventBatchReceiptRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(EventBatchReceipt::try_from).collect()
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        sql_query(
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE state = 'accepted' AND id = $1",
        )
        .bind::<Binary, _>(event_id.to_vec())
        .get_result::<CanonicalEventRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(CanonicalEventRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE state = 'accepted' AND id = $1) AS present")
            .bind::<Binary, _>(event_id.to_vec())
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::database)
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT MAX(actor_seq) AS max_seq FROM canonical_events WHERE state = 'accepted' AND actor_id = $1")
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
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE state = 'accepted' ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT COUNT(*)::bigint AS event_count, \
             COALESCE(SUM(OCTET_LENGTH(canonical_bytes)), 0)::bigint AS canonical_bytes \
             FROM canonical_events WHERE state = 'accepted' AND realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1)",
        )
        .bind::<Text, _>(realm_id)
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
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE state = 'accepted' AND actor_id = $1 ORDER BY actor_seq ASC, received_at ASC, id ASC",
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
        sql_query(
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE state = 'accepted' AND realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
        )
        .bind::<Text, _>(realm_id)
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
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE state = 'accepted' AND ( \
                kind IN ('ak.member.state', 'ak.circle.member.state', 'ak.invite.create', 'ak.invite.accept') \
                OR (envelope #> '{payload,sync_endpoints}') IS NOT NULL \
                OR (envelope #> '{payload,object,sync_endpoints}') IS NOT NULL \
                OR (envelope #> '{payload,patch,sync_endpoints}') IS NOT NULL) \
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
        if let Some(cursor) = query.cursor_event_id.as_deref()
            && self.get(cursor).await?.is_none()
        {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_ids = query.realms.clone();
        let cursor_id = match query.cursor_event_id.as_deref() {
            Some(event_id) => ids::parse_event_id(event_id)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!(
                        "invalid peer events cursor event id: {event_id}"
                    ))
                })?
                .to_vec(),
            None => vec![0_u8; ids::EVENT_ID_BYTES],
        };
        let no_cursor = query.cursor_event_id.is_none();
        let kind_filter = query.kind_filter.as_deref().unwrap_or_default();
        let limit = query.limit.min(i64::MAX as usize) as i64;
        let page_sql = if query.backward {
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE state = 'accepted' AND ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) < (SELECT received_at, id FROM canonical_events WHERE state = 'accepted' AND id = $8)) \
             ORDER BY received_at DESC, id DESC \
             LIMIT $9"
        } else {
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE state = 'accepted' AND ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) > (SELECT received_at, id FROM canonical_events WHERE state = 'accepted' AND id = $8)) \
             ORDER BY received_at ASC, id ASC \
             LIMIT $9"
        };
        sql_query(page_sql)
            .bind::<Bool, _>(realm_ids.is_empty())
            .bind::<Array<Text>, _>(realm_ids)
            .bind::<Bool, _>(query.actors.is_empty())
            .bind::<Array<Text>, _>(query.actors.clone())
            .bind::<Bool, _>(query.kind_filter.is_none())
            .bind::<Text, _>(kind_filter)
            .bind::<Bool, _>(no_cursor)
            .bind::<Binary, _>(cursor_id)
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
        sql_query(
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE state = 'accepted' AND realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) ORDER BY received_at DESC, id DESC",
        )
        .bind::<Text, _>(realm_id)
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}

#[cfg(test)]
mod identity_anchor_receipt_tests {
    use super::identity_anchor_receipt_cardinality_is_valid;

    #[test]
    fn accepted_anchor_units_require_one_control_proposal_ack_per_event() {
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 0, false));
        assert!(identity_anchor_receipt_cardinality_is_valid(2, 2, false));
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 1, false));
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 3, false));
    }

    #[test]
    fn reanchor_conflict_cannot_attach_control_proposal_acks() {
        assert!(identity_anchor_receipt_cardinality_is_valid(2, 0, true));
        assert!(!identity_anchor_receipt_cardinality_is_valid(2, 2, true));
    }
}
