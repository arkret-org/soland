pub(super) mod approval_publications;

mod transaction_locks;
use std::collections::{BTreeMap, BTreeSet};

use diesel::sql_types::SmallInt;
pub(crate) use transaction_locks::{lock_canonical_event_inputs, lock_canonical_realm};

use super::{
    Array, AsyncConnection, AsyncPgConnection, BigInt, Binary, Bool, CanonicalEventRecord,
    DeviceInventoryRecord, DirectConversationFoundingCommitOutcome,
    DirectConversationFoundingSlotRecord, EventBatchReceipt, EventStore, ExistsRow,
    FederationOutboxRecord, IdentityAnchorAccountSlot, IdentityAnchorCommitOutcome,
    IdentityAnchorFrontierCas, IdentityAnchorReanchorSlot, Jsonb, MaxSeqRow,
    MembershipCompensationEvidenceRecord, MessageRecord, MessageStore, Nullable, OptionalExtension,
    PeerEventsPageQuery, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    PublicationEvidenceRecord, QueryableByName, RealmEventStats, RunQueryDsl, Text, Timestamptz,
    Uuid, Value, async_trait, identity_anchor_slot_conflicts, ids, pg_conn, sql_query, sql_types,
};
use crate::control_seal_schedule;
use crate::federation::{
    FederationOutboxRow, insert_federation_outbox_row, qualified_outbox_columns,
};
use crate::governance_history::put_governance_dependency_exact_in_transaction;
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
struct ControlProposalAckRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
}

#[derive(QueryableByName)]
struct MembershipCompensationEvidenceRow {
    #[diesel(sql_type = Binary)]
    event_id: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
    #[diesel(sql_type = Binary)]
    event_digest: Vec<u8>,
    #[diesel(sql_type = Text)]
    admission_id: String,
    #[diesel(sql_type = Text)]
    delegation_id: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    evidence: Value,
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
    /// A second preimage for an identity an accepted fork resolution already
    /// settled.
    ///
    /// It is retained as a forensic variant and rejected, but it is **not**
    /// collision evidence any more: `operations-sync.md` section 12 makes an
    /// accepted `canonical_winner` the closed exemption to whole-group
    /// quarantine, so re-quarantining here would undo the verdict every time a
    /// loser was redelivered.
    AdjudicatedVariant,
}

enum StoreTransactionOutcome<T> {
    Committed(T),
    Collision,
}

/// The winner an accepted fork resolution named for one colliding identity.
#[derive(QueryableByName)]
struct SettledCollisionRow {
    #[diesel(sql_type = Nullable<Binary>)]
    winner_canonical_bytes: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<BigInt>)]
    winner_sealed_at: Option<i64>,
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
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    issuer_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Jsonb)]
    scope: Value,
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
        let invalid = |error: serde_json::Error| {
            PersistenceError::Internal(format!("stored Event Batch Receipt is invalid: {error}"))
        };
        Ok(EventBatchReceipt {
            schema: row.schema,
            receipt_id: serde_json::from_value(Value::String(ids::format_typed_uuid(
                "receipt", &row.id,
            )))
            .map_err(invalid)?,
            issuer_id: row.issuer_id,
            scope: serde_json::from_value(row.scope).map_err(invalid)?,
            events: serde_json::from_value(row.events).map_err(invalid)?,
            created_at: row.created_at,
            proofs: serde_json::from_value(row.proofs).map_err(invalid)?,
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

/// Keep one canonical variant of a colliding identity as forensic evidence.
///
/// `operations-sync.md` section 12 returns every known variant of a collision
/// bucket, so a variant is written here whether it is being quarantined, is the
/// loser a verdict displaced, or is a redelivery a settled identity refuses.
/// The variant's identity is its parent's and is reached through `event_pk`;
/// only the columns that genuinely differ per variant are stored.
#[allow(clippy::too_many_arguments)]
async fn record_collision_variant(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    actor_id: &str,
    actor_seq: i64,
    realm_id: Option<&str>,
    kind: &str,
    schema_id: &str,
    canonical_bytes: &[u8],
    envelope: &Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    sql_query(
        "INSERT INTO event_collision_variants \
         (event_pk, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, \
          received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (event_pk, canonical_bytes) DO NOTHING",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<Text, _>(actor_id)
    .bind::<BigInt, _>(actor_seq)
    .bind::<Nullable<Text>, _>(realm_id)
    .bind::<Text, _>(kind)
    .bind::<Text, _>(schema_id)
    .bind::<Binary, _>(canonical_bytes)
    .bind::<Jsonb, _>(envelope)
    .bind::<Timestamptz, _>(received_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}

/// The accepted fork resolution that settled this colliding identity, if any.
///
/// `None` means the identity is unadjudicated and an incoming second preimage is
/// still open collision evidence. A row with no `winner_canonical_bytes` is
/// `void_all`: the identity has no accepted variant in this Realm and no
/// arrival may revive it.
async fn settled_collision_verdict(
    conn: &mut AsyncPgConnection,
    collision_event_id: &[u8],
    realm_id: Option<&str>,
) -> PersistenceResult<Option<SettledCollisionRow>> {
    // A verdict is keyed by Realm, so a row without one cannot be governed by
    // any and stays open collision evidence.
    let Some(realm_id) = realm_id else {
        return Ok(None);
    };
    sql_query(
        "SELECT winner_canonical_bytes, winner_sealed_at FROM federation_fork_normalization          WHERE collision_event_id = $1 AND realm_id = $2",
    )
    .bind::<Binary, _>(collision_event_id)
    .bind::<Text, _>(realm_id)
    .get_result::<SettledCollisionRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)
}

/// Make the winner of an accepted `canonical_winner` verdict the accepted
/// variant of its identity.
///
/// `event-auth-state-resolution.md` section 6.3.3 point 3. Before this, a
/// verdict could only ever *subtract*: a Station holding the loser dropped it
/// from the accepted read surface and was then unable to answer for that
/// identity at all, which is what left `federation.md` section 4.5.3's second
/// alignment phase unreachable for every loser-only Station.
///
/// The replacement is in place rather than an insert because `canonical_events`
/// holds one row per identity (`UNIQUE (id)`, `UNIQUE (digest_suite, digest)`)
/// and neither key moves — the two variants collide precisely because they share
/// a digest. The loser's bytes are already in `event_collision_variants` by the
/// time this runs; its `projection_events` row goes too, so nothing derived from
/// the loser survives in a read surface.
///
/// Two column meanings decide the statements below:
///
/// * `canonical_bytes` is the **digest preimage**, which by definition excludes `proofs`,
///   `unsigned` and `event_id`. A verdict carries exactly that, so it replaces the column verbatim.
/// * `envelope` is the full wire Event, so it is rebuilt as the winner preimage plus those three
///   members taken from the row already here. That is not a shortcut: both variants compute the
///   same `event_digest`, so the proofs this Station already verified for this identity hold over
///   the winner's bytes unchanged, and re-deriving them from the loser is precisely what must not
///   happen.
///
/// `received_at` comes from the covering Seal rather than a local clock, which
/// is what makes the admission a pure function of the winner's bytes and that
/// Seal: two Stations that admit the same verdict from different histories end
/// up byte-identical.
///
/// Every statement is a no-op on a Station that already holds the winner, which
/// is what makes replaying a verdict idempotent.
pub(crate) async fn admit_collision_winner(
    conn: &mut AsyncPgConnection,
    collision_event_id: &[u8],
    realm_id: Option<&str>,
    winner_canonical_bytes: &[u8],
    winner_sealed_at_ms: i64,
) -> PersistenceResult<()> {
    let Some(realm_id) = realm_id else {
        return Ok(());
    };
    lock_canonical_realm(conn, realm_id).await?;
    let received_at =
        chrono::DateTime::from_timestamp_millis(winner_sealed_at_ms).ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "fork resolution winner sealed_at is out of range".to_owned(),
            )
        })?;

    sql_query(
        "INSERT INTO event_collision_variants          (event_pk, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope,           received_at)          SELECT pk, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope,                 received_at          FROM canonical_events          WHERE id = $1 AND realm_id = $2 AND canonical_bytes <> $3          ON CONFLICT (event_pk, canonical_bytes) DO NOTHING",
    )
    .bind::<Binary, _>(collision_event_id)
    .bind::<Text, _>(realm_id)
    .bind::<Binary, _>(winner_canonical_bytes)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;

    sql_query(
        "DELETE FROM projection_events WHERE event_pk IN (            SELECT pk FROM canonical_events            WHERE id = $1 AND realm_id = $2 AND canonical_bytes <> $3          )",
    )
    .bind::<Binary, _>(collision_event_id)
    .bind::<Text, _>(realm_id)
    .bind::<Binary, _>(winner_canonical_bytes)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;

    sql_query(
        "UPDATE canonical_events SET            canonical_bytes = $3,            envelope = convert_from($3, 'UTF8')::jsonb || (              SELECT COALESCE(jsonb_object_agg(member.key, member.value), '{}'::jsonb)              FROM jsonb_each(canonical_events.envelope) AS member              WHERE member.key IN ('proofs', 'unsigned', 'event_id')            ),            received_at = $4,            state = 'accepted'          WHERE id = $1 AND realm_id = $2 AND canonical_bytes <> $3",
    )
    .bind::<Binary, _>(collision_event_id)
    .bind::<Text, _>(realm_id)
    .bind::<Binary, _>(winner_canonical_bytes)
    .bind::<Timestamptz, _>(received_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn insert_canonical_event(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
) -> PersistenceResult<CanonicalInsertOutcome> {
    lock_canonical_event_inputs(conn, &[record]).await?;
    let identity = ids::validated_event_identity_parts_for_suite(
        &record.event_id,
        &record.canonical_digest,
        &record.canonical_bytes,
        record.digest_suite,
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
        // Which Realm's recovery authority governs this row. A collision group
        // can span Realms and each Realm adjudicates only its own projection,
        // so the verdict is looked up against the Realm of the row that is
        // actually here, not against the Realm the new variant claims.
        if let Some(settled) =
            settled_collision_verdict(conn, &identity.id, stored.realm_id.as_deref()).await?
        {
            // The closed exemption of `operations-sync.md` section 12. This
            // identity is no longer an open collision: an accepted
            // `ak.fork.resolution` has already named what survives here, so a
            // second preimage is evidence to keep, not grounds to quarantine
            // the group again. Requarantining would undo the verdict on every
            // redelivery, and the verdict is exactly what the quarantine was
            // waiting for.
            if let (Some(winner), Some(sealed_at_ms)) = (
                settled.winner_canonical_bytes.as_deref(),
                settled.winner_sealed_at,
            ) && winner == record.canonical_bytes.as_slice()
            {
                // The winner arriving at a Station that holds the loser. The
                // verdict is its admission authority, so it takes the identity
                // over rather than bouncing off the row already here, and the
                // displaced loser is archived by the admission itself.
                admit_collision_winner(
                    conn,
                    &identity.id,
                    stored.realm_id.as_deref(),
                    winner,
                    sealed_at_ms,
                )
                .await?;
                return Ok(CanonicalInsertOutcome::Replay(stored.pk));
            }
            // Either a loser being redelivered, or any variant after
            // `void_all`. Kept as evidence, refused as an arrival, and the
            // accepted row is left exactly as the verdict left it.
            record_collision_variant(
                conn,
                stored.pk,
                &record.actor_id,
                record.actor_seq as i64,
                record.realm_id.as_deref(),
                &record.kind,
                &record.schema_id,
                &record.canonical_bytes,
                &record.envelope,
                record.received_at,
            )
            .await?;
            return Ok(CanonicalInsertOutcome::AdjudicatedVariant);
        }
        // An unadjudicated collision: neither variant can be preferred, so both
        // are kept and the whole group is quarantined until a verdict arrives.
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
                stored.actor_id.to_string(),
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
            record_collision_variant(
                conn,
                stored.pk,
                &actor_id,
                actor_seq,
                realm_id.as_deref(),
                &kind,
                &schema_id,
                &canonical_bytes,
                &envelope,
                received_at,
            )
            .await?;
        }
        sql_query("UPDATE canonical_events SET state = 'quarantined' WHERE pk = $1")
            .bind::<BigInt, _>(stored.pk)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM projection_events WHERE event_pk = $1 AND NOT EXISTS ( \
               SELECT 1 FROM state_seal_control_events \
               WHERE event_digest = $2 \
             )",
        )
        .bind::<BigInt, _>(stored.pk)
        .bind::<Text, _>(&record.canonical_digest)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE federation_outbox SET \
             state = CASE WHEN realm_fanout IS NULL THEN 'policy_suppressed' \
                          ELSE 'cancelled_authority_lost' END, \
             last_error_code = 'witness_disagreement', lease_owner = NULL, lease_token = NULL, \
             lease_expires_at = NULL, leased_from_state = NULL, \
             completed_at = COALESCE(completed_at, created_at) \
             WHERE id IN (SELECT outbox_id FROM event_federation_outbox WHERE event_pk = $1) \
               AND state IN ('pending', 'pending_route', 'leased')",
        )
        .bind::<BigInt, _>(stored.pk)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM state_control_events c WHERE event_digest = $1 AND NOT EXISTS ( \
               SELECT 1 FROM state_seal_control_events b WHERE b.event_digest = c.event_digest \
             )",
        )
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
    lock_canonical_event_inputs(conn, &ordered).await?;
    let mut incoming = BTreeMap::<String, &CanonicalEventRecord>::new();
    for record in ordered {
        let identity = ids::validated_event_identity_parts_for_suite(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
            record.digest_suite,
        )?;
        let stored = sql_query("SELECT canonical_bytes, state FROM canonical_events WHERE id = $1")
            .bind::<Binary, _>(identity.id.to_vec())
            .get_result::<EventPreflightRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        if let Some(stored) = stored {
            if stored.canonical_bytes != record.canonical_bytes {
                // A byte-different preimage for an identity already here.
                // `insert_canonical_event` decides which of the two this is: an
                // open collision, or a variant of an identity an accepted fork
                // resolution already settled. Only the winner of such a verdict
                // is admissible, and it comes back as a replay because the row
                // now holds exactly these bytes.
                if !matches!(
                    insert_canonical_event(conn, record).await?,
                    CanonicalInsertOutcome::Replay(_)
                ) {
                    return Ok(true);
                }
                continue;
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
                // Two preimages of one identity inside a single batch. The
                // second is written so the collision bucket holds both, and the
                // batch is refused whichever way that lands — a settled identity
                // still refuses a second variant, it just does not requarantine.
                debug_assert!(!matches!(
                    insert_canonical_event(conn, record).await?,
                    CanonicalInsertOutcome::Inserted(_) | CanonicalInsertOutcome::Replay(_)
                ));
                return Ok(true);
            }
        } else {
            incoming.insert(record.event_id.clone(), record);
        }
    }
    Ok(false)
}

pub(crate) async fn bind_event_outbox_rows(
    conn: &mut AsyncPgConnection,
    event_pks: &[i64],
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<()> {
    let outbox_id =
        sql_query("SELECT id FROM federation_outbox WHERE peer_id = $1 AND idempotency_key = $2")
            .bind::<Text, _>(delivery.peer_id.as_str())
            .bind::<Text, _>(&delivery.idempotency_key)
            .get_result::<TextIdRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .id;
    let mut bound_event_pks = event_pks.iter().copied().collect::<BTreeSet<_>>();
    if let Some(binding) = delivery.realm_fanout.as_ref() {
        if binding.source_event_ids.is_empty() || binding.authority_witnesses.is_empty() {
            return Err(PersistenceError::Conflict(
                "schema_violation: Realm fanout binding is incomplete".to_owned(),
            ));
        }
        for source_event_id in &binding.source_event_ids {
            let source_event_id = ids::parse_event_id(source_event_id).ok_or_else(|| {
                PersistenceError::SchemaViolation(format!(
                    "malformed Realm fanout source Event id: {source_event_id:?}"
                ))
            })?;
            let event_pk = sql_query(
                "SELECT pk FROM accepted_events \
                 WHERE id = $1 AND realm_id = $2",
            )
            .bind::<Binary, _>(source_event_id.to_vec())
            .bind::<Text, _>(&binding.realm_id)
            .get_result::<PkRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "schema_violation: Realm fanout source Event is not durably accepted"
                        .to_owned(),
                )
            })?
            .pk;
            bound_event_pks.insert(event_pk);
        }
    }
    for event_pk in bound_event_pks {
        sql_query(
            "INSERT INTO event_federation_outbox (event_pk, outbox_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind::<BigInt, _>(event_pk)
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
    control_proposal_ack: &arkret_wire::ControlProposalAck,
    command_unit_event_digests: &[arkret_wire::Hash],
) -> PersistenceResult<()> {
    let event =
        serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()).map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted anchor Event is not canonical wire: {error}"
            ))
        })?;
    let digest = event
        .event_digest_with_digest_suite(record.digest_suite)
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted anchor digest failed: {error}"
            ))
        })?;
    if digest != record.canonical_digest {
        return Err(PersistenceError::Conflict(
            "schema_violation: canonical digest differs from anchor Event digest".to_owned(),
        ));
    }
    let control_proposal_ack = serde_json::to_value(control_proposal_ack).map_err(|error| {
        PersistenceError::Internal(format!("Control Proposal Ack encoding failed: {error}"))
    })?;
    let ingress_class =
        serde_json::to_value(arkret_state::state::store::ControlProposalIngressClass::AckRequired)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "Control Move ingress class encoding failed: {error}"
                ))
            })?;
    if command_unit_event_digests.is_empty()
        || command_unit_event_digests.len() > arkret_wire::seal::MAX_SEAL_DELTA
        || !command_unit_event_digests
            .iter()
            .any(|member| member.as_str() == digest)
        || command_unit_event_digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != command_unit_event_digests.len()
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: invalid registered command unit".to_owned(),
        ));
    }
    let command_unit_event_digests =
        serde_json::to_value(command_unit_event_digests).map_err(|error| {
            PersistenceError::Internal(format!("registered command unit encoding failed: {error}"))
        })?;
    let affected = sql_query(
        "INSERT INTO state_control_events \
         (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class, command_unit_event_digests) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (event_digest) DO UPDATE SET \
           control_proposal_ack = COALESCE( \
             state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
           ) \
         WHERE state_control_events.realm_id = EXCLUDED.realm_id \
           AND state_control_events.digest_suite = EXCLUDED.digest_suite \
           AND state_control_events.event_json = EXCLUDED.event_json \
           AND state_control_events.ingress_class = EXCLUDED.ingress_class \
           AND state_control_events.command_unit_event_digests = EXCLUDED.command_unit_event_digests \
           AND (state_control_events.control_proposal_ack IS NULL \
             OR EXCLUDED.control_proposal_ack IS NULL \
             OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
    )
    .bind::<Text, _>(&digest)
    .bind::<Text, _>(record.digest_suite.as_str())
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(&record.envelope)
    .bind::<Jsonb, _>(&control_proposal_ack)
    .bind::<Jsonb, _>(&ingress_class)
    .bind::<Jsonb, _>(&command_unit_event_digests)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if affected == 0 {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: pending Control Move has different canonical bytes, ingress class or Control Proposal Ack"
                .to_owned(),
        ));
    }
    control_seal_schedule::upsert_for_control_event(conn, event.realm_id.as_str())
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

async fn insert_control_event_governance_dependencies(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
    dependencies: &[soland_storage::GovernanceDependencyWrite],
) -> PersistenceResult<usize> {
    let realm_id = record.realm_id.as_deref().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: Control Event governance dependency is missing Realm".to_owned(),
        )
    })?;
    let mut inserted = 0;
    for dependency in dependencies {
        let soland_storage::GovernanceDependencySource::Event(event_digest) = &dependency.source
        else {
            return Err(PersistenceError::Conflict(
                "schema_violation: Event batch cannot carry a Seal governance dependency"
                    .to_owned(),
            ));
        };
        if event_digest.as_str() != record.canonical_digest {
            continue;
        }
        if dependency.realm_id.as_str() != realm_id {
            return Err(PersistenceError::Conflict(
                "schema_violation: governance dependency Realm does not bind Control Event"
                    .to_owned(),
            ));
        }
        put_governance_dependency_exact_in_transaction(conn, dependency).await?;
        inserted += 1;
    }
    Ok(inserted)
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
    let quarantined = sql_query(
        "SELECT EXISTS (SELECT 1 FROM state_seal_quarantine_realms WHERE realm_id = $1) AS present",
    )
    .bind::<Text, _>(&expected.realm_id)
    .get_result::<ExistsRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if quarantined.present {
        return Err(PersistenceError::Conflict(
            "seal_collision_quarantine".to_owned(),
        ));
    }
    let rows = sql_query(
        "SELECT candidate.id \
         FROM state_seals candidate \
         WHERE candidate.realm_id = $1 \
           AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                           WHERE q.seal_id = candidate.id) \
           AND NOT EXISTS ( \
             SELECT 1 FROM state_seals successor \
             WHERE successor.realm_id = candidate.realm_id \
               AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                               WHERE q.seal_id = successor.id) \
               AND successor.predecessor_ref = candidate.id \
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
    let events = serde_json::to_value(&receipt.events).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt events encode failed: {error}"))
    })?;
    let proofs = serde_json::to_value(&receipt.proofs).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt proofs encode failed: {error}"))
    })?;
    let receipt_pk = sql_query(
        "INSERT INTO event_batch_receipts \
         (schema, id, issuer_id, scope, events, created_at, proofs) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING pk",
    )
    .bind::<Text, _>(&receipt.schema)
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
        receipt.receipt_id.as_str(),
    ))
    .bind::<Text, _>(&receipt.issuer_id)
    .bind::<Jsonb, _>(scope)
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
        let event_digest = event.event_id.event_digest();
        let identity = ids::event_identity_parts(event.event_id.as_str(), event_digest.as_str())?;
        let (digest_suite, digest) = (identity.digest_suite, identity.digest);
        let event_pk =
            sql_query("SELECT pk FROM accepted_events WHERE digest_suite = $1 AND digest = $2")
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
            actor_id: row.actor_id.to_string(),
            actor_seq: row.actor_seq.max(0) as u64,
            realm_id: row.realm_id,
            kind: row.kind,
            schema_id: row.schema_id,
            digest_suite: match row.digest_suite {
                1 => arkret_canonical::DigestSuite::Sha256,
                2 => arkret_canonical::DigestSuite::Blake3,
                _ => unreachable!("canonical_events.digest_suite must be active"),
            },
            canonical_digest: ids::format_event_digest(row.digest_suite as u8, &digest)
                .expect("canonical_events.digest_suite must be active"),
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        }
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn publication_event_for_approval(
        &self,
        approval_event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<arkret_wire::Event>> {
        let mut conn = pg_conn(&self.pool).await?;
        approval_publications::load(&mut conn, approval_event_id).await
    }

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
        // An `AdjudicatedVariant` is refused like a collision — `operations-sync.md`
        // section 12 rejects the newly arrived variant either way — but nothing
        // was quarantined: the exemption exists so a settled identity is not
        // reopened by a redelivery.
        if matches!(
            outcome,
            CanonicalInsertOutcome::Collision
                | CanonicalInsertOutcome::Quarantined
                | CanonicalInsertOutcome::AdjudicatedVariant
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

    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let outbox_columns = qualified_outbox_columns("outbox");
        let rows = sql_query(format!(
            "SELECT {outbox_columns} FROM federation_outbox outbox \
             JOIN event_federation_outbox link ON link.outbox_id = outbox.id \
             JOIN canonical_events event ON event.pk = link.event_pk \
             WHERE event.id = $1 ORDER BY outbox.created_at ASC, outbox.id ASC"
        ))
        .bind::<Binary, _>(event_id.to_vec())
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect()
    }

    async fn mls_frontier_leaves(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<Vec<arkret_wire::mls_transition::MlsSecurityFrontierLeaf>>> {
        #[derive(diesel::QueryableByName)]
        struct InputRow {
            #[diesel(sql_type = Binary)]
            canonical_bytes: Vec<u8>,
        }
        let id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation("invalid MLS input Event id".to_owned())
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query("SELECT input.canonical_bytes FROM mls_frontier_inputs input JOIN accepted_events event ON event.pk = input.event_pk WHERE event.id = $1")
            .bind::<Binary, _>(id.to_vec()).get_result::<InputRow>(&mut *conn).await.optional()
            .map_err(PersistenceError::database)?;
        row.map(|row| {
            let leaves: Vec<arkret_wire::mls_transition::MlsSecurityFrontierLeaf> =
                serde_json::from_slice(&row.canonical_bytes).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "invalid durable MLS frontier inputs: {error}"
                    ))
                })?;
            arkret_wire::mls_transition::validate_mls_frontier_leaves(&leaves)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            if arkret_canonical::canonical_json_bytes(&leaves)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?
                != row.canonical_bytes
            {
                return Err(PersistenceError::Internal(
                    "durable MLS input bytes are not canonical".to_owned(),
                ));
            }
            Ok(leaves)
        })
        .transpose()
    }

    async fn membership_compensation_evidence(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<MembershipCompensationEvidenceRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id_bytes = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let row = sql_query(
            "SELECT event.id AS event_id, event.digest_suite, event.digest AS event_digest, \
                    evidence.admission_id, evidence.delegation_id, evidence.canonical_bytes, \
                    evidence.evidence \
             FROM membership_compensation_evidence evidence \
             JOIN accepted_events event ON event.pk = evidence.event_pk \
             WHERE event.id = $1",
        )
        .bind::<Binary, _>(event_id_bytes.to_vec())
        .get_result::<MembershipCompensationEvidenceRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let evidence = serde_json::from_value(row.evidence).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored membership compensation evidence is invalid: {error}"
                ))
            })?;
            let digest: [u8; 32] = row.event_digest.try_into().map_err(|_| {
                PersistenceError::Internal(
                    "stored membership compensation Event digest has invalid length".to_owned(),
                )
            })?;
            let event_id: [u8; 33] = row.event_id.try_into().map_err(|_| {
                PersistenceError::Internal(
                    "stored membership compensation Event id has invalid length".to_owned(),
                )
            })?;
            Ok(MembershipCompensationEvidenceRecord {
                event_id: ids::format_event_id(&event_id),
                event_digest: ids::format_event_digest(row.digest_suite as u8, &digest)
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "stored membership compensation digest suite is invalid".to_owned(),
                        )
                    })?,
                admission_id: row.admission_id,
                delegation_id: row.delegation_id,
                canonical_bytes: row.canonical_bytes,
                evidence,
            })
        })
        .transpose()
    }

    async fn control_proposal_ack_for_digest(
        &self,
        proposal_digest: &str,
    ) -> PersistenceResult<Option<arkret_wire::ControlProposalAck>> {
        arkret_wire::Hash::new(proposal_digest.to_owned()).map_err(|error| {
            PersistenceError::SchemaViolation(format!("malformed Control Proposal digest: {error}"))
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT control_proposal_ack FROM state_control_events WHERE event_digest = $1",
        )
        .bind::<Text, _>(proposal_digest)
        .get_result::<ControlProposalAckRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(value) = row.and_then(|row| row.control_proposal_ack) else {
            return Ok(None);
        };
        let ack =
            serde_json::from_value::<arkret_wire::ControlProposalAck>(value).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored Control Proposal Ack is invalid: {error}"
                ))
            })?;
        ack.validate_protocol_bounds().map_err(|error| {
            PersistenceError::Internal(format!(
                "stored Control Proposal Ack violates protocol bounds: {error}"
            ))
        })?;
        if ack.proposal_digest.as_str() != proposal_digest {
            return Err(PersistenceError::Internal(
                "stored Control Proposal Ack does not bind its lookup digest".to_owned(),
            ));
        }
        Ok(Some(ack))
    }

    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        governance_dependencies: Vec<soland_storage::GovernanceDependencyWrite>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<soland_storage::RealmBootstrapCommitOutcome> {
        let acks = super::control_proposal_acks_by_digest(&records, control_proposal_acks, true)?;
        let command_unit_event_digests = records
            .iter()
            .map(|record| {
                arkret_wire::Hash::new(record.canonical_digest.clone()).map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "invalid registered command digest: {error}"
                    ))
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let transaction_outcome = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                if preflight_canonical_events(conn, &records).await? {
                    return Ok(StoreTransactionOutcome::Collision);
                }
                let event_ids = records
                    .iter()
                    .map(|record| record.event_id.clone())
                    .collect::<Vec<_>>();
                let record_count = records.len();
                let mut inserted_count = 0;
                let mut replay_count = 0;
                let mut event_pks = Vec::with_capacity(record_count);
                let mut dependency_count = 0;
                for record in records {
                    let event_pk = match insert_canonical_event(conn, &record).await? {
                        CanonicalInsertOutcome::Inserted(pk) => {
                            inserted_count += 1;
                            pk
                        }
                        CanonicalInsertOutcome::Replay(pk) => {
                            replay_count += 1;
                            pk
                        }
                        CanonicalInsertOutcome::Collision
                        | CanonicalInsertOutcome::Quarantined
                        | CanonicalInsertOutcome::AdjudicatedVariant => {
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
                    insert_pending_control_event(
                        conn,
                        &record,
                        control_proposal_ack,
                        &command_unit_event_digests,
                    )
                    .await?;
                    dependency_count += insert_control_event_governance_dependencies(
                        conn,
                        &record,
                        &governance_dependencies,
                    )
                    .await?;
                }
                if dependency_count != governance_dependencies.len() {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: Realm bootstrap governance dependency source is not in batch"
                            .to_owned(),
                    )
                    .into());
                }
                // Same transaction as the Events: the delivery intent for a Realm
                // genesis unit is not a post-commit best-effort follow-up.
                for delivery in outbox {
                    insert_federation_outbox_row(conn, &delivery).await?;
                    bind_event_outbox_rows(conn, &event_pks, &delivery).await?;
                }
                let outcome = if inserted_count == record_count {
                    soland_storage::RealmBootstrapCommitOutcome::Committed
                } else if replay_count == record_count {
                    soland_storage::RealmBootstrapCommitOutcome::ExactRetry { event_ids }
                } else {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                };
                Ok(StoreTransactionOutcome::Committed(outcome))
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

    async fn put_direct_conversation_founding_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        governance_dependencies: Vec<soland_storage::GovernanceDependencyWrite>,
        slot: DirectConversationFoundingSlotRecord,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome> {
        if records.len() != 4
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
        let acks = super::control_proposal_acks_by_digest(&records, control_proposal_acks, true)?;
        let command_unit_event_digests = records
            .iter()
            .map(|record| {
                arkret_wire::Hash::new(record.canonical_digest.clone()).map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "invalid registered command digest: {error}"
                    ))
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
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
            let mut dependency_count = 0;
            for record in records {
                let event_pk = match insert_canonical_event(conn, &record).await? {
                    CanonicalInsertOutcome::Inserted(pk) | CanonicalInsertOutcome::Replay(pk) => pk,
                    CanonicalInsertOutcome::Collision
                    | CanonicalInsertOutcome::Quarantined
                    | CanonicalInsertOutcome::AdjudicatedVariant => {
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
                insert_pending_control_event(
                    conn,
                    &record,
                    ack,
                    &command_unit_event_digests,
                )
                .await?;
                dependency_count += insert_control_event_governance_dependencies(
                    conn,
                    &record,
                    &governance_dependencies,
                )
                .await?;
            }
            if dependency_count != governance_dependencies.len() {
                return Err(PersistenceError::Conflict(
                    "schema_violation: Direct Conversation governance dependency source is not in batch"
                        .to_owned(),
                )
                .into());
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
        governance_dependencies: Vec<soland_storage::GovernanceDependencyWrite>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        account_slot: Option<IdentityAnchorAccountSlot>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let command_unit_event_digests = records
            .iter()
            .map(|record| {
                arkret_wire::Hash::new(record.canonical_digest.clone()).map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "invalid registered command digest: {error}"
                    ))
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
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
                         FROM accepted_events WHERE actor_id = $1 AND kind IN ('ak.device.reanchor', 'ak.device.authorize')",
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
                let control_proposal_acks_by_digest = if reanchor_conflict {
                    if !control_proposal_acks.is_empty() {
                        return Err(PersistenceError::Conflict(
                            "schema_violation: identity anchor receipt cardinality mismatch"
                                .to_owned(),
                        )
                        .into());
                    }
                    BTreeMap::new()
                } else {
                    super::control_proposal_acks_by_digest(
                        &records,
                        control_proposal_acks,
                        true,
                    )?
                };
                if reanchor_slot.is_some() {
                    let reanchor = records.iter().find(|record| record.kind == "ak.device.reanchor")
                        .ok_or_else(||PersistenceError::SchemaViolation("reanchor unit missing anchor Event".to_owned()))?;
                    let reanchor_id = ids::parse_event_id(&reanchor.event_id).ok_or_else(|| {
                        PersistenceError::SchemaViolation(
                            "reanchor unit contains a malformed canonical Event id".to_owned(),
                        )
                    })?;
                    let already_accepted=sql_query("SELECT EXISTS(SELECT 1 FROM accepted_events WHERE id=$1) AS present")
                        .bind::<Binary,_>(reanchor_id.to_vec()).get_result::<ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
                    if !already_accepted {
                        // Match manifest/unlock ordering: accepted Realm frontier, policy, session.
                        if let Some(frontier)=frontier_cas.as_ref() {
                            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                                .bind::<Text,_>(&frontier.realm_id).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                        }
                        let session_id=reanchor.envelope.pointer("/payload/recovery_session_id").and_then(Value::as_str)
                            .ok_or_else(||PersistenceError::SchemaViolation("reanchor session missing".to_owned()))?;
                        crate::recovery::lock_recovery_session_authority(conn,session_id).await?;
                    }
                }
                if let Some(frontier_cas) = frontier_cas {
                    assert_identity_anchor_frontier(conn, &frontier_cas).await.map_err(PersistenceError::database)?;
                }
                if let Some(slot) = account_slot.as_ref() {
                    let affected = sql_query(
                        "INSERT INTO identity_anchor_account_slots \
                            (account_authority_id, account_subject, principal_id, station_id, realm_id, create_event_id) \
                         VALUES ($1, $2, $3, $4, $5, $6) \
                         ON CONFLICT (account_authority_id, account_subject) DO UPDATE SET \
                            principal_id = EXCLUDED.principal_id \
                         WHERE identity_anchor_account_slots.principal_id = EXCLUDED.principal_id \
                           AND identity_anchor_account_slots.station_id = EXCLUDED.station_id \
                           AND identity_anchor_account_slots.realm_id = EXCLUDED.realm_id \
                           AND identity_anchor_account_slots.create_event_id = EXCLUDED.create_event_id",
                    )
                    .bind::<Text, _>(&slot.account_authority_id)
                    .bind::<Text, _>(&slot.account_subject)
                    .bind::<Text, _>(slot.account_id.principal_id.as_str())
                    .bind::<Text, _>(slot.account_id.station_id.as_str())
                    .bind::<Text, _>(&slot.realm_id)
                    .bind::<Text, _>(&slot.create_event_id)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    if affected == 0 {
                        return Err(PersistenceError::Conflict(
                            "account_principal_control_realm_already_exists".to_owned(),
                        )
                        .into());
                    }
                }
                let mut dependency_count = 0;
                for record in &records {
                    let event_pk = match insert_canonical_event(conn, &record).await? {
                        CanonicalInsertOutcome::Inserted(pk) | CanonicalInsertOutcome::Replay(pk) => pk,
                        CanonicalInsertOutcome::Collision
                        | CanonicalInsertOutcome::Quarantined
                        | CanonicalInsertOutcome::AdjudicatedVariant => {
                            unreachable!("batch collision was handled by preflight")
                        }
                    };
                    event_pks.push(event_pk);
                    if !reanchor_conflict {
                        insert_pending_control_event(
                            conn,
                            &record,
                            control_proposal_acks_by_digest
                                .get(&record.canonical_digest)
                                .ok_or_else(|| {
                                    PersistenceError::Conflict(
                                        "schema_violation: identity anchor Control Move is missing Control Proposal Ack"
                                            .to_owned(),
                                    )
                                })?,
                            &command_unit_event_digests,
                        )
                        .await?;
                        dependency_count += insert_control_event_governance_dependencies(
                            conn,
                            &record,
                            &governance_dependencies,
                        )
                        .await?;
                    }
                }
                if !reanchor_conflict && let Some(slot) = account_slot.as_ref() {
                    crate::principal_resolution::genesis::initialize(conn, slot, &records).await?;
                }
                if !reanchor_conflict && dependency_count != governance_dependencies.len() {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: identity anchor governance dependency source is not in batch"
                            .to_owned(),
                    )
                    .into());
                }
                if !reanchor_conflict
                    && let Some(device) = device
                {
                    if device.verification_state == "verified" {
                        let slot = account_slot.as_ref().ok_or_else(|| {
                            PersistenceError::SchemaViolation(
                                "only PCR bootstrap may install accepted device authority".into(),
                            )
                        })?;
                        let receipt = receipt.as_ref().ok_or_else(|| {
                            PersistenceError::SchemaViolation(
                                "PCR bootstrap device authority requires its atomic receipt".into(),
                            )
                        })?;
                        let scope = receipt.pcr_genesis_scope().map_err(|error| {
                            PersistenceError::SchemaViolation(format!(
                                "PCR bootstrap receipt is invalid: {error}"
                            ))
                        })?;
                        let authorize = records
                            .iter()
                            .find(|record| record.kind == "ak.device.authorize")
                            .ok_or_else(|| {
                                PersistenceError::SchemaViolation(
                                    "PCR bootstrap device projection has no authorize Event".into(),
                                )
                            })?;
                        let projected_event_id = device
                            .payload
                            .get("device_authorize_event_id")
                            .and_then(Value::as_str);
                        let projected_device_id = device
                            .payload
                            .get("device_id")
                            .and_then(Value::as_str);
                        let accepted_device_id = authorize
                            .envelope
                            .pointer("/payload/device_id")
                            .and_then(Value::as_str);
                        if device.actor != slot.account_id.principal_id.as_str()
                            || device.device_id != scope.accepted_device_id.as_str()
                            || scope.principal_id != slot.account_id.principal_id
                            || scope.realm_id.as_str() != slot.realm_id
                            || receipt.issuer_id != slot.account_id.station_id
                            || authorize.realm_id.as_deref() != Some(slot.realm_id.as_str())
                            || projected_event_id != Some(authorize.event_id.as_str())
                            || projected_device_id != Some(device.device_id.as_str())
                            || accepted_device_id != Some(device.device_id.as_str())
                            || device
                                .payload
                                .get("authorized_generation_ref")
                                .and_then(Value::as_u64)
                                != Some(1)
                            || device
                                .payload
                                .get("device_authorize_projected")
                                .and_then(Value::as_bool)
                                != Some(true)
                            || device.revoked_at.is_some()
                        {
                            return Err(PersistenceError::SchemaViolation(
                                "PCR bootstrap device projection does not exactly bind the accepted founding authorization"
                                    .into(),
                            )
                            .into());
                        }
                    } else if device.verification_state != "unverified"
                        || device.payload
                            != serde_json::json!({"device_id": device.device_id})
                    {
                        return Err(PersistenceError::SchemaViolation(
                            "non-bootstrap identity admission may only insert an unverified endpoint placeholder"
                                .into(),
                        )
                        .into());
                    }
                    sql_query(
                        "INSERT INTO devices (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                         ON CONFLICT (actor_id, device_id) DO UPDATE SET \
                         payload=EXCLUDED.payload,verification_state=EXCLUDED.verification_state,updated_at=EXCLUDED.updated_at,revoked_at=EXCLUDED.revoked_at \
                         WHERE EXCLUDED.verification_state='verified'",
                    )
                    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
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
        let event_pk = sql_query("SELECT pk FROM accepted_events WHERE id = $1")
            .bind::<Binary, _>(event_id.to_vec())
            .get_result::<PkRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        let Some(event_pk) = event_pk.map(|row| row.pk) else {
            return Ok(Vec::new());
        };
        let rows = sql_query(
            "SELECT receipt.schema, receipt.id, receipt.issuer_id, receipt.scope, \
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

    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>> {
        #[derive(QueryableByName)]
        struct AccountSlotRow {
            #[diesel(sql_type = Text)]
            account_authority_id: String,
            #[diesel(sql_type = Text)]
            account_subject: String,
            #[diesel(sql_type = Text)]
            principal_id: arkret_identifiers::DidCoreId,
            #[diesel(sql_type = Text)]
            station_id: arkret_identifiers::DidCoreId,
            #[diesel(sql_type = Text)]
            realm_id: String,
            #[diesel(sql_type = Text)]
            create_event_id: String,
        }

        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT account_authority_id, account_subject, principal_id, station_id, realm_id, create_event_id \
             FROM identity_anchor_account_slots WHERE principal_id = $1 AND station_id = $2 LIMIT 2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .load::<AccountSlotRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => Ok(Some(IdentityAnchorAccountSlot {
                account_authority_id: row.account_authority_id.clone(),
                account_subject: row.account_subject.clone(),
                account_id: arkret_wire::AccountId::new(
                    row.principal_id.clone(),
                    row.station_id.clone(),
                ),
                realm_id: row.realm_id.clone(),
                create_event_id: row.create_event_id.clone(),
            })),
            _ => Err(PersistenceError::Conflict(
                "account has multiple identity-anchor account slots".to_owned(),
            )),
        }
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
             FROM accepted_events WHERE id = $1",
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
        sql_query("SELECT EXISTS(SELECT 1 FROM accepted_events WHERE id = $1) AS present")
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
        sql_query("SELECT MAX(actor_seq) AS max_seq FROM accepted_events WHERE actor_id = $1")
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
             FROM accepted_events ORDER BY received_at ASC, id ASC",
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
             FROM accepted_events WHERE realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1)",
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
             FROM accepted_events WHERE actor_id = $1 ORDER BY actor_seq ASC, received_at ASC, id ASC",
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
             FROM accepted_events WHERE realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(actor_id)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn realm_actor_position_occupied(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT EXISTS ( \
                 SELECT 1 FROM canonical_events \
                  WHERE realm_id = $1 AND actor_id = $2 \
                 UNION ALL \
                 SELECT 1 FROM federation_fork_normalization \
                  WHERE realm_id = $1 AND actor_id = $2 \
             ) AS occupied",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(actor_id)
        .get_result::<PositionOccupancyRow>(&mut *conn)
        .await
        .map(|row| row.occupied)
        .map_err(PersistenceError::database)
    }

    async fn list_at_realm_actor_position(
        &self,
        realm_id: &str,
        actor_id: &str,
        actor_seq: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let actor_seq = i64::try_from(actor_seq).map_err(|_| {
            PersistenceError::Conflict("actor_seq exceeds i64 storage range".to_owned())
        })?;
        let limit = i64::try_from(limit).map_err(|_| {
            PersistenceError::Conflict("exact-position limit exceeds i64 range".to_owned())
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM accepted_events \
             WHERE realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) \
               AND actor_id = $2 AND actor_seq = $3 \
             ORDER BY id ASC LIMIT $4",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(actor_id)
        .bind::<BigInt, _>(actor_seq)
        .bind::<BigInt, _>(limit)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM accepted_events \
             WHERE realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) \
               AND actor_id = $2 AND kind = $3 \
               AND envelope -> 'payload' ->> 'event_id' = $4 \
             ORDER BY actor_seq ASC, id ASC",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(received_by.as_str())
        .bind::<Text, _>(arkret_wire::EventKind::ModerationFrankingProof.as_str())
        .bind::<Text, _>(target_event_id)
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
             FROM accepted_events \
             WHERE kind IN ('ak.member.state', 'ak.circle.member.state', 'ak.invite.create', 'ak.invite.accept') \
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
             FROM accepted_events \
             WHERE ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) < (SELECT received_at, id FROM accepted_events WHERE id = $8)) \
             ORDER BY received_at DESC, id DESC \
             LIMIT $9"
        } else {
            "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
             FROM accepted_events \
             WHERE ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) > (SELECT received_at, id FROM accepted_events WHERE id = $8)) \
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
             FROM accepted_events WHERE realm_pk = (SELECT pk FROM canonical_realms WHERE wire_id = $1) ORDER BY received_at DESC, id DESC",
        )
        .bind::<Text, _>(realm_id)
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}

const MESSAGE_COLUMNS: &str =
    "event_id, message_id, realm_id, sender, thread_id, content, encrypted, created_at";

/// PostgreSQL-backed message projection. Keyed by the canonical Event id so
/// replayed projection writes dedup idempotently.
pub struct PgMessageStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct MessageRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    message_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    sender: String,
    #[diesel(sql_type = Text)]
    thread_id: String,
    #[diesel(sql_type = Jsonb)]
    content: Value,
    #[diesel(sql_type = Bool)]
    encrypted: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct PositionOccupancyRow {
    #[diesel(sql_type = Bool)]
    occupied: bool,
}

impl From<MessageRow> for MessageRecord {
    fn from(row: MessageRow) -> Self {
        Self {
            event_id: row.event_id,
            message_id: row.message_id,
            realm_id: row.realm_id,
            sender: row.sender,
            thread_id: row.thread_id,
            content: row.content,
            encrypted: row.encrypted,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl MessageStore for PgMessageStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE event_id = $1"
        ))
        .bind::<Text, _>(event_id)
        .get_result::<MessageRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MessageRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // The projection layer dedups on the canonical Event id before
        // writing; DO NOTHING keeps a replayed projection idempotent instead
        // of failing on the uniqueness constraint.
        sql_query(
            "INSERT INTO messages \
             (event_id, message_id, realm_id, sender, thread_id, content, encrypted, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.event_id)
        .bind::<Text, _>(&record.message_id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.sender)
        .bind::<Text, _>(&record.thread_id)
        .bind::<Jsonb, _>(&record.content)
        .bind::<Bool, _>(record.encrypted)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE realm_id = $1 \
             ORDER BY created_at DESC, pk DESC LIMIT $2"
        ))
        .bind::<Text, _>(realm_id)
        .bind::<BigInt, _>(limit as i64)
        .load::<MessageRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Chronological order (oldest first) so thread readers get a natural
        // conversation timeline; the caller decides whether to reverse.
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE thread_id = $1 \
             ORDER BY created_at ASC, pk ASC LIMIT $2"
        ))
        .bind::<Text, _>(thread_id)
        .bind::<BigInt, _>(limit as i64)
        .load::<MessageRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM messages WHERE event_id = $1")
            .bind::<Text, _>(event_id)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
