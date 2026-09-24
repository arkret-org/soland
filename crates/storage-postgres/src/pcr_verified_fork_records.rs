//! Verified PCR fork evidence. There is deliberately no public ingestion port:
//! the service must first supply both historical producer bindings resolved at
//! the common predecessor cut. Current DID material cannot satisfy that input.

use std::collections::BTreeSet;

use arkret_identity::{
    AcceptedDidBinding, RealmAuthorityKeyDirectory, VerifiedRealmAuthority,
    verify_event_proof_with_binding,
};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizePayload, DeviceReanchorPayload, DeviceRevokePayload,
};
use arkret_wire::{ActorId, CommitStreamRef, CommittedEventFullView, EventKind, RealmCommitId};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::{
    AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, PgTransactionError, pg_conn,
};

/// Only `verify` can create this type. Its producer bindings must come from
/// predecessor-cut historical resolution; no existing HTTP path supplies them.
pub(crate) struct VerifiedPcrForkEvidence {
    previous: CommittedEventFullView,
    first: CommittedEventFullView,
    first_binding: AcceptedDidBinding,
    second: CommittedEventFullView,
    second_binding: AcceptedDidBinding,
}

/// A predecessor-cut acceptance, to be constructed only by a durable
/// historical-binding resolver. There is intentionally no constructor from a
/// current `AcceptedDidBinding`; that resolver has not been implemented.
pub(crate) struct HistoricalPcrAcceptedBinding {
    predecessor_commit_id: RealmCommitId,
    actor_id: ActorId,
    accepted: AcceptedDidBinding,
}

fn invalid(reason: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(reason.into())
}

impl VerifiedPcrForkEvidence {
    pub(crate) fn verify(
        previous: CommittedEventFullView,
        left: CommittedEventFullView,
        right: CommittedEventFullView,
        first_binding_at_predecessor: &HistoricalPcrAcceptedBinding,
        second_binding_at_predecessor: &HistoricalPcrAcceptedBinding,
        authority: &VerifiedRealmAuthority,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> PersistenceResult<Self> {
        let (first, first_binding, second, second_binding) =
            if left.commit.commit_id < right.commit.commit_id {
                (
                    left,
                    first_binding_at_predecessor,
                    right,
                    second_binding_at_predecessor,
                )
            } else {
                (
                    right,
                    second_binding_at_predecessor,
                    left,
                    first_binding_at_predecessor,
                )
            };
        if first.commit.commit_id == second.commit.commit_id
            || first.commit.stream_position != second.commit.stream_position
            || first.commit.previous_commit_ref != second.commit.previous_commit_ref
            || first.commit.stream_position == 0
            || first.commit.stream_ref != second.commit.stream_ref
            || first.commit.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: previous.commit.realm_id.clone(),
                })
            || first.commit.realm_id != previous.commit.realm_id
            || second.commit.realm_id != previous.commit.realm_id
            || first.commit.governance_generation != second.commit.governance_generation
            || first.commit.authority_ref != second.commit.authority_ref
        {
            return Err(invalid(
                "PCR fork branches have no common authority predecessor",
            ));
        }
        for view in [&previous, &first, &second] {
            authority
                .verify_committed_item(view, keys)
                .map_err(|error| invalid(format!("PCR fork signed branch is invalid: {error}")))?;
        }
        for branch in [&first, &second] {
            branch
                .commit
                .validate_successor_of(&previous.commit)
                .map_err(|error| invalid(format!("PCR fork predecessor differs: {error}")))?;
        }
        for (branch, binding) in [(&first, first_binding), (&second, second_binding)] {
            if binding.predecessor_commit_id != previous.commit.commit_id
                || binding.actor_id != branch.event.actor_id
            {
                return Err(invalid(
                    "PCR fork producer binding belongs to a different predecessor or actor",
                ));
            }
            let proof = branch
                .event
                .producer_proof
                .as_ref()
                .ok_or_else(|| invalid("PCR fork Event producer proof is absent"))?;
            let bytes = arkret_signatures::EventProofBuilder::new()
                .envelope_bytes(&branch.event)
                .map_err(|error| invalid(format!("PCR fork Event bytes are invalid: {error}")))?;
            verify_event_proof_with_binding(
                proof,
                &bytes,
                &branch.event.actor_id,
                &binding.accepted,
            )
            .map_err(|error| invalid(format!("PCR fork Event producer is invalid: {error}")))?;
        }
        Ok(Self {
            previous,
            first,
            first_binding: first_binding.accepted.clone(),
            second,
            second_binding: second_binding.accepted.clone(),
        })
    }
}

#[derive(QueryableByName)]
struct PriorRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct MarkerRow {
    #[diesel(sql_type = Text)]
    pcr_head_commit_id: String,
    #[diesel(sql_type = BigInt)]
    conflict_revision: i64,
    #[diesel(sql_type = BigInt)]
    actual_count: i64,
}

#[derive(QueryableByName)]
struct ExistingRow {
    #[diesel(sql_type = Jsonb)]
    first_commit: Value,
    #[diesel(sql_type = Jsonb)]
    first_event: Value,
    #[diesel(sql_type = Jsonb)]
    first_accepted_binding: Value,
    #[diesel(sql_type = Jsonb)]
    second_commit: Value,
    #[diesel(sql_type = Jsonb)]
    second_event: Value,
    #[diesel(sql_type = Jsonb)]
    second_accepted_binding: Value,
    #[diesel(sql_type = diesel::sql_types::Array<Text>)]
    affected_device_ids: Vec<String>,
    #[diesel(sql_type = Bool)]
    affects_generation: bool,
}

#[derive(QueryableByName)]
struct DeviceRow {
    #[diesel(sql_type = Text)]
    device_id: String,
}

#[derive(QueryableByName)]
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
}

#[derive(QueryableByName)]
struct GenerationAtPredecessorRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn payload<T: serde::de::DeserializeOwned>(value: &Value) -> PersistenceResult<T> {
    serde_json::from_value(value.clone())
        .map_err(|error| invalid(format!("PCR fork Event payload is invalid: {error}")))
}

/// An internal writer for a fully verified pair. The outer service must pin
/// each AcceptedDidBinding to the predecessor before invoking `verify`.
pub(crate) async fn ingest_verified_pcr_fork(
    pool: &PgPool,
    evidence: VerifiedPcrForkEvidence,
    verified_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<(), PgTransactionError, _>(async move |conn| {
        ingest_in_connection(conn, evidence, verified_at).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

async fn ingest_in_connection(
    conn: &mut AsyncPgConnection,
    evidence: VerifiedPcrForkEvidence,
    verified_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    let realm = evidence.previous.commit.realm_id.as_str();
    // The same authority lock order as PCR Commit writers serializes marker
    // advancement and independent fork ingestion.
    let locked = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(realm)
        .get_result::<RealmLockRow>(&mut *conn)
        .await
        .optional()?;
    if locked.as_ref().is_none_or(|row| row.realm_id != realm) {
        return Err(invalid("PCR fork has no local authority").into());
    }
    let previous = sql_query(
        "SELECT c.commit_json,e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1",
    )
    .bind::<Text, _>(evidence.previous.commit.commit_id.as_str())
    .get_result::<PriorRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| invalid("PCR fork predecessor is not accepted locally"))?;
    if previous.commit_json
        != serde_json::to_value(&evidence.previous.commit).map_err(PersistenceError::database)?
        || previous.envelope
            != serde_json::to_value(&evidence.previous.event).map_err(PersistenceError::database)?
    {
        return Err(invalid("PCR fork predecessor differs from accepted history").into());
    }
    let marker = sql_query(
        "SELECT m.pcr_head_commit_id,m.conflict_revision, \
         (SELECT count(*) FROM pcr_verified_fork_records f WHERE f.realm_id=m.realm_id) AS actual_count \
         FROM pcr_device_conflict_index_cuts m WHERE m.realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(realm)
    .get_result::<MarkerRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| invalid("PCR fork conflict index marker is absent"))?;
    if marker.conflict_revision != marker.actual_count {
        return Err(invalid("PCR fork conflict index marker is incomplete").into());
    }
    let head = sql_query(
        "SELECT commit_id FROM realm_commits WHERE realm_id=$1 \
         AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) \
         ORDER BY stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(realm)
    .get_result::<HeadRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| invalid("PCR fork accepted head is absent"))?;
    if marker.pcr_head_commit_id != head.commit_id {
        return Err(invalid("PCR fork conflict index is not at accepted head").into());
    }
    let mut affected = BTreeSet::<String>::new();
    let mut affects_generation = false;
    for branch in [&evidence.first, &evidence.second] {
        let raw =
            serde_json::to_value(&branch.event.payload).map_err(PersistenceError::database)?;
        match branch.event.kind {
            EventKind::DeviceAuthorize => {
                let event: DeviceAuthorizePayload = payload(&raw)?;
                affected.insert(event.device_id.to_string());
            }
            EventKind::DeviceRevoke => {
                let event: DeviceRevokePayload = payload(&raw)?;
                affected.insert(event.device_id.to_string());
            }
            EventKind::DeviceReanchor => {
                let event: DeviceReanchorPayload = payload(&raw)?;
                affects_generation = true;
                let generation = sql_query(
                    "SELECT CASE WHEN e.kind='ak.device.reanchor' \
                       THEN e.envelope->'payload'->'new_device_generation' \
                       ELSE e.envelope->'payload'->'authorized_generation_ref' END AS value \
                     FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                     WHERE c.realm_id=$1 AND c.stream_position<=$2 AND \
                       (e.kind='ak.device.reanchor' OR \
                        (e.kind='ak.device.authorize' AND \
                         e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor')) \
                     ORDER BY c.stream_position DESC LIMIT 1",
                )
                .bind::<Text, _>(realm)
                .bind::<BigInt, _>(i64::try_from(evidence.previous.commit.stream_position)
                    .map_err(|_| invalid("PCR fork predecessor position overflows SQL"))?)
                .get_result::<GenerationAtPredecessorRow>(&mut *conn)
                .await
                .optional()?
                .ok_or_else(|| invalid("PCR fork predecessor has no device generation"))?;
                if generation.value.as_u64() != Some(event.previous_device_generation) {
                    return Err(
                        invalid("PCR fork reanchor generation differs from predecessor").into(),
                    );
                }
                let rows = sql_query(
                    "SELECT device_id FROM ( \
                       SELECT DISTINCT ON (e.envelope->'payload'->>'device_id') \
                         e.envelope->'payload'->>'device_id' AS device_id, \
                         (e.envelope->'payload'->>'authorized_generation_ref')::bigint AS generation \
                       FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                       WHERE c.realm_id=$1 AND c.stream_position<=$2 AND e.kind='ak.device.authorize' \
                       ORDER BY e.envelope->'payload'->>'device_id',c.stream_position DESC \
                     ) a WHERE generation=$3",
                )
                .bind::<Text, _>(realm)
                .bind::<BigInt, _>(i64::try_from(evidence.previous.commit.stream_position)
                    .map_err(|_| invalid("PCR fork predecessor position overflows SQL"))?)
                .bind::<BigInt, _>(i64::try_from(event.previous_device_generation)
                    .map_err(|_| invalid("PCR fork generation overflows SQL"))?)
                .load::<DeviceRow>(&mut *conn)
                .await?;
                affected.extend(rows.into_iter().map(|row| row.device_id));
            }
            _ => {}
        }
    }
    if affected.is_empty() {
        return Err(invalid("PCR fork has no affected device at predecessor cut").into());
    }
    let affected = affected.into_iter().collect::<Vec<_>>();
    let first_commit =
        serde_json::to_value(&evidence.first.commit).map_err(PersistenceError::database)?;
    let first_event =
        serde_json::to_value(&evidence.first.event).map_err(PersistenceError::database)?;
    let first_binding =
        serde_json::to_value(&evidence.first_binding).map_err(PersistenceError::database)?;
    let second_commit =
        serde_json::to_value(&evidence.second.commit).map_err(PersistenceError::database)?;
    let second_event =
        serde_json::to_value(&evidence.second.event).map_err(PersistenceError::database)?;
    let second_binding =
        serde_json::to_value(&evidence.second_binding).map_err(PersistenceError::database)?;
    let existing = sql_query(
        "SELECT first_commit,first_event,first_accepted_binding,second_commit,second_event,second_accepted_binding,affected_device_ids,affects_generation \
         FROM pcr_verified_fork_records WHERE realm_id=$1 AND first_commit_id=$2 AND second_commit_id=$3",
    )
    .bind::<Text, _>(realm)
    .bind::<Text, _>(evidence.first.commit.commit_id.as_str())
    .bind::<Text, _>(evidence.second.commit.commit_id.as_str())
    .get_result::<ExistingRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(existing) = existing {
        if existing.first_commit != first_commit
            || existing.first_event != first_event
            || existing.first_accepted_binding != first_binding
            || existing.second_commit != second_commit
            || existing.second_event != second_event
            || existing.second_accepted_binding != second_binding
            || existing.affected_device_ids != affected
            || existing.affects_generation != affects_generation
        {
            return Err(PersistenceError::Conflict(
                "pcr_fork_evidence_duplicate_conflict".to_owned(),
            )
            .into());
        }
        return Ok(());
    }
    sql_query(
        "INSERT INTO pcr_verified_fork_records \
         (realm_id,first_commit_id,second_commit_id,stream_position,previous_commit_id, \
          first_commit,first_event,first_accepted_binding,second_commit,second_event,second_accepted_binding,affected_device_ids,affects_generation,verified_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind::<Text, _>(realm)
    .bind::<Text, _>(evidence.first.commit.commit_id.as_str())
    .bind::<Text, _>(evidence.second.commit.commit_id.as_str())
    .bind::<BigInt, _>(i64::try_from(evidence.first.commit.stream_position)
        .map_err(|_| invalid("PCR fork position overflows SQL"))?)
    .bind::<Nullable<Text>, _>(evidence.first.commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
    .bind::<Jsonb, _>(&first_commit)
    .bind::<Jsonb, _>(&first_event)
    .bind::<Jsonb, _>(&first_binding)
    .bind::<Jsonb, _>(&second_commit)
    .bind::<Jsonb, _>(&second_event)
    .bind::<Jsonb, _>(&second_binding)
    .bind::<diesel::sql_types::Array<Text>, _>(&affected)
    .bind::<Bool, _>(affects_generation)
    .bind::<Timestamptz, _>(verified_at)
    .execute(&mut *conn)
    .await?;
    let advanced = sql_query(
        "UPDATE pcr_device_conflict_index_cuts SET conflict_revision=$2,updated_at=$3 \
         WHERE realm_id=$1 AND pcr_head_commit_id=$4 AND conflict_revision=$5",
    )
    .bind::<Text, _>(realm)
    .bind::<BigInt, _>(marker.conflict_revision + 1)
    .bind::<Timestamptz, _>(verified_at)
    .bind::<Text, _>(&marker.pcr_head_commit_id)
    .bind::<BigInt, _>(marker.conflict_revision)
    .execute(&mut *conn)
    .await?;
    if advanced != 1 {
        return Err(
            PersistenceError::Conflict("pcr_fork_conflict_index_cas_mismatch".to_owned()).into(),
        );
    }
    Ok(())
}
