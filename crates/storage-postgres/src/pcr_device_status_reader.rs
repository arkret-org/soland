//! One repeatable-read PCR cut for the device lifecycle inputs. No caller may
//! infer `active` from an empty fork table or an absent transaction result.

use arkret_models_crypto::{SecurityRotationRevokeCommandResult, SecurityTransactionStep};
use arkret_wire::{AccountId, DeviceId};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::pcr_device_revocation_proposals::{
    ConfirmedPcrDeviceCut, confirmed_pcr_device_cut_in_connection,
};
use crate::pcr_device_status_fold::{
    PcrDeviceLifecycle, RevokeCommandDecision, fold_confirmed_device_status,
};
use crate::{
    AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, PgTransactionError, pg_conn,
};

#[derive(QueryableByName)]
struct StatusInputsRow {
    #[diesel(sql_type = Text)]
    pcr_head_commit_id: String,
    #[diesel(sql_type = BigInt)]
    conflict_revision: i64,
    #[diesel(sql_type = BigInt)]
    conflict_record_count: i64,
    #[diesel(sql_type = BigInt)]
    device_conflict_count: i64,
    #[diesel(sql_type = BigInt)]
    generation_conflict_count: i64,
    #[diesel(sql_type = BigInt)]
    proposal_count: i64,
    #[diesel(sql_type = BigInt)]
    bound_transaction_count: i64,
    #[diesel(sql_type = Jsonb)]
    transaction_rows: Value,
}

pub(crate) struct ConfirmedPcrDeviceStatusCut {
    pub authority: ConfirmedPcrDeviceCut,
    pub lifecycle: PcrDeviceLifecycle,
    pub generation_conflicted: bool,
}

fn incomplete(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

/// Read all inputs under a single PostgreSQL REPEATABLE READ snapshot. The
/// transaction-local isolation setting is the first statement after BEGIN.
pub(crate) async fn confirmed_pcr_device_status_cut(
    pool: &PgPool,
    account: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<ConfirmedPcrDeviceStatusCut>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<Option<ConfirmedPcrDeviceStatusCut>, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        confirmed_pcr_device_status_cut_in_connection(conn, account, device_id, now).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Use only while the caller owns one PCR authority transaction. Reads every
/// device input from that same connection; the caller must serialize writers
/// before using this result for admission.
pub(crate) async fn confirmed_pcr_device_status_cut_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<ConfirmedPcrDeviceStatusCut>, PgTransactionError> {
    let Some(authority) = confirmed_pcr_device_cut_in_connection(conn, account, device_id).await?
    else {
        return Ok(None);
    };
    let row = sql_query(
            "SELECT m.pcr_head_commit_id,m.conflict_revision, \
               (SELECT count(*) FROM pcr_verified_fork_records f WHERE f.realm_id=$1) AS conflict_record_count, \
               (SELECT count(*) FROM pcr_verified_fork_records f WHERE f.realm_id=$1 AND $2=ANY(f.affected_device_ids)) AS device_conflict_count, \
               (SELECT count(*) FROM pcr_verified_fork_records f WHERE f.realm_id=$1 AND f.affects_generation) AS generation_conflict_count, \
               (SELECT count(*) FROM pcr_device_revocation_proposals r WHERE r.realm_id=$1 AND r.device_id=$2) AS proposal_count, \
               (SELECT count(*) FROM pcr_device_revocation_proposals r JOIN security_transactions t \
                  ON t.revoke_proposal->>'proposal_event_id'=r.event_id \
                 AND t.revoke_proposal->>'covering_commit_id'=r.commit_id \
                 AND t.kind='security_rotation' AND t.principal_id=$3 AND t.station_id=$4 \
                 AND t.prepared_plan->'revoke_unit'->'request'->'events'->0->>'event_id'=r.event_id \
                WHERE r.realm_id=$1 AND r.device_id=$2) AS bound_transaction_count, \
               (SELECT coalesce(jsonb_agg(jsonb_build_object( \
                    'event_id',r.event_id,'commit_id',r.commit_id,'tag_id',r.tag_id, \
                    'transaction_id',t.id::text, \
                    'proposal',t.revoke_proposal,'outcome',t.revoke_command_outcome, \
                    'terminal',t.terminal_outcome,'accepted_steps',t.accepted_steps) \
                    ORDER BY r.tag_id),'[]'::jsonb) \
                  FROM pcr_device_revocation_proposals r LEFT JOIN security_transactions t \
                    ON t.revoke_proposal->>'proposal_event_id'=r.event_id \
                   AND t.revoke_proposal->>'covering_commit_id'=r.commit_id \
                   AND t.kind='security_rotation' AND t.principal_id=$3 AND t.station_id=$4 \
                   AND t.prepared_plan->'revoke_unit'->'request'->'events'->0->>'event_id'=r.event_id \
                 WHERE r.realm_id=$1 AND r.device_id=$2) AS transaction_rows \
             FROM pcr_device_conflict_index_cuts m WHERE m.realm_id=$1",
        )
        .bind::<Text, _>(authority.realm_id.as_str())
        .bind::<Text, _>(device_id.as_str())
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .get_result::<StatusInputsRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| incomplete("PCR conflict index cut is missing"))?;
    if row.pcr_head_commit_id != authority.authority_commit_id.as_str()
        || row.conflict_revision != row.conflict_record_count
        || row.proposal_count != authority.proposals.len() as i64
        || row.bound_transaction_count != row.proposal_count
    {
        return Err(incomplete("PCR device status inputs are incomplete").into());
    }
    let rows = row
        .transaction_rows
        .as_array()
        .ok_or_else(|| incomplete("PCR revoke transaction rows are not an array"))?;
    if rows.len() != authority.proposals.len() {
        return Err(incomplete("PCR revoke transaction rows are incomplete").into());
    }
    let mut decisions = Vec::with_capacity(rows.len());
    for (source, record) in authority.proposals.iter().zip(rows) {
        let tag_id = record["tag_id"].as_str();
        let event_id = record["event_id"].as_str();
        let commit_id = record["commit_id"].as_str();
        if tag_id != Some(source.tag_id.as_str())
            || event_id != source.tag_id.strip_suffix(":0")
            || record["proposal"]["proposal_event_id"].as_str() != event_id
            || record["proposal"]["covering_commit_id"].as_str() != commit_id
        {
            return Err(incomplete("PCR revoke transaction provenance differs").into());
        }
        let transaction_uuid = record["transaction_id"]
            .as_str()
            .ok_or_else(|| incomplete("PCR revoke transaction id is absent"))?;
        let transaction_id = format!("ak:transaction:{transaction_uuid}");
        let stored = crate::security_transactions::load_one(conn, &transaction_id, false)
            .await?
            .ok_or_else(|| incomplete("PCR revoke transaction is absent"))?;
        let resource = stored.resource;
        let plan = resource
            .security_rotation_plan()
            .ok_or_else(|| incomplete("PCR revoke transaction is not SecurityRotation"))?;
        let durable_step = crate::security_transactions::load_step_outcome(
            conn,
            &transaction_id,
            SecurityTransactionStep::Revoke,
        )
        .await?;
        if resource.revoke_proposal.as_ref().is_none_or(|proposal| {
            Some(proposal.proposal_event_id.as_str()) != event_id
                || Some(proposal.covering_commit_id.as_str()) != commit_id
        }) || plan
            .revoke_unit
            .request
            .events
            .as_slice()
            .first()
            .is_none_or(|event| Some(event.event_id.as_str()) != event_id)
        {
            return Err(incomplete("PCR revoke typed transaction changed its proposal").into());
        }
        let decision = match resource.revoke_command_outcome.as_ref() {
            Some(outcome) if outcome.result == SecurityRotationRevokeCommandResult::Accepted => {
                if durable_step.is_none()
                    || resource
                        .accepted_steps
                        .as_slice()
                        .first()
                        .is_none_or(|step| {
                            step.prepared_material_digest != plan.revoke_unit.request_digest
                        })
                {
                    return Err(incomplete(
                        "PCR revoke accepted step digest differs from the prepared unit",
                    )
                    .into());
                }
                RevokeCommandDecision::Accepted
            }
            Some(outcome) if outcome.result == SecurityRotationRevokeCommandResult::Rejected => {
                if durable_step.is_some() {
                    return Err(
                        incomplete("PCR rejected revoke has an accepted step outcome").into(),
                    );
                }
                RevokeCommandDecision::Rejected
            }
            None if durable_step.is_none() => RevokeCommandDecision::Pending,
            _ => return Err(incomplete("PCR revoke command outcome is invalid").into()),
        };
        if !record["outcome"].is_null()
            && (record["outcome"]["proposal_event_id"].as_str() != event_id
                || record["outcome"]["covering_commit_id"].as_str() != commit_id)
        {
            return Err(incomplete("PCR revoke outcome changed its proposal").into());
        }
        decisions.push(decision);
    }
    let authorization = authority
        .authorization
        .as_ref()
        .ok_or_else(|| incomplete("PCR device has no current authorization"))?;
    let generation = authority
        .current_generation
        .ok_or_else(|| incomplete("PCR device has no current generation"))?;
    let lifecycle = fold_confirmed_device_status(
        &authorization.payload,
        generation,
        &decisions,
        row.device_conflict_count > 0,
        now,
    );
    Ok(Some(ConfirmedPcrDeviceStatusCut {
        authority,
        lifecycle,
        generation_conflicted: row.generation_conflict_count > 0,
    }))
}
