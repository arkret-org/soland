//! Immutable accepted PCR revoke dots and a same-snapshot keyed-set reader.

use arkret_models_collaboration::events_payloads::DeviceRevokePayload;
use arkret_wire::{
    AccountId, CommitStreamRef, DeviceId, Event, EventKind, RealmCommit, RealmCommitId,
};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, pg_conn};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationProposal {
    pub tag_id: String,
    pub value: DeviceRevokePayload,
}

pub(crate) struct ConfirmedRevocationProposals {
    pub authority_commit_id: RealmCommitId,
    pub proposals: Vec<RevocationProposal>,
}

#[derive(QueryableByName)]
struct PrincipalRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

#[derive(QueryableByName)]
struct StoredProposalRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    tag_id: String,
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

#[derive(QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type = Text)]
    head_commit_id: String,
    #[diesel(sql_type = BigInt)]
    accepted_count: i64,
    #[diesel(sql_type = BigInt)]
    projected_count: i64,
    #[diesel(sql_type = BigInt)]
    matched_count: i64,
    #[diesel(sql_type = Jsonb)]
    proposals: Value,
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

/// Called only from a registered revoke UoW after producer, device and
/// command-result validation. It does not itself make a generic revoke safe.
pub(crate) async fn project_revoke_proposal_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::DeviceRevoke
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "revoke proposal Event and accepted PCR Commit differ",
        ));
    }
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("revoke proposal actor is not an Account"))?;
    let principal = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PrincipalRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("revoke proposal has no accepted PCR resolution"))?;
    if principal.pcr_realm_id != event.realm_id.as_str() {
        return Err(invalid("revoke proposal is outside its PCR"));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let typed: DeviceRevokePayload = serde_json::from_value(payload.clone())
        .map_err(|error| invalid(format!("invalid revoke payload: {error}")))?;
    typed
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let tag_id = format!("{}:0", event.event_id);
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("revoke proposal position overflow"))?;
    sql_query(
        "INSERT INTO pcr_device_revocation_proposals \
         (realm_id,device_id,tag_id,event_id,commit_id,stream_position,payload) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(typed.device_id.as_str())
    .bind::<Text, _>(&tag_id)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&payload)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let stored = sql_query(
        "SELECT realm_id,device_id,tag_id,commit_id,stream_position,payload \
         FROM pcr_device_revocation_proposals WHERE event_id=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .get_result::<StoredProposalRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if stored.realm_id != event.realm_id.as_str()
        || stored.device_id != typed.device_id.as_str()
        || stored.tag_id != tag_id
        || stored.commit_id != commit.commit_id.as_str()
        || stored.stream_position != position
        || stored.payload != payload
    {
        return Err(PersistenceError::Conflict(
            "device_revocation_proposal_duplicate_conflict".to_owned(),
        ));
    }
    Ok(())
}

/// One SQL statement fixes the head, accepted revoke count and canonical dot
/// set at one MVCC snapshot. An accepted revoke without its dot is unavailable.
pub(crate) async fn confirmed_revocation_proposals(
    pool: &PgPool,
    account: &AccountId,
    device_id: &DeviceId,
) -> PersistenceResult<Option<ConfirmedRevocationProposals>> {
    let mut conn = pg_conn(pool).await?;
    let row = sql_query(
        "SELECT h.commit_id AS head_commit_id, \
           (SELECT count(*) FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.pcr_realm_id AND e.kind='ak.device.revoke' \
              AND e.envelope->'payload'->>'device_id'=$3) AS accepted_count, \
           (SELECT count(*) FROM pcr_device_revocation_proposals r \
            WHERE r.realm_id=p.pcr_realm_id AND r.device_id=$3) AS projected_count, \
           (SELECT count(*) FROM pcr_device_revocation_proposals r \
            JOIN realm_commits c ON c.commit_id=r.commit_id \
            JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE r.realm_id=p.pcr_realm_id AND r.device_id=$3 \
              AND c.realm_id=r.realm_id AND c.stream_position=r.stream_position \
              AND e.kind='ak.device.revoke' AND e.envelope->>'event_id'=r.event_id \
              AND e.envelope->'payload'=r.payload) AS matched_count, \
           (SELECT coalesce(jsonb_agg(jsonb_build_object('tag_id',r.tag_id,'value',r.payload) \
                   ORDER BY r.tag_id),'[]'::jsonb) \
            FROM pcr_device_revocation_proposals r \
            WHERE r.realm_id=p.pcr_realm_id AND r.device_id=$3) AS proposals \
         FROM principal_resolutions p \
         JOIN LATERAL (SELECT commit_id FROM realm_commits \
                       WHERE realm_id=p.pcr_realm_id \
                         AND stream_ref=jsonb_build_object('kind','realm','realm_id',p.pcr_realm_id) \
                       ORDER BY stream_position DESC LIMIT 1) h ON TRUE \
         WHERE p.principal_id=$1 AND p.station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(device_id.as_str())
    .get_result::<SnapshotRow>(&mut conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    if row.accepted_count != row.projected_count
        || row.projected_count != row.matched_count
    {
        return Err(invalid(
            "accepted PCR revoke proposals are not fully projected",
        ));
    }
    let proposals: Vec<RevocationProposal> = serde_json::from_value(row.proposals)
        .map_err(|error| invalid(format!("stored revoke proposals are invalid: {error}")))?;
    for proposal in &proposals {
        if proposal.value.device_id != *device_id || !proposal.tag_id.ends_with(":0") {
            return Err(invalid("stored revoke proposal selector differs"));
        }
    }
    Ok(Some(ConfirmedRevocationProposals {
        authority_commit_id: RealmCommitId::new(row.head_commit_id)
            .map_err(|error| invalid(error.to_string()))?,
        proposals,
    }))
}
