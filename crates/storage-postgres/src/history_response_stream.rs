use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_collaboration::history_key::{
    HistoryKeyRequest, HistoryKeyRequestReceipt, HistoryKeyRequestReplica,
    HistoryKeyResponseAckRequest, HistoryKeyResponseLostRecord, HistoryKeyResponseRecord,
    HistoryKeyResponseSendReceipt, HistoryKeyResponseSendRequest, HistoryManifestAdmission,
    HistoryReleaseAttestation, HistoryResponseAckEntry, HistoryResponseAckTokenClaims,
    HistoryResponseId, HistoryResponsePageEntry, SealedHistoryResponseCapability,
};
use arkret_wire::{Hash, HistoryEffectiveScope};
use chrono::{DateTime, Duration, Utc};
use soland_storage::{
    ExactWriteOutcome, HISTORY_COMPACT_RECEIPTS_PER_REQUEST_LIMIT,
    HISTORY_COMPACT_RECEIPTS_PER_REQUESTER_LIMIT, HISTORY_RESPONSE_STREAM_ACTIVE_BYTES_LIMIT,
    HistoryAcceptedManifestRecord, HistoryAuthorityViewCas, HistoryRequestPage,
    HistoryRequestPutOutcome, HistoryRequestRecord, HistoryRequestWrite,
    HistoryResponseAckTokenWrite, HistoryResponseCompleteOutcome, HistoryResponseCompleteWrite,
    HistoryResponseReadPage, HistoryResponseReservationInput, HistoryResponseReservationRecord,
    HistoryResponseRetryRecord, HistoryResponseStreamStore, HistoryResponseTombstone,
    PersistenceError, PersistenceResult, history_lost_record_bytes, history_lost_record_digest,
    history_response_capability_commitment_matches, history_scope_parts,
};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Jsonb, Nullable, OptionalExtension, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait,
    pg_conn, sql_query,
};
use crate::governance_history::{
    append_lost_signer_dependencies_in_transaction,
    append_response_signer_dependencies_in_transaction, load_retention,
    persist_retention_in_transaction, release_retention_in_transaction,
};

#[derive(QueryableByName)]
struct RequestRow {
    #[diesel(sql_type = BigInt)]
    request_sequence: i64,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    request_receipt_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_json: Value,
    #[diesel(sql_type = Jsonb)]
    request_receipt_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    sealed_history_response_capability_json: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    request_replica_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    request_replica_json: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    stored_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct TextValueRow {
    #[diesel(sql_type = Text)]
    value: String,
}

fn release_authority_seal_bases(
    attestation: &HistoryReleaseAttestation,
) -> PersistenceResult<BTreeMap<String, Vec<String>>> {
    let views = &attestation.accepted_authority_views;
    let mut bases = BTreeMap::new();
    insert_authority_seal_basis(
        &mut bases,
        views.scope_realm.authority_realm_id.as_str(),
        views
            .scope_realm
            .seal_basis
            .leaves
            .iter()
            .map(|leaf| leaf.as_str().to_owned())
            .collect(),
    )?;
    if let Some(circle) = &views.scope_circle {
        insert_authority_seal_basis(
            &mut bases,
            circle.authority_realm_id.as_str(),
            circle
                .seal_basis
                .leaves
                .iter()
                .map(|leaf| leaf.as_str().to_owned())
                .collect(),
        )?;
    }
    if let Some(pcr) = &views.recipient_pcr_device {
        insert_authority_seal_basis(
            &mut bases,
            pcr.principal_control_realm_id.as_str(),
            pcr.pcr_seal_basis
                .leaves
                .iter()
                .map(|leaf| leaf.as_str().to_owned())
                .collect(),
        )?;
    }
    Ok(bases)
}

fn insert_authority_seal_basis(
    bases: &mut BTreeMap<String, Vec<String>>,
    realm_id: &str,
    mut leaves: Vec<String>,
) -> PersistenceResult<()> {
    leaves.sort();
    leaves.dedup();
    if let Some(existing) = bases.get(realm_id) {
        if existing != &leaves {
            return Err(PersistenceError::SchemaViolation(
                "history authority locators disagree on a Realm Seal basis".to_owned(),
            ));
        }
    } else {
        bases.insert(realm_id.to_owned(), leaves);
    }
    Ok(())
}

async fn lock_and_validate_release_authority(
    conn: &mut AsyncPgConnection,
    attestation: &HistoryReleaseAttestation,
) -> Result<(), PgTransactionError> {
    // Hold the accepted Seal/quarantine relation stable until the stream row
    // is written. Advisory locks alone cannot fence a concurrent writer that
    // does not participate in this service-local lock namespace.
    sql_query("LOCK TABLE state_seals IN SHARE MODE")
        .execute(&mut *conn)
        .await?;
    sql_query("LOCK TABLE state_seal_quarantine IN SHARE MODE")
        .execute(&mut *conn)
        .await?;
    sql_query("LOCK TABLE state_seal_quarantine_realms IN SHARE MODE")
        .execute(&mut *conn)
        .await?;
    let mut bases = release_authority_seal_bases(attestation)?;
    if let Some(agent) = &attestation
        .accepted_authority_views
        .recipient_agent_control_evidence
    {
        let mut authority_realm_id = None;
        for leaf in &agent.control_basis.leaves {
            let realm_id = sql_query("SELECT realm_id AS value FROM state_seals WHERE id=$1")
                .bind::<Text, _>(leaf.as_str())
                .get_result::<TextValueRow>(&mut *conn)
                .await
                .optional()?
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "failed_precondition: Agent authority Seal is unavailable".to_owned(),
                    )
                })?
                .value;
            if authority_realm_id
                .as_ref()
                .is_some_and(|current: &String| current != &realm_id)
            {
                return Err(PersistenceError::SchemaViolation(
                    "Agent authority control basis spans multiple Realms".to_owned(),
                )
                .into());
            }
            authority_realm_id = Some(realm_id);
        }
        insert_authority_seal_basis(
            &mut bases,
            &authority_realm_id.ok_or_else(|| {
                PersistenceError::SchemaViolation(
                    "Agent authority control basis is empty".to_owned(),
                )
            })?,
            agent
                .control_basis
                .leaves
                .iter()
                .map(|leaf| leaf.as_str().to_owned())
                .collect(),
        )?;
    }
    for realm_id in bases.keys() {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind::<Text, _>(realm_id)
            .execute(&mut *conn)
            .await?;
    }
    for (realm_id, expected_leaves) in bases {
        let quarantined = sql_query(
            "SELECT realm_id AS value FROM state_seal_quarantine_realms WHERE realm_id=$1 LIMIT 1",
        )
        .bind::<Text, _>(&realm_id)
        .get_result::<TextValueRow>(&mut *conn)
        .await
        .optional()?;
        if quarantined.is_some() {
            return Err(PersistenceError::Conflict(
                "frontier_unavailable: history authority Realm has a quarantined Seal".to_owned(),
            )
            .into());
        }
        let current_leaves = sql_query(
            "SELECT parent.id AS value FROM state_seals parent WHERE parent.realm_id=$1 AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=parent.id) AND NOT EXISTS (SELECT 1 FROM state_seals child WHERE child.realm_id=$1 AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=child.id) AND child.predecessor_refs ? parent.id) ORDER BY parent.id ASC",
        )
        .bind::<Text, _>(&realm_id)
        .load::<TextValueRow>(&mut *conn)
        .await?
        .into_iter()
        .map(|row| row.value)
        .collect::<Vec<_>>();
        if current_leaves != expected_leaves {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history authority Seal basis is no longer current".to_owned(),
            )
            .into());
        }
    }
    Ok(())
}

#[derive(QueryableByName)]
struct ResponseRow {
    #[diesel(sql_type = Text)]
    response_id: String,
    #[diesel(sql_type = Text)]
    request_id: String,
    #[diesel(sql_type = Text)]
    source_record_digest: String,
    #[diesel(sql_type = Jsonb)]
    source_record_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    manifest_admission_json: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    manifest_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    manifest_admission_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    release_attestation_json: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    release_service_signer_evidence_json: Value,
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = Nullable<Text>)]
    cursor: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    sent_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    reserved_at: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    record_json: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    lost_record_json: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    send_receipt_json: Option<Value>,
    #[diesel(sql_type = BigInt)]
    active_bytes: i64,
    #[diesel(sql_type = BigInt)]
    compact_receipt_bytes: i64,
}

#[derive(QueryableByName)]
struct ResponseStreamRow {
    #[diesel(sql_type = Text)]
    request_id: String,
    #[diesel(sql_type = Text)]
    release_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    response_capability_commitment: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<BigInt>)]
    acked_sequence: Option<i64>,
}

fn authorize_response_stream_row(
    row: Option<ResponseStreamRow>,
    presented: &Hash,
    now: DateTime<Utc>,
) -> PersistenceResult<ResponseStreamRow> {
    let commitment_matches = history_response_capability_commitment_matches(
        row.as_ref()
            .map(|row| row.response_capability_commitment.as_str()),
        presented,
    );
    row.filter(|row| commitment_matches & (row.expires_at > now))
        .ok_or_else(|| PersistenceError::NotFound("history stream unavailable".to_owned()))
}

#[cfg(test)]
mod capability_authorization_tests {
    use super::*;

    fn commitment(hex: char) -> Hash {
        Hash::new(format!("sha256:{}", hex.to_string().repeat(64))).expect("valid hash")
    }

    fn row(commitment: &Hash, expires_at: DateTime<Utc>) -> ResponseStreamRow {
        ResponseStreamRow {
            request_id: "ak:history-key-request:01910000-0000-7000-8000-000000000001".to_owned(),
            release_id: arkret_wire::DidCoreId::new("ak:did_core:webvh:example").unwrap(),
            response_capability_commitment: commitment.as_str().to_owned(),
            expires_at,
            acked_sequence: None,
        }
    }

    #[test]
    fn authorization_hides_missing_and_expired_streams_behind_not_found() {
        let now = Utc::now();
        let presented = commitment('a');
        assert!(authorize_response_stream_row(None, &presented, now).is_err());
        assert!(
            authorize_response_stream_row(
                Some(row(&presented, now - Duration::seconds(1))),
                &presented,
                now,
            )
            .is_err()
        );
        assert!(
            authorize_response_stream_row(
                Some(row(&presented, now + Duration::seconds(1))),
                &presented,
                now,
            )
            .is_ok()
        );
    }
}

#[derive(QueryableByName)]
struct SequenceRow {
    #[diesel(sql_type = BigInt)]
    sequence: i64,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct CompactReceiptAuthorityRow {
    #[diesel(sql_type = Text)]
    requester_actor_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    release_id: arkret_wire::DidCoreId,
}

#[derive(QueryableByName)]
struct AcceptedManifestRow {
    #[diesel(sql_type = Jsonb)]
    source_record_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    manifest_admission_json: Option<Value>,
}

#[derive(QueryableByName)]
struct SumRow {
    #[diesel(sql_type = Nullable<BigInt>)]
    total: Option<i64>,
}

#[derive(QueryableByName)]
struct TokenRow {
    #[diesel(sql_type = Jsonb)]
    claims_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    consumed_request_json: Option<Value>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct TombstoneRow {
    #[diesel(sql_type = Text)]
    response_id: String,
    #[diesel(sql_type = Text)]
    source_record_digest: String,
    #[diesel(sql_type = Text)]
    terminal_status: String,
    #[diesel(sql_type = Timestamptz)]
    expired_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    retain_until: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct RetentionDigestRow {
    #[diesel(sql_type = Nullable<Text>)]
    traversal_retention_digest: Option<String>,
}

fn encode<T: serde::Serialize>(value: &T) -> PersistenceResult<Value> {
    serde_json::to_value(value).map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(value: Value, field: &str) -> PersistenceResult<T> {
    serde_json::from_value(value)
        .map_err(|error| PersistenceError::Internal(format!("stored {field} is invalid: {error}")))
}

fn as_u64(value: i64, field: &str) -> PersistenceResult<u64> {
    u64::try_from(value)
        .map_err(|_| PersistenceError::Internal(format!("stored {field} is negative")))
}

fn as_i64(value: u64, field: &str) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation(format!("{field} exceeds PostgreSQL bigint"))
    })
}

fn stored_hash(value: String, field: &str) -> PersistenceResult<Hash> {
    Hash::new(value).map_err(|error| PersistenceError::Internal(format!("stored {field}: {error}")))
}

fn decode_request(row: RequestRow) -> PersistenceResult<HistoryRequestRecord> {
    let request_replica = row
        .request_replica_json
        .map(|value| decode::<HistoryKeyRequestReplica>(value, "request replica"))
        .transpose()?;
    match (&row.request_replica_digest, &request_replica) {
        (Some(stored), Some(replica))
            if replica
                .request_replica_digest()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?
                .as_str()
                == stored.as_str() => {}
        (None, None) => {}
        _ => {
            return Err(PersistenceError::Internal(
                "stored history request replica binding is invalid".to_owned(),
            ));
        }
    }
    Ok(HistoryRequestRecord {
        sequence: as_u64(row.request_sequence, "request sequence")?,
        write: HistoryRequestWrite {
            request_digest: stored_hash(row.request_digest, "request digest")?,
            request_receipt_digest: stored_hash(
                row.request_receipt_digest,
                "request receipt digest",
            )?,
            request: decode::<HistoryKeyRequest>(row.request_json, "request")?,
            request_receipt: decode::<HistoryKeyRequestReceipt>(
                row.request_receipt_json,
                "request receipt",
            )?,
            sealed_history_response_capability: row
                .sealed_history_response_capability_json
                .map(|value| {
                    decode::<SealedHistoryResponseCapability>(
                        value,
                        "sealed history response capability",
                    )
                })
                .transpose()?,
            local_traversal: None,
            request_replica,
            stored_at: row.stored_at,
        },
    })
}

fn reservation(row: &ResponseRow) -> PersistenceResult<HistoryResponseReservationRecord> {
    let manifest_admission = row
        .manifest_admission_json
        .clone()
        .map(|value| decode::<HistoryManifestAdmission>(value, "manifest admission"))
        .transpose()?;
    match (
        &manifest_admission,
        &row.manifest_digest,
        &row.manifest_admission_digest,
    ) {
        (Some(admission), Some(manifest_digest), Some(admission_digest))
            if admission.manifest_digest.as_str() == manifest_digest.as_str()
                && admission.manifest_admission_digest.as_str() == admission_digest.as_str() => {}
        (None, None, None) => {}
        _ => {
            return Err(PersistenceError::Internal(
                "stored history response manifest binding is invalid".to_owned(),
            ));
        }
    }
    Ok(HistoryResponseReservationRecord {
        sequence: as_u64(row.sequence, "response sequence")?,
        input: HistoryResponseReservationInput {
            source_record_digest: stored_hash(
                row.source_record_digest.clone(),
                "source record digest",
            )?,
            source_record: decode::<HistoryKeyResponseSendRequest>(
                row.source_record_json.clone(),
                "source record",
            )?,
            manifest_admission,
            release_attestation: row
                .release_attestation_json
                .clone()
                .map(|value| decode::<HistoryReleaseAttestation>(value, "release attestation"))
                .transpose()?,
            release_service_signer_evidence: decode::<
                arkret_models_collaboration::governance_dependencies::GovernanceDependency,
            >(
                row.release_service_signer_evidence_json.clone(),
                "release service signer evidence",
            )?,
            sent_at: row.sent_at,
        },
        reserved_at: row.reserved_at,
    })
}

fn page_entry(row: &ResponseRow) -> PersistenceResult<HistoryResponsePageEntry> {
    match row.state.as_str() {
        "accepted" => Ok(HistoryResponsePageEntry::Record {
            record: decode(
                row.record_json.clone().ok_or_else(|| {
                    PersistenceError::Internal("accepted response lost record bytes".to_owned())
                })?,
                "response record",
            )?,
        }),
        "lost" => Ok(HistoryResponsePageEntry::Lost {
            lost_record: decode(
                row.lost_record_json.clone().ok_or_else(|| {
                    PersistenceError::Internal("lost response lacks descriptor".to_owned())
                })?,
                "lost descriptor",
            )?,
        }),
        state => Err(PersistenceError::Internal(format!(
            "stream row has unreadable state {state}"
        ))),
    }
}

async fn request_by(
    conn: &mut AsyncPgConnection,
    column: &str,
    value: &str,
) -> PersistenceResult<Option<HistoryRequestRecord>> {
    let row=sql_query(format!(
        "SELECT request_sequence,request_digest,request_receipt_digest,request_json, \
         request_receipt_json,sealed_history_response_capability_json,request_replica_digest,request_replica_json,stored_at \
         FROM history_key_requests WHERE {column}=$1"
    ))
    .bind::<Text, _>(value)
    .get_result::<RequestRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut record = decode_request(row)?;
    if record.write.sealed_history_response_capability.is_some() {
        let retention_digest = record.write.traversal_retention_digest().clone();
        record.write.local_traversal = Some(
            load_retention(conn, &retention_digest)
                .await?
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "local history request lost its traversal retention".to_owned(),
                    )
                })?
                .write,
        );
    }
    Ok(Some(record))
}

async fn response_by(
    conn: &mut AsyncPgConnection,
    response_id: &str,
    lock: bool,
) -> PersistenceResult<Option<ResponseRow>> {
    let lock = if lock { " FOR UPDATE" } else { "" };
    sql_query(format!(
        "SELECT response_id,request_id,source_record_digest,source_record_json, \
         manifest_admission_json,manifest_digest,manifest_admission_digest,release_attestation_json,release_service_signer_evidence_json,sequence,cursor,sent_at,reserved_at, \
         state,record_json,lost_record_json,send_receipt_json,active_bytes,compact_receipt_bytes \
         FROM history_key_responses WHERE response_id=$1{lock}"
    ))
    .bind::<Text, _>(response_id)
    .get_result::<ResponseRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)
}

pub struct PgHistoryResponseStreamStore {
    pub pool: PgPool,
}

#[async_trait]
impl HistoryResponseStreamStore for PgHistoryResponseStreamStore {
    fn bind_authority_view_cas(&self, _authority_view_cas: Arc<dyn HistoryAuthorityViewCas>) {}

    async fn put_request_exact(
        &self,
        write: HistoryRequestWrite,
    ) -> PersistenceResult<HistoryRequestPutOutcome> {
        write.validate()?;
        let request_json = encode(&write.request)?;
        let receipt_json = encode(&write.request_receipt)?;
        let capability_json = write
            .sealed_history_response_capability
            .as_ref()
            .map(encode)
            .transpose()?;
        let request_replica_digest = write
            .request_replica
            .as_ref()
            .map(HistoryKeyRequestReplica::request_replica_digest)
            .transpose()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let request_replica_json = write.request_replica.as_ref().map(encode).transpose()?;
        let (scope_kind, realm_id, circle_id) = history_scope_parts(&write.request.effective_scope);
        let scope_kind = scope_kind.to_owned();
        let realm_id = realm_id.to_owned();
        let circle_id = circle_id.map(ToOwned::to_owned);
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!("history-request:{}", write.request.request_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await?;
            if let Some(existing) =
                request_by(conn, "request_id", write.request.request_id.as_str()).await?
            {
                if existing.write.request_digest == write.request_digest
                    && existing.write.request_receipt_digest == write.request_receipt_digest
                    && existing.write.request == write.request
                    && existing.write.request_receipt == write.request_receipt
                    && existing.write.sealed_history_response_capability
                        == write.sealed_history_response_capability
                    && existing.write.request_replica == write.request_replica
                {
                    if let Some(expected) = &write.local_traversal {
                        let stored = load_retention(
                            conn,
                            &write.request_receipt.history_traversal_retention.traversal_intent_digest,
                        )
                        .await?
                        .ok_or_else(|| {
                            PersistenceError::Internal(
                                "local history request lost its traversal retention".to_owned(),
                            )
                        })?;
                        if &stored.write != expected {
                            return Err(PersistenceError::Conflict(
                                "duplicate_conflict: local traversal retention differs".to_owned(),
                            )
                            .into());
                        }
                    }
                    return Ok(HistoryRequestPutOutcome::Stored {
                        outcome: ExactWriteOutcome::ExactReplay,
                        record: Box::new(existing),
                    });
                }
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: history request id differs".to_owned(),
                )
                .into());
            }
            if write.local_traversal.is_some() {
                let commitment = write
                    .request_receipt
                    .response_capability_commitment
                    .as_str();
                let capability_lock = format!("history-response-capability:{commitment}");
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                    .bind::<Text, _>(&capability_lock)
                    .execute(&mut *conn)
                    .await?;
                let bound = sql_query(
                    "SELECT request_id AS value FROM history_key_response_streams \
                     WHERE response_capability_commitment=$1 LIMIT 1",
                )
                .bind::<Text, _>(commitment)
                .get_result::<TextValueRow>(&mut *conn)
                .await
                .optional()?;
                if bound.is_some() {
                    return Ok(HistoryRequestPutOutcome::CapabilityCommitmentCollision);
                }
            }
            let collision = sql_query(
                "SELECT request_sequence AS sequence FROM history_key_requests \
                 WHERE request_digest=$1 OR request_receipt_digest=$2 OR request_id=$3 \
                 OR ($4 IS NOT NULL AND request_replica_digest=$4) LIMIT 1",
            )
            .bind::<Text, _>(write.request_digest.as_str())
            .bind::<Text, _>(write.request_receipt_digest.as_str())
            .bind::<Text, _>(write.request.request_id.as_str())
            .bind::<Nullable<Text>, _>(request_replica_digest.as_ref().map(|digest| digest.as_str()))
            .get_result::<SequenceRow>(&mut *conn)
            .await
            .optional()?;
            if collision.is_some() {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: history request digest or stream is already bound"
                        .to_owned(),
                )
                .into());
            }
            let quota_lock = format!(
                "history-request-quota:{scope_kind}:{realm_id}:{}:{}",
                circle_id.as_deref().unwrap_or(""),
                write.request.requester_sender_domain
            );
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind::<Text, _>(&quota_lock)
                .execute(&mut *conn)
                .await?;
            let active = sql_query(
                "SELECT COUNT(*)::bigint AS count FROM history_key_requests \
                 WHERE effective_scope_kind=$1 AND realm_id=$2 AND circle_id IS NOT DISTINCT FROM $3 \
                 AND requester_sender_domain=$4 AND expires_at>$5",
            )
            .bind::<Text, _>(&scope_kind)
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(circle_id.as_deref())
            .bind::<Text, _>(&write.request.requester_sender_domain)
            .bind::<Timestamptz, _>(write.stored_at)
            .get_result::<CountRow>(&mut *conn)
            .await?;
            if active.count >= 16 {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: history request scope sender limit reached".to_owned(),
                )
                .into());
            }
            if let Some(traversal) = &write.local_traversal
                && persist_retention_in_transaction(conn, traversal).await?
                    != ExactWriteOutcome::Inserted
                {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: local traversal retention is already bound".to_owned(),
                    )
                    .into());
                }
            let sequence = sql_query(
                "INSERT INTO history_key_requests \
                 (request_id,request_digest,request_receipt_digest,effective_scope_kind, \
                  realm_id,circle_id,requester_actor_id,requester_sender_domain,release_id, \
                  traversal_retention_digest,request_json, \
                  request_receipt_json,sealed_history_response_capability_json,request_replica_digest,request_replica_json, \
                  stored_at,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
                 RETURNING request_sequence AS sequence",
            )
            .bind::<Text, _>(write.request.request_id.as_str())
            .bind::<Text, _>(write.request_digest.as_str())
            .bind::<Text, _>(write.request_receipt_digest.as_str())
            .bind::<Text, _>(&scope_kind)
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(circle_id.as_deref())
            .bind::<Text, _>(write.request.requester_actor_id.to_string())
            .bind::<Text, _>(&write.request.requester_sender_domain)
            .bind::<Text, _>(write.request_receipt.release_id.as_str())
            .bind::<Nullable<Text>, _>(write.local_traversal.as_ref().map(|_| write.traversal_retention_digest().as_str()))
            .bind::<Jsonb, _>(&request_json)
            .bind::<Jsonb, _>(&receipt_json)
            .bind::<Nullable<Jsonb>, _>(capability_json.as_ref())
            .bind::<Nullable<Text>, _>(request_replica_digest.as_ref().map(|digest| digest.as_str()))
            .bind::<Nullable<Jsonb>, _>(request_replica_json.as_ref())
            .bind::<Timestamptz, _>(write.stored_at)
            .bind::<Timestamptz, _>(write.request.expires_at)
            .get_result::<SequenceRow>(&mut *conn)
            .await?;
            if write.local_traversal.is_some() {
                sql_query(
                    "INSERT INTO history_key_response_streams \
                     (request_id,response_capability_commitment,created_at) \
                     VALUES ($1,$2,$3)",
                )
                .bind::<Text, _>(write.request.request_id.as_str())
                .bind::<Text, _>(write.request_receipt.response_capability_commitment.as_str())
                .bind::<Timestamptz, _>(write.stored_at)
                .execute(&mut *conn)
                .await?;
            }
            Ok(HistoryRequestPutOutcome::Stored {
                outcome: ExactWriteOutcome::Inserted,
                record: Box::new(HistoryRequestRecord {
                    sequence: as_u64(sequence.sequence, "request sequence")?,
                    write,
                }),
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get_request_by_digest(
        &self,
        digest: &Hash,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        request_by(&mut conn, "request_digest", digest.as_str()).await
    }

    async fn get_request_by_receipt_digest(
        &self,
        digest: &Hash,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        request_by(&mut conn, "request_receipt_digest", digest.as_str()).await
    }

    async fn get_request_by_capability_commitment(
        &self,
        response_capability_commitment: &Hash,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let request_id = sql_query(
            "SELECT request_id AS value FROM history_key_response_streams \
             WHERE response_capability_commitment=$1",
        )
        .bind::<Text, _>(response_capability_commitment.as_str())
        .get_result::<TextValueRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        match request_id {
            Some(row) => request_by(&mut conn, "request_id", &row.value).await,
            None => Ok(None),
        }
    }

    async fn list_requests(
        &self,
        scope: &HistoryEffectiveScope,
        after: Option<u64>,
        now: DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<HistoryRequestPage> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "history request list limit is invalid".to_owned(),
            ));
        }
        let (kind, realm, circle) = history_scope_parts(scope);
        let after = after
            .map(|value| as_i64(value, "request cursor"))
            .transpose()?
            .unwrap_or(-1);
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT request_sequence,request_digest,request_receipt_digest,request_json, \
             request_receipt_json,sealed_history_response_capability_json,request_replica_digest,request_replica_json,stored_at FROM history_key_requests \
             WHERE effective_scope_kind=$1 AND realm_id=$2 AND circle_id IS NOT DISTINCT FROM $3 \
             AND expires_at>$4 AND request_sequence>$5 ORDER BY request_sequence LIMIT $6",
        )
        .bind::<Text, _>(kind)
        .bind::<Text, _>(realm)
        .bind::<Nullable<Text>, _>(circle)
        .bind::<Timestamptz, _>(now)
        .bind::<BigInt, _>(after)
        .bind::<BigInt, _>(i64::try_from(limit + 1).unwrap_or(101))
        .load::<RequestRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut records = rows
            .into_iter()
            .map(decode_request)
            .collect::<PersistenceResult<Vec<_>>>()?;
        for record in &mut records {
            if record.write.sealed_history_response_capability.is_some() {
                let retention_digest = record.write.traversal_retention_digest().clone();
                record.write.local_traversal = Some(
                    load_retention(&mut conn, &retention_digest)
                        .await?
                        .ok_or_else(|| {
                            PersistenceError::Internal(
                                "local history request lost its traversal retention".to_owned(),
                            )
                        })?
                        .write,
                );
            }
        }
        let limited = records.len() > limit;
        records.truncate(limit);
        Ok(HistoryRequestPage {
            next_sequence: limited.then(|| records.last().expect("limited page").sequence),
            records,
        })
    }

    async fn list_local_requests(
        &self,
        after: Option<u64>,
        now: DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<HistoryRequestPage> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "local history request list limit is invalid".to_owned(),
            ));
        }
        let after = after
            .map(|value| as_i64(value, "local request cursor"))
            .transpose()?
            .unwrap_or(-1);
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT request_sequence,request_digest,request_receipt_digest,request_json, \
             request_receipt_json,sealed_history_response_capability_json,request_replica_digest,request_replica_json,stored_at FROM history_key_requests \
             WHERE request_replica_digest IS NULL AND expires_at>$1 AND request_sequence>$2 \
             ORDER BY request_sequence LIMIT $3",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<BigInt, _>(after)
        .bind::<BigInt, _>(i64::try_from(limit + 1).unwrap_or(101))
        .load::<RequestRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut records = rows
            .into_iter()
            .map(decode_request)
            .collect::<PersistenceResult<Vec<_>>>()?;
        for record in &mut records {
            let retention_digest = record.write.traversal_retention_digest().clone();
            record.write.local_traversal = Some(
                load_retention(&mut conn, &retention_digest)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "local history request lost its traversal retention".to_owned(),
                        )
                    })?
                    .write,
            );
        }
        let limited = records.len() > limit;
        records.truncate(limit);
        Ok(HistoryRequestPage {
            next_sequence: limited.then(|| records.last().expect("limited page").sequence),
            records,
        })
    }

    async fn reserve_response_exact(
        &self,
        input: HistoryResponseReservationInput,
        reserved_at: DateTime<Utc>,
    ) -> PersistenceResult<(ExactWriteOutcome, HistoryResponseReservationRecord)> {
        input.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,1936879472))")
                .bind::<Text, _>(input.source_record.response_id.as_str())
                .execute(&mut *conn)
                .await?;
            let tombstone = sql_query(
                "SELECT response_id,source_record_digest,terminal_status,expired_at,retain_until \
                 FROM history_key_response_tombstones WHERE response_id=$1 FOR UPDATE",
            )
            .bind::<Text, _>(input.source_record.response_id.as_str())
            .get_result::<TombstoneRow>(&mut *conn)
            .await
            .optional()?;
            if let Some(tombstone) = tombstone {
                return Err(PersistenceError::Conflict(
                    if tombstone.source_record_digest == input.source_record_digest.as_str() {
                        "ttl_expired: history response id has expired".to_owned()
                    } else {
                        "duplicate_conflict: expired history response id differs".to_owned()
                    },
                )
                .into());
            }
            if let Some(row) = response_by(conn, input.source_record.response_id.as_str(), true).await? {
                let existing = reservation(&row)?;
                return if existing.input == input {
                    Ok((ExactWriteOutcome::ExactReplay, existing))
                } else {
                    Err(PersistenceError::Conflict(
                        "duplicate_conflict: history response id differs".to_owned(),
                    ).into())
                };
            }
            if let Some(attestation) = &input.release_attestation {
                lock_and_validate_release_authority(conn, attestation).await?;
            }
            let request = request_by(conn, "request_digest", input.source_record.request_digest.as_str())
                .await?.ok_or_else(|| PersistenceError::NotFound("history response stream unavailable".to_owned()))?;
            if input.source_record.request_digest != request.write.request_digest
                || input.source_record.request_receipt_digest != request.write.request_receipt_digest
                || input.source_record.effective_scope != request.write.request.effective_scope
                || input.source_record.expires_at > request.write.request.expires_at
                || reserved_at > input.source_record.expires_at {
                return Err(PersistenceError::SchemaViolation("history response request binding mismatch".to_owned()).into());
            }
            let sequence = sql_query("UPDATE history_key_response_streams SET next_sequence=next_sequence+1 WHERE request_id=$1 RETURNING next_sequence-1 AS sequence")
                .bind::<Text,_>(request.write.request.request_id.as_str())
                .get_result::<SequenceRow>(&mut *conn).await.optional()?
                .ok_or_else(|| PersistenceError::NotFound("history response stream is not local".to_owned()))?;
            let manifest = input.manifest_admission.as_ref().map(encode).transpose()?;
            let manifest_digest=input.manifest_admission.as_ref().map(|admission|admission.manifest_digest.as_str());
            let manifest_admission_digest=input.manifest_admission.as_ref().map(|admission|admission.manifest_admission_digest.as_str());
            let release = input.release_attestation.as_ref().map(encode).transpose()?;
            sql_query("INSERT INTO history_key_responses (response_id,request_id,source_sender_domain,source_record_digest,source_record_json,manifest_admission_json,manifest_digest,manifest_admission_digest,release_attestation_json,release_service_signer_evidence_json,sequence,sent_at,reserved_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                .bind::<Text,_>(input.source_record.response_id.as_str())
                .bind::<Text,_>(request.write.request.request_id.as_str())
                .bind::<Text,_>(&input.source_record.source_sender_domain)
                .bind::<Text,_>(input.source_record_digest.as_str())
                .bind::<Jsonb,_>(&encode(&input.source_record)?)
                .bind::<Nullable<Jsonb>,_>(manifest.as_ref())
                .bind::<Nullable<Text>,_>(manifest_digest)
                .bind::<Nullable<Text>,_>(manifest_admission_digest)
                .bind::<Nullable<Jsonb>,_>(release.as_ref())
                .bind::<Jsonb,_>(&encode(&input.release_service_signer_evidence)?)
                .bind::<BigInt,_>(sequence.sequence)
                .bind::<Timestamptz,_>(input.sent_at)
                .bind::<Timestamptz,_>(reserved_at)
                .bind::<Timestamptz,_>(input.source_record.expires_at)
                .execute(&mut *conn).await?;
            Ok((ExactWriteOutcome::Inserted, HistoryResponseReservationRecord {
                sequence: as_u64(sequence.sequence,"response sequence")?, input, reserved_at,
            }))
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn complete_response_exact(
        &self,
        write: HistoryResponseCompleteWrite,
    ) -> PersistenceResult<HistoryResponseCompleteOutcome> {
        let bytes = as_i64(
            u64::try_from(write.validate()?)
                .map_err(|_| PersistenceError::Internal("response size overflow".to_owned()))?,
            "response size",
        )?;
        let compact_receipt_bytes = as_i64(
            u64::try_from(write.compact_receipt_bytes()?).map_err(|_| {
                PersistenceError::Internal("compact receipt size overflow".to_owned())
            })?,
            "compact receipt size",
        )?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let row = response_by(conn, write.record.source_record.response_id.as_str(), true).await?
                .ok_or_else(|| PersistenceError::NotFound("response reservation unavailable".to_owned()))?;
            let request_id = row.request_id.clone();
            let authority=sql_query("SELECT r.requester_actor_id,r.release_id FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE s.request_id=$1")
                .bind::<Text,_>(&request_id)
                .get_result::<CompactReceiptAuthorityRow>(&mut *conn).await.optional()?
                .ok_or_else(||PersistenceError::NotFound("response stream unavailable".to_owned()))?;
            for quota_lock in [
                format!("history-compact-service:{}", authority.release_id),
                format!("history-compact-requester_id:{}:{}", authority.release_id, authority.requester_actor_id),
                format!("history-compact-request:{}", request_id),
            ] {
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                    .bind::<Text,_>(&quota_lock).execute(&mut *conn).await?;
            }
            let stream_guard=sql_query("SELECT s.request_id,r.release_id,s.response_capability_commitment,r.expires_at,s.acked_sequence FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE s.request_id=$1 FOR UPDATE OF s")
                .bind::<Text,_>(&request_id)
                .get_result::<ResponseStreamRow>(&mut *conn).await.optional()?
                .ok_or_else(||PersistenceError::NotFound("response stream unavailable".to_owned()))?;
            if stream_guard.release_id != authority.release_id {
                return Err(PersistenceError::Internal("history response stream authority changed".to_owned()).into());
            }
            let request = request_by(conn, "request_id", &request_id)
                .await?.ok_or_else(||PersistenceError::NotFound("history response request is unavailable".to_owned()))?;
            append_response_signer_dependencies_in_transaction(
                conn,
                request.write.traversal_retention_digest(),
                &write.record,
                &write.signer_dependencies,
            ).await?;
            if let Some(receipt_json) = row.send_receipt_json.clone() {
                let receipt: HistoryKeyResponseSendReceipt = decode(receipt_json,"send receipt")?;
                let record = row.record_json.clone().map(|value| decode::<HistoryKeyResponseRecord>(value,"response record")).transpose()?;
                let reserved=reservation(&row)?;
                let exact_reservation=reserved.sequence==write.record.sequence&&reserved.input.source_record==write.record.source_record
                    &&reserved.input.sent_at==write.record.sent_at&&reserved.input.manifest_admission==write.record.manifest_admission
                    &&reserved.input.release_attestation==write.record.release_attestation
                    &&reserved.input.source_record_digest==write.send_receipt.source_record_digest;
                return if record.as_ref().is_none_or(|record|record==&write.record) && receipt==write.send_receipt && row.compact_receipt_bytes==compact_receipt_bytes && exact_reservation {
                    Ok(HistoryResponseCompleteOutcome::ExactReplay(receipt))
                } else { Err(PersistenceError::Conflict("duplicate_conflict: completed response differs".to_owned()).into()) };
            }
            let reserved=reservation(&row)?;
            if reserved.sequence!=write.record.sequence || reserved.input.source_record!=write.record.source_record
                || reserved.input.sent_at!=write.record.sent_at || reserved.input.manifest_admission!=write.record.manifest_admission
                || reserved.input.release_attestation!=write.record.release_attestation
                || reserved.input.source_record_digest!=write.send_receipt.source_record_digest
                || !write.signer_dependencies.contains(&reserved.input.release_service_signer_evidence) {
                return Err(PersistenceError::Conflict("duplicate_conflict: completion differs from reservation".to_owned()).into());
            }
            let requester_total=sql_query("SELECT SUM(s.compact_receipt_bytes)::bigint AS total FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE r.release_id=$1 AND r.requester_actor_id=$2")
                .bind::<Text,_>(&authority.release_id).bind::<Text,_>(authority.requester_actor_id.to_string())
                .get_result::<SumRow>(&mut *conn).await?.total.unwrap_or(0);
            let requester_limit=as_i64(HISTORY_COMPACT_RECEIPTS_PER_REQUESTER_LIMIT,"requester_id compact receipt quota")?;
            if requester_total.checked_add(compact_receipt_bytes).is_none_or(|total| total>requester_limit) {
                return Err(PersistenceError::Conflict("failed_precondition: history requester_id compact receipt quota exceeded".to_owned()).into());
            }
            let service_total=sql_query("SELECT SUM(s.compact_receipt_bytes)::bigint AS total FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE r.release_id=$1")
                .bind::<Text,_>(&authority.release_id).get_result::<SumRow>(&mut *conn).await?.total.unwrap_or(0);
            let advertised_service_limit=as_i64(write.advertised_service_compact_receipt_bytes,"advertised service compact receipt quota")?;
            if service_total.checked_add(compact_receipt_bytes).is_none_or(|total| total>advertised_service_limit) {
                return Err(PersistenceError::Conflict("failed_precondition: history release service compact receipt quota exceeded".to_owned()).into());
            }
            let quota=sql_query("UPDATE history_key_response_streams SET active_bytes=active_bytes+$2,compact_receipt_bytes=compact_receipt_bytes+$3 WHERE request_id=$1 AND active_bytes+$2<=$4 AND compact_receipt_bytes+$3<=$5")
                .bind::<Text,_>(&row.request_id).bind::<BigInt,_>(bytes).bind::<BigInt,_>(compact_receipt_bytes)
                .bind::<BigInt,_>(as_i64(HISTORY_RESPONSE_STREAM_ACTIVE_BYTES_LIMIT,"stream quota")?)
                .bind::<BigInt,_>(as_i64(HISTORY_COMPACT_RECEIPTS_PER_REQUEST_LIMIT,"stream compact receipt quota")?)
                .execute(&mut *conn).await?;
            if quota==0 { return Err(PersistenceError::Conflict("failed_precondition: history stream active or compact receipt quota exceeded".to_owned()).into()); }
            sql_query("UPDATE history_key_responses SET state='accepted',cursor=$2,record_digest=$3,record_json=$4,send_receipt_json=$5,active_bytes=$6,compact_receipt_bytes=$7,accepted_at=$8 WHERE response_id=$1 AND state='reserved'")
                .bind::<Text,_>(&row.response_id).bind::<Text,_>(&write.record.cursor)
                .bind::<Text,_>(write.record.record_digest.as_str()).bind::<Jsonb,_>(&encode(&write.record)?)
                .bind::<Jsonb,_>(&encode(&write.send_receipt)?).bind::<BigInt,_>(bytes)
                .bind::<BigInt,_>(compact_receipt_bytes).bind::<Timestamptz,_>(write.send_receipt.accepted_at).execute(&mut *conn).await?;
            Ok(HistoryResponseCompleteOutcome::Inserted(write.send_receipt))
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn response_retry(
        &self,
        response_id: &HistoryResponseId,
    ) -> PersistenceResult<Option<HistoryResponseRetryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        if let Some(row) = response_by(&mut conn, response_id.as_str(), false).await? {
            return Ok(Some(if let Some(value) = row.send_receipt_json.clone() {
                HistoryResponseRetryRecord::Accepted(Box::new(decode(value, "send receipt")?))
            } else {
                HistoryResponseRetryRecord::Reserved(Box::new(reservation(&row)?))
            }));
        }
        let row=sql_query("SELECT response_id,source_record_digest,terminal_status,expired_at,retain_until FROM history_key_response_tombstones WHERE response_id=$1 AND retain_until>now()")
            .bind::<Text,_>(response_id.as_str()).get_result::<TombstoneRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        row.map(|row| {
            Ok(HistoryResponseRetryRecord::Expired(
                HistoryResponseTombstone {
                    response_id: HistoryResponseId::new(row.response_id)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                    source_record_digest: stored_hash(
                        row.source_record_digest,
                        "tombstone digest",
                    )?,
                    terminal_status: row.terminal_status,
                    expired_at: row.expired_at,
                    retain_until: row.retain_until,
                },
            ))
        })
        .transpose()
    }

    async fn get_accepted_manifest(
        &self,
        request_digest: &Hash,
        manifest_digest: &Hash,
        manifest_admission_digest: &Hash,
    ) -> PersistenceResult<Option<HistoryAcceptedManifestRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row=sql_query("SELECT h.source_record_json,h.manifest_admission_json FROM history_key_responses h JOIN history_key_requests r USING (request_id) WHERE r.request_digest=$1 AND h.manifest_digest=$2 AND h.manifest_admission_digest=$3 AND h.state IN ('accepted','lost','acked')")
            .bind::<Text,_>(request_digest.as_str()).bind::<Text,_>(manifest_digest.as_str()).bind::<Text,_>(manifest_admission_digest.as_str())
            .get_result::<AcceptedManifestRow>(&mut conn).await.optional().map_err(PersistenceError::database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let source_record: HistoryKeyResponseSendRequest =
            decode(row.source_record_json, "accepted manifest source record")?;
        let manifest_admission: HistoryManifestAdmission = decode(
            row.manifest_admission_json.ok_or_else(|| {
                PersistenceError::Internal("accepted manifest admission is missing".to_owned())
            })?,
            "accepted manifest admission",
        )?;
        source_record.validate().map_err(|error| {
            PersistenceError::Internal(format!("stored accepted manifest is invalid: {error}"))
        })?;
        manifest_admission.validate().map_err(|error| {
            PersistenceError::Internal(format!("stored manifest admission is invalid: {error}"))
        })?;
        if source_record
            .manifest_digest()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?
            != *manifest_digest
            || manifest_admission.manifest_digest != *manifest_digest
            || manifest_admission.manifest_admission_digest != *manifest_admission_digest
        {
            return Err(PersistenceError::Internal(
                "stored accepted manifest digest binding is invalid".to_owned(),
            ));
        }
        Ok(Some(HistoryAcceptedManifestRecord {
            source_record,
            manifest_admission,
        }))
    }

    async fn replace_response_with_lost_exact(
        &self,
        response_id: &HistoryResponseId,
        expected: &Hash,
        lost: HistoryKeyResponseLostRecord,
        signer_dependencies: Vec<
            arkret_models_collaboration::governance_dependencies::GovernanceDependency,
        >,
    ) -> PersistenceResult<ExactWriteOutcome> {
        soland_storage::history_lost_signer_retained_dependencies(&lost, &signer_dependencies)?;
        let digest = history_lost_record_digest(&lost)?;
        let lost_bytes = as_i64(
            u64::try_from(history_lost_record_bytes(&lost)?)
                .map_err(|_| PersistenceError::Internal("lost record size overflow".to_owned()))?,
            "lost record size",
        )?;
        let response_id = response_id.clone();
        let expected = expected.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async move|conn|{
            let unlocked=response_by(conn,response_id.as_str(),false).await?.ok_or_else(||PersistenceError::NotFound("response unavailable".to_owned()))?;
            sql_query("SELECT s.request_id,r.release_id,s.response_capability_commitment,r.expires_at,s.acked_sequence FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE s.request_id=$1 FOR UPDATE OF s")
                .bind::<Text,_>(&unlocked.request_id).get_result::<ResponseStreamRow>(&mut *conn).await.optional()?
                .ok_or_else(||PersistenceError::NotFound("response stream unavailable".to_owned()))?;
            let row=response_by(conn,response_id.as_str(),true).await?.ok_or_else(||PersistenceError::NotFound("response unavailable".to_owned()))?;
            if row.state=="lost" { let stored:HistoryKeyResponseLostRecord=decode(row.lost_record_json.ok_or_else(||PersistenceError::Internal("lost descriptor missing".to_owned()))?,"lost descriptor")?; return if stored==lost&&stored.record_digest==expected{Ok(ExactWriteOutcome::ExactReplay)}else{Err(PersistenceError::Conflict("duplicate_conflict: lost descriptor differs".to_owned()).into())}; }
            let record:HistoryKeyResponseRecord=decode(row.record_json.ok_or_else(||PersistenceError::Conflict("duplicate_conflict: response not accepted".to_owned()))?,"response record")?;
            if row.state!="accepted"||record.record_digest!=expected||lost.sequence!=record.sequence||lost.cursor!=record.cursor||lost.response_id!=response_id||lost.record_digest!=expected{return Err(PersistenceError::Conflict("duplicate_conflict: lost descriptor binding mismatch".to_owned()).into());}
            let request=request_by(conn,"request_id",&row.request_id).await?
                .ok_or_else(||PersistenceError::NotFound("history response request is unavailable".to_owned()))?;
            append_lost_signer_dependencies_in_transaction(
                conn,
                request.write.traversal_retention_digest(),
                &lost,
                &signer_dependencies,
            ).await?;
            let quota=sql_query("UPDATE history_key_response_streams SET active_bytes=active_bytes-$2+$3 WHERE request_id=$1 AND active_bytes-$2+$3<=$4")
                .bind::<Text,_>(&row.request_id).bind::<BigInt,_>(row.active_bytes).bind::<BigInt,_>(lost_bytes)
                .bind::<BigInt,_>(as_i64(HISTORY_RESPONSE_STREAM_ACTIVE_BYTES_LIMIT,"stream quota")?).execute(&mut *conn).await?;
            if quota==0{return Err(PersistenceError::Conflict("failed_precondition: history stream active quota exceeded".to_owned()).into());}
            sql_query("UPDATE history_key_responses SET state='lost',record_json=NULL,lost_record_digest=$2,lost_record_json=$3,active_bytes=$4 WHERE response_id=$1")
                .bind::<Text,_>(response_id.as_str()).bind::<Text,_>(digest.as_str()).bind::<Jsonb,_>(&encode(&lost)?).bind::<BigInt,_>(lost_bytes).execute(&mut *conn).await?; Ok(ExactWriteOutcome::Inserted)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn read_response_page(
        &self,
        response_capability_commitment: &Hash,
        after: Option<&str>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> PersistenceResult<HistoryResponseReadPage> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "history stream limit invalid".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let auth=sql_query("SELECT s.request_id,r.release_id,s.response_capability_commitment,r.expires_at,s.acked_sequence FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE s.response_capability_commitment=$1")
            .bind::<Text,_>(response_capability_commitment.as_str()).get_result::<ResponseStreamRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            ;
        let auth = authorize_response_stream_row(auth, response_capability_commitment, now)?;
        let stream = auth.request_id.as_str();
        let after_sequence = if let Some(cursor) = after {
            sql_query(
                "SELECT sequence FROM history_key_responses WHERE request_id=$1 AND cursor=$2",
            )
            .bind::<Text, _>(stream)
            .bind::<Text, _>(cursor)
            .get_result::<SequenceRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| {
                PersistenceError::NotFound("history stream cursor unavailable".to_owned())
            })?
            .sequence
        } else {
            -1
        };
        let rows=sql_query("SELECT response_id,request_id,source_record_digest,source_record_json,manifest_admission_json,manifest_digest,manifest_admission_digest,release_attestation_json,release_service_signer_evidence_json,sequence,cursor,sent_at,reserved_at,state,record_json,lost_record_json,send_receipt_json,active_bytes,compact_receipt_bytes FROM history_key_responses WHERE request_id=$1 AND sequence>$2 AND state IN ('accepted','lost') ORDER BY sequence LIMIT $3")
            .bind::<Text,_>(stream).bind::<BigInt,_>(after_sequence).bind::<BigInt,_>(i64::try_from(limit+1).unwrap_or(101))
            .load::<ResponseRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut entries = rows
            .iter()
            .map(page_entry)
            .collect::<PersistenceResult<Vec<_>>>()?;
        let limited = entries.len() > limit;
        entries.truncate(limit);
        let high_water_sequence = entries.last().map(HistoryResponsePageEntry::sequence);
        let cursor = limited.then(|| match entries.last().expect("limited page") {
            HistoryResponsePageEntry::Record { record } => record.cursor.clone(),
            HistoryResponsePageEntry::Lost { lost_record } => lost_record.cursor.clone(),
        });
        let _ = auth.acked_sequence;
        Ok(HistoryResponseReadPage {
            entries,
            cursor,
            limited,
            high_water_sequence,
        })
    }

    async fn put_ack_token_exact(
        &self,
        response_capability_commitment: &Hash,
        write: HistoryResponseAckTokenWrite,
        now: DateTime<Utc>,
    ) -> PersistenceResult<ExactWriteOutcome> {
        write
            .claims
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if write.ack_token.is_empty() || write.claims.token_expires_at <= now {
            return Err(PersistenceError::SchemaViolation(
                "ack token binding invalid".to_owned(),
            ));
        }
        let high_water_sequence = write
            .claims
            .ordered_ack_entries
            .last()
            .expect("validated claims")
            .sequence;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async move|conn|{
            let auth=sql_query("SELECT s.request_id,r.release_id,s.response_capability_commitment,r.expires_at,s.acked_sequence FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE s.response_capability_commitment=$1 FOR UPDATE OF s")
                .bind::<Text,_>(response_capability_commitment.as_str()).get_result::<ResponseStreamRow>(&mut *conn).await.optional()?;
            let auth = authorize_response_stream_row(auth, response_capability_commitment, now)?;
            if auth.request_id.as_str() != write.claims.request_id.as_str() {
                return Err(PersistenceError::NotFound("history stream unavailable".to_owned()).into());
            }
            if auth.release_id.as_str() != write.claims.release_id.as_str() {
                return Err(PersistenceError::SchemaViolation("ack token release service mismatch".to_owned()).into());
            }
            if let Some(stored)=sql_query("SELECT claims_json,consumed_request_json,consumed_at FROM history_key_response_ack_tokens WHERE ack_token=$1 AND request_id=$2")
                .bind::<Text,_>(&write.ack_token).bind::<Text,_>(write.claims.request_id.as_str())
                .get_result::<TokenRow>(&mut *conn).await.optional()? {
                return if decode::<HistoryResponseAckTokenClaims>(stored.claims_json,"ack token claims")?==write.claims {
                    Ok(ExactWriteOutcome::ExactReplay)
                } else {
                    Err(PersistenceError::Conflict("duplicate_conflict: ack token differs".to_owned()).into())
                };
            }
            for claim in &write.claims.ordered_ack_entries {
                let sequence = as_i64(claim.sequence, "ack sequence")?;
                let row = sql_query("SELECT response_id,request_id,source_record_digest,source_record_json,manifest_admission_json,manifest_digest,manifest_admission_digest,release_attestation_json,release_service_signer_evidence_json,sequence,cursor,sent_at,reserved_at,state,record_json,lost_record_json,send_receipt_json,active_bytes,compact_receipt_bytes FROM history_key_responses WHERE request_id=$1 AND sequence=$2 AND state IN ('accepted','lost')")
                    .bind::<Text, _>(write.claims.request_id.as_str())
                    .bind::<BigInt, _>(sequence)
                    .get_result::<ResponseRow>(&mut *conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        PersistenceError::Conflict(
                            "duplicate_conflict: ack token entry unavailable".to_owned(),
                        )
                    })?;
                let entry = page_entry(&row)?;
                if entry
                    .ack_token_entry()
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                    != *claim
                {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: ack token entry differs".to_owned(),
                    )
                    .into());
                }
                if claim.sequence == high_water_sequence
                    && row.cursor.as_deref() != Some(write.claims.high_water_cursor.as_str())
                {
                    return Err(PersistenceError::SchemaViolation(
                        "ack high-water cursor mismatch".to_owned(),
                    )
                    .into());
                }
            }
            let inserted=sql_query("INSERT INTO history_key_response_ack_tokens (ack_token,request_id,claims_json,issued_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind::<Text,_>(&write.ack_token).bind::<Text,_>(write.claims.request_id.as_str()).bind::<Jsonb,_>(&encode(&write.claims)?)
                .bind::<Timestamptz,_>(now).execute(&mut *conn).await?;
            let _=auth.acked_sequence; if inserted==0{return Err(PersistenceError::Conflict("duplicate_conflict: ack token is already bound".to_owned()).into());} Ok(ExactWriteOutcome::Inserted)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn ack_response_stream(
        &self,
        response_capability_commitment: &Hash,
        request: &HistoryKeyResponseAckRequest,
        now: DateTime<Utc>,
    ) -> PersistenceResult<String> {
        request
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let response_capability_commitment = response_capability_commitment.clone();
        let request = request.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async move|conn|{
            let mb=sql_query("SELECT s.request_id,r.release_id,s.response_capability_commitment,r.expires_at,s.acked_sequence FROM history_key_response_streams s JOIN history_key_requests r USING (request_id) WHERE s.response_capability_commitment=$1 FOR UPDATE OF s").bind::<Text,_>(response_capability_commitment.as_str()).get_result::<ResponseStreamRow>(&mut *conn).await.optional()?;
            let mb = authorize_response_stream_row(mb, &response_capability_commitment, now)?;
            let stream = mb.request_id.clone();
            let token=sql_query("SELECT claims_json,consumed_request_json,consumed_at FROM history_key_response_ack_tokens WHERE ack_token=$1 AND request_id=$2 FOR UPDATE").bind::<Text,_>(&request.ack_token).bind::<Text,_>(&stream).get_result::<TokenRow>(&mut *conn).await.optional()?.ok_or_else(||PersistenceError::NotFound("ack token unavailable".to_owned()))?;
            if let Some(value)=token.consumed_request_json.clone(){let prior:HistoryKeyResponseAckRequest=decode(value,"consumed ack")?;if prior==request{return Ok(request.high_water_cursor);}}
            let claims:HistoryResponseAckTokenClaims=decode(token.claims_json,"ack token claims")?;
            claims.validate().map_err(|error|PersistenceError::Internal(format!("stored ack token claims are invalid: {error}")))?;
            if token.consumed_at.is_some()||claims.token_expires_at<=now||claims.request_id.as_str()!=stream.as_str()||claims.release_id.as_str()!=mb.release_id.as_str()||claims.high_water_cursor!=request.high_water_cursor||claims.ordered_ack_entries.len()!=request.entries.len(){return Err(PersistenceError::Conflict("failed_precondition: ack token invalid".to_owned()).into());}
            let high_water_sequence=as_i64(claims.ordered_ack_entries.last().expect("validated claims").sequence,"ack high water")?;
            let mut expected_sequences=Vec::new(); for(claim,ack)in claims.ordered_ack_entries.iter().zip(&request.entries){let claim_kind=match claim.kind{arkret_models_collaboration::history_key::HistoryResponseAckTokenEntryKind::Record=>"record",arkret_models_collaboration::history_key::HistoryResponseAckTokenEntryKind::Lost=>"lost"}; let(ab_seq,ab_kind,ab_id,ab_digest,status)=match ack{HistoryResponseAckEntry::Record{sequence,response_id,record_digest,status}=>(sequence.to_owned(),"record",response_id.as_str(),record_digest,match status{arkret_models_collaboration::history_key::HistoryResponseRecordStatus::Installed=>"installed",arkret_models_collaboration::history_key::HistoryResponseRecordStatus::CryptographicallyRejected=>"cryptographically_rejected",arkret_models_collaboration::history_key::HistoryResponseRecordStatus::SupersededDuplicate=>"superseded_duplicate"}),HistoryResponseAckEntry::Lost{sequence,response_id,lost_record_digest,..}=>(sequence.to_owned(),"lost",response_id.as_str(),lost_record_digest,"service_record_lost")}; if(claim.sequence,claim_kind,claim.response_id.as_str(),claim.entry_digest.as_str())!=(ab_seq,ab_kind,ab_id,ab_digest.as_str()){return Err(PersistenceError::Conflict("duplicate_conflict: ack entry binding differs".to_owned()).into());} expected_sequences.push(as_i64(ab_seq,"ack sequence")?); sql_query("INSERT INTO history_key_response_dispositions (request_id,sequence,response_id,entry_kind,entry_digest,status,acked_at) VALUES ($1,$2,$3,$4,$5,$6,$7)").bind::<Text,_>(&stream).bind::<BigInt,_>(as_i64(ab_seq,"ack sequence")?).bind::<Text,_>(ab_id).bind::<Text,_>(ab_kind).bind::<Text,_>(ab_digest.as_str()).bind::<Text,_>(status).bind::<Timestamptz,_>(now).execute(&mut *conn).await?;}
            let active=sql_query("SELECT response_id,request_id,source_record_digest,source_record_json,manifest_admission_json,manifest_digest,manifest_admission_digest,release_attestation_json,release_service_signer_evidence_json,sequence,cursor,sent_at,reserved_at,state,record_json,lost_record_json,send_receipt_json,active_bytes,compact_receipt_bytes FROM history_key_responses WHERE request_id=$1 AND sequence>$2 AND sequence<=$3 AND state IN ('accepted','lost') ORDER BY sequence FOR UPDATE").bind::<Text,_>(&stream).bind::<BigInt,_>(mb.acked_sequence.unwrap_or(-1)).bind::<BigInt,_>(high_water_sequence).load::<ResponseRow>(&mut *conn).await?;
            if active.iter().map(|row|row.sequence).collect::<Vec<_>>()!=expected_sequences{return Err(PersistenceError::Conflict("failed_precondition: ack crosses undisposed response".to_owned()).into());} let released: i64=active.iter().map(|row|row.active_bytes).sum();
            sql_query("UPDATE history_key_responses SET state='acked',record_json=NULL,lost_record_json=NULL,active_bytes=0,acked_at=$2 WHERE request_id=$1 AND sequence>$3 AND sequence<=$4 AND state IN ('accepted','lost')").bind::<Text,_>(&stream).bind::<Timestamptz,_>(now).bind::<BigInt,_>(mb.acked_sequence.unwrap_or(-1)).bind::<BigInt,_>(high_water_sequence).execute(&mut *conn).await?;
            sql_query("UPDATE history_key_response_streams SET acked_sequence=$2,acked_cursor=$3,active_bytes=active_bytes-$4 WHERE request_id=$1").bind::<Text,_>(&stream).bind::<BigInt,_>(high_water_sequence).bind::<Text,_>(&request.high_water_cursor).bind::<BigInt,_>(released).execute(&mut *conn).await?;
            sql_query("UPDATE history_key_response_ack_tokens SET consumed_request_json=$2,consumed_at=$3 WHERE ack_token=$1").bind::<Text,_>(&request.ack_token).bind::<Jsonb,_>(&encode(&request)?).bind::<Timestamptz,_>(now).execute(&mut *conn).await?; Ok(request.high_water_cursor)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn expire_requests(&self, now: DateTime<Utc>, limit: usize) -> PersistenceResult<usize> {
        if !(1..=4096).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "expiry limit invalid".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async move|conn|{let rows=sql_query("SELECT request_sequence AS sequence FROM history_key_requests WHERE expires_at<=$1 ORDER BY expires_at,request_sequence FOR UPDATE SKIP LOCKED LIMIT $2").bind::<Timestamptz,_>(now).bind::<BigInt,_>(i64::try_from(limit).unwrap_or(4096)).load::<SequenceRow>(&mut *conn).await?;
            for row in &rows {sql_query("INSERT INTO history_key_response_tombstones (response_id,source_record_digest,terminal_status,expired_at,retain_until) SELECT response_id,source_record_digest,CASE WHEN state='acked' THEN 'acked' ELSE 'expired' END,$2,$3 FROM history_key_responses WHERE request_id=(SELECT request_id FROM history_key_requests WHERE request_sequence=$1) ON CONFLICT DO NOTHING").bind::<BigInt,_>(row.sequence).bind::<Timestamptz,_>(now).bind::<Timestamptz,_>(now+Duration::days(30)).execute(&mut *conn).await?; let retention=sql_query("SELECT traversal_retention_digest FROM history_key_requests WHERE request_sequence=$1").bind::<BigInt,_>(row.sequence).get_result::<RetentionDigestRow>(&mut *conn).await?; sql_query("DELETE FROM history_key_requests WHERE request_sequence=$1").bind::<BigInt,_>(row.sequence).execute(&mut *conn).await?; if let Some(digest)=retention.traversal_retention_digest {let digest=Hash::new(digest).map_err(|error|PersistenceError::Internal(format!("stored traversal retention digest is invalid: {error}")))?; if !release_retention_in_transaction(conn,&digest,Some("request_receipt")).await? {return Err(PersistenceError::Internal("local request traversal retention disappeared during expiry".to_owned()).into());}}}
            sql_query("DELETE FROM history_key_response_tombstones WHERE retain_until<=$1").bind::<Timestamptz,_>(now).execute(&mut *conn).await?;Ok(rows.len())}).await.map_err(PgTransactionError::into_persistence)
    }
}
