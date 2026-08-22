use std::collections::BTreeMap;

use arkret_models_collaboration::history_key::{
    HistoryKeyResponseAckRequest, HistoryKeyResponseLostRecord, HistoryKeyResponseSendReceipt,
    HistoryResponseAckEntry, HistoryResponseId, HistoryResponsePageEntry,
};
use arkret_wire::Hash;
use chrono::{DateTime, Utc};
use soland_storage::{
    ExactWriteOutcome, HISTORY_COMPACT_RECEIPTS_PER_REQUEST_LIMIT,
    HISTORY_COMPACT_RECEIPTS_PER_REQUESTER_LIMIT, HISTORY_RESPONSE_STREAM_ACTIVE_BYTES_LIMIT,
    HistoryAcceptedManifestRecord, HistoryAuthorityViewCas, HistoryRequestPage,
    HistoryRequestPutOutcome, HistoryRequestRecord, HistoryRequestWrite,
    HistoryResponseAckTokenWrite, HistoryResponseCompleteOutcome, HistoryResponseCompleteWrite,
    HistoryResponseReadPage, HistoryResponseReservationInput, HistoryResponseReservationRecord,
    HistoryResponseRetryRecord, HistoryResponseStreamStore, HistoryResponseTombstone,
    HistoryTraversalRetentionStore, PersistenceError, PersistenceResult, history_lost_record_bytes,
    history_lost_record_digest, history_response_capability_commitment_matches,
};

use super::{Arc, MemoryHistoryTraversalRetentionStore, Mutex};

#[derive(Clone)]
struct MemoryResponseRow {
    reservation: HistoryResponseReservationRecord,
    record: Option<arkret_models_collaboration::history_key::HistoryKeyResponseRecord>,
    send_receipt: Option<HistoryKeyResponseSendReceipt>,
    lost_record: Option<HistoryKeyResponseLostRecord>,
    lost_record_digest: Option<Hash>,
    active_bytes: u64,
    compact_receipt_bytes: u64,
    acked_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct MemoryAckToken {
    write: HistoryResponseAckTokenWrite,
    consumed_request: Option<HistoryKeyResponseAckRequest>,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct MemoryResponseStream {
    next_sequence: u64,
    acked_sequence: Option<u64>,
    acked_cursor: Option<String>,
    active_bytes: u64,
    compact_receipt_bytes: u64,
    responses: BTreeMap<u64, MemoryResponseRow>,
    cursors: BTreeMap<String, u64>,
    ack_tokens: BTreeMap<String, MemoryAckToken>,
}

#[derive(Default)]
struct MemoryHistoryResponseStreamData {
    next_request_sequence: u64,
    requests: BTreeMap<String, HistoryRequestRecord>,
    request_digests: BTreeMap<String, String>,
    request_receipt_digests: BTreeMap<String, String>,
    streams: BTreeMap<String, MemoryResponseStream>,
    capability_requests: BTreeMap<String, String>,
    response_requests: BTreeMap<String, String>,
    tombstones: BTreeMap<String, HistoryResponseTombstone>,
}

#[derive(Clone)]
pub(crate) struct MemoryHistoryResponseStreamStore {
    data: Arc<Mutex<MemoryHistoryResponseStreamData>>,
    traversals: MemoryHistoryTraversalRetentionStore,
    authority_view_cas: Arc<Mutex<Option<Arc<dyn HistoryAuthorityViewCas>>>>,
}

impl MemoryHistoryResponseStreamStore {
    pub(crate) fn new(traversals: MemoryHistoryTraversalRetentionStore) -> Self {
        Self {
            data: Arc::default(),
            traversals,
            authority_view_cas: Arc::default(),
        }
    }

    async fn hydrate_local_traversal(
        &self,
        mut record: HistoryRequestRecord,
    ) -> PersistenceResult<HistoryRequestRecord> {
        if record.write.local_traversal.is_some() {
            let retention_digest = record.write.traversal_retention_digest().clone();
            record.write.local_traversal = Some(
                self.traversals
                    .get(&retention_digest)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "local history request lost its traversal retention".to_owned(),
                        )
                    })?
                    .write,
            );
        }
        Ok(record)
    }
}

fn reserve_response_locked(
    data: &mut MemoryHistoryResponseStreamData,
    input: &HistoryResponseReservationInput,
    reserved_at: DateTime<Utc>,
) -> PersistenceResult<(ExactWriteOutcome, HistoryResponseReservationRecord)> {
    let response_id = input.source_record.response_id.as_str().to_owned();
    let request_id = data
        .request_digests
        .get(input.source_record.request_digest.as_str())
        .cloned()
        .ok_or_else(|| {
            PersistenceError::NotFound("history response stream is unavailable".to_owned())
        })?;
    if let Some(tombstone) = data.tombstones.get(&response_id) {
        return Err(PersistenceError::Conflict(
            if tombstone.source_record_digest == input.source_record_digest {
                "ttl_expired: history response id has expired".to_owned()
            } else {
                "duplicate_conflict: expired history response id differs".to_owned()
            },
        ));
    }
    if let Some(existing_stream) = data.response_requests.get(&response_id) {
        let row = data
            .streams
            .get(existing_stream)
            .and_then(|stream| {
                stream.responses.values().find(|row| {
                    row.reservation.input.source_record.response_id.as_str() == response_id
                })
            })
            .ok_or_else(|| {
                PersistenceError::Internal("history response index is corrupt".to_owned())
            })?;
        return if row.reservation.input == *input {
            Ok((ExactWriteOutcome::ExactReplay, row.reservation.clone()))
        } else {
            Err(PersistenceError::Conflict(
                "duplicate_conflict: history response id differs".to_owned(),
            ))
        };
    }
    let request = data.requests.get(&request_id).ok_or_else(|| {
        PersistenceError::Internal("history response request index is corrupt".to_owned())
    })?;
    if input.source_record.request_digest != request.write.request_digest
        || input.source_record.request_receipt_digest != request.write.request_receipt_digest
        || input.source_record.effective_scope != request.write.request.effective_scope
        || input.source_record.expires_at > request.write.request.expires_at
        || reserved_at > input.source_record.expires_at
    {
        return Err(PersistenceError::SchemaViolation(
            "history response does not bind its durable request stream".to_owned(),
        ));
    }
    let stream = data.streams.get_mut(&request_id).ok_or_else(|| {
        PersistenceError::Internal("history response stream row is missing".to_owned())
    })?;
    let sequence = stream.next_sequence;
    stream.next_sequence = stream.next_sequence.checked_add(1).ok_or_else(|| {
        PersistenceError::Internal("history stream sequence exhausted".to_owned())
    })?;
    let reservation = HistoryResponseReservationRecord {
        sequence,
        input: input.clone(),
        reserved_at,
    };
    stream.responses.insert(
        sequence,
        MemoryResponseRow {
            reservation: reservation.clone(),
            record: None,
            send_receipt: None,
            lost_record: None,
            lost_record_digest: None,
            active_bytes: 0,
            compact_receipt_bytes: 0,
            acked_at: None,
        },
    );
    data.response_requests.insert(response_id, request_id);
    Ok((ExactWriteOutcome::Inserted, reservation))
}

fn stream_entry(row: &MemoryResponseRow) -> Option<HistoryResponsePageEntry> {
    if row.acked_at.is_some() {
        return None;
    }
    if let Some(lost_record) = &row.lost_record {
        return Some(HistoryResponsePageEntry::Lost {
            lost_record: lost_record.clone(),
        });
    }
    row.record
        .as_ref()
        .map(|record| HistoryResponsePageEntry::Record {
            record: record.clone(),
        })
}

fn ack_binding(entry: &HistoryResponseAckEntry) -> (u64, &str, &str, &Hash) {
    match entry {
        HistoryResponseAckEntry::Record {
            sequence,
            response_id,
            record_digest,
            ..
        } => (*sequence, "record", response_id.as_str(), record_digest),
        HistoryResponseAckEntry::Lost {
            sequence,
            response_id,
            lost_record_digest,
            ..
        } => (*sequence, "lost", response_id.as_str(), lost_record_digest),
    }
}

fn authorized_stream<'a>(
    data: &'a MemoryHistoryResponseStreamData,
    response_capability_commitment: &Hash,
    now: DateTime<Utc>,
) -> PersistenceResult<(&'a HistoryRequestRecord, &'a MemoryResponseStream)> {
    let request_id = data
        .capability_requests
        .get(response_capability_commitment.as_str());
    let request = request_id.and_then(|request_id| data.requests.get(request_id));
    let commitment_matches = history_response_capability_commitment_matches(
        request.map(|request| {
            request
                .write
                .request_receipt
                .response_capability_commitment
                .as_str()
        }),
        response_capability_commitment,
    );
    let request_id = request_id
        .filter(|_| {
            commitment_matches
                & request.is_some_and(|request| request.write.request.expires_at > now)
        })
        .ok_or_else(|| PersistenceError::NotFound("history stream is unavailable".to_owned()))?;
    let request = data.requests.get(request_id).ok_or_else(|| {
        PersistenceError::Internal("history stream request index is corrupt".to_owned())
    })?;
    let stream = data
        .streams
        .get(request_id)
        .ok_or_else(|| PersistenceError::Internal("history stream row is missing".to_owned()))?;
    Ok((request, stream))
}

fn traversal_writes_exact(
    left: Option<&soland_storage::HistoryTraversalRetentionWrite>,
    right: Option<&soland_storage::HistoryTraversalRetentionWrite>,
) -> PersistenceResult<bool> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => Ok(left.access == right.access
            && left.retention == right.retention
            && left.pins == right.pins
            && soland_storage::history_traversal_canonical(left)?
                == soland_storage::history_traversal_canonical(right)?),
        _ => Ok(false),
    }
}

#[async_trait::async_trait]
impl HistoryResponseStreamStore for MemoryHistoryResponseStreamStore {
    fn bind_authority_view_cas(&self, authority_view_cas: Arc<dyn HistoryAuthorityViewCas>) {
        *self.authority_view_cas.lock() = Some(authority_view_cas);
    }

    async fn put_request_exact(
        &self,
        mut write: HistoryRequestWrite,
    ) -> PersistenceResult<HistoryRequestPutOutcome> {
        write.validate()?;
        let gate = self.traversals.transaction_gate();
        let _guard = gate.lock();
        let request_id = write.request.request_id.as_str().to_owned();
        let normalized_local_objects = write
            .local_traversal
            .as_ref()
            .map(|traversal| {
                soland_storage::history_traversal_canonical(traversal)?
                    .retained_objects
                    .into_iter()
                    .map(|object| {
                        soland_storage::history_traversal_retained_object_from_json(
                            object.object_kind,
                            object.object_json,
                        )
                    })
                    .collect::<PersistenceResult<Vec<_>>>()
            })
            .transpose()?;
        let mut data = self.data.lock();
        if let Some(record) = data.requests.get(&request_id) {
            let traversal_exact = traversal_writes_exact(
                record.write.local_traversal.as_ref(),
                write.local_traversal.as_ref(),
            )?;
            return if record.write.request_digest == write.request_digest
                && record.write.request_receipt_digest == write.request_receipt_digest
                && record.write.request == write.request
                && record.write.request_receipt == write.request_receipt
                && record.write.sealed_history_response_capability
                    == write.sealed_history_response_capability
                && traversal_exact
                && record.write.request_replica == write.request_replica
            {
                Ok(HistoryRequestPutOutcome::Stored {
                    outcome: ExactWriteOutcome::ExactReplay,
                    record: record.clone(),
                })
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: history request id differs".to_owned(),
                ))
            };
        }
        if write.local_traversal.is_some()
            && data.capability_requests.contains_key(
                write
                    .request_receipt
                    .response_capability_commitment
                    .as_str(),
            )
        {
            return Ok(HistoryRequestPutOutcome::CapabilityCommitmentCollision);
        }
        if data
            .request_digests
            .contains_key(write.request_digest.as_str())
            || data
                .request_receipt_digests
                .contains_key(write.request_receipt_digest.as_str())
            || data.requests.contains_key(&request_id)
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: history request digest or stream is already bound".to_owned(),
            ));
        }
        let active_for_scope_sender = data
            .requests
            .values()
            .filter(|record| {
                record.write.request.effective_scope == write.request.effective_scope
                    && record.write.request.requester_sender_domain
                        == write.request.requester_sender_domain
                    && record.write.request.expires_at > write.stored_at
            })
            .count();
        if active_for_scope_sender >= 16 {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history request scope sender limit reached".to_owned(),
            ));
        }
        let sequence = data.next_request_sequence;
        let next_request_sequence = data.next_request_sequence.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("history request sequence exhausted".to_owned())
        })?;
        if let Some(traversal) = write.local_traversal.clone()
            && self.traversals.persist_exact_locked(traversal)? != ExactWriteOutcome::Inserted
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: local traversal retention is already bound".to_owned(),
            ));
        }
        if let (Some(traversal), Some(objects)) =
            (&mut write.local_traversal, normalized_local_objects)
        {
            traversal.objects = objects;
        }
        data.next_request_sequence = next_request_sequence;
        let record = HistoryRequestRecord { sequence, write };
        data.request_digests.insert(
            record.write.request_digest.as_str().to_owned(),
            request_id.clone(),
        );
        data.request_receipt_digests.insert(
            record.write.request_receipt_digest.as_str().to_owned(),
            request_id.clone(),
        );
        if record.write.local_traversal.is_some() {
            data.capability_requests.insert(
                record
                    .write
                    .request_receipt
                    .response_capability_commitment
                    .as_str()
                    .to_owned(),
                request_id.clone(),
            );
            data.streams
                .insert(request_id.clone(), MemoryResponseStream::default());
        }
        data.requests.insert(request_id, record.clone());
        Ok(HistoryRequestPutOutcome::Stored {
            outcome: ExactWriteOutcome::Inserted,
            record,
        })
    }

    async fn get_request_by_digest(
        &self,
        request_digest: &Hash,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let record = {
            let data = self.data.lock();
            data.request_digests
                .get(request_digest.as_str())
                .and_then(|request_id| data.requests.get(request_id))
                .cloned()
        };
        match record {
            Some(record) => self.hydrate_local_traversal(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_request_by_receipt_digest(
        &self,
        request_receipt_digest: &Hash,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let record = {
            let data = self.data.lock();
            data.request_receipt_digests
                .get(request_receipt_digest.as_str())
                .and_then(|request_id| data.requests.get(request_id))
                .cloned()
        };
        match record {
            Some(record) => self.hydrate_local_traversal(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_request_by_id(
        &self,
        request_id: &str,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let record = {
            let data = self.data.lock();
            data.requests.get(request_id).cloned()
        };
        match record {
            Some(record) => self.hydrate_local_traversal(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_request_by_capability_commitment(
        &self,
        response_capability_commitment: &Hash,
    ) -> PersistenceResult<Option<HistoryRequestRecord>> {
        let record = {
            let data = self.data.lock();
            data.capability_requests
                .get(response_capability_commitment.as_str())
                .and_then(|request_id| data.requests.get(request_id))
                .cloned()
        };
        match record {
            Some(record) => self.hydrate_local_traversal(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn list_requests(
        &self,
        effective_scope: &arkret_wire::HistoryEffectiveScope,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> PersistenceResult<HistoryRequestPage> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "history request list limit must be within 1..=100".to_owned(),
            ));
        }
        let mut records = {
            let data = self.data.lock();
            data.requests
                .values()
                .filter(|record| {
                    &record.write.request.effective_scope == effective_scope
                        && after_sequence.is_none_or(|after| record.sequence > after)
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        records.sort_by_key(|record| record.sequence);
        let limited = records.len() > limit;
        records.truncate(limit);
        let mut hydrated = Vec::with_capacity(records.len());
        for record in records {
            hydrated.push(self.hydrate_local_traversal(record).await?);
        }
        Ok(HistoryRequestPage {
            next_sequence: limited.then(|| hydrated.last().expect("non-empty page").sequence),
            records: hydrated,
        })
    }

    async fn list_local_requests(
        &self,
        after_sequence: Option<u64>,
        now: DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<HistoryRequestPage> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "local history request list limit must be within 1..=100".to_owned(),
            ));
        }
        let mut records = {
            let data = self.data.lock();
            data.requests
                .values()
                .filter(|record| {
                    record.write.request_replica.is_none()
                        && record.write.request.expires_at > now
                        && after_sequence.is_none_or(|after| record.sequence > after)
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        records.sort_by_key(|record| record.sequence);
        let limited = records.len() > limit;
        records.truncate(limit);
        let mut hydrated = Vec::with_capacity(records.len());
        for record in records {
            hydrated.push(self.hydrate_local_traversal(record).await?);
        }
        Ok(HistoryRequestPage {
            next_sequence: limited.then(|| hydrated.last().expect("non-empty page").sequence),
            records: hydrated,
        })
    }

    async fn reserve_response_exact(
        &self,
        input: HistoryResponseReservationInput,
        reserved_at: DateTime<Utc>,
    ) -> PersistenceResult<(ExactWriteOutcome, HistoryResponseReservationRecord)> {
        input.validate()?;
        if input.release_attestation.is_none() {
            return reserve_response_locked(&mut self.data.lock(), &input, reserved_at);
        }

        {
            let mut data = self.data.lock();
            let response_id = input.source_record.response_id.as_str();
            if data.tombstones.contains_key(response_id)
                || data.response_requests.contains_key(response_id)
            {
                return reserve_response_locked(&mut data, &input, reserved_at);
            }
        }

        let authority_view_cas = self.authority_view_cas.lock().clone().ok_or_else(|| {
            PersistenceError::Internal(
                "history authority view CAS is not bound to the memory stream".to_owned(),
            )
        })?;
        let attestation = input
            .release_attestation
            .as_ref()
            .expect("checked release attestation")
            .clone();
        let mut outcome = None;
        let cas_result =
            authority_view_cas.with_current_release_authority(&attestation, &mut || {
                let reservation =
                    reserve_response_locked(&mut self.data.lock(), &input, reserved_at)?;
                outcome = Some(reservation);
                Ok(())
            });
        if let Err(error) = cas_result {
            let mut data = self.data.lock();
            if data
                .response_requests
                .contains_key(input.source_record.response_id.as_str())
            {
                return reserve_response_locked(&mut data, &input, reserved_at);
            }
            return Err(error);
        }
        Ok(outcome.expect("history authority CAS must invoke its mutation"))
    }

    async fn complete_response_exact(
        &self,
        write: HistoryResponseCompleteWrite,
    ) -> PersistenceResult<HistoryResponseCompleteOutcome> {
        let canonical_len = write.validate()?;
        let compact_receipt_len = write.compact_receipt_bytes()?;
        let response_id = write.record.source_record.response_id.as_str();
        let gate = self.traversals.transaction_gate();
        let _guard = gate.lock();
        let mut data = self.data.lock();
        let request_id = data
            .response_requests
            .get(response_id)
            .cloned()
            .ok_or_else(|| {
                PersistenceError::NotFound("history response reservation is unavailable".to_owned())
            })?;
        let retention_digest = data
            .requests
            .get(&request_id)
            .ok_or_else(|| {
                PersistenceError::Internal("history response request row is missing".to_owned())
            })?
            .write
            .traversal_retention_digest()
            .clone();
        let stream = data.streams.get(&request_id).ok_or_else(|| {
            PersistenceError::Internal("history response stream row is missing".to_owned())
        })?;
        let row = stream
            .responses
            .get(&write.record.sequence)
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "duplicate_conflict: history response sequence is not reserved".to_owned(),
                )
            })?;
        if let Some(receipt) = &row.send_receipt {
            let exact_reservation = row.reservation.sequence == write.record.sequence
                && row.reservation.input.source_record == write.record.source_record
                && row.reservation.input.sent_at == write.record.sent_at
                && row.reservation.input.manifest_admission == write.record.manifest_admission
                && row.reservation.input.release_attestation == write.record.release_attestation
                && row.reservation.input.source_record_digest
                    == write.send_receipt.source_record_digest;
            return if receipt == &write.send_receipt
                && row
                    .record
                    .as_ref()
                    .is_none_or(|record| record == &write.record)
                && row.compact_receipt_bytes
                    == u64::try_from(compact_receipt_len).map_err(|_| {
                        PersistenceError::Internal("history receipt is too large".to_owned())
                    })?
                && exact_reservation
            {
                Ok(HistoryResponseCompleteOutcome::ExactReplay(receipt.clone()))
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: completed history response differs".to_owned(),
                ))
            };
        }
        if row.reservation.input.source_record != write.record.source_record
            || row.reservation.input.sent_at != write.record.sent_at
            || row.reservation.input.manifest_admission != write.record.manifest_admission
            || row.reservation.input.release_attestation != write.record.release_attestation
            || row.reservation.input.source_record_digest != write.send_receipt.source_record_digest
            || row.reservation.sequence != write.record.sequence
            || !write
                .signer_dependencies
                .contains(&row.reservation.input.release_service_signer_evidence)
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: history response completion differs from reservation"
                    .to_owned(),
            ));
        }
        if stream.cursors.contains_key(&write.record.cursor) {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: history stream cursor is already bound".to_owned(),
            ));
        }
        let active_bytes = u64::try_from(canonical_len)
            .map_err(|_| PersistenceError::Internal("history record is too large".to_owned()))?;
        let compact_receipt_bytes = u64::try_from(compact_receipt_len)
            .map_err(|_| PersistenceError::Internal("history receipt is too large".to_owned()))?;
        if stream.active_bytes.saturating_add(active_bytes)
            > HISTORY_RESPONSE_STREAM_ACTIVE_BYTES_LIMIT
        {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history stream active quota exceeded".to_owned(),
            ));
        }
        if stream
            .compact_receipt_bytes
            .checked_add(compact_receipt_bytes)
            .is_none_or(|total| total > HISTORY_COMPACT_RECEIPTS_PER_REQUEST_LIMIT)
        {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history stream compact receipt quota exceeded".to_owned(),
            ));
        }
        let request = data.requests.get(&request_id).ok_or_else(|| {
            PersistenceError::Internal("history stream request row is missing".to_owned())
        })?;
        let requester_actor_id = request.write.request.requester_actor_id.clone();
        let release_service_id = request.write.request_receipt.release_service_id.clone();
        let mut requester_total = 0_u64;
        let mut service_total = 0_u64;
        for (candidate_request_id, candidate_stream) in &data.streams {
            let candidate_request = data.requests.get(candidate_request_id).ok_or_else(|| {
                PersistenceError::Internal(
                    "history compact receipt accounting index is corrupt".to_owned(),
                )
            })?;
            if candidate_request.write.request_receipt.release_service_id == release_service_id {
                service_total = service_total
                    .checked_add(candidate_stream.compact_receipt_bytes)
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "history service compact receipt accounting overflow".to_owned(),
                        )
                    })?;
                if candidate_request.write.request.requester_actor_id == requester_actor_id {
                    requester_total = requester_total
                        .checked_add(candidate_stream.compact_receipt_bytes)
                        .ok_or_else(|| {
                            PersistenceError::Internal(
                                "history requester compact receipt accounting overflow".to_owned(),
                            )
                        })?;
                }
            }
        }
        if requester_total
            .checked_add(compact_receipt_bytes)
            .is_none_or(|total| total > HISTORY_COMPACT_RECEIPTS_PER_REQUESTER_LIMIT)
        {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history requester compact receipt quota exceeded".to_owned(),
            ));
        }
        if service_total
            .checked_add(compact_receipt_bytes)
            .is_none_or(|total| total > write.advertised_service_compact_receipt_bytes)
        {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history release service compact receipt quota exceeded"
                    .to_owned(),
            ));
        }
        self.traversals.append_response_signer_dependencies_locked(
            &retention_digest,
            &write.record,
            &write.signer_dependencies,
        )?;
        let stream = data
            .streams
            .get_mut(&request_id)
            .expect("validated stream exists");
        stream
            .cursors
            .insert(write.record.cursor.clone(), write.record.sequence);
        stream.active_bytes += active_bytes;
        stream.compact_receipt_bytes += compact_receipt_bytes;
        let row = stream
            .responses
            .get_mut(&write.record.sequence)
            .expect("validated response reservation exists");
        row.active_bytes = active_bytes;
        row.compact_receipt_bytes = compact_receipt_bytes;
        row.record = Some(write.record);
        row.send_receipt = Some(write.send_receipt.clone());
        Ok(HistoryResponseCompleteOutcome::Inserted(write.send_receipt))
    }

    async fn response_retry(
        &self,
        response_id: &HistoryResponseId,
    ) -> PersistenceResult<Option<HistoryResponseRetryRecord>> {
        let data = self.data.lock();
        if let Some(tombstone) = data.tombstones.get(response_id.as_str()) {
            return Ok(Some(HistoryResponseRetryRecord::Expired(tombstone.clone())));
        }
        let Some(request_id) = data.response_requests.get(response_id.as_str()) else {
            return Ok(None);
        };
        let row = data
            .streams
            .get(request_id)
            .and_then(|stream| {
                stream
                    .responses
                    .values()
                    .find(|row| row.reservation.input.source_record.response_id == *response_id)
            })
            .ok_or_else(|| {
                PersistenceError::Internal("history response index is corrupt".to_owned())
            })?;
        Ok(Some(if let Some(receipt) = &row.send_receipt {
            HistoryResponseRetryRecord::Accepted(receipt.clone())
        } else {
            HistoryResponseRetryRecord::Reserved(row.reservation.clone())
        }))
    }

    async fn get_accepted_manifest(
        &self,
        request_digest: &Hash,
        manifest_digest: &Hash,
        manifest_admission_digest: &Hash,
    ) -> PersistenceResult<Option<HistoryAcceptedManifestRecord>> {
        let data = self.data.lock();
        let Some(request_id) = data.request_digests.get(request_digest.as_str()) else {
            return Ok(None);
        };
        let Some(stream) = data.streams.get(request_id) else {
            return Ok(None);
        };
        for row in stream.responses.values() {
            if row.send_receipt.is_none() {
                continue;
            }
            let source_record = &row.reservation.input.source_record;
            if !matches!(
                &source_record.content,
                arkret_models_collaboration::history_key::HistoryKeyResponseContent::Manifest(_)
            ) {
                continue;
            }
            let admission = row
                .reservation
                .input
                .manifest_admission
                .as_ref()
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "accepted history manifest lost its admission".to_owned(),
                    )
                })?;
            if source_record
                .manifest_digest()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?
                == *manifest_digest
                && admission.manifest_digest == *manifest_digest
                && admission.manifest_admission_digest == *manifest_admission_digest
            {
                return Ok(Some(HistoryAcceptedManifestRecord {
                    source_record: source_record.clone(),
                    manifest_admission: admission.clone(),
                }));
            }
        }
        Ok(None)
    }

    async fn replace_response_with_lost_exact(
        &self,
        response_id: &HistoryResponseId,
        expected_record_digest: &Hash,
        lost_record: HistoryKeyResponseLostRecord,
        signer_dependencies: Vec<
            arkret_models_collaboration::governance_dependencies::GovernanceDependency,
        >,
    ) -> PersistenceResult<ExactWriteOutcome> {
        soland_storage::history_lost_signer_retained_dependencies(
            &lost_record,
            &signer_dependencies,
        )?;
        let lost_digest = history_lost_record_digest(&lost_record)?;
        let lost_bytes = u64::try_from(history_lost_record_bytes(&lost_record)?).map_err(|_| {
            PersistenceError::Internal("history lost record is too large".to_owned())
        })?;
        let gate = self.traversals.transaction_gate();
        let _guard = gate.lock();
        let mut data = self.data.lock();
        let request_id = data
            .response_requests
            .get(response_id.as_str())
            .cloned()
            .ok_or_else(|| {
                PersistenceError::NotFound("history response is unavailable".to_owned())
            })?;
        let retention_digest = data
            .requests
            .get(&request_id)
            .ok_or_else(|| {
                PersistenceError::Internal("history response request row is missing".to_owned())
            })?
            .write
            .traversal_retention_digest()
            .clone();
        let stream = data.streams.get_mut(&request_id).ok_or_else(|| {
            PersistenceError::Internal("history response stream row is missing".to_owned())
        })?;
        let row = stream.responses.get(&lost_record.sequence).ok_or_else(|| {
            PersistenceError::Conflict(
                "duplicate_conflict: lost response sequence differs".to_owned(),
            )
        })?;
        if let Some(existing) = &row.lost_record {
            return if existing == &lost_record && &existing.record_digest == expected_record_digest
            {
                Ok(ExactWriteOutcome::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: lost descriptor differs".to_owned(),
                ))
            };
        }
        let record = row.record.as_ref().ok_or_else(|| {
            PersistenceError::Conflict(
                "duplicate_conflict: lost response is not accepted".to_owned(),
            )
        })?;
        if record.source_record.response_id != *response_id
            || &record.record_digest != expected_record_digest
            || lost_record.response_id != *response_id
            || lost_record.record_digest != *expected_record_digest
            || lost_record.cursor != record.cursor
            || lost_record.sequence != record.sequence
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: lost descriptor does not bind the accepted record".to_owned(),
            ));
        }
        let old_active_bytes = row.active_bytes;
        let replacement_total = stream
            .active_bytes
            .checked_sub(old_active_bytes)
            .and_then(|total| total.checked_add(lost_bytes))
            .ok_or_else(|| {
                PersistenceError::Internal("history stream active accounting overflow".to_owned())
            })?;
        if replacement_total > HISTORY_RESPONSE_STREAM_ACTIVE_BYTES_LIMIT {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history stream active quota exceeded".to_owned(),
            ));
        }
        self.traversals.append_lost_signer_dependencies_locked(
            &retention_digest,
            &lost_record,
            &signer_dependencies,
        )?;
        stream.active_bytes = replacement_total;
        let row = stream
            .responses
            .get_mut(&lost_record.sequence)
            .expect("validated response exists");
        row.active_bytes = lost_bytes;
        row.record = None;
        row.lost_record = Some(lost_record);
        row.lost_record_digest = Some(lost_digest);
        Ok(ExactWriteOutcome::Inserted)
    }

    async fn read_response_page(
        &self,
        response_capability_commitment: &Hash,
        after_cursor: Option<&str>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> PersistenceResult<HistoryResponseReadPage> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "history stream list limit must be within 1..=100".to_owned(),
            ));
        }
        let data = self.data.lock();
        let (_, stream) = authorized_stream(&data, response_capability_commitment, now)?;
        let after_sequence = match after_cursor {
            Some(cursor) => Some(*stream.cursors.get(cursor).ok_or_else(|| {
                PersistenceError::NotFound("history stream cursor is unavailable".to_owned())
            })?),
            None => None,
        };
        let mut entries = stream
            .responses
            .iter()
            .filter(|(sequence, _)| after_sequence.is_none_or(|after| **sequence > after))
            .filter_map(|(_, row)| stream_entry(row))
            .collect::<Vec<_>>();
        let limited = entries.len() > limit;
        entries.truncate(limit);
        let high_water_sequence = entries.last().map(HistoryResponsePageEntry::sequence);
        let cursor = if limited {
            entries.last().map(|entry| match entry {
                HistoryResponsePageEntry::Record { record } => record.cursor.clone(),
                HistoryResponsePageEntry::Lost { lost_record } => lost_record.cursor.clone(),
            })
        } else {
            None
        };
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
                "history ack token binding is invalid".to_owned(),
            ));
        }
        let mut data = self.data.lock();
        let (request, stream) = authorized_stream(&data, response_capability_commitment, now)?;
        if request.write.request.request_id != write.claims.request_id {
            return Err(PersistenceError::NotFound(
                "history stream is unavailable".to_owned(),
            ));
        }
        if request.write.request_receipt.release_service_id != write.claims.release_service_id {
            return Err(PersistenceError::SchemaViolation(
                "history ack token release service mismatch".to_owned(),
            ));
        }
        if let Some((existing_request_id, existing)) =
            data.streams
                .iter()
                .find_map(|(candidate_request_id, candidate_stream)| {
                    candidate_stream
                        .ack_tokens
                        .get(&write.ack_token)
                        .map(|existing| (candidate_request_id, existing))
                })
        {
            return if existing_request_id.as_str() == write.claims.request_id.as_str()
                && existing.write == write
            {
                Ok(ExactWriteOutcome::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: history ack token differs".to_owned(),
                ))
            };
        }
        for claim in &write.claims.ordered_ack_entries {
            let stored = stream
                .responses
                .get(&claim.sequence)
                .and_then(stream_entry)
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "duplicate_conflict: history ack token entry is unavailable".to_owned(),
                    )
                })?;
            let stored_claim = stored
                .ack_token_entry()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if stored_claim != *claim {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: history ack token entry differs".to_owned(),
                ));
            }
        }
        let last_sequence = write
            .claims
            .ordered_ack_entries
            .last()
            .expect("validated claims")
            .sequence;
        let last_cursor = match stream
            .responses
            .get(&last_sequence)
            .and_then(stream_entry)
            .expect("validated claim entry")
        {
            HistoryResponsePageEntry::Record { record } => record.cursor,
            HistoryResponsePageEntry::Lost { lost_record } => lost_record.cursor,
        };
        if last_cursor != write.claims.high_water_cursor {
            return Err(PersistenceError::SchemaViolation(
                "history ack token high-water cursor mismatch".to_owned(),
            ));
        }
        let stream = data
            .streams
            .get_mut(write.claims.request_id.as_str())
            .expect("authorized stream");
        stream.ack_tokens.insert(
            write.ack_token.clone(),
            MemoryAckToken {
                write,
                consumed_request: None,
                consumed_at: None,
            },
        );
        Ok(ExactWriteOutcome::Inserted)
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
        let mut data = self.data.lock();
        let (authorized_request, _) =
            authorized_stream(&data, response_capability_commitment, now)?;
        let request_id = authorized_request
            .write
            .request
            .request_id
            .as_str()
            .to_owned();
        let stream = data
            .streams
            .get_mut(&request_id)
            .expect("authorized stream");
        let token = stream
            .ack_tokens
            .get(&request.ack_token)
            .cloned()
            .ok_or_else(|| {
                PersistenceError::NotFound("history ack token is unavailable".to_owned())
            })?;
        if token.consumed_request.as_ref() == Some(request) {
            return Ok(request.high_water_cursor.clone());
        }
        if token.consumed_at.is_some() || token.write.claims.token_expires_at <= now {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history ack token is expired or consumed".to_owned(),
            ));
        }
        if token.write.claims.high_water_cursor != request.high_water_cursor
            || token.write.claims.ordered_ack_entries.len() != request.ack_entries.len()
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: history ack request differs from token".to_owned(),
            ));
        }
        for (claim, ack_entry) in token
            .write
            .claims
            .ordered_ack_entries
            .iter()
            .zip(&request.ack_entries)
        {
            let ack = ack_binding(ack_entry);
            let kind = match claim.kind {
                arkret_models_collaboration::history_key::HistoryResponseAckTokenEntryKind::Record => "record",
                arkret_models_collaboration::history_key::HistoryResponseAckTokenEntryKind::Lost => "lost",
            };
            if (
                claim.sequence,
                kind,
                claim.response_id.as_str(),
                claim.entry_digest.as_str(),
            ) != (ack.0, ack.1, ack.2, ack.3.as_str())
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: history ack entry differs from token".to_owned(),
                ));
            }
        }
        let high_water = token
            .write
            .claims
            .ordered_ack_entries
            .last()
            .expect("non-empty token entries")
            .sequence;
        let expected_sequences = stream
            .responses
            .iter()
            .filter(|(sequence, row)| {
                **sequence <= high_water
                    && stream.acked_sequence.is_none_or(|acked| **sequence > acked)
                    && stream_entry(row).is_some()
            })
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>();
        let token_sequences = token
            .write
            .claims
            .ordered_ack_entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>();
        if expected_sequences != token_sequences {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history ack would cross an undisposed record".to_owned(),
            ));
        }
        let mut released_bytes = 0_u64;
        for ack_entry in &request.ack_entries {
            let sequence = ack_entry.sequence();
            let row = stream
                .responses
                .get_mut(&sequence)
                .expect("token row exists");
            row.acked_at = Some(now);
            row.record = None;
            row.lost_record = None;
            released_bytes = released_bytes
                .checked_add(row.active_bytes)
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "history stream active accounting overflow".to_owned(),
                    )
                })?;
            row.active_bytes = 0;
        }
        stream.active_bytes = stream
            .active_bytes
            .checked_sub(released_bytes)
            .ok_or_else(|| {
                PersistenceError::Internal("history stream active accounting underflow".to_owned())
            })?;
        stream.acked_sequence = Some(high_water);
        stream.acked_cursor = Some(request.high_water_cursor.clone());
        let stored_token = stream
            .ack_tokens
            .get_mut(&request.ack_token)
            .expect("ack token exists");
        stored_token.consumed_request = Some(request.clone());
        stored_token.consumed_at = Some(now);
        Ok(request.high_water_cursor.clone())
    }

    async fn expire_requests(&self, now: DateTime<Utc>, limit: usize) -> PersistenceResult<usize> {
        if !(1..=4_096).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "history request expiry limit is invalid".to_owned(),
            ));
        }
        let gate = self.traversals.transaction_gate();
        let _guard = gate.lock();
        let expired_count = {
            let mut data = self.data.lock();
            data.tombstones.retain(|_, row| row.retain_until > now);
            let mut request_ids = data
                .requests
                .iter()
                .filter(|(_, record)| record.write.request.expires_at <= now)
                .map(|(request_id, record)| (record.write.request.expires_at, request_id.clone()))
                .collect::<Vec<_>>();
            request_ids.sort();
            request_ids.truncate(limit);
            for (_, request_id) in &request_ids {
                let record = data
                    .requests
                    .get(request_id)
                    .expect("selected request exists");
                if record.write.local_traversal.is_some()
                    && !self
                        .traversals
                        .validate_release_locked(record.write.traversal_retention_digest())?
                {
                    return Err(PersistenceError::Internal(
                        "local request traversal retention disappeared before expiry".to_owned(),
                    ));
                }
            }
            let mut retention_digests = Vec::with_capacity(request_ids.len());
            for (_, request_id) in &request_ids {
                let record = data
                    .requests
                    .remove(request_id)
                    .expect("selected request exists");
                let request_id = record.write.request.request_id.as_str().to_owned();
                if let Some(stream) = data.streams.remove(&request_id) {
                    for row in stream.responses.into_values() {
                        let response = &row.reservation.input.source_record;
                        data.tombstones.insert(
                            response.response_id.as_str().to_owned(),
                            HistoryResponseTombstone::new(
                                response.response_id.clone(),
                                row.reservation.input.source_record_digest,
                                if row.acked_at.is_some() {
                                    "acked"
                                } else {
                                    "expired"
                                },
                                now,
                            ),
                        );
                        data.response_requests.remove(response.response_id.as_str());
                    }
                }
                data.capability_requests.remove(
                    record
                        .write
                        .request_receipt
                        .response_capability_commitment
                        .as_str(),
                );
                data.request_digests
                    .remove(record.write.request_digest.as_str());
                data.request_receipt_digests
                    .remove(record.write.request_receipt_digest.as_str());
                if record.write.local_traversal.is_some() {
                    retention_digests.push(record.write.traversal_retention_digest().clone());
                }
            }
            for digest in &retention_digests {
                if !self.traversals.release_locked(digest)? {
                    return Err(PersistenceError::Internal(
                        "local request traversal retention disappeared during expiry".to_owned(),
                    ));
                }
            }
            request_ids.len()
        };
        Ok(expired_count)
    }
}
