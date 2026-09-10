use arkret_models_collaboration::history_key::{
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveRow,
};
use arkret_wire::DidCoreId;

use super::HistoryPreparationError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedArchiveListPage {
    pub items: Vec<OrganizationRecoveryArchiveRow>,
    pub last_sequence: Option<u64>,
    pub limited: bool,
}

pub fn build_archive_list_page(
    candidates: Vec<soland_storage::PendingRhrkAcquisitionRecord>,
    query: &OrganizationRecoveryArchiveListQuery,
    caller: &DidCoreId,
    byte_limit: usize,
    has_more_candidates: bool,
) -> Result<PreparedArchiveListPage, HistoryPreparationError> {
    let mut items = Vec::new();
    let mut last_sequence = None;
    let mut limited = false;
    for record in candidates {
        let Some(outcome) = &record.accepted_outcome else {
            continue;
        };
        let replica = &record.input.archive_replica;
        let archive = &replica.archive;
        if archive.method_controller_principal_id != *caller
            || archive.effective_scope != query.effective_scope
            || archive.recovery_key_id != query.recovery_key_id
            || archive.key_agreement_ref != query.key_agreement_ref
            || archive.accepted_key_evidence_ref != query.accepted_key_evidence_ref
            || archive.holder_trusted_basis != query.holder_trusted_basis
            || query.from_epoch.is_some_and(|from| archive.epoch < from)
            || query.to_epoch.is_some_and(|to| archive.epoch > to)
        {
            continue;
        }
        let item = OrganizationRecoveryArchiveRow {
            archive_sequence: outcome.archive_sequence,
            archive_replica_digest: outcome.archive_replica_digest.clone(),
            archive: archive.clone(),
            container_event_ref: replica.container_event_ref.clone(),
            history_traversal_retention: replica.history_traversal_retention.clone(),
        };
        let mut tentative = items.clone();
        tentative.push(item.clone());
        if arkret_canonical::canonical_json_bytes(&tentative)
            .map_err(|error| HistoryPreparationError::Invariant(error.to_string()))?
            .len()
            > byte_limit
        {
            limited = true;
            break;
        }
        last_sequence = Some(outcome.archive_sequence);
        items.push(item);
    }
    if !limited && has_more_candidates {
        limited = true;
    }
    Ok(PreparedArchiveListPage {
        items,
        last_sequence,
        limited,
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::history_key::{
        OrganizationRecoveryArchiveReplica, OrganizationRecoveryArchiveReplicaOutcome,
        OrganizationRecoveryArchiveRow,
    };
    use chrono::Utc;

    use super::*;

    fn fixture_parts() -> (
        OrganizationRecoveryArchiveListQuery,
        soland_storage::PendingRhrkAcquisitionRecord,
        DidCoreId,
    ) {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        let kat = &fixture["organization_recovery_archive_durable_before_gc_kat"];
        let query = serde_json::from_value(kat["barrier_query"].clone()).unwrap();
        let replica: OrganizationRecoveryArchiveReplica =
            serde_json::from_value(kat["replica"].clone()).unwrap();
        let outcome: OrganizationRecoveryArchiveReplicaOutcome =
            serde_json::from_value(kat["first_receipt"].clone()).unwrap();
        let now = Utc::now();
        let record = soland_storage::PendingRhrkAcquisitionRecord {
            input: soland_storage::PendingRhrkAcquisitionInput {
                acquisition_digest: outcome.archive_replica_digest.clone(),
                archive_replica_digest: outcome.archive_replica_digest.clone(),
                archive_replica: replica,
                next_attempt_at: now,
            },
            state: soland_storage::PendingRhrkAcquisitionState::Accepted,
            attempt_count: 1,
            claim_token: None,
            claim_until: None,
            ready_at: Some(now),
            archive_sequence: Some(outcome.archive_sequence),
            accepted_outcome: Some(outcome),
            last_error_code: None,
            created_at: now,
            updated_at: now,
        };
        let caller = record
            .input
            .archive_replica
            .archive
            .method_controller_principal_id
            .clone();
        (query, record, caller)
    }

    fn expected_item(
        record: &soland_storage::PendingRhrkAcquisitionRecord,
    ) -> OrganizationRecoveryArchiveRow {
        let outcome = record.accepted_outcome.as_ref().unwrap();
        let replica = &record.input.archive_replica;
        OrganizationRecoveryArchiveRow {
            archive_sequence: outcome.archive_sequence,
            archive_replica_digest: outcome.archive_replica_digest.clone(),
            archive: replica.archive.clone(),
            container_event_ref: replica.container_event_ref.clone(),
            history_traversal_retention: replica.history_traversal_retention.clone(),
        }
    }

    #[test]
    fn archive_page_accepts_exact_limit_and_stops_above_it() {
        let (query, record, caller) = fixture_parts();
        let byte_limit = arkret_canonical::canonical_json_bytes(&vec![expected_item(&record)])
            .unwrap()
            .len();
        let exact =
            build_archive_list_page(vec![record.clone()], &query, &caller, byte_limit, false)
                .unwrap();
        assert_eq!(exact.items.len(), 1);
        assert!(!exact.limited);

        let truncated =
            build_archive_list_page(vec![record], &query, &caller, byte_limit - 1, false).unwrap();
        assert!(truncated.items.is_empty());
        assert!(truncated.limited);
        assert_eq!(truncated.last_sequence, None);
    }

    #[test]
    fn archive_page_filters_wrong_tuple_and_marks_more_candidates() {
        let (query, record, caller) = fixture_parts();
        let mut wrong_query = query.clone();
        wrong_query.recovery_key_id.push_str("-other");
        let filtered = build_archive_list_page(
            vec![record.clone()],
            &wrong_query,
            &caller,
            usize::MAX,
            false,
        )
        .unwrap();
        assert!(filtered.items.is_empty());

        let limited =
            build_archive_list_page(vec![record], &query, &caller, usize::MAX, true).unwrap();
        assert_eq!(limited.items.len(), 1);
        assert!(limited.limited);
        assert!(limited.last_sequence.is_some());
    }
}
