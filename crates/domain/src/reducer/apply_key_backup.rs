use super::*;
const KEY_BACKUP_ACTIVE_SERIES_CELL_FAMILY: &str = "ak.component.key_backup.active_series.v1";

impl ProjectionState {
    pub(crate) fn apply_key_backup_active_series(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::EventKind::KEY_BACKUP_ACTIVE_SERIES)
        {
            return ProjectionEffect::Ignored;
        }

        let wire_payload = projection_context_stripped_payload(&operation.payload);
        let record: arkret_sdk::KeyBackupActiveSeries =
            match serde_json::from_value(wire_payload.clone()) {
                Ok(record) => record,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: "key_backup_active_series_schema_violation".to_owned(),
                    };
                }
            };

        let actor_id = record.actor_id.as_str().to_owned();
        let backup_class = backup_class_wire(record.backup_class).to_owned();
        let pointer_key = (actor_id.clone(), backup_class.clone());
        let current_head = self
            .key_backup_active_series
            .get(&pointer_key)
            .and_then(soland_active_series_head);
        let head = match arkret_sdk::validate_key_backup_active_series_transition(
            current_head.as_ref(),
            &record,
        ) {
            Ok(head) => head,
            Err(error) => return rejected(&error.to_string()),
        };
        if current_head
            .as_ref()
            .is_some_and(|current| current.record_digest == head.record_digest)
        {
            return ProjectionEffect::Ignored;
        }
        let active_series_id = head.active_series_id.as_str().to_owned();
        let previous_series_ids = head
            .previous_series_ids
            .iter()
            .map(|series_id| series_id.as_str().to_owned())
            .collect::<Vec<_>>();

        let projection = SolandKeyBackupActiveSeries {
            actor_id: actor_id.clone(),
            backup_class: backup_class.clone(),
            active_series_id: active_series_id.clone(),
            series_pointer_version: head.series_pointer_version,
            previous_series_ids,
            record_digest: head.record_digest,
            frontier_ref: record.frontier_ref.clone(),
            issued_at: record.issued_at,
            auth_data: record.auth_data.clone(),
            extra: record.extra.clone(),
            event_id: operation.operation_id.to_string(),
        };
        let subject = active_series_subject(&actor_id, &backup_class);
        if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
            "ak:cell:{KEY_BACKUP_ACTIVE_SERIES_CELL_FAMILY}:{subject}"
        )) {
            self.cells.insert(cell_id, CellState::Value(wire_payload));
        }
        self.key_backup_active_series
            .insert(pointer_key, projection);

        ProjectionEffect::KeyBackupActiveSeriesProjected {
            actor_id,
            backup_class,
            active_series_id,
        }
    }

    pub fn key_backup_active_series(
        &self,
        actor_id: &str,
        backup_class: &str,
    ) -> Option<&SolandKeyBackupActiveSeries> {
        self.key_backup_active_series
            .get(&(actor_id.to_owned(), backup_class.to_owned()))
    }

    pub fn key_backup_active_series_head(
        &self,
        actor_id: &str,
        backup_class: &str,
    ) -> Option<arkret_sdk::KeyBackupActiveSeriesHead> {
        self.key_backup_active_series(actor_id, backup_class)
            .and_then(soland_active_series_head)
    }
}

fn soland_active_series_head(
    current: &SolandKeyBackupActiveSeries,
) -> Option<arkret_sdk::KeyBackupActiveSeriesHead> {
    Some(arkret_sdk::KeyBackupActiveSeriesHead {
        actor_id: arkret_sdk::Did::new(current.actor_id.clone()).ok()?,
        backup_class: arkret_sdk::BackupClass::try_from(current.backup_class.as_str()).ok()?,
        active_series_id: arkret_sdk::BackupSeriesId::new(current.active_series_id.clone()).ok()?,
        series_pointer_version: current.series_pointer_version,
        previous_series_ids: current
            .previous_series_ids
            .iter()
            .map(|series_id| arkret_sdk::BackupSeriesId::new(series_id.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .ok()?,
        record_digest: current.record_digest.clone(),
    })
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

fn backup_class_wire(backup_class: arkret_sdk::BackupClass) -> &'static str {
    match backup_class {
        arkret_sdk::BackupClass::DidRecovery => "did_recovery",
        arkret_sdk::BackupClass::SecretStorage => "secret_storage",
        arkret_sdk::BackupClass::MlsHistory => "mls_history",
    }
}

fn active_series_subject(actor_id: &str, backup_class: &str) -> String {
    arkret_sdk::composite_subject(&[actor_id, backup_class])
        .expect("string cell-subject parts always have canonical JSON encoding")
}
