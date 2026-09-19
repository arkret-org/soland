use super::*;

impl ProjectionState {
    pub(crate) fn apply_key_backup_active_series(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::KeyBackupActiveSeries)
        {
            return ProjectionEffect::Ignored;
        }

        let record =
            match operation.typed_payload::<arkret_wire::event_spec::KeyBackupActiveSeries>() {
                Ok(record) => record,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: "key_backup_active_series_schema_violation".to_owned(),
                    };
                }
            };

        let actor_id = record.actor_id.to_string();
        let backup_kind = backup_class_wire(record.backup_kind).to_owned();
        let pointer_key = (actor_id.clone(), backup_kind.clone());
        let current_head = self
            .key_backup_active_series
            .get(&pointer_key)
            .and_then(soland_active_series_head);
        let head = match arkret_models_collaboration::events_payloads::validate_key_backup_active_series_transition(
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
            backup_kind: backup_kind.clone(),
            active_series_id: active_series_id.clone(),
            series_pointer_version: head.series_pointer_version,
            previous_series_ids,
            record_digest: head.record_digest,
            source_commit_ref: record.source_commit_ref.clone(),
            issued_at: record.issued_at,
            auth_data: record.auth_data.clone(),
            extra: record.extra.clone(),
            event_id: operation.context.event_id.to_string(),
        };
        self.set_facet(
            operation.realm_id.as_str(),
            FacetRef::composite(facet::KEY_BACKUP_ACTIVE_SERIES, &[&actor_id, &backup_kind]),
            operation.payload.clone(),
        );
        self.key_backup_active_series
            .insert(pointer_key, projection);

        ProjectionEffect::KeyBackupActiveSeriesProjected {
            actor_id,
            backup_kind,
            active_series_id,
        }
    }

    pub fn key_backup_active_series(
        &self,
        actor_id: &str,
        backup_kind: &str,
    ) -> Option<&SolandKeyBackupActiveSeries> {
        self.key_backup_active_series
            .get(&(actor_id.to_owned(), backup_kind.to_owned()))
    }

    pub fn key_backup_active_series_head(
        &self,
        actor_id: &str,
        backup_kind: &str,
    ) -> Option<arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesHead> {
        self.key_backup_active_series(actor_id, backup_kind)
            .and_then(soland_active_series_head)
    }
}

fn soland_active_series_head(
    current: &SolandKeyBackupActiveSeries,
) -> Option<arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesHead> {
    Some(
        arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesHead {
            actor_id: serde_json::from_str(&current.actor_id).ok()?,
            backup_kind: arkret_models_crypto::BackupKind::try_from(current.backup_kind.as_str())
                .ok()?,
            active_series_id: arkret_identifiers::BackupSeriesId::new(
                current.active_series_id.clone(),
            )
            .ok()?,
            series_pointer_version: current.series_pointer_version,
            previous_series_ids: current
                .previous_series_ids
                .iter()
                .map(|series_id| arkret_identifiers::BackupSeriesId::new(series_id.clone()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .ok()?,
            record_digest: current.record_digest.clone(),
        },
    )
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

fn backup_class_wire(backup_kind: arkret_models_crypto::BackupKind) -> &'static str {
    backup_kind.as_str()
}
