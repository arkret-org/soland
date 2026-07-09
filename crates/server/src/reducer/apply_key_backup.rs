use std::collections::BTreeSet;

use super::*;

const KEY_BACKUP_ACTIVE_SERIES_SCHEMA: &str = "ck.schema.key_backup_active_series.v1";
const KEY_BACKUP_ACTIVE_SERIES_CELL_FAMILY: &str = "ck.component.key_backup.active_series.v1";
const REQUIRED_ACTIVE_SERIES_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "actor_id",
    "backup_class",
    "active_series_id",
    "previous_series_ids",
    "frontier_ref",
    "issued_at",
];

impl ProjectionState {
    pub(crate) fn apply_key_backup_active_series(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(cokret_sdk::events::kinds::KEY_BACKUP_ACTIVE_SERIES)
        {
            return ProjectionEffect::Ignored;
        }

        let record: cokret_sdk::KeyBackupActiveSeries =
            match serde_json::from_value(operation.payload.clone()) {
                Ok(record) => record,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: "key_backup_active_series_schema_violation".to_owned(),
                    };
                }
            };

        let actor_id = record.actor_id.as_str().to_owned();
        let backup_class = backup_class_wire(record.backup_class).to_owned();
        let active_series_id = record.active_series_id.as_str().to_owned();
        let previous_series_ids = record
            .previous_series_ids
            .iter()
            .map(|series_id| series_id.as_str().to_owned())
            .collect::<Vec<_>>();

        if record.schema != KEY_BACKUP_ACTIVE_SERIES_SCHEMA {
            return rejected("key_backup_active_series_schema_mismatch");
        }
        if previous_series_ids
            .iter()
            .any(|series_id| series_id == &active_series_id)
        {
            return rejected("key_backup_active_series_active_in_previous");
        }
        if let Err(reason) = validate_active_series_frontier_ref(
            &record.frontier_ref,
            record.auth_data.ssk_generation,
        ) {
            return rejected(reason);
        }
        if let Err(reason) = validate_active_series_auth_data(&record.auth_data) {
            return rejected(reason);
        }

        let projection = SolandKeyBackupActiveSeries {
            actor_id: actor_id.clone(),
            backup_class: backup_class.clone(),
            active_series_id: active_series_id.clone(),
            previous_series_ids,
            frontier_ref: record.frontier_ref.clone(),
            issued_at: record.issued_at,
            ssk_generation: record.auth_data.ssk_generation,
            event_id: operation.operation_id.to_string(),
        };
        let subject = active_series_subject(&actor_id, &backup_class);
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ak:cell:{KEY_BACKUP_ACTIVE_SERIES_CELL_FAMILY}:{subject}"
        )) {
            self.cells
                .insert(cell_id, CellState::Value(operation.payload.clone()));
        }
        self.key_backup_active_series
            .insert((actor_id.clone(), backup_class.clone()), projection);

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
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

fn backup_class_wire(backup_class: cokret_sdk::BackupClass) -> &'static str {
    match backup_class {
        cokret_sdk::BackupClass::DidRecovery => "did_recovery",
        cokret_sdk::BackupClass::SecretStorage => "secret_storage",
        cokret_sdk::BackupClass::MlsHistory => "mls_history",
    }
}

fn active_series_subject(actor_id: &str, backup_class: &str) -> String {
    format!("{actor_id}::{backup_class}")
}

fn validate_active_series_frontier_ref(
    frontier_ref: &Value,
    auth_ssk_generation: u64,
) -> Result<(), &'static str> {
    let Some(frontier) = frontier_ref.as_object() else {
        return Err("key_backup_active_series_frontier_ref_not_object");
    };
    let Some(frontier_digest) = frontier.get("frontier_digest").and_then(Value::as_str) else {
        return Err("key_backup_active_series_frontier_digest_required");
    };
    if !is_active_series_hash(frontier_digest) {
        return Err("key_backup_active_series_frontier_digest_invalid");
    }
    if let Some(seal_ref) = frontier.get("seal_ref").and_then(Value::as_str)
        && !is_seal_ref(seal_ref)
    {
        return Err("key_backup_active_series_seal_ref_invalid");
    }
    let Some(frontier_ssk_generation) = frontier.get("ssk_generation").and_then(Value::as_u64)
    else {
        return Err("key_backup_active_series_frontier_ssk_generation_required");
    };
    if frontier_ssk_generation == 0 || frontier_ssk_generation != auth_ssk_generation {
        return Err("key_backup_active_series_ssk_generation_mismatch");
    }
    Ok(())
}

fn validate_active_series_auth_data(
    auth: &cokret_sdk::KeyBackupActiveSeriesAuthData,
) -> Result<(), &'static str> {
    if !is_did_url(&auth.verification_method) {
        return Err("key_backup_active_series_verification_method_invalid");
    }
    if !matches!(
        auth.signature_algorithm.as_str(),
        "Ed25519" | "ES256" | "ML-DSA-65"
    ) {
        return Err("key_backup_active_series_signature_algorithm_invalid");
    }
    if !is_base64url_non_empty(&auth.signature) {
        return Err("key_backup_active_series_signature_invalid");
    }
    if auth.ssk_generation == 0 {
        return Err("key_backup_active_series_auth_ssk_generation_required");
    }

    let unique_fields = auth.signed_fields.iter().collect::<BTreeSet<_>>();
    if unique_fields.len() != auth.signed_fields.len() {
        return Err("key_backup_active_series_signed_fields_duplicate");
    }
    for field in REQUIRED_ACTIVE_SERIES_SIGNED_FIELDS {
        if !unique_fields
            .iter()
            .any(|candidate| candidate.as_str() == *field)
        {
            return Err("key_backup_active_series_signed_fields_incomplete");
        }
    }
    Ok(())
}

fn is_base64url_non_empty(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn is_active_series_hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("blake3:"))
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn is_seal_ref(value: &str) -> bool {
    value
        .strip_prefix("ak:seal:sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn is_did_url(value: &str) -> bool {
    let Some((did, fragment)) = value.split_once('#') else {
        return false;
    };
    !fragment.is_empty() && cokret_sdk::Did::new(did.to_owned()).is_ok()
}
