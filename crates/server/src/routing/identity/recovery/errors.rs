use super::*;

pub(super) fn stored_recovery_type_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("stored recovery {context} invalid: {error}"))
}

pub(super) fn recovery_session_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) if message.contains("already exists") => {
            AppError::conflict(message).with_wire_code("recovery_session_conflict")
        }
        other => recovery_store_error(other),
    }
}

pub(super) fn recovery_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) => AppError::conflict(message),
        PersistenceError::NotFound(message) => AppError::not_found(message),
        PersistenceError::Database(error) => {
            AppError::internal(format!("recovery persistence database error: {error}"))
        }
        PersistenceError::SchemaViolation(message) => {
            AppError::invalid_param(message).with_wire_code("schema_violation")
        }
        PersistenceError::Internal(message) => AppError::internal(message),
    }
}

pub(super) fn recovery_policy_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) if message.contains("principal/version") => {
            AppError::conflict(message).with_wire_code("recovery_policy_version_not_monotonic")
        }
        PersistenceError::Conflict(message) if message.contains("version") => {
            AppError::conflict(message).with_wire_code("recovery_policy_version_not_monotonic")
        }
        PersistenceError::Conflict(message) if message.contains("supersedes") => {
            AppError::conflict(message).with_wire_code("recovery_policy_supersedes_invalid")
        }
        PersistenceError::Conflict(message) => {
            AppError::conflict(message).with_wire_code("recovery_policy_conflict")
        }
        other => recovery_store_error(other),
    }
}

pub(super) fn recovery_receipt_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) if message.contains("recovery_session_id") => {
            AppError::conflict(message).with_wire_code("recovery_session_id_reused")
        }
        PersistenceError::Conflict(message) => {
            AppError::conflict(message).with_wire_code("recovery_receipt_conflict")
        }
        other => recovery_store_error(other),
    }
}
