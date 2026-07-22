use super::*;

pub(super) fn stored_recovery_type_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("stored recovery {context} invalid: {error}"))
}

pub(super) fn recovery_session_store_error(error: PersistenceError) -> AppError {
    if error.is_conflict_kind() && error.detail().contains("already exists") {
        AppError::conflict(error.detail()).with_wire_code("recovery_session_conflict")
    } else {
        recovery_store_error(error)
    }
}

pub(super) fn recovery_store_error(error: PersistenceError) -> AppError {
    match error.kind() {
        soland_application::ApplicationErrorKind::Conflict => AppError::conflict(error.detail()),
        soland_application::ApplicationErrorKind::NotFound => AppError::not_found(error.detail()),
        soland_application::ApplicationErrorKind::Database => AppError::internal(format!(
            "recovery persistence database error: {}",
            error.detail()
        )),
        soland_application::ApplicationErrorKind::SchemaViolation => {
            AppError::invalid_param(error.detail()).with_wire_code("schema_violation")
        }
        soland_application::ApplicationErrorKind::Internal => AppError::internal(error.detail()),
    }
}

pub(super) fn recovery_application_error(error: soland_application::ApplicationError) -> AppError {
    recovery_store_error(error)
}

pub(super) fn recovery_policy_application_error(
    error: soland_application::ApplicationError,
) -> AppError {
    recovery_policy_store_error(error)
}

pub(super) fn recovery_policy_store_error(error: PersistenceError) -> AppError {
    if !error.is_conflict_kind() {
        return recovery_store_error(error);
    }
    let message = error.detail();
    if message.contains("principal/version") || message.contains("version") {
        AppError::conflict(message).with_wire_code("recovery_policy_version_not_monotonic")
    } else if message.contains("supersedes") {
        AppError::conflict(message).with_wire_code("recovery_policy_supersedes_invalid")
    } else {
        AppError::conflict(message).with_wire_code("recovery_policy_conflict")
    }
}

pub(super) fn recovery_receipt_store_error(error: PersistenceError) -> AppError {
    if !error.is_conflict_kind() {
        return recovery_store_error(error);
    }
    if error.detail().contains("recovery_session_id") {
        AppError::conflict(error.detail()).with_wire_code("recovery_session_id_reused")
    } else {
        AppError::conflict(error.detail()).with_wire_code("recovery_receipt_conflict")
    }
}
