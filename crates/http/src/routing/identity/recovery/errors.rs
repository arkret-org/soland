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
        soland_services::ServiceErrorKind::Conflict => AppError::conflict(error.detail()),
        soland_services::ServiceErrorKind::NotFound => AppError::not_found(error.detail()),
        soland_services::ServiceErrorKind::Database => AppError::internal(format!(
            "recovery persistence database error: {}",
            error.detail()
        )),
        soland_services::ServiceErrorKind::SchemaViolation => {
            AppError::param_invalid(error.detail()).with_wire_code("schema_violation")
        }
        soland_services::ServiceErrorKind::Internal => AppError::internal(error.detail()),
    }
}

pub(super) fn recovery_service_error(error: soland_services::ServiceError) -> AppError {
    recovery_store_error(error)
}

pub(super) fn recovery_policy_service_error(error: soland_services::ServiceError) -> AppError {
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
