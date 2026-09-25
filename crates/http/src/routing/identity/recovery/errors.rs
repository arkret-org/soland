use super::*;

pub(super) fn stored_recovery_type_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("stored recovery {context} invalid: {error}"))
}

pub(super) fn recovery_session_store_error(error: PersistenceError) -> AppError {
    if error.conflict_code() == Some(soland_storage::ConflictCode::RecoverySessionAlreadyExists) {
        AppError::conflict(error.detail()).with_internal_reason("recovery_session_conflict")
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
            AppError::schema_violation(error.detail())
        }
        soland_services::ServiceErrorKind::Internal => AppError::internal(error.detail()),
        soland_services::ServiceErrorKind::UnsupportedEventKind => {
            AppError::new(arkret_wire::ErrorCode::UnsupportedEventKind, error.detail())
        }
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
    // `conflict` is the abstract 409 base code; api-conventions.md 5.1 asks for
    // the precise registry entry. All three arms are the same top-level
    // rejection, discriminated by their registered reason code.
    let rejection = AppError::conflict(message).with_internal_reason("recovery_policy_conflict");
    match error.conflict_code() {
        Some(soland_storage::ConflictCode::RecoveryPolicyVersionNotMonotonic) => {
            rejection.with_reason_code("recovery_policy_version_not_monotonic")
        }
        Some(soland_storage::ConflictCode::RecoveryPolicySupersedesInvalid) => {
            rejection.with_reason_code("recovery_policy_supersedes_invalid")
        }
        Some(soland_storage::ConflictCode::RecoveryPolicyGenesisNotV1) => {
            rejection.with_reason_code("recovery_policy_genesis_not_v1")
        }
        _ => rejection,
    }
}
