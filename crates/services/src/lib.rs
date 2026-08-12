#![forbid(unsafe_code)]

pub mod authorization;
#[doc(hidden)]
pub mod conformance_basis;
pub mod delivery;
pub mod events;
pub mod federation;
pub mod governance;
pub mod hydration;
pub mod identity;
pub mod jobs;
pub mod join_applications;
pub mod operation_semantics;
pub mod organization_registration;
pub mod persistence;
#[doc(hidden)]
pub mod persistence_delivery;
#[doc(hidden)]
pub mod persistence_events;
#[doc(hidden)]
pub mod persistence_identity;
#[doc(hidden)]
pub mod persistence_operations;
pub mod projection;
pub mod protocol_artifacts;
pub mod runtime_guards;
pub mod service_route;
pub mod sync;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("schema violation: {0}")]
    SchemaViolation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceErrorKind {
    NotFound,
    Conflict,
    Database,
    SchemaViolation,
    Internal,
}

impl ServiceError {
    #[must_use]
    pub fn kind(&self) -> ServiceErrorKind {
        match self {
            Self::NotFound(_) => ServiceErrorKind::NotFound,
            Self::Conflict(_) => ServiceErrorKind::Conflict,
            Self::Database(_) => ServiceErrorKind::Database,
            Self::SchemaViolation(_) => ServiceErrorKind::SchemaViolation,
            Self::Internal(_) => ServiceErrorKind::Internal,
        }
    }

    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::Internal(detail.into())
    }

    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    #[must_use]
    pub fn is_conflict_kind(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::NotFound(detail)
            | Self::Conflict(detail)
            | Self::Database(detail)
            | Self::SchemaViolation(detail)
            | Self::Internal(detail) => detail,
        }
    }

    #[must_use]
    pub fn is_conflict(&self, expected: &str) -> bool {
        matches!(self, Self::Conflict(reason) if reason == expected)
    }

    /// The registered conflict code this error carries, if any.
    ///
    /// Routing layers `match` on this. They must not inspect [`Self::detail`]
    /// to decide a status, a wire reason, or a signed decision -- see
    /// [`soland_storage::ConflictCode`].
    #[must_use]
    pub fn conflict_code(&self) -> Option<soland_storage::ConflictCode> {
        match self {
            Self::Conflict(detail) => soland_storage::ConflictCode::from_detail(detail),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_realm_already_exists(&self) -> bool {
        self.conflict_code() == Some(soland_storage::ConflictCode::RealmAlreadyExists)
    }
}

impl From<soland_storage::PersistenceError> for ServiceError {
    fn from(error: soland_storage::PersistenceError) -> Self {
        match error {
            soland_storage::PersistenceError::NotFound(detail) => Self::NotFound(detail),
            soland_storage::PersistenceError::Conflict(detail) => Self::Conflict(detail),
            soland_storage::PersistenceError::Database(detail) => Self::Database(detail),
            soland_storage::PersistenceError::SchemaViolation(detail) => {
                Self::SchemaViolation(detail)
            }
            soland_storage::PersistenceError::Internal(detail) => Self::Internal(detail),
        }
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

pub fn validate_embedded_artifacts() -> Result<(), soland_domain::artifacts::ArtifactError> {
    soland_domain::artifacts::validate_embedded_artifacts()
}

#[cfg(test)]
mod boundary_tests {
    #[test]
    fn public_use_case_types_stay_transport_agnostic() {
        for source in [
            include_str!("delivery.rs"),
            include_str!("authorization.rs"),
            include_str!("events.rs"),
            include_str!("federation.rs"),
            include_str!("governance.rs"),
            include_str!("hydration.rs"),
            include_str!("identity.rs"),
            include_str!("jobs.rs"),
            include_str!("projection.rs"),
            include_str!("runtime_guards.rs"),
            include_str!("sync.rs"),
        ] {
            for forbidden in [
                "salvo::",
                "Extractible",
                "ToSchema",
                "Serialize",
                "Deserialize",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "application use-case source contains transport marker {forbidden}"
                );
            }
        }
    }
}
