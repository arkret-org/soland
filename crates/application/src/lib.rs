#![forbid(unsafe_code)]

pub mod delivery;
pub mod events;
pub mod federation;
pub mod governance;
pub mod identity;
pub mod jobs;
pub mod sync;

#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    #[error(transparent)]
    Storage(#[from] soland_storage::PersistenceError),
}

pub type ApplicationResult<T> = Result<T, ApplicationError>;

pub fn validate_embedded_artifacts() -> Result<(), soland_domain::artifacts::ArtifactError> {
    soland_domain::artifacts::validate_embedded_artifacts()
}

#[cfg(test)]
mod boundary_tests {
    #[test]
    fn public_use_case_types_stay_transport_agnostic() {
        for source in [
            include_str!("delivery.rs"),
            include_str!("events.rs"),
            include_str!("federation.rs"),
            include_str!("governance.rs"),
            include_str!("identity.rs"),
            include_str!("jobs.rs"),
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
