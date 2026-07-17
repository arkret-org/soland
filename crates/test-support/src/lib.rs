#![forbid(unsafe_code)]

pub fn app_config() -> soland::config::AppConfig {
    soland::config::AppConfig::test_default()
}

pub use soland::test_support::project_accepted_operations;
pub use soland_domain::identity::principal_control_realm_for_did;
