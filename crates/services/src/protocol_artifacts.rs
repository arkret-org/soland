use std::collections::BTreeSet;

use arkret_schema::ProtocolSchemaRegistry;
use serde_json::Value;

pub const PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF: &str =
    soland_domain::artifacts::PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF;

pub fn pq_hybrid_tls_required_group() -> &'static str {
    soland_domain::artifacts::pq_hybrid_tls_required_group()
}

pub fn registry_summary() -> Value {
    soland_domain::artifacts::registry_summary()
}

pub fn missing_operation_surface_groups(groups: &[&str]) -> Vec<String> {
    soland_domain::artifacts::missing_operation_surface_groups(groups)
}

pub fn missing_operation_ids(ids: &[&str]) -> Vec<String> {
    soland_domain::artifacts::missing_operation_ids(ids)
}

pub fn operation_ids_for_surface_groups(groups: &[&str]) -> Vec<String> {
    soland_domain::artifacts::operation_ids_for_surface_groups(groups)
}

pub fn registered_operation_ids(ids: &[&str]) -> Vec<String> {
    soland_domain::artifacts::registered_operation_ids(ids)
}

pub fn operation_ids() -> &'static BTreeSet<String> {
    soland_domain::artifacts::operation_ids()
}

pub fn active_local_operation_event_kinds() -> &'static BTreeSet<String> {
    soland_domain::artifacts::active_local_operation_event_kinds()
}

pub fn active_durable_event_kinds() -> &'static BTreeSet<String> {
    soland_domain::artifacts::active_durable_event_kinds()
}

pub fn schema_ids() -> BTreeSet<String> {
    soland_domain::artifacts::schema_ids()
}

/// The process-wide Draft 2020-12 protocol schema catalog, compiled at startup.
pub fn protocol_schema_registry()
-> Result<&'static ProtocolSchemaRegistry, soland_domain::artifacts::ArtifactError> {
    soland_domain::artifacts::protocol_schema_registry()
}

/// The live spec artifacts directory this process resolved, if any.
///
/// `None` means the catalog comes from the SDK's embedded snapshot, which is
/// the normal shape for a deployment without a spec checkout.
pub fn spec_artifacts_dir() -> Option<std::path::PathBuf> {
    arkret_schema::default_spec_artifacts_dir()
}
