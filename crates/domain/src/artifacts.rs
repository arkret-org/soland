use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use arkret_schema::ProtocolSchemaRegistry;
use serde_json::{Value, json};

/// Error raised when an embedded Arkret artifact fails to parse.
///
/// The artifacts are loaded from the SDK's embedded snapshot, so a failure represents a
/// build-vs-spec mismatch — not a runtime input. Callers should surface this through their
/// startup path (see [`validate_embedded_artifacts`]) rather than allowing the
/// first HTTP request to panic on lazy initialisation.
#[derive(Debug, thiserror::Error)]
#[error("invalid embedded Arkret {label}: {detail}")]
pub struct ArtifactError {
    pub label: &'static str,
    pub detail: String,
}

pub const PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF: &str = "deployment-probes.json#/probes/0";

static EVENT_KIND_REGISTRY: OnceLock<Value> = OnceLock::new();
static SCHEMA_REGISTRY: OnceLock<Value> = OnceLock::new();
static OPERATION_REGISTRY: OnceLock<Value> = OnceLock::new();
static ID_KIND_REGISTRY: OnceLock<Value> = OnceLock::new();
static DEPLOYMENT_PROBES: OnceLock<Value> = OnceLock::new();
static ACTIVE_DURABLE_EVENT_KINDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ACTIVE_LOCAL_OPERATION_EVENT_KINDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ACTIVE_DURABLE_CELL_BINDINGS: OnceLock<Vec<EventKindCellBinding>> = OnceLock::new();
static CELL_FAMILY_BINDINGS: OnceLock<Vec<CellFamilyBinding>> = OnceLock::new();
static SCHEMA_ENTRIES: OnceLock<Vec<SchemaRegistryEntry>> = OnceLock::new();
static OPERATION_SURFACE_GROUPS: OnceLock<Vec<OperationSurfaceGroup>> = OnceLock::new();
static OPERATION_IDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ID_KIND_FORMS: OnceLock<HashMap<String, String>> = OnceLock::new();
static PROTOCOL_SCHEMA_REGISTRY: OnceLock<Result<ProtocolSchemaRegistry, String>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct SchemaRegistryEntry {
    pub schema_id: String,
    pub file: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventKindCellBinding {
    pub event_kind: String,
    pub cell_family: String,
    pub lattice: String,
    pub bottom: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellFamilyBinding {
    pub cell_family: String,
    pub lattice: String,
    pub bottom: String,
    pub event_kinds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSurfaceGroup {
    pub surface: String,
    pub surface_class: String,
    pub profile: Option<String>,
    pub operations: Vec<String>,
}

pub fn event_kind_registry() -> &'static Value {
    EVENT_KIND_REGISTRY.get_or_init(|| {
        embedded_artifact("registry/event-kind-registry.json", "event-kind registry")
    })
}

pub fn schema_registry() -> &'static Value {
    SCHEMA_REGISTRY
        .get_or_init(|| embedded_artifact("registry/schema-registry.json", "schema registry"))
}

pub fn operation_registry() -> &'static Value {
    OPERATION_REGISTRY
        .get_or_init(|| embedded_artifact("registry/operation-registry.json", "operation registry"))
}

pub fn id_kind_registry() -> &'static Value {
    ID_KIND_REGISTRY
        .get_or_init(|| embedded_artifact("registry/id-kind-registry.json", "id-kind registry"))
}

pub fn deployment_probes() -> &'static Value {
    DEPLOYMENT_PROBES
        .get_or_init(|| embedded_artifact("deployment-probes.json", "deployment probes"))
}

pub fn pq_hybrid_tls_required_group() -> &'static str {
    deployment_probes()
        .get("probes")
        .and_then(Value::as_array)
        .and_then(|probes| probes.first())
        .and_then(|probe| probe.get("tls"))
        .and_then(|tls| tls.get("required_named_group"))
        .and_then(Value::as_str)
        .unwrap_or("X25519MLKEM768")
}

pub fn active_durable_event_kinds() -> &'static BTreeSet<String> {
    ACTIVE_DURABLE_EVENT_KINDS.get_or_init(|| {
        event_kind_registry()
            .get("event_kinds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("active"))
            .filter(|entry| {
                entry.get("wire_scope").and_then(Value::as_str) == Some("durable_event")
            })
            .filter_map(|entry| entry.get("event_kind").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect()
    })
}

pub fn active_local_operation_event_kinds() -> &'static BTreeSet<String> {
    ACTIVE_LOCAL_OPERATION_EVENT_KINDS.get_or_init(|| {
        event_kind_registry()
            .get("event_kinds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("active"))
            .filter(|entry| {
                matches!(
                    entry.get("wire_scope").and_then(Value::as_str),
                    Some("durable_event" | "actor_private_event")
                )
            })
            .filter_map(|entry| entry.get("event_kind").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect()
    })
}

pub fn active_durable_cell_bindings() -> &'static [EventKindCellBinding] {
    ACTIVE_DURABLE_CELL_BINDINGS
        .get_or_init(|| {
            event_kind_registry()
                .get("event_kinds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("active"))
                .filter(|entry| {
                    entry.get("wire_scope").and_then(Value::as_str) == Some("durable_event")
                })
                .flat_map(|entry| {
                    let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
                        return Vec::new();
                    };
                    entry
                        .get("cell_writes")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|write| {
                            Some(EventKindCellBinding {
                                event_kind: event_kind.to_owned(),
                                cell_family: write
                                    .get("cell_family")
                                    .and_then(Value::as_str)?
                                    .to_owned(),
                                lattice: write.get("lattice").and_then(Value::as_str)?.to_owned(),
                                bottom: write.get("bottom").and_then(Value::as_str)?.to_owned(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        })
        .as_slice()
}

pub fn cell_family_bindings() -> &'static [CellFamilyBinding] {
    CELL_FAMILY_BINDINGS
        .get_or_init(|| {
            let mut by_family: HashMap<String, CellFamilyBinding> = HashMap::new();
            for binding in active_durable_cell_bindings() {
                let entry = by_family
                    .entry(binding.cell_family.clone())
                    .or_insert_with(|| CellFamilyBinding {
                        cell_family: binding.cell_family.clone(),
                        lattice: binding.lattice.clone(),
                        bottom: binding.bottom.clone(),
                        event_kinds: Vec::new(),
                    });
                entry.event_kinds.push(binding.event_kind.clone());
            }
            let mut bindings = by_family.into_values().collect::<Vec<_>>();
            bindings.sort_by(|a, b| a.cell_family.cmp(&b.cell_family));
            bindings
        })
        .as_slice()
}

pub fn schema_entries() -> &'static [SchemaRegistryEntry] {
    SCHEMA_ENTRIES
        .get_or_init(|| {
            schema_registry()
                .get("schemas")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    let schema_id = entry.get("schema_id").and_then(Value::as_str)?;
                    let file = entry.get("file").and_then(Value::as_str)?;
                    Some(SchemaRegistryEntry {
                        schema_id: schema_id.to_owned(),
                        file: file.to_owned(),
                    })
                })
                .collect()
        })
        .as_slice()
}

pub fn schema_ids() -> BTreeSet<String> {
    schema_entries()
        .iter()
        .map(|entry| entry.schema_id.clone())
        .collect()
}

pub fn operation_surface_groups() -> &'static [OperationSurfaceGroup] {
    OPERATION_SURFACE_GROUPS
        .get_or_init(|| {
            operation_registry()
                .get("surface_groups")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    let surface = entry.get("surface").and_then(Value::as_str)?;
                    let surface_class = entry.get("surface_class").and_then(Value::as_str)?;
                    let profile = entry
                        .get("profile")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    let operations = entry
                        .get("operations")
                        .and_then(Value::as_array)?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>();
                    Some(OperationSurfaceGroup {
                        surface: surface.to_owned(),
                        surface_class: surface_class.to_owned(),
                        profile,
                        operations,
                    })
                })
                .collect()
        })
        .as_slice()
}

pub fn operation_ids() -> &'static BTreeSet<String> {
    OPERATION_IDS.get_or_init(|| {
        operation_registry()
            .get("operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("operation_id").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect()
    })
}

pub fn operation_ids_for_surface_groups(surfaces: &[&str]) -> Vec<String> {
    let wanted = surfaces.iter().copied().collect::<BTreeSet<_>>();
    let catalog = operation_ids();
    let mut seen = BTreeSet::new();
    operation_surface_groups()
        .iter()
        .filter(|group| wanted.contains(group.surface.as_str()))
        .flat_map(|group| group.operations.iter())
        .filter(|operation_id| catalog.contains(*operation_id))
        .filter(|operation_id| seen.insert((*operation_id).clone()))
        .cloned()
        .collect()
}

pub fn missing_operation_surface_groups(surfaces: &[&str]) -> Vec<String> {
    let catalog = operation_surface_groups()
        .iter()
        .map(|group| group.surface.as_str())
        .collect::<BTreeSet<_>>();
    surfaces
        .iter()
        .copied()
        .filter(|surface| !catalog.contains(surface))
        .map(ToOwned::to_owned)
        .collect()
}

pub fn registered_operation_ids(candidate_operation_ids: &[&str]) -> Vec<String> {
    let catalog = operation_ids();
    let mut seen = BTreeSet::new();
    candidate_operation_ids
        .iter()
        .copied()
        .filter(|operation_id| catalog.contains(*operation_id))
        .filter(|operation_id| seen.insert((*operation_id).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

pub fn missing_operation_ids(candidate_operation_ids: &[&str]) -> Vec<String> {
    let catalog = operation_ids();
    candidate_operation_ids
        .iter()
        .copied()
        .filter(|operation_id| !catalog.contains(*operation_id))
        .map(ToOwned::to_owned)
        .collect()
}

pub fn id_kind_forms() -> &'static HashMap<String, String> {
    ID_KIND_FORMS.get_or_init(|| {
        id_kind_registry()
            .get("id_kinds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let kind = entry.get("kind").and_then(Value::as_str)?;
                let wire_form = entry.get("wire_form").and_then(Value::as_str)?;
                Some((kind.to_owned(), wire_form.to_owned()))
            })
            .collect()
    })
}

pub fn registry_versions() -> Value {
    json!({
        "event_kind": registry_version(event_kind_registry()),
        "schema": registry_version(schema_registry()),
        "operation": registry_version(operation_registry()),
        "id_kind": registry_version(id_kind_registry())
    })
}

pub fn registry_summary() -> Value {
    json!({
        "source": "arkret-spec/spec/v1/artifacts",
        "versions": registry_versions(),
        "counts": {
            "active_durable_event_kinds": active_durable_event_kinds().len(),
            "active_durable_cell_bindings": active_durable_cell_bindings().len(),
            "cell_families": cell_family_bindings().len(),
            "schemas": schema_entries().len(),
            "operation_surface_groups": operation_surface_groups().len(),
            "operations": operation_ids().len(),
            "id_kinds": id_kind_forms().len(),
            "deployment_probes": deployment_probes()
                .get("probes")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        }
    })
}

fn embedded_artifact(path: &str, label: &str) -> Value {
    arkret_schema::embedded_json_artifact(path).unwrap_or_else(|error| {
        // Should be unreachable for release builds because
        // `validate_embedded_artifacts` runs in main.rs at startup. Lazy
        // callers may still hit this if validation was skipped — fail loudly.
        panic!("invalid embedded Arkret {label}: {error}");
    })
}

/// Validate every embedded Arkret artifact at startup.
///
/// Call from `main` before binding the listener so that a malformed bundled
/// artifact surfaces as a typed [`ArtifactError`] rather than crashing the
/// process on the first HTTP request that happens to touch the offending
/// `OnceLock`.
pub fn validate_embedded_artifacts() -> Result<(), ArtifactError> {
    for (path, label) in [
        ("registry/event-kind-registry.json", "event-kind registry"),
        ("registry/schema-registry.json", "schema registry"),
        ("registry/operation-registry.json", "operation registry"),
        ("registry/id-kind-registry.json", "id-kind registry"),
        ("deployment-probes.json", "deployment probes"),
    ] {
        arkret_schema::embedded_json_artifact(path).map_err(|error| ArtifactError {
            label,
            detail: error.to_string(),
        })?;
    }
    protocol_schema_registry()?;
    Ok(())
}

/// The process-wide Draft 2020-12 protocol schema catalog.
///
/// The catalog is an immutable snapshot of the spec artifacts this process was
/// started against, so it is built once and shared: rebuilding it per request
/// would recompile every logical schema on the admission hot path. The live
/// artifacts directory wins when it is configured; otherwise the SDK's embedded
/// snapshot is authoritative, which is what a deployment without a spec
/// checkout must use.
///
/// The whole catalog is compiled on first access. A residual or mutually
/// inconsistent catalog therefore fails the startup gate with the offending
/// schema ID instead of failing the first Event that happens to reach it.
pub fn protocol_schema_registry() -> Result<&'static ProtocolSchemaRegistry, ArtifactError> {
    PROTOCOL_SCHEMA_REGISTRY
        .get_or_init(build_protocol_schema_registry)
        .as_ref()
        .map_err(|detail| ArtifactError {
            label: "protocol schema catalog",
            detail: detail.clone(),
        })
}

fn build_protocol_schema_registry() -> Result<ProtocolSchemaRegistry, String> {
    let registry = match arkret_schema::schema_registry_from_default_spec_artifacts() {
        Ok(Some(registry)) => registry,
        Ok(None) => arkret_schema::schema_registry_from_embedded_spec_artifacts()
            .map_err(|error| format!("embedded spec artifacts are unusable: {error}"))?,
        Err(error) => {
            return Err(format!(
                "spec artifacts directory is present but unusable: {error}"
            ));
        }
    };
    registry.ensure_all_schemas_compile().map_err(|error| {
        let failed = registry
            .validator_stats()
            .last_failure_schema_id
            .unwrap_or_else(|| "unknown".to_owned());
        format!("schema catalog compilation failed at {failed}: {error}")
    })?;
    Ok(registry)
}

fn registry_version(registry: &Value) -> String {
    registry
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_spec_artifacts_are_embedded() {
        validate_embedded_artifacts().expect("production spec artifacts must be embedded");
    }

    #[test]
    fn startup_gate_compiles_the_whole_schema_catalog_once() {
        let registry =
            protocol_schema_registry().expect("the startup gate must compile every logical schema");
        assert_eq!(registry.schema_ids().count(), schema_entries().len());
        // The catalog is built once per process, so a second call must not
        // recompile it; only the shared validator cache is consulted.
        let compiled_before = registry.validator_stats().compiled_validators;
        protocol_schema_registry().expect("catalog stays available");
        assert_eq!(
            registry.validator_stats().compiled_validators,
            compiled_before
        );
    }

    #[test]
    fn operation_surface_helper_reads_catalog_groups() {
        let groups = operation_surface_groups();
        assert!(
            groups.iter().any(|group| {
                group.surface == "events_sync"
                    && group.surface_class == "core"
                    && group
                        .operations
                        .iter()
                        .any(|op| op == "ak.self.events.command.submit.v1")
            }),
            "events_sync operation surface group should come from operation-registry.json"
        );

        let operations = operation_ids_for_surface_groups(&["events_sync", "push"]);
        assert!(
            operations
                .iter()
                .any(|op| op == "ak.self.events.command.submit.v1")
        );
        assert!(
            operations
                .iter()
                .any(|op| op == "ak.edge.push.command.notify.v1")
        );
        assert!(operations.iter().all(|op| operation_ids().contains(op)));
    }

    #[test]
    fn deployment_probe_helper_reads_pq_tls_group() {
        assert_eq!(pq_hybrid_tls_required_group(), "X25519MLKEM768");
        assert!(
            deployment_probes()
                .get("probes")
                .and_then(Value::as_array)
                .is_some_and(|probes| probes.iter().any(|probe| {
                    probe.get("probe_id").and_then(Value::as_str)
                        == Some("deployment_probe.tls.pq_hybrid_x25519mlkem768.v1")
                }))
        );
    }

    #[test]
    fn event_cell_binding_helper_reads_lattice_metadata() {
        let bindings = active_durable_cell_bindings();
        let member = bindings
            .iter()
            .find(|binding| binding.event_kind == "ak.member.state")
            .expect("member state binding should come from event-kind registry");
        assert_eq!(
            member.cell_family,
            arkret_wire::CellFamilyId::MEMBER_STATE_V1
        );
        assert_eq!(member.lattice, "fsm");
        assert_eq!(member.bottom, "reject");

        let families = cell_family_bindings();
        let consent = families
            .iter()
            .find(|binding| binding.cell_family == arkret_wire::CellFamilyId::CONSENT_GRANT_V1)
            .expect("consent grant family should be grouped");
        assert!(
            consent
                .event_kinds
                .iter()
                .any(|kind| kind == "ak.consent.grant")
        );
        assert!(
            consent
                .event_kinds
                .iter()
                .any(|kind| kind == "ak.consent.revoke")
        );
    }
}
