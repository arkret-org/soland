use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use serde_json::{Value, json};

/// Error raised when an embedded Arkret artifact fails to parse.
///
/// The artifacts (event-kind / schema / operation / id-kind registries) are
/// `include_str!`'d at build time, so a parse failure represents a build-vs-spec
/// mismatch — not a runtime input. Callers should surface this through their
/// startup path (see [`validate_embedded_artifacts`]) rather than allowing the
/// first HTTP request to panic on lazy initialisation.
#[derive(Debug, thiserror::Error)]
#[error("invalid embedded Arkret {label}: {source}")]
pub struct ArtifactError {
    pub label: &'static str,
    #[source]
    pub source: serde_json::Error,
}

pub const EVENT_KIND_REGISTRY_JSON: &str =
    include_str!("../../../../arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json");
pub const SCHEMA_REGISTRY_JSON: &str =
    include_str!("../../../../arkret-spec/spec/v1/artifacts/registry/schema-registry.json");
pub const OPERATION_REGISTRY_JSON: &str =
    include_str!("../../../../arkret-spec/spec/v1/artifacts/registry/operation-registry.json");
pub const ID_KIND_REGISTRY_JSON: &str =
    include_str!("../../../../arkret-spec/spec/v1/artifacts/registry/id-kind-registry.json");
pub const DEPLOYMENT_PROBES_JSON: &str =
    include_str!("../../../../arkret-spec/spec/v1/artifacts/deployment-probes.json");

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
    pub tier: String,
    pub profile: Option<String>,
    pub operations: Vec<String>,
}

pub fn event_kind_registry() -> &'static Value {
    EVENT_KIND_REGISTRY
        .get_or_init(|| parse_artifact(EVENT_KIND_REGISTRY_JSON, "event-kind registry"))
}

pub fn schema_registry() -> &'static Value {
    SCHEMA_REGISTRY.get_or_init(|| parse_artifact(SCHEMA_REGISTRY_JSON, "schema registry"))
}

pub fn operation_registry() -> &'static Value {
    OPERATION_REGISTRY.get_or_init(|| parse_artifact(OPERATION_REGISTRY_JSON, "operation registry"))
}

pub fn id_kind_registry() -> &'static Value {
    ID_KIND_REGISTRY.get_or_init(|| parse_artifact(ID_KIND_REGISTRY_JSON, "id-kind registry"))
}

pub fn deployment_probes() -> &'static Value {
    DEPLOYMENT_PROBES.get_or_init(|| parse_artifact(DEPLOYMENT_PROBES_JSON, "deployment probes"))
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
                .filter_map(|entry| {
                    let event_kind = entry.get("event_kind").and_then(Value::as_str)?;
                    let cell_family = entry.get("cell_family").and_then(Value::as_str)?;
                    let lattice = entry.get("lattice").and_then(Value::as_str)?;
                    let bottom = entry.get("bottom").and_then(Value::as_str)?;
                    Some(EventKindCellBinding {
                        event_kind: event_kind.to_owned(),
                        cell_family: cell_family.to_owned(),
                        lattice: lattice.to_owned(),
                        bottom: bottom.to_owned(),
                    })
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
                    let tier = entry.get("tier").and_then(Value::as_str)?;
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
                        tier: tier.to_owned(),
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

fn parse_artifact(source: &str, label: &str) -> Value {
    serde_json::from_str(source).unwrap_or_else(|error| {
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
    for (json, label) in [
        (EVENT_KIND_REGISTRY_JSON, "event-kind registry"),
        (SCHEMA_REGISTRY_JSON, "schema registry"),
        (OPERATION_REGISTRY_JSON, "operation registry"),
        (ID_KIND_REGISTRY_JSON, "id-kind registry"),
        (DEPLOYMENT_PROBES_JSON, "deployment probes"),
    ] {
        serde_json::from_str::<Value>(json).map_err(|source| ArtifactError { label, source })?;
    }
    Ok(())
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
    fn operation_surface_helper_reads_catalog_groups() {
        let groups = operation_surface_groups();
        assert!(
            groups.iter().any(|group| {
                group.surface == "events_sync"
                    && group.tier == "core"
                    && group
                        .operations
                        .iter()
                        .any(|op| op == "ak.self.events.command.submit")
            }),
            "events_sync operation surface group should come from operation-registry.json"
        );

        let operations = operation_ids_for_surface_groups(&["events_sync", "push"]);
        assert!(
            operations
                .iter()
                .any(|op| op == "ak.self.events.command.submit")
        );
        assert!(
            operations
                .iter()
                .any(|op| op == "ak.edge.push.command.notify")
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
        assert_eq!(member.cell_family, "ak.component.member.state.v1");
        assert_eq!(member.lattice, "fsm");
        assert_eq!(member.bottom, "reject");

        let families = cell_family_bindings();
        let consent = families
            .iter()
            .find(|binding| binding.cell_family == "ak.component.consent.grant.v1")
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
