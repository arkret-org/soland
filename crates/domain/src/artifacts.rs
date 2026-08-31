use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use arkret_wire::{EventKind, EventWireScope, ServiceOperationId};
use serde_json::{Value, json};

pub const PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF: &str = "deployment-probes.json#/probes/0";

static ACTIVE_DURABLE_EVENT_KINDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ACTIVE_LOCAL_OPERATION_EVENT_KINDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ACTIVE_DURABLE_CELL_BINDINGS: OnceLock<Vec<EventKindCellBinding>> = OnceLock::new();
static CELL_FAMILY_BINDINGS: OnceLock<Vec<CellFamilyBinding>> = OnceLock::new();
static OPERATION_IDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ID_KIND_FORMS: OnceLock<HashMap<String, String>> = OnceLock::new();

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

pub const fn pq_hybrid_tls_required_group() -> &'static str {
    arkret_schema::PQ_HYBRID_TLS_REQUIRED_GROUP
}

pub fn active_durable_event_kinds() -> &'static BTreeSet<String> {
    ACTIVE_DURABLE_EVENT_KINDS.get_or_init(|| {
        EventKind::ALL
            .iter()
            .filter(|kind| kind.wire_scope() == EventWireScope::DurableEvent)
            .map(|kind| kind.as_str().to_owned())
            .collect()
    })
}

pub fn active_local_operation_event_kinds() -> &'static BTreeSet<String> {
    ACTIVE_LOCAL_OPERATION_EVENT_KINDS.get_or_init(|| {
        EventKind::ALL
            .iter()
            .filter(|kind| {
                matches!(
                    kind.wire_scope(),
                    EventWireScope::DurableEvent | EventWireScope::ActorPrivateEvent
                )
            })
            .map(|kind| kind.as_str().to_owned())
            .collect()
    })
}

pub fn active_durable_cell_bindings() -> &'static [EventKindCellBinding] {
    ACTIVE_DURABLE_CELL_BINDINGS
        .get_or_init(|| {
            EventKind::ALL
                .iter()
                .filter(|kind| kind.wire_scope() == EventWireScope::DurableEvent)
                .filter_map(EventKind::descriptor)
                .flat_map(|descriptor| {
                    descriptor.cell_writes.iter().filter_map(|write| {
                        Some(EventKindCellBinding {
                            event_kind: descriptor.kind.to_owned(),
                            cell_family: write.cell_family?.as_str().to_owned(),
                            lattice: write.lattice?.as_str().to_owned(),
                            bottom: write.bottom?.as_str().to_owned(),
                        })
                    })
                })
                .collect()
        })
        .as_slice()
}

pub fn cell_family_bindings() -> &'static [CellFamilyBinding] {
    CELL_FAMILY_BINDINGS
        .get_or_init(|| {
            let mut by_family = BTreeMap::<String, CellFamilyBinding>::new();
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
            by_family.into_values().collect()
        })
        .as_slice()
}

pub fn schema_ids() -> BTreeSet<String> {
    arkret_schema::REGISTERED_SCHEMA_IDS
        .iter()
        .map(|entry| entry.schema_id.to_owned())
        .collect()
}

pub fn operation_ids() -> &'static BTreeSet<String> {
    OPERATION_IDS.get_or_init(|| {
        ServiceOperationId::ALL
            .iter()
            .map(|operation| operation.as_str().to_owned())
            .collect()
    })
}

pub fn operation_ids_for_surface_groups(surfaces: &[&str]) -> Vec<String> {
    let wanted = surfaces.iter().copied().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    arkret_schema::REGISTERED_OPERATION_SURFACE_GROUPS
        .iter()
        .filter(|group| wanted.contains(group.surface))
        .flat_map(|group| group.operations)
        .filter_map(|operation| {
            let operation = operation.as_str();
            seen.insert(operation).then(|| operation.to_owned())
        })
        .collect()
}

pub fn missing_operation_surface_groups(surfaces: &[&str]) -> Vec<String> {
    let registered = arkret_schema::REGISTERED_OPERATION_SURFACE_GROUPS
        .iter()
        .map(|group| group.surface)
        .collect::<BTreeSet<_>>();
    surfaces
        .iter()
        .copied()
        .filter(|surface| !registered.contains(surface))
        .map(str::to_owned)
        .collect()
}

pub fn registered_operation_ids(candidate_operation_ids: &[&str]) -> Vec<String> {
    let catalog = operation_ids();
    let mut seen = BTreeSet::new();
    candidate_operation_ids
        .iter()
        .copied()
        .filter(|operation_id| catalog.contains(*operation_id))
        .filter(|operation_id| seen.insert(*operation_id))
        .map(str::to_owned)
        .collect()
}

pub fn missing_operation_ids(candidate_operation_ids: &[&str]) -> Vec<String> {
    let catalog = operation_ids();
    candidate_operation_ids
        .iter()
        .copied()
        .filter(|operation_id| !catalog.contains(*operation_id))
        .map(str::to_owned)
        .collect()
}

pub fn id_kind_forms() -> &'static HashMap<String, String> {
    ID_KIND_FORMS.get_or_init(|| {
        arkret_schema::REGISTERED_ID_KINDS
            .iter()
            .map(|entry| (entry.kind.to_owned(), entry.wire_form.to_owned()))
            .collect()
    })
}

pub fn registry_versions() -> Value {
    json!({
        "event_kind": arkret_schema::EVENT_KIND_REGISTRY_VERSION,
        "schema": arkret_schema::SCHEMA_REGISTRY_VERSION,
        "operation": arkret_schema::OPERATION_REGISTRY_VERSION,
        "id_kind": arkret_schema::ID_KIND_REGISTRY_VERSION,
    })
}

pub fn registry_summary() -> Value {
    json!({
        "source": "arkret-spec generated Rust descriptors",
        "versions": registry_versions(),
        "counts": {
            "active_durable_event_kinds": active_durable_event_kinds().len(),
            "active_durable_cell_bindings": active_durable_cell_bindings().len(),
            "cell_families": cell_family_bindings().len(),
            "schemas": arkret_schema::REGISTERED_SCHEMA_IDS.len(),
            "operation_surface_groups": arkret_schema::REGISTERED_OPERATION_SURFACE_GROUPS.len(),
            "operations": operation_ids().len(),
            "id_kinds": id_kind_forms().len(),
            "deployment_probes": 1,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_descriptors_cover_runtime_indexes() {
        assert!(active_durable_event_kinds().contains("ak.member.state"));
        assert!(operation_ids().contains("ak.self.events.command.submit.v1"));
        assert!(schema_ids().contains(arkret_wire::SchemaId::EVENT_V1));
        assert_eq!(pq_hybrid_tls_required_group(), "X25519MLKEM768");
    }

    #[test]
    fn event_cell_binding_uses_generated_lattice_metadata() {
        let member = active_durable_cell_bindings()
            .iter()
            .find(|binding| binding.event_kind == "ak.member.state")
            .expect("member state binding is generated");
        assert_eq!(
            member.cell_family,
            arkret_wire::CellFamilyId::MEMBER_STATE_V1
        );
        assert_eq!(member.lattice, "fsm");
        assert_eq!(member.bottom, "reject");
    }
}
