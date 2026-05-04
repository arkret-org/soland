use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use serde_json::{Value, json};

pub const EVENT_KIND_REGISTRY_JSON: &str =
    include_str!("../../contrix-spec/artifacts/registry/event-kind-registry.json");
pub const SCHEMA_REGISTRY_JSON: &str =
    include_str!("../../contrix-spec/artifacts/registry/schema-registry.json");
pub const OPERATION_REGISTRY_JSON: &str =
    include_str!("../../contrix-spec/artifacts/registry/operation-registry.json");
pub const ID_KIND_REGISTRY_JSON: &str =
    include_str!("../../contrix-spec/artifacts/registry/id-kind-registry.json");

static EVENT_KIND_REGISTRY: OnceLock<Value> = OnceLock::new();
static SCHEMA_REGISTRY: OnceLock<Value> = OnceLock::new();
static OPERATION_REGISTRY: OnceLock<Value> = OnceLock::new();
static ID_KIND_REGISTRY: OnceLock<Value> = OnceLock::new();
static ACTIVE_DURABLE_EVENT_KINDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static SCHEMA_ENTRIES: OnceLock<Vec<SchemaRegistryEntry>> = OnceLock::new();
static OPERATION_IDS: OnceLock<BTreeSet<String>> = OnceLock::new();
static ID_KIND_FORMS: OnceLock<HashMap<String, String>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct SchemaRegistryEntry {
    pub schema_id: String,
    pub file: String,
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
        "source": "contrix-spec/artifacts",
        "versions": registry_versions(),
        "counts": {
            "active_durable_event_kinds": active_durable_event_kinds().len(),
            "schemas": schema_entries().len(),
            "operations": operation_ids().len(),
            "id_kinds": id_kind_forms().len()
        }
    })
}

fn parse_artifact(source: &str, label: &str) -> Value {
    serde_json::from_str(source).unwrap_or_else(|error| {
        panic!("invalid embedded Contrix {label}: {error}");
    })
}

fn registry_version(registry: &Value) -> String {
    registry
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}
