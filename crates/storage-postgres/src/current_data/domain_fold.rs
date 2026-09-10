//! Server-only domain views over complete, verified causal assertion sets.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{PersistenceResult, projection_error};

#[derive(Clone, Debug)]
pub(super) struct Assertion {
    pub id: String,
    pub actor: Value,
    pub kind: String,
    pub payload: Value,
    /// Complete strict ancestors, including paths through other cells.
    pub ancestors: BTreeSet<String>,
}
fn key(value: &Value) -> PersistenceResult<String> {
    String::from_utf8(arkret_canonical::canonical_json_bytes(value).map_err(projection_error)?)
        .map_err(projection_error)
}
fn later(a: &Assertion, b: &Assertion) -> bool {
    a.ancestors.contains(&b.id)
}
fn heads<'a>(items: &[&'a Assertion]) -> Vec<&'a Assertion> {
    items
        .iter()
        .copied()
        .filter(|a| !items.iter().any(|b| later(b, a)))
        .collect()
}

pub(super) fn reactions(items: &[Assertion]) -> PersistenceResult<Value> {
    let mut groups: BTreeMap<(String, String, String), Vec<&Assertion>> = BTreeMap::new();
    for item in items {
        groups
            .entry((
                key(&item.actor)?,
                key(&item.payload["target_ref"])?,
                key(&item.payload["key"])?,
            ))
            .or_default()
            .push(item);
    }
    let mut result = Vec::new();
    for (_, items) in groups {
        let removes = items
            .iter()
            .filter(|a| a.kind == "ak.reaction.remove")
            .collect::<Vec<_>>();
        let mut adds = items
            .iter()
            .filter(|a| a.kind == "ak.reaction.add" && removes.iter().all(|r| later(a, r)))
            .copied()
            .collect::<Vec<_>>();
        adds.sort_by(|a, b| a.id.cmp(&b.id));
        if let Some(first) = adds.as_slice().first() {
            result.push(json!({"actor_id":first.actor,"key":first.payload["key"],"assertions":adds.iter().map(|a|json!({"event_id":a.id,"payload":a.payload})).collect::<Vec<_>>()}));
        }
    }
    Ok(json!({"reactions":result}))
}

fn effective_pin(
    item: &Assertion,
    items: &[&Assertion],
) -> PersistenceResult<Option<(Value, Vec<String>)>> {
    if item.kind == "ak.pin.remove" {
        return Ok(None);
    }
    if item.kind == "ak.pin.add" {
        return Ok(Some((item.payload.clone(), vec![item.id.clone()])));
    }
    if item.kind != "ak.pin.reorder" {
        return Err(projection_error("unknown pin assertion"));
    }
    let past = items
        .iter()
        .copied()
        .filter(|a| later(item, a))
        .collect::<Vec<_>>();
    let previous = heads(&past);
    let [previous] = previous.as_slice() else {
        return Err(super::PersistenceError::Conflict(
            "failed_precondition: pin_target_not_pinned".into(),
        ));
    };
    let Some((mut value, mut sources)) = effective_pin(previous, items)? else {
        return Err(super::PersistenceError::Conflict(
            "failed_precondition: pin_target_not_pinned".into(),
        ));
    };
    value["rank"] = item.payload["rank"].clone();
    sources.push(item.id.clone());
    sources.sort();
    sources.dedup();
    Ok(Some((value, sources)))
}

pub(super) fn validate_pin_admission(
    items: &[Assertion],
    admitted_id: &str,
) -> PersistenceResult<()> {
    let Some(item) = items.iter().find(|a| a.id == admitted_id) else {
        return Err(projection_error("missing admitted pin assertion"));
    };
    let group = items
        .iter()
        .filter(|a| a.payload["target_ref"] == item.payload["target_ref"])
        .collect::<Vec<_>>();
    if item.kind == "ak.pin.reorder" {
        effective_pin(item, &group)?;
    }
    if let Some(expected) = item.payload.get("expected_rank") {
        let previous = group
            .iter()
            .copied()
            .filter(|a| a.id != item.id)
            .collect::<Vec<_>>();
        let current = heads(&previous);
        let rank = if let [head] = current.as_slice() {
            effective_pin(head, &previous)?.map(|(p, _)| p["rank"].clone())
        } else {
            None
        };
        if rank.as_ref() != Some(expected) {
            return Err(super::PersistenceError::Conflict(
                "failed_precondition: pin_expected_rank_mismatch".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn pins(items: &[Assertion]) -> PersistenceResult<Value> {
    let mut groups: BTreeMap<String, Vec<&Assertion>> = BTreeMap::new();
    for item in items {
        groups
            .entry(key(&item.payload["target_ref"])?)
            .or_default()
            .push(item);
    }
    let mut pins = Vec::new();
    let mut conflicts = Vec::new();
    for (_, items) in groups {
        let current = heads(&items);
        if let [item] = current.as_slice() {
            if let Some((pin, sources)) = effective_pin(item, &items)? {
                pins.push(json!({"pin":pin,"source_event_ids":sources}));
            }
        } else if !current.is_empty() {
            let mut sources = current.iter().map(|a| a.id.clone()).collect::<Vec<_>>();
            sources.sort();
            conflicts.push(
                json!({"target_ref":current[0].payload["target_ref"],"source_event_ids":sources}),
            );
        }
    }
    pins.sort_by(|a, b| {
        a["pin"]["rank"]
            .as_str()
            .cmp(&b["pin"]["rank"].as_str())
            .then_with(|| {
                key(&a["pin"]["target_ref"])
                    .unwrap()
                    .cmp(&key(&b["pin"]["target_ref"]).unwrap())
            })
    });
    Ok(json!({"pins":pins,"conflicts":conflicts}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn a(id: &str, kind: &str, payload: Value, past: &[&str]) -> Assertion {
        Assertion {
            id: id.into(),
            actor: json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:a.example","station_id":"ak:did_core:web:s.example"}}),
            kind: kind.into(),
            payload,
            ancestors: past.iter().map(|id| id.to_string()).collect(),
        }
    }
    #[test]
    fn reaction_remove_wins_concurrency_and_only_observed_readd_survives() {
        let p = json!({"target_ref":{"kind":"message","id":"m"},"key":"x"});
        let add = a("a", "ak.reaction.add", p.clone(), &[]);
        let remove = a("r", "ak.reaction.remove", p.clone(), &[]);
        assert_eq!(
            reactions(&[add.clone(), remove.clone()]).unwrap()["reactions"],
            json!([])
        );
        let readd = a("b", "ak.reaction.add", p.clone(), &["r"]);
        let x = reactions(&[readd.clone(), remove.clone(), add.clone()]).unwrap();
        assert_eq!(x["reactions"][0]["assertions"].as_array().unwrap().len(), 1);
        assert_eq!(x, reactions(&[add, remove, readd]).unwrap());
    }
    #[test]
    fn pin_concurrent_remove_exposes_heads_and_reorder_retains_note() {
        let p = json!({"pin_scope":{"kind":"realm","id":"r"},"target_ref":{"kind":"message","id":"m"},"rank":"a","note":{"ciphertext":"secret"}});
        let add = a("a", "ak.pin.add", p.clone(), &[]);
        let reorder = a(
            "b",
            "ak.pin.reorder",
            json!({"pin_scope":p["pin_scope"],"target_ref":p["target_ref"],"rank":"z"}),
            &["a"],
        );
        let result = pins(&[add.clone(), reorder.clone()]).unwrap();
        assert_eq!(result["pins"][0]["pin"]["note"], p["note"]);
        assert_eq!(result["pins"][0]["pin"]["rank"], "z");
        let remove = a(
            "r",
            "ak.pin.remove",
            json!({"pin_scope":p["pin_scope"],"target_ref":p["target_ref"]}),
            &["a"],
        );
        let conflict = pins(&[add.clone(), reorder, remove.clone()]).unwrap();
        assert_eq!(conflict["pins"], json!([]));
        assert_eq!(
            conflict["conflicts"][0]["source_event_ids"],
            json!(["b", "r"])
        );
        let invalid = a(
            "bad",
            "ak.pin.reorder",
            json!({"target_ref":p["target_ref"],"rank":"x"}),
            &["a", "r"],
        );
        assert!(pins(&[add, remove, invalid]).is_err());
    }
}
