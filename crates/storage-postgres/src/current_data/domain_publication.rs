//! Bounded rebuild of small domain cells; incomplete work remains pending.
use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::sync_frames::current_results::{
    CurrentResultEntry, CurrentSelector, MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES,
};

use super::domain_fold::Assertion;
use super::*;

const MAX_WORK_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORK_NODES: usize = 4096;
#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type=Binary)]
    event_id: Vec<u8>,
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
    #[diesel(sql_type=diesel::sql_types::Bool)]
    available: bool,
}
#[derive(QueryableByName)]
struct Edge {
    #[diesel(sql_type=diesel::sql_types::Nullable<Jsonb>)]
    parents: Option<Value>,
}

pub(super) async fn materialize(
    conn: &mut AsyncPgConnection,
    selector: &CurrentSelector,
    revision: u64,
    target_kind: &str,
    target_key: &str,
    admitted_id: &str,
) -> PersistenceResult<Option<CurrentResultEntry>> {
    let realm = selector
        .scope_ref
        .realm_id_opt()
        .ok_or_else(|| projection_error("domain current needs Realm"))?;
    let scope = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&selector.scope_ref).map_err(projection_error)?,
    )
    .map_err(projection_error)?;
    let mut sources = Vec::new();
    let mut after = Vec::<u8>::new();
    let mut bytes = 0usize;
    loop {
        let row=sql_query("SELECT s.event_id,e.envelope,(s.available AND EXISTS(SELECT 1 FROM accepted_events a WHERE a.id=e.id)) AS available FROM current_data_sources s JOIN canonical_events e ON e.id=s.event_id WHERE s.realm_id=$1 AND s.scope_key=$2 AND s.cell_id=$3 AND s.event_id>$4 ORDER BY s.event_id LIMIT 1")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&scope).bind::<Text,_>(selector.cell_id.as_str()).bind::<Binary,_>(&after)
            .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(row) = row else { break };
        if !row.available {
            return Ok(None);
        }
        bytes += arkret_canonical::canonical_json_bytes(&row.envelope)
            .map_err(projection_error)?
            .len();
        if bytes > MAX_WORK_BYTES || sources.len() >= MAX_WORK_NODES {
            return Ok(None);
        }
        after = row.event_id;
        sources.push(row.envelope);
    }
    // Discover the whole DAG, including intermediates which write other cells.
    // Missing/withdrawn ancestors never become invented concurrency.
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut todo = Vec::new();
    for source in &sources {
        let id = source["event_id"]
            .as_str()
            .ok_or_else(|| projection_error("source identity"))?
            .to_owned();
        let parents = parent_ids(source.get("causal_refs"))?;
        todo.extend(parents.iter().cloned());
        graph.insert(id, parents);
    }
    while let Some(id) = todo.pop() {
        if graph.contains_key(&id) {
            continue;
        }
        if graph.len() >= MAX_WORK_NODES {
            return Ok(None);
        }
        let token = crate::ids::parse_event_id(&id)
            .ok_or_else(|| projection_error("ancestor Event identity"))?;
        let row =
            sql_query("SELECT envelope->'causal_refs' AS parents FROM accepted_events WHERE id=$1")
                .bind::<Binary, _>(token.to_vec())
                .get_result::<Edge>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
        let Some(row) = row else { return Ok(None) };
        bytes += arkret_canonical::canonical_json_bytes(&row.parents)
            .map_err(projection_error)?
            .len();
        if bytes > MAX_WORK_BYTES {
            return Ok(None);
        }
        let parents = parent_ids(row.parents.as_ref())?;
        todo.extend(parents.iter().cloned());
        graph.insert(id, parents);
    }
    let mut assertions = Vec::new();
    for source in sources {
        let id = source["event_id"]
            .as_str()
            .ok_or_else(|| projection_error("source identity"))?
            .to_owned();
        let mut ancestors = BTreeSet::new();
        let mut todo = graph[&id].clone();
        while let Some(parent) = todo.pop() {
            if parent == id {
                return Err(projection_error("cyclic Event ancestry"));
            }
            if ancestors.insert(parent.clone()) {
                todo.extend(graph[&parent].iter().cloned());
            }
        }
        bytes += ancestors.iter().map(String::len).sum::<usize>();
        if bytes > MAX_WORK_BYTES {
            return Ok(None);
        }
        let source_token =
            crate::ids::parse_event_id(&id).ok_or_else(|| projection_error("source identity"))?;
        let ancestor_tokens = ancestors
            .iter()
            .map(|ancestor| {
                crate::ids::parse_event_id(ancestor)
                    .map(|id| id.to_vec())
                    .ok_or_else(|| projection_error("ancestor identity"))
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        sql_query("INSERT INTO current_data_dependencies(source_event_id,ancestor_event_id) SELECT $1,unnest($2::bytea[]) ON CONFLICT DO NOTHING")
            .bind::<Binary,_>(source_token.to_vec()).bind::<Array<Binary>,_>(&ancestor_tokens).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        assertions.push(Assertion {
            id,
            actor: source["actor_id"].clone(),
            kind: source["kind"]
                .as_str()
                .ok_or_else(|| projection_error("source kind"))?
                .to_owned(),
            payload: source["payload"].clone(),
            ancestors,
        });
    }
    let cell = arkret_wire::CellId::from_ref(&selector.cell_id).map_err(projection_error)?;
    // Message existence/redaction is a separate current dependency. Do not
    // expose reactions when that dependency is absent or pending.
    if cell.component() == arkret_wire::CellFamilyId::MESSAGE_REACTIONS_V1 {
        let message = cell
            .subject()
            .parse::<arkret_wire::MessageId>()
            .map_err(projection_error)?;
        let target = message.event_id().token_bytes();
        let exists=sql_query("SELECT envelope->'causal_refs' AS parents FROM accepted_events WHERE id=$1 AND kind='ak.message.create'")
            .bind::<Binary,_>(target.to_vec()).get_result::<Edge>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if exists.is_none() {
            return Ok(None);
        }
        #[derive(QueryableByName)]
        struct Redacted {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            redacted: bool,
        }
        let redacted=sql_query("SELECT EXISTS(SELECT 1 FROM current_data_sources s WHERE realm_id=$1 AND scope_key=$2 AND cell_id=$3) AS redacted")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&scope).bind::<Text,_>(format!("ak:cell:{}:{}", arkret_wire::CellFamilyId::OBJECT_REDACTION_V1,cell.subject()))
            .get_result::<Redacted>(&mut *conn).await.map_err(PersistenceError::database)?;
        if redacted.redacted {
            return Ok(None);
        }
    }
    let value = match cell.component() {
        arkret_wire::CellFamilyId::PIN_V1 => {
            domain_fold::validate_pin_admission(&assertions, admitted_id)?;
            domain_fold::pins(&assertions)?
        }
        arkret_wire::CellFamilyId::MESSAGE_REACTIONS_V1 => domain_fold::reactions(&assertions)?,
        _ => return Ok(None),
    };
    let target = match target_kind {
        "realm" => serde_json::json!({"kind":"realm"}),
        "strand" => serde_json::json!({"kind":"strand","strand_id":target_key}),
        "event" => serde_json::json!({"kind":"event","event_id":target_key}),
        _ => return Err(projection_error("domain target")),
    };
    let mut raw = serde_json::json!({"selector":selector,"target":target,"revision":revision,"result":{"status":"value","value":value}});
    if arkret_canonical::canonical_json_bytes(&raw)
        .map_err(projection_error)?
        .len()
        > MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES
    {
        raw["result"] = serde_json::json!({"status":"unavailable","reason":"limit_exceeded"});
    }
    Ok(Some(
        CurrentResultEntry::try_from_json(raw).map_err(projection_error)?,
    ))
}
fn parent_ids(value: Option<&Value>) -> PersistenceResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| projection_error("causal_refs must be an array"))?
        .iter()
        .map(|digest| {
            let (suite, bytes) = crate::ids::parse_event_digest(
                digest
                    .as_str()
                    .ok_or_else(|| projection_error("causal digest"))?,
            )
            .ok_or_else(|| projection_error("causal digest"))?;
            let mut token = [0u8; 33];
            token[0] = suite;
            token[1..].copy_from_slice(&bytes);
            Ok(crate::ids::format_event_id(&token))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn omitted_causal_refs_is_empty_but_explicit_null_is_invalid() {
        assert!(parent_ids(None).unwrap().is_empty());
        assert!(parent_ids(Some(&serde_json::json!([]))).unwrap().is_empty());
        assert!(parent_ids(Some(&Value::Null)).is_err());
        assert!(parent_ids(Some(&serde_json::json!({}))).is_err());
    }
}
