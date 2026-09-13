use arkret_models_collaboration::sync_frames::current_results::{
    CurrentResultEntry, CurrentSelector, CurrentTarget, MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES,
    current_family_descriptor,
};
use diesel::OptionalExtension;

use super::*;

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type=Binary)]
    event_id: Vec<u8>,
    #[diesel(sql_type=Jsonb)]
    source_value: Value,
    #[diesel(sql_type=diesel::sql_types::BigInt)]
    causal_depth: i64,
    #[diesel(sql_type=diesel::sql_types::Bool)]
    available: bool,
}

pub(super) async fn materialized_current(
    conn: &mut AsyncPgConnection,
    selector: CurrentSelector,
    revision: u64,
) -> PersistenceResult<CurrentResultEntry> {
    let cell = arkret_wire::CellId::from_ref(&selector.cell_id).map_err(projection_error)?;
    let descriptor = current_family_descriptor(cell.component())
        .map_err(projection_error)?
        .ok_or_else(|| projection_error("current family is not registered"))?;
    let target = match descriptor.target_derivation.as_str() {
        "enclosing_realm" => CurrentTarget::Realm,
        "registered_subject_strand" => CurrentTarget::Strand {
            strand_id: cell.subject().parse().map_err(projection_error)?,
        },
        "registered_position_subject_strand" => CurrentTarget::Strand {
            strand_id: cell.strand_position_target().map_err(projection_error)?,
        },
        "message_create_event_from_registered_subject" => CurrentTarget::Event {
            event_id: cell
                .subject()
                .parse::<arkret_wire::MessageId>()
                .map_err(projection_error)?
                .event_id(),
        },
        _ => {
            return Err(projection_error(
                "Data MV family has an unsupported target derivation",
            ));
        }
    };
    let realm = match &selector.scope_ref {
        arkret_wire::ScopeRef::Realm { realm_id }
        | arkret_wire::ScopeRef::Circle { realm_id, .. } => realm_id,
        _ => {
            return Err(projection_error(
                "Data MV current requires an effective scope",
            ));
        }
    };
    let scope = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&selector.scope_ref).map_err(projection_error)?,
    )
    .map_err(projection_error)?;
    let row=sql_query("SELECT s.event_id,s.source_value,s.causal_depth,(s.available AND EXISTS(SELECT 1 FROM accepted_events e WHERE e.id=s.event_id)) AS available FROM current_data_winners h JOIN current_data_sources s USING(realm_id,scope_key,cell_id,event_id) WHERE h.realm_id=$1 AND h.scope_key=$2 AND h.cell_id=$3")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&scope).bind::<Text,_>(selector.cell_id.as_str())
        .get_result::<HeadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| projection_error("causal-register current winner is missing"))?;
    if !row.available {
        return Err(projection_error(
            "current source was withdrawn; rebuild required",
        ));
    }
    let token: [u8; 33] = row
        .event_id
        .as_slice()
        .try_into()
        .map_err(projection_error)?;
    let event_id = crate::ids::format_event_id(&token);
    let mut value = row.source_value;
    if descriptor.materialized_id_from_subject {
        let object = value
            .as_object_mut()
            .ok_or_else(|| projection_error("materialized object is not an object"))?;
        object.insert("id".into(), Value::String(cell.subject().to_owned()));
    }
    if let Some(object) = value.as_object_mut() {
        for omitted in &descriptor.projection_omitted_fields {
            object.remove(omitted);
        }
    }
    let mut raw = serde_json::json!({"selector":selector,"target":target,"revision":revision,"result":{"status":"value","value":value,"source":{"event_id":event_id,"depth":row.causal_depth}}});
    if arkret_canonical::canonical_json_bytes(&raw)
        .map_err(projection_error)?
        .len()
        > MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES
    {
        raw["result"] = serde_json::json!({"status":"unavailable","reason":"limit_exceeded"});
    }
    CurrentResultEntry::try_from_json(raw).map_err(projection_error)
}
