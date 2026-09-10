//! Registration initializes identity in the same transaction as the anchor unit.
//! This does not publish a governance frontier or mark unsealed Moves effective.
use arkret_models_collaboration::sync_frames::current_results::{
    CurrentResultEntry, CurrentSelector,
};
use arkret_wire::{CellRef, ScopeRef};
use diesel_async::AsyncPgConnection;
use soland_storage::{CanonicalEventRecord, IdentityAnchorAccountSlot};

use super::*;
#[cfg(test)]
mod tests;

pub(crate) async fn initialize(
    conn: &mut AsyncPgConnection,
    slot: &IdentityAnchorAccountSlot,
    records: &[CanonicalEventRecord],
) -> Result<(), crate::PgTransactionError> {
    let invalid =
        || PersistenceError::SchemaViolation("invalid principal genesis resolution binding".into());
    let record = records
        .iter()
        .find(|r| r.event_id == slot.create_event_id)
        .ok_or_else(invalid)?;
    let event: Event = serde_json::from_value(record.envelope.clone()).map_err(|_| invalid())?;
    if records.len() != 2 || records[0].event_id != slot.create_event_id {
        return Err(invalid().into());
    }
    let authorize: Event =
        serde_json::from_value(records[1].envelope.clone()).map_err(|_| invalid())?;
    if authorize.kind != arkret_wire::EventKind::DeviceAuthorize
        || authorize.realm_id != event.realm_id
        || authorize.actor_id != event.actor_id
        || authorize.prev_refs != [event.event_id.clone()]
        || records[1]
            .envelope
            .pointer("/payload/authorization_binding_kind")
            .and_then(serde_json::Value::as_str)
            != Some("registration_anchor")
    {
        return Err(invalid().into());
    }
    let commitment: arkret_models_identity::ResolutionCommitment = serde_json::from_value(
        record
            .envelope
            .pointer("/payload/object/initial_resolution")
            .cloned()
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let projection = PrincipalResolutionProjection {
        did: commitment.did,
        method_history_head: commitment.method_history_head,
        version_id: commitment.version_id,
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    if event.realm_id.as_str() != slot.realm_id || !current::source_matches(&event, &projection) {
        return Err(invalid().into());
    }
    validate_principal_resolution_record(&PrincipalResolutionRecord {
        account_id: slot.account_id.clone(),
        pcr_realm_id: event.realm_id.clone(),
        genesis_event: event.clone(),
        current_event: event.clone(),
        projection: projection.clone(),
    })?;
    // Only the winning creation inserts. Exact replay never rewinds an index
    // or current result that may already contain an accepted successor.
    let inserted = sql_query("WITH inserted AS (INSERT INTO principal_resolutions (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) VALUES($1,$2,$3,$4,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING principal_id,station_id), history AS (INSERT INTO principal_resolution_events (principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM inserted) SELECT EXISTS(SELECT 1 FROM inserted) AS applied")
        .bind::<Text,_>(slot.account_id.principal_id.as_str())
        .bind::<Text,_>(slot.account_id.station_id.as_str())
        .bind::<Text,_>(&slot.realm_id).bind::<Text,_>(&slot.create_event_id)
        .bind::<Jsonb,_>(serde_json::to_value(&projection).map_err(|_| invalid())?)
        .bind::<Timestamptz,_>(event.created_at).bind::<Text,_>(&projection.method_history_head)
        .bind::<Jsonb,_>(&record.envelope).get_result::<AppliedRow>(conn).await?.applied;
    if !inserted {
        let matching = sql_query("SELECT EXISTS(SELECT 1 FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2 AND pcr_realm_id=$3 AND genesis_event_id=$4) AS applied")
            .bind::<Text,_>(slot.account_id.principal_id.as_str()).bind::<Text,_>(slot.account_id.station_id.as_str())
            .bind::<Text,_>(&slot.realm_id).bind::<Text,_>(&slot.create_event_id).get_result::<AppliedRow>(conn).await?.applied;
        if !matching {
            return Err(invalid().into());
        }
        return Ok(());
    }
    let selector = CurrentSelector {
        scope_ref: ScopeRef::Realm {
            realm_id: event.realm_id,
        },
        cell_id: CellRef::new("ak:cell:ak.component.identity.resolution.v1:null")
            .map_err(|_| invalid())?,
    };
    let revision = crate::current_results::next_revision(conn).await?;
    let entry = CurrentResultEntry::try_from_json(serde_json::json!({
        "selector": selector, "target": {"kind":"realm"}, "revision":revision,
        "result":{"status":"value","value":projection}
    }))
    .map_err(|_| invalid())?;
    crate::current_results::publish_entries(conn, &[entry]).await?;
    Ok(())
}
