//! Authenticated identity reads use accepted current cells, not the async cache.
use arkret_models_collaboration::sync_frames::current_results::{
    CurrentOutcome, CurrentResultEntry, CurrentSelector,
};
use arkret_wire::{CellRef, EventId, ScopeRef};
use diesel::sql_types::{Binary, Bool};
use diesel_async::AsyncConnection;
use soland_storage::CurrentPrincipalRead;

use super::*;
#[cfg(test)]
mod tests;

pub(super) fn source_matches(event: &Event, projection: &PrincipalResolutionProjection) -> bool {
    let Ok(payload) = serde_json::to_value(&event.payload) else {
        return false;
    };
    let commitment = if event.kind == arkret_wire::EventKind::RealmCreate {
        if payload
            .pointer("/object/purpose")
            .and_then(serde_json::Value::as_str)
            != Some("principal_control")
        {
            return false;
        }
        payload
            .pointer("/object/initial_resolution")
            .cloned()
            .and_then(|value| {
                serde_json::from_value::<arkret_models_identity::ResolutionCommitment>(value).ok()
            })
    } else {
        serde_json::from_value::<arkret_models_identity::PrincipalResolutionUpdatePayload>(payload)
            .ok()
            .map(|value| value.next)
    };
    commitment.is_some_and(|value| {
        value.did == projection.did
            && value.method_history_head == projection.method_history_head
            && value.version_id == projection.version_id
            && event.created_at == projection.updated_at
            && event.event_id.as_str() == projection.resolution_event_ref
    })
}

#[derive(QueryableByName)]
struct Anchor {
    #[diesel(sql_type=Text)]
    pcr_realm_id: String,
    #[diesel(sql_type=Text)]
    genesis_event_id: String,
}
#[derive(QueryableByName)]
struct Current {
    #[diesel(sql_type=Jsonb)]
    payload: serde_json::Value,
    #[diesel(sql_type=Bool)]
    ready: bool,
}
#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type=Jsonb)]
    envelope: serde_json::Value,
}

async fn accepted(
    conn: &mut diesel_async::AsyncPgConnection,
    id: &EventId,
    realm: &RealmId,
) -> Result<Option<Event>, crate::PgTransactionError> {
    let row = sql_query(
        "SELECT envelope FROM canonical_events WHERE id=$1 AND realm_id=$2 AND state='accepted'",
    )
    .bind::<Binary, _>(id.token_bytes().to_vec())
    .bind::<Text, _>(realm.as_str())
    .get_result::<Source>(conn)
    .await
    .optional()?;
    Ok(row.and_then(|row| serde_json::from_value(row.envelope).ok()))
}

/// Repair only derived current publication under the normal Realm lock. The
/// subsequent read still independently validates the exact source and anchor
/// in one snapshot; repair does not grant authority or return a cached success.
pub(super) async fn refresh(
    pool: &PgPool,
    account: &AccountId,
    registry: &dyn arkret_state::state::CellRegistry,
) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
        let anchor = sql_query("SELECT realm_id AS pcr_realm_id,create_event_id AS genesis_event_id FROM identity_anchor_account_slots WHERE principal_id=$1 AND station_id=$2")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<Anchor>(conn).await.optional()?;
        if let Some(anchor) = anchor {
            crate::state_resolution::refresh_current_if_expired(conn, &anchor.pcr_realm_id, registry).await?;
        }
        Ok(())
    }).await.map_err(crate::PgTransactionError::into_persistence)
}

pub(super) async fn read(
    pool: &PgPool,
    account: &AccountId,
) -> PersistenceResult<CurrentPrincipalRead> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.build_transaction().repeatable_read().read_only().run::<_,crate::PgTransactionError,_>(async |conn| {
        let anchor=sql_query("SELECT realm_id AS pcr_realm_id,create_event_id AS genesis_event_id FROM identity_anchor_account_slots WHERE principal_id=$1 AND station_id=$2")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<Anchor>(conn).await.optional()?;
        let Some(anchor)=anchor else {return Ok(CurrentPrincipalRead::Missing);};
        let (Ok(realm),Ok(genesis_id))=(RealmId::new(anchor.pcr_realm_id),EventId::new(anchor.genesis_event_id)) else {
            return Ok(CurrentPrincipalRead::Unavailable);
        };
        let selector=CurrentSelector {scope_ref:ScopeRef::Realm{realm_id:realm.clone()},
            cell_id:CellRef::new("ak:cell:ak.component.identity.resolution.v1:null".to_owned()).expect("registered identity selector")};
        let key=selector.canonical_key().map_err(|e|PersistenceError::Internal(e.to_string()))?;
        // The atomic human genesis unit has one narrow pre-Seal read branch.
        // Accepted Seal or resolution-successor facts close that branch;
        // derived readiness metadata never opens or closes it.
        let current=sql_query("SELECT h.payload, CASE WHEN EXISTS(SELECT 1 FROM state_seals WHERE realm_id=$1) THEN COALESCE(r.ready AND (r.next_expiry IS NULL OR r.next_expiry>statement_timestamp()),FALSE) ELSE h.payload->'result'->'value'->>'resolution_event_ref'=$3 AND NOT EXISTS(SELECT 1 FROM canonical_events u WHERE u.realm_id=$1 AND u.kind='ak.identity.resolution.update' AND u.state='accepted') AND EXISTS(SELECT 1 FROM identity_anchor_account_slots s JOIN canonical_events a ON a.realm_id=s.realm_id AND a.kind='ak.device.authorize' AND a.state='accepted' WHERE s.realm_id=$1 AND s.create_event_id=$3 AND a.envelope->'prev_refs'=jsonb_build_array($3::text) AND a.envelope->'payload'->>'authorization_binding_kind'='registration_anchor') END AS ready FROM current_result_heads h LEFT JOIN governance_current_ready r USING(realm_id) WHERE h.realm_id=$1 AND h.selector_key=$2")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(key).bind::<Text,_>(genesis_id.as_str()).get_result::<Current>(conn).await.optional()?;
        let Some(current)=current.filter(|row|row.ready) else {return Ok(CurrentPrincipalRead::Unavailable);};
        let Ok(entry)=CurrentResultEntry::try_from_json(current.payload) else {return Ok(CurrentPrincipalRead::Unavailable);};
        if entry.selector()!=&selector {return Ok(CurrentPrincipalRead::Unavailable);}
        let CurrentOutcome::Value{value}=entry.result() else {return Ok(CurrentPrincipalRead::Unavailable);};
        let Ok(projection)=serde_json::from_value::<PrincipalResolutionProjection>(value.as_json().clone()) else {return Ok(CurrentPrincipalRead::Unavailable);};
        let Ok(source_id)=EventId::new(projection.resolution_event_ref.clone()) else {return Ok(CurrentPrincipalRead::Unavailable);};
        let Some(genesis_event)=accepted(conn,&genesis_id,&realm).await? else {return Ok(CurrentPrincipalRead::Unavailable);};
        let Some(current_event)=accepted(conn,&source_id,&realm).await? else {return Ok(CurrentPrincipalRead::Unavailable);};
        let record=PrincipalResolutionRecord{account_id:account.clone(),pcr_realm_id:realm.clone(),genesis_event,current_event,projection:projection.clone()};
        if validate_principal_resolution_record(&record).is_err() || !source_matches(&record.current_event,&projection) {
            return Ok(CurrentPrincipalRead::Unavailable);
        }
        Ok(CurrentPrincipalRead::Ready{pcr_realm_id:realm,projection})
    }).await.map_err(crate::PgTransactionError::into_persistence)
}
