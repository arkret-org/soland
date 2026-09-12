//! Contact intent publication is separate from canonical Event admission.
use arkret_wire::{Hash, SealId};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use soland_storage::{
    ConfirmedContactDeliveryIntent, ContactDeliveryIntent, FederationOutboxRecord,
    PersistenceError, PersistenceResult,
};

use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct ReadyRow {
    #[diesel(sql_type=Text)]
    event_digest: String,
    #[diesel(sql_type=Text)]
    seal_id: String,
    #[diesel(sql_type=Jsonb)]
    contact_delivery_intent: serde_json::Value,
}
fn invalid(error: impl ToString) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

pub(super) async fn confirmed(
    pool: &PgPool,
    limit: u16,
) -> PersistenceResult<Vec<ConfirmedContactDeliveryIntent>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    let rows = sql_query("SELECT c.event_digest, d.seal_id, c.contact_delivery_intent FROM state_control_events c JOIN state_seal_control_events d USING (event_digest, realm_id) WHERE d.outcome='committed' AND NOT c.is_pending AND c.contact_delivery_intent IS NOT NULL AND c.contact_delivery_outbox_id IS NULL ORDER BY d.sealed_at, c.event_digest LIMIT $1")
        .bind::<BigInt,_>(i64::from(limit)).load::<ReadyRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    rows.into_iter()
        .map(|row| {
            Ok(ConfirmedContactDeliveryIntent {
                event_digest: Hash::new(row.event_digest).map_err(invalid)?,
                deciding_seal_id: SealId::new(row.seal_id).map_err(invalid)?,
                intent: serde_json::from_value(row.contact_delivery_intent).map_err(invalid)?,
            })
        })
        .collect()
}

#[derive(QueryableByName)]
struct LockedRow {
    #[diesel(sql_type=Nullable<Jsonb>)]
    contact_delivery_intent: Option<serde_json::Value>,
    #[diesel(sql_type=Nullable<Text>)]
    contact_delivery_outbox_id: Option<String>,
    #[diesel(sql_type=Jsonb)]
    event_json: serde_json::Value,
    #[diesel(sql_type=Text)]
    seal_id: String,
    #[diesel(sql_type=Text)]
    outcome: String,
}
#[derive(QueryableByName)]
struct ExistingOutbox {
    #[diesel(sql_type=Text)]
    id: String,
    #[diesel(sql_type=Text)]
    endpoint: String,
    #[diesel(sql_type=Text)]
    payload_json: String,
}

/// Persistence supplies the atomicity/finality fence, not portable evidence
/// verification. The HTTP source-confirmation assembler must finish before
/// invoking this boundary; there is deliberately no worker sending raw intents.
pub(super) async fn finalize(
    pool: &PgPool,
    ready: &ConfirmedContactDeliveryIntent,
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<bool> {
    ready.intent.validate_event_binding()?;
    validate_destination(&ready.intent, delivery)?;
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        let locked = sql_query("SELECT c.contact_delivery_intent, c.contact_delivery_outbox_id, c.event_json, d.seal_id, d.outcome FROM state_control_events c JOIN state_seal_control_events d USING (event_digest, realm_id) WHERE c.event_digest=$1 FOR UPDATE OF c")
            .bind::<Text,_>(ready.event_digest.as_str()).get_result::<LockedRow>(conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| invalid("Contact delivery has no durable command decision"))?;
        if locked.outcome != "committed" || locked.seal_id != ready.deciding_seal_id.as_str()
            || locked.event_json != serde_json::to_value(&ready.intent.event).map_err(invalid)? {
            return Err(invalid("Contact delivery does not bind the exact committed command").into());
        }
        if let Some(intent) = &locked.contact_delivery_intent {
            if intent != &serde_json::to_value(&ready.intent).map_err(invalid)? {
                return Err(invalid("Contact delivery intent changed before materialization").into());
            }
        } else if locked.contact_delivery_outbox_id.is_none() {
            return Err(invalid("Contact delivery intent is absent").into());
        }
        let inserted = if locked.contact_delivery_outbox_id.is_none() {
            crate::federation::insert_federation_outbox_row(conn, delivery).await?
        } else { 0 };
        let existing = sql_query("SELECT id, endpoint, payload_json FROM federation_outbox WHERE peer_id=$1 AND idempotency_key=$2 FOR UPDATE")
            .bind::<Text,_>(delivery.peer_id.as_str()).bind::<Text,_>(&delivery.idempotency_key)
            .get_result::<ExistingOutbox>(conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| invalid("Contact materialized outbox binding is absent"))?;
        if existing.endpoint != delivery.endpoint || existing.payload_json != delivery.payload_json
            || locked.contact_delivery_outbox_id.as_ref().is_some_and(|id| id != &existing.id) {
            return Err(invalid("Contact delivery idempotency key already binds different bytes").into());
        }
        sql_query("UPDATE state_control_events SET contact_delivery_intent=NULL, contact_delivery_outbox_id=$2 WHERE event_digest=$1")
            .bind::<Text,_>(ready.event_digest.as_str()).bind::<Text,_>(&existing.id).execute(conn).await.map_err(PersistenceError::database)?;
        Ok(inserted > 0)
    }).await.map_err(PgTransactionError::into_persistence)
}

fn validate_destination(
    intent: &ContactDeliveryIntent,
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<()> {
    if delivery.endpoint != "/_arkret/peer/contacts"
        || &delivery.peer_id != intent.contact_address.delivery_station_id()
        || delivery.idempotency_key != intent.idempotency_key.as_str()
    {
        return Err(invalid(
            "Contact delivery destination or idempotency binding changed",
        ));
    }
    use arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody;
    let carrier: PeerContactSubmitRequestBody =
        serde_json::from_str(&delivery.payload_json).map_err(invalid)?;
    let (event, address, key, kind) = match &carrier {
        PeerContactSubmitRequestBody::Request {
            signed_event,
            contact_address,
            idempotency_key,
            ..
        } => (
            signed_event,
            contact_address,
            idempotency_key,
            arkret_wire::EventKind::ContactRequested,
        ),
        PeerContactSubmitRequestBody::Response {
            signed_event,
            contact_address,
            idempotency_key,
            ..
        } => (
            signed_event,
            contact_address,
            idempotency_key,
            arkret_wire::EventKind::ContactAccepted,
        ),
        PeerContactSubmitRequestBody::Reject {
            signed_event,
            contact_address,
            idempotency_key,
            ..
        } => (
            signed_event,
            contact_address,
            idempotency_key,
            arkret_wire::EventKind::ContactRejected,
        ),
        PeerContactSubmitRequestBody::ScopeUpdate {
            signed_event,
            contact_address,
            idempotency_key,
            ..
        } => (
            signed_event,
            contact_address,
            idempotency_key,
            arkret_wire::EventKind::ContactScopeUpdate,
        ),
        PeerContactSubmitRequestBody::Tombstone {
            signed_event,
            contact_address,
            idempotency_key,
            ..
        } => (
            signed_event,
            contact_address,
            idempotency_key,
            arkret_wire::EventKind::ContactTombstone,
        ),
        _ => {
            return Err(invalid(
                "Contact Event intent cannot publish a control-only carrier",
            ));
        }
    };
    if event.kind != kind {
        return Err(invalid(
            "Contact delivery branch does not match its Event kind",
        ));
    }
    if serde_json::to_value(event).map_err(invalid)?
        != serde_json::to_value(&intent.event).map_err(invalid)?
        || serde_json::to_value(address).map_err(invalid)?
            != serde_json::to_value(&intent.contact_address).map_err(invalid)?
        || key != &intent.idempotency_key
    {
        return Err(invalid(
            "Contact delivery body does not match its durable intent",
        ));
    }
    Ok(())
}
