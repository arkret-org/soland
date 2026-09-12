//! Private Contact completion: fixed results and delivery only after finality.
use arkret_wire::{ActorId, Hash, SealId};
use diesel::sql_types::{BigInt, Integer, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    CommittedContactCompletionIntent, ContactCompletionBinding, ContactCompletionIntent,
    ContactCompletionResult, ContactCompletionState, FederationOutboxRecord, PersistenceError,
    PersistenceResult,
};

use crate::{PgPool, PgTransactionError, pg_conn};
fn invalid(error: impl ToString) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

#[derive(QueryableByName)]
struct CompletionRow {
    #[diesel(sql_type=Text)]
    event_digest: String,
    #[diesel(sql_type=Jsonb)]
    event_json: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    contact_completion_intent: Option<serde_json::Value>,
    #[diesel(sql_type=Jsonb)]
    contact_completion_binding: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    contact_completion_result: Option<serde_json::Value>,
}
#[derive(QueryableByName)]
struct DecisionRow {
    #[diesel(sql_type=Text)]
    seal_id: String,
    #[diesel(sql_type=Text)]
    outcome: String,
    #[diesel(sql_type=Nullable<Text>)]
    reason_code: Option<String>,
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
const COMPLETION_COLUMNS: &str = "c.event_digest,c.event_json,c.contact_completion_intent,c.contact_completion_binding,c.contact_completion_result";

pub(super) async fn lookup(
    pool: &PgPool,
    actor: &ActorId,
    key: &str,
    request_hash: &str,
) -> PersistenceResult<Option<ContactCompletionState>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    let row=sql_query(format!("SELECT {COMPLETION_COLUMNS} FROM state_control_events c WHERE c.contact_completion_binding->'authenticated_actor'=$1 AND c.contact_completion_binding->>'idempotency_key'=$2"))
        .bind::<Jsonb,_>(serde_json::to_value(actor).map_err(invalid)?).bind::<Text,_>(key).get_result::<CompletionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    row.map(|row| {
        let binding: ContactCompletionBinding =
            serde_json::from_value(row.contact_completion_binding).map_err(invalid)?;
        if binding.request_hash != request_hash {
            return Err(PersistenceError::Conflict(
                "Contact commit key was used for different canonical bytes".into(),
            ));
        }
        Ok(ContactCompletionState {
            event: serde_json::from_value(row.event_json).map_err(invalid)?,
            result: row
                .contact_completion_result
                .map(serde_json::from_value)
                .transpose()
                .map_err(invalid)?,
        })
    })
    .transpose()
}

pub(super) async fn confirmed(
    pool: &PgPool,
    limit: u16,
    after: Option<&Hash>,
) -> PersistenceResult<Vec<CommittedContactCompletionIntent>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    let rows=sql_query(format!("SELECT {COMPLETION_COLUMNS} FROM state_control_events c JOIN state_seal_control_events d USING(event_digest,realm_id) WHERE d.outcome='committed' AND NOT c.is_pending AND c.contact_completion_intent IS NOT NULL AND c.contact_completion_result IS NULL AND ($2::text IS NULL OR c.event_digest>$2) ORDER BY c.event_digest LIMIT $1"))
        .bind::<BigInt,_>(i64::from(limit)).bind::<Nullable<Text>,_>(after.map(Hash::as_str)).load::<CompletionRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut ready = Vec::new();
    for row in rows {
        let decision = decision(&mut conn, &row.event_digest).await?;
        ready.push(CommittedContactCompletionIntent {
            event_digest: Hash::new(row.event_digest).map_err(invalid)?,
            deciding_seal_id: SealId::new(decision.seal_id).map_err(invalid)?,
            intent: serde_json::from_value(
                row.contact_completion_intent
                    .ok_or_else(|| invalid("Contact completion intent missing"))?,
            )
            .map_err(invalid)?,
        });
    }
    Ok(ready)
}
async fn decision(conn: &mut AsyncPgConnection, digest: &str) -> PersistenceResult<DecisionRow> {
    sql_query(
        "SELECT seal_id,outcome,reason_code FROM state_seal_control_events WHERE event_digest=$1",
    )
    .bind::<Text, _>(digest)
    .get_result(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("Contact command has no durable decision"))
}

pub(crate) async fn reject_pending(
    conn: &mut AsyncPgConnection,
    digest: &str,
) -> PersistenceResult<()> {
    let row=sql_query(format!("SELECT {COMPLETION_COLUMNS} FROM state_control_events c WHERE c.event_digest=$1 AND c.contact_completion_binding IS NOT NULL FOR UPDATE"))
        .bind::<Text,_>(digest).get_result::<CompletionRow>(conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(());
    };
    let decision = decision(conn, digest).await?;
    if decision.outcome != "rejected" {
        return Err(invalid(
            "Contact rejected completion lacks rejected command result",
        ));
    }
    let reason = decision
        .reason_code
        .ok_or_else(|| invalid("Rejected command reason is absent"))?;
    let problem = arkret_wire::problem_details::Problem::from_code(
        "failed_precondition",
        "Contact command was rejected by its confirmed Seal",
    )
    .with_extension("reason_code", serde_json::Value::String(reason));
    let binding = serde_json::from_value(row.contact_completion_binding).map_err(invalid)?;
    persist_result(
        conn,
        digest,
        &binding,
        &ContactCompletionResult::Rejected { problem },
        None,
    )
    .await?;
    Ok(())
}

pub(super) async fn finalize(
    pool: &PgPool,
    ready: &CommittedContactCompletionIntent,
    result: &ContactCompletionResult,
    delivery: Option<&FederationOutboxRecord>,
) -> PersistenceResult<bool> {
    ready.intent.validate_event_binding()?;
    let ContactCompletionResult::Accepted { outcome } = result else {
        return Err(invalid(
            "Rejected Contact results are fixed inside the Seal transaction",
        ));
    };
    ready.intent.validate_finalized_outcome(outcome)?;
    let expected_carrier = ready.intent.finalized_carrier(outcome)?;
    match (ready.intent.requires_delivery(), delivery) {
        (true, Some(delivery)) => validate_destination(&ready.intent.plan.target, delivery)?,
        (false, None) => {}
        _ => {
            return Err(invalid(
                "Contact completion changed its delivery obligation",
            ));
        }
    }
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        let row=sql_query(format!("SELECT {COMPLETION_COLUMNS} FROM state_control_events c WHERE c.event_digest=$1 FOR UPDATE"))
            .bind::<Text,_>(ready.event_digest.as_str()).get_result::<CompletionRow>(conn).await.map_err(PersistenceError::database)?;
        let decision=decision(conn,ready.event_digest.as_str()).await?;
        if decision.outcome!="committed" || decision.seal_id!=ready.deciding_seal_id.as_str()
            || row.event_json!=serde_json::to_value(&ready.intent.plan.event).map_err(invalid)? { return Err(invalid("Contact completion does not bind the exact committed command").into()); }
        if let Some(existing)=row.contact_completion_result {
            if existing!=serde_json::to_value(result).map_err(invalid)? { return Err(invalid("Contact terminal result cannot be replaced").into()); }
            if let Some(delivery)=delivery { assert_same_outbox(conn,delivery).await?; }
            return Ok(false);
        }
        if row.contact_completion_intent.as_ref()!=Some(&serde_json::to_value(&ready.intent).map_err(invalid)?) { return Err(invalid("Contact completion intent changed").into()); }
        let outbox_id=if let Some(delivery)=delivery {
            let body:arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody=serde_json::from_str(&delivery.payload_json).map_err(invalid)?;
            if serde_json::to_value(&body).map_err(invalid)? != serde_json::to_value(&expected_carrier).map_err(invalid)? {
                return Err(invalid("Contact outbox does not carry its exact finalized result").into());
            }
            let value=serde_json::to_value(&body).map_err(invalid)?;
            if value.get("signed_event")!=Some(&row.event_json) {return Err(invalid("Contact outbox rebinds its committed Event").into());}
            crate::federation::insert_federation_outbox_row(conn,delivery).await?;
            Some(assert_same_outbox(conn,delivery).await?)
        }else{None};
        update_evidence(conn,&ready.intent,outcome).await?;
        persist_result(conn,ready.event_digest.as_str(),&ready.intent.plan.response_binding,result,outbox_id.as_deref()).await?;
        Ok(true)
    }).await.map_err(PgTransactionError::into_persistence)
}

async fn assert_same_outbox(
    conn: &mut AsyncPgConnection,
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<String> {
    let existing=sql_query("SELECT id,endpoint,payload_json FROM federation_outbox WHERE peer_id=$1 AND idempotency_key=$2 FOR UPDATE")
        .bind::<Text,_>(delivery.peer_id.as_str()).bind::<Text,_>(&delivery.idempotency_key).get_result::<ExistingOutbox>(conn).await.map_err(PersistenceError::database)?;
    if existing.endpoint != delivery.endpoint || existing.payload_json != delivery.payload_json {
        return Err(invalid(
            "Contact delivery idempotency key binds different bytes",
        ));
    }
    Ok(existing.id)
}

async fn persist_result(
    conn: &mut AsyncPgConnection,
    digest: &str,
    binding: &ContactCompletionBinding,
    result: &ContactCompletionResult,
    outbox_id: Option<&str>,
) -> PersistenceResult<()> {
    let (status,body)=match result {
        ContactCompletionResult::Accepted {outcome}=>(200,serde_json::to_value(arkret_models_collaboration::contact_operations::ContactOperationOutcome::Accepted{outcome:outcome.clone()}).map_err(invalid)?),
        ContactCompletionResult::Rejected {problem}=>(i32::from(problem.status),serde_json::to_value(problem).map_err(invalid)?),
    };
    let at = chrono::Utc::now();
    let changed=sql_query("INSERT INTO idempotency_keys(actor_key,authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at) VALUES($1,$2,'ak.self.contact.command.commit',$3,$4,$5,$6,$7,$8) ON CONFLICT(actor_key,operation_id,idempotency_key) DO UPDATE SET response_body=idempotency_keys.response_body WHERE idempotency_keys.request_hash=EXCLUDED.request_hash AND idempotency_keys.response_status=EXCLUDED.response_status AND idempotency_keys.response_body=EXCLUDED.response_body")
        .bind::<Text,_>(binding.authenticated_actor.canonical_key().map_err(invalid)?).bind::<Jsonb,_>(serde_json::to_value(&binding.authenticated_actor).map_err(invalid)?)
        .bind::<Text,_>(&binding.idempotency_key).bind::<Text,_>(&binding.request_hash).bind::<Integer,_>(status).bind::<Jsonb,_>(body).bind::<Timestamptz,_>(at).bind::<Timestamptz,_>(at+chrono::Duration::hours(24)).execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "Contact commit idempotency terminal conflict".into(),
        ));
    }
    let changed=sql_query("UPDATE state_control_events SET contact_completion_intent=NULL,contact_completion_result=$2,contact_delivery_outbox_id=$3 WHERE event_digest=$1 AND (contact_completion_result IS NULL OR contact_completion_result=$2)")
        .bind::<Text,_>(digest).bind::<Jsonb,_>(serde_json::to_value(result).map_err(invalid)?).bind::<Nullable<Text>,_>(outbox_id).execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(invalid("Contact terminal result is immutable"));
    }
    Ok(())
}

async fn update_evidence(
    conn: &mut AsyncPgConnection,
    intent: &ContactCompletionIntent,
    outcome: &arkret_models_collaboration::contact_operations::ContactAcceptedOutcome,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::contact_operations::{
        ContactAcceptedOutcome, ContactPeer, ContactRound, ContactRoundEvidenceBundle,
    };
    let peer: ContactPeer = serde_json::from_value(
        intent
            .plan
            .event
            .payload
            .get("peer")
            .cloned()
            .ok_or_else(|| invalid("Contact Event omits peer"))?,
    )
    .map_err(invalid)?;
    let holder = &intent.plan.event.actor_id;
    let peer = peer.contact_actor_id();
    let mut record = if let Some(record) = super::lock_contact(conn, holder, &peer).await? {
        record
    } else if let Some(record) = super::lock_contact(conn, &peer, holder).await? {
        record
    } else {
        return Err(invalid("Committed Contact mirror is absent"));
    };
    let expected = record.updated_at;
    let finalized_proof = match outcome {
        ContactAcceptedOutcome::Response { current_proof, .. }
        | ContactAcceptedOutcome::ScopeUpdate { current_proof, .. }
        | ContactAcceptedOutcome::Tombstone { current_proof, .. } => Some(current_proof),
        _ => None,
    };
    if let Some(proof) = finalized_proof {
        let head = if &record.requester_id == holder {
            record.request_event_ref.as_ref()
        } else {
            record.response_event_ref.as_ref()
        };
        if record.contact_round_id.as_ref() != Some(&proof.contact_round_id)
            || head != Some(&proof.head_event_ref)
        {
            return Err(PersistenceError::Conflict(
                "Contact current head changed before signature publication".into(),
            ));
        }
        let head_decision = decision(conn, proof.head_event_ref.event_digest().as_str()).await?;
        if head_decision.outcome != "committed" {
            return Err(invalid("Contact proof head is not confirmed"));
        }
    }
    let mut mirror = None;
    match outcome {
        ContactAcceptedOutcome::Request {
            request_acceptance_receipt: receipt,
            ..
        } => {
            if let Some(prior) = record
                .request_receipts
                .iter()
                .find(|prior| prior.core.request_event_ref == intent.plan.event.event_id)
            {
                if prior != receipt {
                    return Err(invalid("Contact source receipt is immutable"));
                }
            } else {
                record.request_receipts.push(receipt.clone());
            }
            if let Some(target) = &intent.plan.local_mirror_target {
                mirror = Some(soland_storage::ContactVerifiedMirrorRecord {
                    target_holder_principal_id: target.clone(),
                    request_event_id: intent.plan.event.event_id.to_string(),
                    request_digest: intent.plan.event.event_id.event_digest().to_string(),
                    canonical_event_bytes: arkret_canonical::canonical_json_bytes(
                        &intent.plan.event,
                    )
                    .map_err(invalid)?,
                    source_receipt: receipt.clone(),
                    issuer_id: receipt.core.issuer_id.to_string(),
                    verified_at: chrono::Utc::now(),
                });
            }
        }
        ContactAcceptedOutcome::Response {
            normal_response_acceptance_receipt: receipt,
            current_proof,
            ..
        } => {
            let payload:arkret_models_collaboration::events_payloads::contact::ContactAcceptedPayload=serde_json::from_value(serde_json::to_value(&intent.plan.event.payload).map_err(invalid)?).map_err(invalid)?;
            let mut pair = [
                receipt.request_receipt.core.holder.contact_actor_id(),
                receipt.request_receipt.core.peer.contact_actor_id(),
            ];
            if arkret_canonical::canonical_json_bytes(&pair[0]).map_err(invalid)?
                > arkret_canonical::canonical_json_bytes(&pair[1]).map_err(invalid)?
            {
                pair.swap(0, 1);
            }
            let contact_round = ContactRound::Normal {
                sorted_pair_member_ids: pair,
                request_event_ref: payload.request_event_ref,
                request_acceptance_receipt_digest: payload.request_acceptance_receipt_digest,
            };
            record.contact_round_evidence = Some(ContactRoundEvidenceBundle {
                contact_round_id: receipt.contact_round_id.clone(),
                previous_terminal_contact_round_id: payload.previous_terminal_contact_round_id,
                contact_round,
                request_receipts: vec![receipt.request_receipt.clone()],
                normal_response_receipt: Some(receipt.clone()),
                glare_concurrency_attestations: None,
                current_proofs: vec![current_proof.clone()],
                continuity_checkpoint: None,
            });
        }
        ContactAcceptedOutcome::ScopeUpdate { current_proof, .. }
        | ContactAcceptedOutcome::Tombstone { current_proof, .. } => {
            let bundle = record
                .contact_round_evidence
                .as_mut()
                .ok_or_else(|| invalid("Contact original round evidence has not completed"))?;
            bundle.current_proofs.retain(|proof| {
                proof.peer != current_proof.peer || proof.issuer_id != current_proof.issuer_id
            });
            bundle.current_proofs.push(current_proof.clone());
            bundle
                .current_proofs
                .sort_by_key(|proof| proof.peer.contact_actor_id());
        }
        ContactAcceptedOutcome::Reject { .. } => {}
    }
    record.updated_at = chrono::Utc::now().max(expected + chrono::Duration::microseconds(1));
    crate::unit_of_work::commit_contact_projection(
        conn,
        soland_storage::ContactProjectionCommit {
            completion_intent: None,
            record,
            expected_updated_at: Some(expected),
            conflict_code: "Contact completion evidence CAS conflict".into(),
            verified_mirror: mirror,
            invite_policy: None,
        },
    )
    .await
}

fn validate_destination(
    intent: &soland_storage::ContactDeliveryTarget,
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
    if serde_json::to_value(address).map_err(invalid)?
        != serde_json::to_value(&intent.contact_address).map_err(invalid)?
        || key != &intent.idempotency_key
    {
        return Err(invalid(
            "Contact delivery body does not match its durable intent",
        ));
    }
    Ok(())
}
