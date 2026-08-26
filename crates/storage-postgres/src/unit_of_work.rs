use async_trait::async_trait;
use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, SmallInt, Text, Timestamptz, Uuid,
};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    CanonicalEventRecord, EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest,
    EventCommitUnitOfWork, PersistenceError, PersistenceResult, ids, validate_actor_scope_commit,
};

use crate::events::{
    CanonicalEventRow, CanonicalInsertOutcome, insert_canonical_event, realm_actor_lock_key,
};
use crate::governance_history::put_governance_dependency_exact_in_transaction;
use crate::{ExistsRow, PgPool, PgTransactionError, control_seal_schedule, pg_conn};

#[derive(diesel::QueryableByName)]
struct EventPreflightRow {
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    state: String,
}

#[derive(diesel::QueryableByName)]
struct DevicePairingCasRow {
    #[diesel(sql_type = Bool)]
    accepted: bool,
}

#[derive(diesel::QueryableByName)]
struct ContactMirrorCommitRow {
    #[diesel(sql_type = Text)]
    target_holder_id: String,
}

#[derive(diesel::QueryableByName)]
struct AppletNamespaceClaimRow {
    #[diesel(sql_type = Text)]
    domain: String,
    #[diesel(sql_type = Text)]
    pattern: String,
    #[diesel(sql_type = Bool)]
    exclusive: bool,
}

#[derive(Clone)]
pub struct PgEventCommitUnitOfWork {
    pool: PgPool,
}

#[derive(diesel::QueryableByName)]
struct AgentCleanupIntentJsonRow {
    #[diesel(sql_type = Jsonb)]
    record_json: serde_json::Value,
}

async fn stage_agent_membership_cascade(
    conn: &mut AsyncPgConnection,
    transition: Option<&soland_storage::AgentMembershipCascadeCommit>,
    events: &[EventCommitRequest],
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::agent_membership_cascade::{
        AgentCleanupRecord, MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS,
    };
    use soland_storage::AgentMembershipCascadeCommit;

    let Some(transition) = transition else {
        return Ok(());
    };
    let event_ids = events
        .iter()
        .map(|request| request.event.event_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    match transition {
        AgentMembershipCascadeCommit::AtomicSelfLeave {
            controller_transition_event_id,
            agent_transition_event_ids,
            expected_agent_ids,
        } => {
            if agent_transition_event_ids.is_empty()
                || agent_transition_event_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: invalid atomic Agent cleanup cardinality".to_owned(),
                ));
            }
            let mut expected = agent_transition_event_ids
                .iter()
                .map(arkret_wire::EventId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if expected.len() != agent_transition_event_ids.len()
                || !expected.insert(controller_transition_event_id.as_str())
                || expected != event_ids
                || expected_agent_ids.len() != agent_transition_event_ids.len()
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: atomic Agent cascade Event set mismatch".to_owned(),
                ));
            }
            let submitted_agent_ids = events
                .iter()
                .filter(|request| request.event.event_id != controller_transition_event_id.as_str())
                .map(|request| request.event.actor_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let expected_agent_ids = expected_agent_ids
                .iter()
                .map(arkret_wire::DidCoreId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if submitted_agent_ids != expected_agent_ids {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: atomic Agent cascade actor set mismatch".to_owned(),
                ));
            }
        }
        AgentMembershipCascadeCommit::EmergencyTerminal { record } => {
            record.validate().map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: invalid Agent cleanup intent: {error}"
                ))
            })?;
            if event_ids
                != std::collections::BTreeSet::from([record.controller_terminal_event_id.as_str()])
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency terminal Event set mismatch".to_owned(),
                ));
            }
            let terminal = events
                .first()
                .expect("validated singleton terminal Event set");
            let typed =
                serde_json::from_value::<arkret_wire::Event>(terminal.event.envelope.clone())
                    .map_err(|error| {
                        PersistenceError::Conflict(format!(
                            "schema_violation: emergency terminal Event is invalid: {error}"
                        ))
                    })?;
            let initiator = typed.executed_by.as_ref().unwrap_or(&typed.actor_id);
            if terminal.event.actor_id != record.controller_authority.principal_id.as_str()
                || terminal.event.realm_id.as_deref() != Some(record.realm_id.as_str())
                || typed.principal_server_id != record.controller_authority.principal_server_id
                || initiator != &record.initiator_authority.principal_id
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency terminal Event does not bind cleanup intent"
                        .to_owned(),
                ));
            }
            let existing = sql_query(
                "SELECT record_json FROM agent_membership_cleanup_intents \
                 WHERE cleanup_intent_digest = $1 OR controller_terminal_event_id = $2 \
                 FOR UPDATE",
            )
            .bind::<Text, _>(record.cleanup_intent_digest.as_str())
            .bind::<Text, _>(record.controller_terminal_event_id.as_str())
            .get_result::<AgentCleanupIntentJsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                let existing = serde_json::from_value::<AgentCleanupRecord>(existing.record_json)
                    .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Agent cleanup intent is invalid: {error}"
                    ))
                })?;
                if existing != **record {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: cleanup intent digest names different content"
                            .to_owned(),
                    ));
                }
            } else {
                let record_json = serde_json::to_value(record).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "Agent cleanup intent encoding failed: {error}"
                    ))
                })?;
                sql_query(
                    "INSERT INTO agent_membership_cleanup_intents \
                     (cleanup_intent_digest, realm_id, controller_terminal_event_id, \
                      record_json, accepted_at, cleanup_due_at, completed_at, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, NULL, $5, $5)",
                )
                .bind::<Text, _>(record.cleanup_intent_digest.as_str())
                .bind::<Text, _>(record.realm_id.as_str())
                .bind::<Text, _>(record.controller_terminal_event_id.as_str())
                .bind::<Jsonb, _>(record_json)
                .bind::<Timestamptz, _>(record.accepted_at)
                .bind::<Timestamptz, _>(record.cleanup_due_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
        }
        AgentMembershipCascadeCommit::EmergencyCleanup {
            cleanup_intent_digest,
            controller_terminal_event_id,
            agent_transition_event_ids,
            completed_at,
        } => {
            let existing = sql_query(
                "SELECT record_json FROM agent_membership_cleanup_intents \
                 WHERE cleanup_intent_digest = $1 FOR UPDATE",
            )
            .bind::<Text, _>(cleanup_intent_digest.as_str())
            .get_result::<AgentCleanupIntentJsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "failed_precondition: Agent cleanup intent is unavailable".to_owned(),
                )
            })?;
            let mut record = serde_json::from_value::<AgentCleanupRecord>(existing.record_json)
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Agent cleanup intent is invalid: {error}"
                    ))
                })?;
            let submitted_event_ids = agent_transition_event_ids
                .iter()
                .map(arkret_wire::EventId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            let actor_ids = events
                .iter()
                .map(|request| request.event.actor_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let expected_actor_ids = record
                .expected_agent_ids
                .iter()
                .map(arkret_wire::DidCoreId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if record.controller_terminal_event_id != *controller_terminal_event_id
                || event_ids != submitted_event_ids
                || agent_transition_event_ids.len() != record.expected_agent_ids.len()
                || actor_ids != expected_actor_ids
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: emergency Agent cleanup does not match frozen intent"
                        .to_owned(),
                ));
            }
            if record.completed_at.is_some() {
                if record.agent_transition_event_ids.as_ref() != Some(agent_transition_event_ids) {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: completed Agent cleanup replay differs".to_owned(),
                    ));
                }
                return Ok(());
            }
            record.completed_at = Some(*completed_at);
            record.agent_transition_event_ids = Some(agent_transition_event_ids.clone());
            record.validate().map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: completed Agent cleanup is invalid: {error}"
                ))
            })?;
            let record_json = serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!(
                    "completed Agent cleanup encoding failed: {error}"
                ))
            })?;
            sql_query(
                "UPDATE agent_membership_cleanup_intents SET \
                     record_json = $2, completed_at = $3, \
                     updated_at = $3 WHERE cleanup_intent_digest = $1",
            )
            .bind::<Text, _>(cleanup_intent_digest.as_str())
            .bind::<Jsonb, _>(record_json)
            .bind::<Timestamptz, _>(*completed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
    }
    Ok(())
}

enum CommitTransactionOutcome {
    Committed(EventCommitOutcome),
    Collision,
}

impl PgEventCommitUnitOfWork {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn contact_event_ref(value: Option<&str>) -> PersistenceResult<Option<Vec<u8>>> {
    value
        .map(|value| {
            ids::event_token_part_or_schema_violation(value, "event").map(|token| token.to_vec())
        })
        .transpose()
}

/// Commit one accepted consent Control Move's holder-private effects.
///
/// The or_set cell row and the eager invite-quarantine invalidation
/// (`consent-model.md` section 4.1.2) run inside the Event transaction, so a
/// failure here rolls the canonical Event back with them. The intent guard
/// repeats admission's `(holder, consent_id)` binding check inside the
/// transaction: a concurrent grant cannot rebind the same consent_id between
/// admission and commit.
async fn commit_consent_projection(
    conn: &mut diesel_async::AsyncPgConnection,
    commit: soland_storage::ConsentProjectionCommit,
) -> PersistenceResult<()> {
    let cell = commit.cell;
    let grant_dots = soland_storage::encode_grant_dots(&cell.grant_dots);
    let revoked_dots = serde_json::Value::Array(
        cell.revoked_dots
            .iter()
            .map(|dot| serde_json::Value::String(dot.clone()))
            .collect(),
    );
    let affected = sql_query(
        "INSERT INTO consent_cells          (id, cell_id, holder_id, peer_id, consent_scope, grant_dots, revoked_dots, updated_at)          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)          ON CONFLICT (holder_id, cell_id) DO UPDATE SET             grant_dots = EXCLUDED.grant_dots,             revoked_dots = EXCLUDED.revoked_dots,             updated_at = EXCLUDED.updated_at          WHERE consent_cells.peer_id = EXCLUDED.peer_id            AND consent_cells.consent_scope = EXCLUDED.consent_scope",
    )
    .bind::<Uuid, _>(uuid::Uuid::now_v7())
    .bind::<Text, _>(&cell.cell_id)
    .bind::<Text, _>(&cell.holder)
    .bind::<Text, _>(&cell.peer)
    .bind::<Text, _>(&cell.consent_scope)
    .bind::<Jsonb, _>(&grant_dots)
    .bind::<Jsonb, _>(&revoked_dots)
    .bind::<Timestamptz, _>(cell.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if affected == 0 {
        return Err(PersistenceError::Conflict(
            "consent_intent_rebind".to_owned(),
        ));
    }
    let Some(cas) = commit.invite_quarantine else {
        return Ok(());
    };
    let record = cas.record;
    let affected = if cas.expected_revision == 0 {
        sql_query(
            "INSERT INTO account_datas              (id, actor_id, account_data_key, payload, revision, tombstone, updated_at)              VALUES ($1, $2, $3, $4, $5, $6, $7)              ON CONFLICT (actor_id, account_data_key) DO NOTHING",
        )
        .bind::<Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.account_data_key)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<BigInt, _>(record.revision as i64)
        .bind::<Bool, _>(record.tombstone)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?
    } else {
        sql_query(
            "UPDATE account_datas SET payload = $1, revision = $2, tombstone = $3,                 updated_at = $4              WHERE actor_id = $5 AND account_data_key = $6 AND revision = $7",
        )
        .bind::<Jsonb, _>(&record.payload)
        .bind::<BigInt, _>(record.revision as i64)
        .bind::<Bool, _>(record.tombstone)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.account_data_key)
        .bind::<BigInt, _>(cas.expected_revision as i64)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?
    };
    if affected == 0 {
        return Err(PersistenceError::Conflict(cas.conflict_code));
    }
    Ok(())
}

async fn commit_contact_projection(
    conn: &mut diesel_async::AsyncPgConnection,
    commit: soland_storage::ContactProjectionCommit,
) -> PersistenceResult<()> {
    let conflict_code = commit.conflict_code;
    let invite_policy = commit.invite_policy;
    let verified_mirror = commit.verified_mirror;
    let record = commit.record;
    let request_receipts = serde_json::to_value(&record.request_receipts).map_err(|error| {
        PersistenceError::Internal(format!("cannot encode Contact request receipts: {error}"))
    })?;
    let request_mirror_receipts =
        serde_json::to_value(&record.request_mirror_receipts).map_err(|error| {
            PersistenceError::Internal(format!("cannot encode Contact mirror receipts: {error}"))
        })?;
    let contact_round_evidence = record
        .contact_round_evidence
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| {
            PersistenceError::Internal(format!("cannot encode Contact round evidence: {error}"))
        })?;
    let contact_round_evidence_history =
        serde_json::to_value(&record.contact_round_evidence_history).map_err(|error| {
            PersistenceError::Internal(format!(
                "cannot encode Contact round evidence history: {error}"
            ))
        })?;
    let control_outcomes = serde_json::to_value(&record.control_outcomes).map_err(|error| {
        PersistenceError::Internal(format!("cannot encode Contact control outcomes: {error}"))
    })?;
    let version = record.version.map(i64::try_from).transpose().map_err(|_| {
        PersistenceError::Internal("Contact version exceeds PostgreSQL BIGINT".to_owned())
    })?;
    let request_event_ref = contact_event_ref(record.request_event_ref.as_deref())?;
    let response_event_ref = contact_event_ref(record.response_event_ref.as_deref())?;
    let tombstone_event_ref = contact_event_ref(record.tombstone_event_ref.as_deref())?;

    let affected = if let Some(expected_updated_at) = commit.expected_updated_at {
        if record.updated_at <= expected_updated_at {
            return Err(PersistenceError::Conflict(conflict_code));
        }
        sql_query(
            "UPDATE contacts SET requester_id = $1, target_id = $2, \
                contact_round_id = $3, version = $4, granted_to_target_scopes = $5, \
                granted_to_requester_scopes = $6, status = $7, request_event_ref = $8, \
                request_receipts = $9, request_mirror_receipts = $10, contact_round_evidence = $11, \
                contact_round_evidence_history = $12, control_outcomes = $13, response_event_ref = $14, \
                tombstone_event_ref = $15, message = $16, peer_service_id = $17, updated_at = $18 \
             WHERE ((requester_id = $1 AND target_id = $2) OR \
                    (requester_id = $2 AND target_id = $1)) AND updated_at = $19",
        )
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_deref())
        .bind::<Nullable<BigInt>, _>(version)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Binary>, _>(request_event_ref)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(response_event_ref)
        .bind::<Nullable<Binary>, _>(tombstone_event_ref)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_id.as_deref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(expected_updated_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?
    } else {
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, contact_round_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, request_event_ref, request_receipts, request_mirror_receipts, contact_round_evidence, contact_round_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_service_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) \
             ON CONFLICT (requester_id, target_id) DO NOTHING",
        )
        .bind::<Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_deref())
        .bind::<Nullable<BigInt>, _>(version)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Binary>, _>(request_event_ref)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(response_event_ref)
        .bind::<Nullable<Binary>, _>(tombstone_event_ref)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_id.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?
    };
    if affected != 1 {
        return Err(PersistenceError::Conflict(conflict_code));
    }
    if let Some(mirror) = verified_mirror {
        let source_receipt = serde_json::to_value(&mirror.source_receipt).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Contact request receipt encode failed: {error}"
            ))
        })?;
        let committed = sql_query(
            "INSERT INTO contact_verified_mirrors \
             (target_holder_id, request_event_id, request_digest, canonical_event_bytes, source_receipt, issuer_service_id, verified_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (target_holder_id, request_event_id) DO UPDATE \
             SET verified_at = contact_verified_mirrors.verified_at \
             WHERE contact_verified_mirrors.request_digest = EXCLUDED.request_digest \
               AND contact_verified_mirrors.canonical_event_bytes = EXCLUDED.canonical_event_bytes \
               AND contact_verified_mirrors.source_receipt = EXCLUDED.source_receipt \
               AND contact_verified_mirrors.issuer_service_id = EXCLUDED.issuer_service_id \
             RETURNING target_holder_id",
        )
        .bind::<Text, _>(&mirror.target_holder_id)
        .bind::<Text, _>(&mirror.request_event_id)
        .bind::<Text, _>(&mirror.request_digest)
        .bind::<Binary, _>(&mirror.canonical_event_bytes)
        .bind::<Jsonb, _>(&source_receipt)
        .bind::<Text, _>(&mirror.issuer_service_id)
        .bind::<Timestamptz, _>(mirror.verified_at)
        .get_result::<ContactMirrorCommitRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if committed
            .as_ref()
            .is_none_or(|row| row.target_holder_id != mirror.target_holder_id)
        {
            return Err(PersistenceError::Conflict(
                "contact_verified_mirror_conflict".to_owned(),
            ));
        }
    }
    if let Some(policy) = invite_policy {
        let subject_id = policy.subject_id.as_str().to_owned();
        let payload = serde_json::to_value(&policy).map_err(|error| {
            PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
        })?;
        let denied_subjects = policy
            .denied_subjects
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect::<Vec<_>>();
        sql_query(
            "INSERT INTO invite_receive_policies \
             (subject_id, policy_payload, denied_subjects, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (subject_id) DO UPDATE SET \
                policy_payload = EXCLUDED.policy_payload, \
                denied_subjects = EXCLUDED.denied_subjects, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&subject_id)
        .bind::<Jsonb, _>(&payload)
        .bind::<Array<Text>, _>(&denied_subjects)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}

#[async_trait]
impl EventCommitUnitOfWork for PgEventCommitUnitOfWork {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.commit_event_batch(EventBatchCommitRequest {
            events: vec![request],
            applet_record: None,
            agent_membership_cascade: None,
        })
        .await
    }

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        if request.events.is_empty() {
            return Err(PersistenceError::Conflict(
                "schema_violation: empty event batch".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let transaction_outcome = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Inspect the whole batch before inserting any of its ordinary
            // rows. A collision in item N may commit quarantine evidence for
            // that identity, but must never commit items 0..N-1 as a prefix.
            let mut ordered = request.events.iter().collect::<Vec<_>>();
            ordered.sort_by(|left, right| left.event.event_id.cmp(&right.event.event_id));
            for item in &ordered {
                let identity = ids::validated_event_identity_parts_for_suite(
                    &item.event.event_id,
                    &item.event.canonical_digest,
                    &item.event.canonical_bytes,
                    item.event.digest_suite,
                )?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
                    .bind::<Binary, _>(identity.id.to_vec())
                    .execute(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
            }
            let mut incoming = std::collections::BTreeMap::<
                String,
                &CanonicalEventRecord,
            >::new();
            for item in &ordered {
                let identity = ids::validated_event_identity_parts_for_suite(
                    &item.event.event_id,
                    &item.event.canonical_digest,
                    &item.event.canonical_bytes,
                    item.event.digest_suite,
                )?;
                let stored = sql_query(
                    "SELECT canonical_bytes, state FROM canonical_events WHERE id = $1",
                )
                .bind::<Binary, _>(identity.id.to_vec())
                .get_result::<EventPreflightRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                if let Some(stored) = stored {
                    if stored.canonical_bytes != item.event.canonical_bytes {
                        let outcome = insert_canonical_event(conn, &item.event).await?;
                        debug_assert_eq!(outcome, CanonicalInsertOutcome::Collision);
                        return Ok(CommitTransactionOutcome::Collision);
                    }
                    if stored.state == "quarantined" {
                        return Ok(CommitTransactionOutcome::Collision);
                    }
                    continue;
                }
                if let Some(previous) = incoming.get(&item.event.event_id) {
                    if previous.canonical_bytes != item.event.canonical_bytes {
                        let inserted = insert_canonical_event(conn, previous).await?;
                        debug_assert!(matches!(inserted, CanonicalInsertOutcome::Inserted(_)));
                        let collision = insert_canonical_event(conn, &item.event).await?;
                        debug_assert_eq!(collision, CanonicalInsertOutcome::Collision);
                        return Ok(CommitTransactionOutcome::Collision);
                    }
                } else {
                    incoming.insert(item.event.event_id.clone(), &item.event);
                }
            }
            // Identity collision evidence takes precedence over parsing or
            // admitting the incoming envelope. Only collision-free bytes may
            // name Realms whose quarantine gates are then locked and checked.
            let mut admission_realms = std::collections::BTreeSet::new();
            for item in &ordered {
                let event = serde_json::from_value::<arkret_wire::Event>(
                    item.event.envelope.clone(),
                )
                .map_err(|error| {
                    PersistenceError::Conflict(format!(
                        "schema_violation: accepted Event envelope is not canonical wire: {error}"
                    ))
                })?;
                admission_realms.insert(event.realm_id.as_str().to_owned());
            }
            for realm_id in admission_realms {
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind::<Text, _>(&realm_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
                let quarantined = sql_query(
                    "SELECT EXISTS (SELECT 1 FROM state_seal_quarantine_realms \
                     WHERE realm_id = $1) AS present",
                )
                .bind::<Text, _>(&realm_id)
                .get_result::<ExistsRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                if quarantined.present {
                    return Err(PersistenceError::Conflict(format!(
                        "seal_collision_quarantine: Realm {realm_id} is blocked"
                    ))
                    .into());
                }
            }
            let mut event_inserted = false;
            let mut projections_inserted = 0;
            let mut outbox_inserted = 0;
            stage_agent_membership_cascade(
                conn,
                request.agent_membership_cascade.as_ref(),
                &request.events,
            )
            .await?;
            for request in request.events {
            if let Some(commit) = request.device_pairing_authorization.as_ref() {
                if commit.authorized_event_ref != request.event.event_id {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: device pairing authorization does not bind committed Event"
                            .to_owned(),
                    )
                    .into());
                }
                let new_device_pubkey =
                    serde_json::to_value(&commit.new_device_pubkey).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "cannot encode device pairing authorization public key: {error}"
                        ))
                    })?;
                // Lock, compare, and consume the short-link inside this Event
                // transaction. Every CAS miss, including an exact response-
                // loss replay of an already-authorized row, aborts all Event/
                // projection/receipt/outbox writes; the caller reconciles via
                // the registered pairing-status query.
                let cas = sql_query(
                    "WITH candidate AS ( \
                         SELECT state, pairing_code, new_device_pubkey, device_id, \
                                authorized_by_actor_id, authorized_event_ref, expires_at \
                         FROM device_pairings WHERE device_pairing_request_id = $1 FOR UPDATE \
                     ), updated AS ( \
                         UPDATE device_pairings AS pairing SET \
                             state = 'authorized', device_id = $4, \
                             authorized_by_actor_id = $5, authorized_event_ref = $6 \
                         FROM candidate \
                         WHERE pairing.device_pairing_request_id = $1 \
                           AND candidate.pairing_code = $2 \
                           AND candidate.new_device_pubkey = $3 \
                           AND candidate.state = 'pending_authorization' \
                           AND candidate.expires_at > $7 \
                         RETURNING 1 \
                     ) \
                     SELECT EXISTS(SELECT 1 FROM updated) AS accepted",
                )
                .bind::<Text, _>(&commit.device_pairing_request_id)
                .bind::<Text, _>(&commit.pairing_code)
                .bind::<Jsonb, _>(&new_device_pubkey)
                .bind::<Text, _>(&commit.device_id)
                .bind::<Text, _>(&commit.authorized_by_actor_id)
                .bind::<Text, _>(&commit.authorized_event_ref)
                .bind::<Timestamptz, _>(commit.changed_at)
                .get_result::<DevicePairingCasRow>(conn)
                .await
                .map_err(PersistenceError::database)?;
                if !cas.accepted {
                    return Err(PersistenceError::Conflict(
                        "device_pairing_not_found".to_owned(),
                    )
                    .into());
                }
            }
            let identity = ids::validated_event_identity_parts_for_suite(
                &request.event.event_id,
                &request.event.canonical_digest,
                &request.event.canonical_bytes,
                request.event.digest_suite,
            )?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
                .bind::<Binary, _>(identity.id.to_vec())
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            let identity_matches = sql_query(
                "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
                 FROM canonical_events WHERE id = $1",
            )
            .bind::<Binary, _>(identity.id.to_vec())
            .load::<CanonicalEventRow>(conn)
            .await
            .map_err(PersistenceError::database)?;
            if identity_matches.iter().any(|existing| {
                existing.digest_suite != i16::from(identity.digest_suite)
                    || existing.digest.as_slice() != identity.digest
            }) {
                return Err(PersistenceError::Conflict(
                    "event_id_digest_mismatch".to_owned(),
                )
                .into());
            }
            if !identity_matches.is_empty() {
                let outcome = insert_canonical_event(conn, &request.event).await?;
                if matches!(
                    outcome,
                    CanonicalInsertOutcome::Collision | CanonicalInsertOutcome::Quarantined
                ) {
                    return Ok(CommitTransactionOutcome::Collision);
                }
                continue;
            }
            if let Some(selector) = request.device_revocation_gate.as_ref() {
                crate::ensure_gate_allowed_in_transaction(conn, selector).await?;
            }
            let realm_id_value = request.event.realm_id.as_deref().ok_or_else(|| {
                PersistenceError::Conflict("schema_violation: missing realm_id".to_owned())
            })?;
            let realm_pk =
                crate::realm_identity::ensure_realm_pk(conn, realm_id_value).await?;
            let scope_lock = realm_actor_lock_key(realm_id_value, &request.event.actor_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&scope_lock)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            let scoped = sql_query(
                "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
                 FROM canonical_events WHERE state = 'accepted' AND realm_pk = $1 AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
            )
            .bind::<BigInt, _>(realm_pk)
            .bind::<Text, _>(&request.event.actor_id)
            .load::<CanonicalEventRow>(conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(CanonicalEventRecord::from)
            .collect::<Vec<_>>();
            validate_actor_scope_commit(scoped.iter(), &request.event)?;
            let event_pk = sql_query(
                "INSERT INTO canonical_events \
                 (id, digest_suite, digest, actor_id, actor_seq, realm_id, realm_pk, kind, schema_id, canonical_bytes, envelope, received_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING pk",
            )
            .bind::<Binary, _>(identity.id.to_vec())
            .bind::<SmallInt, _>(i16::from(identity.digest_suite))
            .bind::<Binary, _>(identity.digest.to_vec())
            .bind::<Text, _>(&request.event.actor_id)
            .bind::<BigInt, _>(request.event.actor_seq as i64)
            .bind::<Nullable<Text>, _>(request.event.realm_id.as_deref())
            .bind::<BigInt, _>(realm_pk)
            .bind::<Text, _>(&request.event.kind)
            .bind::<Text, _>(&request.event.schema_id)
            .bind::<Binary, _>(&request.event.canonical_bytes)
            .bind::<Jsonb, _>(&request.event.envelope)
            .bind::<Timestamptz, _>(request.event.received_at)
            .get_result::<EventPkRow>(conn)
            .await
            .map_err(PersistenceError::database)?
            .pk;
            event_inserted = true;

            let typed_event = serde_json::from_value::<arkret_wire::Event>(
                request.event.envelope.clone(),
            )
            .map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: accepted Event envelope is not canonical wire: {error}"
                ))
            })?;
            if let Some(contact_projection) = request.contact_projection {
                commit_contact_projection(conn, contact_projection).await?;
            }
            if let Some(consent_projection) = request.consent_projection {
                commit_consent_projection(conn, consent_projection).await?;
            }
            // Control/Data routing is defined by the typed Event plane. A
            // closed genesis anchor is a basis-free Control Move; a DataEvent
            // instead carries `seal_ref` plus `auth_context`.
            let is_control_move = typed_event.kind.is_control_plane();
            if is_control_move {
                let event_digest = typed_event
                    .event_digest_with_digest_suite(request.event.digest_suite)
                    .map_err(|error| {
                    PersistenceError::Conflict(format!(
                        "schema_violation: accepted Control Move digest failed: {error}"
                    ))
                })?;
                if event_digest != request.event.canonical_digest {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: canonical digest differs from Control Move digest"
                            .to_owned(),
                    )
                    .into());
                }
                let ingress = request.control_proposal_ingress.as_ref().ok_or_else(|| {
                    PersistenceError::Conflict(
                        "schema_violation: accepted Control Move is missing its durable ingress classification"
                            .to_owned(),
                    )
                })?;
                let control_proposal_ack = match ingress {
                    arkret_state::state::store::ControlProposalIngress::AcklessSelfPrincipal(
                        _,
                    ) => {
                        if typed_event.kind == arkret_wire::EventKind::DeviceRevoke
                            || !soland_storage::has_self_principal_pcr_device_authorized_shape(
                                &typed_event,
                                request.event.digest_suite,
                            )
                        {
                            return Err(PersistenceError::Conflict(
                                "schema_violation: invalid self-principal PCR device-authorized Control Move"
                                    .to_owned(),
                            )
                            .into());
                        }
                        None
                    }
                    arkret_state::state::store::ControlProposalIngress::AckRequired(ack) => {
                        Some({
                            if ack.proposal_digest.as_str() != event_digest
                                || ack.realm_id != typed_event.realm_id
                            {
                                return Err(PersistenceError::Conflict(
                                    "schema_violation: Control Proposal Ack does not bind Control Move"
                                        .to_owned(),
                                )
                                .into());
                            }
                            serde_json::to_value(ack).map_err(|error| {
                                PersistenceError::Internal(format!(
                                    "Control Proposal Ack encoding failed: {error}"
                                ))
                            })?
                        })
                    }
                };
                let ingress_class = serde_json::to_value(ingress.class()).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "Control Move ingress class encoding failed: {error}"
                    ))
                })?;
                sql_query(
                    "INSERT INTO state_control_events \
                     (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (event_digest) DO UPDATE SET \
                       control_proposal_ack = COALESCE( \
                         state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
                       ) \
                     WHERE state_control_events.realm_id = EXCLUDED.realm_id \
                       AND state_control_events.digest_suite = EXCLUDED.digest_suite \
                       AND state_control_events.event_json = EXCLUDED.event_json \
                       AND state_control_events.ingress_class = EXCLUDED.ingress_class \
                       AND (state_control_events.control_proposal_ack IS NULL \
                         OR EXCLUDED.control_proposal_ack IS NULL \
                         OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
                )
                .bind::<Text, _>(&event_digest)
                .bind::<Text, _>(request.event.digest_suite.as_str())
                .bind::<Text, _>(typed_event.realm_id.as_str())
                .bind::<Jsonb, _>(&request.event.envelope)
                .bind::<Nullable<Jsonb>, _>(control_proposal_ack.as_ref())
                .bind::<Jsonb, _>(&ingress_class)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)
                .and_then(|affected| {
                    if affected == 0 {
                        Err(PersistenceError::Conflict(
                            "duplicate_conflict: pending Control Move has different canonical bytes, ingress class or Control Proposal Ack"
                                .to_owned(),
                        ))
                    } else {
                        Ok(())
                    }
                })?;
                control_seal_schedule::upsert_for_control_event(
                    conn,
                    typed_event.realm_id.as_str(),
                )
                .await
                .map_err(PersistenceError::database)?;
                for dependency in &request.governance_dependencies {
                    let source_matches = matches!(
                        &dependency.source,
                        soland_storage::GovernanceDependencySource::ControlEvent(digest)
                            if digest.as_str() == event_digest
                    );
                    if dependency.realm_id != typed_event.realm_id || !source_matches
                    {
                        return Err(PersistenceError::Conflict(
                            "schema_violation: governance dependency does not bind committed Control Move"
                                .to_owned(),
                        )
                        .into());
                    }
                    put_governance_dependency_exact_in_transaction(conn, dependency).await?;
                }
                if typed_event.kind == arkret_wire::EventKind::DeviceRevoke {
                    let transition = request.device_revocation_transition.as_ref().ok_or_else(|| {
                        PersistenceError::Conflict(
                            "schema_violation: accepted device revoke is missing derived transition"
                                .to_owned(),
                        )
                    })?;
                    if transition.proposal_event_id != request.event.event_id
                        || transition.proposal_digest != request.event.canonical_digest
                        || request
                            .control_proposal_ingress
                            .as_ref()
                            .and_then(arkret_state::state::store::ControlProposalIngress::ack)
                            != Some(&transition.control_proposal_ack)
                    {
                        return Err(PersistenceError::Conflict(
                            "schema_violation: device revocation transition does not bind Event and Ack"
                                .to_owned(),
                        )
                        .into());
                    }
                    crate::insert_transition_in_transaction(conn, transition, chrono::Utc::now())
                        .await?;
                } else if request.device_revocation_transition.is_some() {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: non-revoke Event carries device revocation transition"
                            .to_owned(),
                    )
                    .into());
                }
            } else if request.control_proposal_ingress.is_some()
                || request.device_revocation_transition.is_some()
                || !request.governance_dependencies.is_empty()
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: non-Control Event cannot carry Control Proposal authority"
                        .to_owned(),
                )
                .into());
            }

            for projection in request.projections {
                // The projection no longer carries its own copy of the Event
                // identity -- it is reached through `event_pk`. Admitting a
                // projection that names a different Event than the one this
                // unit committed would silently attach it to the wrong row, so
                // the mismatch is rejected here instead of being dropped.
                if projection.event_id != request.event.event_id {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: projection Event id does not match canonical Event"
                            .to_owned(),
                    )
                    .into());
                }
                let operation_id = projection
                    .operation_id
                    .as_deref()
                    .map(ids::typed_uuid_part_or_schema_violation)
                    .transpose()?;
                let projection_realm_pk =
                    crate::realm_identity::ensure_realm_pk(conn, &projection.realm_id).await?;
                if projection_realm_pk != realm_pk {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: projection Realm does not match canonical Event Realm"
                            .to_owned(),
                    )
                    .into());
                }
                projections_inserted += sql_query(
                    "INSERT INTO projection_events \
                     (event_pk, realm_pk, realm_id, event_kind, operation_kind, operation_id, sender_id, payload, created_at, received_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                     ON CONFLICT (event_pk) DO NOTHING",
                )
                .bind::<BigInt, _>(event_pk)
                .bind::<BigInt, _>(projection_realm_pk)
                .bind::<Text, _>(&projection.realm_id)
                .bind::<Text, _>(&projection.event_kind)
                .bind::<Text, _>(&projection.operation_kind)
                .bind::<Nullable<Uuid>, _>(operation_id)
                .bind::<Nullable<Text>, _>(&projection.sender)
                .bind::<Jsonb, _>(&projection.payload)
                .bind::<Timestamptz, _>(projection.created_at)
                .bind::<Timestamptz, _>(projection.received_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            }

            if let Some(record) = request.idempotency {
                let inserted = sql_query(
                    "INSERT INTO idempotency_keys \
                     (principal_id, idempotency_key, service_id, request_hash, response_status, \
                      response_body, created_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (principal_id, idempotency_key) DO NOTHING",
                )
                .bind::<Text, _>(&record.principal_id)
                .bind::<Text, _>(&record.idempotency_key)
                .bind::<Text, _>(&record.service_id)
                .bind::<Text, _>(&record.request_hash)
                .bind::<Integer, _>(record.response_status)
                .bind::<Jsonb, _>(&record.response_body)
                .bind::<Timestamptz, _>(record.created_at)
                .bind::<Timestamptz, _>(record.expires_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if inserted != 1 {
                    return Err(
                        PersistenceError::Conflict("duplicate_conflict".to_owned()).into(),
                    );
                }
            }

            for record in request.outbox {
                record.validate_shape().map_err(|error| {
                    PersistenceError::Conflict(format!("schema_violation: {error}"))
                })?;
                let inserted = sql_query(
                    "INSERT INTO federation_outbox \
                     (id, peer_id, peer_url, endpoint, idempotency_key, payload_json, state, \
                     leased_from_state, realm_fanout, attempts, semantic_attempts, next_attempt_at, last_http_status, \
                     last_error_code, last_response_excerpt, lease_owner, lease_token, \
                     lease_expires_at, policy_version, supersedes_outbox_id, created_at, \
                      completed_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                      $16, $17, $18, $19, $20, $21, $22) \
                     ON CONFLICT (peer_id, idempotency_key) DO NOTHING",
                )
                .bind::<Text, _>(&record.id)
                .bind::<Text, _>(&record.peer_did)
                .bind::<Nullable<Text>, _>(record.peer_url.as_deref())
                .bind::<Text, _>(&record.endpoint)
                .bind::<Text, _>(&record.idempotency_key)
                .bind::<Text, _>(&record.payload_json)
                .bind::<Text, _>(record.state.as_str())
                .bind::<Nullable<Text>, _>(
                    record
                        .leased_from_state
                        .map(soland_storage::FederationOutboxState::as_str),
                )
                .bind::<Nullable<Jsonb>, _>(
                    record
                        .realm_fanout
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|error| {
                            PersistenceError::Internal(format!(
                                "realm fanout encode: {error}"
                            ))
                        })?,
                )
                .bind::<Integer, _>(record.attempts)
                .bind::<Integer, _>(record.semantic_attempts)
                .bind::<BigInt, _>(record.next_attempt_at)
                .bind::<Nullable<Integer>, _>(record.last_http_status)
                .bind::<Nullable<Text>, _>(record.last_error_code.as_deref())
                .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
                .bind::<Nullable<Text>, _>(record.lease_owner.as_deref())
                .bind::<Nullable<Text>, _>(record.lease_token.as_deref())
                .bind::<Nullable<BigInt>, _>(record.lease_expires_at)
                .bind::<Nullable<Text>, _>(record.policy_version.as_deref())
                .bind::<Nullable<Text>, _>(record.supersedes_outbox_id.as_deref())
                .bind::<BigInt, _>(record.created_at)
                .bind::<Nullable<BigInt>, _>(record.completed_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                outbox_inserted += inserted;
                crate::events::bind_event_outbox_rows(conn, &[event_pk], &record).await?;
            }
            }

            if let Some(mutation) = request.applet_record {
                let replacing = mutation.expected_record.is_some();
                let canonical_namespaces =
                    soland_storage::applet_namespaces_from_record(&mutation.record)?;
                if let Some(expected_record) = mutation.expected_record.as_ref() {
                    let expected_namespaces =
                        soland_storage::applet_namespaces_from_record(expected_record)?;
                    if canonical_namespaces != expected_namespaces {
                        return Err(PersistenceError::Conflict(
                            "schema_violation: Applet package.namespaces are immutable".to_owned(),
                        )
                        .into());
                    }
                }
                let managed_authorities =
                    soland_storage::applet_managed_authorities_from_record(&mutation.record)?;
                let previous_managed_authorities = mutation
                    .expected_record
                    .as_ref()
                    .map(soland_storage::applet_managed_authorities_from_record)
                    .transpose()?
                    .unwrap_or_default();
                if !previous_managed_authorities.is_subset(&managed_authorities) {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: Applet managed authority anchors are immutable"
                            .to_owned(),
                    )
                    .into());
                }
                let new_managed_authorities = managed_authorities
                    .difference(&previous_managed_authorities)
                    .cloned()
                    .collect::<Vec<_>>();
                let updated = if let Some(expected_record) = mutation.expected_record {
                    sql_query(
                        "UPDATE applet_registrations SET record = $3, updated_at = NOW() \
                         WHERE id = $1 AND record = $2 AND record->>'revoked_at' IS NULL \
                         AND record->>'status' IN ('installed', 'partially_installed')",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .bind::<Jsonb, _>(&expected_record)
                    .bind::<Jsonb, _>(&mutation.record)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?
                } else {
                    sql_query(
                        "INSERT INTO applet_registrations (id, record, updated_at) \
                         VALUES ($1, $2, NOW()) ON CONFLICT (id) DO NOTHING",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .bind::<Jsonb, _>(&mutation.record)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?
                };
                if updated != 1 {
                    let code = if replacing {
                        "cas_conflict"
                    } else {
                        "duplicate_conflict"
                    };
                    return Err(PersistenceError::Conflict(code.to_owned()).into());
                }

                let namespace_claims = [
                    (
                        arkret_models_integration::AppletNamespaceDomain::Actors,
                        "actors",
                        canonical_namespaces.actors,
                    ),
                    (
                        arkret_models_integration::AppletNamespaceDomain::Realms,
                        "realms",
                        canonical_namespaces.realms,
                    ),
                    (
                        arkret_models_integration::AppletNamespaceDomain::Handles,
                        "handles",
                        canonical_namespaces.handles,
                    ),
                ];
                if !replacing && namespace_claims.iter().any(|(_, _, claims)| !claims.is_empty()) {
                    sql_query(
                        "SELECT pg_advisory_xact_lock(hashtextextended('arkret.applet.namespace.claims', 0))",
                    )
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    let existing = sql_query(
                        "SELECT claims.domain, claims.pattern, claims.exclusive FROM applet_namespace_claims claims JOIN applet_registrations registrations ON registrations.id = claims.applet_id WHERE claims.applet_id <> $1 AND registrations.record->>'revoked_at' IS NULL AND registrations.record->>'status' IN ('installed', 'partially_installed')",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .load::<AppletNamespaceClaimRow>(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    for (domain, domain_wire, claims) in &namespace_claims {
                        for claim in claims {
                            if existing.iter().any(|stored| {
                                stored.domain == *domain_wire
                                    && (claim.exclusive || stored.exclusive)
                                    && arkret_models_integration::namespace_patterns_overlap(
                                        *domain,
                                        &claim.pattern,
                                        &stored.pattern,
                                    )
                            }) {
                                return Err(PersistenceError::Conflict(
                                    "applet_namespace_conflict".to_owned(),
                                )
                                .into());
                            }
                            sql_query(
                                "INSERT INTO applet_namespace_claims (applet_id, domain, pattern, exclusive) VALUES ($1, $2, $3, $4)",
                            )
                            .bind::<Text, _>(mutation.applet_id.as_str())
                            .bind::<Text, _>(*domain_wire)
                            .bind::<Text, _>(&claim.pattern)
                            .bind::<Bool, _>(claim.exclusive)
                            .execute(conn)
                            .await
                            .map_err(PersistenceError::database)?;
                        }
                    }
                }

                for claim in new_managed_authorities {
                    let inserted = sql_query(
                        "INSERT INTO managed_authority_claims (actor_id, principal_server_id, applet_id) VALUES ($1, $2, $3) ON CONFLICT (actor_id, principal_server_id) DO NOTHING",
                    )
                    .bind::<Text, _>(&claim.actor_id)
                    .bind::<Text, _>(&claim.principal_server_id)
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    if inserted != 1 {
                        return Err(PersistenceError::Conflict(
                            "applet_managed_authority_conflict".to_owned(),
                        )
                        .into());
                    }
                }
            }

            Ok(CommitTransactionOutcome::Committed(EventCommitOutcome {
                event_inserted,
                projections_inserted,
                outbox_inserted,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)?;
        match transaction_outcome {
            CommitTransactionOutcome::Committed(outcome) => Ok(outcome),
            CommitTransactionOutcome::Collision => Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            )),
        }
    }
}

#[derive(diesel::QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}
