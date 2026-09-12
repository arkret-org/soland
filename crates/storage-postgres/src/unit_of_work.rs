use arkret_identifiers::EventId;
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
    #[diesel(sql_type = BigInt)]
    pk: i64,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    state: String,
}

#[derive(diesel::QueryableByName)]
struct MembershipCompensationBytesRow {
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
}

#[derive(diesel::QueryableByName)]
struct AppletAdmissionRecordRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
}

/// The identity row is the same linearization lock used by installation
/// revocation. Retained replicas and closed install units never enter it.
async fn ensure_applet_admission_in_transaction(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    if request.replicated {
        return Ok(());
    }
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let fail = || PersistenceError::Conflict("applet_revoked".to_owned());
    let grant_id = if matches!(
        event.kind,
        arkret_wire::EventKind::CapabilityRevoke | arkret_wire::EventKind::CapabilityRelinquish
    ) {
        event
            .payload
            .get("grant_id")
            .and_then(serde_json::Value::as_str)
    } else if event.applet_id.is_some() {
        event.authorization_ref.as_deref()
    } else {
        None
    };
    if let Some(grant_id) = grant_id {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(format!("applet-grant:{grant_id}"))
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    if matches!(
        event.kind,
        arkret_wire::EventKind::CapabilityRevoke | arkret_wire::EventKind::MemberState
    ) {
        // A persisted revoke plan precedes all its Events. Lock the same
        // identity as ordinary admission before the first plan Event lands;
        // the later saga projection update is not the linearization point.
        sql_query("SELECT identity.record FROM applet_managed_identities identity \
            WHERE EXISTS (SELECT 1 FROM applet_installations installation \
                WHERE installation.applet_id = identity.applet_id \
                AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(installation.record #> '{revoke_execution,outcome,steps}', '[]'::jsonb)) step WHERE step->>'effect_ref' = $1) \
                AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(installation.record #> '{revoke_execution,outcome,steps}', '[]'::jsonb)) step WHERE step->>'effect_kind' = 'local_applet_fence')) \
            ORDER BY identity.applet_id, identity.target_station_id FOR UPDATE OF identity")
            .bind::<Text, _>(event.event_id.as_str())
            .load::<AppletAdmissionRecordRow>(conn).await.map_err(PersistenceError::database)?;
    }
    let Some(applet_id) = &event.applet_id else {
        return Ok(());
    };
    let scope_key = soland_storage::applet_effective_scope_key(&event.scope_ref)?;
    let install = sql_query("SELECT record FROM applet_installations WHERE applet_id = $1 AND effective_scope_key = $2 FOR UPDATE")
        .bind::<Text, _>(applet_id.as_str()).bind::<Text, _>(&scope_key)
        .get_result::<AppletAdmissionRecordRow>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(fail)?;
    let bot_actor = install
        .record
        .pointer("/package/bot_actor_id")
        .cloned()
        .ok_or_else(fail)
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::ActorId>(value).map_err(|_| fail())
        })?;
    let target = bot_actor.route_service_id();
    let identity = sql_query("SELECT record FROM applet_managed_identities WHERE applet_id = $1 AND target_station_id = $2 FOR UPDATE")
        .bind::<Text, _>(applet_id.as_str()).bind::<Text, _>(target.as_str())
        .get_result::<AppletAdmissionRecordRow>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(fail)?;
    if identity
        .record
        .get("globally_fenced_at")
        .is_some_and(|value| !value.is_null())
    {
        return Err(fail());
    }
    if install
        .record
        .get("revoked_at")
        .is_some_and(|value| !value.is_null())
        || !matches!(
            install
                .record
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("installed" | "partially_installed")
        )
    {
        return Err(fail());
    }
    if let Some(grant_id) = grant_id {
        let revoked = sql_query("SELECT EXISTS (SELECT 1 FROM canonical_events WHERE realm_id = $1 AND kind IN ('ak.capability.revoke', 'ak.capability.relinquish') AND envelope->'payload'->>'grant_id' = $2) AS present")
            .bind::<Text, _>(event.realm_id.as_str()).bind::<Text, _>(grant_id)
            .get_result::<ExistsRow>(conn).await.map_err(PersistenceError::database)?.present;
        if revoked {
            return Err(fail());
        }
    }
    if let Some(steps) = install.record.pointer("/revoke_execution/outcome/steps") {
        let fenced = sql_query("SELECT EXISTS (SELECT 1 FROM jsonb_array_elements($1::jsonb) step \
            JOIN canonical_events event ON event.envelope->>'event_id' = step->>'effect_ref' \
            WHERE event.realm_id = $2 AND event.kind IN ('ak.capability.revoke', 'ak.member.state') \
            AND EXISTS (SELECT 1 FROM jsonb_array_elements($1::jsonb) fence WHERE fence->>'effect_kind' = 'local_applet_fence')) AS present")
            .bind::<Jsonb, _>(steps).bind::<Text, _>(event.realm_id.as_str())
            .get_result::<ExistsRow>(conn).await.map_err(PersistenceError::database)?.present;
        if fenced {
            return Err(fail());
        }
    }
    Ok(())
}

async fn commit_mls_frontier_input(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    request: &EventCommitRequest,
    event_already_existed: bool,
) -> PersistenceResult<()> {
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    crate::mls_public_state::commit_genesis(conn, event_pk, request).await?;
    arkret_wire::event_submission::validate_mls_submission_leaves(
        &event,
        request.mls_frontier_leaves.as_deref(),
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let Some(leaves) = &request.mls_frontier_leaves else {
        return Ok(());
    };
    let canonical_bytes = arkret_canonical::canonical_json_bytes(leaves)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event_already_existed {
        let stored =
            sql_query("SELECT canonical_bytes FROM mls_frontier_inputs WHERE event_pk = $1")
                .bind::<BigInt, _>(event_pk)
                .get_result::<MembershipCompensationBytesRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
        if stored.is_none_or(|stored| stored.canonical_bytes != canonical_bytes) {
            return Err(PersistenceError::Conflict(
                "accepted MLS transition input is missing or changed".to_owned(),
            ));
        }
        return Ok(());
    }
    sql_query("INSERT INTO mls_frontier_inputs (event_pk, canonical_bytes) VALUES ($1, $2)")
        .bind::<BigInt, _>(event_pk)
        .bind::<Binary, _>(canonical_bytes)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

async fn commit_membership_compensation_evidence(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    request: &EventCommitRequest,
    event_already_existed: bool,
) -> PersistenceResult<()> {
    let event = serde_json::from_value::<arkret_wire::Event>(request.event.envelope.clone())
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Event envelope is not canonical wire: {error}"
            ))
        })?;
    let selects_compensation = event.authorization_ref.as_ref().is_some_and(|value| {
        arkret_wire::MembershipCompensationDelegationRef::new(value.as_str()).is_ok()
    });
    let record = match (
        selects_compensation,
        request.membership_compensation_evidence.as_ref(),
    ) {
        (false, None) => return Ok(()),
        (true, None) | (false, Some(_)) => {
            return Err(PersistenceError::Conflict(
                "schema_violation: membership compensation carrier presence mismatch".to_owned(),
            ));
        }
        (true, Some(record)) => record,
    };
    let expected_bytes =
        arkret_canonical::canonical_json_bytes(&record.evidence).map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: membership compensation evidence is not canonicalizable: {error}"
            ))
        })?;
    if record.event_id != request.event.event_id
        || record.event_digest != request.event.canonical_digest
        || record.admission_id != record.evidence.delegation.core.admission_id.as_str()
        || record.delegation_id != record.evidence.delegation.delegation_id.as_str()
        || record.canonical_bytes != expected_bytes
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: membership compensation evidence record is not self-consistent"
                .to_owned(),
        ));
    }
    record.evidence.validate_for_event(&event).map_err(|error| {
        PersistenceError::Conflict(format!(
            "membership_compensation_conflict: compensation evidence does not bind Event: {error}"
        ))
    })?;
    if event_already_existed {
        let stored = sql_query(
            "SELECT canonical_bytes FROM membership_compensation_evidence WHERE event_pk = $1",
        )
        .bind::<BigInt, _>(event_pk)
        .get_result::<MembershipCompensationBytesRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        return match stored {
            Some(stored) if stored.canonical_bytes == record.canonical_bytes => Ok(()),
            Some(_) => Err(PersistenceError::Conflict(
                "membership_compensation_conflict: Event replay changed its compensation evidence"
                    .to_owned(),
            )),
            None => Err(PersistenceError::Conflict(
                "schema_violation: accepted compensation Event is missing durable evidence"
                    .to_owned(),
            )),
        };
    }
    let evidence_value = serde_json::to_value(&record.evidence).map_err(|error| {
        PersistenceError::Internal(format!(
            "membership compensation evidence serialization failed: {error}"
        ))
    })?;
    sql_query(
        "INSERT INTO membership_compensation_evidence \
         (event_pk, admission_id, delegation_id, canonical_bytes, evidence) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<Text, _>(&record.admission_id)
    .bind::<Text, _>(&record.delegation_id)
    .bind::<Binary, _>(&record.canonical_bytes)
    .bind::<Jsonb, _>(&evidence_value)
    .execute(conn)
    .await
    .map_err(|error| {
        if matches!(
            &error,
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _
            )
        ) {
            PersistenceError::Conflict(
                "membership_compensation_conflict: compensation delegation was already consumed"
                    .to_owned(),
            )
        } else {
            PersistenceError::database(error)
        }
    })?;
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct DevicePairingCasRow {
    #[diesel(sql_type = Bool)]
    accepted: bool,
}

#[derive(diesel::QueryableByName)]
struct ContactMirrorCommitRow {
    #[diesel(sql_type = Text)]
    target_holder_principal_id: String,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
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
                .map(|request| soland_storage::admitted_cascade_agent_id(&request.event))
                .collect::<PersistenceResult<std::collections::BTreeSet<_>>>()?;
            let expected_agent_count = expected_agent_ids.len();
            let expected_agent_ids = expected_agent_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if submitted_agent_ids != expected_agent_ids
                || expected_agent_ids.len() != expected_agent_count
            {
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
            let controller = arkret_wire::ActorId::account(record.controller_account_id.clone());
            let expected_initiator = &record.initiator_actor_id;
            if terminal.event.actor_id != controller.to_string()
                || terminal.event.realm_id.as_deref() != Some(record.realm_id.as_str())
                || typed.actor_id != controller
                || initiator != expected_initiator
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
                .map(|request| soland_storage::admitted_cascade_agent_id(&request.event))
                .collect::<PersistenceResult<std::collections::BTreeSet<_>>>()?;
            let expected_actor_ids = record
                .expected_agent_ids
                .iter()
                .cloned()
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

/// Lock and inspect every Event identity before the transaction writes any
/// ordinary row. Collision evidence deliberately wins over later admission
/// checks so a batch can never commit a valid prefix before item N collides.
async fn preflight_event_batch(
    conn: &mut AsyncPgConnection,
    events: &[EventCommitRequest],
) -> Result<Option<CommitTransactionOutcome>, PgTransactionError> {
    let mut ordered = events.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.event.event_id.cmp(&right.event.event_id));
    let records = ordered.iter().map(|item| &item.event).collect::<Vec<_>>();
    crate::events::lock_canonical_event_inputs(conn, &records).await?;
    let mut incoming = std::collections::BTreeMap::<String, &CanonicalEventRecord>::new();
    for item in &ordered {
        let identity = ids::validated_event_identity_parts_for_suite(
            &item.event.event_id,
            &item.event.canonical_digest,
            &item.event.canonical_bytes,
            item.event.digest_suite,
        )?;
        let stored =
            sql_query("SELECT pk, canonical_bytes, state FROM canonical_events WHERE id = $1")
                .bind::<Binary, _>(identity.id.to_vec())
                .get_result::<EventPreflightRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
        if let Some(stored) = stored {
            if stored.canonical_bytes != item.event.canonical_bytes {
                // A byte-different preimage for an identity already here.
                // `insert_canonical_event` decides which of the two this is: an
                // open collision, or a variant of an identity an accepted fork
                // resolution already settled. Only the winner of such a verdict
                // is admissible, and it comes back as a replay because the row
                // now holds exactly these bytes.
                if !matches!(
                    insert_canonical_event(conn, &item.event).await?,
                    CanonicalInsertOutcome::Replay(_)
                ) {
                    return Ok(Some(CommitTransactionOutcome::Collision));
                }
                commit_mls_frontier_input(conn, stored.pk, item, true).await?;
                commit_membership_compensation_evidence(conn, stored.pk, item, true).await?;
                continue;
            }
            if stored.state == "quarantined" {
                return Ok(Some(CommitTransactionOutcome::Collision));
            }
            commit_mls_frontier_input(conn, stored.pk, item, true).await?;
            commit_membership_compensation_evidence(conn, stored.pk, item, true).await?;
            continue;
        }
        if let Some(previous) = incoming.get(&item.event.event_id) {
            if previous.canonical_bytes != item.event.canonical_bytes {
                let inserted = insert_canonical_event(conn, previous).await?;
                debug_assert!(matches!(inserted, CanonicalInsertOutcome::Inserted(_)));
                // Two preimages of one identity inside a single batch. The
                // second is written so the collision bucket holds both, and the
                // batch is refused whichever way that lands — a settled identity
                // still refuses a second variant, it just does not requarantine.
                let second = insert_canonical_event(conn, &item.event).await?;
                debug_assert!(!matches!(
                    second,
                    CanonicalInsertOutcome::Inserted(_) | CanonicalInsertOutcome::Replay(_)
                ));
                return Ok(Some(CommitTransactionOutcome::Collision));
            }
        } else {
            incoming.insert(item.event.event_id.clone(), &item.event);
        }
    }

    let mut admission_realms = std::collections::BTreeSet::new();
    for item in &ordered {
        let event = serde_json::from_value::<arkret_wire::Event>(item.event.envelope.clone())
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
    Ok(None)
}

impl PgEventCommitUnitOfWork {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn contact_event_ref(value: Option<&EventId>) -> PersistenceResult<Option<Vec<u8>>> {
    value
        .map(|value| {
            ids::event_token_part_or_schema_violation(value.as_str(), "event")
                .map(|token| token.to_vec())
        })
        .transpose()
}

/// Commit one accepted consent Control Move's holder-private effects.
///
/// The or_set cell row and the eager holder-quarantine invalidation
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
        "INSERT INTO consent_cells (id, cell_id, holder_account_id, peer, consent_scope, grant_dots, revoked_dots, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (holder_account_id, cell_id) DO UPDATE SET grant_dots = EXCLUDED.grant_dots, revoked_dots = EXCLUDED.revoked_dots, updated_at = EXCLUDED.updated_at WHERE consent_cells.peer = EXCLUDED.peer AND consent_cells.consent_scope = EXCLUDED.consent_scope",
    )
    .bind::<Uuid, _>(uuid::Uuid::now_v7())
    .bind::<Text, _>(&cell.cell_id)
    .bind::<Jsonb, _>(serde_json::to_value(&cell.holder_account_id).map_err(|error| {
        PersistenceError::SchemaViolation(format!("consent holder account is not serializable: {error}"))
    })?)
    .bind::<Jsonb, _>(serde_json::to_value(&cell.peer).map_err(|error| {
        PersistenceError::SchemaViolation(format!("consent peer is not serializable: {error}"))
    })?)
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
    let Some(cas) = commit.holder_quarantine else {
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
    sql_query(
        "WITH changed AS ( \
             INSERT INTO account_data_changes \
                (actor_id, account_data_key, payload, revision, tombstone, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING position \
         ) \
         INSERT INTO account_data_change_retention \
            (actor_id, latest_position, retained_through_position, updated_at) \
         SELECT $1, position, 0, now() FROM changed \
         ON CONFLICT (actor_id) DO UPDATE SET \
            latest_position = GREATEST(account_data_change_retention.latest_position, EXCLUDED.latest_position), \
            updated_at = EXCLUDED.updated_at",
    )
    .bind::<Text, _>(&record.actor)
    .bind::<Text, _>(&record.account_data_key)
    .bind::<Jsonb, _>(&record.payload)
    .bind::<BigInt, _>(record.revision as i64)
    .bind::<Bool, _>(record.tombstone)
    .bind::<Timestamptz, _>(record.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
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
    let request_slot_states =
        serde_json::to_value(&record.request_slot_states).map_err(|error| {
            PersistenceError::Internal(format!(
                "cannot encode Contact request-slot states: {error}"
            ))
        })?;
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
    let request_event_ref = contact_event_ref(record.request_event_ref.as_ref())?;
    let response_event_ref = contact_event_ref(record.response_event_ref.as_ref())?;
    let tombstone_event_ref = contact_event_ref(record.tombstone_event_ref.as_ref())?;

    let affected = if let Some(expected_updated_at) = commit.expected_updated_at {
        if record.updated_at <= expected_updated_at {
            return Err(PersistenceError::Conflict(conflict_code));
        }
        sql_query(
            "UPDATE contacts SET requester_id = $1, target_id = $2, \
                contact_round_id = $3, version = $4, granted_to_target_scopes = $5, \
                granted_to_requester_scopes = $6, status = $7, pending_incoming_admitted = $8, request_event_ref = $9, \
                request_slot_states = $10, request_receipts = $11, request_mirror_receipts = $12, \
                contact_round_evidence = $13, contact_round_evidence_history = $14, \
                control_outcomes = $15, response_event_ref = $16, tombstone_event_ref = $17, \
                message = $18, peer_id = $19, updated_at = $20 \
             WHERE ((requester_id = $1 AND target_id = $2) OR \
                    (requester_id = $2 AND target_id = $1)) AND updated_at = $21",
        )
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Nullable<BigInt>, _>(version)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<diesel::sql_types::Bool, _>(record.pending_incoming_admitted)
        .bind::<Nullable<Binary>, _>(request_event_ref)
        .bind::<Jsonb, _>(&request_slot_states)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(response_event_ref)
        .bind::<Nullable<Binary>, _>(tombstone_event_ref)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(expected_updated_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?
    } else {
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, contact_round_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, pending_incoming_admitted, request_event_ref, request_slot_states, request_receipts, request_mirror_receipts, contact_round_evidence, contact_round_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22) \
             ON CONFLICT (requester_id, target_id) DO NOTHING",
        )
        .bind::<Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Nullable<BigInt>, _>(version)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<diesel::sql_types::Bool, _>(record.pending_incoming_admitted)
        .bind::<Nullable<Binary>, _>(request_event_ref)
        .bind::<Jsonb, _>(&request_slot_states)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(response_event_ref)
        .bind::<Nullable<Binary>, _>(tombstone_event_ref)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
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
             (target_holder_principal_id, request_event_id, request_digest, canonical_event_bytes, source_receipt, issuer_id, verified_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (target_holder_principal_id, request_event_id) DO UPDATE \
             SET verified_at = contact_verified_mirrors.verified_at \
             WHERE contact_verified_mirrors.request_digest = EXCLUDED.request_digest \
               AND contact_verified_mirrors.canonical_event_bytes = EXCLUDED.canonical_event_bytes \
               AND contact_verified_mirrors.source_receipt = EXCLUDED.source_receipt \
               AND contact_verified_mirrors.issuer_id = EXCLUDED.issuer_id \
             RETURNING target_holder_principal_id",
        )
        .bind::<Text, _>(&mirror.target_holder_principal_id)
        .bind::<Text, _>(&mirror.request_event_id)
        .bind::<Text, _>(&mirror.request_digest)
        .bind::<Binary, _>(&mirror.canonical_event_bytes)
        .bind::<Jsonb, _>(&source_receipt)
        .bind::<Text, _>(&mirror.issuer_id)
        .bind::<Timestamptz, _>(mirror.verified_at)
        .get_result::<ContactMirrorCommitRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if committed
            .as_ref()
            .is_none_or(|row| row.target_holder_principal_id != mirror.target_holder_principal_id)
        {
            return Err(PersistenceError::Conflict(
                "contact_verified_mirror_conflict".to_owned(),
            ));
        }
    }
    if let Some((account_id, policy)) = invite_policy {
        crate::contacts::put_invite_receive_policy(conn, &account_id, &policy).await?;
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
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
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
        soland_storage::validate_franking_replay_nonce_commit(
            &request.events,
            request.franking_replay_nonce.as_ref(),
        )?;
        soland_storage::validate_agent_approval_nonce_commit(
            &request.events,
            request.agent_approval_nonce.as_ref(),
        )?;
        let mut conn = pg_conn(&self.pool).await?;
        let transaction_outcome = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let Some(outcome) = preflight_event_batch(conn, &request.events).await? {
                return Ok(outcome);
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
                // Stage consumption and terminal replay ledger share this Event transaction.
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
                sql_query("INSERT INTO device_pairing_outcomes (request_id, terminal_record, created_at) VALUES ($1,$2,$3)")
                    .bind::<Text,_>(&commit.device_pairing_request_id)
                    .bind::<Jsonb,_>(&commit.terminal_record)
                    .bind::<Timestamptz,_>(commit.changed_at)
                    .execute(conn).await.map_err(PersistenceError::database)?;

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
                    CanonicalInsertOutcome::Collision
                    | CanonicalInsertOutcome::Quarantined
                    | CanonicalInsertOutcome::AdjudicatedVariant
                ) {
                    return Ok(CommitTransactionOutcome::Collision);
                }
                continue;
            }
            if let Some(selector) = request.device_revocation_gate.as_ref() {
                crate::ensure_gate_allowed_in_transaction(conn, selector).await?;
            }
            ensure_applet_admission_in_transaction(conn, &request).await?;
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
                 FROM accepted_events WHERE realm_pk = $1 AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
            )
            .bind::<BigInt, _>(realm_pk)
            .bind::<Text, _>(&request.event.actor_id)
            .load::<CanonicalEventRow>(conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(CanonicalEventRecord::from)
            .collect::<Vec<_>>();
            validate_actor_scope_commit(scoped.iter(), &request.event, request.replicated)?;
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
            commit_mls_frontier_input(conn, event_pk, &request, false).await?;
            commit_membership_compensation_evidence(conn, event_pk, &request, false).await?;

            let typed_event = serde_json::from_value::<arkret_wire::Event>(
                request.event.envelope.clone(),
            )
            .map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: accepted Event envelope is not canonical wire: {error}"
                ))
            })?;
            commit_holder_account_data(conn, &typed_event).await?;
            crate::current_data::commit_sources(conn, &typed_event, request.event.digest_suite).await?;
            if let Some(contact_projection) = request.contact_projection {
                commit_contact_projection(conn, contact_projection).await?;
            }
            if let Some(consent_projection) = request.consent_projection {
                commit_consent_projection(conn, consent_projection).await?;
            }
            // Control/Data routing is defined by the typed Event plane. A
            // closed genesis anchor is a basis-free Control Move; an ordinary Event
            // instead carries `auth_context` with its authority references.
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
                            super::validate_control_proposal_ack_binding(&request.event, ack)?;
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
            {
                return Err(PersistenceError::Conflict(
                    "schema_violation: non-Control Event cannot carry Control Proposal authority"
                        .to_owned(),
                )
                .into());
            }

                for dependency in &request.governance_dependencies {
                    let source_matches = matches!(
                        &dependency.source,
                        soland_storage::GovernanceDependencySource::Event(digest)
                            if digest.as_str() == request.event.canonical_digest
                    );
                    if dependency.realm_id != typed_event.realm_id || !source_matches
                    {
                        return Err(PersistenceError::Conflict(
                            "schema_violation: governance dependency does not bind committed Event"
                                .to_owned(),
                        )
                        .into());
                    }
                    put_governance_dependency_exact_in_transaction(conn, dependency).await?;
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
                let actor_key = record.authenticated_actor.canonical_key().map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "authenticated ActorId is invalid: {error}"
                    ))
                })?;
                let authenticated_actor = serde_json::to_value(&record.authenticated_actor)
                    .map_err(|error| {
                        PersistenceError::SchemaViolation(format!(
                            "authenticated ActorId encode failed: {error}"
                        ))
                    })?;
                let inserted = sql_query(
                    "INSERT INTO idempotency_keys \
                     (actor_key, authenticated_actor, operation_id, idempotency_key, request_hash, response_status, \
                      response_body, created_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                     ON CONFLICT (actor_key, operation_id, idempotency_key) DO NOTHING",
                )
                .bind::<Text, _>(&actor_key)
                .bind::<Jsonb, _>(&authenticated_actor)
                .bind::<Text, _>(&record.operation_id)
                .bind::<Text, _>(&record.idempotency_key)
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
                .bind::<Text, _>(record.peer_id.as_str())
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

            if let Some(nonce) = request.franking_replay_nonce {
                let expires_at = soland_storage::franking_replay_nonce_expires_at(
                    nonce.consumed_at,
                )?;
                let scope_lock = format!(
                    "moderation_franking_replay_nonces.capacity.v1|{}:{}|{}:{}",
                    nonce.realm_id.len(),
                    nonce.realm_id,
                    nonce.received_by.as_str().len(),
                    nonce.received_by
                );
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&scope_lock)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                sql_query(
                    "DELETE FROM moderation_franking_replay_nonces \
                     WHERE realm_id = $1 AND received_by = $2 AND expires_at <= $3",
                )
                .bind::<Text, _>(&nonce.realm_id)
                .bind::<Text, _>(nonce.received_by.as_str())
                .bind::<Timestamptz, _>(nonce.consumed_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                let active = sql_query(
                    "SELECT COUNT(*) AS count FROM moderation_franking_replay_nonces \
                     WHERE realm_id = $1 AND received_by = $2",
                )
                .bind::<Text, _>(&nonce.realm_id)
                .bind::<Text, _>(nonce.received_by.as_str())
                .get_result::<CountRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .count;
                if active
                    >= i64::try_from(
                        soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE,
                    )
                    .expect("franking replay ledger per-scope bound fits i64")
                {
                    return Err(
                        PersistenceError::Conflict("duplicate_conflict".to_owned()).into(),
                    );
                }
                let inserted = sql_query(
                    "INSERT INTO moderation_franking_replay_nonces \
                     (realm_id, received_by, replay_nonce, report_event_id, consumed_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                )
                .bind::<Text, _>(&nonce.realm_id)
                .bind::<Text, _>(nonce.received_by.as_str())
                .bind::<Text, _>(&nonce.replay_nonce)
                .bind::<Text, _>(&nonce.report_event_id)
                .bind::<Timestamptz, _>(nonce.consumed_at)
                .bind::<Timestamptz, _>(expires_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if inserted != 1 {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                }
            }

            if let Some(nonce) = request.agent_approval_nonce {
                let inserted = sql_query(
                    "INSERT INTO agent_approval_nonces \
                     (agent_id, authorization_ref, request_id, approval_nonce, event_id, expires_at, consumed_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
                )
                .bind::<Text, _>(&nonce.agent_id)
                .bind::<Text, _>(&nonce.authorization_ref)
                .bind::<Text, _>(&nonce.request_id)
                .bind::<Text, _>(&nonce.approval_nonce)
                .bind::<Text, _>(&nonce.event_id)
                .bind::<Timestamptz, _>(nonce.expires_at)
                .bind::<Timestamptz, _>(nonce.consumed_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if inserted != 1 {
                    return Err(PersistenceError::Conflict(
                        arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED.to_owned(),
                    )
                    .into());
                }
            }

            if let Some(preview) = request.applet_authoring_preview {
                let updated = sql_query(
                    "UPDATE applet_authoring_previews SET status = 'committed', committed_at = NOW() \
                     WHERE subject_key = $1 AND request_digest = $2 AND status = 'current'",
                )
                .bind::<Text, _>(&preview.subject_key)
                .bind::<Text, _>(&preview.request_digest)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if updated != 1 {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                }
            }

            if let Some(mutation) = request.applet_record {
                soland_storage::validate_applet_installation_record(&mutation.record)?;
                if let Some(expected) = mutation.expected_record.as_ref() {
                    soland_storage::validate_applet_installation_record(expected)?;
                }
                let replacing = mutation.expected_record.is_some();
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                let effective_scope_key =
                    soland_storage::applet_effective_scope_key_from_record(&mutation.record)?;
                if soland_storage::applet_id_from_record(&mutation.record)?
                    != mutation.applet_id.as_str()
                    || soland_storage::applet_id_from_record(&mutation.identity.record)?
                        != mutation.applet_id.as_str()
                    || soland_storage::applet_bot_account_from_identity(&mutation.identity.record)?
                        .station_id
                        != mutation.identity.target_station_id
                {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: Applet identity/installation key does not match its record"
                            .to_owned(),
                    )
                    .into());
                }
                let identity_updated = if let Some(expected_identity) =
                    mutation.identity.expected_record.as_ref()
                {
                    if expected_identity != &mutation.identity.record {
                        return Err(PersistenceError::Conflict(
                            "duplicate_conflict: Applet identity winner changed".to_owned(),
                        )
                        .into());
                    }
                    sql_query(
                        "UPDATE applet_managed_identities SET record = record \
                         WHERE applet_id = $1 AND target_station_id = $2 AND record = $3",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .bind::<Text, _>(mutation.identity.target_station_id.as_str())
                    .bind::<Jsonb, _>(expected_identity)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?
                } else {
                    sql_query(
                        "INSERT INTO applet_managed_identities \
                         (applet_id, target_station_id, record, accepted_at) \
                         VALUES ($1, $2, $3, NOW()) \
                         ON CONFLICT (applet_id, target_station_id) DO NOTHING",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .bind::<Text, _>(mutation.identity.target_station_id.as_str())
                    .bind::<Jsonb, _>(&mutation.identity.record)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?
                };
                if identity_updated != 1 {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: Applet identity winner is not the accepted winner"
                            .to_owned(),
                    )
                    .into());
                }
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
                    soland_storage::applet_managed_authorities_from_record(
                        &mutation.identity.record,
                        &mutation.record,
                    )?;
                let previous_managed_authorities = mutation
                    .expected_record
                    .as_ref()
                    .map(|record| {
                        soland_storage::applet_managed_authorities_from_record(
                            &mutation.identity.record,
                            record,
                        )
                    })
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
                        "UPDATE applet_installations SET record = $4, updated_at = NOW() \
                         WHERE applet_id = $1 AND effective_scope_key = $2 AND record = $3 AND record->>'revoked_at' IS NULL \
                         AND record->>'status' IN ('installed', 'partially_installed')",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .bind::<Text, _>(&effective_scope_key)
                    .bind::<Jsonb, _>(&expected_record)
                    .bind::<Jsonb, _>(&mutation.record)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?
                } else {
                    sql_query(
                        "INSERT INTO applet_installations (applet_id, effective_scope_key, record, updated_at) \
                         VALUES ($1, $2, $3, NOW()) ON CONFLICT (applet_id, effective_scope_key) DO NOTHING",
                    )
                    .bind::<Text, _>(mutation.applet_id.as_str())
                    .bind::<Text, _>(&effective_scope_key)
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
                        "SELECT claims.domain, claims.pattern, claims.exclusive FROM applet_namespace_claims claims WHERE claims.applet_id <> $1",
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
                                "INSERT INTO applet_namespace_claims (applet_id, domain, pattern, exclusive) VALUES ($1, $2, $3, $4) ON CONFLICT (applet_id, domain, pattern) DO NOTHING",
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
                        "INSERT INTO managed_authority_claims (actor_id, station_id, applet_id) VALUES ($1, $2, $3) \
                         ON CONFLICT (actor_id, station_id) DO UPDATE SET applet_id = EXCLUDED.applet_id \
                         WHERE managed_authority_claims.applet_id = EXCLUDED.applet_id",
                    )
                    .bind::<Text, _>(&claim.actor_id)
                    .bind::<Text, _>(&claim.station_id)
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

#[derive(diesel::QueryableByName)]
struct HolderStationRow {
    #[diesel(sql_type=Text)]
    station: String,
}
/// The accepted holder Event and CAS/global current row are one transaction.
async fn commit_holder_account_data(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::AccountDataSet {
        return Ok(());
    }
    let account = event.actor_id.as_account_id().ok_or_else(|| {
        PersistenceError::SchemaViolation("account data holder must be an Account".to_owned())
    })?;
    let station = sql_query(
        "SELECT identity->'identity'->>'service_id' AS station FROM service_identity WHERE id=$1",
    )
    .bind::<Text, _>(soland_storage::SINGLETON_ID)
    .get_result::<HolderStationRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Internal(
            "trusted service identity is unavailable for holder CAS".to_owned(),
        )
    })?;
    if account.station_id.as_str() != station.station {
        return Ok(());
    }
    let key = event
        .payload
        .get("key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PersistenceError::SchemaViolation("account data key missing".to_owned()))?;
    let expected = event
        .payload
        .get("expected_revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("account data revision missing".to_owned())
        })?;
    let tombstone = event
        .payload
        .get("tombstone")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let payload = if tombstone {
        serde_json::Value::Null
    } else {
        event
            .payload
            .get("body")
            .or_else(|| event.payload.get("encrypted_payload"))
            .cloned()
            .ok_or_else(|| {
                PersistenceError::SchemaViolation("account data value missing".to_owned())
            })?
    };
    let record = soland_storage::AccountDataRecord {
        actor: event.actor_id.to_string(),
        account_data_key: key.to_owned(),
        revision: expected.checked_add(1).ok_or_else(|| {
            PersistenceError::Conflict("cas_conflict: account data revision exhausted".to_owned())
        })?,
        payload,
        tombstone,
        updated_at: event.created_at,
    };
    match crate::accounts::compare_account_data_in_transaction(
        conn,
        &record,
        expected,
        Some(&event.event_id),
    )
    .await?
    {
        soland_storage::AccountDataCasResult::Applied(_) => Ok(()),
        soland_storage::AccountDataCasResult::Conflict(_) => Err(PersistenceError::Conflict(
            "cas_conflict: account data revision changed before accepted commit".to_owned(),
        )),
    }
}
