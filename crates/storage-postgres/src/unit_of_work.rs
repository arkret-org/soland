//! One durable boundary for an accepted Event batch.
//!
//! Admission decides; this module installs. Every write an accepted Event
//! produces — the queued producer Event, its authority-signed `RealmCommit`,
//! the installed MLS successor and its recipient Welcome deliveries, the
//! business projections, the federation outbox rows, the idempotency
//! reservation, and the Applet / Agent / moderation batch effects — lands in a
//! single PostgreSQL transaction. A caller therefore observes either the
//! complete accepted operation or none of it, and a rolled-back commit leaves
//! no projection a reader could mistake for accepted state.

use diesel::sql_types::{Array, BigInt, Binary, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    AuthorityCommitWriteOutcome, EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest,
    EventCommitUnitOfWork, PersistenceError, PersistenceResult, ids,
};

use crate::agent_draft_pending_intents::commit_agent_draft_pending_intent_in_connection;
use crate::authority_commit::{commit_transaction_in_connection, queue_event_in_connection};
use crate::device_revocations::{
    commit_revocation_in_connection, ensure_gate_allowed_in_transaction,
};
use crate::federation::enqueue_federation_outbox_in_connection;
use crate::idempotency::record_idempotency_in_connection;
use crate::projection::append_projection_batch_in_connection;
use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(Clone)]
pub struct PgEventCommitUnitOfWork {
    pool: PgPool,
}

impl PgEventCommitUnitOfWork {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
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

#[derive(diesel::QueryableByName)]
struct AppletAdmissionRecordRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
}

fn conflict(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(detail.into())
}

/// Refuse an Applet-authored Event once its installation or managed identity is
/// fenced. The identity row is the same linearization point installation
/// revocation takes, and the exact Events a closed first install carries are
/// admitted by that aggregate rather than by the fence they are creating.
async fn ensure_applet_admission_in_transaction(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    applet_record: Option<&soland_storage::AppletRecordCommit>,
) -> PersistenceResult<()> {
    if closed_applet_install_contains_event(
        event.event_id.as_str(),
        event.applet_id.as_ref().map(arkret_wire::AppletId::as_str),
        applet_record,
    ) {
        return Ok(());
    }
    let fail = || conflict("applet_revoked");
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
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    let Some(applet_id) = &event.applet_id else {
        return Ok(());
    };
    let scope_key = soland_storage::applet_effective_scope_key(&event.scope_ref)?;
    let install = sql_query(
        "SELECT record FROM applet_installations \
         WHERE applet_id = $1 AND effective_scope_key = $2 FOR UPDATE",
    )
    .bind::<Text, _>(applet_id.as_str())
    .bind::<Text, _>(&scope_key)
    .get_result::<AppletAdmissionRecordRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
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
    let identity = sql_query(
        "SELECT record FROM applet_managed_identities \
         WHERE applet_id = $1 AND target_station_id = $2 FOR UPDATE",
    )
    .bind::<Text, _>(applet_id.as_str())
    .bind::<Text, _>(target.as_str())
    .get_result::<AppletAdmissionRecordRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(fail)?;
    if identity
        .record
        .get("globally_fenced_at")
        .is_some_and(|value| !value.is_null())
        || install
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
    Ok(())
}

/// A first install is a closed aggregate: the Events it carries are admitted by
/// the same mutation that creates the fence, so they are not measured against
/// an installation row that does not exist yet.
fn closed_applet_install_contains_event(
    event_id: &str,
    event_applet_id: Option<&str>,
    mutation: Option<&soland_storage::AppletRecordCommit>,
) -> bool {
    let Some(mutation) = mutation.filter(|mutation| mutation.expected_record.is_none()) else {
        return false;
    };
    if event_applet_id != Some(mutation.applet_id.as_str()) {
        return false;
    }
    const IDENTITY_EVENT_FIELDS: &[&str] = &[
        "bot_actor_provision_event",
        "bot_pcr_genesis_event",
        "bot_accountability_grant_event",
        "bot_profile_event",
    ];
    IDENTITY_EVENT_FIELDS.iter().any(|field| {
        mutation
            .identity
            .record
            .get(*field)
            .and_then(|event| event.get("event_id"))
            .and_then(serde_json::Value::as_str)
            == Some(event_id)
    }) || mutation
        .record
        .get("registration_event")
        .and_then(|event| event.get("event_id"))
        .and_then(serde_json::Value::as_str)
        == Some(event_id)
        || mutation
            .record
            .get("capability_grant_events")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|events| {
                events.iter().any(|event| {
                    event.get("event_id").and_then(serde_json::Value::as_str) == Some(event_id)
                })
            })
}

/// Consume one staged device-pairing authorization.
///
/// The CAS and the terminal replay ledger share the Event transaction, so a
/// refused commit leaves the staged request claimable exactly once more.
async fn commit_device_pairing_authorization(
    conn: &mut AsyncPgConnection,
    commit: &soland_storage::DevicePairingAuthorizationCommit,
) -> PersistenceResult<()> {
    let new_device_pubkey = serde_json::to_value(&commit.new_device_pubkey).map_err(|error| {
        PersistenceError::Internal(format!(
            "cannot encode device pairing authorization public key: {error}"
        ))
    })?;
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
               AND candidate.state = 'ready_for_claim' \
               AND candidate.expires_at > $7 \
             RETURNING 1 \
         ) \
         SELECT EXISTS(SELECT 1 FROM updated) AS accepted",
    )
    .bind::<Text, _>(&commit.device_pairing_request_id)
    .bind::<Text, _>(&commit.pairing_code)
    .bind::<Jsonb, _>(&new_device_pubkey)
    .bind::<Text, _>(&commit.device_id)
    .bind::<Text, _>(commit.authorized_by_actor_id.as_str())
    .bind::<Text, _>(&commit.authorized_event_ref)
    .bind::<Timestamptz, _>(commit.changed_at)
    .get_result::<DevicePairingCasRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !cas.accepted {
        return Err(conflict("device_pairing_not_found"));
    }
    sql_query(
        "INSERT INTO device_pairing_outcomes (request_id, terminal_record, created_at) \
         VALUES ($1, $2, $3)",
    )
    .bind::<Text, _>(&commit.device_pairing_request_id)
    .bind::<Jsonb, _>(&commit.terminal_record)
    .bind::<Timestamptz, _>(commit.changed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

fn contact_event_ref(
    value: Option<&arkret_identifiers::EventId>,
) -> PersistenceResult<Option<Vec<u8>>> {
    value
        .map(|value| {
            ids::event_token_part_or_schema_violation(value.as_str(), "event")
                .map(|token| token.to_vec())
        })
        .transpose()
}

/// Install one committed Contact mutation, its verified request mirror, and the
/// holder-private invite policy the same command decided.
async fn commit_contact_projection(
    conn: &mut AsyncPgConnection,
    committed_ref: &arkret_wire::CommittedEventRef,
    commit: soland_storage::ContactProjectionCommit,
) -> PersistenceResult<()> {
    if let Some(intent) = commit.completion_intent.as_ref() {
        intent.validate_event_binding()?;
        if intent.plan.event.event_id != committed_ref.event_id {
            return Err(PersistenceError::SchemaViolation(
                "Contact delivery intent does not bind the committed Event".to_owned(),
            ));
        }
        crate::contacts::completion::stage_in_transaction(conn, committed_ref, intent).await?;
    }
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
            return Err(conflict(conflict_code));
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
        .bind::<Bool, _>(record.pending_incoming_admitted)
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
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    } else {
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, contact_round_id, version, granted_to_target_scopes, granted_to_requester_scopes, status, pending_incoming_admitted, request_event_ref, request_slot_states, request_receipts, request_mirror_receipts, contact_round_evidence, contact_round_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22) \
             ON CONFLICT (requester_id, target_id) DO NOTHING",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Nullable<BigInt>, _>(version)
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Bool, _>(record.pending_incoming_admitted)
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
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    };
    if affected != 1 {
        return Err(conflict(conflict_code));
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
        .get_result::<ContactMirrorCommitRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if committed
            .as_ref()
            .is_none_or(|row| row.target_holder_principal_id != mirror.target_holder_principal_id)
        {
            return Err(conflict("contact_verified_mirror_conflict"));
        }
    }
    if let Some((account_id, policy)) = invite_policy {
        crate::contacts::put_invite_receive_policy(conn, &account_id, &policy).await?;
    }
    Ok(())
}

/// Install one committed consent command's holder-private effects.
///
/// `consent-model.md` section 4.1.2 requires the eager holder-quarantine
/// invalidation to land inside the same transaction boundary as the accepted
/// revoke. The insert guard repeats admission's `(holder, consent_id)` intent
/// binding under the row lock, so a concurrent grant cannot rebind the same
/// `consent_id` between admission and commit.
async fn commit_consent_projection(
    conn: &mut AsyncPgConnection,
    commit: soland_storage::ConsentProjectionCommit,
) -> PersistenceResult<()> {
    let grant = commit.grant;
    let active_grants = soland_storage::encode_consent_grants(&grant.active_grants);
    let revoked_grants = soland_storage::encode_consent_grants(&grant.revoked_grants);
    let holder = serde_json::to_value(&grant.holder_account_id).map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "consent holder account is not serializable: {error}"
        ))
    })?;
    let peer = serde_json::to_value(&grant.peer).map_err(|error| {
        PersistenceError::SchemaViolation(format!("consent peer is not serializable: {error}"))
    })?;
    let affected = sql_query(
        "INSERT INTO consent_grants \
         (consent_id, holder_account_id, peer, consent_scope, active_grants, revoked_grants, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (holder_account_id, consent_id) DO UPDATE SET \
             active_grants = EXCLUDED.active_grants, \
             revoked_grants = EXCLUDED.revoked_grants, \
             updated_at = EXCLUDED.updated_at \
         WHERE consent_grants.peer = EXCLUDED.peer \
           AND consent_grants.consent_scope = EXCLUDED.consent_scope",
    )
    .bind::<Text, _>(grant.consent_id.as_str())
    .bind::<Jsonb, _>(&holder)
    .bind::<Jsonb, _>(&peer)
    .bind::<Text, _>(&grant.consent_scope)
    .bind::<Jsonb, _>(&active_grants)
    .bind::<Jsonb, _>(&revoked_grants)
    .bind::<Timestamptz, _>(grant.updated_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if affected == 0 {
        return Err(conflict("consent_intent_rebind"));
    }
    let Some(cas) = commit.holder_quarantine else {
        return Ok(());
    };
    commit_account_data_cas(conn, cas, None).await
}

/// Replace one holder-private register under the revision read frozen by
/// admission. When `source_event_id` is present, the account-data adapter also
/// verifies that the committed source Event describes this exact value and
/// publishes that source into the holder sync projection. Any conflict aborts
/// the surrounding Event transaction.
async fn commit_account_data_cas(
    conn: &mut AsyncPgConnection,
    cas: soland_storage::AccountDataCasCommit,
    source_event_id: Option<&arkret_wire::EventId>,
) -> PersistenceResult<()> {
    let record = cas.record;
    match crate::accounts::compare_account_data_in_transaction(
        conn,
        &record,
        cas.expected_revision,
        source_event_id,
    )
    .await?
    {
        soland_storage::AccountDataCasResult::Applied(_) => Ok(()),
        soland_storage::AccountDataCasResult::Conflict(_) => {
            let exact_replay = if let Some(event_id) = source_event_id {
                sql_query(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM account_datas d \
                         JOIN account_global_versions v \
                           ON v.actor_key=d.actor_id \
                          AND v.channel='account_data_events' \
                          AND v.item_key='event:'||d.account_data_key \
                          AND v.valid_until IS NULL \
                         WHERE d.actor_id=$1 AND d.account_data_key=$2 \
                           AND d.revision=$3 AND d.payload=$4 AND d.tombstone=$5 \
                           AND v.payload->>'source'='event' \
                           AND v.payload->'value'->>'event_id'=$6 \
                     ) AS accepted",
                )
                .bind::<Text, _>(&record.actor)
                .bind::<Text, _>(&record.account_data_key)
                .bind::<BigInt, _>(i64::try_from(record.revision).map_err(|_| {
                    PersistenceError::Internal(
                        "account data revision exceeds PostgreSQL BIGINT".to_owned(),
                    )
                })?)
                .bind::<Jsonb, _>(&record.payload)
                .bind::<Bool, _>(record.tombstone)
                .bind::<Text, _>(event_id.as_str())
                .get_result::<DevicePairingCasRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .accepted
            } else {
                false
            };
            if exact_replay {
                Ok(())
            } else {
                Err(conflict(cas.conflict_code))
            }
        }
    }
}

/// Freeze or complete an Agent membership cascade intent.
///
/// The cascade is a batch-level product effect: the controller transition and
/// every Agent transition it fans out to are one command unit, and the durable
/// cleanup intent is written in the same transaction as the Events that
/// justify it.
async fn stage_agent_membership_cascade(
    conn: &mut AsyncPgConnection,
    transition: Option<&soland_storage::AgentMembershipCascadeCommit>,
    events: &[EventCommitRequest],
) -> PersistenceResult<()> {
    use soland_storage::{
        AgentCleanupRecord, AgentMembershipCascadeCommit, MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS,
    };

    #[derive(diesel::QueryableByName)]
    struct AgentCleanupIntentJsonRow {
        #[diesel(sql_type = Jsonb)]
        record_json: serde_json::Value,
    }

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
                return Err(PersistenceError::SchemaViolation(
                    "invalid atomic Agent cleanup cardinality".to_owned(),
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
                return Err(conflict(
                    "duplicate_conflict: atomic Agent cascade Event set mismatch",
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
                return Err(conflict(
                    "duplicate_conflict: atomic Agent cascade actor set mismatch",
                ));
            }
        }
        AgentMembershipCascadeCommit::EmergencyTerminal { record } => {
            record.validate().map_err(|error| {
                PersistenceError::SchemaViolation(format!("invalid Agent cleanup intent: {error}"))
            })?;
            if event_ids
                != std::collections::BTreeSet::from([record.controller_terminal_event_id.as_str()])
            {
                return Err(conflict(
                    "duplicate_conflict: emergency terminal Event set mismatch",
                ));
            }
            let terminal = events
                .first()
                .expect("validated singleton terminal Event set");
            let typed =
                serde_json::from_value::<arkret_wire::Event>(terminal.event.envelope.clone())
                    .map_err(|error| {
                        PersistenceError::SchemaViolation(format!(
                            "emergency terminal Event is invalid: {error}"
                        ))
                    })?;
            let initiator = typed.executed_by.as_ref().unwrap_or(&typed.actor_id);
            let controller = arkret_wire::ActorId::account(record.controller_account_id.clone());
            if terminal.event.actor_id != controller.to_string()
                || terminal.event.realm_id.as_deref() != Some(record.realm_id.as_str())
                || typed.actor_id != controller
                || initiator != &record.initiator_actor_id
            {
                return Err(conflict(
                    "duplicate_conflict: emergency terminal Event does not bind cleanup intent",
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
                    return Err(conflict(
                        "duplicate_conflict: cleanup intent digest names different content",
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
            .ok_or_else(|| conflict("failed_precondition: Agent cleanup intent is unavailable"))?;
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
                return Err(conflict(
                    "duplicate_conflict: emergency Agent cleanup does not match frozen intent",
                ));
            }
            if record.completed_at.is_some() {
                if record.agent_transition_event_ids.as_ref() != Some(agent_transition_event_ids) {
                    return Err(conflict(
                        "duplicate_conflict: completed Agent cleanup replay differs",
                    ));
                }
                return Ok(());
            }
            record.completed_at = Some(*completed_at);
            record.agent_transition_event_ids = Some(agent_transition_event_ids.clone());
            record.validate().map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "completed Agent cleanup is invalid: {error}"
                ))
            })?;
            let record_json = serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!(
                    "completed Agent cleanup encoding failed: {error}"
                ))
            })?;
            sql_query(
                "UPDATE agent_membership_cleanup_intents SET \
                     record_json = $2, completed_at = $3, updated_at = $3 \
                 WHERE cleanup_intent_digest = $1",
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

/// Consume one moderation franking replay nonce.
async fn commit_franking_replay_nonce(
    conn: &mut AsyncPgConnection,
    nonce: &soland_storage::FrankingReplayNonceCommit,
) -> PersistenceResult<()> {
    let expires_at = soland_storage::franking_replay_nonce_expires_at(nonce.consumed_at)?;
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
        >= i64::try_from(soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE)
            .expect("franking replay ledger per-scope bound fits i64")
    {
        return Err(conflict("duplicate_conflict"));
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
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(conflict("duplicate_conflict"));
    }
    Ok(())
}

/// Install one Applet installation aggregate: the managed-identity winner, the
/// per-scope installation record, its namespace claims, and every managed
/// authority anchor it introduces.
async fn commit_applet_record(
    conn: &mut AsyncPgConnection,
    mutation: soland_storage::AppletRecordCommit,
) -> PersistenceResult<()> {
    soland_storage::validate_applet_installation_record(&mutation.record)?;
    if let Some(expected) = mutation.expected_record.as_ref() {
        soland_storage::validate_applet_installation_record(expected)?;
    }
    let replacing = mutation.expected_record.is_some();
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(mutation.applet_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let effective_scope_key =
        soland_storage::applet_effective_scope_key_from_record(&mutation.record)?;
    if soland_storage::applet_id_from_record(&mutation.record)? != mutation.applet_id.as_str()
        || soland_storage::applet_id_from_record(&mutation.identity.record)?
            != mutation.applet_id.as_str()
        || soland_storage::applet_bot_account_from_identity(&mutation.identity.record)?.station_id
            != mutation.identity.target_station_id
    {
        return Err(PersistenceError::SchemaViolation(
            "Applet identity/installation key does not match its record".to_owned(),
        ));
    }
    let identity_updated =
        if let Some(expected_identity) = mutation.identity.expected_record.as_ref() {
            if expected_identity != &mutation.identity.record {
                return Err(conflict(
                    "duplicate_conflict: Applet identity winner changed",
                ));
            }
            sql_query(
                "UPDATE applet_managed_identities SET record = record \
             WHERE applet_id = $1 AND target_station_id = $2 AND record = $3",
            )
            .bind::<Text, _>(mutation.applet_id.as_str())
            .bind::<Text, _>(mutation.identity.target_station_id.as_str())
            .bind::<Jsonb, _>(expected_identity)
            .execute(&mut *conn)
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
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
        };
    if identity_updated != 1 {
        return Err(conflict(
            "duplicate_conflict: Applet identity winner is not the accepted winner",
        ));
    }
    let canonical_namespaces = soland_storage::applet_namespaces_from_record(&mutation.record)?;
    if let Some(expected_record) = mutation.expected_record.as_ref() {
        if canonical_namespaces != soland_storage::applet_namespaces_from_record(expected_record)? {
            return Err(PersistenceError::SchemaViolation(
                "Applet package.namespaces are immutable".to_owned(),
            ));
        }
    }
    let managed_authorities = soland_storage::applet_managed_authorities_from_record(
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
        return Err(PersistenceError::SchemaViolation(
            "Applet managed authority anchors are immutable".to_owned(),
        ));
    }
    let new_managed_authorities = managed_authorities
        .difference(&previous_managed_authorities)
        .cloned()
        .collect::<Vec<_>>();
    let updated = if let Some(expected_record) = mutation.expected_record {
        sql_query(
            "UPDATE applet_installations SET record = $4, updated_at = NOW() \
             WHERE applet_id = $1 AND effective_scope_key = $2 AND record = $3 \
               AND record->>'revoked_at' IS NULL \
               AND record->>'status' IN ('installed', 'partially_installed')",
        )
        .bind::<Text, _>(mutation.applet_id.as_str())
        .bind::<Text, _>(&effective_scope_key)
        .bind::<Jsonb, _>(&expected_record)
        .bind::<Jsonb, _>(&mutation.record)
        .execute(&mut *conn)
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
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    };
    if updated != 1 {
        return Err(conflict(if replacing {
            "cas_conflict"
        } else {
            "duplicate_conflict"
        }));
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
    if !replacing
        && namespace_claims
            .iter()
            .any(|(_, _, claims)| !claims.is_empty())
    {
        sql_query(
            "SELECT pg_advisory_xact_lock(hashtextextended('arkret.applet.namespace.claims', 0))",
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let existing = sql_query(
            "SELECT claims.domain, claims.pattern, claims.exclusive \
             FROM applet_namespace_claims claims WHERE claims.applet_id <> $1",
        )
        .bind::<Text, _>(mutation.applet_id.as_str())
        .load::<AppletNamespaceClaimRow>(&mut *conn)
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
                    return Err(conflict("applet_namespace_conflict"));
                }
                sql_query(
                    "INSERT INTO applet_namespace_claims (applet_id, domain, pattern, exclusive) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (applet_id, domain, pattern) DO NOTHING",
                )
                .bind::<Text, _>(mutation.applet_id.as_str())
                .bind::<Text, _>(*domain_wire)
                .bind::<Text, _>(&claim.pattern)
                .bind::<Bool, _>(claim.exclusive)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
        }
    }

    for claim in new_managed_authorities {
        let inserted = sql_query(
            "INSERT INTO managed_authority_claims (actor_id, station_id, applet_id) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (actor_id, station_id) DO UPDATE SET applet_id = EXCLUDED.applet_id \
             WHERE managed_authority_claims.applet_id = EXCLUDED.applet_id",
        )
        .bind::<Text, _>(&claim.actor_id)
        .bind::<Text, _>(&claim.station_id)
        .bind::<Text, _>(mutation.applet_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(conflict("applet_managed_authority_conflict"));
        }
    }
    Ok(())
}

/// Install every write one accepted Event produces.
async fn commit_one_in_connection(
    conn: &mut AsyncPgConnection,
    request: EventCommitRequest,
    applet_record: Option<&soland_storage::AppletRecordCommit>,
    outcome: &mut EventCommitOutcome,
) -> Result<(), PgTransactionError> {
    if request.event.event_id != request.authority_commit.event.event_id.as_str() {
        return Err(PersistenceError::SchemaViolation(
            "canonical Event record does not match the authority transaction".to_owned(),
        )
        .into());
    }
    let event = &request.authority_commit.event;

    if let Some(commit) = request.device_pairing_authorization.as_ref() {
        if commit.authorized_event_ref != request.event.event_id {
            return Err(PersistenceError::SchemaViolation(
                "device pairing authorization does not bind committed Event".to_owned(),
            )
            .into());
        }
        commit_device_pairing_authorization(conn, commit).await?;
    }
    if let Some(selector) = request.device_revocation_gate.as_ref() {
        ensure_gate_allowed_in_transaction(conn, selector).await?;
    }
    ensure_applet_admission_in_transaction(conn, event, applet_record).await?;

    queue_event_in_connection(conn, event, request.event.received_at).await?;
    match commit_transaction_in_connection(conn, &request.authority_commit).await? {
        AuthorityCommitWriteOutcome::Committed => outcome.event_inserted = true,
        AuthorityCommitWriteOutcome::Duplicate => {}
        AuthorityCommitWriteOutcome::StaleAuthority(current) => {
            return Err(conflict(format!(
                "stale_authority: generation {} is current",
                current.generation
            ))
            .into());
        }
    }

    let commit = &request.authority_commit.commit;
    let committed_ref = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };

    if let Some(transition) = request.device_revocation_transition.as_ref() {
        commit_revocation_in_connection(conn, transition).await?;
    }
    if let Some(commit) = request.contact_projection {
        commit_contact_projection(conn, &committed_ref, commit).await?;
    }
    if let Some(commit) = request.agent_draft_pending_intent.as_ref() {
        if event.kind != arkret_wire::EventKind::AgentDraftPropose
            || commit.record.accepted_event_id != event.event_id
            || commit.record.canonical_event_digest.as_str()
                != request.event.canonical_digest.as_str()
        {
            return Err(PersistenceError::SchemaViolation(
                "agent draft pending intent does not bind its accepted proposal Event".to_owned(),
            )
            .into());
        }
        commit_agent_draft_pending_intent_in_connection(conn, commit).await?;
    }
    if let Some(commit) = request.actor_private_account_data {
        commit_account_data_cas(conn, commit, Some(&event.event_id)).await?;
    }
    if let Some(commit) = request.consent_projection {
        commit_consent_projection(conn, commit).await?;
    }

    outcome.projections_inserted += request.projections.len();
    if !request.projections.is_empty() {
        append_projection_batch_in_connection(conn, request.projections).await?;
    }
    for record in &request.outbox {
        if enqueue_federation_outbox_in_connection(conn, record).await? {
            outcome.outbox_inserted += 1;
        }
    }
    if let Some(record) = request.idempotency.as_ref() {
        record_idempotency_in_connection(conn, record).await?;
    }
    Ok(())
}

async fn commit_batch_in_connection(
    conn: &mut AsyncPgConnection,
    request: EventBatchCommitRequest,
) -> Result<EventCommitOutcome, PgTransactionError> {
    if request.events.is_empty() {
        return Err(PersistenceError::SchemaViolation("empty event batch".to_owned()).into());
    }
    soland_storage::validate_franking_replay_nonce_commit(
        &request.events,
        request.franking_replay_nonce.as_ref(),
    )?;
    stage_agent_membership_cascade(
        conn,
        request.agent_membership_cascade.as_ref(),
        &request.events,
    )
    .await?;

    let mut outcome = EventCommitOutcome::default();
    for event in request.events {
        commit_one_in_connection(conn, event, request.applet_record.as_ref(), &mut outcome).await?;
    }

    if let Some(nonce) = request.franking_replay_nonce.as_ref() {
        commit_franking_replay_nonce(conn, nonce).await?;
    }
    if let Some(preview) = request.applet_authoring_preview.as_ref() {
        let updated = sql_query(
            "UPDATE applet_authoring_previews SET status = 'committed', committed_at = NOW() \
             WHERE subject_key = $1 AND request_digest = $2 AND status = 'current'",
        )
        .bind::<Text, _>(&preview.subject_key)
        .bind::<Text, _>(&preview.request_digest)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if updated != 1 {
            return Err(conflict("duplicate_conflict").into());
        }
    }
    if let Some(mutation) = request.applet_record {
        commit_applet_record(conn, mutation).await?;
    }
    Ok(outcome)
}

#[async_trait::async_trait]
impl EventCommitUnitOfWork for PgEventCommitUnitOfWork {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.commit_event_batch(EventBatchCommitRequest {
            events: vec![request],
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
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            commit_batch_in_connection(conn, request).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
