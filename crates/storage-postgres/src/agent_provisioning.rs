//! The controller-PCR unit of `ak.agent.provision` (key-management.md
//! section 3.6.3).
//!
//! One accepted provision writes four typed current results in the
//! transaction that commits it: `agent_provisioning`,
//! `identity_accountability`, `agent_selector_claim` and
//! `agent_pcr_genesis_declaration`. The unit takes the controller PCR
//! authority lock, confirms the signing device is active at that cut,
//! verifies the Event proof against the accepted device key, and refuses a
//! second declaration of the same Agent or the same Agent PCR id before
//! anything is written. Any refusal leaves no row behind.

use arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload;
use arkret_models_collaboration::governance::accountability::AccountabilityProjection;
use arkret_wire::{EventKind, RealmCommit};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use soland_storage::{
    AgentProvisionAdmissionOutcome, AgentProvisionAdmissionWrite, AgentProvisionRecord,
    AuthorityCommitWriteOutcome, ConflictCode, PersistenceError,
};

use crate::actor_profiles::{PcrSelfEventCut, corrupt, rejected, verify_pcr_self_event};
use crate::{AsyncPgConnection, PgTransactionError};

const WHAT: &str = "Agent provision";

#[derive(QueryableByName)]
struct DeclaredRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

/// The four values `event` projects, with the Commit that accepted it.
fn record(
    event: &arkret_wire::Event,
    payload: &AgentProvisionPayload,
    commit: RealmCommit,
) -> Result<AgentProvisionRecord, PgTransactionError> {
    let schema =
        |error: arkret_wire::WireError| rejected(ConflictCode::SchemaViolation, &error.to_string());
    Ok(AgentProvisionRecord {
        event: event.clone(),
        commit,
        provisioning: payload.provisioning_value(),
        accountability: AccountabilityProjection::from_provision(payload, event.created_at)
            .map_err(schema)?,
        selector: payload.selector_claim_value(event).map_err(schema)?,
        declaration: payload.genesis_declaration_value(),
    })
}

fn position(commit: &RealmCommit) -> Result<i64, PgTransactionError> {
    i64::try_from(commit.stream_position)
        .map_err(|_| corrupt("Commit stream position is out of range"))
}

pub(crate) async fn admit_agent_provision_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AgentProvisionAdmissionWrite,
) -> Result<AgentProvisionAdmissionOutcome, PgTransactionError> {
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    if event.kind != EventKind::AgentProvision {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "the Agent provision unit admits only ak.agent.provision",
        ));
    }
    let payload = AgentProvisionPayload::try_from(event)
        .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    payload
        .validate_envelope(event)
        .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    let values = record(event, &payload, commit.clone())?;
    // The Event actor is the controller account (checked above), so the
    // signer the cut verifies is the controller's own active device.
    if let PcrSelfEventCut::Known(stored) = verify_pcr_self_event(
        conn,
        &write.commit,
        Some(payload.controller_authorization_ref.as_str()),
        WHAT,
    )
    .await?
    {
        return Ok(AgentProvisionAdmissionOutcome::Duplicate(record(
            event, &payload, stored,
        )?));
    }
    if payload.principal_control_realm_id == event.realm_id {
        return Err(rejected(
            ConflictCode::AgentPcrGenesisDeclarationConflict,
            "an Agent PCR id cannot be its controller's own PCR",
        ));
    }

    // The controller PCR lock taken above serializes every provision of this
    // PCR, so a missing row here stays missing until this unit commits.
    let already = sql_query(
        "SELECT realm_id FROM agent_provisioning_current_results \
         WHERE realm_id=$1 AND agent_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.agent_id.as_str())
    .get_result::<DeclaredRow>(&mut *conn)
    .await
    .optional()?;
    if already.is_some() {
        return Err(rejected(
            ConflictCode::AgentProvisioningAlreadyDeclared,
            "an accepted provision in this controller PCR already declares the Agent",
        ));
    }
    let claimed = sql_query(
        "SELECT realm_id FROM agent_pcr_genesis_declaration_current_results \
         WHERE principal_control_realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(payload.principal_control_realm_id.as_str())
    .get_result::<DeclaredRow>(&mut *conn)
    .await
    .optional()?;
    if claimed.is_some() {
        return Err(rejected(
            ConflictCode::AgentPcrGenesisDeclarationConflict,
            "an accepted provision already declares this Agent PCR id",
        ));
    }

    crate::authority_commit::queue_event_in_connection(conn, event, write.queued_at).await?;
    match crate::authority_commit::commit_verified_agent_provision_in_connection(
        conn,
        &write.commit,
    )
    .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "Agent provision Event was committed outside this unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                ConflictCode::TemporarilyUnavailable,
                "PCR authority changed before the Agent provision commit",
            ));
        }
    }

    let position = position(commit)?;
    sql_query(
        "INSERT INTO agent_provisioning_current_results \
         (realm_id,agent_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.agent_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(
        serde_json::to_value(&values.provisioning).map_err(PersistenceError::database)?,
    )
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    crate::actor_profiles::write_identity_accountability_in_connection(
        conn,
        &event.realm_id,
        commit,
        &values.accountability,
    )
    .await?;
    let selector_written = sql_query(
        "INSERT INTO agent_selector_claim_current_results \
         (realm_id,controller_principal_id,agent_slug,current_commit_id,\
          current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (realm_id,controller_principal_id,agent_slug) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value, updated_at=EXCLUDED.updated_at \
         WHERE agent_selector_claim_current_results.current_stream_position\
               <EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.controller_principal_id.as_str())
    .bind::<Text, _>(&payload.agent_slug)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(&values.selector).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if selector_written != 1 {
        return Err(corrupt(
            "agent_selector_claim row was not advanced by a later Commit",
        ));
    }
    // The subject is unique across every controller PCR of this Station; a
    // concurrent claim from another controller PCR loses here.
    let declared = sql_query(
        "INSERT INTO agent_pcr_genesis_declaration_current_results \
         (realm_id,principal_control_realm_id,current_commit_id,current_stream_position,\
          value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.principal_control_realm_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(
        serde_json::to_value(&values.declaration).map_err(PersistenceError::database)?,
    )
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if declared != 1 {
        return Err(rejected(
            ConflictCode::AgentPcrGenesisDeclarationConflict,
            "an accepted provision already declares this Agent PCR id",
        ));
    }
    crate::sidecar_authority_change_guard::after_current_writes_in_connection(conn, event).await?;
    Ok(AgentProvisionAdmissionOutcome::Committed(values))
}

/// The accepted provision that forward-declared `agent_pcr_id`, read under a
/// share lock so the declaration cannot move before the reader commits.
pub(crate) async fn declared_agent_provision_in_connection(
    conn: &mut AsyncPgConnection,
    agent_pcr_id: &arkret_wire::RealmId,
) -> Result<Option<(arkret_wire::RealmId, AgentProvisionPayload)>, PgTransactionError> {
    #[derive(QueryableByName)]
    struct ProvisionRow {
        #[diesel(sql_type = Text)]
        realm_id: String,
        #[diesel(sql_type = Jsonb)]
        envelope: serde_json::Value,
    }
    let row = sql_query(
        "SELECT d.realm_id,e.envelope \
         FROM agent_pcr_genesis_declaration_current_results d \
         JOIN realm_commits c ON c.commit_id=d.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE d.principal_control_realm_id=$1 FOR SHARE OF d",
    )
    .bind::<Text, _>(agent_pcr_id.as_str())
    .get_result::<ProvisionRow>(&mut *conn)
    .await
    .optional()?;
    row.map(|row| {
        let event: arkret_wire::Event = serde_json::from_value(row.envelope).map_err(corrupt)?;
        let payload = AgentProvisionPayload::try_from(&event).map_err(corrupt)?;
        let realm_id = arkret_wire::RealmId::new(row.realm_id).map_err(corrupt)?;
        if event.realm_id != realm_id || payload.principal_control_realm_id != *agent_pcr_id {
            return Err(corrupt(
                "agent_pcr_genesis_declaration row differs from its provision Event",
            ));
        }
        Ok((realm_id, payload))
    })
    .transpose()
}
