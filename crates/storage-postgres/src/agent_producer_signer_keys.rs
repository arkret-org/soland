//! Historical Agent producer keys frozen in the original admission transaction.

use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_identity::{
    HistoricalSignerKeyQuerySender, ResolvedSignerKey, SignerKeyQueryResult, SignerKeyQuerySelector,
};

use super::*;

#[derive(QueryableByName)]
struct SourceRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

pub(crate) async fn retain_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    guard: Option<&SelfProducerCommitGuard>,
) -> PersistenceResult<()> {
    let Some(SelfProducerCommitGuard::Agent {
        pcr_realm_id,
        agent_id,
        authorization_ref,
        verification_method,
    }) = guard
    else {
        return Ok(());
    };
    let actor = event.actual_signer();
    if actor.as_account_id().map(|account| &account.principal_id) != Some(agent_id)
        || event
            .producer_proof
            .as_ref()
            .map(|proof| &proof.verification_method)
            != Some(verification_method)
    {
        return Err(PersistenceError::Conflict(
            "Agent historical producer differs from admission guard".into(),
        ));
    }
    let source = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2")
        .bind::<Text,_>(authorization_ref.event_id.as_str()).bind::<Text,_>(authorization_ref.commit_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let source_event: arkret_wire::Event =
        serde_json::from_value(source.envelope).map_err(PersistenceError::database)?;
    let payload = AgentKeyAuthorizePayload::try_from(&source_event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let source_commit: arkret_wire::RealmCommit =
        serde_json::from_value(source.commit_json).map_err(PersistenceError::database)?;
    if source_event.event_id != authorization_ref.event_id
        || source_event.realm_id != *pcr_realm_id
        || source_commit.commit_id != authorization_ref.commit_id
        || source_commit.stream_ref != authorization_ref.stream_ref
        || source_commit.stream_position != authorization_ref.stream_position
        || source_commit.event_ref != source_event.event_id
        || payload.agent_id != *agent_id
        || payload.verification_method != *verification_method
    {
        return Err(PersistenceError::Conflict(
            "Agent historical authorization coordinate differs".into(),
        ));
    }
    let revision = sql_query("SELECT e.envelope,c.commit_json FROM agent_key_current_results k JOIN realm_commits c ON c.commit_id=k.current_commit_id AND c.stream_position=k.current_stream_position AND c.realm_id=k.realm_id JOIN canonical_events e ON e.pk=c.event_pk WHERE k.realm_id=$1 AND k.agent_id=$2 AND k.agent_key_id=$3")
        .bind::<Text,_>(pcr_realm_id.as_str()).bind::<Text,_>(agent_id.as_str()).bind::<Text,_>(payload.key_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let revision_commit: arkret_wire::RealmCommit =
        serde_json::from_value(revision.commit_json).map_err(PersistenceError::database)?;
    if revision_commit.stream_ref != authorization_ref.stream_ref
        || revision_commit.stream_position < authorization_ref.stream_position
    {
        return Err(PersistenceError::Conflict(
            "Agent historical key revision does not cover authorization".into(),
        ));
    }
    let key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &payload.public_key,
        verification_method,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let selector = SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::Agent {
            actor: actor.clone(),
            verification_method: verification_method.clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
        },
    };
    let outcome = SignerKeyQueryResult::HistoricalResolved {
        selector,
        key: ResolvedSignerKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                key.raw_public_key,
            ))
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            authorization_ref: authorization_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: revision_commit.commit_id,
                stream_position: revision_commit.stream_position,
            },
            governance_generation: revision_commit.governance_generation,
        },
        accepted_at: commit.committed_at,
    };
    outcome
        .validate(&event.realm_id)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    sql_query("INSERT INTO agent_producer_signer_keys(commit_id,outcome) VALUES($1,$2)")
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(outcome).map_err(PersistenceError::database)?)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn read(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    selector: &SignerKeyQuerySelector,
) -> PersistenceResult<Option<SignerKeyQueryResult>> {
    let Some(target) = selector.committed_event_ref() else {
        return Ok(None);
    };
    let mut conn = pg_conn(pool).await?;
    let row =
        sql_query("SELECT outcome AS payload FROM agent_producer_signer_keys WHERE commit_id=$1")
            .bind::<Text, _>(target.commit_id.as_str())
            .get_result::<JsonPayloadRow>(&mut conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let outcome: SignerKeyQueryResult =
        serde_json::from_value(row.payload).map_err(PersistenceError::database)?;
    outcome
        .validate(realm_id)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    Ok((outcome.selector() == selector
        && matches!(outcome, SignerKeyQueryResult::HistoricalResolved { .. }))
    .then_some(outcome))
}
