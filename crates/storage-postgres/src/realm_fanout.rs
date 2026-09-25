//! Realm committed-replication fanout planned in the accepting transaction
//! (`federation.md` §4.1.1).
//!
//! After an Event's RealmCommit and its typed current results are written,
//! the same transaction reads the accepted joined members of the Realm,
//! projects each complete ActorId to its routing service, drops this Station
//! and groups the rest by service. Every distinct remote Station gets one
//! durable `committed_replication` intent that carries only the exact source
//! submission and source RealmCommit, with the frozen
//! `(realm_id, member_id, membership_event_ref)` bases that authorized it kept
//! in the sender's outbox metadata. The Event's acceptance, the complete
//! target set and every intent therefore commit or roll back together.
//!
//! A remote Station enters the target set only when one of its members may
//! hold the Event's complete canonical bytes: a plaintext Message body is
//! replicated only to a Station the Realm lists as a private plaintext
//! service for message content, and a moderation report, readable only by
//! moderators, only to a Station hosting a member who holds a moderation
//! capability at this cut.
//!
//! A `leave` or `ban` that ends a member's joined state removes that member
//! from the accepted joined set, so the member's own Station would never
//! learn it. Such an Event is additionally owed to the departing member's
//! Station, frozen with the Event itself as the membership basis, and stays
//! owed only while that Event is still the member's effective membership
//! (`federation.md` §4.1.1).

use std::collections::BTreeMap;

use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, CommittedReplicationBranch, PeerAuthoritySubmitRequest,
    PeerCommittedReplicationRequest,
};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{
    FederationOutboxRecord, PersistenceError, PersistenceResult, RealmFanoutAuthorityWitness,
    RealmFanoutBinding, RealmFanoutOutboxInput, ids,
};

use crate::PgTransactionError;

/// Peer ingress every Realm fanout intent is delivered to.
pub(crate) const PEER_EVENTS_ENDPOINT: &str = "/_arkret/peer/events";

#[derive(diesel::QueryableByName)]
struct JoinedMemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct MembershipEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
}

#[derive(diesel::QueryableByName)]
struct PriorMembershipRow {
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    membership: Option<String>,
}

#[derive(diesel::QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

fn internal(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(detail.to_string())
}

/// The idempotency key of the one intent a RealmCommit owes a peer Station.
#[must_use]
pub(crate) fn fanout_idempotency_key(commit_id: &arkret_wire::RealmCommitId) -> String {
    format!("realm-fanout:{commit_id}")
}

/// Whether the Event carries a plaintext Message body: a create or a revise
/// without an encrypted carrier.
fn plaintext_message(event: &arkret_wire::Event) -> bool {
    matches!(
        event.kind,
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise
    ) && !event.payload.contains_key("encrypted_content")
}

/// The Stations the Realm names as private plaintext services for message
/// content at this cut.
async fn plaintext_message_services(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<String>> {
    let Some(row) = sql_query(
        "SELECT b.value FROM realm_bootstrap_current_results b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.result_family='realm_plaintext_visible_services' \
           AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=b.realm_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(Vec::new());
    };
    Ok(row
        .value
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|service| {
            service.get("visibility").and_then(Value::as_str) == Some("private_plaintext")
                && service
                    .get("data_classes")
                    .and_then(Value::as_array)
                    .is_some_and(|classes| classes.iter().any(|class| class == "message_content"))
        })
        .filter_map(|service| service.get("service_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect())
}

/// The departing member's Station owed a membership Event that ended the
/// member's joined state, with the Event itself as the frozen basis. `None`
/// when the Event is no such transition, the member is hosted here, the
/// member was not joined before it, or the Event is no longer the member's
/// effective membership.
async fn departing_member_target(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    authority_station: &arkret_wire::DidCoreId,
) -> PersistenceResult<Option<(arkret_wire::DidCoreId, RealmFanoutAuthorityWitness)>> {
    if event.kind != arkret_wire::EventKind::MemberState {
        return Ok(None);
    }
    let Ok(payload) = serde_json::to_value(&event.payload).and_then(
        serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >,
    ) else {
        return Ok(None);
    };
    use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
    if !matches!(
        payload.membership,
        MembershipPayloadState::Leave | MembershipPayloadState::Ban
    ) {
        return Ok(None);
    }
    let member = payload.member_id;
    let station = member.route_service_id().clone();
    if &station == authority_station {
        return Ok(None);
    }
    let member_key = member.to_string();
    let current = sql_query(
        "SELECT e.envelope->>'event_id' AS event_id \
         FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE m.realm_id=$1 AND m.member_id=$2 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&member_key)
    .get_result::<MembershipEventRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if current.is_none_or(|row| row.event_id != event.event_id.as_str()) {
        return Ok(None);
    }
    let event_token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("Event id is not canonical".into()))?;
    let prior = sql_query(
        "SELECT pe.kind, pe.envelope->'payload'->>'membership' AS membership \
         FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         JOIN realm_commits pc ON pc.stream_key=c.stream_key \
           AND pc.stream_position < c.stream_position \
         JOIN canonical_events pe ON pe.pk=pc.event_pk \
         WHERE e.id=$1 AND pe.state='committed' AND ( \
           (pe.kind='ak.member.state' AND pe.envelope->'payload'->'member_id'=$2::jsonb) \
           OR (pe.kind='ak.invite.accept' AND pe.envelope->'actor_id'=$2::jsonb)) \
         ORDER BY pc.stream_position DESC LIMIT 1",
    )
    .bind::<Binary, _>(event_token.to_vec())
    .bind::<Text, _>(&member_key)
    .get_result::<PriorMembershipRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let joined_before = prior.is_some_and(|row| {
        row.kind == arkret_wire::EventKind::InviteAccept.as_str()
            || row.membership.as_deref() == Some("join")
    });
    if !joined_before {
        return Ok(None);
    }
    Ok(Some((
        station,
        RealmFanoutAuthorityWitness {
            member_id: member,
            membership_event_ref: event.event_id.to_string(),
        },
    )))
}

/// Every remote Station owed this Event, with the bases that authorize it.
async fn remote_targets(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    authority_station: &arkret_wire::DidCoreId,
    commit_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<BTreeMap<arkret_wire::DidCoreId, Vec<RealmFanoutAuthorityWitness>>> {
    let rows = sql_query(
        "SELECT m.member_id, e.envelope->>'event_id' AS membership_event_id \
         FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE m.realm_id=$1 AND m.membership='join' \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id \
           AND e.state='committed' \
         ORDER BY m.member_id",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .load::<JoinedMemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let plaintext_services = if plaintext_message(event) {
        Some(plaintext_message_services(conn, &event.realm_id).await?)
    } else {
        None
    };
    let mut targets: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in rows {
        let member: arkret_wire::ActorId = serde_json::from_str(&row.member_id)
            .map_err(|error| internal(format!("joined member identity is malformed: {error}")))?;
        let station = member.route_service_id().clone();
        if &station == authority_station {
            continue;
        }
        if plaintext_services
            .as_ref()
            .is_some_and(|services| !services.iter().any(|service| service == station.as_str()))
        {
            continue;
        }
        if event.kind == arkret_wire::EventKind::SelfModerationReport
            && !crate::capability_grant_current_results::actor_holds_realm_action_in_connection(
                conn,
                &event.realm_id,
                &member,
                &[
                    arkret_wire::CapabilityActionId::POLICY_MANAGE,
                    arkret_wire::CapabilityActionId::MODERATION_DECISION,
                ],
                commit_at,
            )
            .await?
        {
            continue;
        }
        arkret_wire::EventId::new(row.membership_event_id.clone())
            .map_err(|error| internal(format!("membership Event id is malformed: {error}")))?;
        targets
            .entry(station)
            .or_default()
            .push(RealmFanoutAuthorityWitness {
                member_id: member,
                membership_event_ref: row.membership_event_id,
            });
    }
    if let Some((station, witness)) =
        departing_member_target(conn, event, authority_station).await?
    {
        targets.entry(station).or_default().push(witness);
    }
    Ok(targets)
}

/// Whether a frozen fanout intent to `peer` is still owed at the current
/// accepted cut (`federation.md` §4.1.1): at least one frozen
/// `(member_id, membership_event_ref)` basis must, as a whole, still be a
/// current joined member routed to `peer` for which the Event's scope and
/// plaintext policy still allow the complete canonical bytes.
pub(crate) async fn fanout_still_owed_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    local_station: &arkret_wire::DidCoreId,
    peer: &arkret_wire::DidCoreId,
    witnesses: &[RealmFanoutAuthorityWitness],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let targets = remote_targets(conn, event, local_station, at).await?;
    Ok(targets
        .get(peer)
        .is_some_and(|current| witnesses.iter().any(|witness| current.contains(witness))))
}

/// Plan and durably enqueue the Realm fanout of one just-committed Event.
///
/// Must run after the Event's typed current results were written, so the
/// joined set is the one the Event itself produced. Returns the number of
/// intents this call inserted.
pub(crate) async fn plan_realm_fanout_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authority_station: &arkret_wire::DidCoreId,
    source: Option<&arkret_wire::EventAdmissionSubmission>,
    created_at: i64,
) -> Result<usize, PgTransactionError> {
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if commit.stream_ref != realm_stream {
        if source.is_some() {
            return Err(PersistenceError::Conflict(
                "Circle and Sidecar fanout target planning is unavailable".to_owned(),
            )
            .into());
        }
        return Ok(0);
    }
    let targets = remote_targets(conn, event, authority_station, commit.committed_at).await?;
    if targets.is_empty() {
        return Ok(0);
    }
    let source = source.ok_or_else(|| {
        PersistenceError::Conflict(
            "Realm Event with remote joined members has no fanout source submission".to_owned(),
        )
    })?;
    if source.event != *event {
        return Err(PersistenceError::SchemaViolation(
            "Realm fanout source submission does not carry the committed Event".to_owned(),
        )
        .into());
    }
    let request =
        PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
            branch: CommittedReplicationBranch::CommittedReplication,
            replications: vec![CommittedEventSubmission {
                event_submission: source.clone(),
                source_commit: commit.clone(),
            }],
        });
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload_json = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&request).map_err(PersistenceError::database)?,
    )
    .map_err(internal)?;
    let event_token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("Event id is not canonical".into()))?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(event_token.to_vec())
        .get_result::<EventPkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .pk;
    let idempotency_key = fanout_idempotency_key(&commit.commit_id);
    let mut inserted = 0;
    for (station, authority_witnesses) in targets {
        let id = format!("{idempotency_key}:{station}");
        let record = FederationOutboxRecord::realm_fanout(RealmFanoutOutboxInput {
            id: id.clone(),
            peer_id: station,
            peer_url: None,
            endpoint: PEER_EVENTS_ENDPOINT.to_owned(),
            idempotency_key: idempotency_key.clone(),
            payload_json: payload_json.clone(),
            binding: RealmFanoutBinding {
                realm_id: event.realm_id.to_string(),
                source_event_ids: vec![event.event_id.to_string()],
                authority_witnesses,
            },
            created_at,
        });
        if crate::federation::enqueue_federation_outbox_in_connection(conn, &record).await? {
            inserted += 1;
            sql_query(
                "INSERT INTO event_federation_outbox (event_pk, outbox_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind::<BigInt, _>(event_pk)
            .bind::<Text, _>(&id)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
    }
    Ok(inserted)
}
