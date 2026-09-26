//! The self Direct Conversation founding unit.
//!
//! `contact-and-direct-conversation.md` sections 5.4 to 6.2: the founder's
//! current Station admits the caller-authored four-Event unit in one
//! transaction. Inside it the Station
//!
//! 1. answers an exact retry (same founder, idempotency key and unit digest) with the stored four
//!    Commits before anything else is judged, and refuses the same key with another unit as
//!    `duplicate_conflict`;
//! 2. claims the founder's unique `(founder_id, trust_domain_id, pair_key)` slot, refusing a second
//!    unit as `direct_conversation_slot_already_committed`;
//! 3. reads the founding authority from its own current state: the pair's accepted Contact round
//!    and both directional heads, from which the root round's founder is derived and must be the
//!    unit's author;
//! 4. installs the genesis authority and commits the four Events on four consecutive Realm-stream
//!    Commits with their typed current results.
//!
//! Any refusal rolls the whole unit back. No founding receipt exists; the
//! Commits and the slot are the only durable acceptance.

use std::collections::BTreeSet;

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, CommittedEventSubmission,
    DirectConversationFoundingFederationSubmission, PeerAuthoritySubmitRequest,
    PeerRegisteredAtomicUnit, PeerRegisteredAtomicUnitRequest, RegisteredAtomicUnitBranch,
};
use arkret_models_collaboration::contact_operations::ContactRound;
use arkret_models_collaboration::objects::direct_conversation::{
    DirectConversationAuthorizationBasis, DirectConversationFoundingAuthorityEvidence,
};
use arkret_wire::ActorId;
use soland_storage::{
    AuthorityCommitWriteOutcome, ConflictCode, ContactRecord,
    DirectConversationFoundingAuthorityRef, DirectConversationFoundingCommitOutcome,
    DirectConversationFoundingCommitUnit, DirectConversationFoundingFacts, FederationOutboxRecord,
    SelfProducerCommitGuard,
};

use super::{
    AsyncConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, Text, Timestamptz, sql_query,
};
use crate::authority_commit::{
    check_self_producer_guard_in_connection, commit_transaction_in_connection,
    queue_event_in_connection,
};
use crate::{PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct StoredUnitRow {
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Jsonb)]
    commits_json: serde_json::Value,
}

fn conflict(code: ConflictCode, detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", code.as_str()))
}

/// The scope both directions of the pair must grant.
const DIRECT_MESSAGE_SCOPE: &str = "direct_message";

/// The current accepted Contact of the pair: the most recent row, with a
/// non-accepted row winning a tie so stale acceptance never masks a change.
pub(crate) fn current_contact(records: Vec<ContactRecord>) -> Option<ContactRecord> {
    records.into_iter().max_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            .then_with(|| (left.status != "accepted").cmp(&(right.status != "accepted")))
    })
}

/// Section 5.4 at the slot-commit linearization point: the pair's current
/// accepted Contact round is the one the genesis names, both directional
/// current heads reference it, grant `direct_message` and are fresh, and the
/// founder derived from its root round is the unit's author.
///
/// Returns the canonical `accepted_contact` authorization basis every binding
/// endorsement must name (section 8.3): the round's accepted request and
/// accept Event refs, its two directional current heads.
async fn verify_contact_round_founding_authority(
    conn: &mut diesel_async::AsyncPgConnection,
    facts: &DirectConversationFoundingFacts,
    contact_round_id: &arkret_wire::Hash,
    local_station: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
    missing_code: ConflictCode,
) -> PersistenceResult<(
    DirectConversationAuthorizationBasis,
    DirectConversationFoundingAuthorityEvidence,
)> {
    let stale = |detail: &str| conflict(ConflictCode::FailedPrecondition, detail);
    let contact = current_contact(
        crate::contacts::pair_contacts_in_connection(conn, &facts.founder_id, &facts.peer_id)
            .await?,
    )
    .ok_or_else(|| conflict(missing_code, "the pair has no local Contact round"))?;
    let grants_direct_message = |scopes: &[String]| {
        scopes
            .iter()
            .any(|scope| scope.as_str() == DIRECT_MESSAGE_SCOPE)
    };
    if contact.status != "accepted"
        || contact.tombstone_event_ref.is_some()
        || !grants_direct_message(&contact.granted_to_target_scopes)
        || !grants_direct_message(&contact.granted_to_requester_scopes)
    {
        return Err(stale(
            "the pair's current Contact does not grant direct_message both ways",
        ));
    }
    let evidence = contact
        .contact_round_evidence
        .clone()
        .ok_or_else(|| stale("the pair's current Contact round has no evidence"))?;
    if contact.contact_round_id.as_ref() != Some(&evidence.contact_round_id)
        || &evidence.contact_round_id != contact_round_id
    {
        return Err(stale(
            "the genesis names a Contact round that is not the pair's current round",
        ));
    }
    if evidence.current_proofs.len() != 2 {
        return Err(stale("both directional current heads are required"));
    }
    let glare_requests = match &evidence.contact_round {
        ContactRound::Glare { requests, .. } => {
            if !requests.iter().any(|request| {
                contact.request_event_ref.as_ref() == Some(&request.request_event_ref)
            }) {
                return Err(stale(
                    "the local Contact request is outside the glare round",
                ));
            }
            Some(requests)
        }
        ContactRound::Normal { .. } => None,
    };
    for proof in &evidence.current_proofs {
        let peer = proof.peer.contact_actor_id();
        let head = if let Some(requests) = glare_requests {
            let matching = evidence
                .request_receipts
                .iter()
                .filter(|receipt| {
                    receipt.core.peer.contact_actor_id() == peer
                        && requests.iter().any(|request| {
                            request.request_event_ref == receipt.core.request_event_ref
                        })
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(stale("a glare direction has no unique accepted request"));
            }
            Some(&matching[0].core.request_event_ref)
        } else if peer == contact.target_id {
            contact.request_event_ref.as_ref()
        } else if peer == contact.requester_id {
            contact.response_event_ref.as_ref()
        } else {
            None
        };
        if proof.terminal
            || proof.contact_round_id != evidence.contact_round_id
            || head != Some(&proof.head_event_ref)
            || (&proof.issuer_id != local_station && proof.fresh_until <= at)
        {
            return Err(stale(
                "a directional current head is terminal, stale or not the accepted head",
            ));
        }
    }
    let founding = DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence: evidence,
        contact_round_continuity_chains: contact.contact_round_evidence_history.clone(),
    };
    let (participants, founder) = founding.participants_and_founder().map_err(|error| {
        stale(&format!(
            "the Contact round evidence does not derive a founder: {error}"
        ))
    })?;
    let DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence,
        contact_round_continuity_chains,
    } = &founding
    else {
        unreachable!("constructed as the human branch above")
    };
    let root = contact_round_evidence
        .continuity_checkpoint
        .is_none()
        .then(|| {
            contact_round_continuity_chains
                .last()
                .unwrap_or(contact_round_evidence)
        });
    if let Some(root) = root
        && let ContactRound::Glare { requests, .. } = &root.contact_round
    {
        let attestations = root
            .glare_concurrency_attestations
            .as_ref()
            .ok_or_else(|| stale("a glare root round needs both concurrency attestations"))?;
        if root.request_receipts.len() != 2
            || attestations.iter().any(|attestation| {
                attestation.complete_through == 0
                    || requests.iter().any(|request| {
                        !attestation
                            .observed_commit_event_ids
                            .contains(&request.request_event_ref)
                    })
            })
        {
            return Err(stale(
                "the glare root round attestations do not cover both requests",
            ));
        }
    }
    if participants.iter().collect::<BTreeSet<_>>()
        != [&facts.founder_id, &facts.peer_id]
            .into_iter()
            .collect::<BTreeSet<_>>()
    {
        return Err(stale(
            "the Contact round pair is not the founding unit's pair",
        ));
    }
    if founder != facts.founder_id {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "only the founder derived from the pair's root Contact round may found it",
        ));
    }
    let mut heads = contact_round_evidence
        .current_proofs
        .iter()
        .map(|proof| proof.head_event_ref.clone())
        .collect::<Vec<_>>();
    heads.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let basis = DirectConversationAuthorizationBasis::accepted_contact(heads);
    basis
        .validate_shape()
        .map_err(|error| stale(&format!("the Contact round heads are not a basis: {error}")))?;
    Ok((basis, founding))
}

fn account_station(actor: &ActorId) -> Option<&arkret_wire::DidCoreId> {
    actor.as_account_id().map(|account| &account.station_id)
}

pub(crate) async fn admit_self_direct_conversation_founding_unit(
    pool: &PgPool,
    unit: &DirectConversationFoundingCommitUnit,
    producer_guards: &[SelfProducerCommitGuard; 4],
    queued_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<DirectConversationFoundingCommitOutcome> {
    let facts = unit
        .facts()
        .map_err(|error| conflict(ConflictCode::DirectConversationFoundingUnitInvalid, error))?;
    unit.validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let authority = unit.transactions[0].expected_authority.clone();
    if facts.governance_station_id != authority.service_id {
        return Err(conflict(
            ConflictCode::DirectConversationFoundingUnitInvalid,
            "the genesis governance Station is not the admitting Station",
        ));
    }
    if account_station(&facts.founder_id) != Some(&authority.service_id) {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "the founder's current Station admits the founding unit",
        ));
    }
    let peer_station = account_station(&facts.peer_id).cloned().ok_or_else(|| {
        conflict(
            ConflictCode::DirectConversationFoundingUnitInvalid,
            "the peer must have a routable Account Station",
        )
    })?;
    let founder_id = facts.founder_id.to_string();
    let peer_id = facts.peer_id.to_string();
    let trust_domain_id = facts.trust_domain_id.as_str().to_owned();
    let pair_key = facts.pair_key.as_str().to_owned();
    let digest = facts.founding_unit_digest.as_str().to_owned();
    let idempotency_key = unit.submission.idempotency_key.as_uuid().to_string();
    let commits = unit.commits();
    let committed_at = commits[3].committed_at;
    let event_ids = unit
        .transactions
        .iter()
        .map(|transaction| transaction.event.event_id.to_string())
        .collect::<Vec<_>>();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        crate::unit_of_work::advisory_lock(
            conn,
            format!("direct-conversation-founding:{founder_id}:{trust_domain_id}:{pair_key}"),
        )
        .await?;
        crate::unit_of_work::advisory_lock(
            conn,
            format!("direct-conversation-founding-key:{founder_id}:{idempotency_key}"),
        )
        .await?;
        let replay = sql_query(
            "SELECT founding_unit_digest,commits_json FROM direct_conversation_founding_slots \
             WHERE founder_id=$1 AND idempotency_key=$2",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&idempotency_key)
        .get_result::<StoredUnitRow>(&mut *conn)
        .await
        .optional()?;
        if let Some(stored) = replay {
            if stored.founding_unit_digest != digest {
                return Err(conflict(
                    ConflictCode::DuplicateConflict,
                    "the idempotency key already founded another unit",
                )
                .into());
            }
            let stored: [arkret_wire::RealmCommit; 4] =
                serde_json::from_value(stored.commits_json).map_err(|error| {
                    PersistenceError::Database(format!(
                        "stored Direct Conversation founding Commits are invalid: {error}"
                    ))
                })?;
            return Ok(DirectConversationFoundingCommitOutcome::Duplicate(stored));
        }
        let occupied = sql_query(
            "SELECT founding_unit_digest,commits_json FROM direct_conversation_founding_slots \
             WHERE founder_id=$1 AND trust_domain_id=$2 AND pair_key=$3",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .get_result::<StoredUnitRow>(&mut *conn)
        .await
        .optional()?;
        if occupied.is_some() {
            return Err(conflict(
                ConflictCode::DirectConversationSlotAlreadyCommitted,
                "the founder's slot for this pair is closed",
            )
            .into());
        }
        let (authorization_basis, founding_evidence) = match &facts.authority_ref {
            DirectConversationFoundingAuthorityRef::ContactRound(contact_round_id) => {
                verify_contact_round_founding_authority(
                    conn,
                    &facts,
                    contact_round_id,
                    &authority.service_id,
                    committed_at,
                    ConflictCode::FailedPrecondition,
                )
                .await?
            }
            // `ak.agent.provision` has no atomic typed current admission yet
            // (task 2230), so no accepted provision or current controller
            // binding can be read at this cut.
            DirectConversationFoundingAuthorityRef::AgentProvision(_) => {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "no accepted Agent provision is readable at the founding cut",
                )
                .into());
            }
        };
        let authority_inserted = sql_query(
            "INSERT INTO realm_authorities \
             (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
             VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
        )
        .bind::<Text, _>(authority.realm_id.as_str())
        .bind::<Text, _>(authority.service_id.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?,
        )
        .execute(&mut *conn)
        .await?;
        if authority_inserted != 1 {
            return Err(conflict(
                ConflictCode::RealmAlreadyExists,
                "the founding genesis names an existing Realm",
            )
            .into());
        }
        for (transaction, guard) in unit.transactions.iter().zip(producer_guards) {
            check_self_producer_guard_in_connection(
                conn,
                &transaction.event,
                guard,
                transaction.commit.committed_at,
            )
            .await?;
            queue_event_in_connection(conn, &transaction.event, queued_at).await?;
            match commit_transaction_in_connection(conn, transaction).await? {
                AuthorityCommitWriteOutcome::Committed => {}
                AuthorityCommitWriteOutcome::Duplicate => {
                    return Err(conflict(
                        ConflictCode::DuplicateConflict,
                        "a founding Event is already committed",
                    )
                    .into());
                }
                AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                    return Err(PersistenceError::Conflict(
                        "stale_realm_authority: the founding genesis authority moved".to_owned(),
                    )
                    .into());
                }
            }
            let event = &transaction.event;
            let commit = &transaction.commit;
            crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
            crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
            crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit)
                .await?;
            crate::strand_current_results::commit_strand_create_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
        }
        crate::account_summary::publish_realm_account_summary_in_connection(
            conn,
            &authority.realm_id,
        )
        .await?;
        sql_query(
            "INSERT INTO direct_conversation_founding_slots \
             (founder_id,trust_domain_id,pair_key,peer_id,founding_unit_digest,realm_id,\
              main_strand_id,authorization_basis,event_ids,commits_json,idempotency_key,accepted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .bind::<Text, _>(&peer_id)
        .bind::<Text, _>(&digest)
        .bind::<Text, _>(facts.realm_id.as_str())
        .bind::<Text, _>(facts.main_strand_id.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&authorization_basis).map_err(PersistenceError::database)?,
        )
        .bind::<Jsonb, _>(serde_json::to_value(&event_ids).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(serde_json::to_value(&commits).map_err(PersistenceError::database)?)
        .bind::<Text, _>(&idempotency_key)
        .bind::<Timestamptz, _>(committed_at)
        .execute(&mut *conn)
        .await?;
        if peer_station != authority.service_id {
            let request = PeerAuthoritySubmitRequest::RegisteredAtomicUnit(
                PeerRegisteredAtomicUnitRequest {
                    branch: RegisteredAtomicUnitBranch::RegisteredAtomicUnit,
                    unit: PeerRegisteredAtomicUnit::DirectConversationFounding(
                        DirectConversationFoundingFederationSubmission {
                            unit_kind: unit.submission.unit_kind,
                            committed_events: std::array::from_fn(|index| {
                                CommittedEventSubmission {
                                    event_submission: unit.submission.events[index].clone(),
                                    source_commit: commits[index].clone(),
                                    welcomes: None,
                                }
                            }),
                            founding_authority_evidence: founding_evidence,
                        },
                    ),
                },
            );
            request
                .validate()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let payload_json = String::from_utf8(
                arkret_canonical::canonical_json_bytes(&request)
                    .map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
            let delivery_key = format!("direct-conversation-founding:{digest}");
            let delivery = FederationOutboxRecord::pending_without_locator(
                delivery_key.clone(),
                peer_station,
                crate::realm_fanout::PEER_EVENTS_ENDPOINT.to_owned(),
                delivery_key,
                payload_json,
                queued_at.timestamp(),
            );
            crate::federation::enqueue_federation_outbox_in_connection(conn, &delivery).await?;
        }
        Ok(DirectConversationFoundingCommitOutcome::Committed(
            commits.clone(),
        ))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// The peer materialization cut. The source has already signed all four
/// Commits; the peer locks its local Contact evidence and installs exactly
/// those rows with a complete anchored replica stream in one transaction.
pub(crate) async fn materialize_peer_direct_conversation_founding_unit(
    pool: &PgPool,
    unit: &DirectConversationFoundingCommitUnit,
    evidence: &DirectConversationFoundingAuthorityEvidence,
    local_station: &arkret_wire::DidCoreId,
    received_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AggregateAcceptanceStatus> {
    let facts = unit
        .facts()
        .map_err(|error| conflict(ConflictCode::DirectConversationFoundingUnitInvalid, error))?;
    unit.validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if &facts.governance_station_id == local_station
        || facts.peer_id.route_service_id() != local_station
    {
        return Err(conflict(
            ConflictCode::DirectConversationFoundingUnitInvalid,
            "the peer Station is not the recipient of the founding unit",
        ));
    }
    let founder_id = facts.founder_id.to_string();
    let peer_id = facts.peer_id.to_string();
    let trust_domain_id = facts.trust_domain_id.as_str().to_owned();
    let pair_key = facts.pair_key.as_str().to_owned();
    let digest = facts.founding_unit_digest.as_str().to_owned();
    let commits = unit.commits();
    let event_ids = unit
        .transactions
        .iter()
        .map(|transaction| transaction.event.event_id.to_string())
        .collect::<Vec<_>>();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        crate::unit_of_work::advisory_lock(
            conn,
            format!("direct-conversation-founding:{founder_id}:{trust_domain_id}:{pair_key}"),
        )
        .await?;
        let occupied = sql_query(
            "SELECT founding_unit_digest,commits_json FROM direct_conversation_founding_slots \
             WHERE founder_id=$1 AND trust_domain_id=$2 AND pair_key=$3",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .get_result::<StoredUnitRow>(&mut *conn)
        .await
        .optional()?;
        if let Some(occupied) = occupied {
            let stored: [arkret_wire::RealmCommit; 4] =
                serde_json::from_value(occupied.commits_json).map_err(PersistenceError::database)?;
            if occupied.founding_unit_digest == digest && stored == commits {
                return Ok(AggregateAcceptanceStatus::Duplicate);
            }
            return Err(conflict(
                ConflictCode::DirectConversationSlotAlreadyCommitted,
                "the peer already holds another founding unit for this pair",
            )
            .into());
        }
        let (basis, local_evidence) = match &facts.authority_ref {
            DirectConversationFoundingAuthorityRef::ContactRound(round_id) => {
                verify_contact_round_founding_authority(
                    conn,
                    &facts,
                    round_id,
                    local_station,
                    commits[3].committed_at,
                    ConflictCode::DependencyMissing,
                )
                .await?
            }
            DirectConversationFoundingAuthorityRef::AgentProvision(_) => {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "no accepted Agent provision is readable at the founding cut",
                )
                .into());
            }
        };
        if &local_evidence != evidence {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "the source founding evidence does not match the peer's current Contact round",
            )
            .into());
        }
        crate::authority_commit::replica::materialize_founding_in_connection(
            conn,
            unit,
            local_station,
            received_at,
        )
        .await?;
        sql_query(
            "INSERT INTO direct_conversation_founding_slots \
             (founder_id,trust_domain_id,pair_key,peer_id,founding_unit_digest,realm_id,\
              main_strand_id,authorization_basis,event_ids,commits_json,idempotency_key,accepted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .bind::<Text, _>(&peer_id)
        .bind::<Text, _>(&digest)
        .bind::<Text, _>(facts.realm_id.as_str())
        .bind::<Text, _>(facts.main_strand_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&basis).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(serde_json::to_value(&event_ids).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(serde_json::to_value(&commits).map_err(PersistenceError::database)?)
        .bind::<Text, _>(format!("peer:{digest}"))
        .bind::<Timestamptz, _>(commits[3].committed_at)
        .execute(&mut *conn)
        .await?;
        Ok(AggregateAcceptanceStatus::Committed)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
