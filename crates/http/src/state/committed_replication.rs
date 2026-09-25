//! `committed_replication` on a non-governance member Station
//! (`federation.md` §3 and §4.1.1).
//!
//! Each item is judged in request order and stored or rejected on its own:
//! the producer proof must be self-consistent, the source RealmCommit must
//! verify under the Realm's current authority chain as served and verified
//! from the authenticated source Station, and the Commit must directly follow
//! the stream this Station holds. A human device of an Account this Station
//! hosts is still verified against local PCR. The only way to open a held
//! Realm stream is the verified `join` of a member this Station hosts.
//! Nothing is admitted, re-signed or fanned out again.

use std::collections::BTreeMap;

use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, CommittedReplicationBranch, PeerCommittedReplicationOutcome,
    PeerCommittedReplicationOutcomeRecord, PeerCommittedReplicationRequest,
};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_wire::{CommitStreamRef, ErrorCode, RealmId};
use soland_services::authority_commit::AuthenticatedPeerContext;
use soland_services::committed_receipt::{CommitContinuity, verify_committed_event_receipt};
use soland_services::{ServiceError, ServiceResult};
use soland_storage::{CommittedReplica, CommittedReplicaOutcome, ConflictCode};

use super::AppState;
use crate::routing::realm_join::LocatedRealmAuthority;

fn temporarily_unavailable(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!(
        "{}: {detail}",
        ConflictCode::TemporarilyUnavailable
    ))
}

/// The reason one item was not stored. A local store or read fault is not a
/// judgement of the item, so it fails the whole request and the source
/// replays the exact body.
fn rejection_reason(error: ServiceError) -> ServiceResult<String> {
    match &error {
        ServiceError::SchemaViolation(_) => Ok(ErrorCode::SCHEMA_VIOLATION.to_owned()),
        ServiceError::UnsupportedEventKind(_) => Ok(ErrorCode::UNSUPPORTED_EVENT_KIND.to_owned()),
        ServiceError::NotFound(_) => Ok(ConflictCode::DependencyMissing.as_str().to_owned()),
        ServiceError::Conflict(detail) => {
            if error.conflict_code() == Some(ConflictCode::TemporarilyUnavailable) {
                return Err(error);
            }
            let token = detail
                .split_once(": ")
                .map_or(detail.as_str(), |(head, _)| head);
            let registered =
                ConflictCode::from_detail(token).is_some() || ErrorCode::from_wire(token).is_some();
            Ok(if registered {
                token.to_owned()
            } else {
                ErrorCode::FAILED_PRECONDITION.to_owned()
            })
        }
        ServiceError::Database(_) | ServiceError::Internal(_) => Err(error),
    }
}

/// Whether the item is the verified `join` of a member this Station hosts,
/// the one Event that may open its held Realm stream: the member's own
/// `ak.member.state{join}` or the directed invitee's `ak.invite.accept`, which
/// is that invitee's join (`governance-objects.md` §5.3).
fn hosted_member_join(state: &AppState, item: &CommittedEventSubmission) -> bool {
    let event = &item.event_submission.event;
    if item.source_commit.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return false;
    }
    match event.kind {
        arkret_wire::EventKind::MemberState => {
            let Ok(payload) = serde_json::to_value(&event.payload)
                .and_then(serde_json::from_value::<MembershipPayload>)
            else {
                return false;
            };
            payload.membership == MembershipPayloadState::Join
                && payload.member_id.route_service_id() == &state.service_core_id()
                && payload
                    .realm_id
                    .as_ref()
                    .is_none_or(|realm_id| realm_id == &event.realm_id)
        }
        arkret_wire::EventKind::InviteAccept => {
            matches!(event.actor_id, arkret_wire::ActorId::Account { .. })
                && event.actor_id.route_service_id() == &state.service_core_id()
        }
        _ => false,
    }
}

async fn replicate_one(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    authorities: &mut BTreeMap<RealmId, LocatedRealmAuthority>,
    item: &CommittedEventSubmission,
) -> ServiceResult<CommittedReplicaOutcome> {
    item.validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let event = &item.event_submission.event;
    super::authority_port::refuse_actor_private_event(&event.kind)?;
    let commit = &item.source_commit;
    if !matches!(commit.stream_ref, CommitStreamRef::Realm { .. }) {
        return Err(ServiceError::UnsupportedEventKind(
            "Circle and Sidecar replicas need their own scope membership basis".to_owned(),
        ));
    }
    if let Some(existing) = state
        .authority_commits()
        .committed_event_by_commit_id(&commit.commit_id)
        .await?
    {
        if existing.commit == *commit && existing.event == *event {
            return Ok(CommittedReplicaOutcome::Duplicate);
        }
        return Err(ServiceError::Conflict(format!(
            "{}: the Commit id is held with different content",
            ConflictCode::DuplicateConflict
        )));
    }
    if state
        .authority_commits()
        .current_authority(&event.realm_id)
        .await?
        .is_some_and(|authority| authority.service_id == state.service_core_id())
    {
        return Err(ServiceError::Conflict(format!(
            "{}: this Station governs the Realm and accepts no replica of it",
            ConflictCode::ForkQuarantine
        )));
    }
    if !authorities.contains_key(&event.realm_id) {
        let located = crate::routing::realm_join::resolve_verified_authority_of_service(
            state,
            &event.realm_id,
            &peer.source_service_id,
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("source Realm authority: {error}")))?;
        authorities.insert(event.realm_id.clone(), located);
    }
    let located = authorities
        .get_mut(&event.realm_id)
        .ok_or_else(|| ServiceError::internal("verified Realm authority vanished"))?;
    if arkret_identity::RealmAuthorityKeyDirectory::public_key(
        &located.keys,
        &commit.signature.verification_method,
    )
    .is_none()
    {
        crate::routing::realm_join::insert_method_key(
            state,
            &mut located.keys,
            &commit.signature.verification_method,
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("RealmCommit signing key: {error}")))?;
    }
    let opens_stream = hosted_member_join(state, item);
    let held = match state
        .authority_commits()
        .stream_head(&commit.stream_ref)
        .await?
    {
        Some(head) => Some(
            state
                .authority_commits()
                .committed_event_by_commit_id(&head.commit_id)
                .await?
                .ok_or_else(|| ServiceError::internal("held stream head has no Commit"))?
                .commit,
        ),
        None => None,
    };
    let continuity = match (&held, opens_stream) {
        (Some(head), _) => CommitContinuity::After(head),
        (None, true) => CommitContinuity::Standalone,
        (None, false) => CommitContinuity::StreamStart,
    };
    verify_committed_event_receipt(
        state.persistence(),
        event,
        commit,
        continuity,
        &located.authority,
        &located.keys,
        &state.service_core_id(),
        state
            .projections()
            .realm_digest_suite(event.realm_id.as_str()),
    )
    .await?;
    state
        .authority_commits()
        .install_committed_replica(&CommittedReplica {
            local_service_id: state.service_core_id(),
            authority: located.current_authority(),
            event: event.clone(),
            commit: commit.clone(),
            opens_stream: opens_stream && held.is_none(),
            received_at: crate::wire::now(),
        })
        .await
}

/// Judge every item of one `committed_replication` request in order.
pub(super) async fn receive(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerCommittedReplicationRequest,
) -> ServiceResult<PeerCommittedReplicationOutcome> {
    let mut authorities = BTreeMap::new();
    let mut replication_outcomes = Vec::with_capacity(request.replications.len());
    for item in &request.replications {
        let record = match replicate_one(state, peer, &mut authorities, item).await {
            Ok(CommittedReplicaOutcome::Stored) => PeerCommittedReplicationOutcomeRecord::Stored {},
            Ok(CommittedReplicaOutcome::Duplicate) => {
                PeerCommittedReplicationOutcomeRecord::Duplicate {}
            }
            Err(error) => PeerCommittedReplicationOutcomeRecord::Rejected {
                reason_code: rejection_reason(error)?,
            },
        };
        replication_outcomes.push(record);
    }
    Ok(PeerCommittedReplicationOutcome {
        branch: CommittedReplicationBranch::CommittedReplication,
        replication_outcomes,
    })
}
