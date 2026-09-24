//! Non-governance receipt of one committed Event (federation §3,
//! device-lifecycle §8.2.2).
//!
//! A `committed_replication` member Station, an invite delivery receiver and
//! every other non-governance consumer of a committed Event never resolves or
//! fetches a foreign human device key. The governance `RealmCommit` is the
//! signed commitment to the admitting Station's device-authorization decision,
//! so such a receiver checks only:
//!
//! 1. the producer proof is self-consistent (`event_digest` over the exact canonical Event bytes,
//!    the method's bare DID projecting to the actual signer, and a human device fragment equal to
//!    the full `device_id`);
//! 2. the `RealmCommit` verifies under the governance Station the verified genesis/handoff chain
//!    names for the Commit's generation;
//! 3. the Commit/Event ref binding and, on a held stream, position and `previous_commit_ref`
//!    continuity.
//!
//! A human device of an Account this Station hosts is still verified against
//! local PCR. Every check is pure and writes nothing.

use arkret_canonical::DigestSuite;
use arkret_identity::{
    RealmAuthorityChainError, RealmAuthorityKeyDirectory, VerifiedRealmAuthority,
};
use arkret_wire::{
    CommitStreamRef, DidCoreId, DidKey, ErrorCode, Event, HumanDeviceProducer, RealmCommit,
};
use soland_storage::DeviceRevocationStore;

use crate::{ServiceError, ServiceResult};

/// Where the receiver already stands on the Commit's stream.
#[derive(Clone, Copy, Debug)]
pub enum CommitContinuity<'a> {
    /// The receiver holds the stream up to this head; the Commit must be its
    /// direct successor.
    After(&'a RealmCommit),
    /// The receiver holds nothing of the stream; the Commit must open it.
    StreamStart,
    /// A committed Event received outside any held stream (invite delivery):
    /// only the Commit/Event binding is judged.
    Standalone,
}

/// How the producer of an accepted receipt is established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedProducer {
    /// A human device of an Account on another Station. No key was resolved:
    /// the verified governance `RealmCommit` is the signed commitment to its
    /// authorization.
    GovernanceCommittedHumanDevice,
    /// A human device of an Account this Station hosts; its producer proof
    /// still has to verify under the local PCR key
    /// ([`verify_committed_event_receipt`] does so).
    HostedHumanDevice(HumanDeviceProducer),
    /// Not a human Account device (Agent, Service or controller method); the
    /// caller applies that producer's own signer evidence rule.
    OtherSigner,
}

/// Verify one committed Event as a non-governance receiver.
pub fn verify_non_governance_committed_event(
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    authority: &VerifiedRealmAuthority,
    keys: &dyn RealmAuthorityKeyDirectory,
    receiver: &DidCoreId,
    digest_suite: DigestSuite,
) -> ServiceResult<ReceivedProducer> {
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let producer = event
        .verify_producer_proof_self_consistency(digest_suite)
        .map_err(|error| {
            ServiceError::protocol(
                error.error_code().unwrap_or(ErrorCode::SignatureInvalid),
                error,
            )
        })?;
    verify_commit_binding(event, commit)?;
    authority
        .verify_commit(commit, keys)
        .map_err(governance_commit_refusal)?;
    verify_continuity(commit, continuity)?;
    Ok(match producer {
        Some(producer) if producer.account_id.station_id == *receiver => {
            ReceivedProducer::HostedHumanDevice(producer)
        }
        Some(_) => ReceivedProducer::GovernanceCommittedHumanDevice,
        None => ReceivedProducer::OtherSigner,
    })
}

/// [`verify_non_governance_committed_event`] on this Station: a human device
/// of an Account it hosts is then fully verified against the key of its local
/// PCR `device_authorization`, and a key mismatch is `signature_invalid`.
/// Nothing is read for a foreign human device.
#[allow(clippy::too_many_arguments)]
pub async fn verify_committed_event_receipt(
    local_pcr: &dyn DeviceRevocationStore,
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    authority: &VerifiedRealmAuthority,
    keys: &(dyn RealmAuthorityKeyDirectory + Sync),
    receiver: &DidCoreId,
    digest_suite: DigestSuite,
) -> ServiceResult<ReceivedProducer> {
    let received = verify_non_governance_committed_event(
        event,
        commit,
        continuity,
        authority,
        keys,
        receiver,
        digest_suite,
    )?;
    if let ReceivedProducer::HostedHumanDevice(producer) = &received {
        let key = local_pcr
            .pcr_device_authorization_key(&producer.account_id, &producer.device_id)
            .await
            .map_err(|error| {
                ServiceError::protocol(
                    ErrorCode::TemporarilyUnavailable,
                    format!("local PCR device authorization: {error}"),
                )
            })?
            .ok_or_else(|| {
                ServiceError::protocol(
                    ErrorCode::DeviceUnauthorized,
                    "hosted producer device has no accepted local PCR authorization",
                )
            })?;
        verify_hosted_human_device_proof(event, &key, digest_suite)?;
    }
    Ok(received)
}

fn verify_hosted_human_device_proof(
    event: &Event,
    key: &DidKey,
    digest_suite: DigestSuite,
) -> ServiceResult<()> {
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| ServiceError::SchemaViolation("Event has no producer proof".to_owned()))?;
    let multibase = key.as_str().strip_prefix("did:key:").ok_or_else(|| {
        ServiceError::protocol(
            ErrorCode::SignatureInvalid,
            "local PCR device key is not did:key",
        )
    })?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        },
        digest_suite,
    )
    .map_err(|error| {
        ServiceError::protocol(
            ErrorCode::SignatureInvalid,
            format!("producer proof does not verify under the local PCR device key: {error}"),
        )
    })
}

fn verify_commit_binding(event: &Event, commit: &RealmCommit) -> ServiceResult<()> {
    let stream_ref = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref != stream_ref
    {
        return Err(ServiceError::protocol(
            ErrorCode::SignatureInvalid,
            "RealmCommit does not bind the exact committed Event",
        ));
    }
    Ok(())
}

/// The SDK maps an invalid signature and a signer that is not the governance
/// Station of the Commit's generation to `signature_invalid`. Of the variants
/// it leaves to the caller, a key this Station could not resolve is retryable
/// and a Commit that is not well formed is `schema_violation`.
fn governance_commit_refusal(error: RealmAuthorityChainError) -> ServiceError {
    let code = error.error_code().unwrap_or(match error {
        RealmAuthorityChainError::MaterialIncomplete(_) | RealmAuthorityChainError::NotFresh(_) => {
            ErrorCode::TemporarilyUnavailable
        }
        _ => ErrorCode::SchemaViolation,
    });
    ServiceError::protocol(code, format!("governance RealmCommit: {error}"))
}

fn verify_continuity(commit: &RealmCommit, continuity: CommitContinuity<'_>) -> ServiceResult<()> {
    let discontinuous =
        |detail: &str| ServiceError::protocol(ErrorCode::FailedPrecondition, detail);
    match continuity {
        CommitContinuity::Standalone => Ok(()),
        CommitContinuity::StreamStart => {
            if commit.stream_position != 0 || commit.previous_commit_ref.is_some() {
                return Err(ServiceError::protocol(
                    ErrorCode::DependencyMissing,
                    "RealmCommit predecessors on its stream are not held",
                ));
            }
            Ok(())
        }
        CommitContinuity::After(head) => {
            if head.stream_ref != commit.stream_ref {
                return Err(discontinuous(
                    "RealmCommit predecessor is on another stream",
                ));
            }
            if commit.stream_position > head.stream_position.saturating_add(1) {
                return Err(ServiceError::protocol(
                    ErrorCode::DependencyMissing,
                    "RealmCommit predecessors between the held head and it are not held",
                ));
            }
            commit
                .validate_successor_of(head)
                .map_err(|error| discontinuous(&error.to_string()))
        }
    }
}
