//! Durable control-seal scheduling.
//!
//! Notifications only reduce latency. Every pass scans the durable pending
//! index, so process restarts and lost wakeups converge without an in-memory
//! queue becoming a second source of truth.

use std::time::Duration;

use arkret_identifiers::RealmId;
use arkret_state::state::{ControlSealAttemptOutcome, ControlSealScheduleClaim};
use tokio::task::JoinSet;

use crate::notary::{NotaryWorker, SigningLeaseSlotResolution};
use crate::state::AppState;

const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const SCHEDULE_REPAIR_INTERVAL: Duration = Duration::from_secs(60);
const SIGNING_LEASE_DURATION_MS: i64 = 15_000;
const SCHEDULE_CLAIM_DURATION_MS: i64 = 20_000;
const REALM_PASS_TIMEOUT: Duration = Duration::from_secs(10);
const SCHEDULE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEDULE_STORE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REALM_ATTEMPTS_PER_PASS: usize = 512;
const MAX_SCHEDULE_REPAIRS_PER_PASS: usize = 512;
const MAX_CONTROL_MOVES_PER_REALM: usize = 256;
const MAX_DEVICE_REVOCATION_CLEANUPS_PER_PASS: usize = 512;
// A full Station can have many independent Realms become pending at
// once. Processing them serially lets an otherwise healthy queue age beyond
// the Event replay window. The durable signing lease remains the per-Realm
// exclusion mechanism; this bound only permits independent Realms to make
// progress concurrently.
const MAX_CONCURRENT_REALM_PASSES: usize = 16;

pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let holder = format!("{}:{}", state.service_id(), uuid::Uuid::new_v4());
        let mut reconciliation = tokio::time::interval(RECONCILIATION_INTERVAL);
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut next_repair_at = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = reconciliation.tick() => {}
                _ = state.control_seal_wakeup_notified() => {}
            }
            let now = tokio::time::Instant::now();
            let repair_due = now >= next_repair_at;
            if repair_due {
                next_repair_at = now + SCHEDULE_REPAIR_INTERVAL;
            }
            run_reconciliation_pass(&state, &holder, repair_due).await;
        }
    })
}

async fn run_reconciliation_pass(state: &AppState, holder: &str, repair_due: bool) {
    if repair_due {
        let repair_now_ms = chrono::Utc::now().timestamp_millis();
        let repair = tokio::time::timeout(
            SCHEDULE_STORE_TIMEOUT,
            state
                .projections()
                .repair_control_seal_schedule(repair_now_ms, MAX_SCHEDULE_REPAIRS_PER_PASS),
        )
        .await;
        match repair {
            Ok(Ok(stats)) => {
                crate::metrics::record_control_seal_repair(
                    stats.scanned,
                    stats.inserted,
                    stats.generation_repaired,
                    stats.stale_deleted,
                    stats.cursor_wrapped,
                );
                tracing::debug!(
                    scanned = stats.scanned,
                    inserted = stats.inserted,
                    generation_repaired = stats.generation_repaired,
                    stale_deleted = stats.stale_deleted,
                    cursor_wrapped = stats.cursor_wrapped,
                    "control-seal schedule repair page completed"
                );
                if stats.inserted > 0 || stats.generation_repaired > 0 {
                    tracing::warn!(
                        inserted = stats.inserted,
                        generation_repaired = stats.generation_repaired,
                        "control-seal schedule repair restored missing write-path state"
                    );
                }
            }
            Ok(Err(error)) => tracing::error!(%error, "control-seal schedule repair failed"),
            Err(_) => tracing::error!(
                timeout_ms = SCHEDULE_STORE_TIMEOUT.as_millis(),
                "control-seal schedule repair timed out"
            ),
        }
    }

    let mut passes = JoinSet::new();
    let mut attempts = 0_usize;
    while attempts < MAX_REALM_ATTEMPTS_PER_PASS {
        if passes.len() >= MAX_CONCURRENT_REALM_PASSES {
            join_next_realm_pass(&mut passes).await;
            continue;
        }
        let free_slots = (MAX_CONCURRENT_REALM_PASSES - passes.len())
            .min(MAX_REALM_ATTEMPTS_PER_PASS - attempts);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let claim_holder = holder.to_owned();
        let claims = tokio::time::timeout(
            SCHEDULE_STORE_TIMEOUT,
            state.projections().claim_due_control_seal_realms(
                &claim_holder,
                now_ms,
                now_ms.saturating_add(SCHEDULE_CLAIM_DURATION_MS),
                free_slots,
            ),
        )
        .await;
        let claims = match claims {
            Ok(Ok(claims)) => claims,
            Ok(Err(error)) => {
                tracing::error!(%error, "control-seal coordinator could not claim due Realms");
                break;
            }
            Err(_) => {
                tracing::error!(
                    timeout_ms = SCHEDULE_STORE_TIMEOUT.as_millis(),
                    "control-seal coordinator claim timed out"
                );
                break;
            }
        };
        if claims.is_empty() {
            if passes.is_empty() {
                break;
            }
            join_next_realm_pass(&mut passes).await;
            continue;
        }
        crate::metrics::record_control_seal_claimed(claims.len());
        attempts = attempts.saturating_add(claims.len());
        for claim in claims {
            // Keep the signing state machine behind a Tokio task boundary.
            // Claimed work is spawned immediately; no leased Realm waits in a
            // local queue while its durable claim expires.
            let state = state.clone();
            passes.spawn(async move {
                run_claimed_realm_pass(&state, claim).await;
            });
        }
        crate::metrics::set_control_seal_in_flight(passes.len());
    }
    while !passes.is_empty() {
        join_next_realm_pass(&mut passes).await;
    }
    tracing::debug!(
        attempts,
        "control-seal reconciliation attempt budget completed"
    );
    run_device_revocation_cleanup_pass(state).await;
}

async fn run_claimed_realm_pass(state: &AppState, claim: ControlSealScheduleClaim) {
    let outcome = match tokio::time::timeout(
        REALM_PASS_TIMEOUT,
        run_realm_pass(state, &claim.realm_id, &claim.holder),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            tracing::error!(
                realm_id = %claim.realm_id,
                timeout_ms = REALM_PASS_TIMEOUT.as_millis(),
                "control-seal Realm pass timed out"
            );
            ControlSealAttemptOutcome::PassTimedOut
        }
    };
    let observed_at_ms = chrono::Utc::now().timestamp_millis();
    let completion = tokio::time::timeout(
        SCHEDULE_COMPLETION_TIMEOUT,
        state
            .projections()
            .complete_control_seal_attempt(&claim, &outcome, observed_at_ms),
    )
    .await;
    match completion {
        Ok(Ok(completion)) => {
            crate::metrics::record_control_seal_attempt(outcome.as_str(), completion.as_str());
            tracing::debug!(
                realm_id = %claim.realm_id,
                generation = claim.generation,
                fence = claim.fence,
                outcome = outcome.as_str(),
                ?completion,
                "control-seal schedule attempt completed"
            );
        }
        Ok(Err(error)) => {
            crate::metrics::record_control_seal_attempt(outcome.as_str(), "store_error");
            tracing::error!(
                %error,
                realm_id = %claim.realm_id,
                generation = claim.generation,
                fence = claim.fence,
                outcome = outcome.as_str(),
                "control-seal schedule completion failed"
            );
        }
        Err(_) => {
            crate::metrics::record_control_seal_attempt(outcome.as_str(), "completion_timed_out");
            tracing::error!(
                realm_id = %claim.realm_id,
                generation = claim.generation,
                fence = claim.fence,
                outcome = outcome.as_str(),
                timeout_ms = SCHEDULE_COMPLETION_TIMEOUT.as_millis(),
                "control-seal schedule completion timed out; claim expiry will recover it"
            );
        }
    }
}

async fn join_next_realm_pass(passes: &mut JoinSet<()>) {
    if let Some(Err(error)) = passes.join_next().await {
        tracing::error!(%error, "isolated control-seal Realm pass failed");
    }
    crate::metrics::set_control_seal_in_flight(passes.len());
}

async fn run_device_revocation_cleanup_pass(state: &AppState) {
    let intents = match state
        .persistence()
        .pending_device_revocation_cleanup_intents(MAX_DEVICE_REVOCATION_CLEANUPS_PER_PASS)
        .await
    {
        Ok(intents) => intents,
        Err(error) => {
            tracing::error!(%error, "device-revocation cleanup intents are unavailable");
            return;
        }
    };
    for intent in intents {
        if intent.material_cleanup_completed_at.is_none()
            && let Err(error) = run_device_revocation_material_cleanup(state, &intent).await
        {
            tracing::error!(
                %error,
                proposal_digest = %intent.proposal_digest,
                proposal_event_id = %intent.proposal_event_id,
                "sealed device-revocation material cleanup failed"
            );
            continue;
        }
        if intent.mls_obligation_completed_at.is_none() {
            run_device_revocation_mls_cleanup(state, &intent).await;
        }
    }
}

async fn run_device_revocation_material_cleanup(
    state: &AppState,
    intent: &soland_storage::DeviceRevocationCleanupIntent,
) -> Result<(), String> {
    let completed_at = chrono::Utc::now();
    let sessions_revoked = state
        .sessions()
        .revoke_actor_device_sessions(
            intent.selector.principal_id.as_str(),
            &intent.selector.device_id,
            completed_at,
        )
        .await
        .map_err(|error| format!("session cleanup failed: {error}"))?;
    let keypackages_retired = crate::routing::mls::retire_device_keypackages(
        state,
        intent.selector.principal_id.as_str(),
        &intent.selector.device_id,
    )
    .await
    .map_err(|error| format!("KeyPackage cleanup failed: {error}"))?;
    let delivery = state
        .deliveries()
        .purge_device_delivery(
            intent.selector.principal_id.as_str(),
            &intent.selector.device_id,
        )
        .await
        .map_err(|error| format!("to-device/push cleanup failed: {error}"))?;

    crate::routing::append_audit_log(
        state,
        Some(intent.selector.principal_id.as_str()),
        "device.revoke.sealed_cleanup",
        serde_json::json!({
            "proposal_digest": intent.proposal_digest,
            "proposal_event_id": intent.proposal_event_id,
            "covering_seal_id": intent.covering_seal_id,
            "device_id": intent.selector.device_id,
            "target_device_authorize_event_id": intent.selector.target_device_authorize_event_id,
            "target_device_generation_ref": intent.selector.target_device_generation_ref,
            "sessions_revoked": sessions_revoked,
            "keypackages_retired": keypackages_retired,
            "to_device_messages_dropped": delivery.to_device_messages_dropped,
            "push_registrations_removed": delivery.push_registrations_removed,
        }),
        "completed",
    )
    .await;
    state
        .persistence()
        .complete_device_revocation_material_cleanup(&intent.proposal_digest, completed_at)
        .await
        .map_err(|error| format!("durable material cleanup acknowledgement failed: {error}"))?;
    Ok(())
}

async fn run_device_revocation_mls_cleanup(
    state: &AppState,
    intent: &soland_storage::DeviceRevocationCleanupIntent,
) {
    crate::routing::mls::enqueue_device_revoke_mls_removals(
        state,
        intent.selector.principal_id.as_str(),
        &intent.selector.device_id,
        &intent.proposal_event_id,
    );
    let has_obligation = state
        .projections()
        .snapshot()
        .pending_mls_removals
        .iter()
        .any(|obligation| {
            obligation
                .membership_frontier
                .iter()
                .any(|event_id| event_id == &intent.proposal_event_id)
        });
    if has_obligation {
        return;
    }
    // No MLS scope currently contains the revoked device generation. The
    // durable task can close immediately; otherwise only an accepted covering
    // MLS commit acknowledges the step through the projection apply path.
    if let Err(error) = state
        .persistence()
        .complete_device_revocation_mls_obligation_by_event_id(
            &intent.proposal_event_id,
            chrono::Utc::now(),
        )
        .await
    {
        tracing::error!(
            %error,
            proposal_event_id = %intent.proposal_event_id,
            "device-revocation empty MLS cleanup acknowledgement failed"
        );
    }
}

async fn run_realm_pass(
    state: &AppState,
    realm_id: &RealmId,
    holder: &str,
) -> ControlSealAttemptOutcome {
    let service_id = state.service_id().clone();
    let slot = match NotaryWorker::for_service(service_id)
        .signing_lease_slot(state, realm_id, MAX_CONTROL_MOVES_PER_REALM)
        .await
    {
        Ok(SigningLeaseSlotResolution::Ready(slot)) => slot,
        Ok(SigningLeaseSlotResolution::NoPendingMoves) => {
            return ControlSealAttemptOutcome::NoAcceptedMoves;
        }
        Ok(SigningLeaseSlotResolution::NotaryValueUnavailable) => {
            return ControlSealAttemptOutcome::NotaryValueUnavailable;
        }
        Ok(SigningLeaseSlotResolution::LocalSignerNotMember) => {
            return ControlSealAttemptOutcome::LocalSignerNotMember;
        }
        Ok(SigningLeaseSlotResolution::ThresholdRequiresExternalCoordinator) => {
            return ControlSealAttemptOutcome::ThresholdRequiresExternalCoordinator;
        }
        Ok(SigningLeaseSlotResolution::MixedRecoveryNotYetEligible { eligible_at_ms }) => {
            return ControlSealAttemptOutcome::MixedRecoveryNotYetEligible { eligible_at_ms };
        }
        Ok(SigningLeaseSlotResolution::MixedRecoveryRequiresExternalCoordinator) => {
            return ControlSealAttemptOutcome::MixedRecoveryRequiresExternalCoordinator;
        }
        Err(error) => {
            tracing::warn!(%error, %realm_id, "control-seal coordinator could not resolve signer slot");
            return ControlSealAttemptOutcome::SignerSlotUnavailable;
        }
    };
    let pending = match state
        .projections()
        .pending_control_events_for_notary(realm_id, None, MAX_CONTROL_MOVES_PER_REALM)
        .await
    {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, %realm_id, "control-seal coordinator could not load pending proposal policy inputs");
            return ControlSealAttemptOutcome::TransientStoreFailure;
        }
    };
    let proposal_policy = match crate::control_proposal::control_proposal_policy(
        state, realm_id, &pending,
    )
    .await
    {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(%error, %realm_id, "control-seal coordinator could not resolve proposal policy");
            return ControlSealAttemptOutcome::ProposalPolicyUnavailable;
        }
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let lease_holder = holder.to_owned();
    let fence = match state
        .projections()
        .try_claim_control_signing_lease(
            realm_id,
            &slot,
            &lease_holder,
            now_ms,
            now_ms.saturating_add(SIGNING_LEASE_DURATION_MS),
        )
        .await
    {
        Ok(Some(fence)) => fence,
        Ok(None) => return ControlSealAttemptOutcome::SigningLeaseBusy,
        Err(error) => {
            tracing::warn!(%error, %realm_id, signer_slot = %slot, "control-seal lease claim failed");
            return ControlSealAttemptOutcome::TransientStoreFailure;
        }
    };

    let worker = NotaryWorker::for_service(state.service_id().clone());
    let attempt_outcome = match worker
        .sign_pending_for_realm(
            state,
            realm_id,
            MAX_CONTROL_MOVES_PER_REALM,
            proposal_policy,
        )
        .await
    {
        Ok(Some(outcome)) => {
            tracing::info!(
                %realm_id,
                seal_id = %outcome.seal_id,
                signer_slot = %slot,
                fence,
                "control-seal signing pass published a Seal"
            );
            ControlSealAttemptOutcome::ProgressPublished
        }
        Ok(None) => {
            tracing::debug!(
                %realm_id,
                signer_slot = %slot,
                fence,
                "control-seal signing pass had no accepted Moves"
            );
            ControlSealAttemptOutcome::NoAcceptedMoves
        }
        Err(error) => {
            tracing::error!(
                %error,
                %realm_id,
                signer_slot = %slot,
                fence,
                "control-seal signing pass failed"
            );
            if let Err(defer_error) =
                defer_due_proposals_after_failed_signing(state, realm_id, proposal_policy).await
            {
                tracing::error!(
                    %defer_error,
                    %realm_id,
                    "control-seal coordinator could not persist bounded defer decisions"
                );
            }
            ControlSealAttemptOutcome::SigningFailed
        }
    };
    let release_holder = holder.to_owned();
    match state
        .projections()
        .release_control_signing_lease(realm_id, &slot, &release_holder, fence)
        .await
    {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            %realm_id,
            signer_slot = %slot,
            fence,
            "control-seal lease was replaced before release"
        ),
        Err(error) => tracing::warn!(
            %error,
            %realm_id,
            signer_slot = %slot,
            fence,
            "control-seal lease release failed"
        ),
    }
    attempt_outcome
}

async fn defer_due_proposals_after_failed_signing(
    state: &AppState,
    realm_id: &RealmId,
    policy: arkret_wire::ControlProposalDecisionPolicy,
) -> Result<(), String> {
    if policy.max_defers == 0 {
        return Ok(());
    }
    let now = chrono::Utc::now();
    let decision_guard =
        chrono::Duration::from_std(RECONCILIATION_INTERVAL).map_err(|error| error.to_string())?;
    let records = state
        .projections()
        .pending_control_records(realm_id, MAX_CONTROL_MOVES_PER_REALM)
        .await
        .map_err(|error| error.to_string())?;
    for record in records {
        let Some(ack) = record.control_proposal_ack.as_ref() else {
            if soland_storage::has_self_principal_pcr_device_authorized_shape(
                &record.event,
                record.digest_suite,
            ) && state
                .projections()
                .snapshot()
                .realm_is_principal_control(record.event.realm_id.as_str())
            {
                // Device-authorized Human PCR moves have no external proposal
                // deadline and therefore never receive coordinator defers.
                continue;
            }
            return Err(format!(
                "pending Control Move {} has no Control Proposal Ack",
                record
                    .event
                    .event_digest_with_digest_suite(record.digest_suite)
                    .map_err(|error| error.to_string())?
            ));
        };
        let current_due_at = record
            .decisions
            .last()
            .map(arkret_wire::ControlProposalDecision::decision_due_at)
            .unwrap_or(ack.decision_due_at);
        if current_due_at > now + decision_guard
            || record.decisions.len() >= usize::from(policy.max_defers)
            || current_due_at >= ack.absolute_due_at
        {
            continue;
        }
        let next_due_at =
            std::cmp::min(current_due_at + policy.decision_window, ack.absolute_due_at);
        if next_due_at <= current_due_at {
            continue;
        }
        let (notary, _) = crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .current_notary_value_for_events(state, realm_id, std::slice::from_ref(&record.event))
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "current proposal notary profile is unavailable".to_owned())?;
        let decision = crate::control_proposal::sign_control_proposal_defer(
            state,
            ack,
            &record.decisions,
            &notary,
            arkret_wire::ControlProposalDeferReason::TemporarilyUnavailable,
            now,
            next_due_at,
            policy,
        )?;
        let digest = arkret_identifiers::Hash::new(
            record
                .event
                .event_digest_with_digest_suite(record.digest_suite)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        state
            .projections()
            .record_control_proposal_decision(&digest, &decision, policy)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
