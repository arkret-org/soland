//! Durable control-seal scheduling.
//!
//! Notifications only reduce latency. Every pass scans the durable pending
//! index, so process restarts and lost wakeups converge without an in-memory
//! queue becoming a second source of truth.

use std::time::Duration;

use arkret_identifiers::RealmId;

use crate::notary::NotaryWorker;
use crate::state::AppState;

const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const SIGNING_LEASE_DURATION_MS: i64 = 15_000;
const MAX_REALMS_PER_PASS: usize = 512;
const MAX_CONTROL_MOVES_PER_REALM: usize = 256;
const MAX_DEVICE_REVOCATION_CLEANUPS_PER_PASS: usize = 512;

pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let holder = format!("{}:{}", state.service_id(), uuid::Uuid::new_v4());
        let mut reconciliation = tokio::time::interval(RECONCILIATION_INTERVAL);
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = reconciliation.tick() => {}
                _ = state.control_seal_wakeup_notified() => {}
            }
            run_reconciliation_pass(&state, &holder).await;
        }
    })
}

async fn run_reconciliation_pass(state: &AppState, holder: &str) {
    let realms = match state
        .projections()
        .pending_control_realms(MAX_REALMS_PER_PASS)
    {
        Ok(realms) => realms,
        Err(error) => {
            tracing::error!(%error, "control-seal reconciliation could not list pending Realms");
            Vec::new()
        }
    };
    let worker = NotaryWorker::for_service(state.service_id().clone());
    tracing::debug!(
        pending_realm_count = realms.len(),
        "control-seal reconciliation scanned durable pending index"
    );
    for realm_id in realms {
        run_realm_pass(state, &worker, &realm_id, holder).await;
    }
    run_device_revocation_cleanup_pass(state).await;
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
            &intent.selector.principal_id,
            &intent.selector.device_id,
            completed_at,
        )
        .await
        .map_err(|error| format!("session cleanup failed: {error}"))?;
    let keypackages_retired = crate::routing::mls::retire_device_keypackages(
        state,
        &intent.selector.principal_id,
        &intent.selector.device_id,
    )
    .await
    .map_err(|error| format!("KeyPackage cleanup failed: {error}"))?;
    let delivery = state
        .deliveries()
        .purge_device_delivery(&intent.selector.principal_id, &intent.selector.device_id)
        .await
        .map_err(|error| format!("to-device/push cleanup failed: {error}"))?;

    crate::routing::append_audit_log(
        state,
        Some(&intent.selector.principal_id),
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
        &intent.selector.principal_id,
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

async fn run_realm_pass(state: &AppState, worker: &NotaryWorker, realm_id: &RealmId, holder: &str) {
    let slot = match worker.signing_lease_slot(state, realm_id, MAX_CONTROL_MOVES_PER_REALM) {
        Ok(Some(slot)) => slot,
        Ok(None) => {
            tracing::debug!(%realm_id, "control-seal Realm is not locally signable");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, %realm_id, "control-seal coordinator could not resolve signer slot");
            return;
        }
    };
    let pending = match state.projections().pending_control_events_for_notary(
        realm_id,
        None,
        MAX_CONTROL_MOVES_PER_REALM,
    ) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, %realm_id, "control-seal coordinator could not load pending proposal policy inputs");
            return;
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
            return;
        }
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let fence = match state.projections().try_claim_control_signing_lease(
        realm_id,
        &slot,
        holder,
        now_ms,
        now_ms.saturating_add(SIGNING_LEASE_DURATION_MS),
    ) {
        Ok(Some(fence)) => fence,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, %realm_id, signer_slot = %slot, "control-seal lease claim failed");
            return;
        }
    };

    match worker.sign_pending_for_realm(
        state,
        realm_id,
        MAX_CONTROL_MOVES_PER_REALM,
        proposal_policy,
    ) {
        Ok(Some(outcome)) => tracing::info!(
            %realm_id,
            seal_id = %outcome.seal_id,
            signer_slot = %slot,
            fence,
            "control-seal signing pass published a Seal"
        ),
        Ok(None) => tracing::debug!(
            %realm_id,
            signer_slot = %slot,
            fence,
            "control-seal signing pass had no accepted Moves"
        ),
        Err(error) => {
            tracing::error!(
                %error,
                %realm_id,
                signer_slot = %slot,
                fence,
                "control-seal signing pass failed"
            );
            if let Err(defer_error) =
                defer_due_proposals_after_failed_signing(state, realm_id, proposal_policy)
            {
                tracing::error!(
                    %defer_error,
                    %realm_id,
                    "control-seal coordinator could not persist bounded defer decisions"
                );
            }
        }
    }
    match state
        .projections()
        .release_control_signing_lease(realm_id, &slot, holder, fence)
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
}

fn defer_due_proposals_after_failed_signing(
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
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
