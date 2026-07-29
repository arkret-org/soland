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
            return;
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

    match worker.sign_pending_for_realm(state, realm_id, MAX_CONTROL_MOVES_PER_REALM) {
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
                defer_due_proposals_after_failed_signing(state, realm_id).await
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

async fn defer_due_proposals_after_failed_signing(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<(), String> {
    let policy = crate::control_proposal::control_proposal_policy(state, realm_id, &[]).await?;
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
        let Some(receipt) = record.proposal_receipt.as_ref() else {
            return Err(format!(
                "pending Control Move {} has no proposal receipt",
                record
                    .event
                    .event_digest()
                    .map_err(|error| error.to_string())?
            ));
        };
        let current_due_at = record
            .decisions
            .last()
            .map(arkret_wire::ControlProposalDecision::decision_due_at)
            .unwrap_or(receipt.decision_due_at);
        if current_due_at > now + decision_guard
            || record.decisions.len() >= usize::from(policy.max_defers)
            || current_due_at >= receipt.absolute_due_at
        {
            continue;
        }
        let next_due_at = std::cmp::min(
            current_due_at + policy.decision_window,
            receipt.absolute_due_at,
        );
        if next_due_at <= current_due_at {
            continue;
        }
        let (notary, _) = crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .current_notary_profile_for_events(state, realm_id, std::slice::from_ref(&record.event))
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "current proposal notary profile is unavailable".to_owned())?;
        let decision = crate::control_proposal::sign_control_proposal_defer(
            state,
            receipt,
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
                .event_digest()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        state
            .projections()
            .record_control_proposal_decision(&digest, &decision)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
